"""Original Root Popen owner and bounded PRIVATE capture, never test PASS.

No activation, engine command, socket or policy override exists. Root callers
must already hold the preparation lock/start intent and supply actual kernel
cgroup identity. Native storage/output quota and whole-platform qualification
remain required; bounded pipes do not bound the job-writable output filesystem.
Only this owner polls/waits its child; another process cannot recreate it.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import selectors
import stat
import subprocess
import time
import threading
from functools import wraps

from . import engine_policy as engine, identity, installation, ledger
from .identity import Denied, require

CHUNK = 65536


@dataclass(frozen=True)
class ExitObservation:
    lease_id: str
    effect_id: str
    exit_code: int | None
    signal: int | None
    stdout_state: str
    stderr_state: str
    receipt_sha256: str
    # Actual process/capture observation only; never VM/phase/evidence PASS.


class Capture:
    def __init__(self, manifest, store, lease_id, effect_id, cgroup_device, cgroup_inode):
        require(os.geteuid() == 0 and type(manifest) is engine.EngineManifest
                and type(store) is ledger.Ledger and store.owner_uid == 0, "supervision-root-capture")
        self.manifest, self.owner_pid = manifest, os.getpid()
        self.details = identity.decode_json(manifest.canonical_bytes)
        self.directory = self.details["engine"]["runroot"]
        self.parent = engine._directory(self.directory, private=True)
        self.parent_identity = (os.fstat(self.parent).st_dev, os.fstat(self.parent).st_ino)
        self.streams = {}
        self.receipt_safe = True
        limits = self.details["capture"]
        try:
            for name in ("stdout", "stderr"):
                fd = os.open(name + ".log", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=self.parent)
                try:
                    os.fchmod(fd, 0o600)
                    info = os.fstat(fd)
                    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                            and stat.S_IMODE(info.st_mode) == 0o600, "supervision-private-log")
                    self.streams[name] = {"fd": fd, "device": info.st_dev, "inode": info.st_ino,
                        "limit": limits[name + "_limit"], "bytes": 0, "hash": hashlib.sha256(),
                        "state": "complete", "eof": False}
                except BaseException:
                    os.close(fd)
                    raise
            os.fsync(self.parent)
            store.bind_engine_capture(lease_id, effect_id, manifest_sha256=manifest.sha256,
                cgroup_device=cgroup_device, cgroup_inode=cgroup_inode,
                stdout_device=self.streams["stdout"]["device"], stdout_inode=self.streams["stdout"]["inode"],
                stderr_device=self.streams["stderr"]["device"], stderr_inode=self.streams["stderr"]["inode"],
                stdout_limit=limits["stdout_limit"], stderr_limit=limits["stderr_limit"], total_limit=limits["total_limit"])
        except BaseException:
            self.close()
            raise

    def _owned(self):
        require(os.geteuid() == 0 and os.getpid() == self.owner_pid, "supervision-original-owner")

    @property
    def problem(self):
        return any(value["state"] != "complete" for value in self.streams.values())

    def append(self, name, raw):
        self._owned()
        row = self.streams[name]
        remaining = min(row["limit"] - row["bytes"], self.details["capture"]["total_limit"]
                        - sum(value["bytes"] for value in self.streams.values()))
        allowed = min(len(raw), max(0, remaining)) if row["state"] != "incomplete" else 0
        try:
            offset = 0
            while offset < allowed:
                written = os.write(row["fd"], raw[offset:allowed])
                require(written > 0, "supervision-log-write")
                row["hash"].update(raw[offset:offset + written])
                row["bytes"] += written
                offset += written
        except Exception:
            row["state"] = "incomplete"
        if allowed < len(raw) and row["state"] == "complete":
            row["state"] = "limited"

    def seal(self):
        self._owned()
        parent = engine._directory(self.directory, private=True)
        try:
            require((os.fstat(parent).st_dev, os.fstat(parent).st_ino) == self.parent_identity,
                    "supervision-log-directory-replaced")
            for name, row in self.streams.items():
                try:
                    os.fsync(row["fd"])
                    info = os.fstat(row["fd"])
                    named = os.stat(name + ".log", dir_fd=parent, follow_symlinks=False)
                    require(stat.S_ISREG(named.st_mode) and named.st_uid == 0 and named.st_nlink == 1
                            and stat.S_IMODE(named.st_mode) == 0o600 and info.st_size == row["bytes"]
                            and (info.st_dev, info.st_ino) == (named.st_dev, named.st_ino)
                            == (row["device"], row["inode"]), "supervision-log-replaced")
                    actual = hashlib.sha256()
                    offset = 0
                    while offset < row["bytes"]:
                        raw = os.pread(row["fd"], min(CHUNK, row["bytes"] - offset), offset)
                        require(bool(raw), "supervision-log-readback")
                        actual.update(raw)
                        offset += len(raw)
                    if actual.digest() != row["hash"].digest():
                        row["state"] = "incomplete"
                        row["hash"] = actual
                except Exception:
                    row["state"] = "incomplete"
                    self.receipt_safe = False
                if not row["eof"]:
                    row["state"] = "incomplete"
            os.fsync(parent)
        finally:
            os.close(parent)

    def close(self):
        for row in self.streams.values():
            if row["fd"] is not None:
                os.close(row["fd"])
                row["fd"] = None
        if self.parent is not None:
            os.close(self.parent)
            self.parent = None


def _serialized(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return call


class OwnedRun:
    """Live original Popen/pidfd owner; never reconstructed from PID or wire."""
    def __init__(self, proc, pidfd, capture, store, lease_id, effect_id):
        require(os.geteuid() == 0 and type(proc) is subprocess.Popen and type(capture) is Capture,
                "supervision-root-process")
        self._lock = threading.RLock()
        self.proc, self.pidfd, self.capture = proc, pidfd, capture
        self.owner_pid, self.store = os.getpid(), store
        self.lease_id, self.effect_id = lease_id, effect_id
        self.process, self.container_id = None, None
        self.returncode, self.observed_at = None, None
        self.exit_receipt = None
        self.selector = selectors.DefaultSelector()
        self.closed = False
        self.stop_attempted = False
        self.withdrawal_hold = False
        self.cgroup_state = "unknown"
        for name in ("stdout", "stderr"):
            stream = getattr(proc, name)
            require(stream is not None, "supervision-private-pipe")
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, name)

    def _owned(self):
        require(os.geteuid() == 0 and os.getpid() == self.owner_pid, "supervision-original-owner")

    def tracked(self, process, container_id):
        self._owned()
        require(self.process is None and self.container_id is None, "supervision-retrack")
        self.process, self.container_id = dict(process), container_id

    @_serialized
    def pump(self, seconds=0.05):
        self._owned()
        require(not self.closed, "supervision-owner-closed")
        if self.selector.get_map():
            for key, _ in self.selector.select(seconds):
                try:
                    raw = os.read(key.fileobj.fileno(), CHUNK)
                except BlockingIOError:
                    continue
                except OSError:
                    self.capture.streams[key.data]["state"] = "incomplete"
                    raw = b""
                if raw:
                    self.capture.append(key.data, raw)
                else:
                    self.capture.streams[key.data]["eof"] = True
                    self.selector.unregister(key.fileobj)
                    key.fileobj.close()
        elif seconds:
            time.sleep(min(seconds, 0.05))
        if self.returncode is None:
            value = self.proc.poll()  # THIS owner alone polls/waits its child.
            if value is not None:
                self.returncode, self.observed_at = value, int(time.time())
        return self.returncode

    @property
    def eof(self):
        return all(row["eof"] for row in self.capture.streams.values())

    @_serialized
    def record_exit(self):
        self._owned()
        require(self.returncode is not None and self.process is not None and self.container_id is not None,
                "supervision-untracked-exit-unknown")
        if self.exit_receipt is not None:
            return self.exit_receipt
        try:
            self.capture.seal()
        except Exception:
            self.capture.receipt_safe = False
            for row in self.capture.streams.values():
                row["state"] = "incomplete"
        require(self.capture.receipt_safe, "supervision-capture-readback-held")
        code = self.returncode if self.returncode >= 0 else None
        signum = -self.returncode if self.returncode < 0 else None
        values = {key: self.process[key] for key in ("pid", "start_ticks", "boot_id")}
        values.update(container_id=self.container_id, manifest_sha256=self.capture.manifest.sha256,
                      exit_code=code, signal=signum, observed_at=self.observed_at)
        for name, row in self.capture.streams.items():
            values[name + "_bytes"] = row["bytes"]
            values[name + "_sha256"] = row["hash"].hexdigest()
            values[name + "_state"] = row["state"]
        self.store.record_engine_exit(self.lease_id, self.effect_id, **values)
        self.exit_receipt = ExitObservation(self.lease_id, self.effect_id, code, signum,
            values["stdout_state"], values["stderr_state"], ledger.digest(values))
        return self.exit_receipt

    @_serialized
    def release(self):
        """Close only after actual durable exit; never lose a running child."""
        self._owned()
        require(self.exit_receipt is not None and self.returncode is not None, "supervision-exit-not-durable")
        if not self.closed:
            for name in ("stdout", "stderr"):
                stream = getattr(self.proc, name)
                if stream is not None:
                    stream.close()
            self.selector.close()
            self.capture.close()
            if self.pidfd is not None:
                os.close(self.pidfd)
            self.closed = True
