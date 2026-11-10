"""Root fixed-engine supervisor; no socket activation or job-controlled argv.

Native Podman is absent on the selected executor. Public start FAILS CLOSED
unless actual namespace/fence/runtime acquisition AND the real private idmapped
filesystem access probe succeed. No version/receipt/boolean substitutes for it.
The actual Popen/ownership/status/cancel code is independently testable with a
synthetic fixed Root executable; such tests are NOT Podman/runtime qualification.
Network hard-expiry acquisition is another mandatory independent native gate.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import ctypes
import fcntl
import grp
import hashlib
import os
from pathlib import PurePosixPath
import pwd
import re
import secrets
import selectors
import select
import signal
import stat
import subprocess
import threading
import time

from . import (cell_contract, engine_policy as engine, identity, installation, kernel, ledger, worker,
               policy_registry, preparation, signed_context, engine_supervision)
from .identity import Denied, require

NSFS_MAGIC = 0x6e736673
CGROUP2_MAGIC = 0x63677270
NS_GET_NSTYPE = 0xb703
CLONE_NEWNET = 0x40000000
IMAGE_CONFIG = "5b4ca16538abccb297f565dda30c511203fade0e30ff14adb439c6d2b06550fd"
CID = re.compile(r"[0-9a-f]{64}\Z")
# Keep local Popen ownership while running; durable authority remains the
# Ledger/kernel tuple, never this cache. A restart must reacquire observations.
_PROCESSES = {}
# Allocation failure after Popen must not lose the original unreaped child.
# These handles are UNKNOWN, never eligible for a fabricated exit receipt.
_UNTRACKED_PROCESSES = {}


class EngineUnknown(Denied):
    """Possible engine effect retained; no automatic retry or foreign cleanup."""


@dataclass(frozen=True)
class EngineStatus:
    lease_id: str
    state: str
    container_id: str | None
    # Observations are never test/VM success or release evidence.


def _fs_type(fd):
    buffer = ctypes.create_string_buffer(256)
    require(ctypes.CDLL(None, use_errno=True).fstatfs(fd, buffer) == 0, "engine-filesystem-stat")
    return ctypes.c_long.from_buffer(buffer).value


@contextmanager
def _namespace(path):
    engine._path(path)
    require(re.fullmatch(r"/run/netns/lit-lease-[0-9a-f]{32}", path), "engine-namespace-path")
    parent = installation._open_directory("/run/netns")
    fd = None
    try:
        fd = os.open(PurePosixPath(path).name, installation.FILE_FLAGS, dir_fd=parent)
        first = os.fstat(fd)
        require(first.st_uid == 0 and not first.st_mode & 0o022 and _fs_type(fd) == NSFS_MAGIC
                and fcntl.ioctl(fd, NS_GET_NSTYPE) == CLONE_NEWNET, "engine-real-network-namespace")
        named = os.stat(PurePosixPath(path).name, dir_fd=parent, follow_symlinks=False)
        require((first.st_dev, first.st_ino) == (named.st_dev, named.st_ino), "engine-namespace-drift")
        yield fd
        named = os.stat(PurePosixPath(path).name, dir_fd=parent, follow_symlinks=False)
        require((first.st_dev, first.st_ino) == (named.st_dev, named.st_ino), "engine-namespace-drift")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _cgroup(details):
    name = "lit-lease-" + details["runtime"]["name"].removeprefix("lit-lease-") + ".slice"
    parent = installation._open_directory("/sys/fs/cgroup")
    fd = None
    try:
        require(_fs_type(parent) == CGROUP2_MAGIC, "engine-cgroup-v2-required")
        # systemd slice hyphens define the actual parent hierarchy; this is
        # not a flat directory named like the unit. No unit is created here.
        fd = installation._open_directory("/sys/fs/cgroup/lit.slice/lit-lease.slice/" + name)
        info = os.fstat(fd)
        require(info.st_uid == 0 and not info.st_mode & 0o022, "engine-cgroup-owner")
        require(kernel.bounded_file(fd, "cgroup.type", 128).strip() == b"domain"
                and not kernel.bounded_file(fd, "cgroup.procs", 65536).strip(), "engine-cgroup-not-private")
        with os.scandir(fd) as entries:
            require(not any(entry.is_dir(follow_symlinks=False) for entry in entries), "engine-cgroup-reused")
        return info.st_dev, info.st_ino
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _reservations(details):
    for path, mapping, accounts in (("/etc/subuid", details["uid_map"], [p.pw_uid for p in pwd.getpwall()]),
                                     ("/etc/subgid", details["gid_map"], [g.gr_gid for g in grp.getgrall()])):
        _, raw, _ = installation._file(path, 1048576, keep=True)
        base, size = mapping["host_base"], mapping["size"]
        rows = []
        for line in raw.decode("ascii").splitlines():
            if not line or line.startswith("#"):
                continue
            match = re.fullmatch(r"([A-Za-z0-9_.-]+):([0-9]+):([1-9][0-9]*)", line)
            require(match is not None, "engine-subid-schema")
            rows.append((match[1], int(match[2]), int(match[3])))
        require(rows.count(("root", base, size)) == 1 and not any(base <= identifier < base + size for identifier in accounts),
                "engine-root-range-not-reserved")
        require(not any(max(base, start) < min(base + size, start + length)
                        for owner, start, length in rows if (owner, start, length) != ("root", base, size)), "engine-subid-overlap")


def _prefix(manifest):
    details = identity.decode_json(manifest.canonical_bytes)
    return [engine.ENGINE, "--root", details["engine"]["storage_root"], "--runroot", details["engine"]["runroot"], "--cgroup-manager=systemd", "--events-backend=none", "--tmpdir=" + details["engine"]["runroot"]]


def _environment(manifest):
    details = identity.decode_json(manifest.canonical_bytes)
    # No caller/process environment, proxies, remote engines or credentials.
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
            "HOME": details["engine"]["runroot"], "XDG_RUNTIME_DIR": details["engine"]["runroot"], "TMPDIR": details["engine"]["runroot"]}


def _command(manifest, arguments, seconds=5):
    """Only internal fixed commands; bounded output and a separately owned CLI."""
    require(os.geteuid() == 0, "engine-executor-root-required")
    proc = subprocess.Popen(_prefix(manifest) + arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=_environment(manifest), close_fds=True, umask=0o077)
    result = bytearray()
    try:
        deadline = time.monotonic() + seconds
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "engine-cli-timeout")
                require(selector.select(remaining), "engine-cli-timeout")
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    break
                result.extend(chunk)
                require(len(result) <= 2 * 1024 ** 2, "engine-cli-output-limit")
        return proc.wait(timeout=max(0.001, deadline - time.monotonic())), bytes(result)
    finally:
        if proc.poll() is None:
            # Popen still owns this unreaped child; never address a foreign PID.
            proc.kill()
            proc.wait(timeout=2)
        proc.stdout.close()


def _pull_group_members(pid, deadline):
    """The unreaped new-session leader pins its process-group identity."""
    members = []
    for entry in os.listdir("/proc"):
        require(time.monotonic() < deadline, "engine-image-pull-timeout")
        if not entry.isdecimal():
            continue
        try:
            with open("/proc/" + entry + "/stat", "rb") as stream:
                fields = stream.read(8192).rsplit(b") ", 1)[1].split()
            if int(fields[2]) == pid and int(entry) != pid and fields[0] != b"Z":
                members.append(int(entry))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return members


def _pull_image(manifest, seconds):
    """One fixed public image pull; no caller transport, authfile or retry."""
    from . import runtime_entry
    require(os.geteuid() == 0 and 0 < seconds <= 120, "engine-image-pull-budget")
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "engine-image-child-owner-required")
    proc = None
    deadline = time.monotonic() + seconds
    try:
        # Do not poll/wait (reap) this leader before its entire new group is
        # checked/signalled: the original unreaped child pins the PGID.
        with runtime_entry._spawn_adoption():
            # Podman 4.9 has no --retry pull option. This is one owned CLI
            # invocation; any registry transport retries stay inside its
            # original process deadline and never replay the journal intent.
            proc = subprocess.Popen(_prefix(manifest) + ["pull", "--tls-verify=true",
                "--platform=linux/amd64", engine.PODMAN_IMAGE], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, env=_environment(manifest), close_fds=True,
                start_new_session=True, umask=0o077)
        total = 0
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0 and selector.select(remaining), "engine-image-pull-timeout")
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    break
                total += len(chunk)
                require(total <= 2 * 1024 ** 2, "engine-image-pull-output-limit")
        while True:
            require(time.monotonic() < deadline, "engine-image-pull-timeout")
            observed = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if observed is not None:
                break
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        require(observed.si_code == os.CLD_EXITED and observed.si_status == 0,
                "engine-image-pull-failed")
        require(not _pull_group_members(proc.pid, deadline), "engine-image-pull-live-helper")
    finally:
        if proc is not None:
            # This Popen child is still ours and unreaped, including when the
            # initial-transition timer fired immediately after spawn adoption.
            # Unknown/partial writes remain owned and are never deleted here.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=2)
            if proc.stdout is not None:
                proc.stdout.close()


def _provision_image(config, prepared, store, manifest):
    """Root preparation only, inside the fresh engine-prepare journal intent."""
    from . import storage_quota
    preparation._fresh(config, prepared, store)
    details = identity.decode_json(manifest.canonical_bytes)
    store.require_exclusive_preparation(prepared.lease_id)
    record = store.read(prepared.lease_id)
    effects = [row for row in record["effects"].values() if row["operation"] == "engine-prepare"]
    require(len(effects) == 1 and effects[0]["state"] == "intent"
            and effects[0]["target"] == "engine:" + prepared.lease_id, "engine-image-fresh-intent")
    _start_budget(prepared, manifest)
    now = time.time()
    runtime = details["limits"]["timeout_seconds"]
    end = min(now + 120, prepared.expires_at - runtime)
    if record.get("authorizations"):
        end = min(end, record["authorizations"][-1]["valid_until"])
    require(end > now, "engine-image-pull-budget")
    # All transfer/extraction temporaries, image layers and engine state are
    # on the original private bounded filesystem, never the global cache.
    with storage_quota.acquire_existing_quota(config.storage_quota_policy_path,
            config.storage_quota_policy_sha256, manifest):
        seconds = min(120, end - time.time())
        from . import runtime_entry
        if runtime_entry._ACTIVE is not None:
            remaining = signal.getitimer(signal.ITIMER_REAL)[0]
            require(remaining > 0, "engine-image-initial-budget")
            seconds = min(seconds, remaining)
        phase_end = time.monotonic() + seconds
        _pull_image(manifest, seconds)
        preparation._fresh(config, prepared, store)
        _backend(manifest, deadline=phase_end)  # Preserve exact image checks.
        _start_budget(prepared, manifest)
        require(time.time() < end and time.monotonic() < phase_end,
                "engine-image-provision-budget-expired")


def _backend(manifest, *, deadline=None):
    def command(arguments):
        seconds = 5 if deadline is None else min(5, deadline - time.monotonic())
        require(seconds > 0, "engine-image-provision-budget-expired")
        return _command(manifest, arguments, seconds=seconds)
    rc, raw = command(["info", "--format=json"])
    require(rc == 0, "engine-info-failed")
    value = identity.decode_json(raw)
    host, store = value["host"], value["store"]
    details = identity.decode_json(manifest.canonical_bytes)
    require(host["security"]["rootless"] is False and host["serviceIsRemote"] is False
            and host["arch"] == "amd64" and host["os"] == "linux" and host["cgroupVersion"] == "v2"
            and host["cgroupManager"] == "systemd" and store["graphRoot"] == details["engine"]["storage_root"]
            and store["runRoot"] == details["engine"]["runroot"], "engine-local-runtime-required")
    for key in ("ociRuntime", "conmon"):
        installation.trusted_file(engine._path(host[key]["path"]), max_bytes=128 * 1024 ** 2)
    rc, raw = command(["image", "inspect", "--format=json", engine.PODMAN_IMAGE])
    images = __import__("json").loads(raw)
    require(rc == 0 and type(images) is list and len(images) == 1, "engine-image-inspect")
    image = images[0]
    # Index-pulled Podman images may report the index in Digest. Pin the
    # authentic graph and exact amd64 config; do not call that a raw child GET.
    require(image["Digest"] in {"sha256:" + engine.IMAGE_INDEX, "sha256:" + engine.IMAGE_CHILD}
            and image["Id"].removeprefix("sha256:") == IMAGE_CONFIG
            and image["Architecture"] == "amd64" and image["Os"] == "linux", "engine-exact-image-required")
    rc, _ = command(["container", "exists", details["runtime"]["name"]])
    require(rc == 1, "engine-runtime-name-not-absent")


def _libc():
    library = ctypes.CDLL(None, use_errno=True)
    library.syscall.restype = ctypes.c_long
    library.unshare.argtypes = [ctypes.c_int]
    library.setns.argtypes = [ctypes.c_int, ctypes.c_int]
    library.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
    return library


def _child_done(pid, pidfd, seconds=5):
    require(select.select([pidfd], [], [], seconds)[0], "engine-probe-child-timeout")
    waited, status = os.waitpid(pid, 0)
    require(waited == pid and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, "engine-probe-child-denied")


def _kill_child(pid, pidfd):
    if pidfd is None:
        # An unreaped direct child cannot have its PID reused. Never signal a
        # PID after waitpid says it is no longer this process's child.
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG)
            if waited == 0:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
        except (ChildProcessError, ProcessLookupError):
            pass
        return
    if pidfd is not None:
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        os.close(pidfd)


def _user_namespace(uid_base, uid_size, gid_base, gid_size):
    """Own helper creates a user namespace; privileged parent writes exact maps."""
    ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
    control_r, control_w = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready_r)
            os.close(control_w)
            os.setgroups([])
            require(_libc().unshare(0x10000000) == 0, "engine-probe-userns-unavailable")
            os.write(ready_w, b"R")
            require(os.read(control_r, 1) == b"X", "engine-probe-map-handshake")
            os._exit(0)
        except BaseException:
            os._exit(2)
    os.close(ready_w)
    os.close(control_r)
    pidfd = namespace = None
    try:
        pidfd = os.pidfd_open(pid, 0)
        require(select.select([ready_r], [], [], 5)[0] and os.read(ready_r, 1) == b"R", "engine-probe-userns-unavailable")
        for name, raw in (("setgroups", b"deny"), ("uid_map", f"0 {uid_base} {uid_size}\n".encode()),
                          ("gid_map", f"0 {gid_base} {gid_size}\n".encode())):
            fd = os.open(f"/proc/{pid}/{name}", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                require(os.write(fd, raw) == len(raw), "engine-probe-map-write")
            finally:
                os.close(fd)
        namespace = os.open(f"/proc/{pid}/ns/user", os.O_RDONLY | os.O_CLOEXEC)
        require(fcntl.ioctl(namespace, NS_GET_NSTYPE) == 0x10000000, "engine-probe-userns-type")
        os.write(control_w, b"X")
        _child_done(pid, pidfd)
        os.close(pidfd)
        pidfd = None
        result, namespace = namespace, None
        return result
    finally:
        for fd in (ready_r, control_w, namespace):
            if fd is not None:
                os.close(fd)
        _kill_child(pid, pidfd)


class _MountAttr(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in ("attr_set", "attr_clr", "propagation", "userns_fd")]


def _mapped_mount(path, userns, readonly):
    library = _libc()
    # open_tree and mount_setattr are Linux asm-generic syscalls on the two
    # supported architectures. Detached clones never enter the host mount tree.
    require(os.uname().machine in {"x86_64", "aarch64"}, "engine-probe-architecture")
    fd = library.syscall(428, ctypes.c_int(-100), ctypes.c_char_p(path.encode()), ctypes.c_uint(1 | os.O_CLOEXEC))
    require(fd >= 0, "engine-open-tree-unavailable")
    try:
        attrs = _MountAttr(0x100000 | 2 | 4 | 8 | (1 if readonly else 0), 0, 0, userns)
        require(library.syscall(442, ctypes.c_int(fd), ctypes.c_char_p(b""), ctypes.c_uint(0x1000),
                                ctypes.byref(attrs), ctypes.sizeof(attrs)) == 0, "engine-live-idmap-unsupported")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _drop_reader_capabilities():
    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [(key, ctypes.c_uint32) for key in ("effective", "permitted", "inheritable")]
    library = _libc()
    require(library.prctl(38, 1, 0, 0, 0) == 0 and library.prctl(47, 4, 0, 0, 0) == 0,
            "engine-probe-nnp")
    require(library.capset(ctypes.byref(Header(0x20080522, 0)), ctypes.byref((Data * 2)())) == 0,
            "engine-probe-capabilities")
    with open("/proc/self/status", "rb") as stream:
        require(b"CapEff:\t0000000000000000" in stream.read(65536), "engine-probe-capabilities")


def _mapped_reader(mounts, readerns, details, sentinel, token, parent_pid):
    require(_libc().prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == parent_pid,
            "engine-probe-parent-drift")
    os.setgroups([])
    require(_libc().setns(readerns, 0x10000000) == 0, "engine-probe-reader-userns")
    os.setresgid(details["cell_gid"], details["cell_gid"], details["cell_gid"])
    os.setresuid(details["cell_uid"], details["cell_uid"], details["cell_uid"])
    # setresuid clears PDEATHSIG; restore it before any mapped filesystem IO.
    require(_libc().prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == parent_pid,
            "engine-probe-parent-drift")
    _drop_reader_capabilities()
    require(os.getuid() == details["cell_uid"] and os.getgid() == details["cell_gid"] and not os.getgroups(),
            "engine-probe-reader-identity")
    for fd, files, readonly in mounts:
        root = os.fstat(fd)
        require(root.st_uid == details["cell_uid"] and root.st_gid == details["cell_gid"], "engine-probe-mapped-owner")
        require(bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY) == readonly, "engine-probe-mount-mode")
        for name, expected in files.items():
            opened = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
            try:
                info = os.fstat(opened)
                require(info.st_uid == details["cell_uid"] and info.st_gid == details["cell_gid"], "engine-probe-file-owner")
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(opened, 65536)
                    if not chunk:
                        break
                    digest.update(chunk)
                require(digest.hexdigest() == expected, "engine-probe-mapped-read")
            finally:
                os.close(opened)
        if readonly and "client.key" in files:
            try:
                opened = os.open("client.key", os.O_WRONLY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as error:
                require(error.errno == 30, "engine-probe-readonly-denial")
            else:
                os.close(opened)
                raise Denied("engine-probe-readonly-bypassed")
        if not readonly:
            opened = os.open(sentinel, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=fd)
            try:
                os.fchmod(opened, 0o600)
                info = os.fstat(opened)
                require(info.st_uid == details["cell_uid"] and info.st_gid == details["cell_gid"]
                        and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, "engine-probe-created-owner")
                require(os.write(opened, token) == len(token), "engine-probe-output-write")
                os.fsync(opened)
            finally:
                os.close(opened)
            opened = os.open(sentinel, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                require(os.read(opened, len(token) + 1) == token, "engine-probe-output-read")
            finally:
                os.close(opened)


def _idmapped_preflight(prepared, manifest):
    """Actual detached idmapped mounts + unprivileged mapped FS access.

    Runs only inside an engine-start intent. No mount propagates outside the
    private helper namespace. A deterministic exclusive output sentinel is the
    only filesystem write; exact owner/token/inode cleanup is verified. Failure
    or unavailable capabilities/syscalls leaves the enclosing intent UNKNOWN.
    This proves these mounts/access, not OCI/runtime/image/operating acceptance.
    """
    require(os.geteuid() == 0 and type(prepared) is cell_contract.PreparedCell
            and type(manifest) is engine.EngineManifest, "engine-probe-root-input")
    require(hashlib.sha256(manifest.canonical_bytes).hexdigest() == manifest.sha256
            and manifest.descriptor_sha256 == prepared.engine_descriptor_sha256, "engine-probe-manifest")
    require(threading.active_count() == 1, "engine-probe-single-thread-required")
    details = identity.decode_json(manifest.canonical_bytes)
    uidmap, gidmap = details["uid_map"], details["gid_map"]
    host_uid, host_gid = uidmap["host_base"] + details["cell_uid"], gidmap["host_base"] + details["cell_gid"]
    sentinel = ".lit-idmap-probe-" + prepared.lease_id
    token = secrets.token_bytes(32)
    output = installation._open_directory(details["output"]["path"])
    mountns = readerns = pidfd = None
    child = None
    succeeded = False
    try:
        try:
            os.stat(sentinel, dir_fd=output, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Denied("engine-probe-existing-output")
        mountns = _user_namespace(host_uid, 1, host_gid, 1)
        readerns = _user_namespace(uidmap["host_base"], uidmap["size"], gidmap["host_base"], gidmap["size"])
        parent_pid = os.getpid()
        child = os.fork()
        if child == 0:
            mounts = []
            try:
                library = _libc()
                require(library.prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == parent_pid,
                        "engine-probe-parent-drift")
                require(library.unshare(0x00020000) == 0
                        and library.mount(None, b"/", None, (1 << 14) | (1 << 18), None) == 0,
                        "engine-probe-private-mountns")
                for tree in details["trees"].values():
                    first = sorted(tree["files"])[0]
                    mounts.append((_mapped_mount(tree["path"], mountns, True), {first: tree["files"][first]}, True))
                mounts.append((_mapped_mount(details["context"]["path"], mountns, True), details["context"]["files"], True))
                mounts.append((_mapped_mount(details["output"]["path"], mountns, False), {}, False))
                reader_parent = os.getpid()
                reader = os.fork()
                if reader == 0:
                    try:
                        _mapped_reader(mounts, readerns, details, sentinel, token, reader_parent)
                        os._exit(0)
                    except BaseException:
                        os._exit(2)
                reader_pidfd = None
                try:
                    reader_pidfd = os.pidfd_open(reader, 0)
                    _child_done(reader, reader_pidfd)
                finally:
                    _kill_child(reader, reader_pidfd)
                os._exit(0)
            except BaseException:
                os._exit(2)
        pidfd = os.pidfd_open(child, 0)
        _child_done(child, pidfd, 10)
        before = os.stat(sentinel, dir_fd=output, follow_symlinks=False)
        # mapped_fsuid() reverses the mount mapping when writing ownership:
        # reader C -> host H -> mount upper0 -> backing filesystem0. The same
        # file reports C/G through the mapped view and Root0:0 through backing.
        # https://www.kernel.org/doc/html/latest/filesystems/idmappings.html
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == 0
                and before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o600, "engine-probe-output-owner")
        fd = os.open(sentinel, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=output)
        try:
            require(os.read(fd, 33) == token and os.fstat(fd).st_ino == before.st_ino, "engine-probe-output-proof")
        finally:
            os.close(fd)
        os.unlink(sentinel, dir_fd=output)
        os.fsync(output)
        require(not os.path.lexists(details["output"]["path"] + "/" + sentinel), "engine-probe-output-cleanup")
        for name, expected in details["context"]["files"].items():
            require(installation.trusted_file(details["context"]["path"] + "/" + name).sha256 == expected,
                    "engine-probe-source-drift")
        succeeded = True
    finally:
        if child is not None:
            _kill_child(child, pidfd)
        for fd in (readerns, mountns, output):
            if fd is not None:
                os.close(fd)
        # An incomplete probe never removes an unverified sentinel or permits
        # start. Its exact deterministic locator remains for Root reconciliation.
    require(succeeded, "engine-probe-not-complete")


@contextmanager
def _preflight(config, prepared, store, manifest):
    details = identity.decode_json(manifest.canonical_bytes)
    # This operating scope admits ONE cell, not a fleet sharing mapped IDs.
    # Root subid/NSS reservations below additionally deny non-pilot allocation.
    store.require_exclusive_preparation(prepared.lease_id)
    _reservations(details)
    _cgroup(details)
    with _namespace(details["network_namespace"]["path"]):
        try:
            from . import network_fence, storage_quota
        except ImportError:
            raise Denied("engine-native-network-fence-unavailable") from None
        worker = ledger.Worker(**store.read(prepared.lease_id)["worker"])
        with network_fence.acquire_existing_fence(prepared, store, worker, config):
            with storage_quota.acquire_existing_quota(config.storage_quota_policy_path,
                    config.storage_quota_policy_sha256, manifest):
                _backend(manifest)
                yield


def _bound(config, registry, selector, store, lease_id, receipt):
    require(type(receipt) is preparation.PreparationReceipt and receipt.lease_id == lease_id,
            "engine-preparation-receipt")
    require(registry.path == config.registry_path and registry.sha256 == config.registry_sha256,
            "engine-registry")
    prepared = cell_contract.prepare_cell(registry, selector, store, lease_id)
    require(receipt.cell_sha256 == prepared.cell_sha256 and receipt.expires_at == prepared.expires_at,
            "engine-preparation-drift")
    manifest = engine.compile_engine_policy(prepared.engine_descriptor_path, prepared.engine_descriptor_sha256)
    cell_contract.bind_engine(prepared, store, manifest)
    require(manifest.sha256 == receipt.engine_policy_sha256, "engine-policy-drift")
    _authenticate(config, registry, selector, store, lease_id, receipt, prepared)
    return prepared, manifest


def _authenticate(config, registry, selector, store, lease_id, receipt, prepared=None):
    """Authenticate prior signed ownership even for expiry cleanup; no renewal."""
    require(type(registry) is policy_registry.Registry
            and policy_registry.load_registry(registry.path, registry.sha256) == registry
            and registry.path == config.registry_path and registry.sha256 == config.registry_sha256, "engine-registry")
    selected = registry.select(selector)
    cell_contract._store(selected, store)
    record = store.read(lease_id)
    require(type(receipt) is preparation.PreparationReceipt and receipt.lease_id == lease_id
            and receipt.cell_sha256 == record["cell_sha256"] == selected.cell_sha256
            and receipt.expires_at == record["expires_at"], "engine-lease-binding")
    cell, _, _ = cell_contract._sealed(selected.cell_config_path, selected.cell_sha256)
    context_path = cell["engine"]["paths"]["context"] + "/" + lease_id
    raw, _ = signed_context._sealed(context_path + "/binding.json", 32768)
    binding = identity.decode_json(raw)
    token = binding["admission"]
    pieces = token.split(".")
    require(len(pieces) == 3 and identity.decode_json(identity.unbase(pieces[0])) == signed_context._header(config.signing_public_key),
            "engine-signed-header")
    signed_context._public(config.signing_public_key).verify(identity.unbase(pieces[2]), (pieces[0] + "." + pieces[1]).encode("ascii"))
    payload = identity.decode_json(identity.unbase(pieces[1]))
    expected_policy = asdict(selected.identity)
    expected_policy["actor_ids"] = sorted(selected.identity.actor_ids)
    require(identity.unbase(pieces[1]) == ledger.canonical(payload) and payload["lease_id"] == lease_id
            and payload["purpose"] == signed_context.PURPOSE and payload["cell_sha256"] == selected.cell_sha256
            and payload["identity"] == record["identity"] and payload["worker"] == record["worker"]
            and payload["policy"] == expected_policy
            and record["identity"]["policy_sha256"] == identity.policy_digest(selected.identity)
            and payload["created_at"] == record["created_at"] and payload["expires_at"] == record["expires_at"]
            and payload["custody_policy_sha256"] == record["policy_sha256"] == selected.custody_policy_sha256
            and payload["engine_policy_sha256"] == receipt.engine_policy_sha256
            and payload["binding_sha256"] == ledger.digest(signed_context._projection(binding))
            and payload["files_sha256"] == signed_context._files(context_path, binding, token), "engine-signed-ownership")
    if prepared is not None:
        require(binding["runtime"] == signed_context.runtime_for_cell(prepared), "engine-runtime-facts")
        selected_policy = signed_context.ContextPolicy(selected.identity, prepared.incus["server"], prepared.incus["project"],
            prepared.expires_at, prepared.cell_sha256, selected.custody_policy_sha256,
            cell["controller"]["archive_sha256"], engine.IMAGE_INDEX, receipt.engine_policy_sha256,
            expected_runtime=ledger.canonical(binding["runtime"]))
        signed_context.verify(token, config.signing_public_key, store, lease_id, ledger.Worker(**record["worker"]),
                              selected_policy, binding, context_path)
    return cell, record


def _process(pid, manifest):
    """Engine-specific exact argv observer; never broaden the Runner parser."""
    require(worker.positive(pid) and type(manifest) is engine.EngineManifest, "engine-process-input")
    expected_argv = manifest.argv
    require(type(expected_argv) is tuple and 0 < len(expected_argv) <= engine.MAX_ENGINE_ARGS
            and all(type(arg) is str and 0 < len(arg) <= 8192 for arg in expected_argv)
            and sum(len(arg.encode("utf-8")) + 1 for arg in expected_argv) <= engine.MAX_ENGINE_ARG_BYTES,
            "engine-argv-limit")
    proc = process = image = named = None
    try:
        proc = os.open("/proc", kernel.FLAGS | os.O_DIRECTORY)
        process = os.open(str(pid), kernel.FLAGS | os.O_DIRECTORY, dir_fd=proc)
        first = worker.parse_proc_stat(kernel.bounded_file(process, "stat", worker.MAX_STAT_BYTES))
        require(first.pid == pid, "engine-process-pid")
        uids = kernel.parse_status_uids(kernel.bounded_file(process, "status", kernel.STATUS_LIMIT))
        kernel.parse_cgroup(kernel.bounded_file(process, "cgroup", kernel.CGROUP_LIMIT))
        raw = kernel.bounded_file(process, "cmdline", engine.MAX_ENGINE_ARG_BYTES)
        require(raw and raw.endswith(b"\0"), "engine-process-cmdline")
        argv = tuple(part.decode("utf-8") for part in raw[:-1].split(b"\0"))
        require(argv == expected_argv, "engine-process-exact-argv")
        executable = os.readlink("exe", dir_fd=process)
        require(uids == (0, 0, 0, 0) and executable == engine.ENGINE
                and os.path.realpath(executable) == executable, "engine-supervisor-executable")
        # Intentional kernel exe symlink exception; both FD and named sealed
        # binary must identify the same inode and expected executable hash.
        image = os.open("exe", os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=process)
        named = os.open(executable, kernel.FLAGS)
        image_info, named_info = os.fstat(image), os.fstat(named)
        require(stat.S_ISREG(image_info.st_mode) and stat.S_ISREG(named_info.st_mode)
                and (image_info.st_dev, image_info.st_ino) == (named_info.st_dev, named_info.st_ino),
                "engine-executable-image-changed")
        proof = installation.trusted_file(engine.ENGINE, max_bytes=128 * 1024 ** 2)
        expected_hash = identity.decode_json(manifest.canonical_bytes)["engine_executable_sha256"]
        require(proof.sha256 == expected_hash and (proof.device, proof.inode) == (image_info.st_dev, image_info.st_ino),
                "engine-supervisor-drift")
        second = worker.parse_proc_stat(kernel.bounded_file(process, "stat", worker.MAX_STAT_BYTES))
        require((first.pid, first.ppid, first.start_ticks, first.comm)
                == (second.pid, second.ppid, second.start_ticks, second.comm), "engine-process-observation-changed")
        require(kernel.bounded_file(process, "cmdline", engine.MAX_ENGINE_ARG_BYTES) == raw,
                "engine-process-observation-changed")
        return {"pid": pid, "start_ticks": second.start_ticks, "boot_id": kernel.read_boot_id(),
                "exe_device": proof.device, "exe_inode": proof.inode, "exe_sha256": proof.sha256}
    except Denied:
        raise
    except (OSError, UnicodeError, ValueError):
        raise Denied("engine-process-read-failed") from None
    finally:
        for fd in (named, image, process, proc):
            if fd is not None:
                os.close(fd)


def _stable_process(pid, manifest, pidfd):
    """Only reacquire reads for the original live Popen; never retry effects."""
    deadline = time.monotonic() + 1
    while True:
        require(time.monotonic() < deadline, "engine-supervisor-not-stable")
        require(not select.select([pidfd], [], [], 0)[0], "engine-supervisor-exited")
        try:
            observed = _process(pid, manifest)
            require(time.monotonic() < deadline, "engine-supervisor-not-stable")
            return observed
        except Denied as error:
            require(str(error) == "engine-process-observation-changed" and time.monotonic() < deadline,
                    "engine-supervisor-not-stable")
            time.sleep(0.005)


def _cid(path):
    if not os.path.lexists(path):
        return None
    _, raw, _ = installation._file(path, 128, private=True, keep=True)
    value = raw.decode("ascii").removesuffix("\n")
    require(CID.fullmatch(value) and raw in (value.encode(), value.encode() + b"\n"), "engine-cidfile")
    return value


def _inspect(manifest, cid):
    require(type(cid) is str and CID.fullmatch(cid), "engine-container-id")
    rc, raw = _command(manifest, ["container", "inspect", "--format=json", cid])
    rows = __import__("json").loads(raw)
    require(rc == 0 and type(rows) is list and len(rows) == 1, "engine-container-inspect")
    row = rows[0]
    details = identity.decode_json(manifest.canonical_bytes)
    require(row["Id"] == cid and row["Name"] == details["runtime"]["name"]
            and row["ImageDigest"] in {"sha256:" + engine.IMAGE_INDEX, "sha256:" + engine.IMAGE_CHILD}
            and row["Image"].removeprefix("sha256:") == IMAGE_CONFIG
            and all(row["Config"]["Labels"].get(key) == value for key, value in details["runtime"]["labels"].items()),
            "engine-container-not-owned")
    require(type(row["State"]["Running"]) is bool, "engine-container-state")
    return row


def _spawn(prepared, manifest, store, effect_id=None):
    require(os.geteuid() == 0, "engine-executor-root-required")
    require(type(manifest) is engine.EngineManifest and manifest.sha256 == hashlib.sha256(manifest.canonical_bytes).hexdigest()
            and manifest.argv[0] == engine.ENGINE, "engine-compiled-input")
    details = identity.decode_json(manifest.canonical_bytes)
    require(not os.path.lexists(details["runtime"]["cidfile"]), "engine-cidfile-exists")
    effect, pidfd, capture, owned, proc = effect_id, None, None, None, None
    try:
        if effect is None:
            effect = store.begin(prepared.lease_id, "engine-start", "engine:" + details["runtime"]["name"])
        else:
            retained = store.read(prepared.lease_id)["effects"].get(effect)
            require(retained is not None and retained["operation"] == "engine-start"
                    and retained["target"] == "engine:" + details["runtime"]["name"]
                    and retained["state"] == "intent" and "engine_process" not in retained
                    and "engine_container_id" not in retained, "engine-spawn-effect")
        require(tuple(details["argv"]) == manifest.argv, "engine-argv-not-compiled")
        path = details["engine"]["runroot"] + "/engine-manifest.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(manifest.canonical_bytes)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        parent = installation._open_directory(details["engine"]["runroot"])
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        cgroup_device, cgroup_inode = _cgroup(details)
        capture = engine_supervision.Capture(manifest, store, prepared.lease_id, effect, cgroup_device, cgroup_inode)
        from . import runtime_entry
        with runtime_entry._spawn_adoption():
            proc = subprocess.Popen(manifest.argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=_environment(manifest), close_fds=True, start_new_session=True, umask=0o077)
            _UNTRACKED_PROCESSES[proc.pid] = (proc, capture)
            owned = engine_supervision.OwnedRun(proc, None, capture, store, prepared.lease_id, effect)
            owned.prepared = prepared
            _PROCESSES[proc.pid] = owned
            del _UNTRACKED_PROCESSES[proc.pid]
            pidfd = os.pidfd_open(proc.pid, 0)
            owned.pidfd = pidfd
        process = _stable_process(proc.pid, manifest, pidfd)
        store.bind_engine_process(prepared.lease_id, effect, **process)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            cid = _cid(details["runtime"]["cidfile"])
            if cid is not None:
                _inspect(manifest, cid)
                require(_stable_process(proc.pid, manifest, pidfd) == process, "engine-supervisor-replaced")
                store.bind_engine_container(prepared.lease_id, effect, cid)
                owned.tracked(process, cid)
                store.record(prepared.lease_id, effect, "verified", evidence_sha256=ledger.digest({
                    "engine_policy_sha256": manifest.sha256, "process": process, "container_id": cid}))
                return EngineStatus(prepared.lease_id, "tracked-not-test-success", cid)
            require(owned.pump(0.02) is None, "engine-supervisor-exited-before-tracking")
            require(not capture.problem, "engine-capture-limit-before-tracking")
        raise Denied("engine-tracking-timeout")
    except Exception:
        if effect is not None:
            try:
                store.record(prepared.lease_id, effect, "unknown", evidence_sha256=ledger.digest({"stage": "engine-start"}))
            except Exception:
                pass
        raise EngineUnknown("engine-start-unknown") from None
    finally:
        if owned is None:
            if pidfd is not None:
                os.close(pidfd)
            if capture is not None and proc is None:
                capture.close()


def start(config_path, config_sha256, registry, selector, store, lease_id, receipt):
    require(os.geteuid() == 0, "engine-executor-root-required")
    from . import root_session
    with root_session._session(config_path, config_sha256) as session:
        return _start_locked(session, registry, selector, store, lease_id, receipt)


def _start_locked(session, registry, selector, store, lease_id, receipt):
    from . import root_session
    require(os.geteuid() == 0, "engine-executor-root-required")
    config = root_session._require_session(session)
    effect = None
    try:
        prepared, manifest = _bound(config, registry, selector, store, lease_id, receipt)
        _start_budget(prepared, manifest)
        with _preflight(config, prepared, store, manifest):
            _bound(config, registry, selector, store, lease_id, receipt)
            _start_budget(prepared, manifest)
            effect = store.begin(lease_id, "engine-start", "engine:lit-lease-" + lease_id)
            _idmapped_preflight(prepared, manifest)
            # Probing never extends authorization; reauthenticate current
            # signed bytes, policy, native assignment and deadline afterward.
            current, compiled = _bound(config, registry, selector, store, lease_id, receipt)
            require(current == prepared and compiled == manifest, "engine-probe-binding-drift")
            _start_budget(current, compiled)
            return _spawn(prepared, manifest, store, effect)
    except EngineUnknown:
        raise
    except Exception:
        if effect is not None:
            try:
                store.record(lease_id, effect, "unknown", evidence_sha256=ledger.digest({"stage": "engine-prestart-probe"}))
            except Exception:
                pass
            raise EngineUnknown("engine-prestart-unknown") from None
        raise Denied("engine-start-denied") from None


def _start_budget(prepared, manifest):
    """A new start needs its original full budget; running renewals do not."""
    details = identity.decode_json(manifest.canonical_bytes)
    remaining = prepared.expires_at - int(time.time())
    require(type(details["limits"]["timeout_seconds"]) is int
            and 0 < details["limits"]["timeout_seconds"] <= remaining, "engine-start-budget-expired")


def _retained(config, registry, selector, store, lease_id, receipt):
    cell, record = _authenticate(config, registry, selector, store, lease_id, receipt)
    path = cell["engine"]["paths"]["runroot"] + "/" + lease_id + "/engine-manifest.json"
    proof, raw, _ = installation._file(path, engine.MAX_DESCRIPTOR, private=True, keep=True)
    require(proof.sha256 == receipt.engine_policy_sha256, "engine-retained-manifest-drift")
    details = identity.decode_json(raw)
    descriptor_path = cell["engine"]["paths"]["descriptor"] + "/" + lease_id + ".json"
    require(details["descriptor"]["path"] == descriptor_path, "engine-retained-descriptor-locator")
    manifest = engine.validate_retained_policy(descriptor_path, details["descriptor"]["sha256"], receipt.engine_policy_sha256)
    require(engine._canonical(details) == raw and details["argv"][0] == engine.ENGINE
            and details["runtime"]["name"] == "lit-lease-" + lease_id
            and details["runtime"]["cidfile"] == str(PurePosixPath(path).parent) + "/container.cid"
            and details["runtime"]["labels"] == {"io.lightning-it.lease": lease_id,
                "io.lightning-it.descriptor": details["descriptor"]["sha256"]}, "engine-retained-runtime")
    binary = installation.trusted_file(engine.ENGINE, max_bytes=128 * 1024 ** 2)
    require(binary.sha256 == details["engine_executable_sha256"], "engine-executable-drift")
    matches = [(key, value) for key, value in record["effects"].items() if value["operation"] == "engine-start"]
    require(len(matches) == 1, "engine-no-unique-start")
    effect_id, effect = matches[0]
    require(effect["target"] == "engine:lit-lease-" + lease_id and "engine_process" in effect
            and "engine_container_id" in effect, "engine-untracked-start")
    process = effect["engine_process"]
    require(process["boot_id"] == kernel.read_boot_id() and process["executable"] == engine.ENGINE
            and process["exe_sha256"] == binary.sha256, "engine-boot-or-executable-changed")
    cid = _cid(details["runtime"]["cidfile"])
    require(cid is None or cid == effect["engine_container_id"], "engine-cidfile-replaced")
    return manifest, effect_id, effect


def _observation(manifest, cid):
    code, _ = _command(manifest, ["container", "exists", cid])
    if code == 1:
        return "absent-observed-not-test-success"
    require(code == 0, "engine-existence-readback")
    row = _inspect(manifest, cid)
    return "owned-running-not-test-success" if row["State"]["Running"] else "owned-stopped-not-test-success"


def status(config_path, config_sha256, registry, selector, store, lease_id, receipt):
    """Read exact retained ownership; never adopt a name/CID or renew identity."""
    require(os.geteuid() == 0, "engine-executor-root-required")
    try:
        with preparation.preparation_lock(config_path, config_sha256) as config:
            manifest, _, effect = _retained(config, registry, selector, store, lease_id, receipt)
            cid = effect["engine_container_id"]
            observed = _observation(manifest, cid)
            _reap_finished()
            return EngineStatus(lease_id, observed, cid)
    except Exception:
        raise Denied("engine-status-denied") from None


def _reap_finished():
    # Only the original owner pumps/waits, and its observation is retained.
    # Status never discards an actual exit code or fabricates a replacement.
    for owned in list(_PROCESSES.values()):
        if owned.owner_pid == os.getpid() and not owned.closed:
            owned.pump(0)


def _signal_owned(process, manifest):
    require(os.geteuid() == 0, "engine-executor-root-required")
    require(process["boot_id"] == kernel.read_boot_id(), "engine-process-boot-changed")
    try:
        fd = os.pidfd_open(process["pid"], 0)
    except ProcessLookupError:
        return
    try:
        if select.select([fd], [], [], 0)[0]:
            _reap_finished()
            return
        observed = _stable_process(process["pid"], manifest, fd)
        require(all(observed[key] == process[key] for key in observed), "engine-process-reused")
        signal.pidfd_send_signal(fd, signal.SIGTERM)
        if not select.select([fd], [], [], 2)[0]:
            require(_stable_process(process["pid"], manifest, fd) == observed, "engine-process-reused")
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            require(select.select([fd], [], [], 2)[0], "engine-supervisor-not-quiescent")
        _reap_finished()
    finally:
        os.close(fd)


def _drained(manifest, capture):
    """Kernel subtree population, not merely original PID/CID disappearance."""
    details = identity.decode_json(manifest.canonical_bytes)
    path = "/sys/fs/cgroup/lit.slice/lit-lease.slice/" + details["runtime"]["name"] + ".slice"
    fd = installation._open_directory(path)
    try:
        info = os.fstat(fd)
        require(_fs_type(fd) == CGROUP2_MAGIC and info.st_uid == 0 and not info.st_mode & 0o022
                and (info.st_dev, info.st_ino) == (capture["cgroup_device"], capture["cgroup_inode"]),
                "engine-cgroup-replaced")
        events = dict(line.split() for line in kernel.bounded_file(fd, "cgroup.events", 4096).splitlines())
        require(events.get(b"populated") in {b"0", b"1"}, "engine-cgroup-events")
        require(events[b"populated"] == b"0", "engine-descendants-not-drained")
        require(not kernel.bounded_file(fd, "cgroup.procs", 65536).strip(), "engine-descendants-not-drained")
    finally:
        os.close(fd)


def _withdraw(config, owned):
    """One journaled withdrawal; an uncertain withdrawal stays held."""
    from . import network_fence
    record = owned.store.read(owned.lease_id)
    attempted = [row for row in record["effects"].values() if row["operation"] == "fence-disable"]
    if attempted:
        owned.withdrawal_hold = any(row["state"] != "verified" for row in attempted)
        return
    try:
        network_fence.disable(config.network_fence_policy_path, config.network_fence_policy_sha256,
            owned.prepared, owned.store, ledger.Worker(**record["worker"]), config)
    except Exception:
        owned.withdrawal_hold = True


def _withdraw_retained(config, registry, selector, store, lease_id):
    """Reacquire only the distinct Root fence-cleanup locator after restart."""
    from . import network_fence
    require(registry.path == config.registry_path and registry.sha256 == config.registry_sha256,
            "engine-cleanup-registry")
    locator = cell_contract.owned_fence_for_cleanup(registry, selector, store, lease_id)
    record = store.read(lease_id)
    attempted = [row for row in record["effects"].values() if row["operation"] == "fence-disable"]
    if attempted:
        return any(row["state"] != "verified" for row in attempted)
    try:
        network_fence.disable(config.network_fence_policy_path, config.network_fence_policy_sha256,
            locator, store, ledger.Worker(**record["worker"]), config)
        return False
    except Exception:
        # A possible withdrawal effect stays held; exact verified owned-stop
        # may still proceed under the Ledger's narrow emergency-stop rule.
        return True


def wait_for_exit(config_path, config_sha256, registry, selector, store, lease_id, receipt):
    """Retain the actual original owner with current auth/deadline supervision."""
    return _wait_original(config_path, config_sha256, registry, selector, store, lease_id, receipt,
                          stop_first=False)


def _abort_after_failure(config_path, config_sha256, registry, selector, store, lease_id, receipt):
    """Internal Root failure path: one journaled owned stop, then original wait.

    No caller owner/command override, signal bypass or replacement child. A
    failed/unknown stop remains held; it never authorizes another stop attempt.
    Actual remote VM cleanup is separate from stopping this local engine.
    """
    return _wait_original(config_path, config_sha256, registry, selector, store, lease_id, receipt,
                          stop_first=True)


def _wait_original(config_path, config_sha256, registry, selector, store, lease_id, receipt, *, stop_first):
    """Long-lived original owner; no preparation lock while pumping/waiting.

    Returns only a durable process/capture observation. Exit zero is not test
    success. Missing original ownership cannot recover the kernel wait result.
    """
    require(os.geteuid() == 0, "engine-executor-root-required")
    with preparation.preparation_lock(config_path, config_sha256) as config:
        manifest, effect_id, effect = _retained(config, registry, selector, store, lease_id, receipt)
        owned = _PROCESSES.get(effect["engine_process"]["pid"])
        require(type(owned) is engine_supervision.OwnedRun and owned.owner_pid == os.getpid()
                and owned.store is store and owned.effect_id == effect_id
                and owned.capture.manifest == manifest, "engine-original-wait-owner-missing")
    if owned.closed:
        require(owned.exit_receipt is not None and owned.cgroup_state == "drained-observed"
                and not owned.withdrawal_hold, "engine-retained-exit-held")
        return owned.exit_receipt
    while True:
        if stop_first and not owned.stop_attempted:
            owned.stop_attempted = True
            try:
                cancel(config_path, config_sha256, registry, selector, store, lease_id, receipt)
            except EngineUnknown:
                owned.withdrawal_hold = True
        owned.pump(0.05)
        record = store.read(lease_id)
        authorization = record["authorizations"][-1]
        expired = int(time.time()) >= min(owned.prepared.expires_at, authorization["valid_until"])
        if (expired or owned.capture.problem) and not owned.stop_attempted:
            owned.stop_attempted = True
            # cancel reacquires the lock only for its finite transition.
            try:
                cancel(config_path, config_sha256, registry, selector, store, lease_id, receipt)
            except EngineUnknown:
                owned.withdrawal_hold = True
        if owned.returncode is not None:
            if not owned.stop_attempted:
                owned.stop_attempted = True
                try:
                    cancel(config_path, config_sha256, registry, selector, store, lease_id, receipt)
                except EngineUnknown:
                    owned.withdrawal_hold = True
            # Descendants retaining pipe endpoints are not silently accepted.
            # A finite drain grace produces incomplete capture and a hold.
            end = time.monotonic() + 2
            while not owned.eof and time.monotonic() < end:
                owned.pump(0.05)
            observed = owned.record_exit()
            try:
                current = store.read(lease_id)["effects"][effect_id]
                _drained(manifest, current["engine_capture"])
                owned.cgroup_state = "drained-observed"
            except Exception:
                owned.cgroup_state = "unknown"
            if not owned.eof or owned.cgroup_state != "drained-observed" or owned.withdrawal_hold:
                raise EngineUnknown("engine-exit-cleanup-held")
            owned.release()
            return observed


def cancel(config_path, config_sha256, registry, selector, store, lease_id, receipt):
    """Root cleanup after expiry is allowed, but only exact owned runtime.

    Unknown starts with complete persisted ownership can be explicitly reconciled
    by this Root cleanup path after actual native readback. Missing PID/CID stays
    held; no lookup/adoption by name and no ordinary engine re-entry exists.
    """
    require(os.geteuid() == 0, "engine-executor-root-required")
    effect_id = None
    try:
        with preparation.preparation_lock(config_path, config_sha256) as config:
            manifest, creator_id, creator = _retained(config, registry, selector, store, lease_id, receipt)
            cid = creator["engine_container_id"]
            owned = _PROCESSES.get(creator["engine_process"]["pid"])
            live_owner = (type(owned) is engine_supervision.OwnedRun and owned.owner_pid == os.getpid()
                          and owned.effect_id == creator_id and owned.store is store)
            if live_owner:
                owned.stop_attempted = True
                _withdraw(config, owned)
                withdrawal_hold = owned.withdrawal_hold
            else:
                # Never reconstruct Popen/capture/exit status. This distinct
                # locator supplies only independently revalidated fence scope.
                withdrawal_hold = _withdraw_retained(config, registry, selector, store, lease_id)
            observed = _observation(manifest, cid)
            evidence = ledger.digest({"engine_policy_sha256": manifest.sha256, "container_id": cid, "state": observed})
            if creator["state"] in {"intent", "unknown"}:
                # Absence alone cannot establish a formerly ambiguous create.
                require(observed != "absent-observed-not-test-success", "engine-unknown-create-absent")
                store.reconcile(lease_id, creator_id, "verified", evidence_sha256=evidence)
            effect_id = store.begin(lease_id, "engine-stop", creator["target"])
            if observed == "owned-running-not-test-success":
                rc, _ = _command(manifest, ["container", "stop", "--time=10", cid], seconds=15)
                require(rc == 0, "engine-stop-response-unknown")
            observed = _observation(manifest, cid)
            require(observed != "owned-running-not-test-success", "engine-stop-not-observed")
            _signal_owned(creator["engine_process"], manifest)
            _drained(manifest, creator["engine_capture"])
            if live_owner:
                owned.cgroup_state = "drained-observed"
            store.record(lease_id, effect_id, "verified", evidence_sha256=ledger.digest({
                "container_id": cid, "state": observed, "engine_policy_sha256": manifest.sha256}))
            require(not withdrawal_hold, "engine-fence-withdrawal-held")
            require(live_owner or ("engine_exit" in creator
                    and creator["engine_exit"]["stdout_state"] == "complete"
                    and creator["engine_exit"]["stderr_state"] == "complete"),
                    "engine-original-exit-unknown-held")
            return EngineStatus(lease_id, observed, cid)
    except Exception:
        if effect_id is not None:
            try:
                store.record(lease_id, effect_id, "unknown", evidence_sha256=ledger.digest({"stage": "engine-stop"}))
            except Exception:
                pass
        raise EngineUnknown("engine-cancel-unknown") from None
