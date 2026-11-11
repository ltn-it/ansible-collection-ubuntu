"""Fixed Linux kernel observations; not service/startup trust or authority.

There is no caller-selected proc root, injected production reader, socket
handler, systemd acquisition or collect_worker authority here. Genuine peer and
process facts must still meet independent root-owned unit/startup/loaded-code
trust and worker.verify_lineage policy before any further decision. This module
cannot itself authorize a lease, TLS credential or engine operation.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
import socket
import stat
import struct

from .identity import Denied, require
from . import worker

STATUS_LIMIT = 65536
CGROUP_LIMIT = 4096
CMDLINE_LIMIT = worker.MAX_ARG_BYTES
FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int


def read_peer(connected_socket):
    """Use SO_PEERCRED on an actual connected Unix stream, never request PID."""
    require(isinstance(connected_socket, socket.socket), "invalid-peer-socket")
    try:
        require(connected_socket.family == socket.AF_UNIX
                and connected_socket.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
                and stat.S_ISSOCK(os.fstat(connected_socket.fileno()).st_mode), "invalid-peer-socket")
        connected_socket.getpeername()
        raw = connected_socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        require(len(raw) == struct.calcsize("3i"), "invalid-peer-credentials")
        pid, uid, gid = struct.unpack("3i", raw)
        require(worker.positive(pid) and uid > 0 and gid > 0, "invalid-peer-credentials")
        return Peer(pid, uid, gid)
    except (OSError, ValueError, struct.error):
        raise Denied("peer-read-failed") from None


def bounded_file(directory_fd, name, limit):
    """Regular procfs files may have st_size0; read bounded bytes regardless."""
    fd = os.open(name, FLAGS, dir_fd=directory_fd)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "invalid-proc-file")
        chunks, size = [], 0
        while True:
            part = os.read(fd, min(4096, limit + 1 - size))
            if not part:
                break
            chunks.append(part)
            size += len(part)
            require(size <= limit, "proc-read-limit")
        return b"".join(chunks)
    finally:
        os.close(fd)


def parse_status_uids(raw):
    require(type(raw) is bytes and 0 < len(raw) <= STATUS_LIMIT, "invalid-proc-status")
    rows = [line for line in raw.splitlines() if line.startswith(b"Uid:")]
    require(len(rows) == 1, "invalid-proc-status")
    match = re.fullmatch(rb"Uid:[ \t]+(0|[1-9][0-9]{0,9})[ \t]+(0|[1-9][0-9]{0,9})"
                         rb"[ \t]+(0|[1-9][0-9]{0,9})[ \t]+(0|[1-9][0-9]{0,9})", rows[0])
    require(match is not None, "invalid-proc-status")
    values = tuple(int(value) for value in match.groups())
    require(all(value <= 4294967295 for value in values), "invalid-proc-status")
    return values


def parse_cgroup(raw):
    require(type(raw) is bytes and 0 < len(raw) <= CGROUP_LIMIT, "invalid-proc-cgroup")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise Denied("invalid-proc-cgroup") from None
    if text.endswith("\n"):
        text = text[:-1]
    require(text.startswith("0::") and "\n" not in text and "\r" not in text, "invalid-proc-cgroup")
    path = text[3:]
    require(worker.absolute_path(path), "invalid-proc-cgroup")
    return path


def parse_cmdline(raw):
    require(type(raw) is bytes and 0 < len(raw) <= CMDLINE_LIMIT and raw.endswith(b"\x00"),
            "invalid-proc-cmdline")
    try:
        argv = tuple(part.decode("utf-8") for part in raw[:-1].split(b"\x00"))
    except UnicodeError:
        raise Denied("invalid-proc-cmdline") from None
    worker.validate_argv(argv)
    return argv


def read_boot_id():
    fd = -1
    try:
        fd = os.open("/proc/sys/kernel/random", FLAGS | os.O_DIRECTORY)
        raw = bounded_file(fd, "boot_id", 64)
        value = raw.decode("ascii").removesuffix("\n")
        require(worker.UUID.fullmatch(value), "invalid-boot-id")
        return value
    except (OSError, UnicodeError):
        raise Denied("boot-read-failed") from None
    finally:
        if fd >= 0:
            os.close(fd)


def read_process(pid):
    """Observe one PID through a fixed proc directory and intended exe link.

    The actual running exe FD and canonical filesystem path must identify the
    same regular image. This does not verify loaded scripts/DLLs/dependencies.
    Stable PID/PPID/start/comm is rechecked; no assertion of atomic whole-proc
    acquisition or protection against a hostile same-UID process is made.
    """
    require(worker.positive(pid), "invalid-process-id")
    proc_fd = process_fd = image_fd = path_fd = -1
    try:
        proc_fd = os.open("/proc", FLAGS | os.O_DIRECTORY)
        process_fd = os.open(str(pid), FLAGS | os.O_DIRECTORY, dir_fd=proc_fd)
        first = worker.parse_proc_stat(bounded_file(process_fd, "stat", worker.MAX_STAT_BYTES))
        require(first.pid == pid, "proc-pid-mismatch")
        uids = parse_status_uids(bounded_file(process_fd, "status", STATUS_LIMIT))
        cgroup = parse_cgroup(bounded_file(process_fd, "cgroup", CGROUP_LIMIT))
        argv = parse_cmdline(bounded_file(process_fd, "cmdline", CMDLINE_LIMIT))
        executable = os.readlink("exe", dir_fd=process_fd)
        require(worker.absolute_path(executable) and not executable.endswith(" (deleted)")
                and os.path.realpath(executable) == executable, "invalid-executable-path")
        # /proc/PID/exe is the single intentional kernel symlink exception.
        image_fd = os.open("exe", os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=process_fd)
        path_fd = os.open(executable, FLAGS)
        image, named = os.fstat(image_fd), os.fstat(path_fd)
        require(stat.S_ISREG(image.st_mode) and stat.S_ISREG(named.st_mode)
                and (image.st_dev, image.st_ino) == (named.st_dev, named.st_ino), "executable-image-changed")
        second = worker.parse_proc_stat(bounded_file(process_fd, "stat", worker.MAX_STAT_BYTES))
        require((first.pid, first.ppid, first.start_ticks, first.comm)
                == (second.pid, second.ppid, second.start_ticks, second.comm), "process-observation-changed")
        return worker.ProcessSnapshot(second, uids, cgroup, executable, image.st_dev, image.st_ino, argv)
    except (OSError, UnicodeError, ValueError):
        raise Denied("process-read-failed") from None
    finally:
        for fd in (path_fd, image_fd, process_fd, proc_fd):
            if fd >= 0:
                os.close(fd)


def read_chain(peer_pid, main_pid, max_depth=64):
    """Bounded ancestry observations only; main_pid does not become trusted here."""
    require(worker.positive(peer_pid) and worker.positive(main_pid)
            and type(max_depth) is int and 0 < max_depth <= worker.MAX_DEPTH, "invalid-chain-input")
    rows, pid = {}, peer_pid
    while True:
        require(len(rows) < max_depth and pid not in rows, "cyclic-or-deep-lineage")
        snapshot = read_process(pid)
        require(snapshot.stat.pid == pid, "proc-pid-mismatch")
        rows[pid] = snapshot
        if pid == main_pid:
            return rows
        pid = snapshot.stat.ppid
        require(worker.positive(pid), "missing-service-ancestor")
