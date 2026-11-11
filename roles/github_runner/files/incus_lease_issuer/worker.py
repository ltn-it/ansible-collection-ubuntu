"""Non-authorizing, pure process-lineage component for the stock runner service.

All snapshots and policy below are INTERNAL root-acquired inputs, never job JSON.
No collect_worker(connected_socket, rootpolicy), /proc reader, systemd reader or
socket handler exists here. A successful fixture comparison does not establish
that the supplied observations are genuine, fresh, or immune to a hostile UID.

Before any authority exists, a separate root-owned acquisition boundary must
verify the installed startup/code/dependency tree and running images (including
scripts, managed DLLs, libraries, .env/.path and update settings), trusted unit
and drop-ins, socket peer, systemd state and kernel observations. Paths, argv,
inode equality and two matching reads alone cannot establish that trust. This
module neither grants engine/TLS rights nor authorizes ledger.prepare.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import re

from .identity import require
from .ledger import Worker

MAX_STAT_BYTES = 4096
MAX_ARG_BYTES = 8192
MAX_SNAPSHOTS = 4096
MAX_DEPTH = 64
LIVE_STATES = frozenset("RSDTtWPI")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def positive(value):
    return type(value) is int and 0 < value <= 2147483647


def decimal(value, *, zero=False):
    require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value), "invalid-proc-stat")
    number = int(value)
    require(number > 0 or zero, "invalid-proc-stat")
    return number


def absolute_path(value):
    return (type(value) is str and 0 < len(value) <= 4096 and value.startswith("/") and not value.startswith("//")
            and "\x00" not in value and not any(ord(c) < 32 for c in value)
            and ".." not in PurePosixPath(value).parts and str(PurePosixPath(value)) == value)


@dataclass(frozen=True)
class ProcStat:
    pid: int
    comm: str
    state: str
    ppid: int
    start_ticks: int


def parse_proc_stat(raw: bytes) -> ProcStat:
    """Bounded /proc/PID/stat parser: comm is not a whitespace-delimited field.

    After the final closing comm delimiter, the tail starts at field3. PPID is
    tail[1] (field4), starttime tail[19] (field22). comm may contain spaces and
    parentheses. Newline/control-bearing comm is conservatively unsupported.
    """
    require(type(raw) is bytes and 0 < len(raw) <= MAX_STAT_BYTES, "invalid-proc-stat")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    require(not any(c < 32 or c == 127 for c in raw), "invalid-proc-stat")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        require(False, "invalid-proc-stat")
    opening = text.find(" (")
    closing = text.rfind(") ")
    require(opening > 0 and closing > opening + 1, "invalid-proc-stat")
    pid = decimal(text[:opening])
    comm = text[opening + 2:closing]
    require(0 < len(comm) <= 256 and positive(pid), "invalid-proc-stat")
    tail = text[closing + 2:].split(" ")
    require(20 <= len(tail) <= 64 and all(tail), "invalid-proc-stat")
    require(len(tail[0]) == 1 and tail[0] in LIVE_STATES, "dead-or-invalid-process")
    require(all(re.fullmatch(r"-?(?:0|[1-9][0-9]{0,19})", part) for part in tail[1:]),
            "invalid-proc-stat")
    ppid, start = decimal(tail[1], zero=True), decimal(tail[19])
    require(ppid <= 2147483647 and start <= 18446744073709551615, "invalid-proc-stat")
    return ProcStat(pid, comm, tail[0], ppid, start)


@dataclass(frozen=True)
class ProcessSnapshot:
    stat: ProcStat
    uids: tuple[int, int, int, int]
    cgroup: str
    executable: str
    exe_device: int
    exe_inode: int
    argv: tuple[str, ...]


@dataclass(frozen=True)
class ExecutablePolicy:
    path: str
    device: int
    inode: int
    argv: tuple[str, ...] = ()


@dataclass(frozen=True)
class LineagePolicy:
    main_pid: int
    service_uid: int
    runner_id: int
    cgroup: str
    main: ExecutablePolicy
    node: ExecutablePolicy
    listener: ExecutablePolicy
    worker: ExecutablePolicy
    max_depth: int = MAX_DEPTH


def validate_argv(argv):
    require(type(argv) is tuple and 0 < len(argv) <= 32
            and all(type(arg) is str and 0 < len(arg) <= 4096
                    and not any(ord(c) < 32 or ord(c) == 127 for c in arg) for arg in argv),
            "invalid-process-argv")
    try:
        size = sum(len(arg.encode("utf-8")) + 1 for arg in argv)
    except UnicodeError:
        require(False, "invalid-process-argv")
    require(size <= MAX_ARG_BYTES, "invalid-process-argv")


def validate_policy(policy):
    require(type(policy) is LineagePolicy and positive(policy.main_pid)
            and positive(policy.service_uid) and positive(policy.runner_id)
            and type(policy.max_depth) is int and 4 <= policy.max_depth <= MAX_DEPTH,
            "invalid-lineage-policy")
    require(absolute_path(policy.cgroup) and policy.cgroup != "/", "invalid-service-cgroup")
    for spec in (policy.main, policy.node, policy.listener, policy.worker):
        require(type(spec) is ExecutablePolicy and absolute_path(spec.path)
                and type(spec.device) is int and spec.device >= 0
                and type(spec.inode) is int and spec.inode > 0, "invalid-executable-policy")
    # The four roles are fixed, never a configurable arbitrary ancestry list.
    require(policy.main.path.endswith("/bash")
            and policy.node.path.endswith("/externals/node24/bin/node"), "unsupported-service-layout")
    runner_root = policy.node.path.removesuffix("/externals/node24/bin/node")
    require(policy.listener.path == runner_root + "/bin/Runner.Listener"
            and policy.worker.path == runner_root + "/bin/Runner.Worker", "unsupported-service-layout")
    for spec in (policy.main, policy.node, policy.listener):
        validate_argv(spec.argv)
    require(len(policy.main.argv) == 2 and policy.main.argv[1] == runner_root + "/runsvc.sh"
            and len(policy.node.argv) == 2
            and policy.node.argv[1] in (runner_root + "/bin/RunnerService.js", "./bin/RunnerService.js")
            and policy.listener.argv == (policy.listener.path, "run", "--startuptype", "service")
            and policy.worker.argv == (), "unsupported-service-argv")


def validate_snapshot(snapshot, pid, policy):
    require(type(snapshot) is ProcessSnapshot and type(snapshot.stat) is ProcStat, "invalid-process-snapshot")
    info = snapshot.stat
    require(positive(info.pid) and info.pid == pid and type(info.ppid) is int
            and 0 <= info.ppid <= 2147483647 and type(info.start_ticks) is int
            and 0 < info.start_ticks <= 18446744073709551615
            and type(info.state) is str and info.state in LIVE_STATES
            and type(info.comm) is str and 0 < len(info.comm) <= 256
            and not any(ord(c) < 32 or ord(c) == 127 for c in info.comm),
            "invalid-process-snapshot")
    require(type(snapshot.uids) is tuple and len(snapshot.uids) == 4
            and all(type(uid) is int and uid == policy.service_uid for uid in snapshot.uids), "process-uid")
    require(snapshot.cgroup == policy.cgroup, "process-cgroup")
    require(absolute_path(snapshot.executable) and type(snapshot.exe_device) is int
            and snapshot.exe_device >= 0 and type(snapshot.exe_inode) is int and snapshot.exe_inode > 0,
            "invalid-process-image")
    validate_argv(snapshot.argv)


def match_role(snapshot, spec, *, worker=False):
    require((snapshot.executable, snapshot.exe_device, snapshot.exe_inode)
            == (spec.path, spec.device, spec.inode), "process-image-mismatch")
    if worker:
        require(len(snapshot.argv) == 4 and snapshot.argv[0] == spec.path
                and snapshot.argv[1] == "spawnclient"
                and all(0 < len(arg) <= 256 for arg in snapshot.argv[2:]), "worker-argv")
    else:
        require(snapshot.argv == spec.argv, "service-argv-mismatch")


def verify_lineage(policy, *, peer_pid, peer_uid, boot_id, snapshots,
                   confirmed_snapshots, confirmed_boot_id):
    """Compare two INTERNAL observations; return a binding, never an authority.

    The caller must separately collect genuine root/kernel facts and establish
    installed/startup/loaded-code trust. Neither mapping is a public request
    argument. This component performs no IO, process creation or socket access.
    """
    validate_policy(policy)
    require(positive(peer_pid) and type(peer_uid) is int and peer_uid == policy.service_uid, "peer-identity")
    require(type(boot_id) is str and UUID.fullmatch(boot_id)
            and confirmed_boot_id == boot_id, "boot-identity")
    require(type(snapshots) is dict and type(confirmed_snapshots) is dict
            and len(snapshots) <= MAX_SNAPSHOTS and len(confirmed_snapshots) <= MAX_SNAPSHOTS,
            "invalid-process-inventory")
    require(all(positive(pid) for pid in snapshots) and all(positive(pid) for pid in confirmed_snapshots),
            "invalid-process-inventory")
    chain, seen, pid = [], set(), peer_pid
    while True:
        require(len(chain) < policy.max_depth and pid not in seen, "cyclic-or-deep-lineage")
        seen.add(pid)
        require(pid in snapshots and pid in confirmed_snapshots, "missing-process")
        process, confirmed = snapshots[pid], confirmed_snapshots[pid]
        validate_snapshot(process, pid, policy)
        validate_snapshot(confirmed, pid, policy)
        require(process == confirmed, "process-observation-changed")
        chain.append(process)
        if pid == policy.main_pid:
            break
        pid = process.stat.ppid
        require(positive(pid), "missing-service-ancestor")
    service_order = list(reversed(chain))
    require(len(service_order) >= 4, "incomplete-service-lineage")
    main, node, listener, worker = service_order[:4]
    for process, spec in ((main, policy.main), (node, policy.node), (listener, policy.listener)):
        match_role(process, spec)
    match_role(worker, policy.worker, worker=True)
    result = Worker(policy.service_uid, policy.runner_id, worker.stat.pid, worker.stat.start_ticks, boot_id)
    result.validate()
    return result
