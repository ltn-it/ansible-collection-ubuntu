"""Root-only integrated worker observations; no handler or lease/TLS grant.

The effective AppArmor label is checked, but Linux's label does not attest that
the loaded profile bytes equal a disk SHA. Profile loading/reload and effective
anti-injection rules remain a native root-operator qualification obligation.
Anonymous/JIT/BSS mappings are not evidence of memory-injection immunity.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import os
from pathlib import PurePosixPath
import re
import stat

from .identity import Denied, require
from . import installation, kernel, service, worker

MAPS_LIMIT = 8 * 1024 * 1024
ENV_LIMIT = 1024 * 1024
MAX_MAPPINGS = 65536
MAX_NAMED_FILES = 4096
MAX_HOST_BYTES = 4 * 1024 * 1024 * 1024
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
FILE = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
JIT_NAME = "/memfd:doublemapper (deleted)"
JIT_PERMISSIONS = frozenset({"---s", "r-xs", "rw-s"})
MAX_PROCESS_FDS = 4096


@dataclass(frozen=True)
class CollectorPolicy:
    service: service.ServicePolicy
    profile_name: str
    profile_path: str
    profile_sha256: str
    config_path: str
    config_sha256: str


@dataclass(frozen=True)
class MappedFile:
    path: str
    major: int
    minor: int
    inode: int
    jit: bool = False


def parse_maps(raw, *, role=None):
    """Only canonical named regular-file coordinates or inode0 anonymous areas."""
    require(type(raw) is bytes and 0 < len(raw) <= MAPS_LIMIT, "invalid-process-maps")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError:
        raise Denied("invalid-process-maps") from None
    require(0 < len(lines) <= MAX_MAPPINGS, "invalid-process-maps")
    found = {}
    for line in lines:
        columns = line.split(None, 5)
        require(5 <= len(columns) <= 6, "invalid-process-maps")
        address, permissions, offset, device, inode = columns[:5]
        path = columns[5] if len(columns) == 6 else ""
        require(re.fullmatch(r"[0-9a-f]{1,16}-[0-9a-f]{1,16}", address)
                and int(address.split("-")[0], 16) < int(address.split("-")[1], 16)
                and re.fullmatch(r"[r-][w-][x-][ps]", permissions)
                and re.fullmatch(r"[0-9a-f]{1,16}", offset)
                and re.fullmatch(r"[0-9a-f]{1,8}:[0-9a-f]{1,8}", device)
                and re.fullmatch(r"0|[1-9][0-9]{0,19}", inode), "invalid-process-maps")
        number = int(inode)
        if number == 0:
            require(path == "" or re.fullmatch(r"\[[A-Za-z0-9_:. -]{1,128}\]", path),
                    "unsupported-anonymous-mapping")
            continue
        major, minor = (int(part, 16) for part in device.split(":"))
        jit = path == JIT_NAME
        if jit:
            require(role in {"listener", "worker"} and permissions in JIT_PERMISSIONS
                    and (major, minor) == (0, 1), "unsupported-jit-mapping")
        else:
            require(worker.absolute_path(path) and not any(c.isspace() for c in path)
                    and "\\" not in path and "memfd:" not in path and not path.endswith("(deleted)"),
                    "unsupported-file-mapping")
        record = MappedFile(path, major, minor, number, jit)
        require(path not in found or found[path] == record, "mapping-backing-changed")
        found[path] = record
        require(len(found) <= MAX_NAMED_FILES, "process-map-limit")
    return tuple(sorted(found.values(), key=lambda row: row.path))


def _retained_jit(process_fd, mapping, uid):
    """Match a kernel-enumerated same-PID retained .NET doublemapper object.

    Only the trusted Listener/Worker closure calls this after confinement gates.
    No caller FD/path is accepted. Sparse JIT backing may be2TiB; neither size
    nor content hash is static code evidence. Mutable JIT memory relies on the
    root-qualified runtime and effective anti-injection profile, not this name.
    """
    require(type(mapping) is MappedFile and mapping.jit and mapping.path == JIT_NAME
            and (mapping.major, mapping.minor) == (0, 1)
            and type(uid) is int and uid >= 0, "invalid-jit-backing")
    directory = os.open("fd", DIR, dir_fd=process_fd)
    try:
        names = []
        with os.scandir(directory) as entries:
            for entry in entries:
                require(len(names) < MAX_PROCESS_FDS
                        and re.fullmatch(r"0|[1-9][0-9]{0,9}", entry.name), "process-fd-limit")
                names.append(entry.name)
        for name in names:
            try:
                target = os.readlink(name, dir_fd=directory)
            except FileNotFoundError:
                # Unrelated descriptors can close during enumeration. None is
                # evidence unless an actually retained matching object opens.
                continue
            require(len(target) <= 4096, "process-fd-link-limit")
            if target != JIT_NAME:
                continue
            # Intentional kernel /proc/PID/fd alias, never a supplied FD number.
            opened = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            try:
                before = os.fstat(opened)
                if (os.major(before.st_dev), os.minor(before.st_dev), before.st_ino) != (
                        mapping.major, mapping.minor, mapping.inode):
                    continue
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 0 and before.st_uid == uid,
                        "untrusted-jit-backing")
                seals = fcntl.fcntl(opened, fcntl.F_GET_SEALS)
                require(seals == fcntl.F_SEAL_SEAL, "unsupported-jit-seals")
                current = os.stat(name, dir_fd=directory)
                after = os.fstat(opened)
                def stamp(info):
                    return info.st_dev, info.st_ino, info.st_uid, info.st_nlink, info.st_mode
                require(os.readlink(name, dir_fd=directory) == JIT_NAME
                        and stamp(before) == stamp(current) == stamp(after), "jit-backing-changed")
                return stamp(after)
            finally:
                os.close(opened)
        require(False, "jit-backing-not-retained")
    finally:
        os.close(directory)


def diagnostics_disabled(raw):
    """Inspect only the selected flag; never return or log environment content."""
    require(type(raw) is bytes and 0 < len(raw) <= ENV_LIMIT and raw.endswith(b"\x00"),
            "invalid-process-environment")
    selected = [entry for entry in raw.split(b"\x00") if entry.startswith(b"DOTNET_EnableDiagnostics=")]
    require(selected == [b"DOTNET_EnableDiagnostics=0"], "process-diagnostics-enabled")


def enforce_label(raw, expected):
    require(type(raw) is bytes and len(raw) <= 1024
            and raw in ((expected + " (enforce)").encode(), (expected + " (enforce)\n").encode()),
            "process-apparmor-profile")


def restrict_status(raw):
    require(type(raw) is bytes and 0 < len(raw) <= kernel.STATUS_LIMIT, "invalid-process-security-status")
    lines = raw.splitlines()
    nnp = [line for line in lines if line.startswith(b"NoNewPrivs:")]
    caps = [line for line in lines if line.startswith(b"CapEff:")]
    require(len(nnp) == len(caps) == 1
            and re.fullmatch(rb"NoNewPrivs:[ \t]+1", nnp[0])
            and re.fullmatch(rb"CapEff:[ \t]+0000000000000000", caps[0]), "process-privilege-state")


def _directory(info):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and not stat.S_IMODE(info.st_mode) & 0o022, "untrusted-process-root-directory")


@contextmanager
def _proc(pid):
    require(worker.positive(pid), "invalid-process-id")
    proc = os.open("/proc", DIR)
    process = -1
    try:
        process = os.open(str(pid), DIR, dir_fd=proc)
        yield process
    finally:
        if process >= 0:
            os.close(process)
        os.close(proc)


@contextmanager
def _view(root, path, *, directory=False):
    """Traverse a kernel-acquired process-root FD without user symlinks."""
    require(worker.absolute_path(path), "invalid-process-root-path")
    parts = PurePosixPath(path).parts[1:]
    fd = os.dup(root)
    try:
        _directory(os.fstat(fd))
        for index, part in enumerate(parts):
            is_directory = directory or index < len(parts) - 1
            following = os.open(part, DIR if is_directory else FILE, dir_fd=fd)
            os.close(fd)
            fd = following
            if is_directory:
                _directory(os.fstat(fd))
        yield fd
    finally:
        os.close(fd)


def _same_file(root, path, host):
    with _view(root, path) as fd:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not stat.S_IMODE(info.st_mode) & 0o022
                and not info.st_mode & (stat.S_ISUID | stat.S_ISGID)
                and (info.st_dev, info.st_ino, info.st_size) == (host.device, host.inode, host.size),
                "process-root-file-mismatch")


def _view_inventory(root, proof, uid):
    """Compare closed startup/code names, including absence of .env/.path extras.

    The mutable _diag directory contents are never opened as code evidence.
    Recovery or other unrelated private mounts need not match the host view.
    """
    names = set(proof.files) | set(proof.symlinks) | set(proof.directories) | set(proof.runtime_directories)
    for directory in (proof.runner_root, *proof.directories):
        expected = {PurePosixPath(path).name for path in names if str(PurePosixPath(path).parent) == directory}
        with _view(root, directory, directory=True) as fd:
            with os.scandir(fd) as entries:
                actual = set()
                for entry in entries:
                    actual.add(entry.name)
                    require(len(actual) <= installation.MAX_ENTRIES, "process-root-inventory-limit")
            require(actual == expected, "process-root-inventory-mismatch")
    for path, target in proof.symlinks.items():
        with _view(root, str(PurePosixPath(path).parent), directory=True) as fd:
            info = os.stat(PurePosixPath(path).name, dir_fd=fd, follow_symlinks=False)
            require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and os.readlink(PurePosixPath(path).name, dir_fd=fd) == target,
                    "process-root-symlink-mismatch")
    for path in proof.runtime_directories:
        with _view(root, str(PurePosixPath(path).parent), directory=True) as fd:
            child = os.open(PurePosixPath(path).name, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            try:
                info = os.fstat(child)
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid
                        and stat.S_IMODE(info.st_mode) == 0o700, "process-runtime-directory")
            finally:
                os.close(child)


def _controls(policy):
    require(type(policy) is CollectorPolicy and type(policy.service) is service.ServicePolicy,
            "invalid-collector-policy")
    # The producer uses a template-hash suffix. Naming is a constraint, not
    # authority: exact profile/config bytes are independently root-selected.
    require(type(policy.profile_name) is str
            and re.fullmatch(r"lit-gh-[A-Za-z0-9_-]{1,64}-[0-9a-f]{16}", policy.profile_name),
            "invalid-collector-profile")
    result = {}
    for path, digest in ((policy.profile_path, policy.profile_sha256), (policy.config_path, policy.config_sha256)):
        require(worker.absolute_path(path) and type(digest) is str and installation.HEX.fullmatch(digest),
                "invalid-collector-policy-file")
        value = installation.trusted_file(path, max_bytes=1048576)
        require(value.sha256 == digest, "collector-policy-file-mismatch")
        result[path] = value
    require(len(result) == 2, "duplicate-collector-policy-file")
    return result


def _closure(pid, snapshot, proof, policy, hosts):
    """Acquire actual maps, effective label, flag and root-view identity."""
    total_host_bytes = sum(item.size for item in hosts.values())

    def host(path):
        nonlocal total_host_bytes
        in_runner = path == proof.runner_root or path.startswith(proof.runner_root + "/")
        require(not in_runner or path in proof.files, "mapped-runner-file-not-sealed")
        if path not in hosts:
            value = installation.trusted_file(path)
            if in_runner:
                require(value.sha256 == proof.files[path], "mapped-runner-file-not-sealed")
            total_host_bytes += value.size
            require(total_host_bytes <= MAX_HOST_BYTES, "collector-host-file-limit")
            hosts[path] = value
        return hosts[path]

    with _proc(pid) as fd:
        before = worker.parse_proc_stat(kernel.bounded_file(fd, "stat", worker.MAX_STAT_BYTES))
        require((before.pid, before.ppid, before.start_ticks)
                == (snapshot.stat.pid, snapshot.stat.ppid, snapshot.stat.start_ticks), "collector-process-changed")
        role = ("listener" if snapshot.executable == proof.listener.path else
                "worker" if snapshot.executable == proof.worker.path else None)
        mapped = parse_maps(kernel.bounded_file(fd, "maps", MAPS_LIMIT), role=role)
        require(any(item.path == snapshot.executable
                    and (item.major, item.minor, item.inode)
                    == (os.major(snapshot.exe_device), os.minor(snapshot.exe_device), snapshot.exe_inode)
                    for item in mapped), "process-executable-not-mapped")
        attr = os.open("attr", DIR, dir_fd=fd)
        try:
            enforce_label(kernel.bounded_file(attr, "current", 1024), policy.profile_name)
        finally:
            os.close(attr)
        diagnostics_disabled(kernel.bounded_file(fd, "environ", ENV_LIMIT))
        restrict_status(kernel.bounded_file(fd, "status", kernel.STATUS_LIMIT))
        # root is a deliberate /proc kernel magic-link exception, never a job path.
        root = os.open("root", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fd)
        try:
            _view_inventory(root, proof, policy.service.installation.service_uid)
            for path, digest in proof.files.items():
                value = host(path)
                require(value.sha256 == digest, "runner-file-changed")
                _same_file(root, path, value)
            for path in (policy.profile_path, policy.config_path):
                _same_file(root, path, host(path))
            for item in mapped:
                if item.jit:
                    _retained_jit(fd, item, policy.service.installation.service_uid)
                    continue
                value = host(item.path)
                require((os.major(value.device), os.minor(value.device), value.inode)
                        == (item.major, item.minor, item.inode), "mapped-file-backing-mismatch")
                _same_file(root, item.path, value)
        finally:
            os.close(root)
        after = worker.parse_proc_stat(kernel.bounded_file(fd, "stat", worker.MAX_STAT_BYTES))
        require((before.pid, before.ppid, before.start_ticks) == (after.pid, after.ppid, after.start_ticks),
                "collector-process-changed")
    return mapped


def collect_worker(connected_unix_socket, policy):
    """Root IO only; no caller PID/snapshot, bypass flag, daemon or grant API."""
    require(os.geteuid() == 0, "root-collector-required")
    try:
        controls = _controls(policy)
        peer = kernel.read_peer(connected_unix_socket)
        install_policy = policy.service.installation
        require(peer.uid == install_policy.service_uid, "collector-peer-uid")
        initial_service = service.read_service(policy.service)
        proof = installation.verify_installation(install_policy)
        require(initial_service.service_uid == install_policy.service_uid
                and proof.runner_root == install_policy.root, "collector-service-identity")
        boot = kernel.read_boot_id()
        first = kernel.read_chain(peer.pid, initial_service.main_pid)
        lineage = worker.LineagePolicy(initial_service.main_pid, install_policy.service_uid,
                                       install_policy.runner_id, initial_service.cgroup,
                                       proof.main, proof.node, proof.listener, proof.worker)
        binding = worker.verify_lineage(lineage, peer_pid=peer.pid, peer_uid=peer.uid, boot_id=boot,
                                        snapshots=first, confirmed_snapshots=first, confirmed_boot_id=boot)
        order, current = [], binding.pid
        while current != initial_service.main_pid:
            order.append(current)
            current = first[current].stat.ppid
        order.append(current)
        require(len(order) == 4, "collector-service-layout")
        hosts = dict(controls)
        closures = {pid: _closure(pid, first[pid], proof, policy, hosts) for pid in order}
        second = kernel.read_chain(peer.pid, initial_service.main_pid)
        require(set(second) == set(first), "collector-lineage-changed")
        for pid in order:
            require(_closure(pid, second[pid], proof, policy, hosts) == closures[pid], "collector-maps-changed")
        final_proof = installation.verify_installation(install_policy)
        require(final_proof == proof and service.read_service(policy.service) == initial_service
                and _controls(policy) == controls, "collector-trust-changed")
        final_peer, final_boot = kernel.read_peer(connected_unix_socket), kernel.read_boot_id()
        require(final_peer == peer, "collector-peer-changed")
        return worker.verify_lineage(lineage, peer_pid=peer.pid, peer_uid=peer.uid, boot_id=boot,
                                     snapshots=first, confirmed_snapshots=second, confirmed_boot_id=final_boot)
    except (OSError, ValueError, KeyError, TypeError):
        raise Denied("collector-acquisition-denied") from None
