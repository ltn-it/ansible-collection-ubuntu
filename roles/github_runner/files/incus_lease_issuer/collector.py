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
import pwd
from pathlib import PurePosixPath
import re
import stat
from types import MappingProxyType

from . import identity
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
IO_URING_NAME = "anon_inode:[io_uring]"
IO_URING_OFFSETS = (0, 0x10000000)


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
    io_uring: bool = False
    offsets: tuple[int, ...] = ()


def parse_maps(raw, *, role=None):
    """Only canonical named regular-file coordinates or inode0 anonymous areas."""
    require(type(raw) is bytes and 0 < len(raw) <= MAPS_LIMIT, "invalid-process-maps")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError:
        raise Denied("invalid-process-maps") from None
    require(0 < len(lines) <= MAX_MAPPINGS, "invalid-process-maps")
    found, ring_offsets = {}, {}
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
        jit, ring = path == JIT_NAME, path == IO_URING_NAME
        if ring:
            require(role == "node" and permissions == "rw-s" and major == 0 and minor > 0,
                    "unsupported-io-uring-mapping")
            position = int(offset, 16)
            key = (path, major, minor, number)
            offsets = ring_offsets.setdefault(key, set())
            require(position in IO_URING_OFFSETS and position not in offsets, "unsupported-io-uring-offsets")
            offsets.add(position)
        elif jit:
            require(role in {"listener", "worker"} and permissions in JIT_PERMISSIONS
                    and (major, minor) == (0, 1), "unsupported-jit-mapping")
        else:
            require(worker.absolute_path(path) and not any(c.isspace() for c in path)
                    and "\\" not in path and "memfd:" not in path and not path.endswith("(deleted)"),
                    "unsupported-file-mapping")
        record = MappedFile(path, major, minor, number, jit, ring)
        key = (path, major, minor, number) if ring else path
        require(key not in found or found[key] == record, "mapping-backing-changed")
        found[key] = record
        require(len(found) <= MAX_NAMED_FILES, "process-map-limit")
    for key, offsets in ring_offsets.items():
        require(offsets == set(IO_URING_OFFSETS), "incomplete-io-uring-mapping")
        value = found[key]
        found[key] = MappedFile(value.path, value.major, value.minor, value.inode,
                                io_uring=True, offsets=IO_URING_OFFSETS)
    return tuple(sorted(found.values(), key=lambda row: (row.path, row.major, row.minor, row.inode)))


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



def _retained_io_uring(process_fd, mapping, uid, gid):
    """Retain only the managed Node's exact non-executable kernel data object.

    An O_PATH handle never reads/submits ring data. The kernel-generated label,
    map coordinates and repeated same-PID alias metadata must identify the same
    type-zero anon inode; regular files, memfds and other anonymous types deny.
    This is data backing evidence, never a substitute for sealed code hashes.
    """
    require(type(mapping) is MappedFile and mapping.io_uring and not mapping.jit
            and mapping.path == IO_URING_NAME and mapping.major == 0 and mapping.minor > 0
            and mapping.offsets == IO_URING_OFFSETS
            and type(uid) is int and uid >= 0 and type(gid) is int and gid >= 0,
            "invalid-io-uring-backing")
    directory = os.open("fd", DIR, dir_fd=process_fd)
    try:
        names = []
        with os.scandir(directory) as entries:
            for entry in entries:
                require(len(names) < MAX_PROCESS_FDS
                        and re.fullmatch(r"0|[1-9][0-9]{0,9}", entry.name), "process-fd-limit")
                names.append(entry.name)
        def stamp(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                    info.st_gid, info.st_nlink, info.st_size)
        for name in names:
            try:
                target = os.readlink(name, dir_fd=directory)
            except FileNotFoundError:
                continue
            require(len(target) <= 4096, "process-fd-link-limit")
            if target != IO_URING_NAME:
                continue
            try:
                before = os.stat(name, dir_fd=directory)
            except FileNotFoundError:
                continue
            if (os.major(before.st_dev), os.minor(before.st_dev), before.st_ino) != (
                    mapping.major, mapping.minor, mapping.inode):
                continue
            # Intentional kernel /proc/PID/fd alias of this same process only.
            opened = os.open(name, os.O_PATH | os.O_CLOEXEC, dir_fd=directory)
            try:
                held = os.fstat(opened)
                require(stat.S_IFMT(held.st_mode) == 0 and stat.S_IMODE(held.st_mode) == 0o600
                        and held.st_uid == uid and held.st_gid == gid
                        and held.st_nlink == 1 and held.st_size == 0, "untrusted-io-uring-backing")
                current = os.stat(name, dir_fd=directory)
                after = os.fstat(opened)
                require(os.readlink(name, dir_fd=directory) == IO_URING_NAME
                        and stamp(before) == stamp(held) == stamp(current) == stamp(after),
                        "io-uring-backing-changed")
                return stamp(after)
            finally:
                os.close(opened)
        require(False, "io-uring-backing-not-retained")
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


def _same_regular_file(fd, host):
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and not stat.S_IMODE(info.st_mode) & 0o022
            and not info.st_mode & (stat.S_ISUID | stat.S_ISGID)
            and (info.st_dev, info.st_ino, info.st_size) == (host.device, host.inode, host.size),
            "process-root-file-mismatch")


def _same_file(root, path, host):
    with _view(root, path) as fd:
        _same_regular_file(fd, host)


@dataclass(frozen=True)
class _TreeLayout:
    proof: installation.InstallationProof
    files: frozenset
    directories: frozenset
    links: MappingProxyType
    runtime: frozenset


def _tree_layout(proof):
    """Validate immutable same-call proof bindings once, never process snapshots."""
    require(type(proof) is installation.InstallationProof
            and all(type(value) is MappingProxyType for value in (proof.files, proof.symlinks,
                proof.trusted_files, proof.file_stamps, proof.tree_stamps, proof.runtime_stamps))
            and type(proof.directories) is tuple and type(proof.runtime_directories) is tuple,
            "process-root-immutable-evidence")
    prefix = proof.runner_root + "/"
    require(type(proof) is installation.InstallationProof
            and set(proof.trusted_files) == set(proof.files)
            and set(proof.file_stamps) == set(proof.files), "process-root-file-evidence")
    require(all(path.startswith(prefix) for path in set(proof.files) | set(proof.symlinks)
                | set(proof.directories) | set(proof.runtime_directories)), "process-root-inventory-path")
    expected_files = {path[len(prefix):] for path in proof.files}
    expected_dirs = {path[len(prefix):] for path in proof.directories}
    expected_links = {path[len(prefix):]: target for path, target in proof.symlinks.items()}
    expected_runtime = {path[len(prefix):] for path in proof.runtime_directories}
    require(set(proof.tree_stamps) == {"."} | expected_files | expected_dirs | set(expected_links)
            and set(proof.runtime_stamps) == expected_runtime, "process-root-tree-evidence")
    require(all(type(stamp) is tuple and len(stamp) == 9
                and all(type(part) is int for part in stamp) for stamp in proof.tree_stamps.values())
            and all(type(stamp) is tuple and len(stamp) == 5
                and all(type(part) is int for part in stamp) for stamp in proof.runtime_stamps.values()),
            "process-root-tree-evidence")
    for path, value in proof.trusted_files.items():
        stamp = proof.file_stamps[path]
        require(type(value) is installation.TrustedFile and value.path == path
                and value.sha256 == proof.files[path] and type(stamp) is tuple and len(stamp) == 9
                and (value.device, value.inode, value.size) == (stamp[0], stamp[1], stamp[6])
                and stamp == proof.tree_stamps[path[len(prefix):]], "process-root-file-evidence")
    return _TreeLayout(proof, frozenset(expected_files), frozenset(expected_dirs),
                       MappingProxyType(expected_links), frozenset(expected_runtime))


def _view_inventory(root, layout, uid):
    """Fresh FD-anchored process tree scan; no namespace observations are cached."""
    require(type(layout) is _TreeLayout, "process-root-layout")
    proof = layout.proof
    with _view(root, proof.runner_root, directory=True) as fd:
        before = installation._stamp(os.fstat(fd))
        require(before == proof.tree_stamps["."], "process-root-directory-changed")
        files, directories, links, stamps, _, runtime = installation._inventory(
            fd, proof.runner_root, hash_files=False, service_uid=uid)
        require(set(files) == layout.files and directories == layout.directories and links == layout.links
                and set(runtime) == layout.runtime, "process-root-inventory-mismatch")
        require(stamps == proof.tree_stamps and runtime == proof.runtime_stamps,
                "process-root-tree-changed")
        require(installation._stamp(os.fstat(fd)) == before, "process-root-directory-changed")
        # Reject path replacement instead of accepting only a detached retained FD.
        with _view(root, proof.runner_root, directory=True) as confirmed:
            require(installation._stamp(os.fstat(confirmed)) == before, "process-root-directory-changed")


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


def _closure(pid, snapshot, proof, policy, hosts, layout):
    """Acquire actual maps, effective label, flag and root-view identity."""
    require(type(layout) is _TreeLayout and layout.proof is proof, "process-root-layout-binding")
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
                "worker" if snapshot.executable == proof.worker.path else
                "node" if snapshot.executable == proof.node.path else None)
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
            _view_inventory(root, layout, policy.service.installation.service_uid)
            for path in (policy.profile_path, policy.config_path):
                _same_file(root, path, host(path))
            for item in mapped:
                if item.io_uring:
                    account = pwd.getpwnam(policy.service.service_user)
                    require(account.pw_uid == policy.service.installation.service_uid, "io-uring-service-user")
                    _retained_io_uring(fd, item, account.pw_uid, account.pw_gid)
                    continue
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


@identity._diagnostic_step("collector")
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
        layout = _tree_layout(proof)
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
        # Only this call's completed fresh stock verification seeds its existing
        # host cache. Namespace checks and the second full stock hash remain fresh.
        require(set(proof.trusted_files) == set(proof.files)
                and set(proof.file_stamps) == set(proof.files), "collector-stock-file-evidence")
        hosts.update(proof.trusted_files)
        closures = {pid: _closure(pid, first[pid], proof, policy, hosts, layout) for pid in order}
        second = kernel.read_chain(peer.pid, initial_service.main_pid)
        require(set(second) == set(first), "collector-lineage-changed")
        for pid in order:
            require(_closure(pid, second[pid], proof, policy, hosts, layout) == closures[pid], "collector-maps-changed")
        final_proof = installation.verify_installation(install_policy)
        require(final_proof == proof and service.read_service(policy.service) == initial_service
                and _controls(policy) == controls, "collector-trust-changed")
        final_peer, final_boot = kernel.read_peer(connected_unix_socket), kernel.read_boot_id()
        require(final_peer == peer, "collector-peer-changed")
        return worker.verify_lineage(lineage, peer_pid=peer.pid, peer_uid=peer.uid, boot_id=boot,
                                     snapshots=first, confirmed_snapshots=second, confirmed_boot_id=final_boot)
    except (OSError, ValueError, KeyError, TypeError) as error:
        identity._diagnostic_failed("collector", error)
        raise Denied("collector-acquisition-denied") from None
