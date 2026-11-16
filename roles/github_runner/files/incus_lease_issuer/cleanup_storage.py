"""Exact Root-owned raw storage release after verified execution withdrawal.

Only the finalizer calls these factories. Immutable Root creator evidence binds
the three original directory inodes and context contents. Descendants are
untrusted: traversal uses directory FDs, never follows links or crosses mounts.
No prefix scan, arbitrary path, mount teardown or destructive retry is exposed.
The separately bounded public-evidence sibling is deliberately retained.
"""
from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import time
import ctypes
import platform
import re
import threading
import struct
import weakref

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import (cell_contract, engine_executor, engine_policy as engine, identity,
               installation, ledger, preparation, signed_context, storage_quota)
from .identity import Denied, require


class CleanupStorageUnknown(Denied):
    """Possible owned deletion retained in the journal; never retry here."""


@dataclass(frozen=True)
class StorageReceipt:
    lease_id: str
    operation: str
    evidence_sha256: str


def _fresh(owner, store, config):
    if type(owner) is cell_contract.PartialPreparationOwner:
        from . import operating_custody
        require(os.geteuid() == 0 and type(store) is ledger.Ledger and store.owner_uid == 0
                and type(config) is preparation.RootConfiguration, "partial-storage-root-inputs")
        require(preparation._config(config.path, config.sha256)[0] == config
                and (owner.registry.path, owner.registry.sha256) == (config.registry_path, config.registry_sha256)
                and cell_contract.partial_preparation_owner(owner.registry, owner.selector, store, owner.lease_id) == owner,
                "partial-storage-owner-drift")
        # During our own one cleanup intent, policy remains checked against the
        # same immutable retention value; unknown effects are always denied by
        # the partial-owner factory, no intent is re-sent by _effect.
        record = store.read(owner.lease_id)
        retained = operating_custody._partial_custody_record(record.get("partial_preparation_custody"), record,
                                                            store.read_policy(record["policy_sha256"]))
        require(store._now() >= retained["retain_until"], "partial-storage-retention")
        return record
    require(os.geteuid() == 0 and type(owner) is cell_contract.OwnedCellForCleanup
            and type(store) is ledger.Ledger and store.owner_uid == 0
            and type(config) is preparation.RootConfiguration, "cleanup-storage-root-inputs")
    require(preparation._config(config.path, config.sha256)[0] == config
            and owner.registry.path == config.registry_path
            and owner.registry.sha256 == config.registry_sha256
            and cell_contract.owned_cell_for_cleanup(owner.registry, owner.selector, store, owner.lease_id) == owner,
            "cleanup-storage-owner-drift")
    return store.read(owner.lease_id)


def _effect(record, operation, target):
    found = [(key, value) for key, value in record["effects"].items()
             if value["operation"] == operation]
    require(len(found) <= 1, "cleanup-storage-ambiguous-effect")
    if not found:
        return None
    require(found[0][1]["target"] == target and found[0][1]["state"] == "verified",
            "cleanup-storage-unresolved-effect")
    return found[0]


def _cleanup_limits(config):
    policy, _, _ = storage_quota._policy(config.storage_quota_policy_path, config.storage_quota_policy_sha256)
    return min(policy["max_inodes"] * 4, 1000000), config.operation_wait_seconds


def _identity(info):
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid, info.st_gid


def _deadline(end):
    require(time.monotonic() < end, "cleanup-storage-budget")


@contextmanager
def _fresh_entries(root):
    fd = os.open(".", installation.DIR_FLAGS, dir_fd=root)
    try:
        require(_identity(os.fstat(fd)) == _identity(os.fstat(root))
                and storage_quota._mount_id(fd) == storage_quota._mount_id(root),
                "cleanup-storage-directory-replaced")
        with os.scandir(fd) as entries:
            yield entries
    finally:
        os.close(fd)


def _directory_at(root, components, identities, mount_id):
    # A fresh open file description avoids sharing readdir state with another
    # observer of the pinned directory FD. Never reopen via a mutable pathname.
    fd = os.open(".", installation.DIR_FLAGS, dir_fd=root)
    try:
        require(_identity(os.fstat(fd)) == identities[()]
                and storage_quota._mount_id(fd) == mount_id, "cleanup-storage-root-replaced")
        for index, name in enumerate(components):
            child = os.open(name, installation.DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            require(_identity(os.fstat(fd)) == identities[components[:index + 1]]
                    and storage_quota._mount_id(fd) == mount_id, "cleanup-storage-directory-replaced")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _inventory_tree(root, end, maximum):
    """Metadata-only bounded inventory; O_PATH never opens device contents."""
    mount_id = storage_quota._mount_id(root)
    identities, nodes, pending = {(): _identity(os.fstat(root))}, [], [()]
    while pending:
        _deadline(end)
        components = pending.pop()
        require(len(components) <= 256, "cleanup-storage-depth")
        fd = _directory_at(root, components, identities, mount_id)
        try:
            with _fresh_entries(fd) as entries:
                for entry in entries:
                    name = entry.name
                    _deadline(end)
                    require(type(name) is str and name not in {"", ".", ".."} and "/" not in name,
                            "cleanup-storage-entry")
                    path = components + (name,)
                    observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    leaf = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        require(_identity(os.fstat(leaf)) == _identity(observed)
                                and observed.st_dev == os.fstat(root).st_dev
                                and storage_quota._mount_id(leaf) == mount_id, "cleanup-storage-foreign-mount")
                    finally:
                        os.close(leaf)
                    require(len(nodes) < maximum, "cleanup-storage-entry-limit")
                    identities[path] = _identity(observed)
                    nodes.append((path, _identity(observed), stat.S_ISDIR(observed.st_mode)))
                    if stat.S_ISDIR(observed.st_mode):
                        pending.append(path)
        finally:
            os.close(fd)
    return tuple(nodes), identities, mount_id


class _Timestamp(ctypes.Structure):
    _fields_ = [('seconds', ctypes.c_int64), ('nanoseconds', ctypes.c_uint32), ('reserved', ctypes.c_int32)]

class _Statx(ctypes.Structure):
    _fields_ = [('mask', ctypes.c_uint32), ('blksize', ctypes.c_uint32), ('attributes', ctypes.c_uint64), ('nlink', ctypes.c_uint32), ('uid', ctypes.c_uint32), ('gid', ctypes.c_uint32), ('mode', ctypes.c_uint16), ('spare0', ctypes.c_uint16), ('ino', ctypes.c_uint64), ('size', ctypes.c_uint64), ('blocks', ctypes.c_uint64), ('attributes_mask', ctypes.c_uint64), ('atime', _Timestamp), ('btime', _Timestamp), ('ctime', _Timestamp), ('mtime', _Timestamp), ('rdev_major', ctypes.c_uint32), ('rdev_minor', ctypes.c_uint32), ('dev_major', ctypes.c_uint32), ('dev_minor', ctypes.c_uint32), ('mount_id', ctypes.c_uint64), ('dio_mem_align', ctypes.c_uint32), ('dio_offset_align', ctypes.c_uint32), ('spare3', ctypes.c_uint64 * 12)]
_LIBC = ctypes.CDLL(None, use_errno=True)
_STATX = getattr(_LIBC, 'statx', None)
if _STATX is not None:
    _STATX.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint, ctypes.POINTER(_Statx)]
    _STATX.restype = ctypes.c_int

def _relative_metadata(parent, name):
    """One no-follow relative stat+mount query; unsupported kernels fail closed."""
    require(type(name) is str and name not in {'', '.', '..'} and ('/' not in name) and ('\x00' not in name), 'cleanup-storage-entry')
    require(platform.system() == 'Linux' and platform.machine() in {'x86_64', 'aarch64'} and (ctypes.sizeof(ctypes.c_void_p) == 8) and (ctypes.sizeof(_Statx) == 256) and (_Statx.mount_id.offset == 144), 'cleanup-storage-statx-layout')
    value = _Statx()
    call = _STATX
    require(call is not None, 'cleanup-storage-statx-unavailable')
    require(call(parent, os.fsencode(name), 256 | 2048, 2047 | 4096, ctypes.byref(value)) == 0, 'cleanup-storage-statx-denied')
    require(value.mask & 4377 == 4377 and value.mount_id > 0, 'cleanup-storage-statx-mount-unavailable')
    return ((os.makedev(value.dev_major, value.dev_minor), value.ino, stat.S_IFMT(value.mode), value.uid, value.gid), value.mount_id)

class _PinnedAncestry:
    """At most root+256 directory FDs; validate named chain on EVERY operation."""

    def __init__(self, root, identities, mount_id):
        self.identities, self.mount_id = (identities, mount_id)
        self.components, self.fds = ((), [])
        fd = os.open('.', installation.DIR_FLAGS, dir_fd=root)
        self.fds.append(fd)
        try:
            require(_identity(os.fstat(fd)) == identities[()] and storage_quota._mount_id(fd) == mount_id, 'cleanup-storage-root-replaced')
        except BaseException:
            self.close()
            raise

    def close(self):
        while self.fds:
            os.close(self.fds.pop())
        self.components = ()

    def trim(self, length):
        while len(self.fds) > length + 1:
            os.close(self.fds.pop())
        self.components = self.components[:length]

    def entry(self, parent, name, expected, *, reason="cleanup-storage-entry-replaced"):
        actual, mount = _relative_metadata(parent, name)
        require(actual == expected and mount == self.mount_id, reason)

    def directory(self, components, end):
        _deadline(end)
        require(type(components) is tuple and len(components) <= 256, 'cleanup-storage-depth')
        common = 0
        for left, right in zip(components, self.components):
            if left != right:
                break
            common += 1
        self.trim(common)
        require(_identity(os.fstat(self.fds[0])) == self.identities[()], 'cleanup-storage-root-replaced')
        for index, name in enumerate(components):
            _deadline(end)
            path = components[:index + 1]
            parent = self.fds[index]
            self.entry(parent, name, self.identities[path], reason="cleanup-storage-directory-replaced")
            if index + 1 == len(self.fds):
                fd = os.open(name, installation.DIR_FLAGS, dir_fd=parent)
                self.fds.append(fd)
                require(len(self.fds) <= 257, 'cleanup-storage-fd-cap')
                require(storage_quota._mount_id(fd) == self.mount_id, 'cleanup-storage-directory-replaced')
                self.entry(parent, name, self.identities[path], reason="cleanup-storage-directory-replaced")
            require(_identity(os.fstat(self.fds[index + 1])) == self.identities[path], 'cleanup-storage-directory-replaced')
        self.components = components
        return self.fds[-1]

_SYNCFS = getattr(_LIBC, 'syncfs', None)

if _SYNCFS is not None:
    _SYNCFS.argtypes = [ctypes.c_int]
    _SYNCFS.restype = ctypes.c_int

def _syncfs_ready(root, identity, mount_id, end):
    """Complete exact pinned filesystem writeback BEFORE directory batch."""
    _deadline(end)
    release = platform.release().split('.')
    require(len(release) >= 2 and release[0].isdigit() and release[1].isdigit() and ((int(release[0]), int(release[1])) >= (5, 8)), 'cleanup-storage-syncfs-kernel')
    require(_SYNCFS is not None, 'cleanup-storage-syncfs-unavailable')
    require(_identity(os.fstat(root)) == identity and storage_quota._mount_id(root) == mount_id, 'cleanup-storage-root-replaced')

def _sync_depth(root, identity, mount_id, end):
    _syncfs_ready(root, identity, mount_id, end)
    require(_SYNCFS(root) == 0, 'cleanup-storage-syncfs-denied')
    require(_identity(os.fstat(root)) == identity and storage_quota._mount_id(root) == mount_id, 'cleanup-storage-root-replaced')
    _deadline(end)

def _remove_tree(root, inventory, end):
    """Depth barriers preserve children-durable BEFORE parent-rmdir semantics."""
    nodes, identities, mount_id = inventory
    require(_identity(os.fstat(root)) == identities[()] and storage_quota._mount_id(root) == mount_id, 'cleanup-storage-root-replaced')
    _syncfs_ready(root, identities[()], mount_id, end)
    batches = {}
    for path, expected, directory in nodes:
        require(1 <= len(path) <= 257, 'cleanup-storage-depth')
        batch = batches.setdefault(len(path), ([], []))
        batch[1 if directory else 0].append((path, expected))
    cache = _PinnedAncestry(root, identities, mount_id)
    removed, directory_count, barriers = (0, 0, 0)
    try:
        for depth in sorted(batches, reverse=True):
            files, directories = batches[depth]
            for path, expected in files:
                _deadline(end)
                parent = cache.directory(path[:-1], end)
                cache.entry(parent, path[-1], expected)
                os.unlink(path[-1], dir_fd=parent)
                removed += 1
            if directories:
                _sync_depth(root, identities[()], mount_id, end)
                barriers += 1
                for path, expected in directories:
                    _deadline(end)
                    parent = cache.directory(path[:-1], end)
                    cache.entry(parent, path[-1], expected)
                    cache.directory(path, end)
                    _deadline(end)
                    cache.trim(len(path) - 1)
                    os.rmdir(path[-1], dir_fd=parent)
                    removed += 1
                    directory_count += 1
        cache.trim(0)
        with _fresh_entries(root) as entries:
            require(next(entries, None) is None, 'cleanup-storage-new-entry')
        _deadline(end)
        os.fsync(root)
        require(_identity(os.fstat(root)) == identities[()] and storage_quota._mount_id(root) == mount_id, 'cleanup-storage-root-replaced')
        _deadline(end)
        return None
    finally:
        cache.close()


def _absent(paths):
    for path in paths:
        parent = engine._directory(str(PurePosixPath(path).parent), private=True)
        try:
            require(PurePosixPath(path).name not in os.listdir(parent), "cleanup-storage-returned-path")
        finally:
            os.close(parent)


def _drain_engine(owner, store, config):
    from . import runtime_rpc
    record = _fresh(owner, store, config)
    require(_effect(record, "engine-stop", "engine:lit-lease-" + owner.lease_id) is not None
            and _effect(record, "fence-disable", "fence:" + owner.lease_id) is not None,
            "cleanup-storage-withdrawal-required")
    receipt = runtime_rpc._receipt(owner.registry, owner.selector, store, owner.lease_id)
    manifest, _, effect = engine_executor._retained(config, owner.registry, owner.selector,
                                                   store, owner.lease_id, receipt)
    require(effect == record["effects"][owner.creators["engine-start"]["id"]]
            and "engine_exit" in effect, "cleanup-storage-original-exit")
    ledger._validate_engine_exit(effect["engine_exit"], effect)
    engine_executor._drained(manifest, effect["engine_capture"])
    return manifest, effect


def _mark_unknown(store, owner, effect, operation):
    try:
        store.record(owner.lease_id, effect, "unknown", evidence_sha256=ledger.digest({
            "component": "cleanup-storage", "operation": operation, "state": "unknown"}))
    except Exception:
        pass


def _published_cleanup_after_failure(store, identifier, operation, target):
    """A failed API return is not proof that its atomic publication failed."""
    record = store.read(identifier)
    candidates = [key for key, row in record['effects'].items()
                  if row['operation'] == operation and row['target'] == target
                  and (row['state'] in {'intent', 'unknown'} or 'cleanup_postcheck' in row)]
    require(len(candidates) <= 1, 'cleanup-storage-publication-ambiguous')
    return candidates[0] if candidates else None


def _consumer_read(path, limit, end):
    """Proc seq files may return a short non-EOF chunk even for large reads."""
    _deadline(end)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        chunks, size = [], 0
        while True:
            _deadline(end)
            chunk = os.read(fd, min(65536, limit + 1 - size))
            if not chunk:
                return b"".join(chunks)
            size += len(chunk)
            require(size <= limit, "cleanup-consumers-read-bound")
            chunks.append(chunk)
    finally:
        os.close(fd)


def _consumer_mount_rows(raw, end=None):
    rows = []
    for line in raw.decode("utf-8", "strict").splitlines():
        if end is not None:
            _deadline(end)
        fields = line.split()
        require(len(fields) >= 10 and "-" in fields and fields[0].isdecimal()
                and re.fullmatch(r"[0-9]+:[0-9]+", fields[2]), "cleanup-consumers-mount-shape")
        paths = []
        for value in fields[3:5]:
            require(not re.search(r"\\(?!040|011|012|134)", value), "cleanup-consumers-mount-escape")
            value = re.sub(r"\\(040|011|012|134)", lambda m: chr(int(m[1], 8)), value).removesuffix(" (deleted)")
            require(value.startswith("/") and ".." not in PurePosixPath(value).parts,
                    "cleanup-consumers-mount-path")
            paths.append(value)
        major, minor = map(int, fields[2].split(":"))
        rows.append((int(fields[0]), os.makedev(major, minor), *paths))
    require(len({r[0] for r in rows}) == len(rows), "cleanup-consumers-mount-duplicate")
    return rows


def _consumer_mount_targets(rows, pinned):
    """Translate pinned local paths to filesystem-relative roots, never host absolutes."""
    targets = []
    for path, device, mount_id in pinned:
        found = [row for row in rows if row[0] == mount_id and row[1] == device]
        require(len(found) == 1, "cleanup-consumers-original-mount")
        row = found[0]
        require(path == row[3] or path.startswith(row[3].rstrip("/") + "/"),
                "cleanup-consumers-original-path")
        relative = str(PurePosixPath(row[2]) / PurePosixPath(path).relative_to(row[3]))
        targets.append((device, relative, row[2], row[3]))
    return targets


def _consumer_mount_aliases(rows, targets, end=None):
    def contains(parent, child):
        return parent == child or child.startswith(parent.rstrip("/") + "/")
    for _, device, root, point in rows:
        if end is not None:
            _deadline(end)
        for dev, target, original_root, original_point in targets:
            if device == dev and (contains(root, target) or contains(target, root)):
                # A normal copy of the original containing mount is harmless;
                # a differently rooted/located bind (including an ancestor) is not.
                require((root, point) == (original_root, original_point),
                        "cleanup-consumers-mount-reference")


def _same_fd_table(tid, observer):
    if tid == observer:
        return True
    require(platform.system() == "Linux" and platform.machine() in {"x86_64", "aarch64"},
            "cleanup-consumers-kcmp-platform")
    number = {"x86_64": 312, "aarch64": 272}[platform.machine()]
    result = _LIBC.syscall(number, tid, observer, 2, 0, 0)  # linux/kcmp.h KCMP_FILES
    if result == -1 and ctypes.get_errno() == 3:
        raise ProcessLookupError()
    require(result >= 0, "cleanup-consumers-fd-table-unavailable")
    return result == 0


def _no_consumers(data, descriptor_path, lease_id, opened, end, identities, mount_targets, original_process=None):
    protected = (data["engine"]["storage_root"], data["engine"]["runroot"],
                 data["output_path"], data["context_path"], descriptor_path)
    allowed = {str(fd): _identity(os.fstat(fd)) for fd in opened if stat.S_ISDIR(os.fstat(fd).st_mode)}
    def referenced(value):
        value = value.removesuffix(" (deleted)")
        return any(value == root or value.startswith(root + "/") for root in protected)
    def read(path, limit):
        return _consumer_read(path, limit, end)
    def stamp(proc):
        raw = read(proc / "stat", 65536)
        suffix = raw.rsplit(b")", 1)
        require(len(suffix) == 2 and len(suffix[1].split()) >= 20, "cleanup-consumers-process-stat")
        fields = suffix[1].split()
        return fields[19], fields[0]
    def task_inventory(leader, maximum):
        tasks = []
        for task in (leader / "task").iterdir():
            _deadline(end)
            require(task.name.isdecimal() and len(tasks) < maximum, "cleanup-consumers-task-bound")
            tasks.append(task)
        require(tasks, "cleanup-consumers-task-inventory")
        return tuple(tasks)
    observer = threading.get_native_id()
    count = total_fds = leaders = 0
    namespaces = set()
    for leader in Path("/proc").iterdir():
        if not leader.name.isdecimal():
            continue
        _deadline(end)
        leaders += 1
        require(leaders <= 65536, "cleanup-consumers-process-bound")
        try:
            leader_stamp = stamp(leader)
            if original_process is not None and int(leader.name) == original_process["pid"]:
                raw = read(leader / "stat", 65536).rsplit(b")", 1)[1].split()
                require(leader_stamp[0] != str(original_process["start_ticks"]).encode() or raw[0] == b"Z",
                        "cleanup-storage-engine-process-live")
            tasks = task_inventory(leader, 65536 - count)
        except (FileNotFoundError, ProcessLookupError):
            require(not leader.exists(), "cleanup-consumers-observation-race")
            continue
        for proc in tasks:
            _deadline(end)
            count += 1
            require(count <= 65536, "cleanup-consumers-task-bound")
            try:
                before = stamp(proc)
                if before[1] == b"Z":
                    # An unreaped terminal TASK has no FD table, mm or nsproxy.
                    # Prove those absences rather than skipping its whole leader;
                    # every live sibling task is still inspected independently.
                    with os.scandir(proc / "fd") as entries:
                        require(next(entries, None) is None, "cleanup-consumers-terminal-fd")
                    require(not read(proc / "maps", 4 * 1024**2).strip(),
                            "cleanup-consumers-terminal-maps")
                    for link in ("cwd", "root", "exe", "ns/mnt"):
                        try:
                            os.readlink(proc / link)
                        except FileNotFoundError:
                            pass
                        else:
                            raise Denied("cleanup-consumers-terminal-reference")
                    require(stamp(proc) == before, "cleanup-consumers-terminal-changed")
                    continue
                shared = False
                groups = read(proc / "cgroup", 65536)
                require(lease_id.encode() not in groups, "cleanup-consumers-owned-cgroup")
                for name in ("cwd", "root", "exe"):
                    try:
                        value = os.readlink(proc / name)
                    except FileNotFoundError:
                        # Kernel threads may lack these links; process identity is
                        # still rechecked below, and visibility errors never pass.
                        continue
                    require(not referenced(value), "cleanup-consumers-process-reference")
                mappings = read(proc / "maps", 8 * 1024**2)
                require(not any(root.encode() in mappings for root in protected), "cleanup-consumers-mapped-reference")
                for line in mappings.decode("utf-8", "strict").splitlines():
                    _deadline(end)
                    fields = line.split(None, 5)
                    require(len(fields) >= 5 and re.fullmatch(r"[0-9a-fA-F]+:[0-9a-fA-F]+", fields[3])
                            and fields[4].isdecimal(), "cleanup-consumers-maps-shape")
                    major, minor = (int(v, 16) for v in fields[3].split(":"))
                    require((os.makedev(major, minor), int(fields[4])) not in identities,
                            "cleanup-consumers-mapped-reference")
                fds = []
                for descriptor in (proc / "fd").iterdir():
                    _deadline(end)
                    fds.append(descriptor)
                    total_fds += 1
                    require(len(fds) <= 65536 and total_fds <= 262144, "cleanup-consumers-fd-bound")
                for descriptor in fds:
                    _deadline(end)
                    try:
                        value = os.readlink(descriptor)
                        observed = descriptor.stat()
                    except FileNotFoundError:
                        # A descriptor closed during this observation is no longer
                        # a consumer. Visibility errors on live FDs still hold.
                        continue
                    if referenced(value) or (observed.st_dev, observed.st_ino) in identities:
                        require(int(leader.name) == os.getpid() and descriptor.name in allowed
                                and _identity(os.fstat(int(descriptor.name))) == allowed[descriptor.name]
                                and _same_fd_table(int(proc.name), observer),
                                "cleanup-consumers-open-reference")
                        shared = True
                ns = (proc / "ns/mnt").stat()
                namespace = (ns.st_dev, ns.st_ino)
                if namespace not in namespaces:
                    namespaces.add(namespace)
                    require(len(namespaces) <= 4096, "cleanup-consumers-namespace-bound")
                    mountinfo = read(proc / "mountinfo", 4 * 1024**2)
                    rows = _consumer_mount_rows(mountinfo, end)
                    require(not any(referenced(row[3]) for row in rows), "cleanup-consumers-mount-reference")
                    _consumer_mount_aliases(rows, mount_targets, end)
                require(not shared or _same_fd_table(int(proc.name), observer),
                        "cleanup-consumers-fd-table-changed")
                after_ns = (proc / "ns/mnt").stat()
                require(before == stamp(proc) and namespace == (after_ns.st_dev, after_ns.st_ino),
                        "cleanup-consumers-process-replaced")
            except (FileNotFoundError, ProcessLookupError):
                require(not proc.exists(), "cleanup-consumers-observation-race")
        try:
            require(leader_stamp == stamp(leader)
                    and {p.name for p in tasks} == {p.name for p in task_inventory(leader, len(tasks))},
                    "cleanup-consumers-task-inventory-changed")
        except (FileNotFoundError, ProcessLookupError):
            require(not leader.exists(), "cleanup-consumers-observation-race")
    _deadline(end)


def _partial_no_consumers(owner, opened, end, inventories):
    require(type(owner) is cell_contract.PartialPreparationOwner, "partial-consumers-owner")
    data = identity.decode_json(owner.engine_descriptor_bytes)
    identities = {value[:2] for _, _, inventory in inventories for value in inventory[1].values()}
    pinned = [(path, inventory[1][()][0], inventory[2]) for path, _, inventory in inventories]
    rows = _consumer_mount_rows(_consumer_read(Path("/proc/self/mountinfo"), 4 * 1024**2, end), end)
    _no_consumers(data, owner.engine_descriptor_path, owner.lease_id, opened, end,
                  identities, _consumer_mount_targets(rows, pinned))


def _postcheck_observation(owner, inventories, spool, end):
    from . import kernel
    identities = {value[:2] for _, _, inventory in inventories for value in inventory[1].values()}
    parents = []
    for path, _, inventory in inventories:
        parent = str(PurePosixPath(path).parent)
        fd = engine._directory(parent, private=True)
        try:
            info = os.fstat(fd); mount = storage_quota._mount_id(fd)
            require(info.st_dev == inventory[1][()][0] and mount == inventory[2],
                    "cleanup-observation-parent-mount")
            parents.append({"path": parent, "identity": list(_identity(info)), "mount_id": mount})
        finally:
            os.close(fd)
    rows = _consumer_mount_rows(_consumer_read(Path("/proc/self/mountinfo"), 4 * 1024**2, end), end)
    pinned = [(path, inventory[1][()][0], inventory[2]) for path, _, inventory in inventories]
    packed = bytearray()
    for pair in sorted(identities):
        _deadline(end); packed.extend(struct.pack(">QQ", *pair))
    group = engine._directory("/sys/fs/cgroup", private=False)
    try:
        require(engine_executor._fs_type(group) == engine_executor.CGROUP2_MAGIC, "cleanup-observation-cgroup-filesystem")
        cgroup_root = [*_identity(os.fstat(group)), storage_quota._mount_id(group)]
    finally:
        os.close(group)
    return {"schema": 1, "paths": [row[0] for row in inventories], "parents": parents,
        "targets": [list(row) for row in _consumer_mount_targets(rows, pinned)],
        "descriptor_sha256": owner.engine_descriptor_sha256, "spool": spool,
        "deadline_monotonic": end, "boot_id": kernel.read_boot_id(), "cgroup_root": cgroup_root}, bytes(packed)


@dataclass(frozen=True, eq=False)
class _CleanupReconciliation:
    store: object
    session: object
    identifier: str
    effect_id: str
    payload: dict
    pid: int
    thread: object

_RECONCILIATIONS = weakref.WeakSet()
_RECONCILIATION_LOCK = threading.Lock()


def _consume_reconciliation(proof, store, identifier, effect_id):
    from . import root_session
    require(type(proof) is _CleanupReconciliation and proof.store is store
            and proof.identifier == identifier and proof.effect_id == effect_id
            and proof.pid == os.getpid() and proof.thread is threading.current_thread(),
            "cleanup-reconciliation-proof")
    with _RECONCILIATION_LOCK:
        require(proof in _RECONCILIATIONS, "cleanup-reconciliation-proof")
        _RECONCILIATIONS.remove(proof)
    root_session._require_session(proof.session)
    return proof.payload


def reconcile_postchecks(session, owner, store, config, cleanup):
    """GET-only original-scope resolution, never a repeated delete or timing PASS."""
    from . import root_session, kernel
    require(root_session._require_session(session) == config, "cleanup-reconciliation-session")
    record = _fresh(owner, store, config)
    from . import operating_custody
    if type(owner) is not cell_contract.PartialPreparationOwner:
        operating_custody.require_cleanup_allowed(store, owner.lease_id)
    require(not any(e["state"] in {"intent", "unknown"} for e in record["effects"].values()),
            "cleanup-reconciliation-uncertain")
    for effect_id, effect in record["effects"].items():
        if "cleanup_postcheck" not in effect:
            continue
        try:
            store.require_cleanup_postchecks(owner.lease_id)
            return  # The original process already has the complete live witnesses.
        except Denied:
            pass
        end = time.monotonic() + config.operation_wait_seconds
        require(effect["state"] == "verified", "cleanup-reconciliation-uncertain")
        value = store.read_cleanup_observation(owner.lease_id, effect_id, deadline=end)
        require(value is not None, "cleanup-reconciliation-metadata-required")
        metadata, pairs = value
        require(set(metadata) == {"schema", "paths", "parents", "targets", "descriptor_sha256", "spool",
                                  "deadline_monotonic", "boot_id", "cgroup_root"}
                and metadata["schema"] == 1 and type(metadata["schema"]) is int
                and metadata["descriptor_sha256"] == owner.engine_descriptor_sha256
                and metadata["boot_id"] == kernel.read_boot_id(), "cleanup-reconciliation-metadata")
        data = identity.decode_json(owner.engine_descriptor_bytes)
        expected = ([data["engine"]["storage_root"], data["engine"]["runroot"], data["output_path"]]
                    if effect["operation"] == "engine-release" else [data["context_path"], owner.engine_descriptor_path])
        require(metadata["paths"] == expected and len(metadata["parents"]) == len(expected),
                "cleanup-reconciliation-paths")
        spool = (str(PurePosixPath(data["engine"]["runroot"]).parent)
                 if type(owner) is cell_contract.PartialPreparationOwner else data["engine"]["runroot"] + ".public-evidence")
        require(metadata["spool"] == spool, "cleanup-reconciliation-spool")
        identities = set(struct.iter_unpack(">QQ", pairs))
        require(len(identities) * 16 == len(pairs), "cleanup-reconciliation-duplicate-inode")
        opened = []
        try:
            pinned = []
            for path, parent in zip(expected, metadata["parents"]):
                require(set(parent) == {"path", "identity", "mount_id"}
                        and parent["path"] == str(PurePosixPath(path).parent), "cleanup-reconciliation-parent")
                fd = engine._directory(parent["path"], private=True); opened.append(fd)
                info = os.fstat(fd)
                require(list(_identity(info)) == parent["identity"]
                        and storage_quota._mount_id(fd) == parent["mount_id"], "cleanup-reconciliation-parent")
                pinned.append((path, info.st_dev, parent["mount_id"]))
            rows = _consumer_mount_rows(_consumer_read(Path("/proc/self/mountinfo"), 4 * 1024**2, end), end)
            targets = _consumer_mount_targets(rows, pinned)
            require([list(row) for row in targets] == metadata["targets"], "cleanup-reconciliation-mount")
            _absent(expected)
            start = next((e for e in record["effects"].values() if e["operation"] == "engine-start"), None)
            process = None
            if start is not None:
                ledger._validate_engine_exit(start["engine_exit"], start)
                process = start["engine_process"]
                require(process["boot_id"] == kernel.read_boot_id(), "cleanup-reconciliation-engine-boot")
            group = engine._directory("/sys/fs/cgroup", private=False)
            try:
                require([*_identity(os.fstat(group)), storage_quota._mount_id(group)] == metadata["cgroup_root"]
                        and engine_executor._fs_type(group) == engine_executor.CGROUP2_MAGIC,
                        "cleanup-reconciliation-cgroup-root")
                if start is not None:
                    relative = "lit.slice/lit-lease.slice/lit-lease-" + owner.lease_id + ".slice"
                    try:
                        child = os.open(relative, installation.DIR_FLAGS, dir_fd=group)
                    except FileNotFoundError:
                        child = None
                    if child is not None:
                        try:
                            info = os.fstat(child); capture = start["engine_capture"]
                            require((info.st_dev, info.st_ino) == (capture["cgroup_device"], capture["cgroup_inode"]),
                                    "cleanup-reconciliation-cgroup-replaced")
                            events = dict(line.split() for line in kernel.bounded_file(child, "cgroup.events", 4096).splitlines())
                            require(events.get(b"populated") == b"0" and not kernel.bounded_file(child, "cgroup.procs", 65536).strip(),
                                    "cleanup-reconciliation-live-owner")
                        finally:
                            os.close(child)
            finally:
                os.close(group)
            _no_consumers(data, owner.engine_descriptor_path, owner.lease_id, opened, end,
                          identities, targets, process)
            with storage_quota.acquire_existing_evidence_quota(config.storage_quota_policy_path,
                    config.storage_quota_policy_sha256, metadata["spool"]):
                require(cleanup.certificates_absent(), "cleanup-reconciliation-certificate-live")
                project = cleanup.readback("project")
                quiet = cleanup.quiet_project() if project["state"] != "absent_observed" else None
                _absent(expected)
                _fresh(owner, store, config)
                for fd, parent in zip(opened, metadata["parents"]):
                    require(list(_identity(os.fstat(fd))) == parent["identity"]
                            and storage_quota._mount_id(fd) == parent["mount_id"], "cleanup-reconciliation-parent")
                    current = engine._directory(parent["path"], private=True)
                    try:
                        require(_identity(os.fstat(current)) == _identity(os.fstat(fd))
                                and storage_quota._mount_id(current) == parent["mount_id"], "cleanup-reconciliation-parent")
                    finally:
                        os.close(current)
            for fd in reversed(opened): os.close(fd)
            opened.clear()
            state = store._load()
            require(state["leases"][owner.lease_id] == record, "cleanup-reconciliation-record-drift")
            payload = {"generation": state["generation"], "effect_sha256": ledger.digest(effect),
                "deadline": end, "observation_sha256": ledger.digest({"sidecar": effect["cleanup_observation"],
                "paths_absent": expected, "native_scope": {"project": project, "quiet": quiet,
                    "certificate_scope_absent": True}, "quota": "verified"})}
            _deadline(end)
            proof = _CleanupReconciliation(store, session, owner.lease_id, effect_id, payload,
                                           os.getpid(), threading.current_thread())
            with _RECONCILIATION_LOCK: _RECONCILIATIONS.add(proof)
            store.resolve_cleanup_postcheck(owner.lease_id, effect_id, proof)
        finally:
            for fd in reversed(opened): os.close(fd)


def release_engine(owner, store, config):
    """Release only the three directory inodes created by engine-prepare."""
    effect, opened = None, []
    publication_attempted = False
    try:
        started = time.monotonic()
        record = _fresh(owner, store, config)
        store.require_cleanup_postchecks(owner.lease_id)
        data = identity.decode_json(owner.engine_descriptor_bytes)
        paths = (data["engine"]["storage_root"], data["engine"]["runroot"], data["output_path"])
        target = "engine:" + owner.lease_id
        previous = _effect(record, "engine-release", target)
        if previous is not None:
            _absent(paths)
            return StorageReceipt(owner.lease_id, "engine-release", previous[1]["evidence_sha256"])
        if type(owner) is not cell_contract.PartialPreparationOwner:
            _drain_engine(owner, store, config)
        maximum, seconds = _cleanup_limits(config)
        end = started + seconds
        _deadline(end)
        directories, inventories, used = [], [], 0
        for path in paths:
            parent = engine._directory(str(PurePosixPath(path).parent), private=True)
            opened.append(parent)
            fd = engine._directory(path, private=True)
            opened.append(fd)
            info = os.fstat(fd)
            directories.append({"path": path, "device": info.st_dev, "inode": info.st_ino})
            inventory = _inventory_tree(fd, end, maximum - used)
            used += len(inventory[0])
            inventories.append((path, parent, fd, inventory))
        creator = record["effects"][owner.creators["engine-prepare"]["id"]]
        require(creator["evidence_sha256"] == ledger.digest({"prepared": owner.prepared_sha256,
                    "directories": directories}), "cleanup-storage-original-inodes")
        # The public sibling stays bounded by the original Root quota even
        # after the raw graph/runroot/output have all been removed.
        spool = (str(PurePosixPath(data["engine"]["runroot"]).parent)
                 if type(owner) is cell_contract.PartialPreparationOwner else
                 data["engine"]["runroot"] + ".public-evidence")
        require(all(spool != path and not spool.startswith(path + "/") for path in paths),
                "cleanup-storage-spool-inside-raw")
        with storage_quota.acquire_existing_evidence_quota(
                config.storage_quota_policy_path, config.storage_quota_policy_sha256, spool):
            _fresh(owner, store, config)
            _deadline(end)
            if type(owner) is cell_contract.PartialPreparationOwner:
                _partial_no_consumers(owner, opened, end,
                    [(path, fd, inventory) for path, _, fd, inventory in inventories])
                _deadline(end)
            observation = _postcheck_observation(owner, [(path, fd, inventory)
                    for path, _, fd, inventory in inventories], spool, end)
            publication_attempted = True
            effect, guard = store.begin_cleanup_with_postcheck(owner.lease_id, 'engine-release', target, end, observation=observation)
            for path, parent, fd, inventory in inventories:
                _deadline(end)
                named = os.stat(PurePosixPath(path).name, dir_fd=parent, follow_symlinks=False)
                require(_identity(named) == _identity(os.fstat(fd)), "cleanup-storage-root-replaced")
                _remove_tree(fd, inventory, end)
                os.rmdir(PurePosixPath(path).name, dir_fd=parent)
                os.fsync(parent)
            _absent(paths)
            evidence = ledger.digest({"lease_id": owner.lease_id, "operation": "engine-release",
                                      "directories": directories, "removed_entries": used})
        # Quota-exit readback precedes the success receipt, within the SAME end.
        _deadline(end)
        store.record(owner.lease_id, effect, "verified", evidence_sha256=evidence)
        for fd in reversed(opened):
            os.close(fd)
        opened.clear()
        store.complete_cleanup_postcheck(guard)
        return StorageReceipt(owner.lease_id, "engine-release", evidence)
    except BaseException:
        if effect is None and publication_attempted:
            try:
                effect = _published_cleanup_after_failure(store, owner.lease_id, 'engine-release', target)
            except BaseException:
                raise CleanupStorageUnknown('cleanup-storage-publication-unknown') from None
        if effect is not None:
            _mark_unknown(store, owner, effect, "engine-release")
            raise CleanupStorageUnknown("cleanup-storage-unknown") from None
        raise Denied("cleanup-storage-denied") from None
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _partial_context_files(owner, store, config, record, context, binding, binding_proof):
    """Authenticate an existing publication for deletion, never renew authority."""
    publication = owner.creators.get("context-publish")
    if publication is None:
        require("admission" not in binding, "partial-context-unrecorded-publication")
        files = signed_context._files(context, binding, None)
        unsigned = binding
    else:
        payload, _ = signed_context._decode_signed(binding.get("admission"), config.signing_public_key)
        engine_sha256 = engine._hash(payload.get("engine_policy_sha256"))
        receipt = preparation.PreparationReceipt(owner.lease_id, owner.cell_sha256, engine_sha256,
                                                 binding_proof.sha256, owner.expires_at)
        # This existing ownership verifier deliberately accepts expired signed
        # ownership while binding every original field/file. It grants nothing.
        engine_executor._authenticate(config, owner.registry, owner.selector, store, owner.lease_id, receipt)
        effect = record["effects"][publication["id"]]
        require(effect["state"] == "verified" and effect["evidence_sha256"] == ledger.digest({
            "prepared": owner.prepared_sha256, "binding_sha256": binding_proof.sha256,
            "engine_policy_sha256": engine_sha256}), "partial-context-original-publication")
        files = signed_context._files(context, binding, binding["admission"])
        unsigned = signed_context._projection(binding)
    files["binding.json"] = hashlib.sha256(ledger.canonical(unsigned)).hexdigest()
    return files


def delete_context(owner, store, config):
    """Authenticate the original TLS context, then unlink that exact inventory."""
    effect, opened = None, []
    publication_attempted = False
    try:
        started = time.monotonic()
        record = _fresh(owner, store, config)
        store.require_cleanup_postchecks(owner.lease_id)
        data = identity.decode_json(owner.engine_descriptor_bytes)
        context, descriptor = data["context_path"], owner.engine_descriptor_path
        target = "context:" + owner.cell_sha256
        previous = _effect(record, "context-delete", target)
        if previous is not None:
            _absent((context, descriptor))
            return StorageReceipt(owner.lease_id, "context-delete", previous[1]["evidence_sha256"])
        require((type(owner) is cell_contract.PartialPreparationOwner and "engine-prepare" not in owner.creators
                 or _effect(record, "engine-release", "engine:" + owner.lease_id) is not None)
                and (type(owner) is cell_contract.PartialPreparationOwner and "certificate-create" not in owner.creators
                 or _effect(record, "certificate-revoke", owner.creator_targets["certificate-create"]) is not None),
                "cleanup-storage-parents-live")
        raw, binding_proof = signed_context._sealed(context + "/binding.json", 32768)
        binding = identity.decode_json(raw)
        if type(owner) is cell_contract.PartialPreparationOwner:
            files = _partial_context_files(owner, store, config, record, context, binding, binding_proof)
        else:
            receipt = preparation.PreparationReceipt(owner.lease_id, owner.cell_sha256, owner.engine_policy_sha256,
                                                     binding_proof.sha256, owner.expires_at)
            engine_executor._authenticate(config, owner.registry, owner.selector, store, owner.lease_id, receipt)
            files = signed_context._files(context, binding, binding["admission"])
            unsigned = {key: value for key, value in binding.items() if key != "admission"}
            files["binding.json"] = hashlib.sha256(ledger.canonical(unsigned)).hexdigest()
        cert_raw, _ = signed_context._sealed(context + "/client.crt")
        fingerprint = hashlib.sha256(x509.load_pem_x509_certificate(cert_raw).public_bytes(
            serialization.Encoding.DER)).hexdigest()
        creator = record["effects"][owner.creators["context-create"]["id"]]
        require((type(owner) is cell_contract.PartialPreparationOwner and "certificate-create" not in owner.creators
                 or "certificate:" + fingerprint == owner.creator_targets["certificate-create"])
                and creator["evidence_sha256"] == ledger.digest({"prepared": owner.prepared_sha256,
                    "files": files, "descriptor": owner.engine_descriptor_sha256, "certificate": fingerprint}),
                "cleanup-storage-original-context")
        proof, descriptor_raw, _ = installation._file(descriptor, engine.MAX_DESCRIPTOR, private=True, keep=True)
        require(proof.sha256 == owner.engine_descriptor_sha256
                and descriptor_raw == owner.engine_descriptor_bytes, "cleanup-storage-original-descriptor")
        parent = engine._directory(str(PurePosixPath(context).parent), private=True)
        opened.append(parent)
        fd = engine._directory(context, private=True)
        opened.append(fd)
        descriptor_parent = engine._directory(str(PurePosixPath(descriptor).parent), private=True)
        opened.append(descriptor_parent)
        maximum, seconds = _cleanup_limits(config)
        end = started + seconds
        _deadline(end)
        inventory = _inventory_tree(fd, end, min(maximum, 16))
        require({"/".join(row[0]) for row in inventory[0]} == {
            "binding.json", "config.yml", "client.crt", "client.key", "servercerts", "servercerts/quality.crt"},
            "cleanup-storage-context-inventory")
        _fresh(owner, store, config)
        if type(owner) is cell_contract.PartialPreparationOwner:
            descriptor_fd = os.open(descriptor, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            opened.append(descriptor_fd)
            descriptor_info = os.fstat(descriptor_fd)
            require((descriptor_info.st_dev, descriptor_info.st_ino) == (proof.device, proof.inode),
                    "cleanup-storage-descriptor-replaced")
            descriptor_mount = storage_quota._mount_id(descriptor_fd)
            os.close(opened.pop())
            _partial_no_consumers(owner, opened, end,
                [(context, fd, inventory), (descriptor, descriptor_parent,
                  ((), {(): _identity(descriptor_info)}, descriptor_mount))])
            _deadline(end)
        descriptor_fd = os.open(descriptor, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            descriptor_inventory = ((), {(): _identity(os.fstat(descriptor_fd))}, storage_quota._mount_id(descriptor_fd))
            context_observation = _postcheck_observation(owner,
                [(context, fd, inventory), (descriptor, descriptor_fd, descriptor_inventory)],
                (str(PurePosixPath(data["engine"]["runroot"]).parent)
                 if type(owner) is cell_contract.PartialPreparationOwner else data["engine"]["runroot"] + ".public-evidence"), end)
        finally:
            os.close(descriptor_fd)
        publication_attempted = True
        effect, guard = store.begin_cleanup_with_postcheck(owner.lease_id, 'context-delete', target, end, observation=context_observation)
        _remove_tree(fd, inventory, end)
        require(_identity(os.stat(PurePosixPath(context).name, dir_fd=parent, follow_symlinks=False))
                == _identity(os.fstat(fd)), "cleanup-storage-context-replaced")
        os.rmdir(PurePosixPath(context).name, dir_fd=parent)
        os.fsync(parent)
        observed = os.stat(PurePosixPath(descriptor).name, dir_fd=descriptor_parent, follow_symlinks=False)
        require((observed.st_dev, observed.st_ino) == (proof.device, proof.inode), "cleanup-storage-descriptor-replaced")
        os.unlink(PurePosixPath(descriptor).name, dir_fd=descriptor_parent)
        os.fsync(descriptor_parent)
        _absent((context, descriptor))
        evidence = ledger.digest({"lease_id": owner.lease_id, "operation": "context-delete",
                                  "creator_sha256": owner.creator_digests["context-create"]})
        store.record(owner.lease_id, effect, "verified", evidence_sha256=evidence)
        for fd in reversed(opened):
            os.close(fd)
        opened.clear()
        store.complete_cleanup_postcheck(guard)
        return StorageReceipt(owner.lease_id, "context-delete", evidence)
    except BaseException:
        if effect is None and publication_attempted:
            try:
                effect = _published_cleanup_after_failure(store, owner.lease_id, 'context-delete', target)
            except BaseException:
                raise CleanupStorageUnknown('cleanup-storage-publication-unknown') from None
        if effect is not None:
            _mark_unknown(store, owner, effect, "context-delete")
            raise CleanupStorageUnknown("cleanup-storage-unknown") from None
        raise Denied("cleanup-storage-denied") from None
    finally:
        for fd in reversed(opened):
            os.close(fd)
