"""Acquire an EXISTING private bounded loop filesystem; never provision one.

Root sealed JSON is an expectation, not quota proof. Admission requires actual
mount namespace/mount IDs, ext4-on-loop kernel identity, fully reserved backing
extents and finite filesystem byte/inode totals. All persistent mutable engine
paths, including capture/libpod data, must share that mount. Container tmpfs
ceilings remain separate. Incus SERVER VM/storage quotas are not proven here.

Caller retains its Root preparation lock and this context through engine use.
No filesystem creation, allocation, mount, resize, device configuration or
cleanup is implemented. Root platform provenance, exclusive slot provisioning,
idmapped/runtime/native functional qualification and custody remain mandatory.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
import ctypes
import fcntl
import hashlib
import os
from pathlib import PurePosixPath
import re
import stat
import struct

from . import engine_policy as engine, identity, installation, kernel, ledger
from .identity import Denied, require

NSFS = 0x6e736673
PROCFS = 0x9fa0
SYSFS = 0x62656572
EXT4 = 0xef53
NS_GET_NSTYPE = 0xb703
CLONE_NEWNS = 0x00020000
LOOP_GET_STATUS64 = 0x4c05
BLKGETSIZE64 = 0x80081272
FS_IOC_FIEMAP = 0xc020660b
MAX_BYTES = 1024 ** 4
MAX_INODES = 2 ** 30
MOUNTINFO_LIMIT = 8 * 1024 ** 2

# Primary supported ABI: Linuxv6.8 include/uapi/linux/{loop,fiemap}.h.
# FIEMAP rejects shared/delayed/unknown/encoded extents. UNWRITTEN is allocated
# physical reservation, not a hole. Data contents and extent splitting may
# legitimately change while the loop filesystem is used.
# https://raw.githubusercontent.com/torvalds/linux/v6.8/include/uapi/linux/loop.h
# https://raw.githubusercontent.com/torvalds/linux/v6.8/include/uapi/linux/fiemap.h
# Podman4.9.3 official docs: podman.1.html#events-backend-type / #tmpdir-path
# and podman-run.1.html#log-driver-driver (local non-TTY passthrough only).


@dataclass(frozen=True)
class QuotaObservation:
    policy_sha256: str
    mount_id: int
    total_bytes: int
    total_inodes: int
    # Observation only; no reusable approval flag or execution authority.


def _root():
    require(os.geteuid() == 0, "storage-quota-root-required")


def _fs_type(fd):
    buffer = ctypes.create_string_buffer(256)
    require(ctypes.CDLL(None, use_errno=True).fstatfs(fd, buffer) == 0, "storage-quota-filesystem-stat")
    return ctypes.c_long.from_buffer(buffer).value


def _number(value, *, zero=False, maximum=2 ** 63 - 1):
    require(type(value) is int and (0 if zero else 1) <= value <= maximum, "storage-quota-integer")
    return value


def _path(value):
    engine._path(value)
    require(re.fullmatch(r"/[A-Za-z0-9_./-]+", value) and value != "/", "storage-quota-path")
    return value


def _policy(path, expected):
    _root()
    proof, raw, stamp = installation._file(engine._path(path), 16384, private=True, keep=True)
    require(proof.sha256 == engine._hash(expected), "storage-quota-policy-drift")
    value = identity.decode_json(raw)
    engine._keys(value, {"schema", "boot_id", "mount_namespace", "mount", "loop_device", "backing_file", "max_bytes", "max_inodes"})
    require(type(value["schema"]) is int and value["schema"] == 1
            and ledger._native_uuid(value["boot_id"]), "storage-quota-schema")
    ns = engine._keys(value["mount_namespace"], {"device", "inode"})
    mount = engine._keys(value["mount"], {"path", "mount_id", "device", "inode", "fstype"})
    backing = engine._keys(value["backing_file"], {"path", "device", "inode", "bytes"})
    for item in (ns, mount, backing):
        _number(item["device"], zero=True)
        _number(item["inode"])
    _number(mount["mount_id"])
    require(mount["fstype"] == "ext4", "storage-quota-filesystem-policy")
    _path(mount["path"])
    _path(backing["path"])
    require(re.fullmatch(r"/dev/loop(0|[1-9][0-9]{0,7})", value["loop_device"]), "storage-quota-loop-policy")
    _number(backing["bytes"], maximum=MAX_BYTES)
    require(backing["bytes"] >= 16 * 1024 ** 2 and backing["bytes"] % 4096 == 0, "storage-quota-backing-size")
    _number(value["max_bytes"], maximum=backing["bytes"])
    _number(value["max_inodes"], maximum=MAX_INODES)
    require(not backing["path"].startswith(mount["path"] + "/"), "storage-quota-recursive-backing")
    return value, proof, stamp


def _read_proc(path, limit):
    fd = os.open(path, installation.FILE_FLAGS)
    try:
        require(_fs_type(fd) == PROCFS and stat.S_ISREG(os.fstat(fd).st_mode), "storage-quota-procfs")
        result = bytearray()
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
            require(len(result) <= limit, "storage-quota-proc-limit")
        return bytes(result)
    finally:
        os.close(fd)


def _mount_id(fd):
    raw = _read_proc("/proc/self/fdinfo/" + str(fd), 8192)
    matches = re.findall(rb"(?m)^mnt_id:\s*([1-9][0-9]{0,19})$", raw)
    require(len(matches) == 1, "storage-quota-fd-mount-id")
    return int(matches[0])


def _unescape(value):
    require(not re.search(r"\\(?!040|011|012|134)", value), "storage-quota-mount-escape")
    return re.sub(r"\\(040|011|012|134)", lambda match: chr(int(match[1], 8)), value)


def _mounts(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MOUNTINFO_LIMIT, "storage-quota-mountinfo-limit")
    rows = raw.decode("utf-8", "strict").splitlines()
    require(len(rows) <= 65536, "storage-quota-mountinfo-limit")
    result = []
    for row in rows:
        require(len(row) <= 8192 and row.count(" - ") == 1, "storage-quota-mountinfo-schema")
        left, right = row.split(" - ")
        prefix, suffix = left.split(), right.split()
        require(len(prefix) >= 6 and len(suffix) == 3
                and all(re.fullmatch(r"[1-9][0-9]{0,19}", part) for part in prefix[:2])
                and re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", prefix[2]), "storage-quota-mountinfo-schema")
        result.append({"id": int(prefix[0]), "parent": int(prefix[1]), "device": prefix[2], "root": _unescape(prefix[3]),
                       "path": _unescape(prefix[4]), "flags": prefix[5].split(","), "optional": prefix[6:],
                       "fstype": suffix[0], "source": _unescape(suffix[1]), "super": suffix[2].split(",")})
    require(len({row["id"] for row in result}) == len(result), "storage-quota-mountinfo-duplicate")
    return result


def _namespace():
    # /proc/self/ns/mnt is the one intentional kernel symlink exception.
    fd = os.open("/proc/self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
    try:
        require(os.fstat(fd).st_uid == 0 and _fs_type(fd) == NSFS and fcntl.ioctl(fd, NS_GET_NSTYPE) == CLONE_NEWNS,
                "storage-quota-real-mount-namespace")
        return fd
    except Exception:
        os.close(fd)
        raise


def _open_file(path):
    parent = installation._open_directory(str(PurePosixPath(path).parent))
    try:
        return os.open(PurePosixPath(path).name, installation.FILE_FLAGS, dir_fd=parent)
    finally:
        os.close(parent)


def _sysfs(number, relative, limit=8192):
    directory = installation._open_directory("/sys/devices/virtual/block/loop" + str(number)
                                              + ("/loop" if relative.startswith("loop/") else ""))
    try:
        require(_fs_type(directory) == SYSFS, "storage-quota-real-sysfs")
        return kernel.bounded_file(directory, relative.removeprefix("loop/"), limit).decode("ascii").strip()
    finally:
        os.close(directory)


def _reservation(fd, size):
    # At most4096 extents. Larger fragmented files fail closed, never guessed
    # from free disk space or st_blocks alone. No FIEMAP_FLAG_SYNC/write effect.
    count = 4096
    data = bytearray(32 + count * 56)
    struct.pack_into("=QQIIII", data, 0, 0, size, 0, 0, count, 0)
    fcntl.ioctl(fd, FS_IOC_FIEMAP, data, True)
    start, length, flags, mapped, actual_count, reserved = struct.unpack_from("=QQIIII", data)
    require((start, length, flags, actual_count, reserved) == (0, size, 0, count, 0) and 0 < mapped <= count,
            "storage-quota-fiemap-schema")
    end, final = 0, False
    for index in range(mapped):
        logical, physical, extent, r1, r2, extent_flags, r3, r4, r5 = struct.unpack_from("=QQQQQIIII", data, 32 + index * 56)
        require(not final and logical == end and physical > 0 and extent > 0
                and not any((r1, r2, r3, r4, r5)) and extent_flags & ~(1 | 0x800) == 0,
                "storage-quota-unreserved-extent")
        end += extent
        final = bool(extent_flags & 1)
    require(end >= size and final, "storage-quota-sparse-or-incomplete-backing")


def _loop(loop_fd, backing_fd, policy):
    loop, backing = os.fstat(loop_fd), os.fstat(backing_fd)
    expected = policy["backing_file"]
    require(stat.S_ISBLK(loop.st_mode) and loop.st_uid == 0 and loop.st_nlink == 1
            and stat.S_IMODE(loop.st_mode) in {0o600, 0o660}, "storage-quota-real-loop-device")
    installation._regular(backing, private=True)
    require((backing.st_dev, backing.st_ino, backing.st_size) == (expected["device"], expected["inode"], expected["bytes"])
            and backing.st_blocks * 512 >= backing.st_size, "storage-quota-backing-reservation")
    # Reopen the fixed names: retained descriptors alone would miss a renamed
    # or replaced device/backing pathname while still referring to old objects.
    for path, expected_info in ((policy["loop_device"], loop), (expected["path"], backing)):
        current_fd = _open_file(path)
        try:
            current = os.fstat(current_fd)
            require((current.st_dev, current.st_ino, current.st_rdev, current.st_mode, current.st_uid, current.st_nlink)
                    == (expected_info.st_dev, expected_info.st_ino, expected_info.st_rdev,
                        expected_info.st_mode, expected_info.st_uid, expected_info.st_nlink), "storage-quota-device-path-drift")
        finally:
            os.close(current_fd)
    info = fcntl.ioctl(loop_fd, LOOP_GET_STATUS64, bytes(232))
    device, inode, rdevice, offset, sizelimit, number, encryption, keysize, flags = struct.unpack_from("=QQQQQIIII", info)
    require((device, inode) == (backing.st_dev, backing.st_ino) and rdevice == 0 and offset == 0 and sizelimit == 0
            and encryption == keysize == 0 and flags in {0, 16}
            and os.major(loop.st_rdev) == 7 and os.minor(loop.st_rdev) == number
            and policy["loop_device"] == "/dev/loop" + str(number), "storage-quota-loop-binding")
    actual_bytes = struct.unpack("=Q", fcntl.ioctl(loop_fd, BLKGETSIZE64, bytes(8)))[0]
    require(actual_bytes == backing.st_size and _sysfs(number, "loop/backing_file") == expected["path"]
            and _sysfs(number, "loop/offset") == "0" and _sysfs(number, "loop/sizelimit") == "0"
            and _sysfs(number, "size") == str(backing.st_size // 512), "storage-quota-loop-sysfs")
    _reservation(backing_fd, backing.st_size)
    return loop.st_rdev


def _manifest(manifest):
    require(type(manifest) is engine.EngineManifest and hashlib.sha256(manifest.canonical_bytes).hexdigest() == manifest.sha256,
            "storage-quota-manifest")
    data = identity.decode_json(manifest.canonical_bytes)
    require(ledger.canonical(data) == manifest.canonical_bytes and tuple(data["argv"]) == manifest.argv,
            "storage-quota-manifest")
    argv = list(manifest.argv)
    run = argv.index("run")
    prefix, arguments = argv[:run], argv[run + 1:]
    runroot = _path(data["engine"]["runroot"])
    storage = _path(data["engine"]["storage_root"])
    require(prefix == [engine.ENGINE, "--root", storage, "--runroot", runroot, "--cgroup-manager=systemd",
                       "--events-backend=none", "--tmpdir=" + runroot], "storage-quota-backend-routing")
    require(arguments.count("--log-driver=passthrough") == 1 and not any(arg.startswith(("--log-driver", "--log-opt"))
            and arg != "--log-driver=passthrough" for arg in arguments)
            and not any(arg.startswith(("--syslog", "--out", "--remote", "--url", "--connection", "--device")) for arg in argv)
            and not any(arg in {"-t", "--tty", "--tty=true", "-d", "--detach", "--detach=true"} for arg in arguments),
            "storage-quota-log-routing")
    capture = engine._keys(data["capture"], {"stdout_limit", "stderr_limit", "total_limit"})
    require(all(type(capture[key]) is int and 0 < capture[key] <= 64 * 1024 ** 2 for key in ("stdout_limit", "stderr_limit"))
            and type(capture["total_limit"]) is int and 0 < capture["total_limit"] <= 128 * 1024 ** 2
            and capture["total_limit"] <= capture["stdout_limit"] + capture["stderr_limit"], "storage-quota-capture-limit")
    paths = [storage, runroot, _path(data["output"]["path"])]
    mounts = [arguments[index + 1] for index, arg in enumerate(arguments[:-1]) if arg == "--mount"]
    for mount in mounts:
        if ",readonly" not in mount:
            require(mount.startswith("type=bind,source=" + paths[2] + ",destination=/quality,")
                    and ",idmap=" in mount, "storage-quota-unbounded-write-mount")
    require(not any(arg.startswith(("--volume", "-v", "--mount=")) for arg in arguments), "storage-quota-unbounded-write-mount")
    return tuple(paths)


def _check(policy, mount_fd, namespace_fd, loop_fd, backing_fd, paths):
    require(kernel.read_boot_id() == policy["boot_id"], "storage-quota-boot-drift")
    ns = os.fstat(namespace_fd)
    require((ns.st_dev, ns.st_ino) == (policy["mount_namespace"]["device"], policy["mount_namespace"]["inode"]),
            "storage-quota-namespace-binding")
    current_ns = _namespace()
    try:
        current = os.fstat(current_ns)
        require((current.st_dev, current.st_ino) == (ns.st_dev, ns.st_ino), "storage-quota-namespace-drift")
    finally:
        os.close(current_ns)
    mount = policy["mount"]
    observed = os.fstat(mount_fd)
    require((observed.st_dev, observed.st_ino) == (mount["device"], mount["inode"])
            and observed.st_uid == 0 and stat.S_IMODE(observed.st_mode) == 0o700
            and _fs_type(mount_fd) == EXT4, "storage-quota-mount-binding")
    rdev = _loop(loop_fd, backing_fd, policy)
    rows = _mounts(_read_proc("/proc/self/mountinfo", MOUNTINFO_LIMIT))
    selected = [row for row in rows if row["path"] == mount["path"]]
    require(len(selected) == 1, "storage-quota-unique-mount")
    row = selected[0]
    require(row["id"] == mount["mount_id"] == _mount_id(mount_fd) and row["root"] == "/"
            and row["fstype"] == "ext4" and row["source"] == policy["loop_device"]
            and row["device"] == str(os.major(rdev)) + ":" + str(os.minor(rdev))
            and row["device"] == str(os.major(observed.st_dev)) + ":" + str(os.minor(observed.st_dev))
            and {"rw", "nosuid", "nodev"} <= set(row["flags"]) and "ro" not in row["flags"]
            and not row["optional"] and "rw" in row["super"], "storage-quota-real-private-loop-mount")
    vfs = os.fstatvfs(mount_fd)
    require(vfs.f_frsize > 0 and vfs.f_blocks > 0 and vfs.f_files > 0
            and vfs.f_blocks * vfs.f_frsize <= policy["max_bytes"] and vfs.f_files <= policy["max_inodes"]
            and not vfs.f_flag & os.ST_RDONLY, "storage-quota-filesystem-ceiling")
    for path, fd in paths:
        require(path.startswith(mount["path"] + "/") and os.fstat(fd).st_dev == observed.st_dev
                and _mount_id(fd) == row["id"], "storage-quota-path-outside")
        require(not any(other["id"] != row["id"] and (path == other["path"] or path.startswith(other["path"] + "/"))
                        and other["path"].startswith(mount["path"] + "/") for other in rows), "storage-quota-mount-escape")
        again = engine._directory(path, private=True)
        try:
            require((os.fstat(again).st_dev, os.fstat(again).st_ino) == (os.fstat(fd).st_dev, os.fstat(fd).st_ino),
                    "storage-quota-path-replaced")
        finally:
            os.close(again)
    return QuotaObservation("", row["id"], vfs.f_blocks * vfs.f_frsize, vfs.f_files)


@contextmanager
def acquire_existing_quota(root_policy_path, expected_sha256, manifest):
    """Root-only kernel acquisition; no boolean/policy-only quota attestation.

    Root factory must bind path/hash to its independently loaded configuration.
    Any pre/post acquisition failure denies; possible engine effects belong to
    its durable UNKNOWN journal, never cleanup/retry authorization here.
    """
    _root()
    mutable = _manifest(manifest)
    with _acquire_paths(root_policy_path, expected_sha256, mutable) as observation:
        yield observation


@contextmanager
def acquire_existing_evidence_quota(root_policy_path, expected_sha256, evidence_directory):
    """Read-only quota acquisition for the Root-derived retained evidence path.

    The trusted exporter supplies its fixed sibling path, never a job locator.
    This proves existing filesystem bounds; it grants no engine operation.
    Unlike execution acquisition, it needs no deleted raw runtime directories.
    """
    _root()
    with _acquire_paths(root_policy_path, expected_sha256, (_path(evidence_directory),)) as observation:
        yield observation


@contextmanager
def _acquire_paths(root_policy_path, expected_sha256, mutable):
    try:
        policy, proof, stamp = _policy(root_policy_path, expected_sha256)
        with ExitStack() as stack:
            def retain(fd):
                stack.callback(os.close, fd)
                return fd
            namespace = retain(_namespace())
            mount = retain(engine._directory(policy["mount"]["path"], private=True))
            loop = retain(_open_file(policy["loop_device"]))
            backing = retain(_open_file(policy["backing_file"]["path"]))
            paths = tuple((path, retain(engine._directory(path, private=True))) for path in mutable)
            observation = _check(policy, mount, namespace, loop, backing, paths)
            yield QuotaObservation(expected_sha256, observation.mount_id, observation.total_bytes, observation.total_inodes)
            require(_policy(root_policy_path, expected_sha256) == (policy, proof, stamp), "storage-quota-policy-drift")
            _check(policy, mount, namespace, loop, backing, paths)
    except Exception:
        raise Denied("storage-quota-acquisition-denied") from None
