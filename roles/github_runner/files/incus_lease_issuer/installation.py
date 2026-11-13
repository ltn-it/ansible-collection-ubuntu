"""Root-acquired, closed-inventory runner installation evidence.

No provisioner exists here. Only the explicit stock _diag data directory is
excluded from code inventory. A manifest records root-provisioned bytes; its
package digest is not a download signature.
This proof cannot bless an already running process, loaded libraries, systemd
configuration or startup environment, and grants no lease/TLS/engine authority.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import PurePosixPath
import re
import stat
import threading
from types import MappingProxyType
from typing import Mapping

from .identity import Denied, decode_json, require
from .worker import ExecutablePolicy

MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_DEPTH = 32
HASH_WORKERS = 4
HASH_PARALLEL_MIN_BYTES = 1024 * 1024
MAX_LINK_TARGET_BYTES = 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
BASH = "/usr/bin/bash"
SUPPORTED_VERSION = "2.338.2"
REQUIRED_FILES = frozenset({
    "run.sh", "config.sh", "svc.sh", "runsvc.sh", "bin/runsvc.sh",
    "bin/RunnerService.js", "bin/Runner.Listener", "bin/Runner.Worker",
    "externals/node24/bin/node", ".runner",
})
REQUIRED_DIRECTORIES = frozenset({"bin", "externals", "externals/node24", "externals/node24/bin"})
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


@dataclass(frozen=True)
class InstallationPolicy:
    root: str
    manifest_path: str
    runner_id: int
    service_uid: int
    runner_version: str = SUPPORTED_VERSION


@dataclass(frozen=True)
class TrustedFile:
    path: str
    device: int
    inode: int
    sha256: str
    size: int


@dataclass(frozen=True)
class InstallationProof:
    runner_root: str
    main: ExecutablePolicy
    node: ExecutablePolicy
    listener: ExecutablePolicy
    worker: ExecutablePolicy
    files: Mapping[str, str]
    symlinks: Mapping[str, str]
    directories: tuple[str, ...]
    runtime_directories: tuple[str, ...]
    manifest_path: str
    manifest_sha256: str
    package_sha256: str
    runner_version: str
    trusted_files: Mapping[str, TrustedFile] = field(default_factory=lambda: MappingProxyType({}))
    file_stamps: Mapping[str, tuple] = field(default_factory=lambda: MappingProxyType({}))
    tree_stamps: Mapping[str, tuple] = field(default_factory=lambda: MappingProxyType({}))
    runtime_stamps: Mapping[str, tuple] = field(default_factory=lambda: MappingProxyType({}))


def _root():
    require(os.geteuid() == 0, "installation-root-required")


def _absolute(path):
    require(type(path) is str and 0 < len(path) <= 4096 and path.startswith("/")
            and not CONTROL.search(path), "installation-path")
    parts = () if path == "/" else tuple(path[1:].split("/"))
    require(all(part not in {"", ".", ".."} for part in parts), "installation-path")
    try:
        path.encode("utf-8")
    except UnicodeError:
        raise Denied("installation-path") from None
    return parts


def _relative(path):
    require(type(path) is str and 0 < len(path) <= 1024 and not path.startswith("/")
            and not CONTROL.search(path), "installation-relative-path")
    parts = path.split("/")
    require(len(parts) <= MAX_DEPTH and all(part not in {"", ".", ".."} for part in parts),
            "installation-relative-path")
    try:
        path.encode("utf-8")
    except UnicodeError:
        raise Denied("installation-relative-path") from None
    return path


def _stamp(info):
    # Reading can change atime; it must not change any of these identity fields.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory(info):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and not stat.S_IMODE(info.st_mode) & 0o022, "installation-untrusted-directory")


def _regular(info, *, private=False):
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and not stat.S_IMODE(info.st_mode) & 0o022
            and not info.st_mode & (stat.S_ISUID | stat.S_ISGID), "installation-untrusted-file")
    if private:
        require(stat.S_IMODE(info.st_mode) == 0o600, "installation-private-manifest")


def _runtime_stamp(info, service_uid):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == service_uid
            and stat.S_IMODE(info.st_mode) == 0o700, "installation-runtime-directory")
    # Mutable log children change directory times/size/link count. They are
    # never read, hashed, imported or executable-policy evidence.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _link_target(path, target):
    require(type(target) is str and 0 < len(target) <= MAX_LINK_TARGET_BYTES
            and not target.startswith("/") and not any(ord(c) < 32 or ord(c) == 127 for c in target)
            and str(PurePosixPath(target)) == target and target != ".", "installation-symlink-target")
    try:
        require(len(target.encode("utf-8")) <= MAX_LINK_TARGET_BYTES, "installation-symlink-target")
    except UnicodeError:
        raise Denied("installation-symlink-target") from None
    resolved = list(PurePosixPath(path).parent.parts)
    leading_parents = True
    for part in PurePosixPath(target).parts:
        if part == "..":
            require(leading_parents and resolved, "installation-symlink-escape")
            resolved.pop()
        else:
            leading_parents = False
            resolved.append(part)
    destination = "/".join(resolved)
    _relative(destination)
    require(destination != "_diag" and not destination.startswith("_diag/"), "installation-symlink-runtime")
    return destination


def _symlink(info):
    # Linux symlink permissions are intrinsically0777. Its sealed, root-owned
    # parent supplies replacement protection, not these ignored permission bits.
    require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o777, "installation-untrusted-symlink")


def _read_link(parent, name, path, before):
    require(hasattr(os, "O_PATH"), "installation-symlink-platform")
    _symlink(before)
    fd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        opened = os.fstat(fd)
        _symlink(opened)
        require(_stamp(before) == _stamp(opened), "installation-entry-changed")
        # Empty-path readlinkat reads the opened symlink, never a replaced name.
        target = os.readlink("", dir_fd=fd)
        _link_target(path, target)
        after = os.fstat(fd)
        require(_stamp(opened) == _stamp(after), "installation-symlink-changed")
        return target, _stamp(after)
    finally:
        os.close(fd)


def _open_directory(path):
    parts = _absolute(path)
    fd = os.open("/", DIR_FLAGS)
    try:
        _directory(os.fstat(fd))
        for part in parts:
            following = os.open(part, DIR_FLAGS, dir_fd=fd)
            try:
                _directory(os.fstat(following))
            except BaseException:
                os.close(following)
                raise
            os.close(fd)
            fd = following
        return fd
    except BaseException:
        os.close(fd)
        raise


def _hash_file(fd, path, limit, *, private=False, keep=False):
    before = os.fstat(fd)
    _regular(before, private=private)
    require(0 <= before.st_size <= limit, "installation-file-limit")
    hasher, chunks, size = hashlib.sha256(), [], 0
    while True:
        chunk = os.read(fd, min(1024 * 1024, limit - size + 1))
        if not chunk:
            break
        size += len(chunk)
        require(size <= limit, "installation-file-limit")
        hasher.update(chunk)
        if keep:
            chunks.append(chunk)
    after = os.fstat(fd)
    require(_stamp(before) == _stamp(after) and size == after.st_size, "installation-file-changed")
    result = TrustedFile(path, after.st_dev, after.st_ino, hasher.hexdigest(), size)
    return result, b"".join(chunks) if keep else None, _stamp(after)


def _file(path, limit, *, private=False, keep=False):
    parts = _absolute(path)
    require(parts, "installation-file-path")
    parent = _open_directory(str(PurePosixPath(path).parent))
    try:
        fd = os.open(parts[-1], FILE_FLAGS, dir_fd=parent)
        try:
            return _hash_file(fd, path, limit, private=private, keep=keep)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def trusted_file(path, max_bytes=MAX_FILE_BYTES):
    """Root-safe regular-file evidence, not a /proc symlink or trust bypass.

    All ancestors and the single-link file must be root-owned and non-writable
    by group/other. The caller supplies only its internal fixed trusted path.
    """
    _root()
    require(type(max_bytes) is int and 0 < max_bytes <= MAX_TOTAL_BYTES, "installation-file-limit")
    try:
        return _file(path, max_bytes)[0]
    except OSError:
        raise Denied("installation-filesystem") from None


def _manifest(raw, policy):
    value = decode_json(raw)
    require(set(value) == {"schema", "runner_id", "service_uid", "runner_version", "package_sha256",
                           "files", "directories", "symlinks", "runtime_directories"}
            and type(value["schema"]) is int and value["schema"] == 1
            and type(value["runner_version"]) is str
            and value["runner_version"] == policy.runner_version == SUPPORTED_VERSION
            and type(value["runner_id"]) is int and value["runner_id"] == policy.runner_id
            and type(value["service_uid"]) is int and value["service_uid"] == policy.service_uid
            and type(value["package_sha256"]) is str and HEX.fullmatch(value["package_sha256"]),
            "installation-manifest")
    files, directories, links = value["files"], value["directories"], value["symlinks"]
    runtime = value["runtime_directories"]
    require(type(runtime) is dict and set(runtime) == {"_diag"}
            and type(runtime["_diag"]) is dict and set(runtime["_diag"]) == {"uid", "mode"}
            and type(runtime["_diag"]["uid"]) is int and runtime["_diag"]["uid"] == policy.service_uid
            and type(runtime["_diag"]["mode"]) is int and runtime["_diag"]["mode"] == 0o700,
            "installation-runtime-policy")
    require(type(files) is dict and type(directories) is list and type(links) is dict
            and len(files) + len(directories) + len(links) <= MAX_ENTRIES, "installation-manifest-limit")
    for path, expected in files.items():
        _relative(path)
        require(type(expected) is str and HEX.fullmatch(expected), "installation-manifest-hash")
    for path in directories:
        _relative(path)
    for path, target in links.items():
        _relative(path)
        destination = _link_target(path, target)
        require(destination in files, "installation-symlink-not-regular-target")
        # No symlink chain or symlink ancestor may supply target code.
        require(all(str(parent) in directories for parent in PurePosixPath(destination).parents
                    if str(parent) != "."), "installation-symlink-target-parent")
    require(len(set(directories)) == len(directories) and not set(files) & set(directories)
            and not set(links) & (set(files) | set(directories))
            and not {".env", ".path"} & set(directories)
            and not any(path == "_diag" or path.startswith("_diag/")
                        for path in set(files) | set(directories) | set(links))
            and not {".env", ".path"} & set(links)
            and REQUIRED_FILES <= set(files) and REQUIRED_DIRECTORIES <= set(directories),
            "installation-required-files")
    return value


def _start_hash_workers(pool):
    """Establish the entire fixed pool before transferring any file FD."""
    gate = threading.Barrier(HASH_WORKERS + 1)
    def ready():
        gate.wait(5)
        return threading.current_thread()
    try:
        started = [pool.submit(ready) for _ in range(HASH_WORKERS)]
        gate.wait(5)
        threads = tuple(future.result() for future in started)
        require(len(set(threads)) == HASH_WORKERS, "installation-hash-worker-count")
        return threads
    except BaseException:
        # A lazy executor start can fail after enqueue. Here that queue contains
        # only barrier tasks, never a file descriptor with ambiguous ownership.
        gate.abort()
        raise

def _inventory(root_fd, root, *, hash_files, service_uid):
    files, directories, links, stamps, startup, runtime, size = {}, set(), {}, {}, {}, {}, 0

    pending, owned = [], []

    def hash_owned(work):
        child, relative, expected = work["fd"], work["relative"], work["stamp"]
        # Ownership of this bounded FD transfers to one worker, including on error.
        try:
            require(_stamp(os.fstat(child)) == expected, "installation-entry-changed")
            result = _hash_file(child, root + "/" + relative,
                1024 * 1024 if relative == ".runner" else MAX_FILE_BYTES, keep=relative == ".runner")
            require(result[2] == expected, "installation-entry-changed")
            return result
        finally:
            try:
                os.close(child)
            finally:
                work["closed"] = True

    def complete_one():
        relative, future, work = pending.pop(0)
        result, content, stamp = future.result()
        require(work["closed"], "installation-hash-file-ownership")
        files[relative], stamps[relative] = result, stamp
        if content is not None:
            startup[relative] = content
        owned.remove(work)

    def walk(fd, prefix, depth):
        nonlocal size
        require(depth <= MAX_DEPTH, "installation-inventory-limit")
        before = os.fstat(fd)
        _directory(before)
        os.lseek(fd, 0, os.SEEK_SET)
        with os.scandir(fd) as entries:
            for entry in entries:
                name = entry.name
                relative = _relative(prefix + name)
                require(len(files) + len(directories) + len(links) < MAX_ENTRIES, "installation-inventory-limit")
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not prefix and name == "_diag":
                    require(hasattr(os, "O_PATH"), "installation-runtime-platform")
                    before_runtime = _runtime_stamp(info, service_uid)
                    child = os.open(name, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        after_runtime = _runtime_stamp(os.fstat(child), service_uid)
                        require(before_runtime == after_runtime, "installation-runtime-changed")
                        runtime[relative] = after_runtime
                    finally:
                        os.close(child)
                elif stat.S_ISLNK(info.st_mode):
                    links[relative], stamps[relative] = _read_link(fd, name, relative, info)
                elif stat.S_ISDIR(info.st_mode):
                    child = os.open(name, DIR_FLAGS, dir_fd=fd)
                    try:
                        _directory(os.fstat(child))
                        require(_stamp(info) == _stamp(os.fstat(child)), "installation-entry-changed")
                        directories.add(relative)
                        walk(child, relative + "/", depth + 1)
                    finally:
                        os.close(child)
                else:
                    _regular(info)
                    child = os.open(name, FILE_FLAGS, dir_fd=fd)
                    work = None
                    try:
                        last = os.fstat(child)
                        _regular(last)
                        require(_stamp(info) == _stamp(last), "installation-entry-changed")
                        require(0 <= last.st_size <= MAX_FILE_BYTES, "installation-file-limit")
                        stamp = _stamp(last)
                        files[relative] = None
                        size += stamp[6]
                        require(size <= MAX_TOTAL_BYTES, "installation-inventory-limit")
                        if hash_files and stamp[6] >= HASH_PARALLEL_MIN_BYTES:
                            require(len(owned) < HASH_WORKERS, "installation-hash-queue-bound")
                            work = {"fd": child, "relative": relative, "stamp": stamp, "closed": False}
                            owned.append(work)  # Register ownership BEFORE possibly ambiguous submit.
                            child = None
                            future = pool.submit(hash_owned, work)
                            pending.append((relative, future, work))
                            if len(pending) >= HASH_WORKERS:
                                complete_one()
                        elif hash_files:
                            result, content, actual_stamp = _hash_file(child, root + "/" + relative,
                                1024 * 1024 if relative == ".runner" else MAX_FILE_BYTES,
                                keep=relative == ".runner")
                            require(actual_stamp == stamp, "installation-entry-changed")
                            files[relative], stamps[relative] = result, actual_stamp
                            if content is not None:
                                startup[relative] = content
                        else:
                            stamps[relative] = stamp
                    finally:
                        if child is not None and not any(item is work for item in owned):
                            os.close(child)
        after = os.fstat(fd)
        require(_stamp(before) == _stamp(after), "installation-directory-changed")
        stamps[prefix[:-1] if prefix else "."] = _stamp(after)

    if hash_files:
        # Only >=1MiB independent files use futures; small files stay synchronous.
        # At most four retained large-file tasks; no unbounded work queue.
        # Context shutdown joins every worker even when walking/hash validation fails.
        threads = ()
        try:
            with ThreadPoolExecutor(max_workers=HASH_WORKERS, thread_name_prefix="lit-stock-hash") as pool:
                threads = _start_hash_workers(pool)
                walk(root_fd, "", 0)
                while pending:
                    complete_one()
        finally:
            # Never close an uncertain submitted FD while any worker could still
            # use its number. Unknown shutdown holds the FD until process exit.
            require(not owned or (threads and all(not thread.is_alive() for thread in threads)),
                    "installation-hash-workers-not-joined")
            for work in owned:
                if not work["closed"]:
                    try:
                        os.close(work["fd"])
                    finally:
                        work["closed"] = True
    else:
        walk(root_fd, "", 0)
    require(set(runtime) == {"_diag"}, "installation-runtime-missing")
    return files, directories, links, stamps, startup, runtime

def verify_installation(policy):
    """Acquire current root-owned FS evidence. Never consume caller snapshots."""
    _root()
    require(type(policy) is InstallationPolicy and type(policy.runner_id) is int and policy.runner_id > 0
            and type(policy.service_uid) is int and policy.service_uid > 0
            and type(policy.runner_version) is str and policy.runner_version == SUPPORTED_VERSION,
            "installation-policy")
    _absolute(policy.root)
    _absolute(policy.manifest_path)
    require(policy.root != "/" and policy.manifest_path != policy.root
            and not policy.manifest_path.startswith(policy.root + "/"), "installation-manifest-location")
    try:
        manifest, raw, manifest_stamp = _file(policy.manifest_path, MAX_MANIFEST_BYTES, private=True, keep=True)
        value = _manifest(raw, policy)
        root_fd = _open_directory(policy.root)
        try:
            files, directories, links, stamps, startup, runtime = _inventory(
                root_fd, policy.root, hash_files=True, service_uid=policy.service_uid)
            require(set(files) == set(value["files"]) and directories == set(value["directories"])
                    and links == value["symlinks"],
                    "installation-inventory-mismatch")
            require(all(result.sha256 == value["files"][name] for name, result in files.items()),
                    "installation-file-hash")
            settings = decode_json(startup[".runner"])
            # RunnerSettings.AgentId is serialized by the pinned camel-case
            # resolver. It is not a fabricated runnerId alias or PascalCase.
            require(not any(k.lower() in {"agentid", "disableupdate"}
                            and k not in {"agentId", "disableUpdate"} for k in settings)
                    and type(settings.get("agentId")) is int and settings["agentId"] == policy.runner_id
                    and settings.get("disableUpdate") is True, "installation-runner-settings")
            _, again_dirs, again_links, again_stamps, _, again_runtime = _inventory(
                root_fd, policy.root, hash_files=False, service_uid=policy.service_uid)
            require(directories == again_dirs and links == again_links
                    and stamps == again_stamps and runtime == again_runtime,
                    "installation-tree-changed")
            # Re-open the configured root through its checked ancestors too:
            # the retained dirfd must still identify the configured directory.
            current = _open_directory(policy.root)
            try:
                require(_stamp(os.fstat(current)) == stamps["."], "installation-root-changed")
            finally:
                os.close(current)
        finally:
            os.close(root_fd)
        check_manifest, _, check_stamp = _file(policy.manifest_path, MAX_MANIFEST_BYTES, private=True)
        require(check_stamp == manifest_stamp and check_manifest == manifest, "installation-manifest-changed")
        bash, _, bash_stamp = _file(BASH, MAX_FILE_BYTES)
        require(bash_stamp[2] & 0o111, "installation-not-executable")
        for name in ("run.sh", "config.sh", "svc.sh", "runsvc.sh", "bin/runsvc.sh", "bin/Runner.Listener",
                     "bin/Runner.Worker", "externals/node24/bin/node"):
            require(stamps[name][2] & 0o111, "installation-not-executable")
        node = files["externals/node24/bin/node"]
        listener, worker = files["bin/Runner.Listener"], files["bin/Runner.Worker"]
        require(stamps["runsvc.sh"][2] & 0o444 and stamps["bin/RunnerService.js"][2] & 0o444,
                "installation-not-readable")
        return InstallationProof(
            policy.root,
            ExecutablePolicy(BASH, bash.device, bash.inode, ("/bin/bash", policy.root + "/runsvc.sh")),
            ExecutablePolicy(node.path, node.device, node.inode,
                             ("./externals/node24/bin/node", "./bin/RunnerService.js")),
            ExecutablePolicy(listener.path, listener.device, listener.inode,
                             (listener.path, "run", "--startuptype", "service")),
            ExecutablePolicy(worker.path, worker.device, worker.inode),
            MappingProxyType({result.path: result.sha256 for result in files.values()}),
            MappingProxyType({policy.root + "/" + name: target for name, target in links.items()}),
            tuple(sorted(policy.root + "/" + name for name in directories)),
            (policy.root + "/_diag",),
            manifest.path, manifest.sha256, value["package_sha256"], value["runner_version"],
            MappingProxyType({result.path: result for result in files.values()}),
            MappingProxyType({policy.root + "/" + name: stamps[name] for name in files}),
            MappingProxyType(dict(stamps)), MappingProxyType(dict(runtime)),
        )
    except OSError:
        raise Denied("installation-filesystem") from None
