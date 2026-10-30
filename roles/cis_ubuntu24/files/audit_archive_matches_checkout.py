#!/usr/bin/python3
"""Compare an offline transport with an admitted checkout; never extract it."""

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile


MAX_BYTES = 64 * 1024 * 1024
MAX_FILES = 10000


def digest(stream):
    value = hashlib.sha256()
    size = 0
    while True:
        block = stream.read(1024 * 1024)
        if not block:
            return value.hexdigest()
        size += len(block)
        if size > MAX_BYTES:
            raise ValueError("Audit transport member exceeds its bound")
        value.update(block)


def validate_git(checkout):
    """Validate every Git input before any Git process reads local configuration."""
    checkout = Path(checkout)
    if str(checkout.resolve(strict=True)) != str(checkout):
        raise ValueError("Audit checkout must be canonical")
    for parent in (checkout, *checkout.parents):
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
            raise ValueError("Unprotected audit checkout ancestry")
    metadata = checkout / ".git"
    info = metadata.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("Audit Git metadata must be an in-place directory")
    total = count = 0
    for directory, directories, files in os.walk(checkout, followlinks=False):
        for path in (Path(directory), *(Path(directory) / name for name in [*directories, *files])):
            info = path.lstat()
            count += 1
            if count > MAX_FILES or info.st_uid != os.geteuid() or info.st_mode & 0o7022:
                raise ValueError("Unprotected audit Git input")
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("Linked or special audit Git input")
            total += info.st_size
            if total > MAX_BYTES:
                raise ValueError("Audit Git input exceeds its bound")
    for name in ("commondir", "config.worktree", "objects/info/alternates", "objects/info/http-alternates"):
        if os.path.lexists(metadata / name):
            raise ValueError("External audit Git metadata")
    if (metadata / "config").stat().st_size > 65536:
        raise ValueError("Audit Git configuration exceeds its bound")
    # Ask Git's own parser, without includes, index access or executable probes.
    # Git accepts deprecated dotted sections that generic INI parsers misclassify.
    environment = git_environment(checkout)
    try:
        config = subprocess.run(["/usr/bin/git", "config", "--null", "--no-includes", "--file",
                                 str(metadata / "config"), "--list"], env=environment, cwd=checkout,
                                capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("Unsupported audit Git configuration") from error
    if config.returncode or len(config.stdout) > MAX_BYTES:
        raise ValueError("Unsupported audit Git configuration")
    for record in config.stdout.split(b"\0"):
        key = record.partition(b"\n")[0]
        if key.split(b".", 1)[0].lower() in {b"include", b"includeif", b"filter", b"extensions"}:
            raise ValueError("External or executable audit Git configuration")


def git_environment(checkout):
    metadata = Path(checkout) / ".git"
    return {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
                   "GIT_CONFIG_COUNT": "0", "GIT_CONFIG_PARAMETERS": "",
                   "GIT_DIR": str(metadata), "GIT_COMMON_DIR": str(metadata),
                   "GIT_OBJECT_DIRECTORY": str(metadata / "objects"),
                   "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1"}


def validate_revision(checkout, revision):
    """Bind every working file to raw authenticated Git trees, never to the index."""
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Unsupported audit commit identity")
    checkout = Path(checkout)
    environment = git_environment(checkout)
    total = count = 0

    def object_bytes(kind, identity):
        nonlocal total, count
        command = ["/usr/bin/git", "-c", "protocol.allow=never", "cat-file"]
        try:
            size = subprocess.run(command + ["-s", identity], env=environment, cwd=checkout,
                                  capture_output=True, timeout=10, check=True)
            size = int(size.stdout)
            total += size
            count += 1
            if size < 0 or total > MAX_BYTES or count > MAX_FILES:
                raise ValueError("Audit commit tree exceeds its bound")
            result = subprocess.run(command + [kind, identity], env=environment, cwd=checkout,
                                    capture_output=True, timeout=10, check=True).stdout
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError("Unreadable pinned audit object") from error
        actual = hashlib.sha1(kind.encode() + b" " + str(len(result)).encode() + b"\0" + result).hexdigest()
        if len(result) != size or actual != identity:
            raise ValueError("Audit object does not match its immutable identity")
        return result

    commit = object_bytes("commit", revision)
    tree = commit.partition(b"\n")[0]
    if not re.fullmatch(rb"tree [0-9a-f]{40}", tree):
        raise ValueError("Malformed pinned audit commit")
    expected = {}
    pending = [(tree[5:].decode("ascii"), "")]
    while pending:
        identity, prefix = pending.pop()
        raw = object_bytes("tree", identity)
        while raw:
            header, separator, remainder = raw.partition(b"\0")
            mode, space, name = header.partition(b" ")
            if (not separator or not space or len(remainder) < 20 or not name or b"/" in name
                    or name in (b".", b"..", b".git")):
                raise ValueError("Malformed pinned audit tree")
            path = prefix + name.decode("utf-8")
            identity, raw = remainder[:20].hex(), remainder[20:]
            if mode == b"40000":
                pending.append((identity, path + "/"))
            elif mode in (b"100644", b"100755") and path not in expected:
                expected[path] = identity, mode == b"100755"
                if len(expected) > MAX_FILES:
                    raise ValueError("Audit commit tree exceeds its bound")
            else:
                raise ValueError("Unsupported pinned audit tree entry")
    actual = {}
    total = 0
    for directory, directories, files in os.walk(checkout, followlinks=False):
        if Path(directory) == checkout:
            directories[:] = [name for name in directories if name != ".git"]
        for name in files:
            path = Path(directory) / name
            info = path.lstat()
            total += info.st_size
            if total > MAX_BYTES or len(actual) >= MAX_FILES:
                raise ValueError("Audit working tree exceeds its bound")
            value = hashlib.sha1(b"blob " + str(info.st_size).encode() + b"\0")
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    value.update(block)
            actual[path.relative_to(checkout).as_posix()] = value.hexdigest(), bool(info.st_mode & 0o111)
    if actual != expected or "run_audit.sh" not in expected:
        raise ValueError("Audit working tree differs from the pinned commit")



def verify(archive, checkout, expected_sha256):
    checkout = Path(checkout)
    if str(checkout.resolve(strict=True)) != str(checkout) or not checkout.is_dir():
        raise ValueError("Audit checkout must be canonical")
    for parent in (checkout, *checkout.parents):
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
            raise ValueError("Unprotected audit checkout ancestry")
    with open(archive, "rb") as stream:
        if digest(stream) != expected_sha256:
            raise ValueError("Audit transport digest changed")
    expected = {}
    total = 0
    for directory, directories, files in os.walk(checkout, followlinks=False):
        if Path(directory) == checkout:
            directories[:] = [name for name in directories if name != ".git"]
        for name in [*directories, *files]:
            path = Path(directory) / name
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise ValueError("Unprotected audit working tree directory")
                continue
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or info.st_mode & 0o7022):
                raise ValueError("Audit working tree contains a linked or special file")
            total += info.st_size
            if total > MAX_BYTES or len(expected) >= MAX_FILES:
                raise ValueError("Audit working tree exceeds its bound")
            with path.open("rb") as stream:
                expected[path.relative_to(checkout).as_posix()] = (digest(stream), bool(info.st_mode & 0o111))
    if "run_audit.sh" not in expected:
        raise ValueError("Audit entrypoint is missing")
    seen, matched = set(), set()
    total = 0
    with tarfile.open(archive, "r:*") as transport:
        for member in transport:
            name = member.name.removeprefix("./").rstrip("/")
            path = PurePosixPath(name)
            if (path.is_absolute() or ".." in path.parts or not path.parts
                    or path.parts[0] != checkout.name or name != path.as_posix()):
                raise ValueError("Unsafe audit transport path")
            if name in seen or len(seen) >= MAX_FILES:
                raise ValueError("Duplicate or excessive audit transport members")
            seen.add(name)
            if not (member.isdir() or member.isfile()):
                raise ValueError("Linked or special audit transport member")
            if member.isdir():
                continue
            total += member.size
            if total > MAX_BYTES:
                raise ValueError("Audit transport exceeds its bound")
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            # Full-checkout transports can carry Git metadata. None of it is
            # extracted or executed; admission already checked the target Git.
            if path.parts[1:2] == (".git",):
                continue
            if relative not in expected:
                raise ValueError("Unexpected audit transport content")
            if member.mode & 0o7022:
                raise ValueError("Unsafe audit transport executable permissions")
            with transport.extractfile(member) as stream:
                actual = digest(stream), bool(member.mode & 0o111)
            if actual != expected[relative]:
                raise ValueError("Audit transport differs from the admitted working tree")
            matched.add(relative)
    if matched != set(expected):
        raise ValueError("Audit transport omits admitted working tree content")


if __name__ == "__main__":
    try:
        if sys.argv[1:2] == ["--git-inputs"]:
            validate_git(sys.argv[2])
            validate_revision(sys.argv[2], sys.argv[3])
        else:
            verify(*sys.argv[1:])
    except (OSError, ValueError, tarfile.TarError):
        sys.exit("Offline audit transport does not match the admitted checkout")
    print("Offline audit transport matches the complete admitted working tree")
