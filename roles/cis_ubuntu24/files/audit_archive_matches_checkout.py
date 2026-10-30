#!/usr/bin/python3
"""Compare an offline transport with an admitted checkout; never extract it."""

import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
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
        verify(*sys.argv[1:])
    except (OSError, ValueError, tarfile.TarError):
        sys.exit("Offline audit transport does not match the admitted checkout")
    print("Offline audit transport matches the complete admitted working tree")
