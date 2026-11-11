#!/usr/bin/python3
"""Verify fixed auditor bytes on a path other controller users cannot replace."""
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

MAX_BYTES = 64 * 1024 * 1024


def verify(path, expected):
    path = Path(path)
    if (not path.is_absolute() or str(path.resolve(strict=True)) != str(path)
            or not re.fullmatch(r"[0-9a-f]{64}", expected)):
        raise ValueError("Unbound auditor source")
    for directory in path.parents:
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
            raise ValueError("Unprotected auditor source ancestry")
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= MAX_BYTES
            or before.st_uid not in (0, os.geteuid()) or before.st_mode & 0o7022):
        raise ValueError("Unprotected auditor source")
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_uid", "st_gid", "st_mode", "st_nlink")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if any(getattr(before, key) != getattr(os.fstat(fd), key) for key in fields):
            raise ValueError("Auditor source changed before opening")
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(fd, min(1024 * 1024, MAX_BYTES + 1 - size))
            if not block:
                break
            size += len(block)
            if size > MAX_BYTES:
                raise ValueError("Auditor source exceeds its bound")
            digest.update(block)
        after = os.fstat(fd)
        if (any(getattr(before, key) != getattr(after, key) for key in fields)
                or size != before.st_size or digest.hexdigest() != expected):
            raise ValueError("Auditor source bytes changed")
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("Exact source arguments required")
        verify(sys.argv[1], sys.argv[2])
    except (OSError, ValueError):
        sys.exit("Refusing missing, linked or changed auditor bytes before vendor execution.")
    print("Protected fixed auditor source verified.")
