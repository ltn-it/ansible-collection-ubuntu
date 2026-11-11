#!/usr/bin/python3
"""Transactional metadata-only APT cache import; never install packages.

The adjacent signed-data verifier is mandatory. An exchange keeps the APT lists
lock inode live in both directories. A retained journal permits explicit rollback
even if the importing controller disappears. No freshness is extended past the
verified acquisition start.
"""
import argparse
from contextlib import ExitStack, contextmanager
import ctypes
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


SPEC = importlib.util.spec_from_file_location("apt_staged_bundle", Path(__file__).with_name("apt_staged_bundle.py"))
METADATA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(METADATA)
require = METADATA.require


def protected_directory(path, create=False):
    require(path.is_absolute() and path.resolve() == path, "Canonical transaction directory required")
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
            "Private owned transaction directory required")


def atomic_json(path, value):
    # A failed receipt replace must not leave one fixed .new name that blocks
    # the recovery receipt. Keep each incomplete write distinct and private.
    fd, name = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    temporary = Path(name)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fsync_directory(path.parent)


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def exchange(left, right):
    """Linux renameat2(RENAME_EXCHANGE): one atomic same-filesystem swap."""
    libc = ctypes.CDLL(None, use_errno=True)
    require(hasattr(libc, "renameat2"), "Atomic directory exchange is unavailable")
    call = libc.renameat2
    call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    call.restype = ctypes.c_int
    if call(-100, os.fsencode(left), -100, os.fsencode(right), 2) != 0:
        error = ctypes.get_errno()
        raise OSError(error, "Atomic APT directory exchange failed")
    fsync_directory(left.parent)
    fsync_directory(right.parent)


@contextmanager
def lock_file(path):
    # APT uses POSIX record locks, not flock. Never replace the lock inode.
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o640)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "Regular package lock required")
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def tree_fingerprint(path):
    result = {}
    for item in sorted(path.iterdir()):
        require(not item.is_symlink(), "Symlink in APT lists state")
        if item.name == "lock":
            require(item.is_file(), "Invalid APT list lock")
            continue
        if item.is_dir():
            require(item.name in ("partial", "auxfiles"), "Unexpected APT list directory")
            require(not any(item.iterdir()), "APT partial state requires reconciliation")
            continue
        info = item.stat()
        require(stat.S_ISREG(info.st_mode), "Unexpected APT list state")
        result[item.name] = {"sha256": METADATA.digest(item), "bytes": info.st_size,
                             "mtime_ns": info.st_mtime_ns, "mode": stat.S_IMODE(info.st_mode),
                             "uid": info.st_uid, "gid": info.st_gid}
    return result


def restore_stamp(stamp, transaction, journal):
    if journal["stamp_exists"]:
        shutil.copy2(transaction / "previous-stamp", stamp, follow_symlinks=False)
        os.chown(stamp, journal["stamp_uid"], journal["stamp_gid"])
    else:
        require(not stamp.exists(), "Unexpected newly created APT freshness stamp")


def rollback_locked(lists, stamp, transaction, journal, swap=exchange):
    snapshot = transaction / "exchange-lists"
    current = tree_fingerprint(lists)
    old = tree_fingerprint(snapshot)
    if current == journal["before"] and old == journal["after"]:
        # Previous rollback completed the exchange before its receipt write.
        pass
    else:
        require(current == journal["after"] and old == journal["before"],
                "APT cache changed after import; retain snapshot for manual reconciliation")
        swap(lists, snapshot)
    restore_stamp(stamp, transaction, journal)
    require(tree_fingerprint(lists) == journal["before"], "Restored APT cache verification failed")
    os.utime(lists, ns=(journal["lists_atime_ns"], journal["lists_mtime_ns"]))
    journal["state"] = "ROLLED_BACK_METADATA_ONLY"
    atomic_json(transaction / "journal.json", journal)
    return {"state": journal["state"], "changed": current != journal["before"],
            "manifest_sha256": journal["manifest_sha256"], "packages_changed": False}


def transact(action, bundle, request, base=Path("/var/lib/apt/lit-staged"),
             lists=Path("/var/lib/apt/lists"), stamp=Path("/var/lib/apt/periodic/update-success-stamp"),
             lock_paths=None, verifier=METADATA.verify, swap=exchange,
             machine_path=Path("/etc/machine-id"), status_path=Path("/var/lib/dpkg/status")):
    require(action in ("import", "rollback"), "Invalid metadata transaction action")
    require(METADATA.SHA256.fullmatch(request["manifest_sha256"]), "Admitted manifest digest required")
    require(request["machine_id"] == machine_path.read_text().strip(), "Wrong target for metadata transaction")
    require(request["status_sha256"] == METADATA.digest(status_path), "Package state changed since admission")
    if action == "import":
        verifier(bundle, request)
        require(not METADATA.read_json(bundle / "manifest.json").get("packages"),
                "Metadata-only import cannot import deb payloads; use a qualified archive-cache transaction")
    require(not lists.is_symlink() and lists.resolve() == lists and lists.is_dir(), "Canonical APT lists required")
    require(not stamp.is_symlink(), "Symlink APT freshness stamp is forbidden")
    protected_directory(base, create=(action == "import"))
    require(base.stat().st_dev == lists.stat().st_dev, "Snapshot must share the APT lists filesystem")
    transaction = base / request["manifest_sha256"]
    lock_paths = lock_paths or [Path("/var/lib/dpkg/lock-frontend"), Path("/var/lib/dpkg/lock"), lists / "lock"]
    with ExitStack() as locks:
        locks.enter_context(lock_file(base / "transaction.lock"))
        for path in lock_paths:
            locks.enter_context(lock_file(path))
        require(request["status_sha256"] == METADATA.digest(status_path), "Package state changed while acquiring locks")
        if action == "rollback":
            protected_directory(transaction)
            journal = METADATA.read_json(METADATA.regular(transaction / "journal.json", METADATA.MAX_MANIFEST))
            require(journal["manifest_sha256"] == request["manifest_sha256"]
                    and journal["machine_id"] == request["machine_id"]
                    and journal["status_sha256"] == request["status_sha256"], "Rollback binding differs")
            return rollback_locked(lists, stamp, transaction, journal, swap=swap)
        # Revalidate under locks, not merely before waiting for package ownership.
        evidence = verifier(bundle, request)
        if transaction.exists():
            protected_directory(transaction)
            journal = METADATA.read_json(METADATA.regular(transaction / "journal.json", METADATA.MAX_MANIFEST))
            require(journal["state"] == "IMPORTED_METADATA_ONLY"
                    and tree_fingerprint(lists) == journal["after"]
                    and lists.stat().st_mtime_ns == journal["imported_lists_mtime_ns"]
                    and (not stamp.exists() or stamp.stat().st_mtime_ns == journal["imported_stamp_mtime_ns"]),
                    "Existing transaction requires reconciliation")
            return {"state": journal["state"], "changed": False, "manifest_sha256": request["manifest_sha256"],
                    "packages_changed": False}
        require(len([path for path in base.iterdir() if path.is_dir()]) < 2, "Retained snapshot limit reached")
        before = tree_fingerprint(lists)
        manifest = METADATA.read_json(bundle / "manifest.json")
        entries = manifest["releases"] + manifest["indexes"]
        bytes_needed = sum((bundle / item["file"]).stat().st_size for item in entries)
        require(shutil.disk_usage(base).free > bytes_needed + 128 * 1024**2, "Insufficient protected staging capacity")
        transaction.mkdir(mode=0o700)
        prepared = transaction / "exchange-lists"
        prepared.mkdir(mode=0o755)
        info = lists.stat()
        os.chmod(prepared, stat.S_IMODE(info.st_mode))
        os.chown(prepared, info.st_uid, info.st_gid)
        for name in ("partial", "auxfiles"):
            previous = lists / name
            if previous.exists():
                following = prepared / name
                following.mkdir(mode=0o700)
                shutil.copystat(previous, following, follow_symlinks=False)
                os.chown(following, previous.stat().st_uid, previous.stat().st_gid)
        journal = {"state": "PREPARING_METADATA_ONLY", "manifest_sha256": request["manifest_sha256"],
                   "machine_id": request["machine_id"], "status_sha256": request["status_sha256"],
                   "before": before, "lists_atime_ns": info.st_atime_ns, "lists_mtime_ns": info.st_mtime_ns,
                   "stamp_exists": stamp.exists(), "stamp_uid": stamp.stat().st_uid if stamp.exists() else None,
                   "stamp_gid": stamp.stat().st_gid if stamp.exists() else None}
        if stamp.exists():
            require(stamp.is_file() and stamp.stat().st_nlink == 1, "Regular unlinked APT freshness stamp required")
            shutil.copy2(stamp, transaction / "previous-stamp", follow_symlinks=False)
        origin = METADATA.utc(evidence["freshness_origin_utc"]).timestamp()
        for item in entries:
            target = prepared / item["target_name"]
            shutil.copyfile(bundle / item["file"], target, follow_symlinks=False)
            os.chmod(target, 0o644)
            os.utime(target, (origin, origin))
            with target.open("rb") as stream:
                os.fsync(stream.fileno())
        # Preserve the inode held by the POSIX APT lists lock across the swap.
        os.link(lists / "lock", prepared / "lock", follow_symlinks=False)
        os.utime(prepared, (origin, origin))
        journal["after"] = tree_fingerprint(prepared)
        journal["imported_lists_mtime_ns"] = prepared.stat().st_mtime_ns
        journal["imported_stamp_mtime_ns"] = int(origin * 10**9) if stamp.exists() else None
        atomic_json(transaction / "journal.json", journal)
        swapped = False
        try:
            swap(lists, prepared)
            swapped = True
            if stamp.exists():
                os.utime(stamp, (origin, origin))
                journal["imported_stamp_mtime_ns"] = stamp.stat().st_mtime_ns
            require(tree_fingerprint(lists) == journal["after"], "Imported package metadata changed")
            journal["state"] = "IMPORTED_METADATA_ONLY"
            atomic_json(transaction / "journal.json", journal)
        except BaseException:
            if swapped or (tree_fingerprint(lists) == journal["after"]
                           and tree_fingerprint(prepared) == journal["before"]):
                rollback_locked(lists, stamp, transaction, journal, swap=swap)
            raise
        return {"state": journal["state"], "changed": True, "manifest_sha256": request["manifest_sha256"],
                "freshness_origin_utc": evidence["freshness_origin_utc"], "rollback_journal": str(transaction / "journal.json"),
                "packages_changed": False, "package_updates_accepted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", required=True, choices=("import", "rollback"))
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--request", required=True, type=Path)
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, "Metadata cache transaction requires root")
        METADATA.regular(args.request, METADATA.MAX_MANIFEST)
        result = transact(args.action, args.bundle, METADATA.read_json(args.request))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"state": "METADATA_TRANSACTION_STOPPED_RECONCILE_JOURNAL", "error_type": type(error).__name__,
                          "packages_changed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
