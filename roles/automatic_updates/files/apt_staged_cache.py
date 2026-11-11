#!/usr/bin/python3
"""Coupled signed APT list/archive/bin cache transaction; never install packages."""
import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess

SPEC = importlib.util.spec_from_file_location("apt_staged_transaction", Path(__file__).with_name("apt_staged_transaction.py"))
TX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TX)
DATA = TX.METADATA
require = DATA.require
MAX_JOURNAL = 64 * 1024 * 1024

DEFAULT_PATHS = {
    "lists": Path("/var/lib/apt/lists"), "archives": Path("/var/cache/apt/archives"),
    "base": Path("/var/lib/apt/lit-staged-patches"), "archive_base": Path("/var/cache/apt/lit-staged-patches"),
    "stamp": Path("/var/lib/apt/periodic/update-success-stamp"),
    "pkgcache": Path("/var/cache/apt/pkgcache.bin"), "srcpkgcache": Path("/var/cache/apt/srcpkgcache.bin"),
    "machine": Path("/etc/machine-id"), "status": Path("/var/lib/dpkg/status"),
    "frontend_lock": Path("/var/lib/dpkg/lock-frontend"), "dpkg_lock": Path("/var/lib/dpkg/lock"),
}


def now():
    return datetime.now(timezone.utc)


def standard_layout():
    options = {"lists": "Dir::State::lists/d", "archives": "Dir::Cache::archives/d",
               "status": "Dir::State::status/f", "pkgcache": "Dir::Cache::pkgcache/f",
               "srcpkgcache": "Dir::Cache::srcpkgcache/f"}
    argv = ["/usr/bin/apt-config", "shell"]
    for name, option in options.items():
        argv += [name.upper(), option]
    raw = subprocess.check_output(argv, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                                  stderr=subprocess.PIPE, timeout=30).decode()
    values = dict(token.split("=", 1) for token in shlex.split(raw))
    for name in options:
        value = values.get(name.upper(), "")
        if name in ("pkgcache", "srcpkgcache") and not value:
            continue  # Disabled generated caches may leave old files to retain.
        require(value and Path(value).resolve() == DEFAULT_PATHS[name], "Unsupported actual APT cache layout")


def file_state(path):
    require(not path.is_symlink(), "Symlink in declared cache file state")
    if not path.exists():
        return None
    DATA.regular(path, DATA.MAX_INDEX, allow_empty=True)
    info = path.stat()
    return {"sha256": DATA.digest(path), "bytes": info.st_size, "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid, "gid": info.st_gid, "mtime_ns": info.st_mtime_ns}


def directory_meta(path):
    require(path.resolve() == path and not path.is_symlink() and path.is_dir(), "Canonical cache directory required")
    info = path.stat()
    require(info.st_uid == os.geteuid() and not info.st_mode & 0o022, "Owned non-writable cache directory required")
    return {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
            "mtime_ns": info.st_mtime_ns, "atime_ns": info.st_atime_ns}


def origin_ns(manifest):
    value = DATA.utc(manifest["started_utc"])
    return int(value.timestamp()) * 10**9 + value.microsecond * 1000


def fresh(manifest, request, clock):
    maximum = request["maximum_age_seconds"]
    require(type(maximum) is int and 0 < maximum <= 3600, "Invalid acquisition freshness policy")
    start, end, current = DATA.utc(manifest["started_utc"]), DATA.utc(manifest["acquired_utc"]), clock()
    require(start <= end <= current and (current - start).total_seconds() < maximum,
            "Acquisition expired before cache mutation")


def event(journal, state):
    journal["state"] = state
    journal.setdefault("events", []).append({"state": state, "utc": now().isoformat()})


def save(journal, location):
    require(len(json.dumps(journal).encode()) < MAX_JOURNAL - 65536, "Cache journal exceeds bounded control capacity")
    TX.atomic_json(location / "journal.json", journal)


def clone_directory_shape(original, destination):
    meta = directory_meta(original)
    destination.mkdir(mode=0o700)
    os.chmod(destination, meta["mode"])
    os.chown(destination, meta["uid"], meta["gid"])
    for name in ("partial", "auxfiles"):
        source = original / name
        if source.exists():
            target = destination / name
            target.mkdir(mode=0o700)
            shutil.copystat(source, target, follow_symlinks=False)
            os.chown(target, source.stat().st_uid, source.stat().st_gid)
    os.link(original / "lock", destination / "lock", follow_symlinks=False)


def durable_copy(source, destination, metadata=None):
    shutil.copy2(source, destination, follow_symlinks=False)
    if metadata:
        os.chmod(destination, metadata["mode"])
        os.chown(destination, metadata["uid"], metadata["gid"])
        os.utime(destination, ns=(metadata["mtime_ns"], metadata["mtime_ns"]))
    with destination.open("rb") as stream:
        os.fsync(stream.fileno())


def restore_files(paths, location, journal):
    for name in ("pkgcache", "srcpkgcache", "stamp"):
        target = paths[name]
        before = journal["before_files"][name]
        if file_state(target) == before:
            continue
        if before is None:
            if target.exists():
                require(name != "stamp", "Unexpected freshness stamp; retain transaction for reconciliation")
                require(target.stat().st_uid == os.geteuid(), "Unexpected generated-cache owner")
                DATA.regular(target, DATA.MAX_INDEX, allow_empty=True)
                target.unlink()
        else:
            source = location / ("previous-" + name)
            require(file_state(source) == before, "Protected cache file snapshot changed")
            # Copy on the target filesystem before atomic replacement if volumes differ.
            fd, name_on_target = TX.tempfile.mkstemp(prefix=".lit-apt-return-", dir=target.parent)
            os.close(fd)
            temporary = Path(name_on_target)
            durable_copy(source, temporary, before)
            os.replace(temporary, target)
            TX.fsync_directory(target.parent)
        require(file_state(target) == before, "Original generated cache or stamp was not restored")


def rollback(paths, location, archive_location, journal, swap):
    if journal["after_dirs"] is None:
        require(journal["state"] in ("PREPARING_CACHES", "ABORTED_PREPARATION"),
                "Unexplained preparation state requires reconciliation")
        require({name: TX.tree_fingerprint(paths[name]) for name in journal["before_dirs"]}
                == journal["before_dirs"], "Live caches changed during interrupted preparation")
        require({name: file_state(paths[name]) for name in journal["before_files"]}
                == journal["before_files"], "Live files changed during interrupted preparation")
        changed = journal["state"] != "ABORTED_PREPARATION"
        if changed:
            event(journal, "ABORTED_PREPARATION")
            save(journal, location)
        return changed
    operations = []
    for name, snapshot in (("lists", location / "exchange-lists"), ("archives", archive_location / "exchange-archives")):
        before, after = journal["before_dirs"][name], journal["after_dirs"][name]
        current, saved = TX.tree_fingerprint(paths[name]), TX.tree_fingerprint(snapshot)
        if current == before and saved == after:
            continue
        require(current == after and saved == before, "Cache changed outside this transaction; preserve snapshots")
        operations.append((paths[name], snapshot))
    stamp = file_state(paths["stamp"])
    require(stamp in (journal["before_files"]["stamp"], journal["after_files"]["stamp"]),
            "Freshness state changed outside this transaction")
    for name in ("pkgcache", "srcpkgcache", "stamp"):
        current = file_state(paths[name])
        before = journal["before_files"][name]
        if current is not None:
            require(current["uid"] in (os.geteuid(), before["uid"] if before else os.geteuid()),
                    "Unexpected generated-file ownership")
        if before is not None:
            require(file_state(location / ("previous-" + name)) == before, "Protected file snapshot changed")
    # Both cache directories and stamp are checked before the first return mutation.
    for target, snapshot in operations:
        swap(target, snapshot)
    restore_files(paths, location, journal)
    for name in ("lists", "archives"):
        require(TX.tree_fingerprint(paths[name]) == journal["before_dirs"][name], "Cache return verification failed")
        meta = journal["directory_meta"][name]
        os.utime(paths[name], ns=(meta["atime_ns"], meta["mtime_ns"]))
    changed = bool(operations) or journal["state"] != "ROLLED_BACK_CACHES"
    if changed:
        event(journal, "ROLLED_BACK_CACHES")
        save(journal, location)
    return changed


def installed_versions(status, packages):
    with status.open() as stream:
        installed = {(row.get("Package"), row.get("Architecture")): row for row in DATA.control_records(stream)}
    for package in packages:
        row = installed.get((package["package"], package["architecture"]), {})
        require(row.get("Version") == package["version"] and row.get("Status", "").endswith(" ok installed"),
                "Expected signed package version is not installed")


def audit_packages():
    result = subprocess.run(["/usr/bin/dpkg", "--audit"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=True)
    require(not result.stdout.strip(), "Package audit requires reconciliation")


def prune_snapshot(path, live):
    if not path.exists():
        return
    TX.protected_directory(path.parent)
    require(path.is_dir() and not path.is_symlink() and not os.path.samefile(path, live),
            "Refuse pruning active or unexpected cache state")
    for child in path.rglob("*"):
        require(not child.is_symlink() and (child.is_dir() or child.is_file()), "Unexpected snapshot object")
    shutil.rmtree(path)


def transact(action, bundle, request, paths=None, verifier=DATA.verify, swap=TX.exchange, clock=now, audit=audit_packages):
    require(action in ("import", "rollback", "confirm", "prune"), "Unsupported cache lifecycle action")
    paths = DEFAULT_PATHS if paths is None else paths
    identity, checksum = request["machine_id"], request["manifest_sha256"]
    require(DATA.SHA256.fullmatch(checksum), "Independent manifest digest required")
    require(paths["machine"].read_text().strip() == identity, "Wrong cache transaction target")
    if action in ("import", "rollback"):
        require(DATA.digest(paths["status"]) == request["status_sha256"], "Installed state changed; cache rollback cannot undo packages")
    manifest = None
    if action == "import":
        verifier(bundle, request)
        manifest = DATA.read_json(bundle / "manifest.json")
        require(manifest["schema"] == 2, "Full cache import requires schema2 target policy and payload verification")
        fresh(manifest, request, clock)
    for name in ("lists", "archives"):
        directory_meta(paths[name])
    for base in ("base", "archive_base"):
        TX.protected_directory(paths[base], create=action == "import")
    require(paths["base"].stat().st_dev == paths["lists"].stat().st_dev
            and paths["archive_base"].stat().st_dev == paths["archives"].stat().st_dev,
            "Each protected snapshot must share its actual cache filesystem")
    location, archive_location = paths["base"] / checksum, paths["archive_base"] / checksum
    with ExitStack() as locks:
        for path in [paths["base"] / "transaction.lock", paths["archive_base"] / "transaction.lock",
                     paths["frontend_lock"], paths["dpkg_lock"], paths["lists"] / "lock", paths["archives"] / "lock"]:
            locks.enter_context(TX.lock_file(path))
        if action in ("import", "rollback"):
            require(DATA.digest(paths["status"]) == request["status_sha256"], "Installed state changed while acquiring locks")
        if location.exists():
            TX.protected_directory(location)
            journal = DATA.read_json(DATA.regular(location / "journal.json", MAX_JOURNAL), limit=MAX_JOURNAL)
            require(journal["manifest_sha256"] == checksum and journal["machine_id"] == identity
                    and journal["status_sha256"] == request["status_sha256"], "Cache lifecycle binding differs")
            if action == "import":
                verifier(bundle, request)
                fresh(manifest, request, clock)
                require(journal["state"] == "IMPORTED_CACHES", "Prior cache attempt requires explicit reconciliation")
                for name in ("lists", "archives"):
                    require(TX.tree_fingerprint(paths[name]) == journal["after_dirs"][name], "Imported cache changed outside transaction")
                require(file_state(paths["stamp"]) == journal["after_files"]["stamp"], "Imported freshness stamp changed")
                for name in ("pkgcache", "srcpkgcache"):
                    generated = file_state(paths[name])
                    require(generated is None or generated["uid"] == os.geteuid(), "Unexpected generated cache ownership")
                return {"state": journal["state"], "changed": False, "packages_changed": False}
            if action == "rollback":
                TX.protected_directory(archive_location)
                changed = rollback(paths, location, archive_location, journal, swap)
            elif action == "confirm":
                require(journal["state"] in ("IMPORTED_CACHES", "CONFIRMED_CACHES"), "Only an imported cache may be confirmed")
                changed = journal["state"] != "CONFIRMED_CACHES"
                if changed:
                    installed_versions(paths["status"], journal["packages"])
                    audit()
                    journal["confirmed_status_sha256"] = DATA.digest(paths["status"])
                    event(journal, "CONFIRMED_CACHES")
                    save(journal, location)
            else:
                require(journal["state"] in ("ROLLED_BACK_CACHES", "CONFIRMED_CACHES", "ABORTED_PREPARATION", "PRUNED_CACHES"),
                        "Active or unexplained snapshots cannot be pruned")
                changed = journal["state"] != "PRUNED_CACHES"
                if changed:
                    prune_snapshot(location / "exchange-lists", paths["lists"])
                    if archive_location.exists():
                        TX.protected_directory(archive_location)
                        prune_snapshot(archive_location / "exchange-archives", paths["archives"])
                    for name in ("pkgcache", "srcpkgcache", "stamp"):
                        previous = location / ("previous-" + name)
                        if previous.exists():
                            DATA.regular(previous, DATA.MAX_INDEX, allow_empty=True).unlink()
                    event(journal, "PRUNED_CACHES")
                    save(journal, location)
            return {"state": journal["state"], "changed": changed, "packages_changed": False,
                    "manifest_sha256": checksum, "package_updates_accepted": False}
        require(action == "import" and not archive_location.exists(), "No admitted transaction exists; preserve unknown state")
        verifier(bundle, request)
        fresh(manifest, request, clock)
        before_dirs = {name: TX.tree_fingerprint(paths[name]) for name in ("lists", "archives")}
        before_files = {name: file_state(paths[name]) for name in ("pkgcache", "srcpkgcache", "stamp")}
        meta = {name: directory_meta(paths[name]) for name in ("lists", "archives")}
        metadata_bytes = sum((bundle / row["file"]).stat().st_size for row in manifest["releases"] + manifest["indexes"])
        binary_bytes = sum(row["bytes"] for row in before_files.values() if row)
        payload_bytes = sum(row["bytes"] for row in manifest["packages"])
        require(shutil.disk_usage(paths["base"]).free > metadata_bytes + binary_bytes + 128 * 1024**2,
                "Insufficient list/file snapshot capacity")
        require(shutil.disk_usage(paths["archive_base"]).free > payload_bytes + 128 * 1024**2,
                "Insufficient archive staging capacity")
        location.mkdir(mode=0o700)
        archive_location.mkdir(mode=0o700)
        journal = {"schema": 1, "manifest_sha256": checksum, "machine_id": identity,
                   "status_sha256": request["status_sha256"], "before_dirs": before_dirs,
                   "before_files": before_files, "directory_meta": meta, "packages": manifest["packages"],
                   "after_dirs": None, "after_files": None, "tool_sha256": DATA.digest(Path(__file__))}
        event(journal, "PREPARING_CACHES")
        save(journal, location)
        TX.atomic_json(location / "request.json", request)
        prepared = {"lists": location / "exchange-lists", "archives": archive_location / "exchange-archives"}
        try:
            for name in ("pkgcache", "srcpkgcache", "stamp"):
                if before_files[name] is not None:
                    durable_copy(paths[name], location / ("previous-" + name), before_files[name])
            for name in ("lists", "archives"):
                clone_directory_shape(paths[name], prepared[name])
            # Cached unrelated debs remain present with identical metadata/inodes.
            for item in paths["archives"].iterdir():
                if item.is_file() and item.name != "lock":
                    os.link(item, prepared["archives"] / item.name, follow_symlinks=False)
            timestamp = origin_ns(manifest)
            for row in manifest["releases"] + manifest["indexes"]:
                target = prepared["lists"] / row["target_name"]
                durable_copy(bundle / row["file"], target)
                os.chmod(target, 0o644)
                os.utime(target, ns=(timestamp, timestamp))
            for row in manifest["packages"]:
                target = prepared["archives"] / row["target_name"]
                if target.exists() and DATA.digest(target) == row["sha256"]:
                    continue
                if target.exists():
                    target.unlink()
                durable_copy(bundle / row["file"], target)
                os.chmod(target, 0o644)
                os.utime(target, ns=(timestamp, timestamp))
            for name in ("lists", "archives"):
                os.utime(prepared[name], ns=(timestamp, timestamp))
            after_dirs = {name: TX.tree_fingerprint(prepared[name]) for name in ("lists", "archives")}
            after_files = {"pkgcache": None, "srcpkgcache": None,
                           "stamp": ({**before_files["stamp"], "mtime_ns": timestamp} if before_files["stamp"] else None)}
            journal.update(after_dirs=after_dirs, after_files=after_files)
            event(journal, "PREPARED_CACHES")
            save(journal, location)
            # Revalidate the exact mutable boundary after preparation, before swap.
            require({name: TX.tree_fingerprint(paths[name]) for name in ("lists", "archives")} == before_dirs,
                    "Cache changed during preparation")
            require({name: file_state(paths[name]) for name in before_files} == before_files, "Generated state changed during preparation")
            fresh(manifest, request, clock)
            for name in ("archives", "lists"):
                if before_dirs[name] != after_dirs[name]:
                    swap(paths[name], prepared[name])
                event(journal, "APPLYING_CACHES")
                save(journal, location)
            for name in ("pkgcache", "srcpkgcache"):
                if paths[name].exists():
                    paths[name].unlink()
                    TX.fsync_directory(paths[name].parent)
                save(journal, location)
            if before_files["stamp"]:
                os.utime(paths["stamp"], ns=(timestamp, timestamp))
            require({name: TX.tree_fingerprint(paths[name]) for name in after_dirs} == after_dirs, "Imported cache verification failed")
            require({name: file_state(paths[name]) for name in after_files} == after_files, "Imported generated state verification failed")
            event(journal, "IMPORTED_CACHES")
            save(journal, location)
        except BaseException:
            if journal["after_dirs"] is not None:
                rollback(paths, location, archive_location, journal, swap)
            else:
                require({name: TX.tree_fingerprint(paths[name]) for name in before_dirs} == before_dirs,
                        "Preparation failed with unexpected cache changes")
                event(journal, "ABORTED_PREPARATION")
                save(journal, location)
            raise
        return {"state": journal["state"], "changed": True, "manifest_sha256": checksum,
                "freshness_origin_utc": manifest["started_utc"], "journal": str(location / "journal.json"),
                "local_return_request": str(location / "request.json"), "packages_changed": False,
                "package_updates_accepted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", required=True, choices=("import", "rollback", "confirm", "prune"))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--request", required=True, type=Path)
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, "Cache lifecycle requires root")
        require(args.action != "import" or args.bundle is not None, "Import needs an admitted bundle")
        if args.action == "import":
            standard_layout()
        request = DATA.read_json(DATA.regular(args.request, DATA.MAX_MANIFEST))
        result = transact(args.action, args.bundle, request)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"state": "CACHE_TRANSACTION_STOPPED_RECONCILE_JOURNAL", "error_type": type(error).__name__,
                          "packages_changed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
