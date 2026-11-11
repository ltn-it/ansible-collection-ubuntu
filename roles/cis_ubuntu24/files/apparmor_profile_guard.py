"""Read-only verification of accepted Ubuntu usernamespace attachment profiles."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_policy(policy):
    require(isinstance(policy, list) and policy, "Expected a nonempty profile list")
    seen = set()
    fields = {"name", "executable", "sha256", "reason", "approval_reference"}
    for item in policy:
        require(isinstance(item, dict) and set(item) == fields, "Invalid profile fields")
        require(all(isinstance(value, str) for value in item.values()), "Invalid profile types")
        name = item["name"]
        require(re.fullmatch(r"[a-z][a-z0-9_-]*", name), "Invalid profile name")
        require(name not in seen, "Duplicate profile name")
        seen.add(name)
        require(re.fullmatch(r"/usr/(?:sbin|bin)/[a-z][a-z0-9_-]*", item["executable"]), "Invalid attachment")
        require(re.fullmatch(r"[0-9a-f]{64}", item["sha256"]), "Invalid profile SHA256")
        for field in ("reason", "approval_reference"):
            require(item[field].strip() and not re.search(r"[\x00-\x1f\x7f]", item[field]), "Invalid approval metadata")


def validate_restoration(restoration, policy):
    """Bind one previously approved repair; metadata never grants approval."""
    validate_policy(policy)
    fields = {"name", "machine_id", "package_version", "source", "previous_sha256", "approval_reference"}
    require(isinstance(restoration, dict) and set(restoration) == fields, "Invalid restoration fields")
    require(all(isinstance(value, str) and value.strip() for value in restoration.values()),
            "Invalid restoration types")
    require(not any(re.search(r"[\x00-\x1f\x7f]", value) for value in restoration.values()),
            "Invalid restoration metadata")
    require(re.fullmatch(r"[0-9a-f]{32}", restoration["machine_id"]), "Invalid machine identity")
    require(re.fullmatch(r"[0-9a-f]{64}", restoration["previous_sha256"]), "Invalid previous SHA256")
    source = Path(restoration["source"])
    require(source.is_absolute() and str(source) == restoration["source"] and ".." not in source.parts,
            "Invalid controller source path")
    selected = [item for item in policy if item["name"] == restoration["name"]]
    require(len(selected) == 1, "Restoration must select exactly one declared profile")
    item = selected[0]
    require(restoration["approval_reference"] == item["approval_reference"], "Restoration approval mismatch")
    require(restoration["previous_sha256"] != item["sha256"], "Restoration requires distinct profile hashes")
    return item


def verify_rollback_paths(restoration, selected, state_root=Path('/var/lib/lit-cis-apparmor'),
                          owner_uid=0, owner_gid=0, trusted_parent=Path('/')):
    """Inspect every existing ancestor and owned rollback object before mutation."""
    stage = state_root / restoration['machine_id'] / (restoration['name'] + '-' + restoration['previous_sha256'])
    for directory in reversed((stage, *stage.parents)):
        if directory != trusted_parent and trusted_parent not in directory.parents:
            continue
        if not os.path.lexists(directory):
            continue
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), "Unsafe rollback ancestor")
        require(info.st_uid == owner_uid and info.st_gid == owner_gid, "Unsafe rollback directory ownership")
        require(not stat.S_IMODE(info.st_mode) & 0o022, "Writable rollback ancestor")
        if directory == stage:
            require(stat.S_IMODE(info.st_mode) == 0o700, "Unsafe rollback directory mode")
    if not stage.exists():
        return
    require(set(path.name for path in stage.iterdir()) <= {'owner.json', 'before.profile'},
            "Unknown rollback directory contents")
    require((stage / 'owner.json').exists(), "Missing rollback ownership binding")
    for name in ('owner.json', 'before.profile'):
        path = stage / name
        if not os.path.lexists(path):
            continue
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "Unsafe rollback object")
        require(info.st_uid == owner_uid and info.st_gid == owner_gid, "Unsafe rollback object ownership")
        require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 65536, "Unsafe rollback object mode or size")
    expected = {key: value for key, value in restoration.items() if key != 'source'}
    expected['accepted_sha256'] = selected['sha256']
    require(json.loads((stage / 'owner.json').read_text()) == expected, "Unrelated rollback ownership binding")
    snapshot = stage / 'before.profile'
    if snapshot.exists():
        require(hashlib.sha256(snapshot.read_bytes()).hexdigest() == restoration['previous_sha256'],
                "Rollback snapshot hash drift")


def verify(policy, profile_root, kernel_profiles, owner_uid=0, owner_gid=0, restoration=None):
    """The CLI fixes all paths and root ownership; parameters permit isolated tests."""
    validate_policy(policy)
    selected = validate_restoration(restoration, policy) if restoration is not None else None
    restoring = False
    profile_root = Path(profile_root)
    require(profile_root.resolve(strict=True) == profile_root, "Redirected profile directory")
    directory = os.open(profile_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    hashes = {}
    try:
        ds = os.fstat(directory)
        require(ds.st_uid == owner_uid and ds.st_gid == owner_gid, "Unsafe profile directory ownership")
        require(stat.S_IMODE(ds.st_mode) in (0o700, 0o750, 0o755), "Writable profile directory")
        for item in policy:
            descriptor = os.open(item["name"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(descriptor, "rb") as stream:
                before = os.fstat(stream.fileno())
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "Unsafe profile object")
                require(before.st_uid == owner_uid and before.st_gid == owner_gid, "Unsafe profile ownership")
                require(stat.S_IMODE(before.st_mode) == 0o644, "Unsafe profile mode")
                require(before.st_size <= 65536, "Unexpected profile size")
                data = stream.read(65537)
                after = os.fstat(stream.fileno())
                identity = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                            "st_size", "st_mtime_ns", "st_ctime_ns")
                require(all(getattr(before, field) == getattr(after, field) for field in identity),
                        "Profile changed during verification")
            digest = hashlib.sha256(data).hexdigest()
            if selected is not None and item["name"] == selected["name"]:
                restoring = digest == restoration["previous_sha256"]
            if restoring and item["name"] == selected["name"]:
                hashes[item["name"]] = digest
                continue
            require(digest == item["sha256"], "Preserved profile hash drift: " + item["name"])
            text = data.decode("utf-8")
            header = (r"(?m)^profile\s+" + re.escape(item["name"]) + r"\s+"
                      + re.escape(item["executable"]) + r"\s+flags=\(unconfined\)\s*\{$")
            require(len(re.findall(header, text)) == 1, "Unexpected attachment declaration")
            require(re.search(r"(?m)^\s*userns,\s*$", text), "Missing usernamespace permission")
            hashes[item["name"]] = digest
    finally:
        os.close(directory)

    loaded = {}
    raw = Path(kernel_profiles).read_text(encoding="utf-8")
    require(0 < len(raw) <= 1048576, "Missing or excessive kernel profile inventory")
    for line in raw.splitlines():
        match = re.fullmatch(r"(.+) \(([^()]+)\)", line)
        require(match is not None, "Malformed kernel profile inventory")
        name, mode = match.groups()
        require(name not in loaded, "Ambiguous loaded profile name")
        loaded[name] = mode
    for name in hashes:
        expected_mode = "enforce" if restoring and name == selected["name"] else "unconfined"
        require(loaded.get(name) == expected_mode, "Preserved profile mode drift: " + name)
    for name, mode in loaded.items():
        if name not in hashes:
            require(mode == "enforce", "Undeclared non-enforcing profile: " + name)
    result = {"preserved_profile_sha256": hashes, "other_enforcing_profiles": len(loaded) - len(hashes),
              "read_only": True, "benchmark_exception_not_pass": True}
    if selected is not None:
        result["restoration_required"] = restoring
    return result


def main():
    require(len(sys.argv) in (2, 3), "Expected policy and optional restoration JSON arguments")
    require(Path("/sys/module/apparmor/parameters/enabled").read_text().strip() == "Y", "AppArmor is not enabled")
    require(Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text().strip() == "1",
            "Unprivileged usernamespace restriction drift")
    restoration = json.loads(sys.argv[2]) if len(sys.argv) == 3 else None
    if restoration is not None:
        selected = validate_restoration(restoration, json.loads(sys.argv[1]))
        require(Path("/etc/machine-id").read_text().strip() == restoration["machine_id"],
                "Restoration target identity mismatch")
        verify_rollback_paths(restoration, selected)
    result = verify(json.loads(sys.argv[1]), Path("/etc/apparmor.d"),
                    Path("/sys/kernel/security/apparmor/profiles"), restoration=restoration)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
