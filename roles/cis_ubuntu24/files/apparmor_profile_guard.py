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


def verify(policy, profile_root, kernel_profiles, owner_uid=0, owner_gid=0):
    """The CLI fixes all paths and root ownership; parameters permit isolated tests."""
    validate_policy(policy)
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
        require(loaded.get(name) == "unconfined", "Preserved profile mode drift: " + name)
    for name, mode in loaded.items():
        if name not in hashes:
            require(mode == "enforce", "Undeclared non-enforcing profile: " + name)
    return {"preserved_profile_sha256": hashes, "other_enforcing_profiles": len(loaded) - len(hashes),
            "read_only": True, "benchmark_exception_not_pass": True}


def main():
    require(len(sys.argv) == 2, "Expected one exact JSON policy argument")
    require(Path("/sys/module/apparmor/parameters/enabled").read_text().strip() == "Y", "AppArmor is not enabled")
    require(Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text().strip() == "1",
            "Unprivileged usernamespace restriction drift")
    result = verify(json.loads(sys.argv[1]), Path("/etc/apparmor.d"),
                    Path("/sys/kernel/security/apparmor/profiles"))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
