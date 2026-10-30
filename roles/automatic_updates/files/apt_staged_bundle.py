#!/usr/bin/python3
"""Verify controller-acquired Ubuntu APT data without network or APT state writes.

The request is an independently admitted controller input, never bundle content.
Verification is deliberately separate from import and package installation.
"""

import argparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import io
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
from urllib.parse import urlsplit


MAX_MANIFEST = 4 * 1024 * 1024
MAX_RELEASE = 32 * 1024 * 1024
MAX_INDEX = 2 * 1024**3
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]*\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON field")
        result[key] = value
    return result


def read_json(path, limit=MAX_MANIFEST):
    require(path.stat().st_size <= limit, "Oversized JSON input")
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def regular(path, limit, allow_empty=False):
    """Reject links in every path component, not just the final file."""
    require(path.is_absolute(), "Absolute local input required")
    for part in [*reversed(path.parents), path]:
        require(not part.is_symlink(), "Symlink input is forbidden")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode), "Regular input file required")
    require((0 if allow_empty else 1) <= info.st_size <= limit, "Empty or oversized input")
    require(info.st_nlink == 1, "Hard-linked input is forbidden")
    return path


def member(root, name, limit, allow_empty=False):
    value = PurePosixPath(name)
    require(isinstance(name, str) and value.parts and not value.is_absolute(), "Relative bundle member required")
    require(str(value) == name and all(part not in (".", "..") for part in value.parts), "Unsafe bundle path")
    return regular(root / name, limit, allow_empty=allow_empty)


def utc(value):
    require(isinstance(value, str), "UTC timestamp required")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None and result.utcoffset().total_seconds() == 0, "UTC timestamp required")
    return result


def release_fields(text):
    fields = {}
    key = None
    for line in text.splitlines():
        if line.startswith((" ", "\t")):
            require(key is not None, "Orphan release continuation")
            fields[key] += "\n" + line.strip()
        elif line:
            require(":" in line, "Malformed signed release")
            key, value = line.split(":", 1)
            require(key not in fields, "Duplicate signed release field")
            fields[key] = value.strip()
    checksums = {}
    for line in fields.get("SHA256", "").splitlines():
        if not line:
            continue
        parts = line.split()
        require(len(parts) == 3 and SHA256.fullmatch(parts[0]), "Malformed signed index checksum")
        checksum, size, name = parts
        require(name not in checksums and size.isdecimal(), "Duplicate or malformed signed index")
        require(not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts,
                "Unsafe signed index path")
        checksums[name] = (checksum, int(size))
    require(checksums, "Signed SHA256 indexes required")
    return fields, checksums


def verify_signature(path, keyring, now, suite, run=subprocess.run):
    with tempfile.TemporaryDirectory(prefix="apt-staged-gpg-") as directory:
        output = Path(directory) / "release"
        result = run([
            "/usr/bin/gpgv", "--homedir", directory, "--status-fd", "1", "--keyring", str(keyring),
            "--output", str(output), str(path),
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "HOME": directory, "LANG": "C.UTF-8"}, timeout=60, check=False)
        require(result.returncode == 0, "InRelease signature verification failed")
        signatures = []
        for line in result.stdout.decode("utf-8", errors="strict").splitlines():
            if line.startswith("[GNUPG:] VALIDSIG "):
                fingerprint = line.split()[2]
                require(re.fullmatch(r"[0-9A-F]{40,64}", fingerprint), "Invalid signer fingerprint")
                signatures.append(fingerprint)
        require(signatures, "No valid InRelease signer")
        fields, checksums = release_fields(regular(output, MAX_RELEASE).read_text())
    require(fields.get("Suite") == suite, "Signed suite differs from admitted repository")
    require("Date" in fields, "Signed repository date required")
    date = parsedate_to_datetime(fields["Date"])
    require(date.tzinfo is not None and date <= now, "Future or unzoned signed repository date")
    if "Valid-Until" in fields:
        expiry = parsedate_to_datetime(fields["Valid-Until"])
        require(expiry.tzinfo is not None and now < expiry, "Expired signed repository")
    return fields, checksums, signatures


def decompressed_digest(path, maximum, popen=subprocess.Popen):
    """APT owns decompression; do not compare .lz4 bytes with signed plaintext hashes."""
    require(0 < maximum <= MAX_INDEX, "Signed index size exceeds policy")
    size = 0
    checksum = hashlib.sha256()
    with tempfile.TemporaryFile() as errors:
        with popen(["/usr/lib/apt/apt-helper", "cat-file", str(path)], stdin=subprocess.DEVNULL,
                   stdout=subprocess.PIPE, stderr=errors,
                   env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}) as process:
            try:
                for block in iter(lambda: process.stdout.read(1024 * 1024), b""):
                    size += len(block)
                    require(size <= maximum, "Decompressed index exceeds signed size")
                    checksum.update(block)
                require(process.wait(timeout=60) == 0, "APT index decompression failed")
            except BaseException:
                process.kill()
                process.wait()
                raise
    return checksum.hexdigest(), size


def repositories(values):
    require(isinstance(values, list) and 0 < len(values) <= 64, "Bounded repository set required")
    result = {}
    for value in values:
        require(set(value) == {"uri", "suite", "components", "list_prefix"}, "Invalid admitted repository")
        uri = urlsplit(value["uri"])
        require(uri.scheme in ("http", "https") and uri.hostname and not uri.username and not uri.password
                and not uri.query and not uri.fragment and uri.port in (None, 80, 443), "Credential-free repository required")
        require(TOKEN.fullmatch(value["suite"]), "Invalid suite")
        require(isinstance(value["components"], list) and value["components"]
                and len(set(value["components"])) == len(value["components"])
                and all(TOKEN.fullmatch(x) for x in value["components"]), "Invalid component set")
        prefix = value["list_prefix"]
        require(re.fullmatch(r"[A-Za-z0-9%+._-]+", prefix), "Invalid admitted APT list prefix")
        require(prefix not in result, "Duplicate APT list prefix")
        result[prefix] = value
    return result


POLICY_OPTIONS = {
    "DEFAULT_RELEASE": ("APT::Default-Release", ""),
    "MACHINE_ID": ("APT::Machine-ID", ""),
    "RECOMMENDS": ("APT::Install-Recommends", True),
    "SUGGESTS": ("APT::Install-Suggests", False),
    "ALWAYS_PHASED": ("APT::Get::Always-Include-Phased-Updates", False),
    "NEVER_PHASED": ("APT::Get::Never-Include-Phased-Updates", False),
}


def apt_policy(run=subprocess.run):
    argv = ["/usr/bin/apt-config", "shell"]
    for name, (option, _) in POLICY_OPTIONS.items():
        argv += [name, option]
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    result = run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                 env=environment, timeout=30, check=True)
    result_values = {}
    for line in result.stdout.decode().splitlines():
        tokens = shlex.split(line)
        require(len(tokens) == 1 and "=" in tokens[0], "Malformed APT policy output")
        name, value = tokens[0].split("=", 1)
        require(name in POLICY_OPTIONS and name not in result_values, "Unexpected APT policy field")
        if name == "MACHINE_ID":
            require(not value or re.fullmatch(r"[A-Fa-f0-9-]{32,36}", value), "Unsupported phased-update identity")
            result_values[name] = value
        elif name == "DEFAULT_RELEASE":
            require(not value or TOKEN.fullmatch(value), "Unsupported default release")
            result_values[name] = value
        else:
            require(value.lower() in ("1", "0", "true", "false", "yes", "no", "on", "off"),
                    "Unsupported APT boolean")
            result_values[name] = value.lower() in ("1", "true", "yes", "on")
    for name, (_, default) in POLICY_OPTIONS.items():
        result_values.setdefault(name, default)
    require(not (result_values["ALWAYS_PHASED"] and result_values["NEVER_PHASED"]), "Contradictory phased-update policy")
    full = run(["/usr/bin/apt-config", "dump"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
               stderr=subprocess.PIPE, env=environment, timeout=30, check=True)
    version = run(["/usr/bin/apt-get", "--version"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE, env=environment, timeout=30, check=True).stdout.decode().splitlines()[0]
    # Full configuration may contain transport credentials. Retain only its hash.
    return {"settings": result_values, "effective_config_sha256": hashlib.sha256(full.stdout).hexdigest(),
            "apt_version": version}


def source_paths():
    paths = list(Path("/etc/apt/sources.list.d").glob("*.list"))
    paths += list(Path("/etc/apt/sources.list.d").glob("*.sources"))
    if Path("/etc/apt/sources.list").exists():
        paths.append(Path("/etc/apt/sources.list"))
    return sorted(paths)


def preference_paths():
    paths = list(Path("/etc/apt/preferences.d").glob("*"))
    if Path("/etc/apt/preferences").exists():
        paths.append(Path("/etc/apt/preferences"))
    require(all(path.is_file() and not path.is_symlink() for path in paths), "Unexpected APT preference object")
    return sorted(paths)


def patch_context(preferences=None, extended=Path("/var/lib/apt/extended_states"), policy=apt_policy):
    preferences = preference_paths() if preferences is None else preferences
    return {"preferences": {str(path): digest(regular(path, MAX_MANIFEST, allow_empty=True)) for path in preferences},
            "extended_states_sha256": digest(regular(extended, MAX_MANIFEST, allow_empty=True)) if extended.exists() else None,
            "apt_policy": policy(), "upgrade_mode": "apt-get upgrade --with-new-pkgs"}


def control_records(lines, comments=False):
    record = {}
    key = None
    size = 0
    for raw in lines:
        line = raw.rstrip("\r\n")
        if comments and line.lstrip().startswith("#"):
            continue
        if not line:
            if record:
                yield record
            record, key, size = {}, None, 0
            continue
        size += len(line)
        require(size <= MAX_MANIFEST, "Oversized control record")
        if line.startswith((" ", "\t")):
            require(key is not None, "Orphan control continuation")
            record[key] += "\n" + line[1:]
        else:
            require(":" in line, "Malformed control field")
            key, value = line.split(":", 1)
            require(re.fullmatch(r"[A-Za-z0-9-]+", key) and key not in record, "Invalid or duplicate control field")
            record[key] = value.strip()
    if record:
        yield record


def parse_sources(paths, keyring_path, architecture):
    """Admit explicit signed Deb822 sources; refuse legacy/credentialed overrides."""
    result = []
    for path in paths:
        raw = regular(path, MAX_MANIFEST, allow_empty=True).read_text()
        if path.name.endswith(".list"):
            require(not any(line.strip() and not line.lstrip().startswith("#") for line in raw.splitlines()),
                    "Active legacy source syntax is not supported")
            continue
        require(path.name.endswith(".sources"), "Deb822 source descriptor required")
        for entry in control_records(raw.splitlines(), comments=True):
            allowed = {"Types", "URIs", "Suites", "Components", "Signed-By", "Architectures", "Enabled"}
            require(set(entry) <= allowed, "Unsupported source option; do not relax authentication")
            require(entry.get("Enabled", "yes") in ("yes", "no"), "Invalid source enablement")
            if entry.get("Enabled") == "no":
                continue
            require(entry.get("Types") == "deb" and entry.get("Signed-By") == str(keyring_path),
                    "Explicit admitted binary source and keyring required")
            require(entry.get("Architectures", architecture).split() == [architecture], "Unsupported source architecture")
            components = entry.get("Components", "").split()
            for uri in entry.get("URIs", "").split():
                for suite in entry.get("Suites", "").split():
                    row = {"uri": uri.rstrip("/"), "suite": suite, "components": components}
                    # Reuse repository syntax checks; APT supplies the real filename later.
                    repositories([{**row, "list_prefix": "syntax-check"}])
                    require(row not in result, "Duplicate source repository")
                    result.append(row)
    require(result, "No admitted binary repositories")
    return result


def capture(destination, expected_machine_id, keyring=Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")):
    """Capture public resolver inputs only, not APT auth/proxy credentials."""
    require(destination.is_absolute() and destination.resolve() == destination and not destination.exists(),
            "New canonical capture directory required")
    require(os.geteuid() == 0, "Target resolver capture requires root")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    def output(argv):
        return subprocess.check_output(argv, stderr=subprocess.PIPE, env=environment, timeout=30).decode().strip()
    architecture = output(["/usr/bin/dpkg", "--print-architecture"])
    require(not output(["/usr/bin/dpkg", "--print-foreign-architectures"]), "Foreign architectures unsupported")
    require(not output(["/usr/bin/dpkg", "--audit"]), "Incomplete package operations require reconciliation")
    require(not shutil.which("aptitude"), "Collector currently supports the actual apt-get fallback only")
    machine = Path("/etc/machine-id").read_text().strip()
    require(re.fullmatch(r"[0-9a-f]{32}", machine) and machine == expected_machine_id,
            "Target identity differs from independently admitted machine")
    sources = source_paths()
    repos = parse_sources(sources, keyring, architecture)
    context = patch_context()
    status = regular(Path("/var/lib/dpkg/status"), MAX_INDEX)
    # Assemble before creating the capture so unsupported policy fails read-only.
    result = {"schema": 2, "machine_id": machine, "architecture": architecture,
              "status_sha256": digest(status), "sources": {str(path): digest(path) for path in sources},
              "keyring": {"path": str(keyring), "sha256": digest(regular(keyring, MAX_RELEASE))},
              "patch_context": context, "repositories": repos, "maximum_age_seconds": 3600,
              "captured_utc": datetime.now(timezone.utc).isoformat(), "payload_files": {}}
    destination.mkdir(mode=0o700, parents=True)
    inputs = [(status, "status")]
    inputs += [(path, "source-" + str(index) + path.suffix) for index, path in enumerate(sources)]
    inputs += [(path, "preference-" + str(index)) for index, path in enumerate(preference_paths())]
    extended = Path("/var/lib/apt/extended_states")
    if extended.exists():
        inputs.append((extended, "extended-states"))
    for original, name in inputs:
        # Snapshot only hash-admitted public files; source credentials were rejected.
        shutil.copyfile(original, destination / name, follow_symlinks=False)
        os.chmod(destination / name, 0o600)
        result["payload_files"][str(original)] = {"file": name, "sha256": digest(destination / name)}
    require(digest(status) == result["status_sha256"] and patch_context() == context,
            "Resolver inputs changed during capture")
    require({str(path): digest(path) for path in source_paths()} == result["sources"], "Sources changed during capture")
    (destination / "machine-id").write_text(machine + "\n")
    with (destination / "capture.json").open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    return {"state": "PUBLIC_TARGET_RESOLVER_CAPTURED_NO_PACKAGE_CHANGE", "capture": str(destination),
            "capture_sha256": digest(destination / "capture.json"), "machine_id": machine,
            "status_sha256": result["status_sha256"], "packages_changed": False}


def package_records(path):
    with tempfile.TemporaryFile() as errors:
        with subprocess.Popen(["/usr/lib/apt/apt-helper", "cat-file", str(path)], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=errors,
                              env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}) as process:
            try:
                yield from control_records(io.TextIOWrapper(process.stdout, encoding="utf-8", errors="strict"))
                require(process.wait(timeout=60) == 0, "Package index decoding failed")
            except BaseException:
                process.kill()
                process.wait()
                raise


def verify_packages(bundle, packages, indexes, architecture, records=package_records):
    require(isinstance(packages, list) and len(packages) <= 4096, "Bounded package set required")
    wanted = {}
    names = set()
    for item in packages:
        require(set(item) == {"file", "target_name", "package", "version", "architecture", "sha256", "bytes",
                              "list_prefix", "meta_key", "repository_filename"}, "Invalid package manifest")
        require(re.fullmatch(r"[A-Za-z0-9.+:%_~-]+\.deb", item["target_name"]), "Invalid archive target filename")
        require(item["architecture"] in (architecture, "all") and SHA256.fullmatch(item["sha256"]),
                "Wrong package architecture or hash")
        require(type(item["bytes"]) is int and 0 < item["bytes"] <= MAX_INDEX, "Invalid package size")
        require(item["target_name"] not in names, "Duplicate package archive")
        names.add(item["target_name"])
        key = (item["package"], item["version"], item["architecture"])
        require(key not in wanted, "Duplicate package version")
        path = member(bundle, item["file"], MAX_INDEX)
        require(path.stat().st_size == item["bytes"] and digest(path) == item["sha256"], "Deb payload checksum mismatch")
        wanted[key] = item
    matched = set()
    if not wanted:
        return 0
    for index in indexes:
        for record in records(member(bundle, index["file"], MAX_INDEX)):
            key = (record.get("Package"), record.get("Version"), record.get("Architecture"))
            if key not in wanted:
                continue
            item = wanted[key]
            if (item["list_prefix"], item["meta_key"]) != (index["list_prefix"], index["meta_key"]):
                continue
            require(record.get("SHA256") == item["sha256"] and record.get("Size") == str(item["bytes"])
                    and record.get("Filename") == item["repository_filename"], "Deb differs from signed package record")
            repository_path = PurePosixPath(item["repository_filename"])
            require(not repository_path.is_absolute() and ".." not in repository_path.parts
                    and str(repository_path).startswith("pool/"), "Unsafe repository payload path")
            matched.add(key)
    require(matched == set(wanted), "Payload missing from verified signed package indexes")
    return len(matched)


def archive_frame(archive, request, expected_digest):
    """Authenticate a flat producer archive before extracting any member."""
    regular(archive, 16 * MAX_INDEX)
    require(SHA256.fullmatch(expected_digest) and digest(archive) == expected_digest, "Transferred archive digest differs")
    with tarfile.open(archive, "r:gz") as opened:
        members = []
        total = 0
        seen = set()
        for item in opened:
            require(len(members) < 5000 and item.isfile() and not item.issym() and not item.islnk(),
                    "Unsupported archive member")
            require(bool(item.name) and PurePosixPath(item.name).name == item.name and item.name not in (".", "..")
                    and item.name not in seen, "Unsafe or duplicate archive member")
            require(0 < item.size <= MAX_INDEX, "Invalid archive member size")
            seen.add(item.name)
            members.append(item)
            total += item.size
        require("manifest.json" in seen, "Archive manifest missing")
        manifest_info = opened.getmember("manifest.json")
        require(manifest_info.size <= MAX_MANIFEST, "Oversized archive manifest")
        raw = opened.extractfile(manifest_info).read(MAX_MANIFEST + 1)
        require(hashlib.sha256(raw).hexdigest() == request["manifest_sha256"], "Archive manifest differs from independent request")
        manifest = json.loads(raw, object_pairs_hook=unique_object)
        expected = {"manifest.json"}
        for row in manifest["releases"] + manifest["indexes"] + manifest["packages"]:
            require(isinstance(row["file"], str) and PurePosixPath(row["file"]).name == row["file"]
                    and row["file"] not in expected, "Unsafe or duplicate manifest file")
            expected.add(row["file"])
        require(seen == expected, "Archive file set differs from authenticated manifest")
    return {"state": "AUTHENTICATED_ARCHIVE_FRAME_NO_SIGNATURE_ACCEPTANCE", "member_count": len(members),
            "member_sizes": {item.name: item.size for item in members},
            "unpacked_bytes": total, "archive_bytes": archive.stat().st_size,
            "archive_sha256": expected_digest, "manifest_sha256": request["manifest_sha256"],
            "machine_id": manifest["machine_id"], "package_count": len(manifest["packages"]),
            "package_plan": [{key: row[key] for key in ("package", "version", "architecture", "bytes")}
                             for row in manifest["packages"]]}


def receive(archive, request, expected_digest, destination, expected_machine_id):
    require(os.geteuid() == 0, "Target bundle staging requires root")
    require(Path("/etc/machine-id").read_text().strip() == request["machine_id"] == expected_machine_id,
            "Wrong bundle receiver identity")
    require(destination.is_absolute() and destination.resolve() == destination and not destination.exists(),
            "New canonical receiver directory required")
    frame = archive_frame(archive, request, expected_digest)
    require(shutil.disk_usage(destination.parent).free > frame["unpacked_bytes"] + 128 * 1024**2,
            "Insufficient safe receiver staging capacity")
    destination.mkdir(mode=0o700)
    with tarfile.open(archive, "r:gz") as opened:
        seen = set()
        for item in opened:
            require(item.isfile() and item.name in frame["member_sizes"] and item.name not in seen
                    and item.size == frame["member_sizes"][item.name], "Archive changed after frame admission")
            seen.add(item.name)
            # Do not use extractall or honor archive owners/modes/links.
            with opened.extractfile(item) as source, (destination / item.name).open("xb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            os.chmod(destination / item.name, 0o600)
    require(seen == set(frame["member_sizes"]) and digest(archive) == expected_digest,
            "Archive changed during staging")
    verified = verify(destination, request)
    return {"state": "SIGNED_TARGET_BUNDLE_STAGED_NO_IMPORT", "changed": True, "verification": verified,
            "archive": frame, "packages_changed": False, "apt_state_changed": False}


def verify(bundle, request, now=None, signature=verify_signature, decompressed=decompressed_digest,
           machine_path=Path("/etc/machine-id"), status_path=Path("/var/lib/dpkg/status"),
           architecture=None, source_paths=None):
    """Return evidence only; never import data or reset a freshness marker."""
    now = now or datetime.now(timezone.utc)
    require(bundle.is_absolute() and bundle.resolve() == bundle, "Canonical absolute bundle directory required")
    regular(bundle / "manifest.json", MAX_MANIFEST)
    require(SHA256.fullmatch(request["manifest_sha256"]), "Independently admitted manifest digest required")
    require(digest(bundle / "manifest.json") == request["manifest_sha256"], "Bundle manifest changed")
    manifest = read_json(bundle / "manifest.json")
    require(manifest["schema"] in (1, 2), "Unsupported bundle schema")
    require(manifest["machine_id"] == request["machine_id"] == machine_path.read_text().strip(), "Wrong target machine")
    if architecture is None:
        architecture = subprocess.check_output(["/usr/bin/dpkg", "--print-architecture"], timeout=15).decode().strip()
        require(not subprocess.check_output(["/usr/bin/dpkg", "--print-foreign-architectures"], timeout=15).strip(),
                "Foreign package architectures are not supported by this bundle schema")
    require(manifest["architecture"] == request["architecture"] == architecture, "Wrong target architecture")
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]*", architecture), "Invalid architecture")
    require(SHA256.fullmatch(request["status_sha256"]), "Admitted package status digest required")
    require(manifest["status_sha256"] == request["status_sha256"] == digest(regular(status_path, MAX_INDEX)),
            "Installed package state changed")
    if manifest["schema"] == 2:
        require(request.get("schema") == 2 and manifest["patch_context"] == request["patch_context"] == patch_context(),
                "Target resolver policy or extended package state changed")
    require(manifest["sources"] == request["sources"] and request["sources"], "Source set changed")
    if source_paths is None:
        source_paths = list(Path("/etc/apt/sources.list.d").glob("*.list"))
        source_paths += list(Path("/etc/apt/sources.list.d").glob("*.sources"))
        if Path("/etc/apt/sources.list").exists():
            source_paths.append(Path("/etc/apt/sources.list"))
    require(set(map(str, source_paths)) == set(request["sources"]), "Active source file set changed")
    for name, expected in request["sources"].items():
        require(SHA256.fullmatch(expected) and digest(regular(Path(name), MAX_MANIFEST, allow_empty=True)) == expected,
                "Target source descriptor changed")
    keyring = regular(Path(request["keyring"]["path"]), MAX_RELEASE)
    require(SHA256.fullmatch(request["keyring"]["sha256"]), "Admitted keyring digest required")
    require(manifest["keyring_sha256"] == request["keyring"]["sha256"] == digest(keyring), "Archive keyring changed")
    maximum_age = request["maximum_age_seconds"]
    require(type(maximum_age) is int and 0 < maximum_age <= 3600, "Freshness policy must not exceed 3600 seconds")
    started, acquired = utc(manifest["started_utc"]), utc(manifest["acquired_utc"])
    require(started <= acquired <= now and (now - started).total_seconds() < maximum_age,
            "Stale, future or invalid acquisition window")
    require(manifest["repositories"] == request["repositories"], "Repository mapping changed")
    admitted = repositories(request["repositories"])
    require(isinstance(manifest["releases"], list) and len(manifest["releases"]) == len(admitted),
            "Missing or extra signed releases")
    releases = {}
    files = set()
    names = set()
    for item in manifest["releases"]:
        prefix = item["list_prefix"]
        require(prefix in admitted and prefix not in releases, "Unexpected or duplicate signed release")
        require(item["target_name"] == prefix + "_InRelease", "Signed release target mapping changed")
        path = member(bundle, item["file"], MAX_RELEASE)
        require(item["file"] not in files, "Duplicate bundle member")
        files.add(item["file"])
        names.add(item["target_name"])
        fields, checksums, signers = signature(path, keyring, now, admitted[prefix]["suite"])
        require(architecture in fields.get("Architectures", "").split(), "Architecture absent from signed release")
        require(set(admitted[prefix]["components"]) <= set(fields.get("Components", "").split()),
                "Component absent from signed release")
        releases[prefix] = {"checksums": checksums, "signers": signers}
    require(isinstance(manifest["indexes"], list) and len(manifest["indexes"]) <= 256, "Bounded index set required")
    seen = set()
    for item in manifest["indexes"]:
        prefix, component = item["list_prefix"], item["component"]
        require(prefix in admitted and component in admitted[prefix]["components"], "Unexpected index source")
        require((prefix, component) not in seen, "Duplicate package index")
        seen.add((prefix, component))
        meta_key = component + "/binary-" + architecture + "/Packages"
        require(item["meta_key"] == meta_key, "Index architecture or signed path changed")
        target_base = prefix + "_" + meta_key.replace("/", "_")
        require(item["target_name"] in (target_base, target_base + ".lz4", target_base + ".xz", target_base + ".gz"),
                "Index target filename changed")
        require(item["target_name"] not in names and item["file"] not in files, "Duplicate index member or target")
        files.add(item["file"])
        names.add(item["target_name"])
        path = member(bundle, item["file"], MAX_INDEX)
        require(meta_key in releases[prefix]["checksums"], "Index absent from signed SHA256 set")
        expected_hash, expected_size = releases[prefix]["checksums"][meta_key]
        require(decompressed(path, expected_size) == (expected_hash, expected_size), "Signed index checksum mismatch")
    expected = {(prefix, component) for prefix, repo in admitted.items() for component in repo["components"]}
    empty = set()
    for prefix, component in expected - seen:
        meta_key = component + "/binary-" + architecture + "/Packages"
        require(releases[prefix]["checksums"].get(meta_key) == (hashlib.sha256(b"").hexdigest(), 0),
                "Incomplete package index coverage")
        empty.add((prefix, component))
    package_count = 0
    if manifest["schema"] == 1:
        require(manifest.get("packages", []) == [], "Deb payload verification is not implemented; refuse payloads")
    else:
        package_count = verify_packages(bundle, manifest["packages"], manifest["indexes"], architecture)
    return {"state": ("SIGNED_APT_METADATA_VERIFIED_NO_IMPORT" if manifest["schema"] == 1
                      else "SIGNED_APT_METADATA_AND_DEBS_VERIFIED_NO_IMPORT"), "changed": False,
            "manifest_sha256": request["manifest_sha256"], "machine_id": request["machine_id"],
            "architecture": architecture, "acquired_utc": manifest["acquired_utc"],
            "freshness_origin_utc": manifest["started_utc"], "signed_release_count": len(releases),
            "package_index_count": len(seen), "signed_empty_index_count": len(empty),
            "signers": {key: row["signers"] for key, row in releases.items()},
            "apt_state_changed": False, "package_payloads_verified": manifest["schema"] == 2,
            "verified_package_count": package_count, "package_updates_accepted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--expected-machine-id")
    parser.add_argument("--inspect-archive", type=Path)
    parser.add_argument("--receive", type=Path)
    parser.add_argument("--expected-archive-sha256")
    args = parser.parse_args()
    try:
        require(sum(bool(value) for value in (args.capture, args.inspect_archive, args.receive)) <= 1,
                "Capture, archive inspection and reception are distinct actions")
        if args.capture:
            require(not args.bundle and not args.request, "Capture and verification are separate actions")
            result = capture(args.capture, args.expected_machine_id)
        elif args.inspect_archive or args.receive:
            require(args.request is not None and args.expected_archive_sha256 is not None, "Independent archive admission required")
            regular(args.request, MAX_MANIFEST)
            request = read_json(args.request)
            if args.inspect_archive:
                result = archive_frame(args.inspect_archive, request, args.expected_archive_sha256)
            else:
                require(args.bundle is not None, "New receiver bundle path required")
                result = receive(args.receive, request, args.expected_archive_sha256, args.bundle, args.expected_machine_id)
        else:
            require(args.bundle is not None and args.request is not None, "Bundle and request required")
            regular(args.request, MAX_MANIFEST)
            result = verify(args.bundle, read_json(args.request))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        print(json.dumps({"state": "REJECTED_NO_IMPORT", "changed": False, "error_type": type(error).__name__}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
