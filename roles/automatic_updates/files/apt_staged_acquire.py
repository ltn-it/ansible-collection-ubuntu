#!/usr/bin/python3
"""Acquire signed Ubuntu data/debs using captured TARGET state, never host APT state."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import resource
import shlex
import shutil
import signal
import subprocess
import tarfile
import time
from urllib.parse import unquote, urlsplit

SPEC = importlib.util.spec_from_file_location("apt_staged_bundle", Path(__file__).with_name("apt_staged_bundle.py"))
DATA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DATA)
require = DATA.require


def snapshot_inputs(snapshot, admitted_digest):
    require(snapshot.is_absolute() and snapshot.resolve() == snapshot, "Canonical capture directory required")
    require(DATA.SHA256.fullmatch(admitted_digest), "Independent capture digest required")
    capture = DATA.regular(snapshot / "capture.json", DATA.MAX_MANIFEST)
    require(DATA.digest(capture) == admitted_digest, "Capture changed in transfer")
    request = DATA.read_json(capture)
    require(request["schema"] == 2, "Resolver capture schema2 required")
    require(request["patch_context"]["upgrade_mode"] == "apt-get upgrade --with-new-pkgs", "Unsupported resolver mode")
    mapped = {}
    for original, item in request["payload_files"].items():
        require(Path(item["file"]).name == item["file"], "Unsafe capture member")
        path = DATA.member(snapshot, item["file"], DATA.MAX_INDEX, allow_empty=True)
        require(DATA.digest(path) == item["sha256"], "Captured payload changed")
        mapped[original] = path
    expected = {"/var/lib/dpkg/status": request["status_sha256"], **request["sources"],
                **request["patch_context"]["preferences"]}
    if request["patch_context"]["extended_states_sha256"] is not None:
        expected["/var/lib/apt/extended_states"] = request["patch_context"]["extended_states_sha256"]
    require(set(mapped) == set(expected), "Unexpected capture file set")
    for original, checksum in expected.items():
        require(DATA.SHA256.fullmatch(checksum) and DATA.digest(mapped[original]) == checksum,
                "Capture payload differs from admitted target state")
    DATA.regular(mapped["/var/lib/dpkg/status"], DATA.MAX_INDEX)
    key = DATA.regular(Path(request["keyring"]["path"]), DATA.MAX_RELEASE)
    require(DATA.digest(key) == request["keyring"]["sha256"], "Collector archive keyring differs")
    sources = [mapped[path] for path in request["sources"]]
    parsed = DATA.parse_sources(sources, key, request["architecture"])
    require(parsed == request["repositories"], "Captured repository policy differs")
    return request, mapped


def print_uri_plan(text):
    result = {}
    for line in text.splitlines():
        if not line.startswith(("'http://", "'https://")):
            continue
        fields = shlex.split(line)
        require(len(fields) == 4 and fields[2].isdecimal(), "Malformed APT URI plan")
        uri, name, size, _ = fields
        parsed = urlsplit(uri)
        require(parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username
                and not parsed.password and not parsed.query and not parsed.fragment, "Credentialed APT download rejected")
        require(DATA.re.fullmatch(r"[A-Za-z0-9.+:%_~-]+\.deb", name) and name not in result,
                "Unsafe or duplicate download filename")
        result[name] = {"uri": uri, "bytes": int(size)}
    require(len(result) <= 4096, "Unbounded package plan")
    return result


def apt_configuration(base, request, user):
    policy = request["patch_context"]["apt_policy"]["settings"]
    options = {
        "Dir::Etc::main": "/dev/null", "Dir::Etc::parts": str(base / "empty"),
        "Dir::Etc::sourcelist": "/dev/null", "Dir::Etc::sourceparts": str(base / "sources"),
        "Dir::Etc::preferences": "/dev/null", "Dir::Etc::preferencesparts": str(base / "preferences"),
        "Dir::Etc::trusted": "/dev/null", "Dir::Etc::trustedparts": str(base / "empty"),
        "Dir::Etc::netrc": "/dev/null", "Dir::Etc::netrcparts": str(base / "empty"),
        "Dir::State": str(base / "state"), "Dir::State::status": str(base / "state/status"),
        "Dir::State::extended_states": str(base / "state/extended_states"),
        "Dir::State::lists": str(base / "lists"), "Dir::Cache": str(base / "cache"),
        "Dir::Cache::archives": str(base / "cache/archives"), "Dir::Log": str(base / "log"),
        "APT::Architecture": request["architecture"], "APT::Sandbox::User": user,
        "APT::Machine-ID": policy.get("MACHINE_ID") or request["machine_id"],
        "Acquire::Languages": "none", "Acquire::Check-Date": "true", "Acquire::Check-Valid-Until": "true",
        "Acquire::AllowInsecureRepositories": "false", "Acquire::AllowWeakRepositories": "false",
        "Acquire::AllowDowngradeToInsecureRepositories": "false", "APT::Get::AllowUnauthenticated": "false",
        "Acquire::Retries": "1", "APT::Get::AutomaticRemove": "false",
    }
    for name, (option, _) in DATA.POLICY_OPTIONS.items():
        if name == "MACHINE_ID":
            continue
        value = policy[name]
        if name == "DEFAULT_RELEASE":
            if value:
                options[option] = value
        else:
            require(type(value) is bool, "Captured APT boolean required")
            options[option] = "true" if value else "false"
    config = "\n".join(key + " " + json.dumps(value) + ";" for key, value in options.items())
    config += '\n#clear APT::Architectures;\nAPT::Architectures { ' + json.dumps(request["architecture"]) + '; };\n'
    for hook in ["APT::Update::Pre-Invoke", "APT::Update::Post-Invoke", "APT::Update::Post-Invoke-Success",
                 "DPkg::Pre-Invoke", "DPkg::Post-Invoke", "DPkg::Pre-Install-Pkgs"]:
        config += "#clear " + hook + ";\n"
    return config


def run_apt(log_path, argv, environment, workspace, timeout):
    """Bound only our own process group; preserve shared-host free-space reserve."""
    deadline = time.monotonic() + timeout
    with log_path.open("xb") as log:
        with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                              env=environment, start_new_session=True) as process:
            try:
                while True:
                    require(time.monotonic() < deadline, "Private APT operation exceeded its deadline")
                    require(shutil.disk_usage(workspace).free > 128 * 1024**2, "Collector free-space reserve reached")
                    try:
                        code = process.wait(timeout=1)
                        break
                    except subprocess.TimeoutExpired:
                        continue
                require(code == 0, "Private APT operation failed; retain its attempt and log")
            except BaseException:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                raise
    return log_path.read_text()


def acquire(snapshot, capture_digest, destination, expected_collector):
    require(os.geteuid() != 0, "Acquisition must be unprivileged")
    require(Path("/etc/machine-id").read_text().strip() == expected_collector, "Wrong collector identity")
    require(destination.is_absolute() and destination.resolve() == destination and not destination.exists(),
            "New canonical acquisition directory required")
    request, mapped = snapshot_inputs(snapshot, capture_digest)
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    architecture = subprocess.check_output(["/usr/bin/dpkg", "--print-architecture"], env=environment, timeout=15).decode().strip()
    require(architecture == request["architecture"], "Native collector architecture must match target")
    version = subprocess.check_output(["/usr/bin/apt-get", "--version"], env=environment, timeout=15).decode().splitlines()[0]
    require(version == request["patch_context"]["apt_policy"]["apt_version"], "Collector APT version differs from target")
    import apt_pkg
    require(callable(apt_pkg.uri_to_filename), "Native APT URI mapping API required")
    require(shutil.disk_usage(destination.parent).free > 512 * 1024**2, "Insufficient collector workspace capacity")
    os.umask(0o077)
    os.nice(15)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
    destination.mkdir(mode=0o700)
    start = datetime.now(timezone.utc).isoformat()
    attempt = {"state": "STARTED_PRIVATE_TARGET_APT_ACQUISITION", "started_utc": start,
               "capture_sha256": capture_digest, "target_machine_id": request["machine_id"],
               "collector_machine_id": expected_collector, "target_package_changes": False}
    (destination / "attempt.json").write_text(json.dumps(attempt, indent=2) + "\n")
    try:
        for name in ["empty", "sources", "preferences", "state", "lists", "lists/partial", "cache",
                     "cache/archives", "cache/archives/partial", "log", "bundle"]:
            (destination / name).mkdir(mode=0o700)
        shutil.copyfile(mapped["/var/lib/dpkg/status"], destination / "state/status")
        extended = mapped.get("/var/lib/apt/extended_states")
        if extended:
            shutil.copyfile(extended, destination / "state/extended_states")
        for index, original in enumerate(request["patch_context"]["preferences"]):
            shutil.copyfile(mapped[original], destination / "preferences" / ("target-" + str(index)))
        # Canonical descriptors derive exclusively from admitted target sources.
        # Their Signed-By path/keyring remains exact, with architecture explicit.
        for index, repo in enumerate(request["repositories"]):
            text = "\n".join(["Types: deb", "URIs: " + repo["uri"], "Suites: " + repo["suite"],
                               "Components: " + " ".join(repo["components"]),
                               "Signed-By: " + request["keyring"]["path"], "Architectures: " + architecture]) + "\n"
            (destination / "sources" / ("target-" + str(index) + ".sources")).write_text(text)
        config = apt_configuration(destination, request, pwd.getpwuid(os.geteuid()).pw_name)
        (destination / "apt.conf").write_text(config)
        environment.update(HOME=str(destination), APT_CONFIG=str(destination / "apt.conf"))
        def run(name, argv, timeout=900):
            return run_apt(destination / (name + ".log"), argv, environment, destination, timeout)
        run("update", ["/usr/bin/apt-get", "update"])
        # URI mapping is supplied by the native installed APT API, not guessed.
        repos = [{**row, "list_prefix": apt_pkg.uri_to_filename(row["uri"] + "/dists/" + row["suite"])}
                 for row in request["repositories"]]
        DATA.repositories(repos)
        bundle = destination / "bundle"
        releases, indexes, verified = [], [], {}
        keyring = Path(request["keyring"]["path"])
        for repo in repos:
            prefix = repo["list_prefix"]
            path = DATA.regular(destination / "lists" / (prefix + "_InRelease"), DATA.MAX_RELEASE)
            fields, checksums, signers = DATA.verify_signature(path, keyring, datetime.now(timezone.utc), repo["suite"])
            require(architecture in fields.get("Architectures", "").split(), "Wrong signed release architecture")
            verified[prefix] = {"checksums": checksums, "signers": signers}
            shutil.copyfile(path, bundle / path.name)
            releases.append({"list_prefix": prefix, "file": path.name, "target_name": path.name})
            for component in repo["components"]:
                meta = component + "/binary-" + architecture + "/Packages"
                require(meta in checksums, "Missing signed component index")
                expected = checksums[meta]
                basename = prefix + "_" + meta.replace("/", "_")
                candidates = [destination / "lists" / (basename + suffix) for suffix in ("", ".lz4", ".xz", ".gz")]
                paths = [candidate for candidate in candidates if candidate.is_file()]
                if expected == (hashlib.sha256(b"").hexdigest(), 0):
                    require(not paths, "Unexpected acquired signed-empty index")
                    continue
                require(len(paths) == 1, "Missing or ambiguous acquired package index")
                index_path = DATA.regular(paths[0], DATA.MAX_INDEX)
                require(DATA.decompressed_digest(index_path, expected[1]) == expected, "Signed index differs")
                shutil.copyfile(index_path, bundle / index_path.name)
                indexes.append({"list_prefix": prefix, "component": component, "meta_key": meta,
                                "file": index_path.name, "target_name": index_path.name})
        run("simulate", ["/usr/bin/apt-get", "--simulate", "upgrade", "--with-new-pkgs"], timeout=120)
        plan_text = run("uri-plan", ["/usr/bin/apt-get", "--print-uris", "--download-only", "--yes",
                                    "upgrade", "--with-new-pkgs"], timeout=120)
        plan = print_uri_plan(plan_text)
        require(shutil.disk_usage(destination).free > 3 * sum(row["bytes"] for row in plan.values())
                + sum(path.stat().st_size for path in bundle.iterdir()) + 128 * 1024**2,
                "Insufficient capacity for resolved deb payloads")
        run("download", ["/usr/bin/apt-get", "--download-only", "--yes", "upgrade", "--with-new-pkgs"])
        archives = sorted((destination / "cache/archives").glob("*.deb"))
        require({path.name for path in archives} == set(plan), "Downloaded set differs from APT URI plan")
        packages = {}
        for path in archives:
            DATA.regular(path, DATA.MAX_INDEX)
            require(path.stat().st_size == plan[path.name]["bytes"], "Downloaded size differs from resolver")
            identity = subprocess.check_output(["/usr/bin/dpkg-deb", "--show", "--showformat",
                                               "${Package}\t${Version}\t${Architecture}\n", str(path)],
                                              env=environment, stderr=subprocess.PIPE, timeout=60).decode().strip().split("\t")
            require(len(identity) == 3, "Malformed deb package identity")
            key = tuple(identity)
            require(key not in packages, "Duplicate resolved package")
            packages[key] = {"file": path.name, "target_name": path.name, "package": identity[0],
                             "version": identity[1], "architecture": identity[2], "sha256": DATA.digest(path),
                             "bytes": path.stat().st_size}
            shutil.copyfile(path, bundle / path.name)
        selected = {}
        repo_map = {repo["list_prefix"]: repo for repo in repos}
        for index in indexes:
            for record in DATA.package_records(bundle / index["file"]):
                key = (record.get("Package"), record.get("Version"), record.get("Architecture"))
                if key not in packages:
                    continue
                item = packages[key]
                if (record.get("SHA256"), record.get("Size")) != (item["sha256"], str(item["bytes"])):
                    continue
                expected_uri = repo_map[index["list_prefix"]]["uri"] + "/" + record.get("Filename", "")
                if unquote(expected_uri) != unquote(plan[item["target_name"]]["uri"]):
                    continue
                selected[key] = {**item, "list_prefix": index["list_prefix"], "meta_key": index["meta_key"],
                                 "repository_filename": record["Filename"]}
        require(set(selected) == set(packages), "Downloaded payload absent from selected signed repository")
        DATA.verify_packages(bundle, list(selected.values()), indexes, architecture)
        manifest = {"schema": 2, "machine_id": request["machine_id"], "architecture": architecture,
                    "status_sha256": request["status_sha256"], "sources": request["sources"],
                    "keyring_sha256": request["keyring"]["sha256"], "patch_context": request["patch_context"],
                    "repositories": repos, "started_utc": start, "acquired_utc": datetime.now(timezone.utc).isoformat(),
                    "releases": releases, "indexes": indexes, "packages": list(selected.values()),
                    "resolver_plan_sha256": DATA.digest(destination / "simulate.log")}
        with (bundle / "manifest.json").open("x") as stream:
            json.dump(manifest, stream, indent=2)
            stream.write("\n")
        final_request = {key: request[key] for key in ("machine_id", "architecture", "status_sha256", "sources",
                                                      "keyring", "patch_context", "maximum_age_seconds")}
        final_request.update(schema=2, repositories=repos, manifest_sha256=DATA.digest(bundle / "manifest.json"))
        (destination / "request.json").write_text(json.dumps(final_request, indent=2) + "\n")
        with tarfile.open(destination / "bundle.tar.gz", "x:gz", compresslevel=1, format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(bundle.iterdir()):
                require(path.is_file() and not path.is_symlink(), "Unexpected bundle member")
                archive.add(path, arcname=path.name, recursive=False)
        receipt = {**attempt, "state": "SIGNED_TARGET_APT_METADATA_AND_DEBS_ACQUIRED_NO_INSTALL",
                   "completed_utc": datetime.now(timezone.utc).isoformat(),
                   "manifest_sha256": final_request["manifest_sha256"], "archive_sha256": DATA.digest(destination / "bundle.tar.gz"),
                   "request_sha256": DATA.digest(destination / "request.json"), "package_count": len(selected),
                   "deb_bytes": sum(item["bytes"] for item in selected.values()), "signed_release_count": len(releases),
                   "index_count": len(indexes), "collector_host_packages_used_as_resolver_state": False,
                   "collector_system_apt_changed": False, "target_package_changes": False,
                   "acquire_helper_sha256": DATA.digest(Path(__file__)),
                   "verify_helper_sha256": DATA.digest(Path(__file__).with_name("apt_staged_bundle.py")),
                   "apt_config_sha256": DATA.digest(destination / "apt.conf")}
        (destination / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        return receipt
    except BaseException as error:
        with (destination / "stopped.json").open("x") as stream:
            json.dump({"state": "STOPPED_RETAIN_ATTEMPT_AND_LOGS", "error_type": type(error).__name__,
                       "target_package_changes": False}, stream, indent=2)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--capture-sha256", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--expected-collector-id", required=True)
    args = parser.parse_args()
    try:
        result = acquire(args.snapshot, args.capture_sha256, args.destination, args.expected_collector_id)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, ImportError) as error:
        print(json.dumps({"state": "ACQUISITION_STOPPED_NO_INSTALL", "error_type": type(error).__name__}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
