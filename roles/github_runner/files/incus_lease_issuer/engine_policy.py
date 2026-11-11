"""Root-loaded semantic compiler for ONE fixed nonprivileged Podman cell.

No execution, installation, image pull, namespace acquisition or operating grant.
Root archive digests and closed filesystem inventories are independently checked;
the trusted materializer still owes archive-to-tree provenance. Context late
binding excludes binding.json bytes from this digest, avoiding the JWS cycle.
Actual nsfs, uid-map/idmapped-FS, cgroup, image-child and deadline preflight are
mandatory at the future Root executor; a compiled argv is not runtime proof.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
from types import MappingProxyType
from typing import Mapping

from .identity import Denied, decode_json, require
from . import installation

IMAGE_INDEX = "58955457d3410706520f34fa7ea9823d5650aa4844c562cd5c0107024d825711"
IMAGE_CHILD = "dee06ca5ada0660589e58e10659e568b9f4797ff0c74379c34c9e7c22b29687a"
IMAGE = "quay.io/l-it/ee-wunder-devtools-ubi9:v1.18.2@sha256:" + IMAGE_INDEX
# Podman's containers/image transport rejects a simultaneous tag and digest.
# Keep the versioned immutable provenance label above for the controller;
# execute only this canonical reference to the exact same pinned index.
PODMAN_IMAGE = "quay.io/l-it/ee-wunder-devtools-ubi9@sha256:" + IMAGE_INDEX
ENGINE = "/usr/bin/podman"
MAX_DESCRIPTOR = 4 * 1024 * 1024
MAX_FILES = 20000
MAX_TOTAL = 2 * 1024 * 1024 * 1024
MAX_ENGINE_ARGS = 512
MAX_ENGINE_ARG_BYTES = 65536
MAX_CAPTURE_STREAM_BYTES = 64 * 1024 ** 2
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
HEX = re.compile(r"[0-9a-f]{64}\Z")
INPUTS = ("PROFILE", "SCENARIO", "TARGET", "TARGET_DISPOSITION", "ROLES", "IMAGE", "INSTANCE_TYPE",
          "CANDIDATE_ARTIFACT", "SOURCE_SHA", "JUNIT_REQUIRED", "ALLURE_REQUIRED", "CPU_LIMIT", "MEMORY_LIMIT", "DISK_LIMIT")
ENV_KEYS = frozenset({"GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
                     "GITHUB_JOB", "GITHUB_SHA", "GITHUB_WORKFLOW"} | {"QUALITY_INPUT_" + x for x in INPUTS})
CONTROLLER_FILES = frozenset({"action.yml", "profile-steps.yml", "run-cell.py", "run-devtools.sh", "run-phase.sh"})
CONTEXT_FILES = frozenset({"config.yml", "client.crt", "client.key", "servercerts/quality.crt"})


@dataclass(frozen=True)
class EngineManifest:
    descriptor_path: str
    descriptor_sha256: str
    image_index_sha256: str
    image_manifest_sha256: str
    argv: tuple[str, ...]
    environment: Mapping[str, str]
    sha256: str
    canonical_bytes: bytes


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _keys(value, expected):
    require(type(value) is dict and set(value) == set(expected), "engine-fields")
    return value


def _hash(value):
    require(type(value) is str and HEX.fullmatch(value), "engine-digest")
    return value


def _integer(value, minimum=1, maximum=2 ** 32 - 1):
    require(type(value) is int and minimum <= value <= maximum, "engine-integer")
    return value


def _path(value):
    require(type(value) is str and 1 < len(value) <= 4096 and value.startswith("/")
            and re.fullmatch(r"/[A-Za-z0-9_./@-]+", value) and str(PurePosixPath(value)) == value
            and ".." not in PurePosixPath(value).parts, "engine-path")
    return value


def _relative(value):
    require(type(value) is str and 0 < len(value) <= 1024 and not value.startswith("/")
            and re.fullmatch(r"[A-Za-z0-9_./@-]+", value) and value != "."
            and str(PurePosixPath(value)) == value and ".." not in PurePosixPath(value).parts
            and len(PurePosixPath(value).parts) <= 32, "engine-relative-path")
    return value


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory(path, *, private=False):
    _path(path)
    fd = os.open("/", DIR)
    try:
        for part in PurePosixPath(path).parts[1:]:
            following = os.open(part, DIR, dir_fd=fd)
            os.close(fd)
            fd = following
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, "engine-directory-owner")
        if private:
            require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, "engine-private-directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _file(path, expected=None, *, private=False, maximum=512 * 1024 * 1024):
    proof = installation.trusted_file(_path(path), max_bytes=maximum)
    if expected is not None:
        require(proof.sha256 == _hash(expected), "engine-file-drift")
    if private:
        require(stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode) == 0o600, "engine-private-file")
    return proof


def _tree(value):
    _keys(value, {"path", "files", "directories"})
    path = _path(value["path"])
    require(type(value["files"]) is dict and 0 < len(value["files"]) <= MAX_FILES
            and type(value["directories"]) is list and len(value["directories"]) <= MAX_FILES,
            "engine-inventory")
    expected_files = {_relative(key): _hash(digest) for key, digest in value["files"].items()}
    expected_dirs = {_relative(item) for item in value["directories"]}
    require(len(expected_dirs) == len(value["directories"]) and not (expected_dirs & set(expected_files)), "engine-inventory")
    found_files, found_dirs, total = {}, set(), 0
    root = _directory(path)
    def walk(fd, prefix=""):
        nonlocal total
        before = os.fstat(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        with os.scandir(fd) as entries:
            for entry in entries:
                relative = prefix + entry.name
                _relative(relative)
                info = entry.stat(follow_symlinks=False)
                require(info.st_uid == 0 and not info.st_mode & 0o022 and not stat.S_ISLNK(info.st_mode), "engine-inventory-owner")
                if stat.S_ISDIR(info.st_mode):
                    require(relative in expected_dirs, "engine-unlisted-directory")
                    found_dirs.add(relative)
                    child = os.open(entry.name, DIR, dir_fd=fd)
                    try:
                        walk(child, relative + "/")
                    finally:
                        os.close(child)
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and relative in expected_files,
                            "engine-unlisted-file")
                    proof = _file(path + "/" + relative, expected_files[relative])
                    total += proof.size
                    require(total <= MAX_TOTAL, "engine-inventory-size")
                    found_files[relative] = proof.sha256
        require(_stamp(before) == _stamp(os.fstat(fd)), "engine-directory-drift")
    try:
        walk(root)
    finally:
        os.close(root)
    require(found_files == expected_files and found_dirs == expected_dirs, "engine-inventory-missing")
    return {"path": path, "files": found_files, "directories": sorted(found_dirs)}


def _context(path):
    fd = _directory(path, private=True)
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        require(set(os.listdir(fd)) in ({"config.yml", "client.crt", "client.key", "servercerts"},
                                        {"config.yml", "client.crt", "client.key", "servercerts", "binding.json"}), "engine-context-inventory")
    finally:
        os.close(fd)
    child = _directory(path + "/servercerts", private=True)
    try:
        os.lseek(child, 0, os.SEEK_SET)
        require(set(os.listdir(child)) == {"quality.crt"}, "engine-context-inventory")
    finally:
        os.close(child)
    files = {relative: _file(path + "/" + relative, private=True, maximum=65536).sha256
             for relative in sorted(CONTEXT_FILES)}
    if os.path.lexists(path + "/binding.json"):
        _file(path + "/binding.json", private=True, maximum=65536)
    # The signer binds the later binding.json to this compiled policy. Its
    # bytes cannot recursively appear in the engine policy's own digest.
    return {"path": path, "files": files, "binding": "late-Root-signed-context-not-validated-here"}


def _output(path):
    fd = _directory(path, private=True)
    try:
        info = os.fstat(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        entries = set(os.listdir(fd))
        require(entries in (set(), {"ownership.json"}), "engine-output-reused")
    finally:
        os.close(fd)
    result = {"path": path, "device": info.st_dev, "inode": info.st_ino,
              "uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
    if entries:
        result["ownership_sha256"] = _file(path + "/ownership.json", private=True, maximum=65536).sha256
    return result


def _retained_output(path, expected):
    require(type(expected) is dict and set(expected) in (
        {"path", "device", "inode", "uid", "gid", "mode"},
        {"path", "device", "inode", "uid", "gid", "mode", "ownership_sha256"}) and expected["path"] == path,
        "engine-retained-output-schema")
    fd = _directory(path, private=True)
    try:
        info = os.fstat(fd)
        require({"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid, "gid": info.st_gid,
                 "mode": stat.S_IMODE(info.st_mode)} == {key: expected[key] for key in ("device", "inode", "uid", "gid", "mode")},
                "engine-retained-output-replaced")
    finally:
        os.close(fd)
    # Contents are job-writable. Never follow children or let them change the
    # originally signed manifest (including any initial ownership-file digest).
    return expected



def controller_files(environment):
    if environment.get("QUALITY_INPUT_PROFILE") == "operating":
        return frozenset({"controller.py"})
    return CONTROLLER_FILES


def _environment(value, runner_uid, cell_uid, cell_gid):
    operating = value.get("QUALITY_INPUT_PROFILE") == "operating"
    expected_keys = ENV_KEYS | {"QUALITY_OPERATING_CASE", "QUALITY_OPERATING_SPEC"} if operating else ENV_KEYS
    _keys(value, expected_keys)
    require(all(type(v) is str and (0 < len(v) <= 2048 or (operating and key == "QUALITY_INPUT_ROLES" and v == ""))
                and not any(ord(c) < 32 or ord(c) == 127 for c in v) for key, v in value.items()), "engine-environment")
    if operating:
        from . import operating_cells
        case = value.get("QUALITY_OPERATING_CASE")
        require(case in operating_cells.CASES and value["QUALITY_INPUT_SCENARIO"] == "g06-operating-" + case
                and value["QUALITY_INPUT_TARGET"] == "ubuntu-24.04" and value["QUALITY_INPUT_TARGET_DISPOSITION"] == "operating"
                and value["QUALITY_INPUT_ROLES"] == "" and value["QUALITY_INPUT_JUNIT_REQUIRED"] == "false"
                and value["QUALITY_INPUT_ALLURE_REQUIRED"] == "false", "engine-operating-kind")
        spec = decode_json(value["QUALITY_OPERATING_SPEC"].encode())
        require(spec == operating_cells.spec(case, value["QUALITY_INPUT_IMAGE"],
            int(value["GITHUB_RUN_ID"])), "engine-operating-spec")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value["GITHUB_REPOSITORY"])
            and all(re.fullmatch(r"[1-9][0-9]{0,19}", value[key]) for key in
                    ("GITHUB_REPOSITORY_ID", "GITHUB_RUN_ID")) and value["GITHUB_RUN_ATTEMPT"] == "1"
            and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value["GITHUB_JOB"])
            and re.fullmatch(r"[0-9a-f]{40}", value["GITHUB_SHA"])
            and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value["QUALITY_INPUT_SOURCE_SHA"]), "engine-native-identity")
    require(all(len(value["QUALITY_INPUT_" + key]) <= 512 for key in INPUTS)
            and value["QUALITY_INPUT_PROFILE"] in ("heavy", "application_acceptance", "operating")
            and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", value[key])
                    for key in ("QUALITY_INPUT_SCENARIO", "QUALITY_INPUT_TARGET"))
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", value["QUALITY_INPUT_CANDIDATE_ARTIFACT"])
            and (operating or re.fullmatch(r"[a-z][a-z0-9_]*(,[a-z][a-z0-9_]*)*", value["QUALITY_INPUT_ROLES"]))
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,511}", value["QUALITY_INPUT_IMAGE"])
            and re.fullmatch(r"[1-9][0-9]{0,2}", value["QUALITY_INPUT_CPU_LIMIT"])
            and re.fullmatch(r"[1-9][0-9]*(KiB|MiB|GiB|TiB)", value["QUALITY_INPUT_MEMORY_LIMIT"])
            and re.fullmatch(r"[1-9][0-9]*(MiB|GiB|TiB)", value["QUALITY_INPUT_DISK_LIMIT"]), "engine-typed-profile-input")
    require(value["QUALITY_INPUT_TARGET_DISPOSITION"] in (("operating",) if operating else ("candidate", "supported"))
            and value["QUALITY_INPUT_INSTANCE_TYPE"] in ("container", "vm")
            and all(value[key] in ("true", "false") for key in ("QUALITY_INPUT_JUNIT_REQUIRED", "QUALITY_INPUT_ALLURE_REQUIRED")),
            "engine-input-contract")
    return {**value, "QUALITY_FAILURE_CUSTODY": "retain-failed-v1", "HOME": "/tmp/wunder", "TMPDIR": "/tmp/wunder", "INCUS_CONF": "/incus",
            "RUNNER_TEMP": "/quality/tmp", "GITHUB_WORKSPACE": "/workspace", "QUALITY_CONTEXT_PHASE": "runtime",
            "QUALITY_DEVTOOLS_IMAGE": IMAGE, "QUALITY_HOST_UID": str(runner_uid),
            "QUALITY_EFFECTIVE_UID": str(cell_uid), "QUALITY_EFFECTIVE_GID": str(cell_gid),
            **({"QUALITY_OPERATING_READY_ACK": "/quality/control/root-operating-ready.json"} if operating else {}),
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "/workspace"}


def _compile(data, descriptor_sha256, *, retained_output=None):
    _keys(data, {"schema", "image", "runner_uid", "runner_gid", "cell_uid", "cell_gid", "uid_map", "gid_map", "limits",
                 "network_namespace_path", "cgroup_parent", "engine", "archives", "trees", "context_path", "output_path", "environment", "capture"})
    require(type(data["schema"]) is int and data["schema"] == 1, "engine-schema")
    image = _keys(data["image"], {"index_sha256", "manifest_sha256", "platform"})
    require(image == {"index_sha256": IMAGE_INDEX, "manifest_sha256": IMAGE_CHILD, "platform": "linux/amd64"}, "engine-image")
    runner, runner_gid, uid, gid = (_integer(data[key]) for key in ("runner_uid", "runner_gid", "cell_uid", "cell_gid"))
    require(uid != runner and gid != runner_gid, "engine-cell-runner-uid")
    maps = []
    for key, logical, host_runner in (("uid_map", uid, runner), ("gid_map", gid, runner_gid)):
        mapping = _keys(data[key], {"host_base", "size"})
        base, size = _integer(mapping["host_base"], 65536), _integer(mapping["size"], 1024, 1048576)
        require(base + size <= 2 ** 32 - 1 and logical < size and not base <= host_runner < base + size,
                "engine-id-map")
        maps.append((base, size, base + logical))
    limits = _keys(data["limits"], {"cpu_millis", "memory_bytes", "timeout_seconds"})
    cpu = _integer(limits["cpu_millis"], 1, 1000000)
    memory = _integer(limits["memory_bytes"], 134217728, 2 ** 40)
    timeout = _integer(limits["timeout_seconds"], 1, 5400)
    capture = _keys(data["capture"], {"stdout_limit", "stderr_limit", "total_limit"})
    _integer(capture["stdout_limit"], 1, MAX_CAPTURE_STREAM_BYTES)
    _integer(capture["stderr_limit"], 1, MAX_CAPTURE_STREAM_BYTES)
    _integer(capture["total_limit"], 1, 2 * MAX_CAPTURE_STREAM_BYTES)
    require(capture["total_limit"] <= capture["stdout_limit"] + capture["stderr_limit"], "engine-capture-limit")
    network = _path(data["network_namespace_path"])
    require(re.fullmatch(r"/run/netns/lit-lease-[0-9a-f]{32}", network), "engine-network-path")
    # Check existing Root ancestors only. A namespace leaf is nsfs, not a
    # hashable regular file. Actual namespace acquisition is NOT implemented.
    network_parent = "/run/netns" if os.path.lexists("/run/netns") else "/run"
    network_parent_fd = _directory(network_parent)
    os.close(network_parent_fd)
    require(type(data["cgroup_parent"]) is str and re.fullmatch(r"lit-lease-[0-9a-f]{32}\.slice", data["cgroup_parent"]), "engine-cgroup-parent")
    require(network.rsplit("lit-lease-", 1)[1] == data["cgroup_parent"].removeprefix("lit-lease-").removesuffix(".slice"), "engine-lease-paths")
    engine = _keys(data["engine"], {"executable", "executable_sha256", "storage_root", "runroot"})
    require(engine["executable"] == ENGINE, "engine-executable")
    executable = _file(ENGINE, engine["executable_sha256"], maximum=128 * 1024 * 1024)
    for key in ("storage_root", "runroot"):
        fd = _directory(engine[key], private=True)
        os.close(fd)
    archives = _keys(data["archives"], {"controller", "candidate"})
    checked_archives = {}
    for key, archive in archives.items():
        _keys(archive, {"path", "sha256"})
        proof = _file(archive["path"], archive["sha256"])
        checked_archives[key] = {"path": proof.path, "sha256": proof.sha256}
    env = _environment(data["environment"], runner, uid, gid)
    trees = _keys(data["trees"], {"workspace", "controller", "candidate"})
    checked_trees = {key: _tree(value) for key, value in trees.items()}
    require(set(checked_trees["controller"]["files"]) == controller_files(env)
            and not checked_trees["controller"]["directories"], "engine-controller-entries")
    context = _context(_path(data["context_path"]))
    output = (_output(_path(data["output_path"])) if retained_output is None
              else _retained_output(_path(data["output_path"]), retained_output))
    paths = [engine["storage_root"], engine["runroot"], context["path"], output["path"]]
    paths += [value["path"] for value in checked_trees.values()] + [value["path"] for value in checked_archives.values()]
    require(len(set(paths)) == len(paths) and not any(left.startswith(right + "/") for left in paths for right in paths if left != right),
            "engine-path-overlap")
    lease_id = network.rsplit("lit-lease-", 1)[1]
    runtime = {"name": "lit-lease-" + lease_id, "cidfile": engine["runroot"] + "/container.cid",
               "labels": {"io.lightning-it.lease": lease_id, "io.lightning-it.descriptor": _hash(descriptor_sha256)}}
    argv = [ENGINE, "--root", engine["storage_root"], "--runroot", engine["runroot"], "--cgroup-manager=systemd",
            "--events-backend=none", "--tmpdir=" + engine["runroot"],
            "run", "--rm", "--log-driver=passthrough", "--name=" + runtime["name"], "--cidfile=" + runtime["cidfile"],
            *["--label=" + key + "=" + value for key, value in sorted(runtime["labels"].items())],
            "--pull=never", "--platform=linux/amd64", "--read-only", "--cap-drop=ALL",
            "--pid=private", "--ipc=private", "--uts=private", "--cgroupns=private",
            "--security-opt=no-new-privileges=true", "--pids-limit=512", "--read-only-tmpfs=false", "--sdnotify=ignore",
            "--user=" + str(uid) + ":" + str(gid), "--uidmap=0:" + str(maps[0][0]) + ":" + str(maps[0][1]),
            "--gidmap=0:" + str(maps[1][0]) + ":" + str(maps[1][1]), "--network=ns:" + network,
            "--cgroup-parent=" + data["cgroup_parent"], "--cpus=" + str(cpu // 1000) + "." + str(cpu % 1000).zfill(3),
            "--memory=" + str(memory), "--timeout=" + str(timeout), "--workdir=/workspace",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777",
            "--tmpfs=/tmp/wunder:rw,exec,nosuid,nodev,size=1g,mode=1777,uid=" + str(uid) + ",gid=" + str(gid)]
    idmap = ",idmap=uids=0-" + str(maps[0][2]) + "-1;gids=0-" + str(maps[1][2]) + "-1"
    for key, target in (("workspace", "/workspace"), ("candidate", "/candidate"), ("controller", "/controller")):
        argv += ["--mount", "type=bind,source=" + checked_trees[key]["path"] + ",destination=" + target + ",readonly" + idmap]
    argv += ["--mount", "type=bind,source=" + context["path"] + ",destination=/incus,readonly" + idmap,
             "--mount", "type=bind,source=" + output["path"] + ",destination=/quality" + idmap]
    for key, value in sorted(env.items()):
        argv += ["--env", key + "=" + value]
    argv += [PODMAN_IMAGE, "python3", "/controller/" + ("controller.py" if env["QUALITY_INPUT_PROFILE"] == "operating" else "run-cell.py")]
    require(len(argv) <= MAX_ENGINE_ARGS and all(type(arg) is str and 0 < len(arg) <= 8192 for arg in argv)
            and sum(len(arg.encode("utf-8")) + 1 for arg in argv) <= MAX_ENGINE_ARG_BYTES, "engine-argv-limit")
    details = {"schema": 1, "image": image, "argv": argv, "environment": env, "archives": checked_archives,
               "trees": checked_trees, "context": context, "output": output, "limits": limits, "capture": capture,
               "runner_uid": runner, "runner_gid": runner_gid, "cell_uid": uid, "cell_gid": gid,
               "uid_map": data["uid_map"], "gid_map": data["gid_map"],
               "engine_executable_sha256": executable.sha256, "engine": engine, "runtime": runtime,
               "network_namespace": {"path": network, "proof": "structural-only-native-nsfs-preflight-required"}}
    return tuple(argv), env, details


def compile_engine_policy(path, expected_sha256):
    """Fixed trusted Root configuration locator/hash only; never a job API."""
    require(os.geteuid() == 0, "engine-policy-root-required")
    try:
        proof, raw, stamp = installation._file(_path(path), MAX_DESCRIPTOR, private=True, keep=True)
        require(proof.sha256 == _hash(expected_sha256), "engine-descriptor-drift")
        data = decode_json(raw)
        argv, environment, details = _compile(data, expected_sha256)
        again, _, again_stamp = installation._file(path, MAX_DESCRIPTOR, private=True, keep=True)
        require(again == proof and again_stamp == stamp, "engine-descriptor-drift")
        details["descriptor"] = {"path": path, "sha256": expected_sha256}
        canonical = _canonical(details)
        return EngineManifest(path, expected_sha256, IMAGE_INDEX, IMAGE_CHILD, argv,
                              MappingProxyType(environment), hashlib.sha256(canonical).hexdigest(), canonical)
    except Denied:
        raise
    except Exception:
        raise Denied("engine-policy-denied") from None


def validate_retained_policy(path, descriptor_sha256, expected_manifest_sha256):
    """Recheck immutable running inputs; return the ORIGINAL signed manifest.

    Caller must authenticate expected_manifest_sha256 through the actual Root
    JWS and engine-start record; a hash/Root file alone grants nothing. Locator
    is derived from the immutable descriptor. Output contents may change, its
    directory identity may not. No altered manifest/digest is manufactured.
    """
    require(os.geteuid() == 0, "engine-policy-root-required")
    try:
        proof, raw, stamp = installation._file(_path(path), MAX_DESCRIPTOR, private=True, keep=True)
        require(proof.sha256 == _hash(descriptor_sha256), "engine-descriptor-drift")
        data = decode_json(raw)
        retained_path = _path(data["engine"]["runroot"]) + "/engine-manifest.json"
        saved, canonical, saved_stamp = installation._file(retained_path, MAX_DESCRIPTOR, private=True, keep=True)
        require(saved.sha256 == _hash(expected_manifest_sha256), "engine-retained-manifest-drift")
        original = decode_json(canonical)
        require(_canonical(original) == canonical, "engine-retained-canonical")
        argv, environment, details = _compile(data, descriptor_sha256, retained_output=original["output"])
        details["descriptor"] = {"path": path, "sha256": descriptor_sha256}
        require(_canonical(details) == canonical, "engine-retained-immutable-drift")
        after, _, after_stamp = installation._file(path, MAX_DESCRIPTOR, private=True, keep=True)
        saved_after, _, saved_after_stamp = installation._file(retained_path, MAX_DESCRIPTOR, private=True, keep=True)
        require(after == proof and after_stamp == stamp and saved_after == saved and saved_after_stamp == saved_stamp,
                "engine-retained-file-drift")
        _retained_output(data["output_path"], original["output"])
        return EngineManifest(path, descriptor_sha256, IMAGE_INDEX, IMAGE_CHILD, argv, MappingProxyType(environment),
                              expected_manifest_sha256, canonical)
    except Denied:
        raise
    except Exception:
        raise Denied("engine-retained-policy-denied") from None
