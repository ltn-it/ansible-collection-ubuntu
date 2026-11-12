"""Bind an actual provider artifact to the complete Root-owned sanitized export.

No job-selected URL/path, caller success flag, token file or metadata-only
artifact acceptance. Bearers live only during this same-job native request.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import PurePosixPath
import stat
import tarfile
import threading
import time
import weakref
import zipfile

from . import admission, cell_contract, evidence_export, generation_acquisition as acquisition
from . import identity, installation, ledger, runtime_rpc, storage_quota, preparation
from .identity import require

_FIELDS = frozenset({"id", "name", "digest_sha256", "size_in_bytes", "capture_receipt_sha256", "export_sha256",
                     "member_inventory_sha256", "native_sha256", "execution_success"})
_PROOFS = weakref.WeakSet()
_GUARD = threading.Lock()


@dataclass(frozen=True, eq=False)
class _UploadProof:
    lease_id: str
    lease_sha256: str
    payload: bytes
    pid: int
    thread: int
    until: float
    directory: str
    directory_stamp: tuple
    zip_stamp: tuple
    intent_stamp: tuple


def validate_record(value, record):
    require(type(value) is dict and set(value) == _FIELDS and type(value["id"]) is int and value["id"] > 0
            and type(value["name"]) is str and 0 < len(value["name"]) <= 512
            and type(value["size_in_bytes"]) is int and value["size_in_bytes"] > 0
            and type(value["execution_success"]) is bool
            and all(type(value[k]) is str and ledger.HEX.fullmatch(value[k]) for k in
                    ("digest_sha256", "capture_receipt_sha256", "export_sha256", "member_inventory_sha256", "native_sha256"))
            and record.get("capture_receipt_sha256") in {None, value["capture_receipt_sha256"]}, "upload-record-binding")


def _relative(name):
    require(type(name) is str and 0 < len(name) <= 1024 and not name.startswith("/")
            and PurePosixPath(name).as_posix() == name and "\\" not in name
            and all(part not in {"", ".", ".."} for part in PurePosixPath(name).parts), "upload-member-path")
    return name


def _hash_stream(reader, size, maximum):
    require(type(size) is int and 0 <= size <= maximum, "upload-member-size")
    digest, count = hashlib.sha256(), 0
    while chunk := reader.read(65536):
        count += len(chunk)
        require(count <= size, "upload-member-expanded-size")
        digest.update(chunk)
    require(count == size, "upload-member-size")
    return digest.hexdigest()


def compare_provider_zip(zip_fd, exported, bounds):
    """Compare exact provider ZIP file bytes to authenticated Root tar members.

    Directory entries are allowed only when they are exact parents of an
    expected file; no wrapper tar or alternate generated manifest is accepted.
    """
    require(type(exported) is evidence_export.ExportReceipt and exported.evidence_policy_complete,
            "upload-root-export-required")
    proof = installation._file(exported.path, bounds["max_total_evidence_bytes"], private=True)[0]
    require(proof.sha256 == exported.sha256 and proof.size == exported.size, "upload-root-export-drift")
    fd = os.open(exported.path, installation.FILE_FLAGS)
    expected, metadata = {}, {}
    try:
        info = os.fstat(fd)
        require((info.st_dev, info.st_ino, info.st_size) == (proof.device, proof.inode, proof.size), "upload-root-export-drift")
        with os.fdopen(os.dup(fd), "rb") as source, tarfile.open(fileobj=source, mode="r:gz") as archive:
            count, total = 0, 0
            for member in archive:
                count += 1
                require(count <= bounds["max_members"] and member.isfile() and not member.pax_headers,
                        "upload-root-export-member")
                if member.name == "normalized/lifecycle.json":
                    require(member.size <= 16384, "upload-lifecycle-limit")
                    reader = archive.extractfile(member)
                    require(reader is not None, "upload-root-export-reader")
                    metadata[member.name] = identity.decode_json(reader.read(member.size + 1))
                if not member.name.startswith("evidence/"):
                    continue
                path = _relative(member.name.removeprefix("evidence/"))
                require(path not in expected, "upload-root-export-duplicate")
                total += member.size
                require(total <= bounds["max_total_evidence_bytes"], "upload-root-expanded-limit")
                reader = archive.extractfile(member)
                require(reader is not None, "upload-root-export-reader")
                if path == "manifest.json":
                    require(member.size <= min(bounds["max_member_bytes"], 1048576), "upload-manifest-limit")
                    raw = reader.read(member.size + 1)
                    require(len(raw) == member.size, "upload-root-export-size")
                    metadata[path] = identity.decode_json(raw)
                    digest = hashlib.sha256(raw).hexdigest()
                else:
                    digest = _hash_stream(reader, member.size, bounds["max_member_bytes"])
                expected[path] = (member.size, digest)
        require(installation._file(exported.path, bounds["max_total_evidence_bytes"], private=True)[0] == proof,
                "upload-root-export-drift")
    finally:
        os.close(fd)
    require(expected and "manifest.json" in metadata, "upload-root-export-empty")
    parents = {str(parent) for name in expected for parent in PurePosixPath(name).parents if str(parent) != "."}
    found, directories, total = {}, set(), 0
    with os.fdopen(os.dup(zip_fd), "rb") as source, zipfile.ZipFile(source) as archive:
        rows = archive.infolist()
        require(0 < len(rows) <= bounds["max_members"] * 2 + 64, "upload-zip-members")
        for member in rows:
            name = member.filename
            if member.is_dir():
                path = _relative(name[:-1])
                require(path in parents and path not in directories and member.file_size == 0, "upload-zip-directory")
                directories.add(path)
                continue
            path = _relative(name)
            mode = member.external_attr >> 16
            require(path in expected and path not in found and not member.flag_bits & 1
                    and stat.S_IFMT(mode) in {0, stat.S_IFREG} and member.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    and member.file_size == expected[path][0], "upload-zip-member")
            total += member.file_size
            require(total <= bounds["max_total_evidence_bytes"], "upload-zip-expanded-limit")
            with archive.open(member) as reader:
                actual = _hash_stream(reader, member.file_size, bounds["max_member_bytes"])
            require(actual == expected[path][1], "upload-root-content-mismatch")
            found[path] = (member.file_size, actual)
    require(found == expected, "upload-root-members-mismatch")
    manifest = metadata["manifest.json"]
    # This boolean is accepted only after Root's static complete report/schema
    # rederivation and exact content binding, and is still NOT final quality.
    require(manifest.get("root_finalization") == "pending" and type(manifest.get("execution_success")) is bool
            and manifest.get("release_eligible") is False and manifest.get("candidate_execution_passed") is False,
            "upload-preliminary-phase")
    lifecycle = metadata.get("normalized/lifecycle.json", {})
    totals, scan, security, prerequisites = (manifest.get(key, {}) for key in
                                            ("test_totals", "secret_scan", "security_evidence", "prerequisites"))
    actual_success = (lifecycle.get("root_finalization") == "pending" and lifecycle.get("destroy_exit_code") is None
        and all(type(lifecycle.get(key)) is int and lifecycle[key] == 0
                for key in ("test_exit_code", "capture_exit_code", "effective_exit_code"))
        and lifecycle.get("infrastructure_error") is False and manifest.get("commit_consistent") is True
        and type(totals.get("tests")) is int and totals["tests"] > 0 and totals.get("failures") == totals.get("errors") == 0
        and scan.get("clean") is True and not scan.get("findings") and not scan.get("errors")
        and not security.get("external_secret_findings", 0) and not manifest.get("blockers")
        and all(value == "success" for key, value in prerequisites.items() if key != "destroy")
        and (not prerequisites or prerequisites.get("destroy") == "pending")
        and all(row.get("status") == "passed" and row.get("meaningful") is True for row in manifest.get("results", [])))
    require(manifest["execution_success"] is actual_success, "upload-execution-outcome-mismatch")
    return ledger.digest(found), actual_success


def _native_artifact(selected, who, artifact, api_token, deadline):
    prefix = "/repos/" + selected.identity.repository
    native = acquisition._json(prefix + "/actions/artifacts/" + str(artifact["id"]), api_token, deadline)
    run = native.get("workflow_run", {})
    require(native.get("id") == artifact["id"] and native.get("name") == artifact["name"]
            and native.get("digest") == "sha256:" + artifact["digest_sha256"] and native.get("expired") is False
            and native.get("size_in_bytes") == artifact["size_in_bytes"] and run.get("id") == who.run_id
            and run.get("repository_id") == selected.identity.repository_id
            and run.get("head_repository_id") == selected.identity.repository_id
            and run.get("head_sha") == who.caller_sha and run.get("head_branch") == "main", "upload-native-artifact")
    rows, total = [], None
    for page in range(1, 12):
        value = acquisition._json(prefix + "/actions/runs/" + str(who.run_id)
                                  + "/artifacts?per_page=100&page=" + str(page), api_token, deadline)
        count, batch = value.get("total_count"), value.get("artifacts")
        require(type(count) is int and 0 < count <= 1000 and type(batch) is list and len(batch) <= 100
                and (total is None or total == count), "upload-native-inventory")
        total = count
        rows.extend(batch)
        if len(rows) == total:
            break
        require(len(rows) < total and len(batch) == 100, "upload-native-inventory")
    require(len(rows) == total and len({r.get("id") for r in rows}) == len(rows)
            and [r.get("id") for r in rows if r.get("name") == artifact["name"]] == [artifact["id"]],
            "upload-native-unique-artifact")
    return ledger.digest(native)


def validate_verification(value):
    fields = {"state", "stage_sha256", "pid", "boot_id", "start_ticks", "deadline"}
    require(type(value) is dict and set(value) == fields and value["state"] in {"intent", "verified"}
            and type(value["stage_sha256"]) is str and ledger.HEX.fullmatch(value["stage_sha256"])
            and ledger._native_uuid(value["boot_id"])
            and all(type(value[k]) is int and value[k] > 0 for k in ("pid", "start_ticks", "deadline")),
            "upload-verification-state")


def verification_active(value):
    """Read-only known uploader liveness, never effect/cleanup authority."""
    from . import kernel
    validate_verification(value)
    try:
        current = kernel.read_process(value["pid"])
        return (value["state"] == "intent" and int(time.time()) < value["deadline"]
                and kernel.read_boot_id() == value["boot_id"] and current.stat.start_ticks == value["start_ticks"]
                and current.uids == (0, 0, 0, 0))
    except Exception:
        return False


def verify_uploaded_artifact(runtime_path, runtime_sha, registry, selector, store, lease_id,
                             proof, connected, token, api_token, supplied):
    """Same-job read transport + fixed Root export byte comparison, no effects grant."""
    selected = registry.select(selector)
    worker, who, remaining = admission.require_intake_native(proof, connected, selected, token, api_token)
    record = store.read(lease_id)
    require(record["worker"] == ledger.asdict(worker)
            and ledger.Ledger._immutable_identity(who) == ledger.Ledger._immutable_identity(identity.Identity(**record["identity"]))
            and type(supplied) is dict and set(supplied) == {"id", "digest_sha256", "size_in_bytes"}
            and type(supplied["id"]) is int and supplied["id"] > 0 and type(supplied["size_in_bytes"]) is int
            and supplied["size_in_bytes"] > 0 and type(supplied["digest_sha256"]) is str
            and ledger.HEX.fullmatch(supplied["digest_sha256"]), "upload-same-job-binding")
    config = runtime_rpc._configuration(runtime_path, runtime_sha)
    owner = cell_contract.owned_cell_for_cleanup(registry, selector, store, lease_id)
    data = identity.decode_json(owner.engine_descriptor_bytes)
    env = data["environment"]
    prefix = "candidate-quality-result" if env["QUALITY_INPUT_TARGET_DISPOSITION"] == "candidate" else "quality-result"
    artifact = {**supplied, "name": prefix + "-" + env["QUALITY_INPUT_SCENARIO"] + "-" + env["QUALITY_INPUT_TARGET"]
                + "-" + who.caller_sha + "-attempt-1"}
    deadline = time.monotonic() + min(120, remaining)
    require(artifact["size_in_bytes"] <= config.capture["max_total_evidence_bytes"], "upload-archive-limit")
    native = _native_artifact(selected, who, artifact, api_token, deadline)
    exported = evidence_export.read_existing(runtime_path, runtime_sha, registry, selector, store, lease_id)
    directory = data["engine"]["runroot"] + ".upload-check"
    from . import kernel
    process = kernel.read_process(os.getpid())
    require(process.uids == (0, 0, 0, 0), "upload-verification-root-owner")
    owner_state = {"pid": os.getpid(), "boot_id": kernel.read_boot_id(), "start_ticks": process.stat.start_ticks,
                   "deadline": min(int(time.time()) + 240, who.valid_until - 31)}
    require(owner_state["deadline"] > int(time.time()), "upload-verification-expired")
    stage_sha = ledger.digest({"directory": directory, "artifact": artifact, "capture_receipt_sha256": exported.receipt_sha256})
    record = store.begin_upload_verification(lease_id, stage_sha, owner_state)
    os.mkdir(directory, 0o700)  # Existing/partial intent is retained, never replayed.
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    fd = None
    try:
        info = os.fstat(parent)
        require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, "upload-private-stage")
        intent = os.open("intent.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(intent, "wb") as stream:
            stream.write(ledger.canonical({"schema": 1, "lease_id": lease_id, "artifact": artifact,
                                          "capture_receipt_sha256": exported.receipt_sha256}))
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
        root = preparation._config(config.preparation_config_path, config.preparation_config_sha256)[0]
        with storage_quota.acquire_existing_evidence_quota(root.storage_quota_policy_path,
                                                          root.storage_quota_policy_sha256, directory):
            fd = os.open("artifact.zip", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            url = acquisition._redirect("/repos/" + selected.identity.repository + "/actions/artifacts/" + str(artifact["id"]) + "/zip",
                                        api_token, deadline)
            acquisition._download(url, fd, None, deadline, config.capture["max_total_evidence_bytes"],
                                  digest=artifact["digest_sha256"], size=artifact["size_in_bytes"])
            os.lseek(fd, 0, os.SEEK_SET)
            inventory, execution_success = compare_provider_zip(fd, exported, config.capture)
        require(_native_artifact(selected, who, artifact, api_token, deadline) == native, "upload-native-artifact-drift")
        admission.require_intake_native(proof, connected, selected, token, api_token)
        require(store.read(lease_id) == record, "upload-lease-drift")
        value = {**artifact, "capture_receipt_sha256": exported.receipt_sha256, "export_sha256": exported.sha256,
            "member_inventory_sha256": inventory, "native_sha256": native, "execution_success": execution_success}
        validate_record(value, record)
        result = _UploadProof(lease_id, ledger.digest(record), ledger.canonical(value), os.getpid(), threading.get_ident(),
            time.monotonic() + 5, directory, _stamp(os.fstat(parent)), _stamp(os.fstat(fd)),
            _stamp(os.stat("intent.json", dir_fd=parent, follow_symlinks=False)))
        with _GUARD:
            _PROOFS.add(result)
        return result
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)
        # Private sanitized transport remains for explicit exact cleanup after
        # Ledger binding; uncertainty never triggers deletion/re-download here.


def require_upload_proof(proof, lease_id, record):
    require(type(proof) is _UploadProof, "upload-native-proof")
    with _GUARD:
        require(proof in _PROOFS, "upload-native-proof")
    require(proof.lease_id == lease_id and proof.lease_sha256 == ledger.digest(record)
            and proof.pid == os.getpid() and proof.thread == threading.get_ident()
            and time.monotonic() < proof.until, "upload-native-proof-drift")
    value = identity.decode_json(proof.payload)
    validate_record(value, record)
    return value


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def require_bound_upload(proof, lease_id, record):
    require(type(proof) is _UploadProof, "upload-transport-proof")
    with _GUARD:
        require(proof in _PROOFS, "upload-transport-proof")
    require(proof.lease_id == lease_id and proof.pid == os.getpid() and proof.thread == threading.get_ident()
            and time.monotonic() < proof.until + 120
            and identity.decode_json(proof.payload) == record.get("uploaded_evidence"), "upload-transport-proof-drift")
    return ledger.digest({"path": proof.directory, "directory": proof.directory_stamp,
                          "zip": proof.zip_stamp, "intent": proof.intent_stamp})


def finish_transport(store, lease_id, proof):
    """Delete only this verified sanitized ZIP staging after durable binding.

    Any uncertain partial local unlink remains an intent; no replay/repair path.
    This does not delete the provider artifact or the retained public export.
    """
    record = store.read(lease_id)
    stage_sha = require_bound_upload(proof, lease_id, record)
    parent = os.open(proof.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    outer = None
    try:
        require(_stamp(os.fstat(parent)) == proof.directory_stamp and set(os.listdir(parent)) == {"intent.json", "artifact.zip"}
                and _stamp(os.stat("artifact.zip", dir_fd=parent, follow_symlinks=False)) == proof.zip_stamp
                and _stamp(os.stat("intent.json", dir_fd=parent, follow_symlinks=False)) == proof.intent_stamp,
                "upload-transport-stage-drift")
        outer_path = str(PurePosixPath(proof.directory).parent)
        name = PurePosixPath(proof.directory).name
        outer = os.open(outer_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        require(_stamp(os.stat(name, dir_fd=outer, follow_symlinks=False)) == proof.directory_stamp,
                "upload-transport-stage-drift")
        store.begin_upload_transport_cleanup(lease_id, proof)
        os.unlink("artifact.zip", dir_fd=parent)
        os.unlink("intent.json", dir_fd=parent)
        os.fsync(parent)
        os.rmdir(name, dir_fd=outer)
        os.fsync(outer)
        require(name not in os.listdir(outer), "upload-transport-returned")
        store.finish_upload_transport_cleanup(lease_id, proof, stage_sha)
    finally:
        if outer is not None:
            os.close(outer)
        os.close(parent)
