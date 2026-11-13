"""Root-only memory acquisition primitives for ordinary Source Main intake.

This module does not authenticate jobs, mint proof tickets, publish generations,
change the runtime anchor, sign contexts, or grant engine authority. The intake
dispatcher must independently authenticate its actual peer before calling these
private primitives and reauthenticate after IO before any subsequent effect.
The existing offline publisher and its inactive/CAS contract remain unchanged.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import os
import stat
import time

from . import admission, generation_acquisition as acquisition, generation_publisher as publisher, identity, installation, ledger
from .identity import Denied, require

ROOT = "/var/lib/lightning-it/incus-run-intakes"
ARCHIVES = ("artifact.zip", "source.tar.gz", "controller.tar.gz")
INVENTORY = frozenset((*ARCHIVES, "intent.json", "sealed.json"))
MAX_RECEIPT = 32 * 1024 * 1024


@dataclass(frozen=True)
class MemoryRequest:
    """Root-derived metadata only; no credential path, URL or reader option."""

    source: acquisition.CommitRequest
    controller: acquisition.CommitRequest
    artifact: acquisition.ArtifactRequest
    max_archive_bytes: int
    max_tree_entries: int
    max_file_bytes: int
    total_timeout_seconds: int


@dataclass(frozen=True)
class RootRunSnapshot:
    """Validated bytes/provenance projection, never native admission authority."""

    acquisition: acquisition.Acquisition
    candidate_name: str
    candidate_sha256: str
    candidate_size: int
    runtime_sha256: str
    runtime_size: int
    source_provenance_sha256: str
    controller_files: tuple[tuple[str, str], ...]
    snapshot_sha256: str


@dataclass(frozen=True)
class SealedRunSnapshot:
    """Root-private archive locator; not a lease, context, or operating grant."""

    directory: str
    device: int
    inode: int
    receipt_sha256: str
    snapshot: RootRunSnapshot


@identity._diagnostic_step("intake-discovery")
def _native_request(selected, who, api_token, deadline, seconds):
    """Derive acquisition locators from the checked Root policy/native API."""
    native = selected.identity
    require(native.repository == acquisition.SUPPLEMENTARY and native.repository_id == 1103407173
            and native.workflow_id == 214182490 and native.workflow_path == ".github/workflows/collection-ci.yml"
            and native.reusable_repository == acquisition.VALIDATION
            and native.reusable_path == ".github/workflows/collection-quality-profile-isolated.yml"
            and who.caller_sha == native.caller_sha and who.reusable_sha == native.reusable_sha,
            "intake-source-domain")
    branch = acquisition._json("/repos/" + native.repository + "/branches/main", api_token, deadline)
    require(branch.get("name") == "main" and branch.get("protected") is True
            and branch.get("commit", {}).get("sha") == native.caller_sha, "intake-current-main")
    branch = acquisition._json("/repos/" + native.reusable_repository + "/branches/main", None, deadline)
    tip = branch.get("commit", {}).get("sha")
    acquisition._hash(tip, acquisition.HEX40)
    require(branch.get("name") == "main" and branch.get("protected") is True, "intake-controller-main")
    compare = acquisition._json("/repos/" + native.reusable_repository + "/compare/"
        + native.reusable_sha + "..." + tip, None, deadline)
    require(compare.get("status") in {"ahead", "identical"}
            and compare.get("base_commit", {}).get("sha") == native.reusable_sha
            and compare.get("merge_base_commit", {}).get("sha") == native.reusable_sha,
            "intake-controller-publication")
    rows, total = [], None
    for page in range(1, 12):
        value = acquisition._json("/repos/" + native.repository + "/actions/runs/" + str(who.run_id)
            + "/artifacts?per_page=100&page=" + str(page), api_token, deadline)
        require(type(value.get("total_count")) is int and 0 < value["total_count"] <= 1000
                and type(value.get("artifacts")) is list and len(value["artifacts"]) <= 100,
                "intake-artifact-inventory")
        if total is None:
            total = value["total_count"]
        require(total == value["total_count"] and all(type(row) is dict for row in value["artifacts"]),
                "intake-artifact-inventory")
        rows.extend(value["artifacts"])
        require(len(rows) <= total, "intake-artifact-inventory")
        if len(rows) == total:
            break
        require(len(value["artifacts"]) == 100, "intake-artifact-inventory")
    require(len(rows) == total and all(type(row.get("id")) is int and row["id"] > 0 for row in rows)
            and len({row["id"] for row in rows}) == total, "intake-artifact-inventory")
    name = "collection-candidate-" + native.caller_sha
    found = [row for row in rows if row.get("name") == name]
    require(len(found) == 1 and found[0].get("expired") is False, "intake-artifact-unique")
    row = found[0]
    digest = row.get("digest")
    require(type(digest) is str and digest.startswith("sha256:"), "intake-artifact-digest")
    item = acquisition.ArtifactRequest(who.run_id, 1, native.caller_sha, native.workflow_id,
        native.workflow_path, row["id"], name, digest[7:], row.get("size_in_bytes"))
    request = MemoryRequest(acquisition.CommitRequest(native.repository, native.repository_id, native.caller_sha),
        acquisition.CommitRequest(native.reusable_repository, 1269461997, native.reusable_sha), item,
        acquisition.MAX_ARCHIVE, 20000, 512 * 1024 * 1024, seconds)
    _validate_request(request)
    return request


@identity._diagnostic_step("snapshot-acquisition")
def acquire_run_snapshot(proof, connected_socket, selected, token, api_token, *,
                         artifact_fd, source_fd, controller_fd):
    """Approved opaque-ticket boundary; no public request metadata or paths.

    The Root dispatcher creates and retains these exclusive FDs and the fixed
    trusted selected policy. This component never makes the policy, accepts
    caller policy JSON, publishes a global generation, or creates a lease.
    Slow IO cannot renew the original OIDC/JTI. After expiry, partials remain
    and no snapshot is returned. Signing/effects still need ordinary admission.
    """
    require(os.geteuid() == 0, "intake-root-required")
    try:
        worker, who, remaining = admission.require_intake_native(
            proof, connected_socket, selected, token, api_token)
        seconds = min(600, int(remaining))
        require(seconds > 0, "intake-auth-budget")
        deadline = time.monotonic() + seconds
        request = _native_request(selected, who, api_token, deadline, seconds)
        # Metadata discovery consumes the same finite original auth budget.
        remaining = int(acquisition._remaining(deadline))
        require(remaining > 0, "intake-auth-budget")
        request = MemoryRequest(request.source, request.controller, request.artifact,
            request.max_archive_bytes, request.max_tree_entries, request.max_file_bytes, remaining)
        again = admission.require_intake_native(proof, connected_socket, selected, token, api_token)
        require(again[0] == worker and again[1] == who, "intake-native-drift")
        remaining = min(int(acquisition._remaining(deadline)), int(again[2]))
        require(remaining > 0, "intake-auth-budget")
        request = MemoryRequest(request.source, request.controller, request.artifact,
            request.max_archive_bytes, request.max_tree_entries, request.max_file_bytes, remaining)
        proven = _acquire_memory(request, api_token, artifact_fd=artifact_fd,
                                 source_fd=source_fd, controller_fd=controller_fd, _absolute_deadline=deadline)
        again = admission.require_intake_native(proof, connected_socket, selected, token, api_token)
        require(again[0] == worker and again[1] == who, "intake-native-drift")
        snapshot = _validate_archives(proven, artifact_fd=artifact_fd,
                                      source_fd=source_fd, controller_fd=controller_fd)
        again = admission.require_intake_native(proof, connected_socket, selected, token, api_token)
        require(again[0] == worker and again[1] == who and time.monotonic() < deadline,
                "intake-native-drift")
        return snapshot
    except Exception as error:
        identity._diagnostic_failed("snapshot-acquisition", error)
        raise Denied("intake-snapshot-held") from None


def _validate_request(request):
    require(type(request) is MemoryRequest, "intake-memory-request")
    for item, repository in ((request.source, acquisition.SUPPLEMENTARY),
                             (request.controller, acquisition.VALIDATION)):
        require(type(item) is acquisition.CommitRequest and item.repository == repository
                and type(item.repository_id) is int
                and item.repository_id == acquisition.REPOSITORIES[repository], "intake-memory-repository")
        acquisition._hash(item.commit_sha, acquisition.HEX40)
    item = request.artifact
    # MainArtifactRequest is the unrelated modern receiver/Nexus domain.
    require(type(item) is acquisition.ArtifactRequest
            and type(item.run_attempt) is int and item.run_attempt == 1
            and item.head_sha == request.source.commit_sha
            and item.workflow_id == 214182490
            and item.workflow_path == ".github/workflows/collection-ci.yml"
            and item.name == "collection-candidate-" + request.source.commit_sha,
            "intake-memory-artifact")
    acquisition._hash(item.digest_sha256)
    for value in (item.run_id, item.workflow_id, item.artifact_id, item.size_in_bytes):
        acquisition._positive(value)
    acquisition._positive(request.max_archive_bytes, acquisition.MAX_ARCHIVE)
    acquisition._positive(request.max_tree_entries, 20000)
    acquisition._positive(request.max_file_bytes, 512 * 1024 * 1024)
    acquisition._positive(request.total_timeout_seconds, 900)
    require(item.size_in_bytes <= request.max_archive_bytes, "intake-memory-artifact-size")


def _acquire_memory(request, api_token, *, artifact_fd, source_fd, controller_fd, _absolute_deadline=None):
    """Acquire into three exclusive Root FDs; no token materialization or retry.

    Private Root primitive, not a public job-facing admission entry. A returned
    Acquisition proves downloaded provenance only. Authentication may expire
    during IO, so its caller must obtain a fresh native proof before sealing a
    run policy or signing/starting anything. Failures retain original partials.
    """
    require(os.geteuid() == 0, "intake-root-required")
    try:
        _validate_request(request)
        require(type(api_token) is str and 0 < len(api_token) <= 16384
                and all(33 <= ord(char) <= 126 for char in api_token), "intake-memory-token")
        deadline = time.monotonic() + request.total_timeout_seconds
        if _absolute_deadline is not None:
            require(type(_absolute_deadline) in {int, float} and _absolute_deadline > time.monotonic(),
                    "intake-auth-budget")
            deadline = min(deadline, _absolute_deadline)
        fds = (artifact_fd, source_fd, controller_fd)
        stamps = [acquisition._fd(fd) for fd in fds]
        require(len(set(stamps)) == 3, "intake-memory-fd-alias")
        for item in (request.source, request.controller):
            acquisition._repository(item, None if item.repository == acquisition.VALIDATION else api_token, deadline)
        native = acquisition._native(request, api_token, deadline)
        trees = [acquisition._tree(item, request, None if item.repository == acquisition.VALIDATION else api_token, deadline)
                 for item in (request.source, request.controller)]
        item = request.artifact
        location = acquisition._redirect("/repos/" + acquisition.SUPPLEMENTARY
            + "/actions/artifacts/" + str(item.artifact_id) + "/zip", api_token, deadline)
        artifact_sha, artifact_size = acquisition._download(location, artifact_fd, None, deadline,
            request.max_archive_bytes, digest=item.digest_sha256, size=item.size_in_bytes)
        commits = []
        for item, fd, tree in zip((request.source, request.controller), fds[1:], trees):
            location = acquisition._redirect("/repos/" + item.repository + "/tarball/" + item.commit_sha,
                                            None if item.repository == acquisition.VALIDATION else api_token, deadline, archive=True)
            digest, size = acquisition._download(location, fd, None, deadline, request.max_archive_bytes)
            commits.append(acquisition.CommitAcquisition(item.repository, item.repository_id,
                item.commit_sha, *tree, digest, size))
        require(acquisition._native(request, api_token, deadline) == native, "intake-memory-native-drift")
        for fd, original, size in zip(fds, stamps, (artifact_size, commits[0].archive_size, commits[1].archive_size)):
            current = os.fstat(fd)
            require((current.st_dev, current.st_ino) == original and stat.S_ISREG(current.st_mode)
                    and current.st_uid == 0 and current.st_nlink == 1
                    and stat.S_IMODE(current.st_mode) == 0o600 and current.st_size == size
                    and os.lseek(fd, 0, os.SEEK_CUR) == size, "intake-memory-fd-drift")
        acquisition._remaining(deadline)
        return acquisition.Acquisition(*commits, request.artifact, artifact_sha, artifact_size,
                                       hashlib.sha256(repr(native).encode("ascii")).hexdigest())
    except Exception:
        # No bearer, signed URL, HTTP body, request/file path or exception text.
        raise Denied("intake-acquisition-held") from None


def _archive_bytes(fd, digest, size):
    require(type(fd) is int and fd >= 0 and type(size) is int
            and 0 < size <= acquisition.MAX_ARCHIVE, "intake-archive")
    acquisition._hash(digest)
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size == size, "intake-archive-file")
    # pread retains the original owner offsets and never accepts a caller path.
    raw, offset = bytearray(), 0
    while offset < size:
        piece = os.pread(fd, min(65536, size - offset), offset)
        require(piece, "intake-archive-short")
        raw.extend(piece)
        offset += len(piece)
    require(installation._stamp(os.fstat(fd)) == installation._stamp(before)
            and hashlib.sha256(raw).hexdigest() == digest,
            "intake-archive-drift")
    return bytes(raw)


def _validate_archives(proven, *, artifact_fd, source_fd, controller_fd):
    """Revalidate inert archive content; no publication or identity assertion."""
    require(os.geteuid() == 0, "intake-root-required")
    try:
        require(type(proven) is acquisition.Acquisition
                and type(proven.artifact) is acquisition.ArtifactRequest, "intake-acquisition")
        fds = (artifact_fd, source_fd, controller_fd)
        identities = [(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in fds]
        stamps = [installation._stamp(os.fstat(fd)) for fd in fds]
        require(len(set(identities)) == 3, "intake-archive-alias")
        metadata = ((proven.artifact_sha256, proven.artifact_size),
                    (proven.source.archive_sha256, proven.source.archive_size),
                    (proven.controller.archive_sha256, proven.controller.archive_size))
        raw = [_archive_bytes(fd, *item) for fd, item in zip(fds, metadata)]
        workspace = publisher._git_archive(raw[1], proven.source)
        controller = publisher._git_archive(raw[2], proven.controller)
        candidates, name, _ = publisher._candidate(raw[0], workspace)
        prefix = ".github/actions/run-quality-profile/"
        files = tuple(sorted((name, hashlib.sha256(controller[prefix + name]).hexdigest())
                             for name in publisher.engine.CONTROLLER_FILES))
        source_sha = hashlib.sha256(ledger.canonical(publisher._source_provenance(proven.source))).hexdigest()
        fields = dict(acquisition=asdict(proven), candidate_name=name,
            candidate_sha256=hashlib.sha256(candidates[name]).hexdigest(), candidate_size=len(candidates[name]),
            runtime_sha256=hashlib.sha256(candidates["runtime-collections.tar.gz"]).hexdigest(),
            runtime_size=len(candidates["runtime-collections.tar.gz"]), source_provenance_sha256=source_sha,
            controller_files=files)
        # Check all three original descriptors again after parsing, not just
        # before it. This does not replace future sealed-stage FD/inventory CAS.
        for fd, item in zip(fds, metadata):
            _archive_bytes(fd, *item)
        require([installation._stamp(os.fstat(fd)) for fd in fds] == stamps, "intake-archive-stamp")
        fields["acquisition"] = proven
        digest_fields = {**fields, "acquisition": asdict(proven)}
        return RootRunSnapshot(**fields, snapshot_sha256=hashlib.sha256(ledger.canonical(digest_fields)).hexdigest())
    except Exception:
        raise Denied("intake-archives-held") from None


def _directory_identity(fd):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, "intake-private-directory")
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode


def _entries(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    return set(os.listdir(fd))


def _write_at(directory, name, value):
    raw = ledger.canonical(value)
    require(len(raw) <= MAX_RECEIPT, "intake-receipt-size")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        data = memoryview(raw)
        while data:
            size = os.write(fd, data)
            require(size > 0, "intake-receipt-write")
            data = data[size:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)
    return hashlib.sha256(raw).hexdigest()


def _read_at(directory, name):
    fd = os.open(name, installation.FILE_FLAGS, dir_fd=directory)
    try:
        proof, raw, stamp = installation._hash_file(fd, name, MAX_RECEIPT, private=True, keep=True)
        value = identity.decode_json(raw)
        require(raw == ledger.canonical(value), "intake-receipt-canonical")
        return value, proof.sha256, stamp
    finally:
        os.close(fd)


def _binding(selected, request):
    domain = asdict(selected.identity)
    # Distinct Heavy/Application native job names can share exact acquired
    # bytes. Each reuse still authenticates its current exact job independently.
    domain.pop("required_native_job_name")
    domain["actor_ids"] = sorted(domain["actor_ids"])
    acquisition._hash(selected.custody_policy_sha256)
    return {"schema": 1, "identity_domain": domain, "custody_policy_sha256": selected.custody_policy_sha256,
            "source": asdict(request.source), "controller": asdict(request.controller),
            "artifact": asdict(request.artifact)}


def _job_binding(worker, who, selected):
    return {"worker_sha256": ledger.digest(asdict(worker)), "run_id": who.run_id,
            "job_id": who.job_id, "check_run_id": who.check_run_id,
            "native_job_name": selected.identity.required_native_job_name,
            "identity_policy_sha256": identity.policy_digest(selected.identity)}


def _proven(value):
    require(type(value) is dict and set(value) == set(acquisition.Acquisition.__dataclass_fields__),
            "intake-provenance-schema")
    commits = []
    for key in ("source", "controller"):
        row = value[key]
        require(type(row) is dict and set(row) == set(acquisition.CommitAcquisition.__dataclass_fields__)
                and type(row["files"]) is list and 0 < len(row["files"]) <= 20000
                and type(row["directories"]) is list and len(row["directories"]) <= 20000,
                "intake-provenance-schema")
        require(all(type(entry) is dict and set(entry) == set(acquisition.TreeEntry.__dataclass_fields__)
                    for entry in row["files"]), "intake-provenance-schema")
        commits.append(acquisition.CommitAcquisition(**{**row,
            "files": tuple(acquisition.TreeEntry(**entry) for entry in row["files"]),
            "directories": tuple(row["directories"])}))
    artifact = value["artifact"]
    require(type(artifact) is dict and set(artifact) == set(acquisition.ArtifactRequest.__dataclass_fields__),
            "intake-provenance-schema")
    return acquisition.Acquisition(*commits, acquisition.ArtifactRequest(**artifact),
        value["artifact_sha256"], value["artifact_size"], value["provenance_sha256"])


def _reuse(stage, binding, request, api_token, deadline):
    """Read-only complete-stage proof. Never complete or repair a partial."""
    require(_entries(stage) == INVENTORY, "intake-stage-incomplete")
    intent, intent_sha, intent_stamp = _read_at(stage, "intent.json")
    sealed, receipt_sha, receipt_stamp = _read_at(stage, "sealed.json")
    require(type(intent) is dict and set(intent) == {"schema", "binding", "original_job"}
            and type(intent["schema"]) is int and intent["schema"] == 1
            and intent["binding"] == binding and type(intent["original_job"]) is dict,
            "intake-original-intent")
    require(type(sealed) is dict and set(sealed) == {"schema", "binding", "intent_sha256", "snapshot", "archive_stamps"}
            and type(sealed["schema"]) is int and sealed["schema"] == 1
            and sealed["binding"] == binding and sealed["intent_sha256"] == intent_sha
            and type(sealed["snapshot"]) is dict
            and set(sealed["snapshot"]) == set(RootRunSnapshot.__dataclass_fields__), "intake-sealed-schema")
    proven = _proven(sealed["snapshot"]["acquisition"])
    require(proven.artifact == request.artifact and proven.artifact_sha256 == request.artifact.digest_sha256
            and proven.artifact_size == request.artifact.size_in_bytes, "intake-sealed-artifact")
    # Reacquire actual Git provenance, not a self-asserted receipt hash/OID list.
    for item, commit in zip((request.source, request.controller), (proven.source, proven.controller)):
        require((item.repository, item.repository_id, item.commit_sha)
                == (commit.repository, commit.repository_id, commit.commit_sha), "intake-sealed-source")
        require(acquisition._tree(item, request, None if item.repository == acquisition.VALIDATION else api_token, deadline)
                == (commit.tree_sha, commit.files, commit.directories), "intake-sealed-tree")
    native = acquisition._native(request, api_token, deadline)
    require(proven.provenance_sha256 == hashlib.sha256(repr(native).encode("ascii")).hexdigest(),
            "intake-sealed-native")
    fds = []
    try:
        for name in ARCHIVES:
            fds.append(os.open(name, installation.FILE_FLAGS, dir_fd=stage))
        stamps = {name: list(installation._stamp(os.fstat(fd))) for name, fd in zip(ARCHIVES, fds)}
        require(stamps == sealed["archive_stamps"], "intake-sealed-inodes")
        snapshot = _validate_archives(proven, **dict(zip(("artifact_fd", "source_fd", "controller_fd"), fds)))
        require(ledger.canonical(asdict(snapshot)) == ledger.canonical(sealed["snapshot"]), "intake-sealed-drift")
        require(_read_at(stage, "intent.json")[2] == intent_stamp
                and _read_at(stage, "sealed.json")[2] == receipt_stamp
                and _entries(stage) == INVENTORY, "intake-sealed-drift")
        return snapshot, receipt_sha
    finally:
        for fd in fds:
            os.close(fd)


def _sealed_state_unchanged(stage, expected_sha):
    # Native reauthentication performs IO after the full archive readback.
    # Recheck sealed file identities after that IO, before returning a locator.
    sealed, digest, _ = _read_at(stage, "sealed.json")
    require(digest == expected_sha and _entries(stage) == INVENTORY
            and _read_at(stage, "intent.json")[1] == sealed["intent_sha256"], "intake-sealed-final-drift")
    current = {name: list(installation._stamp(os.stat(name, dir_fd=stage, follow_symlinks=False)))
               for name in ARCHIVES}
    require(current == sealed["archive_stamps"], "intake-sealed-final-drift")


@identity._diagnostic_step("intake-stage")
def stage_run_snapshot(proof, connected_socket, selected, token, api_token):
    """Fresh native proof -> exclusive per-run stage or read-only exact reuse.

    ROOT is installed by Root delivery, never a caller path. Failed/partial
    directories remain held; this function never deletes, adopts, repairs,
    retries acquisition, publishes an anchor, or accepts an intake receipt as
    operating authority. The caller still derives private per-cell policies.
    """
    require(os.geteuid() == 0, "intake-root-required")
    root = stage = None
    fds = []
    try:
        worker, who, remaining = admission.require_intake_native(proof, connected_socket, selected, token, api_token)
        seconds = min(600, int(remaining))
        require(seconds > 0, "intake-auth-budget")
        deadline = time.monotonic() + seconds
        request = _native_request(selected, who, api_token, deadline, seconds)
        binding = _binding(selected, request)
        name = ledger.digest(binding)
        again = admission.require_intake_native(proof, connected_socket, selected, token, api_token)
        require(again[0] == worker and again[1] == who and time.monotonic() < deadline,
                "intake-stage-native-drift")
        root = installation._open_directory(ROOT)
        root_identity = _directory_identity(root)
        created = False
        try:
            os.mkdir(name, 0o700, dir_fd=root)
            os.fsync(root)
            created = True
        except FileExistsError:
            pass
        stage = os.open(name, installation.DIR_FLAGS, dir_fd=root)
        stage_identity = _directory_identity(stage)
        if created:
            intent_sha = _write_at(stage, "intent.json", {"schema": 1, "binding": binding,
                "original_job": _job_binding(worker, who, selected)})
            for filename in ARCHIVES:
                fd = os.open(filename, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=stage)
                os.fchmod(fd, 0o600)
                fds.append(fd)
            os.fsync(stage)
            snapshot = acquire_run_snapshot(proof, connected_socket, selected, token, api_token,
                **dict(zip(("artifact_fd", "source_fd", "controller_fd"), fds)))
            require(snapshot.acquisition.artifact == request.artifact
                    and snapshot.acquisition.source.commit_sha == request.source.commit_sha
                    and snapshot.acquisition.controller.commit_sha == request.controller.commit_sha,
                    "intake-stage-request-drift")
            require(_entries(stage) == INVENTORY - {"sealed.json"}, "intake-stage-inventory")
            stamps = {filename: list(installation._stamp(os.fstat(fd))) for filename, fd in zip(ARCHIVES, fds)}
            _write_at(stage, "sealed.json", {"schema": 1, "binding": binding, "intent_sha256": intent_sha,
                "snapshot": asdict(snapshot), "archive_stamps": stamps})
        # Newly sealed and reused snapshots pass the same full readback.
        snapshot, receipt_sha = _reuse(stage, binding, request, api_token, deadline)
        again = admission.require_intake_native(proof, connected_socket, selected, token, api_token)
        require(again[0] == worker and again[1] == who and time.monotonic() < deadline,
                "intake-stage-native-drift")
        _sealed_state_unchanged(stage, receipt_sha)
        check = installation._open_directory(ROOT)
        try:
            require(_directory_identity(check) == root_identity
                    and _directory_identity(stage) == stage_identity
                    and installation._stamp(os.stat(name, dir_fd=check, follow_symlinks=False))[:6]
                    == installation._stamp(os.fstat(stage))[:6], "intake-stage-directory-drift")
        finally:
            os.close(check)
        return SealedRunSnapshot(ROOT + "/" + name, stage_identity[0], stage_identity[1], receipt_sha, snapshot)
    except Exception as error:
        identity._diagnostic_failed("intake-stage", error)
        raise Denied("intake-stage-held") from None
    finally:
        for fd in fds:
            os.close(fd)
        if stage is not None:
            os.close(stage)
        if root is not None:
            os.close(root)
