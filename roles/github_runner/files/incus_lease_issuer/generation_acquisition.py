"""Root-only finite GitHub acquisition, never a job/network/activation handler.

The sealer constructs these frozen requests from its private hash-bound Root
request, creates O_EXCL archive files, and retains unknown/partial acquisition
files on failure. This component never extracts or executes candidate code.
Git blob OIDs/modes/sizes, not unrelated SHA lists, bind later archive extraction
in the Root sealer. GitHub commit verification here means authenticated exact
API provenance, not an independent signature or workflow/admission acceptance.

Primary contracts: docs.github.com/en/rest/actions/artifacts;
/rest/git/trees; /rest/git/commits; /rest/repos/contents;
/en/actions/reference/runners/github-hosted-runners (artifact network origins).
"""
from dataclasses import dataclass
import fcntl
import hashlib
import http.client
import os
from pathlib import PurePosixPath
import re
import ssl
import stat
import time
from urllib.parse import urlsplit

from . import installation
from .identity import Denied, decode_json, require

API = "api.github.com"
REPOSITORIES = {"ltn-it/ansible-collection-supplementary": 1103407173,
                "ltn-it/modulix-validation": 1269461997}
SUPPLEMENTARY = "ltn-it/ansible-collection-supplementary"
VALIDATION = "ltn-it/modulix-validation"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_JSON = 8 * 1024 * 1024
MAX_ARCHIVE = 2 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class CommitRequest:
    repository: str
    repository_id: int
    commit_sha: str


@dataclass(frozen=True)
class ArtifactRequest:
    run_id: int
    run_attempt: int
    head_sha: str
    workflow_id: int
    workflow_path: str
    artifact_id: int
    name: str
    digest_sha256: str
    size_in_bytes: int


@dataclass(frozen=True)
class MainArtifactRequest(ArtifactRequest):
    """The Nexus-readback artifact of one fixed Validation Main dispatch."""
    request_id: str


@dataclass(frozen=True)
class AcquisitionRequest:
    source: CommitRequest
    controller: CommitRequest
    artifact: ArtifactRequest | MainArtifactRequest
    credential_path: str
    credential_sha256: str
    max_archive_bytes: int
    max_tree_entries: int
    max_file_bytes: int
    total_timeout_seconds: int


@dataclass(frozen=True)
class TreeEntry:
    path: str
    mode: str
    oid: str
    size: int


@dataclass(frozen=True)
class CommitAcquisition:
    repository: str
    repository_id: int
    commit_sha: str
    tree_sha: str
    files: tuple[TreeEntry, ...]
    directories: tuple[str, ...]
    archive_sha256: str
    archive_size: int


@dataclass(frozen=True)
class Acquisition:
    source: CommitAcquisition
    controller: CommitAcquisition
    artifact: ArtifactRequest | MainArtifactRequest
    artifact_sha256: str
    artifact_size: int
    provenance_sha256: str


def _positive(value, maximum=2**63-1):
    require(type(value) is int and 0 < value <= maximum, "acquisition-integer")


def _hash(value, pattern=HEX64):
    require(type(value) is str and pattern.fullmatch(value), "acquisition-digest")


def _relative(value):
    require(type(value) is str and 0 < len(value) <= 1024
            and re.fullmatch(r"[A-Za-z0-9_./@-]+", value) and not value.startswith("/")
            and value != "." and str(PurePosixPath(value)) == value
            and ".." not in PurePosixPath(value).parts and len(PurePosixPath(value).parts) <= 32,
            "acquisition-tree-path")
    return value


def _validate(request):
    require(type(request) is AcquisitionRequest, "acquisition-request")
    for item, repository in ((request.source, SUPPLEMENTARY), (request.controller, VALIDATION)):
        require(type(item) is CommitRequest and item.repository == repository
                and type(item.repository_id) is int and item.repository_id == REPOSITORIES[repository], "acquisition-repository")
        _hash(item.commit_sha, HEX40)
    item = request.artifact
    require(type(item) in (ArtifactRequest, MainArtifactRequest)
            and type(item.run_attempt) is int and item.run_attempt == 1, "acquisition-artifact-request")
    _hash(item.head_sha, HEX40)
    for value in (item.run_id, item.workflow_id, item.artifact_id, item.size_in_bytes):
        _positive(value)
    if type(item) is MainArtifactRequest:
        _hash(item.request_id)
        require(item.name == "mlx90-candidate-" + item.request_id
                and item.workflow_path == ".github/workflows/mlx90-collection-candidate-validation.yml",
                "acquisition-main-artifact")
    else:
        require(item.head_sha == request.source.commit_sha, "acquisition-artifact-request")
        require(type(item.name) is str and item.name == "collection-candidate-" + item.head_sha,
                "acquisition-artifact-name")
        require(item.workflow_path == ".github/workflows/collection-ci.yml", "acquisition-workflow")
    _hash(item.digest_sha256)
    _hash(request.credential_sha256)
    installation._absolute(request.credential_path)
    _positive(request.max_archive_bytes, MAX_ARCHIVE)
    _positive(request.max_tree_entries, 20000)
    _positive(request.max_file_bytes, 512 * 1024 * 1024)
    _positive(request.total_timeout_seconds, 900)
    require(item.size_in_bytes <= request.max_archive_bytes, "acquisition-artifact-size")


def _remaining(deadline):
    remaining = deadline-time.monotonic()
    require(remaining > 0, "acquisition-deadline")
    return remaining


class _HTTP:
    """No proxy, cookie jar, automatic redirect, retry, or environment auth."""
    def __init__(self, url, bearer, deadline):
        parsed = urlsplit(url)
        require(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
                and parsed.port is None and not parsed.fragment, "acquisition-origin")
        require((bearer is not None and parsed.hostname == API)
                or (bearer is None and ((parsed.hostname == API and
                    (parsed.path == "/repos/" + VALIDATION or parsed.path.startswith("/repos/" + VALIDATION + "/")))
                    or parsed.hostname in {"codeload.github.com", "results-receiver.actions.githubusercontent.com"}
                    or re.fullmatch(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", parsed.hostname))), "acquisition-origin")
        self.connection = http.client.HTTPSConnection(parsed.hostname, timeout=min(10, _remaining(deadline)),
                                                     context=ssl.create_default_context())
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "lit-root-generation/1", "Connection": "close"}
        if bearer is not None:
            require(parsed.hostname == API and parsed.path.startswith("/repos/"), "acquisition-credential-origin")
            headers.update(Authorization="Bearer "+bearer, **{"X-GitHub-Api-Version": "2022-11-28"})
        try:
            self.connection.request("GET", parsed.path + ("?"+parsed.query if parsed.query else ""), headers=headers)
            self.socket = self.connection.sock
            require(self.socket is not None, "acquisition-transport")
            self.response = self.connection.getresponse()
        except BaseException:
            self.connection.close()
            raise
        self.deadline = deadline

    def read(self, count):
        self.socket.settimeout(min(10, _remaining(self.deadline)))
        raw = self.response.read(count)
        _remaining(self.deadline)
        return raw

    def close(self):
        try:
            if hasattr(self, "response"):
                self.response.close()
        finally:
            self.connection.close()


def _request(url, bearer, deadline):
    # Private transport seam for credential-free tests, never a public reader.
    return _HTTP(url, bearer, deadline)


def _json(path, token, deadline):
    response = _request("https://"+API+path, token, deadline)
    try:
        require(response.response.status == 200, "acquisition-api-status")
        chunks, total = [], 0
        while True:
            raw = response.read(min(65536, MAX_JSON+1-total))
            if not raw:
                break
            chunks.append(raw)
            total += len(raw)
            require(total <= MAX_JSON, "acquisition-json-limit")
        return decode_json(b"".join(chunks))
    finally:
        response.close()


def _redirect(path, token, deadline, *, archive=False):
    response = _request("https://"+API+path, token, deadline)
    try:
        require(response.response.status == 302, "acquisition-redirect-status")
        locations = response.response.headers.get_all("Location", [])
        require(len(locations) == 1 and type(locations[0]) is str and len(locations[0]) <= 16384
                and not any(ord(c) <= 32 or ord(c) == 127 for c in locations[0]), "acquisition-location")
        parsed = urlsplit(locations[0])
        require(parsed.scheme == "https" and parsed.hostname and parsed.netloc == parsed.hostname
                and not parsed.fragment and parsed.path.startswith("/") and "\\" not in locations[0], "acquisition-origin")
        if archive:
            require(parsed.hostname == "codeload.github.com", "acquisition-archive-origin")
        else:
            require(parsed.hostname == "results-receiver.actions.githubusercontent.com"
                    or re.fullmatch(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", parsed.hostname),
                    "acquisition-artifact-origin")
        return locations[0]
    finally:
        response.close()


def _fd(fd):
    require(type(fd) is int and fd >= 0, "acquisition-fd")
    value = os.fstat(fd)
    require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1
            and stat.S_IMODE(value.st_mode) == 0o600 and value.st_size == 0 and os.lseek(fd, 0, os.SEEK_CUR) == 0,
            "acquisition-fd")
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    require(flags & os.O_ACCMODE == os.O_RDWR and not flags & os.O_APPEND, "acquisition-fd")
    return value.st_dev, value.st_ino


def _download(url, fd, token, deadline, limit, *, digest=None, size=None):
    before = _fd(fd)
    response = _request(url, token, deadline)
    try:
        require(response.response.status == 200, "acquisition-download-status")
        encoding = response.response.headers.get("Content-Encoding")
        require(encoding in (None, "identity"), "acquisition-content-encoding")
        lengths = response.response.headers.get_all("Content-Length", [])
        require(len(lengths) <= 1, "acquisition-content-length")
        declared = None
        if lengths:
            require(re.fullmatch(r"[1-9][0-9]*", lengths[0]), "acquisition-content-length")
            declared = int(lengths[0])
            require(declared <= limit and (size is None or declared == size), "acquisition-content-length")
        total, hasher = 0, hashlib.sha256()
        while True:
            raw = response.read(min(65536, limit+1-total))
            if not raw:
                break
            total += len(raw)
            require(total <= limit, "acquisition-archive-limit")
            hasher.update(raw)
            view = memoryview(raw)
            while view:
                _remaining(deadline)
                written = os.write(fd, view)
                require(written > 0, "acquisition-write")
                view = view[written:]
        require(total > 0 and (declared is None or total == declared) and (size is None or total == size), "acquisition-download-size")
        actual = hasher.hexdigest()
        require(digest is None or actual == digest, "acquisition-download-digest")
        os.fsync(fd)
        after = os.fstat(fd)
        require((after.st_dev, after.st_ino) == before and stat.S_ISREG(after.st_mode)
                and after.st_uid == 0 and after.st_nlink == 1 and stat.S_IMODE(after.st_mode) == 0o600
                and after.st_size == total and os.lseek(fd, 0, os.SEEK_CUR) == total, "acquisition-fd-drift")
        return actual, total
    finally:
        response.close()


def _repository(item, token, deadline):
    value = _json("/repos/"+item.repository, token, deadline)
    require(value.get("id") == item.repository_id and type(value.get("id")) is int
            and value.get("full_name") == item.repository, "acquisition-repository-mismatch")
    if token is None:
        require(item.repository == VALIDATION and value.get("private") is False, "acquisition-public-controller-only")


def _tree(item, request, token, deadline):
    prefix = "/repos/"+item.repository
    commit = _json(prefix+"/git/commits/"+item.commit_sha, token, deadline)
    require(commit.get("sha") == item.commit_sha and type(commit.get("tree")) is dict, "acquisition-commit")
    tree_sha = commit["tree"].get("sha")
    _hash(tree_sha, HEX40)
    tree = _json(prefix+"/git/trees/"+tree_sha+"?recursive=1", token, deadline)
    require(tree.get("sha") == tree_sha and tree.get("truncated") is False
            and type(tree.get("tree")) is list and 0 < len(tree["tree"]) <= request.max_tree_entries, "acquisition-tree")
    files, directories, seen, total = [], [], set(), 0
    for entry in tree["tree"]:
        require(type(entry) is dict, "acquisition-tree-entry")
        path = _relative(entry.get("path"))
        require(path not in seen, "acquisition-tree-duplicate")
        seen.add(path)
        oid, mode, kind = entry.get("sha"), entry.get("mode"), entry.get("type")
        _hash(oid, HEX40)
        if mode == "040000" and kind == "tree":
            directories.append(path)
        else:
            require(mode in {"100644", "100755"} and kind == "blob" and type(entry.get("size")) is int
                    and 0 <= entry["size"] <= request.max_file_bytes, "acquisition-tree-type")
            total += entry["size"]
            require(total <= MAX_ARCHIVE, "acquisition-tree-total")
            files.append(TreeEntry(path, mode, oid, entry["size"]))
    require(files and all(str(PurePosixPath(path).parent) == "." or str(PurePosixPath(path).parent) in directories
                          for path in seen), "acquisition-tree-parent")
    return tree_sha, tuple(sorted(files, key=lambda entry: entry.path)), tuple(sorted(directories))


def _artifact_repository(item):
    require(type(item) in (ArtifactRequest, MainArtifactRequest), "acquisition-artifact-request")
    return VALIDATION if type(item) is MainArtifactRequest else SUPPLEMENTARY


def _main_readback(prefix, item, token, deadline):
    """Complete attempt-one job inventory; never follow response URLs."""
    jobs, total = [], None
    for page in range(1, 12):
        result = _json(prefix + "/actions/runs/" + str(item.run_id)
            + "/attempts/1/jobs?per_page=100&page=" + str(page), token, deadline)
        require(type(result.get("total_count")) is int and 0 < result["total_count"] <= 1000
                and type(result.get("jobs")) is list and len(result["jobs"]) <= 100,
                "acquisition-main-jobs")
        if total is None:
            total = result["total_count"]
        require(total == result["total_count"] and all(type(job) is dict for job in result["jobs"]),
                "acquisition-main-jobs")
        jobs.extend(result["jobs"])
        require(len(jobs) <= total, "acquisition-main-jobs")
        if len(result["jobs"]) < 100:
            break
    require(len(jobs) == total and all(type(job.get("id")) is int and job["id"] > 0 for job in jobs)
            and len({job["id"] for job in jobs}) == total, "acquisition-main-jobs")
    found = [job for job in jobs if job.get("name") == "Nexus exact-byte readback"]
    require(len(found) == 1, "acquisition-main-readback")
    job = found[0]
    require(type(job.get("run_id")) is int and job["run_id"] == item.run_id
            and job.get("head_sha") == item.head_sha and job.get("status") == "completed"
            and job.get("conclusion") == "success", "acquisition-main-readback")
    return job["id"]


def _native(request, token, deadline):
    item = request.artifact
    repository = _artifact_repository(item)
    modern = type(item) is MainArtifactRequest
    prefix = "/repos/" + repository
    run = _json(prefix+"/actions/runs/"+str(item.run_id), token, deadline)
    attempt = _json(prefix+"/actions/runs/"+str(item.run_id)+"/attempts/1", token, deadline)
    for value in (run, attempt):
        require(type(value.get("id")) is int and value["id"] == item.run_id
                and type(value.get("run_attempt")) is int and value["run_attempt"] == 1
                and value.get("head_sha") == item.head_sha
                and value.get("event") == ("workflow_dispatch" if modern else "push")
                and value.get("head_branch") == "main" and value.get("status") == "in_progress"
                and value.get("conclusion") is None and type(value.get("workflow_id")) is int
                and value["workflow_id"] == item.workflow_id and value.get("path") == item.workflow_path
                and type(value.get("repository")) is dict
                and type(value["repository"].get("id")) is int and value["repository"]["id"] == REPOSITORIES[repository]
                and value["repository"].get("full_name") == repository, "acquisition-native-run")
        if modern:
            require(value.get("display_title") == "MLX-90 collection candidate / " + item.request_id
                    and type(value.get("head_repository")) is dict
                    and type(value["head_repository"].get("id")) is int
                    and value["head_repository"]["id"] == REPOSITORIES[VALIDATION], "acquisition-main-run")
            for name in ("actor", "triggering_actor"):
                actor = value.get(name)
                require(type(actor) is dict and type(actor.get("id")) is int and actor["id"] == 307565056
                        and actor.get("login") == "lightning-it-release-automation[bot]"
                        and actor.get("type") == "Bot", "acquisition-main-actor")
    readback = None
    if modern:
        branch = _json(prefix + "/branches/main", token, deadline)
        require(branch.get("name") == "main" and branch.get("protected") is True
                and type(branch.get("commit")) is dict and branch["commit"].get("sha") == item.head_sha,
                "acquisition-main-protected-caller")
        readback = _main_readback(prefix, item, token, deadline)
    artifact = _json(prefix+"/actions/artifacts/"+str(item.artifact_id), token, deadline)
    native = artifact.get("workflow_run")
    require(type(native) is dict and type(native.get("id")) is int and native["id"] == item.run_id
            and type(native.get("repository_id")) is int and native["repository_id"] == REPOSITORIES[repository]
            and type(native.get("head_repository_id")) is int and native["head_repository_id"] == REPOSITORIES[repository]
            and native.get("head_sha") == item.head_sha and native.get("head_branch") == "main"
            and type(artifact.get("id")) is int and artifact["id"] == item.artifact_id
            and artifact.get("name") == item.name and artifact.get("expired") is False
            and artifact.get("digest") == "sha256:"+item.digest_sha256
            and type(artifact.get("size_in_bytes")) is int and artifact["size_in_bytes"] == item.size_in_bytes,
            "acquisition-native-artifact")
    # Compare only required provenance; mutable timestamps/counters are not policy.
    binding = (item.run_id, item.run_attempt, item.head_sha, item.workflow_id, item.workflow_path,
               item.artifact_id, item.name, item.digest_sha256, item.size_in_bytes)
    return binding + (item.request_id, readback) if modern else binding


def acquire(request, *, artifact_fd, source_fd, controller_fd):
    """Acquire into three Root-created exclusive files; failure retains partials.

    No reader/URL/credential value/job policy may be supplied. The sealer must
    subsequently verify ZIP inner checksums and tar members against these Git
    blob OIDs, including source build exclusions. This result does not conflate
    artifact ZIP, candidate Galaxy tar, runtime bundle or controller tar hashes.
    """
    require(os.geteuid() == 0, "acquisition-root-required")
    try:
        _validate(request)
        deadline = time.monotonic()+request.total_timeout_seconds
        stamps = [_fd(fd) for fd in (artifact_fd, source_fd, controller_fd)]
        require(len(set(stamps)) == 3, "acquisition-fd-alias")
        proof, raw, credential_stamp = installation._file(request.credential_path, 16384, private=True, keep=True)
        require(proof.sha256 == request.credential_sha256, "acquisition-credential-drift")
        token = raw.decode("ascii").removesuffix("\n")
        require(0 < len(token) <= 16384 and not any(ord(c) <= 32 or ord(c) == 127 for c in token), "acquisition-credential")
        for item in (request.source, request.controller):
            _repository(item, token, deadline)
        native = _native(request, token, deadline)
        trees = [_tree(item, request, token, deadline) for item in (request.source, request.controller)]
        location = _redirect("/repos/"+_artifact_repository(request.artifact)+"/actions/artifacts/"
                             +str(request.artifact.artifact_id)+"/zip", token, deadline)
        artifact_sha, artifact_size = _download(location, artifact_fd, None, deadline, request.max_archive_bytes,
            digest=request.artifact.digest_sha256, size=request.artifact.size_in_bytes)
        commits = []
        for item, fd, tree in zip((request.source, request.controller), (source_fd, controller_fd), trees):
            location = _redirect("/repos/"+item.repository+"/tarball/"+item.commit_sha, token, deadline, archive=True)
            sha, size = _download(location, fd, None, deadline, request.max_archive_bytes)
            commits.append(CommitAcquisition(item.repository, item.repository_id, item.commit_sha, *tree, sha, size))
        require(_native(request, token, deadline) == native, "acquisition-native-drift")
        credential_after, _, stamp_after = installation._file(request.credential_path, 16384, private=True)
        require(credential_after == proof and stamp_after == credential_stamp, "acquisition-credential-drift")
        for fd, original, size in zip((artifact_fd, source_fd, controller_fd), stamps,
                                     (artifact_size, commits[0].archive_size, commits[1].archive_size)):
            current = os.fstat(fd)
            require((current.st_dev, current.st_ino) == original and stat.S_ISREG(current.st_mode)
                    and current.st_uid == 0 and current.st_nlink == 1 and stat.S_IMODE(current.st_mode) == 0o600
                    and current.st_size == size and os.lseek(fd, 0, os.SEEK_CUR) == size, "acquisition-fd-drift")
        _remaining(deadline)
        provenance = hashlib.sha256(repr(native).encode("ascii")).hexdigest()
        return Acquisition(*commits, request.artifact, artifact_sha, artifact_size, provenance)
    except Exception:
        # Never expose bearer, signed redirect URL/query, full API/error body,
        # path or HTTP exception text, and never retry a possibly read object.
        raise Denied("acquisition-held") from None
