"""Credential-free Root/private-file and actual fixed-request transport tests.

Only HTTPSConnection IO is modeled; no GitHub call, token mint, candidate code
execution or archive extraction happens. Fixture keys/blobs are synthetic.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from email.message import Message
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import ssl
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import generation_acquisition as acquisition  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()


def tar(files):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as archive:
        for path, contents in files.items():
            entry = tarfile.TarInfo("source-prefix/"+path)
            entry.mode, entry.size = 0o644, len(contents)
            archive.addfile(entry, io.BytesIO(contents))
    return raw.getvalue()


class GuardTests(unittest.TestCase):
    def test_root_guard_and_no_public_reader_or_url_override(self):
        with mock.patch.object(acquisition.os, "geteuid", return_value=2101):
            with self.assertRaisesRegex(Denied, "acquisition-root-required"):
                acquisition.acquire(None, artifact_fd=None, source_fd=None, controller_fd=None)
        with self.assertRaises(TypeError):
            acquisition.acquire(None, artifact_fd=None, source_fd=None, controller_fd=None, reader=object())
        with self.assertRaises(TypeError):
            acquisition.acquire(None, artifact_fd=None, source_fd=None, controller_fd=None, url="https://foreign/")


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootGenerationAcquisitionTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires private Root0700 /run/proof tmpfs")
        self.temp = tempfile.TemporaryDirectory(dir=base, prefix="generation-acquisition-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.token = b"fake-component-token-only\n"
        self.credential = self.root / "read-token"
        self.credential.write_bytes(self.token)
        self.credential.chmod(0o600)
        self.fds = [os.open(self.root/name, os.O_CREAT|os.O_EXCL|os.O_RDWR, 0o600)
                    for name in ("artifact.zip", "source.tar.gz", "controller.tar.gz")]
        for fd in self.fds:
            self.addCleanup(os.close, fd)
        self.source_files = {"galaxy.yml": b"namespace: lit\nname: supplementary\nversion: 1.2.3\n",
                             "roles/example/templates/podman-kube@.service.j2": b"fixture\n"}
        self.controller_files = {".github/actions/run-quality-profile/"+name: (name+" fixture\n").encode()
                                for name in ("action.yml", "profile-steps.yml", "run-cell.py", "run-devtools.sh", "run-phase.sh")}
        candidate, runtime = b"synthetic collection tar", b"synthetic dependencies tar"
        checksums = (sha(candidate)+"  lit-supplementary-1.2.3.tar.gz\n"+
                     sha(runtime)+"  runtime-collections.tar.gz\n").encode()
        zipped = io.BytesIO()
        with zipfile.ZipFile(zipped, "w") as archive:
            archive.writestr("lit-supplementary-1.2.3.tar.gz", candidate)
            archive.writestr("runtime-collections.tar.gz", runtime)
            archive.writestr("candidate-SHA256SUMS", checksums)
        self.artifact = zipped.getvalue()
        self.source_tar, self.controller_tar = tar(self.source_files), tar(self.controller_files)
        source = acquisition.CommitRequest(acquisition.SUPPLEMENTARY, 1103407173, "a"*40)
        controller = acquisition.CommitRequest(acquisition.VALIDATION, 1269461997, "b"*40)
        artifact = acquisition.ArtifactRequest(501, 1, source.commit_sha, 214182490,
            ".github/workflows/collection-ci.yml", 601, "collection-candidate-"+source.commit_sha,
            sha(self.artifact), len(self.artifact))
        self.request = acquisition.AcquisitionRequest(source, controller, artifact,
            str(self.credential), sha(self.token), 1024*1024, 100, 1024*1024, 30)
        self.routes, self.calls, self.read_sizes, self.timeouts = {}, [], [], []
        for item, files, raw, tree_sha in ((source, self.source_files, self.source_tar, "c"*40),
                                          (controller, self.controller_files, self.controller_tar, "d"*40)):
            prefix = "/repos/"+item.repository
            self.json(prefix, {"id": item.repository_id, "full_name": item.repository})
            self.json(prefix+"/git/commits/"+item.commit_sha, {"sha": item.commit_sha, "tree": {"sha": tree_sha}})
            dirs = sorted({str(parent) for path in files for parent in Path(path).parents if parent != Path(".")})
            entries = [{"path": path, "mode": "040000", "type": "tree", "sha": "e"*40} for path in dirs]
            entries += [{"path": path, "mode": "100644", "type": "blob", "sha": blob(contents), "size": len(contents)}
                        for path, contents in files.items()]
            self.json(prefix+"/git/trees/"+tree_sha+"?recursive=1", {"sha": tree_sha, "truncated": False, "tree": entries})
            redirect = "https://codeload.github.com/"+item.repository+"/legacy.tar.gz/"+item.commit_sha
            self.redirect(prefix+"/tarball/"+item.commit_sha, redirect)
            self.routes[("codeload.github.com", "/"+item.repository+"/legacy.tar.gz/"+item.commit_sha)] = (200, raw, {})
        prefix = "/repos/"+source.repository
        self.run_path = prefix+"/actions/runs/501"
        self.run = {"id": 501, "run_attempt": 1, "head_sha": source.commit_sha, "event": "push", "head_branch": "main",
                    "workflow_id": 214182490, "path": artifact.workflow_path, "status": "in_progress", "conclusion": None,
                    "repository": {"id": 1103407173, "full_name": source.repository}}
        self.json(self.run_path, self.run)
        self.json(self.run_path+"/attempts/1", self.run)
        self.artifact_path = prefix+"/actions/artifacts/601"
        self.artifact_metadata = {"id": 601, "name": artifact.name, "expired": False, "digest": "sha256:"+sha(self.artifact),
            "size_in_bytes": len(self.artifact), "workflow_run": {"id": 501, "repository_id": 1103407173,
                "head_repository_id": 1103407173, "head_sha": source.commit_sha, "head_branch": "main"}}
        self.json(self.artifact_path, self.artifact_metadata)
        self.location = "https://productionresultssa1.blob.core.windows.net/actions-results/fixture?sig=fake-SAS-secret"
        self.redirect(self.artifact_path+"/zip", self.location)
        self.routes[("productionresultssa1.blob.core.windows.net", "/actions-results/fixture?sig=fake-SAS-secret")] = (200, self.artifact, {})
        self.callback = None

    def json(self, path, value):
        self.routes[(acquisition.API, path)] = (200, json.dumps(value).encode(), {})

    def redirect(self, path, location, status=302):
        self.routes[(acquisition.API, path)] = (status, b"never read redirect body", {"Location": location})

    def factory(self, host, *, timeout, context):
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        owner = self
        class Connection:
            def __init__(self):
                self.sock = mock.Mock()
                self.sock.settimeout.side_effect = owner.timeouts.append
                self.closed = False
            def request(self, method, path, *, headers):
                owner.calls.append((host, method, path, dict(headers)))
                if owner.callback:
                    owner.callback(host, method, path)
                self.spec = owner.routes[(host, path)]
            def getresponse(self):
                status, body, headers = self.spec
                class Response:
                    def __init__(self):
                        self.status, self.headers, self.stream = status, Message(), io.BytesIO(body)
                        self.length = None
                        for key, value in headers.items():
                            self.headers[key] = value
                    def isclosed(self):
                        return self.stream.closed
                    def read(self, count):
                        owner.read_sizes.append(count)
                        raw = self.stream.read(count)
                        if not raw:
                            self.stream.close()
                        return raw
                    def close(self):
                        self.stream.close()
                return Response()
            def close(self):
                self.closed = True
        return Connection()

    def acquire(self, request=None, **fds):
        values = dict(zip(("artifact_fd", "source_fd", "controller_fd"), self.fds))
        values.update(fds)
        with mock.patch.object(acquisition.http.client, "HTTPSConnection", side_effect=self.factory):
            return acquisition.acquire(self.request if request is None else request, **values)

    def main_fixture(self):
        item = acquisition.MainArtifactRequest(701, 1, "f"*40, 914,
            ".github/workflows/mlx90-collection-candidate-validation.yml", 601,
            "mlx90-candidate-"+"9"*64, sha(self.artifact), len(self.artifact), "9"*64)
        self.request = replace(self.request, artifact=item)
        prefix = "/repos/"+acquisition.VALIDATION
        self.run_path = prefix+"/actions/runs/701"
        actor = {"id": 307565056, "login": "lightning-it-release-automation[bot]", "type": "Bot"}
        self.run = {"id": 701, "run_attempt": 1, "head_sha": item.head_sha,
            "event": "workflow_dispatch", "head_branch": "main", "workflow_id": item.workflow_id,
            "path": item.workflow_path, "status": "in_progress", "conclusion": None,
            "repository": {"id": 1269461997, "full_name": acquisition.VALIDATION},
            "head_repository": {"id": 1269461997}, "actor": actor, "triggering_actor": actor,
            "display_title": "MLX-90 collection candidate / "+item.request_id}
        self.json(self.run_path, self.run)
        self.json(self.run_path+"/attempts/1", self.run)
        self.json(prefix+"/branches/main", {"name": "main", "protected": True, "commit": {"sha": item.head_sha}})
        self.jobs_path = self.run_path+"/attempts/1/jobs?per_page=100&page=1"
        self.jobs = {"total_count": 1, "jobs": [{"id": 950, "run_id": 701, "head_sha": item.head_sha,
            "name": "Nexus exact-byte readback", "status": "completed", "conclusion": "success"}]}
        self.json(self.jobs_path, self.jobs)
        self.artifact_path = prefix+"/actions/artifacts/601"
        self.artifact_metadata = {"id": 601, "name": item.name, "expired": False,
            "digest": "sha256:"+sha(self.artifact), "size_in_bytes": len(self.artifact),
            "workflow_run": {"id": 701, "repository_id": 1269461997, "head_repository_id": 1269461997,
                "head_sha": item.head_sha, "head_branch": "main"}}
        self.json(self.artifact_path, self.artifact_metadata)
        self.redirect(self.artifact_path+"/zip", self.location)

    def test_main_nexus_artifact_uses_independent_consumer_sha_and_exact_endpoint(self):
        self.main_fixture()
        result = self.acquire()
        self.assertIs(type(result.artifact), acquisition.MainArtifactRequest)
        self.assertNotEqual(result.artifact.head_sha, result.source.commit_sha)
        self.assertNotEqual(result.artifact.head_sha, result.controller.commit_sha)
        self.assertEqual(result.artifact.name, "mlx90-candidate-"+"9"*64)
        self.assertEqual(result.artifact_sha256, sha(self.artifact))
        self.assertEqual(sum(path == self.jobs_path for _, _, path, _ in self.calls), 2)
        self.assertFalse(any("/repos/"+acquisition.SUPPLEMENTARY+"/actions/" in path
                             for _, _, path, _ in self.calls))

    def test_main_human_rerun_fork_request_or_unprotected_caller_denies_before_download(self):
        self.main_fixture()
        cases = ({"run_attempt": 2}, {"head_repository": {"id": 1103407173}},
            {"event": "push"}, {"head_branch": "develop"},
            {"display_title": "MLX-90 collection candidate / "+"8"*64},
            {"actor": {"id": 76040632, "login": "litroc", "type": "User"}},
            {"triggering_actor": {"id": 76040632, "login": "litroc", "type": "User"}})
        for changes in cases:
            self.json(self.run_path, {**self.run, **changes})
            with self.subTest(changes=changes), self.assertRaises(Denied):
                self.acquire()
        self.json(self.run_path, self.run)
        for changes in ({"protected": False}, {"commit": {"sha": self.request.source.commit_sha}}):
            self.json("/repos/"+acquisition.VALIDATION+"/branches/main",
                {"name": "main", "protected": True, "commit": {"sha": self.request.artifact.head_sha}, **changes})
            with self.subTest(branch=changes), self.assertRaises(Denied):
                self.acquire()
        self.assertFalse(any(path.endswith("/zip") for _, _, path, _ in self.calls))

    def test_main_requires_one_successful_same_run_readback_and_complete_jobs(self):
        self.main_fixture()
        job = self.jobs["jobs"][0]
        for changes in ({"status": "in_progress"}, {"conclusion": "failure"},
                        {"conclusion": "skipped"}, {"run_id": 501}, {"head_sha": "a"*40},
                        {"name": "Other readback"}):
            self.json(self.jobs_path, {"total_count": 1, "jobs": [{**job, **changes}]})
            with self.subTest(job=changes), self.assertRaises(Denied):
                self.acquire()
        for jobs in ({"total_count": 2, "jobs": [job]},
                     {"total_count": 2, "jobs": [job, {**job, "id": 951}]},
                     {"total_count": 2, "jobs": [job, job]}):
            self.json(self.jobs_path, jobs)
            with self.subTest(jobs=jobs), self.assertRaises(Denied):
                self.acquire()
        self.assertFalse(any(path.endswith("/zip") for _, _, path, _ in self.calls))

    def test_main_readback_on_second_page_is_found_without_trusting_response_urls(self):
        self.main_fixture()
        others = [{"id": 1000+i, "name": "Other job "+str(i)} for i in range(100)]
        self.json(self.jobs_path, {"total_count": 101, "jobs": others})
        second = self.jobs_path.removesuffix("page=1")+"page=2"
        self.json(second, {"total_count": 101, "jobs": self.jobs["jobs"]})
        result = self.acquire()
        self.assertEqual(result.artifact.run_id, 701)
        self.assertEqual(sum(path == second for _, _, path, _ in self.calls), 2)

    def test_main_pagination_count_drift_denies_before_artifact_download(self):
        self.main_fixture()
        others = [{"id": 1000+i, "name": "Other job "+str(i)} for i in range(100)]
        self.json(self.jobs_path, {"total_count": 101, "jobs": others})
        self.json(self.jobs_path.removesuffix("page=1")+"page=2",
                  {"total_count": 102, "jobs": self.jobs["jobs"]})
        with self.assertRaises(Denied):
            self.acquire()
        self.assertFalse(any(path.endswith("/zip") for _, _, path, _ in self.calls))

    def test_main_artifact_expiry_or_producer_repository_cannot_substitute_readback(self):
        self.main_fixture()
        for changes in ({"expired": True}, {"digest": "sha256:"+"0"*64},
            {"workflow_run": {**self.artifact_metadata["workflow_run"], "repository_id": 1103407173}},
            {"workflow_run": {**self.artifact_metadata["workflow_run"], "id": 501}}):
            self.json(self.artifact_path, {**self.artifact_metadata, **changes})
            with self.subTest(changes=changes), self.assertRaises(Denied):
                self.acquire()
        self.assertFalse(any(path.endswith("/zip") for _, _, path, _ in self.calls))

    def test_main_readback_drift_after_download_retains_bytes_but_denies_acquisition(self):
        self.main_fixture()
        def drift(host, method, path):
            if host == "codeload.github.com":
                self.json(self.jobs_path, {"total_count": 1,
                    "jobs": [{**self.jobs["jobs"][0], "id": 951}]})
        self.callback = drift
        with self.assertRaisesRegex(Denied, "^acquisition-held$"):
            self.acquire()
        self.assertEqual(os.pread(self.fds[0], len(self.artifact), 0), self.artifact)

    def test_real_streamed_archives_and_frozen_git_blob_inventory_are_separate_proofs(self):
        result = self.acquire()
        self.assertEqual((result.artifact_sha256, result.artifact_size), (sha(self.artifact), len(self.artifact)))
        self.assertEqual(result.source.archive_sha256, sha(self.source_tar))
        self.assertEqual(result.controller.archive_sha256, sha(self.controller_tar))
        self.assertEqual({entry.path: entry.oid for entry in result.source.files},
                         {path: blob(raw) for path, raw in self.source_files.items()})
        self.assertTrue(all(entry.mode == "100644" and type(entry.size) is int for entry in result.source.files))
        for fd, expected in zip(self.fds, (self.artifact, self.source_tar, self.controller_tar)):
            self.assertEqual(os.pread(fd, len(expected)+1, 0), expected)
        with self.assertRaises(FrozenInstanceError):
            result.source.tree_sha = "f"*40
        self.assertTrue(self.read_sizes and max(self.read_sizes) <= 65536)
        self.assertTrue(all(0 < value <= 10 for value in self.timeouts))
        # Two exact fresh reads, never mutable artifact-name lookup or pagination.
        self.assertEqual(sum(host == acquisition.API and path == self.run_path for host, _, path, _ in self.calls), 2)
        self.assertEqual(sum(path == self.artifact_path for _, _, path, _ in self.calls), 2)

    def test_authorization_only_on_fixed_api_never_redirect_cookie_or_query_leak(self):
        self.acquire()
        for host, method, path, headers in self.calls:
            self.assertEqual(method, "GET")
            self.assertNotIn("Cookie", headers)
            if host == acquisition.API:
                self.assertEqual(headers["Authorization"], "Bearer fake-component-token-only")
                self.assertTrue(path.startswith("/repos/ltn-it/"))
                self.assertEqual(headers["X-GitHub-Api-Version"], "2022-11-28")
            else:
                self.assertNotIn("Authorization", headers)
                self.assertNotIn("X-GitHub-Api-Version", headers)
        self.assertEqual(sum(path == self.artifact_path+"/zip" for _, _, path, _ in self.calls), 1)

    def test_missing_or_wrong_private_credential_fails_before_network(self):
        for change in (replace(self.request, credential_sha256="0"*64),
                       replace(self.request, credential_path=str(self.root/"missing"))):
            with self.assertRaisesRegex(Denied, "^acquisition-held$"):
                self.acquire(change)
        self.credential.chmod(0o644)
        with self.assertRaises(Denied):
            self.acquire()
        self.assertEqual(self.calls, [])

    def test_closed_request_repo_ids_attempt_sha_workflow_and_artifact_name(self):
        variants = [replace(self.request, source=replace(self.request.source, repository_id=1269461997)),
                    replace(self.request, controller=replace(self.request.controller, repository=acquisition.SUPPLEMENTARY)),
                    replace(self.request, artifact=replace(self.request.artifact, run_attempt=2)),
                    replace(self.request, artifact=replace(self.request.artifact, head_sha="0"*40)),
                    replace(self.request, artifact=replace(self.request.artifact, name="candidate")),
                    replace(self.request, artifact=replace(self.request.artifact, workflow_path=".github/workflows/other.yml"))]
        for request in variants:
            with self.subTest(request=request), self.assertRaises(Denied):
                self.acquire(request)
        self.assertEqual(self.calls, [])

    def test_native_mismatch_fails_before_archive_request(self):
        for field, value in (("run_attempt", 2), ("head_sha", "0"*40), ("workflow_id", 55),
                             ("repository", {"id": 1269461997, "full_name": acquisition.VALIDATION}),
                             ("event", "pull_request"), ("status", "completed"), ("head_branch", "develop")):
            self.json(self.run_path, {**self.run, field: value})
            with self.subTest(field=field), self.assertRaises(Denied):
                self.acquire()
        self.assertFalse(any(path.endswith("/zip") for _, _, path, _ in self.calls))

    def test_artifact_expiry_head_digest_size_or_foreign_run_never_downloads(self):
        for changes in ({"expired": True}, {"digest": None}, {"digest": "sha256:"+"0"*64},
                        {"size_in_bytes": len(self.artifact)+1}, {"id": 602},
                        {"workflow_run": {**self.artifact_metadata["workflow_run"], "id": 502}}):
            self.json(self.artifact_path, {**self.artifact_metadata, **changes})
            with self.subTest(changes=changes), self.assertRaises(Denied):
                self.acquire()
        self.assertFalse(any(path.endswith("/zip") for _, _, path, _ in self.calls))

    def test_recursive_tree_truncation_links_submodules_duplicate_and_missing_parent_deny(self):
        path = "/repos/"+acquisition.SUPPLEMENTARY+"/git/trees/"+"c"*40+"?recursive=1"
        original = json.loads(self.routes[(acquisition.API, path)][1])
        variants = [{**original, "truncated": True}, {**original, "sha": "0"*40}]
        for mode, kind in (("120000", "blob"), ("160000", "commit")):
            value = deepcopy(original)
            value["tree"][-1].update(mode=mode, type=kind)
            variants.append(value)
        variants += [{**original, "tree": [*original["tree"], original["tree"][-1]]},
                     {**original, "tree": [row for row in original["tree"] if row["type"] != "tree"]}]
        for value in variants:
            self.json(path, value)
            with self.assertRaises(Denied):
                self.acquire()
        self.assertFalse(any(path.endswith("/zip") for _, _, path, _ in self.calls))

    def test_artifact_redirect_origin_userinfo_port_scheme_and_second_redirect_hold_without_leak(self):
        for location in ("http://productionresultssa1.blob.core.windows.net/x", "https://foreign.example/x",
                         "https://productionresultssa1.blob.core.windows.net.evil/x", "https://user@codeload.github.com/x",
                         "https://productionresultssa1.blob.core.windows.net:443/x", "https://codeload.github.com/x",
                         "https://productionresultssa1.blob.core.windows.net/x#fragment"):
            self.redirect(self.artifact_path+"/zip", location)
            with self.subTest(location=location), self.assertRaisesRegex(Denied, "^acquisition-held$") as caught:
                self.acquire()
            self.assertNotIn("fake-SAS-secret", str(caught.exception))
        self.redirect(self.artifact_path+"/zip", self.location)
        key = ("productionresultssa1.blob.core.windows.net", "/actions-results/fixture?sig=fake-SAS-secret")
        self.routes[key] = (302, b"secret body", {"Location": "https://foreign.example/"})
        with self.assertRaises(Denied):
            self.acquire()
        self.assertFalse(any(host == "foreign.example" for host, *_ in self.calls))

    def test_archive_hash_mismatch_retains_partial_no_retry_and_redacts_error(self):
        key = ("productionresultssa1.blob.core.windows.net", "/actions-results/fixture?sig=fake-SAS-secret")
        self.routes[key] = (200, b"X"*len(self.artifact), {})
        with self.assertRaisesRegex(Denied, "^acquisition-held$"):
            self.acquire()
        self.assertEqual(os.fstat(self.fds[0]).st_size, len(self.artifact))
        before = len(self.calls)
        with self.assertRaises(Denied):
            self.acquire()
        self.assertEqual(len(self.calls), before)

    def test_expiry_reread_after_download_denies_without_replaying_effects(self):
        counts = {"artifact": 0}
        def callback(host, method, path):
            if host == acquisition.API and path == self.artifact_path:
                counts["artifact"] += 1
                if counts["artifact"] == 2:
                    self.json(path, {**self.artifact_metadata, "expired": True})
        self.callback = callback
        with self.assertRaises(Denied):
            self.acquire()
        self.assertTrue(all(os.fstat(fd).st_size > 0 for fd in self.fds))
        self.assertEqual(sum(path.endswith("/zip") for _, _, path, _ in self.calls), 1)

    def test_fds_must_be_distinct_private_empty_single_link_regular_and_not_append(self):
        with self.assertRaises(Denied):
            self.acquire(controller_fd=self.fds[0])
        os.fchmod(self.fds[0], 0o644)
        with self.assertRaises(Denied):
            self.acquire()
        os.fchmod(self.fds[0], 0o600)
        link = self.root / "hardlinked-output"
        os.link(self.root/"artifact.zip", link)
        with self.assertRaises(Denied):
            self.acquire()
        link.unlink()
        flags = fcntl.fcntl(self.fds[0], fcntl.F_GETFL)
        fcntl.fcntl(self.fds[0], fcntl.F_SETFL, flags|os.O_APPEND)
        with self.assertRaises(Denied):
            self.acquire()
        fcntl.fcntl(self.fds[0], fcntl.F_SETFL, flags)
        os.write(self.fds[0], b"existing")
        with self.assertRaises(Denied):
            self.acquire()
        self.assertEqual(self.calls, [])

    def test_body_and_tree_bounds_are_finite_and_http_errors_have_no_body_leak(self):
        self.routes[(acquisition.API, "/repos/"+acquisition.SUPPLEMENTARY)] = (403, b"secret body fake-component-token-only", {})
        with self.assertRaisesRegex(Denied, "^acquisition-held$"):
            self.acquire()
        self.assertEqual(self.read_sizes, [])
        self.calls.clear()
        with self.assertRaises(Denied):
            self.acquire(replace(self.request, total_timeout_seconds=901))
        self.assertEqual(self.calls, [])

    def test_total_deadline_covers_metadata_not_just_archive_socket_reads(self):
        clock = {"now": 100.0}
        def callback(host, method, path):
            clock["now"] = 131.0
        self.callback = callback
        with mock.patch.object(acquisition.time, "monotonic", side_effect=lambda: clock["now"]):
            with self.assertRaisesRegex(Denied, "^acquisition-held$"):
                self.acquire()
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(all(os.fstat(fd).st_size == 0 for fd in self.fds))

    def test_final_private_credential_and_archive_inode_metadata_are_rechecked(self):
        counts = {"run": 0}
        def callback(host, method, path):
            if host == acquisition.API and path == self.run_path:
                counts["run"] += 1
                if counts["run"] == 2:
                    self.credential.chmod(0o644)
        self.callback = callback
        with self.assertRaises(Denied):
            self.acquire()
        self.assertTrue(all(os.fstat(fd).st_size > 0 for fd in self.fds))

    def test_source_archive_redirect_is_exact_codeload_and_has_no_token(self):
        source_path = "/repos/"+acquisition.SUPPLEMENTARY+"/tarball/"+self.request.source.commit_sha
        self.redirect(source_path, "https://productionresultssa1.blob.core.windows.net/not-source")
        with self.assertRaisesRegex(Denied, "^acquisition-held$"):
            self.acquire()
        self.assertEqual(sum(host == "productionresultssa1.blob.core.windows.net" for host, *_ in self.calls), 1)
        self.assertEqual(os.fstat(self.fds[1]).st_size, 0)

    def test_archive_stream_size_and_content_length_are_not_trusted_as_checksums(self):
        key = ("productionresultssa1.blob.core.windows.net", "/actions-results/fixture?sig=fake-SAS-secret")
        self.routes[key] = (200, self.artifact, {"Content-Length": str(len(self.artifact)+1)})
        with self.assertRaises(Denied):
            self.acquire()
        self.assertEqual(os.fstat(self.fds[0]).st_size, 0)

    def test_complete_tree_limits_reject_before_archive_download(self):
        with self.assertRaises(Denied):
            self.acquire(replace(self.request, max_tree_entries=1))
        with self.assertRaises(Denied):
            self.acquire(replace(self.request, max_file_bytes=1))
        self.assertFalse(any(path.endswith("/zip") for _, _, path, _ in self.calls))


if __name__ == "__main__":
    unittest.main()
