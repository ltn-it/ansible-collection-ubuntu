"""Inert memory acquisition/real Root FD tests; no native job authority.

Only HTTPS IO is modeled. The existing acquisition fixture's credential file is
removed before calls, demonstrating that the new memory path needs no file.
The separate intake-ticket/native dispatcher integration is not modeled as PASS.
"""
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

import test_github_runner_incus_generation_acquisition as transport
import test_github_runner_incus_generation_publisher as archives

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import generation_acquisition as acquisition, identity, ledger, run_intake as intake
from incus_lease_issuer.identity import Denied


class MemoryBoundaryTests(unittest.TestCase):
    def test_nonroot_denies_before_io_or_metadata(self):
        with mock.patch.object(intake.os, "geteuid", return_value=501):
            for call in (lambda: intake._acquire_memory(None, "not-a-secret", artifact_fd=-1,
                                                       source_fd=-1, controller_fd=-1),
                         lambda: intake._validate_archives(None, artifact_fd=-1,
                                                           source_fd=-1, controller_fd=-1)):
                with self.assertRaisesRegex(Denied, "intake-root-required"):
                    call()

    def test_request_has_no_credential_path_url_or_reader(self):
        self.assertNotIn("credential_path", intake.MemoryRequest.__dataclass_fields__)
        self.assertNotIn("credential_sha256", intake.MemoryRequest.__dataclass_fields__)
        with self.assertRaises(TypeError):
            intake.MemoryRequest(reader=object())
        with self.assertRaises(TypeError):
            intake._acquire_memory(None, "not-a-secret", artifact_fd=-1, source_fd=-1,
                                   controller_fd=-1, url="https://foreign/")


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootMemoryTests(unittest.TestCase):
    def setUp(self):
        # Reuse the actual bounded HTTPS response fixture, not its test methods.
        self.fx = transport.RootGenerationAcquisitionTests(methodName="runTest")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.fx.credential.unlink()
        old = self.fx.request
        self.request = intake.MemoryRequest(old.source, old.controller, old.artifact,
            old.max_archive_bytes, old.max_tree_entries, old.max_file_bytes, old.total_timeout_seconds)
        self.token = self.fx.token.decode().strip()
        # Native repo reads established V is public; the explicit anonymous
        # controller policy must validate this field, never infer visibility.
        self.fx.json("/repos/" + acquisition.VALIDATION,
                     {"id": self.request.controller.repository_id, "full_name": acquisition.VALIDATION, "private": False})

    def acquire(self, request=None, **fd_changes):
        fds = dict(zip(("artifact_fd", "source_fd", "controller_fd"), self.fx.fds))
        fds.update(fd_changes)
        with mock.patch.object(acquisition.http.client, "HTTPSConnection", side_effect=self.fx.factory):
            return intake._acquire_memory(self.request if request is None else request, self.token, **fds)

    def test_same_memory_token_authenticated_native_download_and_no_tokenfile(self):
        result = self.acquire()
        self.assertEqual(result.artifact_sha256, hashlib.sha256(self.fx.artifact).hexdigest())
        self.assertEqual(result.source.commit_sha, self.request.source.commit_sha)
        self.assertFalse(self.fx.credential.exists())
        self.assertEqual({p.name for p in self.fx.root.iterdir()},
                         {"artifact.zip", "source.tar.gz", "controller.tar.gz"})
        for host, method, path, headers in self.fx.calls:
            self.assertEqual(method, "GET")
            authenticated_source = host == acquisition.API and path.startswith("/repos/" + acquisition.SUPPLEMENTARY)
            self.assertEqual(headers.get("Authorization"), "Bearer " + self.token if authenticated_source else None)
        self.assertNotIn(self.token, repr(result))

    def test_anonymous_controller_reader_requires_actual_public_identity_no_auth_fallback(self):
        self.fx.json("/repos/" + acquisition.VALIDATION,
                     {"id": self.request.controller.repository_id, "full_name": acquisition.VALIDATION, "private": True})
        with self.assertRaises(Denied):
            self.acquire()
        self.assertTrue(all("Authorization" not in headers for host, _, path, headers in self.fx.calls
                            if host == acquisition.API and path.startswith("/repos/" + acquisition.VALIDATION)))
        self.assertFalse(any("/actions/artifacts/" in path for _, _, path, _ in self.fx.calls))
        self.assertTrue(all(os.fstat(fd).st_size == 0 for fd in self.fx.fds))

    def test_wrong_source_workflow_attempt_and_modern_domain_deny_before_io(self):
        for item in (replace(self.request.artifact, run_attempt=2),
                     replace(self.request.artifact, workflow_id=214182491),
                     replace(self.request.artifact, head_sha="9" * 40),
                     acquisition.MainArtifactRequest(**asdict(self.request.artifact), request_id="9" * 64)):
            with self.subTest(item=type(item).__name__), self.assertRaises(Denied):
                self.acquire(replace(self.request, artifact=item))
        self.assertEqual(self.fx.calls, [])

    def test_fd_alias_and_nonempty_never_issue_http(self):
        with self.assertRaises(Denied):
            self.acquire(source_fd=self.fx.fds[0])
        os.write(self.fx.fds[0], b"prior unknown partial")
        with self.assertRaises(Denied):
            self.acquire()
        self.assertEqual(self.fx.calls, [])

    def test_artifact_digest_drift_retains_partial_without_retry(self):
        request = replace(self.request, artifact=replace(self.request.artifact, digest_sha256="0" * 64))
        self.fx.artifact_metadata["digest"] = "sha256:" + "0" * 64
        self.fx.json(self.fx.artifact_path, self.fx.artifact_metadata)
        with self.assertRaisesRegex(Denied, "^intake-acquisition-held$"):
            self.acquire(request)
        self.assertGreater(os.fstat(self.fx.fds[0]).st_size, 0)
        downloads = [p for h, _, p, _ in self.fx.calls if h == "productionresultssa1.blob.core.windows.net"]
        self.assertEqual(len(downloads), 1)
        with self.assertRaises(Denied):
            self.acquire(request)
        self.assertEqual(len([p for h, _, p, _ in self.fx.calls
                              if h == "productionresultssa1.blob.core.windows.net"]), 1)

    def test_native_drift_after_download_denies_and_redacts_transport_error(self):
        count = 0
        def drift(host, method, path):
            nonlocal count
            if host == acquisition.API and path == self.fx.run_path:
                count += 1
                if count == 2:
                    raise RuntimeError(self.token + " signed-query-and-private-body")
        self.fx.callback = drift
        with self.assertRaisesRegex(Denied, "^intake-acquisition-held$") as caught:
            self.acquire()
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn(self.token, str(caught.exception))
        self.assertTrue(all(os.fstat(fd).st_size > 0 for fd in self.fx.fds))

    def valid_archives(self):
        source = {"galaxy.yml": b"version: 1.2.3\n", "README.md": b"inert source"}
        controller = {".github/actions/run-quality-profile/" + name: (name + " inert").encode()
                      for name in intake.publisher.engine.CONTROLLER_FILES}
        source_raw, source_proof = archives.git_input(acquisition.SUPPLEMENTARY, 1103407173, "a" * 40, source)
        controller_raw, controller_proof = archives.git_input(acquisition.VALIDATION, 1269461997, "b" * 40, controller)
        candidate, _ = archives.candidate_zip({"README.md": source["README.md"]})
        for fd, raw in zip(self.fx.fds, (candidate, source_raw, controller_raw)):
            os.write(fd, raw)
            os.fsync(fd)
        artifact = replace(self.request.artifact, digest_sha256=archives.digest(candidate), size_in_bytes=len(candidate))
        proof = acquisition.Acquisition(source_proof, controller_proof, artifact,
            archives.digest(candidate), len(candidate), "c" * 64)
        return proof

    def validate(self, proof):
        return intake._validate_archives(proof, **dict(zip(("artifact_fd", "source_fd", "controller_fd"), self.fx.fds)))

    def test_real_archives_git_blobs_inner_checks_and_controller_inventory(self):
        proof = self.valid_archives()
        offsets = [os.lseek(fd, 0, os.SEEK_CUR) for fd in self.fx.fds]
        result = self.validate(proof)
        self.assertIs(type(result), intake.RootRunSnapshot)
        self.assertEqual(result.acquisition, proof)
        self.assertEqual(set(dict(result.controller_files)), intake.publisher.engine.CONTROLLER_FILES)
        self.assertEqual(len(result.snapshot_sha256), 64)
        self.assertEqual([os.lseek(fd, 0, os.SEEK_CUR) for fd in self.fx.fds], offsets)
        self.assertEqual(self.validate(proof), result)
        self.assertFalse(hasattr(result, "qualified"))

    def test_corruption_mode_and_forged_git_oid_denied(self):
        proof = self.valid_archives()
        bad_entry = replace(proof.source.files[0], oid="0" * 40)
        with self.assertRaises(Denied):
            self.validate(replace(proof, source=replace(proof.source, files=(bad_entry,) + proof.source.files[1:])))
        os.fchmod(self.fx.fds[1], 0o644)
        with self.assertRaises(Denied):
            self.validate(proof)
        os.fchmod(self.fx.fds[1], 0o600)
        os.pwrite(self.fx.fds[0], b"X", 0)
        with self.assertRaises(Denied):
            self.validate(proof)

    def test_parsing_time_file_change_denied_even_when_bytes_restored(self):
        proof = self.valid_archives()
        original = intake.publisher._candidate
        def change(raw, workspace):
            answer = original(raw, workspace)
            os.fchmod(self.fx.fds[1], 0o640)
            os.fchmod(self.fx.fds[1], 0o600)
            return answer
        with mock.patch.object(intake.publisher, "_candidate", side_effect=change):
            with self.assertRaisesRegex(Denied, "^intake-archives-held$"):
                self.validate(proof)

    def native_policy(self):
        native = SimpleNamespace(repository=acquisition.SUPPLEMENTARY, repository_id=1103407173,
            workflow_id=214182490, workflow_path=".github/workflows/collection-ci.yml",
            caller_sha=self.request.source.commit_sha, reusable_repository=acquisition.VALIDATION,
            reusable_path=".github/workflows/collection-quality-profile-isolated.yml",
            reusable_sha=self.request.controller.commit_sha)
        who = SimpleNamespace(run_id=501, caller_sha=native.caller_sha, reusable_sha=native.reusable_sha)
        self.fx.json("/repos/" + native.repository + "/branches/main",
                     {"name": "main", "protected": True, "commit": {"sha": native.caller_sha}})
        self.fx.json("/repos/" + native.reusable_repository + "/branches/main",
                     {"name": "main", "protected": True, "commit": {"sha": native.reusable_sha}})
        self.fx.json("/repos/" + native.reusable_repository + "/compare/" + native.reusable_sha + "..." + native.reusable_sha,
                     {"status": "identical", "base_commit": {"sha": native.reusable_sha},
                      "merge_base_commit": {"sha": native.reusable_sha}})
        self.inventory_path = "/repos/" + native.repository + "/actions/runs/501/artifacts?per_page=100&page=1"
        self.fx.json(self.inventory_path, {"total_count": 1, "artifacts": [self.fx.artifact_metadata]})
        return SimpleNamespace(identity=native), who

    def derive(self, selected, who):
        with mock.patch.object(acquisition.http.client, "HTTPSConnection", side_effect=self.fx.factory):
            return intake._native_request(selected, who, self.token, intake.time.monotonic() + 30, 29)

    def test_actual_native_inventory_derives_request_no_job_artifact_arguments(self):
        selected, who = self.native_policy()
        result = self.derive(selected, who)
        self.assertEqual(result.source, self.request.source)
        self.assertEqual(result.controller, self.request.controller)
        self.assertEqual(result.artifact, self.request.artifact)
        self.assertEqual(result.total_timeout_seconds, 29)
        self.assertFalse(self.fx.credential.exists())

    def test_main_advance_unpublished_controller_duplicate_or_incomplete_inventory_deny(self):
        selected, who = self.native_policy()
        self.fx.json("/repos/" + acquisition.SUPPLEMENTARY + "/branches/main",
                     {"name": "main", "protected": True, "commit": {"sha": "8" * 40}})
        with self.assertRaises(Denied):
            self.derive(selected, who)
        selected, who = self.native_policy()
        prefix = "/repos/" + acquisition.VALIDATION + "/compare/" + selected.identity.reusable_sha
        self.fx.json(prefix + "..." + selected.identity.reusable_sha, {"status": "diverged"})
        with self.assertRaises(Denied):
            self.derive(selected, who)
        for inventory in ({"total_count": 2, "artifacts": [self.fx.artifact_metadata]},
                          {"total_count": 2, "artifacts": [self.fx.artifact_metadata] * 2},
                          {"total_count": 1, "artifacts": [{**self.fx.artifact_metadata, "expired": True}]}):
            selected, who = self.native_policy()
            self.fx.json(self.inventory_path, inventory)
            with self.subTest(inventory=inventory["total_count"]), self.assertRaises(Denied):
                self.derive(selected, who)
        self.assertFalse(any(path.endswith("/zip") for _, _, path, _ in self.fx.calls))

    def test_public_entry_rejects_opaque_ticket_before_discovery_or_fd_effect(self):
        # Models only the approved fixed native-validator rejection. It never
        # mints a successful ticket or calls a native server/assignment reader.
        with mock.patch.object(intake.admission, "require_intake_native", create=True,
                               side_effect=Denied("native ticket rejected")) as guard:
            with self.assertRaisesRegex(Denied, "^intake-snapshot-held$"):
                intake.acquire_run_snapshot(object(), object(), object(), "fake-oidc", self.token,
                    **dict(zip(("artifact_fd", "source_fd", "controller_fd"), self.fx.fds)))
        self.assertEqual(guard.call_count, 1)
        self.assertEqual(self.fx.calls, [])
        self.assertTrue(all(os.fstat(fd).st_size == 0 for fd in self.fx.fds))

    def test_auth_expiry_after_download_never_reaches_archive_seal(self):
        # Ticket/metadata/download are modeled to isolate this lifecycle guard;
        # actual native proof issuance belongs to the owner's admission tests.
        selected, who = self.native_policy()
        answers = [(object(), who, 60)]
        answers.append(answers[0])
        answers.append(Denied("original JWT expired"))
        with mock.patch.object(intake.admission, "require_intake_native", create=True, side_effect=answers), \
             mock.patch.object(intake, "_native_request", return_value=self.request), \
             mock.patch.object(intake, "_acquire_memory", return_value=object()) as download, \
             mock.patch.object(intake, "_validate_archives") as seal:
            with self.assertRaisesRegex(Denied, "^intake-snapshot-held$"):
                intake.acquire_run_snapshot(object(), object(), selected, "fake-oidc", self.token,
                    **dict(zip(("artifact_fd", "source_fd", "controller_fd"), self.fx.fds)))
        self.assertEqual(download.call_count, 1)
        self.assertIsNotNone(download.call_args.kwargs["_absolute_deadline"])
        seal.assert_not_called()


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootStageTests(unittest.TestCase):
    """Real durable files/archive checks; only HTTPS/native ticket modeled."""

    def setUp(self):
        self.helper = RootMemoryTests(methodName="runTest")
        self.helper.setUp()
        self.addCleanup(self.helper.doCleanups)
        self.fx = self.helper.fx
        candidate, _ = archives.candidate_zip(self.fx.source_files)
        self.fx.artifact = candidate
        self.fx.artifact_metadata.update(digest="sha256:" + archives.digest(candidate), size_in_bytes=len(candidate))
        self.fx.json(self.fx.artifact_path, self.fx.artifact_metadata)
        self.fx.routes[("productionresultssa1.blob.core.windows.net", "/actions-results/fixture?sig=fake-SAS-secret")] = (
            200, candidate, {})
        self.selected, _ = self.helper.native_policy()
        native = self.selected.identity
        self.selected.identity = identity.Policy(native.repository, native.repository_id, 762301,
            native.caller_sha, native.workflow_id, native.workflow_path, native.reusable_repository,
            native.reusable_path, native.reusable_sha, 78, "incus-runner-01", 996,
            frozenset({76040632, 247824904}),
            "repo:ltn-it/ansible-collection-supplementary:environment:heavy-isolated-pilot",
            required_native_job_name="Heavy exact fixture")
        self.selected.custody_policy_sha256 = "d" * 64
        self.worker = ledger.Worker(996, 78, 451, 986, "11111111-2222-3333-4444-555555555555")
        self.who = identity.Identity(501, 551, 651, 78, 996, native.caller_sha, native.reusable_sha,
            int(intake.time.time()) + 300, "e" * 64, ledger.AUDIENCE + "f" * 64,
            identity.policy_digest(self.selected.identity))
        self.root = self.fx.root / "sealed-runs"
        self.root.mkdir(mode=0o700)
        self.patch = mock.patch.object(intake, "ROOT", str(self.root))
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.native_calls = 0

    def ticket(self, *args):
        self.native_calls += 1
        return self.worker, self.who, 240

    def stage(self, ticket=None):
        with mock.patch.object(intake.admission, "require_intake_native", create=True,
                               side_effect=self.ticket if ticket is None else ticket), \
             mock.patch.object(acquisition.http.client, "HTTPSConnection", side_effect=self.fx.factory):
            return intake.stage_run_snapshot(object(), object(), self.selected, "fake-oidc", self.helper.token)

    def downloads(self):
        return len([path for host, _, path, _ in self.fx.calls
                    if host == "productionresultssa1.blob.core.windows.net"])

    def stamps(self, directory):
        return {path.name: intake.installation._stamp(path.stat()) for path in Path(directory).iterdir()}

    def test_exclusive_stage_full_readback_and_readonly_same_run_reuse(self):
        result = self.stage()
        self.assertEqual(set(path.name for path in Path(result.directory).iterdir()), intake.INVENTORY)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in Path(result.directory).iterdir()))
        before = self.stamps(result.directory)
        self.assertEqual(self.downloads(), 1)
        reused = self.stage()
        self.assertEqual(reused, result)
        self.assertEqual(self.downloads(), 1)
        self.assertEqual(self.stamps(result.directory), before)
        self.assertGreater(self.native_calls, 6)
        self.assertFalse(self.fx.credential.exists())

    def test_different_current_matrix_job_reuses_bytes_preserves_original_job(self):
        first = self.stage()
        original = Path(first.directory, "intent.json").read_bytes()
        self.selected.identity = replace(self.selected.identity, required_native_job_name="Acceptance exact fixture")
        self.worker = replace(self.worker, pid=453, start_ticks=990)
        self.who = replace(self.who, job_id=552, check_run_id=652,
                           policy_sha256=identity.policy_digest(self.selected.identity))
        self.assertEqual(self.stage(), first)
        self.assertEqual(Path(first.directory, "intent.json").read_bytes(), original)
        self.assertEqual(json.loads(original)["original_job"]["job_id"], 551)
        self.assertEqual(self.downloads(), 1)

    def test_partial_original_intent_holds_without_second_acquisition_or_repair(self):
        with mock.patch.object(intake, "acquire_run_snapshot", side_effect=Denied("possible partial")) as acquire:
            with self.assertRaisesRegex(Denied, "^intake-stage-held$"):
                self.stage()
            path = next(self.root.iterdir())
            before = self.stamps(path)
            with self.assertRaisesRegex(Denied, "^intake-stage-held$"):
                self.stage()
            self.assertEqual(acquire.call_count, 1)
        self.assertEqual(self.stamps(path), before)
        self.assertEqual(set(before), intake.INVENTORY - {"sealed.json"})
        self.assertEqual(self.downloads(), 0)

    def test_same_bytes_replaced_inode_cannot_be_adopted_or_redownloaded(self):
        result = self.stage()
        target = Path(result.directory, "source.tar.gz")
        data = target.read_bytes()
        original = target.stat().st_ino
        saved = self.fx.root / "original-archive"
        target.rename(saved)
        target.write_bytes(data)
        target.chmod(0o600)
        self.assertNotEqual(target.stat().st_ino, original)
        with self.assertRaisesRegex(Denied, "^intake-stage-held$"):
            self.stage()
        self.assertEqual(target.read_bytes(), data)
        self.assertTrue(saved.exists())
        self.assertEqual(self.downloads(), 1)

    def test_foreign_entry_symlink_permissive_archive_and_intent_drift_hold(self):
        result = self.stage()
        directory = Path(result.directory)
        extra = directory / "foreign"
        extra.write_bytes(b"do not delete")
        with self.assertRaises(Denied):
            self.stage()
        self.assertEqual(extra.read_bytes(), b"do not delete")
        extra.unlink()
        target = directory / "controller.tar.gz"
        saved = self.fx.root / "original-controller"
        target.rename(saved)
        target.symlink_to(saved)
        with self.assertRaises(Denied):
            self.stage()
        self.assertTrue(target.is_symlink())
        target.unlink()
        saved.rename(target)
        target.chmod(0o644)
        with self.assertRaises(Denied):
            self.stage()
        target.chmod(0o600)
        intent = directory / "intent.json"
        content = json.loads(intent.read_bytes())
        content["original_job"]["job_id"] = 559
        intent.write_bytes(ledger.canonical(content))
        with self.assertRaises(Denied):
            self.stage()
        self.assertEqual(json.loads(intent.read_bytes())["original_job"]["job_id"], 559)
        self.assertEqual(self.downloads(), 1)

    def test_borrowed_run_and_foreign_base_denied_before_new_files(self):
        first = self.stage()
        self.who = replace(self.who, run_id=502)
        with self.assertRaises(Denied):
            self.stage()
        self.assertEqual(list(self.root.iterdir()), [Path(first.directory)])
        self.who = replace(self.who, run_id=501)
        self.root.chmod(0o755)
        with self.assertRaises(Denied):
            self.stage()
        self.assertEqual(self.downloads(), 1)

    def test_expired_initial_ticket_cannot_allocate_stage(self):
        def expired(*args):
            raise Denied("expired")
        with self.assertRaisesRegex(Denied, "^intake-stage-held$"):
            self.stage(ticket=expired)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(self.downloads(), 0)

    def test_archive_change_during_final_native_readback_denies_locator(self):
        def mutate_after_seal(*args):
            for directory in self.root.iterdir():
                if (directory / "sealed.json").exists():
                    with (directory / "artifact.zip").open("r+b") as stream:
                        stream.write(b"X")
            return self.ticket(*args)
        with self.assertRaisesRegex(Denied, "^intake-stage-held$"):
            self.stage(ticket=mutate_after_seal)
        directory = next(self.root.iterdir())
        self.assertEqual((directory / "artifact.zip").read_bytes()[:1], b"X")
        self.assertTrue((directory / "sealed.json").is_file())
        self.assertEqual(self.downloads(), 1)
