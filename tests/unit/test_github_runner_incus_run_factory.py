"""Real Root files/ledger/socket/RS256; native Worker/HTTPS snapshots modeled.

Synthetic keys and public fixtures only. These tests never prove native running
code, accepted custody, source publication, capacity, or operating activation.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import unittest
from unittest import mock

import test_github_runner_incus_identity as crypto
from test_github_runner_incus_flow import FixtureReader

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import collector, identity, ledger, policy_registry, run_factory as factory
from incus_lease_issuer.identity import Denied


class BoundaryTests(unittest.TestCase):
    def test_root_only_before_policy_or_token_read(self):
        with mock.patch.object(factory.os, "geteuid", return_value=501):
            for call in (lambda: factory.load_bootstrap("/not-read", "a" * 64),
                         lambda: factory.verify_bootstrap_native(None, None, "x", "x", "x", "x")):
                with self.assertRaisesRegex(Denied, "run-factory-root-required"): call()


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        crypto.CurrentJobIdentityTests.setUpClass()

    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("private Root0700 /run/proof required")
        self.temp = tempfile.TemporaryDirectory(dir=base, prefix="run-factory-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store_path = self.root / "ledger"; self.store_path.mkdir(mode=0o700)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(factory.time, "time", return_value=crypto.NOW).start()
        ledger.Ledger.initialize(self.store_path, clock=factory.time.time)
        with ledger.Ledger(self.store_path, clock=factory.time.time) as store:
            custody = store.archive_policy({"custodian_ref": "fixture:owner", "storage_ref": "fixture:storage",
                "approval_ref": "fixture:not-native-acceptance", "retention_seconds": 14400, "max_lease_seconds": 5400})
        self.native = crypto.CurrentJobIdentityTests(); self.native.setUp()
        base_identity = asdict(self.native.policy)
        base_identity.pop("caller_sha"); base_identity.pop("required_native_job_name", None)
        base_identity["actor_ids"] = [76040632, 247824904]
        base_identity["reusable_path"] = ".github/workflows/collection-quality-profile-isolated.yml"
        self.native.claims["job_workflow_ref"] = base_identity["reusable_repository"] + "/" + base_identity["reusable_path"] + "@" + crypto.REUSABLE_SHA
        self.native.run["referenced_workflows"] = [{"path": self.native.claims["job_workflow_ref"], "sha": crypto.REUSABLE_SHA, "ref": crypto.REUSABLE_SHA}]
        self.job_name = "heavy / example_heavy / ubuntu-24.04"
        self.native.job.update(name=self.job_name, started_at=dt.datetime.fromtimestamp(crypto.NOW - 30, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.worker = ledger.Worker(2101, 61, 23456, 777, "12345678-1234-4234-8234-123456789abc")
        self.profile = self.root / "profile"; self.profile.write_bytes(b"inert confinement fixture"); self.profile.chmod(0o600)
        self.collect_config = self.root / "collector.json"; self.collect_config.write_bytes(b"inert Root collector descriptor"); self.collect_config.chmod(0o600)
        self.workflow = b"public fixed Source workflow contract fixture"
        collected = {"service": {"unit": "actions.runner.fixture.service", "service_user": "fixture_runner",
            "installation": {"root": str(self.root / "runner"), "manifest_path": str(self.root / "runner-manifest.json"),
                "runner_id": 61, "service_uid": 2101, "runner_version": "2.338.2"},
            "fragment_path": str(self.root / "runner.service"), "fragment_sha256": "a" * 64, "dropins": []},
            "profile_name": "lit-gh-fixture-0123456789abcdef", "profile_path": str(self.profile),
            "profile_sha256": hashlib.sha256(self.profile.read_bytes()).hexdigest(), "config_path": str(self.collect_config),
            "config_sha256": hashlib.sha256(self.collect_config.read_bytes()).hexdigest()}
        self.selector = policy_registry.profile_selector("heavy", "example_heavy", "ubuntu-24.04")
        template = {"kind": "business", "native_job_name": self.job_name,
            "native_observer_job_name": "Final quality / heavy / example_heavy / ubuntu-24.04",
            "lease_seconds": 1200, "job_timeout_seconds": 1800, "github": {"job": "heavy", "workflow": "CI"},
            "matrix": {"profile": "heavy", "scenario": "example_heavy", "target": "ubuntu-24.04"},
            "engine": {"inert_template": True}, "incus": {"inert_template": True}}
        prep = {key: str(self.root / key) for key in factory.PREPARATION_KEYS}
        for key in factory.PREPARATION_KEYS:
            if key.endswith("sha256") or key == "signing_public_key_hex": prep[key] = "a" * 64
        prep["operation_wait_seconds"] = 5
        self.value = {"schema": 1, "source_identity": base_identity,
            "source_workflow_sha256": hashlib.sha256(self.workflow).hexdigest(), "collector": collected,
            "ledger_path": str(self.store_path), "custody_policy_sha256": custody,
            "controller": {"repository": factory.VALIDATION, "repository_id": 1269461997,
                "reusable_path": base_identity["reusable_path"], "reusable_sha": base_identity["reusable_sha"]},
            "preparation": prep, "runtime": {"authentication_timeout_seconds": 30, "initial_transition_timeout_seconds": 60,
                "heartbeat_lead_seconds": 30, "cleanup_timeout_seconds": 600, "capture": {"fixture": True}},
            "capacity": {"schema": 1, "pool_total_bytes": 32 * 1024 ** 3, "pool_reserve_bytes": 1024 ** 3,
                "engine_total_bytes": 17 * 1024 ** 3, "engine_reserve_bytes": 512 * 1024 ** 2,
                "cold_engine_bytes": 8 * 1024 ** 3, "pool_accounting": "owned-dir-retained-v1",
                "pool_quota_policy_path": str(self.root / "pool-quota.json"), "pool_quota_policy_sha256": "a" * 64},
            "cells": {self.selector: template}}
        self.path = self.root / "bootstrap.json"
        self.seal()
        self.server, self.client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.server.close); self.addCleanup(self.client.close)
        self.collected = mock.patch.object(collector, "collect_worker", return_value=self.worker).start()
        reader = FixtureReader(self.native)
        def read(url, *, bearer=None):
            prefix = identity.API + "/repos/" + crypto.REPOSITORY
            dynamic = {prefix + "/actions/runs/" + str(self.native.run["id"]): self.native.run,
                prefix + "/actions/runs/" + str(self.native.run["id"]) + "/attempts/1/jobs?per_page=100&page=1": self.native.jobs,
                prefix + "/actions/jobs/" + str(self.native.job["id"]): self.native.job,
                prefix + "/branches/main": {"name": "main", "protected": True, "commit": {"sha": self.native.run["head_sha"]}}}
            if url in dynamic: return ledger.canonical(deepcopy(dynamic[url]))
            if url == prefix + "/contents/.github/workflows/collection-ci.yml?ref=" + self.native.claims["sha"]:
                return ledger.canonical({"type": "file", "path": ".github/workflows/collection-ci.yml", "encoding": "base64",
                    "content": base64.b64encode(self.workflow).decode(), "size": len(self.workflow), "sha": "e" * 40})
            if url == prefix + "/git/commits/" + self.native.claims["sha"]:
                return ledger.canonical({"sha": self.native.claims["sha"], "parents": [{"sha": factory.operating_cells.INITIAL_MAIN}]})
            return reader.read(url, bearer=bearer)
        mock.patch.object(identity, "HTTPSReader", return_value=type("Reader", (), {"read": staticmethod(read)})()).start()

    def seal(self):
        self.path.write_bytes(ledger.canonical(self.value)); self.path.chmod(0o600)
        self.sha = ledger.digest(self.value)
        self.bootstrap = factory.load_bootstrap(str(self.path), self.sha)

    def mint(self):
        challenge = factory.challenge_bootstrap(self.server, self.bootstrap, self.selector)
        self.native.claims["aud"] = challenge["audience"]
        token = self.native.token()
        proof = factory.verify_bootstrap_native(self.server, self.bootstrap, self.selector,
            challenge["nonce"], token, "synthetic-job-token")
        return proof, token

    def test_real_signature_socket_nonce_ledger_and_opaque_proof_without_fake_cell(self):
        proof, token = self.mint()
        self.assertEqual(proof.identity.job_id, 902)
        self.assertEqual(proof.policy.identity.caller_sha, crypto.CALLER_SHA)
        self.assertFalse(hasattr(proof.policy, "cell_config_path"))
        worker, who, remaining = factory.require_bootstrap_native(proof, self.server, proof.policy, token, "synthetic-job-token")
        self.assertEqual(worker, self.worker)
        self.assertEqual(who, proof.identity)
        self.assertTrue(0 < remaining < 300)
        self.assertNotIn(token, repr(proof))
        with ledger.Ledger(self.store_path, clock=factory.time.time) as store:
            with store._transaction() as state: self.assertEqual(state["leases"], {})

    def test_unverified_sha_locator_or_forged_dataclass_is_not_authority(self):
        selected = factory.derive_selection(self.bootstrap, self.selector, "9" * 40)
        self.assertEqual(selected.identity.caller_sha, "9" * 40)
        proof, token = self.mint()
        forged = replace(proof)
        for invalid, connected in ((forged, self.server), (proof, self.client), (object(), self.server)):
            with self.assertRaisesRegex(Denied, "^bootstrap-native-denied$"):
                factory.require_bootstrap_native(invalid, connected, proof.policy, token, "synthetic-job-token")

    def test_native_completed_job_wrong_actor_ref_or_unsigned_workflow_drift_deny(self):
        original = deepcopy(self.native.job)
        self.native.job["status"] = "completed"
        with self.assertRaises(Denied): self.mint()
        self.native.job.update(original)
        self.workflow += b" changed but not approved"
        with self.assertRaises(Denied): self.mint()
        self.workflow = b"public fixed Source workflow contract fixture"
        self.native.claims["ref"] = "refs/pull/1/merge"
        with self.assertRaises(Denied): self.mint()

    def test_original_token_expiry_worker_and_policy_drift_hold(self):
        proof, token = self.mint()
        self.collected.return_value = replace(self.worker, pid=23457)
        with self.assertRaises(Denied): factory.require_bootstrap_native(proof, self.server, proof.policy, token, "synthetic-job-token")
        self.collected.return_value = self.worker
        with mock.patch.object(factory.time, "time", return_value=crypto.NOW + 300):
            with self.assertRaises(Denied): factory.require_bootstrap_native(proof, self.server, proof.policy, token, "synthetic-job-token")
        self.path.chmod(0o644)
        with self.assertRaises(Denied): factory.require_bootstrap_native(proof, self.server, proof.policy, token, "synthetic-job-token")

    def test_wrong_nonce_or_claimed_started_timestamp_cannot_mint(self):
        self.native.claims["aud"] = ledger.AUDIENCE + "f" * 64
        with self.assertRaises(Denied):
            factory.verify_bootstrap_native(self.server, self.bootstrap, self.selector, "f" * 64,
                                             self.native.token(), "synthetic-job-token")
        self.native.job["started_at"] = "future or untrusted timestamp"
        with self.assertRaises(Denied): self.mint()

    def test_root_policy_cannot_supply_caller_sha_old_cell_or_unknown_controller_domain(self):
        original = deepcopy(self.value)
        for modify in (lambda v: v["source_identity"].update(caller_sha="a" * 40),
                       lambda v: v["cells"][self.selector]["engine"].update(archives={}),
                       lambda v: v["controller"].update(repository="ltn-it/foreign")):
            self.value = deepcopy(original); modify(self.value)
            self.path.write_bytes(ledger.canonical(self.value)); self.path.chmod(0o600)
            with self.assertRaises(Denied): factory.load_bootstrap(str(self.path), ledger.digest(self.value))

    def test_purpose_selects_exact_observer_job_not_execution_capability(self):
        selected = factory.derive_selection(self.bootstrap, self.selector, crypto.CALLER_SHA, purpose="observer")
        self.assertEqual(selected.identity.required_native_job_name, "Final quality / heavy / example_heavy / ubuntu-24.04")
        challenge = factory.challenge_bootstrap(self.server, self.bootstrap, self.selector)
        self.native.claims["aud"] = challenge["audience"]
        with self.assertRaises(Denied):
            factory.verify_bootstrap_native(self.server, self.bootstrap, self.selector, challenge["nonce"],
                                             self.native.token(), "synthetic-job-token", purpose="observer")

    def test_future_ordinary_role_main_head_with_same_workflow_contract_needs_no_policy_edit(self):
        original = self.path.read_bytes()
        head = "9" * 40
        self.native.claims.update(sha=head, workflow_sha=head, run_id="502", check_run_id="733")
        self.native.run.update(id=502, head_sha=head)
        for job in self.native.jobs["jobs"]: job.update(run_id=502, head_sha=head)
        self.native.job.update(id=904, check_run_url=identity.API + "/repos/" + crypto.REPOSITORY + "/check-runs/733")
        self.worker = replace(self.worker, pid=23458, start_ticks=780)
        self.collected.return_value = self.worker
        proof, token = self.mint()
        self.assertEqual(proof.identity.run_id, 502)
        self.assertEqual(proof.policy.identity.caller_sha, head)
        factory.require_bootstrap_native(proof, self.server, proof.policy, token, "synthetic-job-token")
        self.assertEqual(self.path.read_bytes(), original)

    def test_foreign_signing_key_cannot_turn_same_locator_into_authority(self):
        challenge = factory.challenge_bootstrap(self.server, self.bootstrap, self.selector)
        self.native.claims["aud"] = challenge["audience"]
        with self.assertRaisesRegex(Denied, "^bootstrap-native-denied$"):
            factory.verify_bootstrap_native(self.server, self.bootstrap, self.selector, challenge["nonce"],
                self.native.token(key=self.native.foreign_key), "synthetic-job-token")


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootConfigurationTests(unittest.TestCase):
    """Real compiler/readers/Root FS. Acquisition/native OS observations modeled."""

    @classmethod
    def setUpClass(cls):
        import test_github_runner_incus_generation_publisher as source
        source.RootPublisherTests.setUpClass()
        RootBootstrapTests.setUpClass()

    def setUp(self):
        import test_github_runner_incus_generation_publisher as source
        self.pub = source.RootPublisherTests(methodName="runTest")
        self.pub.setUp(); self.addCleanup(self.pub.doCleanups)
        RootBootstrapTests.setUpClass()
        self.helper = RootBootstrapTests(methodName="runTest")
        self.helper.setUp(); self.addCleanup(self.helper.doCleanups)
        self.root = self.helper.root
        self.directory = self.root / "configurations"; self.directory.mkdir(mode=0o700)
        patch = mock.patch.object(factory, "ROOT", str(self.directory)); patch.start(); self.addCleanup(patch.stop)
        self.helper.native.claims.update(sha=self.pub.source.commit_sha, workflow_sha=self.pub.source.commit_sha,
            job_workflow_sha=self.pub.controller.commit_sha,
            job_workflow_ref=factory.VALIDATION + "/.github/workflows/collection-quality-profile-isolated.yml@" + self.pub.controller.commit_sha)
        self.helper.native.run.update(head_sha=self.pub.source.commit_sha,
            referenced_workflows=[{"path": self.helper.native.claims["job_workflow_ref"], "sha": self.pub.controller.commit_sha,
                                   "ref": self.pub.controller.commit_sha}])
        for job in self.helper.native.jobs["jobs"]: job.update(head_sha=self.pub.source.commit_sha)
        matrix = self.pub.cell["matrix"]
        self.selector = policy_registry.profile_selector(matrix["profile"], matrix["scenario"], matrix["target"])
        self.helper.native.job["name"] = matrix["profile"] + " / " + matrix["scenario"] + " / " + matrix["target"]
        self.helper.selector = self.selector
        base = self.helper.value["source_identity"]
        base["reusable_sha"] = self.pub.controller.commit_sha
        self.helper.value["controller"]["reusable_sha"] = self.pub.controller.commit_sha
        old = self.helper.value["cells"][next(iter(self.helper.value["cells"]))]
        template = deepcopy(self.pub.cell["engine"])
        template.pop("archives"); template.pop("trees")
        old.update(native_job_name=self.helper.native.job["name"],
            native_observer_job_name="Final quality / " + matrix["profile"] + " / " + matrix["scenario"] + " / " + matrix["target"],
            matrix=deepcopy(matrix), engine=template, incus=deepcopy(self.pub.cell["incus"]), github=deepcopy(self.pub.cell["github"]))
        self.helper.value["cells"] = {self.selector: old}
        self.helper.value["preparation"] = {key: value for key, value in self.pub.base.value.items() if key in factory.PREPARATION_KEYS}
        runtime = source.publisher._read(self.pub.runtime_ref["path"], self.pub.runtime_ref["sha256"])
        self.helper.value["runtime"] = {key: value for key, value in runtime.items() if key in factory.RUNTIME_KEYS}
        self.helper.seal()
        self.bootstrap = self.helper.bootstrap
        self.proof, self.token = self.helper.mint()
        stage = self.root / "genuine-stage-fixture"; stage.mkdir(mode=0o700)
        fds = []
        try:
            for name, raw in zip(factory.run_intake.ARCHIVES, (self.pub.artifact_raw, self.pub.source_raw, self.pub.controller_raw)):
                fd = os.open(stage / name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                fds.append(fd); os.write(fd, raw); os.fsync(fd)
            artifact = replace(self.pub.artifact, workflow_id=214182490)
            acquired = replace(self.pub.acquired, artifact=artifact)
            snapshot = factory.run_intake._validate_archives(acquired,
                **dict(zip(("artifact_fd", "source_fd", "controller_fd"), fds)))
        finally:
            for fd in fds: os.close(fd)
        self.snapshot = factory.run_intake.SealedRunSnapshot(str(stage), stage.stat().st_dev, stage.stat().st_ino, "7" * 64, snapshot)
        self.stage = mock.patch.object(factory.run_intake, "stage_run_snapshot", return_value=self.snapshot)
        self.staged = self.stage.start(); self.addCleanup(self.stage.stop)

    def create(self, snapshot=None):
        return factory.create_run_configuration(self.proof, self.helper.server, self.bootstrap, self.selector,
            self.token, "synthetic-job-token", self.snapshot if snapshot is None else snapshot)

    def test_real_private_config_consumed_by_registry_preparation_and_runtime_without_anchor(self):
        original_anchor = self.pub.anchor.exists()
        result = self.create()
        runtime = factory.runtime_rpc.RuntimeRPC(result.runtime_config_path, result.runtime_config_sha256)
        native = runtime._registry.select(self.selector).identity
        self.assertEqual(native.caller_sha, self.proof.identity.caller_sha)
        self.assertEqual(native.reusable_sha, self.proof.identity.reusable_sha)
        self.assertEqual(result.deadline, min(self.proof.job_started_at + 1800, crypto.NOW + 1200))
        self.assertEqual(self.pub.anchor.exists(), original_anchor)
        self.assertFalse((Path(result.directory) / "published.json").exists())
        with ledger.Ledger(self.helper.store_path, clock=factory.time.time) as store:
            with store._transaction() as state: self.assertEqual(state["leases"], {})

    def test_same_job_reuses_original_deadline_and_inodes_never_extends(self):
        first = self.create()
        inventory = factory._inventory(Path(first.directory))
        with mock.patch.object(factory.time, "time", return_value=crypto.NOW + 100):
            again = self.create()
        self.assertEqual(first, again)
        self.assertEqual(factory._inventory(Path(first.directory)), inventory)

    def test_partial_write_intent_retained_and_never_rebuilt(self):
        with mock.patch.object(factory, "_build", side_effect=OSError("synthetic write fault")) as build:
            with self.assertRaisesRegex(Denied, "^run-configuration-held$"): self.create()
            with self.assertRaisesRegex(Denied, "^run-configuration-held$"): self.create()
            self.assertEqual(build.call_count, 1)
        path = next(self.directory.iterdir())
        self.assertEqual({entry.name for entry in path.iterdir()}, {"intent.json"})

    def test_forged_snapshot_or_private_config_tamper_not_adopted(self):
        with self.assertRaises(Denied): self.create(replace(self.snapshot, receipt_sha256="9" * 64))
        self.assertEqual(list(self.directory.iterdir()), [])
        result = self.create()
        path = Path(result.runtime_config_path)
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        with self.assertRaises(Denied): self.create()
        self.assertEqual(path.read_bytes(), original + b" ")

    def test_registered_observer_finds_original_execution_without_config_or_deadline_write(self):
        result = self.create()
        inventory = factory._inventory(Path(result.directory))
        self.helper.native.job["name"] = self.helper.value["cells"][self.selector]["native_observer_job_name"]
        self.helper.native.claims["check_run_id"] = "735"
        self.helper.native.job.update(id=906, check_run_url=identity.API + "/repos/" + crypto.REPOSITORY + "/check-runs/735")
        self.helper.worker = replace(self.helper.worker, pid=23459, start_ticks=781)
        self.helper.collected.return_value = self.helper.worker
        challenge = factory.challenge_bootstrap(self.helper.server, self.bootstrap, self.selector)
        self.helper.native.claims["aud"] = challenge["audience"]
        token = self.helper.native.token()
        observer = factory.verify_bootstrap_native(self.helper.server, self.bootstrap, self.selector,
            challenge["nonce"], token, "synthetic-job-token", purpose="observer")
        factory.require_bootstrap_native(observer, self.helper.server, observer.policy, token, "synthetic-job-token")
        self.assertEqual(factory.find_existing_configuration(self.bootstrap, self.selector, observer), result)
        self.assertEqual(factory._inventory(Path(result.directory)), inventory)
        with self.assertRaises(Denied):
            factory.create_run_configuration(observer, self.helper.server, self.bootstrap, self.selector,
                token, "synthetic-job-token", self.snapshot)
        self.helper.server.close()
        with self.assertRaises(Denied):
            factory.find_existing_configuration(self.bootstrap, self.selector, observer)

    def test_manifest_locator_resolves_readonly_and_origin_is_separately_bound(self):
        result = self.create()
        before = factory._inventory(Path(result.directory))
        self.assertEqual(factory.resolve_configuration(self.bootstrap, self.selector, result.manifest_sha256), result)
        origin = factory.read_configuration_origin(result)
        self.assertEqual((origin["run_id"], origin["job_id"], origin["check_run_id"]),
                         (self.proof.identity.run_id, self.proof.identity.job_id, self.proof.identity.check_run_id))
        self.assertEqual(origin["source_sha"], self.proof.identity.caller_sha)
        self.assertEqual(factory._inventory(Path(result.directory)), before)
        with self.assertRaises(Denied): factory.resolve_configuration(self.bootstrap, self.selector, "9" * 64)
        with self.assertRaises(Denied): factory.read_configuration_origin(replace(result, manifest_sha256="9" * 64))

    def test_runtime_fresh_native_origin_cannot_borrow_another_run_or_check_same_head(self):
        result = self.create()
        runtime = factory.runtime_rpc.RuntimeRPC(result.runtime_config_path, result.runtime_config_sha256,
                                                derived_configuration=result)
        runtime._require_origin(self.proof.identity, self.selector)
        for field in ("run_id", "job_id", "check_run_id"):
            with self.subTest(field=field), self.assertRaises(Denied):
                runtime._require_origin(replace(self.proof.identity, **{field: getattr(self.proof.identity, field) + 1}),
                                        self.selector)
        # The independently sealed original per-job config is unchanged.
        self.assertEqual(factory.read_configuration_origin(result)["check_run_id"], self.proof.identity.check_run_id)

    def test_same_execution_lookup_reuses_original_config_without_public_archive_reacquisition(self):
        result = self.create()
        before = factory._inventory(Path(result.directory))
        self.staged.reset_mock()
        self.assertEqual(factory.find_existing_execution_configuration(self.bootstrap, self.selector, self.proof), result)
        self.staged.assert_not_called()
        self.assertEqual(factory._inventory(Path(result.directory)), before)
        # A different real check cannot borrow another job's source snapshot.
        self.helper.native.claims["check_run_id"] = "733"
        self.helper.native.job["check_run_url"] = identity.API + "/repos/" + crypto.REPOSITORY + "/check-runs/733"
        proof, _ = self.helper.mint()
        with self.assertRaises(Denied):
            factory.find_existing_execution_configuration(self.bootstrap, self.selector, proof)
        self.staged.assert_not_called()

    def test_native_job_start_bound_wins_over_larger_root_lease_window(self):
        self.helper.value["cells"][self.selector]["lease_seconds"] = 5400
        self.helper.seal(); self.bootstrap = self.helper.bootstrap
        self.proof, self.token = self.helper.mint()
        result = self.create()
        self.assertEqual(result.deadline, self.proof.job_started_at + 1800)
        self.assertLess(result.deadline, crypto.NOW + 5400)

    def test_later_real_job_after_retention_gets_own_clock_without_extending_original(self):
        old = self.helper.value["cells"][self.selector]
        new = deepcopy(old); new["matrix"]["scenario"] = "example_late"
        next_selector = policy_registry.profile_selector(new["matrix"]["profile"], "example_late", new["matrix"]["target"])
        new["native_job_name"] = "heavy / example_late / " + new["matrix"]["target"]
        new["native_observer_job_name"] = "Final quality / " + new["native_job_name"]
        self.helper.value["cells"][next_selector] = new
        self.helper.seal(); self.bootstrap = self.helper.bootstrap
        self.proof, self.token = self.helper.mint()
        first = self.create()
        original = Path(first.directory, "sealed-inventory.json").read_bytes()
        late = crypto.NOW + 14400
        with mock.patch.object(factory.time, "time", return_value=late):
            self.selector = next_selector; self.helper.selector = next_selector
            self.helper.native.claims.update(check_run_id="735", iat=late - 20, nbf=late - 20,
                                            exp=late + 300, jti="synthetic-later-job-token")
            self.helper.native.job.update(id=906, name=new["native_job_name"],
                check_run_url=identity.API + "/repos/" + crypto.REPOSITORY + "/check-runs/735",
                started_at=dt.datetime.fromtimestamp(late - 10, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
            self.helper.worker = replace(self.helper.worker, pid=23459, start_ticks=781)
            self.helper.collected.return_value = self.helper.worker
            self.proof, self.token = self.helper.mint()
            second = self.create()
        self.assertNotEqual(first.directory, second.directory)
        self.assertEqual(second.deadline, late + 1200)
        self.assertEqual(Path(first.directory, "sealed-inventory.json").read_bytes(), original)
