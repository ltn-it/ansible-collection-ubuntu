"""Actual Root Ledger/finalizer policy with explicitly offline HTTPS fixtures."""
import datetime as dt
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import test_github_runner_incus_finalization as fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import identity, operating_custody as custody
from incus_lease_issuer.identity import Denied


class PostEngineWatchdogTests(unittest.TestCase):
    def setUp(self):
        from incus_lease_issuer import finalization, operating_watchdog, runtime_rpc

        self.lease = "a" * 32
        self.selector = "cell-" + "b" * 32
        self.record = {"state": "prepared", "cell_sha256": "c" * 64, "policy_sha256": "d" * 64,
                       "effects": {"start": {"operation": "engine-start", "state": "verified",
                                              "engine_exit": {"exit_code": 1}}},
                       "native_terminal": {"conclusion": "failure"}}
        self.store = mock.MagicMock()
        self.store.__enter__.return_value = self.store
        self.store.lease_ids.return_value = [self.lease]
        self.store.read.return_value = self.record
        self.store.read_policy.return_value = {"retention_seconds": 14400,
            "post_engine_failure_retirement": {"schema": 1, "selector": self.selector}}
        row = SimpleNamespace(ledger_path="/private/ledger", cell_sha256=self.record["cell_sha256"],
                              custody_policy_sha256=self.record["policy_sha256"])
        self.registry = SimpleNamespace(policies={self.selector: row})
        self.finalizer = mock.Mock()
        self.finalizer.prepare_post_engine_permit.return_value = {"permit_sha256": "e" * 64}
        self.finalizer.readback_post_engine_failure.return_value = {"readback_sha256": "f" * 64}
        self.allowed = mock.Mock()
        for patch in (
            mock.patch.object(custody.os, "geteuid", return_value=0),
            mock.patch.object(custody.ledger, "Ledger", return_value=self.store),
            mock.patch.object(runtime_rpc, "_configuration"),
            mock.patch.object(runtime_rpc, "RuntimeRPC", return_value=SimpleNamespace(_registry=self.registry)),
            mock.patch.object(operating_watchdog, "_machine_boot",
                              return_value=("1" * 32, "12345678-1234-1234-1234-123456789abc")),
            mock.patch.object(finalization, "RootFinalizer", return_value=self.finalizer),
            mock.patch.object(custody, "require_cleanup_allowed", self.allowed),
        ):
            self.addCleanup(patch.stop)
            patch.start()

    def tick(self):
        return custody.tick_runtime("/private/runtime.json", "0" * 64, "1" * 64)

    def test_opted_in_failure_closes_only_after_separate_readback(self):
        result = self.tick()
        binding = (self.registry, self.selector, self.store, self.lease)
        self.assertEqual(self.finalizer.method_calls, [
            mock.call.prepare_post_engine_permit(*binding),
            mock.call.finalize_post_engine_failure(*binding, "e" * 64),
            mock.call.readback_post_engine_failure(*binding, "e" * 64),
            mock.call.close_post_engine_failure(*binding, "e" * 64, "f" * 64),
        ])
        self.assertFalse(result["native_acceptance"])
        self.allowed.assert_not_called()

    def test_failed_readback_keeps_lease_held_without_ordinary_fallback(self):
        self.finalizer.readback_post_engine_failure.side_effect = Denied("still-present")
        result = self.tick()
        self.assertEqual(result["state"], "HELD")
        self.assertEqual([row["kind"] for row in result["events"]], ["cleanup-unknown"])
        self.assertFalse(result["native_acceptance"])
        self.finalizer.close_post_engine_failure.assert_not_called()
        self.allowed.assert_not_called()

    def test_ordinary_custody_remains_for_non_opted_in_or_ineligible_leases(self):
        self.finalizer.prepare_post_engine_permit.return_value = None
        self.assertFalse(self.tick()["native_acceptance"])
        self.finalizer.prepare_post_engine_permit.assert_called_once()
        self.allowed.assert_called_once_with(self.store, self.lease)
        self.finalizer.reset_mock()
        self.allowed.reset_mock()

        self.store.read_policy.return_value = {"retention_seconds": 14400}
        self.assertFalse(self.tick()["native_acceptance"])
        self.finalizer.prepare_post_engine_permit.assert_not_called()
        self.finalizer.finalize.assert_called_once()
        self.allowed.assert_called_once_with(self.store, self.lease)

    def test_immediate_closure_replays_the_same_custody_alarm(self):
        self.record.update(state="retained", custody={"retain_until": 1000})
        self.store.read_policy.return_value = {"retention_seconds": 0}
        self.allowed.side_effect = Denied("model-original-watchdog-tick")
        with mock.patch.object(custody, "_custody_record") as validate, \
             mock.patch.object(custody, "_prune_retained_graph"):
            initial, = self.tick()["events"]
            self.record["state"] = "closed"
            recovered, = self.tick()["events"]
        self.assertEqual(recovered["kind"], "failed-cell-retained")
        self.assertEqual(recovered["event_id"], initial["event_id"])
        self.assertEqual(recovered["lease_id"], self.lease)
        self.assertEqual(validate.call_count, 2)
        self.finalizer.finalize.assert_not_called()
        self.store.read_policy.return_value = {"retention_seconds": 14400}
        self.assertEqual(self.tick()["events"], [])


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class NativeTerminalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.RootFinalizationTests.setUpClass()

    def setUp(self):
        self.fixture = fixtures.RootFinalizationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.store, self.lease, self.registry = self.fixture.store, self.fixture.lease, self.fixture.registry
        record = self.store.read(self.lease)
        who, policy = record["identity"], self.registry.select("approved").identity
        self.prefix = identity.API + "/repos/" + policy.repository
        actor = {"id": next(iter(policy.actor_ids)), "login": "fixture", "type": "User"}
        self.run = {"id": who["run_id"], "run_attempt": 1, "event": "push", "head_branch": "main",
            "head_sha": policy.caller_sha, "workflow_id": policy.workflow_id, "path": policy.workflow_path,
            "repository": {"id": policy.repository_id, "full_name": policy.repository, "private": False,
                "owner": {"id": policy.owner_id}}, "actor": actor, "triggering_actor": actor,
            "referenced_workflows": [{"path": policy.reusable_repository + "/" + policy.reusable_path + "@" + policy.reusable_sha,
                "sha": policy.reusable_sha}]}
        self.job = {"id": who["job_id"], "run_id": who["run_id"], "run_attempt": 1, "head_sha": who["caller_sha"],
            "runner_id": who["runner_id"], "name": policy.required_native_job_name, "status": "completed",
            "conclusion": "failure", "check_run_url": self.prefix + "/check-runs/" + str(who["check_run_id"]),
            "completed_at": dt.datetime.fromtimestamp(int(time.time()) - 30, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        self.check = {"id": who["check_run_id"], "head_sha": who["caller_sha"], "status": "completed", "conclusion": "failure"}
        self.routes = {self.prefix + "/actions/runs/" + str(who["run_id"]): self.run,
            self.prefix + "/actions/jobs/" + str(who["job_id"]): self.job,
            self.prefix + "/check-runs/" + str(who["check_run_id"]): self.check}
        self.reader = mock.Mock(side_effect=lambda url: custody.ledger.canonical(self.routes[url]))
        reader = mock.patch.object(identity, "HTTPSReader", return_value=mock.Mock(read=self.reader))
        reader.start()
        self.addCleanup(reader.stop)

    def test_actual_factory_joins_original_terminal_job_then_ledger_consumes_opaque_proof(self):
        before = self.store.read(self.lease)
        proof = custody.observe_native_terminal(self.registry, "approved", self.store, self.lease)
        self.assertEqual(self.store.read(self.lease), before)
        result = self.store.bind_native_terminal(self.lease, proof)
        self.assertEqual(result["conclusion"], "failure")
        self.assertEqual(result["job_id"], before["identity"]["job_id"])
        self.assertLess(result["completed_at"], result["observed_at"])
        self.assertEqual(self.store.read(self.lease)["native_terminal"], result)
        with self.assertRaises(Denied):
            self.store.bind_native_terminal(self.lease, result)
        with self.assertRaises(Denied):
            self.store.bind_native_terminal(self.lease, proof)  # Snapshot changed after first consumption.

    def test_independent_tick_reports_busy_ledger_without_wait_or_effects(self):
        import fcntl
        from incus_lease_issuer import engine_policy
        fd = os.open(self.registry.select("approved").ledger_path + "/lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            began = time.monotonic()
            before_requests = list(self.fixture.server.requests)
            with mock.patch.object(engine_policy, "ENGINE", self.fixture.engine.original):
                result = custody.tick_runtime(str(self.fixture.runtime), self.fixture.sha, "f" * 64)
            self.assertLess(time.monotonic() - began, 2)
            self.assertEqual(result["state"], "HELD")
            self.assertFalse(result["native_acceptance"])
            self.assertEqual([event["kind"] for event in result["events"]], ["supervisor-observation-held"])
            self.assertFalse(self.reader.called)
            self.assertEqual(self.fixture.server.requests, before_requests)
        finally:
            os.close(fd)

    def test_known_pending_job_has_one_read_and_durable_backoff_without_terminal_authority(self):
        self.job.update(status="in_progress", conclusion=None, completed_at=None)
        with self.assertRaises(custody.NativeJobPending):
            custody.observe_native_terminal(self.registry, "approved", self.store, self.lease)
        self.assertEqual(self.reader.call_count, 1)
        with self.assertRaises(custody.NativeJobPending):
            custody.observe_native_terminal(self.registry, "approved", self.store, self.lease)
        self.assertEqual(self.reader.call_count, 1)
        self.assertNotIn("native_terminal", self.store.read(self.lease))

    def test_borrowed_job_retry_missing_or_unfinished_native_metadata_never_records_success(self):
        for field, value in (("id", self.job["id"] + 1), ("run_attempt", 2), ("name", "foreign"),
                             ("status", "in_progress"), ("check_run_url", self.prefix + "/check-runs/1")):
            original = self.job[field]
            self.job[field] = value
            with self.subTest(field=field), self.assertRaises(Denied):
                custody.observe_native_terminal(self.registry, "approved", self.store, self.lease)
            self.job[field] = original
            self.assertNotIn("native_terminal", self.store.read(self.lease))
        self.reader.side_effect = OSError("provider inaccessible")
        with self.assertRaises(OSError):
            custody.observe_native_terminal(self.registry, "approved", self.store, self.lease)
        self.assertNotIn("native_terminal", self.store.read(self.lease))
