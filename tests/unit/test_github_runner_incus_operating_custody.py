"""Actual Root Ledger/finalizer policy with explicitly offline HTTPS fixtures."""
import datetime as dt
import os
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

import test_github_runner_incus_finalization as fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import identity, operating_custody as custody
from incus_lease_issuer.identity import Denied


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
