"""Real private Unix HTTP/Ledger/Root crypto+ELF fixtures, not native Incus proof.

Only local Podman/cgroup and paired network kernel readbacks are modeled. The
strong owner comes from actual preparation and original fixed-ELF exit receipts.
"""
from copy import deepcopy
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

import test_github_runner_incus_finalization as fixtures
import test_github_runner_incus_mutation as transport

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import (emergency_stop, engine_executor, engine_policy, ledger, network_fence)
from incus_lease_issuer.identity import Denied


class GuardTests(unittest.TestCase):
    def test_root_factory_and_no_job_locator_or_approval(self):
        with mock.patch.object(os, "geteuid", return_value=2101):
            with self.assertRaisesRegex(Denied, "emergency-root-required"):
                emergency_stop.RootEmergencyStop(None, None)
        with self.assertRaises(TypeError):
            emergency_stop.RootEmergencyStop(None, None, approved=True)
        with self.assertRaises(TypeError):
            object.__new__(emergency_stop.RootEmergencyStop).stop(None, None, None, None, instance="foreign")


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootEmergencyStopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.RootFinalizationTests.setUpClass()

    def setUp(self):
        self.base = fixtures.RootFinalizationTests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.owner, self.store, self.lease = self.base.owner, self.base.store, self.base.lease
        self.server, self.registry = self.base.server, self.base.registry
        value = self.owner.incus
        self.url = "/1.0/instances/"+value["instance"]+"?project="+value["project"]
        self.state_url = "/1.0/instances/"+value["instance"]+"/state?project="+value["project"]
        self.inventory_url = "/1.0/instances?project="+value["project"]
        self.operations_url = "/1.0/operations?project="+value["project"]+"&recursion=1"
        own = value["ownership"]
        self.server.resources[self.inventory_url] = [self.url]
        self.server.resources[self.url] = {"name": value["instance"], "type": "virtual-machine", "config": {
            "user.lit-molecule-owner": own["owner"], "user.lit-molecule-repository": own["repository"],
            "user.lit-molecule-run-id": str(own["run_id"]), "user.lit-molecule-attempt": str(own["run_attempt"]),
            "user.lit-molecule-scenario": own["scenario"], "user.lit-molecule-target": own["target"]}}
        self.server.resources[self.state_url] = {"status": "Running", "status_code": 103, "pid": 12345}
        self.lose_reply = self.async_stop = self.refuse_stop = False
        self.mutation_snapshots = []
        original = self.server.handle
        def handle(method, path, body):
            if method == "PUT" and path == self.state_url:
                record = self.store.read(self.lease)
                self.mutation_snapshots.append(deepcopy(record))
                if not self.refuse_stop:
                    self.server.resources[path] = {"status": "Stopped", "status_code": 102, "pid": 0}
                if self.lose_reply:
                    raise OSError("synthetic lost response, secret never public")
                if self.async_stop:
                    return transport.reply(transport.envelope({"id": transport.OPERATION, "class": "task"},
                        type="async", status="Operation created", status_code=100,
                        operation="/1.0/operations/"+transport.OPERATION), 202)
                return transport.reply(transport.envelope({}))
            return original(method, path, body)
        self.server.handle = handle
        self.stopper = emergency_stop.RootEmergencyStop(str(self.base.runtime), self.base.sha)
        self.requests_start = len(self.server.requests)

    def stop(self, **overrides):
        start_id = self.owner.creators["engine-start"]["id"]
        start = self.store.read(self.lease)["effects"][start_id]
        # These explicit modeled boundaries do NOT claim actual cgroup/Podman/
        # host/private-network proof. Native Unix requests below are real.
        with mock.patch.object(engine_policy, "ENGINE", self.base.engine.original), \
             mock.patch.object(engine_executor, "_retained", return_value=(self.base.engine.manifest, start_id, start)), \
             mock.patch.object(engine_executor, "_drained", side_effect=overrides.get("drain")), \
             mock.patch.object(network_fence, "verify_disabled", side_effect=overrides.get("withdrawal")):
            return self.stopper.stop(self.registry, "approved", self.store, self.lease)

    def puts(self):
        return [row for row in self.requests() if row[0] == "PUT" and row[1] == self.state_url]

    def requests(self):
        # Preparation legitimately PUTs the default profile before this unit.
        return self.server.requests[self.requests_start:]

    def test_actual_once_graceful_stop_has_durable_intent_and_revoked_scope_before_put(self):
        receipt = self.stop()
        self.assertEqual(receipt.disposition, "stopped_observed")
        self.assertEqual(self.puts(), [("PUT", self.state_url,
            {"action": "stop", "timeout": 30, "force": False, "stateful": False})])
        snapshot = self.mutation_snapshots[0]
        self.assertEqual(snapshot["effects"][receipt.effect_id]["state"], "intent")
        self.assertTrue(any(row["operation"] == "certificate-revoke" and row["state"] == "verified"
                            for row in snapshot["effects"].values()))
        self.assertEqual(self.store.read(self.lease)["effects"][receipt.effect_id]["state"], "verified")
        self.assertEqual(self.store.read(self.lease)["state"], "prepared")
        self.assertFalse(any(row[0] == "DELETE" and not row[1].startswith("/1.0/certificates/")
                             for row in self.requests()))
        self.assertEqual(self.stop().effect_id, receipt.effect_id)
        self.assertEqual(len(self.puts()), 1)

    def test_async_uuid_is_retained_before_native_poll_and_survives_restart(self):
        self.async_stop = True
        original = self.server.handle
        polls = []
        def handle(method, path, body):
            if method == "GET" and path == "/1.0/operations/"+transport.OPERATION:
                polls.append(self.store.read(self.lease))
                if len(polls) == 2:
                    self.server.operation_code = 200
            return original(method, path, body)
        self.server.handle = handle
        receipt = self.stop()
        self.assertTrue(polls)
        self.assertEqual(polls[0]["effects"][receipt.effect_id]["incus_operation_id"], transport.OPERATION)
        with ledger.Ledger(self.registry.select("approved").ledger_path, clock=self.store.clock) as reopened:
            self.assertEqual(reopened.read(self.lease)["effects"][receipt.effect_id]["incus_operation_id"], transport.OPERATION)
        self.assertEqual(len(self.puts()), 1)

    def test_lost_response_installed_stop_is_unknown_and_never_adopted_or_replayed(self):
        self.lose_reply = True
        with self.assertRaisesRegex(emergency_stop.EmergencyStopUnknown, "emergency-native-unknown"):
            self.stop()
        self.assertEqual(self.server.resources[self.state_url]["status"], "Stopped")
        effects = [row for row in self.store.read(self.lease)["effects"].values() if row["operation"] == "instance-stop"]
        self.assertEqual([row["state"] for row in effects], ["unknown"])
        before = len(self.server.requests)
        with self.assertRaises(emergency_stop.EmergencyStopDenied):
            self.stop()
        self.assertEqual(len(self.server.requests), before)
        self.assertEqual(len(self.puts()), 1)

    def test_success_response_without_stopped_readback_stays_unknown(self):
        self.refuse_stop = True
        with self.assertRaises(emergency_stop.EmergencyStopUnknown):
            self.stop()
        self.assertEqual(len(self.puts()), 1)
        self.assertTrue(any(row["operation"] == "instance-stop" and row["state"] == "unknown"
                            for row in self.store.read(self.lease)["effects"].values()))

    def test_absent_or_already_stopped_is_observation_not_fake_stop_intent(self):
        self.server.resources[self.state_url] = {"status": "Stopped", "status_code": 102, "pid": 0}
        result = self.stop()
        self.assertEqual((result.disposition, result.effect_id), ("stopped_observed", None))
        self.server.resources[self.inventory_url] = []
        result = self.stop()
        self.assertEqual((result.disposition, result.effect_id), ("absent_observed", None))
        self.assertEqual(self.puts(), [])
        self.assertFalse(any(row["operation"] == "instance-stop" for row in self.store.read(self.lease)["effects"].values()))

    def test_already_absent_certificate_scope_is_journaled_by_readback_without_fake_fp(self):
        fingerprint = self.owner.creator_targets["certificate-create"].removeprefix("certificate:")
        self.server.resources.pop("/1.0/certificates/"+fingerprint)
        result = self.stop()
        self.assertEqual(result.disposition, "stopped_observed")
        rows = [row for row in self.store.read(self.lease)["effects"].values()
                if row["operation"] == "certificate-revoke"]
        self.assertEqual([row["state"] for row in rows], ["verified"])
        self.assertNotIn("certificate_revocation", rows[0])
        self.assertFalse(any(row[0] == "DELETE" for row in self.requests()))
        self.assertEqual(len(self.puts()), 1)

    def test_verified_native_exit_is_not_a_substitute_for_verified_local_stop(self):
        with self.store._transaction() as state:
            effects = state["leases"][self.lease]["effects"]
            stop = next(key for key, row in effects.items() if row["operation"] == "engine-stop")
            del effects[stop]
        with self.assertRaises(emergency_stop.EmergencyStopDenied):
            self.stop()
        self.assertFalse(any(row[0] in {"PUT", "DELETE"} for row in self.requests()))

    def test_foreign_names_project_urls_type_and_each_ownership_field_hold_before_revocation(self):
        original = deepcopy(self.server.resources[self.url])
        for field in original["config"]:
            with self.subTest(field=field):
                self.server.resources[self.url] = deepcopy(original)
                self.server.resources[self.url]["config"][field] = "foreign"
                with self.assertRaises(emergency_stop.EmergencyStopDenied):
                    self.stop()
        self.server.resources[self.url] = original
        for instance_type in ("container", "vm", None):
            self.server.resources[self.url] = {**original, "type": instance_type}
            with self.assertRaises(emergency_stop.EmergencyStopDenied):
                self.stop()
        self.server.resources[self.url] = original
        for urls in ([self.url+"&project=foreign"], [self.url, "/1.0/instances/foreign?project="+self.owner.incus["project"]]):
            self.server.resources[self.inventory_url] = urls
            with self.assertRaises(emergency_stop.EmergencyStopDenied):
                self.stop()
        self.assertFalse(any(row[0] in {"PUT", "DELETE"} for row in self.requests()))

    def test_foreign_or_failed_or_pending_operation_is_not_silently_filtered(self):
        for code, status, group in ((103, "Running", "running"), (200, "Success", "success"), (400, "Failure", "failure")):
            self.server.resources[self.operations_url] = {group: [{"id": transport.OPERATION, "class": "task",
                "status_code": code, "status": status}]}
            with self.assertRaises(emergency_stop.EmergencyStopDenied):
                self.stop()
        self.assertEqual(self.puts(), [])
        self.assertFalse(any(row[0] == "DELETE" for row in self.requests()))

    def test_paired_withdrawal_and_native_local_drain_are_mandatory_before_remote_io(self):
        before = len(self.server.requests)
        for boundary in ("withdrawal", "drain"):
            with self.subTest(boundary=boundary), self.assertRaises(emergency_stop.EmergencyStopDenied):
                self.stop(**{boundary: Denied("synthetic-native-hold")})
        self.assertEqual(len(self.server.requests), before)

    def test_cancelled_and_expired_authority_still_allows_known_owned_shutdown(self):
        self.store.cancel(self.lease, "cancelled")
        expiry = self.owner.expires_at
        self.store.clock = lambda: expiry + 1
        self.assertEqual(self.stop().disposition, "stopped_observed")
        self.assertEqual(self.store.read(self.lease)["state"], "cancelled")
        self.assertEqual(len(self.puts()), 1)

    def test_unknown_other_effect_holds_even_if_instance_looks_stopped(self):
        self.store.begin(self.lease, "capture", "synthetic-capture")
        self.server.resources[self.state_url] = {"status": "Stopped", "status_code": 102, "pid": 0}
        with self.assertRaises(emergency_stop.EmergencyStopDenied):
            self.stop()
        self.assertEqual(self.puts(), [])


if __name__ == "__main__":
    unittest.main()
