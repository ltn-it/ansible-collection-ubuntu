"""Actual private fixed ELF/PIPE/file/Ledger supervision, not Podman proof.

Only unsupported native Podman and cgroup/fence acquisition are modeled. No
kernel PID/exit/log ownership observation is replaced with an acceptance flag.
"""
import hashlib
import os
from pathlib import Path
import signal
import sys
import time
import unittest
from unittest import mock
from dataclasses import replace

import test_github_runner_incus_engine_executor as fixtures

executor, engine, identity = fixtures.executor, fixtures.engine, fixtures.identity
from incus_lease_issuer import engine_supervision as supervision
from incus_lease_issuer.identity import Denied


class GuardTests(unittest.TestCase):
    def test_capture_and_wait_are_root_only_and_no_owner_override(self):
        with mock.patch.object(os, "geteuid", return_value=2101):
            with self.assertRaises(Denied):
                supervision.Capture(None, None, None, None, 0, 1)
            with self.assertRaisesRegex(Denied, "engine-executor-root-required"):
                executor.wait_for_exit(None, None, None, None, None, None, None)
        with self.assertRaises(TypeError):
            executor.wait_for_exit(None, None, None, None, None, None, None, qualified=True)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootSupervisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.RootExecutorTests.setUpClass()

    def setUp(self):
        self.fixture = fixtures.RootExecutorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.store = self.fixture.store
        self.lease = self.fixture.lease

    def program(self, body, *, stdout=1048576, stderr=1048576, total=2097152):
        details = identity.decode_json(self.fixture.manifest.canonical_bytes)
        details["argv"][4] = "import time; time.sleep(0.3); " + body
        details["capture"] = {"stdout_limit": stdout, "stderr_limit": stderr, "total_limit": total}
        raw = engine._canonical(details)
        self.fixture.manifest = replace(self.fixture.manifest, argv=tuple(details["argv"]),
                                        canonical_bytes=raw, sha256=hashlib.sha256(raw).hexdigest())
        self.fixture.details = details

    def launch(self):
        self.fixture.spawn()
        effect_id, effect = self.fixture.engine_effect()
        owned = executor._PROCESSES[effect["engine_process"]["pid"]]
        self.assertEqual(effect["engine_capture"]["manifest_sha256"], self.fixture.manifest.sha256)
        self.assertEqual(effect["engine_capture"]["stdout_inode"], os.stat(
            self.fixture.details["engine"]["runroot"] + "/stdout.log").st_ino)
        return owned

    def finish(self, owned, seconds=4):
        deadline = time.monotonic() + seconds
        while (owned.returncode is None or not owned.eof) and time.monotonic() < deadline:
            owned.pump(0.01)
        self.assertIsNotNone(owned.returncode)
        return owned.record_exit()

    def test_actual_exit_zero_and_private_stdout_are_durable_observation_only(self):
        self.program("import os; os.write(1,b'public-output'); os.write(2,b'private-error')")
        owned = self.launch()
        receipt = self.finish(owned)
        self.assertEqual(receipt.exit_code, 0)
        self.assertEqual(receipt.stdout_state, "complete")
        effect = self.fixture.engine_effect()[1]
        self.assertEqual(effect["engine_exit"]["stdout_sha256"], hashlib.sha256(b"public-output").hexdigest())
        self.assertEqual(effect["engine_exit"]["stderr_sha256"], hashlib.sha256(b"private-error").hexdigest())
        self.assertEqual(effect["state"], "verified")  # Original tracking outcome unchanged.
        self.assertEqual(owned.record_exit(), receipt)
        executor._reap_finished()
        self.assertIs(executor._PROCESSES[owned.proc.pid], owned)  # No discarded exit status.

    def test_owner_allocation_failure_keeps_original_child_unknown_no_replay(self):
        self.program("time.sleep(30)")
        with mock.patch.object(supervision, "OwnedRun", side_effect=OSError("synthetic allocation failure")):
            with self.assertRaises(executor.EngineUnknown):
                self.fixture.traced_spawn()
        effect = self.fixture.engine_effect()[1]
        self.assertEqual(effect["state"], "unknown")
        self.assertNotIn("engine_exit", effect)
        originals = [proc for proc, _ in executor._UNTRACKED_PROCESSES.values()
                     if tuple(proc.args) == self.fixture.manifest.argv]
        self.assertEqual(len(originals), 1)
        self.assertIsNone(originals[0].poll())

    def test_actual_exit_seven_is_retained(self):
        self.program("import sys; sys.exit(7)")
        owned = self.launch()
        self.assertEqual(self.finish(owned).exit_code, 7)

    def test_actual_signal_and_cancel_share_one_original_reaper(self):
        self.program("time.sleep(30)")
        owned = self.launch()
        effect_id, effect = self.fixture.engine_effect()
        with mock.patch.object(executor, "_retained", return_value=(self.fixture.manifest, effect_id, effect)), \
             mock.patch.object(executor, "_command", side_effect=self.fixture.command), \
             mock.patch.object(executor, "_withdraw"), mock.patch.object(executor, "_drained"):
            executor.cancel(*self.fixture.arguments())
        observed = self.finish(owned)
        self.assertEqual(observed.signal, signal.SIGTERM)
        self.assertIsNone(observed.exit_code)

    def test_interleaved_large_output_enforces_independent_total_below_each_stream(self):
        self.program("import os; [(os.write(1,b'a'*4096),os.write(2,b'b'*4096)) for _ in range(32)]",
                     stdout=32768, stderr=32768, total=8192)
        owned = self.launch()
        receipt = self.finish(owned)
        effect = self.fixture.engine_effect()[1]["engine_exit"]
        self.assertEqual(effect["stdout_bytes"] + effect["stderr_bytes"], 8192)
        self.assertIn("limited", (receipt.stdout_state, receipt.stderr_state))
        for name in ("stdout", "stderr"):
            raw = Path(self.fixture.details["engine"]["runroot"], name + ".log").read_bytes()
            self.assertEqual(len(raw), effect[name + "_bytes"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), effect[name + "_sha256"])

    def test_long_lived_wait_persists_exit_before_reply_without_wait_lock(self):
        self.program("import os; os.write(1,b'waited')")
        owned = self.launch()
        effect_id, effect = self.fixture.engine_effect()
        pumped = []
        original = owned.pump
        def unlocked_pump(seconds):
            if not pumped:
                with executor.preparation.preparation_lock(str(self.fixture.fixture.config), self.fixture.fixture.sha):
                    pumped.append(True)  # Actual NB lock is available during wait.
            return original(seconds)
        with mock.patch.object(executor, "_retained", return_value=(self.fixture.manifest, effect_id, effect)), \
             mock.patch.object(executor, "_command", side_effect=self.fixture.command), \
             mock.patch.object(executor, "_withdraw"), mock.patch.object(executor, "_drained"), \
             mock.patch.object(owned, "pump", side_effect=unlocked_pump):
            observed = executor.wait_for_exit(*self.fixture.arguments())
            self.assertEqual(observed.exit_code, 0)
            self.assertEqual(pumped, [True])
            self.assertTrue(owned.closed)
            self.assertIn("engine_exit", self.fixture.engine_effect()[1])
            self.assertEqual(executor.wait_for_exit(*self.fixture.arguments()), observed)

    def test_uncertain_withdrawal_still_one_owned_stop_but_no_cleanup_success(self):
        self.program("time.sleep(30)")
        owned = self.launch()
        effect_id, effect = self.fixture.engine_effect()
        def uncertain(config, actual):
            actual.withdrawal_hold = True
        with mock.patch.object(executor, "_retained", return_value=(self.fixture.manifest, effect_id, effect)), \
             mock.patch.object(executor, "_command", side_effect=self.fixture.command), \
             mock.patch.object(executor, "_withdraw", side_effect=uncertain), \
             mock.patch.object(executor, "_drained"):
            with self.assertRaises(executor.EngineUnknown):
                executor.cancel(*self.fixture.arguments())
        receipt = self.finish(owned)
        self.assertEqual(receipt.signal, signal.SIGTERM)
        self.assertTrue(owned.withdrawal_hold)
        stops = [row for row in self.store.read(self.lease)["effects"].values() if row["operation"] == "engine-stop"]
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0]["state"], "verified")  # Stop known, fence still held.

    def test_replaced_log_is_incomplete_not_accepted_capture(self):
        self.program("import os; os.write(1,b'original')")
        owned = self.launch()
        deadline = time.monotonic() + 3
        while (owned.returncode is None or not owned.eof) and time.monotonic() < deadline:
            owned.pump(0.01)
        path = Path(self.fixture.details["engine"]["runroot"], "stdout.log")
        path.unlink()
        path.write_bytes(b"substitute")
        path.chmod(0o600)
        with self.assertRaisesRegex(Denied, "supervision-capture-readback-held"):
            owned.record_exit()
        self.assertNotIn("engine_exit", self.fixture.engine_effect()[1])

    def test_running_owner_cannot_be_released_or_reconstructed_after_crash(self):
        self.program("time.sleep(30)")
        owned = self.launch()
        with self.assertRaisesRegex(Denied, "supervision-exit-not-durable"):
            owned.release()
        effect_id, effect = self.fixture.engine_effect()
        del executor._PROCESSES[owned.proc.pid]
        try:
            with mock.patch.object(executor, "_retained", return_value=(self.fixture.manifest, effect_id, effect)):
                with self.assertRaisesRegex(Denied, "engine-original-wait-owner-missing"):
                    executor.wait_for_exit(*self.fixture.arguments())
            self.assertNotIn("engine_exit", self.fixture.engine_effect()[1])
        finally:
            executor._PROCESSES[owned.proc.pid] = owned

    def test_descendant_retaining_pipe_is_incomplete_and_cgroup_hold(self):
        # Explicitly reap fixture's own child to avoid leaked descendants even
        # when the production cgroup guard correctly denies cleanup completion.
        self.program("import os; p=os.fork(); "
                     "time.sleep(1.0 if p==0 else 0.05); os._exit(0)")
        owned = self.launch()
        deadline = time.monotonic() + 0.7
        while owned.returncode is None and time.monotonic() < deadline:
            owned.pump(0.01)
        self.assertIsNotNone(owned.returncode)
        self.assertFalse(owned.eof)
        self.assertEqual(owned.record_exit().stdout_state, "incomplete")
        end = time.monotonic() + 2
        while not owned.eof and time.monotonic() < end:
            owned.pump(0.01)
        self.assertTrue(owned.eof)


@unittest.skipUnless(sys.platform=="linux" and os.geteuid()==0,"private proper-EE Root only")
class RootOperatingTerminationPhaseTests(unittest.TestCase):
    def phase(self,name):
        import test_github_runner_incus_full_finalization as fixtures
        value=fixtures.operating_cleanup_fixture("termination:"+name)
        self.assertTrue(value["authorization_unchanged"] and value["deadline_unchanged"] and value["no_new_process"])
        self.assertTrue(value["real_wall_clock_during_wait"])
        self.assertLessEqual(sum(row["arguments"][:2]==["container","stop"] for row in value["commands"]),1)
        return value

    def drained(self,name):
        value=self.phase(name)
        self.assertTrue(value["original_exit_proof_at_return"])
        self.assertFalse(value["child_still_live_at_return"])
        self.assertEqual(value["readiness_calls"], [])
        self.assertEqual(value["actual_Unix_notifications"], [])
        self.assertEqual(len(value["engine_stop_effects"]),1)
        self.assertEqual(value["engine_stop_effects"][0]["state"],"unknown")
        self.assertNotEqual(value["state_at_return"],"closed")
        return value

    def test_normal_ready_emits_exactly_one_actual_unix_frame(self):
        value=self.phase("normal-ready")
        self.assertEqual(value["observed_exit"],23)
        self.assertEqual(len(value["actual_Unix_notifications"]),1)
        self.assertEqual(len(value["readiness_calls"]),1)

    def test_cancel_before_ready_drains_same_unknown_stop_owner(self):
        self.drained("cancel-before-ready")

    def test_previously_attempted_unknown_stop_is_not_retried_or_ready(self):
        self.drained("previous-stop-before-ready")

    def test_existing_root_ack_cannot_reauthorize_ready_during_abort(self):
        self.drained("ready-then-abort")

    def test_cancelled_normal_wait_stops_and_drains_before_ready(self):
        self.drained("normal-cancel-before-ready")

    def test_actual_wall_expiry_before_first_ready_records_expiry_then_drains(self):
        value=self.drained("expiry-before-ready")
        self.assertEqual(value["state_at_return"],"cancelled")
        self.assertGreaterEqual(value["real_wall_at_return"],value["authorization_deadline"])

    def test_actual_wall_expiry_abort_keeps_unknown_stop_and_original_exit(self):
        self.drained("expiry-abort-before-ready")

    def test_already_exited_original_child_is_observed_without_ready_or_stop_retry(self):
        self.drained("previous-stop-child-exited")

    def test_generic_failure_abort_never_runs_live_ready_phase(self):
        self.drained("failure-abort-live-authority")

    def test_real_cancellation_race_stays_denied_then_original_retention_drains(self):
        value=self.phase("ready-race-cancel")
        self.assertEqual(value["production_error"],"Denied:cell-observation-not-live")
        self.assertTrue(value["exit_proof_after_retention"])
        self.assertEqual(value["actual_Unix_notifications"],[])

    def test_wrong_ready_owner_stays_denied_and_never_grants_an_ack(self):
        value=self.phase("wrong-ready-owner")
        self.assertIsNotNone(value["production_error"])
        self.assertTrue(value["exit_proof_after_retention"])
        self.assertEqual(value["actual_Unix_notifications"],[])

    def test_actual_capture_limit_failure_drains_before_live_ready(self):
        value=self.drained("capture-failure-normal")
        self.assertEqual(value["recorded_exit_states"]["stdout_state"],"limited")


if __name__ == "__main__":
    unittest.main()
