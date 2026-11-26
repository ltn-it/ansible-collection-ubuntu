"""Actual local socket/CLI contract; modeled server is not native Root admission."""
from contextlib import redirect_stdout
import os
import sys
import io
import socket
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_github_runner_incus_runtime_client as fixture

client = fixture.client


class InitialChallengeTests(unittest.TestCase):
    def exchange(self, operation, delay, *, derived=False, early_renewal=False):
        connected, server = socket.socketpair()
        self.addCleanup(connected.close)
        self.addCleanup(server.close)
        frames, failures = [], []
        def serve():
            try:
                request = fixture.receive(server)
                time.sleep(delay)
                server.sendall(fixture.frame({"schema": 2, "type": "challenge", "operation": operation,
                    "nonce": fixture.NONCE, "audience": "urn:test:" + fixture.NONCE,
                    "expires_at": int(time.time()) + 60}))
                frames.append(fixture.receive(server))
            except Exception as error:
                failures.append(type(error).__name__)
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        authentication = SimpleNamespace(AUDIENCE="urn:test:", _secret=lambda value: value,
                                          _oidc=lambda audience: fixture.TOKEN)
        connection = (connected, (None, None, None, False), None, None, None)
        configurations = {"registered-cell": "a" * 64} if derived else {}
        renewals = {"registered-cell": 150} if early_renewal else {}
        original_select = client.select.select

        def wait_for_challenge(readable, writable, exceptional, timeout):
            # Model C23's observed 62.514-second pre-challenge work without
            # waiting a full minute on every test run.
            observed = 92.119 if operation == "heartbeat" and early_renewal else 62.514
            if derived and 5 < timeout < observed:
                return [], [], []
            return original_select(readable, writable, exceptional, timeout)

        with patch.object(client, "_authentication", return_value=authentication), \
                patch.object(client, "_connect", return_value=connection), \
                patch.object(client, "_stable"), patch.object(client, "_close"), \
                patch.object(client.select, "select", side_effect=wait_for_challenge), \
                patch.object(client, "_authenticated_reply", wraps=client._authenticated_reply) as wait, \
                patch.dict(client.os.environ, {"GITHUB_TOKEN": fixture.API}), \
                patch.dict(client._CONFIGURATIONS, configurations, clear=True), \
                patch.dict(client._RENEWAL_LEADS, renewals, clear=True):
            result = client._authenticate("registered-cell", operation, fixture.LEASE if operation == "heartbeat" else None)
        thread.join(timeout=2)
        self.assertIs(result, connection)
        self.assertFalse(failures)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["nonce"], fixture.NONCE)
        expected_idle = 120 if operation == "heartbeat" and early_renewal else 90
        self.assertEqual(wait.call_args.kwargs, {"idle_seconds": expected_idle} if derived else {})

    def test_execution_and_observer_wait_for_real_challenge_after_five_second_frame_budget(self):
        for operation in ("run", "observe-profile"):
            with self.subTest(operation=operation):
                self.exchange(operation, client.FRAME_SECONDS + 0.2)

    def test_derived_locator_survives_observed_pre_challenge_delay(self):
        self.exchange("run", 0.01, derived=True)

    def test_early_renewal_allows_observed_heartbeat_delay_only_for_heartbeat(self):
        self.exchange("heartbeat", 0.01, derived=True, early_renewal=True)
        self.exchange("run", 0.01, derived=True, early_renewal=True)

    def test_auth_wait_timeout_denies_without_reading_a_frame_or_sending_auth(self):
        connected, server = socket.socketpair()
        self.addCleanup(connected.close)
        self.addCleanup(server.close)
        with patch.object(client.select, "select", return_value=([], [], [])) as wait, \
                patch.object(client, "_receive", side_effect=AssertionError("no frame without readiness")):
            with self.assertRaises(client.ClientDenied):
                client._authenticated_reply(connected)
        self.assertEqual(wait.call_args.args[-1], 60)
        self.assertEqual(client.FRAME_SECONDS, 5)


    def test_final_observers_await_the_original_root_result_with_bounded_idle(self):
        connection, peer = socket.socketpair()
        self.addCleanup(connection.close)
        self.addCleanup(peer.close)

        def measured_readiness(readable, writable, exceptional, timeout):
            # Six retained-history scans plus the controller reads can pass
            # the former 180-second client ceiling while the Root proof is live.
            return (readable, writable, exceptional) if timeout > 192 else ([], [], [])

        for observe, arguments in ((client.observe_profile, ("heavy", "keycloak-heavy", "ubuntu-24.04")),
                                   (client.observe_operating, ("failure",))):
            with self.subTest(operation=observe.__name__), \
                    patch.object(client, "_authenticate", return_value=(connection,)) as authenticate, \
                    patch.object(client, "_close"), \
                    patch.object(client.select, "select", side_effect=measured_readiness) as wait, \
                    patch.object(client, "_receive", return_value={"type": "unrecognized"}) as read_frame:
                with self.assertRaises(client.ClientDenied):
                    observe(*arguments)
            self.assertEqual(authenticate.call_count, 1)
            self.assertEqual(wait.call_args.args[-1], 240)
            read_frame.assert_called_once_with(connection)
            self.assertEqual(client.FRAME_SECONDS, 5)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root proper EE only")
class CapabilityTests(unittest.TestCase):
    setUp = fixture.RootRuntimeClientTests.setUp
    accept = fixture.RootRuntimeClientTests.accept
    serve = fixture.RootRuntimeClientTests.serve
    finish = fixture.RootRuntimeClientTests.finish

    def test_closed_required_capability_canonical_record_is_local_only(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = client.main(["check", "--require-capability", "initial-auth-idle-v1"])
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), '{"authentication_idle_seconds":60,"capabilities":'
            '["initial-auth-idle-v1"],"frame_seconds":5,"operation":"check","schema":2,'
            '"state":"local-prerequisites-only"}\n')
        self.auth._oidc.assert_not_called()
        self.assertEqual(self.requests, [])

    def test_unknown_or_duplicate_capability_denies_before_any_root_connection(self):
        for argv in (["check", "--require-capability", "arbitrary"],
                     ["check", "--require-capability", "initial-auth-idle-v1",
                      "--require-capability", "initial-auth-idle-v1"]):
            with self.subTest(argv=argv), patch.object(client, "_connect") as connected, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(client.main(argv), 2)
                connected.assert_not_called()
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class InitialBudgetTests(unittest.TestCase):
    """Synthetic times exercise the production reduction-only timer calculation."""
    def config(self, minimum=180):
        from incus_lease_issuer import runtime_rpc
        from types import MappingProxyType
        return runtime_rpc._Configuration("/fixed/config", "a" * 64, "/fixed/registry", "b" * 64,
            "/fixed/preparation", "c" * 64, 60, 300, 30, 600, MappingProxyType({}),
            initial_transition_minimum_seconds=minimum)

    def test_signed_three_hundred_second_claim_is_reduced_not_extended(self):
        from incus_lease_issuer import runtime_rpc
        config = self.config()
        self.assertEqual(runtime_rpc._initial_transition_budget(config, 1300, 1000), (268, 1269))
        self.assertEqual(runtime_rpc._initial_transition_budget(config, 1300, 1000.25), (267, 1269))
        self.assertEqual(runtime_rpc._initial_transition_budget(config, 1600, 1000), (300, 1569))
        self.assertEqual(config.initial_transition_timeout_seconds, 300)

    def test_floor_boundary_and_legacy_absence_require_budget_before_any_lease(self):
        from incus_lease_issuer import runtime_rpc
        from incus_lease_issuer.identity import Denied
        self.assertEqual(runtime_rpc._initial_transition_budget(self.config(), 1212, 1000), (180, 1181))
        for config, expiry in ((self.config(), 1211), (self.config(None), 1300)):
            with self.subTest(expiry=expiry, minimum=config.initial_transition_minimum_seconds):
                with self.assertRaisesRegex(Denied, "runtime-initial-authorization-budget"):
                    runtime_rpc._initial_transition_budget(config, expiry, 1000)
        self.assertEqual(runtime_rpc._initial_transition_budget(self.config(None), 1600, 1000), (300, 1569))

    def test_derived_initial_budget_keeps_the_full_catalogue_renewal_window(self):
        from incus_lease_issuer import runtime_rpc
        from incus_lease_issuer.identity import Denied
        config = self.config()
        with patch.object(client.time, "time", return_value=1000), \
             patch.dict(client._CONFIGURATIONS, {"test-cell": "a" * 64}, clear=True):
            self.assertEqual(client._heartbeat_at("test-cell", 1286), 1196)
            self.assertEqual(client._heartbeat_at("fixed-cell", 1286), 1256)
            self.assertEqual(client._heartbeat_at("test-cell", 1060), 1030)
        self.assertEqual(runtime_rpc._initial_transition_budget(config, 1286, 1000, derived=True), (194, 1195))
        self.assertEqual(runtime_rpc._initial_transition_budget(config, 1272, 1000, derived=True), (180, 1181))
        with self.assertRaisesRegex(Denied, "runtime-initial-authorization-budget"):
            runtime_rpc._initial_transition_budget(config, 1271, 1000, derived=True)

    def test_floor_cannot_raise_maximum_or_accept_malformed_clock_claim(self):
        from incus_lease_issuer import runtime_rpc
        from incus_lease_issuer.identity import Denied
        for minimum in (True, 0, 301, "180"):
            with self.subTest(minimum=minimum), self.assertRaises(Denied):
                runtime_rpc._initial_transition_budget(self.config(minimum), 1600, 1000)
        for expiry, now in ((True, 1000), (1600, float("nan")), (1600, float("inf")), (1600, True)):
            with self.subTest(expiry=expiry, now=now), self.assertRaises(Denied):
                runtime_rpc._initial_transition_budget(self.config(), expiry, now)

    def test_early_renewal_reserves_time_before_the_original_authorization_expires(self):
        from dataclasses import replace
        from incus_lease_issuer import runtime_rpc
        from incus_lease_issuer.identity import Denied
        config = replace(self.config(120), renewal_lead_seconds=150)
        # C24's original native authorization had 286 s left at lease creation.
        self.assertEqual(runtime_rpc._initial_transition_budget(config, 1286, 1000, derived=True), (134, 1135))
        with patch.object(client.time, "time", return_value=1000), \
             patch.dict(client._CONFIGURATIONS, {"test-cell": "a" * 64}, clear=True), \
             patch.dict(client._RENEWAL_LEADS, {"test-cell": 150}, clear=True):
            renewal = client._heartbeat_at("test-cell", 1286)
            self.assertEqual(renewal, 1143)
            self.assertLess(renewal + client.EARLY_RENEWAL_PRE_CHALLENGE_SECONDS, 1286)
            self.assertGreater(1286 - (renewal + 92.119), 50)
        with self.assertRaisesRegex(Denied, "runtime-initial-authorization-budget"):
            runtime_rpc._initial_transition_budget(config, 1271, 1000, derived=True)
        for policy in ({"renewal_lead_seconds": 149, "initial_transition_minimum_seconds": 120},
                       {"renewal_lead_seconds": 150, "initial_transition_minimum_seconds": 180},
                       {"renewal_lead_seconds": 150}):
            with self.subTest(policy=policy), self.assertRaisesRegex(Denied, "runtime-early-renewal-policy"):
                runtime_rpc._validate_early_renewal(policy)
        runtime_rpc._validate_early_renewal({"renewal_lead_seconds": 150, "initial_transition_minimum_seconds": 120})


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootInitialBudgetTests(unittest.TestCase):
    """Real sealed configuration, Unix RPC and Ledger; native provider is modeled."""
    from test_github_runner_incus_runtime_rpc import RootRuntimeTests as _fixture
    setUpClass = classmethod(lambda cls: cls._fixture.setUpClass())
    setUp = _fixture.setUp
    seal = _fixture.seal
    invoke = _fixture.invoke

    def test_root_sealed_floor_is_checked_before_runtime_prepare(self):
        from incus_lease_issuer import ledger
        self.value.update(initial_transition_timeout_seconds=300, initial_transition_minimum_seconds=180)
        self.seal()
        self.assertEqual(self.rpc._config.initial_transition_minimum_seconds, 180)
        before = self.store.read(self.lease)
        with patch.object(ledger.Ledger, "runtime_prepare", autospec=True) as prepare:
            result, replies = self.invoke("run", token_changes={"exp": int(time.time()) + 200})
        prepare.assert_not_called()
        self.assertEqual(result["disposition"], "denied-before-intent")
        self.assertEqual([reply["type"] for reply in replies], ["challenge", "failure"])
        self.assertEqual(self.store.read(self.lease), before)

    def test_invalid_sealed_floor_rejected_and_absent_field_retains_legacy(self):
        from incus_lease_issuer.identity import Denied
        for floor in (True, 0, 301, "180"):
            self.value.update(initial_transition_timeout_seconds=300, initial_transition_minimum_seconds=floor)
            with self.subTest(floor=floor), self.assertRaises(Denied):
                self.seal()
        self.value.pop("initial_transition_minimum_seconds")
        self.seal()
        self.assertIsNone(self.rpc._config.initial_transition_minimum_seconds)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootBootstrapInitialBudgetTests(unittest.TestCase):
    from test_github_runner_incus_run_factory import RootBootstrapTests as _fixture
    setUpClass = classmethod(lambda cls: cls._fixture.setUpClass())
    setUp = _fixture.setUp
    seal = _fixture.seal

    def test_bootstrap_accepts_only_root_sealed_bounded_floor(self):
        from incus_lease_issuer.identity import Denied
        self.assertNotIn("initial_transition_minimum_seconds", self.bootstrap.value["runtime"])
        self.value["runtime"].update(initial_transition_timeout_seconds=300,
                                     initial_transition_minimum_seconds=180)
        self.seal()
        self.assertEqual(self.bootstrap.value["runtime"]["initial_transition_minimum_seconds"], 180)
        for minimum in (True, 0, 301, "180"):
            self.value["runtime"]["initial_transition_minimum_seconds"] = minimum
            with self.subTest(minimum=minimum), self.assertRaises(Denied):
                self.seal()
