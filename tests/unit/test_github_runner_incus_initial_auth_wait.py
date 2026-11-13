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
    def exchange(self, operation, delay):
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
        connection = (connected, None, None, None, None)
        with patch.object(client, "_authentication", return_value=authentication), \
                patch.object(client, "_connect", return_value=connection), \
                patch.object(client, "_stable"), patch.object(client, "_close"), \
                patch.dict(client.os.environ, {"GITHUB_TOKEN": fixture.API}), \
                patch.dict(client._CONFIGURATIONS, {}, clear=True):
            result = client._authenticate("registered-cell", operation)
        thread.join(timeout=2)
        self.assertIs(result, connection)
        self.assertFalse(failures)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["nonce"], fixture.NONCE)

    def test_execution_and_observer_wait_for_real_challenge_after_five_second_frame_budget(self):
        for operation in ("run", "observe-profile"):
            with self.subTest(operation=operation):
                self.exchange(operation, client.FRAME_SECONDS + 0.2)

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

    def test_floor_cannot_raise_maximum_or_accept_malformed_clock_claim(self):
        from incus_lease_issuer import runtime_rpc
        from incus_lease_issuer.identity import Denied
        for minimum in (True, 0, 301, "180"):
            with self.subTest(minimum=minimum), self.assertRaises(Denied):
                runtime_rpc._initial_transition_budget(self.config(minimum), 1600, 1000)
        for expiry, now in ((True, 1000), (1600, float("nan")), (1600, float("inf")), (1600, True)):
            with self.subTest(expiry=expiry, now=now), self.assertRaises(Denied):
                runtime_rpc._initial_transition_budget(self.config(), expiry, now)


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
