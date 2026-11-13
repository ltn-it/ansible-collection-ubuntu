"""Bounded private diagnostics; synthetic requests never qualify native admission."""
import contextvars
import json
import os
from pathlib import Path
import socket
import sys
import syslog
from types import SimpleNamespace
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import identity, run_factory, runtime_rpc


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.uid = mock.patch.object(os, "geteuid", return_value=0)
        self.uid.start()
        self.addCleanup(self.uid.stop)
        self.sink = mock.patch.object(socket, "socket")
        self.socket = self.sink.start()
        self.log = self.socket.return_value.__enter__.return_value.sendto
        self.addCleanup(self.sink.stop)

    def record(self, index=-1):
        raw, destination = self.log.call_args_list[index].args
        self.assertEqual(destination, "/dev/log")
        prefix = "<" + str(syslog.LOG_AUTHPRIV | syslog.LOG_ERR) + ">lit-incus-runtime-v2: "
        self.assertTrue(raw.startswith(prefix.encode()))
        self.assertLess(len(raw), 4096)
        self.socket.assert_called_with(socket.AF_UNIX,
                                       socket.SOCK_DGRAM | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
        value = json.loads(raw[len(prefix):])
        self.assertEqual(set(value), {"schema", "component", "stage", "reason", "wall_ms", "cpu_ms", "counts"})
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["component"], "incus-runtime-v2")
        for key in ("wall_ms", "cpu_ms"):
            self.assertIs(type(value[key]), int)
            self.assertGreaterEqual(value[key], 0)
            self.assertLessEqual(value[key], 86400000)
        return value

    def test_success_and_inactive_helpers_do_not_log(self):
        @identity._diagnostic_step("collector")
        def success():
            return "same-result"
        self.assertEqual(success(), "same-result")
        with identity._diagnostic_request():
            self.assertEqual(success(), "same-result")
        self.assertIsNone(identity._DIAGNOSTIC.get())
        self.log.assert_not_called()

    def test_exact_allowlist_never_formats_or_reflects_exceptions(self):
        class EvilString(str):
            def __hash__(self):
                raise AssertionError("diagnostics hashed an untrusted string subclass")
            def __eq__(self, other):
                raise AssertionError("diagnostics compared an untrusted string subclass")
            def __str__(self):
                raise AssertionError("diagnostics formatted an untrusted string subclass")
        class EvilException(Exception):
            def __getattribute__(self, name):
                raise AssertionError("diagnostics inspected a foreign exception")
            def __str__(self):
                raise AssertionError("diagnostics formatted a foreign exception")
            def __repr__(self):
                raise AssertionError("diagnostics represented a foreign exception")
        class ForeignDenied(identity.Denied):
            def __getattribute__(self, name):
                raise AssertionError("diagnostics inspected a foreign Denied subclass")
        cases = [identity.Denied(), identity.Denied("synthetic-secret-api"),
                 identity.Denied("stale-observation", "synthetic-secret-oidc"),
                 identity.Denied(["stale-observation"]), identity.Denied({"token": "synthetic-secret-api"}),
                 identity.Denied("stale-observation\nsynthetic-secret-api"),
                 identity.Denied("stale-observation\x00"), identity.Denied("x" * 100000),
                 identity.Denied(EvilString("stale-observation")), EvilException(), ForeignDenied()]
        for error in cases:
            with identity._diagnostic_request():
                identity._diagnostic_failed("native-assignment", error)
            self.assertEqual(self.record()["reason"], "unclassified")
        with identity._diagnostic_request():
            identity._diagnostic_failed("native-assignment", identity.Denied("stale-observation"))
        self.assertEqual(self.record()["reason"], "stale-observation")
        self.assertNotIn("synthetic-secret", str(self.log.call_args_list))

    def test_first_inner_error_survives_wrapping_with_one_terminal_record(self):
        @identity._diagnostic_step("collector")
        def inner():
            raise identity.Denied("collector-maps-changed")
        @identity._diagnostic_step("native-current")
        def outer():
            try:
                inner()
            except identity.Denied:
                raise identity.Denied("bootstrap-native-denied") from None
        with self.assertRaisesRegex(identity.Denied, "bootstrap-native-denied"):
            with identity._diagnostic_request():
                outer()
        self.log.assert_called_once()
        value = self.record()
        self.assertEqual((value["stage"], value["reason"]), ("collector", "collector-maps-changed"))
        self.assertEqual(value["counts"], [["collector", 1, 0], ["native-current", 1, 0]])
        self.assertIsNone(identity._DIAGNOSTIC.get())

    def test_nested_and_copied_contexts_do_not_mutate_parent_state(self):
        with identity._diagnostic_request():
            contextvars.copy_context().run(identity._diagnostic_failed, "collector",
                                          identity.Denied("collector-maps-changed"))
            self.assertIsNone(identity._DIAGNOSTIC.get().stage)
            identity._diagnostic_failed("native-current", identity.Denied("stale-observation"))
            before = identity._DIAGNOSTIC.get()
            with identity._diagnostic_request():
                identity._diagnostic_failed("observer-lookup", identity.Denied("run-config-lookup-unique"))
            self.assertIs(identity._DIAGNOSTIC.get(), before)
        self.assertEqual(self.log.call_count, 2)
        self.assertEqual(self.record(0)["stage"], "observer-lookup")
        self.assertEqual(self.record(1)["stage"], "native-current")
        self.assertIsNone(identity._DIAGNOSTIC.get())

    def test_counts_saturate_and_unknown_stage_is_not_reflected(self):
        @identity._diagnostic_step("installation")
        def read():
            return 17
        with identity._diagnostic_request():
            for _ in range(1100):
                self.assertEqual(read(), 17)
            identity._diagnostic_failed("synthetic-secret-selector", identity.Denied("stale-observation"))
            self.assertIsNone(identity._DIAGNOSTIC.get().stage)
            identity._diagnostic_failed("collector", identity.Denied("collector-maps-changed"))
        self.assertEqual(self.record()["counts"], [["installation", 1024, 1024]])
        with self.assertRaisesRegex(ValueError, "unknown-private-diagnostic-stage"):
            identity._diagnostic_step("synthetic-secret-selector")

    def test_sink_failure_preserves_original_exception_and_no_output(self):
        error = identity.Denied("stale-observation")
        self.log.side_effect = BlockingIOError("synthetic-secret-syslog-error")
        with self.assertRaises(identity.Denied) as raised:
            with identity._diagnostic_request():
                identity._diagnostic_failed("native-assignment", error)
                raise error
        self.assertIs(raised.exception, error)
        self.log.assert_called_once()
        self.assertIsNone(identity._DIAGNOSTIC.get())

    def bootstrap(self):
        obj = runtime_rpc.BootstrapRuntimeRPC.__new__(runtime_rpc.BootstrapRuntimeRPC)
        obj._bootstrap = SimpleNamespace(path="/fixed-private-bootstrap", sha256="a" * 64)
        bootstrap = SimpleNamespace(value={"runtime": {"authentication_timeout_seconds": 60}})
        self.enterContext(mock.patch.object(runtime_rpc.admission, "_socket"))
        self.enterContext(mock.patch.object(run_factory, "load_bootstrap", return_value=bootstrap))
        self.enterContext(mock.patch.object(runtime_rpc, "_read", return_value={
            "schema": 2, "cell": "approved-heavy", "operation": "run"}))
        writes = self.enterContext(mock.patch.object(runtime_rpc, "_write"))
        return obj, writes

    def test_before_intent_frame_and_denial_survive_logging_failure(self):
        obj, writes = self.bootstrap()
        self.enterContext(mock.patch.object(run_factory, "challenge_bootstrap",
                                           side_effect=identity.Denied("collector-maps-changed")))
        create = self.enterContext(mock.patch.object(run_factory, "create_run_configuration"))
        self.log.side_effect = RuntimeError("synthetic-secret-log-error")
        expected = {"schema": 2, "type": "failure", "operation": "run", "disposition": "denied-before-intent"}
        self.assertEqual(obj.handle(object()), expected)
        self.assertEqual(writes.call_args.args[1], expected)
        self.assertEqual(writes.call_count, 1)
        create.assert_not_called()
        self.log.assert_called_once()

    def test_staged_failure_keeps_unknown_hold_and_no_secret_in_log(self):
        obj, writes = self.bootstrap()
        self.enterContext(mock.patch.object(run_factory, "challenge_bootstrap", return_value={
            "nonce": "c" * 64, "audience": "synthetic-secret-audience", "expires_at": 1234}))
        self.enterContext(mock.patch.object(runtime_rpc, "_authentication", return_value={
            "nonce": "c" * 64, "token": "synthetic-secret-oidc", "api_token": "synthetic-secret-api"}))
        self.enterContext(mock.patch.object(run_factory, "verify_bootstrap_native", return_value=object()))
        @identity._diagnostic_step("intake-discovery")
        def fail(*args):
            raise identity.Denied("intake-artifact-digest")
        self.enterContext(mock.patch.object(run_factory, "create_run_configuration", side_effect=fail))
        expected = {"schema": 2, "type": "failure", "operation": "run", "disposition": "unknown-hold"}
        self.assertEqual(obj.handle(object()), expected)
        self.assertEqual(writes.call_count, 2)  # Original challenge and sole original failure.
        self.assertEqual(writes.call_args.args[1], expected)
        self.log.assert_called_once()
        self.assertEqual(self.record()["stage"], "intake-discovery")
        self.assertNotIn(b"synthetic-secret", self.log.call_args.args[0])
        self.assertNotIn(b"c" * 64, self.log.call_args.args[0])

    def test_successful_intake_preserves_original_reply_without_diagnostics(self):
        obj, writes = self.bootstrap()
        self.enterContext(mock.patch.object(run_factory, "challenge_bootstrap", return_value={
            "nonce": "c" * 64, "audience": "synthetic-secret-audience", "expires_at": 1234}))
        self.enterContext(mock.patch.object(runtime_rpc, "_authentication", return_value={
            "nonce": "c" * 64, "token": "synthetic-secret-oidc", "api_token": "synthetic-secret-api"}))
        self.enterContext(mock.patch.object(run_factory, "verify_bootstrap_native",
                                           return_value=SimpleNamespace(policy=object())))
        self.enterContext(mock.patch.object(run_factory, "create_run_configuration", return_value=SimpleNamespace(
            manifest_sha256="d" * 64, deadline=4321)))
        self.enterContext(mock.patch.object(run_factory, "require_bootstrap_native"))
        self.enterContext(mock.patch.object(obj, "_binding"))
        expected = {"schema": 2, "type": "intake-ready", "operation": "run", "cell": "approved-heavy",
                    "configuration": "d" * 64, "deadline": 4321, "lease_created": False}
        self.assertEqual(obj.handle(object()), expected)
        self.assertEqual(writes.call_count, 2)
        self.assertEqual(writes.call_args.args[1], expected)
        self.socket.assert_not_called()

    def test_unavailable_journal_socket_never_replaces_original_denial(self):
        self.socket.side_effect = PermissionError("synthetic-secret-socket-error")
        error = identity.Denied("stale-observation")
        with self.assertRaises(identity.Denied) as raised:
            with identity._diagnostic_request():
                identity._diagnostic_failed("native-assignment", error)
                raise error
        self.assertIs(raised.exception, error)
        self.socket.assert_called_once()
        self.log.assert_not_called()
        self.assertIsNone(identity._DIAGNOSTIC.get())

    def test_handed_off_inner_failure_gets_no_second_reply(self):
        obj, writes = self.bootstrap()
        message = {"schema": 2, "cell": "approved-heavy", "operation": "run", "configuration": "b" * 64}
        self.enterContext(mock.patch.object(runtime_rpc, "_read", return_value=message))
        self.enterContext(mock.patch.object(run_factory, "_worker"))
        self.enterContext(mock.patch.object(run_factory, "resolve_configuration", return_value=SimpleNamespace(
            runtime_config_path="/fixed-private-runtime", runtime_config_sha256="d" * 64)))
        def fail(connected, selected):
            identity._diagnostic_failed("runtime-selected", identity.Denied("stale-observation"))
            runtime_rpc._write(connected, {"schema": 2, "type": "failure", "operation": "run",
                                          "disposition": "unknown-hold"})
            raise identity.Denied("runtime-delivery-unknown")
        inner = self.enterContext(mock.patch.object(runtime_rpc, "RuntimeRPC"))
        inner.return_value._handle_selected.side_effect = fail
        self.assertEqual(obj.handle(object()), {"type": "failure"})
        self.assertEqual(writes.call_count, 1)
        self.log.assert_called_once()
        self.assertEqual(self.record()["stage"], "runtime-selected")


if __name__ == "__main__":
    unittest.main()
