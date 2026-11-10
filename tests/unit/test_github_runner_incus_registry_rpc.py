"""Real Unix framing; mocked acquisition does not prove a genuine service."""
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import socket
import struct
import sys
from types import MappingProxyType
import unittest
from unittest import mock

import test_github_runner_incus_admission as admission_fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import admission, ledger, policy_registry, registry_rpc  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


def frame(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return struct.pack("!I", len(raw)) + raw


def reply(client):
    client.settimeout(2)
    def exact(count):
        result = bytearray()
        while len(result) < count:
            part = client.recv(count - len(result))
            if not part:
                raise AssertionError("truncated reply")
            result.extend(part)
        return bytes(result)
    count = struct.unpack("!I", exact(4))[0]
    if not 0 < count <= registry_rpc.MAX_REPLY_BYTES:
        raise AssertionError("unbounded reply")
    value = json.loads(exact(count))
    client.setblocking(False)
    try:
        extra = client.recv(1)
    except BlockingIOError:
        extra = b""
    if extra:
        raise AssertionError("more than one reply")
    return value


class RegistryRPCGuardTests(unittest.TestCase):
    def test_root_guard_precedes_factory_or_socket_work(self):
        with mock.patch.object(registry_rpc.os, "geteuid", return_value=2101):
            with self.assertRaisesRegex(Denied, "registry-rpc-root-required"):
                registry_rpc.RegistryRPC(None)
            instance = object.__new__(registry_rpc.RegistryRPC)
            with self.assertRaisesRegex(Denied, "registry-rpc-root-required"):
                instance.handle(None)

    def test_factory_rejects_arbitrary_registry_or_policy_reader_objects(self):
        with mock.patch.object(registry_rpc.os, "geteuid", return_value=0):
            for value in ({"cell": "caller-path"}, object(), None):
                with self.assertRaises(Denied):
                    registry_rpc.RegistryRPC(value)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "Root private Linux EE fixtures only")
class RootRegistryRPCTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        admission_fixtures.RootAdmissionBridgeTests.setUpClass()

    def setUp(self):
        self.fixture = admission_fixtures.RootAdmissionBridgeTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        selected = self.fixture.policy
        second_path = self.fixture.root / "borrowed-cell.json"
        second_path.write_bytes(self.fixture.cell.read_bytes())
        second_path.chmod(0o600)
        borrowed = replace(selected, identity=replace(selected.identity, required_native_job_name="another-native-cell"),
                           cell_config_path=str(second_path))
        self.registry = policy_registry.Registry("/root/preloaded-registry.json", "a" * 64,
                          MappingProxyType({"approved": selected, "borrowed": borrowed}))
        self.rpc = registry_rpc.RegistryRPC(self.registry)

    def request(self, inner, *, selector=None, raw=None):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            payload = frame({"schema": 1, "cell": "approved"} if selector is None else selector) + frame(inner)
            client.sendall(payload if raw is None else raw)
            client.shutdown(socket.SHUT_WR)
            result = self.rpc.handle(server)
            self.assertEqual(result, reply(client))
            return result
        finally:
            server.close()
            client.close()

    def test_actual_outer_and_inner_frames_reach_real_signed_identity_and_ledger(self):
        challenge = self.request({"schema": 1, "operation": "challenge"})
        self.assertEqual(challenge["status"], "ok")
        admitted = self.request(self.fixture.admit_body(challenge["result"]))
        self.assertEqual(admitted["status"], "ok")
        record = self.fixture.record(admitted["result"]["lease_id"])
        self.assertEqual((record["identity"]["job_id"], record["identity"]["check_run_id"]), (902, 731))
        self.assertEqual(record["cell_sha256"], self.fixture.cell_sha)
        self.assertEqual(self.fixture.collected.call_count, 4)

    def test_lost_real_admit_reply_recovers_exact_lease_without_locator_or_effect_replay(self):
        challenge = self.request({"schema": 1, "operation": "challenge"})
        request = self.fixture.admit_body(challenge["result"])
        with mock.patch.object(registry_rpc, "_write", side_effect=Denied("registry-rpc-write-denied")) as writer:
            with self.assertRaises(Denied):
                self.request(request)
        writer.assert_called_once()
        # Only this Root observer knows the committed locator. The recovering
        # client sends a fresh challenge/token, never the lost lease ID.
        with ledger.Ledger(self.fixture.store_path, clock=admission.time.time) as store:
            with store._transaction() as state:
                self.assertEqual(len(state["leases"]), 1)
                identifier = next(iter(state["leases"]))
            effect = store.begin(identifier, "instance-create", "unknown-owned-effect")
            store.record(identifier, effect, "unknown", evidence_sha256="f" * 64)
            original = store.read(identifier)
        fresh = self.request({"schema": 1, "operation": "challenge"})
        self.fixture.fixture.claims["jti"] = "rpc-lost-admit-recovery-token"
        recovered = self.request(self.fixture.admit_body(fresh["result"], operation="recover"))
        self.assertEqual(recovered["status"], "ok")
        self.assertEqual(recovered["result"], {"schema": 1, "operation": "recover", "lease_id": identifier,
                                               "expires_at": self.fixture.policy.deadline})
        record = self.fixture.record(identifier)
        self.assertEqual(record["effects"], original["effects"])
        self.assertEqual(record["expires_at"], original["expires_at"])
        with ledger.Ledger(self.fixture.store_path, clock=admission.time.time) as store:
            with store._transaction() as state:
                self.assertEqual(set(state["leases"]), {identifier})
            with self.assertRaises(Denied):
                store.begin(identifier, "test", "unknown-is-not-a-retry")

    def test_recover_response_uses_only_existing_safe_lease_fields(self):
        result = {"schema": 1, "operation": "recover", "lease_id": "a" * 32, "expires_at": 1793772300}
        self.assertEqual(registry_rpc._safe_result(result), result)
        for extra in ({"token": "synthetic-secret"}, {"policy": "/root/path"}):
            with self.assertRaises(Denied):
                registry_rpc._safe_result(result | extra)

    def test_borrowed_cell_locator_cannot_authorize_other_native_job(self):
        selector = {"schema": 1, "cell": "borrowed"}
        challenge = self.request({"schema": 1, "operation": "challenge"}, selector=selector)
        self.assertEqual(challenge["status"], "ok")
        denied = self.request(self.fixture.admit_body(challenge["result"]), selector=selector)
        self.assertEqual(denied, {"schema": 1, "status": "denied"})
        with ledger.Ledger(self.fixture.store_path, clock=admission.time.time) as store:
            with store._transaction() as state:
                self.assertEqual(state["leases"], {})
                self.assertEqual(state["tokens"], {})

    def test_missing_extra_unknown_or_path_selector_fields_deny_before_bridge(self):
        selectors = ({"schema": 1}, {"schema": 1, "cell": "approved", "policy": "/caller/policy"},
                     {"schema": 1, "cell": "missing"}, {"schema": True, "cell": "approved"},
                     {"schema": 1, "cell": "../approved"}, {"schema": 1, "cell": "approved", "worker": {}})
        for selected in selectors:
            with self.subTest(fields=tuple(selected)):
                with mock.patch.object(admission, "AdmissionBridge", side_effect=AssertionError("must not instantiate")):
                    self.assertEqual(self.request({"schema": 1, "operation": "challenge"}, selector=selected),
                                     {"schema": 1, "status": "denied"})

    def test_outer_length_duplicate_json_truncation_and_inner_extras_failclosed(self):
        raws = (struct.pack("!I", 0), struct.pack("!I", 513) + b"x" * 513,
                b"\x00\x00", struct.pack("!I", 20) + b"{}",
                struct.pack("!I", len(b'{"schema":1,"cell":"approved","cell":"borrowed"}'))
                + b'{"schema":1,"cell":"approved","cell":"borrowed"}',
                frame({"schema": 1, "cell": "approved"})
                + frame({"schema": 1, "operation": "challenge"}) + b"extra")
        for raw in raws:
            with self.subTest(length=len(raw)):
                self.assertEqual(self.request({}, raw=raw), {"schema": 1, "status": "denied"})

    def test_same_socket_object_and_actual_kernel_peer_are_preserved_to_bridge(self):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            credentials = server.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            client.sendall(frame({"schema": 1, "cell": "approved"}) + frame({"schema": 1, "operation": "challenge"}))
            client.shutdown(socket.SHUT_WR)
            seen = []
            def existing_handle(bridge, connected):
                seen.append(connected)
                self.assertIs(connected, server)
                self.assertEqual(connected.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12), credentials)
                self.assertEqual(admission._request(connected, True), {"schema": 1, "operation": "challenge"})
                return {"schema": 1, "operation": "challenge", "nonce": "a" * 64,
                        "audience": ledger.AUDIENCE + "a" * 64, "expires_at": 1793772300}
            with mock.patch.object(admission.AdmissionBridge, "handle", existing_handle):
                self.rpc.handle(server)
            self.assertEqual(len(seen), 1)
            self.assertEqual(reply(client)["status"], "ok")
        finally:
            server.close()
            client.close()

    def test_exception_and_unsafe_bridge_result_never_disclose_secret_or_raw_data(self):
        for response in (RuntimeError("SYNTHETIC_SECRET /private/path JWT body"),
                         {"schema": 1, "operation": "admit", "lease_id": "a" * 32,
                          "expires_at": 1793772300, "token": "SYNTHETIC_SECRET"}):
            output = io.StringIO()
            effects = {"side_effect": response} if isinstance(response, Exception) else {"return_value": response}
            with mock.patch.object(admission.AdmissionBridge, "handle", **effects), \
                 mock.patch("sys.stdout", output), mock.patch("sys.stderr", output):
                result = self.request({"schema": 1, "operation": "challenge"})
            self.assertEqual(result, {"schema": 1, "status": "denied"})
            self.assertEqual(output.getvalue(), "")

    def test_response_failure_never_replays_operation_or_attempts_second_frame(self):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.sendall(frame({"schema": 1, "cell": "approved"}) + frame({"schema": 1, "operation": "challenge"}))
            client.shutdown(socket.SHUT_WR)
            safe = {"schema": 1, "operation": "admit", "lease_id": "a" * 32, "expires_at": 1793772300}
            with mock.patch.object(admission.AdmissionBridge, "handle", return_value=safe) as bridge, \
                 mock.patch.object(registry_rpc, "_write", side_effect=Denied("registry-rpc-write-denied")) as writer:
                with self.assertRaises(Denied):
                    self.rpc.handle(server)
            bridge.assert_called_once_with(server)
            writer.assert_called_once()
        finally:
            server.close()
            client.close()

    def test_reply_write_has_deadline_without_sleep_or_operation_retry(self):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            with mock.patch.object(registry_rpc.select, "select", return_value=([], [], [])):
                with self.assertRaises(Denied):
                    registry_rpc._write(server, {"schema": 1, "status": "denied"})
        finally:
            server.close()
            client.close()

    def test_actual_partial_reply_then_broken_pipe_never_sends_another_outcome(self):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.sendall(frame({"schema": 1, "cell": "approved"}) + frame({"schema": 1, "operation": "challenge"}))
            client.shutdown(socket.SHUT_WR)
            safe = {"schema": 1, "operation": "admit", "lease_id": "a" * 32, "expires_at": 1793772300}
            original_send, sends = socket.socket.send, []
            def partial_then_fail(connected, data, flags=0):
                self.assertIs(connected, server)
                sends.append(len(data))
                if len(sends) == 1:
                    return original_send(connected, data[:3], flags)
                raise BrokenPipeError("SYNTHETIC_SECRET")
            with mock.patch.object(admission.AdmissionBridge, "handle", return_value=safe) as bridge, \
                 mock.patch.object(socket.socket, "send", partial_then_fail):
                with self.assertRaisesRegex(Denied, "registry-rpc-write-denied"):
                    self.rpc.handle(server)
            bridge.assert_called_once_with(server)
            self.assertEqual(len(sends), 2)
            client.settimeout(2)
            self.assertEqual(len(client.recv(32)), 3)
            client.setblocking(False)
            with self.assertRaises(BlockingIOError):
                client.recv(1)
        finally:
            server.close()
            client.close()


if __name__ == "__main__":
    unittest.main()
