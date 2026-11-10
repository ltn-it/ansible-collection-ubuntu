"""Runtimev2 real Unix framing, RSA/native fixture, Ledger and signed refresh.

Private fixtures model GitHub and unavailable kernel/network observations only;
no operating acceptance, native job, Podman or evidence-export qualification.
"""
import hashlib
import io
import tarfile
import json
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time
import unittest
from unittest import mock

import test_github_runner_incus_refresh as fixtures
import test_github_runner_incus_admission as admission_fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import runtime_rpc, identity, ledger, preparation, engine_policy, root_session
from incus_lease_issuer.identity import Denied


def frame(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return struct.pack("!I", len(raw)) + raw


def receive(connected):
    def exact(count):
        raw = bytearray()
        while len(raw) < count:
            part = connected.recv(count-len(raw))
            if not part:
                raise AssertionError("unexpected response EOF")
            raw.extend(part)
        return bytes(raw)
    return json.loads(exact(struct.unpack("!I", exact(4))[0]))


class RuntimeGuardTests(unittest.TestCase):
    def test_root_no_caller_registry_transport_or_claim_hooks(self):
        with mock.patch.object(os, "geteuid", return_value=2101):
            with self.assertRaisesRegex(Denied, "runtime-root-required"):
                runtime_rpc.RuntimeRPC(None, None)
        for override in ({"worker": {}}, {"registry": {}}, {"reader": object()}, {"qualified": True}):
            with self.assertRaises(TypeError):
                runtime_rpc.RuntimeRPC(None, None, **override)

    def test_strict_selector_duplicates_schema_and_command_fields(self):
        for raw in (b'{"schema":2,"schema":2,"cell":"approved","operation":"status"}',
                    b'{"schema":true,"cell":"approved","operation":"status"}',
                    b'{"schema":2,"cell":"approved","operation":"status","command":"sh"}',
                    b'{"schema":2,"cell":"../approved","operation":"run"}'):
            with self.subTest(raw=raw), admission_fixtures._pair() as (server, client):
                client.sendall(struct.pack("!I", len(raw)) + raw)
                with self.assertRaises(Denied):
                    runtime_rpc._selector(server)

    def test_auth_operation_nonce_and_trailing_bytes_are_exact(self):
        body = {"schema": 2, "operation": "status", "nonce": "a"*64,
                "token": "synthetic-oidc", "api_token": "synthetic-api", "lease_id": "b"*32}
        for change, tail in (({"operation": "cancel"}, b""), ({"nonce": "c"*64}, b""), ({}, b"x")):
            with admission_fixtures._pair() as (server, client):
                client.sendall(frame({**body, **change}) + tail)
                client.shutdown(socket.SHUT_WR)
                with self.assertRaises(Denied):
                    runtime_rpc._authentication(server, "status", "a"*64, 1)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.RootRefreshTests.setUpClass()

    def setUp(self):
        self.fixture = fixtures.RootRefreshTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.store, self.lease = self.fixture.store, self.fixture.lease
        self.config = self.fixture.io.root / "runtime-v2.json"
        descriptor = identity.decode_json(self.fixture.io.prepared.engine_descriptor_bytes)
        self.value = {"schema": 2, "registry_path": self.fixture.registry.path,
            "registry_sha256": self.fixture.registry.sha256,
            "preparation_config_path": str(self.fixture.io.config), "preparation_config_sha256": self.fixture.io.sha,
            "authentication_timeout_seconds": 5, "initial_transition_timeout_seconds": 60,
            "heartbeat_lead_seconds": 30, "cleanup_timeout_seconds": 60,
            "capture": {**descriptor["capture"], "max_total_evidence_bytes": 1048576,
                        "max_members": 100, "max_member_bytes": 1048576}}
        self.sequence = 0
        self.seal()

    def seal(self):
        raw = engine_policy._canonical(self.value)
        self.config.write_bytes(raw)
        self.config.chmod(0o600)
        self.sha = hashlib.sha256(raw).hexdigest()
        self.rpc = runtime_rpc.RuntimeRPC(str(self.config), self.sha)

    def invoke(self, operation, *, wrong_nonce=False, wrong_operation=False, selector="approved", token_changes=None):
        replies, errors = [], []
        self.sequence += 1
        def client_job(client):
            try:
                client.settimeout(5)
                client.sendall(frame({"schema": 2, "cell": selector, "operation": operation}))
                challenge = receive(client)
                replies.append(challenge)
                if challenge["type"] != "challenge":
                    return
                now = int(time.time())
                self.fixture.native.claims.update(aud=challenge["audience"], jti="runtime-rpc-"+str(self.sequence),
                                                 iat=now, nbf=now, exp=now+400)
                if token_changes:
                    self.fixture.native.claims.update(token_changes)
                body = {"schema": 2, "operation": "recover" if wrong_operation else operation,
                        "nonce": "0"*64 if wrong_nonce else challenge["nonce"],
                        "token": self.fixture.native.token(), "api_token": "synthetic-job-github-token"}
                if operation in {"heartbeat", "status", "cancel"}:
                    body["lease_id"] = self.lease
                client.sendall(frame(body))
                client.shutdown(socket.SHUT_WR)
                replies.append(receive(client))
            except BaseException as error:
                errors.append(type(error).__name__)
        with admission_fixtures._pair() as (server, client):
            thread = threading.Thread(target=client_job, args=(client,))
            thread.start()
            try:
                result = self.rpc.handle(server)
            finally:
                thread.join(7)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(replies[-1], result)
        return result, replies

    def test_actual_nonrenewing_status_keeps_authorization_effects_and_context(self):
        before = self.store.read(self.lease)
        old = self.fixture.context.joinpath("binding.json").read_bytes()
        result, replies = self.invoke("status")
        self.assertEqual(result["type"], "result")
        self.assertEqual(result["operation"], "status")
        self.assertEqual(len(replies), 2)
        after = self.store.read(self.lease)
        self.assertEqual(after, before)  # Nonce/JTI consumed globally, lease unchanged.
        self.assertEqual(self.fixture.context.joinpath("binding.json").read_bytes(), old)

    def test_actual_recover_returns_original_lease_without_auth_append_or_exit_guess(self):
        before = self.store.read(self.lease)
        result, _ = self.invoke("recover")
        self.assertEqual(result["type"], "terminal")
        self.assertEqual(result["operation"], "recover")
        self.assertEqual(result["lease_id"], self.lease)
        self.assertEqual(result["exit"], {"kind": "unknown", "code": None, "signal": None})
        self.assertEqual(result["capture"], {"state": "unknown", "receipt_sha256": None})
        self.assertEqual(self.store.read(self.lease), before)

    def test_heartbeat_actual_native_proof_publishes_then_renews_once(self):
        before = self.store.read(self.lease)
        with self.fixture.kernel():
            result, _ = self.invoke("heartbeat")
        self.assertEqual(result["type"], "result")
        self.assertEqual(result["operation"], "heartbeat")
        after = self.store.read(self.lease)
        self.assertEqual(len(after["authorizations"]), len(before["authorizations"])+1)
        self.assertEqual(after["expires_at"], before["expires_at"])
        self.assertEqual(len(self.fixture.nft_calls), 1)
        renewals = [row for row in after["effects"].values() if row["operation"] == "fence-renew"]
        self.assertEqual(len(renewals), 1)
        self.assertEqual(renewals[0]["state"], "verified")
        self.assertIn("fence_authorization", renewals[0])
        self.assertEqual(renewals[0]["host_api_authorization"]["authorization_sha256"],
                         ledger.digest(after["authorizations"][-1]))
        self.assertEqual(len(self.fixture.host_sends), 2)  # Maintenance baseline + paired actual grant.

    def test_run_cannot_reprepare_or_repeat_existing_native_invocation(self):
        before = self.store.read(self.lease)
        with mock.patch.object(preparation, "_prepare_locked", side_effect=AssertionError("no replay prepare")):
            result, _ = self.invoke("run")
        self.assertEqual(result["type"], "failure")
        self.assertEqual(self.store.read(self.lease), before)

    def test_wrong_nonce_operation_or_claim_does_not_consume_lease_authority(self):
        before = self.store.read(self.lease)
        for kwargs in ({"wrong_nonce": True}, {"wrong_operation": True}, {"token_changes": {"aud": "borrowed"}}):
            result, _ = self.invoke("status", **kwargs)
            self.assertEqual(result["type"], "failure")
            self.assertEqual(self.store.read(self.lease), before)
            self.assertNotIn("synthetic", json.dumps(result))

    def test_cancel_uses_fixed_ledger_reason_without_renewing_job_authority(self):
        from incus_lease_issuer import network_fence
        before = self.store.read(self.lease)
        # Existing fixture has no engine and a deny-first fence. Native fence
        # transport alone is modeled; no ordinary credential or engine granted.
        with mock.patch.object(network_fence, "disable"):
            result, _ = self.invoke("cancel")
        self.assertEqual(result["type"], "result")
        self.assertEqual(result["state"], "cleanup-hold")
        after = self.store.read(self.lease)
        self.assertEqual(after["state"], "cancelled")
        self.assertEqual(after["cancel_reason"], "cancelled")
        self.assertEqual(after["authorizations"], before["authorizations"])
        self.assertEqual(after["expires_at"], before["expires_at"])
        self.assertFalse(any(e["operation"] == "engine-start" for e in after["effects"].values()))

    def test_recover_after_raw_release_intent_reads_spool_only_without_effect_retry(self):
        from incus_lease_issuer import evidence_export, finalization
        effect = self.store.begin(self.lease, "engine-release", "engine:"+self.lease)
        before = self.store.read(self.lease)
        self.assertEqual(before["effects"][effect]["state"], "intent")
        with mock.patch.object(evidence_export, "read_existing", side_effect=Denied("sealed-spool-unavailable")) as reader, \
             mock.patch.object(evidence_export, "export_existing", side_effect=AssertionError("no raw fallback")), \
             mock.patch.object(finalization.RootFinalizer, "finalize", side_effect=AssertionError("no cleanup retry")):
            result, _ = self.invoke("recover")
        self.assertEqual(result["type"], "terminal")
        self.assertEqual(result["capture"], {"state": "unknown", "receipt_sha256": None})
        self.assertEqual(result["cleanup"], {"state": "hold"})
        reader.assert_called_once()
        self.assertEqual(self.store.read(self.lease), before)

    def test_root_config_drift_denies_before_native_challenge(self):
        self.config.write_bytes(b"{}")
        self.config.chmod(0o600)
        with mock.patch.object(ledger.Ledger, "runtime_challenge", side_effect=AssertionError("no native challenge")):
            result, _ = self.invoke("status")
        self.assertEqual(result["type"], "failure")

    def test_locked_cores_reject_forged_or_closed_sessions_before_effects(self):
        for core, args in ((preparation._prepare_locked, (self.fixture.registry, "approved", self.store, self.lease)),
                           (fixtures.refresh._refresh_locked, (None, self.fixture.registry, "approved", self.store, self.lease))):
            with self.assertRaises(Denied):
                core(object(), *args)
            with root_session._session(str(self.fixture.io.config), self.fixture.io.sha) as session:
                pass
            with self.assertRaises(Denied):
                core(session, *args)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootPublicCaptureStreamTests(unittest.TestCase):
    def setUp(self):
        import test_github_runner_incus_evidence_export as export_fixtures
        self.fixture = export_fixtures.RootExportTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.exported = self.fixture.invoke()

    def test_actual_normalized_archive_stream_matches_sealed_receipt_and_closed_frames(self):
        import base64
        received, errors = [], []
        with admission_fixtures._pair() as (server, client):
            def consume():
                try:
                    client.settimeout(5)
                    for _ in range(1 + self.exported.chunk_count):
                        received.append(receive(client))
                except BaseException as error:
                    errors.append(type(error).__name__)
            thread = threading.Thread(target=consume)
            thread.start()
            try:
                runtime_rpc._stream(server, self.fixture.lease, self.exported)
            finally:
                thread.join(7)
        self.assertEqual(errors, [])
        self.assertFalse(thread.is_alive())
        manifest = received[0]
        self.assertEqual(manifest["sequence"], 2)
        self.assertEqual(manifest["type"], "capture-manifest")
        self.assertEqual(manifest["sha256"], self.exported.sha256)
        raw = bytearray()
        for index, row in enumerate(received[1:]):
            self.assertEqual(set(row), {"schema", "type", "lease_id", "sequence", "offset", "data"})
            self.assertEqual(row["sequence"], index+3)
            self.assertEqual(row["offset"], len(raw))
            self.assertNotIn("=", row["data"])
            chunk = base64.urlsafe_b64decode(row["data"] + "="*((-len(row["data"])) % 4))
            self.assertLessEqual(len(chunk), 4096)
            raw.extend(chunk)
        self.assertEqual(len(raw), self.exported.size)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.exported.sha256)
        self.assertTrue(self.exported.evidence_policy_complete)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            names = archive.getnames()
            self.assertIn("runtime/evidence-policy.json", names)
            self.assertTrue(any(name.startswith("evidence/") for name in names))
            policy = json.load(archive.extractfile("runtime/evidence-policy.json"))
            self.assertIs(policy["evidence_policy_complete"], True)
            self.assertEqual(policy["scope"], "full-sanitized-cell-transfer")

    def test_archive_drift_never_transfers_any_chunk(self):
        Path(self.exported.path).write_bytes(b"substituted")
        Path(self.exported.path).chmod(0o600)
        attempted = []
        with mock.patch.object(runtime_rpc, "_write", side_effect=lambda _, row: attempted.append(row)):
            with self.assertRaises(Denied):
                runtime_rpc._stream(None, self.fixture.lease, self.exported)
        self.assertEqual([row["type"] for row in attempted], ["capture-manifest"])


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootEvidenceAcquisitionBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_github_runner_incus_cell_contract as cell_fixtures
        cell_fixtures.RootCleanupSemanticTests.setUpClass()

    def test_real_runtime_preparation_loader_and_signed_receipt_boundary(self):
        import test_github_runner_incus_cell_contract as cell_fixtures
        from incus_lease_issuer import evidence_export, engine_executor, signed_context
        fixture = cell_fixtures.RootCleanupSemanticTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        engine_fixture = fixture.engine_fixture
        io = engine_fixture.fixture
        runtime = io.root / "boundary-runtime.json"
        capture = identity.decode_json(engine_fixture.manifest.canonical_bytes)["capture"]
        value = {"schema": 2, "registry_path": fixture.registry.path, "registry_sha256": fixture.registry.sha256,
            "preparation_config_path": str(io.config), "preparation_config_sha256": io.sha,
            "authentication_timeout_seconds": 5, "initial_transition_timeout_seconds": 60,
            "heartbeat_lead_seconds": 30, "cleanup_timeout_seconds": 60,
            "capture": {**capture, "max_total_evidence_bytes": 1048576, "max_members": 100, "max_member_bytes": 1048576}}
        runtime.write_bytes(ledger.canonical(value))
        runtime.chmod(0o600)
        sha = hashlib.sha256(runtime.read_bytes()).hexdigest()
        context = identity.decode_json(engine_fixture.prepared.engine_descriptor_bytes)["context_path"]
        raw, binding_proof = signed_context._sealed(context+"/binding.json", 32768)
        original_binding = identity.decode_json(raw)
        original_claims = identity.decode_json(identity.unbase(original_binding["admission"].split(".")[1]))
        effect_id, effect = engine_fixture.engine_effect()
        observations = []
        def retained(config, registry, selector, store, lease_id, receipt):
            # Native-Podman manifest acquisition alone is modeled. ALL Root
            # config/cell/binding locators are actually loaded by _acquire.
            self.assertIs(type(config), preparation.RootConfiguration)
            self.assertEqual(config.path, str(io.config))
            self.assertEqual(config.sha256, io.sha)
            self.assertEqual(receipt.binding_sha256, binding_proof.sha256)
            self.assertEqual(receipt.engine_policy_sha256, original_claims["engine_policy_sha256"])
            self.assertEqual(receipt.lease_id, fixture.lease)
            self.assertIs(registry, fixture.registry)
            self.assertIs(store, fixture.store)
            observations.append(receipt)
            return engine_fixture.manifest, effect_id, effect
        with mock.patch.object(engine_executor, "_retained", side_effect=retained):
            acquired = evidence_export._acquire(str(runtime), sha, fixture.registry, "approved", fixture.store, fixture.lease)
        self.assertEqual(len(observations), 1)
        self.assertEqual(acquired[2], effect_id)
        self.assertEqual(acquired[3], effect["engine_exit"])
        self.assertEqual(acquired[4]["runtime"]["name"], "lit-lease-"+fixture.lease)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootFailureOwnerBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_github_runner_incus_engine_executor as engine_fixtures
        engine_fixtures.RootExecutorTests.setUpClass()

    def test_accepted_exception_boundary_stops_real_original_owner_without_waiting_for_expiry(self):
        import signal
        import test_github_runner_incus_engine_executor as engine_fixtures
        from incus_lease_issuer import engine_executor
        fixture = engine_fixtures.RootExecutorTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        path, sha, registry, selector, store, lease_id, receipt = fixture.arguments()
        runtime = fixture.fixture.root / "failure-boundary-runtime.json"
        capture = identity.decode_json(fixture.manifest.canonical_bytes)["capture"]
        value = {"schema": 2, "registry_path": registry.path, "registry_sha256": registry.sha256,
            "preparation_config_path": path, "preparation_config_sha256": sha,
            "authentication_timeout_seconds": 5, "initial_transition_timeout_seconds": 60,
            "heartbeat_lead_seconds": 30, "cleanup_timeout_seconds": 60,
            "capture": {**capture, "max_total_evidence_bytes": 1048576, "max_members": 100, "max_member_bytes": 1048576}}
        runtime.write_bytes(ledger.canonical(value));runtime.chmod(0o600)
        dispatcher = runtime_rpc.RuntimeRPC(str(runtime), hashlib.sha256(runtime.read_bytes()).hexdigest())
        fixture.spawn()  # Real fixed ELF, private PIPEs/CID and durable Root process binding.
        effect_id, effect = fixture.engine_effect()
        original = engine_executor._PROCESSES[effect["engine_process"]["pid"]]
        self.assertIsNone(original.returncode)
        before = time.monotonic()
        with mock.patch.object(engine_executor, "_retained", return_value=(fixture.manifest, effect_id, effect)), \
             mock.patch.object(engine_executor, "_command", side_effect=fixture.command), \
             mock.patch.object(engine_executor, "_withdraw"), mock.patch.object(engine_executor, "_drained"):
            dispatcher._retain_after_failure(store, lease_id, selector, receipt)
        self.assertLess(time.monotonic()-before, 5)
        self.assertTrue(original.closed)
        self.assertEqual(original.returncode, -signal.SIGTERM)
        after = store.read(lease_id)
        self.assertEqual(len([row for row in after["effects"].values() if row["operation"] == "engine-stop"]), 1)
        self.assertEqual(after["effects"][effect_id]["engine_exit"]["signal"], signal.SIGTERM)
        self.assertNotEqual(after["state"], "closed")  # Local stop is not remote VM/full cleanup.


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootAbortRemoteBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_github_runner_incus_emergency_stop as stop_fixtures
        stop_fixtures.RootEmergencyStopTests.setUpClass()

    def setUp(self):
        import test_github_runner_incus_emergency_stop as stop_fixtures
        self.fixture = stop_fixtures.RootEmergencyStopTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.store, self.lease = self.fixture.store, self.fixture.lease
        self.rpc = runtime_rpc.RuntimeRPC(str(self.fixture.base.runtime), self.fixture.base.sha)

    def kernel(self):
        from contextlib import ExitStack
        from incus_lease_issuer import engine_executor, network_fence
        stack = ExitStack()
        start_id = self.fixture.owner.creators["engine-start"]["id"]
        start = self.store.read(self.lease)["effects"][start_id]
        stack.enter_context(mock.patch.object(engine_policy, "ENGINE", self.fixture.base.engine.original))
        stack.enter_context(mock.patch.object(engine_executor, "_retained",
            return_value=(self.fixture.base.engine.manifest, start_id, start)))
        stack.enter_context(mock.patch.object(engine_executor, "_drained"))
        stack.enter_context(mock.patch.object(network_fence, "verify_disabled"))
        return stack

    def test_abort_dispatcher_revokes_scope_and_stops_exact_vm_before_evidence_without_cleanup_claim(self):
        from incus_lease_issuer import evidence_export
        # Actual completed local ELF/exit + verified local stop/paired fence
        # journal, Root semantic owner, crypto and Unix HTTP; kernel only modeled.
        before = self.store.read(self.lease)
        with self.kernel(), mock.patch.object(evidence_export, "export_existing", side_effect=AssertionError("no evidence gate")):
            receipt = self.rpc._stop_remote_after_abort(self.store, self.lease, "approved")
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.disposition, "stopped_observed")
        self.assertEqual(self.fixture.puts(), [("PUT", self.fixture.state_url,
            {"action": "stop", "timeout": 30, "force": False, "stateful": False})])
        after = self.store.read(self.lease)
        stops = [row for row in after["effects"].values() if row["operation"] == "instance-stop"]
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0]["state"], "verified")
        self.assertEqual(after["authorizations"], before["authorizations"])
        self.assertEqual(after["expires_at"], before["expires_at"])
        self.assertNotEqual(after["state"], "closed")
        self.assertFalse(any(row["operation"] in {"project-delete", "network-delete", "context-delete"}
                             for row in after["effects"].values()))

    def test_actual_missing_drain_holds_before_remote_write_and_no_synthetic_local_stop(self):
        from incus_lease_issuer import engine_executor
        before = self.store.read(self.lease)
        with self.kernel(), mock.patch.object(engine_executor, "_drained", side_effect=Denied("not-drained")):
            receipt = self.rpc._stop_remote_after_abort(self.store, self.lease, "approved")
        self.assertIsNone(receipt)
        self.assertEqual(self.fixture.puts(), [])
        self.assertEqual(self.store.read(self.lease), before)

    def test_root_abort_classification_uses_current_auth_not_natural_exit_zero(self):
        record = self.store.read(self.lease)
        end = min(record["expires_at"], record["authorizations"][-1]["valid_until"])
        with mock.patch.object(runtime_rpc.time, "time", return_value=end-1):
            self.assertFalse(self.rpc._abort_observed(record))
        with mock.patch.object(runtime_rpc.time, "time", return_value=end):
            self.assertTrue(self.rpc._abort_observed(record))
        cancelled = {**record, "state": "cancelled"}
        with mock.patch.object(runtime_rpc.time, "time", return_value=end-1):
            self.assertTrue(self.rpc._abort_observed(cancelled))


if __name__ == "__main__":
    unittest.main()
