"""Real socket/ledger/RS256 coupling with offline collector/native fixtures.

No fixture proves running-code provenance, accepted cell/custody, native token
availability or grant. Root tests run only in private /run/proof in the EE,
never on host. Production Root ownership checks are never overridden.
"""
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock

import test_github_runner_incus_identity as fixtures
from test_github_runner_incus_flow import FixtureReader

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import admission, collector, identity, installation, ledger, service  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


def frame(body):
    raw = json.dumps(body, separators=(",", ":")).encode()
    return struct.pack("!I", len(raw)) + raw


class NonrootAdmissionTests(unittest.TestCase):
    def test_nonroot_cannot_construct_or_call_bridge(self):
        if os.geteuid() == 0:
            self.skipTest("actual nonroot guard runs in nonroot EE")
        with self.assertRaisesRegex(Denied, "admission-root-required"):
            admission.AdmissionBridge(None)
        bridge = object.__new__(admission.AdmissionBridge)
        with self.assertRaisesRegex(Denied, "admission-root-required"):
            bridge.handle(None)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux UID0 EE only")
class RootAdmissionBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.CurrentJobIdentityTests.setUpClass()

    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires namespace-private root0700 /run/proof tmpfs")
        self.temp = tempfile.TemporaryDirectory(prefix="admission-", dir=base)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store_path = self.root / "store"
        self.store_path.mkdir(mode=0o700)
        self.cell = self.root / "cell.json"
        self.cell.write_bytes(b'{"fixture":"Root-selected-bytes-not-operating-acceptance"}')
        self.cell.chmod(0o600)
        self.cell_sha = hashlib.sha256(self.cell.read_bytes()).hexdigest()
        self.fixture = fixtures.CurrentJobIdentityTests()
        self.fixture.setUp()
        self.fixture.job["name"] = "approved-fixture-matrix-cell"
        self.identity_policy = identity.Policy(**{**asdict(self.fixture.policy),
                                  "required_native_job_name": "approved-fixture-matrix-cell"})
        self.worker = ledger.Worker(2101, 61, 23456, 777, "12345678-1234-4234-8234-123456789abc")
        install = installation.InstallationPolicy("/opt/fixture/runner", "/etc/fixture/manifest.json", 61, 2101)
        system_service = service.ServicePolicy("actions.runner.fixture.service", "fixture_runner", install,
                                              "/etc/systemd/system/actions.runner.fixture.service", "a" * 64)
        collect_policy = collector.CollectorPolicy(system_service, "lit-gh-fixture-0123456789abcdef",
                                                   "/etc/apparmor.d/fixture", "b" * 64,
                                                   "/etc/fixture/collector.json", "c" * 64)
        self.clock = mock.patch.object(admission.time, "time", return_value=fixtures.NOW)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        ledger.Ledger.initialize(self.store_path, clock=admission.time.time)
        with ledger.Ledger(self.store_path, clock=admission.time.time) as store:
            self.custody = store.archive_policy({"custodian_ref": "fixture:reference-only", "storage_ref": "fixture:private",
                "approval_ref": "fixture:not-actual-acceptance", "retention_seconds": 3600, "max_lease_seconds": 1800})
        self.policy = admission.AdmissionPolicy(collect_policy, self.identity_policy, str(self.store_path), None,
                                               str(self.cell), self.cell_sha, self.custody, fixtures.NOW + 1200)
        self.bridge = admission.AdmissionBridge(self.policy)
        self.reader = FixtureReader(self.fixture)
        self.native = mock.patch.object(identity, "HTTPSReader", return_value=self.reader)
        self.native.start()
        self.addCleanup(self.native.stop)
        self.collect = mock.patch.object(collector, "collect_worker", return_value=self.worker)
        self.collected = self.collect.start()
        self.addCleanup(self.collect.stop)

    def request(self, body, *, bridge=None, raw=None):
        with _pair() as pair:
            server, client = pair
            client.sendall(frame(body) if raw is None else raw)
            client.shutdown(socket.SHUT_WR)
            return (bridge or self.bridge).handle(server)

    def challenge(self):
        return self.request({"schema": 1, "operation": "challenge"})

    def admit_body(self, challenge, *, operation="admit", lease_id=None):
        self.fixture.claims["aud"] = challenge["audience"]
        request = {"schema": 1, "operation": operation, "nonce": challenge["nonce"],
                   "token": self.fixture.token(), "api_token": "synthetic-job-github-token"}
        if lease_id is not None:
            request["lease_id"] = lease_id
        return request

    def record(self, identifier):
        with ledger.Ledger(self.store_path, clock=admission.time.time) as store:
            return store.read(identifier)

    def test_root_operation_restriction_precedes_controls_worker_and_ledger(self):
        restricted = admission.AdmissionBridge(self.policy, expected_operation="refresh")
        with mock.patch.object(admission, "_controls") as controls, \
                mock.patch.object(admission, "_worker") as worker, \
                mock.patch.object(ledger, "Ledger") as store:
            for body in ({"schema": 1, "operation": "challenge"},
                         {"schema": 1, "operation": "admit", "nonce": "a" * 64,
                          "token": "synthetic-token", "api_token": "synthetic-api"},
                         {"schema": 1, "operation": "recover", "nonce": "b" * 64,
                          "token": "synthetic-token", "api_token": "synthetic-api"}):
                with self.assertRaisesRegex(Denied, "admission-denied"):
                    self.request(body, bridge=restricted)
            controls.assert_not_called()
            worker.assert_not_called()
            store.assert_not_called()
        for invalid in (False, [], "start", ""):
            with self.assertRaises(Denied):
                admission.AdmissionBridge(self.policy, expected_operation=invalid)

    def test_real_frame_real_signed_identity_and_real_ledger_prepare(self):
        challenge = self.challenge()
        self.assertEqual(set(challenge), {"schema", "operation", "nonce", "audience", "expires_at"})
        result = self.request(self.admit_body(challenge))
        self.assertEqual(set(result), {"schema", "operation", "lease_id", "expires_at"})
        record = self.record(result["lease_id"])
        self.assertEqual(record["worker"], asdict(self.worker))
        self.assertEqual(record["identity"]["job_id"], 902)
        self.assertEqual(record["identity"]["check_run_id"], 731)
        self.assertEqual(record["identity"]["policy_sha256"], identity.policy_digest(self.identity_policy))
        self.assertEqual(record["cell_sha256"], self.cell_sha)
        self.assertEqual(record["policy_sha256"], self.custody)
        self.assertEqual(record["expires_at"], self.policy.deadline)
        self.assertEqual(self.collected.call_count, 4)
        self.assertTrue(all(bearer is None if url == identity.JWKS_URL else bearer == "synthetic-job-github-token"
                            for url, bearer in self.reader.calls))

    def test_refresh_has_fresh_nonce_and_never_extends_fixed_deadline(self):
        first = self.request(self.admit_body(self.challenge()))
        original = self.record(first["lease_id"])
        fresh = self.challenge()
        self.fixture.claims.update(jti="fresh-synthetic-jti", exp=fixtures.NOW + 400)
        result = self.request(self.admit_body(fresh, operation="refresh", lease_id=first["lease_id"]),
                              bridge=admission.AdmissionBridge(self.policy, expected_operation="refresh"))
        current = self.record(result["lease_id"])
        self.assertEqual(current["expires_at"], original["expires_at"])
        self.assertEqual(current["identity"], original["identity"])
        self.assertEqual(len(current["authorizations"]), 2)
        self.assertEqual(current["authorizations"][-1]["valid_until"], fixtures.NOW + 400)

    def test_lost_admit_result_recovers_same_lease_with_fresh_signed_identity_and_no_effect_retry(self):
        first = self.request(self.admit_body(self.challenge()))
        identifier = first["lease_id"]  # Retained only by the test's Root observer.
        with ledger.Ledger(self.store_path, clock=admission.time.time) as store:
            effect = store.begin(identifier, "certificate-create", "unknown-owned-effect")
            store.record(identifier, effect, "unknown", evidence_sha256="f" * 64)
        original = self.record(identifier)
        for index in range(2):
            challenge = self.challenge()
            self.fixture.claims["jti"] = "recovered-synthetic-token-" + str(index)
            result = self.request(self.admit_body(challenge, operation="recover"))
            self.assertEqual(result, {"schema": 1, "operation": "recover", "lease_id": identifier,
                                      "expires_at": self.policy.deadline})
            current = self.record(identifier)
            self.assertEqual(current["effects"], original["effects"])
            self.assertEqual(current["identity"], original["identity"])
            self.assertEqual(current["expires_at"], original["expires_at"])
        with ledger.Ledger(self.store_path, clock=admission.time.time) as store:
            with self.assertRaises(Denied):
                store.begin(identifier, "test", "not-an-effect-retry")

    def test_recover_wire_cannot_supply_locator_policy_or_reuse_old_authority(self):
        first = self.request(self.admit_body(self.challenge()))
        challenge = self.challenge()
        self.fixture.claims["jti"] = "fresh-recover-wire"
        body = self.admit_body(challenge, operation="recover")
        for extra in ({"lease_id": first["lease_id"]}, {"policy": {}}, {"cell": "another-cell"}):
            with self.subTest(fields=extra), self.assertRaises(Denied):
                self.request(body | extra)
        recovered = self.request(body)
        self.assertEqual(recovered["lease_id"], first["lease_id"])
        with self.assertRaises(Denied):
            self.request(body)
        fresh = self.challenge()
        with self.assertRaises(Denied):
            self.request(self.admit_body(fresh, operation="recover"))

    def test_recover_changed_root_policy_domain_cell_deadline_or_worker_denies(self):
        self.request(self.admit_body(self.challenge()))
        challenge = self.challenge()
        self.fixture.claims["jti"] = "fresh-recover-domain"
        body = self.admit_body(challenge, operation="recover")
        expanded = replace(self.identity_policy, actor_ids=frozenset({76040632, 247824904}))
        variants = (replace(self.policy, identity=expanded), replace(self.policy, deadline=self.policy.deadline + 1),
                    replace(self.policy, custody_policy_sha256="0" * 64))
        before = (self.store_path / "state.json").read_bytes()
        for policy in variants:
            with self.subTest(deadline=policy.deadline), self.assertRaises(Denied):
                self.request(body, bridge=admission.AdmissionBridge(policy))
            self.assertEqual((self.store_path / "state.json").read_bytes(), before)
        other = self.root / "another-cell.json"
        other.write_bytes(b"other-root-selected-cell")
        other.chmod(0o600)
        bridge = admission.AdmissionBridge(replace(self.policy, cell_config_path=str(other),
                                      cell_sha256=hashlib.sha256(other.read_bytes()).hexdigest()))
        with self.assertRaises(Denied):
            self.request(body, bridge=bridge)
        self.collected.return_value = replace(self.worker, start_ticks=self.worker.start_ticks + 1)
        with self.assertRaises(Denied):
            self.request(body)
        self.assertEqual((self.store_path / "state.json").read_bytes(), before)

    def test_changed_actor_policy_cannot_refresh_existing_admitted_lease(self):
        first = self.request(self.admit_body(self.challenge()))
        fresh = self.challenge()
        self.fixture.claims["jti"] = "fresh-policy-drift-token"
        body = self.admit_body(fresh, operation="refresh", lease_id=first["lease_id"])
        expanded = replace(self.identity_policy, actor_ids=frozenset({76040632, 247824904}))
        bridge = admission.AdmissionBridge(replace(self.policy, identity=expanded))
        before = (self.store_path / "state.json").read_bytes()
        with self.assertRaises(Denied):
            self.request(body, bridge=bridge)
        self.assertEqual((self.store_path / "state.json").read_bytes(), before)

    def test_replayed_challenge_or_token_cannot_create_second_record(self):
        body = self.admit_body(self.challenge())
        self.request(body)
        before = (self.store_path / "state.json").read_bytes()
        with self.assertRaises(Denied):
            self.request(body)
        self.assertEqual((self.store_path / "state.json").read_bytes(), before)

    def test_foreign_signature_or_audience_denies_without_ledger_admission(self):
        challenge = self.challenge()
        body = self.admit_body(challenge)
        before = (self.store_path / "state.json").read_bytes()
        body["token"] = self.fixture.token(key=self.fixture.foreign_key)
        with self.assertRaises(Denied):
            self.request(body)
        self.fixture.claims["aud"] = "urn:wrong-audience"
        body["token"] = self.fixture.token()
        with self.assertRaises(Denied):
            self.request(body)
        self.assertEqual((self.store_path / "state.json").read_bytes(), before)

    def test_provenance_reacquired_after_external_identity_and_drift_denies(self):
        body = self.admit_body(self.challenge())
        before = (self.store_path / "state.json").read_bytes()
        self.collected.side_effect = [self.worker, replace(self.worker, start_ticks=778)]
        with self.assertRaises(Denied):
            self.request(body)
        self.assertTrue(self.reader.calls)
        self.assertEqual((self.store_path / "state.json").read_bytes(), before)

    def test_root_cell_bytes_changed_during_external_lookup_deny(self):
        body = self.admit_body(self.challenge())
        before = (self.store_path / "state.json").read_bytes()
        original = self.reader.read
        def changed(url, *, bearer=None):
            value = original(url, bearer=bearer)
            if "/actions/jobs/" in url:
                self.cell.write_bytes(b"changed root bytes")
            return value
        self.reader.read = changed
        with self.assertRaises(Denied):
            self.request(body)
        self.assertEqual((self.store_path / "state.json").read_bytes(), before)

    def test_request_cannot_supply_worker_identity_policy_cell_or_deadline(self):
        for extra in ({"worker": asdict(self.worker)}, {"identity": {}}, {"policy": {}},
                      {"cell_sha256": "f" * 64}, {"deadline": self.policy.deadline + 1}, {"pid": 23456}):
            with self.subTest(extra=list(extra)):
                self.collected.reset_mock()
                with self.assertRaises(Denied):
                    self.request({"schema": 1, "operation": "challenge", **extra})
                self.collected.assert_not_called()

    def test_bounded_frames_duplicate_keys_trailing_and_wrong_types_deny(self):
        duplicate = b'{"schema":1,"schema":1,"operation":"challenge"}'
        raw_cases = [struct.pack("!I", admission.MAX_REQUEST_BYTES + 1), b"\x00\x00",
                     struct.pack("!I", 20) + b"{}", frame({"schema": True, "operation": "challenge"}),
                     struct.pack("!I", len(duplicate)) + duplicate,
                     frame({"schema": 1, "operation": "challenge"}) + b"extra"]
        for raw in raw_cases:
            with self.subTest(size=len(raw)):
                self.collected.reset_mock()
                with self.assertRaises(Denied):
                    self.request(None, raw=raw)
                self.collected.assert_not_called()

    def test_nonunix_disconnected_or_datagram_socket_denied(self):
        for sock in (socket.socket(socket.AF_UNIX, socket.SOCK_STREAM), socket.socket(socket.AF_INET, socket.SOCK_STREAM)):
            with sock:
                with self.assertRaises(Denied):
                    self.bridge.handle(sock)
        with _pair(socket.SOCK_DGRAM) as pair:
            with self.assertRaises(Denied):
                self.bridge.handle(pair[0])

    def test_job_api_token_required_only_as_transport_never_jwks_or_authority(self):
        body = self.admit_body(self.challenge())
        for invalid in (None, "", "token\r\nheader", "x" * (admission.MAX_TOKEN_BYTES + 1)):
            with self.subTest(kind=type(invalid).__name__):
                with self.assertRaises(Denied):
                    self.request({**body, "api_token": invalid})
        self.fixture.claims["check_run_id"] = "732"
        body["token"] = self.fixture.token()
        with self.assertRaises(Denied):
            self.request(body)

    def test_prepared_receiver_cell_cannot_be_borrowed_by_another_genuine_run(self):
        self.fixture.receiver_fixture()
        native = identity.Policy(**asdict(self.fixture.policy))
        selected = replace(self.policy, identity=native)
        who = identity.Identity(501, 902, 731, 61, 2101, self.fixture.policy.caller_sha,
            self.fixture.policy.reusable_sha, fixtures.NOW + 300, "a" * 64,
            "urn:fixture", identity.policy_digest(native))
        before = (self.store_path / "state.json").read_bytes()
        for run in (501, 502, True, None):
            self.cell.write_text(json.dumps({"github": {"job": "profile-cells", "workflow": "Validation", "run_id": run}}))
            current = replace(selected, cell_sha256=hashlib.sha256(self.cell.read_bytes()).hexdigest())
            if type(run) is int and run == 501:
                admission._receiver_run(current, who)
            else:
                with self.assertRaises(Denied):
                    admission._receiver_run(current, who)
        self.assertEqual((self.store_path / "state.json").read_bytes(), before)
        with self.assertRaises(Denied):
            admission._receiver_run(selected, who)

    def test_explicit_root_token_mode_cannot_be_overridden_by_request(self):
        token = self.root / "api-token"
        token.write_text("synthetic-root-read-token\n")
        token.chmod(0o600)
        bridge = admission.AdmissionBridge(replace(self.policy, api_read_token_path=str(token)))
        body = self.admit_body(self.challenge())
        with self.assertRaises(Denied):
            self.request(body, bridge=bridge)
        body.pop("api_token")
        result = self.request(body, bridge=bridge)
        self.assertTrue(result["lease_id"])
        self.assertTrue(all(bearer is None if url == identity.JWKS_URL else bearer == "synthetic-root-read-token"
                            for url, bearer in self.reader.calls))

    def test_root_token_file_mode_and_policy_runner_cell_job_binding_deny(self):
        token = self.root / "api-token"
        token.write_text("synthetic-root-read-token")
        token.chmod(0o644)
        bridge = admission.AdmissionBridge(replace(self.policy, api_read_token_path=str(token)))
        with self.assertRaises(Denied):
            self.request({"schema": 1, "operation": "challenge"}, bridge=bridge)
        for changed in (replace(self.identity_policy, runner_id=62),
                        replace(self.identity_policy, required_native_job_name=None)):
            with self.assertRaises(Denied):
                admission.AdmissionBridge(replace(self.policy, identity=changed))

    def test_other_job_in_exact_run_and_same_runner_cannot_borrow_root_cell(self):
        body = self.admit_body(self.challenge())
        before = (self.store_path / "state.json").read_bytes()
        self.fixture.job["name"] = "different-fixture-matrix-cell"
        with self.assertRaises(Denied):
            self.request(body)
        self.assertEqual((self.store_path / "state.json").read_bytes(), before)

    def test_custody_reference_or_cell_bytes_are_not_automatically_archived_or_accepted(self):
        bridge = admission.AdmissionBridge(replace(self.policy, custody_policy_sha256="e" * 64))
        body = self.admit_body(self.challenge())
        before = (self.store_path / "state.json").read_bytes()
        with self.assertRaises(Denied):
            self.request(body, bridge=bridge)
        self.assertEqual((self.store_path / "state.json").read_bytes(), before)

    def test_refresh_cannot_borrow_other_worker_or_changed_root_cell_deadline(self):
        initial = self.request(self.admit_body(self.challenge()))
        fresh = self.challenge()
        self.fixture.claims["jti"] = "new-synthetic-refresh-jti"
        body = self.admit_body(fresh, operation="refresh", lease_id=initial["lease_id"])
        before = (self.store_path / "state.json").read_bytes()
        bridge = admission.AdmissionBridge(replace(self.policy, deadline=self.policy.deadline + 1))
        with self.assertRaises(Denied):
            self.request(body, bridge=bridge)
        self.collected.return_value = replace(self.worker, pid=23457)
        with self.assertRaises(Denied):
            self.request(body)
        self.assertEqual((self.store_path / "state.json").read_bytes(), before)

    def test_token_claims_and_api_bearer_are_never_in_reply_state_or_error(self):
        body = self.admit_body(self.challenge())
        result = self.request(body)
        raw_state = (self.store_path / "state.json").read_text()
        self.assertNotIn(body["token"], raw_state + json.dumps(result))
        self.assertNotIn(body["api_token"], raw_state + json.dumps(result))
        self.reader.read = mock.Mock(side_effect=OSError("synthetic-raw-secret"))
        fresh = self.challenge()
        self.fixture.claims["jti"] = "new-secret-redaction-jti"
        with self.assertRaises(Denied) as caught:
            self.request(self.admit_body(fresh, operation="refresh", lease_id=result["lease_id"]))
        self.assertEqual(str(caught.exception), "admission-denied")


    def test_v2_native_proof_is_nonmutating_and_same_socket_bound(self):
        challenge = self.challenge()
        body = self.admit_body(challenge)
        before = (self.store_path / "state.json").read_bytes()
        with _pair() as (server, client), _pair() as (other, unused):
            proof = admission.verify_runtime_native(server, self.policy, body["nonce"], body["token"], body["api_token"])
            worker, who = admission._require_native(proof, server, self.policy)
            self.assertEqual(worker, self.worker)
            self.assertEqual(who.audience, challenge["audience"])
            self.assertNotIn(body["token"], repr(proof))
            self.assertNotIn(body["api_token"], repr(proof))
            with self.assertRaises(Denied):
                admission._require_native(proof, other, self.policy)
            with self.assertRaises(Denied):
                admission._require_native(replace(proof), server, self.policy)
            with mock.patch.object(admission.time, "monotonic", return_value=proof.until + 1):
                with self.assertRaises(Denied):
                    admission._require_native(proof, server, self.policy)
        self.assertEqual((self.store_path / "state.json").read_bytes(), before)

    def test_v2_native_proof_reacquires_worker_and_rejects_policy_or_control_drift(self):
        body = self.admit_body(self.challenge())
        with _pair() as (server, client):
            proof = admission.verify_runtime_native(server, self.policy, body["nonce"], body["token"], body["api_token"])
            self.collected.return_value = replace(self.worker, pid=self.worker.pid + 1)
            with self.assertRaises(Denied):
                admission._require_native(proof, server, self.policy)
            self.collected.return_value = self.worker
            with self.assertRaises(Denied):
                admission._require_native(proof, server, replace(self.policy, deadline=self.policy.deadline + 1))
            self.cell.write_bytes(b"changed")
            with self.assertRaises(Denied):
                admission._require_native(proof, server, self.policy)


    def test_intake_ticket_revalidates_actual_assignment_without_extending_original_expiry(self):
        body = self.admit_body(self.challenge())
        before = (self.store_path / "state.json").read_bytes()
        with _pair() as (server, client), _pair() as (other, unused):
            ticket = admission.verify_intake_native(server, self.policy, body["nonce"], body["token"], body["api_token"])
            worker, who, remaining = admission.require_intake_native(
                ticket, server, self.policy, body["token"], body["api_token"])
            self.assertEqual(worker, self.worker)
            self.assertGreater(remaining, 0)
            self.assertLessEqual(remaining, who.valid_until - fixtures.NOW - 31)
            self.assertNotIn(body["token"], repr(ticket))
            self.assertNotIn(body["api_token"], repr(ticket))
            for supplied, socket in ((replace(ticket), server), (ticket, other)):
                with self.assertRaises(Denied):
                    admission.require_intake_native(supplied, socket, self.policy, body["token"], body["api_token"])
            with mock.patch.object(admission.time, "monotonic", return_value=ticket.expires_monotonic + 1):
                with self.assertRaises(Denied):
                    admission.require_intake_native(ticket, server, self.policy, body["token"], body["api_token"])
        self.assertEqual((self.store_path / "state.json").read_bytes(), before)

    def test_intake_ticket_rechecks_provider_and_rejects_ended_original_job(self):
        body = self.admit_body(self.challenge())
        with _pair() as (server, client):
            ticket = admission.verify_intake_native(server, self.policy, body["nonce"], body["token"], body["api_token"])
            self.fixture.job.update(status="completed", conclusion="success")
            with self.assertRaises(Denied):
                admission.require_intake_native(ticket, server, self.policy, body["token"], body["api_token"])


class _pair:
    def __init__(self, kind=socket.SOCK_STREAM):
        self.kind = kind

    def __enter__(self):
        self.sockets = socket.socketpair(socket.AF_UNIX, self.kind)
        return self.sockets

    def __exit__(self, *_):
        for sock in self.sockets:
            sock.close()


if __name__ == "__main__":
    unittest.main()
