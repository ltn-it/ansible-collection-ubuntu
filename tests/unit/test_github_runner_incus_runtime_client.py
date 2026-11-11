"""Actual Root Unix/host-file RuntimeV2 client fixtures, no native job grant.

OIDC is explicitly synthetic. Root server framing is real; no engine or external
API runs. Synthetic full-policy fixtures exercise consumer decisions; transport
success alone never constitutes evidence completeness or a passing cell.
"""
import base64
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import tarfile
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
import incus_runtime_client as client  # noqa: E402

TOKEN = "synthetic-oidc-token-do-not-log"
API = "synthetic-job-api-token-do-not-log"
LEASE = "b" * 32
NONCE = "a" * 64


def frame(value):
    return client._frame(value, 8192)


def receive(connected):
    deadline = time.monotonic() + 5
    length = struct.unpack("!I", client._exact(connected, 4, deadline))[0]
    return client._object(client._exact(connected, length, deadline))


def evidence(*, unsafe=None):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name, value in {"lifecycle.json": {"schema_version": 1, "evidence_policy_complete": False},
                            "cell.json": {"schema": 1, "junit_report_count": 0, "allure_report_count": 0,
                                          "evidence_policy_complete": False}}.items():
            raw = json.dumps(value).encode()
            member = tarfile.TarInfo(name)
            member.size, member.mode, member.uid, member.gid = len(raw), 0o600, 0, 0
            archive.addfile(member, io.BytesIO(raw))
        if unsafe:
            member = tarfile.TarInfo(unsafe)
            member.size, member.mode = 3, 0o600
            archive.addfile(member, io.BytesIO(b"bad"))
    return result.getvalue()


def terminal(operation="run"):
    return {"schema": 2, "type": "terminal", "operation": operation, "sequence": 1, "lease_id": LEASE,
            "state": "execution-complete", "exit": {"kind": "exited", "code": 0, "signal": None},
            "capture": {"state": "verified", "receipt_sha256": "c" * 64},
            "cleanup": {"state": "hold"}, "receipt_sha256": "c" * 64}


def full_evidence(*, failed=False, corrupt=False, missing_recording=False, wrong_policy=False, pending=False):
    totals = {"tests": 1, "failures": int(failed), "errors": 0, "skipped": 0}
    lifecycle = {"schema_version": 1, "scenario": "fixture_heavy", "target": "ubuntu24.04", "run_attempt": "1",
                 "test_exit_code": int(failed), "capture_exit_code": 0, "destroy_exit_code": 0,
                 "effective_exit_code": int(failed), "infrastructure_error": False, "evidence_policy_complete": False}
    manifest = {"schema_version": 2, "mode": "ci", "repository": "ltn-it/ansible-collection-supplementary",
        "commit_sha": "e" * 40, "expected_commit_sha": "e" * 40, "commit_consistent": True,
        "workflow_run_id": "501", "workflow_attempt": "1", "release_eligible": not failed,
        "test_totals": totals, "failures": int(failed), "skips": 0, "secret_scan": {"clean": True, "findings": [], "errors": []},
        "security_evidence": {"external_secret_findings": 0}, "prerequisites": {}, "blockers": [],
        "results": [{"id": "fixture", "role": "example", "profile": "heavy", "scenario": "fixture_heavy",
            "target": "ubuntu24.04", "run_attempt": "1", "status": "failed" if failed else "passed", "meaningful": True,
            "totals": totals, "junit": ["junit/probe.xml"], "allure_results": ["allure-results/probe-result.json"],
            "test_cases": [{"name": "fixture", "classname": "example", "roles": ["example"],
                            "status": "failure" if failed else "passed", "duration_seconds": 0}]}],
        "matrix": {"actual_count": 1, "expected": [{"profile": "heavy", "scenario": "fixture_heavy", "target": "ubuntu24.04",
            "run_attempt": "1", "roles": ["example"], "status": "failed" if failed else "passed"}]}}
    if pending:
        lifecycle.update(root_finalization="pending", destroy_exit_code=None)
        manifest.update(root_finalization="pending", execution_success=not failed,
                        candidate_execution_passed=False, release_eligible=False)
    original = {"junit/probe.xml": b'<testsuite tests="1"><testcase classname="example" name="fixture"/></testsuite>',
        "allure-results/probe-result.json": json.dumps({"status": "passed", "attachments": [{"source": "recording.webm"}]}).encode(),
        "allure-results/recording.webm": b"sanitized-recording-fixture", "logs/scenario.log": b"sanitized details"}
    if pending:
        original["environment.json"] = json.dumps({"generated_at": "2026-11-11T00:00:00Z",
            "repository": manifest["repository"], "commit_sha": manifest["commit_sha"], "workflow_run_id": "501",
            "workflow_attempt": "1", "roles": ["example"], "profiles": ["heavy"], "scenarios": ["fixture_heavy"],
            "targets": ["ubuntu24.04"], "tool_versions": {}, "application_versions": {}}).encode()
    if missing_recording:
        del original["allure-results/recording.webm"]
    manifest["checksums"] = {"algorithm": "sha256", "file": "checksums/SHA256SUMS", "entry_count": len(original) + 1}
    original["manifest.json"] = json.dumps(manifest).encode()
    original["checksums/SHA256SUMS"] = "".join(hashlib.sha256(raw).hexdigest() + "  " + name + "\n"
                                               for name, raw in sorted(original.items())).encode()
    if corrupt:
        original["logs/scenario.log"] = b"tampered after checksums"
    members = {"evidence/" + name: raw for name, raw in original.items()}
    members.update({"normalized/lifecycle.json": json.dumps(lifecycle).encode(),
        "normalized/cell.json": json.dumps({"schema": 1, "junit_report_count": 1, "allure_report_count": 1,
                                            "evidence_policy_complete": False}).encode(),
        "normalized/junit-000000.json": b'{"evidence_policy_complete":false}',
        "normalized/allure-000000.json": b'{"evidence_policy_complete":false}',
        "runtime/evidence-policy.json": json.dumps({"schema": 1, "evidence_policy_complete": True,
            "scope": "full-sanitized-cell-transfer", "source_policy_sha256": "f" * 64 if wrong_policy else client.EVIDENCE_POLICY_SHA256,
            "source_manifest_sha256": hashlib.sha256(original["manifest.json"]).hexdigest(),
            "required_junit": True, "required_allure": True,
            **({"root_finalization": "pending"} if pending else {})}).encode()})
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(members.items()):
            member = tarfile.TarInfo(name)
            member.size, member.mode, member.uid, member.gid = len(raw), 0o600, 0, 0
            archive.addfile(member, io.BytesIO(raw))
    return result.getvalue()


class RuntimeShapeTests(unittest.TestCase):
    def test_closed_argv_no_config_socket_token_command_or_path_override(self):
        for arguments in (["run-cell", "--selector", "cell", "--token", TOKEN], ["check", "--config", "/job"],
                          ["run-cell", "--selector", "a", "--selector", "b"], ["run", "--command", "sh"]):
            output, error = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(error):
                self.assertEqual(client.main(arguments), 2)
            self.assertNotIn(TOKEN, output.getvalue() + error.getvalue())
            self.assertEqual(json.loads(output.getvalue())["state"], "denied")

    def test_profile_locator_is_unambiguous_and_not_execution_authority(self):
        chosen = client.profile_selector("heavy", "kernel", "ubuntu24")
        self.assertRegex(chosen, "^cell-[0-9a-f]{64}$")
        self.assertEqual(chosen, client.profile_selector("heavy", "kernel", "ubuntu24"))
        self.assertNotEqual(chosen, client.profile_selector("application_acceptance", "kernel", "ubuntu24"))
        self.assertNotEqual(chosen, client.profile_selector("heavy", "kernel", "Ubuntu24"))
        for values in (("other", "kernel", "ubuntu24"), ("heavy", "../kernel", "ubuntu24"),
                       ("heavy", "kernel", "ubuntu24\n"), ("heavy", "a" * 64, "ubuntu24")):
            with self.assertRaises(client.ClientDenied):
                client.profile_selector(*values)

    def test_root_private_registry_derives_the_same_public_profile_locator(self):
        from incus_lease_issuer import policy_registry
        from incus_lease_issuer.identity import Denied
        for profile in ("heavy", "application_acceptance"):
            for scenario, target in (("kernel", "ubuntu24"), ("A.b-c_9", "Ubuntu24.04"),
                                     ("a"*63, "z"*63)):
                self.assertEqual(client.profile_selector(profile, scenario, target),
                                 policy_registry.profile_selector(profile, scenario, target))
        for values in (([], "x", "y"), ("other", "x", "y"), ("heavy", "../x", "y"),
                       ("heavy", "x", "y\n"), ("heavy", "x"*64, "y")):
            with self.subTest(values=values), self.assertRaises(Denied):
                policy_registry.profile_selector(*values)

    def test_profile_cli_routes_only_closed_locator_and_keeps_full_success_gate(self):
        selected = client.profile_selector("heavy", "kernel", "ubuntu24")
        result = {"evidence_policy_complete": False, "execution_passed": False}
        with mock.patch.object(client, "run_cell", return_value=result) as run, redirect_stdout(io.StringIO()):
            self.assertEqual(client.main(["run-profile", "--profile", "heavy", "--scenario", "kernel",
                                          "--target", "ubuntu24"]), 1)
            run.assert_called_once_with(selected, recover=False)
        for arguments in (["run-profile", "--profile", "heavy", "--scenario", "kernel", "--target", "ubuntu24", "--token", TOKEN],
                          ["run-profile", "--profile", "heavy", "--scenario", "kernel", "--scenario", "other", "--target", "ubuntu24"]):
            output = io.StringIO()
            with mock.patch.object(client, "run_cell") as run, redirect_stdout(output), redirect_stderr(io.StringIO()):
                self.assertEqual(client.main(arguments), 2)
                run.assert_not_called()
            self.assertNotIn(TOKEN, output.getvalue())

    def test_duplicate_nonfinite_and_unknown_exit_are_strict(self):
        for raw in (b'{"schema":2,"schema":2}', b'{"x":NaN}', b'{"x":1e999}', b'[]'):
            with self.assertRaises(client.ClientDenied):
                client._object(raw)
        for change in ({"kind": "unknown", "code": 0, "signal": None},
                       {"kind": "exited", "code": True, "signal": None},
                       {"kind": "signalled", "code": None, "signal": 65}):
            value = terminal()
            value["exit"] = change
            with self.assertRaises(client.ClientDenied):
                client._terminal(value, "run", LEASE)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root proper EE only")
class RootRuntimeClientTests(unittest.TestCase):
    def setUp(self):
        root = Path("/run/proof")
        if not root.is_dir() or root.stat().st_uid != 0 or stat.S_IMODE(root.stat().st_mode) != 0o700:
            self.skipTest("requires private Root0700 /run/proof")
        self.allocation = tempfile.TemporaryDirectory(prefix="runtime-client-", dir=root)
        self.addCleanup(self.allocation.cleanup)
        self.root = Path(self.allocation.name)
        self.path = self.root / "runtime.sock"
        self.config = self.root / "client.json"
        self.config.write_text(json.dumps({"schema": 2, "socket_path": str(self.path)}))
        self.config.chmod(0o644)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        self.path.chmod(0o600)
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.addCleanup(self.listener.close)
        self.stop = threading.Event()
        self.heartbeat_seen = threading.Event()
        self.requests, self.errors, self.connections = [], [], []
        self.mode, self.payload = "normal", evidence()
        cache = mock.patch.dict(client._CONFIGURATIONS, {}, clear=True)
        cache.start(); self.addCleanup(cache.stop)
        self.cleanup_state = "hold"
        self.worker = threading.Thread(target=self.accept, daemon=True)
        self.worker.start()
        self.addCleanup(self.finish)
        patch = mock.patch.object(client, "CONFIG", str(self.config))
        patch.start()
        self.addCleanup(patch.stop)
        self.auth = SimpleNamespace(AUDIENCE="urn:lightning-it:legacy-incus:",
                                    _secret=lambda value: value if isinstance(value, str) and value else client.require(False),
                                    _oidc=mock.Mock(return_value=TOKEN))
        patch = mock.patch.object(client, "_authentication", return_value=self.auth)
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_TOKEN": API,
                    "RUNNER_TEMP": str(self.root), "GITHUB_RUN_ID": "501", "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_REPOSITORY": "ltn-it/ansible-collection-supplementary", "QUALITY_INPUT_SCENARIO": "fixture_heavy",
                    "QUALITY_INPUT_TARGET": "ubuntu24.04", "QUALITY_INPUT_PROFILE": "heavy", "QUALITY_INPUT_SOURCE_SHA": "e" * 40,
                    "QUALITY_INPUT_ROLES": "example", "QUALITY_INPUT_TARGET_DISPOSITION": "supported",
                    "QUALITY_INPUT_JUNIT_REQUIRED": "true", "QUALITY_INPUT_ALLURE_REQUIRED": "true"}, clear=True)
        patch.start()
        self.addCleanup(patch.stop)

    def finish(self):
        self.stop.set()
        self.worker.join(timeout=2)
        for thread in self.connections:
            thread.join(timeout=2)

    def accept(self):
        while not self.stop.is_set():
            try:
                connected, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self.serve, args=(connected,), daemon=True)
            self.connections.append(thread)
            thread.start()

    def serve(self, connected):
        try:
            connected.settimeout(5)
            if connected.recv(1, socket.MSG_PEEK) == b"":
                return  # check() closes without sending a selector or auth.
            selector = receive(connected)
            operation = selector["operation"]
            intake = self.mode == "intake" and "configuration" not in selector
            nonce = ("a" * 64 if intake else NONCE)
            connected.sendall(frame({"schema": 2, "type": "challenge", "operation": operation, "nonce": nonce,
                "audience": self.auth.AUDIENCE + nonce, "expires_at": int(time.time()) + 60,
                **({"phase": "intake"} if intake else {})}))
            auth = receive(connected)
            self.requests.append((selector, auth))
            self.assertEqual(connected.recv(1), b"")
            self.assertEqual(auth["token"], TOKEN)
            self.assertEqual(auth["api_token"], API)
            self.assertEqual(auth["nonce"], nonce)
            if intake:
                connected.sendall(frame({"schema": 2, "type": "intake-ready", "operation": operation,
                    "cell": selector["cell"], "configuration": "f" * 64, "deadline": int(time.time()) + 300,
                    "lease_created": False}))
                return
            if self.mode == "intake":
                self.assertEqual(selector["configuration"], "f" * 64)
            if self.mode == "drop":
                return
            if self.mode == "denied":
                connected.sendall(frame({"schema": 2, "type": "failure", "operation": operation, "disposition": "denied-before-intent"}))
                return
            if operation in {"heartbeat", "status", "cancel"}:
                connected.sendall(frame({"schema": 2, "type": "result", "operation": operation, "lease_id": LEASE,
                    "state": "running", "expires_at": self.deadline if self.mode == "heartbeat" else int(time.time()) + 300,
                    "authorization_expires_at": int(time.time()) + 120, "receipt_sha256": "d" * 64}))
                self.heartbeat_seen.set()
                return
            if operation == "run":
                self.deadline = int(time.time()) + 300
                connected.sendall(frame({"schema": 2, "type": "accepted", "operation": "run", "sequence": 0,
                    "lease_id": LEASE, "state": "preparing", "expires_at": self.deadline,
                    "authorization_expires_at": int(time.time()) + (2 if self.mode == "heartbeat" else 120)}))
                if self.mode == "heartbeat":
                    self.assertTrue(self.heartbeat_seen.wait(5))
            if self.mode == "operating" and operation == "run":
                case = self.operating_case
                uuid = "12345678-1234-1234-1234-123456789abc"
                connected.sendall(frame({"schema": 2, "type": "operating-ready", "operation": "run",
                    "lease_id": LEASE, "case": case, "instance_uuid": uuid}))
                if case == "broker-cancel":
                    self.assertTrue(self.heartbeat_seen.wait(5), "client must request genuine broker cancel only after READY")
                receipt = {"schema": 1, "kind": "operating", "case": case, "selector": "operating-" + case,
                    "run_id": 501, "run_attempt": 1, "source_sha": "e" * 40, "controller_sha": "c" * 40,
                    "lease_id": LEASE, "instance_uuid": uuid, "raw_exit": {"code": 23 if case == "failure" else 143, "signal": None},
                    "vm_state": "stopped", "access": "withdrawn", "retention_seconds": 14400,
                    "terminal_at": None, "retain_until": None, "cutoff": None, "state": "safety-proved-retention-armed"}
                connected.sendall(frame({"schema": 2, "type": "operating-terminal", "operation": "run", "lease_id": LEASE,
                                         "receipt": receipt}))
                return
            value = terminal(operation)
            value["cleanup"] = {"state": self.cleanup_state}
            if self.mode == "drift":
                self.config.write_text(self.config.read_text())
            if self.mode == "no-export":
                connected.sendall(frame(value))
                return
            connected.sendall(frame(value))
            header = {"schema": 2, "type": "capture-manifest", "lease_id": LEASE, "sequence": 2,
                      "size": len(self.payload), "sha256": hashlib.sha256(self.payload).hexdigest(),
                      "chunk_count": (len(self.payload) + 4095) // 4096, "content_type": "application/gzip"}
            if self.mode == "hash":
                header["sha256"] = "e" * 64
            connected.sendall(frame(header))
            for index, offset in enumerate(range(0, len(self.payload), 4096)):
                data = base64.urlsafe_b64encode(self.payload[offset:offset + 4096]).rstrip(b"=").decode()
                chunk = {"schema": 2, "type": "capture-chunk", "lease_id": LEASE, "sequence": index + 3,
                         "offset": offset, "data": data}
                if self.mode == "sequence":
                    chunk["sequence"] += 1
                connected.sendall(frame(chunk))
            if self.mode == "trailing":
                connected.sendall(b"not-eof")
        except (BrokenPipeError, ConnectionResetError):
            pass  # Client rejects a deliberate malformed fixture.
        except Exception as error:
            self.errors.append(type(error).__name__)
        finally:
            connected.close()

    def test_final_receipt_real_eddsa_requires_installed_pin_and_exact_original_native_tuple(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        config = {"schema": 2, "socket_path": str(self.path), "signing_public_key_hex": public.hex()}
        self.config.write_text(json.dumps(config)); self.config.chmod(0o644)
        now = int(time.time())
        payload = {"schema": 1, "purpose": "urn:lightning-it:g06:final-quality:v1", "state": "closed",
            "lease_id": LEASE, "repository": "ltn-it/ansible-collection-supplementary", "repository_id": 1103407173,
            "run_id": 501, "run_attempt": 1, "source_sha": "e" * 40, "controller_sha": "c" * 40,
            "profile": "heavy", "scenario": "fixture_heavy", "target": "ubuntu24.04",
            "execution": {"job_id": 904, "check_run_id": 732, "conclusion": "success", "completed_at": now - 10},
            "artifact": {"id": 991, "name": "quality-result-fixture_heavy-ubuntu24.04-e-1", "digest_sha256": "a" * 64,
                         "size_in_bytes": 100}, "capture_receipt_sha256": "b" * 64,
            "cleanup": {"state": "verified", "ledger_sha256": "d" * 64, "closed_at": now - 5,
                        "resource_absence_sha256": "f" * 64}, "custody_policy_sha256": "a" * 64,
            "cell_sha256": "b" * 64, "engine_policy_sha256": "c" * 64, "signer_public_key_hex": public.hex(), "issued_at": now}
        def signed(value):
            encode = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
            header = {"alg": "EdDSA", "typ": "lit-incus-final-quality+jwt", "kid": hashlib.sha256(public).hexdigest()}
            message = encode(json.dumps(header, sort_keys=True, separators=(",", ":")).encode()) + "." + encode(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
            return {"schema": 1, "receipt": value, "signature": message + "." + encode(key.sign(message.encode()))}
        with mock.patch.dict(os.environ, {"GITHUB_SHA": "e" * 40, "GITHUB_REPOSITORY_ID": "1103407173"}):
            envelope = signed(payload)
            self.assertEqual(client._final_receipt(envelope, "heavy", "fixture_heavy", "ubuntu24.04"), payload)
            for change in ({"run_id": 502}, {"run_attempt": True}, {"signer_public_key_hex": "0" * 64},
                           {"cleanup": {**payload["cleanup"], "closed_at": now - 20}}):
                with self.subTest(change=change), self.assertRaises(client.ClientDenied):
                    client._final_receipt(signed({**payload, **change}), "heavy", "fixture_heavy", "ubuntu24.04")
            altered = {**envelope, "receipt": {**payload, "run_id": 502}}
            with self.assertRaises(client.ClientDenied):
                client._final_receipt(altered, "heavy", "fixture_heavy", "ubuntu24.04")
            foreign = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.config.write_text(json.dumps({**config, "signing_public_key_hex": foreign.hex()}))
            with self.assertRaises(client.ClientDenied):
                client._final_receipt(envelope, "heavy", "fixture_heavy", "ubuntu24.04")

    def test_operating_failure_and_broker_case_require_root_ready_and_publish_no_quality_pass(self):
        self.mode = "operating"
        output = self.output()
        with mock.patch.dict(os.environ, {"GITHUB_SHA": "e" * 40}):
            for case in ("failure", "broker-cancel"):
                self.operating_case = case
                result = client.run_operating(case)
                self.assertEqual(result["state"], "safety-proved-retention-armed")
                receipt = json.loads(Path(result["operating_receipt"]).read_bytes())
                self.assertEqual(receipt["case"], case)
                self.assertIsNone(receipt["terminal_at"])
                self.assertNotIn("quality", result["operating_artifact"])
        self.assertEqual([request[0]["operation"] for request in self.requests], ["run", "run", "cancel"])
        self.assertEqual(self.requests[-1][1]["lease_id"], LEASE)
        self.assertNotIn("final-quality", output.read_text())
        self.assertFalse(self.errors)

    def test_check_is_local_only_no_oidc_authentication_or_lease(self):
        result = client.check()
        self.assertEqual(result["state"], "local-prerequisites-only")
        self.auth._oidc.assert_not_called()
        self.assertEqual(self.requests, [])

    def test_private_intake_is_separate_connection_and_fresh_oidc_before_actual_run(self):
        self.mode = "intake"
        result = client.run_cell("registered-cell")
        self.assertTrue(result["transport_only"])
        self.assertEqual(len(self.requests), 2)
        self.assertNotIn("configuration", self.requests[0][0])
        self.assertEqual(self.requests[1][0]["configuration"], "f" * 64)
        self.assertEqual(self.auth._oidc.call_args_list,
            [mock.call(self.auth.AUDIENCE + "a" * 64), mock.call(self.auth.AUDIENCE + NONCE)])
        self.assertFalse(self.errors)

    def test_same_socket_challenge_auth_and_complete_capture_is_transport_only(self):
        result = client.run_cell("registered-cell")
        self.assertTrue(result["transport_only"])
        self.assertIs(result["evidence_policy_complete"], False)
        self.assertEqual(Path(result["capture_path"]).read_bytes(), self.payload)
        self.assertEqual(stat.S_IMODE(Path(result["capture_path"]).stat().st_mode), 0o600)
        self.assertEqual([row[0]["operation"] for row in self.requests], ["run"])
        self.assertEqual(self.errors, [])
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertNotIn(API, json.dumps(result))

    def test_fresh_separate_heartbeat_before_expiry_retains_hard_deadline(self):
        self.mode = "heartbeat"
        result = client.run_cell("registered-cell")
        self.assertTrue(result["transport_only"])
        self.assertEqual([row[0]["operation"] for row in self.requests], ["run", "heartbeat"])
        self.assertEqual(self.auth._oidc.call_count, 2)
        self.assertEqual(self.errors, [])

    def test_lost_terminal_or_missing_export_never_returns_success_or_retries(self):
        for mode in ("drop", "no-export"):
            self.mode = mode
            count = len(self.requests)
            with self.assertRaises(client.ClientUnknown):
                client.run_cell("registered-cell")
            self.assertEqual(len(self.requests), count + 1)

    def test_explicit_recover_retransfers_into_new_private_directory_without_run(self):
        initial = client.run_cell("registered-cell")
        recovered = client.run_cell("registered-cell", recover=True)
        self.assertNotEqual(initial["capture_path"], recovered["capture_path"])
        self.assertEqual(Path(recovered["capture_path"]).read_bytes(), self.payload)
        self.assertEqual([row[0]["operation"] for row in self.requests], ["run", "recover"])

    def test_hash_sequence_trailing_bytes_and_private_member_names_fail_closed(self):
        for mode in ("hash", "sequence", "trailing", "normal"):
            self.mode = mode
            self.payload = evidence(unsafe="client.key") if mode == "normal" else evidence()
            with self.assertRaises(client.ClientUnknown):
                client.run_cell("registered-cell")

    def test_status_cancel_are_closed_fresh_requests_and_root_denial_is_conclusive(self):
        for operation in ("status", "cancel"):
            result = client.operation("registered-cell", operation, LEASE)
            self.assertEqual(result["operation"], operation)
            self.assertEqual(self.requests[-1][1]["lease_id"], LEASE)
        self.mode = "denied"
        with self.assertRaises(client.ClientDenied):
            client.run_cell("registered-cell")

    def test_configuration_schema_or_socket_symlink_denies_before_authentication(self):
        self.config.write_text(json.dumps({"schema": 1, "socket_path": str(self.path)}))
        with self.assertRaises(client.ClientDenied):
            client.run_cell("registered-cell")
        self.assertEqual(self.requests, [])
        self.config.write_text(json.dumps({"schema": 2, "socket_path": str(self.path)}))
        self.path.rename(self.root / "real.sock")
        self.path.symlink_to(self.root / "real.sock")
        with self.assertRaises(client.ClientDenied):
            client.run_cell("registered-cell")
        self.assertEqual(self.requests, [])

    def test_actual_socket_root_owner_does_not_replace_peer_uid_or_lifetime_config_proof(self):
        with mock.patch.object(client.socket.socket, "getsockopt", return_value=struct.pack("3i", 123, 2101, 2101)):
            with self.assertRaises(client.ClientDenied):
                client.run_cell("registered-cell")
        self.assertEqual(self.requests, [])
        self.mode = "drift"
        with self.assertRaises(client.ClientUnknown):
            client.run_cell("registered-cell")

    def test_symlink_capture_parent_never_receives_archive_bytes(self):
        (self.root / "lit-incus-runtime").symlink_to("/etc")
        with self.assertRaises(client.ClientUnknown):
            client.run_cell("registered-cell")

    def output(self, mode=0o644):
        directory = self.root / "_runner_file_commands"
        directory.mkdir(mode=0o700, exist_ok=True)
        output = directory / "set_output_fixture"
        output.touch(mode=mode)
        os.environ["GITHUB_OUTPUT"] = str(output)
        return output

    def test_complete_original_evidence_and_recording_preserved_with_exact_checksums(self):
        self.payload = full_evidence()
        result = client.run_cell("registered-cell")
        self.assertIs(result["evidence_policy_complete"], True)
        self.assertIs(result["execution_passed"], True)
        package = Path(result["package_directory"])
        self.assertEqual((package / "allure-results/recording.webm").read_bytes(), b"sanitized-recording-fixture")
        self.assertTrue((package / "junit/probe.xml").is_file())
        self.assertTrue((package / "checksums/SHA256SUMS").is_file())
        self.assertFalse((package / "normalized").exists())
        client._package_inventory(str(package), result["_evidence_files"])

    def test_cli_zero_requires_full_semantics_actual_exit_and_verified_root_cleanup(self):
        self.payload, self.cleanup_state = full_evidence(), "verified"
        output = self.output()
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(client.main(["run-cell", "--selector", "registered-cell"]), 0)
        reply = json.loads(stream.getvalue())
        self.assertNotIn("_evidence_files", reply)
        self.assertIn("package-directory=", output.read_text())
        self.assertIn("result-artifact=quality-result-fixture_heavy-ubuntu24.04-" + "e" * 40 + "-attempt-1", output.read_text())
        self.assertNotIn(TOKEN, stream.getvalue() + output.read_text())
        self.assertNotIn(API, stream.getvalue() + output.read_text())

    def test_profile_cli_uses_real_socket_transfer_and_complete_metadata_outputs(self):
        self.payload, self.cleanup_state = full_evidence(), "verified"
        output = self.output()
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(client.main(["run-profile", "--profile", "heavy", "--scenario", "fixture_heavy",
                                          "--target", "ubuntu24.04"]), 0)
        self.assertEqual(self.requests[0][0]["cell"], client.profile_selector("heavy", "fixture_heavy", "ubuntu24.04"))
        self.assertIn("package-directory=", output.read_text())
        self.assertIn("result-artifact=", output.read_text())
        self.assertNotIn(TOKEN, stream.getvalue() + output.read_text())
        self.assertNotIn(API, stream.getvalue() + output.read_text())

    def test_verified_full_diagnostics_root_hold_and_failure_publish_but_never_exit_zero(self):
        output = self.output()
        for failed in (False, True):
            self.payload = full_evidence(failed=failed)
            stream = io.StringIO()
            with redirect_stdout(stream):
                self.assertEqual(client.main(["run-cell", "--selector", "registered-cell"]), 1)
            self.assertIn("package-directory=", output.read_text())

    def test_pending_execution_returns_only_typed_preliminary_success_with_cleanup_still_held(self):
        output = self.output()
        self.payload = full_evidence(pending=True)
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(client.main(["run-cell", "--selector", "registered-cell"]), 0)
        value = json.loads(stream.getvalue())
        self.assertEqual(value["root_finalization"], "pending")
        self.assertEqual(value["cleanup"], {"state": "hold"})
        self.assertIn("execution-state=awaiting-native-end", output.read_text())
        self.payload = full_evidence(pending=True, failed=True)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(client.main(["run-cell", "--selector", "registered-cell"]), 1)

    def test_incomplete_policy_and_corrupt_source_checksum_never_publish(self):
        output = self.output()
        for payload in (evidence(), full_evidence(corrupt=True), full_evidence(wrong_policy=True), full_evidence(missing_recording=True)):
            self.payload = payload
            with redirect_stdout(io.StringIO()):
                self.assertNotEqual(client.main(["run-cell", "--selector", "registered-cell"]), 0)
            self.assertEqual(output.read_text(), "")

    def test_extracted_tree_drift_and_unsafe_native_command_file_deny_publication(self):
        self.payload = full_evidence()
        result = client.run_cell("registered-cell")
        output = self.output()
        output.chmod(0o666)
        with self.assertRaises(client.ClientDenied):
            client._publish(result)
        output.chmod(0o644)
        (Path(result["package_directory"]) / "logs/scenario.log").write_bytes(b"changed after verification")
        with self.assertRaises(client.ClientDenied):
            client._publish(result)
        self.assertEqual(output.read_text(), "")


if __name__ == "__main__":
    unittest.main()
