"""Synthetic signing keys and real private Root filesystem/ledger boundaries.

Run only in the isolated UID0 EE with namespace-private /run/proof root0700.
No native identity, TLS credential or VM operating acceptance is established.
"""
import base64
from dataclasses import replace
from copy import deepcopy
import datetime as dt
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import identity, ledger, signed_context as context  # noqa: E402

NOW = 1793772000
CUSTODY = {"custodian_ref": "synthetic-owner", "storage_ref": "synthetic-store",
           "approval_ref": "synthetic-reference-not-operating-acceptance", "retention_seconds": 3600,
           "max_lease_seconds": 1800}


def raw_public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def encoded(value):
    return base64.urlsafe_b64encode(ledger.canonical(value)).decode().rstrip("=")


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() != 0, "actual nonroot Linux EE only")
class NonrootSignerGuardTests(unittest.TestCase):
    def test_actual_nonroot_cannot_load_sign_or_verify_root_context(self):
        with self.assertRaisesRegex(identity.Denied, "context-root-required"):
            context.RootSigner("/unreadable-root-key", b"x" * 32)
        uninitialized = object.__new__(context.RootSigner)
        with self.assertRaisesRegex(identity.Denied, "context-root-required"):
            uninitialized.issue(None, None, None, None, None, None)
        with self.assertRaisesRegex(identity.Denied, "context-root-required"):
            context.verify(None, None, None, None, None, None, None, None)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux UID0 EE only")
class RootSignedContextTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires namespace-private root0700 /run/proof tmpfs")
        self.temp = tempfile.TemporaryDirectory(prefix="signed-context-", dir=base)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clock = NOW
        patch = mock.patch.object(context.time, "time", side_effect=lambda: self.clock)
        patch.start()
        self.addCleanup(patch.stop)
        self.key = Ed25519PrivateKey.generate()
        self.pub = raw_public(self.key)
        self.key_path = self.root / "root-signing-key.pem"
        self.write(self.key_path, self.key.private_bytes(serialization.Encoding.PEM,
                   serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.directory = self.root / "context"
        self.directory.mkdir(mode=0o700)
        (self.directory / "servercerts").mkdir(mode=0o700)
        for name in context.FILES:
            self.write(self.directory / name, ("synthetic-" + name).encode())
        path = self.root / "ledger"
        path.mkdir(mode=0o700)
        ledger.Ledger.initialize(path, clock=lambda: self.clock)
        self.store = ledger.Ledger(path, clock=lambda: self.clock)
        self.addCleanup(self.store.shutdown)
        self.worker = ledger.Worker(2101, 61, 12345, 987654, "12345678-1234-4234-8234-123456789abc")
        custody = self.store.archive_policy(dict(CUSTODY))
        self.policy = context.ContextPolicy(identity.Policy(
            repository="example/repository", repository_id=123, owner_id=456, caller_sha="a" * 40,
            workflow_id=789, workflow_path=".github/workflows/test.yml",
            reusable_repository="example/controllers", reusable_path=".github/workflows/vm.yml",
            reusable_sha="b" * 40, runner_id=61, runner_name="synthetic-runner", service_uid=2101,
            actor_ids=frozenset({42}), subject="repo:example/repository:ref:refs/heads/develop",
            required_native_job_name="synthetic-cell"),
            "https://incus.example.test:8443", "synthetic-project", NOW + 120,
            "c" * 64, custody, "d" * 64, "e" * 64, "f" * 64)
        challenge = self.store.challenge(self.worker)
        self.who = identity.Identity(501, 902, 731, 61, 2101, "a" * 40, "b" * 40,
                                     NOW + 90, hashlib.sha256(b"synthetic-token").hexdigest(),
                                     challenge["audience"], policy_sha256=identity.policy_digest(self.policy.identity))
        self.lease = self.store.prepare(challenge["nonce"], self.worker, self.who, policy_sha256=custody,
                                        cell_sha256=self.policy.cell_sha256, deadline=self.policy.deadline)
        self.binding = {"schema": 2, "repository": self.policy.identity.repository, "run_id": "501",
                        "run_attempt": "1", "server": self.policy.server, "project": self.policy.project,
                        "expires_at": dt.datetime.fromtimestamp(self.policy.deadline, dt.timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%SZ"), "runtime": {"firewall_controller": "incus"}}
        self.save_binding()
        self.signer = context.RootSigner(str(self.key_path), self.pub)

    @staticmethod
    def write(path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)

    def save_binding(self, token=None):
        self.write(self.directory / "binding.json", ledger.canonical(
            self.binding if token is None else self.binding | {"admission": token}))

    def issue(self, **changes):
        values = dict(store=self.store, lease_id=self.lease, worker=self.worker, policy=self.policy,
                      binding=self.binding, context_dir=str(self.directory)) | changes
        return self.signer.issue(**values)

    def publish(self):
        token = self.issue()
        self.save_binding(token)
        return token

    def verify(self, token, **changes):
        values = dict(pinned_public_key=self.pub, store=self.store, lease_id=self.lease, worker=self.worker,
                      policy=self.policy, binding=self.binding, context_dir=str(self.directory)) | changes
        return context.verify(token, **values)

    def deny(self, function, *args, **kwargs):
        with self.assertRaises(identity.Denied):
            function(*args, **kwargs)

    def forge(self, token, *, header=None, payload=None):
        h, p, _ = token.split(".")
        data = (h if header is None else encoded(header)) + "." + (p if payload is None else encoded(payload))
        return data + "." + base64.urlsafe_b64encode(self.key.sign(data.encode())).decode().rstrip("=")

    def test_round_trip_real_root_files_and_exact_four_file_map(self):
        token = self.publish()
        result = self.verify(token)
        payload = identity.decode_json(identity.unbase(token.split(".")[1]))
        self.assertEqual(set(payload["files_sha256"]), set(context.FILES))
        self.assertEqual(payload["binding_sha256"], ledger.digest(self.binding))
        self.assertNotIn("admission", payload)
        self.assertEqual(payload["identity"]["check_run_id"], 731)
        self.assertEqual(payload["worker"], self.store.read(self.lease)["worker"])
        self.assertEqual(result, {"lease_id": self.lease, "expires_at": NOW + 120,
                                 "binding_sha256": ledger.digest(self.binding)})

    def test_digest_mismatch_each_context_file(self):
        token = self.publish()
        for name in context.FILES:
            with self.subTest(name=name):
                path = self.directory / name
                original = path.read_bytes()
                self.write(path, b"different-synthetic-bytes")
                self.deny(self.verify, token)
                self.write(path, original)

    def test_binding_file_and_expected_tuple_mismatch(self):
        token = self.publish()
        self.write(self.directory / "binding.json", ledger.canonical(self.binding | {
            "project": "other-project", "admission": token}))
        self.deny(self.verify, token)

    def test_signature_tampering_and_wrong_public_key(self):
        token = self.publish()
        parts = token.split(".")
        signature = bytearray(identity.unbase(parts[2]))
        signature[0] ^= 1
        self.deny(self.verify, ".".join(parts[:2]) + "." + base64.urlsafe_b64encode(signature).decode().rstrip("="))
        self.deny(self.verify, token, pinned_public_key=raw_public(Ed25519PrivateKey.generate()))

    def test_signed_algorithm_keyurl_and_missing_header_fields_denied(self):
        token = self.publish()
        header = identity.decode_json(identity.unbase(token.split(".")[0]))
        for mutation in ({**header, "alg": "none"}, {**header, "alg": "RS256"},
                         {**header, "jku": "https://untrusted.example/key"},
                         {k: v for k, v in header.items() if k != "kid"}):
            changed = self.forge(token, header=mutation)
            self.save_binding(changed)
            self.deny(self.verify, changed)

    def test_signed_missing_extra_recursive_payload_denied(self):
        token = self.publish()
        payload = identity.decode_json(identity.unbase(token.split(".")[1]))
        for mutation in ({k: v for k, v in payload.items() if k != "worker"},
                         {**payload, "admission": token}, {**payload, "payload": payload}):
            changed = self.forge(token, payload=mutation)
            self.save_binding(changed)
            self.deny(self.verify, changed)

    def test_expired_authorization_and_fixed_deadline(self):
        token = self.publish()
        self.clock = NOW + 90
        self.deny(self.verify, token)
        self.clock = NOW + 120
        self.deny(self.verify, token)
        self.save_binding()
        self.deny(self.issue)

    def test_cancelled_ledger_denies_previously_signed_context(self):
        token = self.publish()
        self.store.cancel(self.lease, "cancelled")
        self.deny(self.verify, token)

    def test_wrong_lease_worker_boot_and_root_policy_replay(self):
        token = self.publish()
        self.deny(self.verify, token, lease_id="0" * 32)
        self.deny(self.verify, token, worker=replace(self.worker, pid=self.worker.pid + 1))
        self.deny(self.verify, token, worker=replace(self.worker,
                  boot_id="22345678-1234-4234-8234-123456789abc"))
        for key in ("cell_sha256", "custody_policy_sha256", "controller_sha256", "ee_sha256", "engine_policy_sha256"):
            self.deny(self.verify, token, policy=replace(self.policy, **{key: "1" * 64}))
        self.deny(self.verify, token, policy=replace(self.policy, identity=replace(
            self.policy.identity, repository="example/other")))
        self.deny(self.verify, token, policy=replace(self.policy, identity=replace(
            self.policy.identity, required_native_job_name="different-native-cell")))
        self.deny(self.verify, token, policy=replace(self.policy, project="different-project"))
        self.deny(self.verify, token, policy=replace(self.policy, server="https://other.example.test:8443"))

    def test_issue_rejects_schema_attempt_runtime_extra_and_recursive_binding(self):
        for mutation in ({"schema": 1}, {"schema": True}, {"run_attempt": "2"},
                         {"runtime": {"firewall_controller": "host"}}, {"admission": "a.b.c"},
                         {"run_id": {"admission": "recursive"}}, {"extra": "field"}):
            changed = self.binding | mutation
            self.deny(self.issue, binding=changed)

    def bridge_runtime(self):
        return {"firewall_controller": "incus", "bridge": {
            "name": "lit" + "a" * 12, "project": "default", "owner": "synthetic/owner",
            "ipv4_address": "10.77.2.1/24", "dns_domain": "synthetic.invalid", "dhcp": True,
            "nat": True, "firewall": True, "ipv6_address": "none"}, "storage_pool": "approved-pool"}

    def test_full_bridge_facts_are_bound_to_root_policy_body_and_files(self):
        runtime = self.bridge_runtime()
        self.policy = replace(self.policy, expected_runtime=ledger.canonical(runtime))
        self.binding["runtime"] = deepcopy(runtime)
        self.save_binding()
        token = self.publish()
        self.assertEqual(self.verify(token)["lease_id"], self.lease)
        payload = identity.decode_json(identity.unbase(token.split(".")[1]))
        self.assertEqual(payload["binding_sha256"], ledger.digest(self.binding))
        changed = deepcopy(runtime)
        changed["bridge"]["owner"] = "another/wellformed-owner"
        self.deny(self.verify, token, policy=replace(self.policy, expected_runtime=ledger.canonical(changed)))
        self.binding["runtime"] = changed
        self.save_binding()
        self.deny(self.issue)  # Valid syntax and own Root key cannot replace policy facts.

    def test_full_runtime_requires_explicit_root_expectation_not_legacy_policy(self):
        self.binding["runtime"] = self.bridge_runtime()
        self.save_binding()
        self.deny(self.issue)

    def test_bridge_runtime_closed_types_and_network_semantics(self):
        runtime = self.bridge_runtime()
        changes = (lambda v: v.update(extra=True), lambda v: v["bridge"].update(extra=True),
                   lambda v: v["bridge"].update(dhcp="true"), lambda v: v["bridge"].update(nat=1),
                   lambda v: v["bridge"].update(firewall=False), lambda v: v["bridge"].update(project="lease"),
                   lambda v: v["bridge"].update(ipv4_address="10.77.2.0/24"),
                   lambda v: v["bridge"].update(ipv4_address="10.77.2.1"),
                   lambda v: v["bridge"].update(ipv6_address="auto"), lambda v: v.update(storage_pool="foreign/pool"))
        for change in changes:
            value = deepcopy(runtime)
            change(value)
            with self.subTest(runtime=value):
                self.deny(context._runtime, value)

    def test_cannot_resign_lease_under_changed_full_root_identity_policy(self):
        # Keep caller/reusable SHA, Worker, cell and custody unchanged. Align
        # repository binding too, so tuple validation cannot mask a missing
        # durable identity-policy digest check on the issuance boundary.
        for mutation in ({"repository": "example/other"}, {"repository_id": 124}, {"owner_id": 457},
                         {"workflow_id": 790}, {"workflow_path": ".github/workflows/other.yml"},
                         {"required_native_job_name": "other-native-cell"}, {"actor_ids": frozenset({43})},
                         {"subject": "repo:example/repository:ref:refs/heads/other"},
                         {"reusable_repository": "example/other-controllers"},
                         {"reusable_path": ".github/workflows/other-vm.yml"}, {"visibility": "private"}):
            with self.subTest(mutation=mutation):
                changed = replace(self.policy.identity, **mutation)
                binding = self.binding | {"repository": changed.repository}
                self.write(self.directory / "binding.json", ledger.canonical(binding))
                with self.assertRaises(identity.Denied) as caught:
                    self.issue(policy=replace(self.policy, identity=changed), binding=binding)
                self.assertEqual(str(caught.exception), "context-lease-binding")

    def test_standalone_identity_without_full_policy_digest_cannot_sign(self):
        self.store.close(self.lease)
        challenge = self.store.challenge(self.worker)
        standalone = replace(self.who, run_id=502, check_run_id=732, policy_sha256=None,
                             token_id_sha256=hashlib.sha256(b"synthetic-standalone-token").hexdigest(),
                             audience=challenge["audience"])
        self.lease = self.store.prepare(challenge["nonce"], self.worker, standalone,
                                       policy_sha256=self.policy.custody_policy_sha256,
                                       cell_sha256=self.policy.cell_sha256, deadline=self.policy.deadline)
        self.binding["run_id"] = "502"
        self.save_binding()
        with self.assertRaises(identity.Denied) as caught:
            self.issue()
        self.assertEqual(str(caught.exception), "context-lease-binding")

    def test_key_private_pin_link_and_rotation_denied(self):
        self.key_path.chmod(0o644)
        self.deny(context.RootSigner, str(self.key_path), self.pub)
        self.key_path.chmod(0o600)
        self.deny(context.RootSigner, str(self.key_path), raw_public(Ed25519PrivateKey.generate()))
        link = self.root / "key-link"
        link.symlink_to(self.key_path)
        self.deny(context.RootSigner, str(link), self.pub)
        new = Ed25519PrivateKey.generate()
        self.write(self.key_path, new.private_bytes(serialization.Encoding.PEM,
                   serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.deny(self.issue)

    def test_encrypted_key_no_prompt_or_generation(self):
        self.write(self.key_path, self.key.private_bytes(serialization.Encoding.PEM,
                   serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"synthetic-only")))
        self.deny(context.RootSigner, str(self.key_path), self.pub)
        self.deny(context.RootSigner, str(self.root / "missing-key"), self.pub)
        self.assertFalse((self.root / "missing-key").exists())

    def test_same_public_key_file_replacement_requires_explicit_reprovisioning(self):
        raw = self.key_path.read_bytes()
        replacement = self.root / "replacement-key.pem"
        self.write(replacement, raw)
        os.replace(replacement, self.key_path)
        self.deny(self.issue)

    def test_missing_context_file_and_directory_permissions_denied(self):
        token = self.publish()
        self.directory.chmod(0o755)
        self.deny(self.verify, token)
        self.directory.chmod(0o700)
        (self.directory / "client.crt").unlink()
        self.deny(self.verify, token)

    def test_context_file_modes_hardlink_symlink_and_inventory(self):
        token = self.publish()
        path = self.directory / "client.key"
        path.chmod(0o644)
        self.deny(self.verify, token)
        path.chmod(0o600)
        link = self.root / "hardlink"
        os.link(path, link)
        self.deny(self.verify, token)
        link.unlink()
        (self.directory / "extra").write_bytes(b"synthetic")
        self.deny(self.verify, token)

    def test_refresh_invalidates_old_authorization_snapshot(self):
        token = self.publish()
        challenge = self.store.challenge(self.worker)
        refreshed = replace(self.who, valid_until=NOW + 110, audience=challenge["audience"],
                            token_id_sha256=hashlib.sha256(b"synthetic-refreshed").hexdigest())
        self.store.refresh_identity(self.lease, challenge["nonce"], self.worker, refreshed)
        self.deny(self.verify, token)

    def test_nonroot_callers_denied_before_signing_or_verification(self):
        with mock.patch.object(context.os, "geteuid", return_value=2101):
            self.deny(context.RootSigner, str(self.key_path), self.pub)
            self.deny(self.issue)
            self.deny(self.verify, "a.b.c")

    def previous_binding(self, token, **changes):
        values = dict(pinned_public_key=self.pub, store=self.store, lease_id=self.lease, worker=self.worker,
                      policy=self.policy, binding=self.binding, context_dir=str(self.directory)) | changes
        return context.verify_previous_binding(token, **values)

    def rotate_expired_authorization(self):
        token = self.publish()
        self.clock = NOW + 91  # Old authorization90 has expired; hard deadline120 has not.
        challenge = self.store.challenge(self.worker)
        fresh = replace(self.who, valid_until=NOW + 115, audience=challenge["audience"],
                        token_id_sha256=hashlib.sha256(b"fresh-current-integrity-test").hexdigest())
        self.store.refresh_identity(self.lease, challenge["nonce"], self.worker, fresh)
        return token

    def test_previous_binding_authenticates_only_integrity_under_separate_fresh_live_authority(self):
        token = self.rotate_expired_authorization()
        self.deny(self.verify, token)
        result = self.previous_binding(token)
        self.assertEqual(result, {"lease_id": self.lease, "binding_sha256": ledger.digest(self.binding)})
        self.assertNotIn("expires_at", result)
        self.assertEqual(self.store.read(self.lease)["expires_at"], NOW + 120)

    def test_previous_binding_rejects_changed_files_and_unrecorded_old_authorization(self):
        token = self.rotate_expired_authorization()
        path = self.directory / context.FILES[0]
        original = path.read_bytes()
        self.write(path, original + b"changed")
        self.deny(self.previous_binding, token)
        self.write(path, original)
        payload = identity.decode_json(identity.unbase(token.split(".")[1]))
        payload["authorization"]["token_id_sha256"] = "c" * 64
        forged = self.forge(token, payload=payload)
        self.save_binding(forged)
        self.deny(self.previous_binding, forged)
        payload = identity.decode_json(identity.unbase(token.split(".")[1]))
        payload["authorization"]["valid_until"] = float(payload["authorization"]["valid_until"])
        forged = self.forge(token, payload=payload)
        self.save_binding(forged)
        self.deny(self.previous_binding, forged)

    def test_previous_binding_rejects_signature_drift_and_current_expiry_or_hard_deadline(self):
        token = self.rotate_expired_authorization()
        pieces = token.split(".")
        signature = bytearray(identity.unbase(pieces[2]))
        signature[0] ^= 1
        wrong = pieces[0] + "." + pieces[1] + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")
        self.save_binding(wrong)
        self.deny(self.previous_binding, wrong)
        self.save_binding(token)
        self.clock = NOW + 116
        self.deny(self.previous_binding, token)
        self.clock = NOW + 121
        self.deny(self.previous_binding, token)

    def test_previous_binding_has_no_time_or_authorization_override_or_nonroot_entry(self):
        token = self.rotate_expired_authorization()
        for extra in ({"now": NOW}, {"authorization": self.store.read(self.lease)["authorizations"][0]}):
            with self.assertRaises(TypeError):
                self.previous_binding(token, **extra)
        with mock.patch.object(context.os, "geteuid", return_value=2101):
            self.deny(self.previous_binding, token)


if __name__ == "__main__":
    unittest.main()
