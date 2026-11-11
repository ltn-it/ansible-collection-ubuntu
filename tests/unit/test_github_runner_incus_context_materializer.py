"""Real Root private FS/crypto fixtures, never an Incus/native service grant.

The existing semantic fixture models only the fixed Podman binary read; other
registry, lease, descriptor, PEM and new context filesystem reads are real.
"""
from dataclasses import FrozenInstanceError, replace
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import test_github_runner_incus_cell_contract as fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import context_materializer as materializer, engine_policy, identity, signed_context  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class LegacyCertificateView:
    """Delegate real X509 fields while hiding properties absent before42."""
    def __init__(self, certificate):
        self.certificate = certificate

    def __getattr__(self, name):
        if name in {"not_valid_before_utc", "not_valid_after_utc"}:
            raise AttributeError(name)
        if name in {"not_valid_before", "not_valid_after"}:
            # Model pre42 naive UTC from the same real certificate without
            # invoking deprecated properties on the modern qualification EE.
            try:
                return getattr(self.certificate, name + "_utc").replace(tzinfo=None)
            except AttributeError:
                return getattr(self.certificate, name)
        return getattr(self.certificate, name)


def server_pem(*, expired=False, lifetime_seconds=86400):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "private-fixture-server")])
    now = dt.datetime.fromtimestamp(fixtures.cell.time.time(), dt.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now - dt.timedelta(minutes=1) if expired else now + dt.timedelta(seconds=lifetime_seconds))
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM))


class MaterializerAPITests(unittest.TestCase):
    def test_nonroot_guard_and_no_independent_path_server_or_key_arguments(self):
        with mock.patch.object(materializer.os, "geteuid", return_value=2101):
            with self.assertRaisesRegex(Denied, "materialization-root-required"):
                materializer.materialize(None, None)
        for extra in ({"path": "/untrusted"}, {"server": "https://foreign"}, {"key": b"caller-key"}):
            with self.assertRaises(TypeError):
                materializer.materialize(None, None, **extra)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootContextMaterializerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.RootCellContractTests.setUpClass()

    def setUp(self):
        class FixtureDateTime(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls.fromtimestamp(fixtures.cell.time.time(), tz)

        # The nested admission fixture freezes time.time. Keep the materializer
        # wall-clock seam aligned without weakening production expiry checks.
        clock = mock.patch.object(materializer, "dt", SimpleNamespace(
            datetime=FixtureDateTime, timezone=dt.timezone, timedelta=dt.timedelta))
        clock.start()
        self.addCleanup(clock.stop)
        self.fixture = self.real_fixture(None)
        self.store, self.lease = self.fixture.store, self.fixture.lease
        self.prepared = self.fixture.prepare()
        self.context = Path(identity.decode_json(self.prepared.engine_descriptor_bytes)["context_path"])
        self.descriptor = Path(self.prepared.engine_descriptor_path)
        for operation, target in (("network-create", "network:default:" + self.prepared.incus["network"]),
                                  ("project-create", "project:" + self.prepared.incus["project"]),
                                  ("profile-configure", "profile:" + self.prepared.incus["project"] + ":default")):
            effect = self.store.begin(self.lease, operation, target)
            self.store.record(self.lease, effect, "verified", evidence_sha256="f" * 64)

    def real_fixture(self, pin):
        fixture = fixtures.RootCellContractTests()
        original = fixture.seal

        def seal_real_pin():
            selected = fixture.value["incus"]["server_certificate"]
            selected_pin = server_pem() if pin is None else pin
            if pin is None:
                self.pin = selected_pin
            Path(selected["path"]).write_bytes(selected_pin)
            selected["sha256"] = hashlib.sha256(selected_pin).hexdigest()
            original()

        fixture.seal = seal_real_pin
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        return fixture

    def effects(self):
        return [effect for effect in self.store.read(self.lease)["effects"].values()
                if effect["operation"] == "context-create"]

    def test_actual_crypto_files_config_and_descriptor_are_verified_without_admission_or_grant(self):
        receipt = materializer.materialize(self.prepared, self.store)
        self.assertEqual(receipt.lease_id, self.lease)
        self.assertEqual(self.effects()[0]["state"], "verified")
        self.assertEqual(receipt.context_path, str(self.context))
        self.assertEqual(self.descriptor.read_bytes(), self.prepared.engine_descriptor_bytes)
        client = x509.load_pem_x509_certificate((self.context / "client.crt").read_bytes())
        key = serialization.load_pem_private_key((self.context / "client.key").read_bytes(), password=None)
        self.assertIsInstance(key.curve, ec.SECP256R1)
        self.assertEqual(key.public_key().public_numbers(), client.public_key().public_numbers())
        client.public_key().verify(client.signature, client.tbs_certificate_bytes, ec.ECDSA(client.signature_hash_algorithm))
        self.assertEqual(materializer._certificate_validity(client)[1].timestamp(), self.prepared.expires_at)
        self.assertEqual(client.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value,
                         x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]))
        self.assertFalse(client.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertEqual(receipt.certificate_der, client.public_bytes(serialization.Encoding.DER))
        self.assertEqual(receipt.certificate_fingerprint_sha256, hashlib.sha256(receipt.certificate_der).hexdigest())
        self.assertEqual((self.context / "servercerts/quality.crt").read_bytes(), self.pin)
        binding = json.loads((self.context / "binding.json").read_bytes())
        self.assertEqual(binding["schema"], 2)
        self.assertNotIn("admission", binding)
        self.assertEqual(binding["project"], self.prepared.incus["project"])
        self.assertEqual(binding["run_id"], str(self.prepared.incus["ownership"]["run_id"]))
        self.assertEqual(binding["runtime"], signed_context.runtime_for_cell(self.prepared))
        self.assertEqual(binding["runtime"]["bridge"]["ipv4_address"], self.prepared.incus["ipv4_address"])
        self.assertEqual(binding["runtime"]["bridge"]["owner"], self.prepared.incus["ownership"]["owner"])
        self.assertEqual(binding["runtime"]["storage_pool"], self.prepared.incus["pool"])
        self.assertEqual(dt.datetime.fromisoformat(binding["expires_at"]).timestamp(), self.prepared.expires_at)
        self.assertEqual(binding["expires_at"], dt.datetime.fromtimestamp(
            self.prepared.expires_at, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        config = json.loads(receipt.config_bytes)
        self.assertEqual(config["default-remote"], "quality")
        self.assertEqual(config["remotes"]["quality"]["addr"], self.prepared.incus["server"])
        self.assertEqual(config["remotes"]["quality"]["project"], self.prepared.incus["project"])
        for path in (self.context, self.context / "servercerts"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        for name, digest in receipt.files:
            path = self.context / name
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_uid, 0)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        self.assertEqual(stat.S_IMODE(self.descriptor.stat().st_mode), 0o600)
        self.assertNotIn("PRIVATE KEY", repr(receipt))
        with self.assertRaises(FrozenInstanceError):
            receipt.context_path = "/foreign"

    def test_durable_context_intent_precedes_first_local_write(self):
        original = materializer.os.mkdir

        def mkdir(*args, **kwargs):
            effects = self.effects()
            self.assertEqual(len(effects), 1)
            self.assertEqual(effects[0]["state"], "intent")
            return original(*args, **kwargs)

        with mock.patch.object(materializer.os, "mkdir", side_effect=mkdir):
            materializer.materialize(self.prepared, self.store)

    def test_replay_and_existing_context_or_descriptor_are_never_adopted(self):
        self.context.mkdir(mode=0o700)
        marker = self.context / "foreign"
        marker.write_bytes(b"retain")
        with self.assertRaises(materializer.MaterializationDenied):
            materializer.materialize(self.prepared, self.store)
        self.assertEqual(marker.read_bytes(), b"retain")
        self.assertEqual(self.effects(), [])
        marker.unlink()
        self.context.rmdir()
        self.descriptor.write_bytes(b"pre-existing")
        self.descriptor.chmod(0o600)
        with self.assertRaises(materializer.MaterializationDenied):
            materializer.materialize(self.prepared, self.store)
        self.assertEqual(self.descriptor.read_bytes(), b"pre-existing")
        self.descriptor.unlink()
        receipt = materializer.materialize(self.prepared, self.store)
        before = (self.context / "client.key").read_bytes()
        with self.assertRaises(materializer.MaterializationDenied):
            materializer.materialize(self.prepared, self.store)
        self.assertEqual((self.context / "client.key").read_bytes(), before)
        self.assertEqual(self.effects()[0]["state"], "verified")
        self.assertEqual(len(self.effects()), 1)
        self.assertEqual(receipt.engine_descriptor_sha256, self.prepared.engine_descriptor_sha256)

    def test_borrowed_prepared_and_pin_byte_drift_deny_before_intent(self):
        with self.assertRaises(materializer.MaterializationDenied):
            materializer.materialize(replace(self.prepared, expires_at=self.prepared.expires_at + 1), self.store)
        Path(self.prepared.incus["server_certificate"]["path"]).write_bytes(b"malformed private PEM")
        with self.assertRaises(materializer.MaterializationDenied):
            materializer.materialize(self.prepared, self.store)
        self.assertEqual(self.effects(), [])
        self.assertFalse(self.context.exists())

    def test_private_pin_must_be_one_parseable_certificate_before_any_effect(self):
        for pin in (b"Root sealed but not a PEM certificate", self.pin + self.pin):
            fixture = self.real_fixture(pin)
            prepared = fixture.prepare()
            before = fixture.store.read(fixture.lease)["effects"]
            with self.subTest(pin_size=len(pin)), self.assertRaisesRegex(
                    materializer.MaterializationDenied, "^materialization-denied$"):
                materializer.materialize(prepared, fixture.store)
            self.assertEqual(fixture.store.read(fixture.lease)["effects"], before)
            self.assertFalse(Path(identity.decode_json(prepared.engine_descriptor_bytes)["context_path"]).exists())

    def test_actual_expired_sealed_pin_denies_without_intent_or_context(self):
        fixture = self.real_fixture(server_pem(expired=True))
        prepared = fixture.prepare()
        with self.assertRaises(materializer.MaterializationDenied):
            materializer.materialize(prepared, fixture.store)
        self.assertEqual(fixture.store.read(fixture.lease)["effects"], {})
        self.assertFalse(Path(identity.decode_json(prepared.engine_descriptor_bytes)["context_path"]).exists())

    def test_real_modern_and_pre42_pins_preserve_expiry_and_exact_lease_boundary(self):
        parse = x509.load_pem_x509_certificate
        real = parse(self.pin)
        self.assertEqual(materializer._certificate_validity(real),
                         materializer._certificate_validity(LegacyCertificateView(real)))
        remaining = self.prepared.expires_at - int(fixtures.cell.time.time())
        for legacy in (False, True):
            for seconds, allowed in ((remaining, True), (remaining - 1, False), (-1, False)):
                fixture = self.real_fixture(server_pem(lifetime_seconds=seconds))
                prepared = fixture.prepare()
                for operation, target in (("network-create", "network:default:" + prepared.incus["network"]),
                                          ("project-create", "project:" + prepared.incus["project"]),
                                          ("profile-configure", "profile:" + prepared.incus["project"] + ":default")):
                    effect = fixture.store.begin(fixture.lease, operation, target)
                    fixture.store.record(fixture.lease, effect, "verified", evidence_sha256="f" * 64)
                before = fixture.store.read(fixture.lease)["effects"]
                factory = (lambda raw: LegacyCertificateView(parse(raw))) if legacy else parse
                with self.subTest(legacy=legacy, pin_lifetime=seconds), mock.patch.object(
                        materializer.x509, "load_pem_x509_certificate", side_effect=factory):
                    if allowed:
                        result = materializer.materialize(prepared, fixture.store)
                        client = x509.load_der_x509_certificate(result.certificate_der)
                        self.assertEqual(materializer._certificate_validity(client)[1].timestamp(), prepared.expires_at)
                    else:
                        with self.assertRaises(materializer.MaterializationDenied):
                            materializer.materialize(prepared, fixture.store)
                        self.assertEqual(fixture.store.read(fixture.lease)["effects"], before)

    def test_partial_key_write_failure_keeps_owned_files_unknown_and_no_retry(self):
        original = materializer._write

        def fail_after_key(fd, name, raw):
            original(fd, name, raw)
            if name == "client.key":
                raise OSError("secret-error-not-disclosed")

        with mock.patch.object(materializer, "_write", side_effect=fail_after_key):
            with self.assertRaisesRegex(materializer.MaterializationUnknown, "^materialization-unknown$"):
                materializer.materialize(self.prepared, self.store)
        self.assertTrue((self.context / "client.key").is_file())
        self.assertEqual(self.effects()[0]["state"], "unknown")
        self.assertFalse(self.descriptor.exists())
        before = (self.context / "client.key").read_bytes()
        with self.assertRaises(materializer.MaterializationDenied):
            materializer.materialize(self.prepared, self.store)
        self.assertEqual((self.context / "client.key").read_bytes(), before)
        with self.assertRaises(Denied):
            self.store.close(self.lease)

    def test_descriptor_write_then_failure_retains_full_context_and_unknown_intent(self):
        original = materializer._write

        def fail_after_descriptor(fd, name, raw):
            original(fd, name, raw)
            if name == self.descriptor.name:
                raise OSError("simulated-after-write")

        with mock.patch.object(materializer, "_write", side_effect=fail_after_descriptor):
            with self.assertRaises(materializer.MaterializationUnknown):
                materializer.materialize(self.prepared, self.store)
        self.assertEqual(self.descriptor.read_bytes(), self.prepared.engine_descriptor_bytes)
        self.assertTrue((self.context / "servercerts/quality.crt").exists())
        self.assertEqual(self.effects()[0]["state"], "unknown")

    def test_readback_drift_never_records_verified_or_erases_partial_state(self):
        original = materializer._write

        def corrupt_after_descriptor(fd, name, raw):
            original(fd, name, raw)
            if name == self.descriptor.name:
                (self.context / "config.yml").write_bytes(b'{"foreign":true}')

        with mock.patch.object(materializer, "_write", side_effect=corrupt_after_descriptor):
            with self.assertRaises(materializer.MaterializationUnknown):
                materializer.materialize(self.prepared, self.store)
        self.assertEqual(self.effects()[0]["state"], "unknown")
        self.assertEqual((self.context / "config.yml").read_bytes(), b'{"foreign":true}')

    def test_first_mkdir_failure_is_unknown_even_when_no_context_became_visible(self):
        with mock.patch.object(materializer.os, "mkdir", side_effect=OSError("simulated")):
            with self.assertRaises(materializer.MaterializationUnknown):
                materializer.materialize(self.prepared, self.store)
        self.assertFalse(self.context.exists())
        self.assertEqual(self.effects()[0]["state"], "unknown")

    def test_final_verified_record_failure_keeps_complete_owned_state_unknown(self):
        original = self.store.record

        def fail_verified(identifier, effect, outcome, *, evidence_sha256):
            if outcome == "verified":
                raise OSError("simulated-journal-commit-failure")
            return original(identifier, effect, outcome, evidence_sha256=evidence_sha256)

        with mock.patch.object(self.store, "record", side_effect=fail_verified):
            with self.assertRaises(materializer.MaterializationUnknown):
                materializer.materialize(self.prepared, self.store)
        self.assertEqual(self.effects()[0]["state"], "unknown")
        self.assertTrue((self.context / "client.key").exists())
        self.assertEqual(self.descriptor.read_bytes(), self.prepared.engine_descriptor_bytes)

    def test_materialized_tls_files_compile_bind_and_sign_verify_through_actual_context_entry(self):
        receipt = materializer.materialize(self.prepared, self.store)
        descriptor = identity.decode_json(self.prepared.engine_descriptor_bytes)
        # Root engine-directory fixture preparation, not an engine execution.
        for path in (descriptor["engine"]["storage_root"], descriptor["engine"]["runroot"], descriptor["output_path"]):
            Path(path).mkdir(mode=0o700)
        compiled = engine_policy.compile_engine_policy(self.prepared.engine_descriptor_path,
                                                       self.prepared.engine_descriptor_sha256)
        bound = fixtures.cell.bind_engine(self.prepared, self.store, compiled)
        selected = self.prepared.registry.select(self.prepared.selector)
        details = identity.decode_json(self.prepared.canonical_bytes)
        policy = signed_context.ContextPolicy(
            selected.identity, self.prepared.incus["server"], self.prepared.incus["project"], self.prepared.expires_at,
            self.prepared.cell_sha256, selected.custody_policy_sha256, details["controller"]["archive_sha256"],
            compiled.image_manifest_sha256, bound.engine_policy_sha256,
            expected_runtime=fixtures.ledger.canonical(signed_context.runtime_for_cell(self.prepared)))
        key = Ed25519PrivateKey.generate()
        key_path = self.fixture.fs.root / "signer.key"
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        key_path.chmod(0o600)
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        signer = signed_context.RootSigner(str(key_path), public)
        binding_path = self.context / "binding.json"
        binding = json.loads(binding_path.read_bytes())
        worker = self.fixture.io.fixture.worker
        token = signer.issue(self.store, self.lease, worker, policy, binding, str(self.context))
        binding_path.write_text(json.dumps(binding | {"admission": token}, sort_keys=True))
        result = signed_context.verify(token, public, self.store, self.lease, worker, policy, binding, str(self.context))
        self.assertEqual(result["lease_id"], self.lease)
        payload = identity.decode_json(identity.unbase(token.split(".")[1]))
        self.assertEqual(payload["engine_policy_sha256"], bound.engine_policy_sha256)
        self.assertEqual(payload["files_sha256"]["client.crt"], dict(receipt.files)["client.crt"])
        with self.assertRaises(Denied):
            signed_context.verify(token, public, self.store, self.lease, worker,
                                  replace(policy, engine_policy_sha256="a" * 64), binding, str(self.context))


if __name__ == "__main__":
    unittest.main()
