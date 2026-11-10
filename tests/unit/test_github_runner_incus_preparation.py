"""Real Unix/Root FS/crypto component pipeline; no real daemon or native grant."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import test_github_runner_incus_context_materializer as materializer_fixtures
import test_github_runner_incus_mutation as mutation_fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import (cell_contract, context_materializer, context_publisher, identity, ledger,
                                preparation, signed_context, engine_executor)  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class PreparationAPIGuards(unittest.TestCase):
    def test_root_guard_precedes_configuration_or_ledger(self):
        with mock.patch.object(preparation.os, "geteuid", return_value=2101):
            with self.assertRaisesRegex(Denied, "preparation-root-required"):
                preparation.prepare(None, None, None, None, None, None)

    def test_no_job_supplied_worker_server_key_or_command(self):
        for extra in ({"worker": {}}, {"server": "https://caller"}, {"command": ["sh"]}, {"qualified": True}):
            with self.assertRaises(TypeError):
                preparation.prepare(None, None, None, None, None, None, **extra)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Root Linux EE only")
class RootPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        materializer_fixtures.RootContextMaterializerTests.setUpClass()

    def setUp(self):
        helper = materializer_fixtures.RootContextMaterializerTests()
        self.addCleanup(helper.doCleanups)
        self.fixture = helper.real_fixture(None)
        self.store, self.lease = self.fixture.store, self.fixture.lease
        self.prepared = self.fixture.prepare()
        self.root = self.fixture.fs.root
        class FixtureDateTime(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls.fromtimestamp(preparation.cell_contract.time.time(), tz)
        clock = mock.patch.object(context_materializer, "dt", SimpleNamespace(
            datetime=FixtureDateTime, timezone=dt.timezone, timedelta=dt.timedelta))
        clock.start()
        self.addCleanup(clock.stop)
        self.server = mutation_fixtures.MutationFixture(self.root / "incus.socket")
        self.addCleanup(self.server.close)
        self.key = self.root / "signing.pem"
        key = Ed25519PrivateKey.generate()
        self.key.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        self.key.chmod(0o600)
        self.public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.stage = self.root / "publication-staging"
        self.stage.mkdir(mode=0o700)
        self.lock = self.root / "preparation.lock"
        self.lock.write_bytes(b"")
        self.lock.chmod(0o600)
        self.fence_policy = self.root / "network-fence.json"
        self.fence_policy.write_bytes(b'{"fixture":"sealed reference only, no kernel qualification"}')
        self.fence_policy.chmod(0o600)
        self.quota_policy = self.root / "storage-quota.json"
        self.quota_policy.write_bytes(b'{"fixture":"sealed reference only, no quota grant"}')
        self.quota_policy.chmod(0o600)
        self.host_api_policy = self.root / "host-api-fence.json"
        self.host_api_policy.write_bytes(b'{"fixture":"sealed reference only, no endpoint grant"}')
        self.host_api_policy.chmod(0o600)
        self.config = self.root / "preparation.json"
        self.value = {"schema": 1, "registry_path": self.fixture.registry.path,
                      "registry_sha256": self.fixture.registry.sha256, "incus_socket_path": str(self.server.path),
                      "signing_key_path": str(self.key), "signing_public_key_hex": self.public.hex(),
                      "publication_staging_parent": str(self.stage), "lock_path": str(self.lock),
                      "operation_wait_seconds": 1, "network_fence_policy_path": str(self.fence_policy),
                      "network_fence_policy_sha256": hashlib.sha256(self.fence_policy.read_bytes()).hexdigest(),
                      "storage_quota_policy_path": str(self.quota_policy),
                      "storage_quota_policy_sha256": hashlib.sha256(self.quota_policy.read_bytes()).hexdigest(),
                      "host_api_fence_policy_path": str(self.host_api_policy),
                      "host_api_fence_policy_sha256": hashlib.sha256(self.host_api_policy.read_bytes()).hexdigest()}
        self.seal()
        # This component fixture has no native Podman or quota grant. The
        # dedicated image-provision tests replace this boundary with a real
        # subprocess and explicit synthetic backend/quota observations.
        image = mock.patch.object(engine_executor, "_provision_image")
        self.image_provision = image.start()
        self.addCleanup(image.stop)

    def seal(self):
        self.config.write_bytes(ledger.canonical(self.value))
        self.config.chmod(0o600)
        self.sha = hashlib.sha256(self.config.read_bytes()).hexdigest()

    def run_prepare(self):
        return preparation.prepare(str(self.config), self.sha, self.fixture.registry, "approved", self.store, self.lease)

    def effects(self):
        return list(self.store.read(self.lease)["effects"].values())

    def effect(self, operation):
        matches = [value for value in self.effects() if value["operation"] == operation]
        self.assertEqual(len(matches), 1, "one retained effect for this operation")
        return matches[0]

    def writes(self):
        return [value for value in self.server.requests if value[0] != "GET"]

    def assert_unknown_and_no_retry(self):
        with self.assertRaises(preparation.PreparationUnknown):
            self.run_prepare()
        count = len(self.writes())
        self.assertTrue(any(e["state"] in {"intent", "unknown"} for e in self.effects()))
        with self.assertRaises(preparation.PreparationDenied):
            self.run_prepare()
        self.assertEqual(len(self.writes()), count)

    def test_full_actual_component_pipeline_and_signed_live_binding(self):
        result = self.run_prepare()
        self.assertEqual(result.lease_id, self.lease)
        expected = ["network-create", "project-create", "profile-configure", "context-create",
                    "certificate-create", "engine-prepare", "context-publish"]
        # Canonical persisted JSON orders random effect IDs, not execution.
        self.assertCountEqual([e["operation"] for e in self.effects()], expected)
        self.assertTrue(all(e["state"] == "verified" for e in self.effects()))
        self.assertEqual([(r[0], r[1]) for r in self.writes()], [
            ("POST", "/1.0/networks?project=default"), ("POST", "/1.0/projects"),
            ("PUT", "/1.0/profiles/default?project=" + self.prepared.incus["project"]),
            ("POST", "/1.0/certificates")])
        descriptor = identity.decode_json(self.prepared.engine_descriptor_bytes)
        directory = Path(descriptor["context_path"])
        body = json.loads((directory / "binding.json").read_bytes())
        self.assertIn("admission", body)
        self.assertEqual(hashlib.sha256((directory / "binding.json").read_bytes()).hexdigest(), result.binding_sha256)
        payload = identity.decode_json(identity.unbase(body["admission"].split(".")[1]))
        self.assertEqual(payload["engine_policy_sha256"], result.engine_policy_sha256)
        self.assertEqual(payload["cell_sha256"], self.prepared.cell_sha256)
        self.assertEqual(body["runtime"], signed_context.runtime_for_cell(self.prepared))
        self.assertEqual(payload["binding_sha256"], ledger.digest({k: v for k, v in body.items() if k != "admission"}))
        self.assertEqual(payload["policy"]["required_native_job_name"], self.fixture.registry.select("approved").identity.required_native_job_name)
        self.assertEqual(list(self.stage.iterdir()), [])
        self.assertNotIn("PRIVATE KEY", repr(result))
        self.assertNotIn("engine-start", [e["operation"] for e in self.effects()])
        for path in (descriptor["engine"]["storage_root"], descriptor["engine"]["runroot"], descriptor["output_path"]):
            self.assertEqual(stat.S_IMODE(Path(path).stat().st_mode), 0o700)

    def test_every_native_write_observes_actual_durable_intent_first(self):
        original = self.server.handle
        seen = []
        def handle(method, path, body):
            if method != "GET":
                intents = [e for e in self.effects() if e["state"] == "intent"]
                self.assertEqual(len(intents), 1)
                seen.append(intents[0]["operation"])
            return original(method, path, body)
        self.server.handle = handle
        self.run_prepare()
        self.assertEqual(seen, ["network-create", "project-create", "profile-configure", "certificate-create"])

    def test_completed_preparation_does_not_repeat_any_effect(self):
        self.run_prepare()
        count = len(self.writes())
        with self.assertRaises(preparation.PreparationDenied):
            self.run_prepare()
        self.assertEqual(len(self.writes()), count)

    def test_lost_native_response_retains_unknown_and_never_retries(self):
        original = self.server.handle
        def handle(method, path, body):
            result = original(method, path, body)
            return b"" if method == "POST" else result
        self.server.handle = handle
        self.assert_unknown_and_no_retry()
        self.assertEqual(len(self.writes()), 1)

    def test_async_completion_id_is_bound_before_operation_readback(self):
        original = self.server.handle
        def handle(method, path, body):
            if method == "POST" and path.startswith("/1.0/networks"):
                self.server.async_mode = True
                try:
                    return original(method, path, body)
                finally:
                    self.server.async_mode = False
            if path.startswith("/1.0/operations/"):
                self.assertEqual(self.effect("network-create")["incus_operation_id"], mutation_fixtures.OPERATION)
            return original(method, path, body)
        self.server.handle = handle
        self.server.operation_code = 200
        self.run_prepare()
        self.assertEqual(self.effect("network-create")["incus_operation_id"], mutation_fixtures.OPERATION)

    def test_pending_async_is_unknown_despite_matching_visible_resource(self):
        self.server.async_mode = True
        started = time.monotonic()
        self.assert_unknown_and_no_retry()
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(len(self.writes()), 1)
        self.assertIn("/1.0/networks/" + self.prepared.incus["network"] + "?project=default", self.server.resources)

    def test_pending_then_successful_readonly_poll_continues_without_repeat_write(self):
        original = self.server.handle
        polls = []
        def handle(method, path, body):
            if method == "POST" and path.startswith("/1.0/networks"):
                self.server.async_mode = True
                try:
                    return original(method, path, body)
                finally:
                    self.server.async_mode = False
            result = original(method, path, body)
            if path.startswith("/1.0/operations/"):
                polls.append(self.server.operation_code)
                self.server.operation_code = 200
            return result
        self.server.handle = handle
        self.run_prepare()
        self.assertEqual(polls, [103, 200])
        self.assertEqual(len(self.writes()), 4)
        self.assertEqual(self.effect("network-create")["state"], "verified")

    def test_terminal_async_failure_holds_without_wait_or_repeat_write(self):
        self.server.async_mode = True
        self.server.operation_code = 400
        self.assert_unknown_and_no_retry()
        self.assertEqual(len(self.writes()), 1)
        self.assertEqual(sum(path.startswith("/1.0/operations/") for _, path, _ in self.server.requests), 1)

    def test_config_drift_during_pending_poll_holds(self):
        self.server.async_mode = True
        original = self.server.handle
        def handle(method, path, body):
            result = original(method, path, body)
            if path.startswith("/1.0/operations/"):
                self.config.write_bytes(b"changed Root config")
            return result
        self.server.handle = handle
        self.assert_unknown_and_no_retry()
        self.assertEqual(len(self.writes()), 1)

    def test_auth_expiry_during_pending_poll_holds(self):
        self.server.async_mode = True
        original = self.server.handle
        initial = cell_contract.time.time()
        clock = mock.patch.object(cell_contract.time, "time", return_value=initial + 301)
        def handle(method, path, body):
            result = original(method, path, body)
            if path.startswith("/1.0/operations/"):
                clock.start()
            return result
        self.addCleanup(clock.stop)
        self.server.handle = handle
        self.assert_unknown_and_no_retry()
        self.assertEqual(len(self.writes()), 1)

    def test_late_initial_preparation_denies_before_any_effect(self):
        now = int(preparation.time.time())
        with mock.patch.object(preparation.time, "time", return_value=now + 1):
            with self.assertRaises(preparation.PreparationDenied):
                self.run_prepare()
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.effects(), [])

    def test_root_host_api_policy_reference_mandatory_and_hash_bound_before_effects(self):
        original = dict(self.value)
        for field in ("host_api_fence_policy_path", "host_api_fence_policy_sha256"):
            self.value = dict(original)
            del self.value[field]
            self.seal()
            with self.assertRaises(preparation.PreparationDenied):
                self.run_prepare()
        self.value = original
        self.seal()
        self.host_api_policy.write_bytes(b'{"changed":true}')
        with self.assertRaises(preparation.PreparationDenied):
            self.run_prepare()
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.effects(), [])

    def test_root_quota_policy_reference_mandatory_and_hash_bound_before_effects(self):
        original = dict(self.value)
        for field in ("storage_quota_policy_path", "storage_quota_policy_sha256"):
            self.value = dict(original)
            del self.value[field]
            self.seal()
            with self.assertRaises(preparation.PreparationDenied):
                self.run_prepare()
        self.value = original
        self.seal()
        self.quota_policy.write_bytes(b'{"changed":true}')
        with self.assertRaises(preparation.PreparationDenied):
            self.run_prepare()
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.effects(), [])

    def test_root_fence_policy_reference_mandatory_and_hash_bound_before_effects(self):
        original = dict(self.value)
        for field in ("network_fence_policy_path", "network_fence_policy_sha256"):
            self.value = dict(original)
            del self.value[field]
            self.seal()
            with self.assertRaises(preparation.PreparationDenied):
                self.run_prepare()
        self.value = original
        self.seal()
        self.fence_policy.write_bytes(b'{"changed":true}')
        with self.assertRaises(preparation.PreparationDenied):
            self.run_prepare()
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.effects(), [])

    def test_operation_wait_budget_is_mandatory_strict_integer(self):
        for value in (None, True, 0, 61, "1"):
            self.value["operation_wait_seconds"] = value
            self.seal()
            with self.assertRaises(preparation.PreparationDenied):
                self.run_prepare()
        del self.value["operation_wait_seconds"]
        self.seal()
        with self.assertRaises(preparation.PreparationDenied):
            self.run_prepare()
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.effects(), [])

    def test_native_readback_conflict_is_not_success_or_reconciliation(self):
        original = self.server.handle
        def handle(method, path, body):
            result = original(method, path, body)
            if method == "POST" and path.startswith("/1.0/networks"):
                resource = self.server.resources["/1.0/networks/" + body["name"] + "?project=default"]
                resource["config"]["user.lit-molecule-owner"] = "foreign-owner"
            return result
        self.server.handle = handle
        self.assert_unknown_and_no_retry()

    def test_bridge_drift_before_materialization_denies_full_context(self):
        original = self.server.handle
        network_path = "/1.0/networks/" + self.prepared.incus["network"] + "?project=default"
        def handle(method, path, body):
            result = original(method, path, body)
            if method == "PUT" and path.startswith("/1.0/profiles/"):
                self.server.resources[network_path]["config"]["ipv4.address"] = "10.99.1.1/24"
            return result
        self.server.handle = handle
        with self.assertRaises(preparation.PreparationUnknown):
            self.run_prepare()
        self.assertFalse(any(e["operation"] in {"context-create", "certificate-create", "context-publish"} for e in self.effects()))

    def test_bridge_drift_after_context_before_issue_denies_publication(self):
        original = self.server.handle
        network_path = "/1.0/networks/" + self.prepared.incus["network"] + "?project=default"
        def handle(method, path, body):
            result = original(method, path, body)
            if method == "POST" and path == "/1.0/certificates":
                self.server.resources[network_path]["config"]["dns.domain"] = "foreign.invalid"
            return result
        self.server.handle = handle
        with self.assertRaises(preparation.PreparationUnknown):
            self.run_prepare()
        self.assertFalse(any(e["operation"] == "context-publish" for e in self.effects()))
        descriptor = identity.decode_json(self.prepared.engine_descriptor_bytes)
        self.assertNotIn("admission", json.loads((Path(descriptor["context_path"]) / "binding.json").read_bytes()))

    def test_lock_excludes_second_preparer_and_is_released_after_denial(self):
        with preparation.preparation_lock(str(self.config), self.sha):
            with self.assertRaises(preparation.PreparationDenied):
                self.run_prepare()
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.effects(), [])
        self.run_prepare()

    def test_config_hash_mode_registry_and_signing_pin_fail_before_effect(self):
        self.key.write_bytes(b"synthetic secret invalid key")
        with self.assertRaises(preparation.PreparationDenied):
            self.run_prepare()
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.effects(), [])
        self.config.chmod(0o644)
        with self.assertRaises(preparation.PreparationDenied):
            self.run_prepare()

    def test_unknown_publish_holds_and_does_not_retry_even_if_signed_binding_exists(self):
        actual = context_publisher.RootContextPublisher.publish
        def lost_reply(publisher, *args, **kwargs):
            actual(publisher, *args, **kwargs)
            raise context_publisher.PublicationUnknown("synthetic lost reply")
        with mock.patch.object(context_publisher.RootContextPublisher, "publish", lost_reply):
            self.assert_unknown_and_no_retry()
        self.assertEqual(self.effect("context-publish")["state"], "unknown")
        descriptor = identity.decode_json(self.prepared.engine_descriptor_bytes)
        self.assertIn("admission", json.loads((Path(descriptor["context_path"]) / "binding.json").read_bytes()))

    def test_partial_local_engine_directories_hold_and_are_not_adopted(self):
        original = preparation.os.mkdir
        descriptor = identity.decode_json(self.prepared.engine_descriptor_bytes)
        def mkdir(name, *args, **kwargs):
            if name == self.lease and any(e["operation"] == "engine-prepare" and e["state"] == "intent" for e in self.effects()):
                if Path(descriptor["engine"]["storage_root"]).exists():
                    raise OSError("synthetic failure after first engine dir")
            return original(name, *args, **kwargs)
        with mock.patch.object(preparation.os, "mkdir", side_effect=mkdir):
            self.assert_unknown_and_no_retry()
        self.assertTrue(Path(descriptor["engine"]["storage_root"]).is_dir())
        self.assertFalse(Path(descriptor["engine"]["runroot"]).exists())

    def test_root_metadata_version_is_not_binary_provenance_or_operating_acceptance(self):
        self.server.version = "6.0"
        with self.assertRaises(preparation.PreparationDenied):
            self.run_prepare()
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.effects(), [])
