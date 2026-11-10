"""Actual RSA admission/Root FS/publisher/renew coupling with private fixtures.

GitHub HTTPS, collector and namespace/nft observations are explicitly mocked by
the existing component fixtures. This is not native Worker, packet, operating
custody or dispatcher qualification. No host tests or external services.
"""
from dataclasses import replace
from contextlib import contextmanager, nullcontext, ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import unittest
from unittest import mock

import test_github_runner_incus_admission as admission_fixtures
import test_github_runner_incus_network_fence as fence_fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import (collector, context_publisher, engine_policy, identity, ledger, network_fence,
                                preparation, refresh, host_api_fence)  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class RefreshAPITests(unittest.TestCase):
    def test_root_factory_guard_and_no_caller_worker_policy_server_or_key_inputs(self):
        with mock.patch.object(refresh.os, "geteuid", return_value=2101):
            with self.assertRaisesRegex(Denied, "refresh-root-required"):
                refresh.RootRefresher(None, None)
        instance = object.__new__(refresh.RootRefresher)
        for extra in ({"worker": {}}, {"server": "https://caller"}, {"policy": {}}, {"key": b"caller"}):
            with self.assertRaises(TypeError):
                instance.handle(None, None, None, None, **extra)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootRefreshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fence_fixtures.RootFenceComponentTests.setUpClass()

    def setUp(self):
        self.fence = fence_fixtures.RootFenceComponentTests()
        self.fence.setUp()
        self.addCleanup(self.fence.doCleanups)
        self.io, self.store, self.lease = self.fence.io, self.fence.store, self.fence.lease
        self.io.value["network_fence_policy_path"] = str(self.fence.path)
        self.io.value["network_fence_policy_sha256"] = self.fence.sha
        self.host_path = self.io.root / "refresh-host-api.json"
        self.host_path.write_bytes(ledger.canonical({"schema": 1, "backend_ipv4": "10.10.20.30", "backend_port": 8443,
            "table": "lit_api_" + "b"*32, "host_netns": {"boot_id": network_fence.kernel.read_boot_id(), "device": 4, "inode": 5},
            "tools": {network_fence.IP: "c"*64, network_fence.NFT: "d"*64}}))
        self.host_path.chmod(0o600)
        self.host_sha = hashlib.sha256(self.host_path.read_bytes()).hexdigest()
        self.io.value.update(host_api_fence_policy_path=str(self.host_path), host_api_fence_policy_sha256=self.host_sha)
        self.io.seal()
        self.fence.config = preparation._config(str(self.io.config), self.io.sha)[0]
        self.host_exists, self.host_deadline, self.host_pair, self.host_ttl = False, 0, None, 0
        self.host_sends = []
        self.initial = self.io.run_prepare()
        # Actual maintenance baseline journal + actual creator binding, with
        # only unavailable host/private kernel observations modeled.
        with self.initial_kernel(), self.host_kernel():
            host_api_fence.install_baseline(str(self.host_path), self.host_sha, self.fence.config)
            self.fence.call(network_fence.create)
        creator = self.effects("fence-create")[0]
        self.assertIn("host_api", creator)
        self.assertEqual(self.store.host_api_claimants(self.host_sha, creator["host_api"]["baseline_sha256"]), (self.lease,))
        self.registry = self.io.fixture.registry
        self.worker = self.fence.worker
        self.admission = self.io.fixture.io.fixture
        self.native = self.admission.fixture
        self.native.job["name"] = self.registry.select("approved").identity.required_native_job_name
        descriptor = identity.decode_json(self.io.prepared.engine_descriptor_bytes)
        self.context = Path(descriptor["context_path"])
        self.old_raw = (self.context / "binding.json").read_bytes()
        self.instance = refresh.RootRefresher(str(self.io.config), self.io.sha)
        self.nft_calls = []
        self.sequence = 0

    def body(self, *, operation="refresh"):
        self.sequence += 1
        # The parent fixture's store captured its original mock clock callable.
        # Issue the new nonce through the real store with this call's current
        # clock, just like admission, including advanced-time refresh cases.
        with ledger.Ledger(self.registry.select("approved").ledger_path, clock=preparation.time.time) as issuer:
            challenge = issuer.challenge(self.worker)
        now = int(preparation.time.time())
        self.native.claims.update(aud=challenge["audience"], jti="refresh-fixture-" + str(self.sequence),
                                  iat=now, nbf=now, exp=now + 400)
        body = {"schema": 1, "operation": operation, "nonce": challenge["nonce"],
                "token": self.native.token(), "api_token": "synthetic-job-github-token"}
        if operation == "refresh":
            body["lease_id"] = self.lease
        return body

    def invoke(self, body=None):
        body = self.body() if body is None else body
        with admission_fixtures._pair() as (server, client):
            client.sendall(admission_fixtures.frame(body))
            client.shutdown(1)
            return self.instance.handle(server, self.registry, "approved", self.lease)

    def effects(self, operation):
        return [effect for effect in self.store.read(self.lease)["effects"].values()
                if effect["operation"] == operation]

    def assert_locked(self):
        with self.assertRaises(BlockingIOError):
            with preparation.preparation_lock(str(self.io.config), self.io.sha):
                self.fail("the full refresh sequence must hold the preparation lock")

    def owned(self, *_args, **_kwargs):
        deadline = min(self.store.read(self.lease)["expires_at"],
                       self.store.read(self.lease)["authorizations"][-1]["valid_until"])
        return ({}, 1000, 4, deadline)

    def nft(self, _policy, _prepared, *argv, payload=None):
        self.assert_locked()
        self.assertEqual(self.effects("context-refresh")[-1]["state"], "verified")
        auth = self.store.read(self.lease)["authorizations"][-1]
        raw = (self.context / "binding.json").read_bytes()
        self.assertNotEqual(raw, self.old_raw)
        binding = json.loads(raw)
        signed = identity.decode_json(identity.unbase(binding["admission"].split(".")[1]))
        self.assertEqual(signed["authorization"], auth)
        self.assertIsNotNone(re.search(rb"meta time < [0-9]+ accept", payload))
        self.nft_calls.append((argv, payload))
        return b""

    @contextmanager
    def initial_kernel(self):
        info = os.stat(self.fence.path)
        @contextmanager
        def namespace(prepared):
            yield -1, info
        original = network_fence.installation._open_directory
        with mock.patch.object(network_fence, "_worker"), mock.patch.object(network_fence, "_backend"), \
             mock.patch.object(network_fence, "_namespace", side_effect=namespace), \
             mock.patch.object(network_fence, "_run", return_value=b"[]"), \
             mock.patch.object(network_fence, "_nft", return_value=b""), \
             mock.patch.object(network_fence, "_links", return_value=(100, 2)), \
             mock.patch.object(network_fence, "_rules_readback", return_value=(1, 0, 4, 0)), \
             mock.patch.object(network_fence.installation, "_open_directory", side_effect=lambda path:
                 original(str(self.io.root) if path == "/run/netns" else path)):
            yield

    @contextmanager
    def host_kernel(self):
        import test_github_runner_incus_host_api_fence as host_fixtures
        def nft(policy, *args, payload=None):
            if args[-2:] == ("list", "tables"):
                return ledger.canonical({"nftables": [] if not self.host_exists else [
                    {"table": {"family": "inet", "name": policy.table}}]})
            if args[-4:] == ("list", "table", "inet", policy.table):
                return ledger.canonical(host_fixtures.observed(policy, deadline=self.host_deadline,
                    tuple_value=self.host_pair, ttl=self.host_ttl))
            self.host_sends.append((args, payload))
            if args == ("-j", "-f", "-"):
                journal = identity.decode_json(Path(str(self.host_path)+".baseline.json").read_bytes())
                self.assertEqual(journal["state"], "intent")
                self.assertEqual(payload, ledger.canonical(host_api_fence._rules(policy)))
                self.host_exists = True
            elif args == ("-f", "-"):
                text = payload.decode("ascii")
                grant = re.search(r"add element inet [a-z0-9_]+ admitted \{ ([0-9]+) \. ([0-9.]+) timeout ([0-9]+)s \}", text)
                if grant:
                    active = next(row for row in self.effects("fence-renew") if row["state"] == "intent")
                    self.assertIn("host_api_authorization", active)  # Durable BEFORE kernel send.
                    self.host_pair = (int(grant[1]), grant[2])
                    # nft1.0.9 JSON timers are seconds; observed() supplies
                    # the conservative floored expires=timeout-1 profile.
                    self.host_ttl = int(grant[3])
                    self.host_deadline = int(re.search(r"meta time < ([0-9]+) accept", text)[1])
                else:
                    self.assertIn("flush set", text)
                    self.host_pair, self.host_ttl = None, 0
            else:
                raise AssertionError("unexpected host kernel transport")
            return b""
        def index_name(index):
            self.assertEqual(index, 100)  # Exact private fixture's retained host veth.
            return "g06h0"
        def name_index(name):
            self.assertEqual(name, "g06h0")
            return 100
        with mock.patch.object(host_api_fence, "_host", return_value=nullcontext()), \
             mock.patch.object(host_api_fence, "_local"), mock.patch.object(host_api_fence, "_nft", side_effect=nft), \
             mock.patch.object(host_api_fence.socket, "if_indextoname", side_effect=index_name), \
             mock.patch.object(host_api_fence.socket, "if_nametoindex", side_effect=name_index):
            yield

    @contextmanager
    def kernel(self, *, nft=None):
        # BOTH actual grants run: only their kernel reads/sends are modeled.
        with self.host_kernel(), mock.patch.multiple(network_fence, _worker=mock.Mock(),
                _owned=mock.Mock(side_effect=self.owned),
                _nft=mock.Mock(side_effect=self.nft if nft is None else nft)):
            yield

    def test_real_refresh_admission_publish_then_renew_and_entire_sequence_is_locked(self):
        read = self.admission.reader.read
        def native_read(*args, **kwargs):
            self.assert_locked()
            return read(*args, **kwargs)
        before = self.store.read(self.lease)
        with mock.patch.object(self.admission.reader, "read", side_effect=native_read), self.kernel():
            receipt = self.invoke()
        after = self.store.read(self.lease)
        self.assertEqual(receipt.lease_id, self.lease)
        self.assertEqual(receipt.expires_at, before["expires_at"])
        self.assertEqual(after["expires_at"], before["expires_at"])
        self.assertEqual(after["identity"], before["identity"])
        self.assertEqual(len(after["authorizations"]), len(before["authorizations"]) + 1)
        self.assertEqual(receipt.authorization_sha256, ledger.digest(after["authorizations"][-1]))
        self.assertEqual(receipt.binding_sha256, hashlib.sha256((self.context / "binding.json").read_bytes()).hexdigest())
        self.assertEqual(len(self.nft_calls), 1)
        self.assertEqual(self.effects("context-refresh")[0]["state"], "verified")
        renewal = self.effects("fence-renew")[0]
        self.assertEqual(renewal["state"], "verified")
        host_grant = renewal["host_api_authorization"]
        self.assertEqual(host_grant["authorization_sha256"], ledger.digest(after["authorizations"][-1]))
        self.assertEqual(host_grant["host_ifindex"], 100)
        self.assertEqual(host_grant["peer_ipv4"], "10.250.23.2")
        baseline = Path(str(self.host_path)+".baseline.json")
        self.assertEqual(host_grant["baseline_sha256"], hashlib.sha256(baseline.read_bytes()).hexdigest())
        self.assertEqual(len(self.host_sends), 2)  # One baseline, one actual paired grant.

    def test_short_old_authorization_can_expire_before_fresh_refresh_without_extending_hard_lease(self):
        before = self.store.read(self.lease)
        now = before["authorizations"][-1]["valid_until"] + 1
        with mock.patch.object(preparation.time, "time", return_value=now), self.kernel():
            result = self.invoke()
        self.assertEqual(result.expires_at, before["expires_at"])
        self.assertEqual(self.store.read(self.lease)["expires_at"], before["expires_at"])
        self.assertEqual(len(self.nft_calls), 1)

    def test_wrong_operation_or_finished_native_job_cannot_refresh_publish_or_renew(self):
        before = self.store.read(self.lease)
        for body in (self.body(operation="admit"), self.body(operation="challenge")):
            with self.kernel(), self.assertRaises(refresh.RefreshDenied):
                self.invoke(body)
        self.native.job.update(status="completed", conclusion="failure")
        with self.kernel(), self.assertRaises(refresh.RefreshDenied):
            self.invoke()
        self.assertEqual(self.store.read(self.lease), before)
        self.assertEqual((self.context / "binding.json").read_bytes(), self.old_raw)
        self.assertEqual(self.nft_calls, [])

    def test_lock_contention_denies_before_native_authorization_or_file_changes(self):
        before = self.store.read(self.lease)
        with preparation.preparation_lock(str(self.io.config), self.io.sha), self.kernel():
            with self.assertRaises(refresh.RefreshDenied):
                self.invoke()
        self.assertEqual(self.store.read(self.lease), before)
        self.assertEqual(self.nft_calls, [])

    def test_worker_drift_after_actual_admission_retains_unknown_without_publication_or_network(self):
        other = replace(self.worker, start_ticks=self.worker.start_ticks + 1)
        with mock.patch.object(collector, "collect_worker", side_effect=[self.worker, self.worker, self.worker, other]), \
                self.kernel(), self.assertRaises(refresh.RefreshUnknown):
            self.invoke()
        self.assertEqual(self.effects("context-refresh")[0]["state"], "unknown")
        self.assertEqual((self.context / "binding.json").read_bytes(), self.old_raw)
        self.assertEqual(self.nft_calls, [])

    def test_lost_publication_response_retains_unknown_and_never_renews_or_retries(self):
        publish = context_publisher.RootContextPublisher.publish
        def lost(instance, *args, **kwargs):
            publish(instance, *args, **kwargs)
            raise context_publisher.PublicationUnknown("synthetic-lost-reply")
        with mock.patch.object(context_publisher.RootContextPublisher, "publish", lost), self.kernel():
            with self.assertRaises(refresh.RefreshUnknown):
                self.invoke()
        self.assertNotEqual((self.context / "binding.json").read_bytes(), self.old_raw)
        self.assertEqual(self.effects("context-refresh")[0]["state"], "unknown")
        self.assertEqual(self.nft_calls, [])
        before = self.store.read(self.lease)
        with self.kernel(), self.assertRaises(refresh.RefreshDenied):
            self.invoke()
        self.assertEqual(self.store.read(self.lease), before)

    def test_changed_root_tls_bytes_cannot_be_resigned_as_a_fresh_context(self):
        path = self.context / "client.key"
        path.write_bytes(path.read_bytes() + b"unintended-root-drift")
        with self.kernel(), self.assertRaises(refresh.RefreshUnknown):
            self.invoke()
        self.assertEqual(self.effects("context-refresh")[0]["state"], "unknown")
        self.assertEqual((self.context / "binding.json").read_bytes(), self.old_raw)
        self.assertEqual(self.nft_calls, [])

    def test_possible_network_write_failure_keeps_publication_verified_and_network_unknown(self):
        def failed(*args, **kwargs):
            self.nft(*args, **kwargs)
            raise Denied("synthetic-possible-network-write")
        with self.kernel(nft=failed), self.assertRaises(refresh.RefreshUnknown):
            self.invoke()
        self.assertEqual(self.effects("context-refresh")[0]["state"], "verified")
        self.assertEqual(self.effects("fence-renew")[0]["state"], "unknown")
        self.assertEqual(len(self.nft_calls), 1)
        before = self.store.read(self.lease)
        with self.kernel(), self.assertRaises(refresh.RefreshDenied):
            self.invoke()
        self.assertEqual(self.store.read(self.lease), before)
        self.assertEqual(len(self.nft_calls), 1)

    def running_fixture(self):
        prepared = self.io.prepared
        descriptor = identity.decode_json(prepared.engine_descriptor_bytes)
        manifest = engine_policy.compile_engine_policy(prepared.engine_descriptor_path, prepared.engine_descriptor_sha256)
        retained = Path(descriptor["engine"]["runroot"]) / "engine-manifest.json"
        retained.write_bytes(manifest.canonical_bytes)
        retained.chmod(0o600)
        # Initial live grant also uses BOTH real transactions and signed
        # context checks; only kernel observations are modeled.
        with preparation.preparation_lock(str(self.io.config), self.io.sha), self.kernel(nft=lambda *args, **kwargs: b""):
            network_fence.renew(self.fence.config.network_fence_policy_path,
                self.fence.config.network_fence_policy_sha256, prepared, self.store, self.worker, self.fence.config)
        initial_grant = self.effects("fence-renew")[0]
        self.assertIn("fence_authorization", initial_grant)
        self.assertIn("host_api_authorization", initial_grant)
        started = self.store.begin(self.lease, "engine-start", "engine:lit-lease-" + self.lease)
        self.store.bind_engine_process(self.lease, started, pid=99999, start_ticks=123456, boot_id=self.worker.boot_id,
                                       exe_device=2, exe_inode=3, exe_sha256="a" * 64)
        self.store.bind_engine_container(self.lease, started, "b" * 64)
        self.store.record(self.lease, started, "verified", evidence_sha256="e" * 64)
        output = Path(descriptor["output_path"])
        (output / "junit.xml").write_bytes(b"synthetic running output, not a real test result")
        return retained, output

    def test_running_output_changes_use_exact_original_signed_retained_engine_policy(self):
        self.running_fixture()
        before = self.store.read(self.lease)
        # Remaining lease is shorter than the original signed runtime budget.
        # This renews one existing run; it never admits another engine start.
        with mock.patch.object(preparation.time, "time", return_value=before["expires_at"] - 30), self.kernel():
            result = self.invoke()
        self.assertEqual(result.expires_at, before["expires_at"])
        self.assertEqual(len(self.nft_calls), 1)
        body = json.loads((self.context / "binding.json").read_bytes())
        current = identity.decode_json(identity.unbase(body["admission"].split(".")[1]))
        original = json.loads(self.old_raw)
        previous = identity.decode_json(identity.unbase(original["admission"].split(".")[1]))
        self.assertEqual(current["engine_policy_sha256"], previous["engine_policy_sha256"])

    def test_changed_retained_engine_bytes_cannot_be_recomputed_or_resigned_during_running_refresh(self):
        retained, _ = self.running_fixture()
        retained.write_bytes(retained.read_bytes() + b" ")
        with self.kernel(), self.assertRaises(refresh.RefreshUnknown):
            self.invoke()
        self.assertEqual((self.context / "binding.json").read_bytes(), self.old_raw)
        self.assertEqual(self.effects("context-refresh")[0]["state"], "unknown")
        self.assertEqual(self.nft_calls, [])


if __name__ == "__main__":
    unittest.main()
