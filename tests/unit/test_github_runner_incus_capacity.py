"""Actual Root FS/Ledger/Unix pool protocol; loop kernel observations modeled.

No native Incus capacity/reservation, image accounting or operating admission is
proved. Positive cases reuse the explicit loop/ext4 model of the quota suite.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import test_github_runner_incus_preparation as preparation_fixtures
import test_github_runner_incus_storage_quota as quota_fixtures
from incus_lease_issuer import (capacity, identity, ledger, policy_registry,
                                root_session, storage_quota, run_factory, preparation)
from incus_lease_issuer.identity import Denied


class CapacityProtocolTests(unittest.TestCase):
    def test_root_and_no_caller_authority_or_limits(self):
        with mock.patch.object(os, "geteuid", return_value=2101):
            with self.assertRaisesRegex(Denied, "capacity-root-required"):
                capacity.require_capacity(None, None, None, None, None, session=None)
        for extra in ({"approved": True}, {"reader": lambda: {}}, {"pool_bytes": 2**50}):
            with self.assertRaises(TypeError):
                capacity.require_capacity(None, None, None, None, None, session=None, **extra)

    def test_pool_wire_uint64_and_omitted_zero_used_exact_primary_contract(self):
        value = {"space": {"total": 32 * capacity.GIB}, "inodes": {"total": 10000, "used": 5}}
        self.assertEqual(capacity._pool(value), (32 * capacity.GIB, 0))
        for change in (lambda v: v["space"].update(used=True),
                       lambda v: v["space"].update(total=33 * capacity.GIB),
                       lambda v: v["space"].update(used=33 * capacity.GIB),
                       lambda v: v["inodes"].pop("used"),
                       lambda v: v["inodes"].update(used=9999),
                       lambda v: v.update(approved=True)):
            test = deepcopy(value); change(test)
            with self.assertRaises(Denied):
                capacity._pool(test)

    def test_profile_exact_types_no_extra_or_unqualified_accounting(self):
        profile = {**capacity.PROFILE, "pool_quota_policy_path": "/root/private/pool.json",
                   "pool_quota_policy_sha256": "a" * 64}
        self.assertEqual(capacity.validate_profile(profile), profile)
        for change in (lambda v: v.update(schema=True), lambda v: v.update(pool_reserve_bytes=0),
                       lambda v: v.update(pool_accounting="project-logical-usage"),
                       lambda v: v.update(qualified=True)):
            value = dict(profile); change(value)
            with self.assertRaises(Denied):
                capacity.validate_profile(value)


    def test_retained_entitlements_and_real_free_are_independent_no_double_count(self):
        capacity._bounds(32*capacity.GIB, 20*capacity.GIB, 20*capacity.GIB, 10*capacity.GIB)
        capacity._bounds(32*capacity.GIB, capacity.GIB, 0, 24*capacity.GIB)  # Ordinary24G unchanged.
        for total, used, old, new in ((32, 0, 30, 10), (32, 22, 20, 10), (32, 1, 10, 24)):
            with self.assertRaises(Denied):
                capacity._bounds(total*capacity.GIB, used*capacity.GIB, old*capacity.GIB, new*capacity.GIB)

    def test_all_project_inventory_only_exact_known_vm_tuples_no_images(self):
        values = [{"project": "p1", "name": "vm1", "type": "virtual-machine", "content_type": "block"}]
        capacity._volumes(values, [("p1", "vm1")])
        for change in (lambda v: v[0].update(type="image"), lambda v: v[0].update(project="foreign"),
                       lambda v: v[0].update(content_type="filesystem"), lambda v: v.append(deepcopy(v[0]))):
            test = deepcopy(values); change(test)
            with self.assertRaises(Denied): capacity._volumes(test, [("p1", "vm1")])



@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootCapacityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preparation_fixtures.RootPreparationTests.setUpClass()

    def setUp(self):
        self.io = preparation_fixtures.RootPreparationTests()
        self.io.setUp(); self.addCleanup(self.io.doCleanups)
        self.quota = quota_fixtures.RootStorageQuotaTests()
        self.quota.setUp(); self.addCleanup(self.quota.doCleanups)
        self.pool_quota = quota_fixtures.RootStorageQuotaTests()
        self.pool_quota.setUp(); self.addCleanup(self.pool_quota.doCleanups)
        base = Path("/run/pool-proof")
        if not base.is_dir() or base.stat().st_uid != 0:
            self.skipTest("separate private Root700 /run/pool-proof tmpfs required")
        private = tempfile.TemporaryDirectory(dir=base, prefix="capacity-")
        self.addCleanup(private.cleanup)
        self.pool_quota.mount = Path(private.name)
        info = self.pool_quota.mount.stat()
        self.pool_quota.value["mount"].update(path=str(self.pool_quota.mount), device=info.st_dev,
            inode=info.st_ino, mount_id=901)
        self.pool_quota.value["loop_device"] = "/dev/loop778"
        with self.pool_quota.backing.open("r+b") as stream: stream.truncate(32 * capacity.GIB)
        self.pool_quota.value["backing_file"]["bytes"] = 32 * capacity.GIB
        self.pool_quota.value.update(max_bytes=32 * capacity.GIB, max_inodes=10000)
        self.pool_quota.seal()
        self.pool_quota.rows = self.pool_quota.row(mount_id=901, source="/dev/loop778").replace(b" - ext4 /dev/loop778 rw", b" - ext4 /dev/loop778 rw,prjquota")
        self.pool_quota.vfs = SimpleNamespace(f_frsize=4096, f_blocks=32*capacity.GIB//4096,
            f_files=10000, f_favail=9000, f_bavail=31*capacity.GIB//4096, f_flag=0)
        # A separate genuinely initialized EMPTY store: no lease deletion,
        # business-lease transplant or synthetic operating approval.
        self.path = self.io.root / "empty-capacity-ledger"
        self.path.mkdir(mode=0o700)
        ledger.Ledger.initialize(str(self.path))
        self.store = ledger.Ledger(str(self.path))
        self.addCleanup(self.store.shutdown)
        self.store.archive_policy(self.io.store.read_policy(self.io.fixture.registry.select("approved").custody_policy_sha256))
        self.registry_value = identity.decode_json(Path(self.io.fixture.registry.path).read_bytes())
        self.registry_value["ledger_path"] = str(self.path)
        cell = identity.decode_json(Path(self.io.fixture.registry.select("approved").cell_config_path).read_bytes())
        cell["incus"]["project_limits"]["disk_bytes"] = 10 * capacity.GIB
        paths = cell["engine"]["paths"]
        paths.update(storage=self.quota.io.data["engine"]["storage_root"],
                     runroot=self.quota.io.data["engine"]["runroot"], output=self.quota.io.data["output_path"])
        self.cell_path = Path(self.io.fixture.registry.select("approved").cell_config_path)
        self.write(self.cell_path, cell)
        self.registry_value["cells"]["approved"]["cell_sha256"] = self.sha(self.cell_path)
        self.registry_path = Path(self.io.fixture.registry.path)
        self.write(self.registry_path, self.registry_value)
        self.registry = policy_registry.load_registry(str(self.registry_path), self.sha(self.registry_path))
        self.quota.backing.write_bytes(b"")
        with self.quota.backing.open("r+b") as stream:
            stream.truncate(17 * capacity.GIB)  # Sparse FIXTURE, never a physical reservation claim.
        self.quota.value["backing_file"]["bytes"] = 17 * capacity.GIB
        self.quota.value.update(max_bytes=17 * capacity.GIB, max_inodes=10000)
        self.quota.seal()
        self.quota.vfs = SimpleNamespace(f_frsize=4096, f_blocks=(17 * capacity.GIB - 1048576)//4096,
            f_files=10000, f_favail=9000, f_bavail=(9 * capacity.GIB)//4096, f_flag=0)
        self.io.value.update(registry_path=self.registry.path, registry_sha256=self.registry.sha256,
            storage_quota_policy_path=str(self.quota.path), storage_quota_policy_sha256=self.quota.sha)
        self.io.seal()
        self.runtime = self.io.root / "capacity-runtime.json"
        capture = identity.decode_json(self.io.prepared.engine_descriptor_bytes)["capture"]
        self.runtime_value = {"schema": 2, "registry_path": self.registry.path, "registry_sha256": self.registry.sha256,
            "preparation_config_path": str(self.io.config), "preparation_config_sha256": self.io.sha,
            "authentication_timeout_seconds": 5, "initial_transition_timeout_seconds": 60,
            "heartbeat_lead_seconds": 30, "cleanup_timeout_seconds": 60, "capacity": {**capacity.PROFILE, "pool_quota_policy_path": str(self.pool_quota.path),
                "pool_quota_policy_sha256": self.pool_quota.sha},
            "capture": {**capture, "max_total_evidence_bytes": 1048576, "max_members": 100,
                        "max_member_bytes": 1048576}}
        self.seal_runtime()
        self.resource = {"space": {"total": 32 * capacity.GIB, "used": capacity.GIB},
                         "inodes": {"total": 10000, "used": 5}}
        self.pool_route = "/1.0/storage-pools/approved-pool/resources"
        self.volumes_route = "/1.0/storage-pools/approved-pool/volumes?recursion=1&all-projects=true"
        self.io.server.resources["/1.0/storage-pools/approved-pool"] = {"name": "approved-pool", "driver": "dir",
            "status": "Created", "config": {"source": str(self.pool_quota.mount)}}
        self.io.server.resources[self.pool_route] = self.resource
        self.io.server.resources[self.volumes_route] = []
        self.io.server.extensions += ["resources", "storage"]

    @staticmethod
    def write(path, value):
        path.write_bytes(ledger.canonical(value)); path.chmod(0o600)

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def seal_runtime(self):
        self.write(self.runtime, self.runtime_value); self.runtime_sha = self.sha(self.runtime)

    @contextmanager
    def modeled_kernel(self):
        # Loop/block/FIEMAP/ext4/mount namespace OWNER and vfs are models.
        # Root files, separate real tmpfs devices, policy FD identities and
        # actual native Unix protocol remain real. Never native quota acceptance.
        qs = (self.quota, self.pool_quota)
        actual_type, actual_open = storage_quota._fs_type, storage_quota._open_file
        actual_vfs = os.fstatvfs
        def which(fd):
            dev = os.fstat(fd).st_dev
            return next((q for q in qs if q.mount.stat().st_dev == dev), None)
        def fs_type(fd):
            return storage_quota.EXT4 if any((os.fstat(fd).st_dev, os.fstat(fd).st_ino)
                == (q.mount.stat().st_dev, q.mount.stat().st_ino) for q in qs) else actual_type(fd)
        def opened(path):
            q = next((q for q in qs if q.value["loop_device"] == path), None)
            return actual_open(str(q.fake_loop) if q else path)
        def loop(_fd, backing, policy):
            q = next(q for q in qs if q.value["loop_device"] == policy["loop_device"])
            self.assertEqual(os.fstat(backing).st_ino, q.backing.stat().st_ino)
            return q.mount.stat().st_dev
        with mock.patch.object(storage_quota, "_fs_type", side_effect=fs_type), \
             mock.patch.object(storage_quota, "_namespace", side_effect=self.quota.observed_namespace), \
             mock.patch.object(storage_quota, "_open_file", side_effect=opened), \
             mock.patch.object(storage_quota, "_loop", side_effect=loop), \
             mock.patch.object(storage_quota, "_mount_id", side_effect=lambda fd: which(fd).value["mount"]["mount_id"]), \
             mock.patch.object(storage_quota, "_read_proc", side_effect=lambda _p, _l: b"".join(q.rows for q in qs)), \
             mock.patch.object(os, "fstatvfs", side_effect=lambda fd: which(fd).vfs if which(fd) else actual_vfs(fd)):
            yield

    @contextmanager
    def session(self):
        with root_session._session(str(self.io.config), self.io.sha) as session:
            yield session

    def inspect(self, session):
        return capacity.require_capacity(str(self.runtime), self.runtime_sha, self.registry,
                                         "approved", self.store, session=session)

    def test_real_root_unix_reads_no_ledger_or_filesystem_writes_positive_modeled_loop(self):
        before = (self.path / "state.json").read_bytes()
        info = (self.path / "state.json").stat()
        with self.modeled_kernel(), self.session() as session:
            result = self.inspect(session)
        self.assertEqual(result.requested_pool_bytes, 10 * capacity.GIB)
        self.assertEqual(result.pool_free_after_request_bytes, 21 * capacity.GIB)
        self.assertEqual(result.engine_free_after_cold_bytes, capacity.GIB)
        self.assertEqual((self.path / "state.json").read_bytes(), before)
        self.assertEqual((self.path / "state.json").stat().st_ino, info.st_ino)
        self.assertTrue(all(method == "GET" for method, _, _ in self.io.server.requests))
        self.assertEqual(self.store.lease_ids(), ())

    def test_missing_profile_or_forged_session_fails_before_pool_reads(self):
        with self.assertRaises(Denied):
            self.inspect(None)
        self.runtime_value.pop("capacity"); self.seal_runtime()
        with self.session() as session, self.assertRaises(Denied):
            self.inspect(session)
        self.assertFalse(self.io.server.requests)

    def test_foreign_or_live_pool_volume_denies_not_merely_counted_as_used_bytes(self):
        self.io.server.resources[self.volumes_route] = [{"name": "foreign", "type": "virtual-machine"}]
        with self.modeled_kernel(), self.session() as session:
            with self.assertRaisesRegex(Denied, "capacity-(unknown|foreign)-volume"):
                self.inspect(session)

    def test_independent_pool_and_engine_reserve_floors_and_inodes(self):
        with self.modeled_kernel(), self.session() as session:
            self.resource["space"]["used"] = 22 * capacity.GIB
            with self.assertRaisesRegex(Denied, "capacity-pool-headroom"):
                self.inspect(session)
            self.resource["space"]["used"] = capacity.GIB
            self.quota.vfs.f_bavail = (8 * capacity.GIB + 512 * 1024**2 - 4096)//4096
            with self.assertRaisesRegex(Denied, "capacity-engine-headroom"):
                self.inspect(session)
            self.quota.vfs.f_bavail = 9 * capacity.GIB//4096
            self.quota.vfs.f_favail = 1
            with self.assertRaisesRegex(Denied, "capacity-engine-inodes"):
                self.inspect(session)

    def test_actual_unbounded_filesystem_and_fake_regular_loop_do_not_grant_capacity(self):
        with self.session() as session, self.assertRaises(Denied):
            self.inspect(session)

    def test_native_pool_protocol_error_and_changed_second_read_are_holds(self):
        self.resource["space"]["used"] = True
        with self.modeled_kernel(), self.session() as session:
            with self.assertRaisesRegex(Denied, "capacity-integer"):
                self.inspect(session)
        self.resource["space"]["used"] = capacity.GIB
        original = self.io.server.handle
        count = 0
        def drift(method, path, body):
            nonlocal count
            if path == self.pool_route:
                count += 1
                if count == 2:
                    self.resource["space"]["used"] += 4096
            return original(method, path, body)
        with mock.patch.object(self.io.server, "handle", side_effect=drift), self.modeled_kernel(), self.session() as session:
            with self.assertRaisesRegex(Denied, "capacity-observation-drift"):
                self.inspect(session)

    def test_whole_ledger_metadata_drift_during_native_reads_is_not_adopted(self):
        original = self.io.server.handle
        changes = []
        def concurrent_metadata(method, path, body):
            if path == self.pool_route and not changes:
                changes.append(self.store.archive_policy({"custodian_ref": "fixture:concurrent",
                    "storage_ref": "fixture:metadata-only", "approval_ref": "fixture:not-approval",
                    "retention_seconds": 14400, "max_lease_seconds": 5400}))
            return original(method, path, body)
        with mock.patch.object(self.io.server, "handle", side_effect=concurrent_metadata), \
             self.modeled_kernel(), self.session() as session:
            with self.assertRaisesRegex(Denied, "capacity-ledger-drift"):
                self.inspect(session)
        self.assertEqual(len(changes), 1)
        self.assertEqual(self.store.lease_ids(), ())
        self.assertEqual(self.store.read_policy(changes[0])["storage_ref"], "fixture:metadata-only")

    def test_live_real_ledger_lease_prevents_another_prelease_admission(self):
        # Use the existing real prepared lease in its ORIGINAL store, with an
        # independently bound Root registry/config. Never transplant a record.
        self.registry_value["ledger_path"] = self.io.fixture.registry.select("approved").ledger_path
        self.write(self.registry_path, self.registry_value)
        self.registry = policy_registry.load_registry(str(self.registry_path), self.sha(self.registry_path))
        self.io.value.update(registry_path=self.registry.path, registry_sha256=self.registry.sha256)
        self.io.seal()
        self.runtime_value.update(registry_path=self.registry.path, registry_sha256=self.registry.sha256,
            preparation_config_sha256=self.io.sha)
        self.seal_runtime()
        with self.modeled_kernel(), self.session() as session:
            with self.assertRaisesRegex(Denied, "capacity-live-lease"):
                capacity.require_capacity(str(self.runtime), self.runtime_sha, self.registry, "approved",
                                          self.io.store, session=session)
        self.assertFalse(self.io.server.requests)

    def test_retained_and_unknown_effect_accounting_is_explicitly_unqualified(self):
        # Pure guard boundary only: these are NOT injected into the real ledger
        # or treated as actual custody/native/remaining-growth evidence.
        for record, reason in (({"state": "retained", "effects": {}, "upload_verification": {"state": "intent"}}, "capacity-retained-unknown"),
                               ({"state": "prepared", "effects": {"x": {"state": "unknown"}}}, "capacity-unresolved-effect")):
            with self.assertRaisesRegex(Denied, reason):
                capacity._quiescent({"leases": {"synthetic-parser-boundary-only": record}})


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootOriginalCatalogueTests(unittest.TestCase):
    """Actual signed bootstrap/config producer; locator checks grant nothing."""
    @classmethod
    def setUpClass(cls):
        import test_github_runner_incus_run_factory as fixtures
        fixtures.RootConfigurationTests.setUpClass()

    def setUp(self):
        import test_github_runner_incus_run_factory as fixtures
        self.io = fixtures.RootConfigurationTests()
        self.io.setUp(); self.addCleanup(self.io.doCleanups)
        self.configuration = self.io.create()
        self.registry = policy_registry.load_registry(self.configuration.registry_path,
                                                       self.configuration.registry_sha256)
        self.store = ledger.Ledger(self.io.helper.store_path, clock=run_factory.time.time)
        self.addCleanup(self.store.shutdown)
        # A real fresh signed/native-proof fixture identity, not caller JSON.
        proof, _token = self.io.helper.mint()
        selected = self.registry.select(self.io.selector)
        self.lease = self.store.prepare(proof.nonce, proof.worker, proof.identity,
            policy_sha256=selected.custody_policy_sha256, cell_sha256=selected.cell_sha256,
            deadline=selected.deadline)
        self.record = self.store.read(self.lease)

    def test_original_config_tuple_resolves_without_ledger_write_or_new_registry(self):
        before = self.store.read(self.lease)
        found, names = capacity._catalogue({self.lease: self.record})
        self.assertEqual(found[self.lease][0], self.configuration)
        self.assertEqual(len(names), 1)
        self.assertEqual(self.store.read(self.lease), before)
        self.assertEqual(found[self.lease][1]["invocation"]["check_run_id"], self.record["identity"]["check_run_id"])

    def test_partial_or_changed_original_catalogue_never_adopted(self):
        path = Path(self.configuration.runtime_config_path)
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        with self.assertRaises(Denied): capacity._catalogue({self.lease: self.record})
        path.write_bytes(original)
        partial = Path(run_factory.ROOT) / ("f" * 64); partial.mkdir(mode=0o700)
        with self.assertRaises(Denied): capacity._catalogue({self.lease: self.record})
        self.assertTrue(partial.exists())

    def test_borrowed_job_tuple_does_not_find_another_original_configuration(self):
        # Pure resolver negative, never inserted into Ledger or passed as proof.
        altered = deepcopy(self.record)
        altered["identity"]["check_run_id"] += 1
        with self.assertRaisesRegex(Denied, "capacity-old-config-missing"):
            capacity._catalogue({self.lease: altered})
        self.assertEqual(self.store.read(self.lease), self.record)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootPrunedRetentionTests(unittest.TestCase):
    """Genuine registered retained producer + actual graph/capture proof."""
    @classmethod
    def setUpClass(cls):
        import test_github_runner_incus_engine_graph_prune as fixtures
        fixtures.RootGraphPruneTests.setUpClass()

    def setUp(self):
        import test_github_runner_incus_engine_graph_prune as fixtures
        self.io = fixtures.RootGraphPruneTests()
        self.io.setUp(); self.addCleanup(self.io.doCleanups)
        self.io.run_prune()

    def graph_proof(self):
        with self.io.model(), self.io.session() as (owner, _config, _session):
            record = self.io.store.read(self.io.lease)
            starts = [row for row in record["effects"].values() if row["operation"] == "engine-start"]
            return capacity._graph(owner, starts[0], record)

    def test_actual_registered_retention_and_verified_graph_digest_are_readonly(self):
        before = self.io.store.read(self.io.lease)
        self.assertEqual(capacity._quiescent({"leases": {self.io.lease: before}}), {self.io.lease: before})
        self.assertEqual(self.graph_proof()["diagnostics_sha256"], next(row["graph_prune"]["diagnostics_sha256"]
            for row in before["effects"].values() if row["operation"] == "engine-graph-prune"))
        self.assertEqual(self.io.store.read(self.io.lease), before)

    def test_pruned_graph_return_or_raw_diagnostic_drift_holds_without_deletion(self):
        path = self.io.graph / "returned"; path.write_bytes(b"unknown new writer")
        with self.assertRaisesRegex(Denied, "capacity-pruned-graph-returned"): self.graph_proof()
        self.assertEqual(path.read_bytes(), b"unknown new writer")
        path.unlink()
        self.io.raw.write_bytes(b"changed raw data")
        with self.assertRaisesRegex(Denied, "capacity-pruned-diagnostics-drift"): self.graph_proof()
        self.assertEqual(self.io.raw.read_bytes(), b"changed raw data")

    def original_native_proof(self):
        # Component test of the ORIGINAL-reference validator. The fixed
        # catalogue's genuine sealed producer is independently exercised above;
        # this namespace is only a locator fixture, never admission authority.
        ready = self.io.io
        runtime_value = identity.decode_json(ready.runtime.read_bytes())
        profile = {**capacity.PROFILE, "pool_quota_policy_path": "/root/private/closed-pool.json",
                   "pool_quota_policy_sha256": "a" * 64}
        runtime_value["capacity"] = profile
        ready.runtime.write_bytes(ledger.canonical(runtime_value)); ready.runtime.chmod(0o600)
        cfg = SimpleNamespace(runtime_config_path=str(ready.runtime),
            runtime_config_sha256=hashlib.sha256(ready.runtime.read_bytes()).hexdigest(),
            preparation_config_path=str(ready.io.config), preparation_config_sha256=ready.io.sha,
            registry_path=ready.registry.path, registry_sha256=ready.registry.sha256)
        record = ready.store.read(ready.lease)
        current = preparation._config(str(ready.io.config), ready.io.sha)[0]
        with self.io.model():
            return capacity._retained(ready.lease, record, cfg,
                {"invocation": {"selector": "operating-failure"}}, ready.store,
                current, profile, ready.target["pool"])

    def test_original_owned_config_retained_native_proof_is_readonly(self):
        before = self.io.store.read(self.io.lease)
        proof = self.original_native_proof()
        self.assertEqual(proof["reservation"], 10 * capacity.GIB)
        self.assertEqual(proof["volume"], (self.io.io.target["project"], self.io.io.target["instance"]))
        self.assertEqual(proof["native"]["state"]["status"], "Stopped")
        self.assertEqual(self.io.store.read(self.io.lease), before)

    def test_running_or_wrong_device_original_retained_vm_is_not_admitted(self):
        self.io.io.state(True)
        with self.assertRaisesRegex(Denied, "capacity-retained-native-unsafe"):
            self.original_native_proof()
        self.io.io.state(False)
        self.io.io.vm["expanded_devices"]["root"]["pool"] = "foreign-pool"
        with self.assertRaisesRegex(Denied, "capacity-retained-devices"):
            self.original_native_proof()


if __name__ == "__main__":
    unittest.main()
