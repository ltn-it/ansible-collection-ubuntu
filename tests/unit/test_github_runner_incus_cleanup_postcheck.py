"""Real private Ledger/directory durability; native identity, kernel and quota modeled.
No partial-owner class, VM creation, host execution or native acceptance exists here.
"""

from contextlib import contextmanager
import os, sys, time, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import test_github_runner_incus_ledger as fixtures

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "roles/github_runner/files")
)
from incus_lease_issuer import ledger, cleanup_storage as storage
from incus_lease_issuer.identity import Denied


@unittest.skipUnless(
    sys.platform == "linux" and os.geteuid() == 0, "private Root Linux fixture only"
)
class CleanupPostcheckTests(unittest.TestCase):
    def setUp(self):
        self.parent = fixtures.validated_fixture_parent(Path("/run/proof"), private=True)
        self.fixture = fixtures.IncusLedgerTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp(parent=self.parent)

    def prepared(self, store):
        lease, *_ = self.fixture.prepare(store)
        targets = self.fixture.provision(store, lease, through="engine-prepare")
        effect = store.begin(lease, "certificate-revoke", targets["certificate-create"])
        store.record(lease, effect, "verified", evidence_sha256=fixtures.EVIDENCE)
        return lease, targets

    def remaining(self, store, lease, targets):
        for operation, creator in [
            ("context-delete", "context-create"),
            ("project-delete", "project-create"),
            ("network-delete", "network-create"),
        ]:
            effect = store.begin(lease, operation, targets[creator])
            store.record(lease, effect, "verified", evidence_sha256=fixtures.EVIDENCE)

    def test_success_witness_closes_atomically_and_removes_pending_guard(self):
        with self.fixture.open() as store:
            lease, targets = self.prepared(store)
            effect = store.begin(lease, "engine-release", targets["engine-prepare"])
            token = store.begin_cleanup_postcheck(lease, effect, time.monotonic() + 30)
            store.record(lease, effect, "verified", evidence_sha256=fixtures.EVIDENCE)
            store.complete_cleanup_postcheck(token)
            self.remaining(store, lease, targets)
            store.require_cleanup_complete(lease)
            store.close(lease)
            record = store.read(lease)
            self.assertEqual(record["state"], "closed")
            self.assertFalse(
                any("cleanup_postcheck" in e for e in record["effects"].values())
            )

    def test_late_receipt_has_durable_hold_across_reopen_and_cannot_close(self):
        now = [100.0]
        with self.fixture.open() as store, mock.patch.object(
            ledger.time, "monotonic", side_effect=lambda: now[0]
        ):
            lease, targets = self.prepared(store)
            effect = store.begin(lease, "engine-release", targets["engine-prepare"])
            token = store.begin_cleanup_postcheck(lease, effect, 130)
            store.record(lease, effect, "verified", evidence_sha256=fixtures.EVIDENCE)
            now[0] = 131
            with self.assertRaisesRegex(Denied, "cleanup-postcheck-deadline"):
                store.complete_cleanup_postcheck(token)
            self.remaining(store, lease, targets)
            with self.assertRaisesRegex(Denied, "cleanup-postcheck-held"):
                store.close(lease)
            expected = store.read(lease)
        with self.fixture.open() as store:
            self.assertEqual(store.read(lease), expected)
            with self.assertRaisesRegex(Denied, "cleanup-postcheck-held"):
                store.require_cleanup_complete(lease)
            with self.assertRaisesRegex(Denied, "cleanup-postcheck-held"):
                store.close(lease)

    def test_late_context_receipt_also_blocks_subsequent_closure(self):
        now = [100.0]
        with self.fixture.open() as store, mock.patch.object(
            ledger.time, "monotonic", side_effect=lambda: now[0]
        ):
            lease, targets = self.prepared(store)
            effect = store.begin(lease, "engine-release", targets["engine-prepare"])
            store.record(lease, effect, "verified", evidence_sha256=fixtures.EVIDENCE)
            effect = store.begin(lease, "context-delete", targets["context-create"])
            token = store.begin_cleanup_postcheck(lease, effect, 130)
            store.record(lease, effect, "verified", evidence_sha256=fixtures.EVIDENCE)
            now[0] = 131
            with self.assertRaises(Denied):
                store.complete_cleanup_postcheck(token)
            for operation, creator in [
                ("project-delete", "project-create"),
                ("network-delete", "network-create"),
            ]:
                effect = store.begin(lease, operation, targets[creator])
                store.record(
                    lease, effect, "verified", evidence_sha256=fixtures.EVIDENCE
                )
            with self.assertRaisesRegex(Denied, "cleanup-postcheck-held"):
                store.close(lease)

    def test_valid_witness_cannot_survive_store_reopen_forgery_or_process_change(self):
        with self.fixture.open() as store:
            lease, targets = self.prepared(store)
            effect = store.begin(lease, "engine-release", targets["engine-prepare"])
            token = store.begin_cleanup_postcheck(lease, effect, time.monotonic() + 30)
            store.record(lease, effect, "verified", evidence_sha256=fixtures.EVIDENCE)
            store.complete_cleanup_postcheck(token)
            with self.assertRaises(Denied):
                store.complete_cleanup_postcheck(ledger._CleanupPostcheck(token.nonce))
            with mock.patch.object(ledger.os, "getpid", return_value=os.getpid() + 1):
                with self.assertRaises(Denied):
                    store.require_cleanup_postchecks(lease)
        with self.fixture.open() as reopened:
            with self.assertRaises(Denied):
                reopened.require_cleanup_postchecks(lease)

    def test_receipt_drift_invalidates_local_witness(self):
        with self.fixture.open() as store:
            lease, targets = self.prepared(store)
            effect = store.begin(lease, "engine-release", targets["engine-prepare"])
            token = store.begin_cleanup_postcheck(lease, effect, time.monotonic() + 30)
            store.record(lease, effect, "verified", evidence_sha256=fixtures.EVIDENCE)
            store.complete_cleanup_postcheck(token)
            with store._transaction() as state:
                state["leases"][lease]["effects"][effect]["evidence_sha256"] = "0" * 64
            with self.assertRaises(Denied):
                store.require_cleanup_postchecks(lease)

    def test_sidecar_is_private_hash_bound_retained_until_closed_and_gc_is_owned(self):
        import struct
        with self.fixture.open() as store:
            lease, targets = self.prepared(store)
            effect = store.begin(lease, "engine-release", targets["engine-prepare"])
            pairs = struct.pack(">QQ", 1, 2)
            token = store.begin_cleanup_postcheck(lease, effect, time.monotonic() + 30,
                                                   observation=({"fixture": "public-metadata"}, pairs))
            row = store.read(lease)["effects"][effect]
            sidecar = self.fixture.path / row["cleanup_observation"]["name"]
            self.assertEqual(sidecar.stat().st_mode & 0o777, 0o600)
            self.assertEqual(store.read_cleanup_observation(lease, effect), ({"fixture": "public-metadata"}, pairs))
            with self.assertRaisesRegex(Denied, "cleanup-observation-still-needed"):
                store.gc_cleanup_observation(lease, effect)
            store.record(lease, effect, "verified", evidence_sha256=fixtures.EVIDENCE)
            store.complete_cleanup_postcheck(token)
            self.remaining(store, lease, targets)
            closed = store.close(lease)
            self.assertEqual(closed["state"], "closed")
            self.assertEqual(closed["metadata_gc"], "complete")
            self.assertFalse(sidecar.exists())
            retained = store.read(lease)["effects"][effect]
            self.assertEqual(retained["cleanup_observation"], row["cleanup_observation"])
            self.assertIn("cleanup_postcheck_resolution", retained)
            self.assertEqual(store.gc_cleanup_observation(lease, effect)["state"], "already-absent")

    def test_sidecar_tampering_or_public_mode_cannot_grant_completion(self):
        import struct
        for mutation in ("bytes", "mode", "hardlink"):
            with self.subTest(mutation=mutation), self.fixture.open() as store:
                lease, targets = self.prepared(store)
                effect = store.begin(lease, "engine-release", targets["engine-prepare"])
                token = store.begin_cleanup_postcheck(lease, effect, time.monotonic() + 30,
                    observation=({"fixture": "public-metadata"}, struct.pack(">QQ", 1, 2)))
                ref = store.read(lease)["effects"][effect]["cleanup_observation"]
                sidecar = self.fixture.path / ref["name"]
                original = sidecar.read_bytes()
                if mutation == "bytes":
                    sidecar.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                elif mutation == "mode":
                    sidecar.chmod(0o644)
                else:
                    os.link(sidecar, sidecar.with_suffix(".alias"))
                store.record(lease, effect, "verified", evidence_sha256=fixtures.EVIDENCE)
                with self.assertRaises(Denied):
                    store.complete_cleanup_postcheck(token)
                with self.assertRaises(Denied):
                    store.require_cleanup_postchecks(lease)
                if mutation == "mode": sidecar.chmod(0o600)
                if mutation == "hardlink": sidecar.with_suffix(".alias").unlink()
                if mutation == "bytes": sidecar.write_bytes(original)
                # Distinct original lease/fixture; no unresolved effect is reused.
            self.fixture.doCleanups()
            self.fixture.setUp(parent=self.parent)

    def test_large_original_inode_sidecar_cost_includes_packing_fsync_and_readback(self):
        import struct, json
        with self.fixture.open() as store:
            lease, targets = self.prepared(store)
            effect = store.begin(lease, "engine-release", targets["engine-prepare"])
            started = time.monotonic()
            pairs = b"".join(struct.pack(">QQ", 1, n + 1) for n in range(149119))
            token = store.begin_cleanup_postcheck(lease, effect, started + 30,
                observation=({"fixture": "public-metadata", "nodes": 149119}, pairs))
            store.record(lease, effect, "verified", evidence_sha256=fixtures.EVIDENCE)
            store.complete_cleanup_postcheck(token)
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 30)
            print(json.dumps({"representative_sidecar_nodes": 149119, "pair_bytes": len(pairs),
                              "packing_fsync_receipt_readback_seconds": elapsed}), flush=True)

    def test_reopened_guard_rejects_forged_fresh_observation_and_unknown_receipt(self):
        with self.fixture.open() as store:
            lease, targets = self.prepared(store)
            effect = store.begin(lease, "engine-release", targets["engine-prepare"])
            store.begin_cleanup_postcheck(lease, effect, time.monotonic() + 30,
                                         observation=({"fixture": "public-metadata"}, b""))
            store.record(lease, effect, "verified", evidence_sha256=fixtures.EVIDENCE)
        with self.fixture.open() as reopened:
            with self.assertRaises(Denied):
                reopened.resolve_cleanup_postcheck(lease, effect, object())
            with self.assertRaises(Denied):
                reopened.require_cleanup_postchecks(lease)

    def test_sibling_maps_parse_rechecks_identities_paths_deadline_and_changed_bytes(self):
        end = time.monotonic() + 10
        mapping = b"1000-1100 r--p 0 08:01 42 /fixture"
        different = mapping.replace(b"42", b"43")
        forbidden = {(os.makedev(8, 1), 42)}
        parsed = storage._check_task_maps(mapping, (), set(), end, None)
        self.assertIs(storage._check_task_maps(bytes(bytearray(mapping)), (), set(), end, parsed), parsed)
        with self.assertRaisesRegex(Denied, "cleanup-consumers-mapped-reference"):
            storage._check_task_maps(mapping, (), forbidden, end, parsed)
        with self.assertRaisesRegex(Denied, "cleanup-consumers-mapped-reference"):
            storage._check_task_maps(mapping, (b"/fixture",), set(), end, parsed)
        with self.assertRaisesRegex(Denied, "cleanup-storage-budget"):
            storage._check_task_maps(mapping, (), set(), time.monotonic() - 1, parsed)
        self.assertEqual(storage._check_task_maps(different, (), forbidden, end, parsed)[0], different)
        with self.assertRaisesRegex(Denied, "cleanup-consumers-maps-shape"):
            storage._check_task_maps(mapping + b"\nbad", (), set(), end, parsed)
        self.assertIsNone(storage._check_task_maps(mapping + b"x" * (128 * 1024), (), set(), end, parsed))

    def test_unreaped_terminal_task_requires_real_empty_resources_and_keeps_task_scan(self):
        root = self.fixture.path
        data = {"engine": {"storage_root": str(root / "graph"), "runroot": str(root / "run")},
                "output_path": str(root / "output"), "context_path": str(root / "context")}
        def observe():
            storage._no_consumers(data, str(root / "descriptor"), "fixture-unowned",
                                  [], time.monotonic() + 10, set(), [])
        observe()
        child = os.fork()
        if child == 0:
            os._exit(0)
        try:
            os.waitid(os.P_PID, child, os.WEXITED | os.WNOWAIT)
            self.assertEqual(Path(f"/proc/{child}/stat").read_bytes().rsplit(b")", 1)[1].split()[0], b"Z")
            observe()
            actual = storage._consumer_read
            def live_resource(path, limit, end):
                if str(path) == f"/proc/{child}/task/{child}/maps":
                    return b"synthetic-nonempty-terminal-mm"
                return actual(path, limit, end)
            with mock.patch.object(storage, "_consumer_read", side_effect=live_resource):
                with self.assertRaisesRegex(Denied, "cleanup-consumers-terminal-maps"):
                    observe()
        finally:
            os.waitpid(child, 0)
        observe()

    def test_sidecar_reference_cannot_survive_silently_removed_pending_guard(self):
        with self.fixture.open() as store:
            lease, targets = self.prepared(store)
            effect = store.begin(lease, "engine-release", targets["engine-prepare"])
            store.begin_cleanup_postcheck(lease, effect, time.monotonic() + 30,
                                         observation=({"fixture": "metadata"}, b""))
            with self.assertRaisesRegex(Denied, "ledger-corrupt"):
                with store._transaction() as state:
                    del state["leases"][lease]["effects"][effect]["cleanup_postcheck"]
            self.assertIn("cleanup_postcheck", store.read(lease)["effects"][effect])

    def normal_release(self, late=False):
        store = self.fixture.open()
        self.addCleanup(store.shutdown)
        lease, *_ = self.fixture.prepare(store)
        targets = self.fixture.provision(store, lease, through="certificate-create")
        root = self.fixture.path.parent
        paths = [root / name for name in ["graph", "runroot", "output"]]
        for path in paths:
            path.mkdir(mode=0o700)
            (path / "owned").write_bytes(b"fixture")
        directories = [
            {"path": str(p), "device": p.stat().st_dev, "inode": p.stat().st_ino}
            for p in paths
        ]
        prepare = store.begin(lease, "engine-prepare", "engine:" + lease)
        store.record(
            lease,
            prepare,
            "verified",
            evidence_sha256=ledger.digest(
                {"prepared": "a" * 64, "directories": directories}
            ),
        )
        revoke = store.begin(lease, "certificate-revoke", targets["certificate-create"])
        store.record(lease, revoke, "verified", evidence_sha256=fixtures.EVIDENCE)
        descriptor = {
            "engine": {"storage_root": str(paths[0]), "runroot": str(paths[1])},
            "output_path": str(paths[2]),
        }
        owner = SimpleNamespace(
            lease_id=lease,
            engine_descriptor_bytes=ledger.canonical(descriptor),
            engine_descriptor_sha256=ledger.digest(descriptor),
            prepared_sha256="a" * 64,
            creators={"engine-prepare": {"id": prepare}},
        )
        now = [100.0]

        @contextmanager
        def quota(*args):
            yield
            if late:
                now[0] = 131

        # Only external semantic/kernel/quota admission is modeled. Actual inventory,
        # unlink/rmdir/fsync, private Ledger intent/receipt and postcheck remain real.
        with mock.patch.object(
            storage, "_fresh", side_effect=lambda *args: store.read(lease)
        ), mock.patch.object(storage, "_drain_engine"), mock.patch.object(
            storage, "_cleanup_limits", return_value=(1000, 30)
        ), mock.patch.object(
            storage.storage_quota, "acquire_existing_evidence_quota", side_effect=quota
        ), mock.patch.object(
            storage.time, "monotonic", side_effect=lambda: now[0]
        ):
            if late:
                with self.assertRaises(storage.CleanupStorageUnknown):
                    storage.release_engine(
                        owner,
                        store,
                        SimpleNamespace(
                            storage_quota_policy_path="modeled",
                            storage_quota_policy_sha256="b" * 64,
                        ),
                    )
            else:
                storage.release_engine(
                    owner,
                    store,
                    SimpleNamespace(
                        storage_quota_policy_path="modeled",
                        storage_quota_policy_sha256="b" * 64,
                    ),
                )
        self.assertFalse(any(p.exists() for p in paths))
        return store, lease

    def test_real_normal_storage_quota_exit_precedes_success_receipt(self):
        store, lease = self.normal_release(late=True)
        release = next(
            e
            for e in store.read(lease)["effects"].values()
            if e["operation"] == "engine-release"
        )
        self.assertEqual(release["state"], "unknown")
        self.assertIn("cleanup_postcheck", release)
        with self.assertRaisesRegex(Denied, "cleanup-postcheck-held"):
            store.close(lease)

    def test_real_normal_storage_success_has_live_witness(self):
        store, lease = self.normal_release()
        release = next(
            e
            for e in store.read(lease)["effects"].values()
            if e["operation"] == "engine-release"
        )
        self.assertEqual(release["state"], "verified")
        store.require_cleanup_postchecks(lease)
