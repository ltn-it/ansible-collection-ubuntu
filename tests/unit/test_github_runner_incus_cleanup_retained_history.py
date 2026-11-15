"""Real >256MiB retained private metadata; modeled native job/cleanup receipts only."""
import os
import secrets
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

import test_github_runner_incus_cleanup_postcheck as postchecks
import test_github_runner_incus_cleanup_orphans as orphans
from incus_lease_issuer.identity import Denied


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Linux Root fixture only")
class RetainedCleanupHistoryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = postchecks.CleanupPostcheckTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.io = self.fixture.fixture
        original = self.io.prepare
        self.invocation = 1000
        def prepare(store, **kwargs):
            self.invocation += 1
            return original(store, identity_changes={"token_id_sha256": secrets.token_hex(32),
                "run_id": self.invocation, "check_run_id": self.invocation}, **kwargs)
        self.io.prepare = prepare

    def retained(self, store, pairs=b"\0" * 16):
        lease, targets = self.fixture.prepared(store)
        effect = store.begin(lease, "engine-release", targets["engine-prepare"])
        token = store.begin_cleanup_postcheck(lease, effect, time.monotonic() + 30,
            observation=({"fixture": "retained pre-upgrade closed history"}, pairs))
        from test_github_runner_incus_ledger import EVIDENCE
        store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
        store.complete_cleanup_postcheck(token)
        self.fixture.remaining(store, lease, targets)
        # Model authentic historical closed records from the old production
        # caller which retained sidecars. Real Ledger closure and refs persist.
        with mock.patch.object(store, "collect_closed_cleanup_observations", return_value={}):
            store.close(lease)
        return lease, effect, store.read(lease)["effects"][effect]["cleanup_observation"]

    def unpublished(self, store):
        helper = orphans.CleanupOrphanRecoveryTests()
        helper.io = self.io
        lease, effect, _ = helper.prepared(store)
        name, _ = helper.sidecar(store, lease, effect)
        return lease, effect, name

    def test_true_large_retained_history_bounded_batches_then_next_prearm(self):
        with self.io.open() as store:
            rows = [self.retained(store, b"\0" * 16000000) for _ in range(17)]
            total = sum((self.io.path / ref["name"]).stat().st_size for _, _, ref in rows)
            self.assertGreater(total, 268435456)
            lease, effect, orphan = self.unpublished(store)
            before = store._load()
            with self.assertRaisesRegex(Denied, "cleanup-observation-recovery-byte-bound"):
                store.begin_cleanup_postcheck(lease, effect, time.monotonic() + 30,
                    observation=({"fixture": "next guarded entry"}, b"\0" * 16))
            self.assertTrue((self.io.path / orphan).exists())
            batches = []
            while True:
                result = store.collect_closed_cleanup_observations()
                batches.append(result)
                self.assertLessEqual(len(result["removed"]), 16)
                self.assertLessEqual(sum(r["size"] for r in result["removed"]), 268435456)
                self.assertEqual(store._load(), before)
                self.assertTrue((self.io.path / orphan).exists())
                if not result["remaining_closed"]:
                    break
                self.assertTrue(result["removed"])
            self.assertEqual(len(batches), 2)
            self.assertEqual(sum(len(r["removed"]) for r in batches), 17)
            token = store.begin_cleanup_postcheck(lease, effect, time.monotonic() + 30,
                observation=({"fixture": "next actual private prearm"}, b"\0" * 16))
            self.assertFalse((self.io.path / orphan).exists())
            self.assertEqual(store.read(lease)["effects"][effect]["cleanup_postcheck"], token.nonce)
            for old, old_effect, ref in rows:
                self.assertEqual(store.read(old), before["leases"][old])
                self.assertFalse((self.io.path / ref["name"]).exists())
            print("RETAINED_HISTORY", total, "bytes; batches", [len(r["removed"]) for r in batches])

    def test_closed_collection_preserves_active_reference_and_audit(self):
        with self.io.open() as store:
            closed, _, ref = self.retained(store)
            active, effect, _ = self.unpublished(store)
            store.begin_cleanup_postcheck(active, effect, time.monotonic() + 30,
                observation=({"fixture": "active required evidence"}, b"\0" * 16))
            active_ref = store.read(active)["effects"][effect]["cleanup_observation"]
            before = store._load()
            result = store.collect_closed_cleanup_observations()
            self.assertEqual([r["name"] for r in result["removed"]], [ref["name"]])
            self.assertTrue((self.io.path / active_ref["name"]).exists())
            self.assertEqual(store._load(), before)
            with self.assertRaises(Denied):
                store.collect_closed_cleanup_observations(active)

    def test_invalid_missing_foreign_or_linked_metadata_holds_before_collection(self):
        for kind in ("corrupt-closed", "missing-active", "foreign", "hardlink", "mount"):
            with self.subTest(kind=kind), self.io.open() as store:
                _, _, ref = self.retained(store)
                candidate = self.io.path / ref["name"]
                active, effect, orphan = self.unpublished(store)
                alias = self.io.path / "owned-alias"
                if kind == "corrupt-closed":
                    raw = candidate.read_bytes(); candidate.write_bytes(raw[:-1] + b"x")
                elif kind == "missing-active":
                    store.begin_cleanup_postcheck(active, effect, time.monotonic() + 30,
                        observation=({"fixture": "required"}, b"\0" * 16))
                    (self.io.path / store.read(active)["effects"][effect]["cleanup_observation"]["name"]).unlink()
                elif kind == "foreign":
                    path = self.io.path / orphan
                    path.write_bytes(path.read_bytes().replace(active.encode(), b"f" * 32))
                elif kind == "hardlink":
                    os.link(candidate, alias)
                from incus_lease_issuer import storage_quota
                original = storage_quota._mount_id
                def mount(fd):
                    return original(fd) + (1 if kind == "mount" and os.fstat(fd).st_ino == candidate.stat().st_ino else 0)
                with mock.patch.object(storage_quota, "_mount_id", side_effect=mount):
                    with self.assertRaises(Denied):
                        store.collect_closed_cleanup_observations()
                self.assertTrue(candidate.exists())
            self.io.doCleanups(); self.io.setUp(parent=self.fixture.parent)

    def test_postclose_gc_failure_reports_closed_without_replay_grant(self):
        with self.io.open() as store:
            lease, targets = self.fixture.prepared(store)
            from test_github_runner_incus_ledger import EVIDENCE
            effect = store.begin(lease, "engine-release", targets["engine-prepare"])
            store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            self.fixture.remaining(store, lease, targets)
            with mock.patch.object(store, "collect_closed_cleanup_observations", side_effect=Denied("fixture-gc-hold")):
                self.assertEqual(store.close(lease), {"state": "closed", "metadata_gc": "held"})
            self.assertEqual(store.read(lease)["state"], "closed")
            with self.assertRaisesRegex(Denied, "lease-closed"):
                store.close(lease)
