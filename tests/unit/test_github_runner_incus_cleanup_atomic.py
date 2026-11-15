"""Real private Ledger crash/staging proof; native cleanup remains modeled."""
import copy
import os
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

import test_github_runner_incus_cleanup_postcheck as postchecks
from incus_lease_issuer import ledger, storage_quota
from incus_lease_issuer.identity import Denied


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux fixture only")
class AtomicCleanupMetadataTests(unittest.TestCase):
    def setUp(self):
        self.fixture = postchecks.CleanupPostcheckTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.io = self.fixture.fixture

    def prepare(self, store):
        lease, targets = self.fixture.prepared(store)
        return lease, targets["engine-prepare"]

    def call(self, store, lease, target, *, observation=None):
        return store.begin_cleanup_with_postcheck(lease, "engine-release", target,
            time.monotonic() + 30, observation=({"fixture": "atomic original metadata"}, b"\0" * 32)
                if observation is None else observation)

    def cleanups(self, store, lease):
        return {key: value for key, value in store.read(lease)["effects"].items()
                if value["operation"] == "engine-release"}

    def test_metadata_cap_and_space_failure_leave_no_consumed_effect_then_same_entry_succeeds(self):
        with self.io.open() as store:
            lease, target = self.prepare(store)
            before = store.read(lease)
            with self.assertRaisesRegex(Denied, "cleanup-observation-bound"):
                self.call(store, lease, target, observation=({}, b"x" * 16000080))
            with mock.patch.object(ledger.os, "fstatvfs", return_value=type("V", (), {"f_bavail":0,"f_frsize":4096})()):
                with self.assertRaisesRegex(Denied, "cleanup-observation-space"):
                    self.call(store, lease, target)
            self.assertEqual(store.read(lease), before)
            self.assertFalse(store._load().get("cleanup_staging"))
            effect, token = self.call(store, lease, target)
            row = self.cleanups(store, lease)[effect]
            self.assertEqual(row["cleanup_postcheck"], token.nonce)
            self.assertEqual(store.read_cleanup_observation(lease, effect)[1], b"\0" * 32)
            with self.assertRaisesRegex(Denied, "effect-replay|effect-unresolved"):
                self.call(store, lease, target)

    def crash(self, point):
        with self.io.open() as store:
            lease, target = self.prepare(store)
            before = store.read(lease)
        child = os.fork()
        if child == 0:
            with self.io.open() as store:
                original_open, original_save, original_sync = store._open, store._save, ledger.os.fsync
                def opened(name, flags):
                    fd = original_open(name, flags)
                    if name.startswith("cleanup-staging-") and flags & os.O_CREAT:
                        if point == "created": os._exit(71)
                        if point == "midwrite":
                            os.write(fd, b"\0\0"); original_sync(fd); os._exit(71)
                    return fd
                def saved(state):
                    guarded = any("cleanup_postcheck" in e for e in state["leases"][lease]["effects"].values())
                    if guarded and point == "before-publication": os._exit(71)
                    original_save(state)
                    if guarded and point == "after-publication": os._exit(71)
                def synced(fd):
                    original_sync(fd)
                    if point == "renamed" and any(n.startswith("cleanup-observation-") for n in store._entries()):
                        os._exit(71)
                with mock.patch.object(store, "_open", side_effect=opened), mock.patch.object(store, "_save", side_effect=saved), mock.patch.object(ledger.os, "fsync", side_effect=synced):
                    self.call(store, lease, target)
            os._exit(72)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]), 71)
        return lease, target, before

    def test_real_crashes_empty_midwrite_and_published_name_are_exact_reserved_recovery(self):
        for point in ("created", "midwrite", "renamed", "before-publication"):
            with self.subTest(point=point):
                lease, target, before = self.crash(point)
                with self.io.open() as store:
                    self.assertEqual(store.read(lease), before)
                    reservation = store._load()["cleanup_staging"]
                    self.assertEqual(len(reservation), 1)
                    names = [n for n in store._entries() if n.startswith(("cleanup-staging-", "cleanup-observation-"))]
                    self.assertEqual(len(names), 1)
                    result = store.recover_cleanup_observation_orphans()
                    self.assertEqual([row["name"] for row in result["removed"]], names)
                    self.assertEqual(store.read(lease), before)
                    self.assertFalse(store._load().get("cleanup_staging"))
                    self.assertEqual(store.recover_cleanup_observation_orphans()["removed"], [])
                    effect, token = self.call(store, lease, target)
                    self.assertEqual(store.read(lease)["effects"][effect]["cleanup_postcheck"], token.nonce)
                self.io.doCleanups(); self.io.setUp(parent=self.fixture.parent)

    def test_crash_after_atomic_state_save_retains_intent_guard_and_final_no_replay(self):
        lease, target, _ = self.crash("after-publication")
        with self.io.open() as store:
            effects = self.cleanups(store, lease)
            self.assertEqual(len(effects), 1)
            effect, row = next(iter(effects.items()))
            self.assertIn("cleanup_postcheck", row)
            self.assertIn("cleanup_observation", row)
            self.assertFalse(store._load().get("cleanup_staging"))
            self.assertEqual(store.recover_cleanup_observation_orphans()["removed"], [])
            self.assertTrue((self.io.path / row["cleanup_observation"]["name"]).exists())
            with self.assertRaises(Denied): store.close(lease)
            with self.assertRaises(Denied): self.call(store, lease, target)
            self.assertEqual(store.read(lease)["effects"][effect], row)

    def test_post_replace_exception_and_lost_return_never_mean_no_intent(self):
        for point in ("save-return", "bookkeeping"):
            with self.subTest(point=point), self.io.open() as store:
                lease, target = self.prepare(store)
                original = store._save
                def saved(state):
                    original(state)
                    if any("cleanup_postcheck" in e for e in state["leases"][lease]["effects"].values()):
                        raise OSError("modeled post-state-replace failure")
                with mock.patch.object(store, "_save", side_effect=saved) if point == "save-return" else mock.patch.object(store, "_remember_cleanup_postcheck", side_effect=OSError("modeled lost return")):
                    with self.assertRaises(OSError): self.call(store, lease, target)
                effects = self.cleanups(store, lease)
                self.assertEqual(len(effects), 1)
                self.assertIn("cleanup_postcheck", next(iter(effects.values())))
                self.assertEqual(store.recover_cleanup_observation_orphans()["removed"], [])
                with self.assertRaises(Denied): self.call(store, lease, target)
            self.io.doCleanups(); self.io.setUp(parent=self.fixture.parent)

    def test_write_failure_and_short_write_are_reserved_not_resource_intents(self):
        for kind in ("exception", "short", "zero"):
            with self.subTest(kind=kind), self.io.open() as store:
                lease, target = self.prepare(store)
                original = ledger.os.fdopen
                def stream(fd, mode):
                    wrapped = original(fd, mode)
                    if not os.readlink("/proc/self/fd/" + str(fd)).endswith(".bin"):
                        return wrapped
                    class Broken:
                        def __enter__(self): return self
                        def __exit__(self, *args): return wrapped.__exit__(*args)
                        def write(self, raw):
                            if kind == "exception":
                                wrapped.write(raw[:2]); wrapped.flush(); raise OSError("modeled write failure")
                            return 0 if kind == "zero" else wrapped.write(raw[:2])
                    return Broken()
                with mock.patch.object(ledger.os, "fdopen", side_effect=stream):
                    with self.assertRaises((OSError, Denied)): self.call(store, lease, target)
                self.assertEqual(self.cleanups(store, lease), {})
                self.assertEqual(len(store.recover_cleanup_observation_orphans()["removed"]), 1)
                self.call(store, lease, target)
            self.io.doCleanups(); self.io.setUp(parent=self.fixture.parent)

    def test_fallible_metadata_io_before_publication_leaves_no_resource_intent(self):
        for point in ("create", "file-fsync", "published-dir-fsync", "state-before-replace"):
            with self.subTest(point=point), self.io.open() as store:
                lease, target = self.prepare(store)
                opened, synced, saved = store._open, ledger.os.fsync, store._save
                def open_file(name, flags):
                    if point == "create" and name.startswith("cleanup-staging-") and flags & os.O_CREAT:
                        raise OSError("modeled exclusive metadata create failure")
                    return opened(name, flags)
                def sync_file(fd):
                    if point == "file-fsync" and os.readlink("/proc/self/fd/" + str(fd)).endswith(".bin"):
                        raise OSError("modeled metadata file fsync failure")
                    if point == "published-dir-fsync" and fd == store.fd and any(
                            n.startswith("cleanup-observation-") for n in store._entries()):
                        raise OSError("modeled published metadata directory fsync failure")
                    return synced(fd)
                def save_state(state):
                    if point == "state-before-replace" and any("cleanup_postcheck" in e
                            for e in state["leases"][lease]["effects"].values()):
                        raise OSError("modeled final state publication failure")
                    return saved(state)
                with mock.patch.object(store, "_open", side_effect=open_file), mock.patch.object(
                        ledger.os, "fsync", side_effect=sync_file), mock.patch.object(store, "_save", side_effect=save_state):
                    with self.assertRaises(OSError): self.call(store, lease, target)
                self.assertEqual(self.cleanups(store, lease), {})
                self.assertEqual(len(store._load()["cleanup_staging"]), 1)
                store.recover_cleanup_observation_orphans()
                self.assertFalse(store._load().get("cleanup_staging"))
                self.call(store, lease, target)
            self.io.doCleanups(); self.io.setUp(parent=self.fixture.parent)

    def test_unreserved_malformed_final_or_staging_is_never_adopted(self):
        for prefix in ("cleanup-staging-", "cleanup-observation-"):
            with self.subTest(prefix=prefix), self.io.open() as store:
                lease, target = self.prepare(store)
                name = prefix + "f" * 32 + ".bin"
                fd = store._open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL); os.close(fd)
                with self.assertRaises(Denied): self.call(store, lease, target)
                self.assertEqual(self.cleanups(store, lease), {})
                self.assertTrue((self.io.path / name).exists())
            self.io.doCleanups(); self.io.setUp(parent=self.fixture.parent)

    def test_reserved_links_mount_and_store_drift_hold_before_any_unlink(self):
        for kind in ("hardlink", "symlink", "mount", "store"):
            with self.subTest(kind=kind):
                lease, _, before = self.crash("midwrite")
                with self.io.open() as store:
                    name = next(n for n in store._entries() if n.startswith("cleanup-staging-"))
                    path = self.io.path / name; alias = self.io.path.parent / "stage-alias"
                    if kind == "hardlink": os.link(path, alias)
                    if kind == "symlink": path.unlink(); path.symlink_to(self.io.path / "state.json")
                    if kind == "store":
                        with store._transaction() as state:
                            next(iter(state["cleanup_staging"].values()))["store_inode"] += 1
                    original = storage_quota._mount_id
                    def mount(fd):
                        return original(fd) + (1 if kind == "mount" and os.fstat(fd).st_ino == path.stat().st_ino else 0)
                    with mock.patch.object(storage_quota, "_mount_id", side_effect=mount):
                        with self.assertRaises(Denied): store.recover_cleanup_observation_orphans()
                    self.assertTrue(path.exists())
                    self.assertEqual(store.read(lease), before)
                    if alias.exists(): alias.unlink()
                self.io.doCleanups(); self.io.setUp(parent=self.fixture.parent)

    def test_staging_and_orphans_share_one_sixteen_file_maintenance_bound(self):
        import secrets
        import test_github_runner_incus_cleanup_orphans as orphans
        for staged_count in (15, 16):
            with self.subTest(staged_count=staged_count), self.io.open() as store:
                lease, target = self.prepare(store)
                # Authentic unpublished metadata reservations/final files from
                # interrupted writers; no resource effect has been published.
                for _ in range(staged_count):
                    with store._transaction() as state:
                        store._stage_cleanup_observation(state, lease, secrets.token_hex(16),
                            "engine-release", ledger._CleanupPostcheck(secrets.token_hex(16)),
                            ({"fixture": "reserved interrupted publication"}, b"\0" * 16),
                            time.monotonic() + 30, existing=None)
                effect = store.begin(lease, "engine-release", target)
                helper = orphans.CleanupOrphanRecoveryTests(); helper.io = self.io
                names = [helper.sidecar(store, lease, effect)[0] for _ in range(2)]
                before = store.read(lease)
                first = store.recover_cleanup_observation_orphans()
                self.assertEqual(len(first["removed"]), 16)
                self.assertEqual(first["remaining_unreferenced"], staged_count - 14)
                remaining = [name for name in names if (self.io.path / name).exists()]
                self.assertEqual(len(remaining), first["remaining_unreferenced"])
                self.assertFalse(store._load().get("cleanup_staging"))
                second = store.recover_cleanup_observation_orphans()
                self.assertEqual(sorted(row["name"] for row in second["removed"]), sorted(remaining))
                self.assertEqual(second["remaining_unreferenced"], 0)
                self.assertEqual(store.read(lease), before)
            self.io.doCleanups(); self.io.setUp(parent=self.fixture.parent)

    def staged(self, store, lease):
        import secrets
        token = ledger._CleanupPostcheck(secrets.token_hex(16))
        with store._transaction() as state:
            ref = store._stage_cleanup_observation(state, lease, secrets.token_hex(16),
                "engine-release", token, ({"fixture": "proof before scoped GC"}, b"\0" * 16),
                time.monotonic() + 30, existing=None)
        return ref["name"]

    def test_active_or_invalid_collection_scope_does_not_consume_staging(self):
        for requested in ("active", "invalid", "missing"):
            with self.subTest(requested=requested), self.io.open() as store:
                lease, _ = self.prepare(store)
                name = self.staged(store, lease)
                before = store._load()
                scope = lease if requested == "active" else "invalid" if requested == "invalid" else "f" * 32
                with self.assertRaises(Denied): store.collect_closed_cleanup_observations(scope)
                self.assertTrue((self.io.path / name).exists())
                self.assertEqual(store._load(), before)
            self.io.doCleanups(); self.io.setUp(parent=self.fixture.parent)

    def test_corrupt_reference_is_proved_before_any_reserved_staging_deletion(self):
        for kind in ("header", "body"):
            with self.subTest(kind=kind), self.io.open() as store:
                lease, target = self.prepare(store)
                effect, _ = self.call(store, lease, target)
                ref = store.read(lease)["effects"][effect]["cleanup_observation"]
                path = self.io.path / ref["name"]
                raw = path.read_bytes()
                damaged = b"\0" * 4 + raw[4:] if kind == "header" else raw[:-1] + b"x"
                path.write_bytes(damaged)
                staged = self.staged(store, lease)
                before = store._load()
                with self.assertRaises(Denied): store.recover_cleanup_observation_orphans()
                self.assertTrue((self.io.path / staged).exists())
                self.assertEqual(path.read_bytes(), damaged)
                self.assertEqual(store._load(), before)
            self.io.doCleanups(); self.io.setUp(parent=self.fixture.parent)

    def test_closed_lease_scoped_collection_leaves_other_lease_staging_untouched(self):
        import secrets
        import test_github_runner_incus_ledger as fixtures
        with self.io.open() as store:
            closed, target = self.prepare(store)
            effect = store.begin(closed, "engine-release", target)
            store.record(closed, effect, "verified", evidence_sha256=fixtures.EVIDENCE)
            # Normal modeled native cleanup of all creator targets, no sidecar.
            targets = {row["operation"]: row["target"] for row in store.read(closed)["effects"].values()}
            self.fixture.remaining(store, closed, targets)
            own_staged = self.staged(store, closed)
            with mock.patch.object(store, "collect_closed_cleanup_observations", side_effect=Denied("fixture-held-metadata")):
                self.assertEqual(store.close(closed)["state"], "closed")
            other, *_ = self.io.prepare(store, identity_changes={"token_id_sha256":secrets.token_hex(32),
                "run_id":1001, "check_run_id":1001})
            staged = self.staged(store, other)
            staged_bytes = (self.io.path / staged).read_bytes()
            before = store._load()
            result = store.collect_closed_cleanup_observations(closed)
            self.assertEqual([row["name"] for row in result["removed"]], [own_staged])
            self.assertFalse((self.io.path / own_staged).exists())
            self.assertEqual((self.io.path / staged).read_bytes(), staged_bytes)
            after = store._load()
            self.assertEqual(after["leases"], before["leases"])
            remaining = {nonce: row for nonce, row in before["cleanup_staging"].items() if row["lease_id"] == other}
            self.assertEqual(after["cleanup_staging"], remaining)
