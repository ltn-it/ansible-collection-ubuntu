"""Real private Root Ledger crash/recovery; never operating cleanup authority."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import struct
import sys
import time
import unittest
from unittest import mock

import test_github_runner_incus_ledger as fixtures
from incus_lease_issuer import ledger, storage_quota
from incus_lease_issuer.identity import Denied


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Linux Root fixture only")
class CleanupOrphanRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.parent = fixtures.validated_fixture_parent(Path("/run/proof"), private=True)
        self.io = fixtures.IncusLedgerTests()
        self.addCleanup(self.io.doCleanups)
        self.io.setUp(parent=self.parent)

    def prepared(self, store):
        lease, *_ = self.io.prepare(store)
        target = self.io.provision(store, lease, through="engine-prepare")
        effect = store.begin(lease, "certificate-revoke", target["certificate-create"])
        store.record(lease, effect, "verified", evidence_sha256=fixtures.EVIDENCE)
        effect = store.begin(lease, "engine-release", target["engine-prepare"])
        return lease, effect, target

    def sidecar(self, store, lease, effect, *, nonce=None, foreign=False, pairs=b"\0" * 16):
        nonce = nonce or secrets.token_hex(16)
        head = ledger.canonical({"schema":1,"nonce":nonce,"lease_id":"f"*32 if foreign else lease,
            "effect_id":effect,"operation":"engine-release","metadata":{"fixture":"public numeric metadata"}})
        raw = struct.pack(">I",len(head))+head+pairs
        name = "cleanup-observation-"+nonce+".bin"
        fd = store._open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
        with os.fdopen(fd,"wb") as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.fsync(store.fd)
        return name,raw

    def test_actual_crash_after_durable_sidecar_before_state_save_recovers_on_reopen(self):
        with self.io.open() as store:
            lease,effect,_ = self.prepared(store)
            before = store.read(lease)
        child = os.fork()
        if child == 0:
            with self.io.open() as store:
                original_save = store._save
                def crash_final_publication(state):
                    if "cleanup_postcheck" in state["leases"][lease]["effects"][effect]:
                        os._exit(73)
                    return original_save(state)
                with mock.patch.object(store,"_save",side_effect=crash_final_publication):
                    store.begin_cleanup_postcheck(lease,effect,time.monotonic()+30,
                        observation=({"fixture":"actual crash before publication"},b"\0"*16))
            os._exit(74)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(child,0)[1]),73)
        with self.io.open() as store:
            self.assertEqual(store.read(lease),before)
            names=[n for n in store._entries() if n.startswith("cleanup-observation-")]
            self.assertEqual(len(names),1)
            result=store.recover_cleanup_observation_orphans()
            self.assertEqual([row["name"] for row in result["removed"]],names)
            self.assertEqual(store.read(lease),before)
            self.assertEqual(store.read(lease)["effects"][effect]["state"],"intent")
            self.assertFalse(any(n.startswith("cleanup-observation-") for n in store._entries()))
            self.assertEqual(store.recover_cleanup_observation_orphans()["removed"],[])

    def test_auto_prearm_recovers_before_allocating_next_sidecar_inside_original_deadline(self):
        with self.io.open() as store:
            lease,effect,_=self.prepared(store)
            name,raw=self.sidecar(store,lease,effect)
            token=store.begin_cleanup_postcheck(lease,effect,time.monotonic()+30,
                observation=({"fixture":"new guarded sidecar"},b"\0"*16))
            self.assertFalse((self.io.path/name).exists())
            ref=store.read(lease)["effects"][effect]["cleanup_observation"]
            self.assertNotEqual(ref["name"],name)
            self.assertTrue((self.io.path/ref["name"]).is_file())
            self.assertEqual(store.read(lease)["effects"][effect]["cleanup_postcheck"],token.nonce)

    def test_recovery_never_reconciles_or_replays_unknown_effect(self):
        with self.io.open() as store:
            lease,effect,_=self.prepared(store)
            self.sidecar(store,lease,effect)
            store.record(lease,effect,"unknown",evidence_sha256=fixtures.EVIDENCE)
            before=store.read(lease)
            self.assertEqual(len(store.recover_cleanup_observation_orphans()["removed"]),1)
            self.assertEqual(store.read(lease),before)
            with self.assertRaises(Denied):store.close(lease)

    def test_every_durable_reference_is_preserved_while_an_unpublished_sibling_is_reclaimed(self):
        with self.io.open() as store:
            lease,effect,_=self.prepared(store)
            store.begin_cleanup_postcheck(lease,effect,time.monotonic()+30,
                observation=({"fixture":"durable"},b"\0"*16))
            ref=store.read(lease)["effects"][effect]["cleanup_observation"]
            protected=(self.io.path/ref["name"]).read_bytes()
            orphan,_=self.sidecar(store,lease,effect)
            before=store.read(lease)
            result=store.recover_cleanup_observation_orphans()
            self.assertEqual([r["name"]for r in result["removed"]],[orphan])
            self.assertEqual((self.io.path/ref["name"]).read_bytes(),protected)
            self.assertEqual(store.read(lease),before)

    def test_invalid_durable_reference_holds_without_deleting_either_file(self):
        with self.io.open() as store:
            lease,effect,_=self.prepared(store)
            store.begin_cleanup_postcheck(lease,effect,time.monotonic()+30,
                observation=({"fixture":"durable"},b"\0"*16))
            ref=store.read(lease)["effects"][effect]["cleanup_observation"]
            path=self.io.path/ref["name"];raw=path.read_bytes();path.write_bytes(raw[:-1]+b"x")
            orphan,_=self.sidecar(store,lease,effect)
            with self.assertRaises(Denied):store.recover_cleanup_observation_orphans()
            self.assertTrue(path.exists());self.assertTrue((self.io.path/orphan).exists())

    def test_foreign_malformed_or_linked_sidecars_hold_before_any_unlink(self):
        for kind in ("foreign","malformed","hardlink","symlink","mount"):
            with self.subTest(kind=kind),self.io.open() as store:
                lease,effect,_=self.prepared(store)
                good,_=self.sidecar(store,lease,effect)
                bad,_=self.sidecar(store,lease,effect,foreign=kind=="foreign")
                path=self.io.path/bad
                alias=self.io.path.parent/"orphan-alias"
                if kind=="malformed":path.write_bytes(b"not-a-sidecar")
                if kind=="hardlink":os.link(path,alias)
                if kind=="symlink":path.unlink();path.symlink_to(self.io.path/good)
                actual_mount=storage_quota._mount_id
                inode=path.stat().st_ino
                def mount(fd):
                    return actual_mount(fd)+(1 if kind=="mount" and os.fstat(fd).st_ino==inode else 0)
                with mock.patch.object(storage_quota,"_mount_id",side_effect=mount):
                    with self.assertRaises(Denied):store.recover_cleanup_observation_orphans()
                self.assertTrue((self.io.path/good).exists());self.assertTrue(path.exists())
                if alias.exists():alias.unlink()
            self.io.doCleanups();self.io.setUp(parent=self.parent)

    def test_bounded_directory_scan_counts_irrelevant_entries_and_has_no_mutation(self):
        with self.io.open() as store:
            lease,effect,_=self.prepared(store)
            name,_=self.sidecar(store,lease,effect)
            class Entries:
                def __enter__(self):return iter(type("Entry",(),{"name":"unrelated"})() for _ in range(65537))
                def __exit__(self,*args):pass
            with mock.patch.object(ledger.os,"scandir",return_value=Entries()):
                with self.assertRaisesRegex(Denied,"cleanup-observation-recovery-entry-bound"):
                    store.recover_cleanup_observation_orphans()
            self.assertTrue((self.io.path/name).exists())

    def test_expired_deadline_denies_without_mutation(self):
        with self.io.open() as store:
            lease,effect,_=self.prepared(store);name,_=self.sidecar(store,lease,effect)
            with self.assertRaisesRegex(Denied,"cleanup-observation-recovery-deadline"):
                store.recover_cleanup_observation_orphans(deadline=time.monotonic()-1)
            self.assertTrue((self.io.path/name).exists())

    def test_named_store_replacement_during_proof_holds_without_unlink(self):
        with self.io.open() as store:
            lease,effect,_=self.prepared(store);name,_=self.sidecar(store,lease,effect)
            before=store.read(lease)
            moved=self.io.path.with_name("original-store-moved")
            actual=store._cleanup_observation_file
            changed=[]
            def replace(*args,**kwargs):
                result=actual(*args,**kwargs)
                if not changed:
                    self.io.path.rename(moved)
                    self.io.path.mkdir(mode=0o700)
                    changed.append(True)
                return result
            with mock.patch.object(store,"_cleanup_observation_file",side_effect=replace):
                with self.assertRaisesRegex(Denied,"cleanup-observation-recovery-scope"):
                    store.recover_cleanup_observation_orphans()
            self.assertTrue((moved/name).exists())
            self.assertEqual(store.read(lease),before)

    def test_original_deadline_expiring_during_scan_holds_before_unlink(self):
        with self.io.open() as store:
            lease,effect,_=self.prepared(store);name,_=self.sidecar(store,lease,effect)
            now=[100.0]
            class Entries:
                def __enter__(self):
                    def values():
                        now[0]=131.0
                        yield type("Entry",(),{"name":name})()
                    return values()
                def __exit__(self,*args):pass
            with mock.patch.object(ledger.time,"monotonic",side_effect=lambda:now[0]), \
                 mock.patch.object(ledger.os,"scandir",return_value=Entries()):
                with self.assertRaisesRegex(Denied,"cleanup-observation-recovery-deadline"):
                    store.recover_cleanup_observation_orphans(deadline=130.0)
            self.assertTrue((self.io.path/name).exists())


    def test_internal_sixty_second_default_is_not_rejected_by_float_subtraction(self):
        self.assertGreater((4.001+60)-4.001,60)
        with self.io.open() as store, mock.patch.object(ledger.time,"monotonic",return_value=4.001):
            self.assertEqual(store.recover_cleanup_observation_orphans()["removed"],[])

    def test_sixteen_megabyte_metadata_recovery_cost_preserves_all_effect_provenance(self):
        with self.io.open() as store:
            lease,effect,_=self.prepared(store)
            name,raw=self.sidecar(store,lease,effect,pairs=b"\0"*16000000)
            before=store.read(lease);start=time.monotonic()
            result=store.recover_cleanup_observation_orphans()
            elapsed=time.monotonic()-start
            self.assertEqual(result["removed"],[{"name":name,"size":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}])
            self.assertEqual(store.read(lease),before)
            print(json.dumps({"actual_sidecar_bytes":len(raw),"recovery_seconds":elapsed,
                "includes_header_full_hash_unlink_directory_fsync_scope_readback":True,
                "native_operating_acceptance":False}),flush=True)
            self.assertLess(elapsed,60)


if __name__=="__main__":unittest.main()
