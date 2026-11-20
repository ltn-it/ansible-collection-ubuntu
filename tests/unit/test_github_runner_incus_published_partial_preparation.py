"""Real publisher/Root Ledger/TLS files/Unix cleanup; native inputs modeled.

Synthetic keys, no native host, no new execution or operating PASS assertion.
"""
from contextlib import nullcontext
import copy
import os
import sys
from pathlib import Path
import unittest
from unittest import mock

import test_github_runner_incus_partial_preparation as partial
from incus_lease_issuer import (cell_contract, cleanup_storage, engine_executor, engine_policy, identity,
    kernel, ledger, network_fence, operating_custody, preparation, root_session, runtime_rpc, signed_context)
from incus_lease_issuer.identity import Denied


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'isolated Root Linux EE only')
class PublishedPartialPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        partial.PartialPreparationTests.setUpClass()
    def setUp(self):
        self.f=partial.PartialPreparationTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.io.run_prepare()
        self.record=self.f.store.read(self.f.lease)
        self.assertEqual(len(self.record['effects']),7)
        self.assertTrue(all(e['state']=='verified'for e in self.record['effects'].values()))
        self.assertFalse(any(e['operation']in {'engine-start','fence-create'}for e in self.record['effects'].values()))
        self.data=identity.decode_json(self.f.io.prepared.engine_descriptor_bytes)
        self.context=Path(self.data['context_path'])
        self.config=preparation._config(str(self.f.io.config),self.f.io.sha)[0]
        project=self.f.io.prepared.incus['project']
        self.f.io.server.resources['/1.0/instances?project='+project]=[]
        self.f.io.server.resources['/1.0/operations?project='+project+'&recursion=1']={}
    def owner(self):
        return cell_contract.partial_preparation_owner(self.f.registry,'approved',self.f.store,self.f.lease)
    def terminal_and_retain(self):
        terminal=self.f.terminal();owner=self.owner()
        self.f.finalizer.withdraw_partial_preparation(self.f.registry,'approved',self.f.store,self.f.lease)
        retained=operating_custody.retain_partial_preparation(self.f.registry,'approved',self.f.store,self.f.lease)
        return owner,terminal,retained
    def context_files(self,owner,record=None):
        raw,proof=signed_context._sealed(str(self.context/'binding.json'),32768)
        binding=identity.decode_json(raw)
        return cleanup_storage._partial_context_files(owner,self.f.store,self.config,
            self.f.store.read(self.f.lease)if record is None else record,str(self.context),binding,proof)
    def test_healthy_published_original_cannot_be_adopted_for_cleanup(self):
        with self.assertRaisesRegex(Denied,'partial-published-original-still-live'):self.owner()
        before=self.f.store.read(self.f.lease);writes=list(self.f.io.writes())
        with self.assertRaises(Denied):self.f.finalizer.withdraw_partial_preparation(
            self.f.registry,'approved',self.f.store,self.f.lease)
        self.assertEqual(self.f.store.read(self.f.lease),before);self.assertEqual(self.f.io.writes(),writes)
    def test_native_terminal_revoke_four_hours_then_full_cleanup_no_execution(self):
        owner,terminal,retained=self.terminal_and_retain()
        self.assertEqual(retained['terminal_at'],terminal['completed_at'])
        self.assertEqual(retained['retain_until'],terminal['completed_at']+14400)
        original_auth=copy.deepcopy(self.record['authorizations'])
        self.f.now=retained['retain_until']-1
        with self.assertRaises(Denied):self.f.finalizer.finalize_partial_preparation(
            self.f.registry,'approved',self.f.store,self.f.lease)
        self.assertEqual(sum(r[0]=='DELETE'for r in self.f.io.server.requests),1)
        self.assertTrue(self.context.exists())
        self.f.now=retained['retain_until']
        with mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
             mock.patch.object(cleanup_storage.storage_quota,'acquire_existing_evidence_quota',side_effect=lambda *a:nullcontext()):
            result=self.f.finalizer.finalize_partial_preparation(self.f.registry,'approved',self.f.store,self.f.lease)
        record=self.f.store.read(self.f.lease)
        self.assertEqual(result['state'],'FAILED_PARTIAL_PREPARATION_CLOSED');self.assertFalse(result['native_acceptance'])
        self.assertEqual(record['state'],'closed');self.assertEqual(record['authorizations'],original_auth)
        self.assertNotIn('custody',record);self.assertNotIn('owned_instance',record)
        self.assertFalse(any(e['operation']in {'engine-start','engine-stop','fence-create','fence-remove'}for e in record['effects'].values()))
        self.assertEqual(sum(e['operation']=='context-publish'for e in record['effects'].values()),1)
        self.assertEqual(sum(e['operation']=='certificate-revoke'for e in record['effects'].values()),1)
        self.assertFalse(self.context.exists());self.assertFalse(Path(owner.engine_descriptor_path).exists())
        for path in [self.data['engine']['storage_root'],self.data['engine']['runroot'],self.data['output_path']]:
            self.assertFalse(Path(path).exists())
    def create_slice(self, command):
        worker = self.f.store.read(self.f.lease)["worker"]
        boot = mock.patch.object(kernel, "read_boot_id", return_value=worker["boot_id"])
        boot.start()
        self.addCleanup(boot.stop)
        prepared = self.f.io.prepared
        manifest = engine_policy.compile_engine_policy(prepared.engine_descriptor_path,
                                                        prepared.engine_descriptor_sha256)
        with root_session._session(self.config.path, self.config.sha256) as session, \
             mock.patch.object(engine_executor, "_slice_inactive"), \
             mock.patch.object(engine_executor, "_slice_active"), \
             mock.patch.object(engine_executor, "_slice_manager", side_effect=command), \
             mock.patch.object(engine_executor, "_cgroup", return_value=(35, 2101)):
            engine_executor._create_slice(session, prepared, self.f.store, manifest)

    def test_slice_has_original_intent_before_start_and_exact_capture_identity(self):
        store, lease = self.f.store, self.f.lease

        def start(lease_id, action):
            self.assertEqual((lease_id, action), (lease, "start"))
            creator = engine_executor._slice_creator(store.read(lease))
            self.assertEqual((creator["target"], creator["state"]), ("slice:" + lease, "intent"))

        self.create_slice(start)
        creator = engine_executor._slice_creator(store.read(lease))
        self.assertEqual(creator["state"], "verified")
        self.assertEqual(creator["engine_slice"], {
            "boot_id": kernel.read_boot_id(), "cgroup_device": 35, "cgroup_inode": 2101})
        with mock.patch.object(engine_executor, "_slice_active"), \
             mock.patch.object(engine_executor, "_cgroup", return_value=(35, 2102)):
            with self.assertRaisesRegex(Denied, "engine-slice-start-drift"):
                engine_executor._start_cgroup(self.data, store, lease)

    def test_failure_after_slice_before_fence_withdraws_original_certificate(self):
        store, lease = self.f.store, self.f.lease
        self.create_slice(mock.Mock())
        before = store.read(lease)
        self.assertEqual(before["state"], "prepared")
        self.assertNotIn("fence-create", {effect["operation"] for effect in before["effects"].values()})
        runtime = self.f.runtime
        rpc = runtime_rpc.RuntimeRPC(str(runtime), ledger.digest(identity.decode_json(runtime.read_bytes())))
        rpc._retain_after_failure(store, lease, "approved", None)
        after = store.read(lease)
        self.assertEqual(after["state"], "cancelled")
        revoke, = [effect for effect in after["effects"].values() if effect["operation"] == "certificate-revoke"]
        self.assertEqual(revoke["state"], "verified")
        self.assertNotIn("partial_preparation_custody", after)

    def test_indeterminate_slice_start_is_never_replayed(self):
        start = mock.Mock(side_effect=TimeoutError)
        with self.assertRaises(engine_executor.EngineUnknown):
            self.create_slice(start)
        store, lease = self.f.store, self.f.lease
        self.assertEqual(engine_executor._slice_creator(store.read(lease))["state"], "unknown")
        with self.assertRaises(Denied):
            self.create_slice(start)
        start.assert_called_once_with(lease, "start")

    def test_slice_timeout_revokes_only_the_original_certificate_and_holds_cleanup(self):
        store, lease = self.f.store, self.f.lease
        certificate, = [effect for effect in self.record["effects"].values()
                        if effect["operation"] == "certificate-create"]
        fingerprint = certificate["target"].removeprefix("certificate:")
        start = mock.Mock(side_effect=TimeoutError)
        with self.assertRaises(engine_executor.EngineUnknown):
            self.create_slice(start)
        unresolved = engine_executor._slice_creator(store.read(lease))
        self.assertEqual(unresolved["state"], "unknown")
        with self.assertRaisesRegex(Denied, "partial-published-original-still-live"):
            self.f.finalizer.withdraw_partial_preparation(self.f.registry, "approved", store, lease)
        self.assertIn("/1.0/certificates/" + fingerprint, self.f.io.server.resources)
        baseline_writes = list(self.f.io.writes())

        runtime = self.f.runtime
        rpc = runtime_rpc.RuntimeRPC(str(runtime), ledger.digest(identity.decode_json(runtime.read_bytes())))
        rpc._retain_after_failure(store, lease, "approved", None)

        after = store.read(lease)
        self.assertEqual(after["state"], "cancelled")
        self.assertEqual(engine_executor._slice_creator(after), unresolved)
        revoke, = [effect for effect in after["effects"].values() if effect["operation"] == "certificate-revoke"]
        self.assertEqual((revoke["state"], revoke["target"]), ("verified", certificate["target"]))
        self.assertNotIn("/1.0/certificates/" + fingerprint, self.f.io.server.resources)
        native_writes = self.f.io.writes()[len(baseline_writes):]
        self.assertEqual([(row[0], row[1]) for row in native_writes], [("DELETE", "/1.0/certificates/" + fingerprint)])

        self.f.finalizer.withdraw_partial_preparation(self.f.registry, "approved", store, lease)
        with self.assertRaisesRegex(Denied, "partial-preparation-unknown-or-entered"):
            self.f.finalizer.finalize_partial_preparation(self.f.registry, "approved", store, lease)
        with self.assertRaisesRegex(Denied, "effect-unresolved"):
            store.begin(lease, "slice-remove", "slice:" + lease)
        with self.assertRaisesRegex(Denied, "effect-unresolved"):
            store.begin(lease, "project-delete", "project:" + self.f.io.prepared.incus["project"])
        self.assertEqual(self.f.io.writes()[len(baseline_writes):], native_writes)
        self.assertEqual(store.read(lease), after)
        start.assert_called_once_with(lease, "start")

    def test_watchdog_withdraws_certificate_after_unresolved_slice_and_keeps_alarm(self):
        store, lease = self.f.store, self.f.lease
        certificate, = [effect for effect in self.record["effects"].values()
                        if effect["operation"] == "certificate-create"]
        with self.assertRaises(engine_executor.EngineUnknown):
            self.create_slice(mock.Mock(side_effect=TimeoutError))
        self.f.terminal()
        unresolved = engine_executor._slice_creator(store.read(lease))
        runtime = self.f.runtime
        digest = ledger.digest(identity.decode_json(runtime.read_bytes()))
        result = operating_custody.tick_runtime(str(runtime), digest, "f" * 64)
        after = store.read(lease)
        self.assertEqual(engine_executor._slice_creator(after), unresolved)
        revoke, = [effect for effect in after["effects"].values() if effect["operation"] == "certificate-revoke"]
        self.assertEqual((revoke["target"], revoke["state"]), (certificate["target"], "verified"))
        self.assertIn("cleanup-unknown", [event["kind"] for event in result["events"]])
        self.assertNotIn("partial_preparation_custody", after)
        self.assertFalse(result["native_acceptance"])

    def test_verified_fence_without_engine_gets_withdrawn_and_retained_four_hours(self):
        store, lease = self.f.store, self.f.lease
        self.create_slice(mock.Mock())
        boot = kernel.read_boot_id()
        target, baseline = "fence:" + lease, "c" * 64
        effect = store.begin(lease, "fence-create", target)
        store.bind_fence(lease, effect, policy_sha256="b" * 64, boot_id=boot, netns_device=4,
                         netns_inode=4026532529, host_ifindex=21, peer_ifindex=2, nft_table_handle=3)
        store.bind_host_api_fence(lease, effect, policy_sha256="d" * 64, baseline_sha256=baseline, boot_id=boot,
                                  host_netns_device=4, host_netns_inode=4026531840, nft_table_handle=4)
        store.record(lease, effect, "verified", evidence_sha256="e" * 64)
        terminal = self.f.terminal()
        owner = self.owner()
        self.assertEqual(owner.creator_targets["fence-create"], target)
        with self.assertRaisesRegex(Denied, "partial-custody-fence-live"):
            operating_custody._partial_fence_withdrawal(store.read(lease))

        def withdraw(path, digest, fence, opened, worker, config):
            self.assertEqual(fence.lease_id, lease)
            cut = opened.begin(lease, "fence-disable", target)
            opened.bind_host_api_withdrawal(lease, cut, baseline_sha256=baseline)
            opened.record(lease, cut, "verified", evidence_sha256="a" * 64)

        with mock.patch.object(network_fence, "disable", side_effect=withdraw) as cut, \
             mock.patch.object(network_fence, "verify_disabled") as verify:
            self.f.finalizer.withdraw_partial_preparation(self.f.registry, "approved", store, lease)
        cut.assert_called_once()
        verify.assert_called_once()
        retention = operating_custody.retain_partial_preparation(self.f.registry, "approved", store, lease)
        self.assertEqual(retention["retain_until"], terminal["completed_at"] + 14400)
        keep = store.read(lease)
        self.assertNotIn("owned_instance", keep)
        self.assertNotIn("custody", keep)
        self.assertEqual(retention["fence_disable_sha256"], operating_custody._partial_fence_withdrawal(keep)[
            "fence_disable_sha256"])
        self.f.now = retention["retain_until"] - 1
        with self.assertRaisesRegex(Denied, "partial-retention-not-elapsed"):
            operating_custody.require_partial_cleanup_allowed(store, lease)
        self.f.now += 1
        self.assertEqual(operating_custody.require_partial_cleanup_allowed(store, lease), retention)
        # Withdrawal is journaled once. Re-entry confirms the already empty
        # native gate rather than submitting it again.
        with mock.patch.object(network_fence, "disable") as repeat, \
             mock.patch.object(network_fence, "verify_disabled"):
            self.f.finalizer.withdraw_partial_preparation(self.f.registry, "approved", store, lease)
        repeat.assert_not_called()

        def remove_fence(path, digest, selected, opened, worker, config):
            self.assertEqual(selected, owner)
            removal = opened.begin(lease, "fence-remove", target)
            opened.record(lease, removal, "verified", evidence_sha256="f" * 64)

        def stop_slice(lease_id, action):
            self.assertEqual((lease_id, action), (lease, "stop"))
            states = {effect["operation"]:effect["state"] for effect in store.read(lease)["effects"].values()}
            self.assertEqual((states["fence-remove"], states["slice-remove"]), ("verified", "intent"))

        with mock.patch.object(network_fence, "verify_disabled"), \
             mock.patch.object(network_fence, "remove", side_effect=remove_fence), \
             mock.patch.object(engine_executor, "_slice_active"), \
             mock.patch.object(engine_executor, "_drained_cgroup"), \
             mock.patch.object(engine_executor, "_slice_manager", side_effect=stop_slice) as stop, \
             mock.patch.object(engine_executor, "_slice_inactive"), \
             mock.patch.object(cleanup_storage, "_cleanup_limits", return_value=(100000, 30)), \
             mock.patch.object(cleanup_storage.storage_quota, "acquire_existing_evidence_quota",
                               side_effect=lambda *args:nullcontext()):
            closed = self.f.finalizer.finalize_partial_preparation(self.f.registry, "approved", store, lease)
        stop.assert_called_once_with(lease, "stop")
        self.assertEqual(closed["state"], "FAILED_PARTIAL_PREPARATION_CLOSED")
        self.assertFalse(closed["native_acceptance"])
        self.assertFalse(self.context.exists())

    def test_published_signature_and_original_files_authenticate_after_auth_expiry(self):
        self.f.terminal();owner=self.owner()
        deadline=max(self.record['expires_at'],self.record['authorizations'][-1]['valid_until'])+1
        self.f.now=deadline
        with mock.patch.object(signed_context.time,'time',return_value=deadline):
            files=self.context_files(owner)
        self.assertIn('binding.json',files)
        self.assertEqual(self.f.store.read(self.f.lease)['authorizations'],self.record['authorizations'])
        self.assertFalse(any(e['operation']in {'engine-start','fence-create'}for e in self.f.io.effects()))
    def test_wrong_original_publication_receipt_denied_without_deletion(self):
        self.f.terminal();owner=self.owner();record=self.f.store.read(self.f.lease)
        pub=next(e for e in record['effects'].values()if e['operation']=='context-publish')
        pub['evidence_sha256']='a'*64
        with self.assertRaisesRegex(Denied,'partial-context-original-publication'):self.context_files(owner,record)
        self.assertTrue(self.context.exists());self.assertFalse(any(e['operation']=='context-delete'for e in self.f.io.effects()))
    def test_context_signature_or_original_files_drift_denied(self):
        self.f.terminal();owner=self.owner()
        path=self.context/'binding.json';before=path.read_bytes();binding=identity.decode_json(before)
        pieces=binding['admission'].split('.');pieces[2]=('A'if pieces[2][0]!='A'else'B')+pieces[2][1:]
        binding['admission']='.'.join(pieces);path.write_bytes(ledger.canonical(binding))
        with self.assertRaises(Exception):self.context_files(owner)
        path.write_bytes(before)
        key=self.context/'client.key';key.write_bytes(key.read_bytes()+b'\n')
        with self.assertRaises(Denied):self.context_files(owner)
        self.assertFalse(any(e['operation']=='context-delete'for e in self.f.io.effects()))
    def test_unrecorded_published_context_denied(self):
        self.f.terminal();owner=self.owner()
        from dataclasses import replace
        creators=identity.decode_json(owner.creator_bytes)
        creators.pop('context-publish')
        # This modeled owner shape exercises only the internal context reader;
        # actual Root owner creation always checks the full original prefix.
        changed=replace(owner,creator_bytes=ledger.canonical(creators))
        with self.assertRaisesRegex(Denied,'partial-context-unrecorded-publication'):self.context_files(changed)
    def test_unknown_published_prefix_or_entered_fence_never_becomes_partial_owner(self):
        self.f.terminal();before=self.f.store.read(self.f.lease)
        for kind in ['unknown','intent','wrong-target','missing-engine','fence-create','engine-start']:
            record=copy.deepcopy(before)
            pub=next(e for e in record['effects'].values()if e['operation']=='context-publish')
            if kind in {'unknown','intent'}:pub['state']=kind
            elif kind=='wrong-target':pub['target']='context:'+'0'*64
            elif kind=='missing-engine':
                key=next(k for k,e in record['effects'].items()if e['operation']=='engine-prepare');record['effects'].pop(key)
            else:record['effects']['f'*32]={'operation':kind,'target':'modeled-forbidden','state':'verified'}
            with self.subTest(kind=kind),mock.patch.object(self.f.store,'read',return_value=record):
                with self.assertRaises(Denied):self.owner()
        self.assertEqual(self.f.store.read(self.f.lease),before)
    def test_retention_clock_cannot_be_shortened_or_rebound_to_observation(self):
        owner,terminal,retained=self.terminal_and_retain()
        record=self.f.store.read(self.f.lease);policy=self.f.store.read_policy(record['policy_sha256'])
        for key,value in [('retain_until',retained['retain_until']-1),('terminal_at',terminal['observed_at']+1)]:
            changed={**retained,key:value}
            with self.subTest(field=key),self.assertRaises(Denied):
                operating_custody._partial_custody_record(changed,record,policy)
