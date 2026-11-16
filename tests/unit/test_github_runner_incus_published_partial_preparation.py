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
from incus_lease_issuer import (cell_contract,cleanup_storage,identity,ledger,
    operating_custody,preparation,signed_context)
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
