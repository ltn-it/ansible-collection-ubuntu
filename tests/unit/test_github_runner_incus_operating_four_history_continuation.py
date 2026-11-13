"""Fixed-four modeled contracts; actual Root/native provenance remains separate.

All previous three modeled proof realms are retained; production48d remains a
fixed literal. Patched receipt seals below grant no Source/native authority.
"""
import base64
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import identity, ledger, operating_cells as cells, run_factory as factory
from incus_lease_issuer.identity import Denied
import test_github_runner_incus_operating_continuation as legacy_tests
import test_github_runner_incus_operating_three_history_continuation as three_tests


def fourth_native():
    args = deepcopy(three_tests.third_native())
    run, inventory, checks, commit = args
    run.update(id=cells.FOURTH_RUN, head_sha=cells.FOURTH_MAIN)
    run['referenced_workflows'][0].update(sha=cells.FOURTH_REUSABLE,
        path='ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@'+cells.FOURTH_REUSABLE)
    for job in inventory['jobs']:
        job.update(run_id=cells.FOURTH_RUN, head_sha=cells.FOURTH_MAIN)
    for job, check, fixed in zip(inventory['jobs'][22:], checks, cells.continuation_fourth_origin()['jobs']):
        common = {k: fixed[k] for k in ('name','started_at','completed_at','conclusion')}
        job.update(common,id=fixed['job_id'],check_run_url=identity.API+'/repos/'+factory.SOURCE+'/check-runs/'+str(fixed['check_run_id']))
        check.update(common,id=fixed['check_run_id'],head_sha=cells.FOURTH_MAIN)
    commit.update(sha=cells.FOURTH_MAIN,parents=[{'sha':cells.THIRD_MAIN},{'sha':'d'*40}])
    return args


def fourth_observation(counts):
    raw = three_tests.third_observation(counts)
    row = raw['observed']
    for k in ['third_attempt','third_head','third_public_clients','third_run']:
        del row[k]
    row.update(state='ACTUAL_FOURTH_F138_PRODUCT_STORE_AND_CATALOGUES_EMPTY_NO_LEASE',fourth_attempt=1,
        fourth_head=cells.FOURTH_MAIN,fourth_public_clients=cells.FOURTH_CLIENTS,fourth_run=cells.FOURTH_RUN,
        raw_sdk_receipt_sha256=cells.FOURTH_RAW_SDK_RECEIPT)
    return raw


class FourHistoryTests(unittest.TestCase):
    def setUp(self):
        self.three=three_tests.ThreeHistoryTests('runTest');self.three.setUp();self.addCleanup(self.three.doCleanups)
        self.patch('THREE_HISTORY_QUALIFICATION',ledger.digest(self.three.value))
        self.native=fourth_native();self.raw=fourth_observation(deepcopy(self.three.two.counts))
        self.patch('FOURTH_NO_WORK',ledger.digest(self.raw))
        self.value=cells.four_history_continuation_qualification(self.three.value,*self.native,ledger.canonical(self.raw),cells.FOURTH_CLIENTS)
        self.descriptor={'schema':4,'reason':'fourth-runtime-failed-no-work-observed','origin':cells.continuation_origin(),
            'prior':cells.continuation_prior_origin(),'third':cells.continuation_third_origin(),'fourth':cells.continuation_fourth_origin(),
            'qualification':{'path':'/root/qualified.json','sha256':ledger.digest(self.value)},'successor':{'source_sha':'e'*40,
                'run_id':cells.FOURTH_RUN+1,'run_attempt':1,'first_parent':cells.FOURTH_MAIN,
                'source_workflow_sha256':cells.FOUR_HISTORY_WORKFLOW,'reusable_sha':cells.FOUR_HISTORY_REUSABLE}}
    def patch(self,name,value):
        patcher=mock.patch.object(cells,name,value);patcher.start();self.addCleanup(patcher.stop)
    def validate(self,value):return cells.validate_continuation_descriptor(value,cells.FOUR_HISTORY_WORKFLOW,cells.FOUR_HISTORY_REUSABLE)
    def test_all_four_histories_and_exact_previous_qualification_preserved(self):
        self.assertEqual(self.value['previous_qualification'],self.three.value)
        self.assertEqual(self.value['previous_qualification']['previous_qualification']['legacy_qualification'],self.three.two.legacy)
        for value in [self.value,self.three.value,self.three.two.value,self.three.two.legacy]:
            self.assertEqual(cells.validate_continuation_qualification(value),self.three.two.counts)
        self.assertEqual(self.validate(self.descriptor),self.descriptor)
        cells.validate_continuation_commit({'sha':'e'*40,'parents':[{'sha':cells.FOURTH_MAIN}]},self.descriptor,
            'e'*40,cells.FOURTH_RUN+1,cells.FOUR_HISTORY_REUSABLE)
    def test_descriptor_denies_history_loss_old_workflow_replay_and_parent(self):
        changes=[lambda v:v.update(schema=True),lambda v:v.update(reason='retry'),lambda v:v.pop('origin'),
            lambda v:v.pop('prior'),lambda v:v.pop('third'),lambda v:v.pop('fourth'),lambda v:v.update(extra=True),
            lambda v:v['fourth'].update(run_attempt=2),lambda v:v['successor'].update(run_attempt=2),
            lambda v:v['successor'].update(source_workflow_sha256=cells.FOURTH_WORKFLOW),
            lambda v:v['successor'].update(first_parent=cells.THIRD_MAIN),lambda v:v['successor'].update(reusable_sha=cells.ORIGIN_REUSABLE)]
        changes += [lambda v,head=head:v['successor'].update(source_sha=head)for head in [cells.INITIAL_MAIN,cells.ORIGIN_MAIN,cells.PRIOR_MAIN,cells.THIRD_MAIN,cells.FOURTH_MAIN]]
        changes += [lambda v,run=run:v['successor'].update(run_id=run)for run in [cells.ORIGIN_RUN,cells.PRIOR_RUN,cells.THIRD_RUN,cells.FOURTH_RUN]]
        for change in changes:
            value=deepcopy(self.descriptor);change(value)
            with self.subTest(change=change),self.assertRaises(Denied):self.validate(value)
        for head in [cells.INITIAL_MAIN,cells.ORIGIN_MAIN,cells.PRIOR_MAIN,cells.THIRD_MAIN,'a'*40]:
            with self.subTest(parent=head),self.assertRaises(Denied):
                cells.validate_continuation_commit({'sha':'e'*40,'parents':[{'sha':head}]},self.descriptor,
                    'e'*40,cells.FOURTH_RUN+1,cells.FOUR_HISTORY_REUSABLE)
    def test_nested_history_and_fixed_seals_cannot_be_replaced(self):
        changes=[lambda v:v['previous_qualification'].pop('previous_qualification'),
            lambda v:v['previous_qualification']['previous_qualification']['legacy_qualification']['native_origin']['jobs'].pop(),
            lambda v:v['previous_qualification']['previous_qualification']['native_prior']['jobs'].pop(),
            lambda v:v['previous_qualification']['native_third']['jobs'].pop(),lambda v:v['native_fourth']['jobs'].pop(),
            lambda v:v['native_fourth']['jobs'][-1].update(conclusion='success'),lambda v:v['fourth'].update(first_parent=cells.PRIOR_MAIN),
            lambda v:v['fourth_public_clients'].update({'incus_runtime_client.py':'0'*64}),lambda v:v.update(nonce_absence=True)]
        for change in changes:
            value=deepcopy(self.value);change(value)
            with self.subTest(change=change),self.assertRaises(Denied):cells.validate_continuation_qualification(value)
        with mock.patch.object(cells,'FOURTH_NO_WORK',None),self.assertRaises(Denied):cells.validate_continuation_qualification(self.value)
    def test_bounded_no_work_is_not_nonce_absence_reset_or_old_SDK_receipt(self):
        changes=[lambda v:v['observed']['counts'].update(runtime_lease_count=1),
            lambda v:v['observed']['counts']['native_intake_catalogue'].update(entries=1),
            lambda v:v['observed']['counts']['native_run_configuration_catalogue'].update(directory_inode=125),
            lambda v:v['observed'].update(nonce_history_absence_claimed=True),lambda v:v['observed'].update(test_state_reset_or_cleanup_performed=True),
            lambda v:v['observed'].update(probe_sent_no_challenge_or_job_request=False),lambda v:v['observed'].update(operator_raw_ledger_or_signing_key_read_export_or_hash=True),
            lambda v:v['observed'].update(fourth_attempt=2),lambda v:v['observed'].update(at=True),
            lambda v:v['observed'].update(raw_sdk_receipt_sha256='0'*64),lambda v:v.update(rc=1),lambda v:v.update(stderr_bytes=1)]
        for change in changes:
            raw=deepcopy(self.raw);change(raw);value=deepcopy(self.value);value['no_work_receipt_b64']=base64.b64encode(ledger.canonical(raw)).decode()
            with self.subTest(change=change),mock.patch.object(cells,'FOURTH_NO_WORK',ledger.digest(raw)),self.assertRaises(Denied):cells.validate_continuation_qualification(value)
    def test_fourth_native_provider_neighbors_deny(self):
        changes=[(0,lambda v:v.update(run_attempt=2)),(0,lambda v:v.update(status='in_progress')),
            (0,lambda v:v['actor'].update(id=1)),(0,lambda v:v['triggering_actor'].update(login='other')),
            (0,lambda v:v['referenced_workflows'][0].update(sha=cells.PRIOR_REUSABLE)),(1,lambda v:v['jobs'].pop()),
            (1,lambda v:v['jobs'][-1].update(runner_id=79)),(1,lambda v:v['jobs'][-1].update(runner_group_id=7)),
            (1,lambda v:v['jobs'][-1].update(completed_at='2026-11-13T11:43:17Z')),
            (2,lambda v:v[0]['app'].update(id=1)),(2,lambda v:v[0].update(conclusion='success')),
            (3,lambda v:v['parents'][0].update(sha=cells.PRIOR_MAIN))]
        for index,change in changes:
            args=deepcopy(self.native);change(args[index])
            with self.subTest(index=index),self.assertRaises(Denied):cells.fourth_native_projection(*args)


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'isolated Linux UID0 EE only')
class RootFourHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):legacy_tests.RootContinuationTests.setUpClass()
    def setUp(self):
        self.three=three_tests.RootThreeHistoryTests('runTest');self.three.setUp();self.addCleanup(self.three.doCleanups)
        self.old=self.three.old;self.helper=self.old.helper;previous=identity.decode_json(self.old.receipt.read_bytes())
        self.patch('THREE_HISTORY_QUALIFICATION',ledger.digest(previous));self.raw=fourth_observation(self.three.counts)
        self.patch('FOURTH_NO_WORK',ledger.digest(self.raw));self.fourth=fourth_native()
        value=cells.four_history_continuation_qualification(previous,*self.fourth,ledger.canonical(self.raw),cells.FOURTH_CLIENTS)
        self.old.receipt.write_bytes(ledger.canonical(value));self.old.receipt.chmod(0o600)
        self.patch('FOUR_HISTORY_WORKFLOW',self.helper.value['source_workflow_sha256']);self.patch('FOUR_HISTORY_REUSABLE',self.helper.value['source_identity']['reusable_sha'])
        self.old.descriptor.clear();self.old.descriptor.update({'schema':4,'reason':'fourth-runtime-failed-no-work-observed',
            'origin':cells.continuation_origin(),'prior':cells.continuation_prior_origin(),'third':cells.continuation_third_origin(),
            'fourth':cells.continuation_fourth_origin(),'qualification':{'path':str(self.old.receipt),'sha256':ledger.digest(value)},
            'successor':{'source_sha':self.helper.native.claims['sha'],'run_id':self.helper.native.run['id'],'run_attempt':1,
                'first_parent':cells.FOURTH_MAIN,'source_workflow_sha256':self.helper.value['source_workflow_sha256'],
                'reusable_sha':self.helper.value['source_identity']['reusable_sha']}});self.old.parent=cells.FOURTH_MAIN
        original_reader=identity.HTTPSReader();self.fourth_reads=[];origin=cells.continuation_fourth_origin();prefix=identity.API+'/repos/'+factory.SOURCE
        routes={prefix+'/actions/runs/'+str(origin['run_id']):self.fourth[0],
            prefix+'/actions/runs/'+str(origin['run_id'])+'/attempts/1/jobs?per_page=100&page=1':self.fourth[1],
            prefix+'/git/commits/'+origin['source_sha']:self.fourth[3],
            **{prefix+'/check-runs/'+str(row['id']):row for row in self.fourth[2]}}
        def read(url,*,bearer=None):
            if url in routes:self.fourth_reads.append(url);return ledger.canonical(deepcopy(routes[url]))
            return original_reader.read(url,bearer=bearer)
        self.enterContext(mock.patch.object(identity,'HTTPSReader',return_value=type('Reader',(),{'read':staticmethod(read)})()))
        self.helper.seal()
    def patch(self,name,value):self.enterContext(mock.patch.object(cells,name,value))
    def test_four_histories_once_per_proof_but_no_cross_proof_cache(self):
        with mock.patch.object(factory,'_continuation_original_native',wraps=factory._continuation_original_native)as earlier, \
                mock.patch.object(factory,'_continuation_third_native',wraps=factory._continuation_third_native)as third, \
                mock.patch.object(factory,'_continuation_fourth_native',wraps=factory._continuation_fourth_native)as fourth:
            proof,token=self.old.mint()
            for _ in range(2):factory.require_bootstrap_native(proof,self.helper.server,proof.policy,token,'synthetic-job-token')
            self.assertEqual((earlier.call_count,third.call_count,fourth.call_count),(2,1,1));self.assertEqual(len(self.fourth_reads),5)
            self.fourth[2][0]['conclusion']='success'
            with self.assertRaises(Denied):self.old.mint()
            self.assertEqual((earlier.call_count,third.call_count,fourth.call_count),(4,2,2));self.assertEqual(len(self.fourth_reads),10)
    def test_all_five_cells_execution_and_observer_require_fresh_parent(self):
        for selector in self.helper.value['cells']:
            for purpose in ['execution','observer']:
                with self.subTest(selector=selector,purpose=purpose):
                    self.old.parent=cells.THIRD_MAIN
                    try:
                        with self.assertRaises(Denied):self.old.mint(selector,purpose)
                    finally:self.old.parent=cells.FOURTH_MAIN
                    proof,token=self.old.mint(selector,purpose);self.old.parent=cells.THIRD_MAIN
                    try:
                        with self.assertRaises(Denied):factory.require_bootstrap_native(proof,self.helper.server,proof.policy,token,'synthetic-job-token')
                    finally:self.old.parent=cells.FOURTH_MAIN
                    _,who,_=factory.require_bootstrap_native(proof,self.helper.server,proof.policy,token,'synthetic-job-token')
                    self.assertEqual(who.run_id,self.old.descriptor['successor']['run_id'])
        with ledger.Ledger(self.helper.store_path)as store:self.assertEqual(store.lease_ids(),())
    def test_every_history_current_job_and_original_absence_are_still_checked(self):
        for native in [self.old.origin,self.three.prior,self.three.third,self.fourth]:
            native[2][0]['conclusion']='success'
            with self.subTest(origin=native[0]['id']),self.assertRaises(Denied):self.old.mint()
            native[2][0]['conclusion']='failure'
        proof,token=self.old.mint();self.helper.native.job['status']='completed'
        with self.assertRaises(Denied):factory.require_bootstrap_native(proof,self.helper.server,proof.policy,token,'synthetic-job-token')
        self.helper.native.job['status']='in_progress';(self.old.intakes/('c'*64)).mkdir(mode=0o700)
        with self.assertRaises(Denied):factory.require_bootstrap_native(proof,self.helper.server,proof.policy,token,'synthetic-job-token')

if __name__=='__main__':unittest.main()
