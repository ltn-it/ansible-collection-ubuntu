"""Actual fifth CI graph plus modeled Root closure joins; not native acceptance."""
from copy import deepcopy
import json
import os
import tempfile
from types import SimpleNamespace
from pathlib import Path
import sys
import unittest
from unittest import mock

import test_github_runner_incus_operating_four_history_continuation as fourth_tests

FILES=Path(__file__).resolve().parents[2]/'roles/github_runner/files'
sys.path.insert(0,str(FILES))
from incus_lease_issuer import identity,ledger,operating_cells as cells,run_factory as factory
from incus_lease_issuer.identity import Denied


def fifth_native():
    graph=json.loads((Path(__file__).parent/'fixtures/g06-fifth-failed-native-graph.json').read_bytes())
    run=graph['run']
    run['repository']={'id':1103407173,'full_name':'ltn-it/ansible-collection-supplementary','private':False,'owner':{'id':54334171}}
    run['referenced_workflows']=[{'sha':cells.FOUR_HISTORY_REUSABLE,'path':'ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@'+cells.FOUR_HISTORY_REUSABLE}]
    inventory={'total_count':24,'jobs':graph['jobs']}
    checks=[]
    for identifier in cells.FIFTH_CHECKS:
        job=next(row for row in inventory['jobs']if row['id']==identifier)
        checks.append({'id':identifier,'head_sha':cells.FIFTH_MAIN,**{k:job[k]for k in ('name','status','conclusion','started_at','completed_at')},'app':{'id':15368,'slug':'github-actions'}})
    return run,inventory,checks


class FifthPartialHistoryTests(unittest.TestCase):
    def setUp(self):
        self.four=fourth_tests.FourHistoryTests('runTest');self.four.setUp();self.addCleanup(self.four.doCleanups)
        self.old_bytes=ledger.canonical(self.four.value)
        self.native=fifth_native()
        self.retirement={'schema':1,'kind':'original-fifth-partial-preparation-verified-closed','lease_id':cells.FIFTH_LEASE,
            'record_sha256':'c'*64,'closed_at':cells.FIFTH_RETAIN_UNTIL,'retain_until':cells.FIFTH_RETAIN_UNTIL,
            'native_absence_sha256':'d'*64,'catalogues':{'native_intake_catalogue':{'a'*64:'1'*64},
            'native_run_configuration_catalogue':{'b'*64:'2'*64}},
            'original_configuration':{'directory':'/root/configurations/'+'b'*64,'manifest_sha256':'3'*64}}
        self.value=cells.partial_preparation_continuation_qualification(self.four.value,*self.native,self.retirement)
        self.descriptor={'schema':5,'reason':'original-partial-preparation-failed-retired',
            'qualification':{'path':'/root/qualified.json','sha256':ledger.digest(self.value)},
            'successor':{'source_sha':'e'*40,'run_id':cells.FIFTH_RUN+1,'run_attempt':1,'first_parent':cells.FIFTH_MAIN,
                'source_workflow_sha256':cells.FOUR_HISTORY_WORKFLOW,'reusable_sha':cells.FOUR_HISTORY_REUSABLE}}

    def test_actual_complete_failed_graph_joins_unchanged_four_histories_and_new_tuple(self):
        self.assertEqual(cells.validate_continuation_qualification(self.value),self.four.three.two.counts)
        self.assertEqual(ledger.canonical(self.four.value),self.old_bytes)
        self.assertEqual(ledger.canonical(self.value['previous_qualification']),self.old_bytes)
        cells.validate_continuation_descriptor(self.descriptor,cells.FOUR_HISTORY_WORKFLOW,cells.FOUR_HISTORY_REUSABLE)
        cells.validate_continuation_commit({'sha':'e'*40,'parents':[{'sha':cells.FIFTH_MAIN}]},self.descriptor,
            'e'*40,cells.FIFTH_RUN+1,cells.FOUR_HISTORY_REUSABLE)
        graph=self.value['native_fifth'];self.assertEqual(graph['run']['conclusion'],'failure')
        by_id={j['id']:j for j in graph['jobs']}
        self.assertEqual(by_id[132512594125]['conclusion'],'failure')
        self.assertEqual(by_id[132512850572]['runner_id'],78)
        self.assertEqual(by_id[132512850572]['runner_group_id'],8)
        self.assertEqual(by_id[132519922563]['conclusion'],'skipped')
        self.assertEqual(by_id[132519922751]['conclusion'],'skipped')
        self.assertEqual(by_id[132519922881]['conclusion'],'skipped')

    def test_failed_native_cannot_be_green_partial_missing_duplicate_or_borrowed(self):
        for change in [lambda r,j,c:r.update(conclusion='success'),lambda r,j,c:j.update(total_count=True),
            lambda r,j,c:j['jobs'].pop(),lambda r,j,c:j['jobs'].__setitem__(0,deepcopy(j['jobs'][1])),
            lambda r,j,c:j['jobs'][0].update(head_sha='f'*40),lambda r,j,c:c[1].update(id=1),
            lambda r,j,c:c[0].update(conclusion='success')]:
            args=deepcopy(self.native);change(*args)
            with self.assertRaises(Denied):cells.fifth_native_projection(*args)

    def test_actor_profile_changes_do_not_change_failed_execution_graph(self):
        for field in ("actor", "triggering_actor"):
            with self.subTest(field=field):
                changed=deepcopy(self.native)
                changed[0][field].update(avatar_url="https://example.invalid/changed-profile.png",
                    html_url="https://example.invalid/profile", new_profile_field={"ignored":"presentation"})
                changed[0][field].pop("gravatar_id",None)
                self.assertEqual(cells.fifth_native_projection(*changed),self.value['native_fifth'])

    def test_strict_actor_identities_and_complete_execution_evidence_remain_pinned(self):
        for field in ("actor", "triggering_actor"):
            for key,value in (("id",76040633),("id","76040632"),("login","litdeg"),("type","Bot")):
                changed=deepcopy(self.native);changed[0][field][key]=value
                with self.subTest(field=field,key=key,value=value),self.assertRaises(Denied):
                    cells.fifth_native_projection(*changed)
        changes=[lambda r,j,c:r.update(run_attempt=2),
            lambda r,j,c:r.update(head_sha='e'*40),
            lambda r,j,c:r['referenced_workflows'][0].update(sha='e'*40),
            lambda r,j,c:j['jobs'][0].update(run_attempt=2),
            lambda r,j,c:j['jobs'][0].update(runner_id=79),
            lambda r,j,c:j['jobs'][0].update(started_at='2026-11-14T16:35:18Z'),
            lambda r,j,c:j['jobs'][0].update(conclusion='failure'),
            lambda r,j,c:c[0]['app'].update(id=1)]
        for number,change in enumerate(changes):
            changed=deepcopy(self.native);change(*changed)
            with self.subTest(execution_change=number),self.assertRaises(Denied):
                cells.fifth_native_projection(*changed)

    def test_closure_unknown_open_early_missing_catalogue_or_no_work_never_qualifies(self):
        for field,value in [('kind','no-work'),('closed_at',cells.FIFTH_RETAIN_UNTIL-1),('closed_at',True),
                            ('lease_id','f'*32),('record_sha256',None),('catalogues',{})]:
            changed=deepcopy(self.value);changed['retirement'][field]=value
            with self.subTest(field=field),self.assertRaises(Denied):cells.validate_continuation_qualification(changed)
        for field,value in [('run_id',cells.FIFTH_RUN),('first_parent',cells.FOURTH_MAIN),('run_attempt',2)]:
            changed=deepcopy(self.descriptor);changed['successor'][field]=value
            with self.assertRaises(Denied):cells.validate_continuation_descriptor(changed,cells.FOUR_HISTORY_WORKFLOW,cells.FOUR_HISTORY_REUSABLE)

    def test_reader_rechecks_complete_native_inventory_after_checks(self):
        run,jobs,checks=deepcopy(self.native)
        urls={'/actions/runs/'+str(cells.FIFTH_RUN):run,
          '/actions/runs/'+str(cells.FIFTH_RUN)+'/attempts/1/jobs?per_page=100&page=1':jobs,
          **{'/check-runs/'+str(i):v for i,v in zip(cells.FIFTH_CHECKS,checks)}}
        self.assertEqual(factory._continuation_fifth_native(lambda path:urls[path]),self.value['native_fifth'])
        calls=0
        def unstable(path):
            nonlocal calls
            if '/jobs?'in path:
                calls+=1
                if calls==2:return {'total_count':23,'jobs':jobs['jobs'][:-1]}
            return urls[path]
        with self.assertRaises(Denied):factory._continuation_fifth_native(unstable)

    def test_retirement_revalidation_is_original_scope_not_whole_mutable_catalogue(self):
        current={key:self.retirement[key]for key in ('record_sha256','closed_at','native_absence_sha256')}
        with mock.patch.object(factory,'_fifth_closed_projection',return_value=current) as read, \
             mock.patch.object(factory,'collect_partial_preparation_retirement',side_effect=AssertionError('must-not-recollect-original-only-catalogue')):
            factory._revalidate_fifth_retirement(self.retirement,'/root/new-store')
            read.assert_called_once_with('/root/new-store',self.retirement['original_configuration'])
        changed={**current,'record_sha256':'e'*64}
        with mock.patch.object(factory,'_fifth_closed_projection',return_value=changed):
            with self.assertRaises(Denied):factory._revalidate_fifth_retirement(self.retirement,'/root/new-store')


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'isolated Root Linux EE only')
class RetiredCatalogueTests(unittest.TestCase):
    def test_exact_retired_metadata_stays_preserved_unknown_and_changed_entries_hold(self):
        with tempfile.TemporaryDirectory(dir='/run/proof',prefix='retired-catalogue-') as tmp:
            root=Path(tmp);root.chmod(0o700)
            owned=root/('a'*64);owned.mkdir(mode=0o700)
            intent=owned/'intent.json';intent.write_bytes(ledger.canonical({'schema':1,'historical_fixture':'not authority'}));intent.chmod(0o600)
            seal=owned/'sealed-inventory.json';seal.write_bytes(ledger.canonical({'schema':1}));seal.chmod(0o600)
            expected={'directory_device':root.stat().st_dev,'directory_inode':root.stat().st_ino}
            with mock.patch.object(factory,'ROOT',str(root)):
                before=factory._fifth_retired_entry(owned)
                factory._continuation_catalogue(str(root),expected,{'schema':5,'successor':{}},'b'*64,{},
                    intake=False,retired={owned.name:before})
                self.assertTrue(intent.exists());self.assertTrue(seal.exists())
                # The existing inventory helper excludes its own seal leaf;
                # the retirement aggregate deliberately includes that leaf.
                seal.write_bytes(ledger.canonical({'schema':2}))
                with self.assertRaises(Denied):factory._continuation_catalogue(str(root),expected,
                    {'schema':5,'successor':{}},'b'*64,{},intake=False,retired={owned.name:before})
                current=factory._fifth_retired_entry(owned)
                successor={'source_sha':'e'*40,'run_id':cells.FIFTH_RUN+1,'reusable_sha':cells.FOUR_HISTORY_REUSABLE}
                who=factory._invocation(SimpleNamespace(sha256='b'*64),'next',SimpleNamespace(
                    run_id=successor['run_id'],job_id=42,check_run_id=42,caller_sha=successor['source_sha'],
                    reusable_sha=successor['reusable_sha']))
                name=ledger.digest({key:who[key]for key in ('repository','run_id','check_run_id','selector')})
                new=root/name;new.mkdir(mode=0o700)
                metadata={'schema':1,'invocation':who,'snapshot_receipt_sha256':'c'*64,'created_at':1,'deadline':2,
                    'worker':{},'job_started_at':1,'template_sha256':'d'*64}
                future=new/'intent.json';future.write_bytes(ledger.canonical(metadata));future.chmod(0o600)
                # The first valid new configuration must coexist with sealed
                # old entries through every later current-native revalidation.
                descriptor={'schema':5,'successor':successor}
                factory._continuation_catalogue(str(root),expected,descriptor,'b'*64,{'next':{}},
                    intake=False,retired={owned.name:current})
                metadata['invocation']['source_sha']='f'*40
                future.write_bytes(ledger.canonical(metadata))
                with self.assertRaises(Denied):factory._continuation_catalogue(str(root),expected,
                    descriptor,'b'*64,{'next':{}},intake=False,retired={owned.name:current})
                future.unlink();new.rmdir()
                foreign=root/('f'*64);foreign.mkdir(mode=0o700)
                extra=foreign/'intent.json';extra.write_bytes(ledger.canonical({'schema':1}));extra.chmod(0o600)
                with self.assertRaises(Denied):factory._continuation_catalogue(str(root),expected,
                    {'schema':5,'successor':{}},'b'*64,{},intake=False,retired={owned.name:current})
                marker=owned/'publish-intent.json';marker.write_bytes(b'{}');marker.chmod(0o600)
                with self.assertRaises(Denied):factory._fifth_retired_entry(owned)
