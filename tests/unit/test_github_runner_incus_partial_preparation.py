"""Actual original creators/Unix cleanup/Root Ledger; native runtime is modeled.

Synthetic private keys and files stay only inside the disposable isolated EE.
No real lease, deployment, operating acceptance or retry permission is supplied.
"""
from contextlib import nullcontext
import copy
import datetime as dt
import hashlib
import os
from pathlib import Path
import sys
import time
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

import test_github_runner_incus_preparation as fixtures

FILES = Path(__file__).resolve().parents[2] / 'roles/github_runner/files'
sys.path.insert(0, str(FILES))
from incus_lease_issuer import (cell_contract, cleanup_storage, context_publisher, engine_policy,
    finalization, identity, ledger, operating_custody, preparation)
from incus_lease_issuer.identity import Denied


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'isolated Root Linux EE only')
class PartialPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.RootPreparationTests.setUpClass()

    def setUp(self):
        self.io = fixtures.RootPreparationTests()
        archive = ledger.Ledger.archive_policy
        with mock.patch.object(ledger.Ledger, 'archive_policy',
                new=lambda store, policy: archive(store, {**policy, 'retention_seconds':14400})):
            self.io.setUp()
        self.addCleanup(self.io.doCleanups)
        self.store, self.lease = self.io.store, self.io.lease
        self.registry = self.io.fixture.registry
        self.runtime = self.io.root / 'partial-runtime.json'
        capture = identity.decode_json(self.io.prepared.engine_descriptor_bytes)['capture']
        value = {'schema':2, 'registry_path':self.registry.path, 'registry_sha256':self.registry.sha256,
            'preparation_config_path':str(self.io.config), 'preparation_config_sha256':self.io.sha,
            'authentication_timeout_seconds':5, 'initial_transition_timeout_seconds':60,
            'heartbeat_lead_seconds':30, 'cleanup_timeout_seconds':60,
            'capture':{**capture,'max_total_evidence_bytes':1048576,'max_members':100,'max_member_bytes':1048576}}
        self.runtime.write_bytes(ledger.canonical(value));self.runtime.chmod(0o600)
        self.finalizer = finalization.RootFinalizer(str(self.runtime), hashlib.sha256(self.runtime.read_bytes()).hexdigest())
        self.now = int(time.time())
        original_clock = mock.patch.object(self.store, 'clock', side_effect=lambda:self.now)
        original_clock.start();self.addCleanup(original_clock.stop)

    def fail_after_six(self):
        with mock.patch.object(context_publisher, 'RootContextPublisher', side_effect=Denied('fixture-publisher-constructor')):
            with self.assertRaises(preparation.PreparationUnknown): self.io.run_prepare()
        self.assertEqual(len(self.io.effects()),6)
        self.assertTrue(all(e['state']=='verified' for e in self.io.effects()))
        owner=cell_contract.partial_preparation_owner(self.registry,'approved',self.store,self.lease)
        project=owner.incus['project']
        self.io.server.resources['/1.0/instances?project='+project]=[]
        self.io.server.resources['/1.0/operations?project='+project+'&recursion=1']={}
        return owner

    def terminal(self):
        who=self.store.read(self.lease)['identity'];policy=self.registry.select('approved').identity
        prefix=identity.API+'/repos/'+policy.repository
        actor={'id':next(iter(policy.actor_ids)),'type':'User','login':'fixture'}
        run={'id':who['run_id'],'run_attempt':1,'event':'push','head_branch':'main','head_sha':who['caller_sha'],
          'workflow_id':policy.workflow_id,'path':policy.workflow_path,
          'repository':{'id':policy.repository_id,'full_name':policy.repository,'private':False,'owner':{'id':policy.owner_id}},
          'actor':actor,'triggering_actor':actor,'referenced_workflows':[{'path':policy.reusable_repository+'/'+policy.reusable_path+'@'+policy.reusable_sha,'sha':policy.reusable_sha}]}
        job={'id':who['job_id'],'run_id':who['run_id'],'run_attempt':1,'head_sha':who['caller_sha'],'runner_id':who['runner_id'],
          'name':policy.required_native_job_name,'status':'completed','conclusion':'failure',
          'check_run_url':prefix+'/check-runs/'+str(who['check_run_id']),
          'completed_at':dt.datetime.fromtimestamp(self.now,dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
        check={'id':who['check_run_id'],'head_sha':who['caller_sha'],'status':'completed','conclusion':'failure'}
        routes={prefix+'/actions/runs/'+str(who['run_id']):run,prefix+'/actions/jobs/'+str(who['job_id']):job,
                prefix+'/check-runs/'+str(who['check_run_id']):check}
        with mock.patch.object(identity,'HTTPSReader',return_value=SimpleNamespace(read=lambda url:ledger.canonical(routes[url]))):
            proof=operating_custody.observe_native_terminal(self.registry,'approved',self.store,self.lease)
        return self.store.bind_native_terminal(self.lease,proof)

    def test_six_verified_constructor_failure_withdraw_retain_four_hours_exact_cleanup_and_close(self):
        owner=self.fail_after_six()
        self.assertNotIsInstance(owner,cell_contract.OwnedCellForCleanup)
        self.assertNotIsInstance(owner,cell_contract.PreparedCell)
        self.assertFalse(hasattr(owner,'engine_policy_sha256'))
        with self.assertRaises(Denied):cell_contract.owned_cell_for_cleanup(self.registry,'approved',self.store,self.lease)
        self.finalizer.withdraw_partial_preparation(self.registry,'approved',self.store,self.lease)
        deletes=[r for r in self.io.server.requests if r[0]=='DELETE']
        self.assertEqual(len(deletes),1)
        self.assertIn('/1.0/certificates/',deletes[0][1])
        terminal=self.terminal()
        retained=operating_custody.retain_partial_preparation(self.registry,'approved',self.store,self.lease)
        retention=self.store.read_policy(self.store.read(self.lease)['policy_sha256'])['retention_seconds']
        self.assertEqual(retention,14400)
        self.assertEqual(retained['retain_until'],terminal['completed_at']+14400)
        malformed={**retained,'schema':True}
        with self.assertRaises(Denied):operating_custody._partial_custody_record(malformed,self.store.read(self.lease),
            self.store.read_policy(self.store.read(self.lease)['policy_sha256']))
        self.now=retained['retain_until']-1
        with self.assertRaises(Denied):self.finalizer.finalize_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.assertEqual(len([r for r in self.io.server.requests if r[0]=='DELETE']),1)
        self.now+=1
        with mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
             mock.patch.object(cleanup_storage.storage_quota,'acquire_existing_evidence_quota',side_effect=lambda *a:nullcontext()):
            result=self.finalizer.finalize_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.assertEqual(result['state'],'FAILED_PARTIAL_PREPARATION_CLOSED')
        record=self.store.read(self.lease)
        self.assertEqual(record['state'],'closed')
        self.assertNotIn('custody',record);self.assertNotIn('owned_instance',record)
        self.assertFalse(any(e['operation'] in {'engine-start','engine-stop','fence-create','context-publish'} for e in record['effects'].values()))
        self.assertEqual(sum(e['operation']=='certificate-revoke' for e in record['effects'].values()),1)
        self.assertFalse(result['native_acceptance'])
        descriptor=identity.decode_json(owner.engine_descriptor_bytes)
        self.assertFalse(Path(descriptor['context_path']).exists())
        for path in [descriptor['engine']['storage_root'],descriptor['engine']['runroot'],descriptor['output_path']]:self.assertFalse(Path(path).exists())

    def test_closed_original_projection_rechecks_real_scoped_absence_and_rejects_returned_project(self):
        from incus_lease_issuer import operating_cells as cells,run_factory as factory
        owner=self.fail_after_six()
        self.finalizer.withdraw_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.terminal();retained=operating_custody.retain_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.now=retained['retain_until']
        with mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
             mock.patch.object(cleanup_storage.storage_quota,'acquire_existing_evidence_quota',side_effect=lambda *a:nullcontext()):
            self.finalizer.finalize_partial_preparation(self.registry,'approved',self.store,self.lease)
        record=self.store.read(self.lease);who=record['identity']
        original={'directory':'/run/proof/'+'a'*64,'manifest_sha256':'f'*64}
        configuration=SimpleNamespace(manifest_sha256='f'*64,registry_path=self.registry.path,
            registry_sha256=self.registry.sha256,preparation_config_path=str(self.io.config),preparation_config_sha256=self.io.sha)
        origin={'source_sha':who['caller_sha'],'run_id':who['run_id'],'run_attempt':1,'job_id':who['job_id'],
            'check_run_id':who['check_run_id'],'selector':'approved'}
        with mock.patch.multiple(cells,FIFTH_MAIN=who['caller_sha'],FIFTH_RUN=who['run_id'],FIFTH_JOB=who['job_id'],
                FIFTH_CHECK=who['check_run_id'],FIFTH_RUNNER=who['runner_id'],FIFTH_UID=record['worker']['uid'],FIFTH_CELL=record['cell_sha256'],
                FIFTH_POLICY=record['policy_sha256'],FIFTH_LEASE=self.lease,FIFTH_RETAIN_UNTIL=retained['retain_until'],
                FOUR_HISTORY_REUSABLE=who['reusable_sha']), \
             mock.patch.object(factory,'ROOT','/run/proof'), \
             mock.patch.object(factory,'_read_complete',return_value=(configuration,None)), \
             mock.patch.object(factory,'read_configuration_origin',return_value=origin), \
             mock.patch.object(factory.time,'time',return_value=self.now):
            actual=factory._fifth_closed_projection('/run/proof/new-successor-store',original)
            self.assertEqual(actual['record_sha256'],ledger.digest(record))
            self.assertEqual(actual['closed_at'],self.now)
            # A later independent successor certificate changes the complete
            # inventory, but cannot invalidate the old scope's exact absence.
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            public=Path(owner.incus['server_certificate']['path']).read_bytes()
            fingerprint=hashlib.sha256(x509.load_pem_x509_certificate(public).public_bytes(serialization.Encoding.DER)).hexdigest()
            foreign={'name':'later-successor-certificate','type':'client','restricted':True,
                'projects':['later-successor-project'],'fingerprint':fingerprint,'certificate':public.decode()}
            self.io.server.resources['/1.0/certificates/'+fingerprint]=foreign
            self.assertEqual(factory._fifth_closed_projection('/run/proof/new-successor-store',original),actual)
            foreign['projects']=[owner.incus['project']]
            with self.assertRaises(Denied):factory._fifth_closed_projection('/run/proof/new-successor-store',original)
            foreign['projects']=['later-successor-project']
            with self.assertRaises(Denied):factory._fifth_closed_projection(self.registry.select('approved').ledger_path,original)
            # Native metadata at the exact original target returned: no JSON
            # closed receipt may overrule this actual Unix GET readback.
            self.io.server.resources['/1.0/projects/'+owner.incus['project']]={'name':owner.incus['project'],'config':{}}
            with self.assertRaises(Denied):factory._fifth_closed_projection('/run/proof/new-successor-store',original)
        self.assertEqual(self.store.read(self.lease),record)

    def test_watchdog_discovers_pre_engine_failure_and_withdraws_while_native_job_pending(self):
        self.fail_after_six()
        who=self.store.read(self.lease)['identity'];policy=self.registry.select('approved').identity
        pending={'id':who['job_id'],'run_id':who['run_id'],'head_sha':who['caller_sha'],
            'runner_id':who['runner_id'],'name':policy.required_native_job_name,'run_attempt':1,
            'status':'in_progress','conclusion':None}
        with mock.patch.object(identity,'HTTPSReader',return_value=SimpleNamespace(read=lambda url:ledger.canonical(pending))):
            result=operating_custody.tick_runtime(str(self.runtime),hashlib.sha256(self.runtime.read_bytes()).hexdigest(),'f'*64)
        self.assertEqual(result['state'],'CUSTODY_TICK_COMPLETE')
        record=self.store.read(self.lease)
        self.assertNotIn('native_terminal',record)
        self.assertNotIn('partial_preparation_custody',record)
        self.assertEqual(sum(e['operation']=='certificate-revoke' and e['state']=='verified' for e in record['effects'].values()),1)
        self.assertFalse(any(e['operation']=='engine-start' for e in record['effects'].values()))

    def test_watchdog_failed_six_creator_prefix_withdraws_and_retains_original_clock(self):
        self.fail_after_six();terminal=self.terminal()
        result=operating_custody.tick_runtime(str(self.runtime),hashlib.sha256(self.runtime.read_bytes()).hexdigest(),'f'*64)
        record=self.store.read(self.lease)
        self.assertEqual([e['kind']for e in result['events']],['failed-cell-retained'])
        self.assertEqual(record['partial_preparation_custody']['retain_until'],terminal['completed_at']+14400)
        self.assertEqual(sum(e['operation']=='certificate-revoke' and e['state']=='verified' for e in record['effects'].values()),1)
        self.assertFalse(any(e['operation']in {'engine-start','context-publish','fence-create'}for e in record['effects'].values()))

    def test_published_unexpired_pending_start_waits_without_alarm_or_mutation(self):
        self.io.run_prepare()
        before=self.store.read(self.lease)
        self.assertTrue(any(e['operation']=='context-publish' and e['state']=='verified' for e in before['effects'].values()))
        self.assertFalse(any(e['operation']=='engine-start' for e in before['effects'].values()))
        writes=list(self.io.writes())
        with mock.patch.object(identity,'HTTPSReader',side_effect=AssertionError('healthy-wait-must-not-poll')):
            result=operating_custody.tick_runtime(str(self.runtime),hashlib.sha256(self.runtime.read_bytes()).hexdigest(),'f'*64)
        self.assertEqual(result['events'],[])
        self.assertEqual(self.store.read(self.lease),before)
        self.assertEqual(self.io.writes(),writes)

    def test_published_terminal_without_engine_remains_explicit_cleanup_hold(self):
        self.io.run_prepare();self.terminal()
        before=self.store.read(self.lease);writes=list(self.io.writes())
        result=operating_custody.tick_runtime(str(self.runtime),hashlib.sha256(self.runtime.read_bytes()).hexdigest(),'f'*64)
        self.assertEqual([e['kind']for e in result['events']],['cleanup-unknown'])
        self.assertEqual(self.store.read(self.lease),before)
        self.assertEqual(self.io.writes(),writes)

    def test_published_expired_without_engine_remains_explicit_cleanup_hold(self):
        self.io.run_prepare();before=self.store.read(self.lease);writes=list(self.io.writes())
        deadline=min(before['expires_at'],before['authorizations'][-1]['valid_until'])
        with mock.patch.object(ledger.Ledger,'_now',return_value=deadline):
            result=operating_custody.tick_runtime(str(self.runtime),hashlib.sha256(self.runtime.read_bytes()).hexdigest(),'f'*64)
        self.assertEqual([e['kind']for e in result['events']],['cleanup-unknown'])
        self.assertEqual(self.store.read(self.lease),before)
        self.assertEqual(self.io.writes(),writes)

    def retained_partial_owner(self):
        owner=self.fail_after_six()
        self.finalizer.withdraw_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.terminal();retained=operating_custody.retain_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.now=retained['retain_until']
        return owner,preparation._config(str(self.io.config),self.io.sha)[0]

    def assert_consumer_denied_before_release(self,owner,config):
        before=self.store.read(self.lease)
        data=identity.decode_json(owner.engine_descriptor_bytes)
        paths=[data['engine']['storage_root'],data['engine']['runroot'],data['output_path']]
        with mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
             mock.patch.object(cleanup_storage.storage_quota,'acquire_existing_evidence_quota',side_effect=lambda *a:nullcontext()):
            with self.assertRaises(Denied):cleanup_storage.release_engine(owner,self.store,config)
        self.assertEqual(self.store.read(self.lease),before)
        self.assertTrue(all(Path(path).is_dir()for path in paths))
        self.assertFalse(any(e['operation']=='engine-release'for e in self.io.effects()))

    def test_partial_actual_self_open_fd_denied_before_intent_or_unlink(self):
        owner,config=self.retained_partial_owner()
        data=identity.decode_json(owner.engine_descriptor_bytes)
        marker=Path(data['engine']['storage_root'])/'still-open';marker.write_bytes(b'owned fixture')
        fd=os.open(marker,os.O_RDONLY)
        try:self.assert_consumer_denied_before_release(owner,config)
        finally:os.close(fd)
        self.assertEqual(marker.read_bytes(),b'owned fixture')

    def test_partial_actual_self_mapping_denied_before_intent_or_unlink(self):
        import mmap
        owner,config=self.retained_partial_owner()
        data=identity.decode_json(owner.engine_descriptor_bytes)
        marker=Path(data['engine']['storage_root'])/'still-mapped';marker.write_bytes(b'x'*4096)
        fd=os.open(marker,os.O_RDONLY);mapping=mmap.mmap(fd,4096,access=mmap.ACCESS_READ);os.close(fd)
        try:self.assert_consumer_denied_before_release(owner,config)
        finally:mapping.close()
        self.assertEqual(marker.stat().st_size,4096)

    def test_proc_reader_short_chunks_exact_limit_overflow_and_live_release(self):
        probe=self.io.root/'read-chunks';probe.write_bytes(b'fixture')
        end=time.monotonic()+30
        for chunks,expected in [([b'a',b'b',b'c',b''],b'abc'),([b'',],b'')]:
            with mock.patch.object(cleanup_storage.os,'read',side_effect=chunks):
                self.assertEqual(cleanup_storage._consumer_read(probe,3,end),expected)
        with mock.patch.object(cleanup_storage.os,'read',side_effect=[b'a',b'b',b'c',b'd']):
            with self.assertRaisesRegex(Denied,'cleanup-consumers-read-bound'):
                cleanup_storage._consumer_read(probe,3,end)
        with self.assertRaisesRegex(Denied,'cleanup-storage-budget'):
            cleanup_storage._consumer_read(probe,3,time.monotonic()-1)
        owner,config=self.retained_partial_owner()
        actual_read=os.read;chunks=[]
        def short(fd,size):
            if os.readlink(f'/proc/self/fd/{fd}').endswith('/mountinfo'):
                value=actual_read(fd,min(size,64));chunks.append(len(value));return value
            return actual_read(fd,size)
        with mock.patch.object(cleanup_storage.os,'read',side_effect=short), \
             mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
             mock.patch.object(cleanup_storage.storage_quota,'acquire_existing_evidence_quota',side_effect=lambda *a:nullcontext()):
            receipt=cleanup_storage.release_engine(owner,self.store,config)
        self.assertEqual(receipt.operation,'engine-release')
        self.assertGreater(len(chunks),2)
        self.assertIn(0,chunks)

    def test_actual_fd_close_between_readlink_and_stat_allows_valid_release(self):
        owner,config=self.retained_partial_owner()
        data=identity.decode_json(owner.engine_descriptor_bytes)
        marker=Path(data['engine']['storage_root'])/'closing-owned';marker.write_bytes(b'owned fixture')
        fd=os.open(marker,os.O_RDONLY)
        actual_readlink=os.readlink;closed=[]
        def readlink(path,*args,**kwargs):
            value=actual_readlink(path,*args,**kwargs)
            if str(path)==f'/proc/{os.getpid()}/task/{threading.get_native_id()}/fd/{fd}' and not closed:
                os.close(fd);closed.append(True)
            return value
        try:
            with mock.patch.object(cleanup_storage.os,'readlink',side_effect=readlink), \
                 mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
                 mock.patch.object(cleanup_storage.storage_quota,'acquire_existing_evidence_quota',side_effect=lambda *a:nullcontext()):
                receipt=cleanup_storage.release_engine(owner,self.store,config)
            self.assertEqual(closed,[True])
            self.assertEqual(receipt.operation,'engine-release')
            self.assertFalse(marker.exists())
            self.assertTrue(any(e['operation']=='engine-release' and e['state']=='verified' for e in self.io.effects()))
        finally:
            if not closed:os.close(fd)

    def test_partial_actual_hardlink_alias_open_fd_and_mapping_hold(self):
        import mmap
        owner,config=self.retained_partial_owner()
        data=identity.decode_json(owner.engine_descriptor_bytes)
        marker=Path(data['engine']['storage_root'])/'hardlink-owned';marker.write_bytes(b'x'*4096)
        alias=self.io.root/'outside-hardlink';os.link(marker,alias)
        fd=os.open(alias,os.O_RDONLY)
        try:self.assert_consumer_denied_before_release(owner,config)
        finally:os.close(fd)
        fd=os.open(alias,os.O_RDONLY);mapping=mmap.mmap(fd,4096,access=mmap.ACCESS_READ);os.close(fd)
        try:self.assert_consumer_denied_before_release(owner,config)
        finally:mapping.close()
        self.assertEqual(marker.stat().st_ino,alias.stat().st_ino)

    def test_private_thread_fd_table_alias_is_seen_without_leader_descriptor(self):
        import ctypes,threading,fcntl
        owner,config=self.retained_partial_owner()
        marker=Path(identity.decode_json(owner.engine_descriptor_bytes)['engine']['storage_root'])/'thread-owned'
        marker.write_bytes(b'owned fixture');alias=self.io.root/'thread-alias';os.link(marker,alias)
        probe=self.io.root/'fd-table-probe';probe.write_bytes(b'fixture')
        original=os.open(probe,os.O_RDONLY)
        try:table_fd=fcntl.fcntl(original,fcntl.F_DUPFD_CLOEXEC,256)
        finally:os.close(original)
        ready,done=threading.Event(),threading.Event();state={}
        def consumer():
            libc=ctypes.CDLL(None,use_errno=True)
            result=libc.close_range(ctypes.c_uint(table_fd),ctypes.c_uint(table_fd),ctypes.c_uint(2))
            state.update(unshared=result,errno=ctypes.get_errno(),tid=threading.get_native_id())
            fd=None
            try:
                if result==0:fd=os.open(alias,os.O_RDONLY);state['fd']=fd
                ready.set();done.wait(20)
            finally:
                if fd is not None:os.close(fd)
        thread=threading.Thread(target=consumer);thread.start()
        try:
            self.assertTrue(ready.wait(5));self.assertEqual(state['unshared'],0,state)
            self.assertFalse(cleanup_storage._same_fd_table(state['tid'],threading.get_native_id()))
            taskfd=Path(f'/proc/{os.getpid()}/task/{state["tid"]}/fd/{state["fd"]}')
            self.assertEqual(taskfd.stat().st_ino,marker.stat().st_ino)
            with self.assertRaises(FileNotFoundError):Path(f'/proc/{os.getpid()}/fd/{state["fd"]}').stat()
            self.assert_consumer_denied_before_release(owner,config)
        finally:done.set();thread.join(5);os.close(table_fd)
        self.assertFalse(thread.is_alive());self.assertTrue(marker.exists())

    def test_unsupported_kernel_fd_table_proof_is_a_hold(self):
        with mock.patch.object(cleanup_storage._LIBC,'syscall',return_value=-1):
            with self.assertRaisesRegex(Denied,'cleanup-consumers-fd-table-unavailable'):
                cleanup_storage._same_fd_table(123,456)

    def test_mount_roots_resolve_filesystem_relative_and_ancestor_bind_aliases(self):
        dev=os.makedev(8,1)
        rows=cleanup_storage._consumer_mount_rows(b'10 1 8:1 / /srv/quota rw - ext4 /dev/test rw\n')
        targets=cleanup_storage._consumer_mount_targets(rows,[('/srv/quota/graph/lease',dev,10)])
        self.assertEqual(targets,[(dev,'/graph/lease','/','/srv/quota')])
        cleanup_storage._consumer_mount_aliases(rows,targets)
        for root in ['/graph/lease','/graph','/']:
            alias=cleanup_storage._consumer_mount_rows(
                ('20 1 8:1 '+root+' /alias rw - ext4 /dev/test rw\n').encode())
            with self.subTest(root=root),self.assertRaises(Denied):
                cleanup_storage._consumer_mount_aliases(alias,targets)
        cleanup_storage._consumer_mount_aliases(
            cleanup_storage._consumer_mount_rows(b'20 1 8:1 /unrelated /alias rw - ext4 /dev/test rw\n'),targets)
        with self.assertRaises(Denied):
            cleanup_storage._consumer_mount_targets(rows,[('/srv/quota/graph/lease',dev,99)])

    def test_publication_same_device_distinct_mount_and_parent_mount_drift_hold(self):
        for mounts in ([10,11],[10,10,11]):
            with self.subTest(mounts=mounts), \
                 mock.patch.object(preparation.storage_quota,'_mount_id',side_effect=mounts), \
                 mock.patch.object(preparation.signed_context,'RootSigner',side_effect=AssertionError('no signer')):
                with self.assertRaises(preparation.PreparationDenied):self.io.run_prepare()
            self.assertEqual(self.io.effects(),[])
            self.assertEqual(self.io.writes(),[])

    def test_partial_context_live_directory_fd_denied_before_context_intent(self):
        owner,config=self.retained_partial_owner()
        with mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
             mock.patch.object(cleanup_storage.storage_quota,'acquire_existing_evidence_quota',side_effect=lambda *a:nullcontext()):
            cleanup_storage.release_engine(owner,self.store,config)
        context=identity.decode_json(owner.engine_descriptor_bytes)['context_path']
        before=self.store.read(self.lease);fd=os.open(context,os.O_RDONLY|os.O_DIRECTORY)
        try:
            with self.assertRaises(Denied):cleanup_storage.delete_context(owner,self.store,config)
        finally:os.close(fd)
        self.assertEqual(self.store.read(self.lease),before)
        self.assertTrue(Path(context).is_dir())
        self.assertFalse(any(e['operation']=='context-delete'for e in self.io.effects()))

    def test_partial_consumer_scan_shares_original_operation_deadline(self):
        owner,config=self.retained_partial_owner()
        before=self.store.read(self.lease);now=[100.0]
        def late(owner,opened,end,inventories):
            self.assertEqual(end,130.0)
            now[0]=131.0
        with mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
             mock.patch.object(cleanup_storage.storage_quota,'acquire_existing_evidence_quota',side_effect=lambda *a:nullcontext()), \
             mock.patch.object(cleanup_storage.time,'monotonic',side_effect=lambda:now[0]), \
             mock.patch.object(cleanup_storage,'_partial_no_consumers',side_effect=late):
            with self.assertRaises(Denied):cleanup_storage.release_engine(owner,self.store,config)
        self.assertEqual(self.store.read(self.lease),before)
        self.assertFalse(any(e['operation']=='engine-release'for e in self.io.effects()))

    def test_partial_modeled_cgroup_mount_and_incomplete_visibility_hold_before_intent(self):
        owner,config=self.retained_partial_owner()
        data=identity.decode_json(owner.engine_descriptor_bytes)
        proc=self.io.root/'proc-fixture';leader=proc/'101';child=leader/'task'/'101';(child/'fd').mkdir(parents=True)
        (child/'ns').mkdir();(child/'ns/mnt').write_bytes(b'namespace')
        (child/'stat').write_text('101 (fixture) '+' '.join(['S']+['0']*18+['123'])+'\n')
        (leader/'stat').write_bytes((child/'stat').read_bytes())
        (child/'maps').write_bytes(b'');(child/'cgroup').write_bytes(b'0::/foreign\n')
        (child/'mountinfo').write_text('1 0 0:1 / / rw - tmpfs tmpfs rw\n')
        actual_path=Path
        def projected(value):return proc if value=='/proc'else actual_path(value)
        for kind in ['cgroup','mount','visibility']:
            with self.subTest(kind=kind):
                (child/'cgroup').write_bytes(b'0::/foreign\n')
                (child/'mountinfo').write_text('1 0 0:1 / / rw - tmpfs tmpfs rw\n')
                if kind=='cgroup':(child/'cgroup').write_text('0::/lit-lease-'+self.lease+'.slice\n')
                if kind=='mount':(child/'mountinfo').write_text('1 0 0:1 / '+data['engine']['storage_root']+' rw - tmpfs tmpfs rw\n')
                with mock.patch.object(cleanup_storage,'Path',side_effect=projected):
                    if kind=='visibility':
                        actual_open=os.open
                        def opened(path,*args,**kwargs):
                            if str(path)==str(child/'maps'):raise PermissionError('fixture-hidden-proc')
                            return actual_open(path,*args,**kwargs)
                        with mock.patch.object(cleanup_storage.os,'open',side_effect=opened):self.assert_consumer_denied_before_release(owner,config)
                    else:self.assert_consumer_denied_before_release(owner,config)

    def test_alternate_namespace_filesystem_relative_bind_alias_holds_before_intent(self):
        owner,config=self.retained_partial_owner()
        path=identity.decode_json(owner.engine_descriptor_bytes)['engine']['storage_root']
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
        try:
            dev=os.fstat(fd).st_dev
            target=cleanup_storage._consumer_mount_targets(
                cleanup_storage._consumer_mount_rows(Path('/proc/self/mountinfo').read_bytes()),
                [(path,dev,cleanup_storage.storage_quota._mount_id(fd))])[0][1]
        finally:os.close(fd)
        proc=self.io.root/'alternate-proc';leader=proc/'101';child=leader/'task'/'101';(child/'fd').mkdir(parents=True)
        (child/'ns').mkdir();(child/'ns/mnt').write_bytes(b'other namespace')
        (child/'stat').write_text('101 (fixture) '+' '.join(['S']+['0']*18+['123'])+'\n')
        (leader/'stat').write_bytes((child/'stat').read_bytes())
        (child/'maps').write_bytes(b'');(child/'cgroup').write_bytes(b'0::/foreign\n')
        actual_path=Path
        for root in [target,str(Path(target).parent)]:
            (child/'mountinfo').write_text(
                f'999 1 {os.major(dev)}:{os.minor(dev)} {root} /outside-alias rw - tmpfs fixture rw\n')
            with self.subTest(root=root),mock.patch.object(cleanup_storage,'Path',
                    side_effect=lambda value:proc if value=='/proc' else actual_path(value)):
                self.assert_consumer_denied_before_release(owner,config)

    def assert_postcheck_blocks_later_finalization(self):
        before=self.store.read(self.lease)
        self.assertTrue(any('cleanup_postcheck' in e for e in before['effects'].values()))
        with self.assertRaises(Denied):self.store.close(self.lease)
        again=finalization.RootFinalizer(str(self.runtime),hashlib.sha256(self.runtime.read_bytes()).hexdigest())
        with self.assertRaises(Denied):again.finalize_partial_preparation(self.registry,'approved',self.store,self.lease)
        path=self.registry.select('approved').ledger_path
        with ledger.Ledger(path,clock=lambda:self.now)as reopened:
            with self.assertRaisesRegex(Denied,'cleanup-postcheck-held'):reopened.require_cleanup_postchecks(self.lease)
            with self.assertRaisesRegex(Denied,'cleanup-postcheck-held'):reopened.close(self.lease)
        self.assertEqual(self.store.read(self.lease),before)
        self.assertNotEqual(before['state'],'closed')

    def test_successful_postcheck_witness_is_local_not_reconstructible_after_reopen(self):
        owner,config=self.retained_partial_owner()
        with mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
             mock.patch.object(cleanup_storage.storage_quota,'acquire_existing_evidence_quota',side_effect=lambda *a:nullcontext()):
            cleanup_storage.release_engine(owner,self.store,config)
        self.store.require_cleanup_postchecks(self.lease)
        effect=next(e for e in self.io.effects()if e['operation']=='engine-release')
        with self.assertRaises(Denied):self.store.complete_cleanup_postcheck(ledger._CleanupPostcheck(effect['cleanup_postcheck']))
        path=self.registry.select('approved').ledger_path
        with ledger.Ledger(path,clock=lambda:self.now)as reopened:
            with self.assertRaisesRegex(Denied,'cleanup-postcheck-held'):reopened.require_cleanup_postchecks(self.lease)
        with mock.patch.object(ledger.os,'getpid',return_value=os.getpid()+1):
            with self.assertRaisesRegex(Denied,'cleanup-postcheck-held'):self.store.require_cleanup_postchecks(self.lease)

    def test_partial_release_rejects_durable_receipt_finishing_after_budget(self):
        owner,config=self.retained_partial_owner();now=[100.0]
        original=self.store.record
        def late(*args,**kwargs):
            result=original(*args,**kwargs)
            if args[2]=='verified':now[0]=131.0
            return result
        with mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
             mock.patch.object(cleanup_storage.storage_quota,'acquire_existing_evidence_quota',side_effect=lambda *a:nullcontext()), \
             mock.patch.object(cleanup_storage.time,'monotonic',side_effect=lambda:now[0]), \
             mock.patch.object(self.store,'record',side_effect=late):
            with self.assertRaises(cleanup_storage.CleanupStorageUnknown):
                cleanup_storage.release_engine(owner,self.store,config)
        self.assertTrue(any(e['operation']=='engine-release'and e['state']=='verified'for e in self.io.effects()))
        self.assert_postcheck_blocks_later_finalization()

    def test_partial_release_includes_quota_exit_readback_in_budget(self):
        from contextlib import contextmanager
        owner,config=self.retained_partial_owner();now=[100.0]
        @contextmanager
        def quota(*args):
            yield
            now[0]=131.0
        with mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
             mock.patch.object(cleanup_storage.storage_quota,'acquire_existing_evidence_quota',side_effect=quota), \
             mock.patch.object(cleanup_storage.time,'monotonic',side_effect=lambda:now[0]):
            with self.assertRaises(cleanup_storage.CleanupStorageUnknown):
                cleanup_storage.release_engine(owner,self.store,config)
        self.assert_postcheck_blocks_later_finalization()
        self.assertFalse(any(e['operation']=='engine-release' and e['state']=='verified'for e in self.io.effects()))

    def test_partial_context_rejects_durable_receipt_finishing_after_budget(self):
        owner,config=self.retained_partial_owner()
        with mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
             mock.patch.object(cleanup_storage.storage_quota,'acquire_existing_evidence_quota',side_effect=lambda *a:nullcontext()):
            cleanup_storage.release_engine(owner,self.store,config)
        now=[100.0];original=self.store.record
        def late(*args,**kwargs):
            result=original(*args,**kwargs)
            if args[2]=='verified':now[0]=131.0
            return result
        with mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
             mock.patch.object(cleanup_storage.time,'monotonic',side_effect=lambda:now[0]), \
             mock.patch.object(self.store,'record',side_effect=late):
            with self.assertRaises(cleanup_storage.CleanupStorageUnknown):
                cleanup_storage.delete_context(owner,self.store,config)
        self.assert_postcheck_blocks_later_finalization()

    def test_cross_filesystem_rejected_before_any_creator_intent(self):
        actual=os.fstat
        stage=self.io.stage.stat().st_ino
        def observed(fd):
            row=actual(fd)
            values=list(row)
            if row.st_ino==stage:values[2]+=1
            return os.stat_result(values) if row.st_ino==stage else row
        with mock.patch.object(preparation.os,'fstat',side_effect=observed), \
             mock.patch.object(preparation.signed_context,'RootSigner',side_effect=AssertionError('unexpected-signer-read')) as signer:
            with self.assertRaises(preparation.PreparationDenied):self.io.run_prepare()
            signer.assert_not_called()
        self.assertEqual(self.io.effects(),[])
        self.assertEqual(self.io.writes(),[])

    def test_no_effect_preflight_failure_uses_original_native_retention_without_fabricated_creators(self):
        self.assertEqual(self.io.effects(),[])
        self.finalizer.withdraw_partial_preparation(self.registry,'approved',self.store,self.lease)
        terminal=self.terminal()
        retained=operating_custody.retain_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.assertEqual(retained['retain_until'],terminal['completed_at']+14400)
        self.now=retained['retain_until']
        result=self.finalizer.finalize_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.assertEqual(self.io.effects(),[])
        self.assertEqual(self.io.writes(),[])
        self.assertEqual(result['state'],'FAILED_PARTIAL_PREPARATION_CLOSED')

    def test_lost_actual_certificate_response_is_unknown_and_never_resent(self):
        self.fail_after_six()
        from incus_lease_issuer import incus_mutation
        original=incus_mutation.RootPartialPreparationCleanup.certificate_delete
        def lost(cleanup):
            original(cleanup)
            raise incus_mutation.MutationUnknown('fixture-response-lost')
        with mock.patch.object(incus_mutation.RootPartialPreparationCleanup,'certificate_delete',new=lost):
            with self.assertRaises(finalization.FinalizationUnknown):
                self.finalizer.withdraw_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.assertEqual(sum(r[0]=='DELETE' for r in self.io.server.requests),1)
        self.assertTrue(any(e['operation']=='certificate-revoke' and e['state']=='unknown' for e in self.io.effects()))
        with self.assertRaises(Denied):self.finalizer.withdraw_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.assertEqual(sum(r[0]=='DELETE' for r in self.io.server.requests),1)

    def test_unpublished_context_creator_drift_holds_before_context_delete_intent(self):
        owner=self.fail_after_six()
        self.finalizer.withdraw_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.terminal();retained=operating_custody.retain_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.now=retained['retain_until']
        context=Path(identity.decode_json(owner.engine_descriptor_bytes)['context_path'])
        (context/'config.yml').write_bytes(b'foreign-context-bytes')
        with mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
             mock.patch.object(cleanup_storage.storage_quota,'acquire_existing_evidence_quota',side_effect=lambda *a:nullcontext()):
            with self.assertRaises(Denied):self.finalizer.finalize_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.assertFalse(any(e['operation']=='context-delete' for e in self.io.effects()))
        self.assertTrue(context.exists())
        self.assertEqual(sum(r[0]=='DELETE' for r in self.io.server.requests),1)

    def test_unconfirmed_prepublication_certificate_rotation_never_adopts_or_deletes(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        owner=self.fail_after_six()
        original=owner.creator_targets['certificate-create'].removeprefix('certificate:')
        original_path='/1.0/certificates/'+original
        row=self.io.server.resources.pop(original_path)
        public=Path(owner.incus['server_certificate']['path']).read_bytes()
        fingerprint=hashlib.sha256(x509.load_pem_x509_certificate(public).public_bytes(serialization.Encoding.DER)).hexdigest()
        self.io.server.resources['/1.0/certificates/'+fingerprint]={**row,'fingerprint':fingerprint,'certificate':public.decode()}
        before=self.store.read(self.lease)
        with self.assertRaises(Denied):self.finalizer.withdraw_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.assertEqual(self.store.read(self.lease),before)
        self.assertFalse(any(request[0]=='DELETE' for request in self.io.server.requests))

    def test_unknown_creator_and_engine_entry_are_not_partial_cleanup_authority(self):
        self.fail_after_six()
        # Existing durable effect APIs enforce replay/order. Simulate only the
        # known original paired cleanup uncertainty through those real APIs.
        owner=cell_contract.partial_preparation_owner(self.registry,'approved',self.store,self.lease)
        eid=self.store.begin(self.lease,'certificate-revoke',owner.creator_targets['certificate-create'])
        self.store.record(self.lease,eid,'unknown',evidence_sha256='e'*64)
        with self.assertRaises(Denied):cell_contract.partial_preparation_owner(self.registry,'approved',self.store,self.lease)
        count=len(self.io.writes())
        with self.assertRaises(Denied):self.finalizer.withdraw_partial_preparation(self.registry,'approved',self.store,self.lease)
        self.assertEqual(len(self.io.writes()),count)

    def test_same_protected_context_parent_is_valid_producer_choice(self):
        self.io.value['publication_staging_parent']=str(Path(identity.decode_json(self.io.prepared.engine_descriptor_bytes)['context_path']).parent)
        self.io.seal()
        result=self.io.run_prepare()
        self.assertEqual(result.lease_id,self.lease)
        self.assertEqual(len(self.io.effects()),7)
        with self.assertRaises(Denied):cell_contract.partial_preparation_owner(self.registry,'approved',self.store,self.lease)
