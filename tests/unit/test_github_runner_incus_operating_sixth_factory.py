"""Read-only factory joins; public fixed native graph and modeled private retirement. No live closure."""
import base64,copy,hashlib,json,os,socket,sys,tempfile,unittest
from pathlib import Path
from contextlib import ExitStack
from types import SimpleNamespace as NS
from unittest.mock import patch,Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'roles/github_runner/files'))
import test_github_runner_incus_operating_sixth_partial_continuation as sixth_tests
from incus_lease_issuer import run_factory as f,operating_cells as c,ledger,incus_admin,incus_mutation,cleanup_storage
from incus_lease_issuer.identity import Denied
class SixthFactoryTests(unittest.TestCase):
 def setUp(self):
  self.record={'state':'closed','cell_sha256':c.SIXTH_CELL,'policy_sha256':c.SIXTH_POLICY,'closed_at':c.SIXTH_RETAIN_UNTIL,'identity':{'caller_sha':c.SIXTH_MAIN,'run_id':c.SIXTH_RUN,'job_id':c.SIXTH_JOB,'check_run_id':c.SIXTH_CHECK,'runner_id':c.SIXTH_RUNNER,'reusable_sha':c.SIXTH_REUSABLE},'worker':{'uid':995},'effects':{},'partial_preparation_custody':{'terminal_at':c.SIXTH_TERMINAL,'retain_until':c.SIXTH_RETAIN_UNTIL},'native_terminal':{'completed_at':c.SIXTH_TERMINAL}}
  self.creators={n:{}for n in ['network-create','project-create','profile-configure','context-create','certificate-create','engine-prepare','context-publish']}
  self.owner=NS(creators=self.creators,incus={'project':'fixture-project','network':'fixture-network','pool':'fixture-pool'},creator_targets={'certificate-create':'certificate:'+'a'*64},engine_descriptor_bytes=ledger.canonical({'engine':{'storage_root':'/fixture/storage','runroot':'/fixture/run'},'output_path':'/fixture/output','context_path':'/fixture/context'}),engine_descriptor_path='/fixture/descriptor',lease_id=c.SIXTH_LEASE)
  self.origin={'source_sha':c.SIXTH_MAIN,'run_id':c.SIXTH_RUN,'run_attempt':1,'job_id':c.SIXTH_JOB,'check_run_id':c.SIXTH_CHECK,'selector':'fixture'}
  self.configuration=NS(manifest_sha256='b'*64,registry_path='/fixture/registry',registry_sha256='c'*64,preparation_config_path='/fixture/preparation',preparation_config_sha256='d'*64)
  self.original={'directory':f.ROOT+'/'+'e'*64,'manifest_sha256':'b'*64}
 def projection(self,*,bad_absence=False,bad_certificate=False):
  store=NS(lease_ids=lambda:(c.SIXTH_LEASE,),read=lambda _:copy.deepcopy(self.record),require_cleanup_complete=Mock(),read_policy=lambda _:{'retention_seconds':14400})
  class Transaction:
   def __enter__(self):return store
   def __exit__(self,*_):pass
  native=NS(certificate_inventory=lambda:NS(fingerprints=('foreign',)if bad_certificate else (),scope_sha256='1'*64,original_fingerprint='a'*64),certificates_absent=lambda:not bad_certificate,readback=lambda _: {'state':'present'if bad_absence else'absent_observed'})
  with ExitStack()as stack:
   for obj,name,value in [(f,'_read_complete',lambda _:(self.configuration,None)),(f,'read_configuration_origin',lambda _:self.origin),(f.policy_registry,'load_registry',lambda *_:NS(select=lambda _:NS(ledger_path='/fixture/original-store'))),(f.os.path,'lexists',lambda _:False),(f.ledger,'Ledger',lambda *_args,**_kwargs:Transaction()),(f.cell_contract,'partial_preparation_owner',lambda *_:self.owner),(f.preparation,'_config',lambda *_:(NS(incus_socket_path='/fixture/incus.sock'),None,None)),(incus_admin,'RootIncusAdmin',lambda _:NS()),(incus_mutation,'RootPartialPreparationCleanup',lambda *_:native),(cleanup_storage,'_absent',Mock()),(f.time,'time',lambda:c.SIXTH_RETAIN_UNTIL+1)]:stack.enter_context(patch.object(obj,name,value))
   result=f._sixth_closed_projection('/fixture/successor-store',self.original)
  store.require_cleanup_complete.assert_called_once_with(c.SIXTH_LEASE)
  return result
 def test_closed_readback_joins_exact_seven_and_hashes_full_record(self):
  result=self.projection();self.assertEqual(result['record_sha256'],ledger.digest(self.record));self.assertEqual(result['closed_at'],c.SIXTH_RETAIN_UNTIL)
 def test_closed_flag_does_not_substitute_retention_identity_or_exact_creator_prefix(self):
  for change in [lambda:self.record.update(state='retained'),lambda:self.record.update(closed_at=c.SIXTH_RETAIN_UNTIL-1),lambda:self.record['identity'].update(run_id=c.FIFTH_RUN),lambda:self.record['partial_preparation_custody'].update(terminal_at=c.SIXTH_TERMINAL+1),lambda:self.record['native_terminal'].update(completed_at=c.SIXTH_TERMINAL+1),lambda:self.creators.pop('context-publish'),lambda:self.creators.update({'fence-create':{}})]:
   with self.subTest(change=change):
    self.setUp();change()
    with self.assertRaises(Denied):self.projection()
 def test_native_resources_or_returned_certificate_stay_hold(self):
  for kwargs in [{'bad_absence':True},{'bad_certificate':True}]:
   with self.subTest(kwargs=kwargs),self.assertRaises(Denied):self.projection(**kwargs)
 def test_actual_native_reader_rechecks_complete_inventory(self):
  responses={'/actions/runs/'+str(c.SIXTH_RUN):{'fixture':'run'},'/actions/runs/'+str(c.SIXTH_RUN)+'/attempts/1/jobs?per_page=100&page=1':{'fixture':'jobs'}}
  for n in c.SIXTH_CHECKS:responses['/check-runs/'+str(n)]={'fixture':'check','id':n}
  get=Mock(side_effect=lambda p:copy.deepcopy(responses[p]))
  with patch.object(c,'sixth_native_projection',return_value={'native':'modeled'})as verify:self.assertEqual(f._continuation_sixth_native(get),{'native':'modeled'})
  self.assertEqual(get.call_count,6);self.assertEqual(verify.call_args.args[1],{'fixture':'jobs'})
  path='/actions/runs/'+str(c.SIXTH_RUN)+'/attempts/1/jobs?per_page=100&page=1';seen=[0]
  def drift(p):
   if p==path:
    seen[0]+=1
    if seen[0]>1:return {'changed':True}
   return responses[p]
  with patch.object(c,'sixth_native_projection',return_value={}),self.assertRaises(Denied):f._continuation_sixth_native(drift)
 def catalogues(self,root):
  old=root/('a'*64);new=root/('b'*64);old.mkdir(mode=0o700);new.mkdir(mode=0o700)
  intent={'binding':{'source':{'repository':f.SOURCE,'commit_sha':c.SIXTH_MAIN},'controller':{'repository':f.VALIDATION,'commit_sha':c.SIXTH_REUSABLE}},'original_job':{'run_id':c.SIXTH_RUN,'job_id':c.SIXTH_JOB,'check_run_id':c.SIXTH_CHECK}}
  for p,value in [(old/'intent.json',{'fixture':'previous'}),(new/'intent.json',intent)]:p.write_bytes(ledger.canonical(value));p.chmod(0o600)
  return old,new,intent
 @unittest.skipUnless(os.geteuid()==0,'real Root fixture required')
 def test_real_private_catalogue_preserves_previous_and_exact_new_entries(self):
  with tempfile.TemporaryDirectory(dir='/run/proof')as tmp:
   root=Path(tmp);root.chmod(0o700)
   with patch.object(f.run_intake,'ROOT',str(root)):
    old,new,_=self.catalogues(root);previous={old.name:f._fifth_retired_entry(old)}
    result=f._sixth_catalogue_snapshot(str(root),previous,intake=True);self.assertEqual(result[old.name],previous[old.name]);self.assertEqual(result[new.name],f._fifth_retired_entry(new))
    (old/'intent.json').write_bytes(ledger.canonical({'fixture':'changed'}))
    with self.assertRaisesRegex(Denied,'previous-catalogue-drift'):f._sixth_catalogue_snapshot(str(root),previous,intake=True)
 @unittest.skipUnless(os.geteuid()==0,'real Root fixture required')
 def test_real_private_catalogue_foreign_or_unknown_original_job_denied(self):
  for key,value in [('run_id',c.SIXTH_RUN+1),('job_id',c.SIXTH_CHECKS[-1]),('check_run_id',c.SIXTH_CHECKS[-1])]:
   with self.subTest(key=key),tempfile.TemporaryDirectory(dir='/run/proof')as tmp:
    root=Path(tmp);root.chmod(0o700)
    with patch.object(f.run_intake,'ROOT',str(root)):
     old,new,intent=self.catalogues(root);previous={old.name:f._fifth_retired_entry(old)};intent['original_job'][key]=value;(new/'intent.json').write_bytes(ledger.canonical(intent))
     with self.assertRaises(Denied):f._sixth_catalogue_snapshot(str(root),previous,intake=True)
 def test_revalidation_rechecks_both_closed_histories_and_catalogue_union(self):
  prev={'catalogues':{'native_intake_catalogue':{'a':'1'},'native_run_configuration_catalogue':{'b':'2'}}};ret={'catalogues':{'native_intake_catalogue':{'a':'1','c':'3'},'native_run_configuration_catalogue':{'b':'2','d':'4'}}};receipt={'retirement':ret,'previous_qualification':{'retirement':prev}};qualified=({'schema':6,'successor':{'run_id':1,'source_sha':'e'*40,'reusable_sha':'f'*40}},receipt,{"native_intake_catalogue":{},"native_run_configuration_catalogue":{}},None)
  boot=NS(value={'ledger_path':'/fixture/successor','cells':{}},sha256='1'*64)
  # Stop at catalogue access after both real dispatch calls; no Ledger mutation occurs.
  with patch.object(f,'_revalidate_fifth_retirement')as old,patch.object(f,'_revalidate_sixth_retirement')as new,patch.object(f,'_continuation_catalogue',side_effect=RuntimeError('catalogue-boundary')):
   with self.assertRaisesRegex(RuntimeError,'catalogue-boundary'):f._continuation_origin_absent(boot,qualified)
   old.assert_called_once_with(prev,'/fixture/successor');new.assert_called_once_with(ret,'/fixture/successor')
  ret['catalogues']['native_intake_catalogue']['a']='changed'
  with patch.object(f,'_revalidate_fifth_retirement'),patch.object(f,'_revalidate_sixth_retirement'),self.assertRaisesRegex(Denied,'previous-catalogue-drift'):f._continuation_origin_absent(boot,qualified)

 def previous_history_model(self):
  helper=sixth_tests.SixthPartialHistoryTests('runTest');self.addCleanup(helper.doCleanups);helper.setUp()
  model=helper.previous_hash_model();model.start();self.addCleanup(model.stop)
  return helper.previous
 def native_history(self):
  run,jobs,checks=sixth_tests.sixth_native()
  return [run,jobs,*checks]
 def test_public_fixed_provider_graph_through_factory_native_reader(self):
  run,jobs,*checks=self.native_history();responses={'/actions/runs/'+str(c.SIXTH_RUN):run,'/actions/runs/'+str(c.SIXTH_RUN)+'/attempts/1/jobs?per_page=100&page=1':jobs}
  responses.update({'/check-runs/'+str(row['id']):row for row in checks})
  actual=f._continuation_sixth_native(lambda path:copy.deepcopy(responses[path]))
  self.assertEqual(ledger.digest(actual),c.SIXTH_GRAPH)
 def test_root_producer_keeps_modeled_nested5_and_requires_fresh_matching_closure_twice(self):
  previous=self.previous_history_model();self.assertEqual(ledger.digest(previous),c.SIXTH_PREVIOUS_QUALIFICATION)
  closed={'record_sha256':'1'*64,'closed_at':c.SIXTH_RETAIN_UNTIL,'native_absence_sha256':'2'*64}
  def catalogue(directory,prior,*,intake):return {**prior,('e'if intake else'f')*64:'3'*64}
  with patch.object(f,'_root'),patch.object(f,'_revalidate_fifth_retirement')as old,patch.object(f,'_sixth_closed_projection',return_value=closed)as read,patch.object(f,'_sixth_catalogue_snapshot',side_effect=catalogue):
   result=f.collect_sixth_preparation_retirement('/fixture/successor',self.original,previous)
   self.assertEqual(read.call_count,2);self.assertEqual(old.call_count,2);self.assertEqual(result['lease_id'],c.SIXTH_LEASE);self.assertEqual(result['kind'],'original-sixth-post-context-pre-fence-verified-closed')
   self.assertEqual(ledger.digest(previous),c.SIXTH_PREVIOUS_QUALIFICATION)
  with patch.object(f,'_root'),patch.object(f,'_revalidate_fifth_retirement'),patch.object(f,'_sixth_closed_projection',side_effect=[closed,{**closed,'record_sha256':'4'*64}]),patch.object(f,'_sixth_catalogue_snapshot',side_effect=catalogue),self.assertRaisesRegex(Denied,'closed-drift'):
   f.collect_sixth_preparation_retirement('/fixture/successor',self.original,previous)


 def test_whole_native_entry_rechecks_six_histories_and_fresh_absence(self):
  fifth=self.previous_history_model();four=fifth['previous_qualification'];three=four['previous_qualification'];two=three['previous_qualification'];legacy=two['legacy_qualification']
  receipt={'previous_qualification':fifth,'native_sixth':{'fixture':'sixth'}}
  successor={'source_sha':'e'*40,'run_id':c.SIXTH_RUN+1,'reusable_sha':c.SIXTH_REUSABLE}
  qualified=({'schema':6,'successor':successor},receipt,{},None);raw=b'modeled-current-workflow'
  worker=ledger.Worker(995,78,1234,5678,'12345678-1234-4234-8234-123456789abc')
  bootstrap=NS(collector=object(),value={'source_workflow_sha256':hashlib.sha256(raw).hexdigest(),'source_identity':{'runner_id':worker.runner_id,'service_uid':worker.uid}});selected=NS(bootstrap=bootstrap,identity=NS(required_native_job_name='modeled-current-native-job'),template_bytes=b'{}')
  who=NS(caller_sha=successor['source_sha'],run_id=successor['run_id'],reusable_sha=successor['reusable_sha'],job_id=123)
  def get(url,**kwargs):
   if '/contents/'in url:return ledger.canonical({'type':'file','path':'.github/workflows/collection-ci.yml','encoding':'base64','content':base64.b64encode(raw).decode(),'size':len(raw)})
   if '/actions/jobs/'in url:return ledger.canonical({'id':123,'run_id':who.run_id,'head_sha':who.caller_sha,'status':'in_progress','conclusion':None,'name':'modeled-current-native-job','started_at':'2026-11-16T05:42:00Z'})
   return ledger.canonical({'sha':who.caller_sha,'parents':[{'sha':c.SIXTH_MAIN}]})
  order=[];completed=[];expected_history=['origin','prior','third','fourth','fifth','sixth']
  def older(_get,*,prior=False):
   label='prior'if prior else'origin';order.append(label);completed.append(label)
   return two['native_prior']if prior else legacy['native_origin']
  def historical(label,value):
   def read(_get):order.append(label);completed.append(label);return value
   return read
  def barrier(label):
   self.assertCountEqual(completed,expected_history);order.append(label)
  def finish_worker(*_):barrier('worker-finish');return worker
  with ExitStack()as stack:
   connected,peer=socket.socketpair();stack.callback(connected.close);stack.callback(peer.close)
   begin=Mock(side_effect=lambda *_:(worker,object()));finish=Mock(side_effect=finish_worker);discard=Mock()
   # Real socket contract; native/kernel acquisition remains explicitly modeled.
   for obj,name,value in [(f.admission,'_secret',lambda _:None),(f,'_controls',lambda _:'controls'),(f.collector,'begin_worker_acquisition',begin),(f.collector,'finish_worker_acquisition',finish),(f.collector,'discard_worker_acquisition',discard),(f.identity,'verify_github_workflow_assignment',lambda *_args,**_kwargs:(who,f.identity.decode_json(get('/contents/.github/workflows/collection-ci.yml?ref='+who.caller_sha)))),(f.identity,'HTTPSReader',lambda:NS(read=get)),(f,'_continuation_receipt',lambda _:qualified),(f,'_continuation_original_native',older),(f,'_continuation_third_native',historical('third',three['native_third'])),(f,'_continuation_fourth_native',historical('fourth',four['native_fourth'])),(f,'_continuation_fifth_native',historical('fifth',fifth['native_fifth'])),(f,'_continuation_sixth_native',historical('sixth',receipt['native_sixth'])),(f,'_continuation_origin_absent',lambda *_:barrier('fresh-absence')),(c,'validate_continuation_commit',lambda *_:barrier('current-commit'))]:stack.enter_context(patch.object(obj,name,value))
   f._native(connected,selected,'nonce','modeled-auth','modeled-api')
   self.assertCountEqual(order[:-3],expected_history)
   self.assertEqual(order[-3:],['fresh-absence','current-commit','worker-finish'])
   order.clear();completed.clear();expected_history.clear()
   f._native(connected,selected,'nonce','modeled-auth','modeled-api',check_origin=False)
   self.assertEqual(order,['fresh-absence','current-commit','worker-finish'])
   self.assertEqual((begin.call_count,finish.call_count,discard.call_count),(2,2,2))

if __name__=='__main__':unittest.main(verbosity=2)
