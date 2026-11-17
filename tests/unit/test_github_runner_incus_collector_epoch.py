"""Modeled kernel acquisition; no native admission/operating acceptance."""
import ast
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import pathlib
import threading
import os
import sys
import test_github_runner_incus_installation as filesystem
import unittest
from unittest.mock import patch
import test_github_runner_incus_collector as fixtures
from incus_lease_issuer import collector, installation, kernel, service
from incus_lease_issuer.identity import Denied
def has_setuid_capability():
 try:
  with open('/proc/self/status','rb')as source:raw=source.read(65537)
  if len(raw)>65536:return False
  rows=[line.split(b':',1)[1].strip()for line in raw.splitlines()if line.startswith(b'CapEff:')]
  return len(rows)==1 and bool(int(rows[0],16)&(1<<7))
 except (OSError,ValueError):return False

class Socket:
 def fileno(self):return 123
class EpochTests(fixtures.CollectorCompositionTests):
 def epoch(self, mutate=None, **changes):
  defaults={'service':[self.service]*4,'proof':[self.proof,self.proof],'peer':[self.peer]*4,'boot':[fixtures.lineage_fixtures.BOOT]*4,'chains':[self.fixture.snapshots,dict(self.fixture.snapshots)]*2};defaults.update(changes)
  with ExitStack()as s:
   s.enter_context(patch.object(collector.os,'geteuid',return_value=0));s.enter_context(patch.object(collector,'_controls',return_value={}))
   s.enter_context(patch.object(service,'read_service',side_effect=defaults['service']));verify=s.enter_context(patch.object(installation,'verify_installation',side_effect=defaults['proof']))
   s.enter_context(patch.object(kernel,'read_peer',side_effect=defaults['peer']));s.enter_context(patch.object(kernel,'read_boot_id',side_effect=defaults['boot']));s.enter_context(patch.object(kernel,'read_chain',side_effect=defaults['chains']));closure=s.enter_context(patch.object(collector,'_closure',return_value=()))
   sock=Socket();first,token=collector.begin_worker_acquisition(sock,self.policy);self.assertEqual(verify.call_count,1)
   if mutate:mutate(token,sock)
   final=collector.finish_worker_acquisition(token,sock,self.policy)
   self.assertEqual(first,final);self.assertEqual(verify.call_count,2);self.assertEqual(closure.call_count,16)
   with self.assertRaises(Denied):collector.finish_worker_acquisition(token,sock,self.policy)
   return final
 def test_epoch_fresh_full_verification_both_boundaries(self):self.epoch()
 def test_epoch_manifest_peer_service_boot_and_process_drift_denied(self):
  changed=dict(self.fixture.snapshots);changed[104]=replace(changed[104],stat=replace(changed[104].stat,start_ticks=999))
  cases=[{'proof':[self.proof,replace(self.proof,manifest_sha256='3'*64)]},{'peer':[self.peer,replace(self.peer,pid=107)]},{'service':[self.service,replace(self.service,main_pid=201)]},{'boot':[fixtures.lineage_fixtures.BOOT,'22345678-1234-4234-8234-123456789abc']},{'chains':[self.fixture.snapshots,changed]}]
  for case in cases:
   with self.subTest(case=next(iter(case))):
    with self.assertRaises(Denied):self.epoch(**case)
 def test_qualified_mapping_change_between_short_brackets_allowed(self):
  original=collector._closure
  calls=[]
  def mutate(token,sock):
   # This is a distinct, separately qualified closure after native IO; maps
   # are not worker identity. Existing closure validates every mapped backing.
   collector._closure.return_value=('new-qualified-mapping',)
  self.epoch(mutate)
 def test_foreign_mapping_within_short_bracket_denied(self):
  def mutate(token,sock):
   collector._closure.side_effect=[('foreign-unqualified',)]*4+[('changed',)]*4
  with self.assertRaises(Denied):self.epoch(mutate)
 def test_unregistered_copy_does_not_consume_original(self):
  def mutate(token,sock):
   with self.assertRaises(Denied):collector.finish_worker_acquisition(collector._WorkerAcquisition(),sock,self.policy)
  self.epoch(mutate)
 def test_cross_thread_consumes_and_denies(self):
  def mutate(token,sock):
   errors=[]
   def run():
    try:collector.finish_worker_acquisition(token,sock,self.policy)
    except Denied:errors.append(1)
   t=threading.Thread(target=run);t.start();t.join();self.assertEqual(errors,[1])
  with self.assertRaises(Denied):self.epoch(mutate)
 def test_discard_invalidates_no_second_boundary_authority(self):
  with self.assertRaises(Denied):self.epoch(lambda token,sock:collector.discard_worker_acquisition(token))

@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'isolated Root Linux filesystem required')
class RootInventoryTests(unittest.TestCase):
 def setUp(self):
  self.fx=filesystem.RootInstallationFilesystemTests(methodName='runTest');self.addCleanup(self.fx.doCleanups);self.fx.setUp()
  self.proof=installation.verify_installation(self.fx.policy);self.layout=collector._tree_layout(self.proof)
  self.root=os.open('/proc/self/root',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);self.addCleanup(os.close,self.root)
 def scan(self):collector._view_inventory(self.root,self.layout,2101)
 def test_real_process_root_full_scan_and_metadata_only_file_descriptors(self):
  original=os.open;file_flags=[]
  def opened(path,flags,*args,**kwargs):
   if path in self.layout.files or path in {pathlib.PurePosixPath(p).name for p in self.layout.files}:file_flags.append(flags)
   return original(path,flags,*args,**kwargs)
  with patch.object(collector.os,'open',side_effect=opened):self.scan()
  self.assertTrue(file_flags);self.assertTrue(all(flags&os.O_PATH for flags in file_flags))
 @unittest.skipUnless(has_setuid_capability(),"isolated fixture CAP_SETUID required before allocation")
 def test_runtime_children_remain_mutable_but_not_inventory_authority(self):
  directory=os.open(self.fx.runtime,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   os.seteuid(2101)
   try:
    fd=os.open('mutable.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=directory)
    try:os.write(fd,b'inert local test log')
    finally:os.close(fd)
   finally:os.seteuid(0)
  finally:os.close(directory)
  self.scan()
 def test_foreign_entry_replaced_inode_writable_directory_and_symlink_deny(self):
  target=self.fx.root/'bin/Runner.Worker'
  target.chmod(0o777)
  with self.assertRaises(Denied):self.scan()
  target.chmod(0o755)
  with self.assertRaises(Denied):self.scan()
 def test_control_character_name_cannot_be_laundered_by_forged_immutable_layout(self):
  from types import MappingProxyType
  bad='bad\nname';target=self.fx.root/bad;target.write_bytes(b'inert forged name');target.chmod(0o600)
  stamp=installation._stamp(target.stat());trusted=installation.TrustedFile(str(target),stamp[0],stamp[1],'a'*64,stamp[6])
  proof=replace(self.proof,files=MappingProxyType({**self.proof.files,str(target):'a'*64}),trusted_files=MappingProxyType({**self.proof.trusted_files,str(target):trusted}),file_stamps=MappingProxyType({**self.proof.file_stamps,str(target):stamp}),tree_stamps=MappingProxyType({**self.proof.tree_stamps,bad:stamp,'.':installation._stamp(self.fx.root.stat())}))
  with self.assertRaises(Denied):collector._tree_layout(proof)
 def test_original_entry_cap_excludes_mutable_runtime_directory(self):
  maximum=len(self.layout.files)+len(self.layout.directories)+len(self.layout.links)
  original=os.scandir
  @contextmanager
  def ordered(fd):
   with original(fd)as values:rows=list(values)
   yield iter(sorted(rows,key=lambda row:(row.name!='_diag',row.name)))
  with patch.object(installation,'MAX_ENTRIES',maximum),patch.object(collector.os,'scandir',side_effect=ordered):
   fd=installation._open_directory(str(self.fx.root))
   try:installation._inventory(fd,str(self.fx.root),hash_files=False,service_uid=2101)
   finally:os.close(fd)
   self.scan()
 def test_file_replacement_between_stat_and_open_denied(self):
  original=os.open;target=self.fx.root/'bin/Runner.Worker';done=[]
  def opened(path,flags,*args,**kwargs):
   if path=='Runner.Worker' and flags&os.O_PATH and not done:
    done.append(1);raw=target.read_bytes();target.unlink();target.write_bytes(raw);target.chmod(0o755)
   return original(path,flags,*args,**kwargs)
  with patch.object(collector.os,'open',side_effect=opened):
   with self.assertRaises(Denied):self.scan()
  self.assertEqual(done,[1])

if __name__=='__main__':unittest.main()
