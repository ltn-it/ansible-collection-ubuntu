"""Real isolated cache exchanges, interruption return and explicit snapshot lifecycle."""
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / 'roles/automatic_updates/files/apt_staged_cache.py'
SPEC = importlib.util.spec_from_file_location('apt_staged_cache', SOURCE)
CACHE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CACHE)


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.paths = {name: self.root/name for name in CACHE.DEFAULT_PATHS}
        for name in ('lists', 'archives'):
            self.paths[name].mkdir(mode=0o755)
            (self.paths[name]/'partial').mkdir(mode=0o700)
            (self.paths[name]/'lock').touch()
        (self.paths['lists']/'previous-index').write_bytes(b'old signed index')
        (self.paths['archives']/'keep.deb').write_bytes(b'preserved previous package')
        for name in ('pkgcache','srcpkgcache','stamp'):
            self.paths[name].write_bytes(('previous-'+name).encode())
            os.utime(self.paths[name],ns=(1234567890000000000,1234567890000000000))
        self.paths['machine'].write_text('a'*32)
        self.paths['status'].write_text('Package: example\nArchitecture: all\nVersion: 1\nStatus: install ok installed\n')
        self.request={'machine_id':'a'*32,'manifest_sha256':'b'*64,
                      'status_sha256':CACHE.DATA.digest(self.paths['status']),'maximum_age_seconds':3600}
        self.bundle=self.root/'bundle';self.bundle.mkdir()
        (self.bundle/'index').write_bytes(b'new verified signed index')
        (self.bundle/'new.deb').write_bytes(b'new verified signed deb')
        self.time=datetime.now(timezone.utc)
        self.manifest={'schema':2,'started_utc':(self.time-timedelta(seconds=120)).isoformat(),
                       'acquired_utc':(self.time-timedelta(seconds=110)).isoformat(),
                       'releases':[{'file':'index','target_name':'new-index'}],'indexes':[],
                       'packages':[{'file':'new.deb','target_name':'new.deb','package':'example','version':'2',
                         'architecture':'all','sha256':CACHE.DATA.digest(self.bundle/'new.deb'),
                         'bytes':(self.bundle/'new.deb').stat().st_size}]}
        (self.bundle/'manifest.json').write_text(json.dumps(self.manifest))
        self.before_dirs={name:CACHE.TX.tree_fingerprint(self.paths[name]) for name in ('lists','archives')}
        self.before_files={name:CACHE.file_state(self.paths[name]) for name in ('pkgcache','srcpkgcache','stamp')}
        self.before_meta={name:CACHE.directory_meta(self.paths[name]) for name in ('lists','archives')}
        self.lock_inodes={name:(self.paths[name]/'lock').stat().st_ino for name in ('lists','archives')}

    def execute(self,action='import',**kwargs):
        return CACHE.transact(action,self.bundle,self.request,paths=self.paths,verifier=lambda *args: {},
                              clock=kwargs.pop('clock',lambda:self.time),audit=lambda:None,**kwargs)

    def assert_original(self):
        for name in ('lists','archives'):
            self.assertEqual(CACHE.TX.tree_fingerprint(self.paths[name]),self.before_dirs[name])
            self.assertEqual(self.paths[name].stat().st_mtime_ns,self.before_meta[name]['mtime_ns'])
        for name in self.before_files:
            self.assertEqual(CACHE.file_state(self.paths[name]),self.before_files[name])

    def test_success_preserves_archives_and_locks_invalidates_bins_and_returns_exact_state(self):
        result=self.execute()
        self.assertEqual(result['state'],'IMPORTED_CACHES')
        self.assertFalse(result['packages_changed'])
        self.assertFalse(result['package_updates_accepted'])
        self.assertEqual((self.paths['archives']/'keep.deb').read_bytes(),b'preserved previous package')
        self.assertEqual((self.paths['archives']/'new.deb').read_bytes(),b'new verified signed deb')
        for name in ('lists','archives'):
            self.assertEqual((self.paths[name]/'lock').stat().st_ino,self.lock_inodes[name])
        self.assertFalse(self.paths['pkgcache'].exists())
        self.assertFalse(self.paths['srcpkgcache'].exists())
        self.assertEqual(self.paths['stamp'].stat().st_mtime_ns,CACHE.origin_ns(self.manifest))
        self.assertFalse(self.execute()['changed'])
        self.assertTrue(self.execute('rollback')['changed'])
        self.assert_original()
        self.assertFalse(self.execute('rollback')['changed'])

    def test_generated_bins_from_ordinary_apt_read_do_not_break_repeat_or_original_return(self):
        self.execute()
        self.paths['pkgcache'].write_bytes(b'regenerated from new indexes')
        self.paths['srcpkgcache'].write_bytes(b'regenerated source cache')
        self.assertFalse(self.execute()['changed'])
        self.execute('rollback');self.assert_original()

    def test_failure_after_either_directory_exchange_rolls_back_both_caches(self):
        for fail_at in (1,2):
            with self.subTest(fail_at=fail_at):
                calls=[]
                def exchange(left,right):
                    CACHE.TX.exchange(left,right);calls.append(1)
                    if len(calls)==fail_at:raise OSError('injected exchange failure')
                with self.assertRaisesRegex(OSError,'exchange failure'):
                    self.execute(swap=exchange)
                self.assert_original()
                self.execute('prune')
                # A new authenticated transaction identity models a new attempt.
                self.request['manifest_sha256']=('c' if fail_at==1 else 'd')*64

    def test_failure_after_each_binary_invalidation_restores_every_file(self):
        for name in ('pkgcache','srcpkgcache'):
            with self.subTest(name=name):
                original=os.unlink;failed=[]
                def unlink(path,*args,**kwargs):
                    result=original(path,*args,**kwargs)
                    if Path(path)==self.paths[name] and not failed:
                        failed.append(1);raise OSError('injected invalidation failure')
                    return result
                with patch.object(CACHE.os,'unlink',side_effect=unlink):
                    with self.assertRaisesRegex(OSError,'invalidation failure'):self.execute()
                self.assert_original();self.execute('prune')
                self.request['manifest_sha256']=('c' if name=='pkgcache' else 'd')*64

    def test_failure_after_stamp_change_and_final_receipt_have_independent_returns(self):
        original=os.utime;failed=[]
        def utime(path,*args,**kwargs):
            result=original(path,*args,**kwargs)
            if Path(path)==self.paths['stamp'] and not failed:
                failed.append(1);raise OSError('injected stamp failure')
            return result
        with patch.object(CACHE.os,'utime',side_effect=utime):
            with self.assertRaisesRegex(OSError,'stamp failure'):self.execute()
        self.assert_original();self.execute('prune');self.request['manifest_sha256']='c'*64
        original_save=CACHE.save
        def save(journal,location):
            if journal['state']=='IMPORTED_CACHES':raise OSError('injected final receipt failure')
            return original_save(journal,location)
        with patch.object(CACHE,'save',side_effect=save):
            with self.assertRaisesRegex(OSError,'receipt failure'):self.execute()
        self.assert_original()

    def test_abrupt_exit_after_first_exchange_can_be_rolled_back_from_local_journal(self):
        child=os.fork()
        if child==0:
            def terminate(left,right):
                CACHE.TX.exchange(left,right);os._exit(55)
            try:self.execute(swap=terminate)
            except BaseException:os._exit(56)
            os._exit(57)
        _,status=os.waitpid(child,0)
        self.assertEqual(os.waitstatus_to_exitcode(status),55)
        self.assertTrue(self.execute('rollback')['changed']);self.assert_original()

    def test_stale_before_preparation_or_after_preparation_never_changes_live_cache(self):
        with self.assertRaisesRegex(ValueError,'expired'):
            self.execute(clock=lambda:self.time+timedelta(hours=2))
        self.assertFalse(self.paths['base'].exists());self.assert_original()
        times=iter([self.time,self.time,self.time+timedelta(hours=2)])
        with self.assertRaisesRegex(ValueError,'expired'):self.execute(clock=lambda:next(times))
        self.assert_original()

    def test_abrupt_exit_during_preparation_is_reconciled_before_pruning(self):
        child=os.fork()
        if child==0:
            original=CACHE.durable_copy
            def terminate(*args,**kwargs):
                original(*args,**kwargs);os._exit(55)
            with patch.object(CACHE,'durable_copy',side_effect=terminate):
                try:self.execute()
                except BaseException:os._exit(56)
            os._exit(57)
        _,status=os.waitpid(child,0)
        self.assertEqual(os.waitstatus_to_exitcode(status),55)
        with self.assertRaisesRegex(ValueError,'Active'):self.execute('prune')
        self.assertTrue(self.execute('rollback')['changed'])
        self.assertFalse(self.execute('rollback')['changed'])
        self.assert_original()
        self.assertTrue(self.execute('prune')['changed']);self.assert_original()

    def test_actual_apt_layout_resolution_rejects_redirected_cache(self):
        values="LISTS='/var/lib/apt/lists/'\nARCHIVES='/var/cache/apt/archives/'\nSTATUS='/var/lib/dpkg/status'\n"
        with patch.object(CACHE.subprocess,'check_output',return_value=values.encode()):
            CACHE.standard_layout()
        with patch.object(CACHE.subprocess,'check_output',return_value=values.replace('/var/lib/apt/lists/','/tmp/foreign/').encode()):
            with self.assertRaisesRegex(ValueError,'layout'):CACHE.standard_layout()

    def test_wrong_target_status_and_signature_fail_before_snapshot_creation(self):
        for name in ('machine','status'):
            saved=self.paths[name].read_bytes();self.paths[name].write_bytes(b'changed')
            with self.subTest(name=name),self.assertRaises(ValueError):self.execute()
            self.paths[name].write_bytes(saved)
            self.assertFalse(self.paths['base'].exists())
        def reject(*args):raise ValueError('invalid signature')
        with self.assertRaisesRegex(ValueError,'signature'):
            CACHE.transact('import',self.bundle,self.request,paths=self.paths,verifier=reject)
        self.assertFalse(self.paths['base'].exists())

    def test_real_frontend_lock_contention_leaves_live_caches_unchanged(self):
        code="import fcntl,sys;f=open(sys.argv[1],'a');fcntl.lockf(f,fcntl.LOCK_EX);print('locked',flush=True);sys.stdin.read()"
        process=subprocess.Popen([sys.executable,'-c',code,str(self.paths['frontend_lock'])],
                                 stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(),'locked')
            with self.assertRaises(BlockingIOError):self.execute()
            self.assert_original()
        finally:process.communicate(input='',timeout=10)

    def test_external_archive_change_or_tampered_snapshot_is_never_partly_overwritten(self):
        self.execute()
        after=CACHE.TX.tree_fingerprint(self.paths['lists'])
        (self.paths['archives']/'foreign.deb').write_bytes(b'foreign change')
        with self.assertRaisesRegex(ValueError,'outside this transaction'):self.execute('rollback')
        self.assertEqual(CACHE.TX.tree_fingerprint(self.paths['lists']),after)
        (self.paths['archives']/'foreign.deb').unlink()
        saved=self.paths['base']/self.request['manifest_sha256']/'previous-pkgcache'
        saved.write_bytes(b'tampered snapshot')
        with self.assertRaisesRegex(ValueError,'snapshot changed'):self.execute('rollback')
        self.assertEqual(CACHE.TX.tree_fingerprint(self.paths['lists']),after)

    def test_active_prune_and_confirmation_without_installed_version_are_rejected(self):
        self.execute()
        with self.assertRaisesRegex(ValueError,'Active'):self.execute('prune')
        with self.assertRaisesRegex(ValueError,'not installed'):self.execute('confirm')
        self.execute('rollback');self.assert_original()

    def test_confirm_installed_versions_and_prune_retain_tombstone_without_touching_live_cache(self):
        self.execute()
        self.paths['status'].write_text('Package: example\nArchitecture: all\nVersion: 2\nStatus: install ok installed\n')
        self.assertTrue(self.execute('confirm')['changed'])
        self.assertFalse(self.execute('confirm')['changed'])
        before={name:CACHE.TX.tree_fingerprint(self.paths[name]) for name in ('lists','archives')}
        self.assertTrue(self.execute('prune')['changed'])
        self.assertFalse(self.execute('prune')['changed'])
        self.assertEqual({name:CACHE.TX.tree_fingerprint(self.paths[name]) for name in before},before)
        location=self.paths['base']/self.request['manifest_sha256']
        self.assertTrue((location/'journal.json').is_file())
        self.assertTrue((location/'request.json').is_file())
        self.assertFalse((location/'exchange-lists').exists())

    def test_rolled_back_snapshot_can_be_pruned_without_replaying_its_import(self):
        self.execute();self.execute('rollback');self.execute('prune');self.assert_original()
        with self.assertRaisesRegex(ValueError,'reconciliation'):self.execute()

    def test_absent_stamp_is_not_manufactured_and_absent_bins_remain_absent_after_return(self):
        for name in self.before_files:self.paths[name].unlink()
        self.before_files={name:None for name in self.before_files}
        self.execute();self.assertFalse(self.paths['stamp'].exists())
        self.paths['pkgcache'].write_bytes(b'derived new cache')
        self.execute('rollback');self.assert_original()


if __name__=='__main__':unittest.main()
