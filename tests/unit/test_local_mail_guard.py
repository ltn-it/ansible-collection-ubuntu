"""Actual private filesystem guards; fixtures do not prove MTA behavior."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('local_mail_guard', ROOT/'roles/local_mail/files/guard.py')
guard = importlib.util.module_from_spec(spec); spec.loader.exec_module(guard)

class PrivilegeTests(unittest.TestCase):
    def test_nonroot_is_refused_before_reading_paths(self):
        with patch('os.geteuid', return_value=12345):
            with self.assertRaisesRegex(AssertionError, 'local-mail-root-input'): guard.check('initialize')

@unittest.skipUnless(os.geteuid()==0, 'Root-owned local mail configuration')
class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        p=Path(self.temp.name);self.root=p/'state';self.config=p/'config';self.spool=p/'spool';self.processes=p/'proc'
        for path in [self.config,self.spool,self.processes]:path.mkdir(mode=0o700)

    def check(self, mode='initialize'):
        return guard.check(mode,root=self.root,config=self.config,spool=self.spool,processes=self.processes)

    def seal(self):
        self.root.mkdir(mode=0o700);record={'schema':1}
        for filename,key in [('main.cf','main_cf_sha256'),('master.cf','master_cf_sha256')]:
            path=self.config/filename;path.write_bytes(b'synthetic local configuration\n');path.chmod(0o644)
            record[key]=hashlib.sha256(path.read_bytes()).hexdigest()
        self.receipt=self.root/'ownership.json';self.receipt.write_text(json.dumps(record));self.receipt.chmod(0o600)

    def test_empty_initialization_is_readonly_and_managed_requires_ownership(self):
        with self.assertRaises(AssertionError):self.check('managed')
        self.assertEqual(self.check()['state'],'EXPLICIT_EMPTY_INACTIVE_INITIALIZATION')
        self.assertFalse(self.root.exists())

    def test_queued_mail_or_active_foreign_master_prevents_initialization(self):
        directory=self.spool/'deferred';directory.mkdir();mail=directory/'existing-message';mail.write_text('preserve')
        with self.assertRaisesRegex(AssertionError,'local-mail-existing-queue'):self.check()
        self.assertEqual(mail.read_text(),'preserve');mail.unlink()
        process=self.processes/'123';process.mkdir();(process/'comm').write_text('master\n')
        (process/'exe').symlink_to('/usr/lib/postfix/sbin/master')
        with self.assertRaisesRegex(AssertionError,'local-mail-existing-active-master'):self.check()

    def test_owned_config_readback_and_drift_refusal_never_repair(self):
        self.seal();before=self.receipt.read_bytes()
        self.assertEqual(self.check('managed')['state'],'OWNED_LOCAL_MAIL_CONFIGURATION_INTACT')
        path=self.config/'main.cf';path.write_bytes(b'changed config')
        with self.assertRaisesRegex(AssertionError,'local-mail-configuration-drift'):self.check('managed')
        self.assertEqual(path.read_bytes(),b'changed config');self.assertEqual(self.receipt.read_bytes(),before)

    def test_public_linked_or_duplicate_receipts_are_refused(self):
        self.seal();self.receipt.chmod(0o644)
        with self.assertRaises(AssertionError):self.check()
        self.receipt.chmod(0o600);other=self.root/'other';os.link(self.receipt,other)
        with self.assertRaises(AssertionError):self.check()
        other.unlink();self.receipt.write_text('{"schema":1,"schema":1}')
        with self.assertRaisesRegex(AssertionError,'local-mail-duplicate-state-field'):self.check()

    def test_unknown_directory_or_symlink_is_not_adopted(self):
        self.root.mkdir(mode=0o700)
        with self.assertRaisesRegex(AssertionError,'local-mail-unowned-state-directory'):self.check()
        self.root.rmdir();self.root.symlink_to(self.config,target_is_directory=True)
        with self.assertRaisesRegex(AssertionError,'local-mail-unowned-state-directory'):self.check()
