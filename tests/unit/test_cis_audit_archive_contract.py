"""Exercise the actual Ansible audit admission tasks without invoking vendor remediation."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml

ROOT=Path(__file__).resolve().parents[2]


class AuditArchiveTests(unittest.TestCase):
    def run_role(self,root,tasks,variables):
        book=root/'case.yml'
        book.write_text(yaml.safe_dump([{'hosts':'all','gather_facts':False,'vars':variables,'tasks':[{
            'name':'Exercise real collection admission','ansible.builtin.include_role':{
                'name':'cis_ubuntu24','tasks_from':tasks,'apply':{'tags':['setup_audit']}},'tags':['setup_audit']}]}]))
        config=root/'ansible.cfg';config.write_text('[defaults]\nroles_path='+str(ROOT/'roles')+'\nlocal_tmp='+str(root/'local')+'\n')
        env=dict(os.environ,ANSIBLE_CONFIG=str(config),ANSIBLE_REMOTE_TEMP=str(root/'remote'))
        env.pop('ANSIBLE_VAULT_PASSWORD_FILE',None)
        return subprocess.run(['ansible-playbook','-i','localhost,','-c','local',str(book),'--tags','setup_audit'],
                              env=env,capture_output=True,text=True,timeout=90)

    def test_real_profile_guard_admits_only_git_or_complete_archive_contract(self):
        base={'cis_ubuntu24_profile_tag':'level1-server','cis_ubuntu24_execution_mode':'audit',
              'ubtu24cis_level_1':True,'ubtu24cis_level_2':False,'setup_audit':True,'run_audit':True,
              'audit_only':True,'fetch_audit_output':True,'audit_format':'json'}
        bound={'cis_ubuntu24_audit_transport_sha256':'a'*64,'audit_conf_source':'/controller/reviewed.tar.gz',
               'audit_conf_dest':'/protected/checkout'}
        with tempfile.TemporaryDirectory(dir=os.environ['HOME']) as temporary:
            root=Path(temporary)
            for mode,extra,expected in [('git',{},0),('archive',{},2),('archive',bound,0),
                    ('archive',{**bound,'cis_ubuntu24_audit_transport_sha256':''},2),
                    ('archive',{**bound,'audit_conf_source':'relative.tar.gz'},2),('copy',bound,2)]:
                with self.subTest(mode=mode,extra=extra):
                    done=self.run_role(root,'assert.yml',{**base,**extra,'audit_content':mode})
                    self.assertEqual(done.returncode,expected,done.stdout+done.stderr)

    def test_changed_or_linked_archive_stops_before_checkout_or_vendor_access(self):
        with tempfile.TemporaryDirectory(dir=os.environ['HOME']) as temporary:
            root=Path(temporary);archive=root/'reviewed.tar.gz';archive.write_bytes(b'approved fixture bytes')
            link=root/'linked.tar.gz';link.symlink_to(archive)
            digest=hashlib.sha256(archive.read_bytes()).hexdigest()
            for path,expected in [(archive,'0'*64),(link,digest)]:
                with self.subTest(path=path):
                    done=self.run_role(root,'audit_archive.yml',{'audit_conf_source':str(path),
                        'cis_ubuntu24_audit_transport_sha256':expected,'audit_conf_dest':str(root/'must-not-be-created')})
                    self.assertEqual(done.returncode,2,done.stdout+done.stderr)
                    self.assertIn('Refusing an unbound or changed offline audit archive',done.stdout)
                    self.assertNotIn('TASK [cis_ubuntu24 : Require a canonical',done.stdout)
                    self.assertFalse((root/'must-not-be-created').exists())

    def test_non_root_checkout_is_refused_before_any_git_or_vendor_execution(self):
        if os.geteuid()==0:self.skipTest('The unprivileged controller witness is required')
        with tempfile.TemporaryDirectory(dir=os.environ['HOME']) as temporary:
            root=Path(temporary);archive=root/'reviewed.tar.gz';archive.write_bytes(b'approved fixture bytes')
            checkout=root/'UBUNTU24-CIS-Audit';checkout.mkdir(mode=0o755)
            entry=checkout/'run_audit.sh';entry.write_text('#!/bin/sh\nexit 99\n');entry.chmod(0o755)
            done=self.run_role(root,'audit_archive.yml',{'audit_conf_source':str(archive),
                'cis_ubuntu24_audit_transport_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
                'audit_conf_dest':str(root)})
            self.assertEqual(done.returncode,2,done.stdout+done.stderr)
            self.assertIn('Require the protected executable',done.stdout)
            self.assertNotIn('TASK [cis_ubuntu24 : Read actual staged commit',done.stdout)


if __name__=='__main__':unittest.main()
