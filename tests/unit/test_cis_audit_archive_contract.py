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
    def test_archive_binding_does_not_replace_inputs_of_a_following_play(self):
        tasks=yaml.safe_load((ROOT/'roles/cis_ubuntu24/tasks/audit_archive.yml').read_text())
        start=next(i for i,t in enumerate(tasks) if t['name'].startswith('Bind the verified existing checkout'))
        with tempfile.TemporaryDirectory(dir=os.environ['HOME']) as temporary:
            root=Path(temporary)
            variables={'audit_content':'archive','audit_conf_source':'/controller/first.tar',
                       'audit_conf_dest':'/opt/first','audit_conf_dir':'/opt/first/UBUNTU24-CIS-Audit',
                       'cis_ubuntu24_audit_archive_realpath':{'stdout':'/opt/first/UBUNTU24-CIS-Audit'},
                       'cis_ubuntu24_audit_vendor_transport':{'content':'archive','source':'/controller/first.tar',
                          'destination':'/opt/first','directory':'/opt/first/UBUNTU24-CIS-Audit'}}
            book=root/'repeat.yml'
            book.write_text(yaml.safe_dump([
                {'hosts':'all','gather_facts':False,'vars':variables,
                 'tasks':tasks[start:]+[{'ansible.builtin.meta':'end_host'}]},
                {'hosts':'all','gather_facts':False,'vars':{'audit_content':'git',
                   'audit_conf_source':'/controller/second.tar','audit_conf_dest':'/opt/second',
                   'audit_conf_dir':'/opt/second/UBUNTU24-CIS-Audit'},'tasks':[
                     {'ansible.builtin.assert':{'that':["audit_content == 'git'",
                        "audit_conf_source == '/controller/second.tar'","audit_conf_dest == '/opt/second'",
                        "audit_conf_dir == '/opt/second/UBUNTU24-CIS-Audit'"]}}]}]))
            env=dict(os.environ,ANSIBLE_LOCAL_TEMP=str(root/'local'),ANSIBLE_REMOTE_TEMP=str(root/'remote'))
            env.pop('ANSIBLE_VAULT_PASSWORD_FILE',None)
            done=subprocess.run(['ansible-playbook','-i','localhost,','-c','local',str(book)],
                                env=env,capture_output=True,text=True,timeout=90)
            self.assertEqual(done.returncode,0,done.stdout+done.stderr)

    def test_apparmor_postcheck_runs_in_a_following_play_after_vendor_end_host(self):
        with tempfile.TemporaryDirectory(dir=os.environ['HOME']) as temporary:
            root=Path(temporary)
            play=[{'hosts':'all','gather_facts':False,'tasks':[
                {'name':'Model the pinned vendor audit-only termination','ansible.builtin.meta':'end_host'},
                {'ansible.builtin.fail':{'msg':'End-host must skip this task'}}]},
                {'hosts':'all','gather_facts':False,'vars':{'ansible_facts':{
                    'distribution':'Debian','distribution_major_version':'24'}},'tasks':[
                    {'block':[{'ansible.builtin.include_role':{'name':'cis_ubuntu24',
                              'tasks_from':'apparmor_guard.yml'}}],
                     'rescue':[{'ansible.builtin.assert':{'that':[
                         "ansible_failed_task.name == 'Require the native Ubuntu 24 AppArmor target'",
                         "ansible_failed_task.action == 'ansible.builtin.assert'"]}},
                         {'ansible.builtin.set_fact':{'postcheck_reached':True}}]},
                    {'ansible.builtin.assert':{'that':'postcheck_reached | default(false)'}}]}]
            book=root/'postcheck.yml';book.write_text(yaml.safe_dump(play))
            config=root/'ansible.cfg';config.write_text('[defaults]\nroles_path='+str(ROOT/'roles')+'\n')
            env=dict(os.environ,ANSIBLE_CONFIG=str(config),ANSIBLE_LOCAL_TEMP=str(root/'local'),
                     ANSIBLE_REMOTE_TEMP=str(root/'remote'))
            env.pop('ANSIBLE_VAULT_PASSWORD_FILE',None)
            done=subprocess.run(['ansible-playbook','-i','localhost,','-c','local',str(book)],
                                env=env,capture_output=True,text=True,timeout=90)
            self.assertEqual(done.returncode,0,done.stdout+done.stderr)

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
                    ('archive',{**bound,'audit_conf_source':'relative.tar.gz'},2),('copy',bound,2),
                    ('git',{'audit_conf_dest':'/opt/space dir'},2),
                    ('git',{'audit_conf_dest':'/opt/path\n'},2),
                    ('git',{'audit_conf_dir':'/opt/unchecked'},2)]:
                with self.subTest(mode=mode,extra=extra):
                    done=self.run_role(root,'assert.yml',{**base,**extra,'audit_content':mode})
                    self.assertEqual(done.returncode,expected,done.stdout+done.stderr)

    def test_unsafe_vendor_checkout_paths_fail_before_transport_or_vendor_execution(self):
        with tempfile.TemporaryDirectory(dir=os.environ['HOME']) as temporary:
            root=Path(temporary)
            for path in ['/opt/space dir', '/opt/path;touch marker', '/opt/$(touch marker)',
                         '/opt/`touch marker`', '/opt/path\ncommand', '/opt/path\n', '/opt/../foreign', '/opt/./audit']:
                with self.subTest(path=path):
                    done=self.run_role(root,'audit_archive.yml',{'audit_conf_dest':path})
                    self.assertEqual(done.returncode,2,done.stdout+done.stderr)
                    self.assertIn('shell metacharacters or whitespace',done.stdout)
                    self.assertNotIn('TASK [cis_ubuntu24 : Read the exact controller',done.stdout)
            for path in ['/opt', '/opt/reviewed_checkout-1.2']:
                with self.subTest(path=path):
                    done=self.run_role(root,'audit_execution_path.yml',{'audit_conf_dest':path,
                        'audit_conf_dir':path+'/UBUNTU24-CIS-Audit'})
                    self.assertEqual(done.returncode,0,done.stdout+done.stderr)

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

    def test_auditor_refuses_unreviewed_architecture_pin_and_paths_before_acquisition(self):
        with tempfile.TemporaryDirectory(dir=os.environ['HOME']) as temporary:
            root=Path(temporary)
            for extra in [
                {'ansible_facts':{'machine':'s390x'}},
                {'cis_ubuntu24_auditor_source':'relative/goss'},
                {'cis_ubuntu24_auditor_dependency':{'repository':'https://github.com/krameff/goss',
                  'version':'v0.5.0','checksums':{}}},
            ]:
                with self.subTest(extra=extra):
                    done=self.run_role(root,'auditor.yml',{'ansible_facts':{'machine':'x86_64'},**extra})
                    self.assertEqual(done.returncode,2,done.stdout+done.stderr)
                    self.assertIn('Refusing an unreviewed auditor runtime',done.stdout)
                    self.assertNotIn('TASK [cis_ubuntu24 : Acquire',done.stdout)

    def test_offline_auditor_requires_fixed_release_bytes_and_never_downloads(self):
        with tempfile.TemporaryDirectory(dir=os.environ['HOME']) as temporary:
            root=Path(temporary);binary=root/'goss';binary.write_bytes(b'not the reviewed release')
            linked=root/'linked-goss';linked.symlink_to(binary)
            for path in [binary,linked,root/'missing']:
                with self.subTest(path=path):
                    done=self.run_role(root,'auditor.yml',{'ansible_facts':{'machine':'x86_64'},
                        'cis_ubuntu24_auditor_source':str(path),
                        'cis_ubuntu24_auditor_cache_directory':str(root/'no-download')})
                    self.assertEqual(done.returncode,2,done.stdout+done.stderr)
                    self.assertIn('Refusing missing, linked or changed auditor bytes',done.stdout)
                    self.assertNotIn('TASK [cis_ubuntu24 : Bind the admitted auditor',done.stdout)
                    self.assertFalse((root/'no-download').exists())

    def test_admitted_vendor_inputs_survive_include_vars(self):
        # Exercise the real binding task and Ansible precedence, without claiming
        # fixture bytes satisfy the fixed release checksum. Real bytes run natively.
        tasks=yaml.safe_load((ROOT/'roles/cis_ubuntu24/tasks/auditor.yml').read_text())
        defaults=yaml.safe_load((ROOT/'roles/cis_ubuntu24/defaults/main.yml').read_text())
        with tempfile.TemporaryDirectory(dir=os.environ['HOME']) as temporary:
            root=Path(temporary);vendor=root/'vendor.yml'
            vendor.write_text(yaml.safe_dump({'get_audit_binary_method':'download',
                'audit_bin_version':{'release':'v0.5.0'},'audit_bin':'/foreign/goss'}))
            book=root/'bind.yml';book.write_text(yaml.safe_dump([{'hosts':'all','gather_facts':False,
                'vars':{**defaults,'cis_ubuntu24_auditor_controller_file':str(root/'admitted-goss')},
                'tasks':[tasks[-2],{'ansible.builtin.include_vars':str(vendor)},tasks[-1],
                    {'ansible.builtin.assert':{'that':["get_audit_binary_method == 'copy'",
                      "audit_bin_version.release == 'v0.4.8'", "audit_bin == '/usr/local/bin/goss'",
                      'audit_bin_copy_location == cis_ubuntu24_auditor_controller_file',
                      "audit_bin_version.AMD64_checksum == 'sha256:' ~ cis_ubuntu24_auditor_dependency.checksums.x86_64",
                      "audit_bin_version.ARM64_checksum == 'sha256:' ~ cis_ubuntu24_auditor_dependency.checksums.aarch64"]}}]}]))
            env=dict(os.environ,ANSIBLE_LOCAL_TEMP=str(root/'local'),ANSIBLE_REMOTE_TEMP=str(root/'remote'))
            env.pop('ANSIBLE_VAULT_PASSWORD_FILE',None)
            done=subprocess.run(['ansible-playbook','-i','localhost,','-c','local',str(book)],
                env=env,capture_output=True,text=True,timeout=90)
            self.assertEqual(done.returncode,0,done.stdout+done.stderr)

    def test_conflicting_extra_vars_cannot_replace_effective_auditor_bindings(self):
        # Exercise real selection/binding/assert tasks. No fixture is represented
        # as an accepted release binary; real checksum rejection is tested above.
        tasks=yaml.safe_load((ROOT/'roles/cis_ubuntu24/tasks/auditor.yml').read_text())
        defaults=yaml.safe_load((ROOT/'roles/cis_ubuntu24/defaults/main.yml').read_text())
        with tempfile.TemporaryDirectory(dir=os.environ['HOME']) as temporary:
            root=Path(temporary)
            selected=[task for task in tasks if task['name'] in (
                'Select the exact architecture-bound controller auditor input',
                'Require selected auditor facts to match the independently fixed release',
                'Bind the admitted auditor above upstream variable loading',
                'Require effective vendor auditor bindings before upstream execution')]
            book=root/'binding.yml'
            book.write_text(yaml.safe_dump([{'hosts':'all','gather_facts':False,
                'vars':{**defaults,'ansible_facts':{'machine':'x86_64'},
                        'cis_ubuntu24_auditor_source':str(root/'admitted-goss')},
                'tasks':selected+[{'name':'Vendor execution must not be reached on conflicting inputs',
                    'ansible.builtin.debug':{'msg':'admitted'}}]}]))
            env=dict(os.environ,ANSIBLE_LOCAL_TEMP=str(root/'local'),ANSIBLE_REMOTE_TEMP=str(root/'remote'))
            env.pop('ANSIBLE_VAULT_PASSWORD_FILE',None)
            for extra in [{}, {'get_audit_binary_method':'download'},
                    {'audit_bin_copy_location':'/controller/unchecked-goss'},
                    {'audit_bin_path':'/tmp/'}, {'audit_bin':'/tmp/goss'},
                    {'audit_bin_version':{'release':'v0.5.0'}},
                    {'cis_ubuntu24_auditor_sha256':'0'*64},
                    {'cis_ubuntu24_auditor_controller_file':'/controller/unchecked-goss'}]:
                with self.subTest(extra=extra):
                    done=subprocess.run(['ansible-playbook','-i','localhost,','-c','local',str(book),
                        '--extra-vars',__import__('json').dumps(extra)], env=env,capture_output=True,text=True,timeout=90)
                    self.assertEqual(done.returncode,2 if extra else 0,done.stdout+done.stderr)
                    if extra:
                        self.assertNotIn('TASK [Vendor execution',done.stdout)


if __name__=='__main__':unittest.main()
