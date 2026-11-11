"""Real Ansible opt-in/pre-effect guards; live systemd installation tested separately."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULES = ['ephemeral_worker_admission.py', 'ephemeral_worker_lease.py', 'ephemeral_worker_incus.py',
           'ephemeral_worker_watchdog.py', 'ephemeral_worker_alarm.py', 'ephemeral_worker_local_mail.py',
           'ephemeral_worker_local_mail_entry.py']


class LocalMailInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        collection = self.directory / 'collections/ansible_collections/lit/ubuntu'
        collection.parent.mkdir(parents=True); collection.symlink_to(ROOT, target_is_directory=True)
        self.environment = dict(os.environ, ANSIBLE_COLLECTIONS_PATH=str(self.directory/'collections'),
            ANSIBLE_LOCAL_TEMP=str(self.directory/'ansible-local'),
            ANSIBLE_REMOTE_TEMP=str(self.directory/'ansible-remote'), ANSIBLE_NOCOLOR='1')

    def run_role(self, **overrides):
        variables = {'ansible_python_interpreter': sys.executable,
            'github_runner_ephemeral_watchdog_machine_id': '0'*32,
            'github_runner_ephemeral_watchdog_boot_id': '00000000-0000-0000-0000-000000000000',
            'github_runner_ephemeral_local_mail_module_sha256': {
                n: hashlib.sha256((ROOT/'roles/github_runner/files'/n).read_bytes()).hexdigest() for n in MODULES},
            **overrides}
        play = [{'name': 'Local mail installer boundary', 'hosts': 'all', 'gather_facts': False,
            'vars': variables, 'tasks': [{'name': 'Load exact local mail entry', 'ansible.builtin.include_role': {
                'name': 'lit.ubuntu.github_runner', 'tasks_from': 'ephemeral_worker_local_mail'}}]}]
        book = self.directory/'play.yml'; book.write_text(yaml.safe_dump(play))
        return subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(book)],
            cwd=self.directory, env=self.environment, capture_output=True, text=True, timeout=90)

    def before_effects(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertNotIn('TASK [lit.ubuntu.github_runner : Create private local mail directories]', result.stdout)
        self.assertNotIn('TASK [lit.ubuntu.github_runner : Install exact local mail modules]', result.stdout)

    def test_disabled_default_does_not_install_or_activate(self):
        result = self.run_role()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('changed=0', result.stdout)
        activation = result.stdout.split('Activate explicitly selected local mail timer]', 1)[1]
        self.assertIn('skipping: [localhost]', activation)
        self.assertNotIn('changed: [localhost]', result.stdout)

    def test_activation_without_install_is_rejected_before_effects(self):
        result = self.run_role(github_runner_ephemeral_local_mail_activate=True)
        self.before_effects(result)
        self.assertIn('Local mail installation and activation require explicit boolean inputs', result.stdout)

    def test_malformed_module_inventory_is_rejected_before_target_preflight(self):
        result = self.run_role(github_runner_ephemeral_local_mail_install=True,
            github_runner_ephemeral_local_mail_module_sha256={'other.py': 'a'*64})
        self.before_effects(result)
        self.assertNotIn('TASK [lit.ubuntu.github_runner : Inspect Root target', result.stdout)

    def test_wrong_package_bytes_are_rejected_before_target_effects(self):
        pins = {n: hashlib.sha256((ROOT/'roles/github_runner/files'/n).read_bytes()).hexdigest() for n in MODULES}
        pins[MODULES[0]] = 'a'*64
        result = self.run_role(github_runner_ephemeral_local_mail_install=True,
            github_runner_ephemeral_local_mail_module_sha256=pins)
        self.before_effects(result)
        self.assertIn('Local mail module bytes differ', result.stdout)

    def test_live_target_preflight_refuses_invalid_target_without_installing(self):
        result = self.run_role(github_runner_ephemeral_local_mail_install=True)
        self.before_effects(result)
        failure = next(line.split('=>', 1)[1].strip() for line in result.stdout.splitlines()
                       if line.startswith('fatal: ') and 'FAILED!' in line)
        native = json.loads(failure)
        self.assertEqual(json.loads(native['stdout'])['state'], 'LOCAL_MAIL_INSTALL_HELD')

    def test_guard_compiles_and_returns_actual_closed_json_for_invalid_invocation(self):
        guard = ROOT/'roles/github_runner/files/ephemeral_worker_local_mail_install_guard.py'
        result = subprocess.run([sys.executable, '-I', '-B', str(guard)],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), {'state': 'LOCAL_MAIL_INSTALL_HELD', 'error_type': 'ValueError'})
        self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main()
