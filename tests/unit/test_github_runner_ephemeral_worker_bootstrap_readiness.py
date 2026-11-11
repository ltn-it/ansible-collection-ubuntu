"""Actual private guest-tree fixtures; not a live VM or SSH-daemon proof."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'roles/github_runner/files'))
import ephemeral_worker_bootstrap_readiness as readiness

UUID = '12345678-1234-4234-8234-123456789abc'
POLICY = {'authorizedkeysfile': '.ssh/authorized_keys .ssh/authorized_keys2',
          'authorizedkeyscommand': 'none', 'trustedusercakeys': 'none',
          'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no',
          'hostbasedauthentication': 'no', 'gssapiauthentication': 'no', 'kerberosauthentication': 'no'}


class BoundaryTests(unittest.TestCase):
    def test_cli_invalid_input_closed_without_credentials(self):
        import subprocess
        result = subprocess.run([sys.executable, '-I', '-B',
            str(ROOT / 'roles/github_runner/files/ephemeral_worker_bootstrap_readiness.py')],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['state'], 'BOOTSTRAP_NOT_READY')
        self.assertEqual(result.stderr, '')


@unittest.skipUnless(os.geteuid() == 0, 'Root guest file identities')
class GuestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for path, value in {
            '/sys/devices/virtual/dmi/id/product_uuid': UUID + '\n',
            '/etc/machine-id': '1' * 32 + '\n',
            '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash\n',
            '/etc/shadow': 'root:!:1:0:99999:7:::\nubuntu:*:1:0:99999:7:::\n',
        }.items():
            actual = self.root / path.lstrip('/'); actual.parent.mkdir(parents=True, exist_ok=True)
            actual.write_text(value); actual.chmod(0o600)
        self.policies = {name: dict(POLICY) for name in ['root', 'ubuntu']}

    def inspect(self, **overrides):
        return readiness.inspect(**{'expected_uuid': UUID, 'runner_root': '/opt/actions-runner',
            'root': self.root, 'cloud_ready': True, 'ssh_policies': self.policies, **overrides})

    def test_identity_reattest_accepts_existing_runner_without_freshness_bypass(self):
        (self.root / 'opt/actions-runner').mkdir(parents=True)
        result = readiness.identity(UUID, root=self.root)
        self.assertEqual(result, {'guest_uuid': UUID, 'machine_id': '1' * 32})
        with self.assertRaisesRegex(readiness.NotReady, 'bootstrap-existing-runner-root'):
            self.inspect()
        with self.assertRaisesRegex(readiness.NotReady, 'bootstrap-guest-uuid'):
            readiness.identity('22345678-1234-4234-8234-123456789abc', root=self.root)

    def test_fresh_tree_readonly_and_not_registration_authority(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        result = self.inspect()
        self.assertFalse(result['registration_granted'])
        self.assertFalse(result['final_image_qualified'])
        self.assertEqual(result['interactive_accounts_checked'], 2)
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_wrong_uuid_unfinished_cloud_or_machine_id_rejected(self):
        for values in [{'expected_uuid': '22345678-1234-4234-8234-123456789abc'}, {'cloud_ready': False}]:
            with self.subTest(values=values), self.assertRaises(readiness.NotReady): self.inspect(**values)
        (self.root / 'etc/machine-id').write_text('0' * 32)
        with self.assertRaises(readiness.NotReady): self.inspect()

    def test_nonempty_authorized_key_rejected_without_value_in_error(self):
        path = self.root / 'root/.ssh/authorized_keys'; path.parent.mkdir(parents=True)
        path.write_text('synthetic-key-marker-not-a-real-key')
        with self.assertRaises(readiness.NotReady) as captured: self.inspect()
        self.assertNotIn('synthetic-key-marker', str(captured.exception))

    def test_unlocked_or_missing_shadow_entry_rejected(self):
        path = self.root / 'etc/shadow'
        for value in ['root:synthetic-unlocked:1:0:99999:7:::\nubuntu:*:1:0:99999:7:::\n',
                      'root:!:1:0:99999:7:::\n']:
            path.write_text(value)
            with self.assertRaises(readiness.NotReady): self.inspect()

    def test_external_ssh_authority_or_password_login_rejected(self):
        for field, value in [('authorizedkeyscommand', '/external'), ('trustedusercakeys', '/ca.pub'),
                             ('passwordauthentication', 'yes'), ('authorizedkeysfile', '/shared/keys')]:
            self.policies['ubuntu'] = {**POLICY, field: value}
            with self.subTest(field=field), self.assertRaises(readiness.NotReady): self.inspect()

    def test_existing_runner_even_empty_is_not_adopted(self):
        path = self.root / 'opt/actions-runner'; path.mkdir(parents=True)
        with self.assertRaisesRegex(readiness.NotReady, 'existing-runner'): self.inspect()

    def test_trusted_absent_server_facts_do_not_require_installing_ssh(self):
        self.policies = {name: {'server': 'absent'} for name in ['root', 'ubuntu']}
        result = self.inspect()
        self.assertFalse(result['openssh_server_present'])
        path = self.root / 'root/.ssh/authorized_keys'; path.parent.mkdir(parents=True)
        path.write_text('synthetic-stale-admin-context')
        with self.assertRaises(readiness.NotReady): self.inspect()

    def test_home_links_and_public_system_files_rejected(self):
        path = self.root / 'home/ubuntu/.ssh'; path.parent.mkdir(parents=True)
        path.symlink_to(self.root / 'root')
        with self.assertRaisesRegex(readiness.NotReady, 'linked-path'): self.inspect()
        path.unlink(); (self.root / 'etc/passwd').chmod(0o666)
        with self.assertRaisesRegex(readiness.NotReady, 'system-file'): self.inspect()

    def test_policy_coverage_and_parent_escape_fail_closed(self):
        self.policies.pop('ubuntu')
        with self.assertRaisesRegex(readiness.NotReady, 'coverage'): self.inspect()
        self.policies['ubuntu'] = dict(POLICY)
        with self.assertRaises(readiness.NotReady): self.inspect(runner_root='/opt/../root')


class RoleBoundaryTests(unittest.TestCase):
    def test_actual_role_denies_bound_guest_before_token_or_registration_effects(self):
        import subprocess
        import yaml
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            collection = path / 'collections/ansible_collections/lit/ubuntu'
            collection.parent.mkdir(parents=True); collection.symlink_to(ROOT, target_is_directory=True)
            play = [{'hosts': 'all', 'gather_facts': False,
                'vars': {'ansible_python_interpreter': sys.executable,
                    'github_runner_instance': {'name': 'synthetic-worker', 'dir': str(path / 'absent-worker'),
                        'manifest_path': str(path / 'absent-manifest'), 'expected_guest_uuid': UUID,
                        'ephemeral': True}},
                'tasks': [{'ansible.builtin.include_role': {'name': 'lit.ubuntu.github_runner',
                                                          'tasks_from': 'protected_instance'}}]}]
            book = path / 'play.yml'; book.write_text(yaml.safe_dump(play))
            environment = dict(os.environ, ANSIBLE_COLLECTIONS_PATH=str(path / 'collections'),
                ANSIBLE_LOCAL_TEMP=str(path / 'local'), ANSIBLE_REMOTE_TEMP=str(path / 'remote'))
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(book)],
                capture_output=True, text=True, env=environment, cwd=path, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Reattest selected worker VM identity before protected effects', result.stdout)
            self.assertIn('BOOTSTRAP_NOT_READY', result.stdout)
            self.assertNotIn('TASK [lit.ubuntu.github_runner : Require fresh registration credential', result.stdout)
            self.assertNotIn('TASK [lit.ubuntu.github_runner : Create dedicated protected runner', result.stdout)
            self.assertFalse((path / 'absent-worker').exists())
