"""Execute the production Ansible profile guards with inert package fixtures."""
from pathlib import Path
import base64
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class PackagedPodmanProfileGuards(unittest.TestCase):
    def run_guard(self, content, records=None, *, mode='0644', regular=True):
        play = yaml.safe_load((ROOT/'playbooks/github_runner_runtime_host.yml').read_text())[0]
        block = next(task['block'] for task in play['pre_tasks']
                     if task['name'] == 'Restore only the package-authenticated Podman attachment profile')
        selected = [task for task in block if task['name'] in {
            'Require a private administrative package-profile boundary',
            'Derive only the missing package attachment flag',
            'Refuse any result other than the exact installed package profile'}]
        self.assertEqual(3, len(selected))
        vendor = 'profile podman /usr/bin/podman flags=(unconfined) {\n  userns,\n}\n'
        digest = hashlib.md5(vendor.encode()).hexdigest()
        fixtures = {'github_runner_runtime_host_profile_stat': {'stat': {
                        'isreg': regular, 'uid': 0, 'mode': mode}},
                    'github_runner_runtime_host_profile_package': {'stdout': records if records is not None
                        else ' /etc/apparmor.d/podman '+digest},
                    'github_runner_runtime_host_profile_source': {'content':
                        base64.b64encode(content.encode()).decode()}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root/'guards.yml'
            path.write_text(yaml.safe_dump([{'name': 'Inert package-profile guard fixture',
                'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                'vars': fixtures, 'tasks': selected}]))
            environment = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(root/'ansible-tmp'),
                               ANSIBLE_HOME=str(root/'ansible-home'))
            environment.pop('ANSIBLE_CONFIG', None)
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(path)],
                cwd=root, env=environment, capture_output=True, text=True, timeout=60)
            return result

    def test_original_and_already_restored_exact_package_bytes_pass(self):
        for header in ('profile podman /usr/bin/podman {',
                       'profile podman /usr/bin/podman flags=(unconfined) {'):
            with self.subTest(header=header):
                result = self.run_guard(header+'\n  userns,\n}\n')
                self.assertEqual(0, result.returncode, result.stdout+result.stderr)

    def test_unknown_policy_or_untrusted_file_or_package_record_denies(self):
        original = 'profile podman /usr/bin/podman {\n  userns,\n}\n'
        for changed in ({'content': original+'# foreign edit\n'},
                        {'content': original.replace('userns,', 'file,')},
                        {'records': ''}, {'records': ' /etc/apparmor.d/podman '+'0'*32},
                        {'mode': '0666'}, {'regular': False}):
            with self.subTest(case=changed):
                result = self.run_guard(**{'content': original, **changed})
                self.assertNotEqual(0, result.returncode, result.stdout+result.stderr)
                self.assertIn('failed=1', result.stdout)


if __name__ == '__main__':
    unittest.main()
