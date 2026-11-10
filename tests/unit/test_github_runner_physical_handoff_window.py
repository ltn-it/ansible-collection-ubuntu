"""Actual Ansible handoff-window guards; no native helper or host effects."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class PhysicalHandoffWindowTests(unittest.TestCase):
    def run_guards(self, window):
        play = yaml.safe_load((ROOT/'playbooks/github_runner_physical_handoff.yml').read_text())[0]
        tasks = [task for task in play['tasks'] if task['name'] in {
            'Require one selected host and a closed maintenance request',
            'Require the actual owner-approved maintenance window'}]
        self.assertEqual(2, len(tasks))
        values = {'github_runner_physical_handoff_target': 'fixturehost',
            'github_runner_physical_handoff_machine_id': 'a'*32,
            'github_runner_physical_handoff_helper_sha256': 'b'*64,
            'github_runner_physical_handoff_request': {
                'configuration': {'service_state': 'stopped', 'ephemeral': False},
                'native_fence': {'operations_window_reference': 'owner:fixture'},
                'registration_stage': '/inert/fixture'},
            'github_runner_physical_handoff_window': window,
            'github_runner_physical_handoff_now': {'stdout': '10000'}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root/'window.yml'
            path.write_text(yaml.safe_dump([{'name': 'Inert maintenance-window fixture',
                'hosts': 'fixturehost', 'connection': 'local', 'gather_facts': False,
                'vars': values, 'tasks': tasks}]))
            environment = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(root/'tmp'),
                               ANSIBLE_HOME=str(root/'home'))
            environment.pop('ANSIBLE_CONFIG', None)
            return subprocess.run(['ansible-playbook', '-i', 'fixturehost,', str(path)],
                cwd=root, env=environment, capture_output=True, text=True, timeout=60)

    def test_bounded_and_explicit_owner_approved_open_end_pass(self):
        for window in ({'reference': 'owner:fixture', 'starts_at': 9990, 'ends_at': 11000},
                       {'reference': 'owner:fixture', 'starts_at': 9990, 'ends_at': None,
                        'owner_approved_open_end': True}):
            with self.subTest(window=window):
                result = self.run_guards(window)
                self.assertEqual(0, result.returncode, result.stdout+result.stderr)

    def test_unapproved_null_end_or_invalid_window_denies(self):
        base = {'reference': 'owner:fixture', 'starts_at': 9990, 'ends_at': 11000}
        cases = ({'ends_at': None}, {'ends_at': None, 'owner_approved_open_end': False},
                 {'ends_at': None, 'owner_approved_open_end': 'true'},
                 {'ends_at': None, 'owner_approved_open_end': True, 'extra': 'not admitted'},
                 {'starts_at': 10001, 'ends_at': None, 'owner_approved_open_end': True},
                 {'ends_at': 10001}, {'ends_at': 18000}, {'reference': 'different'},
                 {'starts_at': True}, {'ends_at': True})
        for changed in cases:
            with self.subTest(case=changed):
                result = self.run_guards({**base, **changed})
                self.assertNotEqual(0, result.returncode, result.stdout+result.stderr)
                self.assertIn('failed=1', result.stdout)


if __name__ == '__main__':
    unittest.main()
