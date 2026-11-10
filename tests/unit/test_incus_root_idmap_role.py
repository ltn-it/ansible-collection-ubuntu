"""Execute the unchanged Root ID-map task in private Root-owned EE fixtures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]


class RootOwnershipContract(unittest.TestCase):
    def test_role_keeps_root_ownership_and_default_enabled(self):
        defaults = yaml.safe_load((ROOT / 'roles/incus/defaults/main.yml').read_text())
        self.assertIs(defaults['incus_manage_root_idmap'], True)
        task = next(t for t in yaml.safe_load((ROOT / 'roles/incus/tasks/main.yml').read_text())
                    if t.get('name') == 'Reconcile Incus root subordinate ID allocation')
        self.assertEqual(('root', 'root', '0644'), tuple(task['ansible.builtin.lineinfile'][k]
                                                       for k in ('owner', 'group', 'mode')))


@unittest.skipUnless(os.geteuid() == 0, 'Root-owned ID-map task requires isolated Root EE')
class NativeRootTask(unittest.TestCase):
    def test_actual_task_check_apply_preserve_unrelated_and_idempotence(self):
        with tempfile.TemporaryDirectory(dir=os.environ['HOME']) as directory:
            base = Path(directory)
            paths = [base / 'subuid', base / 'subgid']
            for path in paths:
                path.write_text('unrelated:200000:65536\nroot:1:2\n')
                path.chmod(0o600)
            defaults = yaml.safe_load((ROOT / 'roles/incus/defaults/main.yml').read_text())
            defaults.update(incus_root_subuid_path=str(paths[0]), incus_root_subgid_path=str(paths[1]),
                            incus_services=[], ansible_python_interpreter=os.sys.executable)
            task = next(t for t in yaml.safe_load((ROOT / 'roles/incus/tasks/main.yml').read_text())
                        if t.get('name') == 'Reconcile Incus root subordinate ID allocation')
            task['register'] = 'idmap_actual'
            handlers = yaml.safe_load((ROOT / 'roles/incus/handlers/main.yml').read_text())
            report = base / 'report.json'
            book = base / 'play.yml'
            book.write_text(yaml.safe_dump([{'name': 'Private Root subordinate ID fixture', 'hosts': 'localhost',
                'connection': 'local', 'gather_facts': False, 'vars': defaults, 'handlers': handlers,
                'tasks': [task, {'name': 'Retain fixture changed result', 'ansible.builtin.copy': {
                    'content': '{{ idmap_actual | to_json }}', 'dest': str(report), 'mode': '0600'},
                    'check_mode': False, 'changed_when': False}]}]))
            env = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(base / 'local'), ANSIBLE_REMOTE_TEMP=str(base / 'remote'))
            before = [p.read_bytes() for p in paths]
            def invoke(check=False):
                done = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(book)] + (['--check'] if check else []),
                                      env=env, capture_output=True, text=True, timeout=45)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                return json.loads(report.read_text())['changed']
            self.assertTrue(invoke(check=True))
            self.assertEqual(before, [p.read_bytes() for p in paths])
            self.assertTrue(invoke())
            for path in paths:
                self.assertEqual(path.read_text(), 'unrelated:200000:65536\nroot:1000000:10000000\n')
                self.assertEqual((path.stat().st_uid, path.stat().st_gid, path.stat().st_mode & 0o777), (0, 0, 0o644))
            self.assertFalse(invoke())


if __name__ == '__main__':
    unittest.main()
