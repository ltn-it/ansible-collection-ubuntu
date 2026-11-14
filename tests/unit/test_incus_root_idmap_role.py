"""Execute the real Root ID-map tasks in private Root-owned EE fixtures."""
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
        self.assertEqual(defaults['incus_root_idmap_restart_service'], 'incus.service')
        task = next(t for t in yaml.safe_load((ROOT / 'roles/incus/tasks/root_idmap.yml').read_text())
                    if 'ansible.builtin.copy' in t)
        self.assertEqual(('root', 'root', '0644'), tuple(task['ansible.builtin.copy'][k]
                                                       for k in ('owner', 'group', 'mode')))
        handler = yaml.safe_load((ROOT / 'roles/incus/handlers/main.yml').read_text())[0]
        self.assertEqual(handler['ansible.builtin.systemd_service']['name'],
                         '{{ incus_root_idmap_restart_service }}')
        self.assertNotIn('loop', handler)


@unittest.skipUnless(os.geteuid() == 0, 'Root-owned ID-map task requires isolated Root EE')
class NativeRootTask(unittest.TestCase):
    def test_actual_task_check_apply_preserve_unrelated_and_idempotence(self):
        with tempfile.TemporaryDirectory(dir=os.environ['HOME']) as directory:
            base = Path(directory)
            paths = [base / 'subuid', base / 'subgid']
            for path in paths:
                path.write_text('# existing declarations\nroot:1000000:65536\n'
                                'unrelated:200000:65536\nroot:1065536:999934464\n'
                                'root-extra:300000:65536\n')
                path.chmod(0o600)
            defaults = yaml.safe_load((ROOT / 'roles/incus/defaults/main.yml').read_text())
            defaults.update(incus_root_subuid_path=str(paths[0]), incus_root_subgid_path=str(paths[1]),
                            incus_services=[], ansible_python_interpreter=os.sys.executable)
            task = next(t for t in yaml.safe_load((ROOT / 'roles/incus/tasks/main.yml').read_text())
                        if t.get('name') == 'Reconcile Incus root subordinate ID allocation')
            task['ansible.builtin.include_tasks'] = str(ROOT / 'roles/incus/tasks/root_idmap.yml')
            handlers = yaml.safe_load((ROOT / 'roles/incus/handlers/main.yml').read_text())
            report = base / 'report.json'
            book = base / 'play.yml'
            book.write_text(yaml.safe_dump([{'name': 'Private Root subordinate ID fixture', 'hosts': 'localhost',
                'connection': 'local', 'gather_facts': False, 'vars': defaults, 'handlers': handlers,
                'tasks': [task, {'name': 'Retain fixture changed result', 'ansible.builtin.copy': {
                    'content': '{{ incus_idmap_write | to_json }}', 'dest': str(report), 'mode': '0600'},
                    'check_mode': False, 'changed_when': False}]}]))
            env = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(base / 'local'), ANSIBLE_REMOTE_TEMP=str(base / 'remote'))
            before = [p.read_bytes() for p in paths]
            def invoke(check=False):
                done = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(book)] + (['--check'] if check else []),
                                      env=env, capture_output=True, text=True, timeout=45)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                result = json.loads(report.read_text())
                self.assertEqual(result['changed'], any(row['changed'] for row in result['results']))
                return result['changed']
            self.assertTrue(invoke(check=True))
            self.assertEqual(before, [p.read_bytes() for p in paths])
            self.assertTrue(invoke())
            for path in paths:
                self.assertEqual(path.read_text(), '# existing declarations\nunrelated:200000:65536\n'
                                 'root-extra:300000:65536\nroot:1000000:10000000\n')
                self.assertEqual((path.stat().st_uid, path.stat().st_gid, path.stat().st_mode & 0o777), (0, 0, 0o644))
            self.assertFalse(invoke())

            # A change to subuid must be visible even if subgid is already correct.
            paths[0].write_text('unrelated:200000:65536\nroot:1:2\nroot:3:4\n')
            self.assertTrue(invoke())
            rows = json.loads(report.read_text())['results']
            self.assertEqual([row['changed'] for row in rows], [True, False])
            self.assertFalse(invoke())

            # A linked second input must prevent writing the otherwise changing first input.
            outside_second = base / 'outside-second'
            outside_second.write_text('foreign-second-marker\n')
            for link in ('symbolic', 'hard'):
                paths[0].write_text('root:1:2\nroot:3:4\n')
                paths[1].unlink()
                if link == 'symbolic':
                    paths[1].symlink_to(outside_second)
                else:
                    os.link(outside_second, paths[1])
                unchanged_uid = paths[0].read_bytes()
                done = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(book)],
                                      env=env, capture_output=True, text=True, timeout=45)
                self.assertNotEqual(done.returncode, 0)
                self.assertEqual(paths[0].read_bytes(), unchanged_uid)
                self.assertEqual(outside_second.read_text(), 'foreign-second-marker\n')
            paths[1].unlink()
            paths[1].write_text('root:1000000:10000000\n')

            # A foreign final line without a newline remains a separate record.
            for path in paths:
                path.write_text('unrelated:200000:65536')
            self.assertTrue(invoke(check=True))
            self.assertEqual([p.read_text() for p in paths], ['unrelated:200000:65536'] * 2)
            self.assertTrue(invoke())
            self.assertEqual([p.read_text() for p in paths],
                             ['unrelated:200000:65536\nroot:1000000:10000000\n'] * 2)
            self.assertFalse(invoke())

            # Reject linked inputs before replacing either file or touching the target.
            outside = base / 'outside'
            outside.write_text('foreign-marker\n')
            for link in ('symbolic', 'hard'):
                paths[0].unlink()
                if link == 'symbolic':
                    paths[0].symlink_to(outside)
                else:
                    os.link(outside, paths[0])
                unchanged_gid = paths[1].read_bytes()
                done = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(book)],
                                      env=env, capture_output=True, text=True, timeout=45)
                self.assertNotEqual(done.returncode, 0)
                self.assertIn('Subordinate ID files must be regular files with one link.', done.stdout)
                self.assertEqual(outside.read_text(), 'foreign-marker\n')
                self.assertEqual(paths[1].read_bytes(), unchanged_gid)

            # Missing files support both a side-effect-free check and real creation.
            for path in paths:
                path.unlink()
            self.assertTrue(invoke(check=True))
            self.assertTrue(all(not p.exists() for p in paths))
            self.assertTrue(invoke())
            self.assertEqual([p.read_text() for p in paths], ['root:1000000:10000000\n'] * 2)
            self.assertFalse(invoke())


if __name__ == '__main__':
    unittest.main()
