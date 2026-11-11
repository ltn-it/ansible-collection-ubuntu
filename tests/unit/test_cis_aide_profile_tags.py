"""Align wrapper scheduling with the pinned vendor's native Level 1 lifecycle."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class AideProfileTagTests(unittest.TestCase):
    def test_scheduler_cannot_run_when_native_initialization_is_filtered_out(self):
        # Vendor3a2f05b9... tasks/section_6/cis_6.3.x.yml: initialization6.3.1
        # and scheduling6.3.2 have only these profile tags; no ancestor adds L2.
        level1 = ['level1-server', 'level1-workstation']
        for profile in [*level1, 'level2-server', 'level2-workstation']:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory(dir=os.environ['HOME']) as directory:
                root = Path(directory)
                role = root / 'roles/cis_ubuntu24'
                shutil.copytree(ROOT / 'roles/cis_ubuntu24', role)
                main = yaml.safe_load((role / 'tasks/main.yml').read_text())
                selected = [task for task in main if task.get('name') == 'Normalize the upstream AIDE scheduler integration']
                (role / 'tasks/main.yml').write_text(yaml.safe_dump(selected))
                scheduler, initializer = root / 'scheduler', root / 'initializer'
                # Only the service action is replaced by a private marker. The
                # actual wrapper import and Ansible tag propagation execute.
                (role / 'tasks/aide_scheduler.yml').write_text(yaml.safe_dump([{
                    'ansible.builtin.copy': {'dest': str(scheduler), 'content': 'selected', 'mode': '0600'}}]))
                book = root / 'case.yml'
                book.write_text(yaml.safe_dump([{'hosts': 'all', 'gather_facts': False,
                    'vars': {'cis_ubuntu24_profile_tag': profile, 'ubtu24cis_config_aide': True,
                             'ubtu24cis_rule_6_3_2': True}, 'roles': ['cis_ubuntu24'],
                    'tasks': [{'name': 'Witness pinned vendor native initialization selection',
                        'ansible.builtin.copy': {'dest': str(initializer), 'content': 'selected', 'mode': '0600'},
                        'tags': level1}]}]))
                config = root / 'ansible.cfg'
                config.write_text('[defaults]\nroles_path=' + str(root / 'roles') + '\n')
                env = {**os.environ, 'ANSIBLE_CONFIG': str(config), 'ANSIBLE_LOCAL_TEMP': str(root / 'local'),
                       'ANSIBLE_REMOTE_TEMP': str(root / 'remote')}
                env.pop('ANSIBLE_VAULT_PASSWORD_FILE', None)
                done = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(book),
                                       '--tags', profile], env=env, capture_output=True, text=True, timeout=90)
                self.assertEqual(0, done.returncode, done.stdout + done.stderr)
                self.assertEqual(profile in level1, initializer.exists())
                self.assertEqual(initializer.exists(), scheduler.exists())
