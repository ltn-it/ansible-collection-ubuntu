"""Execute the real role task flow against isolated package/OS fixtures."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class LocalMailCheckTests(unittest.TestCase):
    def test_initialization_check_preserves_smtp_then_apply_verifies_and_seals(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            role = base/'roles/local_mail'
            shutil.copytree(ROOT/'roles/local_mail', role)
            config = base/'postfix'
            config.mkdir()
            for name in ('main.cf', 'master.cf'):
                (config/name).write_text('default_transport = smtp\n')
            guard_marker, transport_marker = base/'guard-ran', base/'transport-ran'
            guard_script = base/'guard.py'
            guard_script.write_text('from pathlib import Path\nPath('+repr(str(guard_marker))+').write_text("guard ran")\n')
            transport = base/'postconf.py'
            transport.write_text('from pathlib import Path\np=Path('+repr(str(config/'main.cf'))+')\nvalues=dict((key.strip(),value.strip()) for line in p.read_text().splitlines() if "=" in line and not line.startswith("#") for key,value in [line.split("=",1)])\nPath('+repr(str(transport_marker))+').write_text("read actual rendered config")\nfor key in ("inet_interfaces","inet_protocols","default_transport","relay_transport","forward_path","alias_maps"): print(values[key])\n')
            tasks = yaml.safe_load((role/'tasks/configure.yml').read_text())
            for task in tasks:
                name = task['name']
                if name == 'Read the actual operating system':
                    task.pop('ansible.builtin.setup')
                    task['ansible.builtin.set_fact'] = {'ansible_facts': {'distribution': 'Ubuntu', 'distribution_major_version': '24'}}
                if name == 'Guard owned configuration or explicit empty inactive initialization':
                    task['ansible.builtin.command']['argv'] = [sys.executable, str(guard_script)]
                if name == 'Verify the actually installed package version':
                    task['ansible.builtin.command']['argv'] = ['/bin/echo', '1.2-fixture']
                if name == 'Read actual fixed transport settings':
                    task['ansible.builtin.command']['argv'] = [sys.executable, str(transport)]
                for module in ('ansible.builtin.template', 'ansible.builtin.file', 'ansible.builtin.copy', 'ansible.builtin.stat'):
                    if module not in task:
                        continue
                    for key in ('path', 'dest'):
                        if key in task[module]:
                            task[module][key] = task[module][key].replace('/etc/postfix', str(config)).replace('/var/lib/lit-local-mail', str(base/'receipt'))
                    for key, value in [('owner', str(os.getuid())), ('group', str(os.getgid()))]:
                        if key in task[module]:
                            task[module][key] = value
            (role/'tasks/configure.yml').write_text(yaml.safe_dump(tasks, sort_keys=False))
            play = [{'hosts': 'all', 'gather_facts': False, 'vars': {'ansible_python_interpreter': sys.executable,
                     'local_mail_enabled': True, 'local_mail_initialize': True, 'local_mail_install_packages': False,
                     'local_mail_manage_service': False, 'local_mail_package_version': '1.2-fixture'},
                     'tasks': [{'ansible.builtin.include_role': {'name': 'local_mail'}}]}]
            book = base/'play.yml'
            book.write_text(yaml.safe_dump(play))
            environment = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(base/'local'), ANSIBLE_REMOTE_TEMP=str(base/'remote'), ANSIBLE_NOCOLOR='1')
            command = ['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(book)]
            checked = subprocess.run(command+['--check'], cwd=base, env=environment, capture_output=True, text=True, timeout=90, check=False)
            self.assertEqual(checked.returncode, 0, checked.stdout+checked.stderr)
            self.assertTrue(guard_marker.exists())
            self.assertFalse(transport_marker.exists())
            self.assertFalse((base/'receipt').exists())
            self.assertEqual((config/'main.cf').read_text(), 'default_transport = smtp\n')
            applied = subprocess.run(command, cwd=base, env=environment, capture_output=True, text=True, timeout=90, check=False)
            self.assertEqual(applied.returncode, 0, applied.stdout+applied.stderr)
            self.assertTrue(transport_marker.exists())
            sealed = json.loads((base/'receipt/ownership.json').read_text())
            self.assertEqual(sealed['schema'], 1)
