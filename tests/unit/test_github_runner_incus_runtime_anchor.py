"""Real Ansible rendering must preserve the publisher's exact anchor bytes.

No Root fixture, installation or native service is used. Only privileged directory
and sealed-file transports of the real installation probe are modelled.
"""
import ast
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / 'roles/github_runner/files'
sys.path.insert(0, str(FILES))
from incus_lease_issuer import ledger


class RuntimeAnchorBoundary(unittest.TestCase):
    def test_actual_template_bytes_match_publisher_and_existing_install_probe(self):
        value = {'schema': 1, 'config_path': '/var/lib/lightning-it/incus-runtime-generations/'
                 + 'a' * 32 + '/runtime.json', 'config_sha256': 'b' * 64}
        producer = ast.parse((FILES / 'incus_lease_issuer/generation_publisher.py').read_text())
        assignments = [node for node in ast.walk(producer) if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == 'anchor_raw' for target in node.targets)]
        self.assertEqual(len(assignments), 1)
        expression = ast.Expression(assignments[0].value)
        published = eval(compile(expression, 'actual-anchor-producer', 'eval'), {'ledger': ledger, 'anchor': value})
        template = ROOT / 'roles/github_runner/templates/runtime_v2/anchor.json.j2'
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output = directory / 'anchor.json'
            play = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                     'vars': {'ansible_remote_tmp': str(directory / 'remote'),
                              'ansible_python_interpreter': sys.executable,
                              'github_runner_runtime_v2_bootstrap': False,
                              'github_runner_runtime_v2_configuration_path': value['config_path'],
                              'github_runner_runtime_v2_configuration_sha256': value['config_sha256']},
                     'tasks': [{'name': 'Render the real installation anchor', 'ansible.builtin.template':
                                {'dest': str(output), 'mode': '0600', 'src': str(template)}},
                               {'name': 'Compute the real installation expected hash', 'ansible.builtin.copy':
                                {'dest': str(directory / 'expected.sha256'), 'mode': '0600', 'content':
                                 "{{ lookup('ansible.builtin.template', '" + str(template) + "') | hash('sha256') }}"}}]}]
            playbook = directory / 'render.json'
            playbook.write_text(json.dumps(play))
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(playbook)],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rendered = output.read_bytes()
            self.assertEqual((directory / 'expected.sha256').read_text(), hashlib.sha256(published).hexdigest())
        self.assertEqual(rendered, published)
        self.assertNotEqual(rendered, (json.dumps(value, sort_keys=True, indent=4) + '\n').encode())
        probe = runpy.run_path(str(ROOT / 'roles/github_runner/templates/runtime_v2/install_probe.py.j2'))
        checked = []

        def sealed(path, expected, *, private=False):
            self.assertEqual(path, '/etc/lit/incus-lease-issuer/runtime-v2-anchor.json')
            self.assertTrue(private)
            self.assertEqual(hashlib.sha256(published).hexdigest(), expected)
            checked.append(path)
            return published

        namespace = probe['installed_files'].__globals__
        with mock.patch.dict(namespace, {'directory': mock.Mock(return_value=None), 'sealed': sealed}):
            probe['installed_files']({}, {},
                {'/etc/lit/incus-lease-issuer/runtime-v2-anchor.json': hashlib.sha256(rendered).hexdigest()}, True)
        self.assertEqual(len(checked), 1)


if __name__ == '__main__':
    unittest.main()
