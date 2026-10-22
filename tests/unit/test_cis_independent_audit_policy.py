"""Exercise the real Ansible audit-policy binding that replaces the old template."""
import base64
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml


TASKS = Path(__file__).resolve().parents[2] / 'roles/cis_ubuntu24/tasks/independent_audit.yml'


@unittest.skipUnless(shutil.which('ansible-playbook'), 'requires the governed Ansible EE')
class IndependentAuditPolicyTests(unittest.TestCase):
    def exercise(self, efi):
        schema = {'ubtu24cis_temp_exec_location': '/var', 'ubtu24cis_ptrace_value': 1,
                  'ubtu24cis_rule_7_1_12': True, 'ubtu24cis_pass_max_days': 99999,
                  'ubtu24cis_sshd_client_alive_interval': 300}
        binding = next(task for task in yaml.safe_load(TASKS.read_text())
                       if task['name'] == 'Bind the pinned audit schema to the complete effective policy')
        policy = {'cis_ubuntu24_independent_audit_schema': {
                      'content': base64.b64encode(yaml.safe_dump(schema).encode()).decode()},
                  'ubtu24cis_rule_7_1_12': False, 'ubtu24cis_pass_max_days': 365,
                  'ubtu24cis_sshd_client_alive_interval': 600,
                  'ubtu24cis_audit_back_log_limit': 16384, 'ubtu24cis_sudo_logfile': '/var/log/reviewed.log',
                  'ubtu24cis_level_1': True, 'ubtu24cis_level_2': False,
                  'benchmark_version': 'v1.0.0', 'audit_cmd_timeout': 120000,
                  'audit_run_heavy_tests': True, 'unrelated_secret': 'never-copy-this',
                  'ansible_facts': {'mounts': [{'mount': '/boot/efi'}] if efi else [{'mount': '/'}]}}
        assertions = [
            'cis_ubuntu24_independent_audit_vars.ubtu24cis_rule_7_1_12 == false',
            'cis_ubuntu24_independent_audit_vars.ubtu24cis_pass_max_days == 365',
            'cis_ubuntu24_independent_audit_vars.ubtu24cis_sshd_client_alive_interval == 600',
            'cis_ubuntu24_independent_audit_vars.ubtu24cis_auditd_back_log_limit == 16384',
            "cis_ubuntu24_independent_audit_vars.ubtu24cis_varlog_location == '/var/log/reviewed.log'",
            "cis_ubuntu24_independent_audit_vars.ubtu24cis_temp_exec_location == '/var'",
            'cis_ubuntu24_independent_audit_vars.ubtu24cis_ptrace_value == 1',
            'cis_ubuntu24_independent_audit_vars.ubtu24cis_level_1 == true',
            'cis_ubuntu24_independent_audit_vars.ubtu24cis_level_2 == false',
            'cis_ubuntu24_independent_audit_vars.run_heavy_tests == true',
            "'unrelated_secret' not in cis_ubuntu24_independent_audit_vars",
            'cis_ubuntu24_independent_audit_vars.ubtu24_legacy_boot == ' + ('false' if efi else 'true')]
        play = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False, 'vars': policy,
                 'tasks': [binding, {'name': 'Assert effective audit behavior',
                                     'ansible.builtin.assert': {'that': assertions}}]}]
        with tempfile.TemporaryDirectory(prefix='cis-audit-policy-', dir=os.environ.get('HOME')) as root:
            path = Path(root) / 'play.yml'
            path.write_text(yaml.safe_dump(play, sort_keys=False))
            config = Path(root) / 'ansible.cfg'
            config.write_text('[defaults]\n')
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(path)],
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    env={**os.environ, 'ANSIBLE_CONFIG': str(config),
                                         'ANSIBLE_LOCAL_TEMP': str(Path(root) / 'ansible-tmp')}, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout)

    def test_efi_and_effective_flat_policy_override_pinned_defaults(self):
        self.exercise(True)

    def test_legacy_boot_and_effective_flat_policy_override_pinned_defaults(self):
        self.exercise(False)
