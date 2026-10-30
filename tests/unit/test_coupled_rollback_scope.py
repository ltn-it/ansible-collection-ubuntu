"""Recovered rollback inputs must not overwrite a later play's policy."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.geteuid() == 0, "Requires isolated root-owned verifier metadata")
class RootRollbackScopeTests(unittest.TestCase):
    def test_rollback_bindings_authorize_only_the_invocation_then_new_policy_is_fresh(self):
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
            root = Path(directory)
            role = root / "roles/host_firewall"
            shutil.copytree(ROOT / "roles/host_firewall", role)
            defaults = yaml.safe_load((role / "defaults/main.yml").read_text())
            context = {"schema": "lit.host_firewall.active-context/v1", "target": "localhost",
                       "owned_tables": [["inet", "lit_host"], ["bridge", "lit_container"]],
                       "candidate_sha256": "a" * 64, "approved_readback_sha256": "b" * 64,
                       "policy_fingerprint": "c" * 64, "change_id": "original-change", "mode": "bootstrap",
                       "egress_policy_sha256": "e" * 64, "egress_status": "original"}
            program = root / "describe.py"
            program.write_text("import json\nprint(json.dumps(" + repr(context) + "))\n")
            inputs = {**defaults, "host_firewall_action": "rollback", "host_firewall_expected_inventory_hostname": "localhost",
                      "host_firewall_table_family": "inet", "host_firewall_table_name": "lit_host",
                      "host_firewall_container_ssh_guard_table_name": "lit_container", "host_firewall_container_ssh_guard_managed": True,
                      "host_firewall_transaction_program_argv": [sys.executable, str(program)],
                      "host_firewall_authorization_mode": "controller_confirmation",
                      "host_firewall_confirmation": "ROLLBACK-HOST-FIREWALL:localhost:" + "a" * 64,
                      # Frontend metadata/binding checks only. No verifier,
                      # transaction service or nft mutation is executed here.
                      "host_firewall_authorization_verifier_binary": "/usr/bin/true"}
            assertions = {"ansible.builtin.assert": {"that": [
                "host_firewall_transaction_request.candidate_sha256 == 'a' * 64",
                "host_firewall_transaction_request.policy_fingerprint == 'c' * 64",
                "host_firewall_authorization_contract.change_id == 'original-change'",
                "host_firewall_mode == 'bootstrap'"]}}
            context_task = {"ansible.builtin.include_role": {"name": "host_firewall", "tasks_from": "coupled_rollback_context"}}
            execute = role / "tasks/transaction_execute.yml"
            if execute.exists():
                # Keep the actual scoped request/confirmation/authorization
                # tasks; stop before all persistence and transaction actions.
                selected = [task for task in yaml.safe_load(execute.read_text()) if task.get("name") in (
                    "Build request from invocation-scoped coupled rollback bindings",
                    "Build candidate-bound controller confirmation", "Validate productive authorization boundary")]
                execute.write_text(yaml.safe_dump(selected + [assertions, {"ansible.builtin.meta": "end_host"}]))
                main = yaml.safe_load((role / "tasks/main.yml").read_text())
                tasks = [context_task] + [task for task in main if task.get("name") in (
                    "Freeze the selected transaction bindings for this invocation",
                    "Run the transaction with invocation-scoped bindings")]
                self.assertEqual(len(tasks), 3)
            else:
                tasks = [context_task,
                         {"ansible.builtin.include_role": {"name": "host_firewall", "tasks_from": "controller_confirmation"}},
                         {"ansible.builtin.include_role": {"name": "host_firewall", "tasks_from": "authorization"}},
                         assertions, {"ansible.builtin.meta": "end_host"}]
            marker = root / "new-policy-accepted"
            new_inputs = {**defaults, "host_firewall_action": "plan", "host_firewall_mode": "hardened",
                          "host_firewall_change_id": "next-change", "host_firewall_candidate_sha256": "d" * 64,
                          "host_firewall_approved_readback_sha256": "f" * 64,
                          "host_firewall_policy_material_effective": {"generation": 2},
                          "host_firewall_egress_policy": {"status": "accepted", "generation": 2}}
            book = root / "case.yml"
            book.write_text(yaml.safe_dump([
                {"hosts": "all", "gather_facts": False, "vars": inputs, "tasks": tasks},
                {"hosts": "all", "gather_facts": False, "vars": new_inputs, "tasks": [
                    {"ansible.builtin.assert": {"that": ["host_firewall_mode == 'hardened'",
                        "host_firewall_change_id == 'next-change'", "host_firewall_candidate_sha256 == 'd' * 64",
                        "host_firewall_approved_readback_sha256 == 'f' * 64",
                        "host_firewall_policy_fingerprint == (host_firewall_policy_material_effective | to_json | hash('sha256'))",
                        "host_firewall_egress_policy_sha256 == (host_firewall_egress_policy | to_json | hash('sha256'))",
                        "host_firewall_egress_status == 'accepted'"]}},
                    {"ansible.builtin.copy": {"dest": str(marker), "content": "fresh", "mode": "0600"}}]}]))
            config = root / "ansible.cfg"
            config.write_text("[defaults]\nroles_path=" + str(root / "roles") + "\n")
            env = {**os.environ, "ANSIBLE_CONFIG": str(config), "ANSIBLE_LOCAL_TEMP": str(root / "local"),
                   "ANSIBLE_REMOTE_TEMP": str(root / "remote")}
            env.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
            done = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(book)],
                                  env=env, capture_output=True, text=True, timeout=90)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertTrue(marker.exists())


if __name__ == "__main__":
    unittest.main()
