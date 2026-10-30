"""Real role admission, effective caller precedence, and native section scope."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class NativeBooleanContractTests(unittest.TestCase):
    def test_effective_native_switches_reject_nonbooleans_before_any_mutation(self):
        inputs = [
            {"ubtu24cis_level_2": "false"}, {"ubtu24cis_level_1": "true"},
            {"setup_audit": "false"}, {"run_audit": "false"}, {"audit_only": "false"},
            {"fetch_audit_output": "false"}, {"ubtu24cis_config_aide": "false"},
            {"ubtu24cis_section6": "false"}, {"ubtu24cis_rule_6_3_1": "false"},
            {"ubtu24cis_rule_6_3_2": "false"}, {"ubtu24cis_aide_db_recreate": "false"},
            {"ubtu24cis_rule_1_3_1_3": "false"}, {"ubtu24cis_apparmor_disable": "false"},
            {"ubtu24cis_rule_6_2_4_1": "false"}, {"ubtu24cis_rule_6_2_4_4": "false"},
            {"ubtu24cis_is_router": "false"}, {"ubtu24cis_ipv6_required": "false"},
            {"ubtu24cis_section3": "false"}, {"ubtu24cis_rule_3_3_5": "false"},
            {"ubtu24cis_rule_3_3_8": "false"}, {"ubtu24cis_rule_3_3_9": "false"},
            {"ubtu24cis_rule_3_3_11": "false"}, {"ubtu24cis_level_2": 0},
            {"ubtu24cis_level_2": None}, {}]
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
            root = Path(directory)
            config = root / "ansible.cfg"
            config.write_text("[defaults]\nroles_path=" + str(ROOT / "roles") + "\n")
            marker = root / "mutation"
            for extra in inputs:
                with self.subTest(extra=extra):
                    marker.unlink(missing_ok=True)
                    baseline = {"cis_ubuntu24_profile_tag": "level1-server", "ubtu24cis_level_1": True,
                                "ubtu24cis_level_2": False, "setup_audit": False, "run_audit": False, "audit_only": False}
                    book = root / "case.yml"
                    book.write_text(yaml.safe_dump([{"hosts": "all", "gather_facts": False, "vars": baseline,
                        "tasks": [{"ansible.builtin.include_role": {"name": "cis_ubuntu24", "tasks_from": "assert.yml",
                                                                    "apply": {"tags": "always"}},
                                   "tags": "always"},
                                  {"ansible.builtin.copy": {"dest": str(marker), "content": "past admission", "mode": "0600"},
                                   "tags": "always"}]}]))
                    supplied = root / "caller.yml"
                    supplied.write_text(yaml.safe_dump(extra))
                    env = {**os.environ, "ANSIBLE_CONFIG": str(config), "ANSIBLE_LOCAL_TEMP": str(root / "local"),
                           "ANSIBLE_REMOTE_TEMP": str(root / "remote")}
                    env.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
                    done = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(book),
                                           "--tags", "level1-server", "-e", "@" + str(supplied)],
                                          env=env, capture_output=True, text=True, timeout=45)
                    self.assertEqual(done.returncode, 2 if extra else 0, done.stdout + done.stderr)
                    self.assertEqual(marker.exists(), not bool(extra), done.stdout + done.stderr)

    def test_wrapper_native_helpers_respect_disabled_parent_sections(self):
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
            root = Path(directory)
            role = root / "roles/cis_ubuntu24"
            shutil.copytree(ROOT / "roles/cis_ubuntu24", role)
            selected = [task for task in yaml.safe_load((role / "tasks/main.yml").read_text()) if task.get("name") in (
                "Normalize the upstream AIDE scheduler integration", "Preserve a traversable upstream audit log directory",
                "Persist the network kernel controls audited independently")]
            self.assertEqual(len(selected), 3)
            (role / "tasks/main.yml").write_text(yaml.safe_dump(selected))
            markers = [root / name for name in ("scheduler", "audit-directory", "network-controls")]
            for file, marker in zip(("aide_scheduler.yml", "audit_log_directory.yml", "network_sysctl_persistence.yml"), markers):
                # Only target mutations become private markers. Actual wrapper
                # imports/tags/parent scope run; the pinned native section
                # ancestors in vendor tasks/main.yml use the same booleans.
                (role / "tasks" / file).write_text(yaml.safe_dump([{"ansible.builtin.copy": {
                    "dest": str(marker), "content": "selected", "mode": "0600"}}]))
            config = root / "ansible.cfg"
            config.write_text("[defaults]\nroles_path=" + str(root / "roles") + "\n")
            for enabled in (False, True):
                with self.subTest(enabled=enabled):
                    for marker in markers:
                        marker.unlink(missing_ok=True)
                    book = root / "case.yml"
                    book.write_text(yaml.safe_dump([{"hosts": "all", "gather_facts": False,
                        "vars": {"cis_ubuntu24_execution_mode": "remediate", "ubtu24cis_section3": enabled,
                            "ubtu24cis_section6": enabled, "ubtu24cis_config_aide": True,
                            "ubtu24cis_rule_6_3_2": True, "ubtu24cis_rule_6_2_4_1": False,
                            "ubtu24cis_rule_6_2_4_4": True, "ubtu24cis_rule_3_3_5": True},
                        "roles": ["cis_ubuntu24"]}]))
                    env = {**os.environ, "ANSIBLE_CONFIG": str(config), "ANSIBLE_LOCAL_TEMP": str(root / "local"),
                           "ANSIBLE_REMOTE_TEMP": str(root / "remote")}
                    env.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
                    done = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(book),
                                           "--tags", "level1-server"], env=env, capture_output=True, text=True, timeout=45)
                    self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                    self.assertEqual([marker.exists() for marker in markers], [enabled] * 3, done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
