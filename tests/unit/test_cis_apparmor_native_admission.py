"""Preserved attachments must never reach a truthy native rewrite condition."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class NativeApparmorAdmissionTests(unittest.TestCase):
    def test_only_boolean_false_disables_native_rewrite_before_profile_changes(self):
        for enabled in ("false", "no", "0", 0, None, False, True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
                root = Path(directory)
                profile = root / "podman"
                original = "profile podman /usr/bin/podman flags=(unconfined) { userns, }\n"
                profile.write_text(original)
                variables = {"cis_ubuntu24_profile_tag": "level1-server", "ubtu24cis_rule_1_3_1_3": enabled,
                    "cis_ubuntu24_apparmor_preserved_profiles": [{"name": "podman", "executable": "/usr/bin/podman",
                        "sha256": "a" * 64, "reason": "isolated fixture", "approval_reference": "synthetic-binding"}],
                    "cis_ubuntu24_exceptions": [{"control_ids": ["1.3.1.3"], "approval_state": "accepted",
                        "audit_visibility": "intentional_exception", "approval_reference": "synthetic-binding"}]}
                book = root / "case.yml"
                book.write_text(yaml.safe_dump([{"hosts": "all", "gather_facts": False, "vars": variables,
                    "tasks": [{"ansible.builtin.include_role": {"name": "cis_ubuntu24", "tasks_from": "apparmor_assert"}},
                        {"name": "Pinned3a2f native AppArmor control condition before postcheck",
                         "ansible.builtin.copy": {"dest": str(profile), "content": "rewritten attachment\n", "mode": "0600"},
                         "when": "ubtu24cis_rule_1_3_1_3"}]}]))
                config = root / "ansible.cfg"
                config.write_text("[defaults]\nroles_path=" + str(ROOT / "roles") + "\n")
                env = {**os.environ, "ANSIBLE_CONFIG": str(config), "ANSIBLE_LOCAL_TEMP": str(root / "local"),
                       "ANSIBLE_REMOTE_TEMP": str(root / "remote")}
                env.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
                done = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(book)],
                                      env=env, capture_output=True, text=True, timeout=45)
                self.assertEqual(profile.read_text(), original, done.stdout + done.stderr)
                self.assertEqual(done.returncode, 0 if enabled is False else 2, done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
