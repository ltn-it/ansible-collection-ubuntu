"""Keep wrapper consent and the pinned vendor's actual conditions consistent."""
import base64
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class NativeAideAdmissionTests(unittest.TestCase):
    def run_case(self, root, tasks, variables):
        config = root / "ansible.cfg"
        config.write_text("[defaults]\nroles_path=" + str(ROOT / "roles") + "\n")
        book = root / "case.yml"
        book.write_text(yaml.safe_dump([{"hosts": "all", "gather_facts": False,
                                        "vars": variables, "tasks": tasks}]))
        env = {**os.environ, "ANSIBLE_CONFIG": str(config), "ANSIBLE_LOCAL_TEMP": str(root / "local"),
               "ANSIBLE_REMOTE_TEMP": str(root / "remote")}
        env.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
        return subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(book)],
                              env=env, capture_output=True, text=True, timeout=30)

    def test_string_false_cannot_authorize_the_native_recreate_condition(self):
        # The pinned vendor3a2f05b9 uses the raw variable in its when expression;
        # strings such as CLI -e name=false are truthy in supported Ansible2.18.
        fragment = "# Managed by lit.ubuntu.cis_ubuntu24; inventory-owned mutable data exclusions.\n"
        for recreate in ("false", "no", "0"):
            with self.subTest(recreate=recreate), tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
                root = Path(directory)
                marker = root / "native-initializer"
                variables = {"cis_ubuntu24_aide_exclusions": [], "ubtu24cis_config_aide": True,
                             "ubtu24cis_aide_db_recreate": recreate, "cis_ubuntu24_aide_aged": {"files": []},
                             "cis_ubuntu24_aide_previous_content": {"content": base64.b64encode(fragment.encode()).decode()},
                             "cis_ubuntu24_aide_previous": {"stat": {"exists": True, "isreg": True,
                                "islnk": False, "nlink": 1, "uid": 0, "gid": 0, "mode": "0644",
                                "checksum": hashlib.sha256(fragment.encode()).hexdigest()}},
                             "cis_ubuntu24_aide_database": {"stat": {"exists": True, "isreg": True,
                                "islnk": False, "nlink": 1, "uid": 0, "gid": 0, "mode": "0600", "checksum": "b" * 64}}}
                done = self.run_case(root, [
                    {"ansible.builtin.include_role": {"name": "cis_ubuntu24", "tasks_from": "aide_admission"}},
                    {"name": "Pinned vendor raw recreate condition",
                     "ansible.builtin.copy": {"dest": str(marker), "content": "would initialize", "mode": "0600"},
                     "when": "ubtu24cis_aide_db_recreate"}], variables)
                self.assertFalse(marker.exists(), done.stdout + done.stderr)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)

    def test_container_target_is_refused_before_preparation(self):
        # The pinned vendor subsequently loads vars/is_container.yml, disabling
        # 6.3.1/6.3.2. A wrapper must not change policy ahead of that skipped init.
        for kind in ("docker", "lxc", "openvz", "podman", "container"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
                root = Path(directory)
                marker = root / "preparation"
                done = self.run_case(root, [
                    {"ansible.builtin.include_role": {"name": "cis_ubuntu24", "tasks_from": "aide_target_assert"}},
                    {"ansible.builtin.copy": {"dest": str(marker), "content": "entered", "mode": "0600"}}],
                    {"ansible_facts": {"distribution": "Ubuntu", "distribution_major_version": "24",
                                       "service_mgr": "systemd", "virtualization_type": kind}})
                self.assertFalse(marker.exists(), done.stdout + done.stderr)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
