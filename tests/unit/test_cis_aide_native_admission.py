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
    def run_case(self, root, tasks, variables, extra=None):
        config = root / "ansible.cfg"
        config.write_text("[defaults]\nroles_path=" + str(ROOT / "roles") + "\n")
        book = root / "case.yml"
        book.write_text(yaml.safe_dump([{"hosts": "all", "gather_facts": False,
                                        "vars": variables, "tasks": tasks}]))
        env = {**os.environ, "ANSIBLE_CONFIG": str(config), "ANSIBLE_LOCAL_TEMP": str(root / "local"),
               "ANSIBLE_REMOTE_TEMP": str(root / "remote"),
               "ANSIBLE_ROLES_PATH": str(root / "roles") + ":" + str(ROOT / "roles")}
        env.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
        argv = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(book)]
        if extra:
            supplied = root / "caller-extra.yml"
            supplied.write_text(yaml.safe_dump(extra))
            argv += ["-e", "@" + str(supplied)]
        return subprocess.run(argv,
                              env=env, capture_output=True, text=True, timeout=90)

    @unittest.skipUnless(os.geteuid() == 0, "Requires the isolated root-owned AIDE state fixture")
    def test_native_age_crossing_cannot_add_an_unapproved_initialization(self):
        defaults = yaml.safe_load((ROOT / "roles/cis_ubuntu24/defaults/main.yml").read_text())
        fragment = "# Managed by lit.ubuntu.cis_ubuntu24; inventory-owned mutable data exclusions.\n"
        main = yaml.safe_load((ROOT / "roles/cis_ubuntu24/tasks/main.yml").read_text())
        calls = [task for block in main if "block" in block for task in block["block"]
                 if task.get("name") in ("Apply ansible-lockdown Ubuntu 24 CIS role",
                    "Apply native remediation with the admitted AIDE age decision")]
        self.assertTrue(calls)
        cases = ("age", "approved", "disappeared", "changed", "appeared", "disappeared-late", "changed-late",
                 "override-age", "override-file")
        for case in cases:
            approved = case == "approved"
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
                root = Path(directory)
                database = root / "aide.db"
                database.write_text("bound existing database")
                database.chmod(0o600)
                marker = root / "initialized"
                if approved:
                    os.utime(database, (1, 1))
                observed = database.stat()
                source_state = {"stat": {"exists": True, "isreg": True, "islnk": False,
                    "nlink": observed.st_nlink, "uid": observed.st_uid, "gid": observed.st_gid,
                    "mode": "0600", "size": observed.st_size, "checksum": hashlib.sha256(database.read_bytes()).hexdigest()}}
                if case == "appeared":
                    database.unlink()
                    source_state = {"stat": {"exists": False}}
                vendor = root / "roles/ansible-lockdown.ubuntu24_cis/tasks"
                vendor.mkdir(parents=True)
                # Actual pinned3a2f native find and initializer condition. The
                # marker replaces destructive removal/initialization only.
                (vendor / "main.yml").write_text(yaml.safe_dump([
                    {"name": "Witness a late disappearance before the native stat",
                     "ansible.builtin.file": {"path": str(database), "state": "absent"}, "when": case == "disappeared-late"},
                    {"name": "Witness a late baseline change before the native stat",
                     "ansible.builtin.copy": {"dest": str(database), "content": "unexpected late change", "mode": "0600"},
                     "when": case == "changed-late"},
                    {"name": "Pinned native baseline presence query", "ansible.builtin.stat": {
                        "path": str(database), "follow": False}, "register": "discovered_aide_db_file"},
                    {"name": "Pinned vendor second age query", "ansible.builtin.find": {
                        "paths": str(root), "patterns": "aide.db", "age": "20s"},
                     "register": "discovered_aide_db_age"},
                    {"name": "Pinned native initialization condition", "block": [
                        {"ansible.builtin.copy": {"dest": str(marker), "content": "initialize", "mode": "0600"}},
                        {"ansible.builtin.copy": {"dest": str(database), "content": "new approved baseline", "mode": "0600"}}],
                     "when": "not discovered_aide_db_file.stat.exists or "
                             "(discovered_aide_db_age.files | length > 0) or ubtu24cis_aide_db_recreate"}]))
                variables = {**defaults, "cis_ubuntu24_execution_mode": "remediate",
                    "cis_ubuntu24_aide_exclusions": [], "cis_ubuntu24_aide_owned_policy": {"stat": {"exists": True}},
                    "ubtu24cis_config_aide": True, "ubtu24cis_aide_db_recreate": False,
                    "ubtu24cis_aide_db_file": str(database),
                    "discovered_aide_db_file": {"stat": {"exists": True}},
                    "cis_ubuntu24_aide_previous_content": {"content": base64.b64encode(fragment.encode()).decode()},
                    "cis_ubuntu24_aide_previous": {"stat": {"exists": True, "isreg": True,
                        "islnk": False, "nlink": 1, "uid": 0, "gid": 0, "mode": "0644",
                        "checksum": hashlib.sha256(fragment.encode()).hexdigest()}},
                    "cis_ubuntu24_aide_database": source_state}
                if approved:
                    variables["cis_ubuntu24_aide_rebaseline"] = {
                        "database_sha256": source_state["stat"]["checksum"],
                        "exclusions_sha256": hashlib.sha256(fragment.encode()).hexdigest(),
                        "approval_reference": "isolated-test-change"}
                done = self.run_case(root, [
                    {"ansible.builtin.find": {"paths": str(root), "patterns": "aide.db", "age": "20s"},
                     "register": "cis_ubuntu24_aide_aged"},
                    {"ansible.builtin.assert": {"that":
                        "(cis_ubuntu24_aide_aged.files | length > 0) == " + str(approved).lower()}},
                    {"ansible.builtin.include_role": {"name": "cis_ubuntu24", "tasks_from": "aide_admission"}},
                    {"name": "Cross the real age threshold after completed admission",
                     "ansible.builtin.pause": {"seconds": 21}, "when": case == "age"},
                    {"ansible.builtin.file": {"path": str(database), "state": "absent"}, "when": case == "disappeared"},
                    {"ansible.builtin.copy": {"dest": str(database), "content": "unexpected new bytes", "mode": "0600"},
                     "when": case in ("changed", "appeared")},
                    *calls], variables, extra={"discovered_aide_db_age": {"files": [{"path": str(database)}]}}
                    if case == "override-age" else ({"discovered_aide_db_file": {"stat": {"exists": False}}}
                    if case == "override-file" else None))
                self.assertEqual(done.returncode, 0 if case in ("age", "approved") else 2, done.stdout + done.stderr)
                self.assertEqual(marker.exists(), approved, done.stdout + done.stderr)

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
