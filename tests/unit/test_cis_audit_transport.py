"""The bound archive cannot replace clean pinned audit code at execution."""

import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tarfile
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "roles/cis_ubuntu24/files/audit_archive_matches_checkout.py"
HELPERS = runpy.run_path(str(HELPER))
VERIFY = HELPERS["verify"]
VALIDATE_GIT = HELPERS["validate_git"]


class AuditTransportTests(unittest.TestCase):
    def test_complete_archive_matches_and_mismatches_never_change_the_checkout(self):
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
            root = Path(directory)
            checkout = root / "UBUNTU24-CIS-Audit"
            checkout.mkdir()
            entry = checkout / "run_audit.sh"
            entry.write_bytes(b"#!/bin/sh\nexit 0\n")
            entry.chmod(0o755)
            (checkout / "goss.yml").write_bytes(b"command: {}\n")
            expected = {path.name: path.read_bytes() for path in checkout.iterdir()}
            for case in ("valid", "changed", "missing", "mode", "duplicate", "traversal", "symlink", "hardlink"):
                with self.subTest(case=case):
                    archive = root / "transport.tar.gz"
                    with tarfile.open(archive, "w:gz") as stream:
                        stream.add(entry, arcname=checkout.name + "/run_audit.sh")
                        if case != "missing":
                            content = b"changed audit code" if case == "changed" else expected["goss.yml"]
                            member = tarfile.TarInfo(checkout.name + "/goss.yml")
                            member.size = len(content)
                            member.mode = 0o755 if case == "mode" else 0o644
                            stream.addfile(member, io.BytesIO(content))
                        if case == "duplicate":
                            stream.add(entry, arcname=checkout.name + "/run_audit.sh")
                        if case == "traversal":
                            stream.add(entry, arcname=checkout.name + "/../escaped")
                        if case in ("symlink", "hardlink"):
                            member = tarfile.TarInfo(checkout.name + "/link")
                            member.type = tarfile.SYMTYPE if case == "symlink" else tarfile.LNKTYPE
                            member.linkname = "run_audit.sh"
                            stream.addfile(member)
                    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                    if case == "valid":
                        for _ in range(2):
                            VERIFY(str(archive), str(checkout), digest)
                        with self.assertRaisesRegex(ValueError, "digest changed"):
                            VERIFY(str(archive), str(checkout), "0" * 64)
                    else:
                        with self.assertRaises(ValueError):
                            VERIFY(str(archive), str(checkout), digest)
                    self.assertEqual(expected, {path.name: path.read_bytes() for path in checkout.iterdir()})
                    self.assertFalse((root / "escaped").exists())


@unittest.skipUnless(os.geteuid() == 0, "Requires an isolated root-target Devtools witness")
class RootAuditAdmissionTests(unittest.TestCase):
    def test_git_metadata_cannot_link_to_untrusted_or_executable_configuration(self):
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
            checkout = Path(directory) / "checkout"
            checkout.mkdir()
            metadata = checkout / ".git"
            metadata.mkdir()
            config = metadata / "config"
            base = "[core]\n\tbare = false\n"
            config.write_text(base)
            # This helper boundary runs for the actual effective target uid.
            # Root execution of the complete Ansible path is tested separately.
            VALIDATE_GIT(str(checkout))
            for text in ('[include]\n\tpath = /tmp/untrusted\n',
                         '[includeIf "gitdir:/tmp/"]\n\tpath = /tmp/untrusted\n',
                         '[filter "untrusted"]\n\tclean = /tmp/command\n',
                         '[filter.untrusted]\n\tclean = /tmp/command\n',
                         '[extensions]\n\tworktreeConfig = true\n'):
                with self.subTest(text=text):
                    config.write_text(base + text)
                    with self.assertRaisesRegex(ValueError, "External or executable"):
                        VALIDATE_GIT(str(checkout))
            config.write_text(base)
            config.chmod(0o666)
            with self.assertRaisesRegex(ValueError, "Unprotected"):
                VALIDATE_GIT(str(checkout))
            config.chmod(0o644)
            for name in ("commondir", "config.worktree", "objects/info/alternates", "objects/info/http-alternates"):
                with self.subTest(redirect=name):
                    path = metadata / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("/tmp/untrusted\n")
                    with self.assertRaisesRegex(ValueError, "External audit Git metadata"):
                        VALIDATE_GIT(str(checkout))
                    path.unlink()

    def test_clearing_existing_aide_exclusions_cannot_skip_the_rebaseline_gate(self):
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
            root = Path(directory)
            role = root / "roles/cis_ubuntu24"
            shutil.copytree(ROOT / "roles/cis_ubuntu24", role)
            aide = root / "aide"
            (aide / "aide.conf.d").mkdir(parents=True, mode=0o755)
            previous = aide / "aide.conf.d/90_lit_mutable_data"
            previous.write_text("# Managed by lit.ubuntu.cis_ubuntu24; fixture.\n!/var/lib/example/data(/|$)\n")
            previous.chmod(0o644)
            database = root / "aide.db"
            database.write_bytes(b"EXISTING_SYNTHETIC_AIDE_BASELINE")
            # Relocate only the fixed configuration path in the test copy. All
            # actual ownership, stat, changed-policy and admission logic runs.
            for path in (role / "tasks").glob("*.yml"):
                path.write_text(path.read_text().replace("/etc/aide", str(aide)))
            main = yaml.safe_load((role / "tasks/main.yml").read_text())
            selected = [task for task in main if task.get("name") in (
                "Detect an already managed AIDE policy even when requested exclusions are empty",
                "Prepare guarded AIDE exclusions before upstream initialization",
            )]
            self.assertEqual(len(selected), 2)
            (role / "tasks/main.yml").write_text(yaml.safe_dump(selected))
            config = root / "ansible.cfg"
            config.write_text("[defaults]\nroles_path=" + str(root / "roles") + "\n")
            book = root / "play.yml"
            book.write_text(yaml.safe_dump([{
                "hosts": "all", "gather_facts": False,
                "vars": {
                    "ansible_facts": {"distribution": "Ubuntu", "distribution_major_version": "24", "service_mgr": "systemd"},
                    "cis_ubuntu24_aide_exclusions": [], "cis_ubuntu24_aide_rebaseline": {},
                    "ubtu24cis_config_aide": True, "ubtu24cis_aide_db_file": str(database),
                }, "roles": ["cis_ubuntu24"],
            }]))
            env = {**os.environ, "ANSIBLE_CONFIG": str(config), "ANSIBLE_LOCAL_TEMP": str(root / "local"),
                   "ANSIBLE_REMOTE_TEMP": str(root / "remote")}
            env.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
            result = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(book)],
                                    env=env, capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("needs a reviewed database/exclusion hash binding", result.stdout)
            self.assertNotIn("TASK [cis_ubuntu24 : Install AIDE", result.stdout)
            self.assertIn("!/var/lib/example/data", previous.read_text())
            self.assertEqual(database.read_bytes(), b"EXISTING_SYNTHETIC_AIDE_BASELINE")

    def test_two_audits_keep_generated_vars_external_and_reject_a_changed_archive(self):
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
            root = Path(directory)
            checkout = root / "UBUNTU24-CIS-Audit"
            checkout.mkdir(mode=0o755)
            entry = checkout / "run_audit.sh"
            entry.write_text("#!/bin/sh\nexit 0\n")
            entry.chmod(0o755)
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
            subprocess.run(["git", "-C", str(checkout), "remote", "add", "origin", "https://example.test/audit.git"], check=True)
            subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
            subprocess.run(["git", "-C", str(checkout), "-c", "user.name=Fixture",
                            "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"], check=True)
            commit = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
            archive = root / "transport.tar.gz"
            with tarfile.open(archive, "w:gz") as stream:
                stream.add(checkout, arcname=checkout.name)
            original = archive.read_bytes()
            config = root / "ansible.cfg"
            config.write_text("[defaults]\nroles_path=" + str(ROOT / "roles") + "\n")
            env = {**os.environ, "ANSIBLE_CONFIG": str(config), "ANSIBLE_LOCAL_TEMP": str(root / "local"),
                   "ANSIBLE_REMOTE_TEMP": str(root / "remote")}
            env.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
            unchecked = root / "unchecked"
            unchecked.mkdir()
            marker = root / "unchecked-executed"
            (unchecked / "run_audit.sh").write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n")
            (unchecked / "run_audit.sh").chmod(0o755)
            env.update(GIT_DIR=str(unchecked / "foreign.git"), GIT_WORK_TREE=str(unchecked),
                       GIT_COMMON_DIR=str(unchecked / "foreign-common.git"),
                       GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.fsmonitor",
                       GIT_CONFIG_VALUE_0=str(unchecked / "command"))
            vendor = root / "vendor-defaults.yml"
            vendor.write_text(yaml.safe_dump({"audit_conf_dir": str(unchecked), "audit_content": "archive",
                                              "audit_vars_path": str(unchecked / "vars.yml")}))
            for attempt in range(8):
                archive.write_bytes(original)
                git_config = checkout / ".git/config"
                original_config = git_config.read_text()
                if attempt >= 6:
                    fsmonitor = root / "hostile-fsmonitor"
                    fsmonitor.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\nprintf 'fixture\\0'\n")
                    fsmonitor.chmod(0o755)
                    git_config.write_text(original_config + "\n[core]\n\tfsmonitor = " + str(fsmonitor) + "\n")
                    if attempt == 6:
                        git_config.chmod(0o666)
                if attempt == 2:
                    with tarfile.open(archive, "w:gz") as stream:
                        replacement = b"#!/bin/sh\necho unexpected code\n"
                        member = tarfile.TarInfo(checkout.name + "/run_audit.sh")
                        member.mode, member.size = 0o755, len(replacement)
                        stream.addfile(member, io.BytesIO(replacement))
                variables = {
                    "audit_conf_source": str(archive), "audit_conf_dest": str(root),
                    "cis_ubuntu24_audit_transport_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                    "cis_ubuntu24_audit_dependency": {"repository": "https://example.test/audit.git", "commit": commit},
                }
                tasks = [
                    {"ansible.builtin.include_role": {"name": "cis_ubuntu24", "tasks_from": "audit_archive"}},
                    {"ansible.builtin.include_role": {"name": "cis_ubuntu24", "tasks_from": "audit_variables"}},
                    {"name": "Model vendor include-vars after admission", "ansible.builtin.include_vars": str(vendor)},
                    {"ansible.builtin.assert": {"that": ["audit_content == 'existing'",
                        "audit_conf_dir == audit_conf_dest ~ '/UBUNTU24-CIS-Audit'",
                        "not audit_vars_path.startswith(audit_conf_dest ~ '/UBUNTU24-CIS-Audit/')"]}},
                    {"name": "Model vendor execution at its actual admitted path",
                     "ansible.builtin.command": {"argv": ["{{ audit_conf_dir }}/run_audit.sh"]},
                     "changed_when": False},
                    {"name": "Model vendor generated variables at the actual bound path",
                     "ansible.builtin.copy": {"dest": "{{ audit_vars_path }}", "content": "fixture: true\n", "mode": "0600"}},
                ]
                book = root / "play.yml"
                book.write_text(yaml.safe_dump([{"hosts": "all", "gather_facts": False, "vars": variables, "tasks": tasks}]))
                extra = ({"audit_conf_dir": str(unchecked)} if attempt == 3 else
                         {"audit_content": "archive"} if attempt == 4 else
                         {"audit_vars_path": str(unchecked / "vars.yml")} if attempt == 5 else {})
                command = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(book)]
                if extra:
                    command += ["--extra-vars", json.dumps(extra)]
                result = subprocess.run(command,
                                        env=env, capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, 0 if attempt in (0, 1, 7) else 2, result.stdout + result.stderr)
                if attempt == 2:
                    self.assertIn("Offline audit transport does not match", result.stdout)
                    self.assertNotIn("TASK [Model vendor generated", result.stdout)
                if attempt in (3, 4, 5, 6):
                    self.assertNotIn("TASK [Model vendor execution", result.stdout)
                if attempt == 6:
                    self.assertNotIn("TASK [cis_ubuntu24 : Read actual staged commit", result.stdout)
                self.assertFalse(marker.exists())
                git_config.chmod(0o644)
                git_config.write_text(original_config)
                self.assertEqual(subprocess.check_output(["git", "-C", str(checkout), "status", "--porcelain"]), b"")
                self.assertEqual(entry.read_text(), "#!/bin/sh\nexit 0\n")
                if attempt < 2:
                    self.assertEqual(archive.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
