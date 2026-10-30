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
import zlib

import yaml


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "roles/cis_ubuntu24/files/audit_archive_matches_checkout.py"
HELPERS = runpy.run_path(str(HELPER))
VERIFY = HELPERS["verify"]
VALIDATE_GIT = HELPERS["validate_git"]


class AuditTransportTests(unittest.TestCase):
    def test_working_files_are_bound_to_commit_objects_independently_of_the_index(self):
        validate_revision = HELPERS["validate_revision"]
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
            checkout = Path(directory)
            entry = checkout / "run_audit.sh"
            entry.write_bytes(b"#!/bin/sh\nexit 0\n")
            entry.chmod(0o755)
            (checkout / "nested").mkdir()
            (checkout / "nested/goss.yml").write_text("command: {}\n")
            (checkout / ".gitignore").write_text("ignored\n")
            def git(*args):
                return subprocess.check_output(["git", "-C", directory, *args]).strip()
            git("init", "-q")
            git("add", ".")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture")
            revision = git("rev-parse", "HEAD").decode()
            validate_revision(directory, revision)
            for flag in ("assume-unchanged", "skip-worktree"):
                with self.subTest(flag=flag):
                    git("update-index", "--" + flag, "run_audit.sh")
                    entry.write_bytes(b"#!/bin/sh\necho changed\n")
                    self.assertEqual(git("status", "--porcelain"), b"")
                    with self.assertRaisesRegex(ValueError, "differs from the pinned commit"):
                        validate_revision(directory, revision)
                    entry.write_bytes(b"#!/bin/sh\nexit 0\n")
                    git("update-index", "--no-" + flag, "run_audit.sh")
            ignored = checkout / "ignored"
            ignored.write_text("not in the immutable tree")
            self.assertEqual(git("status", "--porcelain"), b"")
            with self.assertRaises(ValueError):
                validate_revision(directory, revision)
            ignored.unlink()
            entry.chmod(0o644)
            with self.assertRaises(ValueError):
                validate_revision(directory, revision)
            entry.chmod(0o755)
            tree = git("rev-parse", "HEAD^{tree}").decode()
            raw = subprocess.check_output(["git", "-C", directory, "cat-file", "tree", tree])
            object_path = checkout / ".git/objects" / tree[:2] / tree[2:]
            object_path.chmod(0o644)
            changed = raw.replace(b"100755", b"100644")
            object_path.write_bytes(zlib.compress(b"tree " + str(len(changed)).encode() + b"\0" + changed))
            with self.assertRaisesRegex(ValueError, "immutable identity|Unreadable pinned"):
                validate_revision(directory, revision)

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
    def test_aide_rejects_untrusted_databases_before_baseline_admission(self):
        for mode in (0o666, 0o664, 0o755):
            with self.subTest(mode=oct(mode)), tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
                root = Path(directory)
                database = root / "aide.db"
                database.write_bytes(b"UNTRUSTED_SYNTHETIC_BASELINE")
                database.chmod(mode)
                fragment = root / "policy"
                fragment.write_text("# Managed by lit.ubuntu.cis_ubuntu24; inventory-owned mutable data exclusions.\n")
                marker = root / "admitted"
                book = root / "case.yml"
                tasks = [
                    {"ansible.builtin.stat": {"path": str(fragment), "checksum_algorithm": "sha256"},
                     "register": "cis_ubuntu24_aide_previous"},
                    {"ansible.builtin.slurp": {"src": str(fragment)},
                     "register": "cis_ubuntu24_aide_previous_content"},
                    {"ansible.builtin.stat": {"path": str(database), "checksum_algorithm": "sha256"},
                     "register": "cis_ubuntu24_aide_database"},
                    {"ansible.builtin.include_role": {"name": "cis_ubuntu24", "tasks_from": "aide_admission"}},
                    {"ansible.builtin.copy": {"dest": str(marker), "content": "accepted", "mode": "0600"}},
                ]
                book.write_text(yaml.safe_dump([{"hosts": "all", "gather_facts": False, "vars": {
                    "ubtu24cis_config_aide": True, "cis_ubuntu24_aide_exclusions": [],
                    "cis_ubuntu24_aide_aged": {"files": []}}, "tasks": tasks}]))
                config = root / "ansible.cfg"
                config.write_text("[defaults]\nroles_path=" + str(ROOT / "roles") + "\n")
                env = {**os.environ, "ANSIBLE_CONFIG": str(config), "ANSIBLE_LOCAL_TEMP": str(root / "local"),
                       "ANSIBLE_REMOTE_TEMP": str(root / "remote")}
                env.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
                done = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(book)],
                                      env=env, capture_output=True, text=True, timeout=90)
                self.assertFalse(marker.exists(), done.stdout + done.stderr)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertIn("Refusing a foreign or unsafe AIDE", done.stdout)
                self.assertEqual(database.read_bytes(), b"UNTRUSTED_SYNTHETIC_BASELINE")

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

    def test_level2_only_managed_aide_runs_stop_before_any_policy_or_package_change(self):
        for profile in ("level2-server", "level2-workstation"):
            for clearing in (False, True):
                with self.subTest(profile=profile, clearing=clearing), tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
                    root = Path(directory)
                    role = root / "roles/cis_ubuntu24"
                    shutil.copytree(ROOT / "roles/cis_ubuntu24", role)
                    aide = root / "aide"
                    (aide / "aide.conf.d").mkdir(parents=True, mode=0o755)
                    fragment = aide / "aide.conf.d/90_lit_mutable_data"
                    database = root / "aide.db"
                    if clearing:
                        fragment.write_text("# Managed by lit.ubuntu.cis_ubuntu24; fixture.\n!/var/lib/example/data(/|$)\n")
                        fragment.chmod(0o644)
                        database.write_bytes(b"SYNTHETIC_EXISTING_DATABASE")
                    previous = fragment.read_bytes() if fragment.exists() else None
                    for path in (role / "tasks").glob("*.yml"):
                        path.write_text(path.read_text().replace("/etc/aide", str(aide)))
                    prepare = yaml.safe_load((role / "tasks/aide_prepare.yml").read_text())
                    boundary = next(i for i, task in enumerate(prepare) if task["name"] ==
                                    "Prevent package-triggered background AIDE initialization")
                    marker = root / "package-transition"
                    # Keep the real preflight/import/tag path. A private marker
                    # replaces the package boundary; no apt/debconf is executed.
                    prepare = prepare[:boundary] + [
                        {"name": "Witness package transition", "ansible.builtin.copy": {
                            "dest": str(marker), "content": "entered", "mode": "0600"}},
                        {"ansible.builtin.fail": {"msg": "Stop before real package operations"}}]
                    (role / "tasks/aide_prepare.yml").write_text(yaml.safe_dump(prepare))
                    main = yaml.safe_load((role / "tasks/main.yml").read_text())
                    selected = [task for task in main if task.get("name") in (
                        "Detect an already managed AIDE policy even when requested exclusions are empty",
                        "Prepare guarded AIDE exclusions before upstream initialization")]
                    (role / "tasks/main.yml").write_text(yaml.safe_dump(selected))
                    expected_empty = (role / "templates/aide-exclusions.conf.j2").read_text().split("{%", 1)[0]
                    approval = ({"database_sha256": hashlib.sha256(database.read_bytes()).hexdigest(),
                                 "exclusions_sha256": hashlib.sha256(expected_empty.encode()).hexdigest(),
                                 "approval_reference": "https://example.test/reviewed"} if clearing else {})
                    variables = {"ansible_facts": {"distribution": "Ubuntu", "distribution_major_version": "24",
                                 "service_mgr": "systemd"}, "cis_ubuntu24_profile_tag": profile,
                                 "cis_ubuntu24_execution_mode": "remediate", "ubtu24cis_config_aide": True,
                                 "ubtu24cis_aide_db_file": str(database), "ubtu24cis_aide_db_recreate": True,
                                 "cis_ubuntu24_aide_rebaseline": approval,
                                 "cis_ubuntu24_aide_exclusions": [] if clearing else
                                 [{"path": "/var/lib/example/data", "reason": "Mutable fixture data."}]}
                    book = root / "case.yml"
                    book.write_text(yaml.safe_dump([{"hosts": "all", "gather_facts": False,
                                                   "vars": variables, "roles": ["cis_ubuntu24"]}]))
                    config = root / "ansible.cfg"
                    config.write_text("[defaults]\nroles_path=" + str(root / "roles") + "\n")
                    env = {**os.environ, "ANSIBLE_CONFIG": str(config), "ANSIBLE_LOCAL_TEMP": str(root / "local"),
                           "ANSIBLE_REMOTE_TEMP": str(root / "remote")}
                    env.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
                    done = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(book),
                                           "--tags", profile], env=env, capture_output=True, text=True, timeout=90)
                    self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                    self.assertFalse(marker.exists(), done.stdout + done.stderr)
                    self.assertIn("native Level 1", done.stdout)
                    self.assertEqual(previous, fragment.read_bytes() if fragment.exists() else None)
                    self.assertEqual(b"SYNTHETIC_EXISTING_DATABASE" if clearing else None,
                                     database.read_bytes() if database.exists() else None)

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
                    "cis_ubuntu24_profile_tag": "level1-server",
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
            config.write_text("[defaults]\nroles_path=" + str(root / "roles") + ":" + str(ROOT / "roles") + "\n")
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
            vendor_role = root / "roles/ansible-lockdown.ubuntu24_cis/tasks"
            vendor_role.mkdir(parents=True)
            (vendor_role / "main.yml").write_text(yaml.safe_dump([
                {"name": "Model vendor include-vars after admission", "ansible.builtin.include_vars": str(vendor),
                 "when": "not cis_ubuntu24_test_repeat | default(false)"},
                {"name": "Model vendor execution at its actual admitted path",
                 "ansible.builtin.command": {"argv": ["{{ audit_conf_dir }}/run_audit.sh"]}, "changed_when": False},
                {"name": "Model vendor generated variables at the actual bound path",
                 "ansible.builtin.copy": {"dest": "{{ audit_vars_path }}", "content": "fixture: true\n", "mode": "0600"}},
                {"ansible.builtin.meta": "end_host"},
            ]))
            main = yaml.safe_load((ROOT / "roles/cis_ubuntu24/tasks/main.yml").read_text())
            execution = next(task for block in main for task in block.get("block", [])
                             if task.get("name") == "Execute the audit with invocation-scoped admitted vendor parameters")
            for attempt in range(10):
                archive.write_bytes(original)
                git_config = checkout / ".git/config"
                original_config = git_config.read_text()
                if attempt in (6, 7):
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
                if attempt == 8:
                    subprocess.run(["git", "-C", str(checkout), "update-index", "--assume-unchanged", "run_audit.sh"],
                                   check=True)
                    entry.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n")
                    with tarfile.open(archive, "w:gz") as stream:
                        stream.add(checkout, arcname=checkout.name)
                    self.assertEqual(subprocess.check_output(["git", "-C", str(checkout), "status", "--porcelain"]), b"")
                if attempt == 9:
                    entry.write_text("#!/bin/sh\nexit 0\n")
                    subprocess.run(["git", "-C", str(checkout), "update-index", "--no-assume-unchanged", "run_audit.sh"],
                                   check=True)
                variables = {
                    "cis_ubuntu24_execution_mode": "audit",
                    # The pinned vendor does not load transport overrides. Test
                    # repeat/end_host normally; other cases inject hostile vars.
                    "cis_ubuntu24_test_repeat": attempt < 2,
                    "audit_conf_source": str(archive), "audit_conf_dest": str(root),
                    "cis_ubuntu24_audit_transport_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                    "cis_ubuntu24_audit_dependency": {"repository": "https://example.test/audit.git", "commit": commit},
                }
                tasks = [
                    {"ansible.builtin.include_role": {"name": "cis_ubuntu24", "tasks_from": "audit_archive"}},
                    {"ansible.builtin.include_role": {"name": "cis_ubuntu24", "tasks_from": "audit_variables"}},
                    execution,
                ]
                book = root / "play.yml"
                variables["audit_content"] = "archive"
                play = {"hosts": "all", "gather_facts": False, "vars": variables, "tasks": tasks}
                book.write_text(yaml.safe_dump([play, play] if attempt < 2 else [play]))
                extra = ({"audit_conf_dir": str(unchecked)} if attempt == 3 else
                         {"audit_content": "archive"} if attempt == 4 else
                         {"audit_vars_path": str(unchecked / "vars.yml")} if attempt == 5 else
                         {"cis_ubuntu24_audit_vendor_transport": {"content": "existing", "source": str(archive),
                            "destination": str(root), "directory": str(unchecked),
                            "variables": str(unchecked / "vars.yml")}} if attempt == 9 else {})
                command = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(book)]
                if extra:
                    command += ["--extra-vars", json.dumps(extra)]
                result = subprocess.run(command,
                                        env=env, capture_output=True, text=True, timeout=90)
                if attempt == 8:
                    self.assertFalse(marker.exists(), "Pinned revision admitted modified code hidden by the Git index")
                if attempt == 9:
                    self.assertFalse(marker.exists(), "Overridden private bindings admitted an unchecked vendor path")
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
                expected_entry = "#!/bin/sh\ntouch '" + str(marker) + "'\n" if attempt == 8 else "#!/bin/sh\nexit 0\n"
                self.assertEqual(entry.read_text(), expected_entry)
                if attempt < 2:
                    self.assertEqual(archive.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
