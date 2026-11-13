"""Real Linux FS tests; root success cases require an isolated /run/proof tmpfs.

Do not run these root fixtures on a host. Production root/ownership checks are
never mocked or bypassed. Fake package bytes prove only inventory verification,
not a genuine downloaded runner, running-code trust or operating authority.
"""
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import installation  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class ProductionRootGuardTests(unittest.TestCase):
    def test_nonroot_cannot_supply_an_owner_override_or_own_manifest(self):
        if os.geteuid() == 0:
            self.skipTest("run the production root guard separately in the nonroot EE")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            manifest = path / "manifest.json"
            manifest.write_text("{}")
            manifest.chmod(0o600)
            policy = installation.InstallationPolicy(str(path), str(manifest), 61, os.geteuid())
            with self.assertRaises(Denied):
                installation.verify_installation(policy)
            with self.assertRaises(Denied):
                installation.trusted_file(str(manifest))


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux UID0 EE only")
class RootInstallationFilesystemTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir():
            self.skipTest("pre-provision /run/proof as private tmpfs in the isolated EE")
        info = base.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            self.skipTest("/run/proof must be root-owned0700, no test owner exception")
        self.directory = tempfile.TemporaryDirectory(prefix="installation-", dir=base)
        self.parent = Path(self.directory.name)
        self.addCleanup(self.cleanup_fixture)
        self.root = self.parent / "runner"
        self.root.mkdir(mode=0o755)
        self.runtime = self.root / "_diag"
        self.runtime.mkdir(mode=0o700)
        os.chown(self.runtime, 2101, 2101)
        self.manifest = self.parent / "manifest.json"
        for relative in sorted(installation.REQUIRED_DIRECTORIES):
            (self.root / relative).mkdir(parents=True, exist_ok=True, mode=0o755)
        for relative in installation.REQUIRED_FILES:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            path.write_bytes(b"synthetic-package-bytes:" + relative.encode())
            path.chmod(0o644 if relative in {".runner", "bin/RunnerService.js"} else 0o755)
        self.settings({"agentId": 61, "agentName": "fixture", "disableUpdate": True})
        self.policy = installation.InstallationPolicy(str(self.root), str(self.manifest), 61, 2101)
        self.write_manifest()

    def cleanup_fixture(self):
        # Namespace-only CHOWN/FOWNER suffices even when DAC_OVERRIDE is absent.
        # Restore fixture directories before TemporaryDirectory traverses them.
        def restore(path):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                return
            os.chown(path, 0, 0)
            if stat.S_ISDIR(info.st_mode):
                path.chmod(0o700)
                for child in path.iterdir():
                    restore(child)

        if self.parent.exists():
            restore(self.parent)
        self.directory.cleanup()

    def settings(self, value):
        (self.root / ".runner").write_text(json.dumps(value))
        (self.root / ".runner").chmod(0o644)

    def inventory_manifest(self):
        files, directories, links = {}, [], {}

        def walk(directory):
            for path in sorted(directory.iterdir()):
                if path == self.runtime:
                    continue
                relative = str(path.relative_to(self.root))
                if path.is_symlink():
                    links[relative] = os.readlink(path)
                elif path.is_dir():
                    directories.append(relative)
                    walk(path)
                else:
                    files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()

        walk(self.root)
        return {"schema": 1, "runner_id": 61, "service_uid": 2101, "runner_version": "2.338.2",
                "package_sha256": "a" * 64,
                "files": files, "directories": directories, "symlinks": links,
                "runtime_directories": {"_diag": {"uid": 2101, "mode": 448}}}

    def write_manifest(self, value=None):
        value = self.inventory_manifest() if value is None else value
        self.manifest.write_text(json.dumps(value))
        self.manifest.chmod(0o600)

    def deny(self, policy=None):
        with self.assertRaises(Denied):
            installation.verify_installation(self.policy if policy is None else policy)

    def test_root_closed_inventory_returns_immutable_root_acquired_specs(self):
        proof = installation.verify_installation(self.policy)
        self.assertEqual(proof.runner_root, str(self.root))
        self.assertEqual(proof.main.path, "/usr/bin/bash")
        self.assertEqual(proof.main.argv, ("/bin/bash", str(self.root / "runsvc.sh")))
        self.assertEqual(proof.node.argv, ("./externals/node24/bin/node", "./bin/RunnerService.js"))
        self.assertEqual(proof.node.path, str(self.root / "externals/node24/bin/node"))
        self.assertEqual(proof.runner_version, "2.338.2")
        self.assertEqual(proof.listener.argv, (str(self.root / "bin/Runner.Listener"),
                                              "run", "--startuptype", "service"))
        self.assertEqual(proof.worker.argv, ())
        self.assertEqual(proof.worker.inode, (self.root / "bin/Runner.Worker").stat().st_ino)
        self.assertEqual(proof.files[str(self.root / ".runner")],
                         hashlib.sha256((self.root / ".runner").read_bytes()).hexdigest())
        self.assertEqual(set(proof.trusted_files), set(proof.files))
        self.assertEqual(set(proof.file_stamps), set(proof.files))
        for path, trusted in proof.trusted_files.items():
            self.assertEqual(trusted, installation.trusted_file(path))
            self.assertEqual(proof.file_stamps[path], installation._stamp(Path(path).stat()))
        self.assertEqual(proof.package_sha256, "a" * 64)
        self.assertEqual(dict(proof.symlinks), {})
        self.assertEqual(proof.runtime_directories, (str(self.runtime),))
        self.assertNotIn(str(self.runtime), proof.directories)
        with self.assertRaises(TypeError):
            proof.files["/foreign"] = "b" * 64
        with self.assertRaises(FrozenInstanceError):
            proof.runner_root = "/foreign"

    def test_manifest_is_root_private_regular_single_link_not_symlink(self):
        self.manifest.chmod(0o640)
        self.deny()
        self.manifest.chmod(0o600)
        outside = self.parent / "manifest-link"
        os.link(self.manifest, outside)
        self.deny()
        outside.unlink()
        self.manifest.rename(outside)
        self.manifest.symlink_to(outside)
        self.deny()

    def test_user_owned_manifest_is_denied_even_with_matching_hashes(self):
        os.chown(self.manifest, 2101, 2101)
        self.deny()

    def test_user_owned_installation_or_file_is_not_retroactively_trusted(self):
        os.chown(self.root / "bin/Runner.Worker", 2101, 2101)
        self.deny()
        os.chown(self.root / "bin/Runner.Worker", 0, 0)
        os.chown(self.root, 2101, 2101)
        self.deny()

    def test_writable_file_directory_and_ancestor_deny(self):
        target = self.root / "bin/RunnerService.js"
        target.chmod(0o664)
        self.deny()
        target.chmod(0o644)
        (self.root / "bin").chmod(0o777)
        self.deny()
        (self.root / "bin").chmod(0o755)
        self.parent.chmod(0o777)
        self.deny()
        self.parent.chmod(0o700)

    def test_symlink_file_directory_and_root_are_denied(self):
        path = self.root / "bin/Runner.Worker"
        outside = self.parent / "worker"
        path.rename(outside)
        path.symlink_to(outside)
        self.deny()
        path.unlink()
        outside.rename(path)
        binary_dir = self.parent / "bin"
        (self.root / "bin").rename(binary_dir)
        (self.root / "bin").symlink_to(binary_dir, target_is_directory=True)
        self.deny()
        (self.root / "bin").unlink()
        binary_dir.rename(self.root / "bin")
        link = self.parent / "linked-root"
        link.symlink_to(self.root, target_is_directory=True)
        self.deny(replace(self.policy, root=str(link)))

    def test_hardlinked_code_file_is_denied(self):
        os.link(self.root / "bin/Runner.Listener", self.parent / "shared-listener")
        self.deny()

    def stock_js_link(self):
        target = self.root / "externals/node24/lib/node_modules/npm/bin/npm-cli.js"
        target.parent.mkdir(parents=True, mode=0o755)
        target.write_bytes(b"synthetic stock JS with package-relative __dirname")
        target.chmod(0o644)
        link = self.root / "externals/node24/bin/npm"
        literal = "../lib/node_modules/npm/bin/npm-cli.js"
        link.symlink_to(literal)
        return link, target, literal

    def test_manifest_bound_internal_stock_js_symlink_is_preserved_not_dereferenced(self):
        link, target, literal = self.stock_js_link()
        self.write_manifest()
        proof = installation.verify_installation(self.policy)
        self.assertEqual(proof.symlinks[str(link)], literal)
        self.assertNotIn(str(link), proof.files)
        self.assertIn(str(target), proof.files)
        self.assertEqual(os.readlink(link), literal)
        with self.assertRaises(TypeError):
            proof.symlinks[str(link)] = "foreign.js"
        with self.assertRaises(Denied):
            installation.trusted_file(str(link))

    def test_symlink_absolute_escape_runtime_chain_and_oversize_targets_deny(self):
        link, target, literal = self.stock_js_link()
        for value in (str(target), "../../../../../../outside", "../../../_diag/log.js",
                      "absent/../npm", "x" * 1025):
            with self.subTest(target=value):
                link.unlink()
                link.symlink_to(value)
                self.write_manifest()
                self.deny()
        link.unlink()
        link.symlink_to(literal)
        alias = self.root / "externals/node24/bin/npm-alias"
        alias.symlink_to("npm")
        self.write_manifest()
        self.deny()

    def test_symlink_user_owner_tamper_missing_extra_and_manifest_collision_deny(self):
        link, target, literal = self.stock_js_link()
        alternate = target.with_name("npx-cli.js")
        alternate.write_bytes(b"different package entry")
        self.write_manifest()
        original = self.inventory_manifest()
        os.chown(link, 2101, 2101, follow_symlinks=False)
        self.deny()
        os.chown(link, 0, 0, follow_symlinks=False)
        hardlink = self.parent / "hardlinked-symlink"
        os.link(link, hardlink, follow_symlinks=False)
        self.deny()
        hardlink.unlink()
        link.unlink()
        link.symlink_to("../lib/node_modules/npm/bin/npx-cli.js")
        self.deny()
        link.unlink()
        self.deny()
        link.symlink_to(literal)
        extra = link.with_name("unlisted-link")
        extra.symlink_to(literal)
        self.deny()
        extra.unlink()
        self.write_manifest({**original, "files": {**original["files"], str(link.relative_to(self.root)): "b" * 64}})
        self.deny()
        self.write_manifest({**original, "directories": original["directories"] + [str(link.relative_to(self.root))]})
        self.deny()

    def test_special_file_does_not_block_or_become_an_inventory_entry(self):
        os.mkfifo(self.root / "fifo", mode=0o600)
        self.deny()

    def test_missing_and_unlisted_extra_entries_deny(self):
        path = self.root / "bin/Runner.Worker"
        saved = path.read_bytes()
        path.unlink()
        self.deny()
        path.write_bytes(saved)
        path.chmod(0o755)
        (self.root / "unexpected.dll").write_bytes(b"extra")
        self.deny()

    def test_no_unlisted_or_writable_runtime_directory_exception(self):
        runtime = self.root / "_work"
        runtime.mkdir(mode=0o755)
        self.deny()
        self.write_manifest()
        os.chown(runtime, 2101, 2101)
        self.deny()

    def append_log(self, value):
        # FOWNER is scoped to the isolated test namespace. Temporarily enable
        # other-write for the test writer, then restore the required0700 before
        # verification; production verification never relaxes permissions.
        self.runtime.chmod(0o707)
        try:
            with (self.runtime / "untrusted.log").open("ab") as stream:
                stream.write(value)
        finally:
            self.runtime.chmod(0o700)

    def test_mutable_diag_log_append_is_not_immutable_code_evidence(self):
        before = installation.verify_installation(self.policy)
        self.append_log(b"first untrusted log\n")
        self.assertEqual(before, installation.verify_installation(self.policy))
        self.append_log(b"later untrusted log\n")
        after = installation.verify_installation(self.policy)
        self.assertEqual(before, after)
        self.assertFalse(any(path.startswith(str(self.runtime) + "/") for path in after.files))
        with self.assertRaises(Denied):
            installation.trusted_file(str(self.runtime / "untrusted.log"))

    def test_runtime_directory_wrong_uid_mode_missing_and_symlink_deny(self):
        self.runtime.chmod(0o755)
        self.deny()
        self.runtime.chmod(0o700)
        os.chown(self.runtime, 0, 0)
        self.deny()
        os.chown(self.runtime, 2101, 2101)
        self.runtime.rmdir()
        self.deny()
        target = self.parent / "other-runtime"
        target.mkdir(mode=0o700)
        os.chown(target, 2101, 2101)
        self.runtime.symlink_to(target, target_is_directory=True)
        self.deny()

    def test_only_exact_declared_diag_exception_and_no_immutable_runtime_code(self):
        original = self.inventory_manifest()
        for runtime in ({}, {"_work": {"uid": 2101, "mode": 448}},
                        {"_diag": {"uid": 0, "mode": 448}},
                        {"_diag": {"uid": 2101, "mode": 493}},
                        {"_diag": {"uid": 2101, "mode": 448, "extra": True}},
                        {"../_diag": {"uid": 2101, "mode": 448}}):
            with self.subTest(runtime=runtime):
                self.write_manifest({**original, "runtime_directories": runtime})
                self.deny()
        self.write_manifest({**original, "files": {**original["files"], "_diag/plugin.py": "b" * 64}})
        self.deny()
        self.write_manifest({**original, "directories": original["directories"] + ["_diag"]})
        self.deny()

    def test_listed_optional_startup_files_pass_and_unlisted_files_deny(self):
        (self.root / ".env").write_bytes(b"SAFE_SYNTHETIC=1\n")
        (self.root / ".path").write_bytes(b"/usr/bin\n")
        self.deny()
        self.write_manifest()
        proof = installation.verify_installation(self.policy)
        self.assertIn(str(self.root / ".env"), proof.files)
        self.assertIn(str(self.root / ".path"), proof.files)
        (self.root / ".path").chmod(0o666)
        self.deny()

    def test_optional_startup_directory_is_not_treated_as_absent(self):
        (self.root / ".env").mkdir(mode=0o755)
        self.write_manifest()
        self.deny()

    def test_file_hash_tamper_and_nonexecutable_worker_deny(self):
        path = self.root / "bin/Runner.Worker"
        path.write_bytes(b"changed bytes")
        self.deny()
        self.write_manifest()
        path.chmod(0o644)
        self.deny()

    def test_registered_agent_id_and_disabled_update_are_required_without_aliases(self):
        for settings in ({"agentId": 62, "disableUpdate": True},
                         {"agentId": True, "disableUpdate": True},
                         {"runnerId": 61, "disableUpdate": True},
                         {"agentId": 61, "disableUpdate": "true"},
                         {"agentId": 61},
                         {"agentId": 61, "disableUpdate": True, "DisableUpdate": False}):
            with self.subTest(settings=settings):
                self.settings(settings)
                self.write_manifest()
                self.deny()

    def test_manifest_schema_bindings_paths_and_hashes_are_strict(self):
        original = self.inventory_manifest()
        for key, value in (("schema", True), ("runner_id", 62), ("service_uid", True),
                           ("package_sha256", "A" * 64), ("extra", 1)):
            changed = {**original, key: value}
            self.write_manifest(changed)
            self.deny()
        for relative in ("../outside", "/outside", "bin//extra", "bin/./extra"):
            changed = {**original, "files": {**original["files"], relative: "b" * 64}}
            self.write_manifest(changed)
            self.deny()
        self.write_manifest({**original, "directories": original["directories"] + ["bin"]})
        self.deny()

    def test_policy_and_manifest_require_exact_supported_runner_version(self):
        self.assertEqual(self.policy.runner_version, "2.338.2")
        for version in ("2.335.1", "2.338.3", "latest", None, True):
            with self.subTest(policy_version=version):
                self.deny(replace(self.policy, runner_version=version))
        value = self.inventory_manifest()
        value.pop("runner_version")
        self.write_manifest(value)
        self.deny()
        for version in ("2.335.1", "2.338.3", None, True):
            with self.subTest(manifest_version=version):
                self.write_manifest({**self.inventory_manifest(), "runner_version": version})
                self.deny()

    def test_duplicate_and_nonfinite_json_are_denied(self):
        self.manifest.write_bytes(b'{"schema":1,"schema":1}')
        self.deny()
        self.manifest.write_bytes(b'{"schema":NaN}')
        self.deny()
        self.manifest.write_bytes(b'{"schema":1e999}')
        self.deny()
        (self.root / ".runner").write_bytes(b'{"agentId":61,"disableUpdate":true,"disableUpdate":false}')
        self.write_manifest()
        self.deny()

    def test_policy_paths_and_manifest_location_have_no_normalization_bypass(self):
        self.deny(replace(self.policy, root=str(self.root) + "/../runner"))
        self.deny(replace(self.policy, root=str(self.root) + "/"))
        self.deny(replace(self.policy, manifest_path=str(self.root / "manifest.json")))
        self.deny(replace(self.policy, service_uid=True))

    def test_file_changed_after_hash_is_caught_by_whole_tree_confirmation(self):
        original = installation._hash_file
        changed = False

        def mutate(fd, path, *args, **kwargs):
            nonlocal changed
            result = original(fd, path, *args, **kwargs)
            if path == str(self.root / "bin/Runner.Listener") and not changed:
                changed = True
                Path(path).write_bytes(b"replacement after first hash")
            return result

        with mock.patch.object(installation, "_hash_file", side_effect=mutate):
            self.deny()
        self.assertTrue(changed)

    def test_manifest_changed_during_inventory_is_not_used_as_a_stale_policy(self):
        original = installation._inventory
        changed = False

        def mutate(*args, **kwargs):
            nonlocal changed
            result = original(*args, **kwargs)
            if not changed:
                changed = True
                value = self.inventory_manifest()
                value["package_sha256"] = "b" * 64
                self.write_manifest(value)
            return result

        with mock.patch.object(installation, "_inventory", side_effect=mutate):
            self.deny()

    def test_root_safe_file_helper_hashes_and_denies_nonregular_links(self):
        path = self.root / "bin/Runner.Worker"
        proof = installation.trusted_file(str(path))
        self.assertEqual(proof.inode, path.stat().st_ino)
        self.assertEqual(proof.sha256, hashlib.sha256(path.read_bytes()).hexdigest())
        with self.assertRaises(Denied):
            installation.trusted_file(str(path), max_bytes=1)
        with self.assertRaises(Denied):
            installation.trusted_file(str(self.root))


if __name__ == "__main__":
    unittest.main()
