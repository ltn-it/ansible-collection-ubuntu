"""First-use namespace-parent reads stay before the journaled IP effect."""
from pathlib import Path
import os
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import installation, network_fence

class FirstIP(BaseException):
    """Stop exactly before the modeled first mutating command."""

@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "requires Linux Root fixture")
class NamespaceParentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = Path(self.temp.name) / "run"
        self.run.mkdir(mode=0o755)
        self.module = network_fence
        self.calls = []
        self.namespace = "lit-lease-" + "a" * 32

    def attempt(self, command_failure=False):
        def directory(path):
            mapped = {"/run": self.run, "/run/netns": self.run / "netns"}
            if path not in mapped: raise AssertionError("unexpected directory read")
            fd = os.open(mapped[path], installation.DIR_FLAGS)
            try: installation._directory(os.fstat(fd))
            except BaseException:
                os.close(fd)
                raise
            return fd
        class Store:
            def begin(inner, lease, operation, target):
                self.calls.append(("journal", operation))
                return "modeled-effect-id"
            def record(inner, lease, effect, state, **kwargs):
                self.calls.append(("record", state))
        def first(policy, program, argv, **kwargs):
            self.assertEqual(self.calls, [("journal", "fence-create")])
            self.assertEqual(program, self.module.IP)
            self.assertEqual(argv, ["netns", "add", self.namespace])
            self.calls.append(("first-IP", tuple(argv)))
            if command_failure: raise self.module.Denied("fence-command-denied")
            raise FirstIP()
        policy = SimpleNamespace(host="192.0.2.1/30", backend="192.0.2.9")
        prepared = SimpleNamespace(lease_id="a" * 32)
        with mock.patch.object(self.module.installation, "_open_directory", directory), \
             mock.patch.object(self.module, "_bound_policy", return_value=policy), \
             mock.patch.object(self.module, "_fresh"), \
             mock.patch.object(self.module, "_backend"), \
             mock.patch.object(self.module, "_names", return_value=(self.namespace,"host","peer","table")), \
             mock.patch.object(self.module, "_ip", return_value=[]), \
             mock.patch.object(self.module, "_run", side_effect=first):
            self.module.create("/model/policy", "0" * 64, prepared, Store(), object(), object())

    def test_missing_leaf_reaches_journal_before_first_IP(self):
        with self.assertRaises(FirstIP): self.attempt()
        self.assertFalse((self.run / "netns").exists())

    def test_existing_trusted_parent_reaches_same_effect(self):
        (self.run / "netns").mkdir(mode=0o755)
        (self.run / "netns" / "unrelated").touch()
        with self.assertRaises(FirstIP): self.attempt()
        self.assertTrue((self.run / "netns" / "unrelated").exists())

    def test_late_create_conflict_stays_one_unknown_journaled_effect(self):
        with self.assertRaisesRegex(self.module.FenceUnknown, "fence-effect-unknown"):
            self.attempt(command_failure=True)
        self.assertEqual(self.calls[0], ("journal", "fence-create"))
        self.assertEqual(sum(row[0] == "first-IP" for row in self.calls), 1)
        self.assertEqual(self.calls[-1], ("record", "unknown"))
        self.assertFalse((self.run / "netns").exists())

    def test_nonroot_existing_parent_denied(self):
        leaf = self.run / "netns"; leaf.mkdir(mode=0o755)
        inode = leaf.stat().st_ino
        original = installation._directory
        def changed_owner(info):
            if info.st_ino == inode:
                info = SimpleNamespace(st_mode=info.st_mode, st_uid=1001)
            return original(info)
        with mock.patch.object(self.module.installation, "_directory", side_effect=changed_owner):
            with self.assertRaisesRegex(ValueError, "installation-untrusted-directory"): self.attempt()
        self.assertEqual(self.calls, [])

    def test_duplicate_namespace_denied_before_intent(self):
        (self.run / "netns").mkdir(mode=0o755)
        (self.run / "netns" / self.namespace).touch()
        with self.assertRaisesRegex(ValueError, "fence-namespace-exists"): self.attempt()
        self.assertEqual(self.calls, [])

    def test_symlink_parent_denied_before_intent(self):
        target = self.run / "elsewhere"; target.mkdir()
        (self.run / "netns").symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError): self.attempt()
        self.assertEqual(self.calls, [])

    def test_file_parent_denied_before_intent(self):
        (self.run / "netns").touch()
        with self.assertRaises(NotADirectoryError): self.attempt()
        self.assertEqual(self.calls, [])

    def test_untrusted_existing_parent_denied(self):
        (self.run / "netns").mkdir(mode=0o755)
        (self.run / "netns").chmod(0o777)
        with self.assertRaisesRegex(ValueError, "installation-untrusted-directory"): self.attempt()
        self.assertEqual(self.calls, [])

    def test_missing_run_ancestor_not_treated_as_leaf_absence(self):
        self.run.rmdir()
        with self.assertRaises(FileNotFoundError): self.attempt()
        self.assertEqual(self.calls, [])

    def test_permission_error_not_treated_as_absence(self):
        original = os.open
        def denied(path, *args, **kwargs):
            if path == "netns": raise PermissionError("modeled leaf denial")
            return original(path, *args, **kwargs)
        with mock.patch.object(self.module.os, "open", side_effect=denied):
            with self.assertRaises(PermissionError): self.attempt()
        self.assertEqual(self.calls, [])

if __name__ == "__main__": unittest.main(verbosity=2)
