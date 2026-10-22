"""Filesystem and loaded-mode boundary tests; no kernel policy loading."""

import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[2] / "roles/cis_ubuntu24/files/apparmor_profile_guard.py"
SPEC = importlib.util.spec_from_file_location("apparmor_profile_guard", SOURCE)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class ProfileGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.profiles = self.root / "profiles"
        self.profiles.mkdir(mode=0o755)
        self.kernel = self.root / "kernel-profiles"
        self.kernel.write_text("podman (unconfined)\ncrun (unconfined)\ncontainer-default (enforce)\n")
        self.policy = []
        for name in ("podman", "crun"):
            text = f"profile {name} /usr/bin/{name} flags=(unconfined) {{\n  userns,\n}}\n"
            path = self.profiles / name
            path.write_text(text)
            path.chmod(0o644)
            self.policy.append({"name": name, "executable": "/usr/bin/" + name,
                                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                "reason": "Synthetic package-compatible fixture only.",
                                "approval_reference": "TEST-FIXTURE-NOT-A-PRODUCTION-APPROVAL"})

    def verify(self, **extra):
        return GUARD.verify(self.policy, self.profiles, self.kernel,
                            owner_uid=os.getuid(), owner_gid=os.getgid(), **extra)

    def test_exact_policy_is_read_only_and_repeatable(self):
        before = {p.name: p.read_bytes() for p in self.profiles.iterdir()}
        result = self.verify()
        self.assertEqual(result, self.verify())
        self.assertEqual(result["other_enforcing_profiles"], 1)
        self.assertTrue(result["benchmark_exception_not_pass"])
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.profiles.iterdir()})

    def test_rejects_undeclared_non_enforcing_modes(self):
        for mode in ("unconfined", "complain", "kill", "mixed"):
            with self.subTest(mode=mode):
                self.kernel.write_text(f"podman (unconfined)\ncrun (unconfined)\nforeign ({mode})\n")
                with self.assertRaisesRegex(ValueError, "Undeclared non-enforcing"):
                    self.verify()

    def test_rejects_missing_changed_duplicate_or_malformed_kernel_profiles(self):
        for text in ("", "podman (unconfined)\n", "podman (enforce)\ncrun (unconfined)\n",
                     "podman (unconfined)\ncrun (unconfined)\npodman (unconfined)\n", "invalid inventory\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.kernel.write_text(text)
                self.verify()

    def test_rejects_file_hash_and_mode_drift(self):
        path = self.profiles / "podman"
        path.write_text(path.read_text() + "# drift\n")
        with self.assertRaisesRegex(ValueError, "hash drift"):
            self.verify()
        self.policy[0]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        path.chmod(0o666)
        with self.assertRaisesRegex(ValueError, "profile mode"):
            self.verify()

    def test_rejects_symlinks_hardlinks_and_directory_redirection(self):
        path = self.profiles / "podman"
        saved = self.root / "saved"
        path.rename(saved)
        path.symlink_to(saved)
        with self.assertRaises(OSError):
            self.verify()
        path.unlink()
        os.link(saved, path)
        with self.assertRaisesRegex(ValueError, "Unsafe profile object"):
            self.verify()
        alias = self.root / "alias"
        alias.symlink_to(self.profiles)
        with self.assertRaisesRegex(ValueError, "Redirected profile directory"):
            GUARD.verify(self.policy, alias, self.kernel, os.getuid(), os.getgid())

    def test_rejects_unsafe_directory_or_owner(self):
        self.profiles.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "Writable profile directory"):
            self.verify()
        self.profiles.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "directory ownership"):
            GUARD.verify(self.policy, self.profiles, self.kernel, os.getuid() + 1, os.getgid())

    def test_rejects_wrong_attachment_or_missing_permission_even_with_matching_hash(self):
        path = self.profiles / "podman"
        for text in ("profile podman /usr/bin/other flags=(unconfined) {\n userns,\n}\n",
                     "profile podman /usr/bin/podman flags=(unconfined) {\n}\n"):
            with self.subTest(text=text):
                path.write_text(text)
                self.policy[0]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                with self.assertRaises(ValueError):
                    self.verify()

    def test_rejects_invalid_policy_shapes_paths_and_metadata(self):
        invalid = [None, {}, [], ["podman"], self.policy + [self.policy[0]]]
        for key, value in (("name", "../podman"), ("executable", "/usr/bin/a/../podman"),
                           ("sha256", "0" * 63), ("reason", "bad\nreason"),
                           ("approval_reference", ""), ("unknown", "field")):
            policy = copy.deepcopy(self.policy)
            policy[0][key] = value
            invalid.append(policy)
        for policy in invalid:
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                GUARD.validate_policy(policy)


if __name__ == "__main__":
    unittest.main()
