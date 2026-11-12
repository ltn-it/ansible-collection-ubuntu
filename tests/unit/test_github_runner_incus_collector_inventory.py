"""Real Root namespace-tree boundaries; no native Worker or authorization claim."""
from dataclasses import replace
import os
from pathlib import Path
import sys
import tempfile
from types import MappingProxyType
import unittest
from unittest.mock import patch

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import collector, installation  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class ClosedInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/run/proof")
        self.addCleanup(self.temporary.cleanup)
        self.runner = Path(self.temporary.name) / "stock"
        self.runner.mkdir(mode=0o700)
        for number in range(48):
            directory = self.runner / ("directory-" + str(number))
            directory.mkdir(mode=0o700)
            for index in range(6):
                path = directory / ("file-" + str(index))
                path.write_bytes(b"actual sealed-name fixture")
                path.chmod(0o600)
        self.link = self.runner / "stock-link"
        self.link.symlink_to("directory-0/file-0")
        self.runtime = self.runner / "_diag"
        self.runtime.mkdir(mode=0o700)
        fd = installation._open_directory(str(self.runner))
        try:
            files, directories, links, stamps, _, runtime = installation._inventory(
                fd, str(self.runner), hash_files=False, service_uid=os.getuid())
        finally:
            os.close(fd)
        trusted = {str(self.runner / path): installation.trusted_file(str(self.runner / path)) for path in files}
        self.proof = installation.InstallationProof(str(self.runner), None, None, None, None,
            MappingProxyType({path: value.sha256 for path, value in trusted.items()}),
            MappingProxyType({str(self.runner / name): target for name, target in links.items()}),
            tuple(str(self.runner / path) for path in directories), (str(self.runtime),),
            "/synthetic/manifest", "a" * 64, "b" * 64, "2.338.2", MappingProxyType(trusted),
            MappingProxyType({str(self.runner / path): stamps[path] for path in files}),
            MappingProxyType(stamps), MappingProxyType(runtime))
        self.root = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.root)

    def check(self, proof=None, uid=None):
        collector._view_inventory(self.root, collector._tree_layout(self.proof if proof is None else proof),
                                  os.getuid() if uid is None else uid)

    def test_fresh_existing_reader_scans_complete_tree_once_without_code_rehash(self):
        (self.runtime / "mutable-diagnostic-not-code").write_bytes(b"not executable evidence")
        with patch.object(installation, "_inventory", wraps=installation._inventory) as scan, \
                patch.object(installation, "_hash_file", side_effect=AssertionError("metadata scan only")):
            self.check()
        self.assertEqual(scan.call_count, 1)
        self.assertFalse(scan.call_args.kwargs["hash_files"])

    def test_same_call_layout_reuses_only_immutable_bindings_not_namespace_observations(self):
        layout = collector._tree_layout(self.proof)
        with patch.object(installation, "_inventory", wraps=installation._inventory) as scan:
            for _ in range(8): collector._view_inventory(self.root, layout, os.getuid())
        self.assertEqual(scan.call_count, 8)
        self.assertIs(layout.proof, self.proof)
        with self.assertRaises(TypeError): layout.links["foreign"] = "target"
        with self.assertRaises(Denied):
            collector._closure(0, None, replace(self.proof), None, {}, layout)
        with self.assertRaises(Denied): collector._view_inventory(self.root, object(), os.getuid())
        with self.assertRaises(Denied): collector._tree_layout(replace(self.proof, files=dict(self.proof.files)))
        Path(next(iter(self.proof.files))).chmod(0o400)
        with self.assertRaises(Denied): collector._view_inventory(self.root, layout, os.getuid())

    def test_all_leaves_use_parent_relative_fds_and_only_two_full_root_walks(self):
        opened, original = [], os.open
        def tracked(path, flags, *args, **kwargs):
            opened.append((path, flags, kwargs.get("dir_fd")))
            return original(path, flags, *args, **kwargs)
        with patch.object(collector, "_view", wraps=collector._view) as view, patch.object(os, "open", side_effect=tracked):
            self.check()
        self.assertEqual(view.call_count, 2)
        leaves = [path for path, _, parent in opened if parent is not None and path.startswith("file-")]
        self.assertEqual(len(leaves), len(self.proof.files))
        self.assertTrue(all("/" not in path for path in leaves))

    def test_missing_extra_or_replaced_closed_file_is_denied(self):
        path = Path(next(iter(self.proof.files)))
        path.unlink()
        with self.assertRaises(Denied): self.check()
        path.write_bytes(b"actual sealed-name fixture"); path.chmod(0o600)
        with self.assertRaises(Denied): self.check()
        extra = self.runner / "unexpected"; extra.write_bytes(b"not sealed")
        with self.assertRaises(Denied): self.check()

    def test_file_mode_inode_or_symlink_substitution_is_denied(self):
        path = Path(next(iter(self.proof.files)))
        path.chmod(0o400)
        with self.assertRaises(Denied): self.check()
        path.unlink(); path.symlink_to(self.link)
        with self.assertRaises(Denied): self.check()

    def test_wrong_link_or_runtime_owner_mode_is_denied(self):
        self.link.unlink(); self.link.symlink_to("directory-1/file-0")
        with self.assertRaises(Denied): self.check()
        self.link.unlink(); self.link.symlink_to("directory-0/file-0")
        with self.assertRaises(Denied): self.check(uid=os.getuid() + 1)
        self.runtime.chmod(0o755)
        with self.assertRaises(Denied): self.check()

    def test_missing_extra_or_inconsistent_proof_evidence_is_denied(self):
        path = next(iter(self.proof.files))
        bad = replace(self.proof.trusted_files[path], sha256="c" * 64)
        for proof in (replace(self.proof, tree_stamps=MappingProxyType({})),
                      replace(self.proof, runtime_stamps=MappingProxyType({})),
                      replace(self.proof, trusted_files=MappingProxyType({})),
                      replace(self.proof, file_stamps=MappingProxyType({})),
                      replace(self.proof, trusted_files=MappingProxyType({**self.proof.trusted_files, path: bad})),
                      replace(self.proof, directories=self.proof.directories + (str(self.runner / "not-sealed"),))):
            with self.subTest(proof=proof), self.assertRaises(Denied): self.check(proof)

    def test_shadow_root_or_directory_rename_cannot_validate_detached_fd(self):
        original = installation._inventory
        def detached(*args, **kwargs):
            value = original(*args, **kwargs)
            self.runner.rename(self.runner.with_name("detached-stock"))
            self.runner.mkdir(mode=0o700)
            return value
        with patch.object(installation, "_inventory", side_effect=detached):
            with self.assertRaises(Denied): self.check()

    def test_mutation_during_metadata_scan_is_not_a_stale_stamp_success(self):
        original = installation._regular
        changed = []
        path = Path(next(iter(self.proof.files)))
        def mutate(info, **kwargs):
            if not changed:
                changed.append(True)
                path.write_bytes(b"changed during fresh namespace scan")
            return original(info, **kwargs)
        with patch.object(installation, "_regular", side_effect=mutate):
            with self.assertRaises(Denied): self.check()
        self.assertTrue(changed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
