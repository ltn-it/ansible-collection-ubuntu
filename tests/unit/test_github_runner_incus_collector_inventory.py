"""Real Root namespace-tree boundaries; no native Worker or authorization claim."""
from contextlib import contextmanager
from dataclasses import replace
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import MappingProxyType
import unittest
from unittest.mock import patch

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import collector, installation  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux UID0 EE only")
class ClosedInventoryTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir():
            self.skipTest("pre-provision /run/proof as private tmpfs in the isolated EE")
        info = base.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            self.skipTest("/run/proof must be root-owned0700, no test owner exception")
        self.temporary = tempfile.TemporaryDirectory(dir=base)
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
        with patch.object(collector.os, "scandir", wraps=os.scandir) as scan, \
                patch.object(installation, "_hash_file", side_effect=AssertionError("metadata scan only")):
            self.check()
        self.assertEqual(scan.call_count, 1 + len(self.proof.directories))

    def test_same_call_layout_reuses_only_immutable_bindings_not_namespace_observations(self):
        layout = collector._tree_layout(self.proof)
        with patch.object(collector.os, "scandir", wraps=os.scandir) as scan:
            for _ in range(8): collector._view_inventory(self.root, layout, os.getuid())
        self.assertEqual(scan.call_count, 8 * (1 + len(self.proof.directories)))
        self.assertIs(layout.proof, self.proof)
        with self.assertRaises(TypeError): layout.links["foreign"] = "target"
        with self.assertRaises(Denied):
            collector._closure(0, None, replace(self.proof), None, {}, layout)
        with self.assertRaises(Denied): collector._view_inventory(self.root, object(), os.getuid())
        with self.assertRaises(Denied): collector._tree_layout(replace(self.proof, files=dict(self.proof.files)))
        Path(next(iter(self.proof.files))).chmod(0o400)
        with self.assertRaises(Denied): collector._view_inventory(self.root, layout, os.getuid())

    def test_lookup_is_immutable_and_bound_to_exact_sealed_categories_and_stamps(self):
        layout = collector._tree_layout(self.proof)
        expected = {}
        for path in self.proof.files:
            name = str(Path(path).relative_to(self.runner))
            expected[name] = ("file", self.proof.tree_stamps[name], None)
        for path in self.proof.directories:
            name = str(Path(path).relative_to(self.runner))
            expected[name] = ("directory", self.proof.tree_stamps[name], None)
        for path, target in self.proof.symlinks.items():
            name = str(Path(path).relative_to(self.runner))
            expected[name] = ("link", self.proof.tree_stamps[name], target)
        expected["_diag"] = ("runtime", self.proof.runtime_stamps["_diag"], None)
        self.assertEqual(dict(layout.entries), expected)
        with self.assertRaises(TypeError): layout.entries["foreign"] = ("file", (), None)
        with self.assertRaises(TypeError): layout.entries["_diag"][0] = "file"
        self.assertIs(layout.entries["_diag"][1], self.proof.runtime_stamps["_diag"])
        self.assertIs(layout.proof, self.proof)

    def test_overlapping_proof_categories_deny_before_any_namespace_read(self):
        path = next(iter(self.proof.files))
        relative = str(Path(path).relative_to(self.runner))
        cases = (replace(self.proof, directories=self.proof.directories + (path,)),
                 replace(self.proof, symlinks=MappingProxyType({**self.proof.symlinks, path: "directory-0/file-0"})),
                 replace(self.proof, runtime_directories=self.proof.runtime_directories + (path,),
                         runtime_stamps=MappingProxyType({**self.proof.runtime_stamps, relative: (1, 2, 3, 4, 5)})))
        for proof in cases:
            with self.subTest(proof=proof), patch.object(collector, "_view", side_effect=AssertionError("must deny proof first")):
                with self.assertRaisesRegex(Denied, "process-root-tree-evidence"):
                    self.check(proof)

    def test_each_directory_keeps_both_initial_fstats_and_every_leaf_fd_observation(self):
        events = []
        originals = {name: getattr(os, name) for name in ("open", "close", "stat", "fstat", "lseek")}
        def track(name):
            def call(*args, **kwargs):
                result = originals[name](*args, **kwargs)
                events.append((name, args, kwargs, result if name == "open" else None))
                return result
            return call
        from contextlib import ExitStack
        with ExitStack() as stack:
            for name in originals: stack.enter_context(patch.object(os, name, side_effect=track(name)))
            self.check()
        seeks = [index for index, event in enumerate(events) if event[0] == "lseek"]
        self.assertEqual(len(seeks), 1 + len(self.proof.directories))
        for index in seeks:
            fd = events[index][1][0]
            self.assertEqual([(event[0], event[1]) for event in events[index-2:index]],
                             [("fstat", (fd,)), ("fstat", (fd,))])
        leaves = [(index, event) for index, event in enumerate(events) if event[0] == "open"
                  and isinstance(event[1][0], str) and event[1][0].startswith("file-")]
        self.assertEqual(len(leaves), len(self.proof.files))
        for index, event in leaves:
            fd = event[3]
            self.assertEqual(events[index-1][0], "stat")
            self.assertEqual((events[index+1][0], events[index+1][1]), ("fstat", (fd,)))
            self.assertEqual((events[index+2][0], events[index+2][1]), ("close", (fd,)))

    def test_duplicate_fresh_directory_membership_denies_without_reusing_observation(self):
        original = os.scandir
        @contextmanager
        def duplicate(fd):
            with original(fd) as entries:
                values = list(entries)
                yield iter(values + values[:1])
        with patch.object(collector.os, "scandir", side_effect=duplicate):
            with self.assertRaisesRegex(Denied, "process-root-inventory-mismatch"):
                self.check()

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
        original = os.scandir
        root_identity = self.runner.stat().st_ino
        @contextmanager
        def detached(fd):
            with original(fd) as entries:
                yield entries
            if os.fstat(fd).st_ino == root_identity:
                self.runner.rename(self.runner.with_name("detached-stock"))
                self.runner.mkdir(mode=0o700)
        with patch.object(collector.os, "scandir", side_effect=detached):
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
