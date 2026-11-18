"""Fresh FD tree walks retain byte/owner/name binding without ancestor reopens."""
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'roles/github_runner/files'))
from incus_lease_issuer import engine_policy as engine, generation_publisher as publisher, installation
from incus_lease_issuer.identity import Denied


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'private Root Linux EE only')
class FreshTreeWalkTests(unittest.TestCase):
    def setUp(self):
        base = Path('/run/proof')
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest('private Root0700 /run/proof required')
        self.temp = tempfile.TemporaryDirectory(prefix='fresh-tree-', dir=base)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.tree = self.base / 'tree'; self.tree.mkdir(mode=0o700)
        (self.tree / 'a').mkdir(mode=0o700); (self.tree / 'a/b').mkdir(mode=0o700)
        self.files = {}
        for name in ('one', 'a/two', 'a/b/three'):
            raw = ('fresh bytes ' + name).encode()
            path = self.tree / name; path.write_bytes(raw); path.chmod(0o600)
            self.files[name] = hashlib.sha256(raw).hexdigest()
        self.value = {'path': str(self.tree), 'files': self.files, 'directories': ['a', 'a/b']}

    def test_same_public_inventory_and_generation_stamps_with_bounded_root_opens(self):
        with patch.object(installation, '_open_directory', wraps=installation._open_directory) as opened:
            result = publisher._inventory(self.tree)
        self.assertEqual(2, opened.call_count)
        self.assertEqual({'path': str(self.tree), 'files': self.files, 'directories': ['a', 'a/b']}, engine._tree(self.value))
        expected = {}
        for name in ('a', 'a/b'):
            info = (self.tree / name).stat()
            expected[name] = {'kind': 'directory', 'device': info.st_dev, 'inode': info.st_ino}
        for name in self.files:
            proof, _, stamp = installation._file(str(self.tree / name), publisher.MAX_TOTAL)
            expected[name] = {'kind': 'file', 'sha256': proof.sha256, 'stamp': list(stamp)}
        self.assertEqual(expected, result)

    def test_every_new_walk_rehashes_changed_bytes(self):
        before = publisher._inventory(self.tree)
        engine._tree(self.value)
        (self.tree / 'a/two').write_bytes(b'changed bytes')
        with self.assertRaisesRegex(Denied, 'engine-file-drift'): engine._tree(self.value)
        self.assertNotEqual(before, publisher._inventory(self.tree))

    def test_replaced_file_after_open_cannot_keep_old_fd_authority(self):
        for kind in ('engine', 'generation'):
            with self.subTest(kind=kind):
                original = installation._hash_file
                fired = []
                def changed(fd, path, *args, **kwargs):
                    result = original(fd, path, *args, **kwargs)
                    if path.endswith('/one') and not fired:
                        fired.append(True)
                        replacement = self.base / 'replacement'
                        replacement.write_bytes(b'new named inode'); replacement.chmod(0o600)
                        os.replace(replacement, self.tree / 'one')
                    return result
                with patch.object(installation, '_hash_file', side_effect=changed), self.assertRaises(Denied):
                    engine._tree(self.value) if kind == 'engine' else publisher._inventory(self.tree)
                self.assertTrue(fired)
                (self.tree / 'one').write_bytes(b'fresh bytes one')

    def test_replaced_subdirectory_between_stat_and_open_is_rejected(self):
        original = os.open
        for kind in ('engine', 'generation'):
            with self.subTest(kind=kind):
                fired = []
                def changed(path, flags, *args, **kwargs):
                    if path == 'a' and kwargs.get('dir_fd') is not None and not fired:
                        fired.append(True)
                        (self.tree / 'a').rename(self.base / 'old-a')
                        (self.tree / 'a').mkdir(mode=0o700)
                    return original(path, flags, *args, **kwargs)
                with patch.object(os, 'open', side_effect=changed), self.assertRaises(Denied):
                    engine._tree(self.value) if kind == 'engine' else publisher._inventory(self.tree)
                self.assertTrue(fired)
                (self.tree / 'a').rmdir(); (self.base / 'old-a').rename(self.tree / 'a')

    def test_replaced_root_after_hash_is_rejected_before_result(self):
        original = installation._hash_file
        for kind in ('engine', 'generation'):
            with self.subTest(kind=kind):
                fired = []
                def changed(fd, path, *args, **kwargs):
                    result = original(fd, path, *args, **kwargs)
                    if not fired:
                        fired.append(True)
                        self.tree.rename(self.base / 'old-root'); self.tree.mkdir(mode=0o700)
                    return result
                with patch.object(installation, '_hash_file', side_effect=changed), self.assertRaises(Denied):
                    engine._tree(self.value) if kind == 'engine' else publisher._inventory(self.tree)
                self.assertTrue(fired)
                self.tree.rmdir(); (self.base / 'old-root').rename(self.tree)


if __name__ == '__main__':
    unittest.main()
