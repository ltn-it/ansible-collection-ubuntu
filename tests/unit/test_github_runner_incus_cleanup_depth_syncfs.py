import ctypes
import os
import stat
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / 'roles/github_runner/files'
sys.path.insert(0,str(FILES))
from incus_lease_issuer import cleanup_storage as old, installation
from incus_lease_issuer import cleanup_storage as candidate
from incus_lease_issuer.identity import Denied

@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Root Linux EE only")
class GuardedTraversalTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires private Root0700 /run/proof")
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'owned'; self.root.mkdir(mode=0o700)
        self.fd = os.open(self.root, installation.DIR_FLAGS); self.addCleanup(os.close, self.fd)

    def inventory(self):
        return old._inventory_tree(self.fd, time.monotonic() + 10, 1000)

    def test_real_statx_matches_pinned_fd_metadata_and_mount(self):
        (self.root / 'dir').mkdir()
        identity, mount = candidate._relative_metadata(self.fd, 'dir')
        fd = os.open(self.root / 'dir', installation.DIR_FLAGS)
        try:
            self.assertEqual(identity, old._identity(os.fstat(fd)))
            self.assertEqual(mount, old.storage_quota._mount_id(fd))
        finally: os.close(fd)

    def test_actual_removal_nested_hardlinks_symlinks_keeps_foreign_bytes(self):
        foreign = Path(self.temp.name) / 'foreign'; foreign.write_bytes(b'retain')
        (self.root / 'dir').mkdir(); (self.root / 'dir/file').write_bytes(b'own')
        (self.root / 'link').symlink_to(foreign)
        os.link(foreign, self.root / 'hardlink')
        result = candidate._remove_tree(self.fd, self.inventory(), time.monotonic() + 10)
        self.assertIsNone(result)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(foreign.read_bytes(), b'retain')


    def test_replaced_leaf_and_ancestor_deny(self):
        (self.root / 'dir').mkdir(); (self.root / 'dir/file').touch()
        inventory = self.inventory()
        (self.root / 'dir').rename(self.root / 'old'); (self.root / 'dir').mkdir()
        with self.assertRaises(Denied): candidate._remove_tree(self.fd, inventory, time.monotonic() + 10)
        self.assertTrue((self.root / 'old/file').exists())

    def test_cached_same_inode_bind_overmount_denies_and_closes(self):
        (self.root / 'dir').mkdir(); (self.root / 'dir/file').touch()
        inventory = self.inventory()
        cache = candidate._PinnedAncestry(self.fd, inventory[1], inventory[2])
        cache.directory(('dir',), time.monotonic() + 10)
        real = candidate._relative_metadata
        def overmount(parent, name):
            identity, mount = real(parent, name)
            return identity, mount + 1 if name == 'dir' else mount
        before = len(os.listdir('/proc/self/fd'))
        try:
            with mock.patch.object(candidate, '_relative_metadata', side_effect=overmount):
                with self.assertRaises(Denied): cache.directory(('dir',), time.monotonic() + 10)
        finally: cache.close()
        self.assertEqual(cache.fds, [])
        self.assertLess(len(os.listdir('/proc/self/fd')), before)

    def test_statx_missing_mask_unavailable_error_and_unknown_arch_deny(self):
        (self.root / 'file').touch()
        def missing_mask(fd, name, flags, mask, pointer):
            result = ctypes.cast(pointer, ctypes.POINTER(candidate._Statx)).contents
            result.mask = 0x7ff; result.mount_id = 1
            return 0
        for replacement in (None, lambda *args: -1, missing_mask):
            with mock.patch.object(candidate, '_STATX', replacement):
                with self.assertRaises(Denied): candidate._relative_metadata(self.fd, 'file')
        with mock.patch.object(candidate.platform, 'machine', return_value='unknown'):
            with self.assertRaises(Denied): candidate._relative_metadata(self.fd, 'file')

    def test_new_entry_and_budget_deny_without_fd_leak(self):
        (self.root / 'file').touch(); inventory = self.inventory()
        (self.root / 'new').touch()
        before = len(os.listdir('/proc/self/fd'))
        with self.assertRaisesRegex(Denied, 'cleanup-storage-new-entry'):
            candidate._remove_tree(self.fd, inventory, time.monotonic() + 10)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        with self.assertRaisesRegex(Denied, 'cleanup-storage-budget'):
            candidate._remove_tree(self.fd, self.inventory(), time.monotonic() - 1)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_depth257_denies_and_all_descriptors_close(self):
        cache = candidate._PinnedAncestry(self.fd, {():old._identity(os.fstat(self.fd))}, old.storage_quota._mount_id(self.fd))
        try:
            with self.assertRaisesRegex(Denied, 'cleanup-storage-depth'):
                cache.directory(('a',) * 257, time.monotonic() + 10)
        finally: cache.close()
        self.assertEqual(cache.fds, [])

    def test_depth256_positive_uses_at_most257_fds_and_closes_all(self):
        current = self.root
        for _ in range(256): current = current / 'a'; current.mkdir()
        inventory = self.inventory()
        before = len(os.listdir('/proc/self/fd'))
        cache = candidate._PinnedAncestry(self.fd, inventory[1], inventory[2])
        try:
            cache.directory(('a',) * 256, time.monotonic() + 10)
            self.assertEqual(len(cache.fds), 257)
        finally: cache.close()
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_mutation_exception_propagates_and_closes_all_cached_fds(self):
        (self.root / 'dir').mkdir(); (self.root / 'dir/file').touch()
        inventory = self.inventory(); before = len(os.listdir('/proc/self/fd'))
        with mock.patch.object(os, 'unlink', side_effect=OSError('synthetic-mutation-error')):
            with self.assertRaises(OSError):
                candidate._remove_tree(self.fd, inventory, time.monotonic() + 10)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        self.assertTrue((self.root / 'dir/file').exists())




    def test_modeled_child_durable_before_every_parent_rmdir(self):
        (self.root / 'a').mkdir(); (self.root / 'a/b').mkdir()
        (self.root / 'a/b/file').touch(); (self.root / 'a/other').touch()
        (self.root / 'c').mkdir(); (self.root / 'c/file').touch()
        inventory=self.inventory(); deleted=set(); durable=set(); barriers=[]
        original_children={str(p):{str(c) for c in p.iterdir()} for p in self.root.rglob('*') if p.is_dir()}
        real_unlink,real_rmdir,real_fsync=os.unlink,os.rmdir,os.fsync
        def path_at(name,fd):return str(Path(os.readlink('/proc/self/fd/'+str(fd)))/name)
        def unlink(name,*,dir_fd):
            p=path_at(name,dir_fd); real_unlink(name,dir_fd=dir_fd);deleted.add(p)
        def sync(fd):
            self.assertEqual(old._identity(os.fstat(fd)),inventory[1][()])
            durable.update(deleted);barriers.append(set(durable));return 0
        def rmdir(name,*,dir_fd):
            p=path_at(name,dir_fd)
            self.assertTrue(original_children[p] <= durable, p)
            real_rmdir(name,dir_fd=dir_fd);deleted.add(p)
        final=[]
        def fsync(fd):
            self.assertEqual(list(self.root.iterdir()),[]);final.append(True);return real_fsync(fd)
        with mock.patch.object(os,'unlink',side_effect=unlink),mock.patch.object(os,'rmdir',side_effect=rmdir),mock.patch.object(candidate,'_SYNCFS',side_effect=sync),mock.patch.object(os,'fsync',side_effect=fsync):
            result=candidate._remove_tree(self.fd,inventory,time.monotonic()+10)
        self.assertIsNone(result)
        self.assertEqual(len(barriers),2);self.assertEqual(final,[True])

    def test_sync_failure_stops_before_any_parent_rmdir_and_closes_fds(self):
        (self.root/'dir').mkdir();(self.root/'dir/file').touch();inventory=self.inventory()
        before=len(os.listdir('/proc/self/fd'))
        with mock.patch.object(candidate,'_SYNCFS',return_value=-1),mock.patch.object(os,'rmdir',side_effect=AssertionError('parent removed before successful barrier')):
            with self.assertRaisesRegex(Denied,'cleanup-storage-syncfs-denied'):
                candidate._remove_tree(self.fd,inventory,time.monotonic()+10)
        self.assertTrue((self.root/'dir').exists())
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_unsupported_syncfs_and_old_kernel_deny_before_any_unlink(self):
        (self.root/'file').touch();inventory=self.inventory()
        for override in (mock.patch.object(candidate,'_SYNCFS',None),mock.patch.object(candidate.platform,'release',return_value='5.4.0')):
            with override,mock.patch.object(os,'unlink',side_effect=AssertionError('mutation before capability qualification')):
                with self.assertRaises(Denied):candidate._remove_tree(self.fd,inventory,time.monotonic()+10)
        self.assertTrue((self.root/'file').exists())

    def test_barrier_over_deadline_denies_before_parent_rmdir(self):
        (self.root/'dir').mkdir();(self.root/'dir/file').touch();inventory=self.inventory();now=[100.0]
        def sync(fd):now[0]=161.0;return 0
        with mock.patch.object(candidate,'_SYNCFS',side_effect=sync),mock.patch.object(time,'monotonic',side_effect=lambda:now[0]),mock.patch.object(os,'rmdir',side_effect=AssertionError('late parent removal')):
            with self.assertRaisesRegex(Denied,'cleanup-storage-budget'):
                candidate._remove_tree(self.fd,inventory,160.0)
        self.assertTrue((self.root/'dir').exists())

    def test_failure_between_depth_barriers_never_removes_unsynced_parent(self):
        (self.root/'a').mkdir();(self.root/'a/b').mkdir();(self.root/'a/b/file').touch()
        inventory=self.inventory();before=len(os.listdir('/proc/self/fd'))
        with mock.patch.object(candidate,'_SYNCFS',side_effect=[0,-1]):
            with self.assertRaisesRegex(Denied,'cleanup-storage-syncfs-denied'):
                candidate._remove_tree(self.fd,inventory,time.monotonic()+10)
        self.assertTrue((self.root/'a').exists())
        self.assertFalse((self.root/'a/b').exists())
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_installed_product_real_fixture_and_none_return(self):
        (self.root/'a').mkdir();(self.root/'a/file').touch()
        self.assertIsNone(candidate._remove_tree(self.fd,self.inventory(),time.monotonic()+10))
        self.assertEqual(list(self.root.iterdir()),[])

    def test_syncfs_root_identity_drift_denies_before_any_mutation(self):
        (self.root/'file').touch();inventory=self.inventory()
        with mock.patch.object(candidate.storage_quota,'_mount_id',return_value=inventory[2]+1), \
             mock.patch.object(os,'unlink',side_effect=AssertionError('mutation before mount proof')):
            with self.assertRaises(Denied):candidate._remove_tree(self.fd,inventory,time.monotonic()+10)
        self.assertTrue((self.root/'file').exists())

if __name__ == '__main__': unittest.main(verbosity=2)
