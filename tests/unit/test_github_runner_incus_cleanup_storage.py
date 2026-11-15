"""Actual bounded FD deletion in private EE; no native finalization proof."""
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import cleanup_storage as cleanup, installation  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class StorageBoundaryTests(unittest.TestCase):
    def test_public_factories_have_no_job_path_or_proof_overrides(self):
        for operation in (cleanup.release_engine, cleanup.delete_context):
            for extra in ({"path": "/foreign"}, {"qualified": True}, {"reader": lambda: None}):
                with self.assertRaises(TypeError):
                    operation(None, None, None, **extra)
            with self.assertRaises(Denied):
                operation(None, None, None)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Root Linux EE only")
class RootDeletionPrimitiveTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires private Root0700 /run/proof")
        temporary = tempfile.TemporaryDirectory(prefix="storage-delete-", dir=base)
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.tree = self.base / "owned"
        self.tree.mkdir(mode=0o700)
        self.fd = os.open(self.tree, installation.DIR_FLAGS)
        self.addCleanup(os.close, self.fd)

    def inventory(self, maximum=100):
        return cleanup._inventory_tree(self.fd, time.monotonic() + 5, maximum)

    def remove(self, inventory):
        cleanup._remove_tree(self.fd, inventory, time.monotonic() + 5)

    def test_only_owned_entries_unlinked_links_never_followed_and_outside_data_remains(self):
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        marker = outside / "retained.txt"
        marker.write_bytes(b"outside-owned-tree")
        (self.tree / "nested").mkdir(mode=0o700)
        (self.tree / "nested/file").write_bytes(b"own raw state")
        (self.tree / "link").symlink_to(outside, target_is_directory=True)
        os.link(marker, self.tree / "own-hardlink")
        self.remove(self.inventory())
        self.assertEqual(os.listdir(self.fd), [])
        self.assertEqual(marker.read_bytes(), b"outside-owned-tree")
        self.assertEqual(marker.stat().st_nlink, 1)

    def test_replaced_ancestor_denies_before_deleting_replacement_or_original(self):
        child = self.tree / "nested"
        child.mkdir(mode=0o700)
        (child / "file").write_bytes(b"original")
        inventory = self.inventory()
        retained = self.base / "retained-original"
        child.rename(retained)
        child.mkdir(mode=0o700)
        (child / "file").write_bytes(b"replacement")
        with self.assertRaisesRegex(Denied, "directory-replaced"):
            self.remove(inventory)
        self.assertEqual((child / "file").read_bytes(), b"replacement")
        self.assertEqual((retained / "file").read_bytes(), b"original")

    def test_replaced_leaf_is_never_unlinked_by_old_inventory(self):
        leaf = self.tree / "file"
        leaf.write_bytes(b"original")
        inventory = self.inventory()
        leaf.rename(self.base / "original")
        leaf.write_bytes(b"replacement")
        with self.assertRaisesRegex(Denied, "entry-replaced"):
            self.remove(inventory)
        self.assertEqual(leaf.read_bytes(), b"replacement")

    def test_new_entry_is_retained_and_cannot_turn_partial_deletion_into_success(self):
        (self.tree / "original").write_bytes(b"original")
        inventory = self.inventory()
        (self.tree / "new-entry").write_bytes(b"new")
        with self.assertRaisesRegex(Denied, "new-entry"):
            self.remove(inventory)
        self.assertFalse((self.tree / "original").exists())
        self.assertEqual((self.tree / "new-entry").read_bytes(), b"new")

    def test_entry_budget_and_elapsed_deadline_deny_before_any_deletion(self):
        for index in range(3):
            (self.tree / str(index)).write_bytes(b"owned")
        with self.assertRaisesRegex(Denied, "entry-limit"):
            self.inventory(maximum=2)
        with self.assertRaisesRegex(Denied, "budget"):
            cleanup._inventory_tree(self.fd, time.monotonic() - 1, 100)
        with cleanup._fresh_entries(self.fd) as entries:
            self.assertEqual(len(list(entries)), 3)

    def test_same_device_foreign_mount_id_is_not_accepted(self):
        leaf = self.tree / "file"
        leaf.write_bytes(b"owned")
        inode = leaf.stat().st_ino
        original = cleanup.storage_quota._mount_id
        def mount_id(fd):
            actual = original(fd)
            return actual + 1 if os.fstat(fd).st_ino == inode else actual
        with mock.patch.object(cleanup.storage_quota, "_mount_id", side_effect=mount_id):
            with self.assertRaisesRegex(Denied, "foreign-mount"):
                self.inventory()
        self.assertEqual(leaf.read_bytes(), b"owned")

    def test_149119_actual_entries_use_depth_barrier_and_final_root_fsync(self):
        """Real tmpfs deletion/count regression, NOT native Source timing."""
        directories, files = 128, 149119 - 128
        for index in range(directories):
            parent = self.tree / ("layer-" + str(index))
            parent.mkdir(mode=0o700)
            count = files // directories + (index < files % directories)
            for leaf in range(count):
                fd = os.open(parent / str(leaf), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
        end = time.monotonic() + 60
        inventory = cleanup._inventory_tree(self.fd, end, 149119)
        self.assertEqual(len(inventory[0]), 149119)
        actual_fsync, actual_syncfs = os.fsync, cleanup._SYNCFS
        barriers, final = [], []
        def barrier(fd):
            self.assertEqual(os.fstat(fd).st_ino,os.fstat(self.fd).st_ino)
            barriers.append(True)
            return actual_syncfs(fd)
        def final_barrier(fd):
            self.assertEqual(os.listdir(fd),[])
            final.append(True);actual_fsync(fd)
        with mock.patch.object(cleanup,'_SYNCFS',side_effect=barrier), \
             mock.patch.object(cleanup.os,'fsync',side_effect=final_barrier):
            cleanup._remove_tree(self.fd,inventory,end)
        self.assertEqual(os.listdir(self.fd),[])
        self.assertEqual(barriers,[True]);self.assertEqual(final,[True])

    def test_child_removals_durable_before_parent_rmdir_and_root_barrier_last(self):
        paths=[self.tree/'a',self.tree/'a/nested',self.tree/'b']
        for path in paths:
            path.mkdir(mode=0o700);(path/'file').write_bytes(b'owned')
        (self.tree/'file').write_bytes(b'owned')
        children={str(path):{str(x)for x in path.iterdir()}for path in paths}
        deleted,durable,events=set(),set(),[]
        actual_unlink,actual_rmdir,actual_fsync=os.unlink,os.rmdir,os.fsync
        def located(name,fd):return str(Path(os.readlink('/proc/self/fd/'+str(fd)))/name)
        def unlink(name,*,dir_fd):
            value=located(name,dir_fd);actual_unlink(name,dir_fd=dir_fd);deleted.add(value)
        def barrier(fd):
            durable.update(deleted);events.append('syncfs');return 0
        def remove(name,*,dir_fd):
            value=located(name,dir_fd);self.assertTrue(children[value]<=durable)
            actual_rmdir(name,dir_fd=dir_fd);deleted.add(value);events.append('rmdir')
        def final(fd):
            self.assertEqual(os.listdir(fd),[]);events.append('root-fsync');actual_fsync(fd)
        with mock.patch.object(cleanup,'_SYNCFS',side_effect=barrier), \
             mock.patch.object(cleanup.os,'unlink',side_effect=unlink), \
             mock.patch.object(cleanup.os,'rmdir',side_effect=remove), \
             mock.patch.object(cleanup.os,'fsync',side_effect=final):
            self.remove(self.inventory())
        self.assertEqual(events[-1],'root-fsync');self.assertEqual(events.count('syncfs'),2)

    def test_deadline_after_child_barrier_denies_before_rmdir(self):
        child = self.tree / "child"; child.mkdir(mode=0o700)
        (child / "file").write_bytes(b"owned")
        inventory = self.inventory()
        now, actual_syncfs = [1.0], cleanup._SYNCFS
        def barrier(fd):
            result=actual_syncfs(fd)
            now[0] = 3.0
            return result
        with mock.patch.object(cleanup, "_SYNCFS", new=barrier), \
             mock.patch.object(cleanup.time, "monotonic", new=lambda: now[0]):
            with self.assertRaisesRegex(Denied, "cleanup-storage-budget"):
                cleanup._remove_tree(self.fd, inventory, 2.0)
        self.assertTrue(child.is_dir())
        self.assertEqual(list(child.iterdir()), [])

    def test_depth_writeback_failure_denies_before_parent_removal(self):
        child = self.tree / "child"; child.mkdir(mode=0o700)
        (child / "file").write_bytes(b"owned")
        inventory = self.inventory()
        with mock.patch.object(cleanup, "_SYNCFS", return_value=-1):
            with self.assertRaisesRegex(Denied,'cleanup-storage-syncfs-denied'): self.remove(inventory)
        self.assertTrue(child.is_dir())
        self.assertEqual(list(child.iterdir()), [])

    def test_mount_drift_after_inventory_denies_before_any_delete(self):
        child = self.tree / "child"; child.mkdir(mode=0o700)
        leaf = child / "file"; leaf.write_bytes(b"owned")
        inventory = self.inventory()
        original, inode = cleanup.storage_quota._mount_id, child.stat().st_ino
        def mounted(fd):
            actual = original(fd)
            return actual + 1 if os.fstat(fd).st_ino == inode else actual
        with mock.patch.object(cleanup.storage_quota, "_mount_id", side_effect=mounted):
            with self.assertRaisesRegex(Denied, "directory-replaced"):
                self.remove(inventory)
        self.assertEqual(leaf.read_bytes(), b"owned")

    def test_real_relative_statx_identity_and_mount_match_pinned_fd(self):
        (self.tree / "directory").mkdir(mode=0o700)
        identity, mount = cleanup._relative_metadata(self.fd, "directory")
        child = os.open(self.tree / "directory", installation.DIR_FLAGS)
        try:
            self.assertEqual(identity, cleanup._identity(os.fstat(child)))
            self.assertEqual(mount, cleanup.storage_quota._mount_id(child))
        finally:
            os.close(child)

    def test_cached_same_inode_overmount_is_denied_before_use_and_all_fds_close(self):
        # Model the otherwise privileged bind-overmount boundary only. Real
        # native MNT_ID support is exercised separately; this is no mount grant.
        (self.tree / "directory").mkdir(mode=0o700)
        (self.tree / "directory/file").touch()
        inventory = self.inventory()
        cache = cleanup._PinnedAncestry(self.fd, inventory[1], inventory[2])
        cache.directory(("directory",), time.monotonic() + 10)
        real = cleanup._relative_metadata
        def overmount(parent, name):
            identity, mount = real(parent, name)
            return identity, mount + 1 if name == "directory" else mount
        before = len(os.listdir("/proc/self/fd"))
        try:
            with mock.patch.object(cleanup, "_relative_metadata", side_effect=overmount):
                with self.assertRaises(Denied):cache.directory(("directory",), time.monotonic() + 10)
        finally:
            cache.close()
        self.assertEqual(cache.fds, [])
        self.assertLess(len(os.listdir("/proc/self/fd")), before)
        self.assertTrue((self.tree / "directory/file").exists())

    def test_statx_unavailable_missing_mount_mask_unknown_arch_and_native_error_fail_closed(self):
        import ctypes
        (self.tree / "file").touch()
        def no_mount_mask(fd, name, flags, mask, pointer):
            value = ctypes.cast(pointer, ctypes.POINTER(cleanup._Statx)).contents
            value.mask, value.mount_id = 0x7ff, 1
            return 0
        for replacement in (None, lambda *args: -1, no_mount_mask):
            with mock.patch.object(cleanup, "_STATX", replacement):
                with self.assertRaises(Denied):cleanup._relative_metadata(self.fd, "file")
        with mock.patch.object(cleanup.platform, "machine", return_value="unknown"):
            with self.assertRaises(Denied):cleanup._relative_metadata(self.fd, "file")

    def test_depth256_uses_at_most257_fds_then_closes_and_depth257_denies(self):
        current = self.tree
        for _ in range(256):current = current / "a";current.mkdir(mode=0o700)
        inventory = cleanup._inventory_tree(self.fd, time.monotonic() + 10, 1000)
        before = len(os.listdir("/proc/self/fd"))
        cache = cleanup._PinnedAncestry(self.fd, inventory[1], inventory[2])
        try:
            cache.directory(("a",) * 256, time.monotonic() + 10)
            self.assertEqual(len(cache.fds), 257)
            with self.assertRaises(Denied):cache.directory(("a",) * 257, time.monotonic() + 10)
        finally:
            cache.close()
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_unlink_failure_propagates_and_closes_all_cached_descriptors(self):
        (self.tree / "directory").mkdir(mode=0o700)
        (self.tree / "directory/file").touch()
        inventory = self.inventory()
        before = len(os.listdir("/proc/self/fd"))
        with mock.patch.object(cleanup.os, "unlink", side_effect=OSError("synthetic-owned-unlink-failure")):
            with self.assertRaises(OSError):self.remove(inventory)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)
        self.assertTrue((self.tree / "directory/file").exists())


if __name__ == "__main__":
    unittest.main()
