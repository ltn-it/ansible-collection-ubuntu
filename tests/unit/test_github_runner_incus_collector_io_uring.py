"""Closed Node kernel-data contract; syscall metadata fixtures are not native proof."""
from dataclasses import replace
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import collector  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


def rows(inode, *, permissions="rw-s", device="00:0f", label="anon_inode:[io_uring]"):
    return (f"1000-2000 {permissions} 0 {device} {inode} {label}\n"
            f"3000-4000 {permissions} 10000000 {device} {inode} {label}\n").encode()


class IoUringMapsTests(unittest.TestCase):
    def test_three_retained_objects_same_kernel_name_stay_distinct_and_sorted(self):
        mapped = collector.parse_maps(rows(33) + rows(11) + rows(22), role="node")
        self.assertEqual([value.inode for value in mapped], [11, 22, 33])
        self.assertTrue(all(value.io_uring and not value.jit
                            and value.offsets == (0, 0x10000000) for value in mapped))

    def test_ring_is_only_managed_node_nonexecuting_exact_offsets_and_kernel_label(self):
        for role in (None, "listener", "worker", "arbitrary"):
            with self.subTest(role=role), self.assertRaises(Denied):
                collector.parse_maps(rows(11), role=role)
        for bad in (rows(11, permissions="r-xs"), rows(11, permissions="rw-p"),
                    rows(11, device="08:01"), rows(11, label="anon_inode:[eventfd]"),
                    rows(11, label="/memfd:io_uring (deleted)"),
                    rows(11).replace(b"10000000", b"8000000"),
                    rows(11).splitlines(keepends=True)[0], rows(11) + rows(11)):
            with self.subTest(mapping=bad), self.assertRaises(Denied):
                collector.parse_maps(bad, role="node")

    def test_normal_file_backing_and_dotnet_jit_guards_remain_closed(self):
        with self.assertRaises(Denied):
            collector.parse_maps(b"1000-2000 r-xp 0 08:01 11 /usr/lib/a.so\n"
                                 b"3000-4000 r-xp 0 08:01 22 /usr/lib/a.so\n", role="node")
        with self.assertRaises(Denied):
            collector.parse_maps(b"1000-2000 rw-s 0 00:01 33 /memfd:doublemapper (deleted)\n",
                                 role="node")


class IoUringBackingTests(unittest.TestCase):
    def setUp(self):
        self.mapping = collector.parse_maps(rows(33), role="node")[0]
        self.info = SimpleNamespace(st_dev=os.makedev(0, 15), st_ino=33, st_mode=0o600,
                                    st_uid=995, st_gid=983, st_nlink=1, st_size=0)

    def prove(self, *, held=None, aliases=None, links=None, mapping=None):
        held = self.info if held is None else held
        aliases = [self.info, self.info] if aliases is None else aliases
        links = [collector.IO_URING_NAME, collector.IO_URING_NAME] if links is None else links
        scan = unittest.mock.MagicMock()
        scan.__enter__.return_value = iter([SimpleNamespace(name="4")])
        with patch.object(collector.os, "open", side_effect=[50, 51]) as opened, \
                patch.object(collector.os, "close") as closed, \
                patch.object(collector.os, "scandir", return_value=scan), \
                patch.object(collector.os, "readlink", side_effect=links), \
                patch.object(collector.os, "stat", side_effect=aliases), \
                patch.object(collector.os, "fstat", side_effect=[held, held]), \
                patch.object(collector.os, "read", side_effect=AssertionError("no ring-data read")):
            result = collector._retained_io_uring(17, self.mapping if mapping is None else mapping, 995, 983)
        self.assertEqual(opened.call_args_list[1].args, ("4", os.O_PATH | os.O_CLOEXEC))
        self.assertEqual(opened.call_args_list[1].kwargs, {"dir_fd": 50})
        self.assertEqual([call.args for call in closed.call_args_list], [(51,), (50,)])
        return result

    def test_kernel_type_zero_exact_owned_opath_backing_is_observed_not_read(self):
        self.assertEqual(self.prove(), (self.info.st_dev, 33, 0o600, 995, 983, 1, 0))

    def test_fake_regular_file_or_foreign_metadata_is_not_kernel_ring(self):
        for change in ({"st_mode": stat.S_IFREG | 0o600}, {"st_mode": stat.S_IFSOCK | 0o600},
                       {"st_mode": 0o666}, {"st_uid": 0}, {"st_gid": 0}, {"st_nlink": 0},
                       {"st_size": 1}, {"st_ino": 44}, {"st_dev": os.makedev(0, 16)}):
            with self.subTest(change=change), self.assertRaises(Denied):
                self.prove(held=SimpleNamespace(**{**vars(self.info), **change}))

    def test_alias_or_kernel_label_replacement_denies(self):
        changed = SimpleNamespace(**{**vars(self.info), "st_ino": 44})
        with self.assertRaises(Denied):
            self.prove(aliases=[self.info, changed])
        with self.assertRaises(Denied):
            self.prove(links=[collector.IO_URING_NAME, "anon_inode:[eventfd]"])
        with self.assertRaises(Denied):
            self.prove(aliases=[changed])
        with self.assertRaises(Denied):
            self.prove(mapping=replace(self.mapping, offsets=(0,)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
