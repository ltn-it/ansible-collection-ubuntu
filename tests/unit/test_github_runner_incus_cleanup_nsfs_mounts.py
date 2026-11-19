"""Kernel nsfs mount roots remain typed tokens, never filesystem aliases."""
from pathlib import Path
import os
import tempfile
import time
from types import SimpleNamespace
from unittest import mock
import sys
import unittest

FILES = Path(__file__).resolve().parents[2] / 'roles/github_runner/files'
sys.path.insert(0, str(FILES))
from incus_lease_issuer import cleanup_storage as subject
from incus_lease_issuer.identity import Denied


class NamespaceMountRows(unittest.TestCase):
    def row(self, root='net:[4026532529]', filesystem='nsfs', device='0:4', point='/run/netns/test'):
        return f'87 36 {device} {root} {point} rw - {filesystem} nsfs rw\n'.encode()

    def test_actual_stacked_namespace_rows_are_preserved(self):
        raw = self.row() + self.row().replace(b'87 ', b'88 ', 1)
        rows = subject._consumer_mount_rows(raw)
        self.assertEqual([row[0] for row in rows], [87, 88])
        self.assertEqual([row[2] for row in rows], ['net:[4026532529]'] * 2)
        subject._consumer_mount_aliases(rows, [(1792, '/private', '/', '/')])

    def test_namespace_token_cannot_be_selected_as_original_filesystem_root(self):
        rows = subject._consumer_mount_rows(self.row())
        with self.assertRaises(Denied):
            subject._consumer_mount_targets(rows, [('/run/netns/test', rows[0][1], 87)])

    def test_non_path_root_requires_exact_namespace_filesystem_and_device(self):
        for values in [{'filesystem': 'ext4'}, {'device': '8:1'}, {'device': '0:0'},
                       {'root': 'foreign:[1]'}, {'root': 'net:[0]'}, {'root': 'net:[1]/x'},
                       {'root': '../escape'}, {'point': 'net:[1]'}]:
            with self.subTest(values=values), self.assertRaises(Denied):
                subject._consumer_mount_rows(self.row(**values))

    def test_ordinary_filesystem_alias_still_holds(self):
        raw = b'10 1 8:1 / /srv/quota rw - ext4 /dev/test rw\n'
        rows = subject._consumer_mount_rows(raw)
        targets = subject._consumer_mount_targets(rows, [('/srv/quota/raw', rows[0][1], 10)])
        alias = subject._consumer_mount_rows(b'11 1 8:1 /raw /alias rw - ext4 /dev/test rw\n')
        with self.assertRaises(Denied):
            subject._consumer_mount_aliases(alias, targets)

    def test_duplicate_mount_id_and_malformed_tail_hold(self):
        for raw in [self.row() * 2, self.row().rstrip() + b' extra\n']:
            with self.assertRaises(Denied):
                subject._consumer_mount_rows(raw)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Linux Root proc walk")
class NamespaceMountConsumerWalk(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = {"engine": {"storage_root": str(self.root / "graph"), "runroot": str(self.root / "run")},
                     "output_path": str(self.root / "output"), "context_path": str(self.root / "context")}

    def observe(self, forbidden=None):
        subject._no_consumers(self.data, str(self.root / "descriptor"), "fixture-unowned",
                              [], time.monotonic() + 10, set(), [], forbidden_namespace=forbidden)

    def append_namespace(self, raw):
        # Only the mountinfo input is modeled; the process/task/FD/map walk
        # still observes real private-container proc resources.
        identifier = max(int(row.split()[0]) for row in raw.splitlines()) + 1
        return raw + f"{identifier} 1 0:4 net:[4026532529] /unrelated/ns-alias rw - nsfs nsfs rw\n".encode()

    def test_exact_namespace_identity_holds_despite_unrelated_mountpoint_and_storage_device(self):
        actual = subject._consumer_read
        def read(path, limit, end):
            raw = actual(path, limit, end)
            return self.append_namespace(raw) if path.name == "mountinfo" else raw
        with mock.patch.object(subject, "_consumer_read", side_effect=read):
            self.observe()
            self.observe((4, 4026532530))
            with self.assertRaisesRegex(Denied, "namespace-mount-reference"):
                self.observe((4, 4026532529))

    def test_invalid_namespace_coordinates_hold_before_any_proc_scan(self):
        for value in [(True, 1), (4, True), (0, 1), (4, 0), (4,), [4, 1], (os.makedev(8, 1), 1), (4, 2**63)]:
            with self.subTest(value=value), self.assertRaisesRegex(Denied, "forbidden-namespace"):
                self.observe(value)

    def test_every_task_mount_view_is_observed_in_shared_and_distinct_namespaces(self):
        readfd, writefd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(writefd)
            os.read(readfd, 1)
            os._exit(0)
        os.close(readfd)
        actual_read, actual_stat = subject._consumer_read, Path.stat
        target = f"/proc/{child}/task/{child}/ns/mnt"
        initial = actual_stat(Path(target))
        def stat(path, *args, **kwargs):
            if str(path) == target:
                return SimpleNamespace(st_dev=initial.st_dev, st_ino=initial.st_ino + 10000000)
            return actual_stat(path, *args, **kwargs)
        def read(path, limit, end):
            raw = actual_read(path, limit, end)
            if str(path) == f"/proc/{child}/task/{child}/mountinfo":
                identifier = max(int(row.split()[0]) for row in raw.splitlines()) + 2
                point = self.data["engine"]["storage_root"]
                mount = f"{identifier} 1 8:1 / {point} rw - ext4 /dev/test rw\n".encode()
                return self.append_namespace(raw) + mount
            return raw
        try:
            # Only the later task sees the extra mount in its root-relative view.
            for task_stat in (actual_stat, stat):
                with self.subTest(shared=task_stat is actual_stat), mock.patch.object(Path, "stat", task_stat), \
                     mock.patch.object(subject, "_consumer_read", side_effect=read):
                    with self.assertRaisesRegex(Denied, "namespace-mount-reference"):
                        self.observe((4, 4026532529))
                    with self.assertRaisesRegex(Denied, "cleanup-consumers-mount-reference"):
                        self.observe()
        finally:
            os.close(writefd)
            os.waitpid(child, 0)
