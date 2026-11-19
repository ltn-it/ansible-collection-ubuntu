"""Thread table identity is distinct from a time-separated FD snapshot."""
from pathlib import Path
import sys
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import cleanup_storage, network_fence as fence

class ThreadTableTests(unittest.TestCase):
    def probe(self, sharing, tables=()):
        with mock.patch.object(cleanup_storage, "_same_fd_table", side_effect=sharing) as compare, \
             mock.patch.object(fence, "_fd_table", side_effect=tables) as read, \
             mock.patch.object(fence.os, "open", return_value=123) as opened, \
             mock.patch.object(fence.os, "close") as closed:
            fence._thread_file_table_drained(99, 102, 100, 123.5)
        return compare, read, opened, closed

    def test_shared_kernel_table_uses_existing_complete_leader_inventory(self):
        compare, read, opened, closed = self.probe([True, True])
        self.assertEqual(compare.call_args_list, [mock.call(102, 100), mock.call(102, 100)])
        read.assert_not_called()
        opened.assert_not_called()
        closed.assert_not_called()

    def test_independent_table_requires_two_complete_empty_observations(self):
        compare, read, opened, closed = self.probe([False, False], [{}, {}])
        self.assertEqual(compare.call_count, 2)
        self.assertEqual(read.call_args_list, [mock.call(123, 123.5), mock.call(123, 123.5)])
        opened.assert_called_once_with("fd", fence.engine.DIR, dir_fd=99)
        closed.assert_called_once_with(123)

    def test_either_nonempty_private_table_holds_even_if_it_could_match_leader(self):
        for tables in ([{7: (1, 2, 3)}], [{}, {7: (1, 2, 3)}]):
            with self.subTest(tables=tables), self.assertRaisesRegex(fence.Denied, "fence-thread-private-fds-live"):
                self.probe([False, False], tables)

    def test_both_sharing_transitions_hold(self):
        for sharing in ([True, False], [False, True]):
            with self.subTest(sharing=sharing), self.assertRaisesRegex(fence.Denied, "fence-thread-fd-table-changed"):
                self.probe(sharing, [{}, {}])

    def test_unknown_comparison_or_disappearing_task_never_falls_back_to_snapshot_equality(self):
        for sharing in ([PermissionError()], [ProcessLookupError()],
                        [True, PermissionError()], [False, ProcessLookupError()]):
            with self.subTest(sharing=sharing), self.assertRaises(OSError):
                self.probe(sharing, [{}, {}])

    def test_untyped_or_malformed_comparison_holds(self):
        for sharing in ([0], [None], [True, 1], [False, 0]):
            with self.subTest(sharing=sharing), self.assertRaises(fence.Denied):
                self.probe(sharing, [{}, {}])

    def test_failed_private_table_read_closes_only_its_owned_descriptor(self):
        with mock.patch.object(cleanup_storage, "_same_fd_table", return_value=False), \
             mock.patch.object(fence, "_fd_table", side_effect=FileNotFoundError()), \
             mock.patch.object(fence.os, "open", return_value=123), \
             mock.patch.object(fence.os, "close") as close:
            with self.assertRaises(FileNotFoundError):
                fence._thread_file_table_drained(99, 102, 100, 123.5)
            close.assert_called_once_with(123)

if __name__ == "__main__":
    unittest.main()
