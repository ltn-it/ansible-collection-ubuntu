"""Canonical subid validation, without changing host files or accounts."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / 'roles/github_runner/files'
sys.path.insert(0, str(FILES))
from incus_lease_issuer import engine_executor as executor  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class SubidReservationTests(unittest.TestCase):
    def check_ranges(self, uid_rows, gid_rows=None, *, uid_accounts=(), gid_accounts=()):
        details = {'uid_map': {'host_base': 1000000, 'size': 65536},
                   'gid_map': {'host_base': 1000000, 'size': 65536}}
        files = {'/etc/subuid': uid_rows.encode('ascii'),
                 '/etc/subgid': (uid_rows if gid_rows is None else gid_rows).encode('ascii')}

        def sealed_file(path, limit, *, keep):
            self.assertEqual(limit, 1048576)
            self.assertTrue(keep)
            return None, files[path], None

        with mock.patch.object(executor.installation, '_file', side_effect=sealed_file), \
             mock.patch.object(executor.pwd, 'getpwall', return_value=[
                 SimpleNamespace(pw_uid=value) for value in uid_accounts]), \
             mock.patch.object(executor.grp, 'getgrall', return_value=[
                 SimpleNamespace(gr_gid=value) for value in gid_accounts]):
            executor._reservations(details)

    def test_exact_and_containing_reservations_accept_same_window(self):
        for rows in ('root:1000000:65536\n', 'root:1000000:1000000000\n',
                     'root:999999:65538\n', '# reserved\n\nroot:1000000:1000000000\n'):
            with self.subTest(rows=rows):
                self.check_ranges(rows, uid_accounts=(0, 999999, 1065536),
                                  gid_accounts=(0, 999999, 1065536))

    def test_uid_and_gid_are_required_independently(self):
        good, bad = 'root:1000000:1000000000\n', 'other:1000000:1000000000\n'
        for uid_rows, gid_rows in ((good, bad), (bad, good)):
            with self.subTest(uid_rows=uid_rows), self.assertRaisesRegex(Denied, 'engine-root-range-not-reserved'):
                self.check_ranges(uid_rows, gid_rows)

    def test_missing_partial_fragmented_or_duplicate_cover_is_denied(self):
        for rows in ('', 'root:1000001:65536\n', 'root:1000000:65535\n',
                     'root:1000000:32768\nroot:1032768:32768\n',
                     'root:1000000:65536\nroot:1000000:65536\n',
                     'root:1000000:1000000000\nroot:999999:1000000001\n'):
            with self.subTest(rows=rows), self.assertRaisesRegex(Denied, 'engine-root-range-not-reserved'):
                self.check_ranges(rows)

    def test_every_other_overlapping_row_is_denied(self):
        for owner in ('root', 'other', '0'):
            for start, size in ((999999, 2), (1000000, 1), (1030000, 1), (1065535, 1)):
                for reverse in (False, True):
                    rows = ['root:1000000:1000000000', f'{owner}:{start}:{size}']
                    if reverse:
                        rows.reverse()
                    with self.subTest(rows=rows), self.assertRaisesRegex(Denied, 'engine-subid-overlap'):
                        self.check_ranges('\n'.join(rows) + '\n')

    def test_rows_touching_only_window_boundaries_are_allowed(self):
        self.check_ranges('other:999999:1\nroot:1000000:1000000000\nother:1065536:1\n')

    def test_real_uid_or_gid_inside_window_is_denied(self):
        for identifier in (1000000, 1030000, 1065535):
            for key in ('uid_accounts', 'gid_accounts'):
                with self.subTest(identifier=identifier, key=key), \
                     self.assertRaisesRegex(Denied, 'engine-root-range-not-reserved'):
                    self.check_ranges('root:1000000:1000000000\n', **{key: (identifier,)})

    def test_covering_reservation_must_fit_host_id_domain(self):
        self.check_ranges(f'root:1000000:{2 ** 32 - 1 - 1000000}\n')
        for size in (2 ** 32 - 1000000, 2 ** 64):
            with self.subTest(size=size), self.assertRaisesRegex(Denied, 'engine-subid-schema'):
                self.check_ranges(f'root:1000000:{size}\n')

    def test_nonoverlapping_out_of_domain_rows_in_either_file_are_denied(self):
        good = 'root:1000000:1000000000\n'
        for owner in ('root', 'other'):
            for start, length in ((2 ** 32, 1), (2 ** 32 - 1, 1), (2000000000, 2 ** 64)):
                bad = good + f'{owner}:{start}:{length}\n'
                for uid_rows, gid_rows in ((bad, good), (good, bad)):
                    with self.subTest(owner=owner, start=start, uid_rows=uid_rows), \
                         self.assertRaisesRegex(Denied, 'engine-subid-schema'):
                        self.check_ranges(uid_rows, gid_rows)

    def test_malformed_rows_remain_denied(self):
        for row in ('root:1000000:0', 'root:1000000:-1', 'root:1000000:65536:extra', ' root:1000000:65536'):
            with self.subTest(row=row), self.assertRaisesRegex(Denied, 'engine-subid-schema'):
                self.check_ranges('root:1000000:1000000000\n' + row + '\n')
