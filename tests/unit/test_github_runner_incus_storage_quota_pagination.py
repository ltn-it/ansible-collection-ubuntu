"""FIEMAP streaming ABI fixtures; no native quota or allocation claim."""
import struct
import sys
from pathlib import Path
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'roles/github_runner/files'))
from incus_lease_issuer import storage_quota as quota  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class FiemapPaginationTests(unittest.TestCase):
    def reader(self, total, *, change=None):
        calls = []
        buffers = []

        def ioctl(fd, request, data, mutate):
            start, length, flags, mapped, count, reserved = struct.unpack_from('=QQIIII', data)
            self.assertEqual((fd, request, mutate), (17, quota.FS_IOC_FIEMAP, True))
            self.assertEqual((length, flags, mapped, count, reserved),
                             (total * 4096 - start, 0, 0, 4096, 0))
            self.assertEqual(len(data), 32 + 4096 * 56)
            calls.append(start)
            buffers.append(id(data))
            offset = start // 4096
            amount = min(4096, total - offset)
            struct.pack_into('=QQIIII', data, 0, start, length, 0, amount, 4096, 0)
            for index in range(amount):
                number = offset + index
                row = [number * 4096, (number + 1) * 8192, 4096, 0, 0,
                       (0x800 if number % 2 else 0) | (1 if number == total - 1 else 0), 0, 0, 0]
                struct.pack_into('=QQQQQIIII', data, 32 + index * 56, *row)
            if change:
                change(len(calls), data)
        return ioctl, calls, buffers

    def test_actual_fragment_count_streams_same_fixed_buffer_without_sync(self):
        reader, calls, buffers = self.reader(4580)
        with mock.patch.object(quota.fcntl, 'ioctl', side_effect=reader):
            quota._reservation(17, 4580 * 4096)
        self.assertEqual(calls, [0, 4096 * 4096])
        self.assertEqual(len(set(buffers)), 1)

    def test_three_pages_and_single_page_keep_full_coverage(self):
        for total in (1, 8193):
            with self.subTest(total=total):
                reader, calls, _ = self.reader(total)
                with mock.patch.object(quota.fcntl, 'ioctl', side_effect=reader):
                    quota._reservation(17, total * 4096)
                self.assertEqual(len(calls), (total + 4095) // 4096)

    def test_later_page_extent_unknown_gap_overlap_or_unsupported_flags_denied(self):
        for field, value in ((0, 0), (0, 4097 * 4096), (1, 0), (2, 0),
                             (2, 2 ** 64 - 1), (3, 1), (5, 2), (5, 4),
                             (5, 0x2000), (5, 0x100), (6, 1)):
            def change(page, data):
                if page == 2:
                    row = list(struct.unpack_from('=QQQQQIIII', data, 32))
                    row[field] = value
                    struct.pack_into('=QQQQQIIII', data, 32, *row)
            with self.subTest(field=field, value=value):
                reader, _, _ = self.reader(4580, change=change)
                with mock.patch.object(quota.fcntl, 'ioctl', side_effect=reader), self.assertRaises(Denied):
                    quota._reservation(17, 4580 * 4096)

    def test_later_page_header_drift_or_empty_denied(self):
        for field, value in ((0, 0), (1, 1), (2, 1), (3, 0), (3, 4097), (4, 1), (5, 1)):
            def change(page, data):
                if page == 2:
                    row = list(struct.unpack_from('=QQIIII', data))
                    row[field] = value
                    struct.pack_into('=QQIIII', data, 0, *row)
            with self.subTest(field=field, value=value):
                reader, _, _ = self.reader(4580, change=change)
                with mock.patch.object(quota.fcntl, 'ioctl', side_effect=reader), self.assertRaises(Denied):
                    quota._reservation(17, 4580 * 4096)

    def test_premature_last_and_full_coverage_without_last_denied(self):
        def early(page, data):
            if page == 1:
                struct.pack_into('=I', data, 32 + 4095 * 56 + 40, 1)
        def missing(page, data):
            if page == 2:
                struct.pack_into('=I', data, 32 + 483 * 56 + 40, 0)
        for change in (early, missing):
            reader, _, _ = self.reader(4580, change=change)
            with mock.patch.object(quota.fcntl, 'ioctl', side_effect=reader), self.assertRaises(Denied):
                quota._reservation(17, 4580 * 4096)

    def test_one_deadline_not_reset_between_pages_or_after_ioctl(self):
        reader, calls, _ = self.reader(4580)
        # Initial deadline0+5, first page occupies1sec, second returns at5.
        def clock():
            return 0 if not calls else (1 if len(calls) == 1 else 5)
        with mock.patch.object(quota.time, 'monotonic', side_effect=clock), \
                mock.patch.object(quota.fcntl, 'ioctl', side_effect=reader), \
                self.assertRaisesRegex(Denied, 'storage-quota-fiemap-budget'):
            quota._reservation(17, 4580 * 4096)
        self.assertEqual(len(calls), 2)

    def test_deadline_checked_during_extent_iteration(self):
        reader, calls, _ = self.reader(4580)
        ticks = iter([0, 0, 0, 5])
        with mock.patch.object(quota.time, 'monotonic', side_effect=lambda: next(ticks)), \
                mock.patch.object(quota.fcntl, 'ioctl', side_effect=reader), \
                self.assertRaisesRegex(Denied, 'storage-quota-fiemap-budget'):
            quota._reservation(17, 4580 * 4096)
        self.assertEqual(len(calls), 1)

    def test_size_invalid_before_kernel(self):
        for size in (0, -1, True, quota.MAX_BYTES + 1):
            with mock.patch.object(quota.fcntl, 'ioctl') as ioctl, self.assertRaises(Denied):
                quota._reservation(17, size)
            ioctl.assert_not_called()


if __name__ == '__main__':
    unittest.main()
