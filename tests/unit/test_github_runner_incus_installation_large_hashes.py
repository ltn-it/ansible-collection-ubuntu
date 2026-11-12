"""Real Root FS selective hashing/FD ownership; no native admission claim."""
import os
import sys
import threading
import unittest
from unittest import mock

import test_github_runner_incus_installation as fixtures
from incus_lease_issuer import installation
from incus_lease_issuer.identity import Denied


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootLargeHashTests(unittest.TestCase):
    setUp = fixtures.RootInstallationFilesystemTests.setUp
    cleanup_fixture = fixtures.RootInstallationFilesystemTests.cleanup_fixture
    settings = fixtures.RootInstallationFilesystemTests.settings
    inventory_manifest = fixtures.RootInstallationFilesystemTests.inventory_manifest
    write_manifest = fixtures.RootInstallationFilesystemTests.write_manifest
    deny = fixtures.RootInstallationFilesystemTests.deny

    def expand(self):
        for number in range(5):
            path = self.root / ("large-" + str(number))
            path.write_bytes(bytes([number]) * installation.HASH_PARALLEL_MIN_BYTES)
            path.chmod(0o600)
        path = self.root / "below-threshold"
        path.write_bytes(b"x" * (installation.HASH_PARALLEL_MIN_BYTES - 1)); path.chmod(0o600)
        self.write_manifest()

    def test_only_large_files_use_four_bounded_workers_and_every_hash_is_fresh(self):
        self.expand()
        original_submit, original_hash = installation.ThreadPoolExecutor.submit, installation._hash_file
        records, worker_ids, small_ids = [], set(), set()
        barrier, lock = threading.Barrier(4), threading.Lock()
        first_threads = set()
        main = threading.get_ident()
        def submit(pool, fn, *args, **kwargs):
            if fn.__name__ == "hash_owned":
                records.append(args[0])
                self.assertGreaterEqual(args[0]["stamp"][6], 1024 * 1024)
                self.assertLessEqual(sum(not work["closed"] for work in records), 4)
            return original_submit(pool, fn, *args, **kwargs)
        def hashed(fd, path, *args, **kwargs):
            if not path.startswith(str(self.root) + "/"):
                return original_hash(fd, path, *args, **kwargs)
            large = os.fstat(fd).st_size >= installation.HASH_PARALLEL_MIN_BYTES
            if not large:
                small_ids.add(threading.get_ident())
                return original_hash(fd, path, *args, **kwargs)
            with lock:
                worker_ids.add(threading.get_ident())
                first = threading.get_ident() not in first_threads
                first_threads.add(threading.get_ident())
            if first: barrier.wait(5)
            return original_hash(fd, path, *args, **kwargs)
        with mock.patch.object(installation.ThreadPoolExecutor, "submit", submit), \
                mock.patch.object(installation, "_hash_file", side_effect=hashed):
            proof = installation.verify_installation(self.policy)
        self.assertEqual(len(records), 5)
        self.assertEqual(len(worker_ids), 4)
        self.assertEqual(small_ids, {main})
        self.assertTrue(all(work["closed"] for work in records))
        self.assertFalse(any(t.name.startswith("lit-stock-hash") for t in threading.enumerate()))
        for path, trusted in proof.trusted_files.items():
            self.assertEqual(trusted, installation.trusted_file(path))

    def submission_failure(self, *, enqueued):
        self.expand()
        original_submit, original_close, original_hash = installation.ThreadPoolExecutor.submit, os.close, installation._hash_file
        records, closed, hashed = [], [], []
        def submit(pool, fn, *args, **kwargs):
            if fn.__name__ == "hash_owned":
                records.append(args[0])
                if enqueued: original_submit(pool, fn, *args, **kwargs)
                raise RuntimeError("synthetic-large-submit-failure")
            return original_submit(pool, fn, *args, **kwargs)
        def close(fd):
            if any(work["fd"] == fd for work in records): closed.append(fd)
            return original_close(fd)
        def digest(fd, path, *args, **kwargs):
            if any(work["fd"] == fd for work in records): hashed.append(path)
            return original_hash(fd, path, *args, **kwargs)
        with mock.patch.object(installation.ThreadPoolExecutor, "submit", submit), \
                mock.patch.object(os, "close", side_effect=close), \
                mock.patch.object(installation, "_hash_file", side_effect=digest):
            with self.assertRaisesRegex(RuntimeError, "synthetic-large-submit-failure"):
                installation.verify_installation(self.policy)
        self.assertEqual(len(records), 1)
        work = records[0]
        self.assertEqual(closed, [work["fd"]])
        self.assertEqual(hashed, [str(self.root / work["relative"])] if enqueued else [])
        self.assertTrue(work["closed"])
        self.assertFalse(any(t.name.startswith("lit-stock-hash") for t in threading.enumerate()))
        with self.assertRaises(OSError): os.fstat(work["fd"])

    def test_enqueue_then_raise_retains_fd_until_worker_join_and_exactly_one_close(self):
        self.submission_failure(enqueued=True)

    def test_before_enqueue_failure_closes_only_after_pool_join(self):
        self.submission_failure(enqueued=False)

    def test_large_hash_failure_closes_all_other_owned_tasks_after_join(self):
        self.expand()
        original_submit, original_hash = installation.ThreadPoolExecutor.submit, installation._hash_file
        records = []
        def submit(pool, fn, *args, **kwargs):
            if fn.__name__ == "hash_owned": records.append(args[0])
            return original_submit(pool, fn, *args, **kwargs)
        def hashed(fd, path, *args, **kwargs):
            if path.endswith("large-2"): raise Denied("synthetic-large-hash-failure")
            return original_hash(fd, path, *args, **kwargs)
        with mock.patch.object(installation.ThreadPoolExecutor, "submit", submit), \
                mock.patch.object(installation, "_hash_file", side_effect=hashed):
            self.deny()
        self.assertTrue(records)
        self.assertTrue(all(work["closed"] for work in records))
        self.assertFalse(any(t.name.startswith("lit-stock-hash") for t in threading.enumerate()))
        for work in records:
            with self.assertRaises(OSError): os.fstat(work["fd"])

    def test_worker_start_failure_has_no_file_work(self):
        original_start, original_submit = threading.Thread.start, installation.ThreadPoolExecutor.submit
        starts, records = 0, []
        def start(thread):
            nonlocal starts
            starts += 1
            if starts == 3: raise RuntimeError("synthetic-worker-start")
            return original_start(thread)
        def submit(pool, fn, *args, **kwargs):
            if fn.__name__ == "hash_owned": records.append(args[0])
            return original_submit(pool, fn, *args, **kwargs)
        with mock.patch.object(threading.Thread, "start", side_effect=start, autospec=True), \
                mock.patch.object(installation.ThreadPoolExecutor, "submit", submit):
            with self.assertRaisesRegex(RuntimeError, "synthetic-worker-start"):
                installation.verify_installation(self.policy)
        self.assertEqual(records, [])
        self.assertFalse(any(t.name.startswith("lit-stock-hash") for t in threading.enumerate()))
