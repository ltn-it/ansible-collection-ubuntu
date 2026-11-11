"""Real local filesystem exchanges/locks; no system APT paths or network."""
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "roles/automatic_updates/files/apt_staged_transaction.py"
SPEC = importlib.util.spec_from_file_location("apt_staged_transaction", SOURCE)
TX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TX)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.base = self.root / "transactions"
        self.lists = self.root / "lists"
        self.lists.mkdir(mode=0o755)
        self.original = self.lists / "old-index"
        self.original.write_bytes(b"old signed data")
        os.chmod(self.original, 0o644)
        (self.lists / "partial").mkdir(mode=0o700)
        (self.lists / "lock").touch()
        self.stamp = self.root / "update-success-stamp"
        self.stamp.touch()
        os.utime(self.stamp, (1234567890, 1234567890))
        self.stamp_before = self.stamp.stat().st_mtime_ns
        self.machine = self.root / "machine"
        self.machine.write_text("a" * 32)
        self.status = self.root / "status"
        self.status.write_text("Package: fixture\nVersion: 1\n")
        self.request = {"manifest_sha256": "b" * 64, "machine_id": "a" * 32,
                        "status_sha256": hashlib.sha256(self.status.read_bytes()).hexdigest()}
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        (self.bundle / "new-index").write_bytes(b"new verified signed data")
        self.manifest = {"releases": [{"file": "new-index", "target_name": "new-index"}], "indexes": []}
        (self.bundle / "manifest.json").write_text(json.dumps(self.manifest))
        self.origin = datetime.now(timezone.utc) - timedelta(minutes=10)
        self.verifier_calls = []
        self.before = TX.tree_fingerprint(self.lists)
        self.lists_before = self.lists.stat().st_mtime_ns
        self.lock_inode = (self.lists / "lock").stat().st_ino

    def verifier(self, bundle, request):
        self.verifier_calls.append((bundle, request))
        return {"freshness_origin_utc": self.origin.isoformat()}

    def run_transaction(self, action="import", **kwargs):
        return TX.transact(action, self.bundle, self.request, base=self.base, lists=self.lists,
                           stamp=self.stamp, lock_paths=[self.root / "frontend-lock", self.lists / "lock"],
                           verifier=self.verifier, machine_path=self.machine, status_path=self.status, **kwargs)

    def test_actual_exchange_repeat_and_rollback_preserve_original_cache_and_stamp(self):
        result = self.run_transaction()
        self.assertTrue(result["changed"])
        self.assertFalse(result["packages_changed"])
        self.assertFalse(result["package_updates_accepted"])
        self.assertFalse(self.original.exists())
        self.assertEqual((self.lists / "new-index").read_bytes(), b"new verified signed data")
        self.assertEqual((self.lists / "lock").stat().st_ino, self.lock_inode)
        self.assertAlmostEqual(self.lists.stat().st_mtime, self.origin.timestamp(), places=5)
        self.assertAlmostEqual(self.stamp.stat().st_mtime, self.origin.timestamp(), places=5)
        self.assertLess(self.stamp.stat().st_mtime, datetime.now(timezone.utc).timestamp() - 590)
        self.assertFalse(self.run_transaction()["changed"])
        self.assertTrue(self.run_transaction("rollback")["changed"])
        self.assertEqual(TX.tree_fingerprint(self.lists), self.before)
        self.assertEqual(self.lists.stat().st_mtime_ns, self.lists_before)
        self.assertEqual(self.stamp.stat().st_mtime_ns, self.stamp_before)
        self.assertFalse(self.run_transaction("rollback")["changed"])

    def test_failed_admission_cannot_create_transaction_or_change_cache(self):
        def reject(*args):
            raise ValueError("signature rejected")
        self.verifier = reject
        with self.assertRaisesRegex(ValueError, "signature rejected"):
            self.run_transaction()
        self.assertFalse(self.base.exists())
        self.assertEqual(TX.tree_fingerprint(self.lists), self.before)

    def test_metadata_only_transaction_never_silently_ignores_payload_bundles(self):
        self.manifest['packages'] = [{'file': 'requires-archive-transaction.deb'}]
        (self.bundle/'manifest.json').write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, 'qualified archive-cache transaction'):
            self.run_transaction()
        self.assertFalse(self.base.exists())
        self.assertEqual(TX.tree_fingerprint(self.lists), self.before)

    def test_changed_target_or_status_prevents_mutation_and_rollback(self):
        self.run_transaction()
        for path in (self.machine, self.status):
            saved = path.read_bytes()
            path.write_bytes(saved + b"changed")
            for action in ("import", "rollback"):
                with self.subTest(path=path, action=action), self.assertRaises(ValueError):
                    self.run_transaction(action)
            path.write_bytes(saved)

    def test_actual_posix_lock_blocks_import_from_another_process(self):
        lock = self.root / "frontend-lock"
        code = "import fcntl,sys; f=open(sys.argv[1],'a');fcntl.lockf(f,fcntl.LOCK_EX);print('locked',flush=True);sys.stdin.read()"
        process = subprocess.Popen([sys.executable, "-c", code, str(lock)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), "locked")
            with self.assertRaises(BlockingIOError):
                self.run_transaction()
            self.assertEqual(TX.tree_fingerprint(self.lists), self.before)
        finally:
            process.communicate(input="", timeout=10)

    def test_failure_after_swap_automatically_restores_original_state(self):
        calls = []
        def fault(left, right):
            TX.exchange(left, right)
            calls.append(1)
            if len(calls) == 1:
                raise OSError("injected failure after atomic exchange")
        with self.assertRaisesRegex(OSError, "injected failure"):
            self.run_transaction(swap=fault)
        self.assertEqual(len(calls), 2)
        self.assertEqual(TX.tree_fingerprint(self.lists), self.before)
        self.assertEqual(self.stamp.stat().st_mtime_ns, self.stamp_before)
        journal=json.loads((self.base / self.request["manifest_sha256"] / "journal.json").read_text())
        self.assertEqual(journal["state"], "ROLLED_BACK_METADATA_ONLY")

    def test_failed_final_receipt_write_rolls_back_and_retains_outcome(self):
        original = TX.atomic_json
        calls = []
        def fail_once(path, value):
            calls.append(value["state"])
            if len(calls) == 2:
                raise OSError("injected receipt failure")
            return original(path, value)
        with patch.object(TX, "atomic_json", side_effect=fail_once):
            with self.assertRaisesRegex(OSError, "receipt failure"):
                self.run_transaction()
        self.assertEqual(calls[-1], "ROLLED_BACK_METADATA_ONLY")
        self.assertEqual(TX.tree_fingerprint(self.lists), self.before)

    def test_failed_receipt_replace_cannot_block_the_rollback_receipt(self):
        original = TX.os.replace
        calls = []
        def fail_once(source, target):
            calls.append(1)
            if len(calls) == 2:
                raise OSError("injected final journal replace failure")
            return original(source, target)
        with patch.object(TX.os, "replace", side_effect=fail_once):
            with self.assertRaisesRegex(OSError, "journal replace failure"):
                self.run_transaction()
        self.assertEqual(TX.tree_fingerprint(self.lists), self.before)
        transaction = self.base / self.request["manifest_sha256"]
        journal = json.loads((transaction / "journal.json").read_text())
        self.assertEqual(journal["state"], "ROLLED_BACK_METADATA_ONLY")
        self.assertEqual(len(list(transaction.glob(".journal.json.*"))), 1)

    def test_abrupt_process_exit_after_exchange_has_an_independent_return_path(self):
        child = os.fork()
        if child == 0:
            def exit_after_exchange(left, right):
                TX.exchange(left, right)
                os._exit(55)
            try:
                self.run_transaction(swap=exit_after_exchange)
            except BaseException:
                os._exit(56)
            os._exit(57)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 55)
        self.assertEqual((self.lists / "new-index").read_bytes(), b"new verified signed data")
        transaction = self.base / self.request["manifest_sha256"]
        self.assertEqual(json.loads((transaction / "journal.json").read_text())["state"], "PREPARING_METADATA_ONLY")
        self.assertTrue(self.run_transaction("rollback")["changed"])
        self.assertEqual(TX.tree_fingerprint(self.lists), self.before)
        self.assertEqual(self.stamp.stat().st_mtime_ns, self.stamp_before)

    def test_unexpected_cache_change_is_never_overwritten_by_repeat_or_rollback(self):
        self.run_transaction()
        (self.lists / "new-index").write_bytes(b"foreign change")
        for action in ("import", "rollback"):
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.run_transaction(action)
        self.assertEqual((self.lists / "new-index").read_bytes(), b"foreign change")

    def test_absent_stamp_stays_absent_on_import_and_rollback(self):
        self.stamp.unlink()
        self.run_transaction()
        self.assertFalse(self.stamp.exists())
        self.run_transaction("rollback")
        self.assertFalse(self.stamp.exists())

    def test_nonempty_partial_downloads_are_retained_and_block_import(self):
        (self.lists / "partial" / "download").write_bytes(b"incomplete")
        with self.assertRaisesRegex(ValueError, "partial state"):
            self.run_transaction()
        self.assertEqual((self.lists / "partial" / "download").read_bytes(), b"incomplete")


if __name__ == "__main__":
    unittest.main()
