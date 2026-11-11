"""Exact actual ZIP bytes against private Root export; no native API acceptance."""
import hashlib
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile

import test_github_runner_incus_runtime_client as fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import evidence_export, operating_upload as upload
from incus_lease_issuer.identity import Denied


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class ProviderZipBindingTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0:
            self.skipTest("requires private Root /run/proof")
        self.temp = tempfile.TemporaryDirectory(dir=base, prefix="actual-upload-bytes-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        raw = fixtures.full_evidence(pending=True)
        path = self.root / "root-export.tar.gz"
        path.write_bytes(raw)
        path.chmod(0o600)
        self.exported = evidence_export.ExportReceipt(str(path), hashlib.sha256(raw).hexdigest(), len(raw), 1, "a" * 64, True)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            self.members = {row.name.removeprefix("evidence/"): archive.extractfile(row).read()
                            for row in archive if row.name.startswith("evidence/")}
        self.bounds = {"max_members": 100, "max_member_bytes": 1048576, "max_total_evidence_bytes": 2097152}

    def compare(self, members, *, symlink=False):
        path = self.root / "provider.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, raw in members.items():
                info = zipfile.ZipInfo(name)
                if symlink and name == "logs/scenario.log":
                    info.external_attr = 0o120777 << 16
                archive.writestr(info, raw)
        path.chmod(0o600)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            return upload.compare_provider_zip(fd, self.exported, self.bounds)
        finally:
            os.close(fd)

    def test_exact_native_shaped_zip_preserves_preliminary_not_final_outcome(self):
        digest, execution = self.compare(self.members)
        self.assertRegex(digest, "^[a-f0-9]{64}$")
        self.assertIs(execution, True)

    def test_modified_report_even_with_rewritten_checksums_is_not_original_root_capture(self):
        changed = {**self.members, "logs/scenario.log": b"different valid-looking report"}
        changed["checksums/SHA256SUMS"] = b"".join(hashlib.sha256(raw).hexdigest().encode() + b"  " + name.encode() + b"\n"
            for name, raw in sorted(changed.items()) if name != "checksums/SHA256SUMS")
        with self.assertRaises(Denied):
            self.compare(changed)

    def test_extra_missing_symlink_and_unsafe_member_never_bind_upload(self):
        for members in ({**self.members, "extra.json": b"{}"},
                        {name: raw for name, raw in self.members.items() if name != "logs/scenario.log"},
                        {**self.members, "../escape": b"x"}):
            with self.subTest(names=set(members)), self.assertRaises(Denied):
                self.compare(members)
        with self.assertRaises(Denied):
            self.compare(self.members, symlink=True)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class PrivateVerificationIntentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_github_runner_incus_finalization as owned
        owned.RootFinalizationTests.setUpClass()

    def setUp(self):
        import test_github_runner_incus_finalization as owned
        self.fixture = owned.RootFinalizationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_actual_root_uploader_identity_is_durable_before_filesystem_effect_and_no_replay(self):
        from incus_lease_issuer import kernel, operating_custody
        import time
        process = kernel.read_process(os.getpid())
        owner = {"pid": os.getpid(), "boot_id": kernel.read_boot_id(), "start_ticks": process.stat.start_ticks,
                 "deadline": int(time.time()) + 120}
        store, lease = self.fixture.store, self.fixture.lease
        before_requests = list(self.fixture.server.requests)
        record = store.begin_upload_verification(lease, "a" * 64, owner)
        intent = record["upload_verification"]
        self.assertEqual(intent["state"], "intent")
        self.assertTrue(upload.verification_active(intent))
        self.assertEqual(self.fixture.server.requests, before_requests)
        with self.assertRaises(Denied):
            store.begin_upload_verification(lease, "a" * 64, owner)
        with self.assertRaisesRegex(Denied, "custody-upload-verification-held"):
            operating_custody.require_cleanup_allowed(store, lease)
        self.assertFalse(upload.verification_active({**intent, "deadline": int(time.time()) - 1}))
        self.assertFalse(upload.verification_active({**intent, "start_ticks": intent["start_ticks"] + 1}))
        self.assertNotEqual(store.read(lease)["state"], "closed")
        self.assertNotIn("uploaded_evidence", store.read(lease))
