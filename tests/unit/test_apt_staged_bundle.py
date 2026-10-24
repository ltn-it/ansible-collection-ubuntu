"""Reject incomplete and misbound staged metadata before any APT state write."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "roles/automatic_updates/files/apt_staged_bundle.py"
SPEC = importlib.util.spec_from_file_location("apt_staged_bundle", SOURCE)
APT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APT)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.now = datetime(2026, 10, 24, 6, 0, tzinfo=timezone.utc)
        self.machine = self.root / "machine-id"
        self.machine.write_text("a" * 32 + "\n")
        self.status = self.root / "status"
        self.status.write_text("Package: fixture\nVersion: 1\n")
        self.source = self.root / "ubuntu.sources"
        self.source.write_text("Types: deb\nURIs: https://archive.ubuntu.com/ubuntu\n")
        self.keyring = self.root / "keyring"
        self.keyring.write_bytes(b"fixture-keyring")
        self.prefix = "archive.ubuntu.com_ubuntu_dists_noble"
        self.content = b"Package: fixture\nVersion: 2\n\n"
        self.index = self.bundle / (self.prefix + "_main_binary-amd64_Packages.lz4")
        self.index.write_bytes(self.content)
        self.release = self.bundle / (self.prefix + "_InRelease")
        self.release.write_text("signed-fixture-input")
        repo = {"uri": "https://archive.ubuntu.com/ubuntu", "suite": "noble",
                "components": ["main"], "list_prefix": self.prefix}
        self.manifest = {
            "schema": 1, "machine_id": "a" * 32, "architecture": "amd64",
            "status_sha256": APT.digest(self.status), "sources": {str(self.source): APT.digest(self.source)},
            "keyring_sha256": APT.digest(self.keyring), "started_utc": (self.now - timedelta(seconds=30)).isoformat(),
            "acquired_utc": (self.now - timedelta(seconds=10)).isoformat(), "repositories": [repo],
            "releases": [{"list_prefix": self.prefix, "file": self.release.name, "target_name": self.release.name}],
            "indexes": [{"list_prefix": self.prefix, "component": "main", "file": self.index.name,
                         "target_name": self.index.name, "meta_key": "main/binary-amd64/Packages"}], "packages": [],
        }
        self.request = {key: deepcopy(self.manifest[key]) for key in
                        ("machine_id", "architecture", "status_sha256", "sources", "repositories")}
        self.request.update(keyring={"path": str(self.keyring), "sha256": APT.digest(self.keyring)},
                            maximum_age_seconds=3600)
        self.seal()

    def seal(self):
        (self.bundle / "manifest.json").write_text(json.dumps(self.manifest))
        self.request["manifest_sha256"] = APT.digest(self.bundle / "manifest.json")

    def signature(self, path, keyring, now, suite):
        self.assertEqual(path, self.release)
        self.assertEqual(keyring, self.keyring)
        self.assertEqual(now, self.now)
        self.assertEqual(suite, "noble")
        return {"Architectures": "amd64 arm64", "Components": "main universe"}, {
            "main/binary-amd64/Packages": (hashlib.sha256(self.content).hexdigest(), len(self.content)),
        }, ["A" * 40]

    @staticmethod
    def decompressed(path, maximum):
        data = path.read_bytes()
        if len(data) > maximum:
            raise ValueError("Oversized decompression")
        return hashlib.sha256(data).hexdigest(), len(data)

    def verify(self, **kwargs):
        return APT.verify(self.bundle, self.request, now=self.now, signature=self.signature,
                          decompressed=self.decompressed, machine_path=self.machine, status_path=self.status,
                          architecture="amd64", source_paths=[self.source], **kwargs)

    def test_complete_read_only_verification_and_repeat(self):
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in self.root.rglob("*") if path.is_file()}
        first = self.verify()
        self.assertEqual(first, self.verify())
        self.assertEqual(first["state"], "SIGNED_APT_METADATA_VERIFIED_NO_IMPORT")
        self.assertFalse(first["changed"])
        self.assertFalse(first["package_updates_accepted"])
        self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in before})

    def test_independently_admitted_digest_cannot_be_replaced_by_bundle(self):
        (self.bundle / "manifest.json").write_text(json.dumps({**self.manifest, "machine_id": "b" * 32}))
        with self.assertRaisesRegex(ValueError, "manifest changed"):
            self.verify()

    def test_wrong_machine_status_architecture_source_or_keyring(self):
        for name in ("machine_id", "architecture", "status_sha256", "sources", "keyring_sha256"):
            with self.subTest(name=name):
                saved = deepcopy(self.manifest[name])
                self.manifest[name] = {} if name == "sources" else "wrong"
                self.seal()
                with self.assertRaises(ValueError):
                    self.verify()
                self.manifest[name] = saved
                self.seal()

    def test_changed_actual_source_status_or_keyring_is_rejected(self):
        for path in (self.machine, self.status, self.source, self.keyring):
            with self.subTest(path=path.name):
                before = path.read_bytes()
                path.write_bytes(before + b"changed")
                with self.assertRaises(ValueError):
                    self.verify()
                path.write_bytes(before)

    def test_acquisition_start_not_copy_time_controls_freshness(self):
        for start, end in ((-3600, -1), (-3601, -1), (1, 2), (-1, -2)):
            with self.subTest(start=start, end=end):
                self.manifest["started_utc"] = (self.now + timedelta(seconds=start)).isoformat()
                self.manifest["acquired_utc"] = (self.now + timedelta(seconds=end)).isoformat()
                self.seal()
                with self.assertRaises(ValueError):
                    self.verify()

    def test_freshness_policy_cannot_disable_required_hourly_refresh(self):
        for value in (0, -1, True, 3601, "3600"):
            with self.subTest(value=value):
                self.request["maximum_age_seconds"] = value
                with self.assertRaises(ValueError):
                    self.verify()

    def test_missing_duplicate_or_wrong_architecture_index_is_rejected(self):
        original = deepcopy(self.manifest["indexes"])
        for indexes in ([], original + original, [{**original[0], "meta_key": "main/binary-arm64/Packages"}],
                        [{**original[0], "target_name": "foreign_Packages.lz4"}],
                        [{**original[0], "component": "universe"}]):
            with self.subTest(indexes=indexes):
                self.manifest["indexes"] = indexes
                self.seal()
                with self.assertRaises(ValueError):
                    self.verify()

    def test_tampered_truncated_index_or_unverified_deb_fails(self):
        for data in (self.content + b"malicious", self.content[:-1], b"different"):
            with self.subTest(data=data):
                self.index.write_bytes(data)
                with self.assertRaises(ValueError):
                    self.verify()
        self.index.write_bytes(self.content)
        self.manifest["packages"] = [{"file": "unverified.deb"}]
        self.seal()
        with self.assertRaisesRegex(ValueError, "payload verification is not implemented"):
            self.verify()

    def test_member_traversal_symlink_and_hardlink_fail(self):
        original = self.manifest["indexes"][0]["file"]
        for name in ("../status", str(self.status), "./" + original, "x/../" + original):
            with self.subTest(name=name):
                self.manifest["indexes"][0]["file"] = name
                self.seal()
                with self.assertRaises(ValueError):
                    self.verify()
        self.manifest["indexes"][0]["file"] = original
        self.seal()
        self.index.unlink()
        self.index.symlink_to(self.status)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            self.verify()
        self.index.unlink()
        self.index.hardlink_to(self.status)
        with self.assertRaisesRegex(ValueError, "Hard-linked"):
            self.verify()

    def test_signed_release_parser_rejects_duplicate_hashes_and_fields(self):
        checksum = hashlib.sha256(self.content).hexdigest()
        line = f" {checksum} {len(self.content)} main/binary-amd64/Packages\n"
        valid = "Suite: noble\nSHA256:\n" + line
        fields, checksums = APT.release_fields(valid)
        self.assertEqual(fields["Suite"], "noble")
        self.assertEqual(checksums["main/binary-amd64/Packages"][1], len(self.content))
        for text in (valid + line, valid + "Suite: other\n", "SHA256:\n  wrong 1 x\n", " continuation"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                APT.release_fields(text)

    def test_repository_credentials_and_duplicate_mappings_fail(self):
        valid = self.request["repositories"][0]
        for values in ([valid, valid], [{**valid, "uri": "https://token@example.com/ubuntu"}],
                       [{**valid, "uri": "file:///tmp/repo"}], [{**valid, "list_prefix": "../other"}]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                APT.repositories(values)

    def test_duplicate_json_keys_fail(self):
        path = self.root / "duplicate.json"
        path.write_text('{"schema":1,"schema":2}')
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            APT.read_json(path)

    def test_signature_verification_uses_isolated_home_and_rejects_bad_signature(self):
        def failed(argv, **kwargs):
            self.assertEqual(argv[:2], ["/usr/bin/gpgv", "--homedir"])
            self.assertEqual(kwargs["env"]["HOME"], argv[2])
            self.assertNotIn("GNUPGHOME", kwargs["env"])
            return SimpleNamespace(returncode=2, stdout=b"", stderr=b"bad signature")
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            APT.verify_signature(self.release, self.keyring, self.now, "noble", run=failed)

    def test_signed_empty_component_is_distinct_from_missing_nonempty_index(self):
        self.request["repositories"][0]["components"].append("universe")
        self.manifest["repositories"][0]["components"].append("universe")
        self.seal()
        original = self.signature
        def signature(*args):
            fields, checksums, signers = original(*args)
            checksums["universe/binary-amd64/Packages"] = (hashlib.sha256(b"").hexdigest(), 0)
            return fields, checksums, signers
        self.signature = signature
        self.assertEqual(self.verify()["signed_empty_index_count"], 1)
        self.signature = original
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            self.verify()

    def test_valid_signature_still_requires_suite_date_expiry_and_signer(self):
        checksum = hashlib.sha256(self.content).hexdigest()
        def native(fields, status=b"[GNUPG:] VALIDSIG " + b"A" * 40 + b" 0\n"):
            def run(argv, **kwargs):
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(fields + "\nSHA256:\n " + checksum + " " + str(len(self.content))
                                  + " main/binary-amd64/Packages\n")
                return SimpleNamespace(returncode=0, stdout=status, stderr=b"")
            return run
        valid = "Suite: noble\nDate: Sat, 24 Oct 2026 05:00:00 UTC\nValid-Until: Sun, 25 Oct 2026 05:00:00 UTC"
        result = APT.verify_signature(self.release, self.keyring, self.now, "noble", run=native(valid))
        self.assertEqual(result[2], ["A" * 40])
        for fields, status in ((valid.replace("Suite: noble", "Suite: other"), b"[GNUPG:] VALIDSIG " + b"A" * 40),
                               (valid.replace("25 Oct", "23 Oct"), b"[GNUPG:] VALIDSIG " + b"A" * 40),
                               (valid.replace("05:00:00", "07:00:00"), b"[GNUPG:] VALIDSIG " + b"A" * 40),
                               (valid, b"[GNUPG:] GOODSIG ignored")):
            with self.subTest(fields=fields, status=status), self.assertRaises(ValueError):
                APT.verify_signature(self.release, self.keyring, self.now, "noble", run=native(fields, status))


if __name__ == "__main__":
    unittest.main()
