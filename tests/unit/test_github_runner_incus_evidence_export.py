"""Real private FS/archive normalization; mocked acquisition is NOT native proof.

The production factory composes existing signed retained-engine acquisition.
These fixtures replace only that Root acquisition boundary; report reading,
normalization, deterministic sealing, readback and transfer execute unchanged.
"""
from dataclasses import replace
from contextlib import nullcontext
import hashlib
import io
import json
import os
import shutil
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import evidence_export as export, ledger  # noqa: E402
from incus_lease_issuer import evidence_policy as policy  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402

SECRET = "SYNTHETIC_SECRET_NEVER_EXPORTED"


class NormalizationTests(unittest.TestCase):
    def test_junit_per_test_status_duration_identity_hash_without_free_text(self):
        raw = ('<testsuite><testcase name="' + SECRET + '" classname="x" time="0.25"><failure>'
               + SECRET + '</failure><system-out>' + SECRET + '</system-out></testcase>'
               '<testcase name="second"><skipped/></testcase></testsuite>').encode()
        result = export._junit(raw)
        self.assertEqual(result["test_count"], 2)
        self.assertEqual([row["status"] for row in result["tests"]], ["failure", "skipped"])
        self.assertEqual(result["tests"][0]["duration_seconds"], 0.25)
        self.assertEqual(result["source_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["source_bytes"], len(raw))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertIs(result["evidence_policy_complete"], False)

    def test_allure_per_test_projection_excludes_attachments_parameters_and_failure_text(self):
        raw = ledger.canonical({"uuid": SECRET, "fullName": SECRET, "name": SECRET, "status": "broken",
            "start": 1000, "stop": 1250, "attachments": [{"source": "/client.key"}],
            "statusDetails": {"message": SECRET}, "parameters": [{"value": SECRET}]})
        result = export._allure(raw)
        self.assertEqual(result["tests"][0]["status"], "broken")
        self.assertEqual(result["tests"][0]["duration_seconds"], 0.25)
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn("client.key", json.dumps(result))

    def test_malformed_xml_entities_statuses_and_nonfinite_durations_deny(self):
        for raw in (b'<!DOCTYPE x [<!ENTITY a "bad">]><testsuite/>', b'<testsuite/>',
                    b'<testsuite><testcase time="NaN"/></testsuite>',
                    b'<testsuite><testcase><failure/><error/></testcase></testsuite>'):
            with self.subTest(raw=raw), self.assertRaises(Denied):
                export._junit(raw)
        for value in ({"status": "approved", "start": 1, "stop": 2},
                      {"status": "passed", "start": True, "stop": 2},
                      {"status": "passed", "start": 3, "stop": 2}):
            with self.subTest(value=value), self.assertRaises(Denied):
                export._allure(ledger.canonical(value))

    def test_public_factory_has_no_job_locator_reader_or_approval_argument(self):
        with mock.patch.object(os, "geteuid", return_value=2101), self.assertRaisesRegex(Denied, "evidence-export-denied"):
            export.export_existing(None, None, None, None, None, None)
        with self.assertRaises(TypeError):
            export.export_existing(None, None, None, None, None, None, output_path="/job")


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="evidence-export-", dir="/root")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output, self.runroot = self.root / "quality", self.root / "runroot"
        self.output.mkdir(mode=0o700)
        self.runroot.mkdir(mode=0o700)
        self.spool = Path(str(self.runroot) + ".public-evidence")
        quota = mock.patch.object(export, "_quota", return_value=nullcontext())
        quota.start()
        self.addCleanup(quota.stop)
        storepath = self.root / "ledger"
        storepath.mkdir(mode=0o700)
        ledger.Ledger.initialize(storepath)
        self.store = ledger.Ledger(storepath)
        self.addCleanup(self.store.shutdown)
        info = self.output.stat()
        self.details = {"engine": {"runroot": str(self.runroot)}, "output": {
            "path": str(self.output), "device": info.st_dev, "inode": info.st_ino,
            "uid": 0, "gid": info.st_gid, "mode": 0o700}, "environment": {
            "QUALITY_INPUT_SCENARIO": "role_heavy", "QUALITY_INPUT_TARGET": "ubuntu",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": "example/repo", "GITHUB_RUN_ID": "501",
            "QUALITY_INPUT_SOURCE_SHA": "a" * 40, "QUALITY_INPUT_JUNIT_REQUIRED": "true",
            "QUALITY_INPUT_ALLURE_REQUIRED": "true", "QUALITY_INPUT_PROFILE": "heavy", "QUALITY_INPUT_ROLES": "demo"}}
        self.bounds = {"max_total_evidence_bytes": 1024 * 1024, "max_members": 20, "max_member_bytes": 65536}
        self.config = SimpleNamespace(capture=self.bounds, sha256="c" * 64)
        self.manifest = SimpleNamespace(sha256="d" * 64)
        self.actual = {"exit_code": 0, "signal": None, "manifest_sha256": "d" * 64}
        self.lease = "1" * 32
        self.patch = mock.patch.object(export, "_acquire", side_effect=lambda *args: (
            self.config, self.manifest, "2" * 32, self.actual, self.details))
        self.patch.start()
        self.addCleanup(self.patch.stop)
        tls = mock.patch.object(export, "_tls_material", return_value=(b"ROOT_PRIVATE_TLS_MATERIAL",))
        tls.start()
        self.addCleanup(tls.stop)
        suffix = "role_heavy/ubuntu/attempt-1"
        self.base = self.output / "artifacts/cell-evidence" / suffix
        self.lifecycle = self.output / "artifacts/raw" / suffix / "configuration/lifecycle-result.json"
        self.write(self.lifecycle, {"schema_version": 1, "scenario": "role_heavy", "target": "ubuntu",
            "run_attempt": "1", "test_exit_code": 0, "capture_exit_code": 0, "destroy_exit_code": 0,
            "effective_exit_code": 0, "infrastructure_error": False})
        self.source = {"schema_version": 2, "repository": "example/repo", "workflow_run_id": "501",
            "workflow_attempt": "1", "commit_sha": "a" * 40, "expected_commit_sha": "a" * 40,
            "results": [{"scenario": "role_heavy", "target": "ubuntu", "run_attempt": "1",
                         "junit": ["junit/report.xml"], "allure_results": ["allure-results/one-result.json"]}],
            "blockers": [SECRET], "release_eligible": True}
        properties = {"commit_sha": "a" * 40, "profile": "heavy", "scenario": "role_heavy", "target": "ubuntu",
                      "run_attempt": "1", "roles": "demo"}
        prop_xml = "".join(f'<property name="{key}" value="{value}"/>' for key, value in properties.items())
        self.write(self.base / "junit/report.xml", ('<testsuite><properties>' + prop_xml + '</properties>'
            '<testcase classname="checks" name="route" time="0.01"><failure message="assert route available"/>'
            '</testcase></testsuite>').encode())
        labels = {"commit-sha": "a" * 40, "profile": "heavy", "scenario": "role_heavy", "target": "ubuntu",
                  "run-attempt": "1", "role": "demo"}
        self.write(self.base / "allure-results/one-result.json", {"uuid": "actual-test-id", "name": "route",
            "fullName": "checks.route", "status": "failed", "start": 1000, "stop": 1020,
            "labels": [{"name": key, "value": value} for key, value in labels.items()],
            "attachments": [{"source": "recording.webm", "type": "video/webm", "name": "browser recording"}]})
        self.write(self.base / "allure-results/recording.webm", b"\x1a\x45\xdf\xa3 bounded-recording-fixture")
        self.write(self.base / "logs/scenario.log", b"test failed: assert route available; password=[REDACTED]\n")
        report = policy.parse_junit(self.base / "junit/report.xml")
        who = policy.Identity("demo", "heavy", "role_heavy", "ubuntu", "1")
        results = policy._aggregate_reports([{"identity": who, "report": report, "junit": "junit/report.xml",
            "allure_results": ["allure-results/one-result.json"], "allure_complete": True}])
        self.source.update({"mode": "ci", "commit_consistent": True, "test_totals": report["totals"],
            "failures": 1, "skips": 0, "results": results,
            "matrix": {"actual_count": 1, "expected": [{"profile": "heavy", "scenario": "role_heavy",
                "target": "ubuntu", "run_attempt": "1", "status": "failed", "roles": ["demo"]}]},
            "secret_scan": {"canary_detected_before_redaction": True, "clean": True, "files_scanned": 5,
                            "archive_members_scanned": 0, "findings": [], "errors": []},
            "security_evidence": {"required_for_release": [], "missing": [], "external_secret_findings": 0,
                "vulnerability_blocking_findings": 0, "semantic_valid": False}, "prerequisites": {}, "blockers": []})
        self.refresh_checksums()
        self.write(self.output / "artifacts/logs/private.log", SECRET.encode())

    @staticmethod
    def write(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if type(value) is bytes else ledger.canonical(value))
        path.chmod(0o600)

    def invoke(self):
        return export.export_existing("/root/sealed-runtime.json", "c" * 64, None, "selected", self.store, self.lease)

    def refresh_checksums(self):
        paths = sorted(path for path in self.base.rglob("*") if path.is_file()
                       and path.relative_to(self.base).as_posix() not in {"manifest.json", "checksums/SHA256SUMS"})
        self.source["checksums"] = {"algorithm": "sha256", "file": "checksums/SHA256SUMS", "entry_count": len(paths) + 1}
        self.write(self.base / "manifest.json", self.source)
        paths.append(self.base / "manifest.json")
        self.write(self.base / "checksums/SHA256SUMS", "".join(
            hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.relative_to(self.base).as_posix() + "\n"
            for path in sorted(paths)).encode())

    def deny(self):
        with self.assertRaisesRegex(Denied, "^evidence-export-denied$"):
            self.invoke()

    def test_real_seal_readback_chunks_recovery_determinism_and_no_secrets_or_pass(self):
        receipt = self.invoke()
        chunks = list(export.read_chunks(receipt))
        self.assertTrue(all(0 < len(chunk) <= 4096 for chunk in chunks))
        archive = b"".join(chunks)
        self.assertEqual(len(archive), receipt.size)
        self.assertEqual(hashlib.sha256(archive).hexdigest(), receipt.sha256)
        self.assertEqual(len(chunks), receipt.chunk_count)
        self.assertTrue(receipt.evidence_policy_complete)
        self.assertEqual(self.invoke(), receipt)
        self.assertEqual((self.spool / export.ARCHIVE).stat().st_mode & 0o777, 0o600)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as stream:
            self.assertIn("evidence/allure-results/recording.webm", stream.getnames())
            self.assertIn("runtime/evidence-policy.json", stream.getnames())
            members = {row.name: stream.extractfile(row).read() for row in stream.getmembers()}
            self.assertTrue(all(row.isfile() and row.uid == 0 and row.gid == 0 and row.mtime == 0
                                for row in stream.getmembers()))
        self.assertNotIn(SECRET.encode(), b"".join(members.values()))
        self.assertNotIn(b"client.key", b"".join(members.values()))
        self.assertTrue(json.loads(members["runtime/evidence-policy.json"])["evidence_policy_complete"])
        self.assertIn(b'assert route available', members["evidence/junit/report.xml"])
        self.assertIn(b'checks.route', members["evidence/allure-results/one-result.json"])
        self.assertEqual(members["evidence/allure-results/recording.webm"],
                         (self.base / "allure-results/recording.webm").read_bytes())
        self.assertEqual(export._archive(members, self.bounds["max_total_evidence_bytes"]), archive)
        # Immutable recovery does not reread or adopt new mutable job reports.
        self.write(self.base / "junit/report.xml", b"changed")
        self.assertEqual(self.invoke(), receipt)

    def test_sanitized_spool_survives_raw_runtime_deletion_and_replaced_inode_denies(self):
        receipt = self.invoke()
        original = b"".join(export.read_chunks(receipt))
        shutil.rmtree(self.runroot)
        shutil.rmtree(self.output)
        self.assertEqual(b"".join(export.read_chunks(receipt)), original)
        previous = self.spool.with_suffix(".original")
        self.spool.rename(previous)
        shutil.copytree(previous, self.spool)
        with self.assertRaises(Denied):
            list(export.read_chunks(receipt))

    def test_empty_preexisting_spool_and_symlink_are_never_adopted(self):
        self.spool.mkdir(mode=0o700)
        self.deny()
        self.assertEqual(list(self.spool.iterdir()), [])
        self.spool.rmdir()
        self.spool.symlink_to(self.output, target_is_directory=True)
        self.deny()
        self.assertEqual(self.spool.resolve(), self.output)

    def test_wrong_native_tuple_or_lifecycle_logic_denies_before_export(self):
        self.source["workflow_run_id"] = "999"
        self.write(self.base / "manifest.json", self.source)
        self.deny()
        self.assertFalse((self.spool / export.ARCHIVE).exists())
        self.source["workflow_run_id"] = "501"
        self.write(self.base / "manifest.json", self.source)
        data = json.loads(self.lifecycle.read_bytes())
        data["destroy_exit_code"] = 1
        self.write(self.lifecycle, data)
        self.deny()

    def test_report_traversal_context_paths_missing_required_and_wrong_formats_deny(self):
        for bad in ("../client.key", "/client.key", "junit/../../client.key", "junit/report.xml/", "junit//report.xml"):
            self.source["results"][0]["junit"] = [bad]
            self.write(self.base / "manifest.json", self.source)
            self.deny()
        self.source["results"][0]["junit"] = []
        self.write(self.base / "manifest.json", self.source)
        self.deny()

    def test_input_symlink_hardlink_and_directory_symlink_are_not_followed(self):
        report = self.base / "junit/report.xml"
        original = report.read_bytes()
        report.unlink()
        report.symlink_to(self.lifecycle)
        self.deny()
        report.unlink()
        other = self.root / "other.xml"
        self.write(other, original)
        os.link(other, report)
        self.deny()
        report.unlink()
        self.write(report, original)
        directory = self.base / "junit"
        renamed = self.base / "moved"
        directory.rename(renamed)
        directory.symlink_to(renamed, target_is_directory=True)
        self.deny()

    def test_explicit_member_source_total_and_generated_limits_deny(self):
        for changes in ({"max_members": 3}, {"max_member_bytes": 10}, {"max_total_evidence_bytes": 100}):
            old = dict(self.bounds)
            self.bounds.update(changes)
            self.deny()
            self.bounds.update(old)
        self.bounds["max_member_bytes"] = 900
        self.write(self.base / "junit/report.xml", b'<testsuite>' + b'<testcase/>' * 30 + b'</testsuite>')
        self.deny()  # Normalized per-test metadata may exceed the original XML.

    def test_partial_publication_never_overwrites_or_adopts_existing_archive(self):
        raw = b"retained-unknown-partial"
        self.spool.mkdir(mode=0o700)
        self.write(self.spool / export.ARCHIVE, raw)
        self.deny()
        self.assertEqual((self.spool / export.ARCHIVE).read_bytes(), raw)
        self.assertFalse((self.spool / export.RECEIPT).exists())

    def test_receipt_failure_retains_archive_without_replay(self):
        original = export._create
        def fail_receipt(parent, name, raw):
            if name == export.RECEIPT:
                raise OSError(SECRET)
            return original(parent, name, raw)
        with mock.patch.object(export, "_create", side_effect=fail_receipt):
            self.deny()
        self.assertTrue((self.spool / export.ARCHIVE).exists())
        self.deny()

    def test_stream_rejects_archive_or_receipt_tampering(self):
        receipt = self.invoke()
        altered = replace(receipt, sha256="f" * 64)
        with self.assertRaises(Denied):
            list(export.read_chunks(altered))
        self.write(self.spool / export.ARCHIVE, b"replacement")
        with self.assertRaises(Denied):
            list(export.read_chunks(receipt))
        self.deny()

    def test_full_policy_independently_detects_secret_even_with_valid_checksums_and_clean_claim(self):
        for raw in (b"password=unredacted-value", b"Authorization: Bearer long-secret-token-value",
                    b'{"parameters":[{"name":"password","value":"unredacted-value"}]}',
                    b'-----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY-----', policy.CANARY_BYTES):
            with self.subTest(raw=raw):
                self.write(self.base / "logs/scenario.log", raw)
                self.refresh_checksums()
                self.deny()
        self.assertFalse((self.spool / export.ARCHIVE).exists())

    def test_full_policy_rejects_exact_root_tls_in_binary_despite_no_generic_pattern(self):
        self.write(self.base / "allure-results/recording.webm", b"\x00\xffROOT_PRIVATE_TLS_MATERIAL\x00")
        self.refresh_checksums()
        self.deny()

    def test_full_policy_rejects_missing_recording_and_unchecksummed_file(self):
        recording = self.base / "allure-results/recording.webm"
        original = recording.read_bytes()
        recording.unlink()
        self.refresh_checksums()
        self.deny()  # Native Allure still declares its mandatory attachment.
        self.write(recording, original)
        self.refresh_checksums()
        self.write(self.base / "logs/unchecksummed.log", b"not included by source scanner")
        self.deny()

    def test_full_policy_rederives_cases_and_allure_identity_instead_of_accepting_booleans(self):
        self.source["results"][0]["test_cases"][0]["name"] = "fabricated-case"
        self.refresh_checksums()
        self.deny()
        self.source["results"][0]["test_cases"][0]["name"] = "route"
        path = self.base / "allure-results/one-result.json"
        data = json.loads(path.read_bytes())
        data["labels"][0]["value"] = "b" * 40
        self.write(path, data)
        self.refresh_checksums()
        self.deny()

    def test_full_policy_rejects_unknown_category_and_borrowed_root_matrix(self):
        self.write(self.base / "unexpected/unapproved.txt", b"not a Thin evidence category")
        self.refresh_checksums()
        self.deny()
        (self.base / "unexpected/unapproved.txt").unlink()
        (self.base / "unexpected").rmdir()
        self.source["matrix"]["expected"][0]["target"] = "foreign-target"
        self.refresh_checksums()
        self.deny()

    def test_full_policy_scans_nested_trace_archives_and_rejects_links_traversal_and_bombs(self):
        def zip_bytes(name, raw, mode=None):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as stream:
                row = zipfile.ZipInfo(name)
                row.compress_type = zipfile.ZIP_DEFLATED
                if mode is not None:
                    row.create_system = 3
                    row.external_attr = mode << 16
                stream.writestr(row, raw)
            return buffer.getvalue()
        for raw in (zip_bytes("trace.json", b"password=hidden-inside-trace"),
                    zip_bytes("../outside", b"clean"), zip_bytes("link", b"/private", 0o120777),
                    zip_bytes("large", b"a" * 65536),
                    zip_bytes("nested.zip", zip_bytes("inner.json", b"password=inside-nested"))):
            with self.subTest(size=len(raw)):
                self.write(self.base / "playwright-traces/trace.zip", raw)
                self.refresh_checksums()
                self.deny()

    def test_full_policy_preserves_clean_trace_members_and_original_checksums(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as stream:
            stream.writestr("trace.json", '{"action":"page.goto","result":"failed"}')
        original = buffer.getvalue()
        self.write(self.base / "playwright-traces/trace.zip", original)
        self.refresh_checksums()
        receipt = self.invoke()
        with tarfile.open(fileobj=io.BytesIO(b"".join(export.read_chunks(receipt))), mode="r:gz") as stream:
            self.assertEqual(stream.extractfile("evidence/playwright-traces/trace.zip").read(), original)
            self.assertEqual(stream.extractfile("evidence/checksums/SHA256SUMS").read(),
                             (self.base / "checksums/SHA256SUMS").read_bytes())


if __name__ == "__main__":
    unittest.main()
