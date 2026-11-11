"""Pure sanitized diagnostics; all instance/exit native provenance is fixture-only."""
from copy import deepcopy
from dataclasses import replace
import hashlib
from pathlib import Path
import sys
import unittest

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import ledger, operating_export as export
from incus_lease_issuer.identity import Denied


def fixture(case="failure"):
    expected = export.ExpectedOperating(case, 501, "a" * 40, "b" * 40,
        export.operating_cells.instance_name(case, 501), "11111111-2222-3333-4444-555555555555")
    root = {"pid": 101, "start_ticks": 201, "boot_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "container_id": "c" * 64, "manifest_sha256": "d" * 64, "exit_code": 17, "signal": None, "observed_at": 300,
        "stdout_bytes": 0, "stdout_sha256": hashlib.sha256(b"").hexdigest(), "stdout_state": "complete",
        "stderr_bytes": 0, "stderr_sha256": hashlib.sha256(b"").hexdigest(), "stderr_state": "complete"}
    report = {"schema": 1, "kind": "operating", "case": case, "run_id": expected.run_id, "run_attempt": 1,
        "source_sha": expected.source_sha, "controller_sha": expected.controller_sha,
        "execution": {"raw_exit_code": 17, "signal": None},
        "instance": {"name": expected.instance_name, "uuid": expected.instance_uuid, "state": "Running"},
        "observations": {"workload_failed": True, "broker_cancel_sent": False, "controller_heartbeat_ceased": False},
        "root_finalization": "pending"}
    return report, expected, root


class OperatingExportTests(unittest.TestCase):
    def test_three_cases_return_only_bounded_diagnostics_not_quality_acceptance(self):
        for case in ("failure", "broker-cancel", "expiry-controller-loss"):
            raw, expected, root = fixture(case)
            result = export.normalize_operating(ledger.canonical(raw), expected, root)
            value = result.value
            self.assertFalse(value["evidence_policy_complete"])
            self.assertEqual(value["root_finalization"], "pending")
            self.assertEqual(value["reported"]["scope"], "untrusted-controller-observations")
            self.assertEqual(value["root_engine_exit"]["exit_code"], 17)
            self.assertEqual(value["root_engine_exit"]["source_record_sha256"], ledger.digest(root))
            self.assertEqual(result.size, len(result.canonical_bytes))
            self.assertEqual(result.sha256, hashlib.sha256(result.canonical_bytes).hexdigest())
            self.assertNotIn("quality_pass", value)
            self.assertNotIn("operating_acceptance", value)
            self.assertNotIn("roles", value)

    def test_pending_or_missing_controller_report_never_predicts_root_signal(self):
        raw, expected, root = fixture("broker-cancel")
        raw["execution"] = {"raw_exit_code": None, "signal": None}
        root.update(exit_code=None, signal=15)
        result = export.normalize_operating(ledger.canonical(raw), expected, root).value
        self.assertIsNone(result["reported"]["execution"]["signal"])
        self.assertEqual(result["root_engine_exit"]["signal"], 15)
        unavailable = export.normalize_operating(None, expected, root).value
        self.assertEqual(unavailable["controller_report"], "unavailable")
        self.assertIsNone(unavailable["reported"])
        self.assertFalse(unavailable["evidence_policy_complete"])

    def test_known_report_exit_or_signal_contradiction_denies(self):
        raw, expected, root = fixture()
        for execution in ({"raw_exit_code": 0, "signal": None}, {"raw_exit_code": None, "signal": 9},
                          {"raw_exit_code": True, "signal": None}, {"raw_exit_code": 17, "signal": 9}):
            raw["execution"] = execution
            with self.assertRaisesRegex(Denied, "^operating-export-held$"):
                export.normalize_operating(ledger.canonical(raw), expected, root)

    def test_wrong_run_head_controller_case_or_root_ready_uuid_cannot_be_borrowed(self):
        original, expected, root = fixture()
        for key, value in (("run_id", 502), ("run_attempt", 2), ("run_attempt", True),
                           ("source_sha", "9" * 40), ("controller_sha", "9" * 40), ("case", "broker-cancel")):
            raw = deepcopy(original); raw[key] = value
            with self.assertRaises(Denied): export.normalize_operating(ledger.canonical(raw), expected, root)
        for key, value in (("name", "foreign-instance"), ("uuid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), ("state", "Deleted")):
            raw = deepcopy(original); raw["instance"][key] = value
            with self.assertRaises(Denied): export.normalize_operating(ledger.canonical(raw), expected, root)

    def test_no_extra_secret_free_text_duplicates_nonfinite_or_oversize_frame(self):
        raw, expected, root = fixture()
        bad = deepcopy(raw); bad["token"] = "private bearer fixture must never escape"
        frames = [ledger.canonical(bad), ledger.canonical(raw).replace(b'"schema":1', b'"schema":1,"schema":1'),
                  ledger.canonical(raw).replace(b'"workload_failed":true', b'"workload_failed":NaN'),
                  b" " * (export.MAX_RAW + 1)]
        for frame in frames:
            with self.assertRaisesRegex(Denied, "^operating-export-held$") as caught:
                export.normalize_operating(frame, expected, root)
            self.assertNotIn("private bearer", str(caught.exception))

    def test_observation_flags_remain_untrusted_and_require_exact_booleans(self):
        raw, expected, root = fixture()
        raw["observations"] = {key: False for key in raw["observations"]}
        self.assertFalse(export.normalize_operating(ledger.canonical(raw), expected, root).value["reported"]["observations"]["workload_failed"])
        raw["observations"]["workload_failed"] = 1
        with self.assertRaises(Denied): export.normalize_operating(ledger.canonical(raw), expected, root)

    def test_job_supplied_two_field_exit_cannot_replace_full_root_exit_projection(self):
        raw, expected, root = fixture()
        with self.assertRaises(Denied): export.normalize_operating(ledger.canonical(raw), expected, raw["execution"])
        for key, value in (("exit_code", None), ("pid", True), ("stdout_state", "unknown"), ("stdout_sha256", "f" * 64)):
            invalid = {**root, key: value}
            with self.assertRaises(Denied): export.normalize_operating(ledger.canonical(raw), expected, invalid)

    def test_consistent_foreign_instance_tuple_still_fails_root_case_run_name_formula(self):
        raw, expected, root = fixture()
        expected = replace(expected, instance_name="foreign-but-wellformed-name")
        raw["instance"]["name"] = expected.instance_name
        with self.assertRaises(Denied):
            export.normalize_operating(ledger.canonical(raw), expected, root)
