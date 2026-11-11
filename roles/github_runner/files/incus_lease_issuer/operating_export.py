"""Pure bounded operating diagnostics, never business-quality or custody PASS.

Root supplies its independently ready-proved instance tuple and previously
Ledger-validated engine exit. Controller observations remain explicitly
untrusted. This parser cannot establish either input's native provenance.
"""
from dataclasses import dataclass
import hashlib
import re

from . import engine_policy, identity, ledger, operating_cells
from .identity import Denied, require

MAX_RAW = 16384
UUID = re.compile("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\\Z")
OBSERVATIONS = frozenset({"workload_failed", "broker_cancel_sent", "controller_heartbeat_ceased"})
EXIT_KEYS = frozenset({"pid", "start_ticks", "boot_id", "container_id", "manifest_sha256", "exit_code", "signal", "observed_at",
                      "stdout_bytes", "stdout_sha256", "stdout_state", "stderr_bytes", "stderr_sha256", "stderr_state"})


@dataclass(frozen=True)
class ExpectedOperating:
    """controller_sha is native reusable B, not the independent archive/action A."""

    case: str
    run_id: int
    source_sha: str
    controller_sha: str
    instance_name: str
    instance_uuid: str


@dataclass(frozen=True)
class OperatingDiagnostic:
    canonical_bytes: bytes
    sha256: str
    size: int

    @property
    def value(self):
        return identity.decode_json(self.canonical_bytes)


def _status(code, signum, *, pending=False):
    require((pending and code is None and signum is None)
            or (type(code) is int and 0 <= code <= 255 and signum is None)
            or (code is None and type(signum) is int and 1 <= signum <= 64), "operating-exit-status")


def _expected(value):
    require(type(value) is ExpectedOperating, "operating-export-expectation")
    operating_cells.selector(value.case)
    require(type(value.run_id) is int and 0 < value.run_id < 2**63, "operating-export-run")
    for sha in (value.source_sha, value.controller_sha):
        require(type(sha) is str and re.fullmatch("[0-9a-f]{40}", sha), "operating-export-commit")
    require(type(value.instance_name) is str and value.instance_name == operating_cells.instance_name(value.case, value.run_id)
            and type(value.instance_uuid) is str and UUID.fullmatch(value.instance_uuid), "operating-export-instance")


def _root_exit(value):
    require(type(value) is dict and set(value) == EXIT_KEYS, "operating-root-exit-schema")
    _status(value["exit_code"], value["signal"])
    require(all(type(value[key]) is int and value[key] > 0 for key in ("pid", "start_ticks", "observed_at"))
            and type(value["boot_id"]) is str and UUID.fullmatch(value["boot_id"])
            and type(value["container_id"]) is str and re.fullmatch("[0-9a-f]{64}", value["container_id"]),
            "operating-root-exit-process")
    engine_policy._hash(value["manifest_sha256"])
    for stream in ("stdout", "stderr"):
        count = value[stream + "_bytes"]
        require(type(count) is int and 0 <= count <= engine_policy.MAX_CAPTURE_STREAM_BYTES
                and value[stream + "_state"] in {"complete", "limited", "incomplete"}, "operating-root-exit-stream")
        engine_policy._hash(value[stream + "_sha256"])
        require(count != 0 or value[stream + "_sha256"] == hashlib.sha256(b"").hexdigest(),
                "operating-root-exit-stream")
    return {"exit_code": value["exit_code"], "signal": value["signal"], "manifest_sha256": value["manifest_sha256"],
            "observed_at": value["observed_at"], "stdout_state": value["stdout_state"], "stderr_state": value["stderr_state"],
            "source_record_sha256": ledger.digest(value)}


def normalize_operating(raw, expected, actual_root_engine_exit):
    """Return diagnostic bytes only; missing/killed reports cannot become PASS."""
    try:
        _expected(expected)
        actual = _root_exit(actual_root_engine_exit)
        report, source_sha, source_size = None, None, 0
        if raw is not None:
            require(type(raw) is bytes and 0 < len(raw) <= MAX_RAW, "operating-report-bound")
            value = identity.decode_json(raw)
            engine_policy._keys(value, {"schema", "kind", "case", "run_id", "run_attempt", "source_sha", "controller_sha",
                                       "execution", "instance", "observations", "root_finalization"})
            require(type(value["schema"]) is int and value["schema"] == 1 and value["kind"] == "operating"
                    and value["case"] == expected.case and type(value["run_id"]) is int and value["run_id"] == expected.run_id
                    and type(value["run_attempt"]) is int and value["run_attempt"] == 1
                    and value["source_sha"] == expected.source_sha and value["controller_sha"] == expected.controller_sha
                    and value["root_finalization"] == "pending", "operating-report-tuple")
            execution = engine_policy._keys(value["execution"], {"raw_exit_code", "signal"})
            _status(execution["raw_exit_code"], execution["signal"], pending=True)
            if execution["raw_exit_code"] is not None or execution["signal"] is not None:
                require((execution["raw_exit_code"], execution["signal"]) == (actual["exit_code"], actual["signal"]),
                        "operating-report-exit-mismatch")
            instance = engine_policy._keys(value["instance"], {"name", "uuid", "state"})
            require(instance["name"] == expected.instance_name and instance["uuid"] == expected.instance_uuid
                    and type(instance["state"]) is str and instance["state"] in {"Running", "Stopped", "Unknown"},
                    "operating-report-instance")
            observations = engine_policy._keys(value["observations"], OBSERVATIONS)
            require(all(type(item) is bool for item in observations.values()), "operating-report-observations")
            report = {"execution": execution, "instance": instance, "observations": observations,
                      "scope": "untrusted-controller-observations"}
            source_sha, source_size = hashlib.sha256(raw).hexdigest(), len(raw)
        value = {"schema": 1, "kind": "operating-diagnostic", "case": expected.case, "run_id": expected.run_id,
            "run_attempt": 1, "source_sha": expected.source_sha, "controller_sha": expected.controller_sha,
            "expected_instance": {"name": expected.instance_name, "uuid": expected.instance_uuid},
            "controller_report": "available" if report is not None else "unavailable", "reported": report,
            "source_report_sha256": source_sha, "source_report_bytes": source_size, "root_engine_exit": actual,
            "root_finalization": "pending", "evidence_policy_complete": False}
        canonical = ledger.canonical(value)
        require(len(canonical) <= MAX_RAW, "operating-diagnostic-bound")
        return OperatingDiagnostic(canonical, hashlib.sha256(canonical).hexdigest(), len(canonical))
    except Exception:
        # Never print controller bytes, extra secret fields or parser exceptions.
        raise Denied("operating-export-held") from None
