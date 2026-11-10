"""Reviewed static extraction of Lightning IT Thin evidence policy.

Source: ansible-collection-supplementary/scripts/quality_evidence.py
Source SHA256: 0c1dc5877ecb93fd55a9418ff360383c51e356c82c0bdc9268613f7e3c35e2ab
Only bounded scan/report helpers are copied; no assemble/CLI/job-code import.
Root exporter validates its own nofollow inventory and stages sealed bytes.

MIT License

Copyright (c) 2026 Lightning IT

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

ALLOWED_RESULT_STATUSES = (
    "passed",
    "failed",
    "skipped-with-approved-justification",
    "not-applicable",
    "infrastructure-error",
    "blocked-external-service",
    "blocked-external-license",
    "blocked-external-infrastructure",
)
BLOCKED_STATUSES = {
    "blocked-external-service",
    "blocked-external-license",
    "blocked-external-infrastructure",
}
PROFILES = ("tiny", "heavy", "application-acceptance")
TEST_APPLICATION_MODES = {"runtime-container", "declared-evidence", "not-applicable"}
DECLARED_APPLICATION_TYPES = {"application", "external-api", "host-package", "host-service"}
MUTABLE_APPLICATION_VERSIONS = {
    "latest",
    "n/a",
    "not-applicable",
    "unknown",
    "unversioned",
    "unspecified",
}
MANDATORY_PREREQUISITES = (
    "lint",
    "build",
    "coverage",
    "tiny",
    "heavy",
    "acceptance",
    "cleanup",
    "destroy",
)
PROFILE_REGISTRY_KEYS = {
    "tiny": "tiny",
    "heavy": "heavy",
    "application-acceptance": "application_acceptance",
}
REQUIRED_RELEASE_SECURITY_FILES = (
    "sbom.cdx.json",
    "vulnerability-report.json",
    "trivy-vulnerability-report.json",
    "provenance.json",
    "secret-scan-summary.json",
)
EVIDENCE_DIRECTORIES = (
    "source",
    "collection",
    "matrix",
    "junit",
    "allure-results",
    "allure-report",
    "logs",
    "screenshots",
    "playwright-traces",
    "configuration",
    "dependencies",
    "security",
    "checksums",
)
CANARY = "LIT_EVIDENCE_REDACTION_CANARY_7f38f67e"
CANARY_BYTES = CANARY.encode("ascii")
MAX_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 256 * 1024 * 1024
MAX_EVIDENCE_TOTAL_BYTES = 512 * 1024 * 1024
MAX_EVIDENCE_FILES = 10_000
MAX_ARCHIVE_MEMBERS = 4_096
MAX_ARCHIVE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_COMPRESSION_RATIO = 200

SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"authorization|proxy[_-]?authorization|cookie|set-cookie|api[_-]?key|x[_-]?api[_-]?key|"
    r"bind[_-]?credential|private[_-]?key|root[_-]?token|"
    r"unseal[_-]?key|recovery[_-]?key|activation[_-]?(?:code|key))"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:password|passwd|secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
    r"id[_-]?token|authorization|proxy[_-]?authorization|cookie|set-cookie|api[_-]?key|"
    r"x[_-]?api[_-]?key|bind[_-]?credential|private[_-]?key|"
    r"root[_-]?token|unseal[_-]?key|recovery[_-]?key|activation[_-]?(?:code|key))\b"
    r"\s*[:=]\s*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,}\]]+)"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}")
BASIC_AUTH_RE = re.compile(r"(?i)\bbasic\s+[a-z0-9+/]{4,}={0,2}")
JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"
    r"(?![A-Za-z0-9_-])"
)
API_KEY_RE = re.compile(
    r"(?i)\b(?:gh[pousr]_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[a-z0-9-]{10,}|sk-[a-z0-9_-]{20,})\b"
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
URL_CREDENTIAL_RE = re.compile(r"(://[^\s/:@]+:)[^\s/@]+(@)")
SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)\s*:\s*).+$"
)
XML_SECRET_PROPERTY_RE = re.compile(
    r"(?is)(\bname\s*=\s*[\"'](?:password|passwd|secret|client[_-]?secret|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|authorization|cookie|set-cookie|api[_-]?key|x[_-]?api[_-]?key|"
    r"private[_-]?key)[\"'][^>]*?\bvalue\s*=\s*[\"'])([^\"']*)([\"'])"
)


class EvidenceError(RuntimeError):
    """A fail-closed evidence processing error."""


@dataclass(frozen=True)
class Identity:
    """Required identity of one executed role/profile matrix result."""

    role: str
    profile: str
    scenario: str
    target: str
    run_attempt: str

    @property
    def cell_key(self) -> tuple[str, str, str, str]:
        return (self.scenario, self.profile, self.target, self.run_attempt)

    @property
    def result_key(self) -> tuple[str, str, str, str, str]:
        return (self.role, self.profile, self.scenario, self.target, self.run_attempt)

    @property
    def identifier(self) -> str:
        fields = (self.role, self.profile, self.scenario, self.target, f"attempt-{self.run_attempt}")
        return "/".join(slug(field) for field in fields)


def slug(value: object) -> str:
    rendered = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(value).strip()).strip("-.")
    return rendered or "unknown"


def normalize_profile(value: object) -> str:
    profile = str(value or "").strip().lower().replace("_", "-").replace(" ", "-")
    aliases = {
        "acceptance": "application-acceptance",
        "application": "application-acceptance",
        "application-acceptance": "application-acceptance",
    }
    return aliases.get(profile, profile or "unknown")


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _bounded_read(path: Path, limit: int = MAX_EVIDENCE_FILE_BYTES) -> bytes:
    """Read a regular evidence file without allowing unbounded memory use."""

    size = path.stat().st_size
    if size > limit:
        raise EvidenceError(f"{path}: file exceeds {limit}-byte evidence limit")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise EvidenceError(f"{path}: file exceeds {limit}-byte evidence limit")
    return data


def _strict_json_loads(value: str) -> Any:
    def object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        for key, item in pairs:
            if key in payload:
                raise EvidenceError(f"duplicate JSON key: {key}")
            payload[key] = item
        return payload

    return json.loads(value, object_pairs_hook=object_without_duplicates)


def _structured_secret_label(value: Any) -> bool:
    return isinstance(value, str) and SECRET_KEY_RE.search(value) is not None


def _contains_unredacted_value(value: Any) -> bool:
    if isinstance(value, dict):
        return False
    if isinstance(value, list):
        return any(_contains_unredacted_value(item) for item in value)
    return isinstance(value, (str, bytes)) and value not in {"", "[REDACTED]", b"", b"[REDACTED]"}


def _contains_structured_secret_value(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_structured_secret_value(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_structured_secret_value(item) for item in value)
    return value not in {None, "", "[REDACTED]", b"", b"[REDACTED]"}


def _structured_secret_findings(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)) and _contains_unredacted_value(item):
                return True
        label = next(
            (
                item
                for key, item in value.items()
                if str(key).lower() in {"name", "key", "header", "parameter", "field"}
                and _structured_secret_label(item)
            ),
            None,
        )
        if label is not None:
            for key, item in value.items():
                if str(key).lower() in {"value", "values", "content", "text", "default"} and (
                    _contains_structured_secret_value(item)
                ):
                    return True
        return any(_structured_secret_findings(item) for item in value.values())
    if isinstance(value, list):
        return any(_structured_secret_findings(item) for item in value)
    return False


def _scan_payload(data: bytes, display_path: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if CANARY_BYTES in data:
        findings.append({"path": display_path, "kind": "canary"})
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", errors="ignore")
    patterns = (
        ("private-key", PRIVATE_KEY_RE),
        ("bearer-token", BEARER_RE),
        ("basic-authorization", BASIC_AUTH_RE),
        ("jwt", JWT_RE),
        ("api-key", API_KEY_RE),
        ("url-credential", URL_CREDENTIAL_RE),
        ("sensitive-header", SENSITIVE_HEADER_RE),
        ("xml-secret-property", XML_SECRET_PROPERTY_RE),
        ("secret-assignment", SECRET_ASSIGNMENT_RE),
    )
    for kind, pattern in patterns:
        for match in pattern.finditer(text):
            matched = match.group(0)
            if "[REDACTED" in matched:
                continue
            findings.append({"path": display_path, "kind": kind})
            break
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    if parsed is not None and _structured_secret_findings(parsed):
        findings.append({"path": display_path, "kind": "structured-secret"})
    return findings


def _properties(root: ET.Element) -> dict[str, str]:
    properties: dict[str, str] = {}
    containers = [element for element in root.iter() if local_name(element.tag) in {"testsuite", "testsuites"}]
    for container in containers:
        for property_container in container:
            if local_name(property_container.tag) != "properties":
                continue
            for element in property_container:
                if local_name(element.tag) != "property":
                    continue
                name = str(element.attrib.get("name", "")).strip().lower().replace(".", "_")
                if not name:
                    continue
                value = element.attrib.get("value")
                properties[name] = str(value if value is not None else element.text or "").strip()
    for key, value in root.attrib.items():
        properties.setdefault(str(key).strip().lower().replace(".", "_"), str(value).strip())
    return properties


def _split_roles(value: object) -> list[str]:
    if isinstance(value, list):
        return sorted({str(item).strip() for item in value if str(item).strip()})
    return sorted({item.strip() for item in str(value or "").split(",") if item.strip()})


def _case_details(testcase: ET.Element) -> dict[str, Any]:
    status = "passed"
    problem: ET.Element | None = None
    for child in testcase:
        kind = local_name(child.tag)
        if kind in {"failure", "error", "skipped"}:
            status = kind
            problem = child
            break
    duration_value = testcase.attrib.get("time", "0")
    try:
        duration = max(float(duration_value), 0.0)
    except (TypeError, ValueError):
        duration = 0.0
    details: dict[str, Any] = {
        "classname": str(testcase.attrib.get("classname", "unknown")),
        "name": str(testcase.attrib.get("name", "unnamed")),
        "status": status,
        "duration_seconds": duration,
    }
    case_properties: dict[str, str] = {}
    for child in testcase:
        if local_name(child.tag) != "properties":
            continue
        for element in child:
            if local_name(element.tag) != "property":
                continue
            name = str(element.attrib.get("name", "")).strip().lower().replace(".", "_")
            value = element.attrib.get("value")
            case_properties[name] = str(value if value is not None else element.text or "").strip()
    explicit_roles = (
        testcase.attrib.get("roles")
        or testcase.attrib.get("role")
        or case_properties.get("roles")
        or case_properties.get("role")
        or ""
    )
    details["roles"] = _split_roles(explicit_roles)
    if problem is not None:
        details["message"] = str(problem.attrib.get("message") or (problem.text or "").strip())[:4000]
        details["type"] = str(problem.attrib.get("type", ""))
        if status == "skipped":
            approved = str(problem.attrib.get("approved", "")).lower() in {"1", "true", "yes"}
            details["approved"] = approved
    return details


def _is_opaque_process_case(test_cases: Sequence[dict[str, Any]]) -> bool:
    if len(test_cases) != 1:
        return False
    rendered = f"{test_cases[0].get('classname', '')} {test_cases[0].get('name', '')}".lower()
    process_tokens = (
        "molecule process",
        "molecule-process",
        "scenario process",
        "scenario execution",
        "process exit",
        "command exit",
        "molecule test",
    )
    return any(token in rendered for token in process_tokens)


def parse_junit(path: Path) -> dict[str, Any]:
    """Parse JUnit from real testcases, ignoring untrustworthy suite counters."""

    raw = _bounded_read(path)
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise EvidenceError("JUnit document contains a forbidden DTD or entity")
    try:
        # ElementTree is safe here because DTD/entity declarations were rejected above.
        root = ET.fromstring(raw)  # noqa: S314
    except ET.ParseError as error:
        raise EvidenceError(f"malformed JUnit: {error}") from error
    if local_name(root.tag) not in {"testsuite", "testsuites"}:
        raise EvidenceError(f"unsupported JUnit root element: {local_name(root.tag)}")
    test_cases = [_case_details(element) for element in root.iter() if local_name(element.tag) == "testcase"]
    if not test_cases:
        raise EvidenceError("JUnit contains no individual testcases")
    properties = _properties(root)
    suite_roles = _split_roles(_property(properties, "roles", "role"))
    if len(suite_roles) == 1:
        for case in test_cases:
            if not case["roles"]:
                case["roles"] = list(suite_roles)
    elif len(suite_roles) > 1:
        for case in test_cases:
            if not case["roles"]:
                continue
            if len(case["roles"]) != 1:
                raise EvidenceError("multi-role JUnit requires exactly one explicit role per testcase")
            if not set(case["roles"]) <= set(suite_roles):
                raise EvidenceError("JUnit testcase role is not declared by the suite")
    totals = {
        "tests": len(test_cases),
        "failures": sum(case["status"] == "failure" for case in test_cases),
        "errors": sum(case["status"] == "error" for case in test_cases),
        "skipped": sum(case["status"] == "skipped" for case in test_cases),
    }
    approved_property = any(
        properties.get(key, "").lower() in {"1", "true", "yes", "approved"}
        for key in ("approved_skip", "skip_approved")
    ) or bool(properties.get("approved_justification", "").strip())
    skipped_cases = [case for case in test_cases if case["status"] == "skipped"]
    skips_approved = bool(skipped_cases) and (
        approved_property or all(case.get("approved") and case.get("message") for case in skipped_cases)
    )
    opaque = _is_opaque_process_case(test_cases)
    evidence_fallback = properties.get("framework", "").lower() == "evidence-fallback"
    if evidence_fallback:
        status = "infrastructure-error"
    elif totals["failures"] or totals["errors"] or opaque:
        status = "failed"
    elif totals["skipped"]:
        status = "skipped-with-approved-justification" if skips_approved else "failed"
    else:
        status = "passed"
    suite_names = [
        str(element.attrib.get("name", ""))
        for element in root.iter()
        if local_name(element.tag) in {"testsuite", "testsuites"}
    ]
    framework = properties.get("framework", "").lower()
    if not framework and any("pytest" in name.lower() for name in suite_names):
        framework = "pytest"
    logical_payload = {
        "test_cases": test_cases,
        "totals": totals,
        "status": status,
    }
    return {
        "status": status,
        "totals": totals,
        "test_cases": test_cases,
        "properties": properties,
        "framework": framework or "junit",
        "meaningful": not opaque,
        "suite_names": [name for name in suite_names if name],
        "content_sha256": hashlib.sha256(raw).hexdigest(),
        "logical_sha256": hashlib.sha256(
            json.dumps(logical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }


def _report_for_role(report: dict[str, Any], role: str, declared_roles: Sequence[str]) -> dict[str, Any]:
    """Return only testcases explicitly attributable to one role."""

    declared = set(declared_roles)
    cases = report["test_cases"]
    if len(declared) > 1:
        missing = [case["name"] for case in cases if not case.get("roles")]
        if missing:
            raise EvidenceError("multi-role JUnit lacks explicit per-test role identity: " + ", ".join(sorted(missing)))
    selected = [copy.deepcopy(case) for case in cases if role in set(case.get("roles", []))]
    if not selected:
        raise EvidenceError(f"JUnit contains no meaningful testcase explicitly assigned to role {role}")
    totals = {
        "tests": len(selected),
        "failures": sum(case["status"] == "failure" for case in selected),
        "errors": sum(case["status"] == "error" for case in selected),
        "skipped": sum(case["status"] == "skipped" for case in selected),
    }
    skipped = [case for case in selected if case["status"] == "skipped"]
    approved = bool(skipped) and all(case.get("approved") and case.get("message") for case in skipped)
    opaque = _is_opaque_process_case(selected)
    if report.get("framework") == "evidence-fallback" or report.get("infrastructure_error"):
        status = "infrastructure-error"
    elif totals["failures"] or totals["errors"] or opaque:
        status = "failed"
    elif totals["skipped"]:
        status = "skipped-with-approved-justification" if approved else "failed"
    else:
        status = "passed"
    logical_payload = {"test_cases": selected, "totals": totals, "status": status}
    scoped = {
        **report,
        "status": status,
        "totals": totals,
        "test_cases": selected,
        "meaningful": not opaque,
        "logical_sha256": hashlib.sha256(
            json.dumps(logical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    return scoped


def _property(properties: dict[str, str], *names: str) -> str:
    for name in names:
        normalized = name.lower().replace(".", "_")
        if properties.get(normalized):
            return properties[normalized]
    return ""


def _valid_commit(value: str) -> bool:
    return re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is not None


def _tested_commit() -> str:
    """Return the exact source SHA selected and checked out by the workflow."""
    return os.getenv("QUALITY_SOURCE_SHA") or os.getenv("GITHUB_SHA") or "unknown"


def _report_commit(report: dict[str, Any]) -> str:
    return _property(report.get("properties", {}), "commit_sha", "git_commit", "github_sha")


def _allure_status(case_status: str) -> str:
    return {"passed": "passed", "failure": "failed", "error": "broken", "skipped": "skipped"}.get(case_status, "broken")


def _allure_identity(payload: dict[str, Any]) -> dict[str, set[str]]:
    values: dict[str, set[str]] = {}
    for collection in (payload.get("labels", []), payload.get("parameters", [])):
        if not isinstance(collection, list):
            continue
        for item in collection:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip().lower().replace("_", "-")
            value = str(item.get("value", "")).strip()
            if name and value:
                values.setdefault(name, set()).add(value)
    return values


def _allure_has_identity(payload: dict[str, Any], identity: Identity, commit_sha: str) -> bool:
    if not _valid_commit(commit_sha):
        return False
    labels = _allure_identity(payload)
    checks = (
        ({"role"}, identity.role),
        ({"profile"}, identity.profile),
        ({"suite", "scenario"}, identity.scenario),
        ({"host", "target"}, identity.target),
        ({"runattempt", "run-attempt"}, identity.run_attempt),
        ({"commit-sha"}, commit_sha),
    )
    for names, expected in checks:
        observed = set().union(*(labels.get(name, set()) for name in names))
        if observed != {expected}:
            return False
    return True


def _allure_has_testcase_identity(payload: dict[str, Any], case: dict[str, Any]) -> bool:
    """Require the native result to identify the same named JUnit testcase."""

    name = str(case.get("name", ""))
    classname = str(case.get("classname", ""))
    full_name = str(payload.get("fullName", ""))
    if not name or not classname or str(payload.get("name", "")) != name or not full_name:
        return False
    normalized = full_name.replace("#", ".").replace("::", ".")
    base_name = name.split("[", 1)[0]
    classnames = tuple(dict.fromkeys((classname, classname.rsplit(".", 1)[-1])))
    test_names = tuple(dict.fromkeys((name, base_name)))
    return any(
        normalized == f"{candidate}.{test_name}" or normalized.endswith(f".{candidate}.{test_name}")
        for candidate in classnames
        for test_name in test_names
    )


def _native_matches(
    cases: Sequence[dict[str, Any]],
    native: Sequence[tuple[str, dict[str, Any]]],
    identity: Identity,
    *,
    commit_sha: str | None = None,
    used_paths: set[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Match exactly one status- and identity-consistent Allure result per JUnit testcase."""

    matches: list[str] = []
    failures: list[str] = []
    used = used_paths if used_paths is not None else set()
    expected_commit = str(commit_sha or _tested_commit())
    for case in cases:
        case_name = str(case.get("name", ""))
        candidates: list[tuple[str, dict[str, Any]]] = []
        for path, payload in native:
            if path in used:
                continue
            if not _allure_has_testcase_identity(payload, case):
                continue
            if not _allure_has_identity(payload, identity, expected_commit):
                continue
            candidates.append((path, payload))
        if len(candidates) != 1:
            failures.append(f"{identity.identifier}: testcase {case_name!r} has {len(candidates)} exact Allure matches")
            continue
        path, payload = candidates[0]
        used.add(path)
        expected_status = _allure_status(str(case.get("status", "")))
        observed_status = str(payload.get("status", ""))
        if observed_status != expected_status:
            failures.append(
                f"{identity.identifier}: testcase {case_name!r} has Allure status "
                f"{observed_status or '<missing>'}, expected {expected_status}"
            )
            continue
        matches.append(path)
    return sorted(matches), failures


def _merge_status(statuses: Iterable[str]) -> str:
    values = set(statuses)
    for status in ("infrastructure-error", "failed", "skipped-with-approved-justification"):
        if status in values:
            return status
    return "passed" if values == {"passed"} else "infrastructure-error"


def _aggregate_reports(report_rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    seen_hashes: dict[tuple[str, str, str, str, str], set[str]] = {}
    for row in report_rows:
        identity: Identity = row["identity"]
        key = identity.result_key
        group = groups.setdefault(
            key,
            {
                "id": identity.identifier,
                "role": identity.role,
                "profile": identity.profile,
                "scenario": identity.scenario,
                "target": identity.target,
                "run_attempt": identity.run_attempt,
                "status": "passed",
                "totals": {"tests": 0, "failures": 0, "errors": 0, "skipped": 0},
                "test_cases": [],
                "junit": [],
                "allure_results": [],
                "frameworks": [],
                "meaningful": True,
                "blockers": [],
            },
        )
        digest = row["report"].get("logical_sha256", row["report"].get("content_sha256", row["junit"]))
        if digest in seen_hashes.setdefault(key, set()):
            continue
        seen_hashes[key].add(digest)
        report = row["report"]
        group.setdefault("_statuses", []).append(report["status"])
        for total, value in report["totals"].items():
            group["totals"][total] += int(value)
        group["test_cases"].extend(report["test_cases"])
        group["junit"].append(row["junit"])
        group["allure_results"].extend(row.get("allure_results", []))
        group["frameworks"].append(report.get("framework", "junit"))
        group["meaningful"] = group["meaningful"] and bool(report.get("meaningful"))
        if report.get("infrastructure_error"):
            group["blockers"].append(report["infrastructure_error"])
        if report["status"] == "failed" and report["totals"].get("skipped"):
            group["blockers"].append("mandatory JUnit contains an unapproved skip")
        if not row.get("allure_complete", False):
            group["blockers"].append("missing meaningful Allure results for one or more JUnit testcases")
    results: list[dict[str, Any]] = []
    for key in sorted(groups):
        group = groups[key]
        group["status"] = _merge_status(group.pop("_statuses", []))
        group["junit"] = sorted(set(group["junit"]))
        group["allure_results"] = sorted(set(group["allure_results"]))
        group["frameworks"] = sorted(set(group["frameworks"]))
        group["blockers"] = sorted(set(group["blockers"]))
        if group["blockers"] and group["status"] == "passed":
            group["status"] = "failed"
        results.append(group)
    return results

def _valid_totals(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {"tests", "failures", "errors", "skipped"}:
        return False
    return all(isinstance(value[key], int) and not isinstance(value[key], bool) and value[key] >= 0 for key in value)


def _nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _string_array(value: Any, *, nonempty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and (not nonempty or bool(value))
        and all(isinstance(item, str) and bool(item) for item in value)
    )


def _manifest_structure_failures(manifest: dict[str, Any]) -> list[str]:
    """Apply the repository schema without requiring a runtime JSON Schema package."""

    failures: list[str] = []
    required = {
        "schema_version",
        "mode",
        "repository",
        "commit_sha",
        "expected_commit_sha",
        "commit_consistent",
        "workflow_run_id",
        "workflow_attempt",
        "test_totals",
        "failures",
        "skips",
        "results",
        "matrix",
        "security_evidence",
        "secret_scan",
        "checksums",
        "blockers",
        "prerequisites",
        "release_eligible",
    }
    missing = sorted(required - set(manifest))
    failures.extend(f"manifest lacks required field {name}" for name in missing)
    if manifest.get("schema_version") != 2:
        failures.append("manifest schema_version is not 2")
    if manifest.get("mode") not in {"ci", "candidate", "release"}:
        failures.append("manifest mode is invalid")
    if manifest.get("mode") == "candidate":
        if manifest.get("candidate_execution_passed") is not True:
            failures.append("candidate manifest did not record a passing execution")
        if manifest.get("release_eligible") is not False:
            failures.append("candidate evidence must never be release eligible")
    for key in ("repository", "workflow_run_id", "workflow_attempt"):
        if not isinstance(manifest.get(key), str) or not manifest.get(key):
            failures.append(f"manifest {key} is invalid")
    for key in ("commit_sha", "expected_commit_sha"):
        if not isinstance(manifest.get(key), str) or not _valid_commit(str(manifest.get(key, ""))):
            failures.append(f"manifest {key} is not an exact commit")
    if not isinstance(manifest.get("commit_consistent"), bool):
        failures.append("manifest commit_consistent is invalid")
    if not _valid_totals(manifest.get("test_totals")):
        failures.append("manifest test_totals is invalid")
    for key in ("failures", "skips"):
        if not _nonnegative_integer(manifest.get(key)):
            failures.append(f"manifest {key} is invalid")
    results = manifest.get("results")
    if not isinstance(results, list) or not results:
        failures.append("manifest results must be a nonempty array")
        results = []
    for index, result in enumerate(results):
        prefix = f"manifest result {index}"
        if not isinstance(result, dict):
            failures.append(f"{prefix} is not an object")
            continue
        for key in ("id", "role", "profile", "scenario", "target", "run_attempt", "status"):
            if not isinstance(result.get(key), str) or not result.get(key):
                failures.append(f"{prefix} lacks {key}")
        if result.get("profile") not in PROFILES:
            failures.append(f"{prefix} has invalid profile")
        if result.get("status") not in ALLOWED_RESULT_STATUSES:
            failures.append(f"{prefix} has invalid status")
        if not _valid_totals(result.get("totals")):
            failures.append(f"{prefix} has invalid totals")
        if not isinstance(result.get("meaningful"), bool):
            failures.append(f"{prefix} has invalid meaningful flag")
        for key in ("junit", "allure_results"):
            refs = result.get(key)
            if not isinstance(refs, list) or not refs or any(not isinstance(item, str) or not item for item in refs):
                failures.append(f"{prefix} has invalid {key} references")
        cases = result.get("test_cases")
        if not isinstance(cases, list) or not cases:
            failures.append(f"{prefix} has no testcases")
            continue
        for case in cases:
            if not isinstance(case, dict):
                failures.append(f"{prefix} contains a malformed testcase")
                continue
            if not isinstance(case.get("classname"), str):
                failures.append(f"{prefix} contains a testcase with invalid classname")
            if not isinstance(case.get("name"), str) or not case.get("name"):
                failures.append(f"{prefix} contains a testcase with invalid name")
            if case.get("status") not in {"passed", "failure", "error", "skipped"}:
                failures.append(f"{prefix} contains a testcase with invalid status")
            duration = case.get("duration_seconds")
            if not isinstance(duration, (int, float)) or isinstance(duration, bool) or duration < 0:
                failures.append(f"{prefix} contains a testcase with invalid duration")
            if case.get("roles") != [result.get("role")]:
                failures.append(f"{prefix} contains a testcase without explicit role identity")
    matrix = manifest.get("matrix")
    if not isinstance(matrix, dict):
        failures.append("manifest matrix is invalid")
    else:
        expected = matrix.get("expected")
        if not isinstance(expected, list):
            failures.append("manifest matrix expected cells are invalid")
        else:
            for index, cell in enumerate(expected):
                prefix = f"manifest matrix cell {index}"
                if not isinstance(cell, dict):
                    failures.append(f"{prefix} is not an object")
                    continue
                for key in ("scenario", "target", "run_attempt"):
                    if not isinstance(cell.get(key), str) or not cell.get(key):
                        failures.append(f"{prefix} lacks {key}")
                if cell.get("profile") not in PROFILES:
                    failures.append(f"{prefix} has invalid profile")
                if cell.get("status") not in ALLOWED_RESULT_STATUSES:
                    failures.append(f"{prefix} has invalid status")
                disposition = cell.get("target_disposition")
                release_required = cell.get("release_required")
                if disposition is not None or release_required is not None or manifest.get("mode") == "candidate":
                    if disposition not in {"supported", "candidate"}:
                        failures.append(f"{prefix} has invalid target disposition")
                    if not isinstance(release_required, bool):
                        failures.append(f"{prefix} has invalid release-required flag")
                    elif release_required != (disposition == "supported"):
                        failures.append(f"{prefix} target disposition contradicts release-required flag")
                    if manifest.get("mode") == "candidate" and disposition != "candidate":
                        failures.append(f"{prefix} is not a candidate target in candidate mode")
                    if manifest.get("mode") == "release" and disposition != "supported":
                        failures.append(f"{prefix} is not a supported target in release mode")
                roles = cell.get("roles")
                if (
                    not isinstance(roles, list)
                    or not _string_array(roles, nonempty=True)
                    or len(roles) != len(set(roles))
                ):
                    failures.append(f"{prefix} has invalid roles")
        if not _nonnegative_integer(matrix.get("actual_count")):
            failures.append("manifest matrix actual_count is invalid")
        elif isinstance(results, list) and matrix.get("actual_count") != len(results):
            failures.append("manifest matrix actual_count differs from results")
    scan = manifest.get("secret_scan")
    if not isinstance(scan, dict):
        failures.append("manifest secret_scan is invalid")
    else:
        if scan.get("canary_detected_before_redaction") is not True or scan.get("clean") is not True:
            failures.append("manifest secret_scan proof is invalid")
        for key in ("files_scanned", "archive_members_scanned"):
            value = scan.get(key)
            if not _nonnegative_integer(value) or (key == "files_scanned" and isinstance(value, int) and value < 1):
                failures.append(f"manifest secret_scan {key} is invalid")
        for key in ("findings", "errors"):
            if not isinstance(scan.get(key), list) or scan.get(key):
                failures.append(f"manifest secret_scan {key} is invalid")
    security = manifest.get("security_evidence")
    if not isinstance(security, dict):
        failures.append("manifest security_evidence is invalid")
    else:
        for key in ("required_for_release", "missing"):
            if not _string_array(security.get(key)):
                failures.append(f"manifest security_evidence.{key} is invalid")
        for key in ("external_secret_findings", "vulnerability_blocking_findings"):
            if not _nonnegative_integer(security.get(key)):
                failures.append(f"manifest security_evidence.{key} is invalid")
        provenance_commit = security.get("provenance_commit_sha")
        if provenance_commit is not None and (
            not isinstance(provenance_commit, str) or not _valid_commit(provenance_commit)
        ):
            failures.append("manifest security_evidence.provenance_commit_sha is invalid")
        candidate_sha = security.get("candidate_sha256")
        if candidate_sha is not None and (
            not isinstance(candidate_sha, str) or re.fullmatch(r"[0-9a-f]{64}", candidate_sha) is None
        ):
            failures.append("manifest security_evidence.candidate_sha256 is invalid")
        if not isinstance(security.get("semantic_valid"), bool):
            failures.append("manifest security_evidence.semantic_valid is invalid")
    checksums = manifest.get("checksums")
    if not isinstance(checksums, dict):
        failures.append("manifest checksums is invalid")
    else:
        if checksums.get("algorithm") != "sha256" or checksums.get("file") != "checksums/SHA256SUMS":
            failures.append("manifest checksum identity is invalid")
        entry_count = checksums.get("entry_count")
        if not _nonnegative_integer(entry_count) or (isinstance(entry_count, int) and entry_count < 1):
            failures.append("manifest checksum entry_count is invalid")
    blockers = manifest.get("blockers")
    if not isinstance(blockers, list) or not _string_array(blockers) or len(blockers) != len(set(blockers)):
        failures.append("manifest blockers is invalid")
    prerequisites = manifest.get("prerequisites")
    if not isinstance(prerequisites, dict):
        failures.append("manifest prerequisites is invalid")
    elif prerequisites and set(prerequisites) != set(MANDATORY_PREREQUISITES):
        failures.append("manifest prerequisites has incomplete or unknown names")
    elif any(status != "success" for status in prerequisites.values()):
        failures.append("manifest prerequisites contains a non-success status")
    if not isinstance(manifest.get("release_eligible"), bool):
        failures.append("manifest release_eligible is invalid")
    return failures


def _evidence_reference(root: Path, relative: str, category: str) -> tuple[Path | None, str | None]:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] != category:
        return None, f"unsafe {category} evidence reference: {relative}"
    path = root.joinpath(*pure.parts)
    resolved_path = path.resolve()
    if root != resolved_path and root not in resolved_path.parents:
        return None, f"unsafe {category} evidence reference: {relative}"
    if not path.is_file() or path.is_symlink() or resolved_path != path.absolute():
        return None, f"missing {category} evidence reference: {relative}"
    return path, None


def _case_signature(case: dict[str, Any]) -> tuple[Any, ...]:
    try:
        duration = float(case.get("duration_seconds", -1))
    except (TypeError, ValueError):
        duration = -1.0
    roles = case.get("roles", [])
    if not isinstance(roles, list):
        roles = []
    return (
        str(case.get("classname", "")),
        str(case.get("name", "")),
        str(case.get("status", "")),
        duration,
        tuple(sorted(str(role) for role in roles)),
        str(case.get("message", "")),
        str(case.get("type", "")),
    )


def _rederive_manifest_results(root: Path, manifest: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    tested_commit = str(manifest.get("commit_sha", ""))
    used_allure: set[str] = set()
    used_allure_matches: set[str] = set()
    all_rows: list[dict[str, Any]] = []
    manifest_results = manifest.get("results", [])
    if not isinstance(manifest_results, list):
        manifest_results = []
    for item in manifest_results:
        if not isinstance(item, dict):
            continue
        identity = Identity(
            str(item.get("role", "")),
            str(item.get("profile", "")),
            str(item.get("scenario", "")),
            str(item.get("target", "")),
            str(item.get("run_attempt", "")),
        )
        if item.get("id") != identity.identifier:
            failures.append(f"result {item.get('id')} identifier does not match its identity")
        reports: list[tuple[dict[str, Any], str]] = []
        junit_references = item.get("junit", [])
        if not isinstance(junit_references, list):
            junit_references = []
        for relative in junit_references:
            path, error = _evidence_reference(root, str(relative), "junit")
            if error:
                failures.append(error)
                continue
            try:
                report = parse_junit(path)  # type: ignore[arg-type]
            except (EvidenceError, OSError) as parse_error:
                failures.append(f"{relative}: {parse_error}")
                continue
            if _report_commit(report) != tested_commit or not _valid_commit(_report_commit(report)):
                failures.append(f"{relative}: JUnit does not identify the exact tested commit")
            properties = report["properties"]
            observed = {
                "profile": normalize_profile(_property(properties, "profile")),
                "scenario": _property(properties, "scenario"),
                "target": _property(properties, "target"),
                "run_attempt": _property(properties, "run_attempt"),
            }
            for key, expected in (
                ("profile", identity.profile),
                ("scenario", identity.scenario),
                ("target", identity.target),
                ("run_attempt", identity.run_attempt),
            ):
                if observed[key] != expected:
                    failures.append(f"{relative}: JUnit {key} identity differs from manifest")
            declared_roles = _split_roles(_property(properties, "roles", "role"))
            if identity.role not in declared_roles:
                failures.append(f"{relative}: JUnit does not declare role {identity.role}")
                continue
            try:
                reports.append((_report_for_role(report, identity.role, declared_roles), str(relative)))
            except EvidenceError as role_error:
                failures.append(f"{relative}: {role_error}")
        allure_payloads: list[tuple[str, dict[str, Any]]] = []
        allure_references = item.get("allure_results", [])
        if not isinstance(allure_references, list):
            allure_references = []
        for relative in allure_references:
            path, error = _evidence_reference(root, str(relative), "allure-results")
            if error:
                failures.append(error)
                continue
            try:
                payload = _strict_json_loads(_bounded_read(path).decode("utf-8"))  # type: ignore[arg-type]
            except (OSError, EvidenceError, UnicodeDecodeError, json.JSONDecodeError) as parse_error:
                failures.append(f"{relative}: malformed Allure result: {parse_error}")
                continue
            if not isinstance(payload, dict):
                failures.append(f"{relative}: Allure result is not an object")
                continue
            if relative in used_allure:
                failures.append(f"{relative}: Allure result is reused across manifest results")
            used_allure.add(str(relative))
            allure_payloads.append((str(relative), payload))
        rows: list[dict[str, Any]] = []
        for report, relative in reports:
            matched, allure_errors = _native_matches(
                report["test_cases"],
                allure_payloads,
                identity,
                commit_sha=tested_commit,
                used_paths=used_allure_matches,
            )
            failures.extend(allure_errors)
            rows.append(
                {
                    "identity": identity,
                    "report": report,
                    "junit": relative,
                    "allure_results": matched,
                    "allure_complete": not allure_errors and len(matched) == len(report["test_cases"]),
                }
            )
        all_rows.extend(rows)
        derived = _aggregate_reports(rows)
        if len(derived) != 1:
            failures.append(f"result {identity.identifier} cannot be re-derived from referenced evidence")
            continue
        actual = derived[0]
        for key in ("status", "totals", "meaningful"):
            if actual[key] != item.get(key):
                failures.append(f"result {identity.identifier} {key} differs from referenced evidence")
        recorded_cases = item.get("test_cases", [])
        if not isinstance(recorded_cases, list):
            recorded_cases = []
        if sorted(_case_signature(case) for case in actual["test_cases"] if isinstance(case, dict)) != sorted(
            _case_signature(case) for case in recorded_cases if isinstance(case, dict)
        ):
            failures.append(f"result {identity.identifier} testcases differ from referenced JUnit")
        if set(actual["allure_results"]) != set(str(reference) for reference in allure_references):
            failures.append(f"result {identity.identifier} Allure references are not one-to-one")
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    counted_executions: set[tuple[tuple[str, str, str, str], str]] = set()
    for row in all_rows:
        report = row["report"]
        fingerprint = str(report.get("logical_sha256", report.get("content_sha256", row["junit"])))
        execution_key = (row["identity"].cell_key, fingerprint)
        if execution_key in counted_executions:
            continue
        counted_executions.add(execution_key)
        for key in totals:
            totals[key] += int(report["totals"][key])
    if totals != manifest.get("test_totals"):
        failures.append("manifest test_totals differs from referenced JUnit")
    if totals["failures"] + totals["errors"] != manifest.get("failures"):
        failures.append("manifest failures differs from referenced JUnit")
    if totals["skipped"] != manifest.get("skips"):
        failures.append("manifest skips differs from referenced JUnit")
    return failures


