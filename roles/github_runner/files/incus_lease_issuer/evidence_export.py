"""Bounded full sanitized Thin evidence transfer, never release/test PASS.

Only the Root dispatcher calls this factory after durable native exit. Original
reports are job-produced observations, not trusted success claims. Private
process capture and TLS are never exported. Complete source-produced
JUnit/Allure, sanitized logs/failure details and declared attachments/recordings
are preserved only after checksums, independent content scan and static report
rederivation. Policy completion means verified evidence transfer, never an
operating approval, passing test or a substitute for ordinary native admission.
"""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import gzip
import bz2
import hashlib
import io
import math
import lzma
import os
from pathlib import PurePosixPath
import re
import stat
import struct
import tarfile
import tempfile
import zipfile
import xml.etree.ElementTree as ET

from . import (cell_contract, engine_executor, engine_policy as engine, evidence_policy,
               identity, installation, ledger, policy_registry, preparation, storage_quota)
from .identity import Denied, require

CHUNK = 4096
ARCHIVE = "evidence-sanitized.tar.gz"
RECEIPT = "evidence-export.json"


@dataclass(frozen=True)
class ExportReceipt:
    path: str
    sha256: str
    size: int
    chunk_count: int
    receipt_sha256: str
    evidence_policy_complete: bool


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read(root, relative, maximum):
    """Open only explicitly selected relative files, with stable nofollow FDs."""
    path = PurePosixPath(relative)
    require(type(relative) is str and not path.is_absolute() and path.as_posix() == relative
            and all(part not in {"", ".", ".."} for part in path.parts), "export-relative-path")
    directory = os.dup(root)
    try:
        for part in path.parts[:-1]:
            child = os.open(part, engine.DIR, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
                    "export-input-file")
            pieces, size = [], 0
            while True:
                raw = os.read(fd, min(65536, maximum + 1 - size))
                if not raw:
                    break
                pieces.append(raw)
                size += len(raw)
                require(size <= maximum, "export-input-limit")
            named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            require(_stamp(before) == _stamp(os.fstat(fd)) == _stamp(named) and size == before.st_size,
                    "export-input-drift")
            return b"".join(pieces)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def _integer(value, maximum=2 ** 53):
    require(type(value) is int and 0 <= value <= maximum, "export-integer")
    return value


def _duration(value):
    require(type(value) in {str, int, float} and type(value) is not bool, "export-duration")
    number = float(value)
    require(math.isfinite(number) and 0 <= number <= 86400, "export-duration")
    return round(number, 6)


def _junit(raw):
    require(b"<!DOCTYPE" not in raw.upper() and b"<!ENTITY" not in raw.upper(), "export-xml-doctype")
    root = ET.fromstring(raw)
    require(root.tag in {"testsuite", "testsuites"}, "export-junit-root")
    records = []
    for node in root.iter("testcase"):
        statuses = {child.tag for child in node if child.tag in {"failure", "error", "skipped"}}
        require(len(statuses) <= 1, "export-junit-status")
        status_value = next(iter(statuses), "passed")
        # Hash free-text identity; never copy a class/name/failure/stdout string.
        identifier = ledger.digest([node.get("classname", ""), node.get("name", ""), len(records)])
        records.append({"identifier_sha256": identifier, "status": status_value,
                        "duration_seconds": _duration(node.get("time", "0"))})
    require(records, "export-empty-junit")
    declared = {}
    for key in ("tests", "failures", "errors", "skipped"):
        if key in root.attrib:
            value = root.attrib[key]
            require(re.fullmatch(r"[0-9]{1,16}", value), "export-junit-count")
            declared[key] = _integer(int(value))
    return {"schema": 1, "source_sha256": hashlib.sha256(raw).hexdigest(), "source_bytes": len(raw), "test_count": len(records),
            "declared_root_counts": declared,
            "observed_counts": {"tests": len(records), "failures": sum(row["status"] == "failure" for row in records),
                                "errors": sum(row["status"] == "error" for row in records),
                                "skipped": sum(row["status"] == "skipped" for row in records)},
            "tests": records, "evidence_policy_complete": False}


def _allure(raw):
    data = identity.decode_json(raw)
    require(type(data) is dict and data.get("status") in {"passed", "failed", "broken", "skipped", "unknown"},
            "export-allure-status")
    start, stop = _integer(data.get("start")), _integer(data.get("stop"))
    require(stop >= start, "export-allure-time")
    return {"schema": 1, "source_sha256": hashlib.sha256(raw).hexdigest(), "source_bytes": len(raw), "test_count": 1,
            "tests": [{"identifier_sha256": ledger.digest([data.get("uuid"), data.get("fullName"), data.get("name")]),
                       "status": data["status"], "duration_seconds": _duration((stop - start) / 1000)}],
            "evidence_policy_complete": False}


def _acquire(path, sha, registry, selector, store, lease_id):
    # Local import avoids a factory import cycle; no user-provided reader exists.
    from . import runtime_rpc
    config = runtime_rpc._configuration(path, sha)
    require(type(registry) is policy_registry.Registry and config.registry_path == registry.path
            and config.registry_sha256 == registry.sha256, "export-registry")
    root = preparation._config(config.preparation_config_path, config.preparation_config_sha256)[0]
    receipt = runtime_rpc._receipt(registry, selector, store, lease_id)
    manifest, effect_id, effect = engine_executor._retained(root, registry, selector, store, lease_id, receipt)
    details = identity.decode_json(manifest.canonical_bytes)
    actual = effect.get("engine_exit")
    require(type(actual) is dict and actual["manifest_sha256"] == manifest.sha256,
            "export-no-durable-exit")
    ledger._validate_engine_exit(actual, effect)
    require(effect["engine_capture"]["manifest_sha256"] == manifest.sha256, "export-capture-manifest")
    return config, manifest, effect_id, actual, details


def _members(output_fd, details, bounds):
    env = details["environment"]
    scenario, target = env["QUALITY_INPUT_SCENARIO"], env["QUALITY_INPUT_TARGET"]
    require(all(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value)
                for value in (scenario, target)) and env["GITHUB_RUN_ATTEMPT"] == "1", "export-cell-tuple")
    suffix = scenario + "/" + target + "/attempt-1/"
    lifecycle_path = "artifacts/raw/" + suffix + "configuration/lifecycle-result.json"
    lifecycle_raw = _read(output_fd, lifecycle_path, bounds["max_member_bytes"])
    lifecycle = identity.decode_json(lifecycle_raw)
    keys = {"schema_version", "scenario", "target", "run_attempt", "test_exit_code", "capture_exit_code",
            "destroy_exit_code", "effective_exit_code", "infrastructure_error"}
    pending = env.get("QUALITY_FAILURE_CUSTODY") == "retain-failed-v1"
    if pending:
        keys.add("root_finalization")
        require(lifecycle.get("root_finalization") == "pending" and lifecycle.get("destroy_exit_code") is None,
                "export-root-finalization-pending")
    require(type(lifecycle) is dict and set(lifecycle) == keys and type(lifecycle["schema_version"]) is int
            and lifecycle["schema_version"] == 1 and lifecycle["scenario"] == scenario
            and lifecycle["target"] == target and lifecycle["run_attempt"] == "1"
            and type(lifecycle["infrastructure_error"]) is bool, "export-lifecycle-schema")
    code_keys = ("test_exit_code", "capture_exit_code") if pending else ("test_exit_code", "capture_exit_code", "destroy_exit_code")
    for key in (*code_keys, "effective_exit_code"):
        _integer(lifecycle[key], 255)
    expected = next((lifecycle[key] for key in code_keys if lifecycle[key] != 0), 0)
    infrastructure = lifecycle["capture_exit_code"] != 0 or (not pending and lifecycle["destroy_exit_code"] != 0)
    require(lifecycle["effective_exit_code"] == expected and lifecycle["infrastructure_error"] == infrastructure,
            "export-lifecycle-logic")
    base = "artifacts/cell-evidence/" + suffix
    manifest_raw = _read(output_fd, base + "manifest.json", bounds["max_member_bytes"])
    source = identity.decode_json(manifest_raw)
    require(type(source) is dict and type(source.get("schema_version")) is int and source["schema_version"] == 2
            and source.get("repository") == env["GITHUB_REPOSITORY"]
            and source.get("workflow_run_id") == env["GITHUB_RUN_ID"] and source.get("workflow_attempt") == "1"
            and source.get("commit_sha") == env["QUALITY_INPUT_SOURCE_SHA"]
            and source.get("expected_commit_sha") == env["QUALITY_INPUT_SOURCE_SHA"], "export-source-tuple")
    results = source.get("results")
    require(type(results) is list and 0 < len(results) <= bounds["max_members"], "export-results")
    junit, allure = set(), set()
    for row in results:
        require(type(row) is dict and row.get("scenario") == scenario and row.get("target") == target
                and row.get("run_attempt") == "1", "export-result-tuple")
        for key, selected in (("junit", junit), ("allure_results", allure)):
            values = row.get(key)
            require(type(values) is list and len(values) <= bounds["max_members"], "export-report-list")
            for value in values:
                require(type(value) is str and len(value) <= 1024, "export-report-path")
                part = PurePosixPath(value)
                require(not part.is_absolute() and part.as_posix() == value and ".." not in part.parts
                        and len(part.parts) >= 2 and part.parts[0] == ("junit" if key == "junit" else "allure-results")
                        and value.endswith(".xml" if key == "junit" else "-result.json"), "export-report-path")
                selected.add(value)
    require(env["QUALITY_INPUT_JUNIT_REQUIRED"] in {"true", "false"}
            and env["QUALITY_INPUT_ALLURE_REQUIRED"] in {"true", "false"}
            and (env["QUALITY_INPUT_JUNIT_REQUIRED"] != "true" or junit)
            and (env["QUALITY_INPUT_ALLURE_REQUIRED"] != "true" or allure), "export-required-reports")
    require(len(junit) + len(allure) + 2 <= bounds["max_members"], "export-member-limit")
    values = {"lifecycle.json": ledger.canonical(lifecycle | {"evidence_policy_complete": False}),
              "cell.json": ledger.canonical({"schema": 1, "source_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
                  "lifecycle_source_sha256": hashlib.sha256(lifecycle_raw).hexdigest(),
                  "junit_report_count": len(junit), "allure_report_count": len(allure), "result_count": len(results),
                  "evidence_policy_complete": False})}
    source_bytes = len(manifest_raw) + len(lifecycle_raw)
    for kind, paths, parser in (("junit", junit, _junit), ("allure", allure, _allure)):
        for index, relative in enumerate(sorted(paths)):
            raw = _read(output_fd, base + relative, bounds["max_member_bytes"])
            source_bytes += len(raw)
            require(source_bytes <= bounds["max_total_evidence_bytes"], "export-source-total")
            values[f"{kind}-{index:06d}.json"] = ledger.canonical(parser(raw))
    require(source_bytes <= bounds["max_total_evidence_bytes"]
            and all(len(raw) <= bounds["max_member_bytes"] for raw in values.values())
            and sum(map(len, values.values())) <= bounds["max_total_evidence_bytes"], "export-normalized-limit")
    return values


def _safe_member(name):
    require(type(name) is str and 0 < len(name) <= 1024 and re.fullmatch(r"[A-Za-z0-9_./@+ -]+", name)
            and not name.startswith("/") and PurePosixPath(name).as_posix() == name
            and all(part not in {"", ".", ".."} for part in PurePosixPath(name).parts), "export-evidence-path")
    require(not any(part in {"client.key", "client.crt", "quality.crt", "binding.json", ".incus"}
                    for part in PurePosixPath(name).parts), "export-tls-path")
    require(not evidence_policy._scan_payload(name.encode(), "member"), "export-secret-path")
    return name


def _inventory(root, maximum):
    found, entries = set(), 0
    def walk(fd, prefix=""):
        nonlocal entries
        before = os.fstat(fd)
        for name in sorted(os.listdir(fd)):
            entries += 1
            require(entries <= maximum * 2 + 64, "export-inventory-limit")
            relative = _safe_member(prefix + name)
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                require(not prefix or len(PurePosixPath(relative).parts) <= 32, "export-inventory-depth")
                child = os.open(name, engine.DIR, dir_fd=fd)
                try:
                    walk(child, relative + "/")
                finally:
                    os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "export-inventory-file")
                found.add(relative)
                require(len(found) <= maximum, "export-inventory-limit")
        require(_stamp(before) == _stamp(os.fstat(fd)), "export-inventory-drift")
    walk(root)
    require(all(name in {"manifest.json", "role-coverage.yml", "environment.json"}
                or PurePosixPath(name).parts[0] in evidence_policy.EVIDENCE_DIRECTORIES for name in found),
            "export-unknown-evidence-category")
    return found



def _environment_document(value, env):
    require(type(value) is dict and set(value) == {"generated_at", "repository", "commit_sha", "workflow_run_id",
        "workflow_attempt", "roles", "profiles", "scenarios", "targets", "tool_versions", "application_versions"}
        and value["repository"] == env["GITHUB_REPOSITORY"] and value["commit_sha"] == env["QUALITY_INPUT_SOURCE_SHA"]
        and value["workflow_run_id"] == env["GITHUB_RUN_ID"] and value["workflow_attempt"] == "1"
        and value["roles"] == sorted(env["QUALITY_INPUT_ROLES"].split(","))
        and value["profiles"] == [env["QUALITY_INPUT_PROFILE"].replace("_", "-")]
        and value["scenarios"] == [env["QUALITY_INPUT_SCENARIO"]] and value["targets"] == [env["QUALITY_INPUT_TARGET"]]
        and type(value["generated_at"]) is str and 0 < len(value["generated_at"]) <= 64, "export-environment-binding")
    for key in ("tool_versions", "application_versions"):
        require(type(value[key]) is dict and len(value[key]) <= 256
                and all(type(name) is str and type(version) is str and 0 < len(name) <= 128 and len(version) <= 512
                        and not any(ord(c) < 32 for c in name + version) for name, version in value[key].items()),
                "export-environment-version")


def _scan_blob(raw, name, bounds, forbidden, budget, depth=0):
    require(depth <= 4, "export-archive-depth")
    require(not any(value and value in raw for value in forbidden), "export-exact-tls-material")
    require(not evidence_policy._scan_payload(raw, "evidence"), "export-secret-content")
    maximum = min(bounds["max_member_bytes"], evidence_policy.MAX_ARCHIVE_MEMBER_BYTES)
    total_limit = min(bounds["max_total_evidence_bytes"], evidence_policy.MAX_ARCHIVE_TOTAL_BYTES)
    def child(data, child_name):
        _safe_member(child_name)
        budget[0] += 1
        budget[1] += len(data)
        require(budget[0] <= min(bounds["max_members"], evidence_policy.MAX_ARCHIVE_MEMBERS)
                and budget[1] <= total_limit and len(data) <= maximum, "export-archive-limit")
        _scan_blob(data, child_name, bounds, forbidden, budget, depth + 1)
    if zipfile.is_zipfile(io.BytesIO(raw)):
        # Bound central-directory enumeration BEFORE ZipFile allocates one
        # ZipInfo per entry. These policy ceilings never need multi-disk/ZIP64.
        end = raw.rfind(b"PK\x05\x06", max(0, len(raw) - 65557))
        require(end >= 0 and end + 22 <= len(raw), "export-zip-directory")
        _, disk, central_disk, disk_count, count, size, offset, comment = struct.unpack_from("<4s4H2LH", raw, end)
        require(disk == central_disk == 0 and disk_count == count
                and count <= min(bounds["max_members"], evidence_policy.MAX_ARCHIVE_MEMBERS)
                and end + 22 + comment == len(raw) and offset + size == end, "export-zip-directory")
        cursor, actual_count = offset, 0
        while cursor < end:
            require(cursor + 46 <= end and raw[cursor:cursor + 4] == b"PK\x01\x02", "export-zip-directory")
            lengths = struct.unpack_from("<3H", raw, cursor + 28)
            cursor += 46 + sum(lengths)
            actual_count += 1
            require(actual_count <= count and cursor <= end, "export-zip-directory")
        require(actual_count == count, "export-zip-directory")
        with zipfile.ZipFile(io.BytesIO(raw)) as stream:
            rows = stream.infolist()
            require(len(rows) <= min(bounds["max_members"], evidence_policy.MAX_ARCHIVE_MEMBERS), "export-archive-limit")
            seen = set()
            for row in rows:
                name = row.filename.rstrip("/") if row.is_dir() else row.filename
                _safe_member(name)
                require(name not in seen and not (row.flag_bits & 1), "export-archive-member")
                seen.add(name)
                mode = row.external_attr >> 16
                require(stat.S_IFMT(mode) in {0, stat.S_IFREG, stat.S_IFDIR}, "export-archive-link")
                if not row.is_dir():
                    require(row.file_size <= maximum and row.file_size / max(row.compress_size, 1)
                            <= evidence_policy.MAX_ARCHIVE_COMPRESSION_RATIO, "export-archive-limit")
                    with stream.open(row) as item:
                        data = item.read(maximum + 1)
                    require(len(data) == row.file_size, "export-archive-size")
                    child(data, name)
        return
    expanded_raw = raw
    if raw.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
            expanded_raw = compressed.read(total_limit + 1)
    elif raw.startswith(b"BZh"):
        decoder = bz2.BZ2Decompressor()
        expanded_raw = decoder.decompress(raw, max_length=total_limit + 1)
        require(decoder.eof and not decoder.unused_data, "export-compressed-archive")
    elif raw.startswith(b"\xfd7zXZ\x00"):
        decoder = lzma.LZMADecompressor(memlimit=evidence_policy.MAX_ARCHIVE_MEMBER_BYTES)
        expanded_raw = decoder.decompress(raw, max_length=total_limit + 1)
        require(decoder.eof and not decoder.unused_data, "export-compressed-archive")
    require(len(expanded_raw) <= max(total_limit, len(raw)) and (expanded_raw is raw or (
        len(expanded_raw) <= total_limit and len(expanded_raw) / max(len(raw), 1)
        <= evidence_policy.MAX_ARCHIVE_COMPRESSION_RATIO)), "export-compressed-limit")
    try:
        stream = tarfile.open(fileobj=io.BytesIO(expanded_raw), mode="r:")
    except tarfile.ReadError:
        stream = None
    if stream is not None:
        with stream:
            seen, expanded = set(), 0
            for row in stream:
                name = row.name.rstrip("/") if row.isdir() else row.name
                _safe_member(name)
                require(len(seen) < min(bounds["max_members"], evidence_policy.MAX_ARCHIVE_MEMBERS)
                        and name not in seen and (row.isfile() or row.isdir()), "export-archive-member")
                seen.add(name)
                if row.isfile():
                    expanded += row.size
                    require(row.size <= maximum and expanded <= total_limit
                            and expanded / max(len(raw), 1) <= evidence_policy.MAX_ARCHIVE_COMPRESSION_RATIO,
                            "export-archive-limit")
                    item = stream.extractfile(row)
                    require(item is not None, "export-archive-file")
                    with item:
                        data = item.read(maximum + 1)
                    require(len(data) == row.size, "export-archive-size")
                    child(data, name)
        return
    if expanded_raw is not raw:
        child(expanded_raw, "compressed-payload")


def _tls_material(details):
    """Root-derived exact exclusions supplement the source-approved scanner."""
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    values = []
    for relative in ("client.key", "client.crt", "servercerts/quality.crt"):
        _, raw, _ = installation._file(details["context"]["path"] + "/" + relative, 65536, private=True, keep=True)
        values.append(raw)
        if relative == "client.key":
            key = serialization.load_pem_private_key(raw, password=None)
            values.append(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
        else:
            values.append(x509.load_pem_x509_certificate(raw).public_bytes(serialization.Encoding.DER))
        # PEM payload copied without header/footer must also never be exported.
        values.append(b"".join(line for line in raw.splitlines() if not line.startswith(b"-----")))
    return tuple(values)


def _full_members(output_fd, details, bounds, directory, forbidden):
    normalized = _members(output_fd, details, bounds)
    env = details["environment"]
    base = "artifacts/cell-evidence/" + env["QUALITY_INPUT_SCENARIO"] + "/" + env["QUALITY_INPUT_TARGET"] + "/attempt-1"
    fd = os.dup(output_fd)
    try:
        for part in PurePosixPath(base).parts:
            child = os.open(part, engine.DIR, dir_fd=fd)
            os.close(fd)
            fd = child
        paths = _inventory(fd, min(bounds["max_members"], evidence_policy.MAX_EVIDENCE_FILES))
        require({"manifest.json", "checksums/SHA256SUMS"} <= paths, "export-checksums-missing")
        maximum = min(bounds["max_member_bytes"], evidence_policy.MAX_EVIDENCE_FILE_BYTES)
        payloads, total, scan_budget = {}, 0, [0, 0]
        require(evidence_policy._scan_payload(b"password=actual-unredacted-canary", "self-check")
                and evidence_policy._scan_payload(evidence_policy.CANARY_BYTES, "self-check")
                and not evidence_policy._scan_payload(b"password=[REDACTED]", "self-check"),
                "export-scanner-self-check")
        for path in sorted(paths):
            raw = _read(fd, path, maximum)
            total += len(raw)
            require(total <= min(bounds["max_total_evidence_bytes"], evidence_policy.MAX_EVIDENCE_TOTAL_BYTES),
                    "export-full-total")
            _scan_blob(raw, path, bounds, forbidden, scan_budget)
            require(total + scan_budget[1] <= bounds["max_total_evidence_bytes"], "export-expanded-total")
            payloads[path] = raw
        checksums = {}
        for line in payloads["checksums/SHA256SUMS"].decode("utf-8").splitlines():
            require("  " in line, "export-checksum-line")
            expected, path = line.split("  ", 1)
            _safe_member(path)
            require(ledger.HEX.fullmatch(expected) and path not in checksums, "export-checksum-line")
            checksums[path] = expected
        require(set(checksums) == paths - {"checksums/SHA256SUMS"}
                and all(hashlib.sha256(payloads[path]).hexdigest() == sha for path, sha in checksums.items()),
                "export-checksum-mismatch")
        manifest = identity.decode_json(payloads["manifest.json"])
        require(manifest["checksums"]["entry_count"] == len(checksums), "export-checksum-count")
        require(not evidence_policy._manifest_structure_failures(manifest,
            preliminary=env.get("QUALITY_FAILURE_CUSTODY") == "retain-failed-v1"), "export-manifest-schema")
        if env.get("QUALITY_FAILURE_CUSTODY") == "retain-failed-v1":
            require("environment.json" in payloads, "export-environment-required")
        if "environment.json" in payloads:
            _environment_document(identity.decode_json(payloads["environment.json"]), env)
        roles = sorted(env["QUALITY_INPUT_ROLES"].split(","))
        require(roles and sorted(row["role"] for row in manifest["results"]) == roles
                and all(row["profile"] == env["QUALITY_INPUT_PROFILE"].replace("_", "-")
                        for row in manifest["results"]), "export-root-roles")
        expected = manifest["matrix"]["expected"]
        require(len(expected) == 1 and expected[0]["scenario"] == env["QUALITY_INPUT_SCENARIO"]
                and expected[0]["target"] == env["QUALITY_INPUT_TARGET"]
                and expected[0]["profile"] == env["QUALITY_INPUT_PROFILE"].replace("_", "-")
                and expected[0]["run_attempt"] == "1" and sorted(expected[0]["roles"]) == roles,
                "export-root-matrix")
        # Trusted STATIC library operates only on Root-copied, scanned files.
        # It rederives exact role/cell/JUnit/Allure/case/totals/commit identities;
        # no candidate module is imported or executed.
        with tempfile.TemporaryDirectory(prefix="evidence-verify-", dir=directory) as temporary:
            from pathlib import Path
            stage = Path(temporary)
            for path, raw in payloads.items():
                destination = stage / path
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with open(destination, "xb") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(raw)
            require(not evidence_policy._rederive_manifest_results(stage, manifest), "export-report-rederivation")
        # Native Allure attachments (including recordings) are preserved, and
        # every declared attachment must exist in the exact checksummed set.
        def attachments(value, parent):
            if type(value) is dict:
                if "attachments" in value:
                    require(type(value["attachments"]) is list, "export-attachments")
                    for row in value["attachments"]:
                        require(type(row) is dict and type(row.get("source")) is str, "export-attachments")
                        relative = _safe_member(row["source"])
                        require(str(PurePosixPath(parent) / relative) in payloads, "export-missing-attachment")
                for item in value.values():
                    attachments(item, parent)
            elif type(value) is list:
                for item in value:
                    attachments(item, parent)
        for path, raw in payloads.items():
            if path.startswith("allure-results/") and path.endswith(".json"):
                attachments(identity.decode_json(raw), str(PurePosixPath(path).parent))
        require(paths == _inventory(fd, min(bounds["max_members"], evidence_policy.MAX_EVIDENCE_FILES))
                and all(_read(fd, path, maximum) == raw for path, raw in payloads.items()), "export-source-drift")
        members = {"evidence/" + path: raw for path, raw in payloads.items()}
        members.update({"normalized/" + name: raw for name, raw in normalized.items()})
        members["runtime/evidence-policy.json"] = ledger.canonical({
            "schema": 1, "evidence_policy_complete": True, "scope": "full-sanitized-cell-transfer",
            "source_policy_sha256": "0c1dc5877ecb93fd55a9418ff360383c51e356c82c0bdc9268613f7e3c35e2ab",
            "source_manifest_sha256": hashlib.sha256(payloads["manifest.json"]).hexdigest(),
            "required_junit": env["QUALITY_INPUT_JUNIT_REQUIRED"] == "true",
            "required_allure": env["QUALITY_INPUT_ALLURE_REQUIRED"] == "true",
            **({"root_finalization": "pending"} if env.get("QUALITY_FAILURE_CUSTODY") == "retain-failed-v1" else {})})
        require(len(members) <= bounds["max_members"] and sum(map(len, members.values()))
                <= bounds["max_total_evidence_bytes"], "export-full-member-limit")
        return members
    finally:
        os.close(fd)


def _create(parent, name, raw):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            require(count > 0, "export-write")
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent)


def _archive(members, maximum):
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as stream:
            for name, raw in sorted(members.items()):
                row = tarfile.TarInfo(name)
                row.size, row.mode, row.uid, row.gid, row.mtime = len(raw), 0o600, 0, 0, 0
                stream.addfile(row, io.BytesIO(raw))
    raw = buffer.getvalue()
    require(0 < len(raw) <= maximum, "export-archive-limit")
    return raw


def _existing(directory, binding, maximum):
    proof, raw, _ = installation._file(directory + "/" + RECEIPT, engine.MAX_DESCRIPTOR, private=True, keep=True)
    data = identity.decode_json(raw)
    require(type(data) is dict and set(data) == {"schema", "binding", "archive_sha256", "archive_size",
            "chunk_count", "members", "evidence_policy_complete", "spool"} and data["schema"] == 1
            and data["binding"] == binding and data["evidence_policy_complete"] is True, "export-receipt-binding")
    parent = engine._directory(directory, private=True)
    try:
        require(set(os.listdir(parent)) == {ARCHIVE, RECEIPT}
                and data["spool"] == {"path": directory, "device": os.fstat(parent).st_dev,
                                      "inode": os.fstat(parent).st_ino}, "export-spool-drift")
    finally:
        os.close(parent)
    archive, _, _ = installation._file(directory + "/" + ARCHIVE, maximum, private=True, keep=True)
    require(data["archive_sha256"] == archive.sha256 and data["archive_size"] == archive.size
            and data["chunk_count"] == (archive.size + CHUNK - 1) // CHUNK, "export-receipt-archive")
    return ExportReceipt(directory + "/" + ARCHIVE, archive.sha256, archive.size,
                         data["chunk_count"], proof.sha256, True)


def _spool_directory(runroot):
    return engine._path(engine._path(runroot) + ".public-evidence")


@contextmanager
def _quota(config, path):
    root = preparation._config(config.preparation_config_path, config.preparation_config_sha256)[0]
    with storage_quota.acquire_existing_evidence_quota(
            root.storage_quota_policy_path, root.storage_quota_policy_sha256, path) as observation:
        yield observation


def _binding(config, lease_id, effect_id, manifest_sha, actual):
    return {"lease_id": lease_id, "effect_id": effect_id, "manifest_sha256": manifest_sha,
            "exit_sha256": ledger.digest(actual), "config_sha256": config.sha256}


def read_existing(root_config_path, expected_config_sha256, registry, selector, store, lease_id):
    """Read a completed sealed transfer after raw context/engine removal.

    The typed cleanup owner is independently reconstructed from the sealed Root
    registry and original private journal, including actual exit and creators.
    No missing archive, partial publication or mutable job tree is adopted.
    """
    try:
        require(os.geteuid() == 0 and type(store) is ledger.Ledger and store.owner_uid == 0, "export-root")
        from . import runtime_rpc
        config = runtime_rpc._configuration(root_config_path, expected_config_sha256)
        require(type(registry) is policy_registry.Registry and registry.path == config.registry_path
                and registry.sha256 == config.registry_sha256, "export-registry")
        owner = cell_contract.owned_cell_for_cleanup(registry, selector, store, lease_id)
        descriptor = identity.decode_json(owner.engine_descriptor_bytes)
        directory = _spool_directory(descriptor["engine"]["runroot"])
        starts = [(key, value) for key, value in store.read(lease_id)["effects"].items()
                  if value["operation"] == "engine-start"]
        require(len(starts) == 1, "export-retained-start")
        effect_id, effect = starts[0]
        actual = effect["engine_exit"]
        ledger._validate_engine_exit(actual, effect)
        require(actual["manifest_sha256"] == owner.engine_policy_sha256, "export-retained-manifest")
        binding = _binding(config, lease_id, effect_id, owner.engine_policy_sha256, actual)
        with _quota(config, directory):
            return _existing(directory, binding, config.capture["max_total_evidence_bytes"])
    except Exception:
        raise Denied("evidence-export-denied") from None


def export_existing(root_config_path, expected_config_sha256, registry, selector, store, lease_id):
    """Seal normalized observations once; partial publication is a retained hold.

    No writes to the quality tree and no effect retry occur. A pre-existing
    archive without its final matching receipt is never adopted or overwritten.
    """
    try:
        require(os.geteuid() == 0 and type(store) is ledger.Ledger and store.owner_uid == 0, "export-root")
        config, manifest, effect_id, actual, details = _acquire(
            root_config_path, expected_config_sha256, registry, selector, store, lease_id)
        bounds = config.capture
        runroot = details["engine"]["runroot"]
        directory = _spool_directory(runroot)
        binding = _binding(config, lease_id, effect_id, manifest.sha256, actual)
        containing = str(PurePosixPath(directory).parent)
        parent = engine._directory(containing, private=True)
        try:
            if PurePosixPath(directory).name in os.listdir(parent):
                with _quota(config, directory):
                    return _existing(directory, binding, bounds["max_total_evidence_bytes"])
            output = engine._directory(details["output"]["path"], private=True)
            try:
                engine._retained_output(details["output"]["path"], details["output"])
                members = _full_members(output, details, bounds, runroot, _tls_material(details))
                engine._retained_output(details["output"]["path"], details["output"])
            finally:
                os.close(output)
            archive = _archive(members, bounds["max_total_evidence_bytes"])
            data = {"schema": 1, "binding": binding, "archive_sha256": hashlib.sha256(archive).hexdigest(),
                    "archive_size": len(archive), "chunk_count": (len(archive) + CHUNK - 1) // CHUNK,
                    "members": {name: {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                                for name, raw in sorted(members.items())}, "evidence_policy_complete": True}
            with _quota(config, containing):
                # Allocation itself is a durable publishing intent. An existing
                # empty/partial sibling always holds, and is never reinitialized.
                os.mkdir(PurePosixPath(directory).name, 0o700, dir_fd=parent)
                os.fsync(parent)
                spool = engine._directory(directory, private=True)
                try:
                    info = os.fstat(spool)
                    require(info.st_dev == os.fstat(parent).st_dev
                            and storage_quota._mount_id(spool) == storage_quota._mount_id(parent),
                            "export-spool-mount")
                    data["spool"] = {"path": directory, "device": info.st_dev, "inode": info.st_ino}
                    receipt_raw = ledger.canonical(data)
                    require(len(receipt_raw) <= engine.MAX_DESCRIPTOR, "export-receipt-limit")
                    _create(spool, ARCHIVE, archive)
                    _create(spool, RECEIPT, receipt_raw)
                    return _existing(directory, binding, bounds["max_total_evidence_bytes"])
                finally:
                    os.close(spool)
        finally:
            os.close(parent)
    except Exception:
        raise Denied("evidence-export-denied") from None


def read_chunks(receipt):
    """Read only a factory-sealed archive; no request-supplied file locator."""
    try:
        require(os.geteuid() == 0 and type(receipt) is ExportReceipt and receipt.evidence_policy_complete is True
                and PurePosixPath(receipt.path).name == ARCHIVE, "export-receipt-type")
        directory = str(PurePosixPath(receipt.path).parent)
        proof, raw, _ = installation._file(directory + "/" + RECEIPT, engine.MAX_DESCRIPTOR, private=True, keep=True)
        data = identity.decode_json(raw)
        require(proof.sha256 == receipt.receipt_sha256 and data["evidence_policy_complete"] is True
                and data["archive_sha256"] == receipt.sha256 and data["archive_size"] == receipt.size
                and data["chunk_count"] == receipt.chunk_count, "export-stream-receipt")
        require(_existing(directory, data["binding"], receipt.size) == receipt, "export-stream-spool")
        archive, _, _ = installation._file(receipt.path, receipt.size, private=True, keep=True)
        require(archive.sha256 == receipt.sha256 and archive.size == receipt.size, "export-stream-drift")
        parent = engine._directory(directory, private=True)
        try:
            fd = os.open(ARCHIVE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                before = os.fstat(fd)
                require((before.st_dev, before.st_ino) == (archive.device, archive.inode), "export-stream-replaced")
                offset, digest = 0, hashlib.sha256()
                while raw := os.read(fd, CHUNK):
                    offset += len(raw)
                    require(offset <= receipt.size, "export-stream-limit")
                    digest.update(raw)
                    yield raw
                require(offset == receipt.size and digest.hexdigest() == receipt.sha256
                        and _stamp(before) == _stamp(os.fstat(fd)), "export-stream-changed")
            finally:
                os.close(fd)
        finally:
            os.close(parent)
    except Exception:
        raise Denied("evidence-export-denied") from None
