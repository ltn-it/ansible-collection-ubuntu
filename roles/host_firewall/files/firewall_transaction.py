#!/usr/bin/env python3
"""Execute one fail-closed nftables transaction under one host-wide lock."""

from __future__ import annotations

import argparse
import base64
from collections import Counter
import contextlib
import contextvars
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence


AUTHORIZATION_KEYS = {
    "action",
    "approved_readback_sha256",
    "candidate_sha256",
    "change_id",
    "claim_id",
    "egress_policy_sha256",
    "egress_status",
    "expires_at",
    "issued_at",
    "policy_fingerprint",
    "schema",
    "signature",
    "target",
}
REQUEST_COMMON_KEYS = {
    "action",
    "approved_readback_sha256",
    "authorization",
    "candidate_sha256",
    "change_id",
    "egress_policy_sha256",
    "egress_status",
    "mode",
    "policy_fingerprint",
    "schema",
    "target",
}
METADATA_KEYS = {
    "action",
    "apply_authorization_sha256",
    "apply_verification_sha256",
    "approved_readback_sha256",
    "candidate_sha256",
    "change_id",
    "claim_id",
    "created_at",
    "egress_policy_sha256",
    "egress_status",
    "confirmation_unit_sha256",
    "mode",
    "persistent_backup_sha256",
    "persistent_root_sha256",
    "persistent_state_sha256",
    "policy_fingerprint",
    "program_sha256",
    "rollback_timer_sha256",
    "rollback_unit_sha256",
    "runtime_backup_sha256",
    "runtime_canonical_sha256",
    "runtime_state_sha256",
    "schema",
    "target",
    "transaction_id",
    "verifier_path",
    "verifier_sha256",
}
ACTIVE_KEYS = {"metadata_sha256", "schema", "transaction_id", "transaction_path"}
INSTALL_KEYS = {
    "confirmation_unit_base64",
    "program_base64",
    "rollback_timer_base64",
    "rollback_unit_base64",
    "schema",
}
CONFIRMATION_KEYS = {
    "approved_readback_sha256",
    "authorization_claim_id",
    "authorization_sha256",
    "authorization_verification_sha256",
    "candidate_sha256",
    "change_id",
    "confirmed_at",
    "egress_policy_sha256",
    "egress_status",
    "policy_fingerprint",
    "schema",
    "target",
    "transaction_id",
}
ROLLBACK_KEYS = {
    "action",
    "approved_readback_sha256",
    "authorization_claim_id",
    "authorization_sha256",
    "authorization_verification_sha256",
    "candidate_sha256",
    "change_id",
    "egress_policy_sha256",
    "egress_status",
    "mode",
    "policy_fingerprint",
    "restored_persistent_sha256",
    "restored_persistent_state",
    "restored_readback_sha256",
    "restored_runtime_state",
    "rolled_back_at",
    "schema",
    "source",
    "target",
    "transaction_id",
}
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
UTC_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
UNIT_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]{3,128}\.(?:service|timer)$")
COMMAND_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "host_firewall_command_deadline",
    default=None,
)
COMMAND_TIMEOUT: contextvars.ContextVar[float] = contextvars.ContextVar(
    "host_firewall_command_timeout",
    default=15.0,
)


class TransactionError(RuntimeError):
    """Raised when a transaction cannot proceed without weakening a boundary."""


class DuplicateKeyError(ValueError):
    """Raised for duplicate JSON keys."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(raw: bytes, *, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError) as exc:
        raise TransactionError(f"invalid {label} JSON: {exc}") from exc


def require_exact_mapping(value: Any, keys: set[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise TransactionError(f"{label} must contain exactly: {', '.join(sorted(keys))}")
    return value


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def format_utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value: Any, *, label: str) -> dt.datetime:
    if not isinstance(value, str) or not UTC_PATTERN.fullmatch(value):
        raise TransactionError(f"{label} must use exact UTC second precision")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise TransactionError(f"{label} is not a valid UTC timestamp: {exc}") from exc


def require_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise TransactionError(f"{label} must be a lowercase SHA-256 digest")
    return value


def normalize_ip_address(value: str, version: int) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise TransactionError(f"invalid IPv{version} address: {value}") from exc
    if address.version != version:
        raise TransactionError(f"address family mismatch for {value}")
    return address.compressed


def normalize_host_cidr(value: str, version: int) -> str:
    try:
        interface = ipaddress.ip_interface(value)
    except ValueError as exc:
        raise TransactionError(f"invalid IPv{version} host CIDR: {value}") from exc
    expected_prefix = 32 if version == 4 else 128
    if interface.version != version or interface.network.prefixlen != expected_prefix:
        raise TransactionError(f"IPv{version} authorization must use /{expected_prefix}: {value}")
    return f"{interface.ip.compressed}/{expected_prefix}"


def normalize_firewall_inputs(value: Any) -> dict[str, Any]:
    keys = {
        "control_source_address",
        "expected_management_ipv4",
        "expected_management_ipv6",
        "expected_public_ipv4",
        "expected_public_ipv6",
        "management_access",
        "container_service_access",
        "public_service_access",
        "observed_ipv4_addresses",
        "observed_ipv6_addresses",
        "tang_access",
    }
    source = require_exact_mapping(value, keys, label="firewall normalization input")
    result = dict(source)
    result["expected_public_ipv4"] = normalize_ip_address(source["expected_public_ipv4"], 4)
    result["expected_management_ipv4"] = normalize_ip_address(source["expected_management_ipv4"], 4)
    for name in ("expected_public_ipv6", "expected_management_ipv6"):
        raw = source[name]
        result[name] = normalize_ip_address(raw, 6) if raw else ""
    result["observed_ipv4_addresses"] = [
        normalize_ip_address(item, 4) for item in source["observed_ipv4_addresses"]
    ]
    result["observed_ipv6_addresses"] = [
        normalize_ip_address(item, 6) for item in source["observed_ipv6_addresses"]
    ]
    control_source = source["control_source_address"]
    if control_source:
        result["control_source_address"] = normalize_ip_address(
            control_source,
            6 if ":" in control_source else 4,
        )

    management = source["management_access"]
    if not isinstance(management, dict):
        raise TransactionError("management_access must be a mapping")
    normalized_management: dict[str, Any] = {}
    for function, contract in management.items():
        if not isinstance(contract, dict):
            raise TransactionError(f"management function {function} must be a mapping")
        normalized = dict(contract)
        normalized["sources_ipv4"] = [normalize_host_cidr(item, 4) for item in contract.get("sources_ipv4", [])]
        normalized["sources_ipv6"] = [normalize_host_cidr(item, 6) for item in contract.get("sources_ipv6", [])]
        normalized_management[function] = normalized
    result["management_access"] = normalized_management

    public_services = source["public_service_access"]
    if not isinstance(public_services, dict):
        raise TransactionError("public_service_access must be a mapping")
    normalized_public_services: dict[str, Any] = {}
    for function, contract in public_services.items():
        if not isinstance(contract, dict):
            raise TransactionError(f"public service function {function} must be a mapping")
        normalized = dict(contract)
        normalized["sources_ipv4"] = [normalize_host_cidr(item, 4) for item in contract.get("sources_ipv4", [])]
        normalized["sources_ipv6"] = [normalize_host_cidr(item, 6) for item in contract.get("sources_ipv6", [])]
        normalized_public_services[function] = normalized
    result["public_service_access"] = normalized_public_services

    container_services = source["container_service_access"]
    if not isinstance(container_services, dict):
        raise TransactionError("container_service_access must be a mapping")
    normalized_container_services: dict[str, Any] = {}
    for function, contract in container_services.items():
        if not isinstance(contract, dict):
            raise TransactionError(f"container service function {function} must be a mapping")
        normalized = dict(contract)
        normalized["sources_ipv4"] = [normalize_host_cidr(item, 4) for item in contract.get("sources_ipv4", [])]
        normalized["destinations_ipv4"] = [
            normalize_host_cidr(item, 4) for item in contract.get("destinations_ipv4", [])
        ]
        normalized_container_services[function] = normalized
    result["container_service_access"] = normalized_container_services

    tang = source["tang_access"]
    if not isinstance(tang, dict):
        raise TransactionError("tang_access must be a mapping")
    normalized_tang = dict(tang)
    normalized_tang["sources_ipv4"] = [normalize_host_cidr(item, 4) for item in tang.get("sources_ipv4", [])]
    normalized_tang["sources_ipv6"] = [normalize_host_cidr(item, 6) for item in tang.get("sources_ipv6", [])]
    result["tang_access"] = normalized_tang
    return result


def normalize_nft_value(value: Any, parent_key: str = "") -> Any:
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key in sorted(value):
            if key == "handle":
                continue
            if parent_key == "counter" and key in {"bytes", "packets"}:
                continue
            normalized[key] = normalize_nft_value(value[key], key)
        return normalized
    if isinstance(value, list):
        normalized_list = [normalize_nft_value(item, parent_key) for item in value]
        if parent_key == "elem":
            return sorted(normalized_list, key=lambda item: canonical_json(item))
        return normalized_list
    return value


def canonicalize_nft_document(raw: bytes, family: str, table: str) -> bytes:
    document = require_exact_mapping(parse_json(raw, label="nftables"), {"nftables"}, label="nftables document")
    if not isinstance(document["nftables"], list):
        raise TransactionError("nftables must be an array")
    statements: list[dict[str, Any]] = []
    matching_tables = 0
    for statement in document["nftables"]:
        if not isinstance(statement, dict) or len(statement) != 1:
            raise TransactionError("every nftables statement must be a single-key object")
        statement_type, payload = next(iter(statement.items()))
        if statement_type == "metainfo":
            continue
        if not isinstance(payload, dict):
            raise TransactionError(f"{statement_type} payload must be an object")
        if payload.get("family") != family or payload.get("table", payload.get("name")) != table:
            raise TransactionError("nftables readback escaped the configured family/table boundary")
        if statement_type == "table":
            matching_tables += 1
            if payload.get("name") != table:
                raise TransactionError("table identity differs from the configured table")
        statements.append({statement_type: payload})
    if matching_tables != 1:
        raise TransactionError("readback must contain exactly one configured table declaration")
    return canonical_json(normalize_nft_value({"nftables": statements}))


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def run_command(
    argv: Sequence[str],
    *,
    input_bytes: bytes | None = None,
    timeout_seconds: float | None = None,
) -> CommandResult:
    deadline = COMMAND_DEADLINE.get()
    remaining = deadline - time.monotonic() if deadline is not None else None
    if remaining is not None and remaining <= 0:
        raise TransactionError("the bounded transaction command deadline expired")
    effective_timeout = timeout_seconds if timeout_seconds is not None else COMMAND_TIMEOUT.get()
    if remaining is not None:
        effective_timeout = min(effective_timeout, remaining)
    environment = {**os.environ, "LC_ALL": "C", "LANG": "C"}
    try:
        result = subprocess.run(
            list(argv),
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
            timeout=effective_timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise TransactionError(
            f"external command exceeded its {effective_timeout:.3f}s fail-closed timeout: {argv[0]}"
        ) from exc
    return CommandResult(result.returncode, result.stdout, result.stderr)


@contextlib.contextmanager
def command_deadline_until(
    absolute_deadline: float,
    *,
    command_timeout_seconds: float | None = None,
) -> Iterator[None]:
    if absolute_deadline <= time.monotonic():
        raise TransactionError("bounded transaction deadline must be in the future")
    token = COMMAND_DEADLINE.set(absolute_deadline)
    timeout_token = None
    if command_timeout_seconds is not None:
        timeout_token = COMMAND_TIMEOUT.set(command_timeout_seconds)
    try:
        yield
    finally:
        if timeout_token is not None:
            COMMAND_TIMEOUT.reset(timeout_token)
        COMMAND_DEADLINE.reset(token)


@contextlib.contextmanager
def bounded_command_deadline(seconds: float, *, command_timeout_seconds: float | None = None) -> Iterator[None]:
    if seconds <= 0:
        raise TransactionError("bounded transaction deadline must be positive")
    with command_deadline_until(
        time.monotonic() + seconds,
        command_timeout_seconds=command_timeout_seconds,
    ):
        yield


def require_command(result: CommandResult, *, label: str) -> CommandResult:
    if result.returncode != 0:
        diagnostic = result.stderr.decode("utf-8", errors="replace").strip()[:512]
        raise TransactionError(f"{label} failed with rc={result.returncode}: {diagnostic}")
    return result


def parse_table_inventory(raw: bytes, family: str, table: str) -> bool:
    document = require_exact_mapping(parse_json(raw, label="nftables table inventory"), {"nftables"}, label="table inventory")
    if not isinstance(document["nftables"], list):
        raise TransactionError("nftables table inventory must be an array")
    matches = 0
    for statement in document["nftables"]:
        if not isinstance(statement, dict) or len(statement) != 1:
            raise TransactionError("table inventory statement must be a single-key object")
        statement_type, payload = next(iter(statement.items()))
        if statement_type == "metainfo":
            continue
        if statement_type != "table" or not isinstance(payload, dict):
            raise TransactionError("table inventory may contain only table declarations")
        if payload.get("family") == family and payload.get("name") == table:
            matches += 1
    if matches > 1:
        raise TransactionError("table inventory contains duplicate configured table declarations")
    return matches == 1


@dataclass(frozen=True)
class NftTableState:
    present: bool
    text: bytes
    canonical: bytes


def numeric_bridge_document(raw: bytes) -> tuple[bytes, dict[str, int], Counter[tuple[str, int]]]:
    """Bind explicit scalar interface-index matches before a peer disappears.

    nft 1.0.9 still renders live iif/oif indices as names with --numeric.
    The owned guard supports scalar equality only; other index expressions
    fail before mutation rather than producing an incomplete rollback.
    """
    aliases: dict[str, int] = {}
    matches: Counter[tuple[str, int]] = Counter()
    selectors = {"iif", "oif", "sdif"}

    def visit(value: Any) -> Any:
        if isinstance(value, list):
            return [visit(item) for item in value]
        if not isinstance(value, dict):
            return value
        match = value.get("match")
        if isinstance(match, dict):
            left = match.get("left")
            meta = left.get("meta") if isinstance(left, dict) else None
            if isinstance(meta, dict) and meta.get("key") in selectors:
                if (set(value) != {"match"} or set(match) != {"op", "left", "right"}
                        or set(left) != {"meta"} or set(meta) != {"key"} or match["op"] != "=="):
                    raise TransactionError("owned bridge interface indices require scalar equality")
                index = match["right"]
                if isinstance(index, str):
                    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}", index):
                        raise TransactionError("invalid symbolic bridge interface index")
                    if index not in aliases:
                        if re.fullmatch(r"[0-9]+", index):
                            # nft JSON renders a vanished index as decimal TEXT.
                            # A real device with that numeric name must not
                            # silently redirect an old index to another device.
                            number = int(index)
                            if str(number) != index:
                                raise TransactionError("noncanonical numeric bridge interface index")
                            try:
                                named = socket.if_nametoindex(index)
                            except OSError:
                                named = number
                            if named != number:
                                raise TransactionError("ambiguous numeric bridge interface name")
                            aliases[index] = number
                        else:
                            try:
                                aliases[index] = socket.if_nametoindex(index)
                            except OSError as exc:
                                raise TransactionError("bridge interface disappeared during numeric snapshot") from exc
                    index = aliases[index]
                if type(index) is not int or not 0 < index < 2**31:
                    raise TransactionError("owned bridge interface index must be a positive scalar")
                matches[(meta["key"], index)] += 1
                return {"match": {**match, "right": index}}
        meta = value.get("meta")
        if isinstance(meta, dict) and meta.get("key") in selectors:
            raise TransactionError("unsupported owned bridge interface-index expression")
        return {key: visit(item) for key, item in value.items()}

    return canonical_json(visit(parse_json(raw, label="bridge numeric snapshot"))), aliases, matches


def numeric_bridge_text(raw: bytes, aliases: dict[str, int], expected: Counter[tuple[str, int]]) -> bytes:
    """Replace only index operands, preserving names, comments and other bytes."""
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise TransactionError("owned bridge snapshot is not UTF-8") from exc
    tokens = list(re.finditer(r'"(?:[^"\\]|\\.)*"|\#[^\n]*|[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[^\s]', text))
    matches: Counter[tuple[str, int]] = Counter()
    replacements: list[tuple[int, int, str]] = []
    for position, token in enumerate(tokens):
        key = token.group()
        if key not in {"iif", "oif", "sdif"}:
            continue
        if position + 1 == len(tokens):
            raise TransactionError("incomplete bridge text interface-index match")
        operand = tokens[position + 1]
        value = operand.group()
        if value.startswith('"'):
            name = parse_json(value.encode(), label="bridge interface name")
            if not isinstance(name, str) or name not in aliases:
                raise TransactionError("bridge text/JSON interface identities differ")
            index = aliases[name]
            replacements.append((operand.start(), operand.end(), str(index)))
        elif re.fullmatch(r"[0-9]+", value):
            index = int(value)
        else:
            raise TransactionError("unsupported bridge text interface-index expression")
        matches[(key, index)] += 1
    if matches != expected:
        raise TransactionError("bridge text/JSON interface-index matches differ")
    for start, end, replacement in reversed(replacements):
        text = text[:start] + replacement + text[end:]
    return text.encode("utf-8")


def read_nft_table_state(nft_binary: str, family: str, table: str) -> NftTableState:
    inventory_argv = [nft_binary, "--json", "list", "tables"]
    first_inventory = require_command(run_command(inventory_argv), label="nftables table inventory")
    first_present = parse_table_inventory(first_inventory.stdout, family, table)
    if not first_present:
        second_inventory = require_command(run_command(inventory_argv), label="second nftables table inventory")
        if parse_table_inventory(second_inventory.stdout, family, table):
            raise TransactionError("configured table appeared during absence classification")
        return NftTableState(False, b"", b"")

    # --numeric alone does not suppress interface names on supported nft.
    # Resolve explicit index operands in this actual network namespace and
    # cross-check both JSON observations and the retained restore text.
    numeric = ["--numeric"] if family == "bridge" else []
    json_argv = [nft_binary, *numeric, "--json", "list", "table", family, table]
    text_argv = [nft_binary, *numeric, "list", "table", family, table]
    first_json = require_command(run_command(json_argv), label="structured configured-table readback")
    first_raw = first_json.stdout
    if family == "bridge":
        first_raw, aliases, index_matches = numeric_bridge_document(first_raw)
    text = require_command(run_command(text_argv), label="text configured-table snapshot")
    restore_text = numeric_bridge_text(text.stdout, aliases, index_matches) if family == "bridge" else text.stdout
    second_json = require_command(run_command(json_argv), label="second structured configured-table readback")
    second_raw = numeric_bridge_document(second_json.stdout)[0] if family == "bridge" else second_json.stdout
    first_canonical = canonicalize_nft_document(first_raw, family, table)
    second_canonical = canonicalize_nft_document(second_raw, family, table)
    if first_canonical != second_canonical:
        raise TransactionError("configured table changed while its snapshot was captured")
    second_inventory = require_command(run_command(inventory_argv), label="final nftables table inventory")
    if not parse_table_inventory(second_inventory.stdout, family, table):
        raise TransactionError("configured table disappeared while its snapshot was captured")
    return NftTableState(True, restore_text, first_canonical)


def path_components(path: Path) -> list[Path]:
    if not path.is_absolute() or ".." in path.parts:
        raise TransactionError(f"unsafe non-absolute or traversing path: {path}")
    components = [Path(path.anchor)]
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        components.append(current)
    return components


def validate_secure_path_chain(
    path: Path,
    *,
    allow_missing_leaf: bool = False,
    expected_leaf: str | None = None,
) -> None:
    components = path_components(path)
    for index, component in enumerate(components):
        leaf = index == len(components) - 1
        try:
            info = component.lstat()
        except FileNotFoundError:
            if leaf and allow_missing_leaf:
                return
            raise TransactionError(f"required secure path component is missing: {component}") from None
        if stat.S_ISLNK(info.st_mode):
            raise TransactionError(f"symbolic links are prohibited in secure path chains: {component}")
        if info.st_uid != 0:
            raise TransactionError(f"secure path component is not root-owned: {component}")
        if info.st_mode & 0o022:
            raise TransactionError(f"secure path component is group/world writable: {component}")
        if not leaf and not stat.S_ISDIR(info.st_mode):
            raise TransactionError(f"secure parent path component is not a directory: {component}")
        if leaf and expected_leaf == "directory" and not stat.S_ISDIR(info.st_mode):
            raise TransactionError(f"secure path is not a directory: {component}")
        if leaf and expected_leaf == "file" and not stat.S_ISREG(info.st_mode):
            raise TransactionError(f"secure path is not a regular file: {component}")


def ensure_distinct_paths(paths: Sequence[Path]) -> None:
    rendered = [str(path) for path in paths]
    if len(rendered) != len(set(rendered)):
        raise TransactionError("transaction file, program, persistence, and unit paths must be pairwise distinct")


@dataclass(frozen=True)
class RuntimeConfig:
    state_directory: Path
    transactions_directory: Path
    claims_directory: Path
    active_path: Path
    lock_path: Path
    persistent_root: Path
    persistent_include: Path
    program_path: Path
    systemd_unit_directory: Path
    confirmation_service: str
    rollback_service: str
    rollback_timer: str
    persistence_service: str
    watchdog_timeout_seconds: int
    command_timeout_seconds: int
    lock_wait_timeout_seconds: int
    expected_target: str
    expected_egress_policy_sha256: str
    expected_egress_status: str
    table_family: str
    table_name: str
    nft_binary: str
    systemctl_binary: str
    verifier_binary: str
    bridge_table_name: str = ""

    def owned_tables(self) -> tuple[tuple[str, str], ...]:
        primary = ((self.table_family, self.table_name),)
        return primary + (("bridge", self.bridge_table_name),) if self.bridge_table_name else primary

    def transaction_schema(self) -> str:
        return "lit.host_firewall.transaction/v4" if self.bridge_table_name else "lit.host_firewall.transaction/v3"

    def configured_paths(self) -> list[Path]:
        paths = [
            self.state_directory,
            self.transactions_directory,
            self.claims_directory,
            self.active_path,
            self.lock_path,
            self.persistent_root,
            self.persistent_include,
            self.program_path,
            self.systemd_unit_directory,
            self.systemd_unit_directory / self.confirmation_service,
            self.systemd_unit_directory / self.rollback_service,
            self.systemd_unit_directory / self.rollback_timer,
            self.systemd_unit_directory / self.persistence_service,
            Path(self.nft_binary),
            Path(self.systemctl_binary),
        ]
        if self.verifier_binary:
            paths.append(Path(self.verifier_binary))
        return paths

    def validate_shape(self) -> None:
        ensure_distinct_paths(self.configured_paths())
        if not UNIT_PATTERN.fullmatch(self.confirmation_service) or not self.confirmation_service.endswith(".service"):
            raise TransactionError("confirmation service name is invalid")
        if not UNIT_PATTERN.fullmatch(self.rollback_service) or not self.rollback_service.endswith(".service"):
            raise TransactionError("rollback service name is invalid")
        if not UNIT_PATTERN.fullmatch(self.rollback_timer) or not self.rollback_timer.endswith(".timer"):
            raise TransactionError("rollback timer name is invalid")
        if not UNIT_PATTERN.fullmatch(self.persistence_service) or not self.persistence_service.endswith(".service"):
            raise TransactionError("persistence service name is invalid")
        if len(
            {
                self.confirmation_service,
                self.rollback_service,
                self.rollback_timer,
                self.persistence_service,
            }
        ) != 4:
            raise TransactionError("confirmation, rollback, timer, and persistence unit names must be distinct")
        if self.transactions_directory.parent != self.state_directory:
            raise TransactionError("transactions directory must be a direct child of the state directory")
        if self.claims_directory.parent != self.state_directory:
            raise TransactionError("claims directory must be a direct child of the state directory")
        if self.active_path.parent != self.state_directory or self.lock_path.parent != self.state_directory:
            raise TransactionError("active pointer and lock must be direct children of the state directory")
        if self.table_family != "inet" or not re.fullmatch(r"[a-z][a-z0-9_]{2,31}", self.table_name):
            raise TransactionError("configured nftables family or table name is invalid")
        if not isinstance(self.bridge_table_name, str) or (
            self.bridge_table_name and not re.fullmatch(r"[a-z][a-z0-9_]{2,31}", self.bridge_table_name)
        ):
            raise TransactionError("configured bridge guard table name is invalid")
        require_sha256(self.expected_egress_policy_sha256, label="expected egress policy digest")
        if self.expected_egress_status not in {"draft", "approved"}:
            raise TransactionError("expected egress status must be draft or approved")
        if self.watchdog_timeout_seconds < 60 or self.watchdog_timeout_seconds > 900:
            raise TransactionError("watchdog timeout must be between 60 and 900 seconds")
        if self.command_timeout_seconds < 5 or self.command_timeout_seconds > 60:
            raise TransactionError("external command timeout must be between 5 and 60 seconds")
        if self.lock_wait_timeout_seconds < 1 or self.lock_wait_timeout_seconds > 60:
            raise TransactionError("transaction lock wait timeout must be between 1 and 60 seconds")
        if self.command_timeout_seconds * 2 + 5 >= self.watchdog_timeout_seconds:
            raise TransactionError("watchdog timeout must retain time for command failure and rollback")
        if self.lock_wait_timeout_seconds + 5 >= self.watchdog_timeout_seconds:
            raise TransactionError("lock wait timeout must remain strictly below the watchdog timeout")

    def rollback_budget_seconds(self) -> int:
        if self.bridge_table_name:
            return max(self.command_timeout_seconds + 5, min(120, self.watchdog_timeout_seconds // 2))
        return max(self.command_timeout_seconds + 5, min(60, self.watchdog_timeout_seconds // 3))

    def transaction_budget_seconds(self, action: str) -> int:
        safety_margin = 5
        if action == "apply":
            return self.watchdog_timeout_seconds - self.rollback_budget_seconds() - safety_margin
        if action == "watchdog-rollback":
            return self.rollback_budget_seconds()
        return self.watchdog_timeout_seconds - safety_margin

    def validate(self, *, setup: bool = False, emergency: bool = False) -> None:
        self.validate_shape()
        if setup:
            for target in (
                self.state_directory,
                self.program_path,
                self.systemd_unit_directory / self.confirmation_service,
                self.systemd_unit_directory / self.rollback_service,
                self.systemd_unit_directory / self.rollback_timer,
            ):
                validate_secure_path_chain(target.parent, expected_leaf="directory")
                if os.path.lexists(target):
                    validate_secure_path_chain(target, expected_leaf="directory" if target == self.state_directory else "file")
            validate_secure_path_chain(self.persistent_root, expected_leaf="file")
            validate_secure_path_chain(self.persistent_include, expected_leaf="file")
            for binary in (Path(self.nft_binary), Path(self.systemctl_binary)):
                validate_secure_path_chain(binary, expected_leaf="file")
                if not stat.S_IMODE(binary.stat().st_mode) & 0o111:
                    raise TransactionError(f"required command is not executable: {binary}")
            if self.verifier_binary:
                verifier_path = Path(self.verifier_binary)
                validate_secure_path_chain(verifier_path, expected_leaf="file")
                if not stat.S_IMODE(verifier_path.stat().st_mode) & 0o111:
                    raise TransactionError("authorization verifier is not executable")
            return
        for directory in (self.state_directory, self.transactions_directory, self.claims_directory):
            validate_secure_path_chain(directory, expected_leaf="directory")
        runtime_files = [Path(self.nft_binary), Path(self.systemctl_binary)]
        if not emergency:
            runtime_files[0:0] = [
                self.program_path,
                self.systemd_unit_directory / self.confirmation_service,
                self.systemd_unit_directory / self.rollback_service,
                self.systemd_unit_directory / self.rollback_timer,
            ]
        for file_path in runtime_files:
            validate_secure_path_chain(file_path, expected_leaf="file")
        if not emergency and not stat.S_IMODE(self.program_path.stat().st_mode) & 0o100:
            raise TransactionError("transaction program is not root-executable")
        for binary in (Path(self.nft_binary), Path(self.systemctl_binary)):
            if not stat.S_IMODE(binary.stat().st_mode) & 0o111:
                raise TransactionError(f"required command is not executable: {binary}")
        if self.verifier_binary and not emergency:
            verifier_path = Path(self.verifier_binary)
            validate_secure_path_chain(verifier_path, expected_leaf="file")
            if not stat.S_IMODE(verifier_path.stat().st_mode) & 0o111:
                raise TransactionError("authorization verifier is not executable")
        validate_secure_path_chain(self.persistent_root, expected_leaf="file")
        validate_secure_path_chain(self.persistent_include, expected_leaf="file")
        if os.path.lexists(self.active_path):
            validate_secure_path_chain(self.active_path, expected_leaf="file")
        if os.path.lexists(self.lock_path):
            validate_secure_path_chain(self.lock_path, expected_leaf="file")


def open_nofollow(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)


def read_secure_bytes(path: Path) -> bytes:
    validate_secure_path_chain(path, expected_leaf="file")
    descriptor = open_nofollow(path)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise TransactionError(f"secure file changed ownership, type, or mode while opening: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def fsync_directory(path: Path) -> None:
    validate_secure_path_chain(path, expected_leaf="directory")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_exclusive(path: Path, value: bytes, mode: int = 0o400) -> None:
    validate_secure_path_chain(path.parent, expected_leaf="directory")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)
    fsync_directory(path.parent)


def atomic_replace(path: Path, value: bytes, mode: int = 0o600) -> None:
    validate_secure_path_chain(path.parent, expected_leaf="directory")
    if os.path.lexists(path):
        validate_secure_path_chain(path, expected_leaf="file")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def durable_unlink(path: Path, *, missing_ok: bool = False) -> None:
    validate_secure_path_chain(path.parent, expected_leaf="directory")
    try:
        path.unlink()
    except FileNotFoundError:
        if not missing_ok:
            raise
    fsync_directory(path.parent)


def ensure_secure_directory(path: Path) -> None:
    validate_secure_path_chain(path.parent, expected_leaf="directory")
    created = False
    try:
        os.mkdir(path, 0o700)
        created = True
    except FileExistsError:
        pass
    validate_secure_path_chain(path, expected_leaf="directory")
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise TransactionError(f"transaction directory must have exact mode 0700: {path}")
    if created:
        fsync_directory(path.parent)


def write_terminal_disable_watchdog_and_clear_active(
    config: RuntimeConfig,
    terminal_path: Path,
    record: dict[str, Any],
) -> None:
    write_exclusive(terminal_path, canonical_json(record))
    systemctl(config, "disable", "--now", config.rollback_timer)
    durable_unlink(config.active_path)


def finalize_existing_terminal(config: RuntimeConfig) -> None:
    systemctl(config, "disable", "--now", config.rollback_timer)
    durable_unlink(config.active_path, missing_ok=True)


@contextlib.contextmanager
def exclusive_transaction_lock(
    config: RuntimeConfig,
    *,
    absolute_deadline: float | None = None,
) -> Iterator[None]:
    config.validate_shape()
    validate_secure_path_chain(config.lock_path.parent, expected_leaf="directory")
    descriptor = os.open(
        config.lock_path,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        info = os.fstat(descriptor)
        if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise TransactionError("transaction lock is not a root-only regular file")
        lock_deadline = time.monotonic() + config.lock_wait_timeout_seconds
        if absolute_deadline is not None:
            lock_deadline = min(lock_deadline, absolute_deadline)
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if absolute_deadline is not None and time.monotonic() >= absolute_deadline:
                    raise TransactionError(
                        "shared transaction lock was acquired after the bounded action deadline"
                    )
                break
            except BlockingIOError:
                remaining = lock_deadline - time.monotonic()
                if remaining <= 0:
                    raise TransactionError("shared transaction lock wait exceeded its fail-closed timeout") from None
                time.sleep(min(0.05, remaining))
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextlib.contextmanager
def transaction_scope(config: RuntimeConfig, *, action: str) -> Iterator[None]:
    budget_seconds = config.transaction_budget_seconds(action)
    absolute_deadline = time.monotonic() + budget_seconds
    with command_deadline_until(
        absolute_deadline,
        command_timeout_seconds=config.command_timeout_seconds,
    ):
        with exclusive_transaction_lock(config, absolute_deadline=absolute_deadline):
            yield


def decode_install_asset(value: Any, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise TransactionError(f"{label} must be strict base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise TransactionError(f"{label} is not strict base64: {exc}") from exc
    if not decoded:
        raise TransactionError(f"{label} cannot be empty")
    return decoded


def install_runtime(config: RuntimeConfig, payload: dict[str, Any]) -> dict[str, Any]:
    require_exact_mapping(payload, INSTALL_KEYS, label="runtime installation payload")
    if payload["schema"] != "lit.host_firewall.runtime-install/v3":
        raise TransactionError("runtime installation payload schema is invalid")
    assets = {
        config.program_path: (decode_install_asset(payload["program_base64"], label="program"), 0o750),
        config.systemd_unit_directory / config.confirmation_service: (
            decode_install_asset(payload["confirmation_unit_base64"], label="confirmation unit"),
            0o644,
        ),
        config.systemd_unit_directory / config.rollback_service: (
            decode_install_asset(payload["rollback_unit_base64"], label="rollback unit"),
            0o644,
        ),
        config.systemd_unit_directory / config.rollback_timer: (
            decode_install_asset(payload["rollback_timer_base64"], label="rollback timer"),
            0o644,
        ),
    }
    with transaction_scope(config, action="install-runtime"):
        config.validate(setup=True)
        if os.path.lexists(config.active_path):
            raise TransactionError("runtime installation is prohibited while a transaction is active")
        ensure_secure_directory(config.transactions_directory)
        ensure_secure_directory(config.claims_directory)
        for path, (content, mode) in assets.items():
            atomic_replace(path, content, mode)
        systemctl(config, "daemon-reload")
        config.validate()
        return {
            "schema": "lit.host_firewall.runtime-install-result/v3",
            "status": "installed",
            "asset_sha256": {str(path): sha256_bytes(content) for path, (content, _mode) in assets.items()},
        }


def validate_root_include(config: RuntimeConfig) -> None:
    root_content = read_secure_bytes(config.persistent_root).decode("utf-8")
    exact_directive = f'include "{config.persistent_include}"'
    if root_content.splitlines().count(exact_directive) != 1:
        raise TransactionError("administrator root configuration must contain exactly one literal role include")
    if os.path.lexists(config.persistent_include):
        validate_secure_path_chain(config.persistent_include, expected_leaf="file")


def load_request_from_stdin() -> dict[str, Any]:
    encoded = sys.stdin.buffer.read()
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise TransactionError(f"request transport is not strict base64: {exc}") from exc
    value = parse_json(raw, label="transaction request")
    if not isinstance(value, dict):
        raise TransactionError("transaction request must be a mapping")
    return value


def validate_request(request: dict[str, Any], config: RuntimeConfig, *, action: str) -> bytes | None:
    expected_keys = REQUEST_COMMON_KEYS | ({"candidate_base64"} if action == "apply" else set())
    require_exact_mapping(request, expected_keys, label=f"{action} request")
    if request["schema"] != "lit.host_firewall.transaction-request/v3" or request["action"] != action:
        raise TransactionError("transaction request schema or action mismatch")
    if request["target"] != config.expected_target or request["mode"] not in {"bootstrap", "hardened"}:
        raise TransactionError("transaction request target or mode mismatch")
    if not isinstance(request["change_id"], str) or not IDENTIFIER_PATTERN.fullmatch(request["change_id"]):
        raise TransactionError("transaction request change_id is invalid")
    for field in ("candidate_sha256", "approved_readback_sha256", "policy_fingerprint"):
        require_sha256(request[field], label=field)
    require_sha256(request["egress_policy_sha256"], label="egress_policy_sha256")
    if request["egress_policy_sha256"] != config.expected_egress_policy_sha256:
        raise TransactionError("transaction request egress policy digest differs from the configured policy")
    if request["egress_status"] != config.expected_egress_status:
        raise TransactionError("transaction request egress status differs from the configured policy")
    candidate: bytes | None = None
    if action == "apply":
        try:
            candidate = base64.b64decode(request["candidate_base64"], validate=True)
        except (TypeError, ValueError) as exc:
            raise TransactionError(f"candidate_base64 is invalid: {exc}") from exc
        if sha256_bytes(candidate) != request["candidate_sha256"]:
            raise TransactionError("candidate digest differs from the apply request")
    return candidate


def validate_authorization(
    request: dict[str, Any],
    config: RuntimeConfig,
    *,
    now: dt.datetime | None = None,
) -> tuple[dict[str, Any], bytes, bytes]:
    authorization = require_exact_mapping(request["authorization"], AUTHORIZATION_KEYS, label="authorization")
    if authorization["schema"] != "lit.host_firewall.authorization/v2":
        raise TransactionError("authorization schema is not supported")
    for field in (
        "action",
        "approved_readback_sha256",
        "candidate_sha256",
        "change_id",
        "egress_policy_sha256",
        "egress_status",
        "policy_fingerprint",
        "target",
    ):
        if authorization[field] != request[field]:
            raise TransactionError(f"authorization does not bind request field {field}")
    claim_id = authorization["claim_id"]
    if not isinstance(claim_id, str) or not IDENTIFIER_PATTERN.fullmatch(claim_id):
        raise TransactionError("authorization claim_id is invalid")
    issued_at = parse_utc(authorization["issued_at"], label="authorization issued_at")
    expires_at = parse_utc(authorization["expires_at"], label="authorization expires_at")
    current = now or utc_now()
    if issued_at > current or current >= expires_at or expires_at - issued_at > dt.timedelta(minutes=15):
        raise TransactionError("authorization is not currently valid or exceeds the 15-minute maximum lifetime")
    signature = authorization["signature"]
    if not isinstance(signature, str) or len(signature) < 32 or len(signature) > 8192:
        raise TransactionError("authorization signature is malformed")
    try:
        decoded_signature = base64.b64decode(signature, validate=True)
    except ValueError as exc:
        raise TransactionError(f"authorization signature is not strict base64: {exc}") from exc
    if len(decoded_signature) < 32 or len(decoded_signature) > 4096:
        raise TransactionError("authorization signature has an invalid decoded size")
    if not config.verifier_binary:
        raise TransactionError("trusted authorization signature verifier is unavailable")
    verifier_path = Path(config.verifier_binary)
    validate_secure_path_chain(verifier_path, expected_leaf="file")
    payload = canonical_json(authorization)
    receipt_result = require_command(
        run_command([config.verifier_binary, "verify-host-firewall-claim"], input_bytes=payload),
        label="authorization signature verification",
    )
    receipt = require_exact_mapping(
        parse_json(receipt_result.stdout, label="authorization verifier receipt"),
        {"authorization_sha256", "claim_id", "schema", "valid"},
        label="authorization verifier receipt",
    )
    if (
        not isinstance(receipt["schema"], str)
        or receipt["schema"] != "lit.host_firewall.authorization-verification/v1"
        or not isinstance(receipt["claim_id"], str)
        or receipt["claim_id"] != claim_id
        or not isinstance(receipt["authorization_sha256"], str)
        or receipt["authorization_sha256"] != sha256_bytes(payload)
        or type(receipt["valid"]) is not bool
        or receipt["valid"] is not True
    ):
        raise TransactionError("authorization verifier returned a mismatched receipt")
    claim_path = config.claims_directory / f"{claim_id}.json"
    validate_secure_path_chain(claim_path, allow_missing_leaf=True)
    if os.path.lexists(claim_path):
        raise TransactionError("authorization claim was already consumed")
    return authorization, payload, canonical_json(receipt)


def consume_claim(
    config: RuntimeConfig,
    authorization: dict[str, Any],
    authorization_payload: bytes,
    verification_payload: bytes,
    transaction_id: str,
) -> None:
    receipt = canonical_json(
        {
            "schema": "lit.host_firewall.claim-consumption/v1",
            "claim_id": authorization["claim_id"],
            "action": authorization["action"],
            "transaction_id": transaction_id,
            "authorization_sha256": sha256_bytes(authorization_payload),
            "verification_sha256": sha256_bytes(verification_payload),
            "consumed_at": format_utc(utc_now()),
        }
    )
    write_exclusive(config.claims_directory / f"{authorization['claim_id']}.json", receipt)


def transaction_paths(transaction_directory: Path) -> dict[str, Path]:
    names = {
        "candidate": "candidate.nft",
        "apply_authorization": "apply-authorization.json",
        "apply_verification": "apply-verification.json",
        "runtime_backup": "runtime-before.nft",
        "runtime_canonical": "runtime-before.canonical.json",
        "runtime_state": "runtime-before.state",
        "persistent_backup": "persistent-before.nft",
        "persistent_state": "persistent-before.state",
        "metadata": "metadata.json",
        "confirm_request": "confirm-request.json",
        "confirm_verification": "confirm-verification.json",
        "rollback_authorization": "rollback-authorization.json",
        "rollback_verification": "rollback-verification.json",
        "terminal": "terminal.json",
    }
    result = {key: transaction_directory / name for key, name in names.items()}
    ensure_distinct_paths(list(result.values()))
    return result


def load_active(config: RuntimeConfig, *, required: bool) -> tuple[dict[str, Any], Path, dict[str, Path]] | None:
    if not os.path.lexists(config.active_path):
        if required:
            raise TransactionError("no active host firewall transaction exists")
        return None
    active = require_exact_mapping(parse_json(read_secure_bytes(config.active_path), label="active transaction"), ACTIVE_KEYS, label="active transaction")
    if active["schema"] != "lit.host_firewall.active/v3":
        raise TransactionError("active transaction schema is invalid")
    transaction_id = active["transaction_id"]
    if not isinstance(transaction_id, str) or not re.fullmatch(r"[a-f0-9]{32}", transaction_id):
        raise TransactionError("active transaction identifier is invalid")
    transaction_directory = config.transactions_directory / transaction_id
    if active["transaction_path"] != str(transaction_directory):
        raise TransactionError("active transaction path escaped the configured transaction directory")
    validate_secure_path_chain(transaction_directory, expected_leaf="directory")
    require_sha256(active["metadata_sha256"], label="active metadata_sha256")
    return active, transaction_directory, transaction_paths(transaction_directory)


def validate_metadata_and_assets(
    config: RuntimeConfig,
    active: dict[str, Any],
    paths: dict[str, Path],
    *,
    validate_static: bool = True,
) -> dict[str, Any]:
    metadata_raw = read_secure_bytes(paths["metadata"])
    if sha256_bytes(metadata_raw) != active["metadata_sha256"]:
        raise TransactionError("active metadata digest has changed")
    metadata_keys = METADATA_KEYS | ({"owned_tables"} if config.bridge_table_name else set())
    metadata = require_exact_mapping(parse_json(metadata_raw, label="transaction metadata"), metadata_keys, label="transaction metadata")
    if metadata["schema"] != config.transaction_schema():
        raise TransactionError("transaction metadata schema is invalid")
    if config.bridge_table_name and metadata["owned_tables"] != [list(identity) for identity in config.owned_tables()]:
        raise TransactionError("transaction metadata owned-table scope differs from the configured policy")
    if metadata["action"] != "apply" or metadata["mode"] not in {"bootstrap", "hardened"}:
        raise TransactionError("transaction metadata action or mode is invalid")
    if metadata["egress_status"] not in {"draft", "approved"}:
        raise TransactionError("transaction metadata egress status is invalid")
    if metadata["target"] != config.expected_target or metadata["transaction_id"] != active["transaction_id"]:
        raise TransactionError("transaction metadata target or identifier mismatch")
    if not isinstance(metadata["change_id"], str) or not IDENTIFIER_PATTERN.fullmatch(metadata["change_id"]):
        raise TransactionError("transaction metadata change_id is invalid")
    if not isinstance(metadata["claim_id"], str) or not IDENTIFIER_PATTERN.fullmatch(metadata["claim_id"]):
        raise TransactionError("transaction metadata claim_id is invalid")
    parse_utc(metadata["created_at"], label="transaction metadata created_at")
    for field in (
        "approved_readback_sha256",
        "apply_authorization_sha256",
        "apply_verification_sha256",
        "candidate_sha256",
        "confirmation_unit_sha256",
        "egress_policy_sha256",
        "persistent_backup_sha256",
        "persistent_root_sha256",
        "persistent_state_sha256",
        "policy_fingerprint",
        "program_sha256",
        "rollback_timer_sha256",
        "rollback_unit_sha256",
        "runtime_backup_sha256",
        "runtime_canonical_sha256",
        "runtime_state_sha256",
        "verifier_sha256",
    ):
        require_sha256(metadata[field], label=f"metadata {field}")
    asset_hashes = {
        "candidate": "candidate_sha256",
        "apply_authorization": "apply_authorization_sha256",
        "apply_verification": "apply_verification_sha256",
        "runtime_backup": "runtime_backup_sha256",
        "runtime_canonical": "runtime_canonical_sha256",
        "runtime_state": "runtime_state_sha256",
        "persistent_backup": "persistent_backup_sha256",
        "persistent_state": "persistent_state_sha256",
    }
    for asset, metadata_field in asset_hashes.items():
        if sha256_bytes(read_secure_bytes(paths[asset])) != metadata[metadata_field]:
            raise TransactionError(f"transaction asset changed: {asset}")
    if validate_static:
        if metadata["verifier_path"] != config.verifier_binary:
            raise TransactionError("transaction metadata verifier identity differs from the configured verifier")
        static_assets = {
            config.program_path: "program_sha256",
            config.systemd_unit_directory / config.confirmation_service: "confirmation_unit_sha256",
            config.systemd_unit_directory / config.rollback_service: "rollback_unit_sha256",
            config.systemd_unit_directory / config.rollback_timer: "rollback_timer_sha256",
            Path(config.verifier_binary): "verifier_sha256",
        }
        for asset_path, metadata_field in static_assets.items():
            if sha256_bytes(read_secure_bytes(asset_path)) != metadata[metadata_field]:
                raise TransactionError(f"static transaction asset changed: {asset_path}")
        if sha256_bytes(read_secure_bytes(config.persistent_root)) != metadata["persistent_root_sha256"]:
            raise TransactionError("administrator root nftables configuration changed during the transaction")
    runtime_state = read_secure_bytes(paths["runtime_state"])
    persistent_state = read_secure_bytes(paths["persistent_state"])
    if runtime_state not in {b"present\n", b"absent\n"}:
        raise TransactionError("runtime state marker is invalid")
    if persistent_state not in {b"present\n", b"absent\n"}:
        raise TransactionError("persistent state marker is invalid")
    return metadata


def validate_pending_persistence(config: RuntimeConfig, metadata: dict[str, Any], paths: dict[str, Path]) -> None:
    validate_root_include(config)
    if sha256_bytes(read_secure_bytes(config.persistent_include)) != metadata["persistent_backup_sha256"]:
        raise TransactionError("role-owned persistence include changed while confirmation was pending")
    if read_secure_bytes(paths["persistent_state"]) != b"present\n":
        raise TransactionError("pending transaction does not have a rollback-safe persistent include")


def load_terminal(paths: dict[str, Path]) -> dict[str, Any] | None:
    if not os.path.lexists(paths["terminal"]):
        return None
    terminal = parse_json(read_secure_bytes(paths["terminal"]), label="terminal transaction record")
    if not isinstance(terminal, dict):
        raise TransactionError("terminal transaction record must be a mapping")
    schema = terminal.get("schema")
    if schema == "lit.host_firewall.confirmation/v3":
        require_exact_mapping(terminal, CONFIRMATION_KEYS, label="confirmation terminal record")
        parse_utc(terminal["confirmed_at"], label="confirmation timestamp")
        if not isinstance(terminal["authorization_claim_id"], str):
            raise TransactionError("confirmation authorization claim is invalid")
        digest_fields = (
            "approved_readback_sha256",
            "authorization_sha256",
            "authorization_verification_sha256",
            "candidate_sha256",
            "egress_policy_sha256",
            "policy_fingerprint",
        )
    elif schema == "lit.host_firewall.rollback/v3":
        require_exact_mapping(terminal, ROLLBACK_KEYS, label="rollback terminal record")
        parse_utc(terminal["rolled_back_at"], label="rollback timestamp")
        if terminal["source"] not in {"explicit", "watchdog"}:
            raise TransactionError("rollback source is invalid")
        if terminal["restored_runtime_state"] not in {"present", "absent"}:
            raise TransactionError("restored runtime state is invalid")
        if terminal["restored_persistent_state"] != "present":
            raise TransactionError("restored persistence state is invalid")
        if terminal["restored_runtime_state"] == "present":
            require_sha256(terminal["restored_readback_sha256"], label="restored readback digest")
        elif terminal["restored_readback_sha256"] != "":
            raise TransactionError("absent restored runtime must use an empty readback digest")
        if terminal["source"] == "explicit":
            if not isinstance(terminal["authorization_claim_id"], str):
                raise TransactionError("explicit rollback authorization claim is invalid")
            require_sha256(terminal["authorization_sha256"], label="rollback authorization digest")
            require_sha256(
                terminal["authorization_verification_sha256"],
                label="rollback authorization verification digest",
            )
        elif any(
            terminal[field] is not None
            for field in (
                "authorization_claim_id",
                "authorization_sha256",
                "authorization_verification_sha256",
            )
        ):
            raise TransactionError("watchdog rollback cannot claim an external authorization")
        digest_fields = (
            "approved_readback_sha256",
            "candidate_sha256",
            "egress_policy_sha256",
            "policy_fingerprint",
            "restored_persistent_sha256",
        )
    else:
        raise TransactionError("terminal transaction record schema is invalid")
    if not isinstance(terminal["transaction_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", terminal["transaction_id"]):
        raise TransactionError("terminal transaction identifier is invalid")
    for field in digest_fields:
        require_sha256(terminal[field], label=f"terminal {field}")
    return terminal


def write_active(config: RuntimeConfig, transaction_id: str, transaction_directory: Path, metadata_raw: bytes) -> None:
    active_raw = canonical_json(
        {
            "schema": "lit.host_firewall.active/v3",
            "transaction_id": transaction_id,
            "transaction_path": str(transaction_directory),
            "metadata_sha256": sha256_bytes(metadata_raw),
        }
    )
    write_exclusive(config.active_path, active_raw, 0o600)


def systemctl(config: RuntimeConfig, *arguments: str) -> None:
    require_command(run_command([config.systemctl_binary, *arguments]), label=f"systemctl {' '.join(arguments)}")


def require_rollback_service_quiescent(config: RuntimeConfig) -> None:
    result = require_command(
        run_command(
            [
                config.systemctl_binary,
                "show",
                "--property=ActiveState",
                "--value",
                config.rollback_service,
            ]
        ),
        label="rollback service state read",
    )
    try:
        state = result.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise TransactionError("rollback service state is not ASCII") from exc
    if state != "inactive":
        raise TransactionError(f"rollback service is not quiescent: {state!r}")


def create_runtime_backup(state: NftTableState, family: str, table: str) -> bytes:
    prefix = f"destroy table {family} {table}\n".encode("ascii")
    if not state.present:
        return prefix
    return prefix + state.text.rstrip(b"\n") + b"\n"


@dataclass(frozen=True)
class NftPolicyState:
    identities: tuple[tuple[str, str], ...]
    tables: tuple[NftTableState, ...]

    def __post_init__(self) -> None:
        if not self.identities or len(self.identities) != len(self.tables) or len(set(self.identities)) != len(self.identities):
            raise TransactionError("owned-table snapshot identities are empty, duplicated or incomplete")

    @property
    def present(self) -> bool:
        return any(table.present for table in self.tables)

    @property
    def complete(self) -> bool:
        return all(table.present for table in self.tables)

    @property
    def canonical(self) -> bytes:
        # Preserve the exact existing single-table authorization representation.
        if len(self.tables) == 1:
            return self.tables[0].canonical
        if not self.present:
            return b""
        return canonical_json({
            "schema": "lit.host_firewall.owned-tables/v1",
            "tables": [{"family": family, "name": name, "present": state.present,
                        "policy": parse_json(state.canonical, label="owned-table policy") if state.present else None}
                       for (family, name), state in zip(self.identities, self.tables)],
        })

    @property
    def backup(self) -> bytes:
        return b"".join(create_runtime_backup(state, family, name)
                        for (family, name), state in zip(self.identities, self.tables))


def read_nft_policy_state(config: RuntimeConfig) -> NftPolicyState:
    identities = config.owned_tables()
    states = tuple(read_nft_table_state(config.nft_binary, family, name) for family, name in identities)
    if config.bridge_table_name:
        repeated = tuple(read_nft_table_state(config.nft_binary, family, name) for family, name in identities)
        if [(state.present, state.canonical) for state in states] != [
                (state.present, state.canonical) for state in repeated]:
            raise TransactionError("owned-table policy changed during the coupled snapshot")
    return NftPolicyState(identities, states)


def snapshot_persistent(config: RuntimeConfig) -> tuple[bytes, bytes]:
    if not os.path.lexists(config.persistent_include):
        raise TransactionError("a valid preprovisioned persistence include is required for rollback")
    return read_secure_bytes(config.persistent_include), b"present\n"


def apply_transaction(config: RuntimeConfig, request: dict[str, Any]) -> dict[str, Any]:
    candidate = validate_request(request, config, action="apply")
    assert candidate is not None
    with transaction_scope(config, action="apply"):
        config.validate()
        if os.path.lexists(config.active_path):
            raise TransactionError("an active host firewall transaction already exists")
        authorization, authorization_payload, verification_payload = validate_authorization(request, config)
        validate_root_include(config)
        require_command(
            run_command([config.nft_binary, "--check", "--file", "-"], input_bytes=candidate),
            label="candidate nftables check",
        )
        runtime_state = read_nft_policy_state(config)
        persistent_backup, persistent_state = snapshot_persistent(config)

        transaction_id = uuid.uuid4().hex
        transaction_directory = config.transactions_directory / transaction_id
        ensure_secure_directory(transaction_directory)
        paths = transaction_paths(transaction_directory)
        runtime_backup = runtime_state.backup
        runtime_marker = b"present\n" if runtime_state.present else b"absent\n"
        runtime_canonical = runtime_state.canonical
        for key, value in (
            ("candidate", candidate),
            ("apply_authorization", authorization_payload),
            ("apply_verification", verification_payload),
            ("runtime_backup", runtime_backup),
            ("runtime_canonical", runtime_canonical),
            ("runtime_state", runtime_marker),
            ("persistent_backup", persistent_backup),
            ("persistent_state", persistent_state),
        ):
            write_exclusive(paths[key], value)

        metadata = {
            "schema": config.transaction_schema(),
            "transaction_id": transaction_id,
            "target": request["target"],
            "action": "apply",
            "change_id": request["change_id"],
            "mode": request["mode"],
            "egress_policy_sha256": request["egress_policy_sha256"],
            "egress_status": request["egress_status"],
            "candidate_sha256": request["candidate_sha256"],
            "approved_readback_sha256": request["approved_readback_sha256"],
            "policy_fingerprint": request["policy_fingerprint"],
            "apply_authorization_sha256": sha256_bytes(authorization_payload),
            "apply_verification_sha256": sha256_bytes(verification_payload),
            "claim_id": authorization["claim_id"],
            "runtime_backup_sha256": sha256_bytes(runtime_backup),
            "runtime_canonical_sha256": sha256_bytes(runtime_canonical),
            "runtime_state_sha256": sha256_bytes(runtime_marker),
            "persistent_backup_sha256": sha256_bytes(persistent_backup),
            "persistent_state_sha256": sha256_bytes(persistent_state),
            "persistent_root_sha256": sha256_bytes(read_secure_bytes(config.persistent_root)),
            "program_sha256": sha256_bytes(read_secure_bytes(config.program_path)),
            "confirmation_unit_sha256": sha256_bytes(
                read_secure_bytes(config.systemd_unit_directory / config.confirmation_service)
            ),
            "rollback_unit_sha256": sha256_bytes(
                read_secure_bytes(config.systemd_unit_directory / config.rollback_service)
            ),
            "rollback_timer_sha256": sha256_bytes(
                read_secure_bytes(config.systemd_unit_directory / config.rollback_timer)
            ),
            "verifier_path": config.verifier_binary,
            "verifier_sha256": sha256_bytes(read_secure_bytes(Path(config.verifier_binary))),
            "created_at": format_utc(utc_now()),
        }
        if config.bridge_table_name:
            metadata["owned_tables"] = [list(identity) for identity in config.owned_tables()]
        metadata_raw = canonical_json(metadata)
        write_exclusive(paths["metadata"], metadata_raw)
        consume_claim(config, authorization, authorization_payload, verification_payload, transaction_id)
        write_active(config, transaction_id, transaction_directory, metadata_raw)

        try:
            systemctl(config, "enable", "--now", config.rollback_timer)
            require_command(
                run_command([config.nft_binary, "--file", "-"], input_bytes=candidate),
                label="candidate nftables apply",
            )
            applied = read_nft_policy_state(config)
            if not applied.complete or sha256_bytes(applied.canonical) != request["approved_readback_sha256"]:
                raise TransactionError("applied structured readback differs from the independently approved digest")
        except Exception:
            with bounded_command_deadline(
                config.rollback_budget_seconds(),
                command_timeout_seconds=config.command_timeout_seconds,
            ):
                rollback_locked(config, explicit_request=None, watchdog=True)
            raise

        return {
            "schema": "lit.host_firewall.apply-result/v3",
            "status": "pending-confirmation",
            "transaction_id": transaction_id,
            "transaction_path": str(transaction_directory),
            "metadata_sha256": sha256_bytes(metadata_raw),
        }


def stage_confirmation(config: RuntimeConfig, request: dict[str, Any]) -> dict[str, Any]:
    validate_request(request, config, action="confirm")
    with transaction_scope(config, action="stage-confirm"):
        config.validate()
        loaded = load_active(config, required=True)
        assert loaded is not None
        active, transaction_directory, paths = loaded
        metadata = validate_metadata_and_assets(config, active, paths)
        for field in (
            "target",
            "change_id",
            "mode",
            "candidate_sha256",
            "approved_readback_sha256",
            "policy_fingerprint",
            "egress_policy_sha256",
            "egress_status",
        ):
            if request[field] != metadata[field]:
                raise TransactionError(f"confirmation request differs from active metadata field {field}")
        terminal = load_terminal(paths)
        if terminal is not None:
            if terminal["transaction_id"] != active["transaction_id"]:
                raise TransactionError("terminal outcome does not belong to the active transaction")
            raise TransactionError("a terminal outcome already exists for this transaction")
        _authorization, _authorization_payload, verification_payload = validate_authorization(request, config)
        request_raw = canonical_json(request)
        for path, content in (
            (paths["confirm_request"], request_raw),
            (paths["confirm_verification"], verification_payload),
        ):
            if os.path.lexists(path):
                if read_secure_bytes(path) != content:
                    raise TransactionError("a different confirmation artifact is already staged")
            else:
                write_exclusive(path, content)
        return {
            "schema": "lit.host_firewall.confirm-stage/v3",
            "transaction_id": active["transaction_id"],
            "transaction_path": str(transaction_directory),
            "confirmation_path": str(paths["terminal"]),
        }


def confirm_transaction(config: RuntimeConfig) -> dict[str, Any]:
    with transaction_scope(config, action="confirm"):
        config.validate()
        require_rollback_service_quiescent(config)
        loaded = load_active(config, required=True)
        assert loaded is not None
        active, transaction_directory, paths = loaded
        terminal = load_terminal(paths)
        if terminal is not None:
            if terminal["transaction_id"] != active["transaction_id"]:
                raise TransactionError("terminal outcome does not belong to the active transaction")
            if terminal["schema"] != "lit.host_firewall.confirmation/v3":
                raise TransactionError("the active transaction already has a rollback outcome")
            finalize_existing_terminal(config)
            return terminal
        metadata = validate_metadata_and_assets(config, active, paths)
        validate_pending_persistence(config, metadata, paths)
        confirm_request_raw = read_secure_bytes(paths["confirm_request"])
        staged_verification = read_secure_bytes(paths["confirm_verification"])
        request = require_exact_mapping(
            parse_json(confirm_request_raw, label="confirmation request"),
            REQUEST_COMMON_KEYS,
            label="confirmation request",
        )
        validate_request(request, config, action="confirm")
        for field in (
            "target",
            "change_id",
            "mode",
            "candidate_sha256",
            "approved_readback_sha256",
            "policy_fingerprint",
            "egress_policy_sha256",
            "egress_status",
        ):
            if request[field] != metadata[field]:
                raise TransactionError(f"confirmation request differs from active metadata field {field}")
        authorization, authorization_payload, verification_payload = validate_authorization(request, config)
        if verification_payload != staged_verification:
            raise TransactionError("trusted confirmation verification receipt changed after staging")
        if metadata["egress_status"] != "approved":
            raise TransactionError("confirmation requires an approved egress policy")
        current = read_nft_policy_state(config)
        if not current.complete or sha256_bytes(current.canonical) != metadata["approved_readback_sha256"]:
            raise TransactionError("current structured readback differs from approved transaction metadata")

        # Hold the exact bytes validated above so no second path read can introduce a TOCTOU window.
        candidate = read_secure_bytes(paths["candidate"])
        if sha256_bytes(candidate) != metadata["candidate_sha256"]:
            raise TransactionError("candidate changed after the pre-confirmation asset rehash")

        # Asset rehash, metadata validation, root include validation, and readback all happen before watchdog stop.
        systemctl(config, "stop", config.rollback_timer)
        require_rollback_service_quiescent(config)
        validate_metadata_and_assets(config, active, paths)
        validate_pending_persistence(config, metadata, paths)
        if read_secure_bytes(paths["confirm_request"]) != confirm_request_raw:
            raise TransactionError("confirmation request changed while the watchdog was being stopped")
        if read_secure_bytes(paths["confirm_verification"]) != staged_verification:
            raise TransactionError("confirmation verification receipt changed while the watchdog was being stopped")
        final_readback = read_nft_policy_state(config)
        if not final_readback.complete or sha256_bytes(final_readback.canonical) != metadata["approved_readback_sha256"]:
            raise TransactionError("structured runtime drifted after the watchdog was stopped")
        consume_claim(
            config,
            authorization,
            authorization_payload,
            verification_payload,
            active["transaction_id"],
        )
        atomic_replace(config.persistent_include, candidate, 0o600)
        require_command(
            run_command([config.nft_binary, "--check", "--file", str(config.persistent_include)]),
            label="persistent include check",
        )
        require_command(
            run_command([config.nft_binary, "--check", "--file", str(config.persistent_root)]),
            label="administrator root nftables check",
        )
        confirmation = {
            "schema": "lit.host_firewall.confirmation/v3",
            "transaction_id": active["transaction_id"],
            "target": metadata["target"],
            "change_id": metadata["change_id"],
            "candidate_sha256": metadata["candidate_sha256"],
            "approved_readback_sha256": metadata["approved_readback_sha256"],
            "policy_fingerprint": metadata["policy_fingerprint"],
            "egress_policy_sha256": metadata["egress_policy_sha256"],
            "egress_status": metadata["egress_status"],
            "authorization_claim_id": authorization["claim_id"],
            "authorization_sha256": sha256_bytes(authorization_payload),
            "authorization_verification_sha256": sha256_bytes(verification_payload),
            "confirmed_at": format_utc(utc_now()),
        }
        write_terminal_disable_watchdog_and_clear_active(config, paths["terminal"], confirmation)
        return confirmation


def validate_explicit_rollback_request(
    request: dict[str, Any],
    config: RuntimeConfig,
    metadata: dict[str, Any],
) -> tuple[dict[str, Any], bytes, bytes]:
    validate_request(request, config, action="rollback")
    for field in (
        "target",
        "change_id",
        "mode",
        "candidate_sha256",
        "approved_readback_sha256",
        "policy_fingerprint",
        "egress_policy_sha256",
        "egress_status",
    ):
        if request[field] != metadata[field]:
            raise TransactionError(f"rollback request differs from active metadata field {field}")
    return validate_authorization(request, config)


def rollback_locked(
    config: RuntimeConfig,
    *,
    explicit_request: dict[str, Any] | None,
    watchdog: bool,
) -> dict[str, Any]:
    loaded = load_active(config, required=not watchdog)
    if loaded is None:
        return {"schema": "lit.host_firewall.rollback-result/v3", "status": "no-active-transaction"}
    active, transaction_directory, paths = loaded
    terminal = load_terminal(paths)
    if terminal is not None:
        if terminal["transaction_id"] != active["transaction_id"]:
            raise TransactionError("terminal outcome does not belong to the active transaction")
        if terminal["schema"] == "lit.host_firewall.confirmation/v3":
            finalize_existing_terminal(config)
            if watchdog:
                return {"schema": "lit.host_firewall.rollback-result/v3", "status": "already-confirmed"}
            raise TransactionError("the active transaction already has an authoritative confirmation outcome")
        finalize_existing_terminal(config)
        return terminal
    # Only an emergency watchdog rollback may ignore unrelated program, unit, verifier, or administrator-root
    # drift so that restoration cannot be disabled. An explicit signed rollback remains bound to every static asset.
    metadata = validate_metadata_and_assets(config, active, paths, validate_static=not watchdog)
    authorization: dict[str, Any] | None = None
    authorization_payload: bytes | None = None
    verification_payload: bytes | None = None
    if explicit_request is not None:
        authorization, authorization_payload, verification_payload = validate_explicit_rollback_request(
            explicit_request,
            config,
            metadata,
        )
        write_exclusive(paths["rollback_authorization"], authorization_payload)
        write_exclusive(paths["rollback_verification"], verification_payload)
        consume_claim(
            config,
            authorization,
            authorization_payload,
            verification_payload,
            active["transaction_id"],
        )

    validate_root_include(config)
    persistent_state = read_secure_bytes(paths["persistent_state"])
    if persistent_state != b"present\n":
        raise TransactionError("rollback requires a valid preprovisioned persistent include")
    persistent_backup = read_secure_bytes(paths["persistent_backup"])
    atomic_replace(config.persistent_include, persistent_backup, 0o600)
    require_command(
        run_command([config.nft_binary, "--check", "--file", str(config.persistent_root)]),
        label="restored administrator root nftables check",
    )
    restored_persistent = read_secure_bytes(config.persistent_include)
    if restored_persistent != persistent_backup:
        raise TransactionError("rollback did not restore the exact prior persistence include")
    runtime_backup = read_secure_bytes(paths["runtime_backup"])
    require_command(
        run_command([config.nft_binary, "--check", "--file", "-"], input_bytes=runtime_backup),
        label="runtime rollback check",
    )
    require_command(
        run_command([config.nft_binary, "--file", "-"], input_bytes=runtime_backup),
        label="runtime rollback apply",
    )
    restored = read_nft_policy_state(config)
    runtime_state = read_secure_bytes(paths["runtime_state"])
    expected_canonical = read_secure_bytes(paths["runtime_canonical"])
    if runtime_state == b"present\n":
        if not restored.present or restored.canonical != expected_canonical:
            raise TransactionError("rollback did not restore the exact prior role-owned table")
    elif runtime_state == b"absent\n":
        if restored.present or expected_canonical:
            raise TransactionError("rollback did not restore configured-table absence")
    else:
        raise TransactionError("runtime state marker is invalid during rollback")

    restored_runtime_state = runtime_state.decode("ascii").strip()
    restored_readback_sha256 = sha256_bytes(restored.canonical) if restored.present else ""
    rollback_record = {
        "schema": "lit.host_firewall.rollback/v3",
        "transaction_id": active["transaction_id"],
        "target": metadata["target"],
        "change_id": metadata["change_id"],
        "action": metadata["action"],
        "mode": metadata["mode"],
        "candidate_sha256": metadata["candidate_sha256"],
        "approved_readback_sha256": metadata["approved_readback_sha256"],
        "policy_fingerprint": metadata["policy_fingerprint"],
        "egress_policy_sha256": metadata["egress_policy_sha256"],
        "egress_status": metadata["egress_status"],
        "restored_runtime_state": restored_runtime_state,
        "restored_readback_sha256": restored_readback_sha256,
        "restored_persistent_state": "present",
        "restored_persistent_sha256": sha256_bytes(restored_persistent),
        "authorization_claim_id": authorization["claim_id"] if authorization is not None else None,
        "authorization_sha256": (
            sha256_bytes(authorization_payload) if authorization_payload is not None else None
        ),
        "authorization_verification_sha256": (
            sha256_bytes(verification_payload) if verification_payload is not None else None
        ),
        "rolled_back_at": format_utc(utc_now()),
        "source": "watchdog" if watchdog else "explicit",
    }
    write_terminal_disable_watchdog_and_clear_active(config, paths["terminal"], rollback_record)
    return rollback_record


def rollback_transaction(
    config: RuntimeConfig,
    *,
    explicit_request: dict[str, Any] | None,
    watchdog: bool,
) -> dict[str, Any]:
    action = "watchdog-rollback" if watchdog else "rollback"
    with transaction_scope(config, action=action):
        config.validate(emergency=watchdog)
        return rollback_locked(config, explicit_request=explicit_request, watchdog=watchdog)


def describe_active_transaction(config: RuntimeConfig) -> dict[str, Any]:
    """Read immutable rollback context without requiring a running application."""
    with transaction_scope(config, action="describe-active"):
        config.validate()
        loaded = load_active(config, required=True)
        assert loaded is not None
        active, _directory, paths = loaded
        metadata = validate_metadata_and_assets(config, active, paths)
        fields = ("target", "change_id", "mode", "candidate_sha256", "approved_readback_sha256",
                  "policy_fingerprint", "egress_policy_sha256", "egress_status")
        return {"schema": "lit.host_firewall.active-context/v1",
                **{key: metadata[key] for key in fields},
                "owned_tables": [list(identity) for identity in config.owned_tables()]}


def add_config_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--transactions-directory", required=True)
    parser.add_argument("--claims-directory", required=True)
    parser.add_argument("--active-path", required=True)
    parser.add_argument("--lock-path", required=True)
    parser.add_argument("--persistent-root", required=True)
    parser.add_argument("--persistent-include", required=True)
    parser.add_argument("--program-path", required=True)
    parser.add_argument("--systemd-unit-directory", required=True)
    parser.add_argument("--confirmation-service", required=True)
    parser.add_argument("--rollback-service", required=True)
    parser.add_argument("--rollback-timer", required=True)
    parser.add_argument("--persistence-service", required=True)
    parser.add_argument("--watchdog-timeout-seconds", required=True, type=int)
    parser.add_argument("--command-timeout-seconds", required=True, type=int)
    parser.add_argument("--lock-wait-timeout-seconds", required=True, type=int)
    parser.add_argument("--expected-target", required=True)
    parser.add_argument("--expected-egress-policy-sha256", required=True)
    parser.add_argument("--expected-egress-status", required=True)
    parser.add_argument("--table-family", required=True)
    parser.add_argument("--table-name", required=True)
    parser.add_argument("--bridge-table-name", default="")
    parser.add_argument("--nft-binary", required=True)
    parser.add_argument("--systemctl-binary", required=True)
    parser.add_argument("--verifier-binary", default="")


def config_from_args(args: argparse.Namespace) -> RuntimeConfig:
    return RuntimeConfig(
        state_directory=Path(args.state_directory),
        transactions_directory=Path(args.transactions_directory),
        claims_directory=Path(args.claims_directory),
        active_path=Path(args.active_path),
        lock_path=Path(args.lock_path),
        persistent_root=Path(args.persistent_root),
        persistent_include=Path(args.persistent_include),
        program_path=Path(args.program_path),
        systemd_unit_directory=Path(args.systemd_unit_directory),
        confirmation_service=args.confirmation_service,
        rollback_service=args.rollback_service,
        rollback_timer=args.rollback_timer,
        persistence_service=args.persistence_service,
        watchdog_timeout_seconds=args.watchdog_timeout_seconds,
        command_timeout_seconds=args.command_timeout_seconds,
        lock_wait_timeout_seconds=args.lock_wait_timeout_seconds,
        expected_target=args.expected_target,
        expected_egress_policy_sha256=args.expected_egress_policy_sha256,
        expected_egress_status=args.expected_egress_status,
        table_family=args.table_family,
        table_name=args.table_name,
        nft_binary=args.nft_binary,
        systemctl_binary=args.systemctl_binary,
        verifier_binary="" if args.verifier_binary == "-" else args.verifier_binary,
        bridge_table_name="" if args.bridge_table_name == "-" else args.bridge_table_name,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    add_config_arguments(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate-setup")
    subparsers.add_parser("validate-runtime")
    install_parser = subparsers.add_parser("install-runtime")
    install_parser.add_argument("--stdin-base64", action="store_true")
    subparsers.add_parser("apply")
    subparsers.add_parser("stage-confirm")
    subparsers.add_parser("confirm")
    rollback_parser = subparsers.add_parser("rollback")
    rollback_parser.add_argument("--watchdog", action="store_true")
    canonical_parser = subparsers.add_parser("canonicalize")
    canonical_parser.add_argument("--stdin-base64", action="store_true")
    subparsers.add_parser("readback")
    subparsers.add_parser("describe-active")
    normalization_parser = subparsers.add_parser("normalize-inputs")
    normalization_parser.add_argument("--stdin-base64", action="store_true")
    return parser


def read_optional_base64(flag: bool, *, label: str) -> bytes:
    raw = sys.stdin.buffer.read()
    if not flag:
        return raw
    try:
        return base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise TransactionError(f"invalid {label} base64 transport: {exc}") from exc


def main() -> int:
    args = build_parser().parse_args()
    config = config_from_args(args)
    try:
        if args.command == "validate-setup":
            config.validate(setup=True)
            result: Any = {"schema": "lit.host_firewall.setup-validation/v3", "valid": True}
        elif args.command == "validate-runtime":
            config.validate()
            result = {"schema": "lit.host_firewall.runtime-validation/v3", "valid": True}
        elif args.command == "canonicalize":
            raw = read_optional_base64(args.stdin_base64, label="nftables JSON")
            sys.stdout.buffer.write(canonicalize_nft_document(raw, config.table_family, config.table_name))
            return 0
        elif args.command == "readback":
            config.validate_shape()
            state = read_nft_policy_state(config)
            if not state.complete:
                raise TransactionError("readback requires every configured owned table")
            sys.stdout.buffer.write(state.canonical)
            return 0
        elif args.command == "normalize-inputs":
            raw = read_optional_base64(args.stdin_base64, label="normalization input")
            result = normalize_firewall_inputs(parse_json(raw, label="normalization input"))
        else:
            if os.geteuid() != 0:
                raise TransactionError("productive transaction commands require effective UID 0")
            if args.command == "install-runtime":
                raw = read_optional_base64(args.stdin_base64, label="runtime installation payload")
                payload = parse_json(raw, label="runtime installation payload")
                if not isinstance(payload, dict):
                    raise TransactionError("runtime installation payload must be a mapping")
                result = install_runtime(config, payload)
            elif args.command == "apply":
                result = apply_transaction(config, load_request_from_stdin())
            elif args.command == "stage-confirm":
                result = stage_confirmation(config, load_request_from_stdin())
            elif args.command == "confirm":
                result = confirm_transaction(config)
            elif args.command == "describe-active":
                result = describe_active_transaction(config)
            elif args.command == "rollback":
                request = None if args.watchdog else load_request_from_stdin()
                result = rollback_transaction(config, explicit_request=request, watchdog=args.watchdog)
            else:  # pragma: no cover - argparse makes this unreachable.
                raise TransactionError("unsupported transaction command")
        sys.stdout.buffer.write(canonical_json(result))
        return 0
    except (TransactionError, OSError) as exc:
        print(f"host firewall transaction rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
