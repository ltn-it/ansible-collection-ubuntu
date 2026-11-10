"""One Root-selected cell RPC on an already connected Unix stream.

No listener is bound, service activated, ledger initialized or TLS/engine effect
issued here. Root supplies an already loaded Registry. The first frame is only
a locator; AdmissionBridge independently authenticates the second frame on the
SAME socket, preserving real SO_PEERCRED. No caller PID/policy/key/path/reader
or provided Worker is accepted. Fixture coupling is not service provenance or
custodian acceptance. Failed replies never replay admission effects.
"""
from __future__ import annotations

import json
import os
import select
import socket
import struct
import time
from types import MappingProxyType

from . import admission, identity, ledger, policy_registry
from .identity import Denied, require

MAX_SELECTOR_BYTES = 512
MAX_REPLY_BYTES = 2048
FRAME_SECONDS = 5


def _root():
    require(os.geteuid() == 0, "registry-rpc-root-required")


def _selector(connected):
    admission._socket(connected)
    deadline = time.monotonic() + FRAME_SECONDS
    length = struct.unpack("!I", admission._read_exact(connected, 4, deadline))[0]
    require(0 < length <= MAX_SELECTOR_BYTES, "registry-rpc-frame-size")
    value = identity.decode_json(admission._read_exact(connected, length, deadline))
    require(set(value) == {"schema", "cell"} and type(value["schema"]) is int and value["schema"] == 1
            and type(value["cell"]) is str and policy_registry.SELECTOR.fullmatch(value["cell"]),
            "registry-rpc-selector")
    # No trailing peek: the existing strict AdmissionBridge frame comes next.
    return value["cell"]


def _safe_result(result):
    require(type(result) is dict and type(result.get("schema")) is int and result["schema"] == 1,
            "registry-rpc-result")
    operation = result.get("operation")
    require(type(operation) is str and operation in {"challenge", "admit", "refresh", "recover"}, "registry-rpc-result")
    require(type(result.get("expires_at")) is int and result["expires_at"] > 0, "registry-rpc-result")
    if operation == "challenge":
        require(set(result) == {"schema", "operation", "nonce", "audience", "expires_at"}
                and type(result["nonce"]) is str and ledger.HEX.fullmatch(result["nonce"])
                and result["audience"] == ledger.AUDIENCE + result["nonce"], "registry-rpc-result")
    else:
        require(set(result) == {"schema", "operation", "lease_id", "expires_at"}
                and type(result["lease_id"]) is str and ledger.ID.fullmatch(result["lease_id"]),
                "registry-rpc-result")
    return dict(result)


def _write(connected, outcome):
    admission._socket(connected)
    raw = json.dumps(outcome, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    require(0 < len(raw) <= MAX_REPLY_BYTES, "registry-rpc-reply-size")
    frame, offset, deadline = struct.pack("!I", len(raw)) + raw, 0, time.monotonic() + FRAME_SECONDS
    flags = socket.MSG_DONTWAIT | getattr(socket, "MSG_NOSIGNAL", 0)
    try:
        while offset < len(frame):
            remaining = deadline - time.monotonic()
            require(remaining > 0 and select.select([], [connected], [], remaining)[1], "registry-rpc-write-denied")
            try:
                sent = connected.send(frame[offset:], flags)
            except BlockingIOError:
                continue
            require(sent > 0, "registry-rpc-write-denied")
            offset += sent
    except (OSError, ValueError):
        raise Denied("registry-rpc-write-denied") from None


class RegistryRPC:
    """Trusted Root factory only; no per-request configuration hooks."""

    def __init__(self, registry):
        _root()
        require(type(registry) is policy_registry.Registry
                and type(registry.policies) is MappingProxyType
                and 0 < len(registry.policies) <= policy_registry.MAX_CELLS
                and all(type(policy) is admission.AdmissionPolicy for policy in registry.policies.values()),
                "registry-rpc-root-registry")
        self._registry = registry

    def handle(self, connected_unix_socket):
        _root()
        try:
            selected = self._registry.select(_selector(connected_unix_socket))
            result = admission.AdmissionBridge(selected).handle(connected_unix_socket)
            outcome = {"schema": 1, "status": "ok", "result": _safe_result(result)}
        except Exception:
            # Never echo tokens, policy paths, provider bodies or exception data.
            outcome = {"schema": 1, "status": "denied"}
        # Exactly one response attempt, outside the operation exception handler.
        # Partial/failed delivery must not trigger a second reply or effect retry.
        _write(connected_unix_socket, outcome)
        return outcome
