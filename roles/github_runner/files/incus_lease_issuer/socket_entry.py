"""One Root-selected registry RPC on systemd's connected stdin socket.

Trusted Root code supplies both arguments. There is no CLI, environment fallback,
listener or service activation. This entry consumes fd0 and closes its duplicate
on every path. It never reconstructs policy/Worker authority from the wire.
Registry/custody bytes do not establish operating acceptance or a genuine Worker.
"""
from __future__ import annotations

import os
import socket
import struct

from . import admission, identity, installation, policy_registry, registry_rpc
from .identity import require

MAX_CONFIG_BYTES = 16384
DENIED = {"schema": 1, "status": "denied"}


def _connected_stdin():
    duplicate = None
    connected = None
    try:
        duplicate = os.dup(0)
        os.set_inheritable(duplicate, False)
        connected = socket.socket(fileno=duplicate)
        duplicate = None  # socket owns the descriptor from here.
        admission._socket(connected)
        require(len(connected.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                        struct.calcsize("3i"))) == struct.calcsize("3i"),
                "socket-entry-peer")
        result, connected = connected, None
        return result
    finally:
        if connected is not None:
            connected.close()
        if duplicate is not None:
            os.close(duplicate)
        # Accept=yes gives this process sole ownership of this inherited fd.
        # Tests call the entry only in an isolated child, never on parent stdin.
        try:
            os.close(0)
        except OSError:
            pass


def _config(path, expected):
    policy_registry._path(path)
    policy_registry._hash(expected)
    proof, raw, stamp = installation._file(path, MAX_CONFIG_BYTES, private=True, keep=True)
    require(proof.sha256 == expected, "socket-entry-config-bytes")
    value = identity.decode_json(raw)
    require(set(value) == {"schema", "registry_path", "registry_sha256"}
            and type(value["schema"]) is int and value["schema"] == 1, "socket-entry-config-schema")
    policy_registry._path(value["registry_path"])
    policy_registry._hash(value["registry_sha256"])
    return value, proof, stamp


def serve_inherited(root_config_path, expected_config_sha256):
    """Consume connected fd0; return 0 only for a fully delivered successful RPC.

    Before RPC handoff, acquisition/config failure has one constant denial reply
    attempt if a valid socket exists. After handoff, RegistryRPC owns the only
    reply attempt; even a partial/failed delivery never triggers another frame.
    No exception data, tokens, policy paths or tracebacks are printed.
    """
    connected, handed_off = None, False
    try:
        connected = _connected_stdin()
        require(os.geteuid() == 0, "socket-entry-root-required")
        value, proof, stamp = _config(root_config_path, expected_config_sha256)
        registry = policy_registry.load_registry(value["registry_path"], value["registry_sha256"])
        again, after, after_stamp = _config(root_config_path, expected_config_sha256)
        require(again == value and after == proof and after_stamp == stamp, "socket-entry-config-changed")
        rpc = registry_rpc.RegistryRPC(registry)
        handed_off = True
        outcome = rpc.handle(connected)
        return 0 if outcome.get("status") == "ok" else 1
    except Exception:
        if connected is not None and not handed_off:
            try:
                registry_rpc._write(connected, DENIED)
            except Exception:
                pass
        return 1
    finally:
        if connected is not None:
            connected.close()
