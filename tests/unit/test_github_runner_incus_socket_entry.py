"""Isolated fd0 entry fixtures; no activation or genuine Worker provenance."""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest import mock

import test_github_runner_incus_admission as admission_fixtures
import test_github_runner_incus_registry_rpc as rpc_fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import policy_registry, registry_rpc, socket_entry  # noqa: E402


def open_descriptors():
    # Enumerating /proc/self/fd itself temporarily opens a descriptor (possibly
    # fd0 after entry closes it); fstat makes this leak comparison observational.
    result = set()
    for number in range(1024):
        try:
            os.fstat(number)
        except OSError:
            continue
        result.add(number)
    return result


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated UID0 Linux EE only")
class RootSocketEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        admission_fixtures.RootAdmissionBridgeTests.setUpClass()

    def setUp(self):
        self.fixture = admission_fixtures.RootAdmissionBridgeTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        # Build a real Root-loaded registry around the signed identity fixture.
        # Only native HTTPS/collector acquisition is mocked by that fixture.
        collected = asdict(self.fixture.policy.collector)
        collected["service"]["dropins"] = []
        for path_key, hash_key in (("profile_path", "profile_sha256"), ("config_path", "config_sha256")):
            path = self.root / path_key
            path.write_bytes(b"synthetic Root control bytes, not kernel policy proof")
            path.chmod(0o600)
            collected[path_key] = str(path)
            collected[hash_key] = hashlib.sha256(path.read_bytes()).hexdigest()
        native = asdict(self.fixture.identity_policy)
        native.pop("required_native_job_name")
        native["actor_ids"] = sorted(native["actor_ids"])
        self.registry = self.root / "registry.json"
        registry = {"schema": 1, "collector": collected, "identity": native,
                    "ledger_path": str(self.fixture.store_path), "api_read_token_path": None,
                    "cells": {"approved": {"native_job_name": self.fixture.identity_policy.required_native_job_name,
                       "cell_config_path": str(self.fixture.cell), "cell_sha256": self.fixture.cell_sha,
                       "custody_policy_sha256": self.fixture.custody, "deadline": self.fixture.policy.deadline}}}
        self.registry_sha = self.write(self.registry, registry)
        self.config = self.root / "entry.json"
        self.value = {"schema": 1, "registry_path": str(self.registry), "registry_sha256": self.registry_sha}
        self.config_sha = self.write(self.config, self.value)
        self.sequence = 0

    @staticmethod
    def write(path, value):
        path.write_bytes(json.dumps(value, sort_keys=True).encode())
        path.chmod(0o600)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def exchange(self, body=None, *, raw=None, config=None, digest=None, kind="accepted", uid=None, hook=None):
        """Only a forked child ever dup2s/closes fd0; parent terminal unchanged."""
        self.sequence += 1
        listener = client = None
        if kind == "accepted":
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(self.root / ("socket-" + str(self.sequence))))
            listener.listen(1)
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(listener.getsockname())
            server, _ = listener.accept()
        elif kind == "datagram":
            server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        elif kind == "unconnected":
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        elif kind == "tcp":
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            client = socket.create_connection(listener.getsockname())
            server, _ = listener.accept()
        else:
            server = None
        original_stdin = os.fstat(0)
        peer = None if kind != "accepted" else server.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        if kind == "accepted":
            payload = raw if raw is not None else (rpc_fixtures.frame({"schema": 1, "cell": "approved"})
                                                   + rpc_fixtures.frame(body))
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
        read_fd, write_fd = os.pipe()
        with tempfile.TemporaryFile() as output:
            pid = os.fork()
            if pid == 0:
                try:
                    os.close(read_fd)
                    if listener is not None:
                        listener.close()
                    if client is not None:
                        client.close()
                    if server is None:
                        with open("/dev/null", "rb") as source:
                            os.dup2(source.fileno(), 0)
                    else:
                        os.dup2(server.fileno(), 0)
                        server.close()
                    os.dup2(output.fileno(), 1)
                    os.dup2(output.fileno(), 2)
                    if uid is not None:
                        os.setgid(uid)
                        os.setuid(uid)
                    before = open_descriptors()
                    if hook is not None:
                        hook(peer)
                    code = socket_entry.serve_inherited(str(self.config) if config is None else config,
                                                       self.config_sha if digest is None else digest)
                    after = open_descriptors()
                    report = {"code": code, "closed": after == before - {0}}
                    os.write(write_fd, json.dumps(report).encode())
                    os._exit(0)
                except BaseException:
                    os._exit(90)
            os.close(write_fd)
            if server is not None:
                server.close()
            if listener is not None:
                listener.close()
            received = bytearray()
            if client is not None and kind in {"accepted", "tcp"}:
                client.settimeout(7)
                while True:
                    try:
                        part = client.recv(4096)
                    except ConnectionResetError:
                        break
                    if not part:
                        break
                    received.extend(part)
            if client is not None:
                client.close()
            report = os.read(read_fd, 4096)
            os.close(read_fd)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(status, 0, "isolated entry child failed")
            output.seek(0)
            self.assertEqual(output.read(), b"", "entry must not print exception/token/path data")
        self.assertEqual(os.fstat(0), original_stdin)
        result = json.loads(report)
        self.assertTrue(result["closed"], "entry leaked an acquired/inherited descriptor")
        return result["code"], bytes(received)

    def result(self, body=None, **kwargs):
        code, raw = self.exchange(body, **kwargs)
        self.assertGreaterEqual(len(raw), 4)
        count = struct.unpack("!I", raw[:4])[0]
        self.assertEqual(len(raw), count + 4, "exactly one complete bounded reply")
        self.assertLessEqual(count, registry_rpc.MAX_REPLY_BYTES)
        return code, json.loads(raw[4:])

    def deny(self, **kwargs):
        self.assertEqual(self.result({"schema": 1, "operation": "challenge"}, **kwargs),
                         (1, {"schema": 1, "status": "denied"}))

    def test_real_registry_rpc_signed_identity_and_durable_ledger(self):
        code, challenge = self.result({"schema": 1, "operation": "challenge"})
        self.assertEqual((code, challenge["status"]), (0, "ok"))
        code, admitted = self.result(self.fixture.admit_body(challenge["result"]))
        self.assertEqual((code, admitted["status"]), (0, "ok"))
        record = self.fixture.record(admitted["result"]["lease_id"])
        self.assertEqual((record["identity"]["job_id"], record["identity"]["check_run_id"]), (902, 731))
        self.assertEqual(record["cell_sha256"], self.fixture.cell_sha)

    def test_duplicate_preserves_actual_accepted_peer_and_same_rpc_socket(self):
        def hook(peer):
            def handle(instance, connected):
                self.assertEqual(connected.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12), peer)
                self.assertNotEqual(connected.fileno(), 0)
                return registry_rpc.RegistryRPC._original_handle(instance, connected)
            registry_rpc.RegistryRPC._original_handle = registry_rpc.RegistryRPC.handle
            registry_rpc.RegistryRPC.handle = handle
        code, result = self.result({"schema": 1, "operation": "challenge"}, hook=hook)
        self.assertEqual((code, result["status"]), (0, "ok"))

    def test_hash_mode_owner_and_symlink_fail_before_rpc(self):
        self.deny(digest="f" * 64)
        self.config.chmod(0o644)
        self.deny()
        self.config.chmod(0o600)
        os.chown(self.config, 2101, 2101)
        self.deny()
        os.chown(self.config, 0, 0)
        link = self.root / "entry-link"
        link.symlink_to(self.config)
        self.deny(config=str(link))

    def test_closed_schema_types_paths_duplicate_keys_and_bounded_bytes(self):
        for value in ({**self.value, "schema": True}, {**self.value, "schema": 2},
                      {**self.value, "extra": "synthetic-secret"},
                      {**self.value, "registry_path": "relative"}, {**self.value, "registry_sha256": None},
                      {"schema": 1}, [self.value]):
            with self.subTest(type=type(value).__name__):
                digest = self.write(self.config, value)
                self.deny(digest=digest)
        for raw in (b'{"schema":1,"schema":1}', b'{"schema":NaN}', b"x" * 16385):
            self.config.write_bytes(raw)
            self.deny(digest=hashlib.sha256(raw).hexdigest())

    def test_registry_missing_or_drift_denies_without_initializing_ledger(self):
        self.registry.write_bytes(b"synthetic secret corruption")
        self.deny()
        self.registry.unlink()
        self.deny()

    def test_nonroot_denies_without_policy_read(self):
        self.deny(uid=65534)

    def test_non_stream_unconnected_tcp_and_regular_fd_are_rejected(self):
        for kind in ("datagram", "unconnected", "tcp", "regular"):
            with self.subTest(kind=kind):
                self.assertEqual(self.exchange(kind=kind), (1, b""))

    def test_config_acquisition_error_redacted_one_denial(self):
        def hook(peer):
            policy_registry.load_registry = mock.Mock(side_effect=RuntimeError("SYNTHETIC_SECRET /private/path"))
        self.deny(hook=hook)

    def test_changed_config_during_registry_load_denies_before_rpc(self):
        def hook(peer):
            original = policy_registry.load_registry
            def changed(*args):
                loaded = original(*args)
                self.config.write_bytes(b"changed")
                return loaded
            policy_registry.load_registry = changed
        self.deny(hook=hook)

    def test_malformed_selector_denial_is_nonzero(self):
        self.deny(raw=rpc_fixtures.frame({"schema": 1, "cell": "../private"}))

    def test_rpc_partial_reply_failure_has_no_entry_fallback(self):
        def hook(peer):
            def partial(connected, outcome):
                connected.sendall(b"partial")
                raise RuntimeError("SYNTHETIC_SECRET")
            registry_rpc._write = partial
        code, raw = self.exchange({"schema": 1, "operation": "challenge"}, hook=hook)
        self.assertEqual((code, raw), (1, b"partial"))

    def test_pre_rpc_denial_write_failure_is_one_attempt(self):
        def hook(peer):
            calls = []
            def partial(connected, outcome):
                calls.append(1)
                connected.sendall(b"one" if len(calls) == 1 else b"SECOND")
                raise RuntimeError("SYNTHETIC_SECRET")
            registry_rpc._write = partial
        self.assertEqual(self.exchange(digest="f" * 64, hook=hook), (1, b"one"))


class SocketEntryAPITests(unittest.TestCase):
    def test_no_caller_fd_reader_or_config_json_api(self):
        with self.assertRaises(TypeError):
            socket_entry.serve_inherited("/fixed/root/config", "a" * 64, fd=7)
        with self.assertRaises(TypeError):
            socket_entry.serve_inherited("/fixed/root/config", "a" * 64, reader=object())

    def test_missing_fd_returns_denial_without_printing_or_production_root_bypass(self):
        with mock.patch.object(socket_entry.os, "dup", side_effect=OSError("SYNTHETIC_SECRET")), \
             mock.patch.object(socket_entry.os, "close"), \
             mock.patch.object(policy_registry, "load_registry", side_effect=AssertionError("no config acquisition")):
            self.assertEqual(socket_entry.serve_inherited("/fixed/root/config", "a" * 64), 1)
