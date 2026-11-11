"""Actual fork/fd0/Unix/config/timer component; no activation or native engine."""
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import test_github_runner_incus_runtime_rpc as fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import runtime_entry as entry, runtime_rpc
from incus_lease_issuer.identity import Denied


class GuardTests(unittest.TestCase):
    def test_no_argv_environment_or_policy_parameter(self):
        with self.assertRaises(TypeError):
            entry.serve_inherited("/job/config")
        with mock.patch.object(entry.sys, "argv", ["entry", "--config=/job"]), \
             mock.patch.object(entry, "serve_inherited", side_effect=AssertionError("no config override")):
            self.assertEqual(entry.main(), 1)
        with mock.patch.object(entry.os, "geteuid", return_value=2101), \
             mock.patch.object(entry, "_anchor", side_effect=AssertionError("no Root config read")):
            self.assertEqual(entry.serve_inherited(), 1)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.RootRuntimeTests.setUpClass()

    def setUp(self):
        self.fixture = fixtures.RootRuntimeTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.fixture.io.root
        self.anchor = self.root / "runtime-anchor.json"
        self.anchor.write_bytes(json.dumps({"schema": 1, "config_path": str(self.fixture.config),
                                            "config_sha256": self.fixture.sha}, sort_keys=True).encode())
        self.anchor.chmod(0o600)
        self.sequence = 0

    def exchange(self, *, kind="unix", anchor=None, failure=None):
        self.sequence += 1
        if kind == "unix":
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(self.root / ("entry-"+str(self.sequence))))
            listener.listen(1)
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(listener.getsockname())
            server, _ = listener.accept()
            listener.close()
        elif kind == "datagram":
            server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        elif kind == "unconnected":
            server, client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM), None
        else:
            raise AssertionError("unsupported fixture")
        original = os.fstat(0)
        child = os.fork()
        if child == 0:
            try:
                if client is not None:
                    client.close()
                os.dup2(server.fileno(), 0)
                server.close()
                with mock.patch.object(entry, "ANCHOR", str(self.anchor if anchor is None else anchor)):
                    if failure is not None:
                        with mock.patch.object(runtime_rpc.RuntimeRPC, "handle", side_effect=failure):
                            result = entry.serve_inherited()
                    else:
                        result = entry.serve_inherited()
                os._exit(result)
            except BaseException:
                os._exit(90)
        server.close()
        response = None
        try:
            if client is not None and kind == "unix":
                client.settimeout(5)
                client.sendall(fixtures.frame({"schema": 2, "cell": "approved", "operation": "status"}))
                response = fixtures.receive(client)
                if response["type"] == "challenge":
                    now = int(time.time())
                    native = self.fixture.fixture.native
                    native.claims.update(aud=response["audience"], jti="entry-"+str(self.sequence),
                                         iat=now, nbf=now, exp=now+400)
                    client.sendall(fixtures.frame({"schema": 2, "operation": "status", "nonce": response["nonce"],
                        "lease_id": self.fixture.lease, "token": native.token(), "api_token": "synthetic-job-token"}))
                    client.shutdown(socket.SHUT_WR)
                    response = fixtures.receive(client)
        finally:
            if client is not None:
                client.close()
            _, status = os.waitpid(child, 0)
        self.assertEqual((os.fstat(0).st_dev, os.fstat(0).st_ino), (original.st_dev, original.st_ino))
        return os.waitstatus_to_exitcode(status), response

    def test_actual_fd0_root_anchor_native_status_same_socket(self):
        before = self.fixture.store.read(self.fixture.lease)
        code, response = self.exchange()
        self.assertEqual(code, 0)
        self.assertEqual(response["type"], "result")
        self.assertEqual(response["operation"], "status")
        self.assertEqual(self.fixture.store.read(self.fixture.lease), before)

    def test_anchor_sha_mode_and_unknown_fields_deny_without_policy_override(self):
        self.anchor.write_bytes(json.dumps({"schema": 1, "config_path": str(self.fixture.config),
                                            "config_sha256": "0"*64}).encode())
        self.anchor.chmod(0o600)
        code, response = self.exchange()
        self.assertEqual(code, 1)
        self.assertEqual(response["type"], "failure")
        self.assertNotIn(str(self.anchor), json.dumps(response))
        self.anchor.chmod(0o666)
        self.assertEqual(self.exchange()[0], 1)

    def test_datagram_and_unconnected_fd0_deny(self):
        self.assertEqual(self.exchange(kind="datagram")[0], 1)
        self.assertEqual(self.exchange(kind="unconnected")[0], 1)

    def test_fresh_run_executes_real_locked_preparation_then_denies_native_engine_gate(self):
        # A separate actual Root Ledger/Unix endpoint is a NEW fixture cell;
        # no resources or registration from the prepared status fixture adopted.
        import test_github_runner_incus_mutation as mutation_fixtures
        from incus_lease_issuer import ledger, network_fence, engine_executor, root_session
        io = self.fixture.fixture.io
        old_selected = self.fixture.fixture.registry.select("approved")
        fresh_path = self.root / "fresh-runtime-store"
        fresh_path.mkdir(mode=0o700)
        ledger.Ledger.initialize(fresh_path)
        with ledger.Ledger(fresh_path) as fresh:
            self.assertEqual(fresh.archive_policy(self.fixture.store.read_policy(old_selected.custody_policy_sha256)),
                             old_selected.custody_policy_sha256)
        registry_path = Path(self.fixture.value["registry_path"])
        data = json.loads(registry_path.read_bytes())
        data["ledger_path"] = str(fresh_path)
        registry_path.write_bytes(json.dumps(data, sort_keys=True).encode())
        registry_path.chmod(0o600)
        registry_sha = hashlib.sha256(registry_path.read_bytes()).hexdigest()
        native = mutation_fixtures.MutationFixture(self.root / "fresh-incus.socket")
        self.addCleanup(native.close)
        io.value.update(registry_sha256=registry_sha, incus_socket_path=str(native.path))
        io.seal()
        self.fixture.value.update(registry_sha256=registry_sha, preparation_config_sha256=io.sha)
        self.fixture.seal()
        self.anchor.write_bytes(json.dumps({"schema": 1, "config_path": str(self.fixture.config),
                                            "config_sha256": self.fixture.sha}).encode())
        self.anchor.chmod(0o600)
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        # Only kernel/network acquisition is modeled. Native engine prerequisites
        # intentionally remain REAL: absent runtime/subids/idmap means DENY.
        fence_fixture = self.fixture.fixture.fence
        child = os.fork()
        if child == 0:
            try:
                client.close()
                os.dup2(server.fileno(), 0)
                server.close()
                def owned(policy, prepared, store, **kwargs):
                    auth = store.read(prepared.lease_id)["authorizations"][-1]
                    return ({}, 1000, 4, min(auth["valid_until"], prepared.expires_at))
                original_start = engine_executor._start_locked
                def actual_start(session, registry, selector, store, lease_id, receipt):
                    root_session._require_session(session)
                    assert entry._ACTIVE is not None  # Real timer covers start gate.
                    # This persisted observation is not an engine effect/proof;
                    # it confirms actual production entry reached the native gate.
                    marker = self.root / "start-gate-observed"
                    marker.write_bytes(lease_id.encode())
                    marker.chmod(0o600)
                    return original_start(session, registry, selector, store, lease_id, receipt)
                with mock.patch.object(entry, "ANCHOR", str(self.anchor)), fence_fixture.kernel_fixture(), \
                     mock.patch.object(network_fence, "_owned", side_effect=owned), \
                     mock.patch.object(engine_executor, "_start_locked", side_effect=actual_start):
                    os._exit(entry.serve_inherited())
            except BaseException:
                os._exit(90)
        server.close()
        client.settimeout(8)
        try:
            client.sendall(fixtures.frame({"schema": 2, "cell": "approved", "operation": "run"}))
            challenge = fixtures.receive(client)
            now = int(time.time())
            claims = self.fixture.fixture.native
            claims.claims.update(aud=challenge["audience"], jti="entry-fresh-run", iat=now, nbf=now, exp=now+400)
            client.sendall(fixtures.frame({"schema": 2, "operation": "run", "nonce": challenge["nonce"],
                                          "token": claims.token(), "api_token": "synthetic-job-token"}))
            client.shutdown(socket.SHUT_WR)
            accepted = fixtures.receive(client)
            final = fixtures.receive(client)
        finally:
            client.close()
            code = os.waitstatus_to_exitcode(os.waitpid(child, 0)[1])
        self.assertEqual(code, 1)
        self.assertEqual(accepted["type"], "accepted")
        self.assertEqual(accepted["sequence"], 0)
        self.assertEqual(final["type"], "failure")
        self.assertEqual(final["disposition"], "unknown-hold")
        lease_id = accepted["lease_id"]
        self.assertEqual((self.root / "start-gate-observed").read_text(), lease_id)
        with ledger.Ledger(fresh_path) as fresh:
            record = fresh.read(lease_id)
        operations = {effect["operation"] for effect in record["effects"].values()}
        self.assertTrue({"network-create", "project-create", "profile-configure", "context-create",
                         "certificate-create", "engine-prepare", "context-publish", "fence-create", "fence-renew"} <= operations)
        self.assertNotIn("engine-start", operations)
        self.assertFalse(any("engine_exit" in effect for effect in record["effects"].values()))
        writes = [request[0] for request in native.requests if request[0] != "GET"]
        self.assertTrue(writes)  # Real Root Unix transport and preparation executed.

    def test_after_handoff_error_gets_no_second_frame_or_secret_echo(self):
        # A failure after handoff gets no entry fallback (RuntimeRPC owns all
        # frame attempts). Do not try a selector exchange with no receiver.
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        child = os.fork()
        if child == 0:
            client.close()
            os.dup2(server.fileno(), 0)
            server.close()
            with mock.patch.object(entry, "ANCHOR", str(self.anchor)), \
                 mock.patch.object(runtime_rpc.RuntimeRPC, "handle", side_effect=OSError("SECRET_DO_NOT_ECHO")):
                os._exit(entry.serve_inherited())
        server.close()
        client.settimeout(5)
        self.assertEqual(client.recv(8192), b"")
        client.close()
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]), 1)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootTimerTests(unittest.TestCase):
    def fork_case(self, operation):
        child = os.fork()
        if child == 0:
            try:
                operation()
                os._exit(0)
            except BaseException:
                os._exit(91)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]), 0)

    def test_real_timer_interrupts_blocking_read_and_restores_default(self):
        def case():
            read, write = os.pipe()
            try:
                started = time.monotonic()
                try:
                    with entry._initial_effects_deadline(1, int(time.time())+10):
                        os.read(read, 1)  # No write and no manual signal.
                    raise AssertionError("deadline not enforced")
                except entry._InitialDeadline:
                    pass
                assert 0.5 < time.monotonic()-started < 3
                assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
                assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL
            finally:
                os.close(read)
                os.close(write)
        self.fork_case(case)

    def test_adoption_defers_exception_and_does_not_change_actual_child_sigmask(self):
        def case():
            proc = None
            try:
                try:
                    with entry._initial_effects_deadline(5, int(time.time())+10):
                        with entry._spawn_adoption():
                            proc = subprocess.Popen([sys.executable, "-I", "-B", "-c",
                                "import signal; print(int(signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK, [])))"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            os.kill(os.getpid(), signal.SIGALRM)
                            assert proc is not None  # Original actual Popen adopted before raise.
                            proc.pid  # No second Popen/effect is issued.
                    raise AssertionError("pending deadline not raised")
                except entry._InitialDeadline:
                    pass
                stdout, stderr = proc.communicate(timeout=3)
                assert proc.returncode == 0 and stdout == b"0\n" and stderr == b""
            finally:
                if proc is not None and proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=2)
        self.fork_case(case)

    def test_unowned_timer_is_never_overwritten_and_finished_scope_disarms(self):
        def case():
            def previous(_sig, _frame):
                pass
            signal.signal(signal.SIGALRM, previous)
            signal.setitimer(signal.ITIMER_REAL, 30)
            try:
                try:
                    with entry._initial_effects_deadline(1, int(time.time())+10):
                        raise AssertionError("unowned timer accepted")
                except Denied:
                    pass
                assert signal.getsignal(signal.SIGALRM) is previous
                assert signal.getitimer(signal.ITIMER_REAL)[0] > 25
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, signal.SIG_DFL)
            with entry._initial_effects_deadline(1, int(time.time())+10):
                pass
            assert entry._ACTIVE is None and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
        self.fork_case(case)


if __name__ == "__main__":
    unittest.main()
