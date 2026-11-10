"""Fixed synthetic Root ELF supervision; NEVER native Podman qualification.

Only metadata acquisition absent from this EE is modeled. Real subprocesses,
kernel PID/start/boot/executable, private CID files, fsync, Ledger and locks are
used. Public start keeps all actual native acquisition gates; no synthetic grant.
"""
from dataclasses import replace
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import MappingProxyType
import unittest
from unittest import mock

import test_github_runner_incus_preparation as fixtures
import test_github_runner_incus_cell_contract as cell_fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import engine_executor as executor, engine_policy as engine, identity, ledger  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class ExecutorGuardTests(unittest.TestCase):
    def test_root_and_no_command_reader_or_proof_override(self):
        for operation in (executor.start, executor.status, executor.cancel):
            with mock.patch.object(executor.os, "geteuid", return_value=2101):
                with self.assertRaisesRegex(Denied, "engine-executor-root-required"):
                    operation(None, None, None, None, None, None, None)
            with self.assertRaises(TypeError):
                operation(None, None, None, None, None, None, None, qualified=True)

    def test_live_idmap_rejects_untyped_receipts_or_qualified_flags(self):
        with self.assertRaisesRegex(Denied, "engine-probe-root-input"):
            executor._idmapped_preflight(None, None)
        with self.assertRaises(TypeError):
            executor._idmapped_preflight(None, None, qualified=True)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.RootPreparationTests.setUpClass()

    def setUp(self):
        self.fixture = fixtures.RootPreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.receipt = self.fixture.run_prepare()
        self.store, self.lease = self.fixture.store, self.fixture.lease
        self.prepared = self.fixture.prepared
        # Explicit synthetic fence metadata ONLY for private supervisor tests.
        # Public start still acquires the real fence and live-idmap proof.
        effect = self.store.begin(self.lease, "fence-create", "fence:" + self.lease)
        self.store.bind_fence(self.lease, effect, policy_sha256="d" * 64, boot_id=executor.kernel.read_boot_id(),
                              netns_device=4, netns_inode=4026533001, host_ifindex=301, peer_ifindex=2, nft_table_handle=1)
        self.store.record(self.lease, effect, "verified", evidence_sha256="d" * 64)
        auth = self.store.read(self.lease)["authorizations"][-1]
        effect = self.store.begin(self.lease, "fence-renew", "fence:" + self.lease + ":" + auth["token_id_sha256"])
        expiry = min(auth["valid_until"], self.prepared.expires_at)
        self.store.bind_fence_authorization(self.lease, effect, authorization_sha256=ledger.digest(auth),
            allow_expires_at=expiry, issued_boot_ns=1000000000,
            expires_boot_ns=1000000000 + (expiry - int(executor.time.time())) * 1000000000)
        self.store.record(self.lease, effect, "verified", evidence_sha256="d" * 64)
        self.real_manifest = engine.compile_engine_policy(self.prepared.engine_descriptor_path,
                                                         self.prepared.engine_descriptor_sha256)
        self.original = engine.ENGINE
        executable_base = Path("/run/executable-proof")
        if not executable_base.is_dir() or executable_base.stat().st_uid != 0:
            self.skipTest("requires separate private Root exec tmpfs /run/executable-proof")
        directory = tempfile.TemporaryDirectory(prefix="engine-supervisor-", dir=executable_base)
        self.addCleanup(directory.cleanup)
        self.binary = Path(directory.name) / "fixed-synthetic-engine"
        # UBI sleep execs coreutils and coreutils changes startup process state.
        # Copy the actual running Python ELF with a fixed isolated sleep body.
        shutil.copyfile(Path(sys.executable).resolve(), self.binary)
        self.binary.chmod(0o700)
        self.assertEqual(self.binary.read_bytes()[:4], b"\x7fELF")
        support = subprocess.run([str(self.binary), "-I", "-B", "-c", "pass"], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
        self.assertEqual(support.returncode, 0, "actual proper-EE isolated copied Python ELF support")
        # The Root kernel observes this real copied ELF. This is NOT a Podman
        # binary and the test never asserts native engine/runtime compatibility.
        patch = mock.patch.object(engine, "ENGINE", str(self.binary))
        patch.start()
        self.addCleanup(patch.stop)
        ledger_executable = mock.patch.object(ledger, "ENGINE_EXECUTABLE", str(self.binary))
        ledger_executable.start()
        self.addCleanup(ledger_executable.stop)
        details = identity.decode_json(self.real_manifest.canonical_bytes)
        details["argv"] = [str(self.binary), "-I", "-B", "-c", "import time; time.sleep(30)"]
        details["argv"] += ["fixed-fixture-" + str(index) for index in range(40)]
        details["engine"]["executable"] = str(self.binary)
        details["engine_executable_sha256"] = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        raw = engine._canonical(details)
        self.manifest = engine.EngineManifest(self.real_manifest.descriptor_path, self.real_manifest.descriptor_sha256,
            engine.IMAGE_INDEX, engine.IMAGE_CHILD, tuple(details["argv"]), MappingProxyType({}), hashlib.sha256(raw).hexdigest(), raw)
        self.details = details
        self.cid = "c" * 64
        # Cgroup filesystem is not delegated in the private EE. Only this
        # acquisition is modeled; real ELF/process/log ownership stays actual.
        info = self.fixture.root.stat()
        cgroup = mock.patch.object(executor, "_cgroup", return_value=(info.st_dev, info.st_ino))
        cgroup.start()
        self.addCleanup(cgroup.stop)
        self.addCleanup(self.stop_fixture_process)

    def stop_fixture_process(self):
        for pid, (proc, capture) in list(executor._UNTRACKED_PROCESSES.items()):
            if tuple(proc.args) == self.manifest.argv:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=2)
                proc.stdout.close()
                proc.stderr.close()
                capture.close()
                del executor._UNTRACKED_PROCESSES[pid]
        # Fixture cleanup alone may close an untracked failed-start owner after
        # actually waiting its original child; it never manufactures a receipt.
        for pid, owned in list(executor._PROCESSES.items()):
            if tuple(owned.proc.args) != self.manifest.argv:
                continue
            if owned.proc.poll() is None:
                owned.proc.kill()
            end = time.monotonic() + 2
            while (owned.returncode is None or not owned.eof) and time.monotonic() < end:
                owned.pump(0.01)
            try:
                if owned.process is not None and owned.container_id is not None:
                    try:
                        owned.record_exit()
                        owned.release()
                    except Denied:
                        pass
            finally:
                if not owned.closed:
                    # Only this fixture's actually exited original child. This
                    # is not a production reconciliation/receipt or retry.
                    for name in ("stdout", "stderr"):
                        getattr(owned.proc, name).close()
                    owned.selector.close()
                    owned.capture.close()
                    if owned.pidfd is not None:
                        os.close(owned.pidfd)
            del executor._PROCESSES[pid]

    def traced_spawn(self):
        self.private_spawn_causes = []
        previous = sys.gettrace()
        def trace(frame, event, value):
            if (event == "exception" and frame.f_code.co_filename == executor.__file__
                    and frame.f_code.co_name in {"_spawn", "_process"}):
                kind, error, _ = value
                reason = str(error) if isinstance(error, Denied) else None
                self.private_spawn_causes.append({"type": kind.__name__, "reason": reason,
                                                  "errno": getattr(error, "errno", None), "line": frame.f_lineno})
                if frame.f_code.co_name == "_process" and "observed" in frame.f_locals:
                    observed = frame.f_locals["observed"]
                    self.private_spawn_causes[-1].update({"actual_uids": observed.uids,
                        "actual_executable": observed.executable, "expected_executable": engine.ENGINE})
            if event == "exception" and frame.f_code.co_filename == executor.kernel.__file__:
                kind, error, _ = value
                self.private_spawn_causes.append({"kernel_function": frame.f_code.co_name,
                    "type": kind.__name__, "reason": str(error) if isinstance(error, Denied) else None,
                    "errno": getattr(error, "errno", None), "line": frame.f_lineno})
                if frame.f_code.co_name == "parse_cmdline" and "argv" in frame.f_locals:
                    # Only this fixture's own fixed supervisor (no API token,
                    # credential or job-controlled argument is involved).
                    self.private_spawn_causes[-1]["fixture_argv"] = frame.f_locals["argv"]
            return trace
        sys.settrace(trace)
        try:
            return executor._spawn(self.prepared, self.manifest, self.store)
        finally:
            sys.settrace(previous)

    def engine_effect(self):
        rows = [(key, value) for key, value in self.store.read(self.lease)["effects"].items()
                if value["operation"] == "engine-start"]
        self.assertEqual(len(rows), 1)
        return rows[0]

    def command(self, manifest, args, seconds=5):
        # Only unsupported native Podman READ/stop transport is modeled, never
        # PID acquisition or filesystem ownership guards. Stop records an exact
        # CID request; the synthetic ELF has no container and is signaled below.
        if args[:2] == ["container", "inspect"]:
            return 0, json.dumps([{"Id": self.cid, "Name": self.details["runtime"]["name"],
                "ImageDigest": "sha256:" + engine.IMAGE_INDEX, "Image": "sha256:" + executor.IMAGE_CONFIG,
                "Config": {"Labels": self.details["runtime"]["labels"]}, "State": {"Running": self.running}}]).encode()
        if args[:2] == ["container", "exists"]:
            return 0, b""
        if args[:2] == ["container", "stop"]:
            self.assertEqual(args, ["container", "stop", "--time=10", self.cid])
            self.running = False
            return 0, b""
        raise AssertionError("unexpected fixed engine acquisition")

    def spawn(self):
        self.running = True
        errors = []
        bound = threading.Event()
        original_bind = self.store.bind_engine_process
        def bind(*args, **kwargs):
            original_bind(*args, **kwargs)
            bound.set()  # Actual durable binding completed; no competing NB read.
        def cid_writer():
            try:
                if not bound.wait(2):
                    raise AssertionError("supervisor not bound")
                target = self.details["runtime"]["cidfile"]
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    os.fchmod(fd, 0o600)
                    os.write(fd, self.cid.encode())
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except BaseException as error:
                errors.append(type(error).__name__)
        thread = threading.Thread(target=cid_writer)
        thread.start()
        try:
            with mock.patch.object(executor, "_command", side_effect=self.command), \
                 mock.patch.object(self.store, "bind_engine_process", side_effect=bind):
                try:
                    result = self.traced_spawn()
                except executor.EngineUnknown:
                    self.fail("private fixed-ELF cause (no token/exception payload): " + repr(self.private_spawn_causes))
        finally:
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        return result

    def arguments(self):
        return (str(self.fixture.config), self.fixture.sha, self.fixture.fixture.registry,
                "approved", self.store, self.lease, self.receipt)

    def test_real_fixed_elf_pid_boot_hash_and_private_cid_are_durable(self):
        result = self.spawn()
        _, effect = self.engine_effect()
        actual = executor._process(effect["engine_process"]["pid"], self.manifest)
        self.assertEqual(effect["state"], "verified")
        self.assertEqual(effect["engine_container_id"], self.cid)
        self.assertTrue(all(effect["engine_process"][key] == value for key, value in actual.items()))
        self.assertEqual(result.state, "tracked-not-test-success")
        self.assertGreater(len(self.manifest.argv), 32)  # Actual engine argv exceeds Runner's contract.
        with self.assertRaises(Denied):
            executor.worker.validate_argv(self.manifest.argv)  # Runner parser stays unchanged.
        self.assertTrue((Path(self.details["engine"]["runroot"]) / "engine-manifest.json").is_file())

    def test_actual_supervisor_argv_must_equal_complete_signed_array(self):
        self.spawn()
        pid = self.engine_effect()[1]["engine_process"]["pid"]
        changed = replace(self.manifest, argv=self.manifest.argv[:-1] + ("different-fixed-argument",))
        with self.assertRaisesRegex(Denied, "engine-process-exact-argv"):
            executor._process(pid, changed)

    def test_startup_observation_race_reacquires_reads_without_respawn(self):
        self.spawn()
        pid = self.engine_effect()[1]["engine_process"]["pid"]
        original = executor._process
        calls = []
        def observation(*args):
            calls.append(1)
            if len(calls) == 1:
                raise Denied("engine-process-observation-changed")
            return original(*args)
        pidfd = os.pidfd_open(pid, 0)
        try:
            with mock.patch.object(executor, "_process", side_effect=observation), \
                 mock.patch.object(executor.subprocess, "Popen", side_effect=AssertionError("no respawn")):
                actual = executor._stable_process(pid, self.manifest, pidfd)
            self.assertEqual(actual["pid"], pid)
            self.assertEqual(len(calls), 2)
            with mock.patch.object(executor, "_process", side_effect=Denied("engine-process-exact-argv")) as observed:
                with self.assertRaises(Denied):
                    executor._stable_process(pid, self.manifest, pidfd)
                observed.assert_called_once()
        finally:
            os.close(pidfd)

    def test_spawn_replay_does_not_launch_a_second_process(self):
        self.spawn()
        process = self.engine_effect()[1]["engine_process"]
        with mock.patch.object(executor.subprocess, "Popen", side_effect=AssertionError("no replay")):
            with self.assertRaises(Denied):
                self.traced_spawn()
        self.assertEqual(self.engine_effect()[1]["engine_process"], process)

    def test_failed_process_binding_is_unknown_not_retryable(self):
        original = self.store.bind_engine_process
        def lost(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("synthetic lost durable reply")
        with mock.patch.object(self.store, "bind_engine_process", side_effect=lost):
            with self.assertRaises(executor.EngineUnknown):
                self.traced_spawn()
        self.assertEqual(self.engine_effect()[1]["state"], "unknown")
        self.assertIn("engine_process", self.engine_effect()[1], repr(self.private_spawn_causes))

    def test_replaced_executable_or_pid_tuple_never_signals_foreign_process(self):
        self.spawn()
        process = dict(self.engine_effect()[1]["engine_process"])
        process["start_ticks"] += 1
        with mock.patch.object(executor.signal, "pidfd_send_signal", side_effect=AssertionError("must not signal")):
            with self.assertRaises(Denied):
                executor._signal_owned(process, self.manifest)

    def test_status_and_cancel_exact_owned_cid_without_stdout_pass(self):
        self.spawn()
        effect_id, effect = self.engine_effect()
        # Signed native-Podman acquisition is unsupported here; the separate
        # Root signed-context suites cover it. The owned PID/CID is actual.
        with mock.patch.object(executor, "_retained", return_value=(self.manifest, effect_id, effect)), \
             mock.patch.object(executor, "_command", side_effect=self.command), \
             mock.patch.object(executor, "_withdraw"), \
             mock.patch.object(executor, "_drained"):
            state = executor.status(*self.arguments())
            self.assertEqual(state.state, "owned-running-not-test-success")
            stopped = executor.cancel(*self.arguments())
            self.assertEqual(stopped.state, "owned-stopped-not-test-success")
        self.assertTrue(any(e["operation"] == "engine-stop" and e["state"] == "verified"
                            for e in self.store.read(self.lease)["effects"].values()))

    def test_restart_cleanup_reacquires_distinct_fence_but_never_guesses_exit(self):
        from incus_lease_issuer import network_fence
        self.spawn()
        effect_id, effect = self.engine_effect()
        pid = effect["engine_process"]["pid"]
        owned = executor._PROCESSES.pop(pid)  # Model lost owner cache, not a new Popen.
        observations = []
        def withdrawal(path, sha, locator, store, worker, config):
            self.assertIs(type(locator), executor.cell_contract.OwnedFenceForCleanup)
            self.assertFalse(hasattr(locator, "engine_descriptor_path"))
            self.assertEqual(locator.lease_id, self.lease)
            observations.append(locator)
        try:
            with mock.patch.object(executor, "_retained", return_value=(self.manifest, effect_id, effect)), \
                 mock.patch.object(executor, "_command", side_effect=self.command), \
                 mock.patch.object(network_fence, "disable", side_effect=withdrawal), \
                 mock.patch.object(executor, "_drained"):
                with self.assertRaises(executor.EngineUnknown):
                    executor.cancel(*self.arguments())
            self.assertEqual(len(observations), 1)
            self.assertNotIn(pid, executor._PROCESSES)  # No Popen reconstruction.
            current = self.engine_effect()[1]
            self.assertNotIn("engine_exit", current)
            stops = [row for row in self.store.read(self.lease)["effects"].values()
                     if row["operation"] == "engine-stop"]
            self.assertEqual(len(stops), 1)
            self.assertEqual(stops[0]["state"], "verified")  # Known stop, original exit still UNKNOWN.
        finally:
            executor._PROCESSES[pid] = owned  # Original fixture owner only for bounded cleanup.

    def test_restart_invalid_fence_provenance_denies_before_stop_or_signal(self):
        self.spawn()
        effect_id, effect = self.engine_effect()
        pid = effect["engine_process"]["pid"]
        owned = executor._PROCESSES.pop(pid)
        try:
            with mock.patch.object(executor, "_retained", return_value=(self.manifest, effect_id, effect)), \
                 mock.patch.object(executor.cell_contract, "owned_fence_for_cleanup", side_effect=Denied("cell-cleanup-binding")), \
                 mock.patch.object(executor, "_command", side_effect=AssertionError("no stop")), \
                 mock.patch.object(executor, "_signal_owned", side_effect=AssertionError("no signal")):
                with self.assertRaises(executor.EngineUnknown):
                    executor.cancel(*self.arguments())
            self.assertFalse(any(row["operation"] == "engine-stop" for row in self.store.read(self.lease)["effects"].values()))
            self.assertNotIn("engine_exit", self.engine_effect()[1])
        finally:
            executor._PROCESSES[pid] = owned

    def test_internal_failure_aborts_live_original_owner_before_authorization_expiry(self):
        self.spawn()  # Real fixed Python ELF sleeping 30 seconds; never Podman proof.
        effect_id, effect = self.engine_effect()
        owned = executor._PROCESSES[effect["engine_process"]["pid"]]
        self.assertIsNone(owned.returncode)
        self.assertGreater(self.store.read(self.lease)["authorizations"][-1]["valid_until"], time.time())
        stopped = []
        def command(manifest, args, seconds=5):
            if args[:2] == ["container", "stop"]:
                stopped.append(tuple(args))
            return self.command(manifest, args, seconds)
        before = time.monotonic()
        # ONLY unavailable container/network/cgroup observations are modeled;
        # exact original ELF/PID/pidfd, SIGTERM, pipes, wait and Ledger are real.
        with mock.patch.object(executor, "_retained", return_value=(self.manifest, effect_id, effect)), \
             mock.patch.object(executor, "_command", side_effect=command), \
             mock.patch.object(executor, "_withdraw"), mock.patch.object(executor, "_drained"):
            receipt = executor._abort_after_failure(*self.arguments())
            self.assertEqual(receipt.signal, signal.SIGTERM)
            self.assertIsNone(receipt.exit_code)
            self.assertTrue(owned.closed)
            self.assertEqual(executor._abort_after_failure(*self.arguments()), receipt)
        self.assertLess(time.monotonic()-before, 5)
        self.assertEqual(len(stopped), 1)
        effects = self.store.read(self.lease)["effects"].values()
        stops = [row for row in effects if row["operation"] == "engine-stop"]
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0]["state"], "verified")
        self.assertEqual(self.engine_effect()[1]["engine_exit"]["signal"], signal.SIGTERM)

    def test_internal_abort_unknown_withdrawal_stops_once_but_keeps_unknown_hold(self):
        self.spawn()
        effect_id, effect = self.engine_effect()
        owned = executor._PROCESSES[effect["engine_process"]["pid"]]
        def uncertain(config, original):
            original.withdrawal_hold = True
        with mock.patch.object(executor, "_retained", return_value=(self.manifest, effect_id, effect)), \
             mock.patch.object(executor, "_command", side_effect=self.command), \
             mock.patch.object(executor, "_withdraw", side_effect=uncertain), mock.patch.object(executor, "_drained"):
            with self.assertRaises(executor.EngineUnknown):
                executor._abort_after_failure(*self.arguments())
            self.assertEqual(owned.returncode, -signal.SIGTERM)
            self.assertTrue(owned.withdrawal_hold)
            with self.assertRaises(executor.EngineUnknown):
                executor._abort_after_failure(*self.arguments())
        self.assertEqual(len([row for row in self.store.read(self.lease)["effects"].values()
                              if row["operation"] == "engine-stop"]), 1)
        self.assertEqual(self.engine_effect()[1]["engine_exit"]["signal"], signal.SIGTERM)

    def test_public_start_rederives_signed_manifest_and_denies_missing_native_prerequisites(self):
        # Return to the actual compiler-fixed executable before the real public
        # entry. No native acquisition or live-idmap gate is bypassed.
        with mock.patch.object(engine, "ENGINE", self.original), \
             mock.patch.object(executor.subprocess, "Popen", side_effect=AssertionError("no native spawn")):
            with self.assertRaises(Denied):
                executor.start(*self.arguments())
        self.assertFalse(any(e["operation"] == "engine-start" for e in self.store.read(self.lease)["effects"].values()))

    def test_late_new_start_denies_before_native_preflight_or_intent(self):
        now = executor.time.time()
        with mock.patch.object(engine, "ENGINE", self.original), \
             mock.patch.object(executor.time, "time", return_value=now + 1), \
             mock.patch.object(executor, "_preflight", side_effect=AssertionError("no late native acquisition")), \
             mock.patch.object(executor.subprocess, "Popen", side_effect=AssertionError("no late spawn")):
            with self.assertRaises(Denied):
                executor.start(*self.arguments())
        self.assertFalse(any(e["operation"] == "engine-start" for e in self.store.read(self.lease)["effects"].values()))

    def test_budget_consumed_during_probe_retains_unknown_without_spawn(self):
        @contextmanager
        def acquisition(*args):
            yield  # Unsupported native acquisition modeled ONLY for this timing fault.
        now = executor.time.time()
        with mock.patch.object(engine, "ENGINE", self.original), \
             mock.patch.object(executor.time, "time", return_value=now) as clock, \
             mock.patch.object(executor, "_preflight", acquisition), \
             mock.patch.object(executor, "_idmapped_preflight", side_effect=lambda *args: setattr(clock, "return_value", now + 1)), \
             mock.patch.object(executor.subprocess, "Popen", side_effect=AssertionError("no budget after probe")):
            with self.assertRaises(executor.EngineUnknown):
                executor.start(*self.arguments())
        _, effect = self.engine_effect()
        self.assertEqual(effect["state"], "unknown")
        self.assertNotIn("engine_process", effect)

    def test_regular_file_cannot_be_a_namespace(self):
        # Call fixed namespace acquisition with an ordinary file at a matching
        # structural path only through mocked open location, never proof flags.
        ordinary = self.fixture.root / "ordinary"
        ordinary.write_bytes(b"not nsfs")
        with ordinary.open("rb") as stream:
            self.assertNotEqual(executor._fs_type(stream.fileno()), executor.NSFS_MAGIC)

    def test_index_digest_metadata_requires_exact_amd64_child_config(self):
        info = {"host": {"security": {"rootless": False}, "serviceIsRemote": False,
                         "arch": "amd64", "os": "linux", "cgroupVersion": "v2", "cgroupManager": "systemd",
                         "ociRuntime": {"path": str(self.binary)}, "conmon": {"path": str(self.binary)}},
                "store": {"graphRoot": self.details["engine"]["storage_root"],
                          "runRoot": self.details["engine"]["runroot"]}}
        image = {"Digest": "sha256:" + engine.IMAGE_INDEX, "Id": "sha256:" + executor.IMAGE_CONFIG,
                 "Architecture": "amd64", "Os": "linux"}
        def observed(manifest, arguments, seconds=5):
            if arguments == ["info", "--format=json"]:
                return 0, json.dumps(info).encode()
            if arguments == ["image", "inspect", "--format=json", engine.IMAGE]:
                return 0, json.dumps([image]).encode()
            if arguments == ["container", "exists", self.details["runtime"]["name"]]:
                return 1, b""
            raise AssertionError("unexpected metadata query")
        with mock.patch.object(executor, "_command", side_effect=observed):
            executor._backend(self.manifest)  # Real index Digest is not misnamed a child readback.
            image["Id"] = "sha256:" + "f" * 64
            with self.assertRaises(Denied):
                executor._backend(self.manifest)
            image["Id"] = "sha256:" + executor.IMAGE_CONFIG
            image["Architecture"] = "arm64"
            with self.assertRaises(Denied):
                executor._backend(self.manifest)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootLiveIdmapProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cell_fixtures.RootCellContractTests.setUpClass()

    def setUp(self):
        self.fixture = cell_fixtures.RootCellContractTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.prepared = self.fixture.prepare()
        self.manifest = self.fixture.materialize(self.prepared)

    def capable(self):
        with open("/proc/self/status", "rb") as stream:
            rows = stream.read().decode().splitlines()
        bits = int(next(row.split()[1] for row in rows if row.startswith("CapEff:")), 16)
        return all(bits & (1 << capability) for capability in (6, 7, 21))

    def test_real_probe_denies_missing_native_capabilities_without_qualified_fallback(self):
        if self.capable():
            self.skipTest("actual capable-kernel positive is covered separately")
        output = Path(identity.decode_json(self.manifest.canonical_bytes)["output"]["path"])
        before = set(output.iterdir())
        def descriptors():
            result = set()
            for number in range(1024):
                try:
                    os.fstat(number)
                except OSError:
                    continue
                result.add(number)
            return result
        descriptor_before = descriptors()
        children_path = Path("/proc/self/task") / str(os.getpid()) / "children"
        children_before = children_path.read_bytes()
        with self.assertRaises((Denied, OSError)):
            executor._idmapped_preflight(self.prepared, self.manifest)
        self.assertEqual(set(output.iterdir()), before)
        self.assertEqual(descriptors(), descriptor_before)
        self.assertEqual(children_path.read_bytes(), children_before)

    def test_actual_mapped_readonly_and_output_write_when_kernel_capabilities_exist(self):
        if not self.capable():
            self.skipTest("actual private mount/user namespace capabilities unavailable; no native idmap PASS")
        details = identity.decode_json(self.manifest.canonical_bytes)
        before = {name: (Path(details["context"]["path"]) / name).read_bytes() for name in engine.CONTEXT_FILES}
        output = Path(details["output"]["path"])
        executor._idmapped_preflight(self.prepared, self.manifest)
        self.assertEqual(set(output.iterdir()), set())
        for name, raw in before.items():
            path = Path(details["context"]["path"]) / name
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(path.stat().st_uid, 0)

    def test_existing_probe_file_is_never_adopted_or_deleted(self):
        output = Path(identity.decode_json(self.manifest.canonical_bytes)["output"]["path"])
        path = output / (".lit-idmap-probe-" + self.prepared.lease_id)
        path.write_bytes(b"foreign retain")
        with self.assertRaisesRegex(Denied, "engine-probe-existing-output"):
            executor._idmapped_preflight(self.prepared, self.manifest)
        self.assertEqual(path.read_bytes(), b"foreign retain")

    def test_fork_probe_refuses_multithreaded_root_process_before_mutation(self):
        with mock.patch.object(executor.threading, "active_count", return_value=2), \
             mock.patch.object(executor.os, "fork", side_effect=AssertionError("must not fork")):
            with self.assertRaisesRegex(Denied, "engine-probe-single-thread-required"):
                executor._idmapped_preflight(self.prepared, self.manifest)
