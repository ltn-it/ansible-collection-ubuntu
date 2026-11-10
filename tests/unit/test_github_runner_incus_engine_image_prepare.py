"""Fresh-store producer/consumer pipeline with real synthetic processes, not Podman qualification."""
import json
import os
import signal
import sys
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import test_github_runner_incus_engine_policy as engine_fixtures
import test_github_runner_incus_preparation as fixtures
from incus_lease_issuer import engine_executor as executor
from incus_lease_issuer import engine_policy as engine
from incus_lease_issuer import identity, preparation, storage_quota
from incus_lease_issuer.identity import Denied

PROVISION = executor._provision_image
PULL = executor._pull_image
PREFIX = executor._prefix


class ImageReadbackBudgetTests(unittest.TestCase):
    def test_expired_shared_readback_deadline_denies_before_any_query(self):
        with (mock.patch.object(executor, "_command", side_effect=AssertionError("no expired query")),
              self.assertRaisesRegex(Denied, "engine-image-provision-budget-expired")):
            executor._backend(None, deadline=time.monotonic() - 1)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootImagePreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.RootPreparationTests.setUpClass()

    def setUp(self):
        original_setup = engine_fixtures.RootEngineCompilerTests.setUp
        def preparation_headroom(fixture):
            original_setup(fixture)
            fixture.data["limits"]["timeout_seconds"] = 600
        fixture_budget = mock.patch.object(engine_fixtures.RootEngineCompilerTests, "setUp", preparation_headroom)
        fixture_budget.start()
        self.addCleanup(fixture_budget.stop)
        self.io = fixtures.RootPreparationTests()
        self.io.setUp()
        self.addCleanup(self.io.doCleanups)
        self.io.image_provision.side_effect = PROVISION
        self.mode = "success"
        self.quota_live = False
        self.commands = []
        @contextmanager
        def quota(*args):
            self.quota_live = True
            try:
                yield
            finally:
                self.quota_live = False
        patch = mock.patch.object(storage_quota, "acquire_existing_quota", side_effect=quota)
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(executor, "_prefix", side_effect=self.prefix)
        patch.start()
        self.addCleanup(patch.stop)

    def prefix(self, manifest):
        self.assertTrue(self.quota_live, "quota must precede every image mutation and readback")
        self.commands.append(manifest)
        # The actual subprocess parses the same fixed prefix/suffix, writes
        # private store bytes on pull, and inspects only those produced bytes.
        source = r'''import json,os,sys,time
from pathlib import Path
a=sys.argv[1:]
graph=Path(a[a.index("--root")+1]); run=Path(a[a.index("--runroot")+1])
assert os.geteuid()==0 and os.environ["TMPDIR"]==str(run)
assert os.environ["HOME"]==str(run) and "HTTP_PROXY" not in os.environ
command=a[7:]
mode=MODE
image=IMAGE
metadata={"Digest":"sha256:"+INDEX,"Id":"sha256:"+CONFIG,"Architecture":"amd64","Os":"linux"}
if command[0]=="pull":
    # Source Podman 4.9.3 rejects --retry before starting an image copy.
    assert command==["pull","--tls-verify=true","--platform=linux/amd64",image]
    assert not list(graph.iterdir()), "fresh graphroot"
    (graph/"partial").write_text("owned partial image bytes")
    (run/"pull-owner").write_text(str(os.getpid()))
    if mode=="failure": sys.exit(17)
    if mode in ("timeout","helper"):
        child=os.fork()
        if child==0:
            os.close(1)
            time.sleep(20)
            (graph/"late-write").write_text("unsafe surviving helper")
            os._exit(0)
        (run/"helper-pid").write_text(str(child))
        if mode=="timeout": time.sleep(20)
        else: sys.exit(0)
    if mode=="wrong-child": metadata["Digest"]="sha256:"+"f"*64
    if mode=="wrong-config": metadata["Id"]="sha256:"+"f"*64
    if mode=="wrong-platform": metadata["Architecture"]="arm64"
    if mode=="child": metadata["Digest"]="sha256:"+CHILD
    (graph/"image.json").write_text(json.dumps(metadata))
    sys.exit(0)
if command==["info","--format=json"]:
    print(json.dumps({"host":{"security":{"rootless":False},"serviceIsRemote":False,
        "arch":"amd64","os":"linux","cgroupVersion":"v2","cgroupManager":"systemd",
        "ociRuntime":{"path":os.path.realpath(sys.executable)},"conmon":{"path":os.path.realpath(sys.executable)}},
        "store":{"graphRoot":str(graph),"runRoot":str(run)}}))
elif command==["image","inspect","--format=json",image]:
    print(json.dumps([json.loads((graph/"image.json").read_bytes())]))
elif command[:2]==["container","exists"]: sys.exit(1)
else: raise AssertionError(command)
'''
        source = ("MODE=" + repr(self.mode) + "\nIMAGE=" + repr(engine.PODMAN_IMAGE)
                  + "\nINDEX=" + repr(engine.IMAGE_INDEX) + "\nCHILD=" + repr(engine.IMAGE_CHILD)
                  + "\nCONFIG=" + repr(executor.IMAGE_CONFIG) + "\n") + source
        return [sys.executable, "-I", "-B", "-c", source] + PREFIX(manifest)[1:]

    def paths(self):
        data = identity.decode_json(self.io.prepared.engine_descriptor_bytes)
        return Path(data["engine"]["storage_root"]), Path(data["engine"]["runroot"])

    def test_actual_cold_private_store_is_populated_before_verified_and_signed(self):
        receipt = self.io.run_prepare()
        self.assertEqual(receipt.lease_id, self.io.lease)
        graph, run = self.paths()
        self.assertEqual(json.loads((graph / "image.json").read_bytes())["Id"], "sha256:" + executor.IMAGE_CONFIG)
        self.assertEqual(self.io.effect("engine-prepare")["state"], "verified")
        self.assertEqual(self.io.effect("context-publish")["state"], "verified")
        self.assertTrue((run / "pull-owner").is_file())
        self.assertEqual(len(self.commands), 4, "one pull then unchanged info/image/name readbacks")
        from incus_lease_issuer import ledger
        data = identity.decode_json(self.io.prepared.engine_descriptor_bytes)
        paths = (graph, run, Path(data["output_path"]))
        directories = [{"path": str(path), "device": path.stat().st_dev, "inode": path.stat().st_ino}
                       for path in paths]
        self.assertEqual(self.io.effect("engine-prepare")["evidence_sha256"],
            ledger.digest({"prepared": self.io.prepared.sha256, "directories": directories}),
            "existing cleanup consumer still recognizes original directory inodes")
        with self.assertRaises(preparation.PreparationDenied):
            self.io.run_prepare()

    def test_pinned_child_digest_is_also_accepted(self):
        self.mode = "child"
        self.io.run_prepare()
        self.assertEqual(self.io.effect("engine-prepare")["state"], "verified")

    def failed(self, mode):
        self.mode = mode
        with self.assertRaises(preparation.PreparationUnknown):
            self.io.run_prepare()
        self.assertEqual(self.io.effect("engine-prepare")["state"], "unknown")
        self.assertFalse(any(row["operation"] in {"context-publish", "engine-start"} for row in self.io.effects()))
        graph, run = self.paths()
        self.assertTrue((graph / "partial").is_file(), "unknown partial data retained")
        if mode.startswith("wrong-"):
            self.assertEqual(len(self.commands), 3, "wrong image rejected by actual unchanged inspect consumer")
        calls = len(self.commands)
        with self.assertRaises(preparation.PreparationDenied):
            self.io.run_prepare()
        self.assertEqual(len(self.commands), calls, "unknown attempt cannot retry")
        return graph, run

    def test_failed_cold_pull_keeps_owned_partial_data_unknown_without_retry(self):
        self.failed("failure")

    def test_wrong_child_is_not_tagged_or_accepted(self):
        self.failed("wrong-child")

    def test_wrong_config_is_not_accepted(self):
        self.failed("wrong-config")

    def test_wrong_platform_is_not_accepted(self):
        self.failed("wrong-platform")

    def assert_helper_dead(self, run):
        pid = int((run / "helper-pid").read_text())
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                fields = Path("/proc/" + str(pid) + "/stat").read_bytes().rsplit(b") ", 1)[1].split()
                if fields[0] == b"Z":
                    return
            except FileNotFoundError:
                return
            time.sleep(0.01)
        self.fail("owned helper survived bounded group termination")

    def test_timeout_kills_owned_parent_and_helper_then_retains_unknown(self):
        with mock.patch.object(executor, "_pull_image", side_effect=lambda m, s: PULL(m, min(s, 0.3))):
            graph, run = self.failed("timeout")
        self.assert_helper_dead(run)
        self.assertFalse((graph / "late-write").exists())

    def test_parent_exit_does_not_accept_live_helper_or_leave_writer(self):
        graph, run = self.failed("helper")
        self.assert_helper_dead(run)
        self.assertFalse((graph / "late-write").exists())

    def test_quota_failure_precedes_any_pull(self):
        with (mock.patch.object(storage_quota, "acquire_existing_quota", side_effect=Denied("no real quota")),
              self.assertRaises(preparation.PreparationUnknown)):
            self.io.run_prepare()
        self.assertEqual(self.commands, [])
        self.assertEqual(self.io.effect("engine-prepare")["state"], "unknown")

    def test_consumed_full_engine_budget_denies_publication_after_pull(self):
        def budget(prepared, manifest):
            if self.commands:
                raise Denied("engine-start-budget-expired")
        with mock.patch.object(executor, "_start_budget", side_effect=budget):
            self.failed("success")

    def test_automatic_child_reaping_is_denied_before_spawn(self):
        original = executor.signal.getsignal
        def disposition(number):
            return signal.SIG_IGN if number == signal.SIGCHLD else original(number)
        with (mock.patch.object(executor.signal, "getsignal", side_effect=disposition),
              self.assertRaises(preparation.PreparationUnknown)):
            self.io.run_prepare()
        self.assertEqual(self.commands, [])
        self.assertEqual(self.io.effect("engine-prepare")["state"], "unknown")

    def test_retained_previous_lease_blocks_image_allocation(self):
        from incus_lease_issuer import ledger
        fixture = self.io.fixture
        selected = fixture.registry.select("approved")
        from dataclasses import replace
        worker = replace(fixture.io.fixture.worker, uid=2102, runner_id=62)
        nonce = fixture.store.challenge(worker)["nonce"]
        who = identity.Identity(502, 903, 732, worker.runner_id, worker.uid,
            selected.identity.caller_sha, selected.identity.reusable_sha, int(time.time()) + 300,
            "8" * 64, ledger.AUDIENCE + nonce, identity.policy_digest(selected.identity))
        fixture.store.prepare(nonce, worker, who, policy_sha256=selected.custody_policy_sha256,
            cell_sha256=selected.cell_sha256, deadline=selected.deadline)
        with self.assertRaises(preparation.PreparationUnknown):
            self.io.run_prepare()
        self.assertEqual(self.commands, [])
        self.assertEqual(self.io.effect("engine-prepare")["state"], "unknown")

    def test_no_remaining_full_budget_denies_before_pull(self):
        with (mock.patch.object(executor, "_start_budget", side_effect=Denied("engine-start-budget-expired")),
              self.assertRaises(preparation.PreparationUnknown)):
            self.io.run_prepare()
        self.assertEqual(self.commands, [])

    def test_initial_deadline_during_spawn_adoption_terminates_owned_process(self):
        from incus_lease_issuer import runtime_entry
        original = executor.subprocess.Popen
        acquired = []
        def interrupted(*args, **kwargs):
            proc = original(*args, **kwargs)
            command = args[0] if args else kwargs["args"]
            if "--platform=linux/amd64" in command:
                acquired.append(proc)
                os.kill(os.getpid(), signal.SIGALRM)
            return proc
        # The synthetic Incus HTTP fixture owns a thread; production's
        # single-thread gate is independently tested by runtime_entry tests.
        with (mock.patch.object(runtime_entry, "_single_thread"), self.assertRaises(Denied),
              runtime_entry._initial_effects_deadline(2, int(time.time()) + 10),
              mock.patch.object(executor.subprocess, "Popen", side_effect=interrupted),
              self.assertRaises(preparation.PreparationUnknown)):
            self.io.run_prepare()
        self.assertEqual(len(acquired), 1)
        self.assertIsNotNone(acquired[0].returncode)
        self.assertEqual(self.io.effect("engine-prepare")["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
