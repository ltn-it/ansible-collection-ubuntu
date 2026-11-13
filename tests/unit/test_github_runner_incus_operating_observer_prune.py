"""Real retained Ledger/graph/prune producer; native auth/cgroup/HTTPS are models.

The observer is exercised through its constructor and real observation loop with
an explicit fake clock. This is not native VM, capacity or custody acceptance.
"""
from contextlib import ExitStack
from copy import deepcopy
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

import test_github_runner_incus_engine_graph_prune as graph_fixtures
from incus_lease_issuer import runtime_rpc, run_factory, capacity, root_session, operating_custody
from incus_lease_issuer.identity import Denied


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootOperatingObserverPruneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        graph_fixtures.RootGraphPruneTests.setUpClass()

    def setUp(self):
        self.graph = graph_fixtures.RootGraphPruneTests()
        self.graph.setUp()
        self.addCleanup(self.graph.doCleanups)
        self.now = 0.0
        self.sleeps = 0
        self.replies = []

    def observe(self, after_sleep=None, remaining=120):
        io = self.graph.io
        record = self.graph.store.read(self.graph.lease)
        who = record["identity"]
        origin = {"run_id": who["run_id"], "job_id": who["job_id"],
                  "check_run_id": who["check_run_id"], "source_sha": who["caller_sha"],
                  "reusable_sha": who["reusable_sha"]}
        observer = SimpleNamespace(run_id=who["run_id"], caller_sha=who["caller_sha"],
            reusable_sha=who["reusable_sha"], job_id=who["job_id"]+1, check_run_id=who["check_run_id"]+1)
        config = SimpleNamespace(runtime_config_path=str(io.runtime), runtime_config_sha256=io.runtime_sha)
        bootstrap = SimpleNamespace(value={"runtime": {"authentication_timeout_seconds": 5}})
        proof = SimpleNamespace(policy=object())
        def sleep(seconds):
            self.now += seconds
            self.sleeps += 1
            if after_sleep is not None:
                after_sleep(self.sleeps)
        with ExitStack() as stack:
            stack.enter_context(self.graph.model())
            for target, name, value in (
                (run_factory, "load_bootstrap", bootstrap),
                (run_factory, "challenge_bootstrap", {"nonce": "a"*64, "audience": "synthetic"}),
                (run_factory, "verify_bootstrap_native", proof),
                (run_factory, "find_existing_configuration", config),
                (run_factory, "require_bootstrap_native", (None, observer, remaining)),
                (run_factory, "read_configuration_origin", origin),
                (runtime_rpc, "_authentication", {"nonce": "a"*64, "token": "synthetic", "api_token": "synthetic"}),
            ):
                stack.enter_context(mock.patch.object(target, name, return_value=value))
            stack.enter_context(mock.patch.object(runtime_rpc, "_write", side_effect=lambda _c, value: self.replies.append(value)))
            stack.enter_context(mock.patch.object(runtime_rpc.time, "monotonic", side_effect=lambda: self.now))
            stack.enter_context(mock.patch.object(runtime_rpc.time, "sleep", side_effect=sleep))
            broker = runtime_rpc.BootstrapRuntimeRPC("synthetic-locator", "a"*64)
            return broker._observe(object(), bootstrap, graph_fixtures.ready_fixtures.SELECTOR, "observe-operating")

    def test_retained_waits_for_real_verified_empty_graph_then_returns_same_receipt(self):
        before = deepcopy(self.graph.store.read(self.graph.lease)["custody"])
        self.assertTrue(list(self.graph.graph.iterdir()))
        result = self.observe(lambda count: self.graph.run_prune() if count == 2 else None)
        self.assertEqual(self.sleeps, 2)
        self.assertEqual(result["type"], "operating-receipt")
        self.assertEqual(result["receipt"]["state"], "retained")
        self.assertEqual(self.graph.store.read(self.graph.lease)["custody"], before)
        self.assertEqual(list(self.graph.graph.iterdir()), [])
        self.assertNotIn("capacity", result)

    def test_verified_producer_holding_original_lock_waits_then_same_session_receipt(self):
        held = self.graph.session()
        with self.graph.model():
            owner, config, session = held.__enter__()
            released = False
            try:
                graph_fixtures.prune.prune_graph(owner, self.graph.store, config, session=session)
                before = deepcopy(self.graph.store.read(self.graph.lease))
                def release(count):
                    nonlocal released
                    if count == 2:
                        held.__exit__(None, None, None)
                        released = True
                original = operating_custody.operating_outcome
                calls = []
                def receipt(*args, **kwargs):
                    proof = kwargs["session"]
                    calls.append(root_session._require_session(proof))
                    return original(*args, **kwargs)
                with mock.patch.object(operating_custody, "operating_outcome", side_effect=receipt):
                    result = self.observe(release)
                self.assertTrue(released)
                self.assertEqual(self.sleeps, 2)
                self.assertEqual(len(calls), 1)
                self.assertEqual(result["receipt"]["state"], "retained")
                self.assertEqual(self.graph.store.read(self.graph.lease), before)
            finally:
                if not released:
                    held.__exit__(None, None, None)

    def test_body_EAGAIN_is_not_reinterpreted_as_preentry_lock_contention(self):
        import errno
        self.graph.run_prune()
        with mock.patch.object(capacity, "_graph", side_effect=BlockingIOError(errno.EAGAIN, "synthetic-body")):
            with self.assertRaises(BlockingIOError):
                self.observe()
        self.assertEqual(self.sleeps, 0)
        self.assertEqual(len(self.replies), 1)

    def test_wrong_lock_metadata_holds_without_retry(self):
        self.graph.run_prune()
        config = self.graph.io.io.config
        from incus_lease_issuer import preparation
        path = Path(preparation._config(str(config), self.graph.io.io.sha)[0].lock_path)
        path.chmod(0o644)
        self.addCleanup(path.chmod, 0o600)
        with self.assertRaisesRegex(Denied, "root-session-lock-file"):
            self.observe()
        self.assertEqual(self.sleeps, 0)

    def test_invalid_or_different_preparation_session_cannot_issue_receipt(self):
        self.graph.run_prune()
        io = self.graph.io
        with self.assertRaises(Denied):
            operating_custody.operating_outcome(str(io.runtime), io.runtime_sha, self.graph.registry,
                graph_fixtures.ready_fixtures.SELECTOR, self.graph.store, self.graph.lease,
                retained=True, session=object())
        with self.graph.model(), self.graph.session() as (_owner, config, session):
            with mock.patch.object(operating_custody, "_preparation_reference",
                    return_value=(config.path, "0"*64)):
                with self.assertRaisesRegex(Denied, "operating-outcome-session-domain"):
                    operating_custody.operating_outcome(str(io.runtime), io.runtime_sha, self.graph.registry,
                        graph_fixtures.ready_fixtures.SELECTOR, self.graph.store, self.graph.lease,
                        retained=True, session=session)

    def test_missing_producer_proof_times_out_without_creating_prune(self):
        with self.assertRaisesRegex(Denied, "runtime-observer-wait-held"):
            self.observe(remaining=3)
        self.assertEqual(self.now, 3)
        self.assertFalse(any(row["operation"] == "engine-graph-prune"
            for row in self.graph.store.read(self.graph.lease)["effects"].values()))
        self.assertEqual(len(self.replies), 1)

    def test_proof_arriving_at_original_observer_deadline_does_not_extend_wait(self):
        with self.assertRaisesRegex(Denied, "runtime-observer-wait-held"):
            self.observe(lambda count: self.graph.run_prune() if count == 3 else None, remaining=3)
        self.assertEqual(self.now, 3)
        self.assertEqual(len(self.replies), 1)

    def test_unfinished_producer_intent_waits_but_is_never_completed_by_observer(self):
        effect = self.graph.store.begin(self.graph.lease, "engine-graph-prune", "engine:"+self.graph.lease)
        with self.assertRaisesRegex(Denied, "runtime-observer-wait-held"):
            self.observe(remaining=3)
        self.assertEqual(self.graph.store.read(self.graph.lease)["effects"][effect]["state"], "intent")

    def test_failed_producer_proof_denies_without_observation_success(self):
        effect = self.graph.store.begin(self.graph.lease, "engine-graph-prune", "engine:"+self.graph.lease)
        self.graph.store.record(self.graph.lease, effect, "unknown", evidence_sha256="d"*64)
        with self.assertRaisesRegex(Denied, "runtime-observer-prune-held"):
            self.observe()
        self.assertEqual(self.sleeps, 0)
        self.assertEqual(len(self.replies), 1)

    def test_verified_marker_does_not_credit_returned_graph_bytes(self):
        self.graph.run_prune()
        (self.graph.graph/"returned-layer").write_bytes(b"not empty")
        with self.assertRaisesRegex(Denied, "capacity-pruned-graph-returned"):
            self.observe()
        self.assertEqual(len(self.replies), 1)

    def test_verified_marker_does_not_credit_changed_original_capture(self):
        self.graph.run_prune()
        self.graph.raw.write_bytes(b"changed diagnostic")
        with self.assertRaises(Denied):
            self.observe()
        self.assertEqual(len(self.replies), 1)

    def test_final_pool_and_engine_admission_are_not_granted_by_observer(self):
        self.graph.run_prune()
        with mock.patch.object(capacity, "require_capacity", side_effect=AssertionError("observer must not admit")):
            result = self.observe()
        self.assertEqual(result["receipt"]["state"], "retained")
        # The independent admission still rejects real headroom/reservation failure.
        with self.assertRaises(Denied):
            capacity._bounds(32*capacity.GIB, 22*capacity.GIB, 20*capacity.GIB, 10*capacity.GIB)
