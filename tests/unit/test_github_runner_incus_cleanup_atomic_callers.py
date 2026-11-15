"""Real public cleanup caller recovery; native/kernel facts retain fixture models.

The established signed-context/fixed-engine/Unix finalizer pipeline supplies the
real owner and Ledger. No successful cleanup/owner/consumer check is mocked.
Only historical native receipts and unavailable kernel/quota facts are models.
"""
import json
import os
from pathlib import Path
import secrets
import sys
import time
import unittest
from unittest import mock

import test_github_runner_incus_full_finalization as full
import test_github_runner_incus_ledger as history
from incus_lease_issuer import cleanup_storage as storage, identity, ledger
from incus_lease_issuer.identity import Denied


class FixtureStopped(BaseException):
    """Expected held caller terminates the disposable fixture, never a success."""


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "proper private Root Linux EE only")
class AtomicCleanupCallerTests(unittest.TestCase):
    def historical_sidecar(self, store):
        """Real historical lifecycle/bytes; only native creator receipts modeled."""
        helper = history.IncusLedgerTests()
        worker = ledger.Worker(**{**history.WORKER, "uid": 2901, "runner_id": 901})
        now = store._now()
        lease, *_ = helper.prepare(store, worker=worker, deadline=now + 120,
            identity_changes={"run_id": 91001, "job_id": 91002, "check_run_id": 91003,
                "runner_id": worker.runner_id, "service_uid": worker.uid,
                "valid_until": now + 300, "token_id_sha256": secrets.token_hex(32)})
        targets = helper.provision(store, lease, through="engine-prepare")
        effect = store.begin(lease, "certificate-revoke", targets["certificate-create"])
        store.record(lease, effect, "verified", evidence_sha256=history.EVIDENCE)
        effect, guard = store.begin_cleanup_with_postcheck(lease, "engine-release",
            targets["engine-prepare"], time.monotonic() + 60,
            observation=({"fixture": "authentic historical metadata, modeled native receipts"}, b"\0" * 16))
        store.record(lease, effect, "verified", evidence_sha256=history.EVIDENCE)
        store.complete_cleanup_postcheck(guard)
        for operation, creator in (("context-delete", "context-create"),
                ("project-delete", "project-create"), ("network-delete", "network-create")):
            effect = store.begin(lease, operation, targets[creator])
            store.record(lease, effect, "verified", evidence_sha256=history.EVIDENCE)
        # Model an authentic historical post-close GC interruption, using the
        # actual closed transaction and preserved real sidecar reference.
        with mock.patch.object(store, "collect_closed_cleanup_observations", side_effect=Denied("fixture-gc-interruption")):
            result = store.close(lease)
        self.assertEqual(result, {"state": "closed", "metadata_gc": "held"})
        record = store.read(lease)
        ref = next(e["cleanup_observation"] for e in record["effects"].values() if "cleanup_observation" in e)
        self.assertTrue((store.path / ref["name"]).is_file())
        return lease, record, ref

    @staticmethod
    def paths(owner, method):
        value = identity.decode_json(owner.engine_descriptor_bytes)
        return ([value["engine"]["storage_root"], value["engine"]["runroot"], value["output_path"]]
            if method == "release_engine" else [value["context_path"], owner.engine_descriptor_path])

    def exercise(self, method, failure):
        fixture = full.RootFullCoreFinalizationTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUpClass(); fixture.setUp()
        marker = fixture.io.root / ("atomic-caller-" + method + "-" + failure + ".json")
        original = getattr(storage, method)
        hit = {"called": False}

        def caller(owner, store, config):
            def trace(phase):
                values = store.read(owner.lease_id)["effects"].values()
                (fixture.io.root / "atomic-caller-trace.json").write_bytes(ledger.canonical({
                    "phase": phase, "effects": [{"operation": e["operation"], "state": e["state"],
                    "guard": "cleanup_postcheck" in e} for e in values]}))
            trace("caller-entry")
            self.assertFalse(hit["called"]); hit["called"] = True
            paths = self.paths(owner, method)
            self.assertTrue(all(os.path.lexists(p) for p in paths))
            initial = store.read(owner.lease_id)
            authorizations, expires = initial["authorizations"], initial["expires_at"]
            operation = "engine-release" if method == "release_engine" else "context-delete"
            self.assertFalse(any(e["operation"] == operation for e in initial["effects"].values()))
            if failure in {"observation", "metadata-cap"}:
                old, historical, ref = self.historical_sidecar(store)
                trace("historical-sidecar-created")
                before = store.read(owner.lease_id)
                real_observation = storage._postcheck_observation
                def observation(*args, **kwargs):
                    if failure == "observation":
                        raise Denied("fixture-metadata-preparation")
                    metadata, pairs = real_observation(*args, **kwargs)
                    return {**metadata, "fixture_oversize_header": "x" * 65537}, pairs
                with mock.patch.object(storage, "_postcheck_observation", side_effect=observation), self.assertRaises(Denied):
                    original(owner, store, config)
                trace("metadata-call-returned-denied")
                self.assertTrue(store.read(owner.lease_id) == before, "metadata preparation consumed active effect")
                self.assertTrue(all(os.path.lexists(p) for p in paths))
                self.assertTrue((store.path / ref["name"]).exists())
                collected = store.collect_closed_cleanup_observations(deadline=time.monotonic() + 60)
                self.assertIn(ref["name"], [row["name"] for row in collected["removed"]])
                self.assertFalse((store.path / ref["name"]).exists())
                self.assertEqual(store.read(old), historical)
                self.assertEqual(store.read(owner.lease_id), before)
                # Same real public function and store; no reset, reprepare or
                # lookup mock can manufacture this successful second call.
                result = original(owner, store, config)
                self.assertTrue(all(not os.path.lexists(p) for p in paths))
                effect = [e for e in store.read(owner.lease_id)["effects"].values() if e["operation"] == operation]
                self.assertEqual(len(effect), 1); self.assertEqual(effect[0]["state"], "verified")
                store.require_cleanup_postchecks(owner.lease_id)
                self.assertEqual(store.read(owner.lease_id)["authorizations"], authorizations)
                self.assertEqual(store.read(owner.lease_id)["expires_at"], expires)
                marker.write_bytes(ledger.canonical({"passed": True, "same_public_entry": method,
                    "failure": failure, "historical_metadata_removed": True, "native_acceptance": False}))
                return result

            if failure == "commit-return":
                save = store._save
                committed = {"seen": False}
                def save_then_raise(state):
                    save(state)
                    rows = state["leases"][owner.lease_id]["effects"].values()
                    if not committed["seen"] and any(e["operation"] == operation and "cleanup_postcheck" in e for e in rows):
                        committed["seen"] = True
                        raise OSError("fixture-durable-save-return-interrupted")
                with mock.patch.object(store, "_save", side_effect=save_then_raise), self.assertRaises(Denied):
                    original(owner, store, config)
                self.assertTrue(committed["seen"])
            elif failure == "deadline-after-publication":
                atomic = store.begin_cleanup_with_postcheck
                real_clock = time.monotonic
                clock = {"late": None}
                def after_publication(*args, **kwargs):
                    value = atomic(*args, **kwargs)
                    clock["late"] = args[3] + 1
                    return value
                with mock.patch.object(store, "begin_cleanup_with_postcheck", side_effect=after_publication), \
                        mock.patch.object(storage.time, "monotonic", side_effect=lambda: real_clock() if clock["late"] is None else clock["late"]), \
                        self.assertRaises(Denied):
                    original(owner, store, config)
            else:
                self.assertEqual(failure, "unlink-started")
                unlink = os.unlink
                removed = []
                def unlink_then_raise(path, *, dir_fd=None):
                    parent = os.readlink("/proc/self/fd/" + str(dir_fd)) if dir_fd is not None else os.getcwd()
                    absolute = os.path.normpath(os.path.join(parent, os.fsdecode(path)))
                    owned = any(absolute.startswith(str(root).rstrip("/") + "/") for root in paths)
                    if owned and not removed:
                        unlink(path, dir_fd=dir_fd)
                        removed.append(absolute)
                        raise OSError("fixture-first-owned-unlink-return-interrupted")
                    return unlink(path, dir_fd=dir_fd)
                with mock.patch.object(storage.os, "unlink", side_effect=unlink_then_raise), self.assertRaises(Denied):
                    original(owner, store, config)
                trace("mutation-returned-denied-count-" + str(len(removed)))
                self.assertEqual(len(removed), 1)
                self.assertFalse(os.path.lexists(removed[0]))
            held = store.read(owner.lease_id)
            effects = [e for e in held["effects"].values() if e["operation"] == operation]
            self.assertEqual(len(effects), 1)
            self.assertIn(effects[0]["state"], {"intent", "unknown"})
            self.assertIn("cleanup_postcheck", effects[0])
            trace("held-record-checked")
            remaining_paths = [os.path.lexists(p) for p in paths]
            if failure != "unlink-started":
                self.assertTrue(all(remaining_paths))
            # Current store and a genuinely reopened store must both retain
            # the original allocation. No second intent or deletion is allowed.
            with self.assertRaises(Denied): original(owner, store, config)
            self.assertEqual(store.read(owner.lease_id), held)
            with ledger.Ledger(store.path, owner_uid=store.owner_uid, clock=store.clock) as reopened:
                with self.assertRaises(Denied): original(owner, reopened, config)
                self.assertEqual(reopened.read(owner.lease_id), held)
                with self.assertRaises(Denied): reopened.close(owner.lease_id)
            self.assertEqual([os.path.lexists(p) for p in paths], remaining_paths)
            if failure == "unlink-started":
                self.assertFalse(os.path.lexists(removed[0]))
            marker.write_bytes(ledger.canonical({"passed": True, "same_public_entry": method,
                "failure": failure, "persistent_original_guard": True, "native_acceptance": False}))
            raise FixtureStopped("expected-held-original-allocation")

        with mock.patch.object(storage, method, side_effect=caller):
            if failure in {"observation", "metadata-cap"}:
                try:
                    fixture.test_actual_signed_fixed_engine_exit_public_evidence_and_owned_cleanup_close()
                except AssertionError as error:
                    diagnostic = fixture.io.root / "atomic-caller-trace.json"
                    self.fail("real caller pipeline failed; " + (diagnostic.read_text() if diagnostic.exists() else "no caller entry"))
                self.assertEqual(fixture.store.read(fixture.lease)["state"], "closed")
            else:
                # The normal fixture expects closure. Its child deliberately
                # terminates on our proven HOLD, never fabricates a success.
                with self.assertRaises(AssertionError):
                    fixture.test_actual_signed_fixed_engine_exit_public_evidence_and_owned_cleanup_close()
        diagnostic = fixture.io.root / "atomic-caller-trace.json"
        self.assertTrue(marker.exists(), "child must finish every recovery/replay assertion; " + (diagnostic.read_text() if diagnostic.exists() else "no entry"))
        self.assertTrue(json.loads(marker.read_bytes())["passed"])

    def test_observation_failure_then_real_historical_maintenance_same_entry_succeeds(self):
        for method in ("release_engine", "delete_context"):
            with self.subTest(method=method): self.exercise(method, "observation")

    def test_real_sidecar_cap_failure_then_historical_maintenance_same_entry_succeeds(self):
        for method in ("release_engine", "delete_context"):
            with self.subTest(method=method): self.exercise(method, "metadata-cap")

    def test_durable_publication_return_failure_is_held_without_mutation_or_reuse(self):
        for method in ("release_engine", "delete_context"):
            with self.subTest(method=method): self.exercise(method, "commit-return")

    def test_deadline_after_atomic_publication_is_held_without_first_unlink_or_reuse(self):
        for method in ("release_engine", "delete_context"):
            with self.subTest(method=method): self.exercise(method, "deadline-after-publication")

    def test_first_actual_unlink_failure_retains_original_guard_and_denies_reentry(self):
        for method in ("release_engine", "delete_context"):
            with self.subTest(method=method): self.exercise(method, "unlink-started")

    def test_delegated_failed_or_skipped_setup_runs_registered_real_cleanup(self):
        real_setup = full.RootFullCoreFinalizationTests.setUp
        original_binary = ledger.ENGINE_EXECUTABLE
        for failure in (unittest.SkipTest, RuntimeError):
            with self.subTest(failure=failure.__name__):
                observed = {}
                def stopped_setup(instance):
                    real_setup(instance)
                    observed["binary"] = Path(instance.cpp.binary)
                    observed["root"] = instance.io.root
                    instance.addCleanup(observed.__setitem__, "cleanup_ran", True)
                    raise failure("fixture-setup-interrupted")
                class Probe(AtomicCleanupCallerTests):
                    def runTest(inner):
                        inner.exercise("release_engine", "observation")
                result = unittest.TestResult()
                with mock.patch.object(full.RootFullCoreFinalizationTests, "setUp", stopped_setup):
                    Probe("runTest").run(result)
                self.assertEqual(len(result.skipped), int(failure is unittest.SkipTest))
                self.assertEqual(len(result.errors), int(failure is RuntimeError))
                self.assertTrue(observed.get("cleanup_ran"))
                self.assertFalse(observed["binary"].exists())
                self.assertFalse(observed["root"].exists())
                self.assertEqual(ledger.ENGINE_EXECUTABLE, original_binary)
