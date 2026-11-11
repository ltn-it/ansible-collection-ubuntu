"""Real operating cell/Ledger/Unix/ELF; cgroup/fence/quota/HTTPS modeled.

The actual original child exits23 AFTER real Root ACK. Native terminal and
retained proof are minted by existing fixed factories using modeled HTTPS and
kernel observations. No fabricated retained Ledger record or operating PASS.
"""
from contextlib import contextmanager
from copy import deepcopy
import datetime as dt
import hashlib
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

import test_github_runner_incus_operating_ready_custody as ready_fixtures
from incus_lease_issuer import (cell_contract, cleanup_storage, engine_executor,
    engine_graph_prune as prune, engine_policy, identity, ledger, network_fence,
    operating_custody as custody, root_session)
from incus_lease_issuer.identity import Denied


class GraphBoundaryTests(unittest.TestCase):
    def test_no_job_path_approval_or_reader_and_root_required(self):
        with mock.patch.object(os, "geteuid", return_value=2101):
            with self.assertRaisesRegex(Denied, "graph-prune-root-required"):
                prune.prune_graph(None, None, None, session=None)
        for extra in ({"graph_path": "/job"}, {"approved": True}, {"reader": lambda: {}}):
            with self.assertRaises(TypeError):
                prune.prune_graph(None, None, None, session=None, **extra)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootGraphPruneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ready_fixtures.RootOperatingReadyCustodyTests.setUpClass()

    def setUp(self):
        self.io = ready_fixtures.RootOperatingReadyCustodyTests()
        self.io.setUp(); self.addCleanup(self.io.doCleanups)
        self.io.launch(); self.io.ready()
        self.io.supervisor.finish(self.io.owned)
        self.io.stopped_and_withdrawn()
        self.store, self.lease, self.registry = self.io.store, self.io.lease, self.io.registry
        self.graph = Path(self.io.descriptor["engine"]["storage_root"])
        layer = self.graph / "synthetic-public-ee-layer"
        layer.mkdir(mode=0o700)
        (layer / "recoverable.bin").write_bytes(b"public immutable fixture EE content" * 100)
        (layer / "recoverable.bin").chmod(0o600)
        self.outside = self.io.io.root / "must-remain.bin"
        self.outside.write_bytes(b"not graph content"); self.outside.chmod(0o600)
        (layer / "outside-link").symlink_to(self.outside)
        self.raw = Path(self.io.descriptor["output_path"]) / "operating-result.json"
        self.raw.write_bytes(b'{"synthetic_diagnostic":"unchanged raw data"}\n'); self.raw.chmod(0o600)
        self.spool = Path(self.io.descriptor["engine"]["runroot"] + ".public-evidence")
        self.spool.mkdir(mode=0o700)
        (self.spool / "preserved.bin").write_bytes(b"not an export receipt; preserved fixture sibling")
        (self.spool / "preserved.bin").chmod(0o600)
        self.bind_terminal()
        def remove(_path, _sha, owner, store, _worker, _config):
            effect = store.begin(self.lease, "fence-remove", "fence:" + self.lease)
            store.record(self.lease, effect, "verified", evidence_sha256="e" * 64)
        with self.model(), mock.patch.object(network_fence, "remove", side_effect=remove):
            custody.retain_stopped(str(self.io.runtime), self.io.runtime_sha,
                                  self.registry, ready_fixtures.SELECTOR, self.store, self.lease)
        self.assertEqual(self.store.read(self.lease)["state"], "retained")
        self.requests = list(self.io.server.requests)

    def bind_terminal(self):
        record = self.store.read(self.lease)
        who, policy = record["identity"], self.registry.select(ready_fixtures.SELECTOR).identity
        prefix = identity.API + "/repos/" + policy.repository
        actor = {"id": next(iter(policy.actor_ids)), "login": "fixture", "type": "User"}
        run = {"id": who["run_id"], "run_attempt": 1, "event": "push", "head_branch": "main",
            "head_sha": policy.caller_sha, "workflow_id": policy.workflow_id, "path": policy.workflow_path,
            "repository": {"id": policy.repository_id, "full_name": policy.repository, "private": False,
                           "owner": {"id": policy.owner_id}}, "actor": actor, "triggering_actor": actor,
            "referenced_workflows": [{"path": policy.reusable_repository + "/" + policy.reusable_path + "@" + policy.reusable_sha,
                                      "sha": policy.reusable_sha}]}
        completed = dt.datetime.fromtimestamp(self.store._now() - 1, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        job = {"id": who["job_id"], "run_id": who["run_id"], "run_attempt": 1, "head_sha": who["caller_sha"],
            "runner_id": who["runner_id"], "name": policy.required_native_job_name, "status": "completed",
            "conclusion": "failure", "check_run_url": prefix + "/check-runs/" + str(who["check_run_id"]),
            "completed_at": completed}
        check = {"id": who["check_run_id"], "head_sha": who["caller_sha"], "status": "completed", "conclusion": "failure"}
        routes = {prefix + "/actions/runs/" + str(who["run_id"]): run,
                  prefix + "/actions/jobs/" + str(who["job_id"]): job,
                  prefix + "/check-runs/" + str(who["check_run_id"]): check}
        with mock.patch.object(identity, "HTTPSReader", return_value=mock.Mock(read=lambda url: ledger.canonical(routes[url]))):
            proof = custody.observe_native_terminal(self.registry, ready_fixtures.SELECTOR, self.store, self.lease)
        self.store.bind_native_terminal(self.lease, proof)

    @contextmanager
    def model(self):
        """Only private kernel/native-engine/quota observations are models."""
        def retained(*_args):
            effect_id, effect = self.io.engine.engine_effect()
            return self.io.engine.manifest, effect_id, effect
        with mock.patch.object(engine_policy, "ENGINE", self.io.engine.original), \
             mock.patch.object(engine_executor, "_retained", side_effect=retained), \
             mock.patch.object(engine_executor, "_drained"), \
             mock.patch.object(network_fence, "verify_disabled"), \
             mock.patch.object(cleanup_storage, "_cleanup_limits", return_value=(4096, 10)):
            yield

    @contextmanager
    def session(self):
        with root_session._session(str(self.io.io.config), self.io.io.sha) as session:
            config = root_session._require_session(session)
            owner = cell_contract.owned_cell_for_cleanup(self.registry, ready_fixtures.SELECTOR, self.store, self.lease)
            yield owner, config, session

    def run_prune(self):
        with self.model(), self.session() as (owner, config, session):
            return prune.prune_graph(owner, self.store, config, session=session)

    def preserved(self):
        roots = [Path(self.io.descriptor["engine"]["runroot"]), Path(self.io.descriptor["output_path"]),
                 Path(self.io.descriptor["context_path"]), self.spool]
        return {str(path): (path.stat().st_dev, path.stat().st_ino,
                 hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
                for root in roots for path in (root, *root.rglob("*")) if not path.is_symlink()}

    def test_prune_children_only_preserves_captures_vm_roots_spool_and_retention(self):
        before = self.preserved()
        graph_id = self.graph.stat().st_dev, self.graph.stat().st_ino
        record = deepcopy(self.store.read(self.lease))
        remote = deepcopy(self.io.server.resources)
        result = self.run_prune()
        self.assertEqual(list(self.graph.iterdir()), [])
        self.assertEqual((self.graph.stat().st_dev, self.graph.stat().st_ino), graph_id)
        self.assertEqual(self.preserved(), before)
        self.assertEqual(self.io.server.resources, remote)
        self.assertEqual(self.outside.read_bytes(), b"not graph content")
        after = self.store.read(self.lease)
        self.assertEqual(after["custody"], record["custody"])
        self.assertEqual(after["state"], "retained")
        self.assertEqual(after["custody"]["storage_reservation_bytes"], 10 * 1024**3)
        effects = [row for row in after["effects"].values() if row["operation"] == "engine-graph-prune"]
        self.assertEqual(len(effects), 1); self.assertEqual(effects[0]["state"], "verified")
        self.assertEqual(result.evidence_sha256, effects[0]["evidence_sha256"])
        self.assertTrue(all(row[0] == "GET" for row in self.io.server.requests[len(self.requests):]))
        before = self.store.read(self.lease)
        self.assertEqual(self.run_prune(), result)
        self.assertEqual(self.store.read(self.lease), before)

    def test_corrupt_capture_is_preserved_and_prevents_any_graph_effect(self):
        capture = Path(self.io.descriptor["engine"]["runroot"]) / "stdout.log"
        capture.write_bytes(b"drift")
        with self.assertRaises(Denied):
            self.run_prune()
        self.assertTrue(any(self.graph.iterdir()))
        self.assertFalse(any(row["operation"] == "engine-graph-prune" for row in self.store.read(self.lease)["effects"].values()))
        self.assertEqual(capture.read_bytes(), b"drift")

    def barrier_failure(self, *, expired):
        before = self.preserved()
        graph_id = self.graph.stat().st_dev, self.graph.stat().st_ino
        actual_fsync, actual_deadline = os.fsync, cleanup_storage._deadline
        crossed = [False]
        def barrier(fd):
            if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == graph_id:
                if not expired:
                    raise OSError("injected final directory barrier failure")
                actual_fsync(fd)
                crossed[0] = True
                return
            actual_fsync(fd)
        def deadline(end):
            if crossed[0]:
                raise Denied("cleanup-storage-budget")
            actual_deadline(end)
        with mock.patch.object(cleanup_storage.os, "fsync", new=barrier), \
             mock.patch.object(cleanup_storage, "_deadline", new=deadline):
            with self.assertRaises(prune.GraphPruneUnknown): self.run_prune()
        record = self.store.read(self.lease)
        effects = [row for row in record["effects"].values() if row["operation"] == "engine-graph-prune"]
        self.assertEqual(len(effects), 1)
        self.assertEqual(effects[0]["state"], "unknown")
        self.assertEqual((self.graph.stat().st_dev, self.graph.stat().st_ino), graph_id)
        self.assertEqual(self.preserved(), before)
        with self.assertRaises(Denied): self.run_prune()
        self.assertEqual(self.store.read(self.lease), record)

    def test_final_directory_fsync_failure_is_durably_unknown_never_verified_or_retried(self):
        self.barrier_failure(expired=False)

    def test_deadline_after_final_directory_fsync_is_unknown_never_verified_or_retried(self):
        self.barrier_failure(expired=True)

    def test_original_graph_inode_and_foreign_mount_denials_preserve_owned_data(self):
        moved = self.graph.with_name(self.graph.name + "-original")
        self.graph.rename(moved); self.graph.mkdir(mode=0o700)
        with self.assertRaises(Denied):
            self.run_prune()
        self.assertTrue(any(moved.iterdir()))
        self.graph.rmdir(); moved.rename(self.graph)
        actual = cleanup_storage.storage_quota._mount_id
        with mock.patch.object(cleanup_storage.storage_quota, "_mount_id", side_effect=lambda fd: actual(fd) + (0 if os.fstat(fd).st_ino == self.graph.stat().st_ino else 1)):
            with self.assertRaises(Denied):
                self.run_prune()
        self.assertTrue(any(self.graph.iterdir()))

    def test_live_descendant_or_running_replaced_vm_denies_without_new_intent(self):
        with self.model(), self.session() as (owner, config, session), \
             mock.patch.object(engine_executor, "_drained", side_effect=Denied("engine-descendants-not-drained")):
            with self.assertRaises(Denied):
                prune.prune_graph(owner, self.store, config, session=session)
        self.io.state(True)
        with self.assertRaises(Denied):
            self.run_prune()
        self.io.state(False)
        self.io.vm["config"]["volatile.uuid"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        with self.assertRaises(Denied):
            self.run_prune()
        self.assertTrue(any(self.graph.iterdir()))

    def test_verified_reentry_denies_changed_raw_diagnostic_without_deleting_it(self):
        self.run_prune()
        original = self.raw.read_bytes()
        self.raw.write_bytes(b'{"synthetic_diagnostic":"post-prune drift"}\n')
        before = self.store.read(self.lease)
        with mock.patch.object(cleanup_storage, "_remove_tree") as remove:
            with self.assertRaises(Denied):
                self.run_prune()
            remove.assert_not_called()
        self.assertEqual(self.store.read(self.lease), before)
        self.assertNotEqual(self.raw.read_bytes(), original)

    def test_partial_unlink_unknown_is_not_replayed_or_adopted(self):
        original = cleanup_storage._remove_tree
        def fail_after_owned_removal(fd, inventory, end):
            original(fd, inventory, end)
            raise OSError("fixed fixture post-unlink failure")
        with mock.patch.object(cleanup_storage, "_remove_tree", side_effect=fail_after_owned_removal):
            with self.assertRaises(prune.GraphPruneUnknown):
                self.run_prune()
        self.assertEqual(list(self.graph.iterdir()), [])
        before = self.store.read(self.lease)
        self.assertEqual([row["state"] for row in before["effects"].values()
                          if row["operation"] == "engine-graph-prune"], ["unknown"])
        with mock.patch.object(cleanup_storage, "_remove_tree") as remove:
            with self.assertRaises(Denied):
                self.run_prune()
            remove.assert_not_called()
        self.assertEqual(self.store.read(self.lease), before)


if __name__ == "__main__":
    unittest.main()
