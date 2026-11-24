"""Early retirement applies only to positive, protected pre-VM evidence."""

from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "roles/github_runner/files"))
from incus_lease_issuer import identity, ledger, operating_cells, policy_registry, startup_retirement


class StartupRetirementTests(unittest.TestCase):
    def setUp(self):
        self.now = 500
        self.policy = {"custodian_ref": "owner", "storage_ref": "private",
                       "approval_ref": "per-scope", "retention_seconds": 14400,
                       "max_lease_seconds": 900, "startup_retirement": startup_retirement.POLICY}
        self.record = {
            "state": "prepared", "policy_sha256": ledger.digest(self.policy), "cell_sha256": "1" * 64,
            "identity": {"run_id": 100, "check_run_id": 103, "job_id": 103,
                         "caller_sha": "2" * 40, "reusable_sha": "3" * 40},
            "native_terminal": {"schema": 1, "repository": "ltn-it/ansible-collection-supplementary",
                                "repository_id": 1, "run_id": 100, "run_attempt": 1, "check_run_id": 103,
                                "job_id": 103, "source_sha": "2" * 40, "controller_sha": "3" * 40,
                                "conclusion": "failure", "completed_at": 402, "observed_at": 404,
                                "native_sha256": "4" * 64, "cell_sha256": "1" * 64},
            "effects": {"scope": {"operation": "project-create", "state": "verified"}},
        }
        self.refresh_bindings()

    def refresh_bindings(self):
        self.archive = {"original": ledger.digest(self.record), "terminal": ledger.digest(self.record["native_terminal"]),
                        "failure": "a" * 64, "inventory": "b" * 64, "sha256": "c" * 64}
        self.observations = {"original": self.archive["original"], "inventory": self.archive["inventory"],
                             "at": 499, "startup_boundary": startup_retirement.START_BOUNDARY,
                             "start_effect": None, "exclusive_ownership": True, "never_started_vm": True,
                             "active_consumers": 0, "access_withdrawn": True}

    def floor(self, *, selector=None, profile="heavy", **changes):
        scenario, target = "keycloak-heavy", "ubuntu-24.04"
        if selector is None:
            selector = policy_registry.profile_selector("heavy", scenario, target)
        return startup_retirement.effective_floor(
            self.record, self.policy, selector=selector, profile=profile, scenario=scenario, target=target,
            archive=self.archive, observations=self.observations | changes, now=self.now)

    def test_proved_abort_before_engine_can_be_retired_without_delay(self):
        original = deepcopy(self.record)
        self.assertEqual(self.floor(), 499)
        self.assertEqual(self.record, original)

    def test_previous_bound_lease_keeps_four_hours(self):
        self.policy.pop("startup_retirement")
        self.record["policy_sha256"] = ledger.digest(self.policy)
        self.refresh_bindings()
        self.assertEqual(self.floor(), 14802)

    def test_all_reserved_operating_cells_keep_the_four_hour_floor(self):
        for case in operating_cells.CASES:
            with self.subTest(case=case):
                selector = operating_cells.selector(case)
                self.assertEqual(self.floor(selector=selector), 14802)
                self.assertEqual(self.floor(selector=selector, profile="operating"), 14802)
        self.assertEqual(self.floor(profile="operating"), 14802)

    def test_ambiguous_resource_identity_vm_or_consumer_evidence_holds(self):
        for mismatch in ({"exclusive_ownership": False}, {"never_started_vm": False},
                         {"active_consumers": 1}, {"active_consumers": False}, {"access_withdrawn": False},
                         {"at": 399}, {"at": 501}, {"inventory": "f" * 64}, {"original": "d" * 64}):
            with self.subTest(mismatch=mismatch), self.assertRaises(identity.Denied):
                self.floor(**mismatch)

    def test_archive_from_another_job_and_unknown_creator_never_authorize(self):
        self.archive["terminal"] = "5" * 64
        with self.assertRaises(identity.Denied):
            self.floor()
        self.record["effects"]["scope"]["state"] = "unknown"
        self.refresh_bindings()
        with self.assertRaises(identity.Denied):
            self.floor()

    def test_oci_exit_does_not_prove_workload_was_never_started(self):
        self.record["effects"]["start"] = {"operation": "engine-start", "state": "unknown",
                                           "engine_exit": {"exit_code": 126}}
        self.refresh_bindings()
        original = deepcopy(self.record)
        with self.assertRaises(identity.Denied):
            self.floor(startup_boundary="root-attested-pre-workload-abort",
                       start_effect=ledger.digest(self.record["effects"]["start"]))
        with self.assertRaises(identity.Denied):
            self.floor()
        self.assertEqual(self.record, original)

    def test_later_deleted_vm_is_not_a_never_allocated_vm(self):
        self.record["owned_instance"] = {"name": "formerly-present"}
        self.record["effects"]["delete"] = {"operation": "instance-delete", "state": "verified"}
        self.refresh_bindings()
        with self.assertRaises(identity.Denied):
            self.floor()
        # The creation/deletion history cannot be waived even by a broken
        # external inventory that projects the now-empty project.
        self.record.pop("owned_instance")
        self.refresh_bindings()
        with self.assertRaises(identity.Denied):
            self.floor()

    def test_post_engine_readback_requires_complete_capture_and_empty_project(self):
        from incus_lease_issuer import (cell_contract, cleanup_storage, engine_graph_prune, finalization,
                                      incus_admin, incus_mutation, network_fence, operating_custody)

        lease, project, cert = "a" * 32, "proof-project", "certificate:" + "b" * 64
        selector = policy_registry.profile_selector("heavy", "keycloak-heavy", "ubuntu-24.04")
        owner = SimpleNamespace(incus={"project": project, "network": "proof-bridge", "pool": "proof-pool",
                                      "instance": "keycloak-heavy"}, creator_targets={"certificate-create": cert},
            engine_descriptor_bytes=ledger.canonical({"environment": {"QUALITY_INPUT_PROFILE": "heavy",
                "QUALITY_INPUT_SCENARIO": "keycloak-heavy", "QUALITY_INPUT_TARGET": "ubuntu-24.04"}}))
        actual = {"observed_at": 401, "signal": None, "exit_code": 1,
                  "stdout_state": "complete", "stderr_state": "complete"}
        start = {"operation": "engine-start", "state": "verified", "engine_exit": actual}
        self.record["worker"] = {"uid": 1, "runner_id": 78, "pid": 2, "start_ticks": 3,
                                 "boot_id": "11111111-1111-1111-1111-111111111111"}
        self.record["effects"].update(start=start,
            revoke={"operation": "certificate-revoke", "state": "verified", "target": cert})
        store = mock.Mock()
        store.read.return_value = self.record
        store._now.return_value = self.now
        admin = mock.Mock()
        cleanup = mock.Mock()
        cleanup.certificates_absent.return_value = True
        cleanup.readback.return_value = {"state": "required_fields_match"}
        cleanup._verify_delete_scope.side_effect = lambda kind: {"kind": kind, "used_by": []}
        cleanup.quiet_project.return_value = {"state": "quiet_observed"}
        finalizer = object.__new__(finalization.RootFinalizer)
        config = SimpleNamespace(incus_socket_path="/run/proof/incus.sock")
        with ExitStack() as patches:
            for subject, name, value in (
                (cell_contract, "owned_cell_for_cleanup", owner), (finalizer, "_fresh", config),
                (cleanup_storage, "_drain_engine", (None, start)), (engine_graph_prune, "_diagnostics", "d" * 64),
                (network_fence, "verify_disabled", None), (incus_admin, "RootIncusAdmin", admin),
                (incus_mutation, "RootIncusCleanup", cleanup),
            ):
                patches.enter_context(mock.patch.object(subject, name, return_value=value))
            admin.pool_volumes.side_effect = [[{"project": "unrelated"}], [{"project": "unrelated"}]]
            original = deepcopy(self.record)
            proof = finalizer._observe_failed_engine_without_vm(None, None, selector, store, lease)
            self.assertEqual(proof["original_sha256"], ledger.digest(original))
            self.assertEqual(proof["engine_exit_sha256"], ledger.digest(actual))
            self.assertEqual(cleanup.quiet_project.call_count, 2)
            self.assertEqual(self.record, original)
            self.assertFalse(any(call[0] not in {"read", "_now"} for call in store.mock_calls))
            with self.assertRaisesRegex(identity.Denied, "custody-retention-not-elapsed"):
                operating_custody.cleanup_allowed_record(self.record, self.policy, self.now)

            for row in ({"project": project}, {"name": "ambiguous"}):
                admin.pool_volumes.side_effect = [[], [row]]
                with self.subTest(volume=row), self.assertRaisesRegex(identity.Denied, "failure-observation-volumes"):
                    finalizer._observe_failed_engine_without_vm(None, None, selector, store, lease)
            admin.pool_volumes.side_effect = [[], []]
            cleanup.quiet_project.side_effect = [{"state": "quiet_observed"}, identity.Denied("mutation-project-not-quiet")]
            with self.assertRaisesRegex(identity.Denied, "mutation-project-not-quiet"):
                finalizer._observe_failed_engine_without_vm(None, None, selector, store, lease)
            admin.pool_volumes.side_effect = [[], []]
            cleanup.quiet_project.side_effect = None
            cleanup._verify_delete_scope.side_effect = [
                {"used_by": []}, {"used_by": []}, {"used_by": ["/1.0/profiles/default"]}, {"used_by": []},
            ]
            with self.assertRaisesRegex(identity.Denied, "failure-observation-drift"):
                finalizer._observe_failed_engine_without_vm(None, None, selector, store, lease)
            self.record["owned_instance"] = {"name": "bound-vm"}
            with self.assertRaisesRegex(identity.Denied, "failure-observation-unresolved"):
                finalizer._observe_failed_engine_without_vm(None, None, selector, store, lease)
            del self.record["owned_instance"]
            actual["stderr_state"] = "incomplete"
            with self.assertRaisesRegex(identity.Denied, "failure-observation-original-exit"):
                finalizer._observe_failed_engine_without_vm(None, None, selector, store, lease)

    @unittest.skipUnless(os.geteuid() == 0 and Path("/run/proof").is_dir(), "isolated Root archive fixture")
    def test_private_archive_is_bound_to_the_exact_original_and_every_member(self):
        with TemporaryDirectory(dir="/run/proof") as temporary:
            archive = Path(temporary)
            members = {"original": ledger.canonical(self.record), "terminal": ledger.canonical(self.record["native_terminal"]),
                       "failure": ledger.canonical({"reason": "pre-engine fixture"}),
                       "inventory": ledger.canonical({"scope": "exact fixture"})}
            manifest = {key: hashlib.sha256(data).hexdigest() for key, data in members.items()}
            for name, data in (members | {"manifest": ledger.canonical(manifest)}).items():
                path = archive / (name + ".json")
                path.write_bytes(data)
                path.chmod(0o600)
            binding = ledger.digest(manifest)
            self.assertEqual(startup_retirement.archived_original(str(archive), binding, self.record),
                             manifest | {"sha256": binding})
            evidence_path = archive / "failure.json"
            evidence_path.write_bytes(b"replacement")
            with self.assertRaises(identity.Denied):
                startup_retirement.archived_original(str(archive), binding, self.record)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and Path("/run/proof").is_dir(),
                     "isolated Linux Root archive fixture")
class PostEngineArchiveTests(unittest.TestCase):
    def setUp(self):
        from incus_lease_issuer import cell_contract, generation_publisher, root_session

        self.root = Path(self.enterContext(TemporaryDirectory(dir="/run/proof")))
        bank, self.runroot = self.root / "ledger", self.root / "runroot"
        generation_publisher._mkdir(bank)
        generation_publisher._mkdir(self.runroot)
        ledger.Ledger.initialize(str(bank))
        self.store = self.enterContext(ledger.Ledger(str(bank), clock=lambda: 500))
        self.lease, manifest_sha = "a" * 32, "1" * 64
        binding = StartupRetirementTests()
        binding.setUp()
        self.record = binding.record
        capture = {"manifest_sha256": manifest_sha, "total_limit": 64}
        process = {"pid": 10, "start_ticks": 11, "boot_id": "22ee1b5a-fee8-4294-bf0b-4a151df0876d"}
        actual = process | {"container_id": "b" * 64, "manifest_sha256": manifest_sha,
                            "exit_code": 1, "signal": None, "observed_at": 400}
        self.logs = {"stdout.log": b"synthetic output\xff\n", "stderr.log": b""}
        for name, raw in self.logs.items():
            path = self.runroot / name
            generation_publisher._write(path, raw)
            info, stream = path.stat(), path.stem
            capture.update({stream + "_device": info.st_dev, stream + "_inode": info.st_ino, stream + "_limit": 32})
            actual.update({stream + "_bytes": len(raw), stream + "_sha256": hashlib.sha256(raw).hexdigest(),
                           stream + "_state": "complete"})
        self.record["effects"]["c" * 32] = {"operation": "engine-start", "target": "engine:lit-lease-" + self.lease,
            "state": "verified", "at": 300, "engine_process": process, "engine_capture": capture,
            "engine_container_id": actual["container_id"], "engine_exit": actual}
        registry = SimpleNamespace(path=str(self.root / "registry"), sha256="c" * 64)
        self.owner = cell_contract.OwnedCellForCleanup(registry, "heavy:keycloak", self.lease, "1" * 64, 700,
            "3" * 64, str(self.root / "descriptor"), ledger.canonical({"engine": {"runroot": str(self.runroot)}}),
            "4" * 64, manifest_sha, b"{}", b"{}", "5" * 64, b"{}", "6" * 64)
        self.folder = startup_retirement._post_engine_archive_path(self.store, self.lease)
        self.enterContext(mock.patch.object(self.store, "read", side_effect=lambda _: deepcopy(self.record)))
        self.enterContext(mock.patch.object(cell_contract, "owned_cell_for_cleanup", return_value=self.owner))
        self.enterContext(mock.patch.object(root_session, "_require_session",
            return_value=SimpleNamespace(registry_path=registry.path, registry_sha256=registry.sha256)))

    def publish(self):
        return startup_retirement._publish_post_engine_archive(None, self.owner, self.store)

    def readback(self, binding):
        return startup_retirement._read_post_engine_archive(self.store, self.lease, binding)

    def test_interrupted_before_publish_leaves_no_archive_and_retry_seals_binary_and_empty_streams(self):
        with mock.patch.object(startup_retirement, "_publish_staged", side_effect=OSError("fixture interruption")):
            with self.assertRaises(OSError):
                self.publish()
        self.assertFalse(self.folder.exists())
        self.assertEqual(list(self.folder.parent.iterdir()), [])
        receipt = self.publish()
        self.assertEqual(self.readback(receipt[1]), receipt)
        for name, raw in self.logs.items():
            self.assertEqual((self.folder / name).read_bytes(), raw)
            self.assertEqual((self.folder / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.folder / "terminal.json").read_bytes(), ledger.canonical(self.record["native_terminal"]))
        self.assertEqual(self.folder.stat().st_mode & 0o777, 0o700)

    def test_lost_reply_after_publish_reuses_exact_archive_without_reading_source_or_modifying_destination(self):
        publish_stage = startup_retirement._publish_staged

        def publish_then_lose_reply(staged, folder):
            publish_stage(staged, folder)
            raise OSError("fixture lost publisher acknowledgement")

        with mock.patch.object(startup_retirement, "_publish_staged", side_effect=publish_then_lose_reply):
            with self.assertRaises(OSError):
                self.publish()
        inodes = {path.name: path.stat().st_ino for path in self.folder.iterdir()}
        for name in self.logs:
            (self.runroot / name).unlink()
        receipt = self.publish()
        self.assertEqual(self.readback(receipt[1]), receipt)
        self.assertEqual({path.name: path.stat().st_ino for path in self.folder.iterdir()}, inodes)

    def test_orphan_stage_holds_without_creating_another_copy(self):
        self.folder.parent.mkdir(mode=0o700)
        orphan = self.folder.with_name("." + self.lease + ".interrupted")
        orphan.mkdir(mode=0o700)
        with self.assertRaisesRegex(identity.Denied, "post-engine-archive-staging-held"):
            self.publish()
        self.assertEqual(list(self.folder.parent.iterdir()), [orphan])

    def test_retry_syncs_the_parent_directory_after_an_interrupted_mkdir(self):
        from incus_lease_issuer import generation_publisher

        def make_then_interrupt(path):
            path.mkdir(mode=0o700)
            raise OSError("fixture lost parent mkdir acknowledgement")

        with mock.patch.object(generation_publisher, "_mkdir", side_effect=make_then_interrupt):
            with self.assertRaises(OSError):
                self.publish()
        self.assertTrue(self.folder.parent.is_dir())
        self.assertFalse(self.folder.exists())
        synced, original_fsync = [], os.fsync

        def observe_fsync(fd):
            synced.append(os.fstat(fd).st_ino)
            return original_fsync(fd)

        with mock.patch.object(os, "fsync", side_effect=observe_fsync):
            receipt = self.publish()
        self.assertEqual(synced[0], self.root.stat().st_ino)
        self.assertEqual(self.readback(receipt[1]), receipt)

    def test_source_and_archive_hash_drift_deny_without_adoption_or_overwrite(self):
        source = self.runroot / "stdout.log"
        original = self.logs[source.name]
        changed = b"x" * len(original)
        source.write_bytes(changed)
        with self.assertRaisesRegex(identity.Denied, "engine-capture-file-drift"):
            self.publish()
        self.assertFalse(self.folder.exists())
        source.write_bytes(original)
        receipt = self.publish()
        with self.assertRaisesRegex(identity.Denied, "post-engine-archive-manifest-binding"):
            self.readback("0" * 64)
        terminal = self.record["native_terminal"]
        original_native_sha = terminal["native_sha256"]
        terminal["native_sha256"] = "e" * 64
        with self.assertRaisesRegex(identity.Denied, "post-engine-archive-manifest-binding"):
            self.readback(receipt[1])
        terminal["native_sha256"] = original_native_sha
        archive = self.folder / source.name
        archive.write_bytes(changed)
        with self.assertRaisesRegex(identity.Denied, "post-engine-archive-member-drift"):
            self.readback(receipt[1])
        with self.assertRaisesRegex(identity.Denied, "post-engine-archive-member-drift"):
            self.publish()
        self.assertEqual(archive.read_bytes(), changed)

    def completed_cleanup(self, with_image=False):
        target_by_operation = {
            "project-create": "project:proof-project",
            "network-create": "network:default:proof-bridge",
            "engine-prepare": "engine:" + self.lease,
            "context-create": "context:" + self.record["cell_sha256"],
            "fence-create": "fence:" + self.lease,
            "slice-create": "slice:" + self.lease,
            "certificate-create": "certificate:" + "7" * 64,
        }
        prepare = {operation: {"operation": operation, "target": target, "state": "verified", "at": 300}
                   for operation, target in target_by_operation.items()}
        withdrawals = {
            "certificate-revoke": target_by_operation["certificate-create"],
            "engine-stop": "engine:lit-lease-" + self.lease,
            "fence-disable": target_by_operation["fence-create"],
        }
        if with_image:
            target_by_operation["image-copy"] = "image:proof-project:" + operating_cells.IMAGE
            prepare["image-copy"] = {"operation": "image-copy", "target": target_by_operation["image-copy"],
                                     "state": "verified", "at": 300}
        self.record["effects"].pop("scope")
        self.record["effects"].update(prepare)
        for operation, target in withdrawals.items():
            self.record["effects"][operation] = {
                "operation": operation, "target": target, "state": "verified", "at": 401,
            }
        original = deepcopy(self.record)
        _, binding = self.publish()
        for creator, target in target_by_operation.items():
            operation = ledger.CREATES[creator]
            if operation not in withdrawals:
                self.record["effects"][operation] = {
                    "operation": operation, "target": target, "state": "verified", "at": 410,
                }
        return original, binding

    def read_cleanup_journal(self, binding):
        return startup_retirement._read_post_engine_cleanup_journal(self.store, self.lease, binding)

    def test_verified_cleanup_reopens_original_archive_and_runner_stays_held(self):
        original, binding = self.completed_cleanup()
        for name in self.logs:
            (self.runroot / name).unlink()
        with (mock.patch.object(self.store, "require_cleanup_complete") as require_complete,
              mock.patch.object(self.store, "close") as close):
            journal = self.read_cleanup_journal(binding)
        require_complete.assert_called_once_with(self.lease)
        close.assert_not_called()
        self.assertEqual(journal, {
            "schema": 1, "state": "awaiting-independent-absence", "lease_id": self.lease,
            "archive_sha256": binding, "original_sha256": ledger.digest(original),
            "journal_sha256": ledger.digest(self.record), "native_acceptance": False,
        })
        with self.assertRaisesRegex(identity.Denied, "engine-other-pilot-lease-active"):
            ledger.Ledger._require_exclusive_preparation({"leases": {self.lease: self.record}})

    def test_unknown_or_crossed_delete_is_held_before_cleanup_postcheck(self):
        _, binding = self.completed_cleanup()
        operation = self.record["effects"]["project-delete"]
        with mock.patch.object(self.store, "require_cleanup_complete") as require_complete:
            for change in ({"state": "unknown"}, {"target": "project:other"}, {"at": 390}):
                original = dict(operation)
                operation.update(change)
                with self.subTest(change=change), self.assertRaisesRegex(identity.Denied, "post-engine-cleanup-journal-held"):
                    self.read_cleanup_journal(binding)
                operation.update(original)
            require_complete.assert_not_called()

    def test_private_image_requires_its_own_verified_delete_before_complete_readback(self):
        _, binding = self.completed_cleanup(with_image=True)
        removed = self.record["effects"].pop("image-delete")
        with mock.patch.object(self.store, "require_cleanup_complete") as require_complete:
            with self.assertRaisesRegex(identity.Denied, "post-engine-cleanup-journal-held"):
                self.read_cleanup_journal(binding)
            progress = startup_retirement._read_post_engine_cleanup_journal(self.store, self.lease, binding, complete=False)
            self.assertTrue(progress["cleanup_started"])
            require_complete.assert_not_called()
            self.record["effects"]["image-delete"] = removed
            self.assertEqual(self.read_cleanup_journal(binding)["state"], "awaiting-independent-absence")

    def test_independent_readback_is_private_immutable_and_does_not_touch_the_archive(self):
        _, binding = self.completed_cleanup()
        value = {"schema": 1, "archive_sha256": binding}
        signature = startup_retirement._publish_post_engine_readback(self.store, self.lease, value)
        self.assertEqual(signature, startup_retirement._publish_post_engine_readback(self.store, self.lease, value))
        self.assertEqual(startup_retirement._read_post_engine_readback(self.store, self.lease, signature), value)
        with self.assertRaisesRegex(identity.Denied, "post-engine-readback-drift"):
            startup_retirement._publish_post_engine_readback(self.store, self.lease, value | {"schema": 2})
        self.assertEqual(set(member.name for member in self.folder.iterdir()),
                         {"original.json", "terminal.json", "stdout.log", "stderr.log", "manifest.json"})

    def test_original_record_drift_and_pending_cleanup_postcheck_hold(self):
        _, binding = self.completed_cleanup()
        with mock.patch.object(self.store, "require_cleanup_complete",
                               side_effect=identity.Denied("cleanup-postcheck-held")) as require_complete:
            with self.assertRaisesRegex(identity.Denied, "cleanup-postcheck-held"):
                self.read_cleanup_journal(binding)
            self.record["native_terminal"]["native_sha256"] = "e" * 64
            with self.assertRaisesRegex(identity.Denied, "post-engine-cleanup-original-drift"):
                self.read_cleanup_journal(binding)
            require_complete.assert_called_once_with(self.lease)

    def test_incomplete_capture_holds_before_archive_creation(self):
        self.record["effects"]["c" * 32]["engine_exit"]["stderr_state"] = "incomplete"
        with self.assertRaisesRegex(identity.Denied, "post-engine-archive-complete-exit"):
            self.publish()
        self.assertFalse(self.folder.parent.exists())


class PostEngineFinalizerTests(unittest.TestCase):
    def setUp(self):
        from incus_lease_issuer import finalization, root_session

        self.lease_id = "a" * 32
        self.permit_sha = "1" * 64
        self.readback_sha = "2" * 64
        self.finalizer = object.__new__(finalization.RootFinalizer)
        self.finalizer._runtime = SimpleNamespace(preparation_config_path="/root/preparation.json",
                                                  preparation_config_sha256="b" * 64)
        self.sessions = self.enterContext(mock.patch.object(root_session, "_session"))
        self.store = mock.Mock()
        self.record = {"state": "prepared", "worker": {}, "effects": {}}
        self.store.read.return_value = self.record
        self.enterContext(mock.patch.object(ledger, "Worker"))
        self.target = (mock.sentinel.registry, "heavy-keycloak-heavy-ubuntu-24.04", self.store, self.lease_id, self.permit_sha)
        self.permit = {"archive_sha256": "3" * 64, "original_sha256": "4" * 64}
        self.cleanup = mock.Mock()
        self.cleanup.certificates_absent.return_value = True
        self.owner = SimpleNamespace(incus={"project": "proof-project", "network": "proof-network"})
        self.config = SimpleNamespace(operation_wait_seconds=1)
        self.progress = {"cleanup_started": False}
        self.enterContext(mock.patch.object(self.finalizer, "_post_engine_scope",
            return_value=(self.permit, self.progress, self.record, self.owner, self.config, self.cleanup)))
        self.enterContext(mock.patch.object(finalization.network_fence, "verify_disabled"))

    def test_first_mutation_requires_fresh_permit_and_respects_the_private_copy(self):
        image = "image:proof-project:" + operating_cells.IMAGE
        self.record["effects"]["copy"] = {"operation": "image-copy", "target": image}
        awaiting = {"state": "awaiting-independent-absence", "native_acceptance": False}
        with (mock.patch.object(self.finalizer, "_observe_failed_engine_without_vm") as observe,
              mock.patch.object(startup_retirement, "_require_post_engine_observation", create=True) as recheck,
              mock.patch.object(startup_retirement, "_read_post_engine_permit", create=True) as permit,
              mock.patch.object(self.finalizer, "_release_owned_resources") as release,
              mock.patch.object(startup_retirement, "_read_post_engine_cleanup_journal", return_value=awaiting)):
            with self.assertRaisesRegex(identity.Denied, "post-engine-cleanup-denied"):
                self.finalizer.finalize_post_engine_failure(*self.target)
            release.assert_not_called()

            permit.return_value = self.permit
            self.assertEqual(self.finalizer.finalize_post_engine_failure(*self.target), awaiting)
        recheck.assert_called_with(self.permit, observe.return_value, self.store._now.return_value)
        self.assertEqual(release.call_args.args[-1], image)
        self.store.close.assert_not_called()

    def test_verified_cleanup_resume_holds_if_original_project_returned(self):
        self.progress["cleanup_started"] = True
        self.record["effects"]["delete"] = {"operation": "project-delete", "target": "project:proof-project"}
        self.cleanup.readback.return_value = {"state": "required_fields_match"}
        with (mock.patch.object(self.finalizer, "_release_owned_resources") as release,
              self.assertRaisesRegex(identity.Denied, "post-engine-cleanup-denied")):
            self.finalizer.finalize_post_engine_failure(*self.target)
        release.assert_not_called()
        self.store.close.assert_not_called()

    def test_independent_absence_reacquires_storage_witnesses_and_holds_on_returned_volume(self):
        from incus_lease_issuer import cleanup_storage, finalization

        storage = {"cleanup_postcheck": "nonce", "cleanup_observation": {"name": "sidecar"}}
        self.cleanup.readback.return_value = {"state": "absent_observed"}
        with (
            mock.patch.object(cleanup_storage, "_reconcile_verified_postchecks") as refresh,
            mock.patch.object(self.finalizer, "_fresh"),
            mock.patch.object(finalization.engine_executor, "_slice_inactive"),
            mock.patch.object(finalization.network_fence, "verify_disabled", return_value={"admitted": 0}),
            mock.patch.object(startup_retirement, "_read_post_engine_permit", return_value=self.permit, create=True),
            mock.patch.object(startup_retirement, "_read_post_engine_cleanup_journal", return_value={}),
        ):
            with self.assertRaisesRegex(identity.Denied, "post-engine-independent-storage-witness-required"):
                self.finalizer._post_engine_absence(mock.sentinel.session, *self.target)
            refresh.assert_not_called()
            self.record["effects"].update({operation: storage | {"operation": operation}
                                           for operation in ("engine-release", "context-delete")})
            self.cleanup._client.pool_volumes.return_value = [{"project": self.owner.incus["project"]}]
            with self.assertRaisesRegex(identity.Denied, "post-engine-pool-volume-returned"):
                self.finalizer._post_engine_absence(mock.sentinel.session, *self.target)
            self.cleanup._client.pool_volumes.return_value = []
            proof = self.finalizer._post_engine_absence(mock.sentinel.session, *self.target)
        self.assertEqual(proof["state"], "verified-absence")
        self.assertEqual([call.kwargs for call in refresh.call_args_list], [{"refresh": True}, {"refresh": True}])
        self.store.close.assert_not_called()

    def test_readback_and_close_use_separate_sessions_and_recheck_before_close(self):
        self.record = {"state": "prepared"}
        self.store.read.return_value = self.record
        proof = {"state": "verified-absence", "journal_sha256": ledger.digest(self.record), "native_acceptance": False}
        with (mock.patch.object(self.finalizer, "_post_engine_absence", return_value=proof) as observe,
              mock.patch.object(startup_retirement, "_publish_post_engine_readback", return_value=self.readback_sha),
              mock.patch.object(startup_retirement, "_read_post_engine_readback", side_effect=FileNotFoundError) as read):
            self.assertEqual(self.finalizer.readback_post_engine_failure(*self.target)["readback_sha256"], self.readback_sha)
            self.store.close.assert_not_called()
            with self.assertRaises(FileNotFoundError):
                self.finalizer.close_post_engine_failure(*self.target, self.readback_sha)
            self.store.close.assert_not_called()
            read.side_effect = None
            read.return_value = proof | {"journal_sha256": "f" * 64}
            with self.assertRaisesRegex(identity.Denied, "post-engine-closure-held"):
                self.finalizer.close_post_engine_failure(*self.target, self.readback_sha)
            self.store.close.assert_not_called()
            read.return_value = proof
            self.store.close.side_effect = lambda _: self.store.read.configure_mock(
                return_value={"state": "closed", "closed_at": 501})
            receipt = self.finalizer.close_post_engine_failure(*self.target, self.readback_sha)
        self.assertEqual(receipt["state"], "FAILED_POST_ENGINE_CLOSED")
        self.assertFalse(receipt["native_acceptance"])
        self.store.close.assert_called_once_with(self.lease_id)
        self.assertEqual(observe.call_count, 3)
        self.assertEqual(self.sessions.call_count, 4)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux Root test")
class ProtectedStartupRetirementTests(unittest.TestCase):
    def test_registered_pre_vm_failure_retires_through_the_real_root_finalizer(self):
        from incus_lease_issuer import cell_contract, finalization, operating_custody, preparation
        from test_github_runner_incus_partial_preparation import PartialPreparationTests
        from test_github_runner_incus_run_factory import RootBootstrapTests

        RootBootstrapTests.setUpClass()
        bootstrap_fixture = RootBootstrapTests()
        try:
            bootstrap_fixture.setUp()
            selected_policy, published_policy = bootstrap_fixture.publish_and_verify_startup_bootstrap()
        finally:
            bootstrap_fixture.doCleanups()

        PartialPreparationTests.setUpClass()
        fixture = PartialPreparationTests()
        self.addCleanup(fixture.doCleanups)
        archive_policy = ledger.Ledger.archive_policy
        def opted_in(store, _policy):
            digest = archive_policy(store, published_policy)
            self.assertEqual(digest, selected_policy.custody_policy_sha256)
            return digest
        with mock.patch.object(ledger.Ledger, "archive_policy", new=opted_in):
            fixture.setUp()
        self.assertEqual(fixture.store.read(fixture.lease)["policy_sha256"], selected_policy.custody_policy_sha256)
        cell = fixture.io.fixture
        selected = policy_registry.profile_selector("heavy", "example_heavy", "ubuntu24.04")
        entry = cell.registry_value["cells"].pop("approved")
        cell.registry_value["cells"][selected] = entry
        digest = cell.io.write(cell.io.registry, cell.registry_value)
        fixture.registry = policy_registry.load_registry(str(cell.io.registry), digest)
        fixture.io.value["registry_sha256"] = digest
        fixture.io.seal()
        runtime = json.loads(fixture.runtime.read_bytes())
        runtime["registry_sha256"] = digest
        runtime["preparation_config_sha256"] = fixture.io.sha
        fixture.runtime.write_bytes(ledger.canonical(runtime))
        fixture.finalizer = finalization.RootFinalizer(str(fixture.runtime), ledger.digest(runtime))

        with mock.patch.object(preparation.context_materializer, "materialize",
                               side_effect=identity.Denied("fixture-abort-before-context")):
            with self.assertRaises(preparation.PreparationUnknown):
                preparation.prepare(str(fixture.io.config), fixture.io.sha, fixture.registry,
                                    selected, fixture.store, fixture.lease)
        terminal = fixture.terminal(selected)
        owner = cell_contract.partial_preparation_owner(fixture.registry, selected, fixture.store, fixture.lease)
        project = owner.incus["project"]
        resources = fixture.io.server.resources
        resources["/1.0/instances?project=" + project] = []
        resources["/1.0/operations?project=" + project + "&recursion=1"] = {}
        resources["/1.0/storage-pools/" + owner.incus["pool"] + "/volumes?recursion=1&all-projects=true"] = [
            {"project": "unrelated", "name": "preserve"}]
        original = fixture.store.read(fixture.lease)
        self.assertEqual({e["operation"] for e in original["effects"].values()},
                         startup_retirement.PRE_AUTHORITY_CREATORS)
        archived = Path(fixture.store.path).parent / "startup-retirement" / fixture.lease
        abort = startup_retirement.original_preparation_abort(fixture.store, fixture.lease, original)
        self.assertEqual((abort["diagnostic"], abort["stage"]), ("preparation-unknown", "context-materialize"))

        requests = fixture.io.server.requests
        resources["/1.0/operations?project=" + project + "&recursion=1"] = {"running": ["/item"]}
        held = operating_custody.tick_runtime(str(fixture.runtime), ledger.digest(runtime), "f" * 64)
        self.assertEqual([event["kind"] for event in held["events"]], ["cleanup-unknown"])
        self.assertEqual(fixture.store.read(fixture.lease), original)
        self.assertFalse(archived.exists())
        self.assertFalse(any(row[0] == "DELETE" for row in requests))
        resources["/1.0/operations?project=" + project + "&recursion=1"] = {}

        with mock.patch.object(startup_retirement, "original_preparation_abort", return_value=None):
            held = operating_custody.tick_runtime(str(fixture.runtime), ledger.digest(runtime), "f" * 64)
        self.assertEqual([event["kind"] for event in held["events"]], ["failed-cell-retained"])
        self.assertFalse(archived.exists())

        with mock.patch.object(startup_retirement, "_publish_staged",
                               side_effect=OSError("fixture-interrupt-before-archive-rename")):
            held = operating_custody.tick_runtime(str(fixture.runtime), ledger.digest(runtime), "f" * 64)
        self.assertEqual([event["kind"] for event in held["events"]], ["cleanup-unknown"])
        self.assertFalse(archived.exists())
        self.assertEqual(fixture.store.read(fixture.lease), original)

        with mock.patch.object(finalization.RootFinalizer, "finalize_partial_preparation",
                               side_effect=identity.Denied("fixture-interrupt-after-bind")):
            held = operating_custody.tick_runtime(str(fixture.runtime), ledger.digest(runtime), "f" * 64)
        self.assertEqual([event["kind"] for event in held["events"]], ["cleanup-unknown"])
        bound = fixture.store.read(fixture.lease)
        self.assertIn("pre_vm_retirement", bound["partial_preparation_custody"])
        self.assertFalse(any(row[0] == "DELETE" for row in requests))

        archived_failure = archived / "failure.json"
        original_failure = archived_failure.read_bytes()
        failure = json.loads(original_failure)
        self.assertEqual(failure["root_abort"], abort)
        self.assertEqual(failure["native_terminal_sha256"], ledger.digest(terminal))
        archived_failure.write_bytes(ledger.canonical({**failure, "root_abort": {**abort, "diagnostic": "changed"}}))
        held = operating_custody.tick_runtime(str(fixture.runtime), ledger.digest(runtime), "f" * 64)
        self.assertEqual([event["kind"] for event in held["events"]], ["cleanup-unknown"])
        self.assertEqual(fixture.store.read(fixture.lease), bound)
        self.assertFalse(any(row[0] == "DELETE" for row in requests))
        archived_failure.write_bytes(original_failure)

        with mock.patch.object(startup_retirement, "_publish_staged",
                               side_effect=OSError("fixture-interrupt-before-independent-receipt-rename")):
            held = operating_custody.tick_runtime(str(fixture.runtime), ledger.digest(runtime), "f" * 64)
        self.assertEqual([event["kind"] for event in held["events"]], ["cleanup-unknown"])
        self.assertEqual(fixture.store.read(fixture.lease)["state"], "closed")
        self.assertFalse((archived / "verified-absent.json").exists())
        self.assertEqual(len(list(archived.glob(".verified-absent.json.*"))), 1)

        watch = operating_custody.tick_runtime(str(fixture.runtime), ledger.digest(runtime), "f" * 64)
        self.assertEqual(watch["events"], [])
        self.assertFalse(watch["native_acceptance"])
        result = json.loads((archived / "verified-absent.json").read_bytes())
        latest = fixture.store.read(fixture.lease)
        self.assertEqual(latest["state"], "closed")
        self.assertLess(latest["closed_at"], terminal["completed_at"] + 14400)
        self.assertFalse(result["native_acceptance"])
        self.assertEqual(result["closed_record_sha256"], ledger.digest(latest))
        self.assertEqual((archived / "original.json").read_bytes(), ledger.canonical(original))
        self.assertEqual(archived_failure.read_bytes(), original_failure)
        receipt = (archived / "verified-absent.json").read_bytes()
        repeated = operating_custody.tick_runtime(str(fixture.runtime), ledger.digest(runtime), "f" * 64)
        self.assertEqual(repeated["events"], [])
        self.assertEqual((archived / "verified-absent.json").read_bytes(), receipt)
        self.assertEqual([request[1] for request in requests if request[0] == "DELETE"],
                         ["/1.0/projects/" + project, "/1.0/networks/" + owner.incus["network"] + "?project=default"])


if __name__ == "__main__":
    unittest.main()
