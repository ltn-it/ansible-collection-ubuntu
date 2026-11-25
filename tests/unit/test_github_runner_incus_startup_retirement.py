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

    def test_zero_wait_operating_uses_the_same_pre_authority_proof(self):
        from incus_lease_issuer import operating_cells

        self.policy = {**self.policy, "retention_seconds": 0, ledger.G06_NO_WAIT_MARKER: "7" * 64}
        self.policy.pop("startup_retirement")
        self.record["policy_sha256"] = ledger.digest(self.policy)
        self.refresh_bindings()
        self.assertEqual(startup_retirement.effective_floor(self.record, self.policy,
            selector=operating_cells.selector("broker-cancel"), profile="operating",
            scenario="g06-operating-broker-cancel", target=operating_cells.TARGET,
            archive=self.archive, observations=self.observations, now=self.now), self.observations["at"])
        with self.assertRaisesRegex(identity.Denied, "startup-retirement-fresh-scope"):
            startup_retirement.effective_floor(self.record, self.policy,
                selector=operating_cells.selector("broker-cancel"), profile="operating",
                scenario="g06-operating-broker-cancel", target=operating_cells.TARGET,
                archive=self.archive, observations=self.observations | {"active_consumers": 1}, now=self.now)

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
        self.policy["post_engine_failure_retirement"] = {"schema": 1, "selector": selector}
        self.record["policy_sha256"] = ledger.digest(self.policy)
        manifest = "8" * 64
        image_effect = {"operation": "image-copy", "target": "image:" + project + ":" + operating_cells.IMAGE,
                        "state": "verified"}
        image = {"fingerprint": operating_cells.IMAGE, "type": "virtual-machine",
                 "architecture": "x86_64", "public": False}
        owner = SimpleNamespace(incus={"project": project, "network": "proof-bridge", "pool": "proof-pool",
                                      "instance": "keycloak-heavy"}, creator_targets={"certificate-create": cert},
            creators={"engine-start": {}, "image-copy": {"target": image_effect["target"],
                                                         "sha256": ledger.digest(image_effect)}},
            engine_policy_sha256=manifest,
            engine_descriptor_bytes=ledger.canonical({"environment": {"QUALITY_INPUT_PROFILE": "heavy",
                "QUALITY_INPUT_SCENARIO": "keycloak-heavy", "QUALITY_INPUT_TARGET": "ubuntu-24.04",
                "QUALITY_INPUT_INSTANCE_TYPE": "vm", "QUALITY_INPUT_IMAGE": operating_cells.IMAGE}}))
        process = {"pid": 10, "start_ticks": 11, "boot_id": "22ee1b5a-fee8-4294-bf0b-4a151df0876d"}
        actual = process | {"observed_at": 401, "signal": None, "exit_code": 1, "manifest_sha256": manifest,
                            "container_id": "e" * 64}
        capture = {"manifest_sha256": manifest, "total_limit": 10, "cgroup_device": 5, "cgroup_inode": 6}
        for stream in ("stdout", "stderr"):
            actual.update({stream + "_state": "complete", stream + "_sha256": hashlib.sha256(b"").hexdigest(),
                           stream + "_bytes": 0})
            capture[stream + "_limit"] = 5
        start = {"operation": "engine-start", "target": "engine:lit-lease-" + lease, "at": 400, "state": "verified",
                 "engine_exit": actual, "engine_process": process, "engine_capture": capture,
                 "engine_container_id": actual["container_id"]}
        self.record["worker"] = {"uid": 1, "runner_id": 78, "pid": 2, "start_ticks": 3,
                                 "boot_id": "11111111-1111-1111-1111-111111111111"}
        self.record["authorizations"] = [{"token_id_sha256": "6" * 64}]
        slice_binding = {"boot_id": self.record["worker"]["boot_id"], "cgroup_device": 5, "cgroup_inode": 6}
        self.record["effects"].update(start=start, image=image_effect,
            slice={"operation": "slice-create", "state": "verified", "target": "slice:" + lease,
                   "engine_slice": slice_binding, "evidence_sha256": ledger.digest(slice_binding)},
            revoke={"operation": "certificate-revoke", "state": "verified", "target": cert},
            engine_stop={"operation": "engine-stop", "state": "verified"},
            fence_stop={"operation": "fence-disable", "state": "verified"})
        owner.creators["project-create"] = {}
        store = mock.Mock()
        store.read.return_value = self.record
        store._now.return_value = self.now
        store.read_policy.return_value = self.policy
        admin = mock.Mock()
        cleanup = mock.Mock()
        cleanup.certificates_absent.return_value = True
        cleanup.readback.return_value = {"state": "required_fields_match", "metadata_sha256": "f" * 64}
        cleanup._default_cached_image_identity.return_value = ledger.digest(image)
        cleanup._verify_delete_scope.side_effect = lambda kind, **_: {"kind": kind, "used_by": []}
        cleanup.quiet_project.return_value = {"state": "quiet_observed"}
        finalizer = object.__new__(finalization.RootFinalizer)
        config = SimpleNamespace(incus_socket_path="/run/proof/incus.sock")
        with ExitStack() as patches:
            for subject, name, value in (
                (cell_contract, "owned_cell_for_cleanup", owner), (finalizer, "_fresh", config),
                (cleanup_storage, "_drain_engine", (None, start)), (engine_graph_prune, "_diagnostics", "d" * 64),
                (cleanup_storage, "observe_post_engine_consumers", "e" * 64),
                (network_fence, "verify_disabled", None), (incus_admin, "RootIncusAdmin", admin),
                (incus_mutation, "RootIncusCleanup", cleanup),
            ):
                patches.enter_context(mock.patch.object(subject, name, return_value=value))
            admin.pool_volumes.side_effect = [[{"project": "unrelated"}], [{"project": "unrelated"}]]
            original = deepcopy(self.record)
            proof = finalizer._observe_failed_engine_without_vm(None, None, selector, store, lease)
            self.assertEqual(proof["original_sha256"], ledger.digest(original))
            self.assertEqual(proof["image_effect_sha256"], ledger.digest(image_effect))
            self.assertEqual(proof["default_image_sha256"], ledger.digest(image))
            self.assertEqual(proof["scope_sha256"], ledger.digest(owner.incus))
            self.assertEqual(proof["terminal_sha256"], ledger.digest(self.record["native_terminal"]))
            cleanup._verify_delete_scope.assert_any_call("project", staged_image=True)
            self.assertEqual(cleanup._default_cached_image_identity.call_count, 2)
            self.assertEqual(cleanup.quiet_project.call_count, 2)
            self.assertEqual(self.record, original)
            self.assertFalse(any(call[0] not in {"read", "_now", "read_policy"} for call in store.mock_calls))
            with self.assertRaisesRegex(identity.Denied, "custody-retention-not-elapsed"):
                operating_custody.cleanup_allowed_record(self.record, self.policy, self.now)
            self.record["effects"]["slice"]["target"] = "slice:" + "0" * 32
            with self.assertRaisesRegex(identity.Denied, "failure-observation-slice"):
                finalizer._observe_failed_engine_without_vm(None, None, selector, store, lease)
            self.record["effects"]["slice"]["target"] = "slice:" + lease

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
            with mock.patch.object(cleanup, "_default_cached_image_identity",
                                   side_effect=identity.Denied("mutation-default-cached-image")), \
                    self.assertRaisesRegex(identity.Denied, "mutation-default-cached-image"):
                finalizer._observe_failed_engine_without_vm(None, None, selector, store, lease)
            with mock.patch.object(cleanup_storage, "observe_post_engine_consumers",
                                   side_effect=identity.Denied("cleanup-consumers-open-reference")), \
                    self.assertRaisesRegex(identity.Denied, "cleanup-consumers-open-reference"):
                finalizer._observe_failed_engine_without_vm(None, None, selector, store, lease)
            admin.pool_volumes.side_effect = [[], []]
            cleanup._verify_delete_scope.side_effect = [
                {"used_by": []}, {"used_by": []}, {"used_by": ["/1.0/profiles/default"]}, {"used_by": []},
            ]
            with self.assertRaisesRegex(identity.Denied, "failure-observation-drift"):
                finalizer._observe_failed_engine_without_vm(None, None, selector, store, lease)
            self.record["owned_instance"] = {"name": "bound-vm"}
            with self.assertRaisesRegex(identity.Denied, "failure-observation-unresolved"):
                finalizer._observe_failed_engine_without_vm(None, None, selector, store, lease)
            del self.record["owned_instance"]
            self.record["effects"]["renewal"] = {"operation": "fence-renew", "state": "verified",
                                                   "target": "fence:" + "0" * 32 + ":" + "6" * 64}
            with self.assertRaisesRegex(identity.Denied, "failure-observation-foreign-renewal"):
                finalizer._observe_failed_engine_without_vm(None, None, selector, store, lease)
            del self.record["effects"]["renewal"]
            actual["stderr_state"] = "incomplete"
            with self.assertRaisesRegex(identity.Denied, "post-engine-archive-complete-exit"):
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

    def test_project_attachments_allow_only_the_verified_private_image_and_default_profile(self):
        from incus_lease_issuer import incus_mutation

        mutation = object.__new__(incus_mutation.RootIncusMutator)
        mutation._project = SimpleNamespace(project="proof-project")
        profile = "/1.0/profiles/default?project=proof-project"
        image = "/1.0/images/" + operating_cells.IMAGE + "?project=proof-project"
        project = {"config": {}, "used_by": [image, profile]}
        with (mock.patch.object(incus_mutation, "_project", return_value={"config": {}}),
              mock.patch.object(mutation, "_observe", return_value=project),
              mock.patch.object(mutation, "_matches", return_value=True)):
            self.assertIs(mutation._verify_delete_scope("project", staged_image=True), project)
            with self.assertRaisesRegex(identity.Denied, "mutation-delete-in-use"):
                mutation._verify_delete_scope("project")
            for attached in ("/1.0/storage-pools/pool/buckets/extra", "/1.0/images/other", image,
                             "/1.0/storage-pools/pool/volumes/custom/extra"):
                project["used_by"] = [image, profile, attached]
                with self.subTest(attached=attached), self.assertRaisesRegex(identity.Denied, "mutation-delete-in-use"):
                    mutation._verify_delete_scope("project", staged_image=True)
            project["used_by"] = [profile]
            with self.assertRaisesRegex(identity.Denied, "mutation-delete-in-use"):
                mutation._verify_delete_scope("project", staged_image=True)
            self.assertIs(mutation._verify_delete_scope("project"), project)

    def test_default_image_identity_is_private_stable_and_read_twice(self):
        from incus_lease_issuer import incus_mutation

        mutation = object.__new__(incus_mutation.RootIncusMutator)
        pinned = {"fingerprint": operating_cells.IMAGE, "type": "virtual-machine",
                  "architecture": "x86_64", "public": False}
        first, second = pinned | {"last_used_at": 12}, pinned | {"last_used_at": 13}
        with mock.patch.object(mutation, "_image_observe", side_effect=[first, second]) as read:
            self.assertEqual(mutation._default_cached_image_identity(), ledger.digest(pinned))
            self.assertEqual(read.call_args_list, [mock.call("default")] * 2)
        with mock.patch.object(mutation, "_image_observe", side_effect=[pinned, pinned | {"public": True}]), \
                self.assertRaisesRegex(identity.Denied, "mutation-default-cached-image"):
            mutation._default_cached_image_identity()


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and Path("/run/proof").is_dir(),
                     "isolated Linux Root archive fixture")
class PostEngineArchiveTests(unittest.TestCase):
    def setUp(self):
        from contextlib import nullcontext
        from incus_lease_issuer import cell_contract, generation_publisher, root_session, storage_quota

        self.root = Path(self.enterContext(TemporaryDirectory(dir="/run/proof")))
        self.lease, manifest_sha = "a" * 32, "1" * 64
        bank = self.root / "ledger"
        storage = self.root / "shared-quota"
        self.runroot = storage / self.lease
        generation_publisher._mkdir(bank)
        generation_publisher._mkdir(storage)
        generation_publisher._mkdir(self.runroot)
        ledger.Ledger.initialize(str(bank))
        self.store = self.enterContext(ledger.Ledger(str(bank), clock=lambda: 500))
        binding = StartupRetirementTests()
        binding.setUp()
        self.store.archive_policy(binding.policy)
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
        self.folder = startup_retirement._post_engine_archive_path(self.owner)
        self.config = SimpleNamespace(registry_path=registry.path, registry_sha256=registry.sha256,
            storage_quota_policy_path=str(self.root / "quota.json"), storage_quota_policy_sha256="d" * 64)
        self.quota = self.enterContext(mock.patch.object(storage_quota, "acquire_existing_evidence_quota",
            side_effect=lambda *_: nullcontext()))
        self.enterContext(mock.patch.object(self.store, "read", side_effect=lambda _: deepcopy(self.record)))
        self.enterContext(mock.patch.object(cell_contract, "owned_cell_for_cleanup", side_effect=lambda *_: self.owner))
        self.enterContext(mock.patch.object(root_session, "_require_session",
            return_value=self.config))

    def publish(self):
        return startup_retirement._publish_post_engine_archive(None, self.owner, self.store)

    def readback(self, binding):
        return startup_retirement._read_post_engine_archive(self.store, self.lease, binding, self.folder)

    def locate_permit(self):
        return startup_retirement._locate_post_engine_permit(self.store, self.lease, self.folder)

    def permit_observation(self):
        from dataclasses import replace

        selector = policy_registry.profile_selector("heavy", "keycloak-heavy", "ubuntu-24.04")
        self.owner = replace(self.owner, selector=selector)
        policy = StartupRetirementTests()
        policy.setUp()
        value = policy.policy | {"post_engine_failure_retirement": {"schema": 1, "selector": selector}}
        self.record["policy_sha256"] = ledger.digest(value)
        self.enterContext(mock.patch.object(self.store, "read_policy", return_value=value))
        return {"lease_id": self.lease, "original_sha256": ledger.digest(self.record),
                "terminal_sha256": ledger.digest(self.record["native_terminal"]),
                "scope_sha256": ledger.digest(self.owner.incus), "census_sha256": "9" * 64,
                "policy_sha256": self.record["policy_sha256"], "image_effect_sha256": None,
                "default_image_sha256": None, "observed_at": 490}

    def test_permit_reopens_archived_original_after_verified_cleanup_journal_changes(self):
        observation = self.permit_observation()
        self.assertIsNone(self.locate_permit())
        permit = startup_retirement._publish_post_engine_permit(None, self.owner, self.store, observation)
        path = startup_retirement._post_engine_permit_path(self.store, self.lease)
        body = startup_retirement._read_post_engine_permit(self.store, self.lease, permit["permit_sha256"], self.folder)
        self.assertEqual(path.read_bytes(), ledger.canonical(body))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.locate_permit(), permit)
        self.record["effects"]["deleted"] = {"operation": "engine-release", "state": "verified"}
        for name in self.logs:
            (self.runroot / name).unlink()
        self.assertEqual(self.locate_permit(), permit)
        with self.assertRaisesRegex(identity.Denied, "post-engine-permit-observation-drift"):
            startup_retirement._require_post_engine_observation(
                permit, observation | {"original_sha256": ledger.digest(self.record)}, 500)
        with self.assertRaisesRegex(identity.Denied, "post-engine-permit-observation-drift"):
            startup_retirement._require_post_engine_observation(permit, observation, 1000)
        startup_retirement._require_post_engine_observation(permit, observation | {"observed_at": 498}, 500)

    def test_no_wait_permit_archives_a_signalled_engine_after_native_cancel(self):
        import dataclasses
        from incus_lease_issuer import operating_cells

        self.owner = dataclasses.replace(self.owner, selector=operating_cells.selector("broker-cancel"))
        policy = self.store.read_policy(self.record["policy_sha256"])
        original = deepcopy(self.record)
        self.record["native_terminal"]["conclusion"] = "cancelled"
        self.record["effects"]["c" * 32]["engine_exit"].update(exit_code=None, signal=15, observed_at=450)
        with self.assertRaisesRegex(identity.Denied, "post-engine-archive-failed-start"):
            self.publish()
        scope = policy | {"retention_seconds": 0, ledger.G06_NO_WAIT_MARKER: "7" * 64}
        self.record["policy_sha256"] = self.store.archive_policy(scope)
        observation = {"lease_id": self.lease, "original_sha256": ledger.digest(self.record),
                       "terminal_sha256": ledger.digest(self.record["native_terminal"]),
                       "scope_sha256": ledger.digest(self.owner.incus), "census_sha256": "9" * 64,
                       "policy_sha256": self.record["policy_sha256"], "image_effect_sha256": None,
                       "default_image_sha256": None, "observed_at": 490}
        permit = startup_retirement._publish_post_engine_permit(None, self.owner, self.store, observation)
        self.assertEqual(self.locate_permit(), permit)
        self.assertEqual((self.folder / "terminal.json").read_bytes(), ledger.canonical(self.record["native_terminal"]))
        self.assertEqual((self.folder / "stdout.log").read_bytes(), self.logs["stdout.log"])
        self.assertEqual(self.store.read_policy(original["policy_sha256"]), policy)

    def test_corrupt_or_uncommitted_permit_cannot_be_interpreted_as_an_absent_permit(self):
        observation = self.permit_observation()
        self.publish()
        path = startup_retirement._post_engine_permit_path(self.store, self.lease)
        path.parent.mkdir(mode=0o700)
        self.assertIsNone(self.locate_permit())
        staged = path.with_name("." + path.name + ".interrupted")
        staged.write_text("{")
        with self.assertRaisesRegex(identity.Denied, "post-engine-permit-staging-held"):
            self.locate_permit()
        staged.unlink()
        permit = startup_retirement._publish_post_engine_permit(None, self.owner, self.store, observation)
        capture = self.folder / "stdout.log"
        capture.write_bytes(b"x" * len(capture.read_bytes()))
        with self.assertRaisesRegex(identity.Denied, "post-engine-archive-member-drift"):
            startup_retirement._read_post_engine_permit(self.store, self.lease, permit["permit_sha256"], self.folder)
        with self.assertRaisesRegex(identity.Denied, "post-engine-archive-member-drift"):
            self.locate_permit()

    def test_producer_leaves_only_proved_existing_vm_to_ordinary_custody(self):
        from contextlib import nullcontext
        from incus_lease_issuer import finalization, operating_custody, root_session

        self.permit_observation()
        finalizer = object.__new__(finalization.RootFinalizer)
        finalizer._runtime = SimpleNamespace(preparation_config_path="/run/proof/runtime.json",
                                             preparation_config_sha256="a" * 64)
        admin, cleanup = mock.Mock(), mock.Mock()
        admin.instances.return_value = ["/1.0/instances/declared?project=proof-project"]
        cleanup.readback.return_value = {"state": "required_fields_match", "metadata_sha256": "f" * 64}
        session, config, proof = object(), object(), object()
        with (mock.patch.object(root_session, "_session", side_effect=lambda *_: nullcontext(session)),
              mock.patch.object(finalizer, "_fresh", return_value=config),
              mock.patch.object(startup_retirement, "_post_engine_evidence_quota", return_value=nullcontext()),
              mock.patch.object(finalizer, "_post_engine_transport", return_value=(admin, cleanup)),
              mock.patch.object(operating_custody, "observe_owned_instance", return_value=proof) as observe,
              mock.patch.object(operating_custody, "require_instance_proof") as verify,
              mock.patch.object(finalizer, "_observe_failed_engine_without_vm") as census,
              mock.patch.object(startup_retirement, "_publish_post_engine_permit") as publish):
            args = (self.owner.registry, self.owner.selector, self.store, self.lease)
            self.assertIsNone(finalizer.prepare_post_engine_permit(*args))
            observe.assert_called_once_with(config, *args)
            verify.assert_called_once_with(proof, self.lease, self.record)
            self.assertEqual(cleanup.readback.call_args_list, [mock.call("project")] * 2)
            observe.side_effect = identity.Denied("mutation-instance-inventory")
            with self.assertRaisesRegex(identity.Denied, "mutation-instance-inventory"):
                finalizer.prepare_post_engine_permit(*args)
            cleanup.readback.return_value = {"state": "conflict"}
            with self.assertRaisesRegex(identity.Denied, "post-engine-permit-vm-project"):
                finalizer.prepare_post_engine_permit(*args)
            census.assert_not_called()
            publish.assert_not_called()

            # A VM that was already observed follows stopped custody, including
            # when its archive exists and the shared permit directory is present.
            self.record["owned_instance"] = {"uuid": "original-vm"}
            with mock.patch.object(startup_retirement, "_locate_post_engine_permit",
                                   side_effect=identity.Denied("post-engine-archive-manifest-binding")) as locate:
                self.assertIsNone(finalizer.prepare_post_engine_permit(*args))
            locate.assert_not_called()

    def test_consumer_census_pins_the_created_storage_and_the_exact_disabled_namespace(self):
        from contextlib import nullcontext
        from dataclasses import replace
        from incus_lease_issuer import cleanup_storage, generation_publisher, kernel, network_fence

        graph, output, context = (self.root / name for name in ("storage", "output", "context"))
        for path in (graph, output, context):
            generation_publisher._mkdir(path)
        data = {"engine": {"storage_root": str(graph), "runroot": str(self.runroot)},
                "output_path": str(output), "context_path": str(context)}
        descriptor = ledger.canonical(data)
        generation_publisher._write(Path(self.owner.engine_descriptor_path), descriptor)
        start = self.record["effects"]["c" * 32]
        boot = start["engine_process"]["boot_id"]
        info = SimpleNamespace(st_dev=os.makedev(0, 4), st_ino=150)
        prepare = [{"path": str(path), "device": path.stat().st_dev, "inode": path.stat().st_ino}
                   for path in (graph, self.runroot, output)]
        self.record["effects"]["prepare"] = {"evidence_sha256": ledger.digest({
            "prepared": self.owner.prepared_sha256, "directories": prepare,
        })}
        self.record["effects"]["fence"] = {"fence": {"boot_id": boot,
                                                   "netns_device": info.st_dev, "netns_inode": info.st_ino}}
        owner = replace(self.owner, engine_descriptor_bytes=descriptor,
                        engine_descriptor_sha256=hashlib.sha256(descriptor).hexdigest(),
                        creator_bytes=ledger.canonical({"engine-start": {"id": "c" * 32},
                                                        "engine-prepare": {"id": "prepare"},
                                                        "fence-create": {"id": "fence"}}))
        with (mock.patch.object(cleanup_storage, "_fresh", return_value=self.record),
              mock.patch.object(cleanup_storage, "_cleanup_limits", return_value=(100, 10)),
              mock.patch.object(kernel, "read_boot_id", return_value=boot),
              mock.patch.object(network_fence, "_host_namespace", return_value=(info.st_dev, 1)),
              mock.patch.object(network_fence, "_namespace_witness",
                                side_effect=lambda _: nullcontext((33, info))) as witness,
              mock.patch.object(network_fence, "_namespace_cookie", return_value=45),
              mock.patch.object(network_fence, "_namespace_refs_drained") as net,
              mock.patch.object(cleanup_storage, "_no_consumers") as storage):
            digest = cleanup_storage.observe_post_engine_consumers(owner, self.store, object(), start)
            self.assertRegex(digest, ledger.HEX)
            self.assertEqual(witness.call_args_list, [mock.call("lit-lease-" + self.lease)] * 2)
            self.assertEqual(net.call_args_list, [mock.call(33, info, 45)] * 2)
            self.assertEqual(storage.call_count, 2)
            self.assertEqual(storage.call_args.kwargs, {
                "forbidden_namespace": (info.st_dev, info.st_ino), "retained_namespace_alias": True,
            })
            self.record["effects"]["prepare"]["evidence_sha256"] = "0" * 64
            with self.assertRaisesRegex(identity.Denied, "cleanup-post-engine-creator-inodes"):
                cleanup_storage.observe_post_engine_consumers(owner, self.store, object(), start)

    def test_interrupted_before_publish_leaves_no_archive_and_retry_seals_binary_and_empty_streams(self):
        with mock.patch.object(startup_retirement, "_publish_staged", side_effect=OSError("fixture interruption")):
            with self.assertRaises(OSError):
                self.publish()
        self.assertFalse(self.folder.exists())
        self.assertEqual(set(self.folder.parent.iterdir()), {self.runroot})
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
        orphan = self.folder.with_name("." + self.folder.name + ".interrupted")
        orphan.mkdir(mode=0o700)
        with self.assertRaisesRegex(identity.Denied, "post-engine-archive-staging-held"):
            self.publish()
        self.assertEqual(set(self.folder.parent.iterdir()), {self.runroot, orphan})

    def test_permit_retry_syncs_the_parent_directory_after_an_interrupted_mkdir(self):
        from incus_lease_issuer import generation_publisher

        observation = self.permit_observation()
        permit = startup_retirement._post_engine_permit_path(self.store, self.lease)

        def make_then_interrupt(path):
            path.mkdir(mode=0o700)
            raise OSError("fixture lost parent mkdir acknowledgement")

        with mock.patch.object(generation_publisher, "_mkdir", side_effect=make_then_interrupt):
            with self.assertRaises(OSError):
                startup_retirement._publish_post_engine_permit(None, self.owner, self.store, observation)
        self.assertTrue(permit.parent.is_dir())
        self.assertFalse(permit.exists())
        self.assertTrue(self.folder.exists())
        synced, original_fsync = [], os.fsync

        def observe_fsync(fd):
            synced.append(os.fstat(fd).st_ino)
            return original_fsync(fd)

        with mock.patch.object(os, "fsync", side_effect=observe_fsync):
            receipt = startup_retirement._publish_post_engine_permit(None, self.owner, self.store, observation)
        self.assertIn(self.root.stat().st_ino, synced)
        self.assertEqual(self.locate_permit(), receipt)

    def test_archive_refuses_an_unverified_quota_before_capture_or_staging(self):
        from incus_lease_issuer import engine_executor

        self.quota.side_effect = identity.Denied("storage-quota-acquisition-denied")
        with mock.patch.object(engine_executor, "_bound_capture_file") as copy:
            with self.assertRaisesRegex(identity.Denied, "storage-quota-acquisition-denied"):
                self.publish()
            copy.assert_not_called()
        self.quota.assert_called_once_with(self.config.storage_quota_policy_path,
            self.config.storage_quota_policy_sha256, str(self.folder.parent))
        self.assertEqual(set(self.folder.parent.iterdir()), {self.runroot})

    def test_shared_quota_accounts_for_other_generations_and_staging(self):
        from incus_lease_issuer import engine_executor

        older = self.folder.with_name("b" * 32 + ".post-engine-evidence")
        staged = self.folder.with_name("." + "c" * 32 + ".post-engine-evidence.interrupted")
        for folder in (older, staged):
            folder.mkdir(mode=0o700)
            (folder / "stdout.log").write_bytes(b"previous")
        for available_blocks, available_inodes in ((0, 100), (100, 0)):
            available = SimpleNamespace(f_frsize=4096, f_bavail=available_blocks, f_favail=available_inodes)
            with self.subTest(blocks=available_blocks, inodes=available_inodes), \
                 mock.patch.object(os, "fstatvfs", return_value=available), \
                 mock.patch.object(engine_executor, "_bound_capture_file") as copy:
                with self.assertRaisesRegex(identity.Denied, "post-engine-archive-capacity"):
                    self.publish()
                copy.assert_not_called()
        self.assertEqual(set(self.folder.parent.iterdir()), {self.runroot, older, staged})
        self.assertEqual([(entry / "stdout.log").read_bytes() for entry in (older, staged)], [b"previous"] * 2)

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
        return startup_retirement._read_post_engine_cleanup_journal(self.store, self.lease, binding, self.folder)

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
            progress = startup_retirement._read_post_engine_cleanup_journal(
                self.store, self.lease, binding, self.folder, complete=False)
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

    def test_reused_independent_readback_syncs_both_directories_after_interrupted_rename(self):
        _, binding = self.completed_cleanup()
        value = {"schema": 1, "archive_sha256": binding}
        path = startup_retirement._post_engine_readback_path(self.store, self.lease)
        sync = os.fsync

        def interrupted(fd):
            if path.is_file() and os.path.samestat(os.fstat(fd), path.parent.stat()):
                raise OSError("interrupted directory sync after rename")
            sync(fd)

        with mock.patch.object(os, "fsync", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "interrupted directory sync after rename"):
                startup_retirement._publish_post_engine_readback(self.store, self.lease, value)
        self.assertTrue(path.is_file())
        confirmed = []

        def record_sync(fd):
            confirmed.append(os.fstat(fd))
            sync(fd)

        with mock.patch.object(os, "fsync", side_effect=record_sync):
            digest = startup_retirement._publish_post_engine_readback(self.store, self.lease, value)
        self.assertEqual(digest, ledger.digest(value))
        self.assertEqual(len(confirmed), 2)
        self.assertTrue(os.path.samestat(confirmed[0], path.parent.stat()))
        self.assertTrue(os.path.samestat(confirmed[1], path.parent.parent.stat()))

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
        entries = set(self.folder.parent.iterdir())
        with self.assertRaisesRegex(identity.Denied, "post-engine-archive-complete-exit"):
            self.publish()
        self.assertEqual(set(self.folder.parent.iterdir()), entries)


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
        self.enterContext(mock.patch.object(startup_retirement, "_post_engine_archive_path",
            return_value=Path("/proof/archive")))
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
        self.assertEqual(release.call_args.kwargs, {"private_archive": Path("/proof/archive")})
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
        self.assertEqual([call.kwargs for call in refresh.call_args_list],
                         [{"refresh": True, "private_archive": Path("/proof/archive")}] * 2)
        self.store.close.assert_not_called()

    def test_private_copy_requires_the_exact_unchanged_default_image(self):
        verify = self.finalizer._check_post_engine_default_image
        self.assertIsNone(verify(self.record, self.cleanup, self.permit))
        self.cleanup._default_cached_image_identity.assert_not_called()
        self.record["effects"]["copy"] = {"operation": "image-copy"}
        with self.assertRaisesRegex(identity.Denied, "post-engine-default-image-drift"):
            verify(self.record, self.cleanup, self.permit)
        self.permit["default_image_sha256"] = "a" * 64
        self.cleanup._default_cached_image_identity.return_value = "a" * 64
        self.assertEqual(verify(self.record, self.cleanup, self.permit), "a" * 64)
        self.cleanup._default_cached_image_identity.return_value = "b" * 64
        with self.assertRaisesRegex(identity.Denied, "post-engine-default-image-drift"):
            verify(self.record, self.cleanup, self.permit)

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
