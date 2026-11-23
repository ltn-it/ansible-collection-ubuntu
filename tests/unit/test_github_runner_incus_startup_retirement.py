"""Early retirement applies only to positive, protected pre-VM evidence."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
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


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux Root test")
class ProtectedStartupRetirementTests(unittest.TestCase):
    def test_registered_pre_vm_failure_retires_through_the_real_root_finalizer(self):
        from incus_lease_issuer import cell_contract, finalization, operating_custody, preparation
        from test_github_runner_incus_partial_preparation import PartialPreparationTests

        PartialPreparationTests.setUpClass()
        fixture = PartialPreparationTests()
        self.addCleanup(fixture.doCleanups)
        archive_policy = ledger.Ledger.archive_policy
        def opted_in(store, policy):
            return archive_policy(store, startup_retirement.business_policy(policy))
        with mock.patch.object(ledger.Ledger, "archive_policy", new=opted_in):
            fixture.setUp()
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
        failure = {"schema": 1, "native_terminal_sha256": ledger.digest(terminal),
                   "diagnostic": "fixture-abort-before-context"}
        diagnostic = fixture.io.root / "native-failure.json"
        diagnostic.write_bytes(ledger.canonical(failure))
        diagnostic.chmod(0o600)
        locator = fixture.finalizer.archive_before_vm_authority(fixture.registry, selected, fixture.store,
            fixture.lease, str(diagnostic), ledger.digest(failure))
        self.assertEqual(locator[0], str(archived))

        requests = fixture.io.server.requests
        resources["/1.0/operations?project=" + project + "&recursion=1"] = {"running": ["/item"]}
        with self.assertRaises(identity.Denied):
            fixture.finalizer.retire_before_vm_authority(fixture.registry, selected, fixture.store, fixture.lease, *locator)
        self.assertEqual(fixture.store.read(fixture.lease), original)
        self.assertFalse(any(row[0] == "DELETE" for row in requests))
        resources["/1.0/operations?project=" + project + "&recursion=1"] = {}

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
        self.assertEqual([request[1] for request in requests if request[0] == "DELETE"],
                         ["/1.0/projects/" + project, "/1.0/networks/" + owner.incus["network"] + "?project=default"])


if __name__ == "__main__":
    unittest.main()
