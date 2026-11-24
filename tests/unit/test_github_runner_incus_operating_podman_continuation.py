"""The failed first Podman start remains immutable history."""

from contextlib import ExitStack, nullcontext
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "roles/github_runner/files"))
from incus_lease_issuer import (cleanup_storage, engine_executor, host_api_fence, identity, incus_admin,
                               incus_mutation, ledger, network_fence, operating_cells as cells,
                               run_factory, storage_quota)

def census_native_capture():
    fixture = Path(__file__).parent / "fixtures/g06-thirteenth-failed-native-graph.json"
    return json.loads(fixture.read_bytes())


def sixteenth_native_capture():
    fixture = Path(__file__).parent / "fixtures/g06-sixteenth-original-terminal-projection.json"
    return json.loads(fixture.read_bytes())


def seventeenth_native_capture():
    fixture = Path(__file__).parent / "fixtures/g06-seventeenth-original-terminal-projection.json"
    return json.loads(fixture.read_bytes())


def podman_exit_fixture():
    manifest_sha256 = "a" * 64
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    cid = "b" * 64
    process = {"pid": 123, "start_ticks": 42, "boot_id": "a" * 36}
    exit_info = process | {"container_id": cid, "manifest_sha256": manifest_sha256,
                           "exit_code": 126, "signal": None, "observed_at": 200,
                           "stdout_bytes": 0, "stdout_sha256": empty_sha256, "stdout_state": "complete",
                           "stderr_bytes": 0, "stderr_sha256": empty_sha256, "stderr_state": "complete"}
    effect = {"operation": "engine-start", "state": "unknown", "at": 100, "engine_process": process,
              "engine_capture": {"manifest_sha256": manifest_sha256, "stdout_limit": 1,
                                 "stderr_limit": 1, "total_limit": 2},
              "engine_container_id": cid, "engine_exit": exit_info}
    proof = {"format": "podman-4.9-sqlite-and-containers-storage",
             "container_id_sha256": hashlib.sha256(cid.encode()).hexdigest(),
             "name": "lit-lease-" + cells.EIGHTEENTH_LEASE, "engine_exit_sha256": ledger.digest(exit_info),
             "manifest_sha256": manifest_sha256, "container_config_rows": 0, "container_state_rows": 0,
             "original_id_namespace_rows": 0, "storage_container_rows": 0,
             "cid_file_absent": True, "host_effects": 0,
             "database_sha256": "c" * 64, "volatile_catalogue_sha256": "d" * 64}
    return effect, proof


class EighteenthContinuationTests(unittest.TestCase):
    def test_actual_failed_native_run_and_fresh_inventory_are_bound(self):
        fixture = Path(__file__).parent / "fixtures/g06-eighteenth-original-terminal-projection.json"
        capture = json.loads(fixture.read_bytes())
        graph = capture["graph"]
        run = graph["run"] | {"repository": capture["repository"], "referenced_workflows": [capture["controller"]]}
        inventory = {"total_count": len(graph["jobs"]), "jobs": graph["jobs"]}
        provider = Mock(side_effect=[run, inventory, *capture["checks"], deepcopy(inventory)])
        self.assertEqual(run_factory._continuation_eighteenth_native(provider), graph)
        check_path = f"/actions/runs/{cells.EIGHTEENTH_RUN}"
        jobs_path = check_path + "/attempts/1/jobs?per_page=100&page=1"
        self.assertEqual(provider.call_args_list, [
            call(check_path), call(jobs_path), *[call(f"/check-runs/{identifier}") for identifier in cells.EIGHTEENTH_CHECKS],
            call(jobs_path),
        ])
        changed = deepcopy(inventory)
        next(row for row in changed["jobs"] if row["id"] == cells.EIGHTEENTH_CHECKS[0])["runner_id"] = 79
        provider = Mock(side_effect=[run, changed, *capture["checks"], deepcopy(changed)])
        with self.assertRaisesRegex(identity.Denied, "continuation-ninth-original-failed-graph"):
            run_factory._continuation_eighteenth_native(provider)

    def test_successor_cannot_admit_a_replay_even_when_qualification_is_published(self):
        workflow, reusable, qualification = "a" * 64, "b" * 40, "c" * 64
        successor = {"source_sha": "e" * 40, "run_id": 99910000001, "run_attempt": 1,
                     "first_parent": cells.EIGHTEENTH_MAIN, "source_workflow_sha256": workflow,
                     "reusable_sha": reusable}
        descriptor = {"schema": 18, "reason": cells.EIGHTEENTH_REASON,
                      "qualification": {"path": "/unit/new-qualification.json", "sha256": qualification},
                      "successor": successor}
        with (patch.multiple(cells, EIGHTEENTH_QUALIFICATION=qualification, EIGHTEENTH_SUCCESSOR_WORKFLOW=workflow,
                            EIGHTEENTH_SUCCESSOR_REUSABLE=reusable)):
            self.assertEqual(cells.validate_continuation_descriptor(descriptor, workflow, reusable), descriptor)
            for change in ({"run_id": cells.EIGHTEENTH_RUN}, {"source_sha": cells.EIGHTEENTH_MAIN}):
                with self.subTest(change=change), self.assertRaises(identity.Denied):
                    cells.validate_continuation_descriptor(descriptor | {"successor": successor | change}, workflow, reusable)
        with patch.object(cells, "EIGHTEENTH_QUALIFICATION", None), self.assertRaises(identity.Denied):
            cells.validate_continuation_descriptor(descriptor, workflow, reusable)

    def test_podman_absence_is_bound_to_the_original_exit_and_private_store(self):
        effect, proof = podman_exit_fixture()
        exit_sha256 = ledger.digest(effect["engine_exit"])
        run_factory._revalidate_oci_exit(cells.EIGHTEENTH_LEASE, effect, exit_sha256, proof)
        for change in ({"storage_container_rows": 1}, {"cid_file_absent": False},
                       {"container_id_sha256": "0" * 64}, {"engine_exit_sha256": "0" * 64}):
            with self.subTest(change=change), self.assertRaisesRegex(identity.Denied, "continuation-eighteenth"):
                run_factory._revalidate_oci_exit(cells.EIGHTEENTH_LEASE, effect, exit_sha256, proof | change)


class SeventeenthContinuationTests(unittest.TestCase):
    def test_bootstrap_requires_all_published_pins_and_a_fresh_first_push(self):
        workflow, reusable, qualification = "a" * 64, "b" * 40, "c" * 64
        successor = {"source_sha": "e" * 40, "run_id": 99910000001, "run_attempt": 1,
                     "first_parent": cells.SEVENTEENTH_MAIN, "source_workflow_sha256": workflow,
                     "reusable_sha": reusable}
        descriptor = {"schema": 17, "reason": cells.SEVENTEENTH_REASON,
                      "qualification": {"path": "/unit/new-qualification.json", "sha256": qualification},
                      "successor": successor}
        for missing in ("SEVENTEENTH_QUALIFICATION", "SEVENTEENTH_SUCCESSOR_WORKFLOW", "SEVENTEENTH_SUCCESSOR_REUSABLE"):
            pins = {"SEVENTEENTH_QUALIFICATION": qualification, "SEVENTEENTH_SUCCESSOR_WORKFLOW": workflow,
                    "SEVENTEENTH_SUCCESSOR_REUSABLE": reusable}
            with self.subTest(missing=missing), patch.multiple(cells, **(pins | {missing: None})):
                with self.assertRaises(identity.Denied):
                    cells.validate_continuation_descriptor(descriptor, workflow, reusable)
        with patch.multiple(cells, SEVENTEENTH_QUALIFICATION=qualification,
                            SEVENTEENTH_SUCCESSOR_WORKFLOW=workflow, SEVENTEENTH_SUCCESSOR_REUSABLE=reusable):
            self.assertEqual(cells.validate_continuation_descriptor(descriptor, workflow, reusable), descriptor)
            commit = {"sha": successor["source_sha"], "parents": [{"sha": cells.SEVENTEENTH_MAIN}]}
            cells.validate_continuation_commit(commit, descriptor, successor["source_sha"], successor["run_id"], reusable)
            for invalid in ({"run_attempt": 2}, {"run_id": cells.SEVENTEENTH_RUN},
                            {"source_sha": cells.SEVENTEENTH_MAIN}, {"first_parent": cells.SIXTEENTH_MAIN},
                            {"reusable_sha": cells.SIXTEENTH_SUCCESSOR_REUSABLE}):
                with self.subTest(invalid=invalid), self.assertRaises(identity.Denied):
                    cells.validate_continuation_descriptor(
                        descriptor | {"successor": successor | invalid}, workflow, reusable)

    def test_qualification_pins_new_catalogue_entries_without_replacing_history(self):
        kinds = ("native_run_configuration_catalogue", "native_intake_catalogue")
        prior = {kind: {"a" * 64: "b" * 64} for kind in kinds}
        previous = {"schema": 16, "previous_qualification": {"retirement": {"catalogues": prior}}}
        graph = seventeenth_native_capture()["graph"]
        additions = {kind: {"name": str(index) * 64, "device": 10, "inode": index,
                            "receipt_sha256": "c" * 64, "inventory_sha256": "d" * 64}
                     for index, kind in enumerate(kinds, start=1)}
        steps = {f"{step}-{phase}.json" for step in cells.SEVENTEENTH_RETIREMENT_STEPS for phase in ("intent", "receipt")}
        journal = {name: "e" * 64 for name in steps | {"complete-receipt.json", "storage-identities.json"}}
        retired = {"original_bootstrap": {"path": "/unit/old/bootstrap.json", "sha256": "f" * 64, "device": 20, "inode": 21},
                   "original_bank": {"path": "/unit/old/ledger", "state_file_sha256": "0" * 64, "device": 20, "inode": 22},
                   "original_record": {"lease_id": cells.SEVENTEENTH_LEASE, "sha256": "a" * 64,
                                       "unknown_effect_id": "1" * 32},
                   "new_entries": additions,
                   "catalogues": {kind: prior[kind] | {additions[kind]["name"]: "d" * 64} for kind in kinds},
                   "journal": {"path": "/unit/journal", "members": journal},
                   "retain_until": cells.SEVENTEENTH_RETAIN_UNTIL, "storage_unique_mount_id": 123,
                   "namespace_cookie": 456}
        receipt = {"schema": 17, "purpose": cells.SEVENTEENTH_REASON, "native_seventeenth": graph,
                   "previous_qualification": previous, "retirement": retired}
        identities = {kind: {"directory_device": 20, "directory_inode": index}
                      for index, kind in enumerate(kinds, start=24)}
        with patch.object(cells, "_validate_sixteenth_qualification", return_value=identities) as validate_previous:
            with patch.object(cells, "SEVENTEENTH_QUALIFICATION", ledger.digest(receipt)):
                self.assertEqual(cells.validate_continuation_qualification(receipt), identities)
            validate_previous.assert_called_once_with(previous)
            changed = deepcopy(receipt)
            changed["retirement"]["catalogues"][kinds[0]]["a" * 64] = "e" * 64
            with (patch.object(cells, "SEVENTEENTH_QUALIFICATION", ledger.digest(changed)),
                  self.assertRaisesRegex(identity.Denied, "continuation-seventeenth-preserved-catalogues")):
                cells.validate_continuation_qualification(changed)

    def test_native_history_uses_the_actual_seventeenth_run_checks_and_second_inventory(self):
        capture = seventeenth_native_capture()
        graph = capture["graph"]
        checks = capture["checks"]
        run = graph["run"] | {"repository": capture["repository"], "referenced_workflows": [capture["controller"]]}
        inventory = {"total_count": len(graph["jobs"]), "jobs": graph["jobs"]}
        provider = Mock(side_effect=[run, inventory, *checks, deepcopy(inventory)])
        self.assertEqual(run_factory._continuation_seventeenth_native(provider), graph)
        run_path = f"/actions/runs/{graph['run']['id']}"
        jobs_path = run_path + "/attempts/1/jobs?per_page=100&page=1"
        self.assertEqual(provider.call_args_list, [
            call(run_path), call(jobs_path), *[call(f"/check-runs/{row['id']}") for row in checks], call(jobs_path),
        ])
        drifted = deepcopy(inventory)
        drifted["jobs"][0]["name"] += " (changed)"
        changed_check = checks[0] | {"app": checks[0]["app"] | {"id": 1}}
        for first, check_rows, second, reason in (
            (drifted, checks, drifted, "continuation-ninth-original-failed-graph"),
            (inventory, checks, drifted, "continuation-ninth-native-inventory-drift"),
            (inventory, [changed_check, *checks[1:]], inventory, "continuation-ninth-native-check"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(identity.Denied, reason):
                run_factory._continuation_seventeenth_native(Mock(side_effect=[run, first, *check_rows, second]))


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and Path("/run/proof").is_dir(),
                     "requires private root proof tmpfs")
class OCIRetirementFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir="/run/proof")
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.root = self.parent / f"runner01-original-retirement-{self.run_id}"
        self.root.mkdir(mode=0o700)
        self.bank = self.parent / "original-bank"
        self.bank.mkdir(mode=0o700)
        self.bank_file = self.bank / "state.json"
        self.bank_file.write_bytes(b'{"retained":true}\n')
        self.bank_file.chmod(0o600)
        bank = self.bank.stat()
        self.effect = "1" * 32
        self.record = {
            "state": "prepared", "identity": {}, "created_at": self.floor - 15000, "expires_at": self.floor - 14300,
            "effects": {self.effect: {"operation": "engine-start", "state": "unknown",
                                      "engine_capture": {}, "engine_process": {}}},
            "native_terminal": {"source_sha": self.source_revision, "controller_sha": self.controller_revision,
                                "run_id": self.run_id, "job_id": self.job_id, "check_run_id": self.job_id,
                                "run_attempt": 1, "conclusion": "failure", "completed_at": self.floor - 14400},
            "policy_sha256": "a" * 64,
        }
        self.retirement = {
            "journal": {"path": str(self.root), "members": {}},
            "original_record": {"lease_id": self.lease, "sha256": ledger.digest(self.record),
                                "unknown_effect_id": self.effect},
            "original_bootstrap": {"path": "/unit/bootstrap.json", "sha256": "b" * 64, "device": 20, "inode": 21},
            "original_bank": {"path": str(self.bank), "device": bank.st_dev, "inode": bank.st_ino,
                              "state_file_sha256": hashlib.sha256(self.bank_file.read_bytes()).hexdigest()},
            "new_entries": {"native_run_configuration_catalogue": {"name": "original-configuration"},
                            "native_intake_catalogue": {"name": "original-intake"}},
            "retain_until": self.floor,
            "storage_unique_mount_id": 123,
            "namespace_cookie": 456,
        }
        self.previous = {"schema": self.previous_schema}
        self.config = SimpleNamespace(registry_path="/unit/registry", registry_sha256="e" * 64,
                                      preparation_config_path="/unit/preparation", preparation_config_sha256="f" * 64)
        self.preparation = SimpleNamespace(lock_path=str(self.parent / "lock"), storage_quota_policy_sha256="c" * 64)
        self.selected = SimpleNamespace(ledger_path=str(self.bank), cell_config_path="/unit/cell",
                                        cell_sha256="a" * 64, identity={})
        scope = {"run": self.run_id, "original_lease": self.lease,
                 "original_record_sha256": self.retirement["original_record"]["sha256"]}
        for position, step in enumerate(cells.SEVENTEENTH_RETIREMENT_STEPS):
            intent = scope | {"at": self.floor + 2 * position, "step": step, "metadata": {"fixture_step": step}}
            self.write(step + "-intent.json", intent)
            self.write(step + "-receipt.json", intent | {"at": intent["at"] + 1,
                "state": "separate-effect-verified", "original_unknown_resolved": False})
        self.write("storage-identities.json", {"identities": [[1792, 8]]})
        self.write("complete-receipt.json", scope | {"at": self.floor + 28, "scope": self.scope,
            "retain_until": self.floor, "original_bank_sha256": self.retirement["original_bank"]["state_file_sha256"],
            "storage_policy_sha256": self.preparation.storage_quota_policy_sha256, "storage_unique_mount_id": 123,
            "original_unknown_preserved": True, "original_unknown_resolved": False,
            "native_case_acceptance": False, "all_original_resources_absent": True})

    def write(self, name, row):
        payload = ledger.canonical(row) + b"\n"
        path = self.root / name
        path.write_bytes(payload)
        path.chmod(0o600)
        self.retirement["journal"]["members"][name] = hashlib.sha256(payload).hexdigest()

    def read(self):
        with patch.object(run_factory.time, "time", return_value=self.floor + 35):
            return self.read_journal(self.retirement, self.parent)

    def revalidate(self, successor_bank=None, successor=None):
        pin = self.retirement["original_bootstrap"]
        original = SimpleNamespace(path=pin["path"], sha256=pin["sha256"], file_stamp=(20, 21),
                                   value={"ledger_path": str(self.bank)})
        descriptor = {"schema": self.previous_schema, "successor": {"source_sha": self.source_revision,
                     "run_id": self.run_id, "reusable_sha": self.controller_revision}}
        invocation = {"invocation": {"selector": "original-cell"}}
        store = Mock(path=self.bank)
        store.lease_ids.return_value = (self.lease,)
        store.read.side_effect = lambda _: deepcopy(self.record)
        store.read_policy.return_value = {"retention_seconds": 14400}
        with (patch.object(run_factory.time, "time", return_value=self.floor + 35),
              patch.multiple(run_factory, load_bootstrap=Mock(return_value=original),
                             _continuation_receipt=Mock(return_value=(descriptor, self.previous)),
                             _retired_original_entries=Mock(return_value=({}, self.config, invocation))),
              patch.object(run_factory.policy_registry, "load_registry",
                           return_value=Mock(**{"select.return_value": self.selected})),
              patch.object(run_factory.preparation, "_config",
                           return_value=(self.preparation, None, None)),
              patch.object(ledger, "_observe_historical_bank", return_value=nullcontext()),
              patch.object(ledger, "Ledger", return_value=nullcontext(store))):
            self.read_retirement(self.retirement, self.previous, successor_bank, successor)
        return store

    def reseal_record(self):
        digest = ledger.digest(self.record)
        self.retirement["original_record"]["sha256"] = digest
        for name in self.retirement["journal"]["members"]:
            row = json.loads((self.root / name).read_bytes())
            if "original_record_sha256" in row:
                self.write(name, row | {"original_record_sha256": digest})


class SeventeenthRetirementJournalTests(OCIRetirementFixture):
    run_id = cells.SEVENTEENTH_RUN
    job_id = cells.SEVENTEENTH_CHECKS[0]
    lease = cells.SEVENTEENTH_LEASE
    floor = cells.SEVENTEENTH_RETAIN_UNTIL
    source_revision = cells.SEVENTEENTH_MAIN
    controller_revision = cells.SIXTEENTH_SUCCESSOR_REUSABLE
    previous_schema = 16
    scope = "exact-seventeenth-original-retirement"
    read_journal = staticmethod(run_factory._seventeenth_journal)
    read_retirement = staticmethod(run_factory._revalidate_seventeenth_retirement)

    def test_separate_native_receipt_preserves_actual_failed_result(self):
        rows = self.read()
        name = "complete-receipt.json"
        self.assertFalse(rows[name]["native_case_acceptance"])
        for changed in ({"original_unknown_resolved": True}, {"native_case_acceptance": True},
                        {"original_bank_sha256": "d" * 64}, {"at": self.floor + 36}):
            with self.subTest(changed=changed):
                self.write(name, rows[name] | changed)
                with self.assertRaisesRegex(identity.Denied, "continuation-seventeenth-journal-completion"):
                    self.read()

    def test_early_effect_or_missing_receipt_holds_admission(self):
        rows = self.read()
        step = cells.SEVENTEENTH_RETIREMENT_STEPS[0]
        name = step + "-intent.json"
        self.write(name, rows[name] | {"at": self.floor - 1})
        with self.assertRaisesRegex(identity.Denied, "continuation-seventeenth-journal-effect"):
            self.read()
        self.write(name, rows[name])
        (self.root / (step + "-receipt.json")).unlink()
        with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-journal-inventory"):
            self.read()

    def test_full_revalidation_reads_the_sealed_bank_journal_and_resource_state(self):
        with patch.object(run_factory, "_twelfth_resources_absent") as absence:
            self.revalidate()
        absence.assert_called_once_with(self.config, self.selected, self.record, self.lease, self.read(), None, None,
                                        expected_cookie=456)

    def test_changed_or_aliased_bank_denies_before_resource_readback(self):
        with (patch.object(run_factory, "_twelfth_resources_absent") as absence,
              self.assertRaisesRegex(identity.Denied, "continuation-seventeenth-bank-alias")):
            successor = str(self.parent / "successor")
            real_open = run_factory.installation._open_directory
            with patch.object(run_factory.installation, "_open_directory",
                              side_effect=lambda path: real_open(str(self.bank) if path == successor else path)):
                self.revalidate(successor, {})
        absence.assert_not_called()
        self.bank_file.write_bytes(b'{"retained":false}\n')
        with (patch.object(run_factory, "_twelfth_resources_absent") as absence,
              self.assertRaisesRegex(identity.Denied, "continuation-seventeenth-original-bank")):
            self.revalidate()
        absence.assert_not_called()

    def test_resolved_engine_effect_denies_even_with_matching_record_hash(self):
        self.record["effects"][self.effect]["state"] = "verified"
        self.reseal_record()
        with self.assertRaisesRegex(identity.Denied, "continuation-seventeenth-original-unknown"):
            self.revalidate()

    def test_retention_must_bind_to_the_actual_terminal_time(self):
        self.record["native_terminal"]["completed_at"] += 1
        self.reseal_record()
        with self.assertRaisesRegex(identity.Denied, "continuation-seventeenth-original-terminal-retention"):
            self.revalidate()

    def test_returned_storage_path_denies_successor_admission(self):
        graph = self.parent / "graph"
        graph.mkdir(mode=0o700)
        cell = {"engine": {"paths": {"descriptor": str(self.parent)}}}
        data = {"engine": {"storage_root": str(graph), "runroot": str(self.parent / "runroot")},
                "output_path": str(self.parent / "output"), "context_path": str(self.parent / "context")}
        with (patch.multiple(run_factory.cell_contract, _sealed=Mock(return_value=(cell, None, None)),
                             _environment=Mock(return_value={}), _descriptor=Mock(return_value=data)),
              self.assertRaisesRegex(identity.Denied, "cleanup-storage-returned-path")):
            self.revalidate()


class EighteenthRetirementJournalTests(OCIRetirementFixture):
    run_id = cells.EIGHTEENTH_RUN
    job_id = cells.EIGHTEENTH_CHECKS[0]
    lease = cells.EIGHTEENTH_LEASE
    floor = cells.EIGHTEENTH_RETAIN_UNTIL
    source_revision = cells.EIGHTEENTH_MAIN
    controller_revision = cells.SEVENTEENTH_SUCCESSOR_REUSABLE
    previous_schema = 17
    scope = "exact-eighteenth-original-retirement"
    read_journal = staticmethod(run_factory._eighteenth_journal)
    read_retirement = staticmethod(run_factory._revalidate_eighteenth_retirement)
    absence_name = "podman-container-absence.json"

    def setUp(self):
        super().setUp()
        effect, proof = podman_exit_fixture()
        self.record["effects"][self.effect] = effect
        self.retirement["original_record"]["engine_exit_sha256"] = ledger.digest(effect["engine_exit"])
        self.reseal_record()
        self.receipt = {"run": self.run_id, "original_lease": self.lease,
                        "original_record_sha256": ledger.digest(self.record),
                        "at": self.floor, "proof": proof}
        self.write(self.absence_name, self.receipt)

    def test_full_revalidation_matches_original_exit_and_rechecks_scoped_absence_without_writes(self):
        original = deepcopy(self.record)
        bank = self.bank_file.read_bytes()
        journal = {name: (self.root / name).read_bytes() for name in self.retirement["journal"]["members"]}
        with patch.object(run_factory, "_twelfth_resources_absent") as absent:
            store = self.revalidate()
        absent.assert_called_once_with(self.config, self.selected, original, self.lease, self.read(), None, None,
                                       expected_cookie=456)
        self.assertEqual(store.method_calls, [
            call.lease_ids(), call.read(self.lease), call.read_policy(original["policy_sha256"]), call.read(self.lease),
        ])
        self.assertEqual(self.record, original)
        self.assertEqual(original["effects"][self.effect]["state"], "unknown")
        self.assertEqual(self.bank_file.read_bytes(), bank)
        self.assertTrue(all((self.root / name).read_bytes() == raw for name, raw in journal.items()))

    def test_missing_podman_receipt_denies_before_scoped_readback(self):
        (self.root / self.absence_name).unlink()
        with (patch.object(run_factory, "_twelfth_resources_absent") as absent,
              self.assertRaisesRegex(identity.Denied, "continuation-twelfth-journal-inventory")):
            self.revalidate()
        absent.assert_not_called()

    def test_late_or_mismatched_podman_receipt_denies_before_scoped_readback(self):
        for change in ({"at": self.floor + 1}, {"at": self.floor - 1},
                       {"proof": self.receipt["proof"] | {"engine_exit_sha256": "0" * 64}}):
            with self.subTest(change=change), patch.object(run_factory, "_twelfth_resources_absent") as absent:
                self.write(self.absence_name, self.receipt | change)
                with self.assertRaisesRegex(identity.Denied, "continuation-eighteenth-podman-absence"):
                    self.revalidate()
                absent.assert_not_called()

    def test_receipt_cannot_replace_actual_exit_or_scoped_absence(self):
        original = deepcopy(self.record)
        wanted = self.retirement["original_record"]["engine_exit_sha256"]
        self.retirement["original_record"]["engine_exit_sha256"] = "0" * 64
        self.write(self.absence_name, self.receipt | {"proof": self.receipt["proof"] | {"engine_exit_sha256": "0" * 64}})
        with (patch.object(run_factory, "_twelfth_resources_absent") as absent,
              self.assertRaisesRegex(identity.Denied, "continuation-eighteenth-original-exit")):
            self.revalidate()
        absent.assert_not_called()
        self.retirement["original_record"]["engine_exit_sha256"] = wanted
        self.write(self.absence_name, self.receipt)
        graph = self.parent / "returned-graph"
        graph.mkdir(mode=0o700)
        cell = {"engine": {"paths": {"descriptor": str(self.parent)}}}
        descriptor = {"engine": {"storage_root": str(graph), "runroot": str(self.parent / "runroot")},
                      "output_path": str(self.parent / "output"), "context_path": str(self.parent / "context")}
        with (patch.multiple(run_factory.cell_contract, _sealed=Mock(return_value=(cell, None, None)),
                             _environment=Mock(return_value={}), _descriptor=Mock(return_value=descriptor)),
              self.assertRaisesRegex(identity.Denied, "cleanup-storage-returned-path")):
            self.revalidate()
        self.assertEqual(self.record, original)
        self.assertEqual(self.record["effects"][self.effect]["state"], "unknown")


@unittest.skipUnless(os.geteuid() == 0 and sys.platform == "linux", "private Root Linux EE only")
class NineteenthRetirementJournalTests(OCIRetirementFixture):
    run_id = cells.NINETEENTH_RUN
    job_id = cells.NINETEENTH_CHECKS[0]
    lease = cells.NINETEENTH_LEASE
    floor = cells.NINETEENTH_RETAIN_UNTIL
    source_revision = cells.NINETEENTH_MAIN
    controller_revision = cells.EIGHTEENTH_SUCCESSOR_REUSABLE
    previous_schema = 18
    scope = "exact-nineteenth-original-retirement"
    read_journal = staticmethod(run_factory._nineteenth_journal)

    def setUp(self):
        super().setUp()
        for name in tuple(self.retirement["journal"]["members"]):
            if name.endswith(("-intent.json", "-receipt.json")) and name != "complete-receipt.json":
                (self.root / name).unlink()
                del self.retirement["journal"]["members"][name]
        original = self.retirement["original_record"]
        original["start_effect_id"] = original.pop("unknown_effect_id")
        original["engine_exit_sha256"] = "b" * 64
        identity = {"run": self.run_id, "original_lease": self.lease, "original_record_sha256": original["sha256"]}
        self.write("diagnostic-archive.json", identity | {"at": self.floor})
        self.write("podman-container-absence.json", identity | {"at": self.floor + 1})
        for index, step in enumerate(cells.NINETEENTH_RETIREMENT_STEPS):
            actual = identity | {"step": step, "metadata": {"reference": step}, "at": self.floor + 2 + index * 2}
            self.write(step + "-intent.json", actual)
            self.write(step + "-receipt.json", actual | {"at": actual["at"] + 1, "state": "separate-effect-verified"})
        complete = json.loads((self.root / "complete-receipt.json").read_bytes())
        complete["original_failure_preserved"] = True
        self.write("complete-receipt.json", complete)

    def test_retirement_has_original_diagnostics_and_separate_idle_baseline_normalization(self):
        proof = self.read()
        self.assertIn("diagnostic-archive.json", proof)
        self.assertNotIn("certificate-revoke-receipt.json", proof)
        self.assertIn("fence-baseline-normalize-receipt.json", proof)
        self.assertFalse(proof["complete-receipt.json"]["native_case_acceptance"])

    def test_late_diagnostic_archive_is_denied(self):
        name = "diagnostic-archive.json"
        record = json.loads((self.root / name).read_bytes())
        self.write(name, record | {"at": self.floor + 3})
        with self.assertRaisesRegex(identity.Denied, "continuation-nineteenth-journal-binding"):
            self.read()


class SixteenthContinuationTests(unittest.TestCase):
    def test_pinned_successor_admits_first_attempt_and_rejects_replay(self):
        workflow = cells.SIXTEENTH_SUCCESSOR_WORKFLOW
        reusable = cells.SIXTEENTH_SUCCESSOR_REUSABLE
        successor = {
            "source_sha": "a" * 40, "run_id": 90000000001, "run_attempt": 1,
            "first_parent": cells.SIXTEENTH_MAIN, "source_workflow_sha256": workflow, "reusable_sha": reusable,
        }
        descriptor = {
            "schema": 16, "reason": cells.SIXTEENTH_REASON,
            "qualification": {"path": "/unit/g06-qualification.json", "sha256": cells.SIXTEENTH_QUALIFICATION},
            "successor": successor,
        }
        self.assertEqual(cells.validate_continuation_descriptor(descriptor, workflow, reusable), descriptor)
        commit = {"sha": successor["source_sha"], "parents": [{"sha": cells.SIXTEENTH_MAIN}]}
        cells.validate_continuation_commit(commit, descriptor, successor["source_sha"], successor["run_id"], reusable)
        for invalid in ({"run_attempt": 2}, {"run_id": cells.SIXTEENTH_RUN}, {"source_sha": cells.SIXTEENTH_MAIN},
                        {"first_parent": cells.FIFTEENTH_MAIN}, {"reusable_sha": cells.FIFTEENTH_SUCCESSOR_REUSABLE}):
            with self.subTest(invalid=invalid), self.assertRaises(identity.Denied):
                cells.validate_continuation_descriptor(descriptor | {"successor": successor | invalid}, workflow, reusable)

    def test_qualification_binds_the_original_terminal_graph(self):
        graph = sixteenth_native_capture()
        reference = {"device": 10, "inode": 20}
        previous = {"schema": 15}
        receipt = {
            "schema": 16, "purpose": cells.SIXTEENTH_REASON, "native_sixteenth": graph,
            "previous_qualification": previous,
            "previous_bootstrap": reference | {"path": "/unit/old/bootstrap.json", "sha256": "a" * 64},
            "previous_bank": reference | {"path": "/unit/old/ledger", "state_file_sha256": "b" * 64},
        }
        counts = {"native_intake_catalogue": 10, "native_run_configuration_catalogue": 9}
        with (patch.object(cells, "SIXTEENTH_QUALIFICATION", ledger.digest(receipt)),
              patch.object(cells, "_validate_fifteenth_qualification", return_value=counts) as validate_previous):
            self.assertEqual(cells.validate_continuation_qualification(receipt), counts)
            validate_previous.assert_called_once_with(previous)
        changed = deepcopy(receipt)
        changed["native_sixteenth"]["run"]["conclusion"] = "success"
        with (patch.object(cells, "SIXTEENTH_QUALIFICATION", ledger.digest(changed)),
              self.assertRaisesRegex(identity.Denied, "continuation-sixteenth-history")):
            cells.validate_continuation_qualification(changed)

    def test_native_history_observes_the_exact_original_jobs_and_checks(self):
        graph = sixteenth_native_capture()
        controller = cells.FIFTEENTH_SUCCESSOR_REUSABLE
        run = graph["run"] | {
            "repository": {"id": 1103407173, "full_name": "ltn-it/ansible-collection-supplementary",
                           "private": False, "owner": {"id": 54334171}},
            "referenced_workflows": [{"sha": controller,
                "path": "ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@" + controller}],
        }
        inventory = {"total_count": len(graph["jobs"]), "jobs": graph["jobs"]}
        jobs = {row["id"]: row for row in graph["jobs"]}
        check_ids = cells.SIXTEENTH_CHECKS
        checks = [jobs[identifier] | {"app": {"id": 15368, "slug": "github-actions"}} for identifier in check_ids]
        provider = Mock(side_effect=[run, inventory, *checks, inventory])
        self.assertEqual(run_factory._continuation_sixteenth_native(provider), graph)
        run_path = f"/actions/runs/{cells.SIXTEENTH_RUN}"
        jobs_path = run_path + "/attempts/1/jobs?per_page=100&page=1"
        self.assertEqual(provider.call_args_list, [call(run_path), call(jobs_path),
            *[call(f"/check-runs/{identifier}") for identifier in check_ids], call(jobs_path)])
        drifted = deepcopy(inventory)
        drifted["jobs"][0]["name"] += " (modified)"
        for before, after, reason in ((drifted, drifted, "continuation-ninth-original-failed-graph"),
                                      (inventory, drifted, "continuation-ninth-native-inventory-drift")):
            with self.subTest(reason=reason), self.assertRaisesRegex(identity.Denied, reason):
                run_factory._continuation_sixteenth_native(Mock(side_effect=[run, before, *checks, after]))


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Root Linux preservation fixture")
class SixteenthBankPreservationTests(unittest.TestCase):
    def setUp(self):
        parent = Path("/run/proof")
        if not parent.is_dir() or parent.stat().st_uid != 0 or parent.stat().st_mode & 0o077:
            self.skipTest("private Root fixture directory /run/proof required")
        root = Path(self.enterContext(tempfile.TemporaryDirectory(dir=parent, prefix="sixteenth-preservation-")))
        self.old, self.new = root / "original", root / "successor"
        for bank in (self.old, self.new):
            bank.mkdir(mode=0o700)
            ledger.Ledger.initialize(str(bank))
        self.state = self.old / "state.json"
        self.bootstrap_path = root / "bootstrap.json"
        self.bootstrap_path.touch(mode=0o600)
        original_stat = self.bootstrap_path.stat()
        previous = {"schema": 15}
        original = SimpleNamespace(path=str(self.bootstrap_path), sha256="a" * 64, value={"ledger_path": str(self.old)},
                                   file_stamp=(original_stat.st_dev, original_stat.st_ino))
        self.receipt = {
            "previous_bootstrap": {"path": original.path, "sha256": original.sha256,
                                   "device": original_stat.st_dev, "inode": original_stat.st_ino},
            "previous_bank": {"path": str(self.old), "device": self.old.stat().st_dev, "inode": self.old.stat().st_ino,
                              "state_file_sha256": hashlib.sha256(self.state.read_bytes()).hexdigest()},
            "previous_qualification": previous,
        }
        self.load = self.enterContext(patch.object(run_factory, "load_bootstrap", return_value=original))
        self.enterContext(patch.object(run_factory, "_continuation_receipt", return_value=(
            {"schema": 15, "successor": {"run_id": cells.SIXTEENTH_RUN, "source_sha": cells.SIXTEENTH_MAIN}}, previous)))

    def test_empty_original_is_verified_without_modifying_its_state(self):
        state = self.state.read_bytes(), self.state.stat().st_mtime_ns
        run_factory._revalidate_sixteenth_prelease(self.receipt, str(self.new))
        self.assertEqual((self.state.read_bytes(), self.state.stat().st_mtime_ns), state)

    def test_original_bank_reuse_and_alias_are_refused(self):
        with self.assertRaisesRegex(identity.Denied, "continuation-tenth-bank-reuse"):
            run_factory._revalidate_sixteenth_prelease(self.receipt, str(self.old))
        with (patch.object(run_factory.installation, "_open_directory", return_value=os.open(self.old, os.O_RDONLY)),
              self.assertRaisesRegex(identity.Denied, "continuation-tenth-bank-alias")):
            run_factory._revalidate_sixteenth_prelease(self.receipt, str(self.new))

    def test_changed_bank_state_and_bootstrap_inode_are_refused(self):
        with ledger.Ledger(str(self.old)) as store:
            store.archive_policy({"custodian_ref": "synthetic-custodian", "storage_ref": "synthetic-store",
                                  "approval_ref": "synthetic-approval", "retention_seconds": 14400,
                                  "max_lease_seconds": 1800})
        with self.assertRaisesRegex(identity.Denied, "continuation-sixteenth-original-prelease-state"):
            run_factory._revalidate_sixteenth_prelease(self.receipt, str(self.new))
        original = self.load.return_value
        with (patch.object(original, "file_stamp", (original.file_stamp[0], original.file_stamp[1] + 1)),
              self.assertRaisesRegex(identity.Denied, "continuation-sixteenth-original-bootstrap")):
            run_factory._revalidate_sixteenth_prelease(self.receipt, str(self.new))


class PodmanContinuationTests(unittest.TestCase):
    def setUp(self):
        self.lookup = {"path": "/unit/qualification.json", "sha256": "b" * 64}
        self.route = {
            "schema": 12,
            "reason": cells.TWELFTH_REASON,
            "qualification": self.lookup,
            "successor": {
                "source_sha": "a" * 40,
                "run_id": 44910000000,
                "run_attempt": 1,
                "first_parent": cells.TWELFTH_MAIN,
                "source_workflow_sha256": "c" * 64,
                "reusable_sha": "d" * 40,
            },
        }

    def validate(self, route):
        return cells.validate_continuation_descriptor(route, "c" * 64, "d" * 40)

    def test_fourteenth_successor_binds_new_workflow_and_cannot_readmit_the_failed_push(self):
        successor = {
            "source_sha": "a" * 40, "run_id": 90000000001, "run_attempt": 1,
            "first_parent": cells.FOURTEENTH_MAIN, "source_workflow_sha256": cells.FOURTEENTH_SUCCESSOR_WORKFLOW,
            "reusable_sha": cells.FOURTEENTH_SUCCESSOR_REUSABLE,
        }
        route = {"schema": 14, "reason": cells.FOURTEENTH_REASON,
                 "qualification": {"path": "/unit/qualification.json", "sha256": cells.FOURTEENTH_QUALIFICATION},
                 "successor": successor}
        digest = successor["source_workflow_sha256"]
        reusable = successor["reusable_sha"]
        self.assertEqual(cells.validate_continuation_descriptor(route, digest, reusable), route)
        commit = {"sha": successor["source_sha"], "parents": [{"sha": cells.FOURTEENTH_MAIN}]}
        cells.validate_continuation_commit(commit, route, successor["source_sha"], successor["run_id"], reusable)
        for invalid in ({"run_attempt": 2}, {"run_id": cells.FOURTEENTH_RUN},
                        {"source_sha": cells.FOURTEENTH_MAIN}, {"source_sha": cells.THIRTEENTH_MAIN},
                        {"first_parent": cells.THIRTEENTH_MAIN}, {"reusable_sha": cells.THIRTEENTH_SUCCESSOR_REUSABLE},
                        {"source_workflow_sha256": cells.THIRTEENTH_SUCCESSOR_WORKFLOW}):
            with self.subTest(invalid=invalid), self.assertRaises(identity.Denied):
                cells.validate_continuation_descriptor(route | {"successor": successor | invalid}, digest, reusable)

    def test_fifteenth_successor_requires_completed_retirement_and_fresh_push(self):
        descriptor = {"schema": 15, "reason": cells.FIFTEENTH_REASON, "qualification": self.lookup,
                      "successor": self.route["successor"] | {"first_parent": cells.FIFTEENTH_MAIN}}
        with patch.object(cells, "FIFTEENTH_QUALIFICATION", None):
            with self.assertRaisesRegex(identity.Denied, "continuation-fifteenth-qualification"):
                self.validate(descriptor)
        with patch.multiple(cells, FIFTEENTH_QUALIFICATION="b" * 64,
                            FIFTEENTH_SUCCESSOR_WORKFLOW="c" * 64, FIFTEENTH_SUCCESSOR_REUSABLE="d" * 40):
            row = descriptor["successor"]
            commit = {"sha": row["source_sha"], "parents": [{"sha": cells.FIFTEENTH_MAIN}]}
            cells.validate_continuation_commit(commit, descriptor, row["source_sha"], row["run_id"], row["reusable_sha"])
            for stale in ({"run_id": cells.FIFTEENTH_RUN}, {"source_sha": cells.FIFTEENTH_MAIN},
                          {"run_attempt": 2}, {"first_parent": cells.FOURTEENTH_MAIN}):
                with self.subTest(stale=stale), self.assertRaises(identity.Denied):
                    self.validate(descriptor | {"successor": row | stale})

    def test_fifteenth_journals_preserve_retention_scope_and_order(self):
        lease = cells.FIFTEENTH_LEASE
        original = {"lease_id": lease, "sha256": "e" * 64}
        floor = cells.FIFTEENTH_RETAIN_UNTIL
        identity_fields = {"run": cells.FIFTEENTH_RUN, "original_lease": lease,
                           "original_record_sha256": original["sha256"]}
        names = ("overlay-retirement", "quota-privacy", "network-retirement")
        journals, rows = {}, {}
        for index, ((phase, steps), name) in enumerate(zip(cells.FIFTEENTH_RETIREMENT_STEPS.items(), names)):
            path = f"/unit/c14-{name}-{cells.FIFTEENTH_RUN}"
            start = floor + 30 * index
            journals[phase] = {"path": path}
            data = {"complete-receipt.json": identity_fields | {"at": start + len(steps) * 2,
                    "original_unknown_preserved": True, "all_original_resources_absent": True,
                    "native_case_acceptance": False, "engine_parent_mode": "0o700"}}
            for offset, step in enumerate(steps):
                intent = identity_fields | {"at": start + 2 * offset, "step": step, "metadata": {}}
                data[step + "-intent.json"] = intent
                data[step + "-receipt.json"] = intent | {"at": intent["at"] + 1,
                    "state": "separate-effect-verified", "original_unknown_resolved": False}
            if phase == "network":
                data["storage-identities.json"] = {"identities": [[1, 2]]}
            rows[path] = data
        retirement = {"original_record": original, "retain_until": floor, "journals": journals}

        def read(ref, expected_names):
            self.assertEqual(set(rows[ref["path"]]), expected_names)
            return rows[ref["path"]]

        with (patch.object(run_factory, "_twelfth_journal_members", side_effect=read),
              patch.object(run_factory.time, "time", return_value=floor + 100)):
            self.assertEqual(run_factory._fifteenth_journals(retirement, Path("/unit")), rows[journals["network"]["path"]])
            overlay = rows[journals["overlay"]["path"]]
            overlay["overlay-unmount-intent.json"]["at"] = floor - 1
            with self.assertRaisesRegex(identity.Denied, "continuation-fifteenth-journal-effect"):
                run_factory._fifteenth_journals(retirement, Path("/unit"))
            overlay["overlay-unmount-intent.json"]["at"] = floor
            quota = rows[journals["quota"]["path"]]
            quota["restore-quota-mode-receipt.json"]["original_unknown_resolved"] = True
            with self.assertRaisesRegex(identity.Denied, "continuation-fifteenth-journal-effect"):
                run_factory._fifteenth_journals(retirement, Path("/unit"))

    def test_unproduced_retirement_cannot_authorize_a_successor(self):
        with patch.object(cells, "TWELFTH_QUALIFICATION", None):
            with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-qualification"):
                self.validate(self.route)

    def test_exact_new_push_with_pinned_retirement_and_workflow_pair(self):
        with patch.multiple(cells, TWELFTH_QUALIFICATION="b" * 64,
                            TWELFTH_SUCCESSOR_WORKFLOW="c" * 64, TWELFTH_SUCCESSOR_REUSABLE="d" * 40):
            self.assertEqual(self.validate(self.route), self.route)
            for field, value in (
                    ("run_id", cells.TWELFTH_RUN), ("run_id", cells.ELEVENTH_RUN),
                    ("source_sha", cells.TWELFTH_MAIN), ("run_attempt", 2),
                    ("first_parent", cells.ELEVENTH_MAIN),
                    ("source_workflow_sha256", cells.ELEVENTH_SUCCESSOR_WORKFLOW),
                    ("reusable_sha", cells.ELEVENTH_SUCCESSOR_REUSABLE)):
                candidate = deepcopy(self.route)
                candidate["successor"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(identity.Denied):
                    self.validate(candidate)
            candidate = deepcopy(self.route)
            candidate["qualification"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-qualification"):
                self.validate(candidate)

    def test_native_identity_rejects_drift_in_the_actual_failed_run_inventory(self):
        path = Path(__file__).parent / "fixtures/g06-twelfth-failed-native-graph.json"
        captured = json.loads(path.read_text())
        graph = cells.twelfth_native_projection(captured["run"], captured["inventory"], captured["checks"])
        self.assertEqual(ledger.digest(graph), cells.TWELFTH_GRAPH)
        captured["inventory"]["jobs"][0]["conclusion"] = "cancelled"
        with self.assertRaisesRegex(identity.Denied, "continuation-ninth-original-failed-graph"):
            cells.twelfth_native_projection(captured["run"], captured["inventory"], captured["checks"])

    def test_census_hold_requires_a_new_protected_push_bound_to_the_sealed_prefix(self):
        parent = cells.THIRTEENTH_MAIN
        candidate = {
            "schema": 13,
            "reason": cells.THIRTEENTH_REASON,
            "qualification": {"path": "/unit/qualification.json", "sha256": cells.THIRTEENTH_QUALIFICATION},
            "successor": self.route["successor"] | {
                "first_parent": parent,
                "source_workflow_sha256": cells.THIRTEENTH_SUCCESSOR_WORKFLOW,
                "reusable_sha": cells.THIRTEENTH_SUCCESSOR_REUSABLE,
            },
        }
        caller = candidate["successor"]
        commit = {"sha": caller["source_sha"], "parents": [{"sha": parent}]}
        cells.validate_continuation_commit(commit, candidate, caller["source_sha"], caller["run_id"], caller["reusable_sha"])
        for field, invalid in (("first_parent", cells.TWELFTH_MAIN), ("run_id", cells.THIRTEENTH_RUN),
                               ("run_attempt", 2), ("reusable_sha", cells.TWELFTH_SUCCESSOR_REUSABLE)):
            changed = deepcopy(candidate)
            changed["successor"][field] = invalid
            with self.subTest(field=field), self.assertRaises(identity.Denied):
                cells.validate_continuation_descriptor(changed, caller["source_workflow_sha256"], caller["reusable_sha"])

    def test_census_hold_preserves_only_one_additional_intake_and_no_configuration(self):
        intake_key = "native_intake_catalogue"
        config_key = "native_run_configuration_catalogue"
        previous = {"retirement": {"catalogues": {intake_key: {"old": "intake"}, config_key: {"old": "config"}}}}
        capture = census_native_capture()
        graph = cells.thirteenth_native_projection(capture["run"], capture["inventory"], capture["checks"])
        value = {
            "schema": 13, "purpose": cells.THIRTEENTH_REASON, "native_thirteenth": graph,
            "previous_qualification": previous,
            "retirement": {
                "schema": 1, "kind": "sealed-source-intake-with-no-configuration-or-lease",
                "original_bootstrap": {}, "original_bank": {},
                "intake": {"name": "new", "inventory_sha256": "seal"},
                "catalogues": {intake_key: {"old": "intake", "new": "seal"}, config_key: {"old": "config"}},
            },
        }
        with patch.object(cells, "_validate_twelfth_qualification", return_value={"old": "counts"}):
            with patch.object(cells, "THIRTEENTH_QUALIFICATION", ledger.digest(value)):
                self.assertEqual(cells.validate_continuation_qualification(value), {"old": "counts"})
            value["retirement"]["catalogues"][config_key]["new"] = "unpublished"
            with patch.object(cells, "THIRTEENTH_QUALIFICATION", ledger.digest(value)), \
                 self.assertRaisesRegex(identity.Denied, "continuation-thirteenth-preserved-catalogues"):
                cells.validate_continuation_qualification(value)

    def test_storage_manifest_covers_distinct_full_inode_identities(self):
        raw = {"identities": [[1792, 8], [1792, 9]]}
        self.assertEqual(run_factory._twelfth_storage_identities(raw, 2), {(1792, 8), (1792, 9)})
        for entries in ([[1792, 8], [1792, 8]], [[1792, True]], [[1792, 8], [1792, 9], [1792, 10]]):
            with self.subTest(entries=entries), self.assertRaises(identity.Denied):
                run_factory._twelfth_storage_identities({"identities": entries}, 2)

    def test_existing_storage_can_recycle_inode_numbers_only_after_exact_successor_intent(self):
        successor = self.route["successor"]
        lease = "a" * 32
        row = {
            "identity": {"run_id": successor["run_id"], "caller_sha": successor["source_sha"],
                         "reusable_sha": successor["reusable_sha"]},
            "created_at": 1001, "cell_sha256": "f" * 64, "effects": {},
        }
        with patch.object(ledger, "Ledger") as bank:
            store = bank.return_value.__enter__.return_value
            snapshot = {"leases": {}}
            store._transaction.side_effect = lambda **options: nullcontext(snapshot)
            check = lambda: run_factory._twelfth_successor_storage_started("/unit/bank", successor, 1000)
            self.assertFalse(check())
            snapshot["leases"][lease] = row
            self.assertFalse(check())
            row["effects"]["context"] = {"operation": "context-create", "target": "context:" + row["cell_sha256"],
                                           "state": "intent"}
            self.assertTrue(check())
            for key, value in (("run_id", cells.TWELFTH_RUN), ("reusable_sha", cells.ELEVENTH_SUCCESSOR_REUSABLE)):
                with self.subTest(key=key), patch.dict(row["identity"], {key: value}):
                    with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-storage-generation"):
                        check()
            with patch.dict(row, created_at=999):
                with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-storage-generation"):
                    check()
            row["effects"]["context"]["target"] = "context:" + "b" * 64
            with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-storage-intent"):
                check()

    def test_host_fence_remains_bound_to_the_exact_live_successor(self):
        policy = SimpleNamespace(sha256="e" * 64)
        config = SimpleNamespace(host_api_fence_policy_path="/unit/policy", host_api_fence_policy_sha256=policy.sha256)
        baseline = {"baseline_sha256": "f" * 64, "nft_table_handle": 111}
        successor = self.route["successor"]
        auth = {"valid_until": 5000}
        active = {
            "identity": {"run_id": successor["run_id"], "caller_sha": successor["source_sha"],
                         "reusable_sha": successor["reusable_sha"]},
            "state": "prepared",
            "authorizations": [auth],
            "effects": {
                "creating": {"operation": "fence-create", "state": "verified", "host_api": baseline,
                             "fence": {"host_ifindex": 42}},
                "renewing": {"operation": "fence-renew", "state": "verified", "host_api_authorization": {
                    "authorization_sha256": ledger.digest(auth), "host_ifindex": 42, "peer_ipv4": "10.0.0.2",
                    "issued_boot_ns": 1000000000,
                    "baseline_sha256": baseline["baseline_sha256"], "allow_expires_at": auth["valid_until"],
                }},
            },
        }
        with (patch.object(host_api_fence, "_bound", return_value=policy),
              patch.object(host_api_fence, "_host", side_effect=lambda _: nullcontext()),
              patch.object(host_api_fence, "_baseline", return_value=baseline),
              patch.object(host_api_fence, "_readback", return_value=(111, 99, 0, 0)) as readback,
              patch.object(ledger, "Ledger") as bank):
            store = bank.return_value.__enter__.return_value
            store.host_api_claimants.return_value = ()
            run_factory._twelfth_host_fence(config, 41, "/unit/bank", successor)
            readback.assert_called_once_with(policy)
            readback.return_value = (111, 99, 100, 3000)
            with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-host-fence-baseline"):
                run_factory._twelfth_host_fence(config, 41, "/unit/bank", successor)
            store.host_api_claimants.return_value = ("a" * 32,)
            store.read.return_value = active
            readback.return_value = (111, 99, 100, 5000)
            run_factory._twelfth_host_fence(config, 41, "/unit/bank", successor)
            readback.assert_called_with(policy, tuple_value=(42, "10.0.0.2"), maximum_ms=5400000)
            with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-host-fence-original-tuple"):
                run_factory._twelfth_host_fence(config, 42, "/unit/bank", successor)

    def test_verify_retired_before_cutover_requires_exact_zero_fence_and_no_new_bank(self):
        policy = SimpleNamespace(sha256="e" * 64)
        config = SimpleNamespace(host_api_fence_policy_path="/unit/policy", host_api_fence_policy_sha256=policy.sha256)
        with (patch.object(host_api_fence, "_bound", return_value=policy),
              patch.object(host_api_fence, "_host", return_value=nullcontext()),
              patch.object(host_api_fence, "_baseline", return_value={"nft_table_handle": 111}),
              patch.object(host_api_fence, "_readback", return_value=(111, 99, 0, 0)) as readback,
              patch.object(ledger, "Ledger") as bank):
            run_factory._twelfth_host_fence(config, 41, None, None)
            readback.assert_called_once_with(policy, expected_deadline=0)
            bank.assert_not_called()
            readback.return_value = (111, 99, 1, 3)
            with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-host-fence-baseline"):
                run_factory._twelfth_host_fence(config, 41, None, None)
        with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-successor-pair"):
            run_factory._revalidate_twelfth_retirement({}, {}, "/unit/successor-bank")


class CensusNativeHistoryTests(unittest.TestCase):
    def setUp(self):
        self.native = census_native_capture()
        self.prefix = f"/actions/runs/{cells.THIRTEENTH_RUN}"
        self.jobs = self.prefix + "/attempts/1/jobs?per_page=100&page=1"
        self.graph = cells.thirteenth_native_projection(self.native["run"], self.native["inventory"],
                                                        self.native["checks"])
        self.responses = {self.prefix: self.native["run"], self.jobs: self.native["inventory"]}
        self.responses.update({"/check-runs/" + str(row["id"]): row for row in self.native["checks"]})

    def get(self, name):
        return deepcopy(self.responses[name])

    def test_actual_terminal_graph_and_checks_match_the_fixed_digest(self):
        read = Mock(side_effect=self.get)
        self.assertEqual(run_factory._continuation_thirteenth_native(read), self.graph)
        self.assertEqual(ledger.digest(self.graph), cells.THIRTEENTH_GRAPH)
        check_calls = [call(f"/check-runs/{check}") for check in cells.THIRTEENTH_CHECKS]
        self.assertEqual(read.call_args_list, [call(self.prefix), call(self.jobs), *check_calls, call(self.jobs)])

    def test_changed_or_missing_native_checks_and_terminal_jobs_are_held(self):
        checks = self.native["checks"]
        for changed in (checks[:1], [checks[0] | {"conclusion": "success"}, checks[1]], list(reversed(checks))):
            with self.subTest(changed=len(changed)), self.assertRaisesRegex(identity.Denied, "native-check"):
                cells.thirteenth_native_projection(self.native["run"], self.native["inventory"], changed)
        inventory = deepcopy(self.native["inventory"])
        inventory["jobs"][0]["conclusion"] = "cancelled"
        with self.assertRaisesRegex(identity.Denied, "original-failed-graph"):
            cells.thirteenth_native_projection(self.native["run"], inventory, checks)

    def test_second_read_must_still_match_the_complete_inventory(self):
        drifted = deepcopy(self.native["inventory"])
        drifted["jobs"].pop()
        checks = self.native["checks"]
        read = Mock(side_effect=[self.native["run"], self.native["inventory"], *checks, drifted])
        with self.assertRaisesRegex(identity.Denied, "native-inventory-drift"):
            run_factory._continuation_thirteenth_native(read)

    def test_schema_thirteen_joins_every_previous_family_and_the_actual_graph(self):
        generations = ("third", "fourth", "fifth", "sixth", "seventh", "eighth",
                       "ninth", "tenth", "eleventh", "twelfth")
        receipt = {"legacy_qualification": {"native_origin": {"generation": "original"}},
                   "native_prior": {"generation": "prior"}}
        for part in generations:
            receipt = {"previous_qualification": receipt, f"native_{part}": {"generation": part}}
        receipt = {"previous_qualification": receipt, "native_thirteenth": self.graph}
        with ExitStack() as stack:
            original = stack.enter_context(patch.object(run_factory, "_continuation_original_native",
                side_effect=lambda _, prior=False: {"generation": "prior" if prior else "original"}))
            previous = {part: stack.enter_context(patch.object(run_factory, f"_continuation_{part}_native",
                        return_value={"generation": part})) for part in generations}
            run_factory._continuation_native_histories(self.get, {"schema": 13}, receipt)
            self.assertCountEqual(original.call_args_list, [call(self.get), call(self.get, prior=True)])
            for family in previous.values():
                family.assert_called_once_with(self.get)
            with self.assertRaisesRegex(identity.Denied, "continuation-thirteenth-native-drift"):
                run_factory._continuation_native_histories(
                    self.get, {"schema": 13}, receipt | {"native_thirteenth": {}})


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                     "isolated Root Linux preservation fixture")
class CensusPreservationTests(unittest.TestCase):
    def setUp(self):
        parent = Path("/run/proof")
        if not parent.is_dir() or parent.stat().st_uid != 0 or parent.stat().st_mode & 0o077:
            self.skipTest("private Root fixture directory /run/proof required")
        temporary = tempfile.TemporaryDirectory(dir=parent, prefix="census-preservation-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.original_bank, self.successor_bank, self.earlier_bank = (
            self.root / name for name in ("previous-ledger", "successor-ledger", "earlier-ledger"))
        self.intakes, self.configs = self.root / "intakes", self.root / "configs"
        for path in (self.original_bank, self.successor_bank, self.earlier_bank, self.intakes, self.configs):
            path.mkdir(mode=0o700)
        for bank in (self.original_bank, self.successor_bank, self.earlier_bank):
            ledger.Ledger.initialize(str(bank))
        self.state = self.original_bank / "state.json"
        self.original = self.root / "bootstrap.json"
        self.write(self.original, {"fixture": "original bootstrap"})
        predecessor = {"run_id": cells.THIRTEENTH_RUN, "source_sha": cells.THIRTEENTH_MAIN}
        self.original_bootstrap = SimpleNamespace(
            value={"ledger_path": str(self.original_bank)}, path=str(self.original),
            sha256=hashlib.sha256(self.original.read_bytes()).hexdigest(),
            file_stamp=self.coordinate(self.original),
        )

        job = cells.THIRTEENTH_CHECKS[0]
        binding = {"artifact": {"run_id": cells.THIRTEENTH_RUN, "run_attempt": 1},
                   "source": {"commit_sha": cells.THIRTEENTH_MAIN},
                   "controller": {"commit_sha": cells.TWELFTH_SUCCESSOR_REUSABLE}}
        self.intake = self.intakes / ledger.digest(binding)
        self.intake.mkdir(mode=0o700)
        for name in run_factory.run_intake.ARCHIVES:
            archive = self.intake / name
            archive.write_bytes(("fixture archive " + name).encode())
            archive.chmod(0o600)
        intent = {"binding": binding, "original_job": {"run_id": cells.THIRTEENTH_RUN, "job_id": job, "check_run_id": job}}
        intent_sha = self.write(self.intake / "intent.json", intent)
        self.sealed = {"binding": binding, "intent_sha256": intent_sha}
        seal_sha = self.write(self.intake / "sealed.json", self.sealed)
        prior_config = self.configs / ("d" * 64)
        prior_config.mkdir(mode=0o700)
        self.write(prior_config / "intent.json", {"fixture": "earlier admitted configuration"})

        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(run_factory, "ROOT", str(self.configs)))
        stack.enter_context(patch.object(run_factory.run_intake, "ROOT", str(self.intakes)))
        catalogues = {
            "native_intake_catalogue": {self.intake.name: run_factory._fifth_retired_entry(self.intake)},
            "native_run_configuration_catalogue": {prior_config.name: run_factory._fifth_retired_entry(prior_config)},
        }
        ninth = {"retirement": {"original_bootstrap": {}}, "previous_qualification": {}}
        tenth = {"previous_bank": self.reference(self.earlier_bank), "previous_qualification": ninth}
        eleventh = {"retirement": {}, "previous_qualification": tenth}
        twelfth = {"retirement": {"catalogues": {}}, "previous_qualification": eleventh}
        record = {
            "original_bootstrap": self.reference(self.original) | {"sha256": self.original_bootstrap.sha256},
            "original_bank": self.reference(self.original_bank) | {
                "state_file_sha256": hashlib.sha256(self.state.read_bytes()).hexdigest()
            },
            "intake": self.reference(self.intake) | {"name": self.intake.name, "receipt_sha256": seal_sha},
            "catalogues": catalogues,
        }
        self.receipt = {"retirement": record, "previous_qualification": twelfth}
        self.successor = SimpleNamespace(value={"ledger_path": str(self.successor_bank), "cells": {"heavy": {}}},
                                         sha256="c" * 64)
        self.descriptor = {"schema": 13, "successor": {"run_id": 90000000001,
                           "source_sha": "a" * 40, "reusable_sha": "b" * 40}}
        self.counts = {}
        for kind, directory in (("native_intake_catalogue", self.intakes),
                                ("native_run_configuration_catalogue", self.configs)):
            device, inode = self.coordinate(directory)
            self.counts[kind] = {"directory_device": device, "directory_inode": inode}
        # Isolate already-tested earlier generations and bootstrap parsing.
        stack.enter_context(patch.object(run_factory, "load_bootstrap", return_value=self.original_bootstrap))
        stack.enter_context(patch.object(run_factory, "_continuation_receipt",
              return_value=({"schema": 12, "successor": predecessor}, twelfth)))
        stack.enter_context(patch.object(run_factory, "_revalidate_twelfth_retirement"))
        stack.enter_context(patch.object(run_factory, "_revalidate_eleventh_retirement"))
        stack.enter_context(patch.object(run_factory, "_ninth_retired_partial_projection", return_value=ninth["retirement"]))
        stack.enter_context(patch.dict(cells.NINTH_RETIRED_PARTIAL, original_bank=self.reference(self.earlier_bank)))

    @staticmethod
    def coordinate(path):
        info = path.stat()
        return info.st_dev, info.st_ino

    def reference(self, path):
        device, inode = self.coordinate(path)
        return {"path": str(path), "device": device, "inode": inode}

    @staticmethod
    def write(path, value):
        raw = ledger.canonical(value)
        path.write_bytes(raw)
        path.chmod(0o600)
        return hashlib.sha256(raw).hexdigest()

    def revalidate(self):
        run_factory._continuation_origin_absent(
            self.successor, (self.descriptor, self.receipt, self.counts, None))

    def snapshot(self):
        return {path.relative_to(self.root): (self.coordinate(path), path.stat().st_mtime_ns, path.read_bytes())
                for path in self.root.rglob("*") if path.is_file()}

    def assert_held_without_changes(self, reason):
        before = self.snapshot()
        with self.assertRaisesRegex(identity.Denied, reason):
            self.revalidate()
        self.assertEqual(self.snapshot(), before)

    def test_successor_observes_the_original_files_read_only(self):
        before = self.snapshot()
        self.revalidate()
        self.assertEqual(self.snapshot(), before)

    def test_reused_or_nonempty_predecessor_bank_is_held(self):
        with patch.dict(self.successor.value, ledger_path=str(self.original_bank)):
            self.assert_held_without_changes("continuation-tenth-bank-reuse")
        lease_ids = ledger.Ledger.lease_ids
        with patch.object(ledger.Ledger, "lease_ids",
                          lambda store: ("e" * 32,) if Path(store.path) == self.original_bank else lease_ids(store)):
            self.assert_held_without_changes("continuation-tenth-original-lease")

    def test_altered_ledger_digest_is_held(self):
        proof = self.receipt["retirement"]["original_bank"]
        with patch.dict(proof, state_file_sha256="0" * 64):
            self.assert_held_without_changes("continuation-thirteenth-original-bank")

    def test_missing_or_altered_sealed_intake_is_held(self):
        seal = self.intake / "sealed.json"
        self.write(seal, self.sealed | {"unexpected": True})
        self.assert_held_without_changes("continuation-thirteenth-intake-seal")
        seal.unlink()
        self.assert_held_without_changes("continuation-thirteenth-intake-identity")

    def test_changed_retired_archive_is_held(self):
        archive = self.intake / next(iter(run_factory.run_intake.ARCHIVES))
        archive.write_bytes(b"unexpected archive content")
        self.assert_held_without_changes("continuation-fifth-retired-entry-drift")

    def test_configuration_from_the_held_predecessor_is_rejected(self):
        invocation = {"repository": run_factory.SOURCE, "run_id": cells.THIRTEENTH_RUN, "run_attempt": 1,
                      "check_run_id": cells.THIRTEENTH_CHECKS[0], "job_id": cells.THIRTEENTH_CHECKS[0],
                      "source_sha": cells.THIRTEENTH_MAIN, "reusable_sha": cells.TWELFTH_SUCCESSOR_REUSABLE,
                      "selector": "heavy", "bootstrap_sha256": self.original_bootstrap.sha256}
        identity_fields = ("repository", "run_id", "check_run_id", "selector")
        directory = self.configs / ledger.digest({key: invocation[key] for key in identity_fields})
        directory.mkdir(mode=0o700)
        self.write(directory / "intent.json", {"schema": 1, "invocation": invocation,
            "snapshot_receipt_sha256": "a" * 64, "created_at": 1, "deadline": 2,
            "worker": {}, "job_started_at": 1, "template_sha256": "b" * 64})
        self.assert_held_without_changes("continuation-configuration-original-or-unknown")


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                     "isolated Root Linux preservation fixture")
class AuthorizationHoldPreservationTests(unittest.TestCase):
    def setUp(self):
        from test_github_runner_incus_operating_eighth_prelease_continuation import EighthCompleteStageTests

        fixture = EighthCompleteStageTests("runTest")
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        original = run_factory.load_bootstrap(fixture.original["path"], fixture.original["sha256"])
        self.old_bank, self.new_bank = fixture.old_bank, fixture.next_bank
        self.intake, self.configuration = Path(fixture.stage.directory), Path(fixture.configuration.directory)
        self.paths = [Path(original.path), self.old_bank / "state.json", self.new_bank / "state.json"]
        self.paths.extend(path for directory in (self.intake, self.configuration) for path in directory.rglob("*")
                          if path.is_file())
        bank_info = self.old_bank.stat()
        self.retirement = {
            "original_bootstrap": fixture.original | {"device": original.file_stamp[0], "inode": original.file_stamp[1]},
            "original_bank": {"path": str(self.old_bank), "device": bank_info.st_dev, "inode": bank_info.st_ino,
                              "state_file_sha256": hashlib.sha256((self.old_bank / "state.json").read_bytes()).hexdigest()},
            "new_entries": {"native_intake_catalogue": fixture.prefix["intake"],
                            "native_run_configuration_catalogue": fixture.prefix["configuration"]},
        }
        who = fixture.created.proof.identity
        self.previous = {"schema": 13, "fixture": "sealed predecessor"}
        descriptor = {"schema": 13, "successor": {
            "run_id": who.run_id, "source_sha": who.caller_sha, "reusable_sha": who.reusable_sha}}
        self.enterContext(patch.object(run_factory, "_continuation_receipt",
                                       return_value=(descriptor, self.previous, fixture.counts, None)))
        self.enterContext(patch.multiple(cells, FOURTEENTH_MAIN=who.caller_sha, FOURTEENTH_RUN=who.run_id,
            FOURTEENTH_CHECKS=(who.job_id,), THIRTEENTH_SUCCESSOR_REUSABLE=who.reusable_sha))

    def snapshot(self):
        evidence = {}
        for path in self.paths:
            observed = path.stat()
            evidence[path] = (observed.st_dev, observed.st_ino, observed.st_mode, observed.st_mtime_ns, path.read_bytes())
        return evidence

    def observe(self, successor=None):
        run_factory._revalidate_fourteenth_preservation(self.retirement, self.previous, str(successor or self.new_bank))

    def assert_held_without_changes(self, reason, successor=None):
        before = self.snapshot()
        with self.assertRaisesRegex(identity.Denied, reason):
            self.observe(successor)
        self.assertEqual(self.snapshot(), before)

    def test_preserves_both_complete_entries_and_distinct_banks(self):
        before = self.snapshot()
        self.observe()
        self.assertEqual(self.snapshot(), before)

    def test_retired_configuration_is_excluded_from_successor_catalogue(self):
        root = self.configuration.parent
        catalogues = {"native_run_configuration_catalogue": {
            entry.name: run_factory._fifth_retired_entry(entry) for entry in root.iterdir()}}
        qualified = ({"schema": 14}, {"retirement": {"catalogues": catalogues}}, None, None)
        successor = SimpleNamespace(value={"ledger_path": str(self.new_bank)})
        receipt = run_factory._continuation_receipt
        before = self.snapshot()
        with patch.object(run_factory, "_continuation_receipt",
                          side_effect=lambda value: qualified if value is successor.value else receipt(value)), \
             patch.object(run_factory, "_continuation_origin_absent", side_effect=lambda *_: self.observe()):
            fd = run_factory.installation._open_directory(str(root))
            try:
                self.assertEqual(run_factory._current_configuration_catalogue(successor, fd), [])
            finally:
                os.close(fd)
        self.assertEqual(self.snapshot(), before)

    def test_rejects_alias_and_nonempty_original_bank(self):
        self.assert_held_without_changes("continuation-tenth-bank-reuse", self.old_bank)
        lease_ids = ledger.Ledger.lease_ids
        with patch.object(ledger.Ledger, "lease_ids",
                          lambda store: ("f" * 32,) if Path(store.path) == self.old_bank else lease_ids(store)):
            self.assert_held_without_changes("continuation-tenth-original-lease")

    def test_rejects_changed_intake_seal(self):
        seal = self.intake / "sealed.json"
        body = json.loads(seal.read_bytes())
        seal.write_bytes(ledger.canonical(body | {"fixture_drift": True}))
        self.assert_held_without_changes("continuation-ninth-prefix-receipt")

    def test_rejects_changed_archive(self):
        archive = self.intake / run_factory.run_intake.ARCHIVES[0]
        archive.write_bytes(b"damaged fixture archive")
        self.assert_held_without_changes("intake-archive-stamps")

    def test_rejects_changed_generated_configuration(self):
        config = self.configuration / "runtime.json"
        config.write_bytes(config.read_bytes() + b" ")
        self.assert_held_without_changes("run-config-inventory-drift")


class PodmanRetirementContinuationTests(unittest.TestCase):
    def setUp(self):
        root = Path("/unit/retirement")
        record = "b" * 64
        lease = cells.TWELFTH_LEASE
        namespace = {"device": 4, "inode": 42}
        empty_alias = {"device": 4, "inode": 43}
        original_operation = run_factory._twelfth_original_operation(record)
        binding = {"original_lease": lease, "original_record_sha256": record}
        original = {"storage-identities.json": {"identities": [[4, 44]]}}
        remaining = {}
        for index, step in enumerate(run_factory._TWELFTH_RETIREMENT_STEPS):
            metadata = {"test": step}
            if step == "namespace-mounts":
                metadata = {"namespace": namespace, "mount_ids": [17]}
            if step == "namespace-alias":
                metadata = {"identity": empty_alias}
            journal = original if index <= 4 else remaining
            intent = {**binding, "step": step, "at": 1010 + 3 * index, "metadata": metadata}
            if journal is original:
                intent["operation"] = original_operation
            journal[step + "-intent.json"] = intent
            if step == "namespace-mounts":
                journal[step + "-unknown.json"] = {**intent, "at": 1023, "state": "unknown-no-repeat"}
            else:
                journal[step + "-receipt.json"] = {
                    **intent, "at": intent["at"] + 1, "state": "separate-effect-verified",
                    "original_unknown_resolved": False,
                }
        original_members = {name: ledger.digest(row) for name, row in original.items()}
        original_digest = ledger.digest(original_members)
        following_operation = hashlib.sha256(
            f"G06-remaining-retirement:{original_operation}:{original_digest}".encode()
        ).hexdigest()[:32]
        for row in remaining.values():
            row["operation"] = following_operation
        remaining["namespace-mounts-observation.json"] = {
            "namespace": namespace, "original_mount_ids": [17], "mounted_ids_observed": [],
            "empty_alias_stamp": empty_alias, "namespace_reference_censuses": 2,
            "original_attempt_stays_unknown": True, "original_journal_sha256": original_digest,
            "original_unknown_sha256": original_members["namespace-mounts-unknown.json"],
            "observed_at": 1024,
        }
        remaining["complete-receipt.json"] = {
            **binding, "operation": following_operation, "scope": "exact-twelfth-unattempted-retirement",
            "original_bank_sha256": "c" * 64, "retain_until": 1000, "at": 1050,
            "original_unknown_resolved": False, "native_case_acceptance": False,
            "all_original_resources_absent": True, "namespace": namespace,
            "storage_policy_sha256": "f" * 64, "storage_unique_mount_id": 1001,
            "completed_storage_reference_censuses": 4,
        }
        self.original, self.remaining = original, remaining
        self.retirement = {
            "original_record": {"lease_id": lease, "sha256": record},
            "original_bank": {"path": str(root / "bank" / "original"), "state_file_sha256": "c" * 64},
            "retain_until": 1000,
            "journal": {
                "path": str(root / ("partial-retirement-" + original_operation)),
                "members": original_members,
                "continuation": {
                    "path": str(root / ("partial-retirement-" + following_operation)),
                    "members": {name: ledger.digest(row) for name, row in remaining.items()},
                },
            },
        }

    def read(self):
        def load_members(ref, names):
            rows = self.remaining if ref is self.retirement["journal"]["continuation"] else self.original
            run_factory.require(set(rows) == names, "continuation-twelfth-journal-inventory")
            return deepcopy(rows)

        with patch.object(run_factory, "_twelfth_journal_members", side_effect=load_members):
            return run_factory._twelfth_journal(self.retirement)

    def test_separate_observation_preserves_original_unknown(self):
        rows = self.read()
        self.assertEqual(rows["namespace-mounts-unknown.json"]["state"], "unknown-no-repeat")
        self.assertTrue(rows["namespace-mounts-observation.json"]["original_attempt_stays_unknown"])
        self.assertFalse(rows["complete-receipt.json"]["native_case_acceptance"])

    def test_missing_observation_denies_retirement(self):
        del self.remaining["namespace-mounts-observation.json"]
        with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-journal-inventory"):
            self.read()

    def test_changed_operation_or_journal_location_denies_retirement(self):
        with patch.dict(self.remaining["complete-receipt.json"], {"operation": "a" * 32}):
            with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-journal-lineage"):
                self.read()
        self.retirement["journal"]["continuation"]["path"] += "-different"
        with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-journal-lineage"):
            self.read()

    def test_changed_mount_observations_deny_retirement(self):
        observation = self.remaining["namespace-mounts-observation.json"]
        for key, value in (
            ("original_journal_sha256", "0" * 64),
            ("original_unknown_sha256", "0" * 64),
            ("namespace", {"device": 4, "inode": 99}),
            ("original_mount_ids", [19]),
            ("mounted_ids_observed", [17]),
            ("observed_at", 1022),
        ):
            with self.subTest(key=key), patch.dict(observation, {key: value}):
                with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-observed-mounts"):
                    self.read()


class PodmanRetirementRevalidationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bank_file = self.root / "state.json"
        self.bank_file.write_bytes(b'{"retained":true}\n')
        self.lease = cells.TWELFTH_LEASE
        self.effect_id = "d" * 32
        self.record = {
            "state": "prepared", "created_at": 4000, "expires_at": 8000, "identity": {},
            "effects": {self.effect_id: {
                "operation": "engine-start", "state": "unknown", "engine_capture": {},
            }},
            "native_terminal": {
                "source_sha": cells.TWELFTH_MAIN, "controller_sha": cells.ELEVENTH_SUCCESSOR_REUSABLE,
                "run_id": cells.TWELFTH_RUN, "job_id": cells.TWELFTH_CHECKS[0],
                "check_run_id": cells.TWELFTH_CHECKS[0], "run_attempt": 1,
                "conclusion": "failure", "completed_at": 5000,
            },
            "policy_sha256": "c" * 64,
        }
        self.retirement = {
            "original_bootstrap": {"path": "/unit/bootstrap", "sha256": "b" * 64, "device": 7, "inode": 8},
            "original_record": {"lease_id": self.lease, "sha256": ledger.digest(self.record),
                                "unknown_effect_id": self.effect_id},
            "original_bank": {"path": str(self.root), "device": 7, "inode": 9,
                              "state_file_sha256": hashlib.sha256(self.bank_file.read_bytes()).hexdigest()},
            "new_entries": {
                "native_run_configuration_catalogue": {"name": "original-configuration"},
                "native_intake_catalogue": {"name": "original-intake"},
            },
            "retain_until": 19400,
        }
        self.previous = {"approved_predecessor": True}
        self.original = SimpleNamespace(
            file_stamp=(7, 8), value={"ledger_path": str(self.root)}, path="/unit/bootstrap", sha256="b" * 64,
        )
        self.configuration = SimpleNamespace(
            registry_path="/unit/registry", registry_sha256="e" * 64,
            preparation_config_path="/unit/preparation", preparation_config_sha256="f" * 64,
        )
        self.selected = SimpleNamespace(
            ledger_path=str(self.root), cell_config_path="/unit/cell", cell_sha256="a" * 64, identity={},
        )
        self.rows = {"verified_journal": True}
        self.store = Mock()
        self.store.lease_ids.return_value = (self.lease,)
        self.store.read.side_effect = lambda _lease: deepcopy(self.record)
        self.store.read_policy.return_value = {"retention_seconds": 14400}

    def revalidate(self, successor_bank=None, successor=None, successor_store=None):
        def read_bank(path, maximum, *, private, keep):
            self.assertEqual(str(self.bank_file), path)
            self.assertEqual(run_factory.MAX_POLICY, maximum)
            self.assertTrue(private)
            self.assertFalse(keep)
            return SimpleNamespace(sha256=hashlib.sha256(self.bank_file.read_bytes()).hexdigest()), None, (7, 9)

        descriptor = {"schema": 11, "successor": {
            "source_sha": cells.TWELFTH_MAIN, "run_id": cells.TWELFTH_RUN,
            "reusable_sha": cells.ELEVENTH_SUCCESSOR_REUSABLE,
        }}
        origin = {"invocation": {"selector": "original-cell"}}
        with ExitStack() as stack:
            stack.enter_context(patch.multiple(
                run_factory, load_bootstrap=Mock(return_value=self.original),
                _continuation_receipt=Mock(return_value=(descriptor, self.previous)),
                _retired_original_entries=Mock(return_value=({}, self.configuration, origin)),
                _twelfth_journal=Mock(return_value=self.rows),
            ))
            stack.enter_context(patch.object(
                run_factory.policy_registry, "load_registry", return_value=Mock(
                    **{"select.return_value": self.selected}
                ),
            ))
            stack.enter_context(patch.object(ledger, "_observe_historical_bank", return_value=nullcontext()))
            stack.enter_context(patch.object(
                ledger, "Ledger", side_effect=lambda path, **_: nullcontext(
                    successor_store if path == successor_bank else self.store
                ),
            ))
            stack.enter_context(patch.object(run_factory.installation, "_file", side_effect=read_bank))
            return run_factory._revalidate_twelfth_retirement(
                self.retirement, self.previous, successor_bank, successor
            )

    def test_verified_retention_and_unchanged_original_bank_allow_revalidation(self):
        with patch.object(run_factory, "_twelfth_resources_absent") as absence:
            self.revalidate()
        absence.assert_called_once_with(
            self.configuration, self.selected, self.record, self.lease, self.rows, None, None
        )

    def test_changed_state_file_is_rejected_before_resource_readback(self):
        self.bank_file.write_bytes(b'{"retained":false}\n')
        with (patch.object(run_factory, "_twelfth_resources_absent") as absence,
              self.assertRaisesRegex(identity.Denied, "continuation-twelfth-original-bank")):
            self.revalidate()
        absence.assert_not_called()

    def test_resolved_engine_effect_still_denies_when_its_record_digest_matches(self):
        self.record["effects"][self.effect_id]["state"] = "verified"
        self.retirement["original_record"]["sha256"] = ledger.digest(self.record)
        with (patch.object(run_factory, "_twelfth_resources_absent") as absence,
              self.assertRaisesRegex(identity.Denied, "continuation-twelfth-original-unknown-preserved")):
            self.revalidate()
        absence.assert_not_called()

    def test_returned_graph_directory_denies_successor_admission(self):
        graph = self.root / "graph"
        graph.mkdir()
        cell = {"engine": {"paths": {"descriptor": str(self.root)}}}
        data = {
            "engine": {"storage_root": str(graph), "runroot": str(self.root / "runroot")},
            "output_path": str(self.root / "output"), "context_path": str(self.root / "context"),
        }
        # Use the real filesystem inventory with an unprivileged, test-owned directory.
        def open_test_directory(path, *, private):
            self.assertTrue(private)
            self.assertEqual(str(self.root), path)
            return os.open(path, os.O_RDONLY | os.O_DIRECTORY)

        with (patch.object(run_factory.preparation, "_config", return_value=(SimpleNamespace(), None, None)),
              patch.multiple(run_factory.cell_contract, _sealed=Mock(return_value=(cell, None, None)),
                             _environment=Mock(return_value={}), _descriptor=Mock(return_value=data)),
              patch.object(run_factory.engine, "_directory", side_effect=open_test_directory),
              self.assertRaisesRegex(identity.Denied, "cleanup-storage-returned-path")):
            self.revalidate()

    def modeled_successor_revalidation(self, stack):
        retained = self.root
        successor_bank = retained / "successor-bank"
        successor_bank.mkdir()
        successor = {"run_id": 44910000000, "source_sha": "b" * 40, "reusable_sha": "c" * 40}
        successor_lease = "a" * 32
        boot_id = "11111111-1111-1111-1111-111111111111"
        namespace = {"device": 4, "inode": 1358, "host_ifindex": 41, "cookie": 1359, "boot_id": boot_id}
        certificate = "d" * 64
        baseline = {"nft_table_handle": 111, "baseline_sha256": "e" * 64, "policy_sha256": "f" * 64}
        current_auth = {"valid_until": 31000}
        current_record = {
            "identity": {"run_id": successor["run_id"], "caller_sha": successor["source_sha"],
                         "reusable_sha": successor["reusable_sha"]},
            "created_at": 21000, "cell_sha256": self.selected.cell_sha256,
            "state": "prepared", "authorizations": [current_auth],
            "effects": {
                "context": {"operation": "context-create", "state": "intent",
                            "target": "context:" + self.selected.cell_sha256},
                "creator": {"operation": "fence-create", "state": "verified", "host_api": baseline,
                            "fence": {"host_ifindex": 42, "netns_device": 4, "netns_inode": 1360}},
                "grant": {"operation": "fence-renew", "state": "verified", "host_api_authorization": {
                    "authorization_sha256": ledger.digest(current_auth), "host_ifindex": 42,
                    "issued_boot_ns": 1000000000,
                    "peer_ipv4": "10.0.0.2", "baseline_sha256": baseline["baseline_sha256"],
                    "allow_expires_at": 31000,
                }},
            },
        }
        successor_store = Mock()
        successor_store.lease_ids.return_value = (successor_lease,)
        successor_store.host_api_claimants.return_value = (successor_lease,)
        successor_store.read.side_effect = lambda _: deepcopy(current_record)
        successor_store._transaction.return_value = nullcontext({"leases": {successor_lease: current_record}})
        self.record["effects"].update({
            "fence": {"operation": "fence-create", "state": "verified", "fence": {
                "netns_device": 4, "netns_inode": 1358, "host_ifindex": 41, "boot_id": boot_id,
            }},
            "tls": {"operation": "certificate-create", "state": "verified",
                    "certificate_scope": {"initial_fingerprint": certificate}},
        })
        self.retirement["original_record"]["sha256"] = ledger.digest(self.record)
        policy = SimpleNamespace(sha256=baseline["policy_sha256"])
        config = SimpleNamespace(
            host_api_fence_policy_path="/unit/host-api", host_api_fence_policy_sha256=policy.sha256,
            network_fence_policy_path="/unit/network", network_fence_policy_sha256="1" * 64,
            storage_quota_policy_path="/unit/storage", storage_quota_policy_sha256="2" * 64,
            incus_socket_path="/unit/incus.socket",
        )
        descriptor = str(retained / (self.lease + ".json"))
        data = {"engine": {"storage_root": str(retained / "graph"), "runroot": str(retained / "runroot")},
                "output_path": str(retained / "output"), "context_path": str(retained / "context")}
        paths = {"graph-remove": data["engine"]["storage_root"], "runroot-remove": data["engine"]["runroot"],
                 "output-remove": data["output_path"], "context-remove": data["context_path"],
                 "descriptor-unlink": descriptor}
        device = retained.stat().st_dev
        for index, (step, path) in enumerate(paths.items(), 201):
            self.rows[step + "-receipt.json"] = {"metadata": {
                "path": path, "device": device, "inode": index, "mount_id": 9, "sha256": ledger.digest(data),
            }}
        self.rows.update({
            "complete-receipt.json": {"namespace": namespace, "at": 20000, "storage_unique_mount_id": 1001,
                                      "storage_policy_sha256": config.storage_quota_policy_sha256},
            "certificate-revoke-receipt.json": {"metadata": {"fingerprint": certificate}},
            "storage-identities.json": {"identities": [[device, i] for i in range(201, 206)]},
        })
        cell = {"engine": {"paths": {"descriptor": str(retained)}}, "incus": {}}
        target = {"project": "old-project", "network": "old-network", "pool": "old-pool",
                  "ipv4_address": "10.0.0.1/24", "dns_domain": "example.invalid",
                  "ownership": {"owner": "g06", "repository": "fixture/repo", "run_id": cells.TWELFTH_RUN,
                                "run_attempt": 1, "scenario": "quality", "target": "isolated",
                                "lease_id": self.lease, "cell_sha256": self.selected.cell_sha256},
                  "project_limits": {"cpu": 2, "memory_bytes": 1073741824, "disk_bytes": 1073741824,
                                     "instances": 1, "virtual_machines": 1}}

        def open_directory(path, *, private=False):
            self.assertIn(Path(path), (retained, successor_bank))
            return os.open(path, os.O_RDONLY | os.O_DIRECTORY)

        stack.enter_context(patch.object(run_factory.preparation, "_config", return_value=(config, None, None)))
        stack.enter_context(patch.multiple(
            run_factory.cell_contract, _sealed=Mock(return_value=(cell, None, None)),
            _environment=Mock(return_value={}), _descriptor=Mock(return_value=data),
            _incus=Mock(return_value=target),
        ))
        stack.enter_context(patch.object(run_factory.engine, "_directory", side_effect=open_directory))
        stack.enter_context(patch.object(run_factory.installation, "_open_directory", side_effect=open_directory))
        stack.enter_context(patch.object(os.path, "lexists", return_value=False))
        admin = Mock()
        mutator = Mock()
        mutator.readback.return_value = {"state": "absent_observed"}
        stack.enter_context(patch.object(incus_admin, "RootIncusAdmin", return_value=admin))
        stack.enter_context(patch.object(incus_mutation, "RootIncusMutator", return_value=mutator))
        certificates = stack.enter_context(patch.object(
            incus_mutation, "_certificate_inventory", return_value=([], None)
        ))
        stack.enter_context(patch.multiple(
            network_fence, _bound_policy=Mock(), _host_namespace=Mock(return_value=(4, 1)),
            _ip=Mock(return_value=[{"ifname": "lo", "ifindex": 1}, {"ifname": "new", "ifindex": 42}]),
        ))
        census = stack.enter_context(patch.object(network_fence, "_namespace_refs_drained_once"))
        stack.enter_context(patch.object(engine_executor, "_slice_inactive"))
        gate = Mock(return_value=(111, 99, 13000, 31000))
        stack.enter_context(patch.multiple(
            host_api_fence, _bound=Mock(return_value=policy), _host=Mock(return_value=nullcontext()),
            _baseline=Mock(return_value=baseline), _readback=gate,
        ))
        stack.enter_context(patch.multiple(
            storage_quota, _acquire_paths=Mock(return_value=nullcontext()), _mount_id=Mock(return_value=9),
        ))
        consumers = Mock()
        stack.enter_context(patch.multiple(
            cleanup_storage, _cleanup_limits=Mock(return_value=(10, 2)),
            _unique_mount_id=Mock(return_value=1001), _consumer_read=Mock(),
            _consumer_mount_rows=Mock(), _consumer_mount_targets=Mock(return_value=()),
            _no_consumers=consumers,
        ))
        return (str(successor_bank), successor, successor_store), SimpleNamespace(
            mutator=mutator, certificates=certificates, certificate=certificate, census=census,
            consumers=consumers, gate=gate,
        )

    def test_retirement_revalidation_checks_all_observations_with_a_live_successor(self):
        with ExitStack() as stack:
            args, provider = self.modeled_successor_revalidation(stack)
            self.revalidate(*args)
        self.assertEqual(provider.mutator.readback.call_args_list, [call(kind) for kind in (
            "project", "bridge", "profile", "project", "bridge", "profile"
        )])
        self.assertEqual(provider.certificates.call_count, 2)
        self.assertEqual(provider.census.call_count, 2)
        self.assertEqual(provider.consumers.call_count, 2)
        self.assertEqual(provider.gate.call_count, 2)
        self.assertTrue(all(entry.kwargs["tuple_value"] == (42, "10.0.0.2")
                            for entry in provider.gate.call_args_list))

    def test_returned_certificate_denies_before_successor_admission(self):
        with ExitStack() as stack:
            args, provider = self.modeled_successor_revalidation(stack)
            provider.certificates.return_value = ([
                {"name": "renamed", "projects": [], "fingerprint": provider.certificate},
            ], None)
            with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-certificate-returned"):
                self.revalidate(*args)

    def test_surviving_original_namespace_reference_denies_successor_admission(self):
        with ExitStack() as stack:
            args, provider = self.modeled_successor_revalidation(stack)
            provider.census.side_effect = identity.Denied("fence-namespace-fd-live")
            with self.assertRaisesRegex(identity.Denied, "fence-namespace-fd-live"):
                self.revalidate(*args)


@unittest.skipUnless(os.geteuid() == 0 and Path("/run/proof").is_dir(), "requires private root proof tmpfs")
class PodmanRetirementJournalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir="/run/proof")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.retirement = {
            "original_record": {"lease_id": cells.TWELFTH_LEASE, "sha256": "b" * 64},
            "original_bank": {"state_file_sha256": "c" * 64},
            "retain_until": 1000,
            "journal": {"path": str(self.root), "members": {}},
        }
        binding = {"operation": "a" * 32, "original_lease": cells.TWELFTH_LEASE,
                   "original_record_sha256": "b" * 64}
        namespace = {"device": 4, "inode": 4026532529, "host_ifindex": 12352,
                     "cookie": 1359, "boot_id": "5bf7df2f-6157-4836-9139-0bb5c0ee5dad"}
        for position, step in enumerate(run_factory._TWELFTH_RETIREMENT_STEPS, start=1):
            metadata = {"namespace": namespace} if step == "namespace-mounts" else {"test": step}
            row = binding | {"step": step, "at": 1000 + position, "metadata": metadata}
            self.write(step + "-intent.json", row)
            self.write(step + "-receipt.json", row | {
                "state": "separate-effect-verified", "original_unknown_resolved": False,
            })
        self.write("storage-identities.json", {"identities": [[1792, 8], [1792, 9]]})
        self.write("complete-receipt.json", binding | {
            "scope": "exact-twelfth-original-retirement", "original_bank_sha256": "c" * 64,
            "retain_until": 1000, "at": 1020, "original_unknown_resolved": False,
            "native_case_acceptance": False, "all_original_resources_absent": True, "namespace": namespace,
            "completed_storage_reference_censuses": 4,
            "storage_policy_sha256": "f" * 64, "storage_unique_mount_id": 1001,
        })

    def write(self, name, value):
        raw = ledger.canonical(value) + b"\n"
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)
        self.retirement["journal"]["members"][name] = hashlib.sha256(raw).hexdigest()

    def test_complete_journal_preserves_the_unknown_original(self):
        rows = run_factory._twelfth_journal(self.retirement)
        self.assertFalse(rows["complete-receipt.json"]["original_unknown_resolved"])
        self.assertFalse(rows["complete-receipt.json"]["native_case_acceptance"])
        forged = rows["complete-receipt.json"] | {"original_unknown_resolved": True}
        self.write("complete-receipt.json", forged)
        with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-retirement-result"):
            run_factory._twelfth_journal(self.retirement)

    def test_incomplete_journal_and_actions_before_retention_are_denied(self):
        step = run_factory._TWELFTH_RETIREMENT_STEPS[0]
        intent = self.root / (step + "-intent.json")
        old = json.loads(intent.read_text())
        self.write(intent.name, old | {"at": 999})
        with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-journal-effect"):
            run_factory._twelfth_journal(self.retirement)
        self.write(intent.name, old)
        (self.root / (step + "-receipt.json")).unlink()
        with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-journal-inventory"):
            run_factory._twelfth_journal(self.retirement)

    def test_terminal_namespace_cannot_substitute_a_different_cookie(self):
        complete = self.root / "complete-receipt.json"
        row = json.loads(complete.read_text())
        row["namespace"]["cookie"] += 1
        self.write(complete.name, row)
        with self.assertRaisesRegex(identity.Denied, "continuation-twelfth-journal-namespace"):
            run_factory._twelfth_journal(self.retirement)
