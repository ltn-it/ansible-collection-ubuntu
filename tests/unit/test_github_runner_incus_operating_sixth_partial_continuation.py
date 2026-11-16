"""Actual public sixth graph and modeled future closure; no native acceptance."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import operating_cells as cells, ledger
from incus_lease_issuer.identity import Denied
import test_github_runner_incus_operating_fifth_partial_continuation as fifth_tests


def sixth_native():
    graph = json.loads((Path(__file__).parent / "fixtures/g06-sixth-failed-native-graph.json").read_bytes())
    run = graph["run"]
    run["repository"] = {"id": 1103407173, "full_name": "ltn-it/ansible-collection-supplementary",
                         "private": False, "owner": {"id": 54334171}}
    run["referenced_workflows"] = [{"sha": cells.SIXTH_REUSABLE,
        "path": "ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@" + cells.SIXTH_REUSABLE}]
    inventory = {"total_count": 24, "jobs": graph["jobs"]}
    checks = []
    for identifier in cells.SIXTH_CHECKS:
        job = next(row for row in inventory["jobs"] if row["id"] == identifier)
        checks.append({"id": identifier, "head_sha": cells.SIXTH_MAIN,
            **{k: job[k] for k in ("name", "status", "conclusion", "started_at", "completed_at")},
            "app": {"id": 15368, "slug": "github-actions"}})
    return run, inventory, checks


class SixthPartialHistoryTests(unittest.TestCase):
    def setUp(self):
        self.fifth = fifth_tests.FifthPartialHistoryTests("runTest")
        self.fifth.setUp(); self.addCleanup(self.fifth.doCleanups)
        self.previous = deepcopy(self.fifth.value)
        self.old_bytes = ledger.canonical(self.previous)
        self.native = sixth_native()
        self.retirement = {"schema": 1, "kind": "original-sixth-post-context-pre-fence-verified-closed",
            "lease_id": cells.SIXTH_LEASE, "record_sha256": "c" * 64,
            "closed_at": cells.SIXTH_RETAIN_UNTIL, "retain_until": cells.SIXTH_RETAIN_UNTIL,
            "native_absence_sha256": "d" * 64,
            "catalogues": {"native_intake_catalogue": {"a" * 64: "1" * 64, "c" * 64: "4" * 64},
                           "native_run_configuration_catalogue": {"b" * 64: "2" * 64, "d" * 64: "5" * 64}},
            "original_configuration": {"directory": "/root/configurations/" + "d" * 64,
                                       "manifest_sha256": "3" * 64}}
        self.descriptor = {"schema": 6, "reason": "original-post-context-pre-fence-failed-retired",
            "qualification": {"path": "/root/qualified.json", "sha256": "a" * 64},
            "successor": {"source_sha": "e" * 40, "run_id": cells.SIXTH_RUN + 1, "run_attempt": 1,
                          "first_parent": cells.SIXTH_MAIN, "source_workflow_sha256": cells.SIXTH_SUCCESSOR_WORKFLOW,
                          "reusable_sha": cells.SIXTH_SUCCESSOR_REUSABLE}}

    def previous_hash_model(self):
        # Public fixtures use modeled private-retirement metadata. Only this
        # exact valid five-history snapshot stands for the private pinned3fcc;
        # native closure or a real schema6 receipt is never claimed here.
        original = ledger.digest
        return mock.patch.object(ledger, "digest", side_effect=lambda value:
            cells.SIXTH_PREVIOUS_QUALIFICATION if ledger.canonical(value) == self.old_bytes else original(value))

    def qualification(self):
        return cells.sixth_preparation_continuation_qualification(self.previous, *self.native, self.retirement)

    def test_complete_failed_graph_and_nested_previous_bytes_preserved(self):
        with self.previous_hash_model():
            value = self.qualification()
            self.assertEqual(cells.validate_continuation_qualification(value), self.fifth.four.three.two.counts)
        self.assertEqual(ledger.canonical(value["previous_qualification"]), self.old_bytes)
        rows = {j["id"]: j for j in value["native_sixth"]["jobs"]}
        self.assertEqual(rows[cells.SIXTH_CHECKS[0]]["conclusion"], "success")
        self.assertEqual(rows[cells.SIXTH_JOB]["conclusion"], "failure")
        self.assertEqual(rows[cells.SIXTH_CHECKS[2]]["conclusion"], "failure")
        self.assertEqual(value["native_sixth"]["run"]["conclusion"], "failure")

    def test_exact_new_tuple_and_first_parent_commit_pass(self):
        cells.validate_continuation_descriptor(self.descriptor, cells.SIXTH_SUCCESSOR_WORKFLOW, cells.SIXTH_SUCCESSOR_REUSABLE)
        cells.validate_continuation_commit({"sha": "e" * 40, "parents": [{"sha": cells.SIXTH_MAIN}]},
            self.descriptor, "e" * 40, cells.SIXTH_RUN + 1, cells.SIXTH_SUCCESSOR_REUSABLE)

    def test_old_rerun_parent_or_future_unknown_tuple_denied(self):
        for field, value in [("source_sha", cells.SIXTH_MAIN), ("run_id", cells.SIXTH_RUN),
                             ("run_attempt", 2), ("first_parent", cells.FIFTH_MAIN),
                             ("source_sha", None), ("run_id", None)]:
            changed = deepcopy(self.descriptor); changed["successor"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(Denied):
                cells.validate_continuation_descriptor(changed, cells.SIXTH_SUCCESSOR_WORKFLOW, cells.SIXTH_SUCCESSOR_REUSABLE)

    def test_mixed_unknown_or_argument_mismatched_pair_denied(self):
        for pair in [(cells.SIXTH_WORKFLOW, cells.SIXTH_REUSABLE),
                     (cells.SIXTH_SUCCESSOR_WORKFLOW, cells.SIXTH_REUSABLE),
                     (cells.SIXTH_WORKFLOW, cells.SIXTH_SUCCESSOR_REUSABLE),
                     (cells.FOUR_HISTORY_WORKFLOW, cells.SIXTH_REUSABLE),
                     (cells.SIXTH_SUCCESSOR_WORKFLOW, cells.FOUR_HISTORY_REUSABLE),
                     ("0" * 64, cells.SIXTH_REUSABLE), (cells.SIXTH_SUCCESSOR_WORKFLOW, "0" * 40)]:
            changed = deepcopy(self.descriptor)
            changed["successor"].update(source_workflow_sha256=pair[0], reusable_sha=pair[1])
            with self.subTest(pair=pair), self.assertRaises(Denied):
                cells.validate_continuation_descriptor(changed, *pair)
        with self.assertRaises(Denied):
            cells.validate_continuation_descriptor(self.descriptor, cells.FOUR_HISTORY_WORKFLOW, cells.FOUR_HISTORY_REUSABLE)

    def test_commit_native_must_match_current_tuple(self):
        for commit in [{"sha": "e" * 40, "parents": [{"sha": cells.FIFTH_MAIN}]},
                       {"sha": "f" * 40, "parents": [{"sha": cells.SIXTH_MAIN}]}]:
            with self.assertRaises(Denied):
                cells.validate_continuation_commit(commit, self.descriptor, "e" * 40,
                                                  cells.SIXTH_RUN + 1, cells.SIXTH_SUCCESSOR_REUSABLE)

    def test_unknown_successor_pins_deny_without_changing_original_history(self):
        before = deepcopy(self.native)
        for values in ({"SIXTH_SUCCESSOR_WORKFLOW": None}, {"SIXTH_SUCCESSOR_REUSABLE": None},
                       {"SIXTH_SUCCESSOR_WORKFLOW": None, "SIXTH_SUCCESSOR_REUSABLE": None}):
            with self.subTest(values=values), mock.patch.multiple(cells, **values):
                with self.assertRaisesRegex(Denied, "continuation-sixth-successor-pins-unbound"):
                    cells.validate_continuation_descriptor(self.descriptor,
                        self.descriptor["successor"]["source_workflow_sha256"],
                        self.descriptor["successor"]["reusable_sha"])
                self.assertEqual(cells.sixth_native_projection(*self.native), cells.sixth_native_projection(*before))
        self.assertEqual(cells.SIXTH_REUSABLE, "a94199c94fd00226e194613d0fb9d52705baa808")
        self.assertEqual(cells.SIXTH_WORKFLOW, "64e3d2ca0bd5e442233ec53b00d6f76fb7ba40064abea36237edeb783089b4ba")

    def test_actual_graph_missing_duplicate_green_or_borrowed_denied(self):
        changes = [lambda r, j, c: r.update(conclusion="success"), lambda r, j, c: r.update(run_attempt=2),
            lambda r, j, c: j.update(total_count=True), lambda r, j, c: j["jobs"].pop(),
            lambda r, j, c: j["jobs"].__setitem__(0, deepcopy(j["jobs"][1])),
            lambda r, j, c: c[0].update(conclusion="failure"), lambda r, j, c: c[1].update(conclusion="success"),
            lambda r, j, c: c[2]["app"].update(id=1),
            lambda r, j, c: r["referenced_workflows"][0].update(sha=cells.FOUR_HISTORY_REUSABLE)]
        for number, change in enumerate(changes):
            args = deepcopy(self.native); change(*args)
            with self.subTest(number=number), self.assertRaises(Denied): cells.sixth_native_projection(*args)

    def test_previous_hash_or_nested_history_drift_denied(self):
        with self.previous_hash_model(): value = self.qualification()
        changed = deepcopy(value); changed["previous_qualification"]["retirement"]["record_sha256"] = "e" * 64
        with self.previous_hash_model(), self.assertRaises(Denied): cells.validate_continuation_qualification(changed)
        with self.assertRaises(Denied): cells.validate_continuation_qualification(value)

    def test_open_early_missing_or_unknown_closed_proof_denied(self):
        for field, value in [("closed_at", cells.SIXTH_RETAIN_UNTIL - 1), ("closed_at", True),
                             ("retain_until", cells.SIXTH_RETAIN_UNTIL + 1),
                             ("retain_until", float(cells.SIXTH_RETAIN_UNTIL)),
                             ("retain_until", str(cells.SIXTH_RETAIN_UNTIL)), ("retain_until", True),
                             ("kind", "no-work"),
                             ("lease_id", cells.FIFTH_LEASE), ("record_sha256", None), ("catalogues", {})]:
            changed = deepcopy(self.retirement); changed[field] = value
            with self.subTest(field=field), self.previous_hash_model(), self.assertRaises(Denied):
                cells.sixth_preparation_continuation_qualification(self.previous, *self.native, changed)
        with self.previous_hash_model(), self.assertRaises(Denied):
            cells.sixth_preparation_continuation_qualification(self.previous, *self.native, None)

    def test_old_five_history_interfaces_unchanged(self):
        self.assertEqual(cells.validate_continuation_qualification(self.previous), self.fifth.four.three.two.counts)
        old = deepcopy(self.fifth.descriptor)
        cells.validate_continuation_descriptor(old, cells.FOUR_HISTORY_WORKFLOW, cells.FOUR_HISTORY_REUSABLE)

if __name__ == "__main__": unittest.main(verbosity=2)
