"""The spent pre-lease run is evidence only, including at observer lookup."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "roles/github_runner/files"))
from incus_lease_issuer import identity, operating_cells as cells, run_factory


class TenthPreleaseTests(unittest.TestCase):
    def setUp(self):
        self.route = {
            "schema": 10,
            "reason": "terminal-original-push-without-lease-or-catalogue-addition",
            "qualification": {"path": "/unit/qualification.json", "sha256": cells.TENTH_QUALIFICATION},
            "successor": {"source_sha": "a" * 40, "run_id": 100, "run_attempt": 1,
                          "first_parent": cells.TENTH_MAIN,
                          "source_workflow_sha256": cells.TENTH_SUCCESSOR_WORKFLOW,
                          "reusable_sha": cells.TENTH_SUCCESSOR_REUSABLE},
        }

    def validate(self, route):
        return cells.validate_continuation_descriptor(route, cells.TENTH_SUCCESSOR_WORKFLOW,
                                                      cells.TENTH_SUCCESSOR_REUSABLE)

    def test_only_changed_caller_and_fresh_original_push(self):
        self.assertEqual(self.validate(self.route), self.route)
        for field, bad in (("source_sha", cells.TENTH_MAIN), ("run_id", cells.TENTH_RUN),
                           ("run_attempt", 2), ("run_attempt", True), ("first_parent", cells.NINTH_MAIN),
                           ("source_workflow_sha256", cells.NINTH_SUCCESSOR_WORKFLOW),
                           ("reusable_sha", cells.NINTH_SUCCESSOR_REUSABLE)):
            with self.subTest(field=field, invalid=bad):
                route = deepcopy(self.route)
                route["successor"][field] = bad
                with self.assertRaises(identity.Denied):
                    self.validate(route)
        self.route["qualification"]["sha256"] = "0" * 64
        with self.assertRaises(identity.Denied):
            self.validate(self.route)

    def test_original_main_must_be_actual_first_parent(self):
        commit = {"sha": "a" * 40, "parents": [{"sha": cells.TENTH_MAIN}]}
        cells.validate_continuation_commit(commit, self.route, commit["sha"], 100, cells.TENTH_SUCCESSOR_REUSABLE)
        commit["parents"] = [{"sha": cells.NINTH_MAIN}, {"sha": cells.TENTH_MAIN}]
        with self.assertRaises(identity.Denied):
            cells.validate_continuation_commit(commit, self.route, commit["sha"], 100, cells.TENTH_SUCCESSOR_REUSABLE)

    def test_retained_lease_blocks_before_opening_the_candidate_bank(self):
        bank = {"path": "/unit/old", "device": 10, "inode": 20}
        with patch.object(run_factory.ledger, "Ledger") as store, \
                patch.object(run_factory.installation, "_open_directory") as open_directory:
            store.return_value.__enter__.return_value.lease_ids.return_value = ("retained",)
            with self.assertRaisesRegex(identity.Denied, "continuation-tenth-original-lease"):
                run_factory._check_empty_previous_bank(bank, "/unit/new")
            open_directory.assert_not_called()

    def test_same_ledger_path_is_denied(self):
        bank = {"path": "/unit/old", "device": 10, "inode": 20}
        with self.assertRaisesRegex(identity.Denied, "continuation-tenth-bank-reuse"):
            run_factory._check_empty_previous_bank(bank, bank["path"])
