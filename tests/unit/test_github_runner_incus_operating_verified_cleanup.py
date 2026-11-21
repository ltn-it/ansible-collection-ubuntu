"""A closed partial preparation cannot be replayed as a new operating run."""

from copy import deepcopy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "roles/github_runner/files"))
from incus_lease_issuer import identity, ledger, operating_cells as cells, run_factory


class VerifiedCleanupTests(unittest.TestCase):
    def test_next_attempt_must_be_a_new_push_with_the_closed_original_as_parent(self):
        route = {
            "schema": 11,
            "reason": cells.ELEVENTH_REASON,
            "qualification": {"path": "/unit/qualification.json", "sha256": cells.ELEVENTH_QUALIFICATION},
            "successor": {"source_sha": "a" * 40, "run_id": 100, "run_attempt": 1,
                          "first_parent": cells.ELEVENTH_MAIN,
                          "source_workflow_sha256": cells.ELEVENTH_SUCCESSOR_WORKFLOW,
                          "reusable_sha": cells.ELEVENTH_SUCCESSOR_REUSABLE},
        }
        commit = {"sha": "a" * 40, "parents": [{"sha": cells.ELEVENTH_MAIN}]}
        cells.validate_continuation_commit(commit, route, commit["sha"], 100, cells.ELEVENTH_SUCCESSOR_REUSABLE)
        for key, bad in (("source_sha", cells.ELEVENTH_MAIN), ("run_id", cells.ELEVENTH_RUN),
                         ("run_attempt", 2), ("first_parent", cells.TENTH_MAIN),
                         ("source_workflow_sha256", cells.TENTH_SUCCESSOR_WORKFLOW),
                         ("reusable_sha", cells.TENTH_SUCCESSOR_REUSABLE)):
            with self.subTest(key=key):
                replay = deepcopy(route)
                replay["successor"][key] = bad
                with self.assertRaises(identity.Denied):
                    cells.validate_continuation_descriptor(
                        replay, cells.ELEVENTH_SUCCESSOR_WORKFLOW, cells.ELEVENTH_SUCCESSOR_REUSABLE)
        commit["parents"] = [{"sha": cells.TENTH_MAIN}, {"sha": cells.ELEVENTH_MAIN}]
        with self.assertRaises(identity.Denied):
            cells.validate_continuation_commit(commit, route, commit["sha"], 100, cells.ELEVENTH_SUCCESSOR_REUSABLE)

    def test_closed_flag_does_not_replace_retention_or_live_absence(self):
        completed = 1_700_000_000
        retain_until = completed + 14400
        record = {
            "state": "closed", "effects": {}, "policy_sha256": "b" * 64, "closed_at": retain_until,
            "partial_preparation_custody": {"retain_until": retain_until},
            "native_terminal": {"run_id": cells.ELEVENTH_RUN, "run_attempt": 1, "completed_at": completed,
                                "conclusion": "failure", "source_sha": cells.ELEVENTH_MAIN,
                                "controller_sha": cells.TENTH_SUCCESSOR_REUSABLE,
                                "job_id": cells.ELEVENTH_CHECKS[0], "check_run_id": cells.ELEVENTH_CHECKS[0]},
        }
        lease = "c" * 32
        absence = {"project": {"state": "absent_observed"}}
        retirement = {"lease_id": lease, "retain_until": retain_until, "closed_at": retain_until,
                      "record_sha256": ledger.digest(record), "native_absence_sha256": ledger.digest(absence),
                      "bank": {"state_file_sha256": "d" * 64}}
        store = Mock(path=Path("/unit/old"))
        store.read.return_value = record
        store.lease_ids.return_value = (lease,)
        store.read_policy.return_value = {"retention_seconds": 14400}
        file_proof = (SimpleNamespace(sha256="d" * 64), None, (1, 2))
        with (patch.object(run_factory.installation, "_file", return_value=file_proof),
              patch.object(run_factory.ledger.Ledger, "_cleanup_complete"),
              patch.object(run_factory.cell_contract, "partial_preparation_owner"),
              patch.object(run_factory, "_closed_preparation_absence", return_value=absence) as observe):
            run_factory._verify_closed_original_record(store, None, "unit", None, retirement)
            observe.return_value = {"project": {"state": "present"}}
            with self.assertRaisesRegex(identity.Denied, "original-absence-drift"):
                run_factory._verify_closed_original_record(store, None, "unit", None, retirement)
            record["closed_at"] -= 1
            retirement.update(closed_at=record["closed_at"], record_sha256=ledger.digest(record))
            with self.assertRaisesRegex(identity.Denied, "original-retention"):
                run_factory._verify_closed_original_record(store, None, "unit", None, retirement)
