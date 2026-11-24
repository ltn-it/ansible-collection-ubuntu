"""The spent pre-lease run is evidence only, including at observer lookup."""

from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "roles/github_runner/files")
)
from incus_lease_issuer import identity, ledger, operating_cells as cells, run_factory


class SealedPreleaseContinuationTests(unittest.TestCase):
    def test_sealed_intake_requires_its_original_inode_before_readback(self):
        digest = "a" * 64
        previous = {"schema": 19}
        original = SimpleNamespace(path="/unit/old/bootstrap.json", sha256=digest, file_stamp=(10, 20),
                                   value={"ledger_path": "/unit/old/ledger"})
        descriptor = {"schema": 19, "successor": {"run_id": cells.TWENTIETH_RUN,
                                                 "source_sha": cells.TWENTIETH_MAIN}}
        proof = {
            "previous_bootstrap": {"path": original.path, "sha256": digest, "device": 10, "inode": 20},
            "previous_bank": {"path": original.value["ledger_path"], "device": 10, "inode": 30,
                              "state_file_sha256": digest},
            "previous_qualification": previous,
            "sealed_intake": {"name": "b" * 64, "device": 10, "inode": 40,
                              "seal_sha256": digest, "intent_sha256": digest},
        }
        intent = {
            "original_job": {"run_id": cells.TWENTIETH_RUN, "job_id": cells.TWENTIETH_CHECKS[0],
                             "check_run_id": cells.TWENTIETH_CHECKS[0]},
            "binding": {"source": {"commit_sha": cells.TWENTIETH_MAIN},
                        "controller": {"commit_sha": cells.NINETEENTH_SUCCESSOR_REUSABLE}},
        }
        with (
            patch.object(run_factory, "load_bootstrap", return_value=original),
            patch.object(run_factory, "_continuation_receipt", return_value=(descriptor, previous)),
            patch.object(run_factory, "_check_empty_previous_bank"),
            patch.object(ledger, "_observe_historical_bank"),
            patch.object(ledger, "Ledger") as bank,
            patch.object(run_factory.installation, "_file", return_value=(SimpleNamespace(sha256=digest), b"", None)),
            patch.object(run_factory.installation, "_open_directory", return_value=42),
            patch.object(run_factory.run_intake, "_directory_identity", return_value=(10, 40, 0, 0, 0o40700)),
            patch.object(run_factory.run_intake, "_read_at", return_value=(intent, digest, None)),
            patch.object(run_factory.run_intake, "_sealed_state_unchanged") as check_seal,
            patch.object(run_factory.os, "close") as close,
        ):
            transaction = bank.return_value.__enter__.return_value._transaction
            transaction.return_value.__enter__.return_value = {"leases": {}, "tokens": {}}
            run_factory._revalidate_twentieth_prelease(proof, "/unit/new/ledger")
            check_seal.assert_called_once_with(42, digest)
            close.assert_called_once_with(42)
            check_seal.reset_mock()
            proof["sealed_intake"]["inode"] = 41
            with self.assertRaisesRegex(identity.Denied, "continuation-twentieth-intake-identity"):
                run_factory._revalidate_twentieth_prelease(proof, "/unit/new/ledger")
            check_seal.assert_not_called()


class TenthPreleaseTests(unittest.TestCase):
    def setUp(self):
        self.route = {
            "schema": 10,
            "reason": "terminal-original-push-without-lease-or-catalogue-addition",
            "qualification": {
                "path": "/unit/qualification.json",
                "sha256": cells.TENTH_QUALIFICATION,
            },
            "successor": {
                "source_sha": "a" * 40,
                "run_id": 100,
                "run_attempt": 1,
                "first_parent": cells.TENTH_MAIN,
                "source_workflow_sha256": cells.TENTH_SUCCESSOR_WORKFLOW,
                "reusable_sha": cells.TENTH_SUCCESSOR_REUSABLE,
            },
        }

    def validate(self, route):
        return cells.validate_continuation_descriptor(
            route, cells.TENTH_SUCCESSOR_WORKFLOW, cells.TENTH_SUCCESSOR_REUSABLE
        )

    def test_only_changed_caller_and_fresh_original_push(self):
        self.assertEqual(self.validate(self.route), self.route)
        for field, bad in (
            ("source_sha", cells.TENTH_MAIN),
            ("run_id", cells.TENTH_RUN),
            ("run_attempt", 2),
            ("run_attempt", True),
            ("first_parent", cells.NINTH_MAIN),
            ("source_workflow_sha256", cells.NINTH_SUCCESSOR_WORKFLOW),
            ("reusable_sha", cells.NINTH_SUCCESSOR_REUSABLE),
        ):
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
        cells.validate_continuation_commit(
            commit, self.route, commit["sha"], 100, cells.TENTH_SUCCESSOR_REUSABLE
        )
        commit["parents"] = [{"sha": cells.NINTH_MAIN}, {"sha": cells.TENTH_MAIN}]
        with self.assertRaises(identity.Denied):
            cells.validate_continuation_commit(
                commit, self.route, commit["sha"], 100, cells.TENTH_SUCCESSOR_REUSABLE
            )

    def test_retained_lease_blocks_before_opening_the_candidate_bank(self):
        bank = {"path": "/unit/old", "device": 10, "inode": 20}
        with (
            patch.object(run_factory.ledger, "Ledger") as store,
            patch.object(run_factory.installation, "_open_directory") as open_directory,
        ):
            store.return_value.__enter__.return_value.lease_ids.return_value = (
                "retained",
            )
            with self.assertRaisesRegex(
                identity.Denied, "continuation-tenth-original-lease"
            ):
                run_factory._check_empty_previous_bank(bank, "/unit/new")
            open_directory.assert_not_called()

    def test_same_ledger_path_is_denied(self):
        bank = {"path": "/unit/old", "device": 10, "inode": 20}
        with self.assertRaisesRegex(identity.Denied, "continuation-tenth-bank-reuse"):
            run_factory._check_empty_previous_bank(bank, bank["path"])


class TenthNativeEvidenceTests(unittest.TestCase):
    setUp = TenthPreleaseTests.setUp

    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / "fixtures/g06-tenth-failed-native-graph.json"
        cls.captured = json.loads(path.read_text())

    def native_reader(self, *, omit=None, drift_after_read=False):
        captured = deepcopy(self.captured)
        prefix = f"/actions/runs/{cells.TENTH_RUN}"
        inventory_path = f"{prefix}/attempts/1/jobs?per_page=100&page=1"
        responses = {
            prefix: captured["run"],
            inventory_path: captured["inventory"],
            **{f"/check-runs/{check['id']}": check for check in captured["checks"]},
        }
        self.assertEqual(
            tuple(check["id"] for check in captured["checks"]), cells.TENTH_CHECKS
        )
        calls = []
        self.addCleanup(calls.clear)

        def get(path):
            calls.append(path)
            if path == omit:
                return {}
            row = deepcopy(responses[path])
            if drift_after_read and path == inventory_path and calls.count(path) == 2:
                row["jobs"].pop()
            return row

        return get, calls, inventory_path

    def test_factory_joins_all_ten_histories_with_captured_terminal_graph(self):
        tenth = cells.tenth_native_projection(
            self.captured["run"], self.captured["inventory"], self.captured["checks"]
        )
        first = {"id": "first"}
        second = {"id": "second"}
        prior = {
            "legacy_qualification": {"native_origin": first},
            "native_prior": second,
        }
        functions = {}
        for generation in (
            "third",
            "fourth",
            "fifth",
            "sixth",
            "seventh",
            "eighth",
            "ninth",
        ):
            expected = {"id": generation}
            prior = {"previous_qualification": prior, f"native_{generation}": expected}
            functions[f"_continuation_{generation}_native"] = expected
        expected_counts = {
            "native_intake_catalogue": 28,
            "native_run_configuration_catalogue": 28,
        }
        receipt = {
            "schema": 10,
            "purpose": "terminal-original-push-without-lease-or-catalogue-addition",
            "previous_bank": {"path": "/old", "device": 3, "inode": 4},
            "previous_bootstrap": {
                "ledger_path": "/old",
                "operating_continuation": {
                    "qualification": {"sha256": ledger.digest(prior)},
                    "successor": {
                        "source_sha": cells.TENTH_MAIN,
                        "run_id": cells.TENTH_RUN,
                    },
                },
                "source_workflow_sha256": cells.NINTH_SUCCESSOR_WORKFLOW,
                "source_identity": {"reusable_sha": cells.NINTH_SUCCESSOR_REUSABLE},
            },
            "previous_qualification": prior,
            "native_tenth": tenth,
        }
        raw = ledger.canonical(receipt)
        digest = hashlib.sha256(raw).hexdigest()
        self.route["qualification"]["sha256"] = digest
        config = {
            "operating_continuation": self.route,
            "source_workflow_sha256": cells.TENTH_SUCCESSOR_WORKFLOW,
            "source_identity": {"reusable_sha": cells.TENTH_SUCCESSOR_REUSABLE},
        }
        get, paths, inventory_path = self.native_reader()
        with ExitStack() as stack:
            stack.enter_context(patch.object(cells, "TENTH_QUALIFICATION", digest))
            stack.enter_context(
                patch.object(cells, "_validate_ninth_retired_partial_descriptor")
            )
            earlier = stack.enter_context(
                patch.object(
                    cells,
                    "_validate_ninth_retired_partial_qualification",
                    return_value=expected_counts,
                )
            )
            stack.enter_context(
                patch.object(
                    run_factory.installation,
                    "_file",
                    return_value=(SimpleNamespace(sha256=digest), raw, "stamp"),
                )
            )
            descriptor, qualified, counts, _ = run_factory._continuation_receipt(config)
            self.assertEqual(counts, expected_counts)
            earlier.assert_called_once_with(prior)
            original = stack.enter_context(
                patch.object(
                    run_factory,
                    "_continuation_original_native",
                    side_effect=lambda _, prior=False: second if prior else first,
                )
            )
            past = [
                stack.enter_context(
                    patch.object(run_factory, name, return_value=expected)
                )
                for name, expected in functions.items()
            ]
            run_factory._continuation_native_histories(get, descriptor, qualified)
            self.assertEqual(original.call_count, 2)
            self.assertTrue(all(test.call_count == 1 for test in past))
            self.assertEqual(paths.count(inventory_path), 2)
            self.assertEqual(
                [p for p in paths if p.startswith("/check-runs/")],
                [f"/check-runs/{check}" for check in cells.TENTH_CHECKS],
            )
            changed = deepcopy(qualified)
            changed["native_tenth"]["run"]["run_attempt"] = 2
            with self.assertRaisesRegex(
                identity.Denied, "continuation-tenth-native-drift"
            ):
                run_factory._continuation_native_histories(get, descriptor, changed)

    def test_missing_check_and_second_inventory_drift_are_rejected(self):
        for check in cells.TENTH_CHECKS:
            with self.subTest(check=check):
                get, _, _ = self.native_reader(omit=f"/check-runs/{check}")
                with self.assertRaises(identity.Denied):
                    run_factory._continuation_tenth_native(get)
        get, _, _ = self.native_reader(drift_after_read=True)
        with self.assertRaisesRegex(
            identity.Denied, "continuation-ninth-native-inventory-drift"
        ):
            run_factory._continuation_tenth_native(get)

    def test_empty_bank_alias_is_denied_and_fd_is_closed(self):
        bank = {"path": "/unit/old", "device": 10, "inode": 20}
        with (
            patch.object(run_factory.ledger, "_observe_historical_bank"),
            patch.object(run_factory.ledger, "Ledger") as store,
            patch.object(run_factory.installation, "_open_directory", return_value=42),
            patch.object(
                run_factory.os,
                "fstat",
                return_value=SimpleNamespace(st_dev=10, st_ino=20),
            ),
            patch.object(run_factory.os, "close") as close,
        ):
            store.return_value.__enter__.return_value.lease_ids.return_value = ()
            with self.assertRaisesRegex(
                identity.Denied, "continuation-tenth-bank-alias"
            ):
                run_factory._check_empty_previous_bank(bank, "/unit/new")
            close.assert_called_once_with(42)
