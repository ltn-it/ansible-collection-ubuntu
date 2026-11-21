"""The failed first Podman start remains immutable history."""

from contextlib import nullcontext
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "roles/github_runner/files"))
from incus_lease_issuer import host_api_fence, identity, ledger, operating_cells as cells, run_factory


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
            readback.assert_called_once_with(policy, expected_deadline=0)
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
