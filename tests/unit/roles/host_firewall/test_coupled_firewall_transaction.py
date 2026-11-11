from __future__ import annotations

from dataclasses import replace
from collections import Counter
import contextlib
import json
import unittest
from unittest import mock

from test_firewall_transaction import nft_document, runtime_config, transaction


def bridge_state(*, present: bool = True, verdict: str = "drop"):
    if not present:
        return transaction.NftTableState(False, b"", b"")
    document = {"nftables": [
        {"table": {"family": "bridge", "name": "lit_ssh_guard"}},
        {"chain": {"family": "bridge", "table": "lit_ssh_guard", "name": "input",
                   "type": "filter", "hook": "input", "prio": -200, "policy": "accept"}},
        {"rule": {"family": "bridge", "table": "lit_ssh_guard", "chain": "input",
                  "expr": [{"counter": {"packets": 5, "bytes": 100}}, {verdict: None}]}}]}
    canonical = transaction.canonicalize_nft_document(json.dumps(document).encode(), "bridge", "lit_ssh_guard")
    return transaction.NftTableState(True, b"table bridge lit_ssh_guard { }\n", canonical)


def inet_state(*, present: bool = True):
    if not present:
        return transaction.NftTableState(False, b"", b"")
    canonical = transaction.canonicalize_nft_document(nft_document(), "inet", "lit_host_firewall")
    return transaction.NftTableState(True, b"table inet lit_host_firewall { }\n", canonical)


class CoupledPolicySnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = replace(runtime_config(), bridge_table_name="lit_ssh_guard")

    def state(self, primary=None, guard=None):
        values = (inet_state() if primary is None else primary, bridge_state() if guard is None else guard)
        return transaction.NftPolicyState(self.config.owned_tables(), values)

    def test_default_consumer_preserves_exact_old_canonical_bytes_and_single_read(self) -> None:
        config = runtime_config()
        prior = inet_state()
        with mock.patch.object(transaction, "read_nft_table_state", return_value=prior) as reader:
            value = transaction.read_nft_policy_state(config)
        reader.assert_called_once_with(config.nft_binary, "inet", config.table_name)
        self.assertEqual(value.canonical, prior.canonical)
        self.assertEqual(value.backup, transaction.create_runtime_backup(prior, "inet", config.table_name))
        self.assertEqual(config.transaction_schema(), "lit.host_firewall.transaction/v3")

    def test_coupled_snapshot_reads_only_the_two_configured_tables_and_rechecks_both(self) -> None:
        with mock.patch.object(transaction, "read_nft_table_state", side_effect=[
                inet_state(), bridge_state(), inet_state(), bridge_state()]) as reader:
            value = transaction.read_nft_policy_state(self.config)
        self.assertEqual(reader.call_args_list, [
            mock.call(self.config.nft_binary, "inet", "lit_host_firewall"),
            mock.call(self.config.nft_binary, "bridge", "lit_ssh_guard")]*2)
        self.assertTrue(value.complete)

    def test_guard_drift_between_coupled_reads_is_rejected(self) -> None:
        with mock.patch.object(transaction, "read_nft_table_state", side_effect=[
                inet_state(), bridge_state(), inet_state(), bridge_state(verdict="accept")]):
            with self.assertRaisesRegex(transaction.TransactionError, "coupled snapshot"):
                transaction.read_nft_policy_state(self.config)

    def test_same_inet_with_different_guard_cannot_share_approved_readback_hash(self) -> None:
        before = self.state()
        after = self.state(guard=bridge_state(verdict="accept"))
        self.assertNotEqual(transaction.sha256_bytes(before.canonical), transaction.sha256_bytes(after.canonical))

    def test_missing_guard_is_not_a_complete_applied_policy(self) -> None:
        value = self.state(guard=bridge_state(present=False))
        self.assertTrue(value.present)
        self.assertFalse(value.complete)
        bundle = json.loads(value.canonical)
        self.assertFalse(bundle["tables"][1]["present"])
        self.assertIsNone(bundle["tables"][1]["policy"])

    def test_mixed_prior_state_restores_inet_and_explicit_guard_absence_in_one_batch(self) -> None:
        value = self.state(guard=bridge_state(present=False))
        self.assertEqual(value.backup, b"destroy table inet lit_host_firewall\n"
                         b"table inet lit_host_firewall { }\n"
                         b"destroy table bridge lit_ssh_guard\n")

    def test_guard_only_prior_state_retains_exact_missing_inet_identity(self) -> None:
        value = self.state(primary=inet_state(present=False))
        self.assertTrue(value.present)
        self.assertFalse(value.complete)
        self.assertIn(b"destroy table inet lit_host_firewall\n", value.backup)
        self.assertIn(b"table bridge lit_ssh_guard { }\n", value.backup)
        self.assertFalse(json.loads(value.canonical)["tables"][0]["present"])

    def test_both_absent_preserves_empty_prior_canonical_but_destroys_both_on_rollback(self) -> None:
        value = self.state(inet_state(present=False), bridge_state(present=False))
        self.assertFalse(value.present)
        self.assertFalse(value.complete)
        self.assertEqual(value.canonical, b"")
        self.assertEqual(value.backup.count(b"destroy table"), 2)

    def test_snapshot_cannot_silently_zip_away_an_owned_table(self) -> None:
        with self.assertRaises(transaction.TransactionError):
            transaction.NftPolicyState(self.config.owned_tables(), (inet_state(),))

    def test_coupled_mode_reserves_more_rollback_time_inside_existing_watchdog(self) -> None:
        self.assertGreater(self.config.rollback_budget_seconds(), runtime_config().rollback_budget_seconds())
        self.assertLess(self.config.transaction_budget_seconds("apply") + self.config.rollback_budget_seconds(),
                        self.config.watchdog_timeout_seconds)

    def test_guard_name_rejects_injected_or_untyped_scope(self) -> None:
        for invalid in ('guard; delete table inet other', None):
            with self.subTest(name=invalid):
                with self.assertRaises(transaction.TransactionError):
                    replace(self.config, bridge_table_name=invalid).validate_shape()

    def test_transaction_metadata_cannot_be_reinterpreted_with_another_guard_scope(self) -> None:
        metadata = {name: None for name in transaction.METADATA_KEYS}
        metadata.update(schema="lit.host_firewall.transaction/v4", owned_tables=[
            ["inet", "lit_host_firewall"], ["bridge", "another_guard"]])
        raw = transaction.canonical_json(metadata)
        active = {"metadata_sha256": transaction.sha256_bytes(raw)}
        paths = transaction.transaction_paths(self.config.transactions_directory / ("1"*32))
        with mock.patch.object(transaction, "read_secure_bytes", return_value=raw), \
             mock.patch.object(transaction, "run_command") as runner:
            with self.assertRaisesRegex(transaction.TransactionError, "owned-table scope"):
                transaction.validate_metadata_and_assets(self.config, active, paths)
            runner.assert_not_called()

    def test_bridge_readback_and_restore_text_request_numeric_interface_indices(self) -> None:
        state = bridge_state()
        inventory = transaction.canonical_json({"nftables": [
            {"table": {"family": "bridge", "name": "lit_ssh_guard"}}]})
        outputs = [inventory, state.canonical, state.text, state.canonical, inventory]
        with mock.patch.object(transaction, "run_command", side_effect=[
                transaction.CommandResult(0, output, b"") for output in outputs]) as reader:
            observed = transaction.read_nft_table_state("/nft", "bridge", "lit_ssh_guard")
        self.assertEqual(observed, state)
        for call in reader.call_args_list[1:4]:
            self.assertIn("--numeric", call.args[0])

    def test_active_rollback_context_needs_no_live_container_or_nft_query(self) -> None:
        metadata = {name: name + "-public-value" for name in (
            "target", "change_id", "mode", "candidate_sha256", "approved_readback_sha256",
            "policy_fingerprint", "egress_policy_sha256", "egress_status")}
        metadata["apply_authorization_sha256"] = "not-returned"
        with mock.patch.object(transaction, "transaction_scope", return_value=contextlib.nullcontext()), \
             mock.patch.object(transaction.RuntimeConfig, "validate"), \
             mock.patch.object(transaction, "load_active", return_value=({}, self.config.state_directory, {})), \
             mock.patch.object(transaction, "validate_metadata_and_assets", return_value=metadata), \
             mock.patch.object(transaction, "run_command") as commands:
            result = transaction.describe_active_transaction(self.config)
        commands.assert_not_called()
        self.assertNotIn("apply_authorization_sha256", result)
        self.assertEqual(result["candidate_sha256"], metadata["candidate_sha256"])
        self.assertEqual(result["owned_tables"], [["inet", "lit_host_firewall"], ["bridge", "lit_ssh_guard"]])


class NumericBridgeSnapshotTests(unittest.TestCase):
    @staticmethod
    def document(value="veth0"):
        return transaction.canonical_json({"nftables": [
            {"table": {"family": "bridge", "name": "lit_ssh_guard"}},
            {"rule": {"family": "bridge", "table": "lit_ssh_guard", "chain": "input", "expr": [
                {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "veth0"}},
                {"match": {"op": "==", "left": {"meta": {"key": "iif"}}, "right": value}},
                {"accept": None}]}}]})

    def test_real_nft_symbolic_index_format_becomes_numeric_without_rewriting_ifname_or_comment(self):
        with mock.patch.object(transaction.socket, "if_nametoindex", return_value=4) as resolver:
            raw, aliases, matches = transaction.numeric_bridge_document(self.document())
        resolver.assert_called_once_with("veth0")
        expressions = json.loads(raw)["nftables"][1]["rule"]["expr"]
        self.assertEqual(expressions[0]["match"]["right"], "veth0")
        self.assertEqual(expressions[1]["match"]["right"], 4)
        text = b'table bridge lit_ssh_guard { iifname "veth0" iif "veth0" accept comment "iif \\\"veth0\\\""\n# iif "veth0"\n}\n'
        retained = transaction.numeric_bridge_text(text, aliases, matches)
        self.assertEqual(retained, text.replace(b'iif "veth0" accept', b'iif 4 accept'))

    def test_deleted_device_numeric_readback_has_same_canonical_identity_without_name_lookup(self):
        with mock.patch.object(transaction.socket, "if_nametoindex", return_value=4):
            before, _, _ = transaction.numeric_bridge_document(self.document())
        with mock.patch.object(transaction.socket, "if_nametoindex", side_effect=OSError) as resolver:
            after, aliases, matches = transaction.numeric_bridge_document(self.document(4))
            restored = transaction.numeric_bridge_text(b'iifname "veth0" iif 4 accept', aliases, matches)
        resolver.assert_not_called()
        self.assertEqual(before, after)
        self.assertEqual(restored, b'iifname "veth0" iif 4 accept')

    def test_disappeared_device_during_capture_fails_before_snapshot_return(self):
        with mock.patch.object(transaction.socket, "if_nametoindex", side_effect=OSError):
            with self.assertRaisesRegex(transaction.TransactionError, "disappeared"):
                transaction.numeric_bridge_document(self.document())

    def test_actual_nft_deleted_index_decimal_string_matches_original_numeric_identity(self):
        with mock.patch.object(transaction.socket, "if_nametoindex", return_value=4):
            before, _, _ = transaction.numeric_bridge_document(self.document())
        with mock.patch.object(transaction.socket, "if_nametoindex", side_effect=OSError):
            after, aliases, matches = transaction.numeric_bridge_document(self.document("4"))
            restored = transaction.numeric_bridge_text(b'iifname "veth0" iif 4 accept', aliases, matches)
        self.assertEqual(before, after)
        self.assertEqual(restored, b'iifname "veth0" iif 4 accept')

    def test_numeric_interface_name_cannot_redirect_an_absent_index(self):
        with mock.patch.object(transaction.socket, "if_nametoindex", return_value=11):
            with self.assertRaisesRegex(transaction.TransactionError, "ambiguous numeric"):
                transaction.numeric_bridge_document(self.document("4"))
        with mock.patch.object(transaction.socket, "if_nametoindex") as resolver:
            with self.assertRaisesRegex(transaction.TransactionError, "noncanonical"):
                transaction.numeric_bridge_document(self.document("04"))
        resolver.assert_not_called()

    def test_name_reuse_between_actual_readbacks_changes_numeric_canonical_and_stops(self):
        inventory = transaction.canonical_json({"nftables": [{"table": {
            "family": "bridge", "name": "lit_ssh_guard"}}]})
        outputs = [inventory, self.document(), b'table bridge lit_ssh_guard { iif "veth0" accept }',
                   self.document()]
        with mock.patch.object(transaction, "run_command", side_effect=[
                transaction.CommandResult(0, raw, b"") for raw in outputs]), \
             mock.patch.object(transaction.socket, "if_nametoindex", side_effect=[4, 5]):
            with self.assertRaisesRegex(transaction.TransactionError, "changed while"):
                transaction.read_nft_table_state("/nft", "bridge", "lit_ssh_guard")

    def test_text_and_structured_snapshot_must_bind_same_names_and_match_counts(self):
        for text in (b'iif "other" accept', b'iif "veth0" iif "veth0" accept', b'accept'):
            with self.subTest(text=text):
                with self.assertRaisesRegex(transaction.TransactionError, "differ"):
                    transaction.numeric_bridge_text(text, {"veth0": 4}, Counter({("iif", 4): 1}))

    def test_invalid_or_non_scalar_index_values_fail_closed(self):
        for value in (True, 0, -1, 2**31, [], {"set": [4, 5]}, 'bad name'):
            with self.subTest(value=value):
                with self.assertRaises(transaction.TransactionError):
                    transaction.numeric_bridge_document(self.document(value))

    def test_index_assignment_or_non_equality_is_rejected_instead_of_losing_restore_semantics(self):
        document = json.loads(self.document(4))
        document["nftables"][1]["rule"]["expr"][1]["match"]["op"] = "!="
        with self.assertRaisesRegex(transaction.TransactionError, "scalar equality"):
            transaction.numeric_bridge_document(transaction.canonical_json(document))
        with self.assertRaisesRegex(transaction.TransactionError, "unsupported"):
            transaction.numeric_bridge_document(transaction.canonical_json({"mangle": {
                "key": {"meta": {"key": "iif"}}, "value": 4}}))

    def test_set_or_assignment_text_is_rejected_before_a_restore_backup_is_returned(self):
        for text in (b'iif { "veth0" } accept', b'meta iif set 4', b'iif'):
            with self.subTest(text=text):
                with self.assertRaises(transaction.TransactionError):
                    transaction.numeric_bridge_text(text, {"veth0": 4}, Counter({("iif", 4): 1}))


if __name__ == "__main__":
    unittest.main()
