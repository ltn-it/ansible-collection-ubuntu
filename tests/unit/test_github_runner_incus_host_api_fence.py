"""Root sealed-file and modeled host-kernel fixtures, no native host firewall.

The rules/readback model is explicit: passing this suite does not qualify the
new iface_index concatenation ABI, real endpoint isolation or installation.
"""
from copy import deepcopy
from contextlib import ExitStack
import datetime as dt
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import host_api_fence as host, ledger, network_fence as namespace  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


def policy():
    return host._Policy("/root/host-api.json", "a" * 64, "10.10.20.30", 8443, "lit_api_" + "b" * 32,
                        "11111111-1111-1111-1111-111111111111", 4, 5,
                        ((namespace.IP, "c" * 64), (namespace.NFT, "d" * 64)))


def observed(selected, *, deadline=0, tuple_value=None, ttl=0):
    objects = deepcopy([row["add"] for row in host._rules(selected, deadline)["nftables"]])
    for index, row in enumerate(objects, 1):
        kind = next(iter(row))
        row[kind]["handle"] = index
        if kind == "set" and tuple_value:
            row[kind]["elem"] = [{"elem": {"val": {"concat": ["g06h0", tuple_value[1]]},
                                               "timeout": ttl, "expires": ttl - 1}}]
        if kind == "rule":
            if row[kind]["chain"] == "gate":
                row[kind]["expr"][0]["match"]["right"] = dt.datetime.fromtimestamp(
                    deadline, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            for expr in row[kind]["expr"]:
                if "counter" in expr:
                    expr["counter"] = {"packets": 7, "bytes": 100}
    return {"nftables": [{"metainfo": {"json_schema_version": 1}}, *objects]}


class HostRulesTests(unittest.TestCase):
    def test_nonroot_closed_entries_before_policy_or_kernel_access(self):
        with mock.patch.object(host.os, "geteuid", return_value=2101):
            for entry, args in ((host.install_baseline, (None,) * 3), (host.bind_creator, (None,) * 7),
                                (host.install_bootstrap_baseline, (None,) * 2),
                                (host.grant, (None,) * 7), (host.withdraw, (None,) * 7),
                                (host.verify_withdrawn, (None,) * 4)):
                with self.assertRaisesRegex(Denied, "host-api-root-required"):
                    entry(*args)
        for overrides in ({"qualified": True}, {"reader": lambda: None}, {"command": "nft flush ruleset"}):
            with self.assertRaises(TypeError):
                host.install_baseline(None, None, None, **overrides)
            with self.assertRaises(TypeError):
                host.install_bootstrap_baseline(None, None, **overrides)

    def read(self, value, *, kernel_name="g06h0", kernel_index=41, **kwargs):
        # Root-kernel name/index mapping is explicitly modeled here. A string
        # in nft JSON is never treated as an independent ownership assertion.
        with mock.patch.object(host, "_nft", return_value=ledger.canonical(value)), \
             mock.patch.object(host.socket, "if_indextoname", return_value=kernel_name), \
             mock.patch.object(host.socket, "if_nametoindex", return_value=kernel_index):
            return host._readback(policy(), **kwargs)

    def test_deny_first_persistent_endpoint_only_both_directions(self):
        objects = [row["add"] for row in host._rules(policy())["nftables"]]
        self.assertEqual([row["set"]["type"] for row in objects if "set" in row], [["iface_index", "ipv4_addr"]])
        self.assertFalse(any("elem" in row["set"] for row in objects if "set" in row))
        hooks = [row["chain"] for row in objects if "chain" in row and "hook" in row["chain"]]
        self.assertEqual({(row["hook"], row["policy"]) for row in hooks}, {("input", "accept"), ("output", "accept")})
        rules = [row["rule"] for row in objects if "rule" in row]
        for name, field in (("input_endpoint", "iif"), ("output_endpoint", "oif")):
            selected = [row["expr"] for row in rules if row["chain"] == name]
            self.assertEqual(selected[0][0]["match"]["left"]["concat"][0], {"meta": {"key": field}})
            self.assertEqual(selected[0][-1], {"jump": {"target": "gate"}})
            self.assertEqual(selected[1][-1], {"drop": None})
        raw = ledger.canonical(objects)
        for forbidden in (b'"ct"', b"conntrack", b"established", b"flowtable", b"flush", b"delete", b"dynset"):
            self.assertNotIn(forbidden, raw)
        self.assertEqual(self.read(observed(policy())), (1, 4, 0, 0))

    def test_actual_nft109_name_tuple_seconds_and_exact_absolute_utc_readback(self):
        value = observed(policy(), deadline=1800000000, tuple_value=(41, "10.250.23.2"), ttl=30)
        element = next(row["set"] for row in value["nftables"] if "set" in row)["elem"][0]
        # Exact execution4 native-grant.json element, not the old int/ms fixture.
        self.assertEqual(element, {"elem": {"expires": 29, "timeout": 30,
                                          "val": {"concat": ["g06h0", "10.250.23.2"]}}})
        self.assertEqual(self.read(value, tuple_value=(41, "10.250.23.2"), maximum_ms=30000,
                                   expected_deadline=1800000000), (1, 4, 29000, 1800000000))
        for tuple_value in ((42, "10.250.23.2"), (41, "10.250.23.3"), ("lth1", "10.250.23.2")):
            with self.assertRaises(Denied):
                self.read(value, tuple_value=tuple_value, maximum_ms=30000)
        with self.assertRaises(Denied):
            self.read(value, tuple_value=(41, "10.250.23.2"), maximum_ms=29998)
        with self.assertRaises(Denied):
            self.read(value, tuple_value=(41, "10.250.23.2"), maximum_ms=30000, expected_deadline=1800000001)

    def test_foreign_accept_or_wrong_endpoint_or_order_never_adopted(self):
        original = observed(policy())
        variants = []
        extra = deepcopy(original)
        extra["nftables"].append({"rule": {"family": "inet", "table": policy().table, "chain": "input", "handle": 90,
                                          "expr": [{"accept": None}]}})
        variants.append(extra)
        wrong = deepcopy(original)
        next(row["rule"] for row in wrong["nftables"] if "rule" in row and row["rule"]["chain"] == "input")["expr"][0]["match"]["right"] = "127.0.0.1"
        variants.append(wrong)
        reordered = deepcopy(original)
        positions = [i for i, row in enumerate(reordered["nftables"]) if "rule" in row and row["rule"]["chain"] == "input_endpoint"]
        reordered["nftables"][positions[0]], reordered["nftables"][positions[1]] = reordered["nftables"][positions[1]], reordered["nftables"][positions[0]]
        variants.append(reordered)
        for value in variants:
            with self.assertRaises(Denied):
                self.read(value)

    def test_native_name_requires_both_current_kernel_mappings_without_numeric_fallback(self):
        original = observed(policy(), tuple_value=(41, "10.250.23.2"), ttl=30)
        for name in (41, "41", "foreign0", "g06h0\n"):
            value = deepcopy(original)
            next(row["set"] for row in value["nftables"] if "set" in row)["elem"][0]["elem"]["val"]["concat"][0] = name
            with self.subTest(name=name), self.assertRaises(Denied):
                self.read(value, tuple_value=(41, "10.250.23.2"), maximum_ms=30000)
        for changes in ({"kernel_name": "replacement0"}, {"kernel_index": 42}):
            with self.subTest(changes=changes), self.assertRaises(Denied):
                self.read(original, tuple_value=(41, "10.250.23.2"), maximum_ms=30000, **changes)
        with mock.patch.object(host, "_nft", return_value=ledger.canonical(original)), \
             mock.patch.object(host.socket, "if_indextoname", side_effect=OSError("unavailable")):
            with self.assertRaisesRegex(Denied, "host-api-tuple-interface"):
                host._readback(policy(), tuple_value=(41, "10.250.23.2"), maximum_ms=30000)

    def test_native_seconds_floor_is_not_treated_as_remaining_time_upper_bound(self):
        original = observed(policy(), tuple_value=(41, "10.250.23.2"), ttl=30)
        for field, invalid in (("timeout", 30000), ("expires", 29999), ("expires", 0),
                               ("timeout", True), ("expires", "29"), ("expires", 29.5), ("expires", 31)):
            value = deepcopy(original)
            next(row["set"] for row in value["nftables"] if "set" in row)["elem"][0]["elem"][field] = invalid
            with self.subTest(field=field, value=invalid), self.assertRaises(Denied):
                self.read(value, tuple_value=(41, "10.250.23.2"), maximum_ms=30000)
        with self.assertRaises(Denied):
            self.read(original, tuple_value=(41, "10.250.23.2"), maximum_ms=29999)
        self.assertEqual(self.read(original, tuple_value=(41, "10.250.23.2"), maximum_ms=30000)[2], 29000)

    def test_unknown_units_timezone_or_extra_allow_deny(self):
        for timestamp in (1800000000, "2027-01-15T08:00:00Z", "2027-01-15 08:00:00+00:00", "9999-01-01 00:00:00"):
            value = observed(policy())
            value["nftables"][4]["rule"]["expr"][0]["match"]["right"] = timestamp
            with self.assertRaises(Denied):
                self.read(value)
        value = observed(policy(), tuple_value=(41, "10.250.23.2"), ttl=30)
        selected = next(row["set"] for row in value["nftables"] if "set" in row)
        selected["elem"].append(deepcopy(selected["elem"][0]))
        with self.assertRaises(Denied):
            self.read(value, tuple_value=(41, "10.250.23.2"), maximum_ms=30000)

    def test_fixed_nft_table_route_not_general_host_executor(self):
        with mock.patch.object(namespace, "_run", return_value=b"{}") as run:
            host._nft(policy(), "-n", "-j", "-T", "-a", "list", "table", "inet", policy().table)
            run.assert_called_once_with(policy(), namespace.NFT,
                ["-n", "-j", "-T", "-a", "list", "table", "inet", policy().table], payload=None)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Root Linux EE only")
class HostPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="host-api-", dir="/run/proof")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "policy.json"
        self.value = {"schema": 1, "backend_ipv4": "10.10.20.30", "backend_port": 8443,
                      "table": "lit_api_" + "b" * 32, "host_netns": {"boot_id": policy().boot_id, "device": 4, "inode": 5},
                      "tools": {namespace.IP: "c" * 64, namespace.NFT: "d" * 64}}
        self.seal()

    def seal(self):
        self.path.write_bytes(ledger.canonical(self.value))
        self.path.chmod(0o600)
        self.sha = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def configuration(self):
        return host.preparation.RootConfiguration("/root/config", "a" * 64, "/root/registry", "b" * 64,
            "/run/incus.sock", "/root/key", b"c" * 32, "/root/stage", "/root/lock", 1,
            "/root/network-policy", "d" * 64, "/root/quota-policy", "e" * 64, str(self.path), self.sha)

    def test_actual_root_sealed_policy_and_config_binding(self):
        selected = host._policy(str(self.path), self.sha)
        self.assertEqual(selected.backend, "10.10.20.30")
        config = host.preparation.RootConfiguration("/root/config", "a" * 64, "/root/registry", "b" * 64,
            "/run/incus.sock", "/root/key", b"c" * 32, "/root/stage", "/root/lock", 1,
            "/root/network-policy", "d" * 64, "/root/quota-policy", "e" * 64, str(self.path), self.sha)
        with mock.patch.object(host.preparation, "_config", return_value=(config, None, None)):
            self.assertEqual(host._bound(str(self.path), self.sha, config), selected)
        with self.assertRaisesRegex(Denied, "host-api-root-policy-binding"):
            host._bound(str(self.path), self.sha, SimpleNamespace())
        with self.assertRaisesRegex(Denied, "host-api-policy-drift"):
            host._policy(str(self.path), "e" * 64)

    def test_reject_public_loopback_ipv6_schema_bool_and_foreign_table(self):
        original = deepcopy(self.value)
        for changes in ({"backend_ipv4": "127.0.0.1"}, {"backend_ipv4": "8.8.8.8"}, {"backend_ipv4": "::1"},
                        {"backend_port": True}, {"table": "filter"}, {"qualified": True}):
            self.value = {**original, **changes}
            self.seal()
            with self.assertRaises((Denied, ValueError)):
                host._policy(str(self.path), self.sha)

    def test_group_readable_policy_symlink_and_nonroot_deny(self):
        self.path.chmod(0o640)
        with self.assertRaises(Denied):
            host._policy(str(self.path), self.sha)
        self.path.chmod(0o600)
        link = self.path.with_name("symlink.json")
        link.symlink_to(self.path)
        with self.assertRaises((Denied, OSError)):
            host._policy(str(link), self.sha)
        with mock.patch.object(host.os, "geteuid", return_value=2101):
            with self.assertRaisesRegex(Denied, "host-api-root-required"):
                host._policy(str(self.path), self.sha)

    def test_baseline_real_private_journal_intent_precedes_modeled_kernel_create(self):
        selected = host._policy(str(self.path), self.sha)
        journal = Path(str(self.path) + ".baseline.json")
        calls = []
        def nft(_policy, *argv, payload=None):
            calls.append(argv)
            if argv[-2:] == ("list", "tables"):
                return ledger.canonical({"nftables": []})
            self.assertEqual(host.identity.decode_json(journal.read_bytes())["state"], "intent")
            self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)
            self.assertEqual(payload, ledger.canonical(host._rules(selected)))
            return b""
        with mock.patch.object(host, "_bound", return_value=selected), \
             mock.patch.object(host, "_host", return_value=mock.MagicMock()), \
             mock.patch.object(host, "_local"), mock.patch.object(host, "_nft", side_effect=nft), \
             mock.patch.object(host, "_readback", return_value=(17, 20, 0, 0)):
            receipt = host.install_baseline(str(self.path), self.sha, self.configuration())
            self.assertEqual(receipt["nft_table_handle"], 17)
            self.assertEqual(host.identity.decode_json(journal.read_bytes())["state"], "verified")
            self.assertEqual(receipt["baseline_sha256"], hashlib.sha256(journal.read_bytes()).hexdigest())
            with self.assertRaises(Denied):
                host.install_baseline(str(self.path), self.sha, self.configuration())
        self.assertEqual(sum(argv[:3] == ("-j", "-f", "-") for argv in calls), 1)

    def test_baseline_possible_send_failure_retains_unknown_never_retries_or_deletes(self):
        selected = host._policy(str(self.path), self.sha)
        journal = Path(str(self.path) + ".baseline.json")
        def nft(_policy, *argv, payload=None):
            if argv[-2:] == ("list", "tables"):
                return ledger.canonical({"nftables": []})
            raise OSError("synthetic-private-failure-must-not-leak")
        with mock.patch.object(host, "_bound", return_value=selected), \
             mock.patch.object(host, "_host", return_value=mock.MagicMock()), \
             mock.patch.object(host, "_local"), mock.patch.object(host, "_nft", side_effect=nft):
            with self.assertRaisesRegex(host.HostFenceUnknown, "^host-api-baseline-unknown$"):
                host.install_baseline(str(self.path), self.sha, self.configuration())
            self.assertEqual(host.identity.decode_json(journal.read_bytes())["state"], "unknown")
            with self.assertRaises(Denied):
                host.install_baseline(str(self.path), self.sha, self.configuration())
        self.assertTrue(journal.exists())

    def test_preexisting_table_is_never_adopted_and_private_parent_is_mandatory(self):
        selected = host._policy(str(self.path), self.sha)
        existing = {"nftables": [{"table": {"family": "inet", "name": selected.table}}]}
        with mock.patch.object(host, "_bound", return_value=selected), \
             mock.patch.object(host, "_host", return_value=mock.MagicMock()), \
             mock.patch.object(host, "_local"), mock.patch.object(host, "_nft", return_value=ledger.canonical(existing)) as nft:
            with self.assertRaises(Denied):
                host.install_baseline(str(self.path), self.sha, self.configuration())
            self.assertEqual(nft.call_count, 1)
        self.assertFalse(Path(str(self.path) + ".baseline.json").exists())
        self.path.parent.chmod(0o750)
        with self.assertRaisesRegex(Denied, "host-api-private-journal-parent"):
            host._journal_parent(selected)
        self.path.parent.chmod(0o700)

    def modeled_lease(self, operation="fence-renew"):
        selected = host._policy(str(self.path), self.sha)
        baseline = {"policy_sha256": selected.sha256, "baseline_sha256": "f" * 64, "boot_id": selected.boot_id,
                    "host_netns_device": selected.device, "host_netns_inode": selected.inode, "nft_table_handle": 17}
        lease, effect = "a" * 32, "b" * 32
        prepared = SimpleNamespace(lease_id=lease)
        record = {"expires_at": 1800000090, "authorizations": [{"token_id_sha256": "c" * 64, "valid_until": 1800000100}],
                  "effects": {"d" * 32: {"operation": "fence-create", "state": "verified", "host_api": baseline,
                      "fence": {"host_ifindex": 41}}, effect: {"operation": operation, "state": "intent",
                      "target": "fence:" + lease + (":" + "c" * 64 if operation == "fence-renew" else ""),
                      "fence_authorization": {"modeled": True}}}}
        store = mock.Mock()
        store.read.return_value = record
        store.host_api_claimants.return_value = (lease,)
        return selected, baseline, prepared, store, record, effect

    def test_grant_pairs_existing_intent_and_prebinds_before_exact_timed_absolute_send(self):
        selected, baseline, prepared, store, record, effect = self.modeled_lease()
        private = SimpleNamespace(backend=selected.backend, port=selected.port, peer="10.250.23.2/30")
        def bind(_lease, _effect, **metadata):
            record["effects"][effect]["host_api_authorization"] = metadata
        store.bind_host_api_authorization.side_effect = bind
        def send(_policy, *argv, payload=None):
            self.assertIn("host_api_authorization", record["effects"][effect])
            self.assertEqual(argv, ("-f", "-"))
            self.assertIn(b"41 . 10.250.23.2 timeout 84s", payload)
            self.assertIn(b"meta time < 1800000090", payload)
            self.assertNotIn(b"delete", payload)
        with mock.patch.object(host, "_bound", return_value=selected), \
             mock.patch.object(host, "_host", return_value=mock.MagicMock()), mock.patch.object(host, "_local"), \
             mock.patch.object(host, "_baseline", return_value=baseline), \
             mock.patch.object(host, "_namespace_policy", return_value=private), \
             mock.patch.object(namespace, "_fresh", return_value=record), mock.patch.object(namespace, "_signed") as signed, \
             mock.patch.object(namespace, "_owned", return_value=({}, 85000, 4, 1800000090)), \
             mock.patch.object(host.time, "time", return_value=1800000000), \
             mock.patch.object(host, "_readback", side_effect=[(17, 20, 0, 0), (17, 20, 83000, 1800000090)]), \
             mock.patch.object(host, "_nft", side_effect=send) as nft:
            receipt = host.grant(str(self.path), self.sha, prepared, store, object(), object(), effect)
            self.assertRegex(receipt, r"^[0-9a-f]{64}$")
            self.assertEqual(nft.call_count, 1)
            self.assertEqual(signed.call_count, 3)
            with self.assertRaisesRegex(Denied, "host-api-grant-replay"):
                host.grant(str(self.path), self.sha, prepared, store, object(), object(), effect)
        store.begin.assert_not_called()
        store.record.assert_not_called()

    def test_real_grant_and_current_parser_preserve_fractional_clock_reserve(self):
        selected, baseline, prepared, store, record, effect = self.modeled_lease()
        baseline["nft_table_handle"] = 1
        private = SimpleNamespace(backend=selected.backend, port=selected.port, peer="10.250.23.2/30")
        issued = 1800000000.1
        clock = {"now": issued, "applied": None, "ttl": None}
        def bind(_lease, _effect, **metadata):
            record["effects"][effect]["host_api_authorization"] = metadata
        store.bind_host_api_authorization.side_effect = bind
        def nft(_policy, *argv, payload=None):
            if payload is not None:
                # Actual production grant is the source of the TTL and gate.
                self.assertIn(b"timeout 83s", payload)
                self.assertIn(b"meta time < 1800000090", payload)
                clock["ttl"] = 83
                clock["applied"] = issued + 5  # Worst bounded command delay.
                clock["now"] = clock["applied"] + 0.1
                return b""
            value = observed(selected)
            if clock["applied"] is not None:
                value = observed(selected, deadline=1800000090, tuple_value=(41, "10.250.23.2"), ttl=clock["ttl"])
                element = next(row["set"] for row in value["nftables"] if "set" in row)["elem"][0]["elem"]
                element["expires"] = int(clock["ttl"] - (clock["now"]-clock["applied"]))
            return ledger.canonical(value)
        with mock.patch.object(host, "_bound", return_value=selected), \
             mock.patch.object(host, "_host", return_value=mock.MagicMock()), mock.patch.object(host, "_local"), \
             mock.patch.object(host, "_baseline", return_value=baseline), \
             mock.patch.object(host, "_namespace_policy", return_value=private), \
             mock.patch.object(namespace, "_fresh", return_value=record), mock.patch.object(namespace, "_signed"), \
             mock.patch.object(namespace, "_owned", return_value=({}, 85000, 4, 1800000090)), \
             mock.patch.object(host.time, "time", side_effect=lambda: clock["now"]), \
             mock.patch.object(host.socket, "if_indextoname", return_value="g06h0"), \
             mock.patch.object(host.socket, "if_nametoindex", return_value=41), \
             mock.patch.object(host, "_nft", side_effect=nft):
            host.grant(str(self.path), self.sha, prepared, store, object(), object(), effect)
            record["effects"][effect]["state"] = "verified"  # Outer namespace transaction owns this step.
            config = SimpleNamespace(host_api_fence_policy_path=str(self.path), host_api_fence_policy_sha256=self.sha)
            for elapsed in (0.1, 1.2, 20.2):
                clock["now"] = clock["applied"] + elapsed
                self.assertRegex(host.verify_current(prepared, store, object(), config), r"^[0-9a-f]{64}$")
        self.assertEqual(record["effects"][effect]["host_api_authorization"]["allow_expires_at"], 1800000090)

    def test_withdraw_marks_once_before_cut_never_deletes_baseline(self):
        selected, baseline, prepared, store, record, effect = self.modeled_lease("fence-disable")
        private = SimpleNamespace(backend=selected.backend, port=selected.port, peer="10.250.23.2/30")
        def mark(_lease, _effect, **metadata):
            if "host_api_withdrawal" in record["effects"][effect]:
                raise Denied("host-api-withdrawal-replay")
            record["effects"][effect]["host_api_withdrawal"] = metadata
        store.bind_host_api_withdrawal.side_effect = mark
        def send(_policy, *argv, payload=None):
            self.assertEqual(record["effects"][effect]["host_api_withdrawal"], {"baseline_sha256": baseline["baseline_sha256"]})
            self.assertEqual(payload, ("flush set inet " + selected.table + " admitted\n").encode())
        with mock.patch.object(host, "_bound", return_value=selected), \
             mock.patch.object(host, "_host", return_value=mock.MagicMock()), \
             mock.patch.object(host, "_baseline", return_value=baseline), \
             mock.patch.object(host, "_namespace_policy", return_value=private), \
             mock.patch.object(namespace, "_fresh", return_value=record), \
             mock.patch.object(host, "_readback", return_value=(17, 20, 0, 0)), \
             mock.patch.object(host, "_nft", side_effect=send) as nft:
            host.withdraw(str(self.path), self.sha, prepared, store, object(), object(), effect)
            with self.assertRaisesRegex(Denied, "host-api-withdrawal-replay"):
                host.withdraw(str(self.path), self.sha, prepared, store, object(), object(), effect)
            self.assertEqual(nft.call_count, 1)
        store.begin.assert_not_called()
        store.record.assert_not_called()

    def test_foreign_claimant_or_possible_prior_send_blocks_new_grant(self):
        selected, baseline, prepared, store, record, effect = self.modeled_lease()
        store.host_api_claimants.return_value = (prepared.lease_id, "e" * 32)
        with mock.patch.object(host, "_baseline", return_value=baseline):
            with self.assertRaisesRegex(Denied, "host-api-baseline-claimants"):
                host._owned(selected, prepared, store)
        record["effects"][effect]["state"] = "unknown"
        with self.assertRaisesRegex(Denied, "host-api-effect-not-new-intent"):
            host._effect(record, effect, "fence-renew", record["effects"][effect]["target"])

    def test_readonly_removed_creator_can_observe_empty_baseline_without_reclaiming_slot(self):
        selected, baseline, prepared, store, record, _ = self.modeled_lease()
        store.host_api_claimants.return_value = ()
        with mock.patch.object(host, "_baseline", return_value=baseline):
            with self.assertRaises(Denied):
                host._owned(selected, prepared, store)
            self.assertEqual(host._owned(selected, prepared, store, removed=True)[0], baseline)
            store.host_api_claimants.return_value = ("e" * 32,)
            with self.assertRaises(Denied):
                host._owned(selected, prepared, store, removed=True)

    def test_missing_host_current_authorization_denies_engine_before_kernel_access(self):
        selected, _, prepared, store, record, effect = self.modeled_lease()
        record["effects"][effect]["state"] = "verified"
        config = SimpleNamespace(host_api_fence_policy_path=str(self.path), host_api_fence_policy_sha256=self.sha)
        with mock.patch.object(host, "_bound", return_value=selected), \
             mock.patch.object(namespace, "_fresh", return_value=record), mock.patch.object(namespace, "_signed"), \
             mock.patch.object(host, "_nft") as nft:
            with self.assertRaisesRegex(Denied, "host-api-latest-grant-unverified"):
                host.verify_current(prepared, store, object(), config)
            nft.assert_not_called()

    def test_actual_wrong_or_foreign_root_host_namespace_never_yields(self):
        selected = host._policy(str(self.path), self.sha)
        # The fixture policy deliberately does not name this real namespace.
        # Keep-id EEs can also expose an unmapped Host Root NS owner; neither
        # condition is converted to an accepted Root-owned namespace.
        with self.assertRaises(Denied):
            with host._host(selected):
                self.fail("wrong kernel namespace must not be accepted")

    def test_verified_removed_cleanup_uses_shared_strong_owner_without_live_factory_or_writes(self):
        selected, baseline, prepared, store, record, effect = self.modeled_lease("fence-disable")
        record["effects"][effect]["state"] = "verified"
        record["effects"][effect]["host_api_withdrawal"] = {"baseline_sha256": baseline["baseline_sha256"]}
        record["effects"]["e" * 32] = {"operation": "fence-remove", "state": "verified",
                                          "target": "fence:" + prepared.lease_id}
        # Structurally typed fixture only; the shared helper's independent
        # Root strong-owner/removal checks have their own namespace tests.
        owner = host.cell_contract.OwnedCellForCleanup(registry=None, selector="fixture", lease_id=prepared.lease_id,
            cell_sha256="a" * 64, expires_at=1800000090, identity_policy_sha256="b" * 64,
            engine_descriptor_path="/root/descriptor", engine_descriptor_bytes=b"{}", engine_descriptor_sha256="c" * 64,
            engine_policy_sha256="d" * 64, incus_bytes=b"{}", creator_bytes=b"{}", prepared_sha256="e" * 64,
            canonical_bytes=b"{}", sha256="f" * 64)
        config = SimpleNamespace(host_api_fence_policy_path=str(self.path), host_api_fence_policy_sha256=self.sha)
        store.host_api_claimants.return_value = ()
        with mock.patch.object(namespace, "_cleanup_context", return_value=(None, record)) as cleanup, \
             mock.patch.object(host.cell_contract, "owned_fence_for_cleanup", side_effect=AssertionError("no live locator")), \
             mock.patch.object(namespace, "_fresh", side_effect=AssertionError("no live acquisition")), \
             mock.patch.object(host, "_bound", return_value=selected), \
             mock.patch.object(host, "_host", return_value=mock.MagicMock()), \
             mock.patch.object(host, "_baseline", return_value=baseline), \
             mock.patch.object(host, "_readback", return_value=(17, 20, 0, 0)) as readback, \
             mock.patch.object(host, "_nft") as nft:
            self.assertEqual(host.verify_withdrawn(owner, store, object(), config),
                             {"baseline_sha256": baseline["baseline_sha256"], "admitted": 0})
            self.assertEqual(cleanup.call_args.args[0], owner)
            nft.assert_not_called()
            store.host_api_claimants.return_value = ("f" * 32,)
            with self.assertRaisesRegex(Denied, "host-api-baseline-claimants"):
                host.verify_withdrawn(owner, store, object(), config)
            self.assertEqual(readback.call_count, 1)  # Never inspect/change a new lease's grant.
            cleanup.side_effect = Denied("fence-removal-unresolved")
            for state in ("unknown", "intent"):
                record["effects"]["e" * 32]["state"] = state
                with self.assertRaisesRegex(Denied, "fence-removal-unresolved"):
                    host.verify_withdrawn(owner, store, object(), config)
            nft.assert_not_called()
            store.begin.assert_not_called()
            store.record.assert_not_called()


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Root Linux EE only")
class BootstrapBaselineTests(unittest.TestCase):
    """Real sealed bootstrap/ledger/journal; host kernel alone is modeled."""
    @classmethod
    def setUpClass(cls):
        import test_github_runner_incus_run_factory as fixtures
        fixtures.RootBootstrapTests.setUpClass()

    def setUp(self):
        import test_github_runner_incus_run_factory as fixtures
        self.host = HostPolicyTests()
        self.host.setUp(); self.addCleanup(self.host.doCleanups)
        self.bootstrap = fixtures.RootBootstrapTests()
        self.bootstrap.setUp(); self.addCleanup(self.bootstrap.doCleanups)
        self.bootstrap.value["preparation"].update(
            host_api_fence_policy_path=str(self.host.path), host_api_fence_policy_sha256=self.host.sha)
        self.bootstrap.seal()
        self.journal = Path(str(self.host.path) + ".baseline.json")
        self.selected = host._policy(str(self.host.path), self.host.sha)
        self.calls = []

    def install(self):
        return host.install_bootstrap_baseline(str(self.bootstrap.path), self.bootstrap.sha)

    def model(self, hook=None):
        def nft(selected, *argv, payload=None):
            self.calls.append(argv)
            if argv[-2:] == ("list", "tables"):
                if hook: hook("inventory")
                return ledger.canonical({"nftables": []})
            self.assertEqual(argv, ("-j", "-f", "-"))
            self.assertEqual(payload, ledger.canonical(host._rules(self.selected)))
            self.assertEqual(host.identity.decode_json(self.journal.read_bytes())["state"], "intent")
            self.assertEqual(stat.S_IMODE(self.journal.stat().st_mode), 0o600)
            if hook: hook("create")
            return b""
        stack = ExitStack()
        stack.enter_context(mock.patch.object(host, "_host", return_value=mock.MagicMock()))
        stack.enter_context(mock.patch.object(host, "_local"))
        stack.enter_context(mock.patch.object(host, "_nft", side_effect=nft))
        stack.enter_context(mock.patch.object(host, "_readback", return_value=(17, 20, 0, 0)))
        return stack

    def test_real_bootstrap_without_registry_or_key_creates_deny_only_baseline(self):
        from incus_lease_issuer import policy_registry, signed_context
        self.assertNotIn("registry_path", self.bootstrap.value["preparation"])
        self.assertFalse(Path(self.bootstrap.value["preparation"]["signing_key_path"]).exists())
        with self.model(), \
             mock.patch.object(host.preparation, "_config", side_effect=AssertionError("no static preparation")), \
             mock.patch.object(policy_registry, "load_registry", side_effect=AssertionError("no registry")), \
             mock.patch.object(signed_context.RootSigner, "__init__", side_effect=AssertionError("no signer")), \
             mock.patch.object(ledger.Ledger, "prepare", side_effect=AssertionError("no lease")):
            receipt = self.install()
        self.assertEqual(receipt["nft_table_handle"], 17)
        self.assertEqual(receipt["policy_sha256"], self.host.sha)
        self.assertEqual(receipt["baseline_sha256"], hashlib.sha256(self.journal.read_bytes()).hexdigest())
        self.assertEqual(self.calls, [("-n", "-j", "list", "tables"), ("-j", "-f", "-")])
        self.assertEqual(host.identity.decode_json(self.journal.read_bytes())["state"], "verified")
        with ledger.Ledger(self.bootstrap.store_path, clock=host.time.time) as store:
            with store._transaction() as state:
                self.assertEqual(state["leases"], {})

    def test_wrong_bootstrap_or_host_policy_seal_denies_before_kernel(self):
        with mock.patch.object(host, "_host", side_effect=AssertionError("no kernel")):
            with self.assertRaises(Denied):
                host.install_bootstrap_baseline(str(self.bootstrap.path), "f" * 64)
            self.host.path.write_bytes(self.host.path.read_bytes() + b" ")
            with self.assertRaises(Denied): self.install()
        self.assertFalse(self.journal.exists())

    def test_unknown_journal_never_adopted_or_replayed(self):
        self.journal.write_bytes(ledger.canonical(host._journal_value(self.selected, "unknown")))
        self.journal.chmod(0o600)
        before = self.journal.read_bytes()
        with self.model(), self.assertRaises(Denied): self.install()
        self.assertEqual(self.journal.read_bytes(), before)
        self.assertEqual(self.calls, [("-n", "-j", "list", "tables")])

    def test_bootstrap_drift_during_inventory_denies_before_intent_or_create(self):
        def drift(phase):
            if phase == "inventory":
                self.bootstrap.path.write_bytes(self.bootstrap.path.read_bytes() + b" ")
        with self.model(drift), self.assertRaises(Denied): self.install()
        self.assertFalse(self.journal.exists())
        self.assertEqual(self.calls, [("-n", "-j", "list", "tables")])

    def test_bootstrap_drift_after_possible_create_retains_unknown_no_retry(self):
        def drift(phase):
            if phase == "create":
                self.bootstrap.path.write_bytes(self.bootstrap.path.read_bytes() + b" ")
        with self.model(drift), self.assertRaises(host.HostFenceUnknown): self.install()
        self.assertEqual(host.identity.decode_json(self.journal.read_bytes())["state"], "unknown")
        # Restoring original configuration never adopts the unknown effect.
        self.bootstrap.path.write_bytes(ledger.canonical(self.bootstrap.value))
        with self.model(), self.assertRaises(Denied): self.install()
        self.assertEqual(sum(argv == ("-j", "-f", "-") for argv in self.calls), 1)


if __name__ == "__main__":
    unittest.main()
