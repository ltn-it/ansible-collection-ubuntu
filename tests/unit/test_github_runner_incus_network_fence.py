"""Closed-command/Root FS/journal fixtures, NOT native namespace qualification.

The only subprocess fixtures are synthetic sealed executables, never ip/nft.
Kernel paths are mocked in journal tests; actual nsfs placeholder rejection is
independent. Central proper EE executes these tests; no host/native activation.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import datetime as dt
import hashlib
import os
from pathlib import Path
import stat
import socket
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import test_github_runner_incus_preparation as preparation_fixtures
import test_github_runner_incus_cell_contract as cleanup_fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import network_fence as fence, identity, ledger  # noqa: E402
from incus_lease_issuer import host_api_fence as host_fence  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class FenceBoundaryTests(unittest.TestCase):
    def test_native_ip_path_is_fixed_canonical_binary_without_alias_resolution(self):
        self.assertEqual(fence.IP, "/usr/bin/ip")

    def test_ip_array_parser_accepts_native_shape_and_rejects_bad_nested_json(self):
        self.assertEqual(fence._array(b'[{"ifindex":2,"addr_info":[{"local":"10.1.2.3"}]}]'),
                         [{"ifindex": 2, "addr_info": [{"local": "10.1.2.3"}]}])
        self.assertEqual(fence._array(b'[]'), [])
        for raw in (b'{}', b'[1]', b'[[{}]]', b'[{"ifindex":1,"ifindex":2}]',
                    b'[{"addr_info":[{"local":"a","local":"b"}]}]', b'[{"value":NaN}]',
                    b'[{"value":1e999}]', b'[],"other":1', b'[] garbage',
                    b'[' + b'{},' * 8192 + b'{}]'):
            with self.assertRaisesRegex(Denied, "fence-ip-json-denied"):
                fence._array(raw)
        with self.assertRaisesRegex(Denied, "fence-ip-json-limit"):
            fence._array(b' ' * (fence.LIMIT + 1))

    def test_nonroot_before_inputs_or_possible_effect(self):
        with mock.patch.object(fence.os, "geteuid", return_value=2101):
            for entry in (fence.create, fence.renew, fence.disable, fence.remove):
                with self.assertRaisesRegex(Denied, "fence-root-required"):
                    entry(None, None, None, None, None, None)
            with self.assertRaisesRegex(Denied, "fence-root-required"):
                fence.verify_disabled(None, None, None, None)
            with self.assertRaisesRegex(Denied, "fence-root-required"):
                with fence.acquire_existing_fence(None, None, None, None):
                    self.fail("nonroot must never acquire a fence")

    def test_no_job_command_url_runner_or_acceptance_input(self):
        for extra in ({"command": ["sh"]}, {"reader": lambda: None}, {"qualified": True}, {"url": "https://job"}):
            with self.assertRaises(TypeError):
                fence.create(None, None, None, None, None, None, **extra)

    def test_missing_root_factory_binding_denies_engine(self):
        with mock.patch.object(fence.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(Denied, "fence-root-policy-not-bound"):
                with fence.acquire_existing_fence(None, None, None, object()):
                    self.fail("configuration has no fence policy")

    def test_unproven_namespace_drain_never_creates_cleanup_intent(self):
        store = mock.Mock()
        with mock.patch.object(fence.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(fence.KernelHold, "fence-kernel-hold"):
                fence.remove(None, None, None, store, None, None)
        store.begin.assert_not_called()

    def test_cookie_uses_owned_duplicate_and_preserves_original_socket_io_and_flags(self):
        if sys.platform != "linux":
            self.skipTest("Linux socket cookie")
        first, second = socket.socketpair()
        try:
            first.setblocking(False)
            flags = fence.fcntl.fcntl(first.fileno(), fence.fcntl.F_GETFL)
            cookie = fence._socket_cookie(first.fileno())
            self.assertGreater(cookie, 0)
            self.assertEqual(fence._socket_cookie(second.fileno()), cookie)
            self.assertEqual(fence.fcntl.fcntl(first.fileno(), fence.fcntl.F_GETFL), flags)
            first.sendall(b"original-descriptor-still-owned")
            self.assertEqual(second.recv(64), b"original-descriptor-still-owned")
        finally:
            first.close()
            second.close()

    def test_multithread_cookie_witness_never_forks(self):
        with mock.patch.object(fence.os, "listdir", return_value=["1", "2"]), mock.patch.object(fence.os, "fork") as fork:
            with self.assertRaisesRegex(Denied, "fence-observer-single-thread"):
                fence._namespace_cookie(-1, None)
            fork.assert_not_called()

    def test_unqualified_pidfd_duplication_is_a_hold_not_an_assumed_socket_absence(self):
        with mock.patch.object(fence.platform, "machine", return_value="unsupported"):
            with self.assertRaisesRegex(Denied, "fence-pidfd-unsupported"):
                fence._borrow_socket(os.getpid() + 1, -1, 0)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Root Linux EE only")
class RootFenceComponentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preparation_fixtures.RootPreparationTests.setUpClass()

    def setUp(self):
        self.io = preparation_fixtures.RootPreparationTests()
        self.io.setUp()
        self.addCleanup(self.io.doCleanups)
        self.prepared, self.store, self.lease, self.root = self.io.prepared, self.io.store, self.io.lease, self.io.root
        self.worker = ledger.Worker(**self.store.read(self.lease)["worker"])
        self.config = fence.preparation._config(str(self.io.config), self.io.sha)[0]
        self.path = self.root / "fence-policy.json"
        self.value = {"schema": 1, "backend_ipv4": "10.10.20.30", "backend_port": 8443,
                      "host_address": "10.250.23.1/30", "namespace_address": "10.250.23.2/30",
                      "tools": {fence.IP: "a" * 64, fence.NFT: "b" * 64}}
        self.seal()
        self.io.value["network_fence_policy_path"] = str(self.path)
        self.io.value["network_fence_policy_sha256"] = self.sha
        self.io.seal()
        self.config = fence.preparation._config(str(self.io.config), self.io.sha)[0]

    def seal(self):
        self.path.write_bytes(ledger.canonical(self.value))
        self.path.chmod(0o600)
        self.sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.policy = fence._policy(str(self.path), self.sha)

    def call(self, entry):
        return entry(str(self.path), self.sha, self.prepared, self.store, self.worker, self.config)

    def effects(self):
        return list(self.store.read(self.lease)["effects"].values())

    def readback(self, *, ttl=0, deadline=0):
        rows = [deepcopy(row["add"]) for row in fence._rules(self.policy, self.prepared, deadline)["nftables"]]
        for index, row in enumerate(rows, 1):
            kind = next(iter(row))
            value = row[kind]
            value["handle"] = index
            if kind == "rule":
                if value["chain"] == "gate":
                    value["expr"][0]["match"]["right"] = dt.datetime.fromtimestamp(
                        deadline, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                for expr in value["expr"]:
                    if "counter" in expr:
                        expr["counter"] = {"packets": 7, "bytes": 1024}
            if kind == "set" and ttl:
                value["elem"] = [{"elem": {"val": {"concat": [self.policy.backend, self.policy.port]},
                                               "timeout": ttl + 1, "expires": ttl}}]
        return {"nftables": [{"metainfo": {"json_schema_version": 1}}, *rows]}

    def check_readback(self, data, maximum=0):
        with mock.patch.object(fence, "_nft", return_value=ledger.canonical(data)):
            return fence._rules_readback(self.policy, self.prepared, maximum_ms=maximum)

    def test_root_private_policy_rejects_drift_schema_host_and_shared_subnet(self):
        cases = ({"backend_ipv4": "127.0.0.1"}, {"backend_ipv4": "8.8.8.8"}, {"backend_ipv4": "169.254.1.1"},
                 {"namespace_address": "10.250.23.1/30"}, {"backend_ipv4": "10.250.23.2"},
                 {"host_address": "10.250.23.1/24"}, {"backend_port": True}, {"accepted": True})
        original = deepcopy(self.value)
        for changes in cases:
            self.value = {**original, **changes}
            self.path.write_bytes(ledger.canonical(self.value))
            digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
            with self.assertRaises((Denied, ValueError)):
                fence._policy(str(self.path), digest)
        self.value = original
        self.seal()
        self.path.chmod(0o644)
        with self.assertRaises(Denied):
            fence._policy(str(self.path), self.sha)
        self.path.chmod(0o600)
        self.path.write_bytes(b"private changed bytes")
        with self.assertRaisesRegex(Denied, "fence-policy-drift"):
            fence._policy(str(self.path), self.sha)

    def test_separate_root_sealed_policy_cannot_replace_root_configuration_reference(self):
        alternate = self.root / "alternate-fence-policy.json"
        alternate.write_bytes(self.path.read_bytes())
        alternate.chmod(0o600)
        before = self.effects()
        for entry in (fence.create, fence.renew, fence.disable):
            with mock.patch.object(fence, "_run") as command:
                with self.assertRaisesRegex(Denied, "fence-root-policy-binding"):
                    entry(str(alternate), self.sha, self.prepared, self.store, self.worker, self.config)
                command.assert_not_called()
        self.assertEqual(self.effects(), before)

    def test_new_rules_are_deny_first_and_each_direction_uses_timed_set(self):
        data = fence._rules(self.policy, self.prepared)
        sets = [row["add"]["set"] for row in data["nftables"] if "set" in row["add"]]
        self.assertEqual(sets[0]["flags"], ["timeout"])
        self.assertNotIn("elem", sets[0])
        rules = [row["add"]["rule"] for row in data["nftables"] if "rule" in row["add"]]
        for chain in ("input", "output"):
            expressions = [rule["expr"] for rule in rules if rule["chain"] == chain]
            self.assertEqual(expressions[0][-1], {"accept": None})  # Own loopback only.
            self.assertEqual(expressions[1][-2]["match"]["right"], "@admitted")
            self.assertEqual(expressions[1][-1], {"jump": {"target": "gate"}})
            self.assertEqual(expressions[2][-1], {"drop": None})
        raw = ledger.canonical(data)
        for forbidden in (b"conntrack", b'"ct"', b"dynset", b"update", b"flowtable", b"flush"):
            self.assertNotIn(forbidden, raw)
        self.assertEqual(self.check_readback(self.readback()), (1, 0, 4, 0))
        gate = [row["add"]["rule"] for row in data["nftables"]
                if "rule" in row["add"] and row["add"]["rule"]["chain"] == "gate"]
        self.assertEqual(gate[0]["expr"], fence._gate_expression(0))

    def test_ruleset_rejects_extra_table_accept_reorder_wrong_endpoint_and_timer(self):
        variants = []
        extra = self.readback()
        extra["nftables"].append({"table": {"family": "ip", "name": "foreign", "handle": 99}})
        variants.append(extra)
        for change in ("bypass", "reorder", "endpoint", "timer", "untimed", "dynamic"):
            value = self.readback(ttl=29)
            rule = next(row["rule"] for row in value["nftables"] if "rule" in row and len(row["rule"]["expr"]) == 4)
            element = next(row["set"] for row in value["nftables"] if "set" in row)["elem"][0]["elem"]
            if change == "bypass":
                rule["expr"] = [{"accept": None}]
            elif change == "reorder":
                rule["expr"] = list(reversed(rule["expr"]))
            elif change == "endpoint":
                element["val"]["concat"][0] = "10.0.0.99"
            elif change == "timer":
                element["expires"] = 1001
            elif change == "untimed":
                del element["expires"]
            else:
                rule["expr"].insert(0, {"ct": {"key": "state"}})
            variants.append(value)
        for value in variants:
            with self.assertRaises(Denied):
                self.check_readback(value, maximum=30000)
        self.assertEqual(self.check_readback(self.readback(ttl=29), maximum=30000), (1, 29000, 4, 0))
        with self.assertRaisesRegex(Denied, "fence-unexpected-allow"):
            self.check_readback(self.readback(ttl=29))

    def test_actual_nft109_canonical_utc_gate_normalizes_to_exact_epoch(self):
        deadline = int(time.time()) + 120
        data = self.readback(ttl=29, deadline=deadline)
        with mock.patch.object(fence, "_nft", return_value=ledger.canonical(data)):
            self.assertEqual(fence._rules_readback(self.policy, self.prepared, maximum_ms=30000,
                                                  expected_deadline=deadline)[-1], deadline)
            with self.assertRaisesRegex(Denied, "fence-absolute-gate-deadline"):
                fence._rules_readback(self.policy, self.prepared, maximum_ms=30000, expected_deadline=deadline + 1)
        # Includes the exact shape observed by native absolute-time2. The native
        # absolute-time1 integer-output assumption remains a preserved failure.
        self.assertEqual(fence._gate_deadline("2026-11-04 14:31:37"),
                         int(dt.datetime(2026, 11, 4, 14, 31, 37, tzinfo=dt.timezone.utc).timestamp()))
        self.assertEqual(fence._gate_deadline("1970-01-01 00:00:00"), 0)
        self.assertEqual(fence._gate_deadline("2106-02-07 06:28:15"), 4294967295)

    def test_native_seconds_quantization_and_wrong_units_fail_closed(self):
        original = self.readback(ttl=29)
        for field, invalid in (("timeout", 30000), ("expires", 29999), ("expires", 0),
                               ("timeout", True), ("expires", "29"), ("expires", 29.5), ("expires", 31)):
            value = deepcopy(original)
            next(row["set"] for row in value["nftables"] if "set" in row)["elem"][0]["elem"][field] = invalid
            with self.subTest(field=field, value=invalid), self.assertRaises(Denied):
                self.check_readback(value, maximum=30000)
        with self.assertRaises(Denied):
            self.check_readback(original, maximum=29999)
        self.assertEqual(self.check_readback(original, maximum=30000)[1], 29000)

    def test_existing_issuance_reserve_covers_fractional_clock_and_maximum_apply_delay(self):
        record = {"expires_at": 1800000136, "authorizations": [{"valid_until": 1800000200}]}
        issued = 1800000100.1
        with mock.patch.object(fence.time, "time", return_value=issued):
            deadline, remaining = fence._remaining(record)
        ttl = remaining - 6  # Same fixed five-second command + one-second reserve.
        self.assertEqual(ttl, 29)
        for apply_delay in (0, 4.999, 5):
            for after_apply in (0.1, 1.2, 12.2, 26.2):
                now = issued + apply_delay + after_apply
                data = self.readback(ttl=int(ttl-after_apply), deadline=deadline)
                next(row["set"] for row in data["nftables"] if "set" in row)["elem"][0]["elem"]["timeout"] = ttl
                with self.subTest(delay=apply_delay, elapsed=after_apply), \
                     mock.patch.object(fence.time, "time", return_value=now):
                    _, seconds = fence._remaining(record)
                    self.assertGreater(self.check_readback(data, maximum=seconds*1000)[1], 0)
    def test_absolute_gate_rejects_noncanonical_dates_units_and_timezones(self):
        deadline = int(time.time()) + 120
        data = self.readback(ttl=29, deadline=deadline)
        for replacement in (deadline, deadline * 1000000000, str(deadline), True,
                            "2026-11-04T14:31:37Z", "2026-11-04 14:31:37Z", "2026-11-04 14:31:37+00:00",
                            "2026-11-04 14:31:37 UTC", "2026-11-04 14:31:37-03:00", "2026-11-04 14:31:37.0",
                            "2026-11-4 14:31:37", "2026-11-04 14:31", "2026-02-30 14:31:37",
                            "2026-11-04 14:31:60", "1969-12-31 23:59:59", "2106-02-07 06:28:16",
                            "9999-12-31 23:59:59", "2026-11-04 14:31:37\n"):
            value = deepcopy(data)
            gate = next(row["rule"] for row in value["nftables"] if "rule" in row and row["rule"]["chain"] == "gate")
            gate["expr"][0]["match"]["right"] = replacement
            with self.assertRaises(Denied):
                self.check_readback(value, maximum=30000)

    def test_duplicate_json_and_unbounded_ruleset_fail_closed(self):
        for raw in (b'{"nftables":[],"nftables":[]}', b'{"nftables":[NaN]}'):
            with mock.patch.object(fence, "_nft", return_value=raw):
                with self.assertRaises(Denied):
                    fence._rules_readback(self.policy, self.prepared)

    def test_real_private_regular_file_is_not_namespace_proof(self):
        parent = self.root / "namespace-placeholders"
        parent.mkdir(mode=0o700)
        name = fence._names(self.prepared)[0]
        (parent / name).write_bytes(b"")
        (parent / name).chmod(0o600)
        real_open = fence.installation._open_directory
        def selected(path):
            return real_open(str(parent) if path == "/run/netns" else path)
        with mock.patch.object(fence.installation, "_open_directory", side_effect=selected):
            with self.assertRaisesRegex(Denied, "fence-real-namespace-required"):
                with fence._namespace(self.prepared):
                    self.fail("regular-file inode cannot prove an NSFS namespace")

    def test_actual_fixed_subprocess_fd_hash_bounds_and_error_redaction(self):
        # /run/proof intentionally remains noexec. The central proper EE must
        # provide a separate private exec tmpfs; do not weaken production file
        # checks, run host tools, or silently skip the real execution boundary.
        parent = fence.installation._open_directory("/run/executable-proof")
        try:
            info = os.fstat(parent)
            self.assertEqual((info.st_uid, stat.S_IMODE(info.st_mode)), (0, 0o700))
            self.assertFalse(os.fstatvfs(parent).f_flag & os.ST_NOEXEC, "dedicated fixture tmpfs must permit exec")
        finally:
            os.close(parent)
        allocation = tempfile.TemporaryDirectory(prefix="fence-tool-", dir="/run/executable-proof")
        self.addCleanup(allocation.cleanup)
        executable = Path(allocation.name) / "synthetic-ip"
        nft = Path(allocation.name) / "synthetic-nft"
        executable.write_bytes(b"#!/bin/sh\nprintf '%s' sealed-fixed-tool\n")
        nft.write_bytes(b"#!/bin/sh\nprintf '%s' PRIVATE-TOKEN-DO-NOT-LOG >&2\nexit 7\n")
        for file in (executable, nft):
            file.chmod(0o700)
        policy = replace(self.policy, tools=((str(executable), hashlib.sha256(executable.read_bytes()).hexdigest()),
                                            (str(nft), hashlib.sha256(nft.read_bytes()).hexdigest())))
        with mock.patch.object(fence, "IP", str(executable)), mock.patch.object(fence, "NFT", str(nft)):
            self.assertEqual(fence._run(policy, str(executable), []), b"sealed-fixed-tool")
            with self.assertRaisesRegex(Denied, "^fence-command-denied$") as caught:
                fence._run(policy, str(nft), [])
            self.assertNotIn("PRIVATE-TOKEN", str(caught.exception))
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            with self.assertRaisesRegex(Denied, "fence-command-denied"):
                fence._run(policy, str(executable), [])

    def test_old_alias_policy_and_actual_symlink_tool_deny_before_execution(self):
        value = deepcopy(self.value)
        value["tools"] = {"/usr/sbin/ip": "a" * 64, fence.NFT: "b" * 64}
        self.path.write_bytes(ledger.canonical(value))
        with self.assertRaises(Denied):
            fence._policy(str(self.path), hashlib.sha256(self.path.read_bytes()).hexdigest())
        target = self.root / "actual-regular-ip-fixture"
        target.write_bytes(b"#!/bin/sh\nexit 0\n")
        target.chmod(0o700)
        alias = self.root / "ip-symlink-fixture"
        alias.symlink_to(target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        policy = replace(self.policy, tools=((str(alias), digest),))
        with mock.patch.object(fence, "IP", str(alias)), mock.patch.object(fence.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(Denied, "^fence-command-denied$"):
                fence._run(policy, str(alias), [])
            popen.assert_not_called()

    @contextmanager
    def kernel_fixture(self, *, fail_on=None):
        """Modeled private+host kernel observations, NOT persistent baseline proof."""
        self.commands, self.nft_calls = [], []
        info = os.stat(self.path)
        @contextmanager
        def namespace(prepared):
            yield -1, info
        def command(policy, program, argv, *, payload=None):
            self.commands.append((program, tuple(argv), payload))
            if fail_on is not None and len(self.commands) == fail_on:
                raise Denied("synthetic possible kernel effect")
            return b"[]"
        def nft(policy, prepared, *argv, payload=None):
            self.nft_calls.append((argv, payload))
            return b""
        real_open = fence.installation._open_directory
        with mock.patch.object(fence, "_worker"), mock.patch.object(fence, "_backend"), \
             mock.patch.object(host_fence, "bind_creator"), mock.patch.object(host_fence, "grant"), \
             mock.patch.object(host_fence, "withdraw"), \
             mock.patch.object(fence, "_namespace", side_effect=namespace), \
             mock.patch.object(fence, "_run", side_effect=command), \
             mock.patch.object(fence, "_nft", side_effect=nft), \
             mock.patch.object(fence, "_links", return_value=(100, 2)), \
             mock.patch.object(fence, "_rules_readback", return_value=(1, 0, 4, 0)), \
             mock.patch.object(fence.installation, "_open_directory", side_effect=lambda path:
                 real_open(str(self.root) if path == "/run/netns" else path)):
            yield info

    def test_actual_prepared_cell_create_journals_before_mutation_and_starts_denied(self):
        with self.kernel_fixture() as info:
            receipt = self.call(fence.create)
        self.assertEqual(receipt.operation, "fence-create")
        effect = self.effects()[-1]
        self.assertEqual(effect["state"], "verified")
        self.assertEqual(effect["fence"]["netns_inode"], info.st_ino)
        self.assertEqual(effect["fence"]["policy_sha256"], self.sha)
        mutation_commands = [argv for _, argv, _ in self.commands if not argv[:1] == ("-j",)]
        self.assertEqual(mutation_commands[0], ("netns", "add", "lit-lease-" + self.lease))
        self.assertEqual(len(self.nft_calls), 1)
        self.assertNotIn(b'"elem"', self.nft_calls[0][1])
        self.assertFalse(any("sysctl" in " ".join(argv) or "flush" in argv for _, argv, _ in self.commands))
        with self.kernel_fixture():
            with self.assertRaises(Denied):
                self.call(fence.create)
            self.assertFalse(any(argv[:2] == ("netns", "add") for _, argv, _ in self.commands))

    def test_possible_first_or_later_kernel_effect_retains_unknown_no_cleanup_or_retry(self):
        with self.kernel_fixture(fail_on=3):
            with self.assertRaisesRegex(fence.FenceUnknown, "^fence-effect-unknown$"):
                self.call(fence.create)
            self.assertEqual(self.effects()[-1]["state"], "unknown")
            before = len(self.commands)
            with self.assertRaises(Denied):
                self.call(fence.create)
            self.assertFalse(any("delete" in argv or "del" in argv for _, argv, _ in self.commands))
            self.assertGreaterEqual(len(self.commands), before)  # Read-only preflight may repeat, never effects.

    def create_fixture(self):
        with self.kernel_fixture():
            self.call(fence.create)

    def test_host_creator_is_bound_inside_existing_create_intent_after_namespace_identity(self):
        observed = []
        def bound(*args):
            effect = self.store.read(self.lease)["effects"][args[-1]]
            observed.append((effect["operation"], effect["state"], "fence" in effect))
        with self.kernel_fixture(), mock.patch.object(host_fence, "bind_creator", side_effect=bound):
            self.call(fence.create)
        self.assertEqual(observed, [("fence-create", "intent", True)])

    def test_host_withdrawal_precedes_private_cut_in_the_same_once_intent(self):
        self.create_fixture()
        observed = []
        def withdraw(*args):
            effect = self.store.read(self.lease)["effects"][args[-1]]
            self.assertEqual((effect["operation"], effect["state"]), ("fence-disable", "intent"))
            observed.append("host-cut")
        with mock.patch.object(fence, "_owned", return_value=({}, 0, 4, 0)), \
             mock.patch.object(host_fence, "withdraw", side_effect=withdraw), \
             mock.patch.object(fence, "_nft", side_effect=lambda *args, **kwargs: observed.append("private-cut")):
            self.call(fence.disable)
        self.assertEqual(observed, ["host-cut", "private-cut"])

    def test_unknown_private_namespace_cannot_prevent_known_host_access_withdrawal(self):
        self.create_fixture()
        with mock.patch.object(host_fence, "withdraw") as withdraw, \
             mock.patch.object(fence, "_owned", side_effect=Denied("private-kernel-uncertain")), \
             mock.patch.object(fence, "_nft") as nft:
            with self.assertRaises(fence.FenceUnknown):
                self.call(fence.disable)
            withdraw.assert_called_once()
            nft.assert_not_called()
        effects = [row for row in self.effects() if row["operation"] == "fence-disable"]
        self.assertEqual([row["state"] for row in effects], ["unknown"])

    def test_renew_journals_latest_fullauth_digest_and_conservative_fixed_deadline(self):
        self.create_fixture()
        record = self.store.read(self.lease)
        absolute_deadline = min(record["expires_at"], record["authorizations"][-1]["valid_until"])
        with mock.patch.object(fence, "_worker"), mock.patch.object(fence, "_signed"), \
             mock.patch.object(host_fence, "grant"), \
             mock.patch.object(fence, "_owned", return_value=({}, 1000, 4, absolute_deadline)), \
             mock.patch.object(fence, "_nft") as nft:
            receipt = self.call(fence.renew)
        self.assertEqual(receipt.operation, "fence-renew")
        record = self.store.read(self.lease)
        auth = record["authorizations"][-1]
        renewed = [effect for effect in self.effects() if effect["operation"] == "fence-renew"
                   and effect["target"] == "fence:" + self.lease + ":" + auth["token_id_sha256"]]
        self.assertEqual(len(renewed), 1)
        effect = renewed[0]
        self.assertEqual(effect["state"], "verified")
        metadata = effect["fence_authorization"]
        self.assertEqual(metadata["authorization_sha256"], ledger.digest(auth))
        self.assertEqual(effect["target"], "fence:" + self.lease + ":" + auth["token_id_sha256"])
        self.assertEqual(metadata["allow_expires_at"], min(record["expires_at"], auth["valid_until"]))
        ttl = (metadata["expires_boot_ns"] - metadata["issued_boot_ns"]) // 1000000000
        self.assertLessEqual(ttl, metadata["allow_expires_at"] - int(time.time()) - 5)
        self.assertIn(("timeout " + str(ttl) + "s").encode(), nft.call_args.kwargs["payload"])
        self.assertIn(("meta time < " + str(absolute_deadline) + " accept").encode(), nft.call_args.kwargs["payload"])
        with mock.patch.object(fence, "_worker"), mock.patch.object(fence, "_signed"), \
             mock.patch.object(host_fence, "grant"), \
             mock.patch.object(fence, "_owned", return_value=({}, 1000, 4, absolute_deadline)), mock.patch.object(fence, "_nft") as nft:
            with self.assertRaises(Denied):
                self.call(fence.renew)
            nft.assert_not_called()

    def test_real_renew_parser_handles_fractional_clock_and_bounded_apply_delay(self):
        self.create_fixture()
        record = self.store.read(self.lease)
        deadline = min(record["expires_at"], record["authorizations"][-1]["valid_until"])
        issued = float(int(time.time())) + 0.1
        clock = {"now": issued, "applied": None, "ttl": None}
        def nft(_policy, _prepared, *argv, payload=None):
            if payload is not None:
                # The actual Root renewal builds this closed transaction.
                clock["ttl"] = int(payload.decode("ascii").split(" timeout ")[1].split("s }")[0])
                self.assertEqual(clock["ttl"], int(deadline-issued)-6)
                clock["applied"] = issued + 5
                clock["now"] = clock["applied"] + 0.1
                return b""
            data = self.readback()
            if clock["applied"] is not None:
                remaining = int(clock["ttl"]-(clock["now"]-clock["applied"]))
                data = self.readback(ttl=remaining, deadline=deadline)
                next(row["set"] for row in data["nftables"] if "set" in row)["elem"][0]["elem"]["timeout"] = clock["ttl"]
            return ledger.canonical(data)
        def owned(policy, prepared, store, *, maximum_ms=0):
            # Namespace/links already modeled by create_fixture; retain the
            # real bounded JSON parser instead of modeling its result.
            _table, expires, gate, actual_deadline = fence._rules_readback(policy, prepared, maximum_ms=maximum_ms)
            return {}, expires, gate, actual_deadline
        with mock.patch.object(fence, "_worker"), mock.patch.object(fence, "_signed"), \
             mock.patch.object(host_fence, "grant"), \
             mock.patch.object(fence.time, "time", side_effect=lambda: clock["now"]), \
             mock.patch.object(fence, "_owned", side_effect=owned), mock.patch.object(fence, "_nft", side_effect=nft):
            self.call(fence.renew)
            for elapsed in (0.1, 1.2, 20.2):
                clock["now"] = clock["applied"] + elapsed
                _, seconds = fence._remaining(self.store.read(self.lease))
                self.assertGreater(owned(self.policy, self.prepared, self.store, maximum_ms=seconds*1000)[1], 0)
        effects = [row for row in self.effects() if row["operation"] == "fence-renew"]
        self.assertEqual([row["state"] for row in effects], ["verified"])
        self.assertEqual(effects[0]["fence_authorization"]["allow_expires_at"], deadline)

    def test_invalid_latest_signed_context_denies_before_grant_intent(self):
        self.create_fixture()
        count = len(self.effects())
        with mock.patch.object(fence, "_worker"), mock.patch.object(fence, "_signed", side_effect=Denied("old signature")), \
             mock.patch.object(fence, "_nft") as nft:
            with self.assertRaises(Denied):
                self.call(fence.renew)
            nft.assert_not_called()
        self.assertEqual(len(self.effects()), count)

    def test_actual_signed_running_output_requires_retained_manifest_and_verified_engine_journal(self):
        # Actual private Root preparation, crypto, manifest and Ledger. Only
        # kernel fencing/Worker observations are modeled; no engine is started.
        self.io.run_prepare()
        self.create_fixture()
        record = self.store.read(self.lease)
        deadline = min(record["expires_at"], record["authorizations"][-1]["valid_until"])
        with mock.patch.object(fence, "_worker"), mock.patch.object(fence, "_owned", return_value=({}, 1000, 4, deadline)), \
             mock.patch.object(host_fence, "grant"), \
             mock.patch.object(fence, "_nft"):
            self.call(fence.renew)  # Includes actual pre-start full JWS verification.
        manifest = fence.engine.compile_engine_policy(self.prepared.engine_descriptor_path,
                                                       self.prepared.engine_descriptor_sha256)
        details = identity.decode_json(manifest.canonical_bytes)
        retained = Path(details["engine"]["runroot"]) / "engine-manifest.json"
        retained.write_bytes(manifest.canonical_bytes)
        retained.chmod(0o600)
        effect = self.store.begin(self.lease, "engine-start", "engine:lit-lease-" + self.lease)
        output = Path(details["output"]["path"]) / "test-output.txt"
        output.write_bytes(b"synthetic running engine output")
        output.chmod(0o600)
        with self.assertRaisesRegex(Denied, "fence-engine-start-unverified"):
            fence._signed(self.prepared, self.store, self.worker, self.config)
        self.store.bind_engine_process(self.lease, effect, pid=12345, start_ticks=54321,
                                      boot_id=fence.kernel.read_boot_id(), exe_device=1, exe_inode=2,
                                      exe_sha256=details["engine_executable_sha256"])
        self.store.bind_engine_container(self.lease, effect, "d" * 64)
        self.store.record(self.lease, effect, "verified", evidence_sha256="f" * 64)
        with self.assertRaisesRegex(Denied, "engine-output-reused"):
            fence.engine.compile_engine_policy(self.prepared.engine_descriptor_path,
                                                self.prepared.engine_descriptor_sha256)
        fence._signed(self.prepared, self.store, self.worker, self.config)
        self.assertEqual(retained.read_bytes(), manifest.canonical_bytes)
        self.assertEqual(output.read_bytes(), b"synthetic running engine output")
        # A different retained digest cannot acquire authority from an unsigned
        # claim. Actual crypto still authenticates the exact original manifest.
        binding_path = Path(details["context"]["path"]) / "binding.json"
        old_binding = binding_path.read_bytes()
        binding = identity.decode_json(old_binding)
        pieces = binding["admission"].split(".")
        payload = identity.decode_json(identity.unbase(pieces[1]))
        payload["engine_policy_sha256"] = "e" * 64
        import base64
        pieces[1] = base64.urlsafe_b64encode(ledger.canonical(payload)).rstrip(b"=").decode("ascii")
        binding["admission"] = ".".join(pieces)
        binding_path.write_bytes(ledger.canonical(binding))
        with self.assertRaises(Denied):
            fence._signed(self.prepared, self.store, self.worker, self.config)
        binding_path.write_bytes(old_binding)
        tls_file = Path(details["context"]["path"]) / "client.crt"
        tls_file.write_bytes(tls_file.read_bytes() + b"immutable drift")
        with self.assertRaises(Denied):
            fence._signed(self.prepared, self.store, self.worker, self.config)

    def test_emergency_disable_after_cancel_with_other_unknown_holds_and_never_renews(self):
        self.create_fixture()
        other = self.store.begin(self.lease, "test", "fixture-observation")
        self.store.record(self.lease, other, "unknown", evidence_sha256="f" * 64)
        self.store.cancel(self.lease, "job_ended")
        with mock.patch.object(fence, "_owned", return_value=({}, 0, 4, 0)), \
             mock.patch.object(host_fence, "withdraw"), mock.patch.object(fence, "_nft") as nft:
            self.call(fence.disable)
            self.assertEqual(nft.call_count, 1)
            self.assertTrue(nft.call_args.kwargs["payload"].startswith(b"flush set inet lit_lease_"))
        self.assertEqual(self.store.read(self.lease)["effects"][other]["state"], "unknown")
        disabled = [effect for effect in self.effects() if effect["operation"] == "fence-disable"
                    and effect["target"] == "fence:" + self.lease]
        self.assertEqual(len(disabled), 1)
        self.assertEqual(disabled[0]["state"], "verified")
        with mock.patch.object(fence, "_owned", return_value=({}, 0, 4, 0)), \
             mock.patch.object(host_fence, "withdraw"), mock.patch.object(fence, "_nft") as nft:
            with self.assertRaises(Denied):
                self.call(fence.disable)
            nft.assert_not_called()

    def test_restart_cleanup_uses_distinct_derived_fence_owner_not_prepared_grant(self):
        self.create_fixture()
        self.store.cancel(self.lease, "cancelled")
        original = self.store.read(self.lease)
        owner = fence.cell_contract.owned_fence_for_cleanup(self.prepared.registry, self.prepared.selector,
                                                          self.store, self.lease)
        with self.kernel_fixture():
            receipt = fence.disable(str(self.path), self.sha, owner, self.store, self.worker, self.config)
        self.assertEqual(receipt.operation, "fence-disable")
        current = self.store.read(self.lease)
        self.assertEqual(current["authorizations"], original["authorizations"])
        self.assertEqual(current["expires_at"], original["expires_at"])
        self.assertEqual(current["state"], "cancelled")
        for entry in (fence.create, fence.renew):
            with self.kernel_fixture():
                with self.assertRaises(Denied):
                    entry(str(self.path), self.sha, owner, self.store, self.worker, self.config)
                self.assertEqual(self.commands, [])
                self.assertEqual(self.nft_calls, [])

    def test_modified_cleanup_owner_is_rejected_before_any_kernel_effect(self):
        self.create_fixture()
        owner = fence.cell_contract.owned_fence_for_cleanup(self.prepared.registry, self.prepared.selector,
                                                          self.store, self.lease)
        forged = replace(owner, creator_sha256="0" * 64)
        with self.kernel_fixture():
            with self.assertRaisesRegex(Denied, "fence-cleanup-owner-drift"):
                fence.disable(str(self.path), self.sha, forged, self.store, self.worker, self.config)
            self.assertEqual(self.commands, [])
            self.assertEqual(self.nft_calls, [])

    def test_worker_process_is_rechecked_not_accepted_from_matching_ledger_json(self):
        record = self.store.read(self.lease)
        observed = SimpleNamespace(stat=SimpleNamespace(start_ticks=self.worker.start_ticks + 1, state="S"),
                                   uids=(self.worker.uid,) * 4)
        with mock.patch.object(fence.kernel, "read_process", return_value=observed), \
             mock.patch.object(fence.kernel, "read_boot_id", return_value=self.worker.boot_id):
            with self.assertRaisesRegex(Denied, "fence-worker-not-live"):
                fence._worker(record, self.worker)

    def test_deadline_uses_min_and_never_rounds_up(self):
        with mock.patch.object(fence.time, "time", return_value=100.9):
            deadline, ttl = fence._remaining({"expires_at": 500, "authorizations": [{"valid_until": 106}]})
            self.assertEqual((deadline, ttl), (106, 5))
            self.assertEqual(fence._remaining({"expires_at": 104, "authorizations": [{"valid_until": 106}]}), (104, 3))
            with self.assertRaisesRegex(Denied, "fence-authorization-expired"):
                fence._remaining({"expires_at": 100, "authorizations": [{"valid_until": 106}]})


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootFenceRemovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cleanup_fixtures.RootCleanupSemanticTests.setUpClass()

    def setUp(self):
        self.value = {"schema": 1, "backend_ipv4": "10.10.20.30", "backend_port": 8443,
                      "host_address": "10.250.23.1/30", "namespace_address": "10.250.23.2/30",
                      "tools": {fence.IP: "a" * 64, fence.NFT: "b" * 64}}
        raw = ledger.canonical(self.value)
        self.sha = hashlib.sha256(raw).hexdigest()
        real_bind = ledger.Ledger.bind_fence
        # At initial fixture creation only, choose this actual sealed policy
        # digest for synthetic namespace metadata. Never rewrite persisted state.
        def bind(store, *args, **kwargs):
            kwargs["policy_sha256"] = self.sha
            return real_bind(store, *args, **kwargs)
        self.fixture = cleanup_fixtures.RootCleanupSemanticTests()
        with mock.patch.object(ledger.Ledger, "bind_fence", new=bind):
            self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.engine = self.fixture.engine_fixture
        self.io = self.engine.fixture
        self.store, self.lease = self.fixture.store, self.fixture.lease
        self.owner = self.fixture.owner()
        self.worker = ledger.Worker(**self.store.read(self.lease)["worker"])
        self.path = self.io.root / "removal-fence-policy.json"
        self.path.write_bytes(raw)
        self.path.chmod(0o600)
        self.io.value["network_fence_policy_path"] = str(self.path)
        self.io.value["network_fence_policy_sha256"] = self.sha
        self.io.seal()
        self.config = fence.preparation._config(str(self.io.config), self.io.sha)[0]
        self.fence_owner = fence.cell_contract.owned_fence_for_cleanup(self.owner.registry, self.owner.selector,
                                                                      self.store, self.lease)
        creator = next(row for row in self.store.read(self.lease)["effects"].values() if row["operation"] == "fence-create")
        self.metadata = creator["fence"]
        for operation, target in (("engine-stop", "engine:lit-lease-" + self.lease),
                                  ("fence-disable", "fence:" + self.lease)):
            effect = self.store.begin(self.lease, operation, target)
            self.store.record(self.lease, effect, "verified", evidence_sha256="d" * 64)
        self.aliases = self.io.root / "modeled-netns"
        self.aliases.mkdir(mode=0o700)
        self.alias = self.aliases / ("lit-lease-" + self.lease)
        self.alias.write_bytes(b"explicit modeled nsfs only")
        self.alias.chmod(0o600)
        self.commands, self.closed_fds = [], []

    @contextmanager
    def observations(self, *, fail_command=None):
        """ONLY native namespace/cgroup/proc/tool observations modeled.

        Real private Root files/FD lifecycle, all semantic owner/config checks,
        Ledger begin/binding/outcomes and exact removal command selection run.
        This positive is explicitly NOT native NSFS/ip/nft/drain qualification.
        """
        info = SimpleNamespace(st_dev=self.metadata["netns_device"], st_ino=self.metadata["netns_inode"])
        @contextmanager
        def namespace(_owner):
            fd = os.open(self.alias, os.O_RDONLY | os.O_CLOEXEC)
            try:
                yield fd, info
            finally:
                os.close(fd)
                self.closed_fds.append(fd)
        def command(_policy, program, argv, *, payload=None):
            if argv[:2] in (["link", "delete"], ["netns", "delete"]):
                pending = [row for row in self.store.read(self.lease)["effects"].values()
                           if row["operation"] == "fence-remove"]
                self.assertEqual(len(pending), 1)
                self.assertEqual(pending[0]["state"], "intent")
            self.commands.append((program, tuple(argv)))
            if fail_command is not None and len(self.commands) == fail_command:
                raise OSError("synthetic-possible-effect-secret")
            if argv[:2] == ["netns", "delete"]:
                self.alias.unlink()  # Fixture's own fixed private alias only.
            return b"[]"
        real_open = fence.installation._open_directory
        with mock.patch.object(fence.engine, "ENGINE", self.engine.original), \
             mock.patch.object(host_fence, "verify_withdrawn"), \
             mock.patch.object(fence, "_namespace", side_effect=namespace), \
             mock.patch.object(fence, "_removal_witness", side_effect=namespace), \
             mock.patch.object(fence, "_links", return_value=(self.metadata["host_ifindex"], self.metadata["peer_ifindex"])), \
             mock.patch.object(fence, "_rules_readback", return_value=(self.metadata["nft_table_handle"], 0, 4, 0)), \
             mock.patch.object(fence, "_namespace_cookie", return_value=17), \
             mock.patch.object(fence, "_namespace_refs_drained") as refs, \
             mock.patch.object(fence, "_engine_drained") as cgroup, \
             mock.patch.object(fence, "_run", side_effect=command), \
             mock.patch.object(fence.installation, "_open_directory", side_effect=lambda path:
                 real_open(str(self.aliases) if path == "/run/netns" else path)):
            yield refs, cgroup

    def remove(self):
        return fence.remove(str(self.path), self.sha, self.owner, self.store, self.worker, self.config)

    def test_actual_journal_fixed_commands_alias_absence_and_owned_fd_close(self):
        before = self.store.read(self.lease)
        with self.observations() as (refs, cgroup):
            proof = fence.verify_disabled(self.owner, self.store, self.worker, self.config)
            self.assertEqual(proof["admitted"], 0)
            self.assertEqual(self.store.read(self.lease), before)
            receipt = self.remove()
            self.assertEqual(receipt.operation, "fence-remove")
            self.assertEqual(refs.call_count, 3)
            self.assertEqual(cgroup.call_count, 2)
            # Crash between known removal commit and lease.close can only
            # repeat readback, never recreate or delete resources again.
            with mock.patch.object(fence.cell_contract, "owned_fence_for_cleanup",
                    side_effect=AssertionError("verified removal must not mint a live fence locator")):
                self.assertEqual(self.remove(), receipt)
                self.assertEqual(fence.verify_disabled(self.owner, self.store, self.worker, self.config)["admitted"], 0)
        mutations = [argv for _, argv in self.commands if argv[:2] in (("link", "delete"), ("netns", "delete"))]
        self.assertEqual(mutations, [("link", "delete", "dev", "lth" + self.lease[:12]),
                                     ("netns", "delete", "lit-lease-" + self.lease)])
        self.assertFalse(self.alias.exists())
        current = self.store.read(self.lease)
        removal = [row for row in current["effects"].values() if row["operation"] == "fence-remove"]
        self.assertEqual(len(removal), 1)
        self.assertEqual(removal[0]["state"], "verified")
        self.assertEqual(current["authorizations"], before["authorizations"])
        self.assertEqual(current["expires_at"], before["expires_at"])
        for fd in self.closed_fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_uncertain_proc_socket_or_cgroup_observation_is_hold_before_intent(self):
        with self.observations() as (refs, _):
            refs.side_effect = PermissionError("private-proc")
            with self.assertRaisesRegex(fence.KernelHold, "fence-kernel-hold"):
                self.remove()
        self.assertEqual(self.commands, [])
        self.assertFalse(any(row["operation"] == "fence-remove" for row in self.store.read(self.lease)["effects"].values()))
        with self.observations() as (_, cgroup):
            cgroup.side_effect = PermissionError("unknown-cgroup")
            with self.assertRaises(fence.KernelHold):
                self.remove()
        self.assertEqual(self.commands, [])

    def test_missing_original_exit_or_verified_stop_never_reaches_kernel_drain(self):
        record = self.store.read(self.lease)
        start = next(row for row in record["effects"].values() if row["operation"] == "engine-start")
        start.pop("engine_exit")
        with self.assertRaises(Denied):
            fence._engine_drained(self.owner, record)
        record = self.store.read(self.lease)
        record["effects"] = {key: row for key, row in record["effects"].items() if row["operation"] != "engine-stop"}
        with self.assertRaises(Denied):
            fence._engine_drained(self.owner, record)

    def test_host_namespace_change_after_possible_removal_is_unknown_not_verified(self):
        host = fence._host_namespace()
        with self.observations(), mock.patch.object(fence, "_host_namespace",
                side_effect=[host, host, host, (host[0], host[1] + 1)]):
            with self.assertRaises(fence.FenceUnknown):
                self.remove()
        removal = [row for row in self.store.read(self.lease)["effects"].values() if row["operation"] == "fence-remove"]
        self.assertEqual([row["state"] for row in removal], ["unknown"])

    def test_lost_kernel_reply_is_unknown_and_never_replayed(self):
        with self.observations(fail_command=1):
            with self.assertRaisesRegex(fence.FenceUnknown, "fence-effect-unknown"):
                self.remove()
        count = len(self.commands)
        with self.observations():
            with self.assertRaises(fence.KernelHold):
                self.remove()
        self.assertEqual(len(self.commands), count)
        removal = [row for row in self.store.read(self.lease)["effects"].values() if row["operation"] == "fence-remove"]
        self.assertEqual([row["state"] for row in removal], ["unknown"])

    def test_foreign_owner_or_namespace_identity_cannot_begin_removal(self):
        forged = replace(self.owner, cell_sha256="0" * 64)
        with self.observations():
            with self.assertRaises(fence.KernelHold):
                fence.remove(str(self.path), self.sha, forged, self.store, self.worker, self.config)
            with mock.patch.object(fence, "_host_namespace", return_value=(self.metadata["netns_device"], self.metadata["netns_inode"])):
                with self.assertRaises(fence.KernelHold):
                    self.remove()
        self.assertEqual(self.commands, [])

    def test_real_proc_observer_rejects_a_namespace_with_current_live_tasks(self):
        fd = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as current:
                cookie = fence._socket_cookie(current.fileno())
            with self.assertRaises((Denied, OSError)):
                fence._namespace_refs_drained(fd, info, cookie)
        finally:
            os.close(fd)

    def test_real_regular_alias_file_is_not_a_removal_namespace_witness(self):
        real_open = fence.installation._open_directory
        with mock.patch.object(fence.installation, "_open_directory", side_effect=lambda path:
                real_open(str(self.aliases) if path == "/run/netns" else path)):
            with self.assertRaisesRegex(Denied, "fence-removal-namespace"):
                with fence._removal_witness(self.fence_owner):
                    self.fail("ordinary Root file cannot establish an NSFS cleanup witness")

    def test_real_fd_inventory_includes_actual_namespace_and_socket_without_consumption(self):
        namespace = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
        directory = os.open("/proc/self/fd", fence.engine.DIR)
        first, second = socket.socketpair()
        try:
            observed = fence._fd_table(directory, time.monotonic() + 2)
            info = os.fstat(namespace)
            self.assertEqual(observed[namespace][:2], (info.st_dev, info.st_ino))
            self.assertEqual(observed[first.fileno()][2], stat.S_IFSOCK)
            self.assertIn(namespace, fence._fd_table(directory, time.monotonic() + 2))
            borrowed = fence._borrow_socket(os.getpid(), -1, first.fileno())
            os.close(borrowed)
            first.sendall(b"not consumed by observer")
            self.assertEqual(second.recv(64), b"not consumed by observer")
        finally:
            first.close()
            second.close()
            os.close(directory)
            os.close(namespace)


if __name__ == "__main__":
    unittest.main()
