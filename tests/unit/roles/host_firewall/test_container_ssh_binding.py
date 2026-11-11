from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location(
    "container_ssh_binding_under_test", ROOT / "roles/host_firewall/files/container_ssh_binding.py")
assert SPEC is not None and SPEC.loader is not None
binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binding)


def capability() -> dict:
    return {"interface": "br_fixture", "source_ipv4": "10.77.0.20/32",
            "destination_ipv4": "10.77.0.1", "port": 1905,
            "modes": ["hardened"], "container_name": "fixture-console"}


def observation() -> dict:
    return {
        "container": {"id": "a" * 64, "name": "fixture-console", "pid": 1234,
                      "running": True, "privileged": False, "network_mode": "bridge"},
        "namespace": "4:101", "host_namespace": "4:100",
        "host_links": [
            {"ifindex": 5, "ifname": "br_fixture", "linkinfo": {"info_kind": "bridge"}},
            {"ifindex": 10, "ifname": "veth_fixture", "link_index": 2, "master": "br_fixture",
             "linkinfo": {"info_kind": "veth"}}],
        "host_addresses": [{"ifindex": 5, "ifname": "br_fixture", "addr_info": [
            {"family": "inet", "local": "10.77.0.1", "prefixlen": 24}]}],
        "peer_links": [{"ifindex": 2, "ifname": "eth0", "link_index": 10}],
        "peer_addresses": [{"ifindex": 2, "ifname": "eth0", "addr_info": [
            {"family": "inet", "local": "10.77.0.20", "prefixlen": 24}]}],
    }


class ContainerSshBindingTests(unittest.TestCase):
    def resolve(self, value: dict) -> dict:
        return binding.resolve_observation(capability(), value)

    def test_binds_actual_namespace_bridge_and_both_veth_ends(self) -> None:
        value = self.resolve(observation())
        self.assertEqual((value["host_ifname"], value["host_ifindex"], value["peer_ifindex"]),
                         ("veth_fixture", 10, 2))
        self.assertEqual(value["namespace"], "4:101")
        self.assertEqual(value["container_id"], "a" * 64)

    def test_host_namespace_is_rejected(self) -> None:
        value = observation()
        value["namespace"] = value["host_namespace"]
        with self.assertRaises(ValueError):
            self.resolve(value)

    def test_namespace_identity_must_be_an_actual_device_inode_pair(self) -> None:
        for invalid in (None, "unknown", "4:0"):
            with self.subTest(namespace=invalid):
                value = observation()
                value["namespace"] = invalid
                with self.assertRaises(ValueError):
                    self.resolve(value)

    def test_privileged_and_host_network_container_are_rejected(self) -> None:
        for field, invalid in (("privileged", True), ("network_mode", "host")):
            with self.subTest(field=field):
                value = observation()
                value["container"][field] = invalid
                with self.assertRaises(ValueError):
                    self.resolve(value)

    def test_wrong_bridge_membership_is_rejected(self) -> None:
        value = observation()
        value["host_links"][1]["master"] = "another_bridge"
        with self.assertRaises(ValueError):
            self.resolve(value)

    def test_wrong_reverse_veth_link_is_rejected(self) -> None:
        value = observation()
        value["host_links"][1]["link_index"] = 9
        with self.assertRaises(ValueError):
            self.resolve(value)

    def test_non_bridge_and_non_veth_are_rejected(self) -> None:
        for item in (0, 1):
            with self.subTest(item=item):
                value = observation()
                value["host_links"][item]["linkinfo"]["info_kind"] = "dummy"
                with self.assertRaises(ValueError):
                    self.resolve(value)

    def test_gateway_must_be_observed_on_selected_bridge(self) -> None:
        value = observation()
        value["host_addresses"][0]["addr_info"][0]["local"] = "10.77.0.99"
        with self.assertRaises(ValueError):
            self.resolve(value)

    def test_source_must_exist_once_in_selected_namespace(self) -> None:
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                value = observation()
                if duplicate:
                    value["peer_addresses"].append(copy.deepcopy(value["peer_addresses"][0]))
                else:
                    value["peer_addresses"][0]["addr_info"][0]["local"] = "10.77.0.30"
                with self.assertRaises(ValueError):
                    self.resolve(value)

    def test_source_outside_bridge_subnet_is_rejected(self) -> None:
        cap = capability()
        cap["source_ipv4"] = "10.78.0.20/32"
        with self.assertRaises(ValueError):
            binding.resolve_observation(cap, observation())

    def test_stable_repeated_observations_return_identical_binding(self) -> None:
        first = observation()
        second = copy.deepcopy(first)
        self.assertEqual(binding.stable_binding(capability(), first, second), self.resolve(first))

    def test_container_or_pid_race_stops_before_render(self) -> None:
        for field, value in (("id", "b" * 64), ("pid", 5678)):
            with self.subTest(field=field):
                second = observation()
                second["container"][field] = value
                with self.assertRaises(ValueError):
                    binding.stable_binding(capability(), observation(), second)

    def test_host_port_recreation_requires_new_binding(self) -> None:
        second = observation()
        second["host_links"][1].update(ifindex=11, ifname="veth_new")
        second["peer_links"][0]["link_index"] = 11
        with self.assertRaises(ValueError):
            binding.stable_binding(capability(), observation(), second)

    def test_missing_container_identity_is_not_ignored(self) -> None:
        value = capability()
        del value["container_name"]
        with self.assertRaises(ValueError):
            binding.normalize_capability(value)

    def test_invalid_ports_names_modes_and_source_ranges_are_rejected(self) -> None:
        for field, value in (("port", 22), ("port", True), ("interface", 'br"; accept'),
                             ("container_name", "--remote"), ("modes", ["hardened", "hardened"]),
                             ("source_ipv4", "10.77.0.0/24"), ("source_ipv4", "127.0.0.1/32"),
                             ("source_ipv4", "::1/128")):
            with self.subTest(field=field, value=value):
                cap = capability()
                cap[field] = value
                with self.assertRaises(ValueError):
                    binding.normalize_capability(cap)

    def test_guard_binds_bridge_port_name_and_index_for_ip_and_arp(self) -> None:
        value = self.resolve(observation())
        guard = binding.render_guard({"console": value}, "hardened", "fixture_guard")
        self.assertIn('meta ibrname "br_fixture" iifname "veth_fixture" meta iif 10', guard)
        self.assertIn("ether type ip ip saddr 10.77.0.20 counter drop", guard)
        self.assertIn("ether type arp arp saddr ip 10.77.0.20 counter drop", guard)
        self.assertNotIn("tcp dport", guard)

    def test_inactive_capability_does_not_implicitly_grant_ssh(self) -> None:
        guard = binding.render_guard({"console": self.resolve(observation())}, "bootstrap", "fixture_guard")
        self.assertNotIn("10.77.0.20", guard)

    def test_conflicting_bridge_source_identity_is_rejected(self) -> None:
        value = self.resolve(observation())
        with self.assertRaises(ValueError):
            binding.render_guard({"console": value, "another": copy.deepcopy(value)},
                                 "hardened", "fixture_guard")

    def test_failed_inspect_cannot_leak_environment_or_stderr(self) -> None:
        result = subprocess.CompletedProcess(["podman"], 1,
                                             b'{"Env":["UNIT_PRIVATE_VALUE"]}', b"UNIT_PRIVATE_VALUE")
        with mock.patch.object(binding.subprocess, "run", return_value=result):
            with self.assertRaises(ValueError) as error:
                binding.read_command(["/usr/bin/podman", "inspect", "fixture-console"])
        self.assertNotIn("UNIT_PRIVATE_VALUE", str(error.exception))

    def test_successful_observation_returns_no_raw_inspect_environment(self) -> None:
        fixture = observation()
        values = [copy.deepcopy(fixture["container"]), fixture["host_links"], fixture["host_addresses"],
                  fixture["peer_links"], fixture["peer_addresses"]]
        reader = mock.Mock(side_effect=values)
        with mock.patch.object(binding, "trusted_binary", side_effect=lambda name: "/usr/bin/" + name), \
             mock.patch.object(binding, "namespace", side_effect=["4:100", "4:101", "4:101"]):
            result = binding.observe(capability(), reader)
        self.assertEqual(result, fixture)
        inspect_arguments = reader.call_args_list[0].args[0]
        self.assertIn("--format", inspect_arguments)
        self.assertNotIn("Config.Env", str(inspect_arguments))
        self.assertNotIn("Env", json.dumps(result))

    def test_unexpected_raw_inspect_fields_stop_without_returning_private_data(self) -> None:
        value = copy.deepcopy(observation()["container"])
        value["Config"] = {"Env": ["UNIT_PRIVATE_VALUE"]}
        with mock.patch.object(binding, "trusted_binary", return_value="/usr/bin/podman"):
            with self.assertRaises(ValueError) as error:
                binding.observe(capability(), mock.Mock(return_value=value))
        self.assertNotIn("UNIT_PRIVATE_VALUE", str(error.exception))


if __name__ == "__main__":
    unittest.main()
