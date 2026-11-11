#!/usr/bin/env python3
"""Read-only rootful namespace/veth discovery and bridge guard rendering.

No nft, link, persistence or service mutation is exposed by this program. Its
output needs the caller's complete transactional installation and lifecycle.
Container namespaces, including shared pod namespaces, are the trust unit.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Callable


PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in
                         ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
INTERFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}\Z")
CONTAINER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z")
CAPABILITY_KEYS = {"interface", "source_ipv4", "destination_ipv4", "port", "modes", "container_name"}
MODE = {"bootstrap", "hardened"}
NAMESPACE = re.compile(r"[0-9]+:[1-9][0-9]*\Z")


def require(condition: Any, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def private_address(value: Any) -> ipaddress.IPv4Address:
    require(isinstance(value, str), "IPv4 address must be text")
    address = ipaddress.IPv4Address(value)
    require(str(address) == value and any(address in network for network in PRIVATE_NETWORKS),
            "Address must be an exact RFC1918 IPv4 address")
    return address


def normalize_capability(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == CAPABILITY_KEYS, "Invalid SSH capability fields")
    require(isinstance(value["interface"], str) and INTERFACE.fullmatch(value["interface"]),
            "Invalid bridge interface")
    require(isinstance(value["container_name"], str) and CONTAINER.fullmatch(value["container_name"]),
            "Invalid rootful container name")
    require(isinstance(value["source_ipv4"], str), "Source must be one IPv4 /32")
    source = ipaddress.IPv4Network(value["source_ipv4"], strict=True)
    require(source.prefixlen == 32 and str(source) == value["source_ipv4"], "Source must be one exact IPv4 /32")
    private_address(str(source.network_address))
    destination = private_address(value["destination_ipv4"])
    require(destination != source.network_address, "Source and host gateway must differ")
    require(type(value["port"]) is int and value["port"] == 1905, "Only the declared regular SSH port is supported")
    modes = value["modes"]
    require(isinstance(modes, list) and modes and all(isinstance(item, str) for item in modes), "Invalid modes")
    require(len(set(modes)) == len(modes) and set(modes) <= MODE, "Invalid or duplicate modes")
    return {**value, "modes": sorted(modes)}


def one(values: list[Any], message: str) -> Any:
    require(len(values) == 1, message)
    return values[0]


def index(value: Any) -> int:
    require(type(value) is int and value > 0, "Invalid kernel interface index")
    return value


def validate_container(cap: dict[str, Any], container: dict[str, Any]) -> None:
    require(isinstance(container["id"], str) and re.fullmatch(r"[0-9a-f]{64}", container["id"]),
            "Invalid immutable rootful container identity")
    require(container["name"] == cap["container_name"] and container["running"] is True,
            "Container name/state differs")
    require(type(container["pid"]) is int and container["pid"] > 1, "Invalid namespace process")
    require(container["privileged"] is False and isinstance(container["network_mode"], str)
            and container["network_mode"] and container["network_mode"] != "host",
            "Privileged or host-network containers are not admissible")


def resolve_observation(capability: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any]:
    """Resolve one sanitized actual-kernel observation; no state is changed."""
    cap = normalize_capability(capability)
    container = observation["container"]
    validate_container(cap, container)
    require(all(isinstance(observation[key], str) and NAMESPACE.fullmatch(observation[key])
                for key in ("namespace", "host_namespace")), "Invalid observed kernel namespace identity")
    require(observation["namespace"] != observation["host_namespace"], "Host namespace is forbidden")
    bridge = one([row for row in observation["host_links"] if row["ifname"] == cap["interface"]],
                 "Bridge interface missing or ambiguous")
    bridge_index = index(bridge["ifindex"])
    require(bridge.get("linkinfo", {}).get("info_kind") == "bridge", "Expected an actual kernel bridge")
    gateway = one([address for row in observation["host_addresses"]
                   if row["ifindex"] == bridge_index and row["ifname"] == bridge["ifname"]
                   for address in row.get("addr_info", [])
                   if address.get("family") == "inet" and address.get("local") == cap["destination_ipv4"]],
                  "Destination is not the actual bridge gateway")
    require(type(gateway["prefixlen"]) is int and 1 <= gateway["prefixlen"] <= 30, "Invalid bridge prefix")
    source = ipaddress.IPv4Network(cap["source_ipv4"]).network_address
    network = ipaddress.IPv4Interface(cap["destination_ipv4"] + "/" + str(gateway["prefixlen"])).network
    require(source in network and source not in {network.network_address, network.broadcast_address},
            "Source is outside the observed bridge subnet")
    peer_addresses = [row for row in observation["peer_addresses"]
                      if any(address.get("family") == "inet" and address.get("local") == str(source)
                             for address in row.get("addr_info", []))]
    peer_address = one(peer_addresses, "Selected source missing or ambiguous in the selected namespace")
    peer = one([row for row in observation["peer_links"]
                if row["ifindex"] == peer_address["ifindex"] and row["ifname"] == peer_address["ifname"]],
               "Peer interface missing or ambiguous")
    peer_index = index(peer["ifindex"])
    host_index = index(peer["link_index"])
    host = one([row for row in observation["host_links"] if row["ifindex"] == host_index],
               "Host veth missing or ambiguous")
    require(host.get("linkinfo", {}).get("info_kind") == "veth" and index(host["link_index"]) == peer_index,
            "Both observed veth directions must agree")
    require(host.get("master") in (bridge_index, bridge["ifname"]), "Observed veth belongs to another bridge")
    require(isinstance(host["ifname"], str) and INTERFACE.fullmatch(host["ifname"]), "Invalid host veth name")
    require(isinstance(peer["ifname"], str) and INTERFACE.fullmatch(peer["ifname"]), "Invalid namespace veth name")
    return {**cap, "container_id": container["id"], "namespace_pid": container["pid"],
            "namespace": observation["namespace"], "bridge_ifindex": bridge_index,
            "host_ifindex": host_index, "host_ifname": host["ifname"],
            "peer_ifindex": peer_index, "peer_ifname": peer["ifname"]}


def stable_binding(capability: dict[str, Any], first: dict[str, Any], second: dict[str, Any]) -> dict[str, Any]:
    before = resolve_observation(capability, first)
    after = resolve_observation(capability, second)
    require(before == after, "Container, namespace, bridge or peer changed during discovery")
    return after


def trusted_binary(name: str) -> str:
    paths = {"podman": "/usr/bin/podman", "ip": "/usr/sbin/ip", "nsenter": "/usr/bin/nsenter"}
    path = Path(paths[name]).resolve(strict=True)
    require(stat.S_ISREG(path.stat().st_mode) and os.access(path, os.X_OK), "Trusted executable absent")
    for item in (path, *path.parents):
        status = item.stat()
        require(status.st_uid == 0 and not status.st_mode & 0o022, "Untrusted executable path")
    return str(path)


def read_command(arguments: list[str]) -> Any:
    completed = subprocess.run(arguments, capture_output=True, timeout=10, check=False,
                               env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C"})
    require(completed.returncode == 0 and len(completed.stdout) <= 2097152,
            "Bounded read-only container/network discovery failed")
    return json.loads(completed.stdout, object_pairs_hook=unique_object)


def namespace(pid: int | None = None) -> str:
    status = Path("/proc/self/ns/net" if pid is None else "/proc/" + str(pid) + "/ns/net").stat()
    return str(status.st_dev) + ":" + str(status.st_ino)


def observe(capability: dict[str, Any], reader: Callable[[list[str]], Any] = read_command) -> dict[str, Any]:
    cap = normalize_capability(capability)
    # Ask Podman only for public identity fields. Never read the raw inspect
    # body: its environment may contain application credentials.
    template = ('{"id":{{json .ID}},"name":{{json .Name}},"pid":{{json .State.Pid}},'
                '"running":{{json .State.Running}},"privileged":{{json .HostConfig.Privileged}},'
                '"network_mode":{{json .HostConfig.NetworkMode}}}')
    container = reader([trusted_binary("podman"), "--remote=false", "container", "inspect",
                        "--format", template, cap["container_name"]])
    require(isinstance(container, dict) and set(container) ==
            {"id", "name", "pid", "running", "privileged", "network_mode"}, "Unexpected inspect fields")
    require(isinstance(container["name"], str), "Invalid inspected name")
    container["name"] = container["name"].removeprefix("/")
    validate_container(cap, container)
    pid = container["pid"]
    host_namespace = namespace()
    peer_namespace = namespace(pid)
    require(peer_namespace != host_namespace, "Host network namespace is forbidden")
    ip = trusted_binary("ip")
    prefix = [trusted_binary("nsenter"), "--target", str(pid), "--net", "--", ip]
    value = {"container": container, "host_namespace": host_namespace, "namespace": peer_namespace,
             "host_links": reader([ip, "-j", "-d", "link", "show"]),
             "host_addresses": reader([ip, "-j", "address", "show"]),
             "peer_links": reader([*prefix, "-j", "-d", "link", "show"]),
             "peer_addresses": reader([*prefix, "-j", "address", "show"])}
    require(namespace(pid) == peer_namespace, "Namespace changed while reading kernel state")
    return value


def discover(capability: dict[str, Any]) -> dict[str, Any]:
    require(os.geteuid() == 0, "Rootful host discovery requires target root")
    return stable_binding(capability, observe(capability), observe(capability))


def render_guard(bindings: dict[str, dict[str, Any]], mode: str, table_name: str) -> str:
    require(mode in MODE and re.fullmatch(r"[a-z][a-z0-9_]{2,31}", table_name), "Invalid guard identity")
    lines = ["destroy table bridge " + table_name, "table bridge " + table_name + " {",
             "    chain input {", "        type filter hook input priority -200; policy accept;"]
    protected: set[tuple[str, str]] = set()
    for name, binding in sorted(bindings.items()):
        require(re.fullmatch(r"[a-z][a-z0-9_]{0,47}", name), "Invalid capability name")
        cap = normalize_capability({key: binding[key] for key in CAPABILITY_KEYS})
        if mode not in cap["modes"]:
            continue
        identity = (cap["interface"], cap["source_ipv4"])
        require(identity not in protected, "Conflicting source identity on one bridge")
        protected.add(identity)
        require(INTERFACE.fullmatch(binding["host_ifname"]), "Invalid observed host port")
        port = index(binding["host_ifindex"])
        bridge = "meta ibrname " + json.dumps(cap["interface"])
        ingress = "iifname " + json.dumps(binding["host_ifname"]) + " meta iif " + str(port)
        source = str(ipaddress.IPv4Network(cap["source_ipv4"]).network_address)
        for protocol, field in (("ip", "ip saddr"), ("arp", "arp saddr ip")):
            packet = "ether type " + protocol + " " + field + " " + source
            lines.append("        " + bridge + " " + ingress + " " + packet + " counter accept")
            lines.append("        " + bridge + " " + packet + " counter drop")
    return "\n".join([*lines, "    }", "}", ""])


def main() -> int:
    try:
        require(sys.argv[1:] == ["--discover"], "Only read-only discovery is supported")
        raw = sys.stdin.buffer.read(1048577)
        require(len(raw) <= 1048576, "Discovery input is too large")
        request = json.loads(raw, object_pairs_hook=unique_object)
        require(set(request) == {"capabilities", "mode", "table_name"}, "Invalid discovery request fields")
        require(isinstance(request["capabilities"], dict), "Capabilities must be a mapping")
        render_guard({}, request["mode"], request["table_name"])
        for name, capability in request["capabilities"].items():
            require(re.fullmatch(r"[a-z][a-z0-9_]{0,47}", name), "Invalid capability name")
            normalize_capability(capability)
        bindings = {name: discover(value) for name, value in request["capabilities"].items()
                    if request["mode"] in value["modes"]}
        guard = render_guard(bindings, request["mode"], request["table_name"])
        print(json.dumps({"schema": "lit.host_firewall.container-ssh-binding/v1", "bindings": bindings,
                          "guard": guard, "guard_sha256": hashlib.sha256(guard.encode()).hexdigest(),
                          "mutations": False, "transactional_installation_required": True}))
        return 0
    except Exception as error:
        print(json.dumps({"discovery_stopped": True, "error_type": type(error).__name__, "mutations": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
