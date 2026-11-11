"""Root-only, deny-first private Incus API network namespace component.

This is NOT a platform activation gate. It supports one same-host private IPv4
API endpoint only. Legacy controller-delegated guest HTTP, DNS/image downloads,
IPv6, host/guest/Unix-socket bypass prevention, accepted watchdog and backend
stream destruction require separate measured platform policy. No steady
conntrack accept bypasses the timed set. Packet traffic cannot renew the set.

Caller MUST hold preparation.preparation_lock across fresh native-job admission,
Ledger refresh, context publication and renewal. These functions journal their
own effects, never retry, adopt, roll back, or repair UNKNOWN kernel effects.
Package/daemon provenance, custody and the entire platform contract remain
prerequisites of the future Root factory; version readback is not provenance.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import ctypes
import datetime as dt
import fcntl
import ipaddress
import os
import platform
from pathlib import PurePosixPath
import re
import select
import selectors
import subprocess
import signal
import socket
import stat
import struct
import time

from . import (cell_contract, engine_policy as engine, identity, incus_admin,
               installation, kernel, ledger, preparation, signed_context)
from .identity import Denied, require

# Native canonical Root-owned regular binary; /usr/sbin/ip and /bin are aliases.
# Policy accepts this exact path only; do not resolve aliases at runtime.
IP = "/usr/bin/ip"
NFT = "/usr/sbin/nft"
NSFS_MAGIC = 0x6e736673
NS_GET_NSTYPE = 0xb703
CLONE_NEWNET = 0x40000000
LIMIT = 1024 * 1024
EXTENSIONS = frozenset({"projects", "projects_limits", "certificate_project", "virtual-machines"})


class FenceUnknown(Denied):
    """A retained intent/possible kernel effect requires Root reconciliation."""


class KernelHold(Denied):
    """Native ownership/drain is uncertain; no deletion authority follows."""


@dataclass(frozen=True)
class _Policy:
    path: str
    sha256: str
    backend: str
    port: int
    host: str
    peer: str
    tools: tuple


@dataclass(frozen=True)
class FenceReceipt:
    lease_id: str
    operation: str
    evidence_sha256: str
    # No credentials, request bodies or runtime/Heavy acceptance.


def _root():
    require(os.geteuid() == 0, "fence-root-required")


def _policy(path, expected):
    _root()
    proof, raw, _ = installation._file(engine._path(path), 8192, private=True, keep=True)
    require(proof.sha256 == engine._hash(expected), "fence-policy-drift")
    value = identity.decode_json(raw)
    engine._keys(value, {"schema", "backend_ipv4", "backend_port", "host_address", "namespace_address", "tools"})
    require(type(value["schema"]) is int and value["schema"] == 1, "fence-policy-schema")
    backend = ipaddress.IPv4Address(value["backend_ipv4"])
    require(str(backend) == value["backend_ipv4"] and backend.is_private and not backend.is_loopback
            and not backend.is_link_local and not backend.is_multicast and not backend.is_unspecified,
            "fence-private-backend")
    port = engine._integer(value["backend_port"], 1, 65535)
    host, peer = (ipaddress.IPv4Interface(value[k]) for k in ("host_address", "namespace_address"))
    require(str(host) == value["host_address"] and str(peer) == value["namespace_address"]
            and host.network == peer.network and host.network.prefixlen == 30 and host.ip != peer.ip
            and host.ip in host.network.hosts() and peer.ip in peer.network.hosts()
            and host.ip.is_private and peer.ip.is_private and backend not in host.network,
            "fence-private-link")
    tools = engine._keys(value["tools"], {IP, NFT})
    for digest in tools.values():
        engine._hash(digest)
    return _Policy(path, expected, str(backend), port, str(host), str(peer), tuple(sorted(tools.items())))


def _bound_policy(path, expected, config):
    require(type(config) is preparation.RootConfiguration
            and path == config.network_fence_policy_path and expected == config.network_fence_policy_sha256,
            "fence-root-policy-binding")
    return _policy(path, expected)


def _names(prepared):
    require(type(prepared) in {cell_contract.PreparedCell, cell_contract.OwnedFenceForCleanup}
            and ledger.ID.fullmatch(prepared.lease_id), "fence-cell")
    lease = prepared.lease_id
    return "lit-lease-" + lease, "lth" + lease[:12], "ltp" + lease[:12], "lit_lease_" + lease


def _alias(prepared):
    return "lit-lease:" + prepared.lease_id + ":" + prepared.cell_sha256


@contextmanager
def _namespace(prepared):
    name = _names(prepared)[0]
    parent = installation._open_directory("/run/netns")
    fd = None
    try:
        fd = os.open(name, installation.FILE_FLAGS, dir_fd=parent)
        before = os.fstat(fd)
        buffer = ctypes.create_string_buffer(256)
        require(before.st_uid == 0 and not before.st_mode & 0o022
                and ctypes.CDLL(None, use_errno=True).fstatfs(fd, buffer) == 0
                and ctypes.c_long.from_buffer(buffer).value == NSFS_MAGIC
                and fcntl.ioctl(fd, NS_GET_NSTYPE) == CLONE_NEWNET, "fence-real-namespace-required")
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require((named.st_dev, named.st_ino) == (before.st_dev, before.st_ino), "fence-namespace-drift")
        yield fd, before
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require((named.st_dev, named.st_ino) == (before.st_dev, before.st_ino), "fence-namespace-drift")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _run(policy, program, argv, *, payload=None):
    """Internal fixed argv only; sealed FD execution, bounded time and output.

    No public reader/runner injection, shell, environment inheritance, retries,
    arbitrary program or namespace-enter operation is exposed.
    """
    _root()
    require(program in {IP, NFT}, "fence-tool")
    require(payload is None or type(payload) is bytes and len(payload) <= 16384, "fence-command-input")
    opened, proc = [], None
    try:
        for path, digest in policy.tools:
            parent = installation._open_directory(str(PurePosixPath(path).parent))
            try:
                fd = os.open(PurePosixPath(path).name, installation.FILE_FLAGS, dir_fd=parent)
            finally:
                os.close(parent)
            opened.append((path, fd))
            proof, _, _ = installation._hash_file(fd, path, 64 * 1024 ** 2)
            require(proof.sha256 == digest and os.fstat(fd).st_mode & 0o111, "fence-tool-drift")
        fds = dict(opened)
        arguments = list(argv)
        # Namespace nft invocation enters only the Root-derived namespace.
        if program == IP and len(arguments) >= 4 and arguments[:2] == ["netns", "exec"]:
            require(arguments[3] == NFT, "fence-namespace-command")
            arguments[3] = "/proc/self/fd/" + str(fds[NFT])
        proc = subprocess.Popen(["/proc/self/fd/" + str(fds[program]), *arguments],
                                executable="/proc/self/fd/" + str(fds[program]),
                                stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, pass_fds=tuple(fds.values()),
                                close_fds=True, env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C", "TZ": "UTC"}, umask=0o077)
        result, offset, deadline = bytearray(), 0, time.monotonic() + 5
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            if payload is not None:
                os.set_blocking(proc.stdin.fileno(), False)
                selector.register(proc.stdin, selectors.EVENT_WRITE)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "fence-command-timeout")
                events = selector.select(remaining)
                require(events, "fence-command-timeout")
                for key, _ in events:
                    if key.fileobj is proc.stdin:
                        offset += os.write(proc.stdin.fileno(), payload[offset:])
                        if offset == len(payload):
                            selector.unregister(proc.stdin)
                            proc.stdin.close()
                    else:
                        chunk = os.read(proc.stdout.fileno(), 65536)
                        if not chunk:
                            selector.unregister(proc.stdout)
                        else:
                            result.extend(chunk)
                            require(len(result) <= LIMIT, "fence-command-output-limit")
        require(proc.wait(timeout=max(0.001, deadline - time.monotonic())) == 0, "fence-command-failed")
        require(time.monotonic() <= deadline, "fence-command-timeout")
        for path, fd in opened:
            os.lseek(fd, 0, os.SEEK_SET)
            proof, _, _ = installation._hash_file(fd, path, 64 * 1024 ** 2)
            current = installation.trusted_file(path, max_bytes=64 * 1024 ** 2)
            require(proof == current and proof.sha256 == dict(policy.tools)[path], "fence-tool-drift")
        return bytes(result)
    except Exception:
        raise Denied("fence-command-denied") from None
    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.kill()  # Still-owned unreaped child only, never a discovered PID.
                proc.wait(timeout=2)
            proc.stdout.close()
            if proc.stdin is not None:
                proc.stdin.close()
        for _, fd in opened:
            os.close(fd)


def _ip(policy, *argv):
    return _array(_run(policy, IP, ["-j", *argv]))


def _array(raw):
    """Bounded iproute2 JSON array; retain duplicate/nonfinite rejection.

    identity.decode_json intentionally accepts only objects. Wrapping an array
    preserves its recursive strict parser without relaxing that shared API.
    The exact wrapper key inventory also rejects attempts to escape the array.
    """
    require(type(raw) is bytes and 0 < len(raw) <= LIMIT, "fence-ip-json-limit")
    try:
        value = identity.decode_json(b'{"rows":' + raw + b'}')
        require(set(value) == {"rows"} and type(value["rows"]) is list and len(value["rows"]) <= 8192
                and all(type(row) is dict for row in value["rows"]), "fence-ip-json-array")
        return value["rows"]
    except Exception:
        raise Denied("fence-ip-json-denied") from None


def _nft(policy, prepared, *argv, payload=None):
    return _run(policy, IP, ["netns", "exec", _names(prepared)[0], NFT, *argv], payload=payload)


def _match(left, right):
    return {"match": {"op": "==", "left": left, "right": right}}


def _expressions(policy, outgoing):
    field, port = ("daddr", "dport") if outgoing else ("saddr", "sport")
    return [
        [_match({"meta": {"key": "oifname" if outgoing else "iifname"}}, "lo"), {"accept": None}],
        [_match({"payload": {"protocol": "ip", "field": field}}, policy.backend),
         _match({"payload": {"protocol": "tcp", "field": port}}, policy.port),
         _match({"concat": [{"payload": {"protocol": "ip", "field": field}},
                             {"payload": {"protocol": "tcp", "field": port}}]}, "@admitted"), {"jump": {"target": "gate"}}],
        [{"counter": None}, {"drop": None}],
    ]


def _gate_expression(deadline):
    # Official nft(8) META EXPRESSION: integer time values are UNIX timestamps;
    # this is input syntax only. Actual nft1.0.9 JSON output remains a UTC date
    # string even with -T; _gate_deadline implements that measured profile.
    # https://netfilter.org/projects/nftables/manpage.html#lbAR
    require(type(deadline) is int and 0 <= deadline <= 4294967295, "fence-absolute-deadline")
    return [{"match": {"op": "<", "left": {"meta": {"key": "time"}}, "right": deadline}}, {"accept": None}]


def _gate_deadline(raw):
    """Measured nft1.0.9/TZ=UTC JSON profile; no alternate unit/TZ guessing.

    Native absolute-time2 proved this exact string and millisecond set timers.
    Integer JSON output has NOT been qualified and is deliberately rejected.
    Host wall-clock trust remains an independent mandatory platform condition.
    """
    require(type(raw) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}", raw),
            "fence-absolute-utc-format")
    try:
        parsed = dt.datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
        deadline = int(parsed.timestamp())
        require(0 <= deadline <= 4294967295 and parsed.strftime("%Y-%m-%d %H:%M:%S") == raw,
                "fence-absolute-utc-range")
        return deadline
    except (ValueError, OverflowError, OSError):
        raise Denied("fence-absolute-utc-denied") from None


def _rules(policy, prepared, deadline=0):
    """Deterministic nft JSON transaction; new table, empty timeout set."""
    table = _names(prepared)[3]
    base = {"family": "inet", "table": table}
    objects = [{"table": {"family": "inet", "name": table, "comment": _alias(prepared)}},
               {"set": {**base, "name": "admitted", "type": ["ipv4_addr", "inet_service"], "flags": ["timeout"]}},
               {"chain": {**base, "name": "gate"}},
               {"rule": {**base, "chain": "gate", "expr": _gate_expression(deadline)}}]
    for chain in ("output", "input"):
        objects.append({"chain": {**base, "name": chain, "type": "filter", "hook": chain,
                                    "prio": -300, "policy": "drop"}})
        objects.extend({"rule": {**base, "chain": chain, "expr": expr}}
                       for expr in _expressions(policy, chain == "output"))
    return {"nftables": [{"add": obj} for obj in objects]}


def _rules_readback(policy, prepared, *, maximum_ms=0, expected_deadline=None):
    """Strict namespace-wide semantic inventory; unknown schemas fail closed.

    nft1.0.9 JSON timers are integer seconds, floored on output. Check the
    conservative remaining-time upper bound before converting once to a
    lower-bound ms liveness value. No alternate unit/schema is guessed; the
    independently checked absolute per-packet deadline remains mandatory.
    """
    data = identity.decode_json(_nft(policy, prepared, "-j", "-T", "list", "ruleset"))
    require(type(data) is dict and set(data) == {"nftables"} and type(data["nftables"]) is list,
            "fence-nft-schema")
    observed, table_handle, gate_handle, actual_deadline, expires = [], None, None, None, 0
    for row in data["nftables"]:
        require(type(row) is dict and len(row) == 1, "fence-nft-schema")
        kind = next(iter(row))
        if kind == "metainfo":
            continue
        require(kind in {"table", "set", "chain", "rule"} and type(row[kind]) is dict, "fence-extra-nft-object")
        value = dict(row[kind])
        handle = value.pop("handle", None)
        require(type(handle) is int and handle > 0, "fence-nft-handle")
        if kind == "table":
            require(table_handle is None, "fence-extra-nft-table")
            table_handle = handle
        if kind == "set":
            elements = value.pop("elem", [])
            require(type(elements) is list and len(elements) <= 1, "fence-extra-nft-element")
            if elements:
                require(maximum_ms > 0 and type(elements[0]) is dict and set(elements[0]) == {"elem"},
                        "fence-unexpected-allow")
                element = elements[0]["elem"]
                require(type(element) is dict and set(element) == {"val", "timeout", "expires"}
                        and element["val"] == {"concat": [policy.backend, policy.port]}
                        and type(element["timeout"]) is int and type(element["expires"]) is int
                        and 0 < element["expires"] <= element["timeout"] <= 5400
                        and type(maximum_ms) is int and (element["expires"] + 1) * 1000 <= maximum_ms,
                        "fence-timer-bound")
                expires = element["expires"] * 1000
        if kind == "rule":
            expressions = value.get("expr")
            require(type(expressions) is list, "fence-nft-rule")
            expressions = [dict(expr) for expr in expressions]
            for expr in expressions:
                if "counter" in expr:
                    counter = expr["counter"]
                    require(type(counter) is dict and set(counter) == {"packets", "bytes"}
                            and all(type(v) is int and v >= 0 for v in counter.values()), "fence-nft-counter")
                    expr["counter"] = None
            value["expr"] = expressions
            if value.get("chain") == "gate":
                require(gate_handle is None and len(expressions) == 2 and type(expressions[0]) is dict
                        and set(expressions[0]) == {"match"}, "fence-absolute-gate-schema")
                actual_deadline = _gate_deadline(expressions[0]["match"].get("right"))
                expressions[0] = {"match": {**expressions[0]["match"], "right": actual_deadline}}
                value["expr"] = expressions
                require(expressions == _gate_expression(actual_deadline), "fence-absolute-gate-drift")
                gate_handle = handle
        observed.append({kind: value})
    require(gate_handle is not None and (expected_deadline is None or actual_deadline == expected_deadline),
            "fence-absolute-gate-deadline")
    expected = [row["add"] for row in _rules(policy, prepared, actual_deadline)["nftables"]]
    # nft groups objects by type rather than insertion order. Rule order within
    # each chain IS security-sensitive and is compared unchanged.
    for kind in ("table", "set", "chain"):
        actual = [row for row in observed if kind in row]
        wanted = [row for row in expected if kind in row]
        require(sorted(actual, key=ledger.canonical) == sorted(wanted, key=ledger.canonical), "fence-nft-policy-drift")
    for chain in ("input", "output", "gate"):
        require([row for row in observed if "rule" in row and row["rule"].get("chain") == chain]
                == [row for row in expected if "rule" in row and row["rule"]["chain"] == chain],
                "fence-nft-rule-drift")
    require(len(observed) == len(expected), "fence-extra-nft-rule")
    return table_handle, expires, gate_handle, actual_deadline


def _worker(record, worker):
    require(type(worker) is ledger.Worker and record["worker"] == asdict(worker), "fence-worker-binding")
    worker.validate()
    observed = kernel.read_process(worker.pid)
    require(kernel.read_boot_id() == worker.boot_id and observed.stat.start_ticks == worker.start_ticks
            and observed.uids == (worker.uid,) * 4 and observed.stat.state not in {"Z", "X", "x"},
            "fence-worker-not-live")


def _fresh(prepared, store, worker, config, *, live=True):
    _root()
    require(type(prepared) in ({cell_contract.PreparedCell} if live else
                              {cell_contract.PreparedCell, cell_contract.OwnedFenceForCleanup})
            and type(store) is ledger.Ledger and store.owner_uid == 0
            and type(config) is preparation.RootConfiguration, "fence-root-inputs")
    require(preparation._config(config.path, config.sha256)[0] == config, "fence-root-config-drift")
    record = store.read(prepared.lease_id)
    require(record["cell_sha256"] == prepared.cell_sha256 and record["expires_at"] == prepared.expires_at
            and prepared.registry.path == config.registry_path and prepared.registry.sha256 == config.registry_sha256,
            "fence-cell-binding")
    if live:
        require(cell_contract.prepare_cell(prepared.registry, prepared.selector, store, prepared.lease_id) == prepared,
                "fence-cell-drift")
        _worker(record, worker)
    else:
        require(type(worker) is ledger.Worker and record["worker"] == asdict(worker), "fence-worker-binding")
        worker.validate()
        owner = cell_contract.owned_fence_for_cleanup(prepared.registry, prepared.selector, store, prepared.lease_id)
        if type(prepared) is cell_contract.OwnedFenceForCleanup:
            require(owner == prepared, "fence-cleanup-owner-drift")
        else:
            require(owner.cell_sha256 == prepared.cell_sha256 and owner.expires_at == prepared.expires_at,
                    "fence-cleanup-owner-drift")
    return record


def _signed(prepared, store, worker, config):
    descriptor = identity.decode_json(prepared.engine_descriptor_bytes)
    cell, _, _ = cell_contract._sealed(prepared.registry.select(prepared.selector).cell_config_path, prepared.cell_sha256)
    selected = prepared.registry.select(prepared.selector)
    context = descriptor["context_path"]
    _, raw, _ = installation._file(context + "/binding.json", 32768, private=True, keep=True)
    binding = identity.decode_json(raw)
    record = store.read(prepared.lease_id)
    starts = [effect for effect in record["effects"].values() if effect["operation"] == "engine-start"]
    require(len(starts) <= 1, "fence-engine-start-ambiguous")
    if starts:
        start = starts[0]
        require(start["state"] == "verified" and start["target"] == "engine:lit-lease-" + prepared.lease_id
                and "engine_process" in start and "engine_container_id" in start
                and not any(effect["operation"] == "engine-stop" for effect in record["effects"].values()),
                "fence-engine-start-unverified")
        pieces = binding["admission"].split(".")
        require(len(pieces) == 3, "fence-context-token-shape")
        # This claim is ONLY a bounded lookup candidate. It authorizes nothing:
        # the sealed retained manifest and all immutable inputs are revalidated,
        # then full independent JWS verification authenticates this exact digest
        # against the current Ledger authorization before renewal can journal.
        claimed = identity.decode_json(identity.unbase(pieces[1]))["engine_policy_sha256"]
        manifest = engine.validate_retained_policy(prepared.engine_descriptor_path,
                                                   prepared.engine_descriptor_sha256, engine._hash(claimed))
    else:
        manifest = engine.compile_engine_policy(prepared.engine_descriptor_path, prepared.engine_descriptor_sha256)
    policy = signed_context.ContextPolicy(selected.identity, prepared.incus["server"], prepared.incus["project"],
        prepared.expires_at, prepared.cell_sha256, selected.custody_policy_sha256,
        cell["controller"]["archive_sha256"], manifest.image_index_sha256, manifest.sha256,
        expected_runtime=ledger.canonical(signed_context.runtime_for_cell(prepared)))
    signed_context.verify(binding["admission"], config.signing_public_key, store, prepared.lease_id, worker,
                          policy, binding, context)
    require([effect for effect in store.read(prepared.lease_id)["effects"].values()
             if effect["operation"] in {"engine-start", "engine-stop"}]
            == [effect for effect in record["effects"].values()
                if effect["operation"] in {"engine-start", "engine-stop"}], "fence-engine-journal-drift")


def _backend(policy, prepared, config):
    target = prepared.incus
    client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path, target["project"],
                        target["network"], "default", target["pool"], ()))
    incus_admin.qualify_backend(client.server(), expected_version="7.6", expected_extensions=EXTENSIONS)
    addresses = _ip(policy, "-4", "address", "show", "to", policy.backend + "/32")
    require(type(addresses) is list and any(type(row) is dict and any(
        item.get("local") == policy.backend and item.get("family") == "inet"
        for item in row.get("addr_info", [])) for row in addresses), "fence-backend-not-local")


def _links(policy, prepared):
    namespace, host, peer, _ = _names(prepared)
    rows = _ip(policy, "-d", "link", "show", "dev", host)
    inner = _array(_run(policy, IP, ["-n", namespace, "-j", "-d", "link", "show", "dev", peer]))
    require(type(rows) is list and len(rows) == 1 and type(inner) is list and len(inner) == 1, "fence-veth-inventory")
    left, right = rows[0], inner[0]
    for item, name in ((left, host), (right, peer)):
        require(item["ifname"] == name and item.get("ifalias") == _alias(prepared)
                and item.get("linkinfo", {}).get("info_kind") == "veth" and "UP" in item["flags"]
                and type(item["ifindex"]) is int and item["ifindex"] > 0, "fence-veth-ownership")
    require(left.get("link_index") == right["ifindex"] and right.get("link_index") == left["ifindex"],
            "fence-veth-pair")
    for name, address, prefix in ((host, policy.host, []), (peer, policy.peer, ["-n", namespace])):
        values = _array(_run(policy, IP, [*prefix, "-j", "address", "show", "dev", name]))
        interface = ipaddress.IPv4Interface(address)
        require(type(values) is list and len(values) == 1 and values[0].get("addr_info") == [{
            "family": "inet", "local": str(interface.ip), "prefixlen": 30, "broadcast": str(interface.network.broadcast_address),
            "scope": "global", "label": name, "valid_life_time": 4294967295, "preferred_life_time": 4294967295}],
            "fence-address-policy")
    routes = _array(_run(policy, IP, ["-n", namespace, "-j", "-4", "route", "show", "table", "main"]))
    require(type(routes) is list and len(routes) == 2, "fence-route-policy")
    expected_routes = [{"dst": policy.backend, "gateway": str(ipaddress.IPv4Interface(policy.host).ip),
                        "dev": peer, "flags": []},
                       {"dst": str(ipaddress.IPv4Interface(policy.peer).network), "dev": peer, "protocol": "kernel",
                        "scope": "link", "prefsrc": str(ipaddress.IPv4Interface(policy.peer).ip), "flags": []}]
    require(sorted(routes, key=ledger.canonical) == sorted(expected_routes, key=ledger.canonical), "fence-route-policy")
    return left["ifindex"], right["ifindex"]


def _owned(policy, prepared, store, *, maximum_ms=0):
    record = store.read(prepared.lease_id)
    effects = [e for e in record["effects"].values() if e["operation"] == "fence-create" and e["state"] == "verified"]
    require(len(effects) == 1 and "fence" in effects[0], "fence-not-owned")
    metadata = effects[0]["fence"]
    require(metadata["policy_sha256"] == policy.sha256 and metadata["boot_id"] == kernel.read_boot_id(), "fence-ownership-drift")
    with _namespace(prepared) as (_, info):
        require((info.st_dev, info.st_ino) == (metadata["netns_device"], metadata["netns_inode"]), "fence-namespace-replaced")
        left, right = _links(policy, prepared)
        handle, expires, gate, deadline = _rules_readback(policy, prepared, maximum_ms=maximum_ms)
        require((left, right, handle) == (metadata["host_ifindex"], metadata["peer_ifindex"], metadata["nft_table_handle"]),
                "fence-kernel-ownership-drift")
    require(deadline <= prepared.expires_at, "fence-gate-after-hard-deadline")
    return metadata, expires, gate, deadline


def _unknown(store, prepared, effect):
    try:
        store.record(prepared.lease_id, effect, "unknown", evidence_sha256=ledger.digest({"component": "network-fence", "state": "unknown"}))
    except Exception:
        pass  # Intent/committed state is retained; never repair or retry.


def _transaction(store, prepared, operation, target, action):
    effect = store.begin(prepared.lease_id, operation, target)
    try:
        observed = action(effect)
        digest = ledger.digest(observed)
        store.record(prepared.lease_id, effect, "verified", evidence_sha256=digest)
        return FenceReceipt(prepared.lease_id, operation, digest)
    except Exception:
        _unknown(store, prepared, effect)
        raise FenceUnknown("fence-effect-unknown") from None


def create(root_policy_path, expected_sha256, prepared, store, worker, root_configuration):
    """Create an entirely new owned API-only namespace with NO API allow."""
    _root()
    policy = _bound_policy(root_policy_path, expected_sha256, root_configuration)
    _fresh(prepared, store, worker, root_configuration)
    _backend(policy, prepared, root_configuration)
    namespace, host, peer, _ = _names(prepared)
    parent = installation._open_directory("/run/netns")
    try:
        require(namespace not in os.listdir(parent), "fence-namespace-exists")
    finally:
        os.close(parent)
    links = _ip(policy, "link", "show")
    require(type(links) is list and not any(row.get("ifname") in {host, peer} for row in links), "fence-link-exists")
    addresses = _ip(policy, "-4", "address", "show")
    network = ipaddress.IPv4Interface(policy.host).network
    require(not any(ipaddress.IPv4Interface(str(a["local"]) + "/" + str(a["prefixlen"])).network.overlaps(network)
                    for row in addresses for a in row.get("addr_info", []) if a.get("family") == "inet"), "fence-link-subnet-overlap")

    def action(effect):
        # Never remove these after a failed command. Their names and any bound
        # kernel identity remain for explicit Root reconciliation.
        _run(policy, IP, ["netns", "add", namespace])
        with _namespace(prepared) as (_, info):
            _nft(policy, prepared, "-j", "-f", "-", payload=ledger.canonical(_rules(policy, prepared)))
            _run(policy, IP, ["link", "add", host, "type", "veth", "peer", "name", peer])
            _run(policy, IP, ["link", "set", host, "alias", _alias(prepared)])
            _run(policy, IP, ["link", "set", peer, "alias", _alias(prepared)])
            _run(policy, IP, ["link", "set", peer, "netns", namespace])
            _run(policy, IP, ["link", "set", "dev", host, "addrgenmode", "none"])
            _run(policy, IP, ["-n", namespace, "link", "set", "dev", peer, "addrgenmode", "none"])
            _run(policy, IP, ["address", "add", policy.host, "broadcast", "+", "dev", host])
            _run(policy, IP, ["-n", namespace, "address", "add", policy.peer, "broadcast", "+", "dev", peer])
            _run(policy, IP, ["-n", namespace, "route", "add", policy.backend + "/32", "via",
                              str(ipaddress.IPv4Interface(policy.host).ip), "dev", peer])
            _run(policy, IP, ["-n", namespace, "link", "set", "lo", "up"])
            _run(policy, IP, ["-n", namespace, "link", "set", peer, "up"])
            _run(policy, IP, ["link", "set", host, "up"])
            left, right = _links(policy, prepared)
            handle, expires, _, deadline = _rules_readback(policy, prepared, expected_deadline=0)
            require(expires == 0 and deadline == 0, "fence-create-not-denied")
            metadata = dict(policy_sha256=policy.sha256, boot_id=kernel.read_boot_id(), netns_device=info.st_dev,
                            netns_inode=info.st_ino, host_ifindex=left, peer_ifindex=right, nft_table_handle=handle)
            store.bind_fence(prepared.lease_id, effect, **metadata)
            from . import host_api_fence
            host_api_fence.bind_creator(root_configuration.host_api_fence_policy_path,
                root_configuration.host_api_fence_policy_sha256, prepared, store, worker, root_configuration, effect)
            _fresh(prepared, store, worker, root_configuration)
            require(_policy(root_policy_path, expected_sha256) == policy, "fence-policy-drift")
            return metadata
    return _transaction(store, prepared, "fence-create", "fence:" + prepared.lease_id, action)


def _remaining(record):
    deadline = min(record["expires_at"], record["authorizations"][-1]["valid_until"])
    # Whole seconds deliberately expire early. Never round a TTL upwards.
    seconds = int(deadline - time.time())
    require(0 < seconds <= 5400, "fence-authorization-expired")
    return deadline, seconds


def renew(root_policy_path, expected_sha256, prepared, store, worker, root_configuration):
    """Root fresh-auth + signed-context gate; no packet-driven TTL renewal."""
    _root()
    policy = _bound_policy(root_policy_path, expected_sha256, root_configuration)
    record = _fresh(prepared, store, worker, root_configuration)
    _signed(prepared, store, worker, root_configuration)
    deadline, _ = _remaining(record)
    _owned(policy, prepared, store, maximum_ms=5400000)
    target = "fence:" + prepared.lease_id + ":" + record["authorizations"][-1]["token_id_sha256"]

    def action(effect):
        latest = _fresh(prepared, store, worker, root_configuration)
        require(latest["authorizations"][-1] == record["authorizations"][-1], "fence-authorization-drift")
        _signed(prepared, store, worker, root_configuration)
        _, _, gate, _ = _owned(policy, prepared, store, maximum_ms=5400000)
        _, remaining = _remaining(latest)
        # Relative kernel timeout begins at netlink application, not at this
        # calculation. Reserve the five-second command bound plus one second;
        # the independent absolute per-packet guard is the final deadline cap.
        ttl = remaining - 6
        require(ttl > 0, "fence-authorization-budget-too-short")
        issued = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        table = _names(prepared)[3]
        # Explicit UNIX seconds: even a Root child delayed before applying this
        # transaction cannot accept a packet after the absolute auth deadline.
        # The guard applies to both directions, including established streams.
        raw = ("replace rule inet " + table + " gate handle " + str(gate) + " meta time < " + str(deadline)
               + " accept\nflush set inet " + table + " admitted\nadd element inet " + table + " admitted { "
               + policy.backend + " . " + str(policy.port) + " timeout " + str(ttl) + "s }\n").encode("ascii")
        _nft(policy, prepared, "-f", "-", payload=raw)
        _, expires, _, actual_deadline = _owned(policy, prepared, store, maximum_ms=ttl * 1000)
        require(expires > 0 and actual_deadline == deadline and time.time() < deadline, "fence-renewal-not-live")
        # Re-read observation time after the effect. Metadata uses a conservative
        # original boot bound, never the later observation plus a fresh TTL.
        metadata = dict(authorization_sha256=ledger.digest(record["authorizations"][-1]), allow_expires_at=deadline,
                        issued_boot_ns=issued, expires_boot_ns=issued + ttl * 1000000000)
        store.bind_fence_authorization(prepared.lease_id, effect, **metadata)
        from . import host_api_fence
        host_api_fence.grant(root_configuration.host_api_fence_policy_path,
            root_configuration.host_api_fence_policy_sha256, prepared, store, worker, root_configuration, effect)
        _fresh(prepared, store, worker, root_configuration)
        _signed(prepared, store, worker, root_configuration)
        require(_policy(root_policy_path, expected_sha256) == policy, "fence-policy-drift")
        return metadata
    return _transaction(store, prepared, "fence-renew", target, action)


def disable(root_policy_path, expected_sha256, prepared, store, worker, root_configuration):
    """Emergency exact-owned cut, allowed after expiry/cancel; not stream kill."""
    _root()
    policy = _bound_policy(root_policy_path, expected_sha256, root_configuration)
    _fresh(prepared, store, worker, root_configuration, live=False)

    def action(effect):
        from . import host_api_fence
        host_api_fence.withdraw(root_configuration.host_api_fence_policy_path,
            root_configuration.host_api_fence_policy_sha256, prepared, store, worker, root_configuration, effect)
        _owned(policy, prepared, store, maximum_ms=5400000)
        _nft(policy, prepared, "-f", "-", payload=("flush set inet " + _names(prepared)[3] + " admitted\n").encode("ascii"))
        _, expires, _, _ = _owned(policy, prepared, store)
        require(expires == 0, "fence-disable-not-empty")
        require(_policy(root_policy_path, expected_sha256) == policy, "fence-policy-drift")
        return {"lease_id": prepared.lease_id, "policy_sha256": policy.sha256, "admitted": 0}
    return _transaction(store, prepared, "fence-disable", "fence:" + prepared.lease_id, action)


def _cleanup_context(owner, store, worker, config):
    _root()
    require(type(owner) is cell_contract.OwnedCellForCleanup and type(store) is ledger.Ledger
            and store.owner_uid == 0 and type(config) is preparation.RootConfiguration, "fence-cleanup-inputs")
    require(preparation._config(config.path, config.sha256)[0] == config
            and owner.registry.path == config.registry_path and owner.registry.sha256 == config.registry_sha256
            and cell_contract.owned_cell_for_cleanup(owner.registry, owner.selector, store, owner.lease_id) == owner,
            "fence-cleanup-owner-drift")
    record = store.read(owner.lease_id)
    require(type(worker) is ledger.Worker and record["worker"] == asdict(worker), "fence-worker-binding")
    worker.validate()
    removed = [row for row in record["effects"].values() if row["operation"] == "fence-remove"]
    if removed:
        require(len(removed) == 1 and removed[0]["state"] == "verified"
                and removed[0]["target"] == "fence:" + owner.lease_id, "fence-removal-unresolved")
        # A removed namespace has no LIVE fence locator. The independently
        # rederived strong owner and original creator/removal receipts supply
        # read-only absence locators, never a namespace acquisition/grant.
        return None, record
    fence = cell_contract.owned_fence_for_cleanup(owner.registry, owner.selector, store, owner.lease_id)
    record = _fresh(fence, store, worker, config, live=False)
    return fence, record


def verify_disabled(owner, store, worker, config):
    """Read-only exact owned empty gate, including after raw context deletion."""
    _root()
    try:
        return _verify_disabled(owner, store, worker, config)
    except Exception:
        raise KernelHold("fence-kernel-hold") from None


def _verify_disabled(owner, store, worker, config):
    fence, record = _cleanup_context(owner, store, worker, config)
    policy = _bound_policy(config.network_fence_policy_path, config.network_fence_policy_sha256, config)
    from . import host_api_fence
    host_api_fence.verify_withdrawn(owner, store, worker, config)
    require(any(row["operation"] == "fence-disable" and row["target"] == "fence:" + owner.lease_id
                and row["state"] == "verified" for row in record["effects"].values()), "fence-disable-unverified")
    removed = [row for row in record["effects"].values() if row["operation"] == "fence-remove"]
    if removed:
        require(len(removed) == 1 and removed[0]["state"] == "verified", "fence-removal-unresolved")
        metadata = _removed_observed(policy, owner, record)
        return {"lease_id": owner.lease_id, "policy_sha256": policy.sha256,
                "ownership_sha256": ledger.digest(metadata), "admitted": 0}
    metadata, expires, _, _ = _owned(policy, fence, store)
    require(expires == 0, "fence-disable-not-empty")
    return {"lease_id": owner.lease_id, "policy_sha256": policy.sha256,
            "ownership_sha256": ledger.digest(metadata), "admitted": 0}


def _host_namespace():
    value = os.stat("/proc/self/ns/net")  # Intentional kernel namespace alias.
    return value.st_dev, value.st_ino


def _removed_observed(policy, owner, record):
    """Read back a KNOWN verified removal; never reconcile an unknown effect."""
    creators = [row for row in record["effects"].values()
                if row["operation"] == "fence-create" and row["state"] == "verified"]
    require(type(owner) is cell_contract.OwnedCellForCleanup and len(creators) == 1 and "fence" in creators[0]
            and creators[0]["target"] == "fence:" + owner.lease_id, "fence-not-owned")
    namespace, host_link = "lit-lease-" + owner.lease_id, "lth" + owner.lease_id[:12]
    metadata, host = creators[0]["fence"], _host_namespace()
    require(metadata["boot_id"] == kernel.read_boot_id() and metadata["policy_sha256"] == policy.sha256,
            "fence-ownership-drift")
    rows = _ip(policy, "link", "show")
    require(not any(row.get("ifname") == host_link or row.get("ifindex") == metadata["host_ifindex"]
                    for row in rows), "fence-veth-still-present")
    parent = installation._open_directory("/run/netns")
    try:
        require(namespace not in os.listdir(parent), "fence-alias-still-present")
    finally:
        os.close(parent)
    require(_host_namespace() == host, "fence-host-namespace-changed")
    return metadata


def _process_stat(fd, pid):
    value = kernel.worker.parse_proc_stat(kernel.bounded_file(fd, "stat", kernel.worker.MAX_STAT_BYTES))
    require(value.pid == pid, "fence-proc-identity")
    return value


def _engine_drained(owner, record):
    starts = [row for row in record["effects"].values() if row["operation"] == "engine-start"]
    require(len(starts) == 1 and starts[0]["state"] == "verified", "fence-engine-untracked")
    start = starts[0]
    ledger._validate_engine_exit(start.get("engine_exit"), start)
    require(start["engine_exit"]["manifest_sha256"] == owner.engine_policy_sha256
            and start["engine_process"]["boot_id"] == kernel.read_boot_id()
            and any(row["operation"] == "engine-stop" and row["target"] == start["target"]
                    and row["state"] == "verified" for row in record["effects"].values()), "fence-engine-stop-unverified")
    descriptor = identity.decode_json(owner.engine_descriptor_bytes)
    name = "lit-lease-" + owner.lease_id + ".slice"
    require(descriptor["cgroup_parent"] == name, "fence-cgroup-locator")
    path = "/sys/fs/cgroup/lit.slice/lit-lease.slice/" + name
    fd = installation._open_directory(path)
    try:
        info, capture = os.fstat(fd), start["engine_capture"]
        buffer = ctypes.create_string_buffer(256)
        require(ctypes.CDLL(None, use_errno=True).fstatfs(fd, buffer) == 0
                and ctypes.c_long.from_buffer(buffer).value == 0x63677270
                and info.st_uid == 0 and not info.st_mode & 0o022
                and (info.st_dev, info.st_ino) == (capture["cgroup_device"], capture["cgroup_inode"]),
                "fence-cgroup-replaced")
        rows = [line.split() for line in kernel.bounded_file(fd, "cgroup.events", 4096).splitlines()]
        require(all(len(row) == 2 for row in rows), "fence-cgroup-events")
        events = dict(rows)
        require(len(events) == len(rows) and set(events) == {b"populated", b"frozen"}
                and events[b"populated"] == b"0" and events[b"frozen"] in {b"0", b"1"}
                and not kernel.bounded_file(fd, "cgroup.procs", 65536).strip(), "fence-cgroup-populated")
        named = installation._open_directory(path)
        try:
            require((os.fstat(named).st_dev, os.fstat(named).st_ino) == (info.st_dev, info.st_ino), "fence-cgroup-replaced")
        finally:
            os.close(named)
    finally:
        os.close(fd)
    # A durable original-parent wait is required above. PID absence/reuse is
    # only a current no-longer-running observation, never reconstructed exit.
    process = start["engine_process"]
    try:
        pidfd = os.pidfd_open(process["pid"], 0)
    except ProcessLookupError:
        return
    fd = -1
    try:
        fd = os.open("/proc/" + str(process["pid"]), engine.DIR)
        observed = _process_stat(fd, process["pid"])
        require(observed.start_ticks != process["start_ticks"], "fence-supervisor-not-reaped")
        after = _process_stat(fd, process["pid"])
        require(observed.start_ticks == after.start_ticks and not select.select([pidfd], [], [], 0)[0],
                "fence-supervisor-observation-changed")
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(pidfd)


def _socket_cookie(fd):
    # Linux6.8 net/core/sock.c SO_NETNS_COOKIE returns sock_net(sk)->net_cookie.
    # https://github.com/torvalds/linux/blob/v6.8/net/core/sock.c#L1867
    duplicate = os.dup(fd)
    try:
        value, length = ctypes.c_uint64(), ctypes.c_uint32(8)
        require(ctypes.CDLL(None, use_errno=True).getsockopt(duplicate, socket.SOL_SOCKET, 71,
                ctypes.byref(value), ctypes.byref(length)) == 0 and length.value == 8 and value.value > 0,
                "fence-socket-cookie")
        return value.value
    finally:
        os.close(duplicate)


def _namespace_cookie(fd, info):
    """One bounded, single-thread Root child; parent NEVER calls setns."""
    require(len(os.listdir("/proc/self/task")) == 1, "fence-observer-single-thread")
    inherited = [int(name) for name in os.listdir("/proc/self/fd") if name.isascii() and name.isdecimal()]
    require(len(inherited) <= 65536, "fence-observer-fd-limit")
    reader, writer = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    parent, child, reaped = os.getpid(), None, False
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        child = os.fork()
        if child == 0:
            try:
                os.close(reader)
                require(libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == parent,
                        "fence-observer-parent")
                for selected in inherited:
                    if selected not in {fd, writer}:
                        try:
                            os.close(selected)  # Child-owned inherited copy only.
                        except OSError:
                            pass
                require(libc.setns(fd, CLONE_NEWNET) == 0, "fence-observer-setns")
                require(_host_namespace() == (info.st_dev, info.st_ino), "fence-observer-namespace")
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as witness:
                    raw = struct.pack("=Q", _socket_cookie(witness.fileno()))
                require(os.write(writer, raw) == 8, "fence-observer-write")
                os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(writer)
        writer = -1
        deadline, raw = time.monotonic() + 2, b""
        while time.monotonic() < deadline:
            if select.select([reader], [], [], max(0, deadline - time.monotonic()))[0]:
                part = os.read(reader, 9)
                raw += part
                require(len(raw) <= 8, "fence-observer-output")
            found, status = os.waitpid(child, os.WNOHANG)
            if found:
                reaped = True
                require(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and len(raw) == 8,
                        "fence-observer-failed")
                return struct.unpack("=Q", raw)[0]
        raise KernelHold("fence-kernel-hold")
    finally:
        for selected in (reader, writer):
            if selected >= 0:
                os.close(selected)
        if child and child > 0 and not reaped:
            os.kill(child, signal.SIGKILL)  # Still-owned unreaped child cannot be PID-reused.
            os.waitpid(child, 0)


def _fd_table(fd, deadline):
    values = {}
    os.lseek(fd, 0, os.SEEK_SET)
    with os.scandir(fd) as entries:
        for entry in entries:
            require(time.monotonic() < deadline and len(values) < 65536
                    and entry.name.isascii() and entry.name.isdecimal(), "fence-proc-bounds")
            info = entry.stat(follow_symlinks=True)  # Fixed /proc task FD kernel aliases only.
            values[int(entry.name)] = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
    return values


def _borrow_socket(pid, pidfd, number):
    if pid == os.getpid():
        return os.dup(number)
    require(platform.machine() in {"x86_64", "aarch64"}, "fence-pidfd-unsupported")
    # pidfd_getfd(2), syscall438 on these Linux ABIs. It duplicates, never
    # changes/closes the target's descriptor; PTRACE_REALCREDS permission needed.
    # https://github.com/torvalds/linux/blob/v6.8/kernel/pid.c#L628
    value = ctypes.CDLL(None, use_errno=True).syscall(438, pidfd, number, 0)
    require(value >= 0, "fence-pidfd-getfd")
    return value


def _namespace_refs_drained(witness_fd, info, cookie):
    """Bounded current proc references under the qualified private-EE boundary.

    No global refcount/anti-Root attestation: queued SCM_RIGHTS or io_uring
    registered files are not exposed by proc FD tables. Native private mounts,
    UID/AppArmor/IPC isolation must prevent such untrusted outside retention.
    Unknown proc/ptrace/cookie/thread-FD observations HOLD, never assume absence.
    """
    deadline, target, count = time.monotonic() + 10, (info.st_dev, info.st_ino), 0
    proc = os.open("/proc", engine.DIR)
    try:
        with os.scandir(proc) as processes:
            for entry in processes:
                if not entry.name.isascii() or not entry.name.isdecimal():
                    continue
                count += 1
                require(count <= 16384 and time.monotonic() < deadline, "fence-proc-bounds")
                pid = int(entry.name)
                process = os.open(entry.name, engine.DIR, dir_fd=proc)
                pidfd = tasks = leader_fd = -1
                try:
                    before = _process_stat(process, pid)
                    pidfd = os.pidfd_open(pid, 0)
                    tasks = os.open("task", engine.DIR, dir_fd=process)
                    tids = sorted(os.listdir(tasks))
                    require(0 < len(tids) <= 4096 and all(name.isascii() and name.isdecimal() for name in tids),
                            "fence-proc-tasks")
                    leader_fd = os.open("fd", engine.DIR, dir_fd=process)
                    original = _fd_table(leader_fd, deadline)
                    for tid in tids:
                        task = os.open(tid, engine.DIR, dir_fd=tasks)
                        thread_fds = -1
                        try:
                            task_before = _process_stat(task, int(tid))
                            namespace = os.stat("ns/net", dir_fd=task)
                            require((namespace.st_dev, namespace.st_ino) != target, "fence-namespace-task-live")
                            if int(tid) != pid:
                                thread_fds = os.open("fd", engine.DIR, dir_fd=task)
                                require(_fd_table(thread_fds, deadline) == original, "fence-thread-fd-divergence")
                                require(_fd_table(thread_fds, deadline) == original, "fence-thread-fd-divergence")
                            task_after = _process_stat(task, int(tid))
                            require((task_before.pid, task_before.start_ticks) == (task_after.pid, task_after.start_ticks),
                                    "fence-proc-task-changed")
                        finally:
                            if thread_fds >= 0:
                                os.close(thread_fds)
                            os.close(task)
                    for number, observed in original.items():
                        if observed[:2] == target:
                            require(pid == os.getpid() and number == witness_fd, "fence-namespace-fd-live")
                        if observed[2] == stat.S_IFSOCK:
                            borrowed = _borrow_socket(pid, pidfd, number)
                            try:
                                current = os.fstat(borrowed)
                                require((current.st_dev, current.st_ino, stat.S_IFMT(current.st_mode)) == observed
                                        and _socket_cookie(borrowed) != cookie, "fence-namespace-socket-live")
                            finally:
                                os.close(borrowed)
                    after = _process_stat(process, pid)
                    os.lseek(tasks, 0, os.SEEK_SET)
                    after_tids = sorted(os.listdir(tasks))
                    require((before.pid, before.start_ticks) == (after.pid, after.start_ticks)
                            and after_tids == tids and not select.select([pidfd], [], [], 0)[0],
                            "fence-proc-changed")
                    if pid != os.getpid():
                        require(_fd_table(leader_fd, deadline) == original, "fence-proc-fds-changed")
                finally:
                    for selected in (leader_fd, tasks, pidfd, process):
                        if selected >= 0:
                            os.close(selected)
    finally:
        os.close(proc)


@contextmanager
def _removal_witness(fence):
    # Normal _namespace deliberately checks the named alias after yielding.
    # Removal retains this independently acquired witness across alias deletion.
    parent = installation._open_directory("/run/netns")
    fd = -1
    try:
        fd = os.open(_names(fence)[0], installation.FILE_FLAGS, dir_fd=parent)
        info, buffer = os.fstat(fd), ctypes.create_string_buffer(256)
        named = os.stat(_names(fence)[0], dir_fd=parent, follow_symlinks=False)
        require(info.st_uid == 0 and not info.st_mode & 0o022
                and ctypes.CDLL(None, use_errno=True).fstatfs(fd, buffer) == 0
                and ctypes.c_long.from_buffer(buffer).value == NSFS_MAGIC
                and fcntl.ioctl(fd, NS_GET_NSTYPE) == CLONE_NEWNET
                and (named.st_dev, named.st_ino) == (info.st_dev, info.st_ino), "fence-removal-namespace")
        yield fd, info
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)


def remove(root_policy_path, expected_sha256, owner, store, worker, root_configuration):
    """One exact owned withdrawal after native drain; uncertainty is never retry."""
    _root()
    effect = None
    try:
        fence, record = _cleanup_context(owner, store, worker, root_configuration)
        policy = _bound_policy(root_policy_path, expected_sha256, root_configuration)
        previous = [row for row in record["effects"].values() if row["operation"] == "fence-remove"]
        if previous:
            require(len(previous) == 1 and previous[0]["state"] == "verified", "fence-removal-unresolved")
            verify_disabled(owner, store, worker, root_configuration)
            return FenceReceipt(owner.lease_id, "fence-remove", previous[0]["evidence_sha256"])
        verify_disabled(owner, store, worker, root_configuration)
        _engine_drained(owner, record)
        host = _host_namespace()
        with _removal_witness(fence) as (fd, info):
            metadata, _, _, _ = _owned(policy, fence, store)
            require((info.st_dev, info.st_ino) == (metadata["netns_device"], metadata["netns_inode"])
                    and host != (info.st_dev, info.st_ino), "fence-removal-ownership")
            cookie = _namespace_cookie(fd, info)
            for _ in range(2):
                _namespace_refs_drained(fd, info, cookie)
                require(_host_namespace() == host, "fence-host-namespace-changed")
            _engine_drained(owner, store.read(owner.lease_id))
            verify_disabled(owner, store, worker, root_configuration)
            effect = store.begin(owner.lease_id, "fence-remove", "fence:" + owner.lease_id)
            _run(policy, IP, ["link", "delete", "dev", _names(fence)[1]])
            remaining = _ip(policy, "link", "show")
            require(not any(row.get("ifindex") == metadata["host_ifindex"] or row.get("ifname") == _names(fence)[1]
                            for row in remaining), "fence-veth-still-present")
            inner = _ip(policy, "-n", _names(fence)[0], "link", "show")
            require(not any(row.get("ifindex") == metadata["peer_ifindex"] or row.get("ifname") == _names(fence)[2]
                            for row in inner), "fence-peer-still-present")
            _run(policy, IP, ["netns", "delete", _names(fence)[0]])
            parent = installation._open_directory("/run/netns")
            try:
                require(_names(fence)[0] not in os.listdir(parent), "fence-alias-still-present")
            finally:
                os.close(parent)
            _namespace_refs_drained(fd, info, cookie)
            require(_host_namespace() == host and _policy(root_policy_path, expected_sha256) == policy,
                    "fence-removal-drift")
        evidence = ledger.digest({"lease_id": owner.lease_id, "ownership": metadata,
                                  "state": "owned-alias-veth-removed-after-observed-drain"})
        store.record(owner.lease_id, effect, "verified", evidence_sha256=evidence)
        return FenceReceipt(owner.lease_id, "fence-remove", evidence)
    except Exception:
        if effect is not None:
            _unknown(store, owner, effect)
            raise FenceUnknown("fence-effect-unknown") from None
        raise KernelHold("fence-kernel-hold") from None


@contextmanager
def acquire_existing_fence(prepared, store, worker, config):
    """Live kernel acquisition for engine preflight, never a caller proof flag.

    Both Root-bound private namespace and persistent host endpoint fences must
    remain actually admitted for the latest full native authorization.
    """
    _root()
    path = getattr(config, "network_fence_policy_path", None)
    digest = getattr(config, "network_fence_policy_sha256", None)
    require(path is not None and digest is not None, "fence-root-policy-not-bound")
    policy = _policy(path, digest)
    record = _fresh(prepared, store, worker, config)
    _signed(prepared, store, worker, config)
    _, seconds = _remaining(record)
    expected = "fence:" + prepared.lease_id + ":" + record["authorizations"][-1]["token_id_sha256"]
    require(not any(e["operation"] == "fence-disable" for e in record["effects"].values()), "fence-disabled")
    matches = [e for e in record["effects"].values() if e["operation"] == "fence-renew" and e["target"] == expected
               and e["state"] == "verified"]
    require(len(matches) == 1 and matches[0]["fence_authorization"]["authorization_sha256"]
            == ledger.digest(record["authorizations"][-1]), "fence-latest-authorization-not-bound")
    authorization = matches[0]["fence_authorization"]
    require(time.clock_gettime_ns(time.CLOCK_BOOTTIME) < authorization["expires_boot_ns"], "fence-kernel-budget-expired")
    with _namespace(prepared) as (fd, _):
        _, expires, _, deadline = _owned(policy, prepared, store, maximum_ms=seconds * 1000)
        require(expires > 0 and deadline == authorization["allow_expires_at"], "fence-kernel-allow-absent")
        from . import host_api_fence
        host_api_fence.verify_current(prepared, store, worker, config)
        yield fd  # Retain actual NSFS FD for the duration; no synthetic receipt.
        _fresh(prepared, store, worker, config)
        host_api_fence.verify_current(prepared, store, worker, config)
