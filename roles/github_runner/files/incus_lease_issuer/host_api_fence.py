"""Root-only persistent private IPv4 Incus endpoint fence.

No installer/listener activation or global firewall policy is implemented here.
This table MUST exist before the new endpoint starts listening and MUST remain
after every lease: withdrawal removes an allow element, never this baseline.
Other host rules/tables are neither flushed nor adopted. Both request and
response packets need an exact owned veth/peer tuple, a timed element and the
absolute authorization deadline; established conntrack is never sufficient.

Caller holds the same preparation lock across current native authorization,
signed context publication, namespace renewal and this grant. Required typed
Ledger operations and Root configuration bindings are integration requirements,
not optional approval flags. Unknown possible effects are retained, not retried.
Strict IPv4-only listener/alias/Unix-socket isolation, clock trust and native
kernel qualification remain independent platform obligations.

Primary syntax contracts: https://netfilter.org/projects/nftables/manpage.html
and https://wiki.nftables.org/wiki-nftables/index.php/Data_types (iface_index).
These are syntax evidence, not native support or operating qualification.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import ctypes
import fcntl
import ipaddress
import os
from pathlib import PurePosixPath
import re
import socket
import stat
import time

from . import cell_contract, engine_policy as engine, identity, installation, kernel, ledger, preparation
from . import network_fence as namespace
from .identity import Denied, require


@dataclass(frozen=True)
class _Policy:
    path: str
    sha256: str
    backend: str
    port: int
    table: str
    boot_id: str
    device: int
    inode: int
    tools: tuple


@dataclass(frozen=True)
class HostFenceReceipt:
    lease_id: str
    operation: str
    evidence_sha256: str


class HostFenceUnknown(Denied):
    """Durable intent/possible effect; Root reconciliation, never retry."""


def _root():
    require(os.geteuid() == 0, "host-api-root-required")


def _policy(path, expected):
    _root()
    proof, raw, _ = installation._file(engine._path(path), 8192, private=True, keep=True)
    require(proof.sha256 == engine._hash(expected), "host-api-policy-drift")
    value = identity.decode_json(raw)
    engine._keys(value, {"schema", "backend_ipv4", "backend_port", "table", "host_netns", "tools"})
    require(type(value["schema"]) is int and value["schema"] == 1, "host-api-policy-schema")
    address = ipaddress.IPv4Address(value["backend_ipv4"])
    require(str(address) == value["backend_ipv4"] and address.is_private and not any((
        address.is_loopback, address.is_link_local, address.is_multicast, address.is_unspecified)),
        "host-api-private-ipv4")
    port = engine._integer(value["backend_port"], 1, 65535)
    require(type(value["table"]) is str and re.fullmatch(r"lit_api_[0-9a-f]{32}", value["table"]),
            "host-api-table")
    host = engine._keys(value["host_netns"], {"boot_id", "device", "inode"})
    require(ledger._native_uuid(host["boot_id"]), "host-api-boot")
    device, inode = engine._integer(host["device"], 0), engine._integer(host["inode"], 1)
    tools = engine._keys(value["tools"], {namespace.IP, namespace.NFT})
    for digest in tools.values():
        engine._hash(digest)
    return _Policy(path, expected, str(address), port, value["table"], host["boot_id"], device, inode,
                   tuple(sorted(tools.items())))


def _bound(path, expected, config):
    require(type(config) is preparation.RootConfiguration
            and preparation._config(config.path, config.sha256)[0] == config
            and path == getattr(config, "host_api_fence_policy_path", None)
            and expected == getattr(config, "host_api_fence_policy_sha256", None),
            "host-api-root-policy-binding")
    return _policy(path, expected)


@contextmanager
def _host(policy):
    # Intentional kernel alias, never a configurable path/symlink exception.
    fd = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        buffer = ctypes.create_string_buffer(256)
        require(info.st_uid == 0 and ctypes.CDLL(None, use_errno=True).fstatfs(fd, buffer) == 0
                and ctypes.c_long.from_buffer(buffer).value == namespace.NSFS_MAGIC
                and fcntl.ioctl(fd, namespace.NS_GET_NSTYPE) == namespace.CLONE_NEWNET,
                "host-api-real-root-netns")
        require(kernel.read_boot_id() == policy.boot_id and (info.st_dev, info.st_ino) == (policy.device, policy.inode),
                "host-api-host-namespace-drift")
        yield
        named = os.stat("/proc/self/ns/net")
        require((named.st_dev, named.st_ino) == (info.st_dev, info.st_ino)
                and kernel.read_boot_id() == policy.boot_id, "host-api-host-namespace-drift")
    finally:
        os.close(fd)


def _nft(policy, *arguments, payload=None):
    # Reuse sealed-FD bounded fixed-tool transport, never namespace-enter argv.
    return namespace._run(policy, namespace.NFT, list(arguments), payload=payload)


def _local(policy):
    rows = namespace._array(namespace._run(policy, namespace.IP,
        ["-j", "-4", "address", "show", "to", policy.backend + "/32"]))
    require(any(any(item.get("family") == "inet" and item.get("local") == policy.backend
                    for item in row.get("addr_info", [])) for row in rows), "host-api-endpoint-not-local")


def _match(left, right):
    return namespace._match(left, right)


def _rules(policy, deadline=0):
    base = {"family": "inet", "table": policy.table}
    objects = [{"table": {"family": "inet", "name": policy.table, "comment": "lit-host-api:" + policy.sha256}},
               {"set": {**base, "name": "admitted", "type": ["iface_index", "ipv4_addr"], "flags": ["timeout"]}},
               {"chain": {**base, "name": "gate"}},
               {"rule": {**base, "chain": "gate", "expr": namespace._gate_expression(deadline)}}]
    for hook, field, port, interface in (("input", "daddr", "dport", "iif"),
                                          ("output", "saddr", "sport", "oif")):
        scoped = hook + "_endpoint"
        peerfield = "saddr" if hook == "input" else "daddr"
        objects.extend([
            {"chain": {**base, "name": hook, "type": "filter", "hook": hook, "prio": -300, "policy": "accept"}},
            {"chain": {**base, "name": scoped}},
            {"rule": {**base, "chain": hook, "expr": [
                _match({"payload": {"protocol": "ip", "field": field}}, policy.backend),
                _match({"payload": {"protocol": "tcp", "field": port}}, policy.port),
                {"jump": {"target": scoped}}]}},
            {"rule": {**base, "chain": scoped, "expr": [
                _match({"concat": [{"meta": {"key": interface}},
                       {"payload": {"protocol": "ip", "field": peerfield}}]}, "@admitted"),
                {"jump": {"target": "gate"}}]}},
            {"rule": {**base, "chain": scoped, "expr": [{"counter": None}, {"drop": None}]}},
        ])
    return {"nftables": [{"add": row} for row in objects]}


def _readback(policy, *, tuple_value=None, maximum_ms=0, expected_deadline=None):
    """Exact table-local native1.0.9 profile; unrelated tables stay opaque.

    nft1.0.9 emits existing iface_index values as names even with -n. Bind
    these to the retained index through both current Root-kernel directions.
    Timers are integer seconds, floored on output; return a lower-bound ms
    liveness value only after checking its conservative upper bound. Absolute
    time remains the independently required exact per-packet UTC deadline.
    """
    data = identity.decode_json(_nft(policy, "-n", "-j", "-T", "-a", "list", "table", "inet", policy.table))
    engine._keys(data, {"nftables"})
    require(type(data["nftables"]) is list and len(data["nftables"]) <= 32, "host-api-nft-inventory")
    observed, table_handle, gate_handle, deadline, expires = [], None, None, None, 0
    for item in data["nftables"]:
        require(type(item) is dict and len(item) == 1, "host-api-nft-object")
        kind = next(iter(item))
        if kind == "metainfo":
            continue
        require(kind in {"table", "chain", "set", "rule"} and type(item[kind]) is dict, "host-api-nft-object")
        row = dict(item[kind])
        handle = row.pop("handle", None)
        require(type(handle) is int and handle > 0, "host-api-nft-handle")
        if kind == "table":
            require(table_handle is None, "host-api-extra-table")
            table_handle = handle
        if kind == "set":
            elements = row.pop("elem", [])
            require(type(elements) is list and len(elements) <= 1, "host-api-extra-allow")
            if elements:
                require(type(elements[0]) is dict and set(elements[0]) == {"elem"}, "host-api-element-schema")
                element = elements[0]["elem"]
                value = element.get("val") if type(element) is dict else None
                require(type(element) is dict and set(element) == {"val", "timeout", "expires"}
                        and type(value) is dict and set(value) == {"concat"}
                        and type(value["concat"]) is list and len(value["concat"]) == 2
                        and type(value["concat"][0]) is str
                        and type(value["concat"][1]) is str
                        and type(tuple_value) is tuple and len(tuple_value) == 2
                        and type(tuple_value[0]) is int and 0 < tuple_value[0] <= 4294967295
                        and value["concat"][1] == tuple_value[1]
                        and type(element["timeout"]) is int and type(element["expires"]) is int
                        and 0 < element["expires"] <= element["timeout"] <= 5400
                        and type(maximum_ms) is int and (element["expires"] + 1) * 1000 <= maximum_ms,
                        "host-api-tuple-timer")
                try:
                    name = socket.if_indextoname(tuple_value[0])
                    require(value["concat"][0] == name
                            and socket.if_nametoindex(name) == tuple_value[0]
                            and socket.if_indextoname(tuple_value[0]) == name, "host-api-tuple-interface")
                except (OSError, OverflowError):
                    raise Denied("host-api-tuple-interface") from None
                expires = element["expires"] * 1000
        if kind == "rule":
            expressions = row.get("expr")
            require(type(expressions) is list, "host-api-rule-schema")
            expressions = [dict(expr) for expr in expressions]
            for expression in expressions:
                if "counter" in expression:
                    counter = expression["counter"]
                    require(type(counter) is dict and set(counter) == {"packets", "bytes"}
                            and all(type(v) is int and v >= 0 for v in counter.values()), "host-api-counter")
                    expression["counter"] = None
            if row.get("chain") == "gate":
                require(gate_handle is None and len(expressions) == 2 and set(expressions[0]) == {"match"},
                        "host-api-gate-schema")
                deadline = namespace._gate_deadline(expressions[0]["match"].get("right"))
                expressions[0] = {"match": {**expressions[0]["match"], "right": deadline}}
                require(expressions == namespace._gate_expression(deadline), "host-api-gate-drift")
                gate_handle = handle
            row["expr"] = expressions
        observed.append({kind: row})
    require(table_handle is not None and gate_handle is not None
            and (expected_deadline is None or deadline == expected_deadline), "host-api-deadline-drift")
    expected = [row["add"] for row in _rules(policy, deadline)["nftables"]]
    for kind in ("table", "chain", "set"):
        require(sorted((row for row in observed if kind in row), key=ledger.canonical)
                == sorted((row for row in expected if kind in row), key=ledger.canonical), "host-api-policy-drift")
    for chain in ("input", "output", "input_endpoint", "output_endpoint", "gate"):
        require([row for row in observed if "rule" in row and row["rule"].get("chain") == chain]
                == [row for row in expected if "rule" in row and row["rule"].get("chain") == chain],
                "host-api-rule-drift")
    require(len(observed) == len(expected), "host-api-extra-object")
    return table_handle, gate_handle, expires, deadline


def _journal_value(policy, state, handle=None):
    return {"schema": 1, "state": state, "policy_sha256": policy.sha256, "boot_id": policy.boot_id,
            "host_netns_device": policy.device, "host_netns_inode": policy.inode, "nft_table_handle": handle}


def _journal_parent(policy):
    parent = installation._open_directory(str(PurePosixPath(policy.path).parent))
    try:
        require(stat.S_IMODE(os.fstat(parent).st_mode) == 0o700, "host-api-private-journal-parent")
        return parent, PurePosixPath(policy.path).name + ".baseline.json"
    except BaseException:
        os.close(parent)
        raise


def _baseline(policy):
    parent, _ = _journal_parent(policy)
    os.close(parent)
    proof, raw, _ = installation._file(policy.path + ".baseline.json", 4096, private=True, keep=True)
    value = identity.decode_json(raw)
    engine._keys(value, set(_journal_value(policy, "verified")))
    handle = value["nft_table_handle"]
    require(type(handle) is int and handle > 0 and value == _journal_value(policy, "verified", handle)
            and raw == ledger.canonical(value), "host-api-baseline-unverified")
    return {"policy_sha256": policy.sha256, "baseline_sha256": proof.sha256, "boot_id": policy.boot_id,
            "host_netns_device": policy.device, "host_netns_inode": policy.inode, "nft_table_handle": handle}


def _save_journal(fd, parent, leaf, value):
    before = os.fstat(fd)
    named = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600
            and (before.st_dev, before.st_ino) == (named.st_dev, named.st_ino), "host-api-journal-drift")
    raw = ledger.canonical(value)
    os.lseek(fd, 0, os.SEEK_SET)
    require(os.write(fd, raw) == len(raw), "host-api-journal-write")
    os.ftruncate(fd, len(raw))
    os.fsync(fd)
    os.fsync(parent)


def install_baseline(root_policy_path, expected_sha256, root_configuration):
    """Root maintenance once, BEFORE listener enable; independent of jobs.

    Existing journal/table (even apparently matching) is never adopted/retried.
    Intent file and parent are durable before create. This API has no delete.
    """
    _root()
    policy = _bound(root_policy_path, expected_sha256, root_configuration)
    return _install_baseline(policy, root_configuration)


def _baseline_policy(binding):
    """Closed Root maintenance bindings; never caller policy paths or hooks."""
    if type(binding) is preparation.RootConfiguration:
        return _bound(binding.host_api_fence_policy_path,
                      binding.host_api_fence_policy_sha256, binding)
    from . import run_factory
    require(type(binding) is run_factory.RootBootstrapPolicy, "host-api-baseline-binding")
    current = run_factory.load_bootstrap(binding.path, binding.sha256)
    require(current == binding, "host-api-bootstrap-drift")
    config = current.value["preparation"]
    return _policy(config["host_api_fence_policy_path"], config["host_api_fence_policy_sha256"])


def install_bootstrap_baseline(bootstrap_path, expected_sha256):
    """Deny-first Root maintenance before any per-job registry exists.

    The sealed bootstrap alone selects the host policy. This creates no lease,
    signer, listener, native job or runtime grant and never adopts a journal.
    """
    _root()
    from . import run_factory
    bootstrap = run_factory.load_bootstrap(bootstrap_path, expected_sha256)
    return _install_baseline(_baseline_policy(bootstrap), bootstrap)


def _install_baseline(policy, binding):
    _root()
    require(_baseline_policy(binding) == policy, "host-api-policy-drift")
    parent, leaf = _journal_parent(policy)
    fd, attempted = None, False
    try:
        with _host(policy):
            _local(policy)
            data = identity.decode_json(_nft(policy, "-n", "-j", "list", "tables"))
            engine._keys(data, {"nftables"})
            require(type(data["nftables"]) is list and len(data["nftables"]) <= 4096, "host-api-table-inventory")
            for row in data["nftables"]:
                require(type(row) is dict and len(row) == 1 and set(row) <= {"metainfo", "table"}, "host-api-table-inventory")
                if "table" in row:
                    require(type(row["table"]) is dict and not (row["table"].get("family") == "inet"
                            and row["table"].get("name") == policy.table), "host-api-preexisting-table")
            require(_baseline_policy(binding) == policy, "host-api-policy-drift")
            fd = os.open(leaf, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            _save_journal(fd, parent, leaf, _journal_value(policy, "intent"))
            attempted = True
            _nft(policy, "-j", "-f", "-", payload=ledger.canonical(_rules(policy)))
            handle, _, expires, deadline = _readback(policy, expected_deadline=0)
            require(expires == deadline == 0, "host-api-baseline-not-denied")
            require(_baseline_policy(binding) == policy, "host-api-policy-drift")
            _save_journal(fd, parent, leaf, _journal_value(policy, "verified", handle))
            return _baseline(policy)
    except Exception:
        if attempted:
            try:
                _save_journal(fd, parent, leaf, _journal_value(policy, "unknown"))
            except Exception:
                pass  # Retained partial/intent is itself a permanent deny.
            raise HostFenceUnknown("host-api-baseline-unknown") from None
        raise Denied("host-api-baseline-denied") from None
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _effect(record, effect_id, operation, target):
    require(type(effect_id) is str and ledger.ID.fullmatch(effect_id), "host-api-effect")
    effect = record["effects"].get(effect_id)
    require(effect is not None and effect["operation"] == operation and effect["target"] == target
            and effect["state"] == "intent", "host-api-effect-not-new-intent")
    return effect


def _namespace_policy(prepared, store, config):
    policy = namespace._bound_policy(config.network_fence_policy_path, config.network_fence_policy_sha256, config)
    return policy


def bind_creator(path, expected, prepared, store, worker, config, effect_id):
    """Called within existing fence-create intent, after creator metadata bind."""
    _root()
    policy = _bound(path, expected, config)
    record = namespace._fresh(prepared, store, worker, config)
    effect = _effect(record, effect_id, "fence-create", "fence:" + prepared.lease_id)
    require("fence" in effect and effect["fence"]["boot_id"] == policy.boot_id, "host-api-creator-unbound")
    private = _namespace_policy(prepared, store, config)
    require((private.backend, private.port) == (policy.backend, policy.port), "host-api-endpoint-binding")
    with _host(policy):
        _local(policy)
        baseline = _baseline(policy)
        handle, _, expires, _ = _readback(policy)
        require(handle == baseline["nft_table_handle"] and expires == 0, "host-api-baseline-not-empty")
        require(not store.host_api_claimants(policy.sha256, baseline["baseline_sha256"]), "host-api-baseline-busy")
        # Actual current owned veth/namespace creator, not a caller assertion.
        with namespace._namespace(prepared) as (_, info):
            left, right = namespace._links(private, prepared)
            require((info.st_dev, info.st_ino, left, right) == tuple(effect["fence"][key] for key in
                    ("netns_device", "netns_inode", "host_ifindex", "peer_ifindex")), "host-api-creator-drift")
        store.bind_host_api_fence(prepared.lease_id, effect_id, **baseline)
        require(_bound(path, expected, config) == policy, "host-api-policy-drift")
        return baseline


def _owned(policy, prepared, store, *, removed=False):
    baseline = _baseline(policy)
    record = store.read(prepared.lease_id)
    creates = [row for row in record["effects"].values() if row["operation"] == "fence-create" and row["state"] == "verified"]
    require(len(creates) == 1 and creates[0].get("host_api") == baseline,
            "host-api-creator-not-owned")
    claims = store.host_api_claimants(policy.sha256, baseline["baseline_sha256"])
    require(claims == (prepared.lease_id,) or (removed and claims == ()),
            "host-api-baseline-claimants")
    return baseline, creates[0]["fence"]


def grant(path, expected, prepared, store, worker, config, effect_id):
    """Paired host send within EXISTING fence-renew intent, never close it.

    Metadata is durable before possible send, allowing an unknown grant to be
    withdrawn safely. Any failure propagates UNKNOWN to namespace transaction.
    Caller serialization is mandatory; there is no atomic nft/Ledger CAS.
    """
    _root()
    policy = _bound(path, expected, config)
    record = namespace._fresh(prepared, store, worker, config)
    target = "fence:" + prepared.lease_id + ":" + record["authorizations"][-1]["token_id_sha256"]
    effect = _effect(record, effect_id, "fence-renew", target)
    require("fence_authorization" in effect and "host_api_authorization" not in effect, "host-api-grant-replay")
    namespace._signed(prepared, store, worker, config)
    private = _namespace_policy(prepared, store, config)
    require((private.backend, private.port) == (policy.backend, policy.port), "host-api-endpoint-binding")
    with _host(policy):
        _local(policy)
        baseline, creator = _owned(policy, prepared, store)
        _, namespace_expires, _, namespace_deadline = namespace._owned(private, prepared, store, maximum_ms=5400000)
        require(namespace_expires > 0 and namespace_deadline == min(record["expires_at"], record["authorizations"][-1]["valid_until"]),
                "host-api-paired-namespace-not-live")
        peer = str(ipaddress.IPv4Interface(private.peer).ip)
        pair = (creator["host_ifindex"], peer)
        handle, gate, _, _ = _readback(policy, tuple_value=pair, maximum_ms=5400000)
        require(handle == baseline["nft_table_handle"], "host-api-baseline-handle-drift")
        latest = namespace._fresh(prepared, store, worker, config)
        require(latest["authorizations"][-1] == record["authorizations"][-1], "host-api-authorization-drift")
        namespace._signed(prepared, store, worker, config)
        deadline, remaining = namespace._remaining(latest)
        # Five-second command bound plus the one-second JSON floor/readback
        # reserve. This only shortens access; absolute authority is unchanged.
        ttl = remaining - 6
        require(ttl > 0, "host-api-authorization-budget")
        issued = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        metadata = {"baseline_sha256": baseline["baseline_sha256"], "host_ifindex": pair[0], "peer_ipv4": peer,
                    "authorization_sha256": ledger.digest(latest["authorizations"][-1]), "allow_expires_at": deadline,
                    "issued_boot_ns": issued, "expires_boot_ns": issued + ttl * 1000000000}
        store.bind_host_api_authorization(prepared.lease_id, effect_id, **metadata)
        raw = ("replace rule inet " + policy.table + " gate handle " + str(gate) + " meta time < " + str(deadline)
               + " accept\nflush set inet " + policy.table + " admitted\nadd element inet " + policy.table
               + " admitted { " + str(pair[0]) + " . " + peer + " timeout " + str(ttl) + "s }\n").encode("ascii")
        _nft(policy, "-f", "-", payload=raw)
        actual, _, expires, _ = _readback(policy, tuple_value=pair, maximum_ms=ttl * 1000, expected_deadline=deadline)
        require(actual == handle and expires > 0 and time.time() < deadline, "host-api-grant-not-live")
        namespace._fresh(prepared, store, worker, config)
        namespace._signed(prepared, store, worker, config)
        require(_bound(path, expected, config) == policy, "host-api-policy-drift")
        return ledger.digest(metadata)


def withdraw(path, expected, prepared, store, worker, config, effect_id):
    """First paired fence-disable intent; only empty the owned baseline set."""
    _root()
    policy = _bound(path, expected, config)
    record = namespace._fresh(prepared, store, worker, config, live=False)
    _effect(record, effect_id, "fence-disable", "fence:" + prepared.lease_id)
    with _host(policy):
        baseline, creator = _owned(policy, prepared, store)
        private = _namespace_policy(prepared, store, config)
        require((private.backend, private.port) == (policy.backend, policy.port), "host-api-endpoint-binding")
        pair = (creator["host_ifindex"], str(ipaddress.IPv4Interface(private.peer).ip))
        handle, _, _, _ = _readback(policy, tuple_value=pair, maximum_ms=5400000)
        require(handle == baseline["nft_table_handle"], "host-api-baseline-handle-drift")
        store.bind_host_api_withdrawal(prepared.lease_id, effect_id, baseline_sha256=baseline["baseline_sha256"])
        _nft(policy, "-f", "-", payload=("flush set inet " + policy.table + " admitted\n").encode("ascii"))
        actual, _, expires, _ = _readback(policy)
        require(actual == handle and expires == 0 and _bound(path, expected, config) == policy,
                "host-api-withdraw-not-empty")
        return ledger.digest({"baseline": baseline, "admitted": 0})


def verify_withdrawn(owner, store, worker, config):
    """Read-only cleanup prerequisite; baseline survives raw context deletion."""
    _root()
    require(type(owner) is cell_contract.OwnedCellForCleanup, "host-api-cleanup-owner")
    locator, record = namespace._cleanup_context(owner, store, worker, config)
    # The shared helper returns no LIVE locator only after independently
    # rederiving the strong owner and exact verified removal. The owner below
    # is solely a lease-id lookup for read-only old baseline absence checks.
    removed = locator is None
    prepared = owner if removed else locator
    require(any(row["operation"] == "fence-disable" and row["state"] == "verified" for row in record["effects"].values()),
            "host-api-disable-unverified")
    policy = _bound(config.host_api_fence_policy_path, config.host_api_fence_policy_sha256, config)
    with _host(policy):
        baseline, _ = _owned(policy, prepared, store, removed=removed)
        require(any(row["operation"] == "fence-disable" and row["state"] == "verified"
                    and row.get("host_api_withdrawal", {}).get("baseline_sha256") == baseline["baseline_sha256"]
                    for row in record["effects"].values()), "host-api-withdrawal-unverified")
        handle, _, expires, _ = _readback(policy)
        require(handle == baseline["nft_table_handle"] and expires == 0, "host-api-withdraw-not-empty")
        return {"baseline_sha256": baseline["baseline_sha256"], "admitted": 0}


def verify_current(prepared, store, worker, config):
    """Actual paired host kernel gate for engine preflight, never a bool grant."""
    _root()
    policy = _bound(config.host_api_fence_policy_path, config.host_api_fence_policy_sha256, config)
    record = namespace._fresh(prepared, store, worker, config)
    namespace._signed(prepared, store, worker, config)
    require(not any(row["operation"] == "fence-disable" for row in record["effects"].values()), "host-api-disabled")
    target = "fence:" + prepared.lease_id + ":" + record["authorizations"][-1]["token_id_sha256"]
    renewals = [row for row in record["effects"].values() if row["operation"] == "fence-renew"
                and row["target"] == target and row["state"] == "verified"]
    require(len(renewals) == 1 and "host_api_authorization" in renewals[0], "host-api-latest-grant-unverified")
    metadata = renewals[0]["host_api_authorization"]
    deadline, seconds = namespace._remaining(record)
    require(metadata["authorization_sha256"] == ledger.digest(record["authorizations"][-1])
            and metadata["allow_expires_at"] == deadline
            and time.clock_gettime_ns(time.CLOCK_BOOTTIME) < metadata["expires_boot_ns"], "host-api-current-budget")
    private = _namespace_policy(prepared, store, config)
    require((private.backend, private.port) == (policy.backend, policy.port), "host-api-endpoint-binding")
    with _host(policy):
        baseline, creator = _owned(policy, prepared, store)
        pair = (creator["host_ifindex"], str(ipaddress.IPv4Interface(private.peer).ip))
        require(metadata["baseline_sha256"] == baseline["baseline_sha256"]
                and (metadata["host_ifindex"], metadata["peer_ipv4"]) == pair, "host-api-current-tuple")
        handle, _, expires, _ = _readback(policy, tuple_value=pair, maximum_ms=seconds * 1000, expected_deadline=deadline)
        require(handle == baseline["nft_table_handle"] and expires > 0, "host-api-current-allow-absent")
        return ledger.digest({"baseline": baseline, "authorization": metadata})
