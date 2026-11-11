"""Root readonly pre-lease headroom with full retained reservations.

Two INDEPENDENT bounds: old FULL reservations + new FULL reservation + reserve
fit native total; actual native free space fits new FULL reservation + reserve.
Never add old reservations to already-used physical bytes, subtract logical
project Usage, or credit a guessed image allocation. All retained resources
must be independently owned/stopped/withdrawn/drained with pruned engine cache.

The genuine global Root session spans inspection and subsequent runtime_prepare.
Read-only old-registry/owner acquisition occurs outside Ledger transactions;
a final short transaction rejects ANY whole-state drift. This helper reserves
nothing. The 512MiB engine floor is PRE-ADMISSION only, not continuous protection.

Primary7.6 shared/api/resource.go750-788 (pool counters), driver_dir.go Info:
https://github.com/lxc/incus/blob/v7.6.0/internal/server/storage/drivers/driver_dir.go
DIR OptimizedImages:false; ANY image/custom/foreign volume remains a HOLD.
No native capacity/operating acceptance is established by fixture tests.
"""
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import dataclass
import os
from pathlib import Path
import re

from . import (cell_contract, cleanup_storage, engine_graph_prune, engine_policy as engine,
    identity, incus_admin, incus_mutation, installation, ledger, network_fence,
    operating_custody, policy_registry, preparation, root_session, run_factory,
    runtime_rpc, storage_quota)
from .identity import require

GIB = 1024 ** 3
PROFILE = {"schema": 1, "pool_total_bytes": 32 * GIB, "pool_reserve_bytes": GIB,
    "engine_total_bytes": 17 * GIB, "engine_reserve_bytes": 512 * 1024**2,
    "cold_engine_bytes": 8 * GIB, "pool_accounting": "owned-dir-retained-v1"}
POOL_REFS = {"pool_quota_policy_path", "pool_quota_policy_sha256"}


@dataclass(frozen=True)
class CapacityObservation:
    pool: str
    pool_total_bytes: int
    pool_used_bytes: int
    requested_pool_bytes: int
    pool_free_after_request_bytes: int
    retained_reservation_bytes: int
    engine_total_bytes: int
    engine_available_bytes: int
    engine_free_after_cold_bytes: int
    ledger_sha256: str


def validate_profile(value):
    engine._keys(value, set(PROFILE) | POOL_REFS)
    require(all(type(value[key]) is type(expected) and value[key] == expected
                for key, expected in PROFILE.items()), "capacity-profile")
    engine._path(value["pool_quota_policy_path"])
    engine._hash(value["pool_quota_policy_sha256"])
    return dict(value)


def _number(value, *, positive=False):
    require(type(value) is int and (1 if positive else 0) <= value < 2**63, "capacity-integer")
    return value


def _pool(value):
    engine._keys(value, {"space", "inodes"})
    for key in ("space", "inodes"):
        require(type(value[key]) is dict and set(value[key]) <= {"total", "used"}
            and "total" in value[key] and (key == "space" or "used" in value[key]), "capacity-pool-shape")
        total = _number(value[key]["total"], positive=True)
        used = _number(value[key].get("used", 0))  # Primary uint64 space.used omitempty.
        require(used <= total, "capacity-pool-inconsistent")
    require(value["space"]["total"] <= PROFILE["pool_total_bytes"], "capacity-pool-not-bounded")
    require(value["inodes"]["total"] - value["inodes"]["used"] >= 4096, "capacity-pool-inodes")
    return value["space"]["total"], value["space"].get("used", 0)


def _bounds(total, used, old, requested):
    for value in (total, used, old, requested):
        _number(value)
    require(old + requested + PROFILE["pool_reserve_bytes"] <= total, "capacity-reservation-total")
    require(total - used >= requested + PROFILE["pool_reserve_bytes"], "capacity-pool-headroom")


def _quiescent(state):
    require(len(state["leases"]) <= 4096, "capacity-ledger-limit")
    retained = {}
    for identifier, record in state["leases"].items():
        require(not any(row["state"] in {"intent", "unknown"} for row in record["effects"].values()),
                "capacity-unresolved-effect")
        require(record["state"] in {"closed", "retained"}, "capacity-live-lease")
        if record["state"] == "retained":
            require(operating_custody.known_retention(record), "capacity-retained-unknown")
            retained[identifier] = record
    return retained


def _same_store(store, path):
    fd = installation._open_directory(path)
    try:
        a, b = os.fstat(store.fd), os.fstat(fd)
        require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino), "capacity-ledger-binding")
    finally:
        os.close(fd)


def _catalogue(records):
    """Resolve ORIGINAL sealed private configs, never from the new registry.

    Root-owned paths are bounded locators; actual full manifest/inventory and
    original run/job/check/head/B/cell/policy are independently compared below.
    This routine must never execute inside an open Ledger transaction.
    """
    if not records:
        return {}, None
    root = installation._open_directory(run_factory.ROOT)
    try:
        run_factory.run_intake._directory_identity(root)
        os.lseek(root, 0, os.SEEK_SET)
        names = sorted(os.listdir(root))
        require(len(names) <= 256 and all(re.fullmatch(r"[0-9a-f]{64}", name) for name in names),
                "capacity-catalogue-inventory")
        found = {}
        for name in names:
            cfg, receipt = run_factory._read_complete(Path(run_factory.ROOT) / name)
            row = receipt["invocation"]
            for identifier, record in records.items():
                who = record["identity"]
                expected = (who["run_id"], who["job_id"], who["check_run_id"], who["caller_sha"], who["reusable_sha"])
                actual = tuple(row[key] for key in ("run_id", "job_id", "check_run_id", "source_sha", "reusable_sha"))
                if actual == expected:
                    require(identifier not in found, "capacity-old-config-ambiguous")
                    found[identifier] = (cfg, receipt)
        os.lseek(root, 0, os.SEEK_SET)
        require(set(found) == set(records) and sorted(os.listdir(root)) == names, "capacity-old-config-missing")
        return found, tuple(names)
    finally:
        os.close(root)


def _graph(owner, start, record):
    data = identity.decode_json(owner.engine_descriptor_bytes)
    matches = [row for row in record["effects"].values() if row["operation"] == "engine-graph-prune"]
    require(len(matches) == 1 and matches[0]["state"] == "verified"
            and matches[0]["target"] == "engine:" + owner.lease_id, "capacity-engine-not-pruned")
    path = data["engine"]["storage_root"]
    fd = engine._directory(path, private=True)
    try:
        info = os.fstat(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        require(os.listdir(fd) == [], "capacity-pruned-graph-returned")
        expected = {"graph_device": info.st_dev, "graph_inode": info.st_ino,
            "diagnostics_sha256": engine_graph_prune._diagnostics(owner, start),
            "manifest_sha256": owner.engine_policy_sha256, "exit_sha256": ledger.digest(start["engine_exit"])}
        require(matches[0].get("graph_prune") == expected, "capacity-pruned-diagnostics-drift")
        return expected
    finally:
        os.close(fd)


def _raw_native(client):
    return {"instance": client.instance(), "state": client.instance_state(),
            "operations": client.operations(), "certificates": client.certificates()}


def _retained(identifier, record, cfg, receipt, store, current, profile, pool):
    old_runtime = runtime_rpc._configuration(cfg.runtime_config_path, cfg.runtime_config_sha256)
    old_config = preparation._config(cfg.preparation_config_path, cfg.preparation_config_sha256)[0]
    old_registry = policy_registry.load_registry(cfg.registry_path, cfg.registry_sha256)
    selector = receipt["invocation"]["selector"]
    selected = old_registry.select(selector)
    _same_store(store, selected.ledger_path)
    require(selected.cell_sha256 == record["cell_sha256"]
        and identity.policy_digest(selected.identity) == record["identity"]["policy_sha256"]
        and selected.custody_policy_sha256 == record["policy_sha256"], "capacity-old-domain")
    require(old_config.lock_path == current.lock_path and old_config.incus_socket_path == current.incus_socket_path
        and (old_config.storage_quota_policy_path, old_config.storage_quota_policy_sha256)
            == (current.storage_quota_policy_path, current.storage_quota_policy_sha256)
        and validate_profile(dict(old_runtime.capacity)) == profile, "capacity-old-platform")
    operating_custody._custody_record(record["custody"], record, store.read_policy(record["policy_sha256"]))
    owner = cell_contract.owned_cell_for_cleanup(old_registry, selector, store, identifier)
    target = owner.incus
    require(target["pool"] == pool and target["project_limits"]["disk_bytes"] == record["custody"]["storage_reservation_bytes"],
            "capacity-old-reservation")
    _, start = cleanup_storage._drain_engine(owner, store, old_config)
    graph = _graph(owner, start, record)
    network_fence.verify_disabled(owner, store, ledger.Worker(**record["worker"]), old_config)
    fp = owner.creator_targets["certificate-create"].removeprefix("certificate:")
    client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(current.incus_socket_path,
        target["project"], target["network"], "default", pool, (fp,), target["instance"]))
    cleanup = incus_mutation.RootIncusCleanup(client, owner, store)
    observed = cleanup.stop_inventory()
    native = _raw_native(client)
    devices = native["instance"].get("expanded_devices")
    spec = identity.decode_json(identity.decode_json(owner.engine_descriptor_bytes)["environment"]["QUALITY_OPERATING_SPEC"].encode())
    require(type(devices) is dict and set(devices) == {"root", "eth0"}
        and devices["root"].get("type") == "disk" and devices["root"].get("path") == "/"
        and devices["root"].get("pool") == pool and devices["root"].get("size") == "5GiB"
        and devices["root"].get("size.state", "500MiB") == "500MiB"
        and devices["eth0"].get("type") == "nic" and devices["eth0"].get("network") == target["network"]
        and native["instance"].get("config", {}).get("volatile.base_image") == spec["image"],
        "capacity-retained-devices")
    require(observed["state"] == "stopped_observed" and cleanup.certificates_absent()
        and native["instance"].get("config", {}).get("volatile.uuid") == record["custody"]["instance_uuid"]
        and all(rows == [] for rows in native["operations"].values())
        and cleanup.stop_inventory() == observed and _raw_native(client) == native, "capacity-retained-native-unsafe")
    return {"owner": owner, "config": old_config, "client": client, "native": native, "graph": graph,
            "start": start, "record": record, "configuration": cfg, "receipt": receipt,
            "volume": (target["project"], target["instance"]),
            "reservation": record["custody"]["storage_reservation_bytes"]}


def _volumes(values, expected):
    require(type(values) is list and len(values) <= 4096, "capacity-volume-inventory")
    observed = []
    for value in values:
        require(type(value) is dict and value.get("type") == "virtual-machine"
            and value.get("content_type") == "block" and type(value.get("project")) is str
            and type(value.get("name")) is str, "capacity-unknown-volume")
        observed.append((value["project"], value["name"]))
    require(len(observed) == len(set(observed)) and set(observed) == set(expected), "capacity-foreign-volume")


def _acquire(stack, path, sha, maximum, mutable):
    policy, proof, stamp = storage_quota._policy(path, sha)
    require(policy["max_bytes"] == maximum and policy["backing_file"]["bytes"] == maximum, "capacity-quota-profile")
    scope = storage_quota._acquire_paths(path, sha, mutable)
    scope.__enter__()
    # Always run final independent kernel proof, preserving a specific capacity
    # denial only if the final quota verification independently succeeds.
    stack.callback(scope.__exit__, None, None, None)
    fd = engine._directory(policy["mount"]["path"], private=True)
    stack.callback(os.close, fd)
    return policy, proof, stamp, fd


def _pool_source(descriptor, policy):
    source = descriptor.get("config", {}).get("source")
    require(descriptor.get("driver") == "dir" and descriptor.get("status") == "Created"
        and type(source) is str and (source == policy["mount"]["path"]
            or source.startswith(policy["mount"]["path"] + "/")), "capacity-pool-source")
    engine._path(source)
    return source


def require_capacity(runtime_config_path, runtime_config_sha256, registry, selector, store, *, session):
    require(os.geteuid() == 0, "capacity-root-required")
    current = root_session._require_session(session)
    runtime = runtime_rpc._configuration(runtime_config_path, runtime_config_sha256)
    proof, raw, stamp = installation._file(runtime_config_path, 16384, private=True, keep=True)
    require(proof.sha256 == runtime_config_sha256, "capacity-runtime-drift")
    profile = validate_profile(identity.decode_json(raw).get("capacity"))
    require((runtime.preparation_config_path, runtime.preparation_config_sha256) == (current.path, current.sha256)
        and type(registry) is policy_registry.Registry
        and (runtime.registry_path, runtime.registry_sha256) == (registry.path, registry.sha256)
        and (current.registry_path, current.registry_sha256) == (registry.path, registry.sha256)
        and policy_registry.load_registry(registry.path, registry.sha256) == registry, "capacity-configuration-binding")
    selected = registry.select(selector)
    require(type(store) is ledger.Ledger and store.owner_uid == 0, "capacity-ledger")
    _same_store(store, selected.ledger_path)
    with store._transaction() as state:
        initial = deepcopy(state)
    records = _quiescent(initial)
    digest = ledger.digest(initial)
    catalogue, names = _catalogue(records)
    value, cell_proof, cell_stamp = cell_contract._sealed(selected.cell_config_path, selected.cell_sha256)
    cell_contract._cell_fields(value)
    requested = _number(value["incus"]["project_limits"]["disk_bytes"], positive=True)
    pool = value["incus"]["pool"]
    old = [_retained(identifier, record, *catalogue[identifier], store, current, profile, pool)
           for identifier, record in records.items()]
    reserved = sum(item["reservation"] for item in old)
    volumes = [item["volume"] for item in old]
    require(len(volumes) == len(set(volumes)), "capacity-owned-volume-collision")
    client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(current.incus_socket_path,
                         "default", "lit-capacity-observation", "default", pool, ()))
    incus_admin.qualify_backend(client.server(), expected_version="7.6", expected_extensions=frozenset({"resources", "storage"}))
    descriptor = client.pool()
    require(descriptor.get("name") == pool, "capacity-pool-identity")
    pool_policy, _, _ = storage_quota._policy(profile["pool_quota_policy_path"], profile["pool_quota_policy_sha256"])
    source = _pool_source(descriptor, pool_policy)
    references = [(registry.path, registry.sha256), (current.path, current.sha256)]
    for item in old:
        cfg = item["configuration"]
        references += [(cfg.registry_path, cfg.registry_sha256), (cfg.preparation_config_path, cfg.preparation_config_sha256),
            (cfg.runtime_config_path, cfg.runtime_config_sha256),
            (str(Path(cfg.directory) / "sealed-inventory.json"), cfg.manifest_sha256)]
    reference_proofs = [(path, installation._file(path, engine.MAX_DESCRIPTOR, private=True, keep=True))
                        for path, _sha in references]
    require(all(observed[0].sha256 == expected for (_path, observed), (_name, expected)
                in zip(reference_proofs, references)), "capacity-reference-drift")
    old_paths = []
    for item in old:
        details = identity.decode_json(item["owner"].engine_descriptor_bytes)
        old_paths += [details["engine"]["storage_root"], details["engine"]["runroot"], details["output_path"]]
    with ExitStack() as stack:
        engine_paths = value["engine"]["paths"]
        eq, ep, es, engine_fd = _acquire(stack, current.storage_quota_policy_path,
            current.storage_quota_policy_sha256, PROFILE["engine_total_bytes"],
            tuple(engine_paths[key] for key in ("storage", "runroot", "output")) + tuple(old_paths))
        pq, pp, ps, pool_fd = _acquire(stack, profile["pool_quota_policy_path"],
            profile["pool_quota_policy_sha256"], PROFILE["pool_total_bytes"],
            () if source == pool_policy["mount"]["path"] else (source,))
        require(eq["mount"]["device"] != pq["mount"]["device"], "capacity-shared-filesystem")
        mounts = storage_quota._mounts(storage_quota._read_proc("/proc/self/mountinfo", storage_quota.MOUNTINFO_LIMIT))
        rows = [row for row in mounts if row["id"] == pq["mount"]["mount_id"]]
        require(len(rows) == 1 and "prjquota" in set(rows[0]["flags"] + rows[0]["super"]), "capacity-pool-project-quota")
        native_volumes = client.pool_volumes(); _volumes(native_volumes, volumes)
        resources = client.pool_resources(); total, used = _pool(resources)
        _bounds(total, used, reserved, requested)
        pool_fs, fs = os.fstatvfs(pool_fd), os.fstatvfs(engine_fd)
        require(pool_fs.f_frsize * pool_fs.f_blocks == total, "capacity-pool-filesystem-mismatch")
        require(_number(pool_fs.f_bavail) * _number(pool_fs.f_frsize, positive=True)
                >= requested + PROFILE["pool_reserve_bytes"], "capacity-pool-filesystem-headroom")
        fs_total = _number(fs.f_blocks, positive=True) * _number(fs.f_frsize, positive=True)
        available = _number(fs.f_bavail) * fs.f_frsize
        require(0 < fs_total <= PROFILE["engine_total_bytes"] and available <= fs_total, "capacity-engine-inconsistent")
        require(_number(fs.f_favail) >= 4096, "capacity-engine-inodes")
        require(available >= PROFILE["cold_engine_bytes"] + PROFILE["engine_reserve_bytes"], "capacity-engine-headroom")
        # Entire old catalogue/config provenance is checked OUTSIDE the final
        # Ledger transaction; its fixed inventory readers below take no locks.
        for item in old:
            require(run_factory._read_complete(Path(item["configuration"].directory))
                    == (item["configuration"], item["receipt"]), "capacity-old-configuration-drift")
        with store._transaction() as state:
            require(state == initial and ledger.digest(state) == digest, "capacity-ledger-drift")
            require(client.pool() == descriptor and client.pool_volumes() == native_volumes
                and client.pool_resources() == resources and os.fstatvfs(pool_fd) == pool_fs
                and os.fstatvfs(engine_fd) == fs, "capacity-observation-drift")
            for item in old:
                require(_raw_native(item["client"]) == item["native"]
                    and _graph(item["owner"], item["start"], item["record"]) == item["graph"]
                    and run_factory._inventory(Path(item["configuration"].directory)) == item["receipt"]["inventory"],
                    "capacity-retained-readback-drift")
            if names is not None:
                fd = installation._open_directory(run_factory.ROOT)
                try: require(tuple(sorted(os.listdir(fd))) == names, "capacity-catalogue-drift")
                finally: os.close(fd)
            require(all(installation._file(path, engine.MAX_DESCRIPTOR, private=True, keep=True) == observed
                        for path, observed in reference_proofs), "capacity-reference-drift")
            require(cell_contract._sealed(selected.cell_config_path, selected.cell_sha256) == (value, cell_proof, cell_stamp)
                and storage_quota._policy(current.storage_quota_policy_path, current.storage_quota_policy_sha256) == (eq, ep, es)
                and storage_quota._policy(profile["pool_quota_policy_path"], profile["pool_quota_policy_sha256"]) == (pq, pp, ps)
                and installation._file(runtime_config_path, 16384, private=True, keep=True) == (proof, raw, stamp)
                and root_session._require_session(session) == current, "capacity-control-drift")
            return CapacityObservation(pool, total, used, requested, total-used-requested, reserved,
                                       fs_total, available, available-PROFILE["cold_engine_bytes"], digest)
