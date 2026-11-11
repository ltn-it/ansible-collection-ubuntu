"""Once-only pruning of recoverable public operating EE graph CHILDREN.

Never removes the original graph-root inode, raw runroot/output/control,
context/descriptor, evidence spool or Incus VM/project/image. Old engine-release
and its retention/destruction gates are unchanged. No engine command is run.

Requires actual terminal armed custody, original exit/capture/drain, withdrawn
API/TLS and exact stopped VM. The approved original-execution drain and held global Root session are the
writer boundary, as for existing release_engine. No promise excludes an
uncoordinated privileged future writer. No whole-host process scan is added.
"""
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import os
import time

from . import (cell_contract, cleanup_storage as cleanup, engine_policy as engine,
               identity, incus_admin, incus_mutation, installation, ledger,
               network_fence, operating_custody as custody, root_session)
from .identity import Denied, require

class GraphPruneUnknown(Denied):
    """An owned graph deletion may have occurred; never retry/adopt here."""


@dataclass(frozen=True)
class GraphPruneReceipt:
    lease_id: str
    evidence_sha256: str
    # This is not capacity, export, test success or operating acceptance.


def _diagnostics(owner, start):
    data = identity.decode_json(owner.engine_descriptor_bytes)
    runroot, output = data["engine"]["runroot"], data["output_path"]
    actual, capture = start["engine_exit"], start["engine_capture"]
    found = {}
    for name in ("stdout", "stderr"):
        size = actual[name + "_bytes"]
        proof, _raw, stamp = installation._file(runroot + "/" + name + ".log", max(1, size), private=True, keep=True)
        require(proof.size == size and proof.sha256 == actual[name + "_sha256"]
                and (proof.device, proof.inode) == (capture[name + "_device"], capture[name + "_inode"]),
                "graph-prune-capture-drift")
        found[name] = (proof, stamp)
    # These are diagnostic DATA, not code, approval or a sealed export. Cases
    # killed before final reporting may legitimately have no result JSON.
    for relative in ("operating-result.json", "control/operating-created.json", "control/root-operating-ready.json"):
        try:
            from . import evidence_export
            fd = engine._directory(output, private=True)
            try:
                raw = evidence_export._read(fd, relative, 16384)
            finally:
                os.close(fd)
            found[relative] = hashlib.sha256(raw).hexdigest()
        except FileNotFoundError:
            found[relative] = None
    return ledger.digest({"capture": {name: {"sha256": proof.sha256, "device": proof.device,
        "inode": proof.inode, "size": proof.size, "stamp": list(stamp)}
        for name in ("stdout", "stderr") for proof, stamp in (found[name],)},
        "diagnostics": {name: value for name, value in found.items() if name not in {"stdout", "stderr"}}})


def _safe(owner, store, config, session):
    require(root_session._require_session(session) == config, "graph-prune-session")
    record = cleanup._fresh(owner, store, config)
    data = identity.decode_json(owner.engine_descriptor_bytes)
    require(data["environment"].get("QUALITY_INPUT_PROFILE") == "operating", "graph-prune-operating-only")
    require(record["state"] == "retained" and "native_terminal" in record and "custody" in record,
            "graph-prune-custody-not-armed")
    custody._custody_record(record["custody"], record, store.read_policy(record["policy_sha256"]))
    # The prune's OWN verified record is permitted on readonly reentry; any
    # intent/unknown, including a prior prune, remains a hard no-retry hold.
    require(not any(row["state"] in {"intent", "unknown"} for row in record["effects"].values()),
            "graph-prune-unresolved")
    _, start = cleanup._drain_engine(owner, store, config)
    require(all(start["engine_exit"][key + "_state"] == "complete" for key in ("stdout", "stderr")),
            "graph-prune-capture-incomplete")
    network_fence.verify_disabled(owner, store, ledger.Worker(**record["worker"]), config)
    target = owner.incus
    fingerprint = owner.creator_targets["certificate-create"].removeprefix("certificate:")
    client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path, target["project"],
        target["network"], "default", target["pool"], (fingerprint,), target["instance"]))
    remote = incus_mutation.RootIncusCleanup(client, owner, store)
    first = remote.stop_inventory()
    require(first["state"] == "stopped_observed" and remote.certificates_absent()
            and client.instance().get("config", {}).get("volatile.uuid") == record["custody"]["instance_uuid"]
            and remote.stop_inventory() == first, "graph-prune-native-not-safe")
    return record, data, start


def prune_graph(owner, store, config, *, session):
    """No arbitrary path/reader/approval/force flag and no retry of unknown IO."""
    require(os.geteuid() == 0, "graph-prune-root-required")
    effect = None
    try:
        record, data, start = _safe(owner, store, config, session)
        target = "engine:" + owner.lease_id
        prior = cleanup._effect(record, "engine-graph-prune", target)
        maximum, seconds = cleanup._cleanup_limits(config)
        end = time.monotonic() + seconds
        paths = (data["engine"]["storage_root"], data["engine"]["runroot"], data["output_path"])
        diagnostic = _diagnostics(owner, start)
        with ExitStack() as stack:
            directories, opened = [], []
            for path in paths:
                fd = engine._directory(path, private=True)
                stack.callback(os.close, fd)
                info = os.fstat(fd)
                directories.append({"path": path, "device": info.st_dev, "inode": info.st_ino})
                opened.append(fd)
            creator = record["effects"][owner.creators["engine-prepare"]["id"]]
            require(creator["evidence_sha256"] == ledger.digest({"prepared": owner.prepared_sha256,
                    "directories": directories}), "graph-prune-original-inodes")
            graph = opened[0]
            inventory = cleanup._inventory_tree(graph, end, maximum)
            binding = {"graph_device": directories[0]["device"], "graph_inode": directories[0]["inode"],
                "diagnostics_sha256": diagnostic, "manifest_sha256": owner.engine_policy_sha256,
                "exit_sha256": ledger.digest(start["engine_exit"])}
            if prior is not None:
                require(prior[1].get("graph_prune") == binding, "graph-prune-original-binding-drift")
                require(inventory[0] == (), "graph-prune-graph-returned")
                require(_diagnostics(owner, start) == diagnostic, "graph-prune-diagnostics-drift")
                return GraphPruneReceipt(owner.lease_id, prior[1]["evidence_sha256"])
            # Reacquire all safety/provenance immediately before the one intent.
            require(_safe(owner, store, config, session)[0] == record
                    and _diagnostics(owner, start) == diagnostic, "graph-prune-pre-effect-drift")
            effect = store.begin(owner.lease_id, "engine-graph-prune", target)
            store.bind_engine_graph_prune(owner.lease_id, effect, **binding)
            cleanup._remove_tree(graph, inventory, end)  # Intentionally NO rmdir(graph).
            named = engine._directory(paths[0], private=True)
            try:
                require(cleanup._identity(os.fstat(graph)) == inventory[1][()]
                        == cleanup._identity(os.fstat(named))
                        and cleanup.storage_quota._mount_id(named) == inventory[2], "graph-prune-root-drift")
            finally:
                os.close(named)
            # All raw diagnostic bytes and captures remain exactly as observed.
            require(_diagnostics(owner, start) == diagnostic, "graph-prune-diagnostics-drift")
            after = cleanup._inventory_tree(graph, end, maximum)
            require(after[0] == (), "graph-prune-not-empty")
            evidence = ledger.digest({"lease_id": owner.lease_id, "operation": "engine-graph-prune",
                "root": directories[0], "manifest_sha256": owner.engine_policy_sha256,
                "exit_sha256": ledger.digest(start["engine_exit"]), "diagnostics_sha256": diagnostic,
                "removed_inventory_sha256": ledger.digest(inventory[0]), "removed_entries": len(inventory[0])})
            require(store.read(owner.lease_id)["effects"][effect].get("graph_prune") == binding,
                    "graph-prune-journal-drift")
            store.record(owner.lease_id, effect, "verified", evidence_sha256=evidence)
            return GraphPruneReceipt(owner.lease_id, evidence)
    except BaseException:
        if effect is not None:
            cleanup._mark_unknown(store, owner, effect, "engine-graph-prune")
            raise GraphPruneUnknown("graph-prune-unknown") from None
        raise Denied("graph-prune-held") from None
