"""Root-only owned-cell finalization; cleanup is never workload PASS.

No socket/CLI or job target arguments exist. Every target is rederived from the
sealed registry and original private creator records, including after expiry.
Unknown effects, foreign resources or lost ownership retain a hold; no write is
retried or adopted. Native platform/capacity/custody qualification is separate.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import PurePosixPath
import time

from . import (cell_contract, engine_executor, identity, incus_admin, incus_mutation,
               ledger, network_fence, runtime_rpc)
from .identity import Denied, require


class FinalizationDenied(Denied):
    """Before a new cleanup intent; no destructive retry permission."""


class FinalizationUnknown(Denied):
    """Possible cleanup effect retained; explicit native reconciliation only."""


@dataclass(frozen=True)
class FinalizationReceipt:
    lease_id: str
    closed_at: int
    evidence_receipt_sha256: str
    receipt_sha256: str


def _operating_evidence(runtime, registry, selector, store, owner, record, *, released):
    """Seal only Root-bound operating diagnostics; never business evidence/PASS.

    The original private spool is the publishing intent. A partial spool is
    held, never adopted. Its completed receipt survives raw storage deletion.
    """
    from . import engine_policy, evidence_export, operating_custody, operating_export
    descriptor = identity.decode_json(owner.engine_descriptor_bytes)
    env = descriptor["environment"]
    require(env.get("QUALITY_INPUT_PROFILE") == "operating", "finalization-operating-kind")
    operating_custody.require_cleanup_allowed(store, owner.lease_id)
    operating_custody._custody_record(record.get("custody"), record,
                                     store.read_policy(record["policy_sha256"]))
    terminal = record["native_terminal"]
    start_id = owner.creators["engine-start"]["id"]
    start = record["effects"][start_id]
    actual = start["engine_exit"]
    ledger._validate_engine_exit(actual, start)
    require(actual["manifest_sha256"] == owner.engine_policy_sha256
            and all(actual[name + "_state"] == "complete" for name in ("stdout", "stderr")),
            "finalization-operating-original-exit")
    operating_custody.validate_instance_record(record["owned_instance"], record, owner.lease_id)
    binding = {"runtime_config_sha256": runtime.sha256, "lease_id": owner.lease_id,
        "cell_sha256": record["cell_sha256"], "descriptor_sha256": owner.engine_descriptor_sha256,
        "manifest_sha256": owner.engine_policy_sha256, "exit_sha256": ledger.digest(actual),
        "native_terminal_sha256": ledger.digest(terminal), "custody_sha256": ledger.digest(record["custody"]),
        "instance_sha256": ledger.digest(record["owned_instance"])}
    directory = evidence_export._spool_directory(descriptor["engine"]["runroot"])
    parent = engine_policy._directory(str(PurePosixPath(directory).parent), private=True)
    fd = None
    try:
        name = PurePosixPath(directory).name
        if name not in os.listdir(parent):
            require(not released, "finalization-operating-spool-missing")
            from . import engine_graph_prune
            # This authenticates both capture bytes/inodes against the actual
            # original exit before either raw storage or its hashes disappear.
            diagnostics_sha = engine_graph_prune._diagnostics(owner, start)
            output = engine_policy._directory(descriptor["output_path"], private=True)
            try:
                try:
                    raw = evidence_export._read(output, "operating-result.json", operating_export.MAX_RAW)
                except FileNotFoundError:
                    raw = None
            finally:
                os.close(output)
            expected = operating_export.ExpectedOperating(env["QUALITY_OPERATING_CASE"],
                record["identity"]["run_id"], record["identity"]["caller_sha"],
                record["identity"]["reusable_sha"], owner.incus["instance"], record["owned_instance"]["uuid"])
            diagnostic = operating_export.normalize_operating(raw, expected, actual)
            with evidence_export._quota(runtime, str(PurePosixPath(directory).parent)):
                os.mkdir(name, 0o700, dir_fd=parent)
                os.fsync(parent)
                fd = engine_policy._directory(directory, private=True)
                info = os.fstat(fd)
                require(info.st_dev == os.fstat(parent).st_dev
                        and evidence_export.storage_quota._mount_id(fd)
                            == evidence_export.storage_quota._mount_id(parent), "finalization-operating-spool-mount")
                value = {"schema": 1, "kind": "operating-finalization-diagnostic", "binding": binding,
                    "diagnostic": diagnostic.value, "diagnostics_sha256": diagnostics_sha,
                    "spool": {"device": info.st_dev, "inode": info.st_ino},
                    "evidence_policy_complete": False, "quality_pass": False}
                require(engine_graph_prune._diagnostics(owner, start) == diagnostics_sha,
                        "finalization-operating-diagnostic-drift")
                evidence_export._create(fd, "operating-finalization.json", ledger.canonical(value))
        if fd is None:
            fd = engine_policy._directory(directory, private=True)
        with evidence_export._quota(runtime, directory):
            require(os.listdir(fd) == ["operating-finalization.json"], "finalization-operating-spool-inventory")
            raw = evidence_export._read(fd, "operating-finalization.json", engine_policy.MAX_DESCRIPTOR)
            value = identity.decode_json(raw)
            info = os.fstat(fd)
            require(set(value) == {"schema", "kind", "binding", "diagnostic", "diagnostics_sha256", "spool",
                                  "evidence_policy_complete", "quality_pass"}
                    and type(value["schema"]) is int and value["schema"] == 1
                    and value["kind"] == "operating-finalization-diagnostic" and value["binding"] == binding
                    and value["evidence_policy_complete"] is False and value["quality_pass"] is False
                    and value["spool"] == {"device": info.st_dev, "inode": info.st_ino}
                    and ledger.canonical(value) == raw, "finalization-operating-spool-binding")
            if not released:
                from . import engine_graph_prune
                require(value["diagnostics_sha256"] == engine_graph_prune._diagnostics(owner, start),
                        "finalization-operating-diagnostic-drift")
            return hashlib.sha256(raw).hexdigest()
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _effect(record, operation, target):
    matches = [(key, value) for key, value in record["effects"].items()
               if value["operation"] == operation and value["target"] == target]
    require(len(matches) <= 1, "finalization-duplicate-effect")
    return matches[0] if matches else None


class RootFinalizer:
    def __init__(self, root_runtime_config_path, expected_config_sha256):
        require(os.geteuid() == 0, "finalization-root-required")
        self._runtime = runtime_rpc._configuration(root_runtime_config_path, expected_config_sha256)

    def _fresh(self, session, registry, selector, store, owner):
        from . import root_session
        config = root_session._require_session(session)
        require(runtime_rpc._configuration(self._runtime.path, self._runtime.sha256) == self._runtime
                and registry.path == self._runtime.registry_path and registry.sha256 == self._runtime.registry_sha256
                and config.registry_path == registry.path and config.registry_sha256 == registry.sha256
                and cell_contract.owned_cell_for_cleanup(registry, selector, store, owner.lease_id) == owner,
                "finalization-root-drift")
        return config

    def _remote_delete(self, session, registry, selector, store, owner, cleanup, operation, target, kind, action):
        config = self._fresh(session, registry, selector, store, owner)
        existing = _effect(store.read(owner.lease_id), operation, target)
        if existing is not None:
            require(existing[1]["state"] == "verified" and cleanup.readback(kind)["state"] == "absent_observed",
                    "finalization-prior-effect-held")
            return
        effect = store.begin(owner.lease_id, operation, target)
        try:
            before = cleanup.readback(kind)
            require(before["state"] in {"required_fields_match", "absent_observed"}, "finalization-delete-not-owned")
            if before["state"] != "absent_observed":
                if operation == "certificate-revoke":
                    inventory = cleanup.certificate_inventory()
                    require(len(inventory.fingerprints) == 1 and not inventory.rotation_candidates,
                            "finalization-certificate-scope")
                    store.bind_certificate_revocation(owner.lease_id, effect,
                        current_fingerprint=inventory.fingerprints[0], scope_sha256=inventory.scope_sha256,
                        inventory_sha256=inventory.inventory_sha256)
                self._fresh(session, registry, selector, store, owner)
                receipt = action()
                require(type(receipt) is incus_mutation.MutationReceipt and receipt.operation == operation
                        and receipt.target == target, "finalization-mutation-receipt")
                if receipt.operation_id is not None:
                    store.bind_native_operation(owner.lease_id, effect, receipt.operation_id)
                    end = time.monotonic() + config.operation_wait_seconds
                    while True:
                        self._fresh(session, registry, selector, store, owner)
                        require(time.monotonic() < end, "finalization-operation-timeout")
                        observed = cleanup.operation_readback(receipt)
                        if observed["state"] == "success_requires_resource_readback":
                            break
                        require(observed["state"] == "pending", "finalization-operation-failed")
                        time.sleep(min(0.05, max(0, end-time.monotonic())))
            self._fresh(session, registry, selector, store, owner)
            observed = cleanup.readback(kind)
            require(observed["state"] == "absent_observed", "finalization-delete-not-observed")
            if operation == "certificate-revoke":
                require(cleanup.certificates_absent() is True, "finalization-certificate-scope-not-empty")
            store.record(owner.lease_id, effect, "verified", evidence_sha256=ledger.digest(observed))
        except Exception:
            try:
                store.record(owner.lease_id, effect, "unknown", evidence_sha256=ledger.digest({"stage": operation}))
            except Exception:
                pass
            raise FinalizationUnknown("finalization-remote-unknown") from None

    def finalize(self, registry, selector, store, lease_id):
        """Explicit Root call, serialized; no effect retry or job acceptance.

        Sanitized evidence must already survive in a separately bounded Root
        spool. Raw context/engine storage is never retained as a success waiver.
        """
        require(os.geteuid() == 0, "finalization-root-required")
        from . import root_session, cleanup_storage, evidence_export, emergency_stop, operating_custody
        attempted = False
        try:
            # Safety withdrawal is independent of destructive eligibility.
            # Its own finite session remains OUTSIDE ours, but expected safety
            # failures belong to this same finalization exception domain.
            initial = store.read(lease_id)
            if initial["state"] != "closed" and _effect(initial, "engine-release", "engine:" + lease_id) is None:
                emergency_stop.RootEmergencyStop(self._runtime.path, self._runtime.sha256).stop(
                    registry, selector, store, lease_id)
            elif initial["state"] != "closed":
                # Re-entry reads verified effects only. Deleted raw files
                # cannot reconstruct an original Popen owner or permit retry.
                ledger.Ledger._owned_instance_deleted(initial)
                require(any(row["operation"] == "certificate-revoke" and row["state"] == "verified"
                            for row in initial["effects"].values()), "finalization-prior-release-unsafe")
            with root_session._session(self._runtime.preparation_config_path,
                                       self._runtime.preparation_config_sha256) as session:
                owner = cell_contract.owned_cell_for_cleanup(registry, selector, store, lease_id)
                config = self._fresh(session, registry, selector, store, owner)
                record = store.read(lease_id)
                require(not any(effect["state"] in {"intent", "unknown"} for effect in record["effects"].values()),
                        "finalization-unresolved-effect")
                # Acquisition and spool publication do not permit overwriting
                # a partial archive. An explicit retained read survives deletion.
                raw_released = _effect(record, "engine-release", "engine:"+lease_id)
                descriptor = identity.decode_json(owner.engine_descriptor_bytes)
                if descriptor["environment"].get("QUALITY_INPUT_PROFILE") == "operating":
                    evidence_sha = _operating_evidence(self._runtime, registry, selector, store, owner, record,
                                                      released=raw_released is not None)
                else:
                    exported = (evidence_export.read_existing(self._runtime.path, self._runtime.sha256,
                        registry, selector, store, lease_id) if raw_released is not None else
                        evidence_export.export_existing(self._runtime.path, self._runtime.sha256,
                        registry, selector, store, lease_id))
                    raw_paths = [descriptor["engine"]["storage_root"], descriptor["engine"]["runroot"],
                                 descriptor["output_path"], descriptor["context_path"]]
                    spool = descriptor["engine"]["runroot"] + ".public-evidence"
                    require(type(exported) is evidence_export.ExportReceipt and exported.evidence_policy_complete is True
                            and str(PurePosixPath(exported.path).parent) == spool
                            and all(exported.path != path and not exported.path.startswith(path+"/") for path in raw_paths),
                            "finalization-evidence-spool-required")
                    evidence_sha = exported.receipt_sha256
                if record["state"] == "closed":
                    return FinalizationReceipt(lease_id, record["closed_at"], evidence_sha,
                        ledger.digest({"lease_id": lease_id, "closed_at": record["closed_at"],
                                       "effects": record["effects"], "evidence": evidence_sha}))
                worker = ledger.Worker(**record["worker"])
                # Normal run owner has stopped/reaped and withdrawn already.
                # A finalizer never replays either effect; native readback is
                # still mandatory before destroying the unique project.
                stop = _effect(record, "engine-stop", "engine:lit-lease-"+lease_id)
                require(stop is not None and stop[1]["state"] == "verified", "finalization-owned-stop-required")
                disable = _effect(record, "fence-disable", "fence:"+lease_id)
                require(disable is not None and disable[1]["state"] == "verified", "finalization-fence-withdrawal-required")
                network_fence.verify_disabled(owner, store, worker, config)
                start = record["effects"][owner.creators["engine-start"]["id"]]
                if raw_released is None:
                    retained = runtime_rpc._receipt(registry, selector, store, lease_id)
                    manifest, _, native_start = engine_executor._retained(config, registry, selector, store, lease_id, retained)
                    require(native_start == start, "finalization-engine-drift")
                    engine_executor._drained(manifest, start["engine_capture"])
                # Native drain is reacquired again by local storage release and
                # namespace removal. Original exit alone never proves it.
                target = owner.incus
                fingerprint = owner.creator_targets["certificate-create"].removeprefix("certificate:")
                client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path,
                    target["project"], target["network"], "default", target["pool"], (fingerprint,), target["instance"]))
                cleanup = incus_mutation.RootIncusCleanup(client, owner, store)
                project_deleted = _effect(record, "project-delete", "project:"+target["project"])
                if project_deleted is None:
                    observed = cleanup.stop_inventory()
                    if observed["state"] != "absent_observed" and "owned_instance" not in record:
                        store.bind_observed_instance(lease_id, operating_custody.observe_owned_instance(
                            config, registry, selector, store, lease_id))
                    elif "owned_instance" in record:
                        prior_delete = _effect(record, "instance-destroy", "instance:" + target["project"] + ":" + target["instance"])
                        require(observed["state"] != "absent_observed" or prior_delete is not None
                                and prior_delete[1]["state"] == "verified", "finalization-instance-disappeared")
                attempted = True
                self._remote_delete(session, registry, selector, store, owner, cleanup, "certificate-revoke",
                    owner.creator_targets["certificate-create"], "certificate", cleanup.certificate_delete)
                self._fresh(session, registry, selector, store, owner)
                # Revoke access promptly above; never destroy retained failure
                # storage merely because sanitized export completed.
                operating_custody.require_cleanup_allowed(store, lease_id)
                if store.read(lease_id).get("owned_instance") is not None:
                    self._remote_delete(session, registry, selector, store, owner, cleanup, "instance-destroy",
                        "instance:" + target["project"] + ":" + target["instance"], "instance", cleanup.instance_delete)
                if project_deleted is None:
                    cleanup.wait_quiet(config.operation_wait_seconds)
                cleanup_storage.release_engine(owner, store, config)
                self._fresh(session, registry, selector, store, owner)
                cleanup_storage.delete_context(owner, store, config)
                copies = [row for row in store.read(lease_id)["effects"].values() if row["operation"] == "image-copy"]
                if copies:
                    require(len(copies) == 1 and copies[0]["state"] == "verified", "finalization-image-copy-held")
                    self._remote_delete(session, registry, selector, store, owner, cleanup, "image-delete",
                        copies[0]["target"], "image", cleanup.image_delete)
                self._remote_delete(session, registry, selector, store, owner, cleanup, "project-delete",
                    "project:"+target["project"], "project", cleanup.project_delete)
                require(cleanup.readback("profile")["state"] == "absent_observed", "finalization-default-profile-returned")
                self._remote_delete(session, registry, selector, store, owner, cleanup, "network-delete",
                    "network:default:"+target["network"], "bridge", cleanup.bridge_delete)
                self._fresh(session, registry, selector, store, owner)
                network_fence.remove(config.network_fence_policy_path, config.network_fence_policy_sha256,
                                     owner, store, worker, config)
                self._fresh(session, registry, selector, store, owner)
                require(cleanup.certificates_absent() is True, "finalization-certificate-returned")
                require(cleanup.readback("project")["state"] == "absent_observed"
                        and cleanup.readback("bridge")["state"] == "absent_observed", "finalization-resource-returned")
                store.close(lease_id)
                closed = store.read(lease_id)
                require(closed["state"] == "closed", "finalization-close-not-observed")
                return FinalizationReceipt(lease_id, closed["closed_at"], evidence_sha,
                    ledger.digest({"lease_id": lease_id, "closed_at": closed["closed_at"],
                                   "effects": closed["effects"], "evidence": evidence_sha}))
        except FinalizationUnknown:
            raise
        except emergency_stop.EmergencyStopUnknown:
            # A safety write can be UNKNOWN before this finalizer has begun
            # any destructive operation. Never demote it to a known denial.
            raise FinalizationUnknown("finalization-safety-unknown") from None
        except emergency_stop.EmergencyStopDenied:
            raise FinalizationDenied("finalization-safety-denied") from None
        except Exception:
            if attempted:
                raise FinalizationUnknown("finalization-cleanup-held") from None
            raise FinalizationDenied("finalization-denied") from None
