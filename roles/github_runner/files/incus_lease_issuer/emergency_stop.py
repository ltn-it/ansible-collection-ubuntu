"""Root-owned remote graceful STOP only; never deletion, retention or test PASS.

Partial startup without the strong original creator/exit receipts holds. Local
engine-stop and paired withdrawal must already be verified and natively drained.
The trusted Root-admin/platform boundary is unchanged; candidate labels alone do
not establish ownership. No operation is retried after an uncertain response.
"""
from dataclasses import dataclass
import os
import time

from . import (cell_contract, engine_executor, incus_admin, incus_mutation, ledger,
               network_fence, root_session, runtime_rpc)
from .identity import Denied, require


class EmergencyStopDenied(Denied):
    pass


class EmergencyStopUnknown(Denied):
    pass


@dataclass(frozen=True)
class StopReceipt:
    lease_id: str
    disposition: str
    effect_id: str | None
    evidence_sha256: str


def _effect(record, operation, target):
    rows = [(key, row) for key, row in record["effects"].items()
            if row["operation"] == operation and row["target"] == target]
    require(len(rows) <= 1, "emergency-duplicate-effect")
    return rows[0] if rows else None


class RootEmergencyStop:
    def __init__(self, root_runtime_config_path, expected_sha256):
        require(os.geteuid() == 0, "emergency-root-required")
        self._runtime = runtime_rpc._configuration(root_runtime_config_path, expected_sha256)

    def _fresh(self, session, registry, selector, store, owner):
        config = root_session._require_session(session)
        require(runtime_rpc._configuration(self._runtime.path, self._runtime.sha256) == self._runtime
                and registry.path == self._runtime.registry_path and registry.sha256 == self._runtime.registry_sha256
                and config.registry_path == registry.path and config.registry_sha256 == registry.sha256
                and cell_contract.owned_cell_for_cleanup(registry, selector, store, owner.lease_id) == owner,
                "emergency-root-drift")
        return config

    def _execute(self, session, registry, selector, store, owner, cleanup, operation, target, action, readback):
        effect = store.begin(owner.lease_id, operation, target)
        try:
            if operation == "certificate-revoke":
                inventory = cleanup.certificate_inventory()
                require(len(inventory.fingerprints) == 1 and not inventory.rotation_candidates,
                        "emergency-certificate-scope")
                store.bind_certificate_revocation(owner.lease_id, effect,
                    current_fingerprint=inventory.fingerprints[0], scope_sha256=inventory.scope_sha256,
                    inventory_sha256=inventory.inventory_sha256)
            self._fresh(session, registry, selector, store, owner)
            receipt = action()
            require(type(receipt) is incus_mutation.MutationReceipt and receipt.operation == operation
                    and receipt.target == target, "emergency-native-receipt")
            if receipt.operation_id is not None:
                store.bind_native_operation(owner.lease_id, effect, receipt.operation_id)
                end = time.monotonic() + self._runtime.cleanup_timeout_seconds
                while True:
                    self._fresh(session, registry, selector, store, owner)
                    require(time.monotonic() < end, "emergency-operation-timeout")
                    observed = cleanup.operation_readback(receipt)
                    if observed["state"] == "success_requires_resource_readback":
                        break
                    require(observed["state"] == "pending", "emergency-operation-failed")
                    time.sleep(min(0.05, max(0, end-time.monotonic())))
            self._fresh(session, registry, selector, store, owner)
            observed = readback()
            require(observed["state"] in {"absent_observed", "stopped_observed"}, "emergency-stop-unobserved")
            store.record(owner.lease_id, effect, "verified", evidence_sha256=ledger.digest(observed))
            return effect, observed
        except Exception:
            try:
                store.record(owner.lease_id, effect, "unknown", evidence_sha256=ledger.digest({"stage": operation}))
            except Exception:
                pass
            raise EmergencyStopUnknown("emergency-native-unknown") from None

    def stop(self, registry, selector, store, lease_id):
        require(os.geteuid() == 0, "emergency-root-required")
        try:
            with root_session._session(self._runtime.preparation_config_path,
                                       self._runtime.preparation_config_sha256) as session:
                owner = cell_contract.owned_cell_for_cleanup(registry, selector, store, lease_id)
                config = self._fresh(session, registry, selector, store, owner)
                record = store.read(lease_id)
                require(record["state"] != "closed" and not any(row["state"] in {"intent", "unknown"}
                        for row in record["effects"].values()), "emergency-unresolved-effect")
                for operation, target in (("engine-stop", "engine:lit-lease-"+lease_id),
                                          ("fence-disable", "fence:"+lease_id)):
                    prior = _effect(record, operation, target)
                    require(prior is not None and prior[1]["state"] == "verified", "emergency-local-stop-required")
                worker = ledger.Worker(**record["worker"])
                network_fence.verify_disabled(owner, store, worker, config)
                retained = runtime_rpc._receipt(registry, selector, store, lease_id)
                manifest, _, start = engine_executor._retained(config, registry, selector, store, lease_id, retained)
                engine_executor._drained(manifest, start["engine_capture"])
                value = owner.incus
                fingerprint = owner.creator_targets["certificate-create"].removeprefix("certificate:")
                client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path,
                    value["project"], value["network"], "default", value["pool"], (fingerprint,), value["instance"]))
                cleanup = incus_mutation.RootIncusCleanup(client, owner, store)
                cleanup.stop_inventory()  # Foreign objects/operations hold before ANY remote write.
                cert_target = owner.creator_targets["certificate-create"]
                revoked = _effect(record, "certificate-revoke", cert_target)
                if revoked is not None:
                    require(revoked[1]["state"] == "verified" and cleanup.certificates_absent(),
                            "emergency-prior-revocation-held")
                elif cleanup.certificates_absent():
                    effect = store.begin(lease_id, "certificate-revoke", cert_target)
                    try:
                        require(cleanup.certificates_absent(), "emergency-certificate-returned")
                        store.record(lease_id, effect, "verified", evidence_sha256=ledger.digest({"state": "absent_observed"}))
                    except Exception:
                        store.record(lease_id, effect, "unknown", evidence_sha256=ledger.digest({"stage": "certificate-revoke"}))
                        raise EmergencyStopUnknown("emergency-native-unknown") from None
                else:
                    self._execute(session, registry, selector, store, owner, cleanup, "certificate-revoke", cert_target,
                        cleanup.certificate_delete, lambda: cleanup.readback("certificate"))
                observed = cleanup.stop_inventory()
                target = "instance:"+value["project"]+":"+value["instance"]
                prior = _effect(store.read(lease_id), "instance-stop", target)
                if prior is not None:
                    require(prior[1]["state"] == "verified" and observed["state"] in {"absent_observed", "stopped_observed"},
                            "emergency-prior-stop-held")
                    return StopReceipt(lease_id, observed["state"], prior[0], ledger.digest(observed))
                if observed["state"] != "running_observed":
                    return StopReceipt(lease_id, observed["state"], None, ledger.digest(observed))
                effect, observed = self._execute(session, registry, selector, store, owner, cleanup, "instance-stop", target,
                    lambda: cleanup.instance_stop(min(30, self._runtime.cleanup_timeout_seconds)), cleanup.stop_inventory)
                return StopReceipt(lease_id, observed["state"], effect, ledger.digest(observed))
        except EmergencyStopUnknown:
            raise
        except Exception:
            raise EmergencyStopDenied("emergency-stop-held") from None
