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
from pathlib import Path, PurePosixPath
import time

from . import (cell_contract, engine_executor, identity, incus_admin, incus_mutation,
               ledger, network_fence, operating_cells, runtime_rpc)
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


def _operating_evidence(runtime, registry, selector, store, owner, record, *, session, released, observation=False):
    """Seal only Root-bound operating diagnostics; never business evidence/PASS.

    The original private spool is the publishing intent. A partial spool is
    held, never adopted. Its completed receipt survives raw storage deletion.
    """
    from . import engine_policy, evidence_export, operating_custody, operating_export, startup_retirement
    descriptor = identity.decode_json(owner.engine_descriptor_bytes)
    env = descriptor["environment"]
    require(env.get("QUALITY_INPUT_PROFILE") == "operating", "finalization-operating-kind")
    operating_custody.require_cleanup_allowed(store, owner.lease_id)
    policy = store.read_policy(record["policy_sha256"])
    operating_custody._custody_record(record.get("custody"), record, policy)
    immediate = policy["retention_seconds"] == 0
    require(not observation or immediate and released and record["state"] == "closed",
            "finalization-operating-spool-observation")
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
    if immediate:
        _, binding["private_failure_archive_sha256"] = startup_retirement.preserve_custody_failure(
            session, owner, store, record, released=released)
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
            stopped = operating_custody.operating_outcome(runtime.path, runtime.sha256, registry, selector,
                store, owner.lease_id, retained=True, session=session) if immediate else None
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
                if immediate:
                    value["stopped_receipt"] = stopped
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
            fields = {"schema", "kind", "binding", "diagnostic", "diagnostics_sha256", "spool",
                      "evidence_policy_complete", "quality_pass"}
            if immediate:
                fields.add("stopped_receipt")
                require(value.get("stopped_receipt") == operating_custody._operating_receipt(record, owner.lease_id,
                    selector, env["QUALITY_OPERATING_CASE"], actual, policy, retained=True),
                    "finalization-operating-stopped-receipt-drift")
            require(set(value) == fields
                    and type(value["schema"]) is int and value["schema"] == 1
                    and value["kind"] == "operating-finalization-diagnostic" and value["binding"] == binding
                    and value["evidence_policy_complete"] is False and value["quality_pass"] is False
                    and value["spool"] == {"device": info.st_dev, "inode": info.st_ino}
                    and ledger.canonical(value) == raw, "finalization-operating-spool-binding")
            if not released:
                from . import engine_graph_prune
                require(value["diagnostics_sha256"] == engine_graph_prune._diagnostics(owner, start),
                        "finalization-operating-diagnostic-drift")
            return value["stopped_receipt"] if observation else hashlib.sha256(raw).hexdigest()
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
                and registry == owner.registry and selector == owner.selector
                and (cell_contract.revalidate_partial_preparation(owner, store)
                     if isinstance(owner, cell_contract.PartialPreparationOwner) else
                     cell_contract.owned_cell_for_cleanup(registry, selector, store, owner.lease_id) == owner),
                "finalization-root-drift")
        return config

    def _remote_delete(self, session, registry, selector, store, owner, cleanup, operation, target, kind, action):
        if type(owner) is cell_contract.PartialCertificateWithdrawal:
            require(operation == "certificate-revoke" and kind == "certificate", "partial-certificate-only")
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
            if isinstance(owner, cell_contract.PartialPreparationOwner):
                require(before["state"] == "required_fields_match", "partial-original-resource-disappeared")
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

    def withdraw_partial_preparation(self, registry, selector, store, lease_id):
        """Immediate original certificate withdrawal; no data/VM cleanup gate."""
        from . import root_session
        with root_session._session(self._runtime.preparation_config_path,
                                  self._runtime.preparation_config_sha256) as session:
            owner = cell_contract.partial_preparation_withdrawal_owner(registry, selector, store, lease_id)
            config = self._fresh(session, registry, selector, store, owner)
            if "fence-create" in owner.creators:
                record = store.read(lease_id)
                worker = ledger.Worker(**record["worker"])
                disable = _effect(record, "fence-disable", "fence:" + lease_id)
                if disable is None:
                    fence = cell_contract.owned_fence_for_cleanup(registry, selector, store, lease_id)
                    network_fence.disable(config.network_fence_policy_path, config.network_fence_policy_sha256,
                                          fence, store, worker, config)
                network_fence.verify_disabled(owner, store, worker, config)
            target = owner.incus
            fingerprint = owner.creator_targets.get("certificate-create", "").removeprefix("certificate:")
            client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path,
                target["project"], target["network"], "default", target["pool"],
                (fingerprint,) if fingerprint else ()))
            cleanup = incus_mutation.RootPartialPreparationCleanup(client, owner, store)
            if fingerprint:
                previous = _effect(store.read(lease_id), "certificate-revoke", owner.creator_targets["certificate-create"])
                if previous is None:
                    require(cleanup.certificate_inventory().fingerprints == (fingerprint,),
                            "partial-original-certificate-not-present")
                self._remote_delete(session, registry, selector, store, owner, cleanup, "certificate-revoke",
                    owner.creator_targets["certificate-create"], "certificate", cleanup.certificate_delete)
            else:
                require(cleanup.certificates_absent(), "partial-uncreated-certificate-scope-held")
            return {"lease_id": lease_id, "certificate_scope_absent": cleanup.certificates_absent(),
                    "native_acceptance": False}

    def _startup_scope(self, session, registry, selector, store, lease_id):
        from . import startup_retirement
        owner = cell_contract.partial_preparation_owner(registry, selector, store, lease_id)
        config = self._fresh(session, registry, selector, store, owner)
        record = store.read(lease_id)
        policy = store.read_policy(record["policy_sha256"])
        require(startup_retirement.pre_vm_archive_enabled(policy)
                and record.get("native_terminal", {}).get("conclusion") in startup_retirement.FAILURES
                and "partial_preparation_custody" not in record, "startup-retirement-unavailable")
        descriptor = identity.decode_json(owner.engine_descriptor_bytes)
        env = descriptor["environment"]
        profile, scenario, target = (env.get("QUALITY_INPUT_" + name)
                                     for name in ("PROFILE", "SCENARIO", "TARGET"))
        require(startup_retirement.pre_vm_cell_matches(policy, selector, profile, scenario, target),
                "startup-retirement-cell")
        return owner, config, record, policy, profile, scenario, target

    def archive_before_vm_authority(self, registry, selector, store, lease_id):
        """Archive the original Root failure with its authenticated terminal job."""
        from . import root_session, startup_retirement
        with root_session._session(self._runtime.preparation_config_path,
                                  self._runtime.preparation_config_sha256) as session:
            owner, config, record, *_ = self._startup_scope(session, registry, selector, store, lease_id)
            abort = startup_retirement.original_preparation_abort(store, lease_id, record)
            if abort is None:
                return None
            failure = {"schema": 1, "native_terminal_sha256": ledger.digest(record["native_terminal"]),
                       "root_abort": abort}
            inventory = startup_retirement.observe_before_context(owner, store, config)
            return startup_retirement.publish_original_archive(store, lease_id, record, failure, inventory)

    def retire_before_vm_authority(self, registry, selector, store, lease_id, archive_dir, archive_sha256):
        """Root-only retirement through the common finalizer with archived native proof."""
        from . import operating_custody, root_session, startup_retirement
        with root_session._session(self._runtime.preparation_config_path,
                                  self._runtime.preparation_config_sha256) as session:
            owner, config, record, policy, profile, scenario, target = self._startup_scope(
                session, registry, selector, store, lease_id)
            require(startup_retirement.private_archive_locator(store, lease_id) == (archive_dir, archive_sha256),
                    "startup-retirement-archive-locator")
            archive = startup_retirement.archived_original(archive_dir, archive_sha256, record)
            inventory = startup_retirement.observe_before_context(owner, store, config)
            observed_at = store._now()
            observations = {"original": ledger.digest(record), "inventory": ledger.digest(inventory),
                "at": observed_at, "startup_boundary": startup_retirement.START_BOUNDARY, "start_effect": None,
                "exclusive_ownership": True, "never_started_vm": True, "active_consumers": 0,
                "access_withdrawn": True}
            require(startup_retirement.effective_floor(record, policy, selector=selector, profile=profile,
                    scenario=scenario, target=target, archive=archive, observations=observations,
                    now=store._now()) == observed_at, "startup-retirement-native-gate")
            require(startup_retirement.archived_original(archive_dir, archive_sha256, record) == archive,
                    "startup-retirement-archive-drift")
            operating_custody._retain_partial_preparation(registry, selector, store, lease_id, pre_vm={
                "original_sha256": observations["original"], "observed_at": observed_at,
                "archive_sha256": archive["sha256"], "inventory_sha256": archive["inventory"]})
        return self.finalize_partial_preparation(registry, selector, store, lease_id)

    def verify_retired_before_vm_authority(self, registry, selector, store, lease_id, archive_dir):
        """Independently re-open the exact retired scope before recording absence."""
        from . import root_session, startup_retirement
        with root_session._session(self._runtime.preparation_config_path,
                                  self._runtime.preparation_config_sha256) as session:
            owner = cell_contract.partial_preparation_owner(registry, selector, store, lease_id)
            config = self._fresh(session, registry, selector, store, owner)
            record = store.read(lease_id)
            locator = self._pre_vm_archive(store, lease_id, record)
            require(locator is not None and locator[0] == archive_dir, "startup-retirement-archive-locator")
            expected = startup_retirement.observe_before_context(owner, store, config, closed=True)
            receipt = {"schema": 1, "lease_id": lease_id, "closed_record_sha256": ledger.digest(record),
                       "archive_sha256": locator[1], "resources": expected,
                       "native_acceptance": False}
            startup_retirement.publish_readback(archive_dir, receipt)
            return receipt

    def finalize_partial_preparation(self, registry, selector, store, lease_id):
        """One finite original no-engine failure lifecycle; never normal VM finalization."""
        from . import root_session, cleanup_storage, operating_custody
        self.withdraw_partial_preparation(registry, selector, store, lease_id)
        with root_session._session(self._runtime.preparation_config_path,
                                  self._runtime.preparation_config_sha256) as session:
            owner = cell_contract.partial_preparation_owner(registry, selector, store, lease_id)
            config = self._fresh(session, registry, selector, store, owner)
            record = store.read(lease_id)
            archived = self._pre_vm_archive(store, lease_id, record)
            policy = store.read_policy(record["policy_sha256"])
            require(policy["retention_seconds"] != 0 or archived is not None, "partial-zero-wait-original-archive")
            target = owner.incus
            fingerprint = owner.creator_targets.get("certificate-create", "").removeprefix("certificate:")
            client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path,
                target["project"], target["network"], "default", target["pool"],
                (fingerprint,) if fingerprint else ()))
            cleanup = incus_mutation.RootPartialPreparationCleanup(client, owner, store)
            require(cleanup.certificates_absent(), "partial-certificate-scope-live")
            if "project-create" in owner.creators and _effect(store.read(lease_id), "project-delete",
                    owner.creator_targets["project-create"]) is None:
                cleanup.quiet_project()
            cleanup_storage.reconcile_postchecks(session, owner, store, config, cleanup)
            operating_custody.require_partial_cleanup_allowed(store, lease_id)
            if "fence-create" in owner.creators:
                worker = ledger.Worker(**store.read(lease_id)["worker"])
                network_fence.remove(config.network_fence_policy_path, config.network_fence_policy_sha256,
                                     owner, store, worker, config)
            engine_executor._remove_slice(session, owner, store)
            if "engine-prepare" in owner.creators:
                cleanup_storage.release_engine(owner, store, config)
            if "context-create" in owner.creators:
                cleanup_storage.delete_context(owner, store, config)
            if "image-copy" in owner.creators:
                copied = owner.creator_targets["image-copy"]
                parent = _effect(store.read(lease_id), "project-delete", owner.creator_targets["project-create"])
                if parent is None:
                    self._remote_delete(session, registry, selector, store, owner, cleanup,
                        "image-delete", copied, "image", cleanup.image_delete)
                    cleanup.wait_quiet(config.operation_wait_seconds)
                else:
                    child = _effect(store.read(lease_id), "image-delete", copied)
                    require(parent[1]["state"] == "verified" and child is not None
                            and child[1]["state"] == "verified"
                            and cleanup.readback("project")["state"] == "absent_observed",
                            "partial-prior-image-or-project-held")
            for operation, creator, kind, action in (
                    ("project-delete", "project-create", "project", cleanup.project_delete),
                    ("network-delete", "network-create", "bridge", cleanup.bridge_delete)):
                if creator in owner.creators:
                    self._remote_delete(session, registry, selector, store, owner, cleanup,
                        operation, owner.creator_targets[creator], kind, action)
            self._fresh(session, registry, selector, store, owner)
            require(cleanup.certificates_absent(), "partial-certificate-returned")
            store.close(lease_id)
            record = store.read(lease_id)
            receipt = {"schema": 1, "state": "FAILED_PARTIAL_PREPARATION_CLOSED", "lease_id": lease_id,
                       "closed_at": record["closed_at"], "effects_sha256": ledger.digest(record["effects"]),
                       "partial_custody_sha256": ledger.digest(record["partial_preparation_custody"]),
                       "native_acceptance": False}
        # A readback has its own fresh Root session and can be recovered
        # independently from the closed ledger, without reissuing any effect.
        self.reconcile_pre_vm_readback(registry, selector, store, lease_id)
        return receipt

    @staticmethod
    def _pre_vm_archive(store, lease_id, record):
        from . import startup_retirement
        evidence = record.get("partial_preparation_custody", {}).get("pre_vm_retirement")
        if evidence is None:
            return None
        locator = startup_retirement.private_archive_locator(store, lease_id)
        require(locator is not None and locator[1] == evidence["archive_sha256"],
                "startup-retirement-archive-locator")
        startup_retirement.archived_original(*locator, record)
        return locator

    def reconcile_pre_vm_readback(self, registry, selector, store, lease_id):
        from . import startup_retirement
        record = store.read(lease_id)
        locator = self._pre_vm_archive(store, lease_id, record)
        if locator is not None and not startup_retirement.readback_confirmed(locator[0], lease_id, record,
                record["partial_preparation_custody"]["pre_vm_retirement"]):
            self.verify_retired_before_vm_authority(registry, selector, store, lease_id, locator[0])

    def _observe_failed_engine_without_vm(self, session, registry, selector, store, lease_id):
        """Read the post-engine failure boundary. This observation grants no cleanup authority."""
        from . import cleanup_storage, engine_graph_prune, operating_cells, policy_registry, startup_retirement

        owner = cell_contract.owned_cell_for_cleanup(registry, selector, store, lease_id)
        config = self._fresh(session, registry, selector, store, owner)
        record = store.read(lease_id)
        policy = startup_retirement._post_engine_opt_in(store, record, selector)
        immediate = ledger.G06_NO_WAIT_MARKER in policy
        env = identity.decode_json(owner.engine_descriptor_bytes)["environment"]
        profile, scenario, target_name = (env["QUALITY_INPUT_" + key] for key in ("PROFILE", "SCENARIO", "TARGET"))
        if immediate and profile == "operating":
            require(selector == operating_cells.selector(env["QUALITY_OPERATING_CASE"]), "failure-observation-cell")
        else:
            require((profile == "heavy" or immediate and profile == "application_acceptance")
                    and selector == policy_registry.profile_selector(profile, scenario, target_name),
                    "failure-observation-cell")
        observed_at = store._now()
        terminal = record.get("native_terminal")
        expected_start, _, _ = startup_retirement._post_engine_archive_inputs(lease_id, record, immediate=immediate)
        slice_creator = engine_executor._slice_creator(record)
        require(slice_creator is not None and slice_creator["state"] == "verified"
                and slice_creator["target"] == "slice:" + lease_id, "failure-observation-slice")
        slice_binding = slice_creator.get("engine_slice")
        ledger._validate_slice(slice_binding, record["worker"]["boot_id"])
        require(slice_creator["evidence_sha256"] == ledger.digest(slice_binding)
                and all(slice_binding[key] == expected_start["engine_capture"][key]
                        for key in ("cgroup_device", "cgroup_inode")), "failure-observation-slice")
        scope = set(owner.creators)
        required = scope | {"certificate-revoke", "engine-stop", "fence-disable", "slice-create"}
        operations = {row["operation"] for row in record["effects"].values()}
        renewal_prefixes = {"context-refresh": "context:" + record["cell_sha256"] + ":",
                            "fence-renew": "fence:" + lease_id + ":"}
        tokens = {row["token_id_sha256"] for row in record["authorizations"]}
        for row in record["effects"].values():
            prefix = renewal_prefixes.get(row["operation"])
            if prefix is not None:
                require(row["target"].startswith(prefix) and row["target"].removeprefix(prefix) in tokens,
                        "failure-observation-foreign-renewal")
        require(max(terminal["observed_at"], expected_start["engine_exit"]["observed_at"]) <= observed_at
                and record["state"] in {"prepared", "cancelled"}
                and not {"custody", "partial_preparation_custody", "owned_instance", "uploaded_evidence"} & record.keys()
                and record.get("upload_verification", {}).get("state") != "intent"
                and required <= operations <= required | renewal_prefixes.keys()
                and all(row["state"] == "verified" for row in record["effects"].values()),
                "failure-observation-unresolved")
        _, start = cleanup_storage._drain_engine(owner, store, config)
        require(start == expected_start and start["engine_exit"]["manifest_sha256"] == owner.engine_policy_sha256,
                "failure-observation-original-exit")
        capture = engine_graph_prune._diagnostics(owner, start)
        worker = ledger.Worker(**record["worker"])
        disabled = network_fence.verify_disabled(owner, store, worker, config)
        target = owner.incus
        cert = owner.creator_targets["certificate-create"]
        require(_effect(record, "certificate-revoke", cert) is not None, "failure-observation-cert-withdrawal")
        staged_image = operating_cells.uses_cached_vm_image(env)
        image_effect = owner.creators.get("image-copy")
        require((staged_image and image_effect is not None
                 and image_effect["target"] == "image:" + target["project"] + ":" + operating_cells.IMAGE)
                or not staged_image and image_effect is None, "failure-observation-image-scope")
        admin, cleanup = self._post_engine_transport(config, owner, store)
        before = self._post_engine_project_census(cleanup, admin, target, staged_image)
        native_census = cleanup_storage.observe_post_engine_consumers(owner, store, config, start)
        after = self._post_engine_project_census(cleanup, admin, target, staged_image)
        self._fresh(session, registry, selector, store, owner)
        require(before == after and store.read(lease_id) == record
                and engine_graph_prune._diagnostics(owner, start) == capture
                and network_fence.verify_disabled(owner, store, worker, config) == disabled
                and observed_at <= store._now() <= observed_at + startup_retirement.MAX_OBSERVATION_AGE,
                "failure-observation-drift")
        return {"lease_id": lease_id, "observed_at": observed_at, "original_sha256": ledger.digest(record),
                "terminal_sha256": ledger.digest(terminal), "policy_sha256": record["policy_sha256"],
                "scope_sha256": ledger.digest(target), "image_effect_sha256": image_effect["sha256"] if staged_image else None,
                "default_image_sha256": before["default_image_sha256"],
                "census_sha256": ledger.digest({"incus": before, "native": native_census,
                                                "capture": capture, "fence": disabled})}

    @staticmethod
    def _post_engine_transport(config, owner, store):
        target = owner.incus
        fingerprint = owner.creator_targets["certificate-create"].removeprefix("certificate:")
        admin = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path,
            target["project"], target["network"], "default", target["pool"], (fingerprint,), target["instance"]))
        return admin, incus_mutation.RootIncusCleanup(admin, owner, store)

    @staticmethod
    def _post_engine_project_census(cleanup, admin, target, staged_image):
        profile = cleanup.readback("profile")
        require(cleanup.certificates_absent() and profile["state"] == "required_fields_match",
                "failure-observation-scope")
        scope = {
            "project": ledger.digest(cleanup._verify_delete_scope("project", staged_image=staged_image)),
            "bridge": ledger.digest(cleanup._verify_delete_scope("bridge")),
            "profile": profile["metadata_sha256"],
        }
        image = cleanup.readback("image")
        require(image["state"] == ("required_fields_match" if staged_image else "absent_observed"),
                "failure-observation-image-scope")
        scope["default_image_sha256"] = cleanup._default_cached_image_identity() if staged_image else None
        require(all(type(row.get("project")) is str and row["project"] != target["project"]
                    for row in admin.pool_volumes()), "failure-observation-volumes")
        return scope | {"quiet": cleanup.quiet_project(), "image": image}

    def prepare_post_engine_permit(self, registry, selector, store, lease_id):
        """Issue or recover the private preflight evidence for an opted-in POC failure."""
        from . import operating_custody, root_session, startup_retirement

        require(os.geteuid() == 0 and type(store) is ledger.Ledger and store.owner_uid == 0,
                "post-engine-permit-root")
        with root_session._session(self._runtime.preparation_config_path,
                                   self._runtime.preparation_config_sha256) as session:
            owner = cell_contract.owned_cell_for_cleanup(registry, selector, store, lease_id)
            config = self._fresh(session, registry, selector, store, owner)
            record = store.read(lease_id)
            startup_retirement._post_engine_opt_in(store, record, selector)
            archive = startup_retirement._post_engine_archive_path(owner)
            quota_directory = archive if os.path.lexists(archive) else archive.parent
            with startup_retirement._post_engine_evidence_quota(config, quota_directory):
                existing = startup_retirement._locate_post_engine_permit(store, lease_id, archive)
                if existing is not None:
                    require(existing["policy_sha256"] == record["policy_sha256"]
                            and existing["scope_sha256"] == ledger.digest(owner.incus), "post-engine-permit-resume-scope")
                    require(quota_directory == archive, "post-engine-permit-archive-missing")
                    return startup_retirement._confirm_durable_post_engine_permit(store, lease_id, existing, archive)
            if {"owned_instance", "custody"} & record.keys():
                return None
            admin, cleanup = self._post_engine_transport(config, owner, store)
            if admin.instances():
                project = cleanup.readback("project")
                require(project["state"] == "required_fields_match", "post-engine-permit-vm-project")
                proof = operating_custody.observe_owned_instance(config, registry, selector, store, lease_id)
                operating_custody.require_instance_proof(proof, lease_id, record)
                require(cleanup.readback("project") == project and store.read(lease_id) == record,
                        "post-engine-permit-vm-drift")
                return None
            observation = self._observe_failed_engine_without_vm(session, registry, selector, store, lease_id)
            return startup_retirement._publish_post_engine_permit(session, owner, store, observation)

    def _release_owned_resources(self, session, store, owner, config, cleanup, project_deleted, image_target, *,
                                 private_archive=None):
        from . import cleanup_storage

        registry, selector, lease_id = owner.registry, owner.selector, owner.lease_id
        target = owner.incus
        worker = ledger.Worker(**store.read(lease_id)["worker"])
        cleanup_storage.release_engine(owner, store, config, private_archive=private_archive)
        self._fresh(session, registry, selector, store, owner)
        cleanup_storage.delete_context(owner, store, config, private_archive=private_archive)
        if image_target is not None and project_deleted is None:
            self._remote_delete(session, registry, selector, store, owner, cleanup, "image-delete",
                image_target, "image", cleanup.image_delete)
            # A terminal own task can still appear in Incus's task listing.
            cleanup.wait_quiet(config.operation_wait_seconds)
        self._remote_delete(session, registry, selector, store, owner, cleanup, "project-delete",
            "project:" + target["project"], "project", cleanup.project_delete)
        require(cleanup.readback("profile")["state"] == "absent_observed", "finalization-default-profile-returned")
        self._remote_delete(session, registry, selector, store, owner, cleanup, "network-delete",
            "network:default:" + target["network"], "bridge", cleanup.bridge_delete)
        self._fresh(session, registry, selector, store, owner)
        network_fence.remove(config.network_fence_policy_path, config.network_fence_policy_sha256,
                             owner, store, worker, config)
        engine_executor._remove_slice(session, owner, store)
        self._fresh(session, registry, selector, store, owner)
        require(cleanup.certificates_absent() is True, "finalization-certificate-returned")
        require(cleanup.readback("project")["state"] == "absent_observed"
                and cleanup.readback("bridge")["state"] == "absent_observed", "finalization-resource-returned")

    def _post_engine_scope(self, session, registry, selector, store, lease_id, permit_sha256):
        from . import startup_retirement

        owner = cell_contract.owned_cell_for_cleanup(registry, selector, store, lease_id)
        config = self._fresh(session, registry, selector, store, owner)
        archive = startup_retirement._post_engine_archive_path(owner)
        with startup_retirement._post_engine_evidence_quota(config, archive):
            permit = startup_retirement._read_post_engine_permit(store, lease_id, permit_sha256, archive)
            progress = startup_retirement._read_post_engine_cleanup_journal(
                store, lease_id, permit["archive_sha256"], archive, complete=False)
        require(progress["original_sha256"] == permit["original_sha256"], "post-engine-permit-original-drift")
        record = store.read(lease_id)
        startup_retirement._post_engine_opt_in(store, record, selector)
        require(ledger.digest(record) == progress["journal_sha256"]
                and permit["scope_sha256"] == ledger.digest(owner.incus)
                and permit["policy_sha256"] == record["policy_sha256"], "post-engine-cleanup-journal-drift")
        target = owner.incus
        fingerprint = owner.creator_targets["certificate-create"].removeprefix("certificate:")
        admin = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path,
            target["project"], target["network"], "default", target["pool"], (fingerprint,), target["instance"]))
        return permit, progress, record, owner, config, incus_mutation.RootIncusCleanup(admin, owner, store)

    def _check_post_engine_resume(self, owner, record, cleanup, project_deleted, image_target):
        target = owner.incus
        image_deleted = None if image_target is None else _effect(record, "image-delete", image_target)
        if project_deleted is None:
            staged_image = image_target is not None and image_deleted is None
            cleanup._verify_delete_scope("project", staged_image=staged_image)
            require(cleanup.readback("profile")["state"] == "required_fields_match", "post-engine-profile-drift")
            if image_target is not None:
                expected = "required_fields_match" if staged_image else "absent_observed"
                require(cleanup.readback("image")["state"] == expected, "post-engine-image-drift")
        else:
            require((image_target is None or image_deleted is not None)
                    and all(cleanup.readback(kind)["state"] == "absent_observed" for kind in ("project", "profile")),
                    "post-engine-deleted-project-returned")
        if _effect(record, "network-delete", "network:default:" + target["network"]) is None:
            cleanup._verify_delete_scope("bridge")
        else:
            require(cleanup.readback("bridge")["state"] == "absent_observed", "post-engine-deleted-bridge-returned")
        require(all(type(row.get("project")) is str and row["project"] != target["project"]
                    for row in cleanup._client.pool_volumes()), "post-engine-pool-volume-returned")

    @staticmethod
    def _check_post_engine_default_image(record, cleanup, permit):
        expected = permit.get("default_image_sha256")
        if any(row["operation"] == "image-copy" for row in record["effects"].values()):
            require(type(expected) is str and ledger.HEX.fullmatch(expected)
                    and cleanup._default_cached_image_identity() == expected, "post-engine-default-image-drift")
        else:
            require(expected is None, "post-engine-default-image-unbound")
        return expected

    def finalize_post_engine_failure(self, registry, selector, store, lease_id, permit_sha256):
        """Remove exact owned resources under the previously sealed POC permit. Keep the lease open."""
        from . import cleanup_storage, root_session, startup_retirement

        attempted = False
        try:
            with root_session._session(self._runtime.preparation_config_path,
                                       self._runtime.preparation_config_sha256) as session:
                permit, progress, record, owner, config, cleanup = self._post_engine_scope(
                    session, registry, selector, store, lease_id, permit_sha256)
                worker = ledger.Worker(**record["worker"])
                require(cleanup.certificates_absent() is True, "post-engine-certificate-returned")
                network_fence.verify_disabled(owner, store, worker, config)
                project_deleted = _effect(record, "project-delete", "project:" + owner.incus["project"])
                copies = [effect["target"] for effect in record["effects"].values() if effect["operation"] == "image-copy"]
                image_target = copies[0] if copies else None
                archive = startup_retirement._post_engine_archive_path(owner)
                if project_deleted is None:
                    cleanup.wait_quiet(config.operation_wait_seconds)
                if progress["cleanup_started"]:
                    self._check_post_engine_resume(owner, record, cleanup, project_deleted, image_target)
                    self._check_post_engine_default_image(record, cleanup, permit)
                    cleanup_storage._reconcile_verified_postchecks(session, owner, store, config, cleanup,
                                                                   private_archive=archive)
                else:
                    observation = self._observe_failed_engine_without_vm(session, registry, selector, store, lease_id)
                    startup_retirement._require_post_engine_observation(permit, observation, store._now())
                require(startup_retirement._read_post_engine_permit(store, lease_id, permit_sha256, archive) == permit
                        and store.read(lease_id) == record, "post-engine-authorization-drift")
                attempted = True
                self._release_owned_resources(session, store, owner, config, cleanup, project_deleted, image_target,
                                              private_archive=archive)
                return startup_retirement._read_post_engine_cleanup_journal(store, lease_id, permit["archive_sha256"], archive)
        except FinalizationUnknown:
            raise
        except Exception:
            if attempted:
                raise FinalizationUnknown("post-engine-cleanup-held") from None
            raise FinalizationDenied("post-engine-cleanup-denied") from None

    def _post_engine_absence(self, session, registry, selector, store, lease_id, permit_sha256):
        from . import cleanup_storage, startup_retirement

        permit, _, record, owner, config, cleanup = self._post_engine_scope(
            session, registry, selector, store, lease_id, permit_sha256)
        for operation in ("engine-release", "context-delete"):
            rows = [effect for effect in record["effects"].values() if effect["operation"] == operation]
            require(len(rows) == 1 and "cleanup_postcheck" in rows[0] and "cleanup_observation" in rows[0],
                    "post-engine-independent-storage-witness-required")
        archive = startup_retirement._post_engine_archive_path(owner)
        cleanup_storage._reconcile_verified_postchecks(session, owner, store, config, cleanup, refresh=True,
                                                       private_archive=archive)
        journal = startup_retirement._read_post_engine_cleanup_journal(store, lease_id, permit["archive_sha256"], archive)
        resources = {kind: cleanup.readback(kind) for kind in ("project", "profile", "bridge")}
        require(all(row["state"] == "absent_observed" for row in resources.values())
                and cleanup.certificates_absent() is True, "post-engine-incus-scope-returned")
        volumes = cleanup._client.pool_volumes()
        require(all(type(row.get("project")) is str and row["project"] != owner.incus["project"] for row in volumes),
                "post-engine-pool-volume-returned")
        worker = ledger.Worker(**record["worker"])
        fence = network_fence.verify_disabled(owner, store, worker, config)
        engine_executor._slice_inactive(lease_id)
        default_image = self._check_post_engine_default_image(record, cleanup, permit)
        self._fresh(session, registry, selector, store, owner)
        require(startup_retirement._read_post_engine_permit(store, lease_id, permit_sha256, archive) == permit
                and store.read(lease_id) == record, "post-engine-readback-journal-drift")
        return {**journal, "state": "verified-absence", "permit_sha256": permit_sha256,
                "resources_sha256": ledger.digest({"incus": resources, "certificate_scope_absent": True,
                    "project_volumes": [], "fence": fence, "slice": "absent", "local_consumer_census": "verified",
                    "default_image_sha256": default_image})}

    def readback_post_engine_failure(self, registry, selector, store, lease_id, permit_sha256):
        """Acquire fresh Root-only provider and consumer evidence without changing the lease."""
        from . import root_session, startup_retirement

        with root_session._session(self._runtime.preparation_config_path,
                                   self._runtime.preparation_config_sha256) as session:
            receipt = self._post_engine_absence(session, registry, selector, store, lease_id, permit_sha256)
            digest = startup_retirement._publish_post_engine_readback(store, lease_id, receipt)
            return {**receipt, "readback_sha256": digest}

    def close_post_engine_failure(self, registry, selector, store, lease_id, permit_sha256, readback_sha256):
        """Close only after the separately persisted absence agrees with a fresh repeat."""
        from . import root_session, startup_retirement

        with root_session._session(self._runtime.preparation_config_path,
                                   self._runtime.preparation_config_sha256) as session:
            receipt = startup_retirement._read_post_engine_readback(store, lease_id, readback_sha256)
            observed = self._post_engine_absence(session, registry, selector, store, lease_id, permit_sha256)
            require(observed == receipt == startup_retirement._read_post_engine_readback(store, lease_id, readback_sha256)
                    and ledger.digest(store.read(lease_id)) == receipt["journal_sha256"], "post-engine-closure-held")
            store.close(lease_id)
            record = store.read(lease_id)
            require(record["state"] == "closed", "post-engine-close-not-observed")
            return {"schema": 1, "state": "FAILED_POST_ENGINE_CLOSED", "lease_id": lease_id,
                    "closed_at": record["closed_at"], "readback_sha256": readback_sha256, "native_acceptance": False}

    def finalize(self, registry, selector, store, lease_id):
        """Explicit Root call, serialized; no effect retry or job acceptance.

        Sanitized evidence must already survive in a separately bounded Root
        spool. Raw context/engine storage is never retained as a success waiver.
        """
        require(os.geteuid() == 0, "finalization-root-required")
        from . import root_session, cleanup_storage, evidence_export, emergency_stop, operating_custody, startup_retirement
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
                policy = store.read_policy(record["policy_sha256"])
                private_archive = None
                if descriptor["environment"].get("QUALITY_INPUT_PROFILE") == "operating":
                    evidence_sha = _operating_evidence(self._runtime, registry, selector, store, owner, record,
                                                      session=session, released=raw_released is not None)
                    if policy["retention_seconds"] == 0:
                        private_archive = startup_retirement._post_engine_archive_path(owner)
                elif policy["retention_seconds"] == 0 and not operating_custody.require_cleanup_allowed(store, lease_id):
                    private_archive, evidence_sha = startup_retirement.preserve_custody_failure(
                        session, owner, store, record, released=raw_released is not None)
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
                copies = [row for row in record["effects"].values() if row["operation"] == "image-copy"]
                if copies or operating_cells.uses_cached_vm_image(descriptor["environment"]):
                    require(len(copies) == 1 and copies[0]["state"] == "verified"
                            and copies[0]["target"] == "image:" + target["project"] + ":" + operating_cells.IMAGE,
                            "finalization-image-copy-held")
                if project_deleted is not None:
                    # A verified parent deletion makes scoped child inventories
                    # unavailable. Fresh parent absence and exact original child
                    # deletion receipts are required, never a generic404 waiver.
                    require(project_deleted[1]["state"] == "verified"
                            and cleanup.readback("project")["state"] == "absent_observed",
                            "finalization-deleted-project-returned")
                    if "owned_instance" in record:
                        child = _effect(record, "instance-destroy",
                            "instance:" + target["project"] + ":" + target["instance"])
                        require(child is not None and child[1]["state"] == "verified",
                                "finalization-prior-instance-held")
                    if copies:
                        child = _effect(record, "image-delete", copies[0]["target"])
                        require(child is not None and child[1]["state"] == "verified",
                                "finalization-prior-image-held")
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
                if project_deleted is None and store.read(lease_id).get("owned_instance") is not None:
                    self._remote_delete(session, registry, selector, store, owner, cleanup, "instance-destroy",
                        "instance:" + target["project"] + ":" + target["instance"], "instance", cleanup.instance_delete)
                if project_deleted is None:
                    cleanup.wait_quiet(config.operation_wait_seconds)
                if private_archive is None:
                    cleanup_storage.reconcile_postchecks(session, owner, store, config, cleanup)
                else:
                    cleanup_storage._reconcile_verified_postchecks(
                        session, owner, store, config, cleanup, private_archive=private_archive)
                image_target = copies[0]["target"] if copies else None
                self._release_owned_resources(session, store, owner, config, cleanup, project_deleted, image_target,
                                              private_archive=private_archive)
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
