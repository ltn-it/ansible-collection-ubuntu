"""Serialized Root-only single-cell preparation; no listener or execution.

This internal component is NOT an activatable service/operating grant. Real
package/binary provenance, capacity/headroom, private network hard expiry and
accepted custody/window remain mandatory before its future trusted caller may
invoke effects. Incus's version/extension response does not prove those facts.
The one exported lock serializes preparation; future refresh/recovery dispatch
MUST acquire the same lock (the current admission bridge does not yet do so).
Unknown or previous journal effects are retained and never retried/adopted.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import PurePosixPath
import stat
import time

from . import (cell_contract, context_materializer, context_publisher, engine_policy,
               identity, incus_admin, incus_mutation, installation, ledger, policy_registry, signed_context)
from .identity import Denied, require


class PreparationDenied(Denied):
    """Preflight denied before any new durable effect attempt."""


class PreparationUnknown(Denied):
    """Retained effects need explicit Root reconciliation; never retry here."""


@dataclass(frozen=True)
class RootConfiguration:
    path: str
    sha256: str
    registry_path: str
    registry_sha256: str
    incus_socket_path: str
    signing_key_path: str
    signing_public_key: bytes
    publication_staging_parent: str
    lock_path: str
    operation_wait_seconds: int
    network_fence_policy_path: str
    network_fence_policy_sha256: str
    storage_quota_policy_path: str
    storage_quota_policy_sha256: str
    host_api_fence_policy_path: str
    host_api_fence_policy_sha256: str


@dataclass(frozen=True)
class PreparationReceipt:
    lease_id: str
    cell_sha256: str
    engine_policy_sha256: str
    binding_sha256: str
    expires_at: int


def _config(path, expected):
    require(os.geteuid() == 0, "preparation-root-required")
    proof, raw, stamp = installation._file(engine_policy._path(path), 16384, private=True, keep=True)
    require(proof.sha256 == engine_policy._hash(expected), "preparation-config-drift")
    data = identity.decode_json(raw)
    engine_policy._keys(data, {"schema", "registry_path", "registry_sha256", "incus_socket_path", "signing_key_path",
                               "signing_public_key_hex", "publication_staging_parent", "lock_path", "operation_wait_seconds",
                               "network_fence_policy_path", "network_fence_policy_sha256",
                               "storage_quota_policy_path", "storage_quota_policy_sha256",
                               "host_api_fence_policy_path", "host_api_fence_policy_sha256"})
    require(type(data["schema"]) is int and data["schema"] == 1, "preparation-config-schema")
    for key in ("registry_path", "incus_socket_path", "signing_key_path", "publication_staging_parent", "lock_path", "network_fence_policy_path", "storage_quota_policy_path", "host_api_fence_policy_path"):
        engine_policy._path(data[key])
    engine_policy._hash(data["registry_sha256"])
    public = bytes.fromhex(engine_policy._hash(data["signing_public_key_hex"]))
    signed_context._public(public)
    wait = engine_policy._integer(data["operation_wait_seconds"], 1, 60)
    fence_hash = engine_policy._hash(data["network_fence_policy_sha256"])
    fence, _, _ = installation._file(data["network_fence_policy_path"], 8192, private=True, keep=True)
    require(fence.sha256 == fence_hash, "preparation-fence-policy-drift")
    quota_hash = engine_policy._hash(data["storage_quota_policy_sha256"])
    quota, _, _ = installation._file(data["storage_quota_policy_path"], 16384, private=True, keep=True)
    require(quota.sha256 == quota_hash, "preparation-quota-policy-drift")
    host_hash = engine_policy._hash(data["host_api_fence_policy_sha256"])
    host, _, _ = installation._file(data["host_api_fence_policy_path"], 8192, private=True, keep=True)
    require(host.sha256 == host_hash, "preparation-host-api-policy-drift")
    return RootConfiguration(path, expected, data["registry_path"], data["registry_sha256"], data["incus_socket_path"],
                             data["signing_key_path"], public, data["publication_staging_parent"], data["lock_path"], wait,
                             data["network_fence_policy_path"], fence_hash,
                             data["storage_quota_policy_path"], quota_hash,
                             data["host_api_fence_policy_path"], host_hash), proof, stamp


@contextmanager
def preparation_lock(root_config_path, expected_config_sha256):
    """Root factory lock, also required around future refresh dispatch.

    Lock file must already exist, Root0600 beneath a private Root0700 parent.
    No initialization, lock replacement or blocking wait is performed here.
    """
    lock = parent = None
    try:
        config, proof, stamp = _config(root_config_path, expected_config_sha256)
        parent = engine_policy._directory(str(PurePosixPath(config.lock_path).parent), private=True)
        lock = os.open(PurePosixPath(config.lock_path).name, installation.FILE_FLAGS, dir_fd=parent)
        before = os.fstat(lock)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size == 0, "preparation-lock-file")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = os.stat(PurePosixPath(config.lock_path).name, dir_fd=parent, follow_symlinks=False)
        require(installation._stamp(current) == installation._stamp(before), "preparation-lock-drift")
        again, after, after_stamp = _config(root_config_path, expected_config_sha256)
        require(again == config and after == proof and after_stamp == stamp, "preparation-config-drift")
        yield config
    finally:
        if lock is not None:
            os.close(lock)
        if parent is not None:
            os.close(parent)


def _fresh(config, prepared, store):
    require(_config(config.path, config.sha256)[0] == config, "preparation-config-drift")
    require(cell_contract.prepare_cell(prepared.registry, prepared.selector, store, prepared.lease_id) == prepared,
            "preparation-cell-drift")


def _typed(prepared, config, certificate=None):
    value = prepared.incus
    owner = incus_mutation.Ownership(**value["ownership"])
    project = incus_mutation.ProjectSpec(value["project"], value["network"], value["pool"],
                                         incus_mutation.ProjectLimits(**value["project_limits"]), owner)
    bridge = incus_mutation.BridgeSpec(value["network"], value["ipv4_address"], value["dns_domain"], owner)
    fingerprints = () if certificate is None else (hashlib.sha256(certificate.der).hexdigest(),)
    target = incus_admin.AdminTarget(config.incus_socket_path, value["project"], value["network"], "default",
                                     value["pool"], fingerprints)
    return incus_mutation.RootIncusMutator(incus_admin.RootIncusAdmin(target), project, bridge, certificate)


def _unknown(store, prepared, effect, stage):
    if effect is not None:
        try:
            store.record(prepared.lease_id, effect, "unknown",
                         evidence_sha256=ledger.digest({"prepared": prepared.sha256, "stage": stage}))
        except Exception:
            pass  # A retained intent/verified commit is never repaired or replayed.


def _remote(config, prepared, store, mutator, operation, target, kind, action):
    _fresh(config, prepared, store)
    if kind != "profile":
        require(mutator.readback(kind)["state"] == "absent_observed", "preparation-resource-exists")
    effect = None
    try:
        effect = store.begin(prepared.lease_id, operation, target)
        if kind == "certificate":
            require(operation == "certificate-create", "preparation-certificate-stage")
            baseline = mutator.certificate_scope_baseline()
            require(type(baseline) is incus_mutation.CertificateScopeBaseline
                    and target == "certificate:" + baseline.initial_fingerprint,
                    "preparation-certificate-scope")
            store.bind_certificate_scope(prepared.lease_id, effect,
                initial_fingerprint=baseline.initial_fingerprint, certificate_name=baseline.certificate_name,
                project=baseline.project, baseline_inventory_sha256=baseline.baseline_inventory_sha256,
                authorizer_profile=baseline.authorizer_profile)
        receipt = action()
        require(type(receipt) is incus_mutation.MutationReceipt and receipt.operation == operation
                and receipt.target == target, "preparation-native-receipt")
        if receipt.response == "operation_pending":
            store.bind_native_operation(prepared.lease_id, effect, receipt.operation_id)
            _wait_operation(config, prepared, store, mutator, receipt)
        else:
            require(receipt.response == "sync_received", "preparation-native-receipt")
        observed = mutator.readback(kind)
        require(observed["state"] == "required_fields_match", "preparation-native-readback")
        _fresh(config, prepared, store)
        store.record(prepared.lease_id, effect, "verified", evidence_sha256=ledger.digest({
            "prepared": prepared.sha256, "operation": operation, "target": target,
            "native_operation_id": receipt.operation_id, "readback": observed}))
    except Exception:
        _unknown(store, prepared, effect, operation)
        raise PreparationUnknown("preparation-unknown") from None


def _wait_operation(config, prepared, store, mutator, receipt):
    """Poll the same native operation, never resend its mutation.

    The monotonic allowance does not renew lease/JWT/native-job budgets. An
    existing individual GET has its own maximum five-second transport timeout;
    it can return after this smaller allowance, which is then UNKNOWN, never
    success or permission for a later effect. Whole-job feasibility is unproven.
    """
    deadline = time.monotonic() + config.operation_wait_seconds
    while True:
        _fresh(config, prepared, store)
        require(time.monotonic() < deadline, "preparation-operation-timeout")
        observed = mutator.operation_readback(receipt)
        _fresh(config, prepared, store)
        require(time.monotonic() < deadline, "preparation-operation-timeout")
        if observed["state"] == "success_requires_resource_readback":
            return
        require(observed["state"] == "pending", "preparation-operation-failed")
        remaining = deadline - time.monotonic()
        require(remaining > 0, "preparation-operation-timeout")
        time.sleep(min(0.05, remaining))


def _engine_directories(config, prepared, store):
    _fresh(config, prepared, store)
    descriptor = identity.decode_json(prepared.engine_descriptor_bytes)
    paths = (descriptor["engine"]["storage_root"], descriptor["engine"]["runroot"], descriptor["output_path"])
    parents, effect = [], None
    try:
        for path in paths:
            name = PurePosixPath(path).name
            fd = engine_policy._directory(str(PurePosixPath(path).parent), private=True)
            parents.append((path, fd, name))
            try:
                os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise Denied("preparation-engine-directory-exists")
        effect = store.begin(prepared.lease_id, "engine-prepare", "engine:" + prepared.lease_id)
        receipts = []
        for path, fd, name in parents:
            os.mkdir(name, 0o700, dir_fd=fd)
            child = os.open(name, installation.DIR_FLAGS, dir_fd=fd)
            try:
                os.fchmod(child, 0o700)
                os.fsync(child)
                os.fsync(fd)
                proof = os.fstat(child)
                require(proof.st_uid == 0 and stat.S_IMODE(proof.st_mode) == 0o700 and not os.listdir(child),
                        "preparation-engine-directory")
                actual = engine_policy._directory(path, private=True)
                try:
                    require((os.fstat(actual).st_dev, os.fstat(actual).st_ino) == (proof.st_dev, proof.st_ino),
                            "preparation-engine-directory-drift")
                finally:
                    os.close(actual)
                receipts.append({"path": path, "device": proof.st_dev, "inode": proof.st_ino})
            finally:
                os.close(child)
        _fresh(config, prepared, store)
        store.record(prepared.lease_id, effect, "verified", evidence_sha256=ledger.digest({
            "prepared": prepared.sha256, "directories": receipts}))
    except Exception:
        _unknown(store, prepared, effect, "engine-prepare")
        raise PreparationUnknown("preparation-unknown") from None
    finally:
        for _, fd, _ in parents:
            os.close(fd)


def _bridge_facts_readback(config, prepared, store, transport):
    _fresh(config, prepared, store)
    require(transport.readback("bridge")["state"] == "required_fields_match", "preparation-bridge-facts-drift")
    require(transport.readback("project")["state"] == "required_fields_match"
            and transport.readback("profile")["state"] == "required_fields_match", "preparation-storage-facts-drift")
    _fresh(config, prepared, store)
    return signed_context.runtime_for_cell(prepared)


def _publish(config, prepared, store, signer, manifest, materialized, transport):
    _fresh(config, prepared, store)
    runtime = _bridge_facts_readback(config, prepared, store, transport)
    selected = prepared.registry.select(prepared.selector)
    record = store.read(prepared.lease_id)
    worker = ledger.Worker(**record["worker"])
    details = identity.decode_json(prepared.canonical_bytes)
    policy = signed_context.ContextPolicy(selected.identity, prepared.incus["server"], prepared.incus["project"],
                                          prepared.expires_at, prepared.cell_sha256, selected.custody_policy_sha256,
                                          details["controller"]["archive_sha256"], manifest.image_index_sha256, manifest.sha256,
                                          expected_runtime=ledger.canonical(runtime))
    publisher = context_publisher.RootContextPublisher(signer, config.signing_public_key, materialized.context_path,
                                                        config.publication_staging_parent)
    old = dict(materialized.files)["binding.json"]
    effect = None
    try:
        effect = store.begin(prepared.lease_id, "context-publish", "context:" + prepared.cell_sha256)
        outcome = publisher.publish(store, prepared.lease_id, worker, policy, expected_old_binding_sha256=old)
        raw, proof = signed_context._sealed(materialized.context_path + "/binding.json", 32768)
        binding = identity.decode_json(raw)
        require(outcome == {"binding_sha256": proof.sha256}, "preparation-publication-readback")
        signed_context.verify(binding["admission"], config.signing_public_key, store, prepared.lease_id,
                              worker, policy, binding, materialized.context_path)
        require(_bridge_facts_readback(config, prepared, store, transport) == runtime,
                "preparation-bridge-facts-drift")
        store.record(prepared.lease_id, effect, "verified", evidence_sha256=ledger.digest({
            "prepared": prepared.sha256, "binding_sha256": proof.sha256, "engine_policy_sha256": manifest.sha256}))
        return proof.sha256
    except Exception:
        _unknown(store, prepared, effect, "context-publish")
        raise PreparationUnknown("preparation-unknown") from None


def prepare(root_config_path, expected_config_sha256, registry, selector, store, lease_id):
    """Public Root wrapper; the private core requires an actually owned session."""
    require(os.geteuid() == 0, "preparation-root-required")
    from . import root_session
    try:
        with root_session._session(root_config_path, expected_config_sha256) as session:
            return _prepare_locked(session, registry, selector, store, lease_id)
    except PreparationUnknown:
        raise
    except Exception:
        raise PreparationDenied("preparation-denied") from None


def _prepare_locked(session, registry, selector, store, lease_id):
    from . import root_session
    config = root_session._require_session(session)
    started = False
    try:
        require(type(registry) is policy_registry.Registry and registry.path == config.registry_path
                and registry.sha256 == config.registry_sha256, "preparation-registry")
        prepared = cell_contract.prepare_cell(registry, selector, store, lease_id)
        require(not store.read(lease_id)["effects"], "preparation-previous-attempt")
        descriptor = identity.decode_json(prepared.engine_descriptor_bytes)
        require(descriptor["limits"]["timeout_seconds"] <= prepared.expires_at - int(time.time()),
                "preparation-engine-start-budget")
        # Validate the actual provisioned key before any remote/local effect.
        signer = signed_context.RootSigner(config.signing_key_path, config.signing_public_key)
        stage = engine_policy._directory(config.publication_staging_parent, private=True)
        os.close(stage)
        transport = _typed(prepared, config)
        target = prepared.incus
        _remote(config, prepared, store, transport, "network-create", "network:default:" + target["network"],
                "bridge", transport.bridge_create)
        started = True
        _remote(config, prepared, store, transport, "project-create", "project:" + target["project"],
                "project", transport.project_create)
        _remote(config, prepared, store, transport, "profile-configure", "profile:" + target["project"] + ":default",
                "profile", transport.configure_default_profile)
        _fresh(config, prepared, store)
        _bridge_facts_readback(config, prepared, store, transport)
        materialized = context_materializer.materialize(prepared, store)
        certificate = incus_mutation.CertificateSpec("lit-lease-" + lease_id, target["project"],
                                                      materialized.certificate_der, prepared.expires_at)
        transport = _typed(prepared, config, certificate)
        _remote(config, prepared, store, transport, "certificate-create", "certificate:" + materialized.certificate_fingerprint_sha256,
                "certificate", transport.certificate_create)
        _engine_directories(config, prepared, store)
        manifest = engine_policy.compile_engine_policy(prepared.engine_descriptor_path, prepared.engine_descriptor_sha256)
        cell_contract.bind_engine(prepared, store, manifest)
        binding = _publish(config, prepared, store, signer, manifest, materialized, transport)
        return PreparationReceipt(lease_id, prepared.cell_sha256, manifest.sha256, binding, prepared.expires_at)
    except Exception as error:
        if started or isinstance(error, PreparationUnknown):
            raise PreparationUnknown("preparation-unknown") from None
        raise PreparationDenied("preparation-denied") from None
