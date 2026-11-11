"""Serialized Root refresh -> signed publication -> bounded network renewal.

This internal factory is not a dispatcher, operating grant or live service.
All cooperating Root admission/recovery/cancel callers must use the same
preparation lock; their integration remains separate. No socket refeed, supplied
Worker, caller policy, automatic retry, rollback or hard-deadline extension.
The durable authorization append can precede a process crash before publication
intent; its consumed nonce/JTI and original context remain Root reconciliation
evidence, never permission to replay that request or renew the old context.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import os

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import (admission, cell_contract, context_publisher, engine_policy, identity, incus_mutation,
               ledger, network_fence, policy_registry, preparation, signed_context)
from .identity import Denied, require


class RefreshDenied(Denied):
    """No authorization/publication/network change observed from this call."""


class RefreshUnknown(Denied):
    """Retained authorization/effect state requires explicit Root readback."""


@dataclass(frozen=True)
class RefreshReceipt:
    lease_id: str
    expires_at: int
    binding_sha256: str
    authorization_sha256: str


def _old_context(policy, lease_id):
    """Root CAS bytes only, not authority from an old possibly expired JWT."""
    value, _, _ = cell_contract._sealed(policy.cell_config_path, policy.cell_sha256)
    paths = value["engine"]["paths"]
    context = engine_policy._path(paths["context"]) + "/" + lease_id
    descriptor = engine_policy._path(paths["descriptor"]) + "/" + lease_id + ".json"
    raw, proof = signed_context._sealed(context + "/binding.json", 32768)
    body = identity.decode_json(raw)
    signed_context._projection(body)
    engine_raw, engine_proof = signed_context._sealed(descriptor, cell_contract.MAX_CELL)
    return context, proof.sha256, descriptor, engine_raw, engine_proof.sha256


def _same_worker(connected, policy, expected):
    worker = admission._worker(connected, policy)
    require(asdict(worker) == expected, "refresh-worker-drift")
    return worker


def _context_policy(prepared, selected, manifest):
    details = identity.decode_json(prepared.canonical_bytes)
    return signed_context.ContextPolicy(
        selected.identity, prepared.incus["server"], prepared.incus["project"], prepared.expires_at,
        prepared.cell_sha256, selected.custody_policy_sha256, details["controller"]["archive_sha256"],
        manifest.image_index_sha256, manifest.sha256,
        expected_runtime=ledger.canonical(signed_context.runtime_for_cell(prepared)))


class RootRefresher:
    """Trusted Root factory references only; never construct from job JSON."""
    def __init__(self, root_config_path, expected_config_sha256):
        require(os.geteuid() == 0, "refresh-root-required")
        try:
            preparation._config(root_config_path, expected_config_sha256)
        except Exception:
            raise RefreshDenied("refresh-denied") from None
        self._path, self._sha = root_config_path, expected_config_sha256

    def handle(self, connected_socket, registry, selector, lease_id):
        require(os.geteuid() == 0, "refresh-root-required")
        from . import root_session
        try:
            selected = registry.select(selector)
            with root_session._session(self._path, self._sha) as session:
                with ledger.Ledger(selected.ledger_path, clock=preparation.time.time) as store:
                    return _refresh_locked(session, connected_socket, registry, selector, store, lease_id)
        except RefreshUnknown:
            raise
        except Exception:
            raise RefreshDenied("refresh-denied") from None


def _refresh_locked(session, connected_socket, registry, selector, store, lease_id, *, native_proof=None):
    from . import root_session
    require(os.geteuid() == 0, "refresh-root-required")
    config = root_session._require_session(session)
    effect, before, attempted = None, None, False
    try:
        require(type(registry) is policy_registry.Registry and type(lease_id) is str
                and ledger.ID.fullmatch(lease_id) and registry.path == config.registry_path
                and registry.sha256 == config.registry_sha256
                and policy_registry.load_registry(registry.path, registry.sha256) == registry,
                "refresh-registry-drift")
        selected = registry.select(selector)
        admission._validate_policy(selected)
        network_fence._policy(config.network_fence_policy_path, config.network_fence_policy_sha256)
        before = store.read(lease_id)
        require(before["state"] == "prepared" and before["expires_at"] == selected.deadline
                and before["cell_sha256"] == selected.cell_sha256
                and before["policy_sha256"] == selected.custody_policy_sha256
                and int(preparation.time.time()) < before["expires_at"], "refresh-root-binding")
        require(not any(e["state"] in {"intent", "unknown"} or e["operation"] in ledger.CLEANUPS
                        or e["operation"] == "fence-disable" for e in before["effects"].values()),
                "refresh-retained-effect")
        require(all(any(e["operation"] == operation and e["state"] == "verified"
                        for e in before["effects"].values())
                    for operation in ("context-create", "context-publish", "fence-create")),
                "refresh-owned-context-required")
        running = [e for e in before["effects"].values() if e["operation"] == "engine-start"]
        require(not running or (len(running) == 1 and running[0]["state"] == "verified"
                                and "engine_process" in running[0] and "engine_container_id" in running[0]),
                "refresh-running-engine-unbound")
        _same_worker(connected_socket, selected, before["worker"])
        context, old_sha, descriptor, engine_raw, engine_sha = _old_context(selected, lease_id)
        # Actual bridge owns strict framing, live native identity,
        # fresh nonce/JTI and collector-before/after verification.
        if native_proof is None:
            result = admission.AdmissionBridge(selected, expected_operation="refresh").handle(connected_socket)
            require(result == {"schema": 1, "operation": "refresh", "lease_id": lease_id,
                               "expires_at": selected.deadline}, "refresh-admission-result")
        else:
            native_worker, native_identity = admission._require_native(native_proof, connected_socket, selected)
            require(asdict(native_worker) == before["worker"], "refresh-native-worker")
            store.runtime_refresh_identity(lease_id, native_proof.nonce, native_worker, native_identity,
                cell_sha256=selected.cell_sha256, identity_policy_sha256=identity.policy_digest(selected.identity))
        after = store.read(lease_id)
        attempted = after != before
        require(after["authorizations"][:-1] == before["authorizations"]
                and len(after["authorizations"]) == len(before["authorizations"]) + 1
                and after["identity"] == before["identity"] and after["worker"] == before["worker"]
                and after["effects"] == before["effects"] and after["expires_at"] == before["expires_at"],
                "refresh-admission-result")
        auth = after["authorizations"][-1]
        target = "context:" + selected.cell_sha256 + ":" + auth["token_id_sha256"]
        effect = store.begin(lease_id, "context-refresh", target)
        attempted = True
        try:
            prepared = cell_contract.prepare_cell(registry, selector, store, lease_id)
            require(prepared.engine_descriptor_path == descriptor and prepared.engine_descriptor_bytes == engine_raw
                    and prepared.engine_descriptor_sha256 == engine_sha, "refresh-engine-drift")
            starts = [e for e in before["effects"].values() if e["operation"] == "engine-start"]
            if starts:
                require(len(starts) == 1 and starts[0]["state"] == "verified"
                        and "engine_process" in starts[0] and "engine_container_id" in starts[0],
                        "refresh-running-engine-unbound")
                original_raw, _ = signed_context._sealed(context + "/binding.json", 32768)
                original = identity.decode_json(original_raw)
                token_parts = original["admission"].split(".")
                require(len(token_parts) == 3, "refresh-previous-token")
                # Locator only: the previous-binding verifier below
                # MUST authenticate this SHA before publication.
                claims = identity.decode_json(identity.unbase(token_parts[1]))
                manifest = engine_policy.validate_retained_policy(descriptor, engine_sha,
                                                                  claims.get("engine_policy_sha256"))
            else:
                manifest = engine_policy.compile_engine_policy(descriptor, engine_sha)
                cell_contract.bind_engine(prepared, store, manifest)
            raw_cert, _ = signed_context._sealed(context + "/client.crt")
            der = x509.load_pem_x509_certificate(raw_cert).public_bytes(serialization.Encoding.DER)
            certificate = incus_mutation.CertificateSpec("lit-lease-" + lease_id, prepared.incus["project"],
                                                         der, prepared.expires_at)
            transport = preparation._typed(prepared, config, certificate)
            runtime = preparation._bridge_facts_readback(config, prepared, store, transport)
            require(transport.readback("certificate")["state"] == "required_fields_match",
                    "refresh-certificate-drift")
            worker = _same_worker(connected_socket, selected, before["worker"])
            policy = _context_policy(prepared, selected, manifest)
            old_raw, old_proof = signed_context._sealed(context + "/binding.json", 32768)
            require(old_proof.sha256 == old_sha, "refresh-original-binding-drift")
            old_binding = identity.decode_json(old_raw)
            signed_context.verify_previous_binding(old_binding["admission"], config.signing_public_key,
                                                   store, lease_id, worker, policy, old_binding, context)
            signer = signed_context.RootSigner(config.signing_key_path, config.signing_public_key)
            publisher = context_publisher.RootContextPublisher(signer, config.signing_public_key, context,
                                                               config.publication_staging_parent)
            outcome = publisher.publish(store, lease_id, worker, policy, expected_old_binding_sha256=old_sha)
            raw, proof = signed_context._sealed(context + "/binding.json", 32768)
            binding = identity.decode_json(raw)
            require(outcome == {"binding_sha256": proof.sha256}, "refresh-publication-readback")
            signed_context.verify(binding["admission"], config.signing_public_key, store, lease_id,
                                  worker, policy, binding, context)
            require(preparation._bridge_facts_readback(config, prepared, store, transport) == runtime
                    and store.read(lease_id)["authorizations"][-1] == auth, "refresh-provenance-drift")
            _same_worker(connected_socket, selected, before["worker"])
            store.record(lease_id, effect, "verified", evidence_sha256=ledger.digest({
                "binding_sha256": proof.sha256, "authorization_sha256": ledger.digest(auth),
                "engine_policy_sha256": manifest.sha256}))
            # No network write occurs until new live publication
            # is independently verified for the current identity.
            network_fence.renew(config.network_fence_policy_path, config.network_fence_policy_sha256,
                                prepared, store, worker, config)
            require(store.read(lease_id)["authorizations"][-1] == auth
                    and store.read(lease_id)["expires_at"] == before["expires_at"], "refresh-final-drift")
            _same_worker(connected_socket, selected, before["worker"])
            return RefreshReceipt(lease_id, prepared.expires_at, proof.sha256, ledger.digest(auth))
        except Exception:
            try:
                store.record(lease_id, effect, "unknown", evidence_sha256=ledger.digest({
                    "component": "refresh", "stage": "context-publication"}))
            except Exception:
                pass  # Retain intent/already verified record without retry or overwrite.
            raise RefreshUnknown("refresh-unknown") from None
    except Exception:
        if before is not None and not attempted:
            try:
                # Admission may have committed then lost its response.
                with ledger.Ledger(selected.ledger_path, clock=preparation.time.time) as observed:
                    attempted = observed.read(lease_id) != before
            except Exception:
                attempted = True
        if attempted:
            raise RefreshUnknown("refresh-unknown") from None
        raise RefreshDenied("refresh-denied") from None
