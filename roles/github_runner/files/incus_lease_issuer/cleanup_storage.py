"""Exact Root-owned raw storage release after verified execution withdrawal.

Only the finalizer calls these factories. Immutable Root creator evidence binds
the three original directory inodes and context contents. Descendants are
untrusted: traversal uses directory FDs, never follows links or crosses mounts.
No prefix scan, arbitrary path, mount teardown or destructive retry is exposed.
The separately bounded public-evidence sibling is deliberately retained.
"""
from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import os
from pathlib import PurePosixPath
import stat
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import (cell_contract, engine_executor, engine_policy as engine, identity,
               installation, ledger, preparation, signed_context, storage_quota)
from .identity import Denied, require


class CleanupStorageUnknown(Denied):
    """Possible owned deletion retained in the journal; never retry here."""


@dataclass(frozen=True)
class StorageReceipt:
    lease_id: str
    operation: str
    evidence_sha256: str


def _fresh(owner, store, config):
    require(os.geteuid() == 0 and type(owner) is cell_contract.OwnedCellForCleanup
            and type(store) is ledger.Ledger and store.owner_uid == 0
            and type(config) is preparation.RootConfiguration, "cleanup-storage-root-inputs")
    require(preparation._config(config.path, config.sha256)[0] == config
            and owner.registry.path == config.registry_path
            and owner.registry.sha256 == config.registry_sha256
            and cell_contract.owned_cell_for_cleanup(owner.registry, owner.selector, store, owner.lease_id) == owner,
            "cleanup-storage-owner-drift")
    return store.read(owner.lease_id)


def _effect(record, operation, target):
    found = [(key, value) for key, value in record["effects"].items()
             if value["operation"] == operation]
    require(len(found) <= 1, "cleanup-storage-ambiguous-effect")
    if not found:
        return None
    require(found[0][1]["target"] == target and found[0][1]["state"] == "verified",
            "cleanup-storage-unresolved-effect")
    return found[0]


def _cleanup_limits(config):
    policy, _, _ = storage_quota._policy(config.storage_quota_policy_path, config.storage_quota_policy_sha256)
    return min(policy["max_inodes"] * 4, 1000000), config.operation_wait_seconds


def _identity(info):
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid, info.st_gid


def _deadline(end):
    require(time.monotonic() < end, "cleanup-storage-budget")


@contextmanager
def _fresh_entries(root):
    fd = os.open(".", installation.DIR_FLAGS, dir_fd=root)
    try:
        require(_identity(os.fstat(fd)) == _identity(os.fstat(root))
                and storage_quota._mount_id(fd) == storage_quota._mount_id(root),
                "cleanup-storage-directory-replaced")
        with os.scandir(fd) as entries:
            yield entries
    finally:
        os.close(fd)


def _directory_at(root, components, identities, mount_id):
    # A fresh open file description avoids sharing readdir state with another
    # observer of the pinned directory FD. Never reopen via a mutable pathname.
    fd = os.open(".", installation.DIR_FLAGS, dir_fd=root)
    try:
        require(_identity(os.fstat(fd)) == identities[()]
                and storage_quota._mount_id(fd) == mount_id, "cleanup-storage-root-replaced")
        for index, name in enumerate(components):
            child = os.open(name, installation.DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            require(_identity(os.fstat(fd)) == identities[components[:index + 1]]
                    and storage_quota._mount_id(fd) == mount_id, "cleanup-storage-directory-replaced")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _inventory_tree(root, end, maximum):
    """Metadata-only bounded inventory; O_PATH never opens device contents."""
    mount_id = storage_quota._mount_id(root)
    identities, nodes, pending = {(): _identity(os.fstat(root))}, [], [()]
    while pending:
        _deadline(end)
        components = pending.pop()
        require(len(components) <= 256, "cleanup-storage-depth")
        fd = _directory_at(root, components, identities, mount_id)
        try:
            with _fresh_entries(fd) as entries:
                for entry in entries:
                    name = entry.name
                    _deadline(end)
                    require(type(name) is str and name not in {"", ".", ".."} and "/" not in name,
                            "cleanup-storage-entry")
                    path = components + (name,)
                    observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    leaf = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        require(_identity(os.fstat(leaf)) == _identity(observed)
                                and observed.st_dev == os.fstat(root).st_dev
                                and storage_quota._mount_id(leaf) == mount_id, "cleanup-storage-foreign-mount")
                    finally:
                        os.close(leaf)
                    require(len(nodes) < maximum, "cleanup-storage-entry-limit")
                    identities[path] = _identity(observed)
                    nodes.append((path, _identity(observed), stat.S_ISDIR(observed.st_mode)))
                    if stat.S_ISDIR(observed.st_mode):
                        pending.append(path)
        finally:
            os.close(fd)
    return tuple(nodes), identities, mount_id


def _remove_tree(root, inventory, end):
    nodes, identities, mount_id = inventory
    require(_identity(os.fstat(root)) == identities[()]
            and storage_quota._mount_id(root) == mount_id, "cleanup-storage-root-replaced")
    for path, expected, directory in sorted(nodes, key=lambda row: len(row[0]), reverse=True):
        _deadline(end)
        fd = _directory_at(root, path[:-1], identities, mount_id)
        try:
            current = os.stat(path[-1], dir_fd=fd, follow_symlinks=False)
            require(_identity(current) == expected, "cleanup-storage-entry-replaced")
            # Links/sockets/devices are unlinked as entries, never opened or
            # followed. A nested directory is removed only when already empty.
            if directory:
                # All children precede this node. Persist their removals once
                # on the independently reopened, identity/mount-checked child
                # before removing its name. The caller already has a durable
                # intent: interrupted batches remain unknown, never verified.
                child = _directory_at(root, path, identities, mount_id)
                try:
                    _deadline(end)
                    os.fsync(child)
                    _deadline(end)
                finally:
                    os.close(child)
                os.rmdir(path[-1], dir_fd=fd)
            else:
                os.unlink(path[-1], dir_fd=fd)
        finally:
            os.close(fd)
    with _fresh_entries(root) as entries:
        require(next(entries, None) is None, "cleanup-storage-new-entry")
    _deadline(end)
    os.fsync(root)
    _deadline(end)


def _absent(paths):
    for path in paths:
        parent = engine._directory(str(PurePosixPath(path).parent), private=True)
        try:
            require(PurePosixPath(path).name not in os.listdir(parent), "cleanup-storage-returned-path")
        finally:
            os.close(parent)


def _drain_engine(owner, store, config):
    from . import runtime_rpc
    record = _fresh(owner, store, config)
    require(_effect(record, "engine-stop", "engine:lit-lease-" + owner.lease_id) is not None
            and _effect(record, "fence-disable", "fence:" + owner.lease_id) is not None,
            "cleanup-storage-withdrawal-required")
    receipt = runtime_rpc._receipt(owner.registry, owner.selector, store, owner.lease_id)
    manifest, _, effect = engine_executor._retained(config, owner.registry, owner.selector,
                                                   store, owner.lease_id, receipt)
    require(effect == record["effects"][owner.creators["engine-start"]["id"]]
            and "engine_exit" in effect, "cleanup-storage-original-exit")
    ledger._validate_engine_exit(effect["engine_exit"], effect)
    engine_executor._drained(manifest, effect["engine_capture"])
    return manifest, effect


def _mark_unknown(store, owner, effect, operation):
    try:
        store.record(owner.lease_id, effect, "unknown", evidence_sha256=ledger.digest({
            "component": "cleanup-storage", "operation": operation, "state": "unknown"}))
    except Exception:
        pass


def release_engine(owner, store, config):
    """Release only the three directory inodes created by engine-prepare."""
    effect, opened = None, []
    try:
        record = _fresh(owner, store, config)
        data = identity.decode_json(owner.engine_descriptor_bytes)
        paths = (data["engine"]["storage_root"], data["engine"]["runroot"], data["output_path"])
        target = "engine:" + owner.lease_id
        previous = _effect(record, "engine-release", target)
        if previous is not None:
            _absent(paths)
            return StorageReceipt(owner.lease_id, "engine-release", previous[1]["evidence_sha256"])
        _drain_engine(owner, store, config)
        maximum, seconds = _cleanup_limits(config)
        end = time.monotonic() + seconds
        directories, inventories, used = [], [], 0
        for path in paths:
            parent = engine._directory(str(PurePosixPath(path).parent), private=True)
            opened.append(parent)
            fd = engine._directory(path, private=True)
            opened.append(fd)
            info = os.fstat(fd)
            directories.append({"path": path, "device": info.st_dev, "inode": info.st_ino})
            inventory = _inventory_tree(fd, end, maximum - used)
            used += len(inventory[0])
            inventories.append((path, parent, fd, inventory))
        creator = record["effects"][owner.creators["engine-prepare"]["id"]]
        require(creator["evidence_sha256"] == ledger.digest({"prepared": owner.prepared_sha256,
                    "directories": directories}), "cleanup-storage-original-inodes")
        # The public sibling stays bounded by the original Root quota even
        # after the raw graph/runroot/output have all been removed.
        spool = data["engine"]["runroot"] + ".public-evidence"
        require(all(spool != path and not spool.startswith(path + "/") for path in paths),
                "cleanup-storage-spool-inside-raw")
        with storage_quota.acquire_existing_evidence_quota(
                config.storage_quota_policy_path, config.storage_quota_policy_sha256, spool):
            _fresh(owner, store, config)
            _deadline(end)
            effect = store.begin(owner.lease_id, "engine-release", target)
            for path, parent, fd, inventory in inventories:
                _deadline(end)
                named = os.stat(PurePosixPath(path).name, dir_fd=parent, follow_symlinks=False)
                require(_identity(named) == _identity(os.fstat(fd)), "cleanup-storage-root-replaced")
                _remove_tree(fd, inventory, end)
                os.rmdir(PurePosixPath(path).name, dir_fd=parent)
                os.fsync(parent)
            _absent(paths)
            evidence = ledger.digest({"lease_id": owner.lease_id, "operation": "engine-release",
                                      "directories": directories, "removed_entries": used})
            store.record(owner.lease_id, effect, "verified", evidence_sha256=evidence)
            return StorageReceipt(owner.lease_id, "engine-release", evidence)
    except BaseException:
        if effect is not None:
            _mark_unknown(store, owner, effect, "engine-release")
            raise CleanupStorageUnknown("cleanup-storage-unknown") from None
        raise Denied("cleanup-storage-denied") from None
    finally:
        for fd in reversed(opened):
            os.close(fd)


def delete_context(owner, store, config):
    """Authenticate the original TLS context, then unlink that exact inventory."""
    effect, opened = None, []
    try:
        record = _fresh(owner, store, config)
        data = identity.decode_json(owner.engine_descriptor_bytes)
        context, descriptor = data["context_path"], owner.engine_descriptor_path
        target = "context:" + owner.cell_sha256
        previous = _effect(record, "context-delete", target)
        if previous is not None:
            _absent((context, descriptor))
            return StorageReceipt(owner.lease_id, "context-delete", previous[1]["evidence_sha256"])
        require(_effect(record, "engine-release", "engine:" + owner.lease_id) is not None
                and _effect(record, "certificate-revoke", owner.creator_targets["certificate-create"]) is not None,
                "cleanup-storage-parents-live")
        raw, binding_proof = signed_context._sealed(context + "/binding.json", 32768)
        binding = identity.decode_json(raw)
        receipt = preparation.PreparationReceipt(owner.lease_id, owner.cell_sha256, owner.engine_policy_sha256,
                                                 binding_proof.sha256, owner.expires_at)
        engine_executor._authenticate(config, owner.registry, owner.selector, store, owner.lease_id, receipt)
        files = signed_context._files(context, binding, binding["admission"])
        unsigned = {key: value for key, value in binding.items() if key != "admission"}
        files["binding.json"] = hashlib.sha256(ledger.canonical(unsigned)).hexdigest()
        cert_raw, _ = signed_context._sealed(context + "/client.crt")
        fingerprint = hashlib.sha256(x509.load_pem_x509_certificate(cert_raw).public_bytes(
            serialization.Encoding.DER)).hexdigest()
        creator = record["effects"][owner.creators["context-create"]["id"]]
        require("certificate:" + fingerprint == owner.creator_targets["certificate-create"]
                and creator["evidence_sha256"] == ledger.digest({"prepared": owner.prepared_sha256,
                    "files": files, "descriptor": owner.engine_descriptor_sha256, "certificate": fingerprint}),
                "cleanup-storage-original-context")
        proof, descriptor_raw, _ = installation._file(descriptor, engine.MAX_DESCRIPTOR, private=True, keep=True)
        require(proof.sha256 == owner.engine_descriptor_sha256
                and descriptor_raw == owner.engine_descriptor_bytes, "cleanup-storage-original-descriptor")
        parent = engine._directory(str(PurePosixPath(context).parent), private=True)
        opened.append(parent)
        fd = engine._directory(context, private=True)
        opened.append(fd)
        descriptor_parent = engine._directory(str(PurePosixPath(descriptor).parent), private=True)
        opened.append(descriptor_parent)
        maximum, seconds = _cleanup_limits(config)
        end = time.monotonic() + seconds
        inventory = _inventory_tree(fd, end, min(maximum, 16))
        require({"/".join(row[0]) for row in inventory[0]} == {
            "binding.json", "config.yml", "client.crt", "client.key", "servercerts", "servercerts/quality.crt"},
            "cleanup-storage-context-inventory")
        _fresh(owner, store, config)
        effect = store.begin(owner.lease_id, "context-delete", target)
        _remove_tree(fd, inventory, end)
        require(_identity(os.stat(PurePosixPath(context).name, dir_fd=parent, follow_symlinks=False))
                == _identity(os.fstat(fd)), "cleanup-storage-context-replaced")
        os.rmdir(PurePosixPath(context).name, dir_fd=parent)
        os.fsync(parent)
        observed = os.stat(PurePosixPath(descriptor).name, dir_fd=descriptor_parent, follow_symlinks=False)
        require((observed.st_dev, observed.st_ino) == (proof.device, proof.inode), "cleanup-storage-descriptor-replaced")
        os.unlink(PurePosixPath(descriptor).name, dir_fd=descriptor_parent)
        os.fsync(descriptor_parent)
        _absent((context, descriptor))
        evidence = ledger.digest({"lease_id": owner.lease_id, "operation": "context-delete",
                                  "creator_sha256": owner.creator_digests["context-create"]})
        store.record(owner.lease_id, effect, "verified", evidence_sha256=evidence)
        return StorageReceipt(owner.lease_id, "context-delete", evidence)
    except BaseException:
        if effect is not None:
            _mark_unknown(store, owner, effect, "context-delete")
            raise CleanupStorageUnknown("cleanup-storage-unknown") from None
        raise Denied("cleanup-storage-denied") from None
    finally:
        for fd in reversed(opened):
            os.close(fd)
