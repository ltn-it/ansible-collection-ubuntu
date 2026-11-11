"""Closed Root-internal Incus mutation primitive, NOT an activated provisioner.

Only the future trusted Root factory may construct these deterministic types
from independently sealed cell semantics. No job request may construct them.
Before use that executor MUST qualify actual package/daemon provenance, accepted
operating/network/custody policy and persist a durable exact-target intent.
The live exact7.6/extension readback here is only an additional prerequisite;
it does not attest a patched binary. There is no caller 'qualified' flag.

This object prevents resending an attempted operation within its own lifetime.
Crash/restart at-most-once, ownership registry, async reconciliation and cleanup
ordering require the external Root ledger. HTTP success is never verified
resource ownership. Every possible mutation send with a failed, rejected or
ambiguous reply is UNKNOWN, including409/404; no automatic retry/rollback.
Default-profile configuration is a separate conditional write before granting
TLS; actual per-VM disk size remains the lifecycle's instance/device setting.

Pinned API: lxc/incus commit8f5e6c2235f6424ec59d3dc06f12e344a4a416e2,
shared/api/certificate.go (POST base64DER), shared/api/operation.go and
status_code.go, internal/server/response/response.go (sync HTTP201/code200).
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import datetime as dt
import hashlib
import ipaddress
import os
import re
import socket
import struct
import time
from urllib.parse import urlencode

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import identity, incus_admin as admin, installation
from .identity import Denied, require
from .ledger import canonical, HEX, ID, CERTIFICATE_AUTHORIZER_PROFILE, digest

EXTENSIONS = frozenset({"projects", "projects_limits", "projects_limits_disk", "projects_restrictions",
                        "certificate_project", "certificate_self_renewal", "project_usage"})
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}\Z")
OWNER = re.compile(r"[A-Za-z0-9._/-]{1,255}\Z")


def _certificate_validity(certificate):
    # Aware properties arrived in cryptography42; older X509 values are
    # documented naive UTC, so timestamp() must not interpret them locally.
    # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate.not_valid_before_utc
    try:
        return certificate.not_valid_before_utc, certificate.not_valid_after_utc
    except AttributeError:
        return (certificate.not_valid_before.replace(tzinfo=dt.timezone.utc),
                certificate.not_valid_after.replace(tzinfo=dt.timezone.utc))


class MutationDenied(Denied):
    """No mutation send attempted by this call; no backend qualification claim."""


class MutationUnknown(Denied):
    """Possible mutation send: retain durable intent and perform owned readback."""


@dataclass(frozen=True)
class Ownership:
    owner: str
    repository: str
    run_id: int
    run_attempt: int
    scenario: str
    target: str
    lease_id: str
    cell_sha256: str


@dataclass(frozen=True)
class ProjectLimits:
    cpu: int
    memory_bytes: int
    disk_bytes: int
    instances: int
    virtual_machines: int
    containers: int = 0


@dataclass(frozen=True)
class ProjectSpec:
    project: str
    network: str
    pool: str
    limits: ProjectLimits
    ownership: Ownership


@dataclass(frozen=True)
class BridgeSpec:
    network: str
    ipv4_address: str
    dns_domain: str
    ownership: Ownership


@dataclass(frozen=True)
class CertificateSpec:
    name: str
    project: str
    der: bytes
    deadline: int


@dataclass(frozen=True)
class MutationReceipt:
    operation: str
    target: str
    response: str
    operation_id: str | None = None


@dataclass(frozen=True)
class CertificateScopeBaseline:
    initial_fingerprint: str
    certificate_name: str
    project: str
    baseline_inventory_sha256: str
    authorizer_profile: str


@dataclass(frozen=True)
class CertificateInventory:
    original_fingerprint: str
    fingerprints: tuple[str, ...]
    rotation_candidates: tuple[str, ...]
    inventory_sha256: str
    scope_sha256: str


def _certificate_inventory(client):
    rows = client.certificates()
    require(type(rows) is list and len(rows) <= 4096, "mutation-certificate-inventory")
    seen = set()
    for row in rows:
        require(type(row) is dict and type(row.get("fingerprint")) is str
                and HEX.fullmatch(row["fingerprint"]) and row["fingerprint"] not in seen
                and type(row.get("name")) is str and len(row["name"]) <= 1024
                and type(row.get("type")) is str and row["type"] in {"client", "server", "metrics"}
                and type(row.get("restricted")) is bool and type(row.get("projects")) is list
                and len(row["projects"]) <= 4096
                and all(type(item) is str and admin.NAME.fullmatch(item) for item in row["projects"])
                and len(set(row["projects"])) == len(row["projects"])
                and type(row.get("certificate")) is str and 0 < len(row["certificate"]) <= 32768,
                "mutation-certificate-inventory")
        try:
            parsed = x509.load_pem_x509_certificate(row["certificate"].encode())
        except Exception:
            raise MutationDenied("mutation-certificate-inventory") from None
        require(hashlib.sha256(parsed.public_bytes(serialization.Encoding.DER)).hexdigest() == row["fingerprint"],
                "mutation-certificate-inventory")
        seen.add(row["fingerprint"])
    return rows, digest(sorted(rows, key=lambda row: row["fingerprint"]))


def _labels(owner):
    require(type(owner) is Ownership and type(owner.owner) is str and OWNER.fullmatch(owner.owner)
            and type(owner.repository) is str and identity.REPOSITORY.fullmatch(owner.repository)
            and type(owner.run_id) is int and owner.run_id > 0
            and type(owner.run_attempt) is int and owner.run_attempt == 1
            and all(type(v) is str and admin.NAME.fullmatch(v) for v in (owner.scenario, owner.target))
            and type(owner.lease_id) is str and ID.fullmatch(owner.lease_id)
            and type(owner.cell_sha256) is str and HEX.fullmatch(owner.cell_sha256), "mutation-ownership")
    return {"user.lit-molecule-owner": owner.owner, "user.lit-molecule-repository": owner.repository,
            "user.lit-molecule-run-id": str(owner.run_id), "user.lit-molecule-attempt": "1",
            "user.lit-molecule-scenario": owner.scenario, "user.lit-molecule-target": owner.target,
            "user.lit-incus-lease-id": owner.lease_id, "user.lit-incus-cell-sha256": owner.cell_sha256}


def _project(spec):
    require(type(spec) is ProjectSpec and type(spec.limits) is ProjectLimits
            and all(type(v) is str and admin.NAME.fullmatch(v) for v in (spec.project, spec.network, spec.pool))
            and spec.project != "default", "mutation-project")
    limits = spec.limits
    require(all(type(v) is int and 0 < v <= 2 ** 63 - 1 for v in
                (limits.cpu, limits.memory_bytes, limits.disk_bytes, limits.instances, limits.virtual_machines))
            and type(limits.containers) is int and limits.containers == 0
            and limits.instances == limits.virtual_machines, "mutation-limits")
    config = {"restricted": "true", "features.networks": "false", "features.networks.zones": "false",
              "features.profiles": "true", "features.images": "true", "features.storage.volumes": "true",
              "features.storage.buckets": "true", "restricted.devices.nic": "managed",
              "restricted.networks.access": spec.network, "restricted.devices.disk": "managed",
              "restricted.storage-pools.access": spec.pool, "restricted.virtual-machines.lowlevel": "block",
              "limits.cpu": str(limits.cpu), "limits.memory": str(limits.memory_bytes),
              "limits.disk": str(limits.disk_bytes), "limits.instances": str(limits.instances),
              "limits.virtual-machines": str(limits.virtual_machines), "limits.containers": "0",
              **_labels(spec.ownership)}
    return {"name": spec.project, "description": "Root lease " + spec.ownership.lease_id, "config": config}


def _bridge(spec):
    require(type(spec) is BridgeSpec and type(spec.network) is str and admin.NAME.fullmatch(spec.network)
            and type(spec.ipv4_address) is str and type(spec.dns_domain) is str
            and len(spec.dns_domain) <= 253 and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x)
                                                  for x in spec.dns_domain.split(".")), "mutation-bridge")
    subnet = ipaddress.ip_interface(spec.ipv4_address)
    require(subnet.version == 4 and str(subnet) == spec.ipv4_address, "mutation-subnet")
    config = {"ipv4.address": spec.ipv4_address, "ipv4.dhcp": "true", "ipv4.nat": "true",
              "ipv4.firewall": "true", "ipv6.address": "none", "dns.domain": spec.dns_domain,
              "dns.mode": "managed", "user.lit-molecule-firewall-controller": "incus",
              "user.lit-molecule-firewalld-zone": "none", **_labels(spec.ownership)}
    return {"name": spec.network, "type": "bridge", "description": "Root lease " + spec.ownership.lease_id,
            "config": config}


class RootIncusMutator:
    """Fixed Root targets/specs; no per-call body, URL, method or policy hooks.

    certificate=None is the explicit precontext stage, with an empty AdminTarget
    fingerprint tuple. After materialization the executor constructs NEW fixed
    certificate-bound objects. There is no late binding or placeholder DER.
    External durable journaling covers both objects and process restarts; their
    separate in-memory attempt sets are not a global replay guarantee.
    """
    def __init__(self, client, project, bridge, certificate=None):
        admin._root()
        try:
            require(type(client) is admin.RootIncusAdmin, "mutation-admin-client")
            self._client, self._project, self._bridge, self._certificate = client, project, bridge, certificate
            _project(project)
            _bridge(bridge)
            target = client._target
            require(bridge.ownership == project.ownership and target.project == project.project
                    and target.network == bridge.network == project.network and target.pool == project.pool
                    and target.network_project == "default", "mutation-fixed-target")
            self._attempts, self._operations = set(), {}
            self._fingerprint = None
            if certificate is None:
                require(target.certificate_fingerprints == (), "mutation-precontext-certificate-target")
                return
            require(type(certificate) is CertificateSpec and certificate.project == project.project
                    and type(certificate.name) is str and LABEL.fullmatch(certificate.name)
                    and type(certificate.deadline) is int and certificate.deadline > 0
                    and type(certificate.der) is bytes and 0 < len(certificate.der) <= 16384, "mutation-certificate")
            parsed = x509.load_der_x509_certificate(certificate.der)
            require(parsed.public_bytes(serialization.Encoding.DER) == certificate.der, "mutation-certificate")
            self._fingerprint = hashlib.sha256(certificate.der).hexdigest()
            require(target.certificate_fingerprints == (self._fingerprint,), "mutation-fixed-certificate")
        except Exception:
            raise MutationDenied("mutation-denied") from None

    def _backend(self):
        # Live source/API prerequisite only. The executor still must qualify
        # real installed package/binary provenance before invoking this object.
        admin.qualify_backend(self._client.server(), expected_version="7.6", expected_extensions=EXTENSIONS)

    def _require_certificate(self):
        admin._root()
        require(type(self._certificate) is CertificateSpec and type(self._fingerprint) is str,
                "mutation-certificate-stage-required")

    def _exchange(self, method, path, body=None, *, attempt=None, etag=None):
        parent = connected = None
        sent = False
        try:
            admin._root()
            raw = b"" if body is None else canonical(body)
            require(len(raw) <= 65536, "mutation-request-limit")
            deadline = time.monotonic() + admin.REQUEST_SECONDS
            parent = installation._open_directory(self._client._parent)
            self._client._stable(parent)
            connected = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connected.settimeout(admin.REQUEST_SECONDS)
            connected.connect(self._client._target.socket_path)
            pid, uid, _gid = struct.unpack("3i", connected.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(pid > 0 and uid == 0, "mutation-peer")
            self._client._stable(parent)
            remaining = deadline - time.monotonic()
            require(remaining > 0, "mutation-timeout")
            connected.settimeout(remaining)
            headers = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n"
            if etag is not None:
                require(method == "PUT" and path == self._profile_path() and type(etag) is bytes
                        and re.fullmatch(rb'"[\x21\x23-\x7e]{1,128}"', etag), "mutation-profile-etag")
                headers += "If-Match: " + etag.decode("ascii") + "\r\n"
            if body is not None:
                headers += f"Content-Type: application/json\r\nContent-Length: {len(raw)}\r\n"
            if attempt is not None:
                require(attempt not in self._attempts, "mutation-replay")
                self._attempts.add(attempt)
            sent = True
            connected.sendall(headers.encode("ascii") + b"\r\n" + raw)
            reader = admin._Response(connected, deadline)
            status, envelope = reader.read_envelope()
            self._client._stable(parent)
            return status, envelope, reader.headers.get(b"etag")
        except BaseException:
            if attempt is not None and sent:
                raise MutationUnknown("mutation-unknown") from None
            raise MutationDenied("mutation-denied") from None
        finally:
            close_failed = False
            if connected is not None:
                try:
                    connected.close()
                except OSError:
                    close_failed = True
            if parent is not None:
                try:
                    os.close(parent)
                except OSError:
                    close_failed = True
            if close_failed:
                if attempt is not None and sent:
                    raise MutationUnknown("mutation-unknown") from None
                raise MutationDenied("mutation-denied") from None

    @staticmethod
    def _sync(status, envelope):
        return (status in {200, 201} and envelope.get("type") == "sync"
                and type(envelope.get("status_code")) is int and envelope["status_code"] == 200
                and envelope.get("status") == "Success" and envelope.get("operation", "") == ""
                and type(envelope.get("error_code", 0)) is int and envelope.get("error_code", 0) == 0
                and envelope.get("error", "") == "" and "metadata" in envelope)

    def _mutate(self, operation, target, method, path, body=None, *, etag=None):
        admin._root()
        require((operation, target) not in self._attempts, "mutation-replay")
        try:
            self._backend()
            status, envelope, _ = self._exchange(method, path, body, attempt=(operation, target), etag=etag)
        except MutationUnknown:
            raise
        except Exception:
            raise MutationDenied("mutation-denied") from None
        try:
            if self._sync(status, envelope):
                return MutationReceipt(operation, target, "sync_received")
            require(status == 202 and envelope.get("type") == "async"
                    and type(envelope.get("status_code")) is int and envelope["status_code"] == 100
                    and envelope.get("status") == "Operation created"
                    and type(envelope.get("error_code", 0)) is int and envelope.get("error_code", 0) == 0
                    and envelope.get("error", "") == "",
                    "mutation-response")
            location = envelope.get("operation")
            require(type(location) is str and location.startswith("/1.0/operations/"), "mutation-operation")
            operation_id = location[len("/1.0/operations/"):]
            require(UUID.fullmatch(operation_id), "mutation-operation")
            metadata = envelope.get("metadata")
            require(type(metadata) is dict and metadata.get("id") == operation_id
                    and metadata.get("class") == "task", "mutation-operation")
            receipt = MutationReceipt(operation, target, "operation_pending", operation_id)
            require(operation_id not in self._operations, "mutation-operation-reuse")
            self._operations[operation_id] = receipt
            return receipt
        except BaseException:
            # Even explicit rejected/conflict replies can follow a durable side
            # effect. Never infer not_applied from an HTTP/error response.
            raise MutationUnknown("mutation-unknown") from None

    def project_create(self):
        return self._mutate("project-create", "project:" + self._project.project,
                            "POST", "/1.0/projects", _project(self._project))

    def bridge_create(self):
        return self._mutate("network-create", "network:default:" + self._bridge.network,
                            "POST", "/1.0/networks?project=default", _bridge(self._bridge))

    def certificate_create(self):
        self._require_certificate()
        spec = self._certificate
        parsed = x509.load_der_x509_certificate(spec.der)
        now = time.time()
        not_before, not_after = _certificate_validity(parsed)
        require(not_before.timestamp() <= now < not_after.timestamp()
                <= spec.deadline, "mutation-certificate-expiry")
        body = {"name": spec.name, "type": "client", "restricted": True, "projects": [spec.project],
                "certificate": base64.b64encode(spec.der).decode("ascii"),
                "description": "Root lease " + self._project.ownership.lease_id}
        return self._mutate("certificate-create", "certificate:" + self._fingerprint,
                            "POST", "/1.0/certificates", body)

    def certificate_scope_baseline(self):
        """Root's complete absent-name/project-scope baseline BEFORE POST.

        Pinned TLS-authorizer and other Root admins remain platform trust, not
        facts established by this read. No operating approval is returned.
        """
        self._require_certificate()
        self._backend()
        require(self._certificate.name == "lit-lease-" + self._project.ownership.lease_id,
                "mutation-certificate-scope-name")
        rows, sha = _certificate_inventory(self._client)
        require(all(row["name"] != self._certificate.name and row["fingerprint"] != self._fingerprint
                    and not (row["restricted"] and self._project.project in row["projects"]) for row in rows),
                "mutation-certificate-scope-preexists")
        _, second = _certificate_inventory(self._client)
        require(sha == second, "mutation-certificate-inventory-drift")
        return CertificateScopeBaseline(self._fingerprint, self._certificate.name, self._project.project,
                                       sha, CERTIFICATE_AUTHORIZER_PROFILE)

    def _profile_path(self):
        return "/1.0/profiles/default?" + urlencode({"project": self._project.project})

    def _profile(self):
        return {"description": "Root lease " + self._project.ownership.lease_id,
                "config": _labels(self._project.ownership),
                "devices": {"root": {"type": "disk", "path": "/", "pool": self._project.pool}}}

    def configure_default_profile(self):
        admin._root()
        project = self._observe("project")
        require(project is not None and self._matches("project", project), "mutation-profile-project-owner")
        allowed = [self._profile_path()]
        require(type(project.get("used_by")) is list and project["used_by"] in ([], allowed),
                "mutation-profile-project-in-use")
        self._backend()
        status, envelope, etag = self._exchange("GET", self._profile_path())
        require(status == 200 and self._sync(status, envelope), "mutation-profile-readback")
        profile = envelope["metadata"]
        require(type(profile) is dict and profile.get("name") == "default"
                and profile.get("description") == "Default Incus profile for project " + self._project.project
                and profile.get("config") == {} and profile.get("devices") == {}
                and profile.get("used_by") == [], "mutation-profile-not-empty-owned")
        require(type(etag) is bytes and re.fullmatch(rb'"[\x21\x23-\x7e]{1,128}"', etag),
                "mutation-profile-etag")
        return self._mutate("profile-configure", "profile:" + self._project.project + ":default",
                            "PUT", self._profile_path(), self._profile(), etag=etag)

    def _observe(self, kind):
        admin._root()
        paths = {"project": "/1.0/projects/" + self._project.project,
                 "bridge": "/1.0/networks/" + self._bridge.network + "?project=default",
                 "profile": self._profile_path()}
        if kind == "certificate":
            self._require_certificate()
            paths["certificate"] = "/1.0/certificates/" + self._fingerprint
        self._backend()
        status, envelope, _ = self._exchange("GET", paths[kind])
        if (status == 404 and envelope.get("type") == "error" and type(envelope.get("error_code")) is int
                and envelope["error_code"] == 404):
            return None
        require(status == 200 and self._sync(status, envelope) and type(envelope["metadata"]) is dict,
                "mutation-readback-denied")
        return envelope["metadata"]

    def _matches(self, kind, metadata):
        if kind == "profile":
            expected = self._profile()
            return (metadata.get("name") == "default"
                    and all(metadata.get(k) == v for k, v in expected.items()))
        if kind in {"project", "bridge"}:
            expected = _project(self._project) if kind == "project" else _bridge(self._bridge)
            config = metadata.get("config")
            return (metadata.get("name") == expected["name"] and metadata.get("description") == expected["description"]
                    and type(config) is dict and all(config.get(k) == v for k, v in expected["config"].items())
                    and (kind != "bridge" or (metadata.get("type") == "bridge" and metadata.get("managed") is True)))
        try:
            spec = self._certificate
            parsed = x509.load_pem_x509_certificate(metadata.get("certificate", "").encode())
            return (metadata.get("fingerprint") == self._fingerprint and metadata.get("name") == spec.name
                    and metadata.get("type") == "client" and metadata.get("restricted") is True
                    and metadata.get("projects") == [spec.project]
                    and parsed.public_bytes(serialization.Encoding.DER) == spec.der)
        except Exception:
            return False

    def readback(self, kind):
        """Selected snapshots only; absence can race pending remote operations.

        Matching required fields is not a complete semantic/capacity assertion;
        Root cell policy still must evaluate backend-added configuration.
        """
        require(type(kind) is str and kind in {"project", "bridge", "certificate", "profile"},
                "mutation-readback-kind")
        metadata = self._observe(kind)
        return {"state": "absent_observed" if metadata is None else (
            "required_fields_match" if self._matches(kind, metadata) else "conflict"),
            "metadata_sha256": hashlib.sha256(canonical(metadata)).hexdigest()}

    def _delete(self, kind, operation, target, path):
        metadata = self._observe(kind)
        require(metadata is not None and self._matches(kind, metadata), "mutation-delete-not-owned")
        if kind != "certificate":
            expected = _project(self._project) if kind == "project" else _bridge(self._bridge)
            # Unknown extra configuration is a semantic recovery hold. Future
            # backend-generated keys need pinned source/runtime qualification,
            # never a blanket volatile/config ignore rule before deletion.
            require(set(metadata["config"]) == set(expected["config"]), "mutation-delete-config-drift")
            users = metadata.get("used_by")
            allowed = [] if kind == "bridge" else ["/1.0/profiles/default?" + urlencode({"project": self._project.project})]
            require(type(users) is list and (not users or users == allowed), "mutation-delete-in-use")
        return self._mutate(operation, target, "DELETE", path)

    def project_delete(self):
        return self._delete("project", "project-delete", "project:" + self._project.project,
                            "/1.0/projects/" + self._project.project)

    def bridge_delete(self):
        return self._delete("bridge", "network-delete", "network:default:" + self._bridge.network,
                            "/1.0/networks/" + self._bridge.network + "?project=default")

    def certificate_delete(self):
        self._require_certificate()
        return self._delete("certificate", "certificate-revoke", "certificate:" + self._fingerprint,
                            "/1.0/certificates/" + self._fingerprint)

    def operation_readback(self, receipt):
        admin._root()
        require(type(receipt) is MutationReceipt and receipt.operation_id in self._operations
                and self._operations[receipt.operation_id] == receipt, "mutation-untracked-operation")
        self._backend()
        status, envelope, _ = self._exchange("GET", "/1.0/operations/" + receipt.operation_id)
        require(status == 200 and self._sync(status, envelope), "mutation-operation-readback")
        value = envelope["metadata"]
        require(type(value) is dict and value.get("id") == receipt.operation_id and value.get("class") == "task"
                and type(value.get("status_code")) is int, "mutation-operation-readback")
        code = value["status_code"]
        require(code in set(range(100, 114)) | {200, 400, 401}, "mutation-operation-status")
        require(code != 200 or value.get("err", "") == "", "mutation-operation-status")
        # Remote terminal failure still does not prove a resource was not made.
        return {"operation_id": receipt.operation_id, "state": "pending" if code < 200 else (
            "success_requires_resource_readback" if code == 200 else "failed_requires_resource_readback"),
            "status_code": code}


class RootIncusCleanup(RootIncusMutator):
    """Verified Root creator scope, usable after auth expiry/raw-context deletion.

    7.6 self-renew preserves name/type/restricted/projects, but NOT description
    or expiry. A pre-POST complete absent-scope baseline plus the original Root
    creator proves this scope under the same trusted pinned TLS/Root-admin
    platform boundary. No protection against an uncoordinated trusted Root admin
    is claimed. Unknown/multiple/foreign-project credentials always hold.

    Pinned primary: https://github.com/lxc/incus/blob/8f5e6c2235f6424ec59d3dc06f12e344a4a416e2/cmd/incusd/certificates.go#L1021
    Restricted TLS rights: https://github.com/lxc/incus/blob/8f5e6c2235f6424ec59d3dc06f12e344a4a416e2/internal/server/auth/driver_tls.go#L73
    """
    def __init__(self, client, owned, store):
        from . import cell_contract, ledger
        admin._root()
        try:
            require(type(owned) is cell_contract.OwnedCellForCleanup and type(store) is ledger.Ledger
                    and store.owner_uid == 0 and type(client) is admin.RootIncusAdmin, "mutation-cleanup-input")
            require(cell_contract.owned_cell_for_cleanup(owned.registry, owned.selector, store, owned.lease_id) == owned,
                    "mutation-cleanup-owner-drift")
            value = owned.incus
            owner = Ownership(**value["ownership"])
            project = ProjectSpec(value["project"], value["network"], value["pool"], ProjectLimits(**value["project_limits"]), owner)
            bridge = BridgeSpec(value["network"], value["ipv4_address"], value["dns_domain"], owner)
            _project(project)
            _bridge(bridge)
            target = client._target
            original = owned.creator_targets["certificate-create"].removeprefix("certificate:")
            require(HEX.fullmatch(original) and target.project == project.project and target.network == bridge.network
                    and target.network_project == "default" and target.pool == project.pool
                    and target.certificate_fingerprints == (original,), "mutation-cleanup-target")
            self._client, self._project, self._bridge = client, project, bridge
            self._fingerprint, self._certificate = original, None
            self._owner, self._store = owned, store
            self._attempts, self._operations = set(), {}
            self._scope()
        except Exception:
            raise MutationDenied("mutation-cleanup-denied") from None

    def _scope(self):
        from . import cell_contract, ledger
        require(cell_contract.owned_cell_for_cleanup(self._owner.registry, self._owner.selector,
                self._store, self._owner.lease_id) == self._owner, "mutation-cleanup-owner-drift")
        record = self._store.read(self._owner.lease_id)
        creator = record["effects"][self._owner.creators["certificate-create"]["id"]]
        scope = creator.get("certificate_scope")
        ledger._certificate_scope(scope, self._owner.lease_id, creator, list(record["effects"].values()))
        return scope

    def project_create(self):
        raise MutationDenied("mutation-cleanup-only")

    def bridge_create(self):
        raise MutationDenied("mutation-cleanup-only")

    def certificate_create(self):
        raise MutationDenied("mutation-cleanup-only")

    def configure_default_profile(self):
        raise MutationDenied("mutation-cleanup-only")

    def quiet_project(self):
        """Two whole empty snapshots, not permanent quiescence or foreign-op adoption."""
        self._scope()
        self._backend()
        first, operations = self._client.instances(), self._client.operations()
        require(not first and all(not rows for rows in operations.values()), "mutation-project-not-quiet")
        second, operations2 = self._client.instances(), self._client.operations()
        require(second == first and operations2 == operations, "mutation-project-not-quiet")
        return {"state": "quiet_observed", "instances_sha256": digest(first), "operations_sha256": digest(operations)}

    def stop_inventory(self):
        """Stable exact declared VM only; foreign resources/operations hold.

        Mutable job labels alone are not authority: this also requires the
        freshly sealed cell and its unique verified Root-created project.
        """
        self._scope()
        self._backend()
        value = self._owner.incus
        name, project = value["instance"], value["project"]
        require(self._client._target.instance == name, "mutation-instance-target")
        expected_url = "/1.0/instances/" + name + "?" + urlencode({"project": project})
        expected_labels = {"user.lit-molecule-owner": value["ownership"]["owner"],
            "user.lit-molecule-repository": value["ownership"]["repository"],
            "user.lit-molecule-run-id": str(value["ownership"]["run_id"]),
            "user.lit-molecule-attempt": str(value["ownership"]["run_attempt"]),
            "user.lit-molecule-scenario": value["ownership"]["scenario"],
            "user.lit-molecule-target": value["ownership"]["target"]}
        def observe():
            rows, operations = self._client.instances(), self._client.operations()
            require(rows in ([], [expected_url]), "mutation-instance-inventory")
            record = self._store.read(self._owner.lease_id)
            permitted = {row["incus_operation_id"] for row in record["effects"].values()
                if row["operation"] in {"certificate-revoke", "instance-stop"}
                and row["state"] in {"intent", "verified"} and "incus_operation_id" in row}
            require(all(row["id"] in permitted and row["class"] == "task" and row["status_code"] == 200
                        and row.get("err", "") == "" for group in operations.values() for row in group),
                    "mutation-instance-operation-held")
            if not rows:
                return {"state": "absent_observed", "operations_sha256": digest(operations)}
            instance, state = self._client.instance(), self._client.instance_state()
            require(instance.get("name") == name and instance.get("type") == "virtual-machine"
                    and type(instance.get("config")) is dict
                    and all(instance["config"].get(key) == expected for key, expected in expected_labels.items()),
                    "mutation-instance-owner")
            require((state.get("status"), state.get("status_code")) in {("Running", 103), ("Stopped", 102)},
                    "mutation-instance-state")
            require(type(state.get("pid")) is int and state["pid"] >= 0
                    and (state["status_code"] != 103 or state["pid"] > 0), "mutation-instance-state")
            return {"state": "stopped_observed" if state["status_code"] == 102 else "running_observed",
                    "instance_sha256": digest(instance),
                    "state_sha256": digest({key: state[key] for key in ("status", "status_code", "pid")}),
                    "operations_sha256": digest(operations)}
        first, second = observe(), observe()
        require(first == second, "mutation-instance-drift")
        return first

    def instance_stop(self, timeout):
        """One graceful, non-stateful stop, exclusively from a durable intent."""
        require(type(timeout) is int and 1 <= timeout <= 30, "mutation-instance-timeout")
        require(self.stop_inventory()["state"] == "running_observed", "mutation-instance-not-running")
        value = self._owner.incus
        target = "instance:" + value["project"] + ":" + value["instance"]
        effects = self._store.read(self._owner.lease_id)["effects"].values()
        require(sum(row["operation"] == "instance-stop" and row["target"] == target
                    and row["state"] == "intent" for row in effects) == 1, "mutation-instance-intent")
        path = "/1.0/instances/" + value["instance"] + "/state?" + urlencode({"project": value["project"]})
        return self._mutate("instance-stop", target, "PUT", path,
                            {"action": "stop", "timeout": timeout, "force": False, "stateful": False})

    def certificate_inventory(self):
        scope = self._scope()
        self._backend()
        rows, sha = _certificate_inventory(self._client)
        selected = []
        for row in rows:
            touches = row["name"] == scope["name"] or self._project.project in row["projects"]
            if touches or row["fingerprint"] == self._fingerprint:
                require(row["name"] == scope["name"] and row["type"] == "client" and row["restricted"] is True
                        and row["projects"] == scope["projects"], "mutation-certificate-scope-conflict")
                selected.append(row["fingerprint"])
        require(len(selected) <= 1, "mutation-certificate-scope-multiple")
        _, sha2 = _certificate_inventory(self._client)
        require(sha == sha2, "mutation-certificate-inventory-drift")
        return CertificateInventory(self._fingerprint, tuple(selected), (), sha, digest(scope))

    def certificates_absent(self):
        """Complete stable scope absence, never merely original-fingerprint 404."""
        first = self.certificate_inventory()
        second = self.certificate_inventory()
        require(first == second, "mutation-certificate-inventory-drift")
        return not first.fingerprints

    def certificate_delete(self):
        """Exactly one DELETE, actual current FP bound BEFORE send on original intent."""
        snapshot = self.certificate_inventory()
        require(len(snapshot.fingerprints) == 1, "mutation-certificate-not-present")
        record = self._store.read(self._owner.lease_id)
        target = "certificate:" + self._fingerprint
        matches = [row for row in record["effects"].values() if row["operation"] == "certificate-revoke"
                   and row["target"] == target and row["state"] == "intent"]
        require(len(matches) == 1 and matches[0].get("certificate_revocation") == {
            "current_fingerprint": snapshot.fingerprints[0], "scope_sha256": snapshot.scope_sha256,
            "inventory_sha256": snapshot.inventory_sha256}, "mutation-certificate-revocation-unbound")
        return self._mutate("certificate-revoke", target, "DELETE", "/1.0/certificates/" + snapshot.fingerprints[0])

    def readback(self, kind):
        require(type(kind) is str and kind in {"certificate", "project", "bridge", "profile"}, "mutation-cleanup-readback-kind")
        if kind == "certificate":
            snapshot = self.certificate_inventory()
            return {"state": "required_fields_match" if snapshot.fingerprints else "absent_observed",
                    "metadata_sha256": snapshot.inventory_sha256}
        self._scope()
        return super().readback(kind)

    def project_delete(self):
        self.quiet_project()
        require(self.certificates_absent(), "mutation-certificate-still-present")
        return super().project_delete()

    def bridge_delete(self):
        self._scope()
        require(self.certificates_absent(), "mutation-certificate-still-present")
        return super().bridge_delete()
