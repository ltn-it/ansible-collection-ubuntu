"""Root-only TLS2 context authentication primitive; no TLS or engine grant.

Trusted callers supply policy, collected Worker and an existing prepared Ledger.
There is no request handler, key generation, issuer activation or acceptance
flag. Certificate restriction, revocation, network fencing and operating window
qualification remain separate obligations. Never construct these inputs from
candidate/job JSON. Verification authenticates bytes against independent Root
expectations; syntactically valid JWS is never sufficient.
"""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import datetime as dt
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import identity, installation, ledger
from .identity import Denied, require

FILES = ("config.yml", "client.crt", "client.key", "servercerts/quality.crt")
BASE = frozenset({"schema", "repository", "run_id", "run_attempt", "server", "project", "expires_at", "runtime"})
PURPOSE = "legacy-incus-tls2"
TYPE = "lit-incus-context+jws"


@dataclass(frozen=True)
class ContextPolicy:
    identity: identity.Policy
    server: str
    project: str
    deadline: int
    cell_sha256: str
    custody_policy_sha256: str
    controller_sha256: str
    ee_sha256: str
    engine_policy_sha256: str
    # Canonical Root-fixed facts. None is ONLY the standalone legacy component
    # fixture contract; the real materializer/preparation always require facts.
    expected_runtime: bytes | None = None


def _root():
    require(os.geteuid() == 0, "context-root-required")


def _public(raw):
    require(type(raw) is bytes and len(raw) == 32, "context-public-key")
    return Ed25519PublicKey.from_public_bytes(raw)


def _header(raw):
    _public(raw)
    return {"alg": "EdDSA", "typ": TYPE, "kid": hashlib.sha256(raw).hexdigest()}


def _runtime(value, *, allow_legacy=False):
    require(type(value) is dict, "context-runtime")
    if allow_legacy and value == {"firewall_controller": "incus"}:
        return value
    require(set(value) == {"firewall_controller", "bridge", "storage_pool"}
            and value["firewall_controller"] == "incus", "context-runtime")
    bridge = value["bridge"]
    require(type(bridge) is dict and set(bridge) == {
        "name", "project", "owner", "ipv4_address", "dns_domain", "dhcp", "nat", "firewall", "ipv6_address"},
        "context-runtime-bridge")
    require(type(bridge["name"]) is str and re.fullmatch(r"lit[0-9a-f]{12}", bridge["name"])
            and bridge["project"] == "default" and bridge["ipv6_address"] == "none"
            and type(bridge["owner"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}", bridge["owner"])
            and all(type(bridge[k]) is bool and bridge[k] for k in ("dhcp", "nat", "firewall")),
            "context-runtime-bridge")
    require(type(bridge["ipv4_address"]) is str, "context-runtime-address")
    subnet = ipaddress.IPv4Interface(bridge["ipv4_address"])
    require(str(subnet) == bridge["ipv4_address"] and 8 <= subnet.network.prefixlen <= 30
            and subnet.ip not in (subnet.network.network_address, subnet.network.broadcast_address), "context-runtime-address")
    require(type(bridge["dns_domain"]) is str and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]", bridge["dns_domain"])
            and type(value["storage_pool"]) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", value["storage_pool"]), "context-runtime-target")
    return value


def runtime_for_cell(prepared):
    """Derive nonsecret facts from the semantic Root cell, never request JSON.

    This is not a native readback or operating approval. The Root preparation
    caller must re-read its exact BridgeSpec before materializing/publishing.
    """
    from . import cell_contract
    _root()
    require(type(prepared) is cell_contract.PreparedCell, "context-runtime-cell")
    value = prepared.incus
    return _runtime({"firewall_controller": "incus", "bridge": {
        "name": value["network"], "project": "default", "owner": value["ownership"]["owner"],
        "ipv4_address": value["ipv4_address"], "dns_domain": value["dns_domain"],
        "dhcp": True, "nat": True, "firewall": True, "ipv6_address": "none"}, "storage_pool": value["pool"]})


def _sealed(path, limit=1048576):
    """Read bounded private Root bytes with ancestor and replacement checks."""
    proof = installation.trusted_file(path, max_bytes=limit)
    fd = os.open(path, installation.FILE_FLAGS)
    try:
        before = os.fstat(fd)
        require(stat.S_IMODE(before.st_mode) == 0o600 and before.st_uid == 0 and before.st_nlink == 1
                and (before.st_dev, before.st_ino, before.st_size) == (proof.device, proof.inode, proof.size),
                "context-file-private")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        require(len(raw) <= limit and hashlib.sha256(raw).hexdigest() == proof.sha256
                and installation.trusted_file(path, max_bytes=limit) == proof,
                "context-file-drift")
        return raw, proof
    finally:
        os.close(fd)


def _projection(binding):
    require(type(binding) is dict and set(binding) in (BASE, BASE | {"admission"}), "context-binding-fields")
    projected = {k: v for k, v in binding.items() if k != "admission"}
    require(type(projected["schema"]) is int and projected["schema"] == 2
            and type(projected["runtime"]) is dict, "context-binding-schema")
    _runtime(projected["runtime"], allow_legacy=True)
    # Strict shallow field types also reject recursive/admission payload objects.
    require(all(type(projected[k]) is str for k in BASE - {"schema", "runtime"}), "context-binding-types")
    require(re.fullmatch(r"[1-9][0-9]{0,19}", projected["run_id"])
            and projected["run_attempt"] == "1", "context-binding-invocation")
    return projected


def _files(directory, binding, token):
    installation._absolute(directory)
    root = Path(directory)
    for path in (root, root / "servercerts"):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) == 0o700, "context-directory-private")
    require(set(os.listdir(root)) == {"binding.json", "config.yml", "client.crt", "client.key", "servercerts"}
            and set(os.listdir(root / "servercerts")) == {"quality.crt"}, "context-file-inventory")
    raw, _ = _sealed(str(root / "binding.json"), 32768)
    actual = identity.decode_json(raw)
    require(_projection(actual) == _projection(binding), "context-binding-file")
    if token is None:
        require("admission" not in actual and "admission" not in binding, "context-recursive-admission")
    else:
        require(actual.get("admission") == token
                and ("admission" not in binding or binding["admission"] == token), "context-admission-file")
    return {name: hashlib.sha256(_sealed(str(root / name))[0]).hexdigest() for name in FILES}


def _expected(store, lease_id, worker, policy, binding, directory, token, now):
    _root()
    require(type(now) is int and now > 0 and type(store) is ledger.Ledger and store.owner_uid == 0,
            "context-root-ledger")
    require(type(worker) is ledger.Worker and type(policy) is ContextPolicy
            and type(policy.identity) is identity.Policy, "context-trusted-input")
    worker.validate()
    policy.identity.validate()
    require(policy.identity.required_native_job_name is not None, "context-native-cell-job")
    require(type(policy.deadline) is int and 0 < policy.deadline - now <= 5400, "context-expired")
    for field in ("cell_sha256", "custody_policy_sha256", "controller_sha256", "ee_sha256", "engine_policy_sha256"):
        require(type(getattr(policy, field)) is str and ledger.HEX.fullmatch(getattr(policy, field)),
                "context-policy-digest")
    require(type(policy.server) is str and type(policy.project) is str
            and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", policy.project)
            and policy.project != "default", "context-server-project")
    url = urlsplit(policy.server)
    require(url.scheme == "https" and url.hostname and not url.username and not url.password
            and url.path in ("", "/") and not url.query and not url.fragment, "context-server-project")
    body = _projection(binding)
    expiry = dt.datetime.fromtimestamp(policy.deadline, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = store.read(lease_id)
    who = record["identity"]
    auth = record["authorizations"][-1]
    require(record["state"] == "prepared" and record["expires_at"] == policy.deadline
            and record["created_at"] <= now < record["expires_at"] and auth["valid_until"] > now,
            "context-lease-inactive")
    require(record["worker"] == asdict(worker) and record["cell_sha256"] == policy.cell_sha256
            and record["policy_sha256"] == policy.custody_policy_sha256
            and who["runner_id"] == worker.runner_id == policy.identity.runner_id
            and who["service_uid"] == worker.uid == policy.identity.service_uid
            and who["caller_sha"] == policy.identity.caller_sha
            and who["reusable_sha"] == policy.identity.reusable_sha
            and who.get("policy_sha256") == identity.policy_digest(policy.identity), "context-lease-binding")
    runtime = {"firewall_controller": "incus"}
    if policy.expected_runtime is not None:
        require(type(policy.expected_runtime) is bytes and 0 < len(policy.expected_runtime) <= 4096,
                "context-runtime-policy")
        runtime = _runtime(identity.decode_json(policy.expected_runtime))
        require(ledger.canonical(runtime) == policy.expected_runtime, "context-runtime-policy")
    require(body == {"schema": 2, "repository": policy.identity.repository, "run_id": str(who["run_id"]),
                     "run_attempt": "1", "server": policy.server, "project": policy.project,
                     "expires_at": expiry, "runtime": runtime}, "context-binding-policy")
    trusted_policy = asdict(policy.identity)
    trusted_policy["actor_ids"] = sorted(policy.identity.actor_ids)
    return {"schema": 1, "purpose": PURPOSE, "lease_id": lease_id,
            "created_at": record["created_at"], "expires_at": policy.deadline,
            "binding_sha256": ledger.digest(body), "files_sha256": _files(directory, binding, token),
            "identity": who, "authorization": auth, "worker": asdict(worker), "policy": trusted_policy,
            **{k: getattr(policy, k) for k in ("cell_sha256", "custody_policy_sha256", "controller_sha256",
                                             "ee_sha256", "engine_policy_sha256")}}


def _base(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class RootSigner:
    """Use one provisioned sealed Ed25519 key pinned to raw public bytes.

    No key generation, fallback, rotation, network key lookup or job input API.
    The caller owns writing admission into binding.json after successful issue.
    """
    def __init__(self, key_path, expected_public_key):
        _root()
        self._path, self._public = key_path, expected_public_key
        _public(expected_public_key)
        try:
            self._load()
        except Denied:
            raise
        except Exception:
            raise Denied("context-signing-key") from None

    def _load(self):
        raw, proof = _sealed(self._path, 8192)
        try:
            key = serialization.load_pem_private_key(raw, password=None)
        except (ValueError, TypeError):
            raise Denied("context-signing-key") from None
        require(isinstance(key, Ed25519PrivateKey), "context-signing-key")
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        require(public == self._public, "context-signing-key-pin")
        if hasattr(self, "_proof"):
            require(proof == self._proof, "context-signing-key-drift")
        self._proof = proof
        return key

    def issue(self, store, lease_id, worker, policy, binding, context_dir):
        try:
            now = int(time.time())
            expected = _expected(store, lease_id, worker, policy, binding, context_dir, None, now)
            key = self._load()
            data = _base(ledger.canonical(_header(self._public))) + "." + _base(ledger.canonical(expected))
            # Re-read ledger and context before signing; no authority survives drift.
            require(_expected(store, lease_id, worker, policy, binding, context_dir, None, int(time.time())) == expected,
                    "context-provenance-drift")
            token = data + "." + _base(key.sign(data.encode("ascii")))
            require(len(token) <= 16384, "context-token-size")
            return token
        except Denied:
            raise
        except Exception:
            raise Denied("context-signing-denied") from None


    def issue_final_receipt(self, registry, selector, store, lease_id):
        """Sign ONLY actual closed operating proof, never a supplied payload.

        The original provisioned public pin is external authority. This new
        purpose does not reissue expired engine access or sign pending quality.
        """
        from . import operating_custody
        payload = operating_custody.final_receipt_payload(registry, selector, store, lease_id,
                                                         self._public.hex())
        key = self._load()
        header = {"alg": "EdDSA", "typ": "lit-incus-final-quality+jwt",
                  "kid": hashlib.sha256(self._public).hexdigest()}
        signing = _base(ledger.canonical(header)) + "." + _base(ledger.canonical(payload))
        expected = operating_custody.final_receipt_payload(registry, selector, store, lease_id,
                                                          self._public.hex(), issued_at=payload["issued_at"])
        require(expected == payload, "final-receipt-provenance-drift")
        token = signing + "." + _base(key.sign(signing.encode("ascii")))
        return {"schema": 1, "receipt": payload, "signature": token}


def _decode_signed(token, pinned_public_key):
    require(type(token) is str and 0 < len(token) <= 16384, "context-token-size")
    pieces = token.split(".")
    require(len(pieces) == 3, "context-token-shape")
    header = identity.decode_json(identity.unbase(pieces[0]))
    require(header == _header(pinned_public_key), "context-header")
    signature = identity.unbase(pieces[2])
    require(len(signature) == 64, "context-signature")
    _public(pinned_public_key).verify(signature, (pieces[0] + "." + pieces[1]).encode("ascii"))
    raw = identity.unbase(pieces[1])
    return identity.decode_json(raw), raw


def verify(token, pinned_public_key, store, lease_id, worker, policy, binding, context_dir):
    """Independently authenticate against current Root expectations; grants nothing."""
    _root()
    try:
        payload, raw = _decode_signed(token, pinned_public_key)
        expected = _expected(store, lease_id, worker, policy, binding, context_dir, token, int(time.time()))
        require(payload == expected and raw == ledger.canonical(expected),
                "context-payload-binding")
        require(_expected(store, lease_id, worker, policy, binding, context_dir, token, int(time.time())) == expected,
                "context-provenance-drift")
        return {"lease_id": lease_id, "expires_at": expected["expires_at"],
                "binding_sha256": expected["binding_sha256"]}
    except InvalidSignature:
        raise Denied("context-signature") from None
    except Denied:
        raise
    except Exception:
        raise Denied("context-verification-denied") from None


def verify_previous_binding(token, pinned_public_key, store, lease_id, worker, policy, binding, context_dir):
    """Authenticate immutable old context bytes while requiring NEW live authority.

    This is integrity evidence for refresh only, never historical admission or
    network authority. No caller time/authorization override exists. The old
    authorization must be retained in this same lease's history; every other
    signed field and file digest must exactly match current Root expectations.
    Ordinary verify remains strictly current-authorization-only.
    """
    _root()
    try:
        payload, raw = _decode_signed(token, pinned_public_key)
        current = _expected(store, lease_id, worker, policy, binding, context_dir, token, int(time.time()))
        history = store.read(lease_id)["authorizations"][:-1]
        previous = payload.get("authorization")
        require(type(previous) is dict and any(ledger.canonical(previous) == ledger.canonical(auth) for auth in history),
                "context-previous-authorization")
        expected = current | {"authorization": previous}
        require(payload == expected and raw == ledger.canonical(expected), "context-previous-binding")
        require(_expected(store, lease_id, worker, policy, binding, context_dir, token, int(time.time())) == current
                and any(ledger.canonical(previous) == ledger.canonical(auth)
                        for auth in store.read(lease_id)["authorizations"][:-1]), "context-provenance-drift")
        return {"lease_id": lease_id, "binding_sha256": expected["binding_sha256"]}
    except InvalidSignature:
        raise Denied("context-signature") from None
    except Denied:
        raise
    except Exception:
        raise Denied("context-previous-verification-denied") from None
