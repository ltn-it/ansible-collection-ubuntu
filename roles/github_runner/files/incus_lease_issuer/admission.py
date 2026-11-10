"""Root-only admission bridge over an already connected Unix stream socket.

This module neither binds/listens on a socket nor initializes a ledger, activates
an issuer, signs context, creates TLS credentials or grants an engine operation.
Its immutable policy is provisioned by trusted Root code, never request JSON.
Cell bytes and archived custody references are bindings, NOT operating acceptance
or validated cell semantics; those remain the full Root caller's obligations.

A request may carry a short-lived job GITHUB_TOKEN solely as native metadata-read
transport. Signed OIDC + independently acquired current assignment + the Root
collector remain authority. No PAT minting or new App permissions are assumed.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import os
from pathlib import PurePosixPath
import select
import socket
import stat
import struct
import time
import threading
import weakref

from . import collector, identity, installation, ledger, service
from .identity import Denied, require

MAX_REQUEST_BYTES = 20480
MAX_TOKEN_BYTES = 16384
FRAME_TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class AdmissionPolicy:
    collector: collector.CollectorPolicy
    identity: identity.Policy
    ledger_path: str
    api_read_token_path: str | None
    cell_config_path: str
    cell_sha256: str
    custody_policy_sha256: str
    deadline: int


def _root():
    require(os.geteuid() == 0, "admission-root-required")


def _absolute(value):
    require(type(value) is str and value.startswith("/") and value != "/" and len(value) <= 4096
            and str(PurePosixPath(value)) == value and ".." not in PurePosixPath(value).parts
            and not any(ord(c) < 32 or ord(c) == 127 for c in value), "admission-root-path")


def _validate_policy(policy):
    _root()
    require(type(policy) is AdmissionPolicy and type(policy.collector) is collector.CollectorPolicy
            and type(policy.identity) is identity.Policy, "admission-policy")
    policy.identity.validate()
    native_name = getattr(policy.identity, "required_native_job_name", None)
    require(type(native_name) is str and 0 < len(native_name) <= 1024
            and not any(ord(c) < 32 or ord(c) == 127 for c in native_name), "admission-native-cell-job-required")
    service.validate_policy(policy.collector.service)
    install = policy.collector.service.installation
    require(policy.identity.runner_id == install.runner_id
            and policy.identity.service_uid == install.service_uid, "admission-policy-runner")
    _absolute(policy.ledger_path)
    _absolute(policy.cell_config_path)
    if policy.api_read_token_path is not None:
        _absolute(policy.api_read_token_path)
        require(policy.api_read_token_path != policy.cell_config_path, "admission-policy-path")
    require(type(policy.cell_sha256) is str and ledger.HEX.fullmatch(policy.cell_sha256)
            and type(policy.custody_policy_sha256) is str and ledger.HEX.fullmatch(policy.custody_policy_sha256)
            and type(policy.deadline) is int and policy.deadline > 0, "admission-policy-binding")


def _secret(value):
    require(type(value) is str and 0 < len(value) <= MAX_TOKEN_BYTES
            and all(33 <= ord(c) <= 126 for c in value), "admission-token-input")
    return value


def _root_token(path):
    proof = installation.trusted_file(path, max_bytes=MAX_TOKEN_BYTES)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(before.st_uid == 0 and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                and (before.st_dev, before.st_ino, before.st_size) == (proof.device, proof.inode, proof.size),
                "admission-root-token-private")
        raw = os.read(fd, MAX_TOKEN_BYTES + 1)
        require(hashlib.sha256(raw).hexdigest() == proof.sha256
                and installation.trusted_file(path, max_bytes=MAX_TOKEN_BYTES) == proof,
                "admission-root-token-drift")
        return _secret(raw.decode("ascii").removesuffix("\n")), proof
    finally:
        os.close(fd)


def _controls(policy):
    from . import cell_contract
    proof = installation.trusted_file(policy.cell_config_path, max_bytes=cell_contract.MAX_CELL)
    require(proof.sha256 == policy.cell_sha256, "admission-cell-bytes-drift")
    token, token_proof = (None, None) if policy.api_read_token_path is None else _root_token(policy.api_read_token_path)
    return (proof, token_proof), token


def _socket(connected):
    require(isinstance(connected, socket.socket) and connected.family == socket.AF_UNIX
            and connected.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM,
            "admission-connected-unix-required")
    connected.getpeername()


def _read_exact(connected, count, deadline):
    chunks, size = [], 0
    while size < count:
        remaining = deadline - time.monotonic()
        require(remaining > 0 and select.select([connected], [], [], remaining)[0], "admission-frame-timeout")
        try:
            part = connected.recv(count - size, socket.MSG_DONTWAIT)
        except BlockingIOError:
            continue
        require(part, "admission-frame-truncated")
        chunks.append(part)
        size += len(part)
    return b"".join(chunks)


def _request(connected, job_api_token):
    _socket(connected)
    deadline = time.monotonic() + FRAME_TIMEOUT_SECONDS
    length = struct.unpack("!I", _read_exact(connected, 4, deadline))[0]
    require(0 < length <= MAX_REQUEST_BYTES, "admission-frame-size")
    raw = _read_exact(connected, length, deadline)
    try:
        require(not connected.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT), "admission-frame-trailing")
    except BlockingIOError:
        pass
    request = identity.decode_json(raw)
    require(type(request.get("schema")) is int and request["schema"] == 1
            and request.get("operation") in ("challenge", "admit", "refresh", "recover"), "admission-request-schema")
    operation = request["operation"]
    fields = {"schema", "operation"}
    if operation != "challenge":
        fields |= {"nonce", "token"}
        if job_api_token:
            fields.add("api_token")
        require(type(request.get("nonce")) is str and ledger.HEX.fullmatch(request["nonce"]), "admission-nonce")
        _secret(request.get("token"))
        if job_api_token:
            _secret(request.get("api_token"))
    if operation == "refresh":
        fields.add("lease_id")
        require(type(request.get("lease_id")) is str and ledger.ID.fullmatch(request["lease_id"]), "admission-lease-id")
    require(set(request) == fields, "admission-request-fields")
    return request


def _worker(connected, policy):
    # collect_worker itself acquires SO_PEERCRED and revalidates boot/lineage,
    # exact service, installation, loaded-code closure and anti-injection state.
    result = collector.collect_worker(connected, policy.collector)
    require(type(result) is ledger.Worker, "admission-collected-worker")
    result.validate()
    require(result.runner_id == policy.identity.runner_id and result.uid == policy.identity.service_uid,
            "admission-collected-worker-binding")
    return result


@dataclass(frozen=True, eq=False)
class _NativeProof:
    worker: ledger.Worker
    identity: identity.Identity
    nonce: str
    policy: AdmissionPolicy
    controls: tuple
    connected: object
    fd: int
    pid: int
    thread: int
    until: float


_NATIVE_PROOFS = weakref.WeakSet()
_NATIVE_GUARD = threading.Lock()


def _receiver_run(selected, who):
    """A prepared Main request cannot be borrowed by another genuine Main run."""
    if not identity.validation_main_receiver(selected.identity):
        return
    from . import cell_contract
    proof, raw, _ = installation._file(selected.cell_config_path, cell_contract.MAX_CELL,
                                       private=True, keep=True)
    require(proof.sha256 == selected.cell_sha256, "runtime-receiver-cell-drift")
    value = identity.decode_json(raw)
    github = value.get("github")
    require(type(github) is dict and set(github) == {"job", "workflow", "run_id"}
            and type(github["run_id"]) is int and github["run_id"] > 0
            and github["run_id"] == who.run_id, "runtime-receiver-run-binding")


def verify_runtime_native(connected_socket, selected, nonce, token, api_token):
    """Verify a parsed v2 proof without framing, lease mutation or renewal.

    JWT/API bearers are used only during this call and never retained in the
    resulting process-local capability. Ledger consumes its nonce/JTI later.
    """
    _root()
    try:
        _validate_policy(selected)
        _socket(connected_socket)
        require(type(nonce) is str and ledger.HEX.fullmatch(nonce), "runtime-native-nonce")
        _secret(token)
        controls, root_bearer = _controls(selected)
        if selected.api_read_token_path is None:
            bearer = _secret(api_token)
        else:
            require(api_token is None, "runtime-native-token-mode")
            bearer = root_bearer
        before = _worker(connected_socket, selected)
        who = identity.verify_github_assignment(token, selected.identity,
            audience=ledger.AUDIENCE + nonce, peer_uid=before.uid,
            access_token=bearer, clock=time.time)
        require(type(who) is identity.Identity
                and who.policy_sha256 == identity.policy_digest(selected.identity),
                "runtime-native-policy")
        _receiver_run(selected, who)
        require(_worker(connected_socket, selected) == before
                and _controls(selected)[0] == controls, "runtime-native-provenance-drift")
        proof = _NativeProof(before, who, nonce, selected, controls, weakref.ref(connected_socket),
                             connected_socket.fileno(), os.getpid(), threading.get_ident(),
                             time.monotonic() + FRAME_TIMEOUT_SECONDS)
        with _NATIVE_GUARD:
            _NATIVE_PROOFS.add(proof)
        return proof
    except Exception:
        raise Denied("runtime-native-denied") from None


def _require_native(proof, connected_socket, selected):
    """Reacquire provenance for the same live socket and minted native proof."""
    _root()
    require(type(proof) is _NativeProof, "runtime-native-proof")
    with _NATIVE_GUARD:
        require(proof in _NATIVE_PROOFS, "runtime-native-proof")
    require(proof.pid == os.getpid() and proof.thread == threading.get_ident()
            and proof.connected() is connected_socket and proof.fd == connected_socket.fileno()
            and proof.policy == selected and time.monotonic() < proof.until
            and int(time.time()) < proof.identity.valid_until, "runtime-native-proof-expired")
    _socket(connected_socket)
    require(_controls(selected)[0] == proof.controls
            and _worker(connected_socket, selected) == proof.worker, "runtime-native-provenance-drift")
    return proof.worker, proof.identity


class AdmissionBridge:
    """Trusted Root factory input only. There are no per-request policy hooks.

    The future local server owns framing/replies and real operating disposition.
    handle consumes one four-byte big-endian length-prefixed JSON request and
    returns only bounded safe metadata. No connected listener is installed here.
    """
    def __init__(self, policy, *, expected_operation=None):
        _validate_policy(policy)
        require(expected_operation is None or (type(expected_operation) is str
                and expected_operation in {"challenge", "admit", "refresh", "recover"}),
                "admission-root-operation")
        self._policy = policy
        self._expected_operation = expected_operation

    def handle(self, connected_unix_socket):
        _root()
        try:
            policy = self._policy
            _validate_policy(policy)
            request = _request(connected_unix_socket, policy.api_read_token_path is None)
            require(self._expected_operation is None or request["operation"] == self._expected_operation,
                    "admission-operation-mismatch")
            now = int(time.time())
            require(0 < policy.deadline - now <= 5400, "admission-root-deadline")
            controls, root_api_token = _controls(policy)
            before = _worker(connected_unix_socket, policy)
            # Open only an existing initialized Root store; no archive/init or
            # owner override is reconstructed from a job's request.
            with ledger.Ledger(policy.ledger_path, clock=time.time) as store:
                if request["operation"] == "challenge":
                    after = _worker(connected_unix_socket, policy)
                    require(after == before and _controls(policy)[0] == controls, "admission-provenance-drift")
                    challenge = store.challenge(after, ttl=min(300, policy.deadline - int(time.time())))
                    return {"schema": 1, "operation": "challenge", **challenge}
                if request["operation"] == "refresh":
                    existing = store.read(request["lease_id"])
                    require(existing["worker"] == asdict(before) and existing["state"] == "prepared"
                            and existing["expires_at"] == policy.deadline
                            and existing["cell_sha256"] == policy.cell_sha256
                            and existing["policy_sha256"] == policy.custody_policy_sha256,
                            "admission-refresh-root-binding")
                bearer = request["api_token"] if policy.api_read_token_path is None else root_api_token
                who = identity.verify_github_assignment(request["token"], policy.identity,
                    audience=ledger.AUDIENCE + request["nonce"], peer_uid=before.uid,
                    access_token=bearer, clock=time.time)
                after = _worker(connected_unix_socket, policy)
                require(after == before and _controls(policy)[0] == controls, "admission-provenance-drift")
                require(type(who) is identity.Identity, "admission-verified-identity")
                require(who.policy_sha256 == identity.policy_digest(policy.identity),
                        "admission-verified-policy")
                if request["operation"] == "admit":
                    identifier = store.prepare(request["nonce"], after, who,
                        policy_sha256=policy.custody_policy_sha256, cell_sha256=policy.cell_sha256,
                        deadline=policy.deadline)
                elif request["operation"] == "recover":
                    identifier = store.recover(request["nonce"], after, who,
                        policy_sha256=policy.custody_policy_sha256, cell_sha256=policy.cell_sha256,
                        deadline=policy.deadline)
                else:
                    identifier = request["lease_id"]
                    store.refresh_identity(identifier, request["nonce"], after, who)
                return {"schema": 1, "operation": request["operation"], "lease_id": identifier,
                        "expires_at": policy.deadline}
        except Exception:
            # Do not expose request JWT/API bearer, raw metadata/claims, native
            # response bodies or paths through an exception to the local client.
            raise Denied("admission-denied") from None
