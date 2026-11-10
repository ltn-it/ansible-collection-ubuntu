"""Private durable replay/effect ledger, not a lease or TLS authority.

Only the future root-owned handler may call this API. Worker values must come
from its kernel collector; Identity must come from verify_github_assignment.
Neither object, policy nor evidence records may be reconstructed from a job's
request JSON. Root policy archival records bytes, not operating acceptance.
"""
from __future__ import annotations

import contextlib
import copy
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import time

from .identity import Denied, Identity, decode_json, require

HEX = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[0-9a-f]{32}\Z")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
AUDIENCE = "urn:lightning-it:legacy-incus:"
# Fixed trusted implementation path; never a request/configuration parameter.
ENGINE_EXECUTABLE = "/usr/bin/podman"
MAX_CAPTURE_STREAM_BYTES = 64 * 1024 * 1024
RUNTIME_OPERATIONS = frozenset({"run", "heartbeat", "status", "cancel", "recover"})
CERTIFICATE_AUTHORIZER_PROFILE = "incus-7.6-tls-8f5e6c2235f6424ec59d3dc06f12e344a4a416e2"


def _certificate_scope(value, identifier, effect, effects):
    require(type(value) is dict and set(value) == {"initial_fingerprint", "name", "type", "restricted", "projects",
            "baseline_inventory_sha256", "authorizer_profile"}, "invalid-certificate-scope")
    require(type(value["initial_fingerprint"]) is str and HEX.fullmatch(value["initial_fingerprint"]),
            "invalid-certificate-scope")
    require(effect["operation"] == "certificate-create" and effect["target"] == "certificate:" + value["initial_fingerprint"]
            and type(value["initial_fingerprint"]) is str and HEX.fullmatch(value["initial_fingerprint"])
            and value["name"] == "lit-lease-" + identifier and value["type"] == "client" and value["restricted"] is True
            and type(value["projects"]) is list and len(value["projects"]) == 1
            and type(value["projects"][0]) is str
            and any(row["operation"] == "project-create" and row["state"] == "verified"
                    and row["target"] == "project:" + value["projects"][0] for row in effects)
            and type(value["baseline_inventory_sha256"]) is str and HEX.fullmatch(value["baseline_inventory_sha256"])
            and value["authorizer_profile"] == CERTIFICATE_AUTHORIZER_PROFILE, "invalid-certificate-scope")


def _certificate_revocation(value, effect, effects):
    require(type(value) is dict and set(value) == {"current_fingerprint", "scope_sha256", "inventory_sha256"}
            and all(type(item) is str and HEX.fullmatch(item) for item in value.values()), "invalid-certificate-revocation")
    matches = [row for row in effects if row["operation"] == "certificate-create" and row["state"] == "verified"
               and row["target"] == effect["target"] and "certificate_scope" in row]
    require(effect["operation"] == "certificate-revoke" and len(matches) == 1
            and digest(matches[0]["certificate_scope"]) == value["scope_sha256"], "invalid-certificate-revocation")


@dataclass(frozen=True)
class RuntimeProof:
    """Consumed native invocation locator, never a renewable authorization."""
    lease_id: str
    operation: str
    cell_sha256: str
    identity_policy_sha256: str
    worker_sha256: str
    identity_sha256: str
    valid_until: int


def _runtime_scope(operation, cell_sha256, identity_policy_sha256):
    require(type(operation) is str and operation in RUNTIME_OPERATIONS
            and type(cell_sha256) is str and HEX.fullmatch(cell_sha256)
            and type(identity_policy_sha256) is str and HEX.fullmatch(identity_policy_sha256),
            "invalid-runtime-scope")
    return {"operation": operation, "cell_sha256": cell_sha256,
            "identity_policy_sha256": identity_policy_sha256}
CREATES = {
    "certificate-create": "certificate-revoke", "instance-create": "instance-destroy",
    "network-create": "network-delete", "project-create": "project-delete",
    "context-create": "context-delete", "engine-start": "engine-stop",
    "engine-prepare": "engine-release",
    "fence-create": "fence-remove",
}
PROVISIONING = frozenset({"network-create", "project-create", "profile-configure", "context-create", "context-publish",
                          "engine-prepare", "engine-start", "fence-create"})
WITHDRAWALS = frozenset({"fence-disable"})
ONCE = PROVISIONING | WITHDRAWALS | {"instance-stop"}
CLEANUPS = frozenset(CREATES.values())
OBSERVATIONS = frozenset({"test", "capture", "evidence-upload"})
OPERATIONS = frozenset(CREATES) | CLEANUPS | OBSERVATIONS | WITHDRAWALS | {
    "profile-configure", "context-publish", "context-refresh", "fence-renew", "instance-stop"}
INCUS_OPERATIONS = frozenset({"network-create", "network-delete", "project-create", "project-delete",
                              "profile-configure", "certificate-create", "certificate-revoke",
                              "instance-create", "instance-destroy", "instance-stop"})


def _native_uuid(value):
    return type(value) is str and UUID.fullmatch(value) and value != "00000000-0000-0000-0000-000000000000"


def _validate_engine_process(value):
    require(type(value) is dict and set(value) == {
        "pid", "start_ticks", "boot_id", "executable", "exe_device", "exe_inode", "exe_sha256"},
        "invalid-engine-process")
    require(all(type(value[key]) is int and value[key] > 0 for key in ("pid", "start_ticks", "exe_inode"))
            and type(value["exe_device"]) is int and value["exe_device"] >= 0
            and _native_uuid(value["boot_id"]) and value["executable"] == ENGINE_EXECUTABLE
            and type(value["exe_sha256"]) is str and HEX.fullmatch(value["exe_sha256"]), "invalid-engine-process")


def _validate_engine_capture(value):
    require(type(value) is dict and set(value) == {
        "manifest_sha256", "cgroup_device", "cgroup_inode", "stdout_device", "stdout_inode",
        "stderr_device", "stderr_inode", "stdout_limit", "stderr_limit", "total_limit"}, "invalid-engine-capture")
    require(type(value["manifest_sha256"]) is str and HEX.fullmatch(value["manifest_sha256"])
            and all(type(value[key]) is int and value[key] >= 0
                    for key in ("cgroup_device", "stdout_device", "stderr_device"))
            and all(type(value[key]) is int and value[key] > 0
                    for key in ("cgroup_inode", "stdout_inode", "stderr_inode"))
            and (value["stdout_device"], value["stdout_inode"]) != (value["stderr_device"], value["stderr_inode"])
            and all(type(value[key]) is int and 0 < value[key] <= MAX_CAPTURE_STREAM_BYTES
                    for key in ("stdout_limit", "stderr_limit"))
            and type(value["total_limit"]) is int
            and 0 < value["total_limit"] <= value["stdout_limit"] + value["stderr_limit"], "invalid-engine-capture")


def _validate_engine_exit(value, effect):
    require(type(value) is dict and set(value) == {
        "pid", "start_ticks", "boot_id", "container_id", "manifest_sha256", "exit_code", "signal", "observed_at",
        "stdout_bytes", "stdout_sha256", "stdout_state", "stderr_bytes", "stderr_sha256", "stderr_state"},
        "invalid-engine-exit")
    process, capture = effect.get("engine_process"), effect.get("engine_capture")
    require(effect["operation"] == "engine-start" and effect["state"] in {"intent", "unknown", "verified"}
            and type(process) is dict and type(capture) is dict and "engine_container_id" in effect,
            "engine-exit-untracked")
    require(all(type(value[key]) is int and value[key] == process[key] for key in ("pid", "start_ticks"))
            and value["boot_id"] == process["boot_id"] and type(value["container_id"]) is str
            and value["container_id"] == effect["engine_container_id"]
            and value["manifest_sha256"] == capture["manifest_sha256"], "engine-exit-binding")
    code, signum = value["exit_code"], value["signal"]
    require((type(code) is int and 0 <= code <= 255 and signum is None)
            or (code is None and type(signum) is int and 1 <= signum <= 64), "invalid-engine-exit-status")
    require(type(value["observed_at"]) is int and value["observed_at"] >= effect["at"], "invalid-engine-exit-time")
    for stream in ("stdout", "stderr"):
        size, sha, state = (value[stream + suffix] for suffix in ("_bytes", "_sha256", "_state"))
        require(type(size) is int and 0 <= size <= capture[stream + "_limit"]
                and type(sha) is str and HEX.fullmatch(sha) and type(state) is str
                and state in {"complete", "limited", "incomplete"}
                and (size != 0 or sha == hashlib.sha256(b"").hexdigest()), "invalid-engine-exit-capture")
    require(value["stdout_bytes"] + value["stderr_bytes"] <= capture["total_limit"], "invalid-engine-exit-capture")


def _validate_fence(value):
    require(type(value) is dict and set(value) == {
        "policy_sha256", "boot_id", "netns_device", "netns_inode", "host_ifindex", "peer_ifindex", "nft_table_handle"},
        "invalid-fence-metadata")
    require(type(value["policy_sha256"]) is str and HEX.fullmatch(value["policy_sha256"])
            and _native_uuid(value["boot_id"]) and type(value["netns_device"]) is int and value["netns_device"] >= 0
            and all(type(value[key]) is int and value[key] > 0 for key in
                    ("netns_inode", "host_ifindex", "peer_ifindex", "nft_table_handle")), "invalid-fence-metadata")


def _validate_fence_authorization(value, lease, effect):
    require(type(value) is dict and set(value) == {
        "authorization_sha256", "allow_expires_at", "issued_boot_ns", "expires_boot_ns"}, "invalid-fence-authorization")
    authorization = value["authorization_sha256"]
    require(type(authorization) is str and HEX.fullmatch(authorization), "invalid-fence-authorization")
    token = effect["target"].rsplit(":", 1)[-1]
    auth = next((item for item in lease["authorizations"] if item["token_id_sha256"] == token), None)
    require(auth is not None and authorization == digest(auth) and type(value["allow_expires_at"]) is int
            and value["allow_expires_at"] == min(auth["valid_until"], lease["expires_at"])
            and all(type(value[key]) is int and value[key] > 0 for key in ("issued_boot_ns", "expires_boot_ns"))
            and 0 < value["expires_boot_ns"] - value["issued_boot_ns"]
            <= (value["allow_expires_at"] - effect["at"]) * 1000000000, "invalid-fence-authorization")


def _validate_host_api(value):
    require(type(value) is dict and set(value) == {"policy_sha256", "baseline_sha256", "boot_id",
            "host_netns_device", "host_netns_inode", "nft_table_handle"}, "invalid-host-api-fence")
    require(all(type(value[key]) is str and HEX.fullmatch(value[key]) for key in ("policy_sha256", "baseline_sha256"))
            and _native_uuid(value["boot_id"]) and type(value["host_netns_device"]) is int
            and value["host_netns_device"] >= 0 and all(type(value[key]) is int and value[key] > 0
                for key in ("host_netns_inode", "nft_table_handle")), "invalid-host-api-fence")


def _validate_host_api_authorization(value, lease, effect):
    require(type(value) is dict and set(value) == {"baseline_sha256", "host_ifindex", "peer_ipv4",
            "authorization_sha256", "allow_expires_at", "issued_boot_ns", "expires_boot_ns"},
            "invalid-host-api-authorization")
    _validate_fence_authorization({key: value[key] for key in (
        "authorization_sha256", "allow_expires_at", "issued_boot_ns", "expires_boot_ns")}, lease, effect)
    creator = [row for row in lease["effects"].values() if row["operation"] == "fence-create"
               and row["state"] == "verified" and "host_api" in row and "fence" in row]
    require(len(creator) == 1 and value["baseline_sha256"] == creator[0]["host_api"]["baseline_sha256"]
            and type(value["host_ifindex"]) is int and value["host_ifindex"] == creator[0]["fence"]["host_ifindex"]
            and type(value["peer_ipv4"]) is str, "invalid-host-api-authorization")
    try:
        address = ipaddress.IPv4Address(value["peer_ipv4"])
    except ValueError:
        raise Denied("invalid-host-api-authorization") from None
    require(str(address) == value["peer_ipv4"] and address.is_private and not address.is_loopback
            and not address.is_link_local and not address.is_multicast and not address.is_unspecified,
            "invalid-host-api-authorization")


def _target_valid(operation, target):
    if type(target) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}", target):
        return False
    if operation == "instance-stop":
        return bool(re.fullmatch(r"instance:[A-Za-z0-9][A-Za-z0-9_-]{0,62}:[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", target))
    if operation in {"project-create", "project-delete"}:
        return bool(re.fullmatch(r"project:[A-Za-z0-9][A-Za-z0-9_-]{0,62}", target)
                    and target != "project:default")
    if operation in {"network-create", "network-delete"}:
        return bool(re.fullmatch(r"network:default:lit[0-9a-f]{12}", target))
    if operation == "profile-configure":
        return bool(re.fullmatch(r"profile:[A-Za-z0-9][A-Za-z0-9_-]{0,62}:default", target)
                    and target != "profile:default:default")
    if operation in {"context-create", "context-delete", "context-publish"}:
        # Root selects this immutable cell/descriptor locator BEFORE TLS bytes
        # exist; it is not a claim about a final certificate or engine digest.
        return bool(re.fullmatch(r"context:[0-9a-f]{64}", target))
    if operation == "context-refresh":
        return bool(re.fullmatch(r"context:[0-9a-f]{64}:[0-9a-f]{64}", target))
    if operation in {"engine-prepare", "engine-release"}:
        return bool(re.fullmatch(r"engine:[0-9a-f]{32}", target))
    if operation in {"engine-start", "engine-stop"}:
        return bool(re.fullmatch(r"engine:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", target))
    if operation in {"fence-create", "fence-remove", "fence-disable"}:
        return bool(re.fullmatch(r"fence:[0-9a-f]{32}", target))
    if operation == "fence-renew":
        return bool(re.fullmatch(r"fence:[0-9a-f]{32}:[0-9a-f]{64}", target))
    return True


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


@dataclass(frozen=True)
class Worker:
    uid: int
    runner_id: int
    pid: int
    start_ticks: int
    boot_id: str

    def validate(self):
        require(all(type(v) is int and v > 0 for v in (self.uid, self.runner_id, self.pid, self.start_ticks)),
                "invalid-worker")
        require(type(self.boot_id) is str and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", self.boot_id), "invalid-worker")


class Ledger:
    """Open a pre-provisioned private store; never create an operating store.

    Production owner_uid is root0. Nonroot owner selection exists for isolated
    component tests, never as a job-request or deployment option. No public
    handler exists in this component. State is never silently reset or pruned.
    """

    def __init__(self, path, *, owner_uid=0, clock=time.time):
        self._setup(path, owner_uid, clock)
        try:
            with self._transaction():
                pass
        except BaseException:
            self.shutdown()
            raise

    def _setup(self, path, owner_uid, clock):
        require(type(owner_uid) is int and owner_uid >= 0, "invalid-store-owner")
        self.owner_uid, self.clock = owner_uid, clock
        path = Path(path)
        require(path.is_absolute() and ".." not in path.parts, "invalid-store-path")
        self.fd = -1
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for name in path.parts[1:]:
                following = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = following
                info = os.fstat(fd)
                require(info.st_uid in {0, owner_uid}, "untrusted-store-ancestor")
                writable = stat.S_IMODE(info.st_mode) & 0o022
                # Test temp directories may live below root's sticky /tmp.
                require(not writable or (owner_uid != 0 and info.st_uid == 0
                                         and info.st_mode & stat.S_ISVTX), "writable-store-ancestor")
            self._private(os.fstat(fd), directory=True)
            self.fd, fd = fd, -1
        except OSError:
            raise Denied("unsafe-store-path") from None
        finally:
            if fd >= 0:
                os.close(fd)

    @classmethod
    def initialize(cls, path, *, owner_uid=0, clock=time.time):
        """Explicit first installation into a new, empty, pre-provisioned store.

        Never call this as an automatic missing-state recovery. A partial
        initialization also fails closed and needs an operator disposition.
        """
        instance = object.__new__(cls)
        instance._setup(path, owner_uid, clock)
        try:
            require(not instance._entries(), "store-not-empty")
            lock = instance._open("lock", os.O_RDWR | os.O_CREAT | os.O_EXCL)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                require(set(instance._entries()) == {"lock"}, "store-not-empty")
                store_id = secrets.token_hex(16)
                marker = instance._open(".initialized", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                with os.fdopen(marker, "wb") as stream:
                    stream.write(canonical({"version": 1, "store_id": store_id}))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(instance.fd)
                instance._save({"version": 1, "store_id": store_id, "generation": 0, "policies": {},
                                "challenges": {}, "tokens": {}, "leases": {}})
            finally:
                os.close(lock)
        finally:
            instance.shutdown()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.shutdown()

    def shutdown(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def _entries(self):
        # fdopendir/listdir can leave the shared directory cursor at EOF.
        # Rewind the trusted descriptor; do not reopen an unchecked path.
        try:
            os.lseek(self.fd, 0, os.SEEK_SET)
            return os.listdir(self.fd)
        except OSError:
            raise Denied("store-read-failed") from None

    def _private(self, info, *, directory=False):
        require(info.st_uid == self.owner_uid
                and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
                and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                and (directory or info.st_nlink == 1), "unsafe-store-object")

    def _open(self, name, flags):
        try:
            fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=self.fd)
        except OSError:
            raise Denied("unsafe-store-object") from None
        try:
            self._private(os.fstat(fd))
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _load(self):
        marker = self._open(".initialized", os.O_RDONLY)
        with os.fdopen(marker, "rb") as stream:
            identity = decode_json(stream.read(1024))
        require(type(identity.get("version")) is int and identity["version"] == 1
                and type(identity.get("store_id")) is str and ID.fullmatch(identity["store_id"]), "ledger-corrupt")
        try:
            os.stat("state.json", dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            raise Denied("ledger-state-missing") from None
        fd = self._open("state.json", os.O_RDONLY)
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(8388609)
        require(len(raw) <= 8388608, "ledger-capacity")
        state = decode_json(raw)
        require(type(state.get("version")) is int and state["version"] == 1 and type(state.get("generation")) is int
                and state.get("store_id") == identity["store_id"]
                and all(type(state.get(k)) is dict for k in ("policies", "challenges", "tokens", "leases")),
                "ledger-corrupt")
        checksum = state.get("checksum")
        require(type(checksum) is str and checksum == digest({k: v for k, v in state.items() if k != "checksum"}),
                "ledger-corrupt")
        self._validate_state(state)
        return state

    def _save(self, state):
        state["generation"] += 1
        self._validate_state(state)
        state["checksum"] = digest({k: v for k, v in state.items() if k != "checksum"})
        raw = canonical(state)
        require(len(raw) <= 8388608 and sum(len(state[k]) for k in ("challenges", "tokens", "leases")) <= 10000,
                "ledger-capacity")
        name = ".state-" + secrets.token_hex(16)
        fd = self._open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            # Replace only the private directory entry, never follow a link.
            os.replace(name, "state.json", src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(name, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    @contextlib.contextmanager
    def _transaction(self):
        require(self.fd >= 0, "ledger-closed")
        self._private(os.fstat(self.fd), directory=True)
        fd = self._open("lock", os.O_RDWR)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Denied("ledger-busy") from None
            state = self._load()
            before = canonical(state)
            yield state
            if canonical(state) != before:
                self._save(state)
        finally:
            os.close(fd)

    def _now(self):
        now = self.clock()
        require(type(now) in {int, float} and math.isfinite(now) and now > 0, "invalid-clock")
        return int(now)

    @staticmethod
    def _validate_policy(policy):
        required = {"custodian_ref", "storage_ref", "approval_ref", "retention_seconds", "max_lease_seconds"}
        require(type(policy) is dict and set(policy) == required, "invalid-custody-policy")
        for key in ("custodian_ref", "storage_ref", "approval_ref"):
            value = policy[key]
            require(type(value) is str and 0 < len(value) <= 512
                    and not any(ord(c) < 32 for c in value), "invalid-custody-reference")
        require(type(policy["retention_seconds"]) is int and 0 < policy["retention_seconds"] <= 86400
                and type(policy["max_lease_seconds"]) is int and 0 < policy["max_lease_seconds"] <= 5400,
                "invalid-custody-limits")

    @classmethod
    def _validate_state(cls, state):
        """Detect malformed/crossed snapshots, not tampering by a root attacker."""
        try:
            for key, policy in state["policies"].items():
                cls._validate_policy(policy)
                require(HEX.fullmatch(key) and digest(policy) == key, "ledger-corrupt")
            used_invocations, live_runners, live_uids, token_links = set(), set(), set(), {}
            native_operations, engine_processes, engine_containers, fence_namespaces = set(), set(), set(), set()
            capture_streams, capture_cgroups = set(), set()
            certificate_revocations = set()
            fence_host_interfaces = set()
            for key, lease in state["leases"].items():
                require(ID.fullmatch(key) and lease["state"] in {"prepared", "cancelled", "closed"}, "ledger-corrupt")
                worker = Worker(**lease["worker"])
                worker.validate()
                who = Identity(**lease["identity"])
                require(who.policy_sha256 is None or (type(who.policy_sha256) is str
                        and HEX.fullmatch(who.policy_sha256)), "ledger-corrupt")
                require(all(type(v) is int and v > 0 for v in
                            (who.run_id, who.job_id, who.check_run_id, who.runner_id, who.service_uid, who.valid_until))
                        and who.runner_id == worker.runner_id and who.service_uid == worker.uid, "ledger-corrupt")
                policy = state["policies"][lease["policy_sha256"]]
                require(HEX.fullmatch(lease["cell_sha256"]) and type(lease["created_at"]) is int
                        and type(lease["expires_at"]) is int
                        and 0 < lease["expires_at"] - lease["created_at"] <= policy["max_lease_seconds"], "ledger-corrupt")
                invocation = (who.run_id, who.check_run_id)
                require(invocation not in used_invocations, "ledger-corrupt")
                used_invocations.add(invocation)
                if lease["state"] != "closed":
                    require(who.runner_id not in live_runners and who.service_uid not in live_uids, "ledger-corrupt")
                    live_runners.add(who.runner_id)
                    live_uids.add(who.service_uid)
                authorizations = lease["authorizations"]
                require(type(authorizations) is list and authorizations, "ledger-corrupt")
                for authorization in authorizations:
                    token = authorization["token_id_sha256"]
                    nonce = authorization["audience"][len(AUDIENCE):]
                    challenge = state["challenges"][digest(nonce)]
                    require(HEX.fullmatch(token) and token not in token_links and HEX.fullmatch(nonce)
                            and authorization["audience"] == AUDIENCE + nonce
                            and type(authorization["valid_until"]) is int and authorization["valid_until"] > 0
                            and challenge["state"] == "consumed" and challenge["lease_id"] == key
                            and challenge["worker"] == lease["worker"], "ledger-corrupt")
                    token_links[token] = key
                require(authorizations[0]["token_id_sha256"] == who.token_id_sha256
                        and authorizations[0]["audience"] == who.audience, "ledger-corrupt")
                effect_targets, provisioned = set(), set()
                for effect_key, effect in lease["effects"].items():
                    require(ID.fullmatch(effect_key) and effect["operation"] in OPERATIONS
                            and effect["state"] in {"intent", "unknown", "verified", "not_applied", "failed"}
                            and _target_valid(effect["operation"], effect["target"]), "ledger-corrupt")
                    pair = (effect["operation"], effect["target"])
                    require(pair not in effect_targets, "ledger-corrupt")
                    effect_targets.add(pair)
                    if effect["operation"] in ONCE:
                        require(effect["operation"] not in provisioned, "ledger-corrupt")
                        provisioned.add(effect["operation"])
                    if effect["state"] != "intent":
                        require(HEX.fullmatch(effect["evidence_sha256"]), "ledger-corrupt")
                    if effect["state"] == "failed":
                        require(effect["operation"] in OBSERVATIONS, "ledger-corrupt")
                    if "incus_operation_id" in effect:
                        native = effect["incus_operation_id"]
                        require(effect["operation"] in INCUS_OPERATIONS and _native_uuid(native)
                                and native not in native_operations, "ledger-corrupt")
                        native_operations.add(native)
                    if "engine_process" in effect:
                        process = effect["engine_process"]
                        _validate_engine_process(process)
                        process_key = (process["boot_id"], process["pid"], process["start_ticks"])
                        require(effect["operation"] == "engine-start" and process_key not in engine_processes,
                                "ledger-corrupt")
                        engine_processes.add(process_key)
                    if "engine_container_id" in effect:
                        container = effect["engine_container_id"]
                        require(effect["operation"] == "engine-start" and "engine_process" in effect
                                and type(container) is str and HEX.fullmatch(container)
                                and container not in engine_containers, "ledger-corrupt")
                        engine_containers.add(container)
                    if "engine_capture" in effect:
                        capture = effect["engine_capture"]
                        _validate_engine_capture(capture)
                        require(effect["operation"] == "engine-start", "ledger-corrupt")
                        cgroup = (worker.boot_id, capture["cgroup_device"], capture["cgroup_inode"])
                        require(cgroup not in capture_cgroups, "ledger-corrupt")
                        capture_cgroups.add(cgroup)
                        for stream in ("stdout", "stderr"):
                            selected = (worker.boot_id, capture[stream + "_device"], capture[stream + "_inode"])
                            require(selected not in capture_streams, "ledger-corrupt")
                            capture_streams.add(selected)
                    if "engine_exit" in effect:
                        _validate_engine_exit(effect["engine_exit"], effect)
                    if "fence" in effect:
                        fence = effect["fence"]
                        _validate_fence(fence)
                        key_fence = (fence["boot_id"], fence["netns_device"], fence["netns_inode"])
                        require(effect["operation"] == "fence-create" and key_fence not in fence_namespaces,
                                "ledger-corrupt")
                        require((fence["boot_id"], fence["host_ifindex"]) not in fence_host_interfaces, "ledger-corrupt")
                        fence_namespaces.add(key_fence)
                        fence_host_interfaces.add((fence["boot_id"], fence["host_ifindex"]))
                    if "fence_authorization" in effect:
                        require(effect["operation"] == "fence-renew", "ledger-corrupt")
                        _validate_fence_authorization(effect["fence_authorization"], lease, effect)
                    if "host_api" in effect:
                        _validate_host_api(effect["host_api"])
                        require(effect["operation"] == "fence-create" and "fence" in effect
                                and effect["host_api"]["boot_id"] == effect["fence"]["boot_id"], "ledger-corrupt")
                    if "host_api_authorization" in effect:
                        require(effect["operation"] == "fence-renew" and "fence_authorization" in effect, "ledger-corrupt")
                        _validate_host_api_authorization(effect["host_api_authorization"], lease, effect)
                    if "host_api_withdrawal" in effect:
                        value = effect["host_api_withdrawal"]
                        require(effect["operation"] == "fence-disable" and type(value) is dict
                                and set(value) == {"baseline_sha256"} and type(value["baseline_sha256"]) is str
                                and HEX.fullmatch(value["baseline_sha256"])
                                and any(row["operation"] == "fence-create" and row["state"] == "verified"
                                    and row.get("host_api", {}).get("baseline_sha256") == value["baseline_sha256"]
                                    for row in lease["effects"].values()), "ledger-corrupt")
                effects = list(lease["effects"].values())
                for effect in effects:
                    if effect["operation"] == "instance-stop":
                        cls._instance_stop_scope(key, effect["target"], effects)
                    if "certificate_scope" in effect:
                        _certificate_scope(effect["certificate_scope"], key, effect, effects)
                    if "certificate_revocation" in effect:
                        _certificate_revocation(effect["certificate_revocation"], effect, effects)
                        fingerprint = effect["certificate_revocation"]["current_fingerprint"]
                        require(fingerprint not in certificate_revocations, "ledger-corrupt")
                        certificate_revocations.add(fingerprint)
                    if effect["operation"] in {"engine-prepare", "engine-release"}:
                        require(effect["target"] == "engine:" + key, "ledger-corrupt")
                    if effect["operation"] in {"engine-start", "engine-stop"}:
                        require(effect["target"] == "engine:lit-lease-" + key, "ledger-corrupt")
                    if effect["operation"] in {"fence-create", "fence-remove", "fence-disable", "fence-renew"}:
                        base = "fence:" + key
                        require(effect["target"] == base if effect["operation"] != "fence-renew" else (
                            effect["target"].startswith(base + ":")
                            and any(effect["target"] == base + ":" + auth["token_id_sha256"]
                                    for auth in authorizations)), "ledger-corrupt")
                        if effect["operation"] in {"fence-disable", "fence-renew"}:
                            require(any(other["operation"] == "fence-create" and other["state"] == "verified"
                                        and other["target"] == base for other in effects), "ledger-corrupt")
                    if effect["operation"] == "context-publish":
                        require(effect["target"] == "context:" + lease["cell_sha256"]
                                and any(other["operation"] == "context-create" and other["state"] == "verified"
                                        and other["target"] == effect["target"] for other in effects), "ledger-corrupt")
                    if effect["operation"] == "context-refresh":
                        base = "context:" + lease["cell_sha256"]
                        require(any(effect["target"] == base + ":" + auth["token_id_sha256"]
                                    for auth in authorizations[1:])
                                and all(any(other["operation"] == operation and other["target"] == base
                                            and other["state"] == "verified" for other in effects)
                                        for operation in ("context-create", "context-publish")), "ledger-corrupt")
                    if effect["operation"] == "profile-configure":
                        require(any(other["operation"] == "project-create" and other["state"] == "verified"
                                    and effect["target"] == "profile:" + other["target"].removeprefix("project:") + ":default"
                                    for other in effects), "ledger-corrupt")
                    if effect["operation"] in CLEANUPS:
                        require(any(CREATES.get(other["operation"]) == effect["operation"]
                                    and other["target"] == effect["target"] and other["state"] == "verified"
                                    for other in effects), "ledger-corrupt")
                if lease["state"] == "closed":
                    cls._cleanup_complete(list(lease["effects"].values()))
            host_slots, host_policies = set(), set()
            for lease in state["leases"].values():
                effects = list(lease["effects"].values())
                if any(row["operation"] == "fence-remove" and row["state"] == "verified" for row in effects):
                    continue
                for effect in effects:
                    if "host_api" not in effect or effect["state"] not in {"intent", "unknown", "verified"}:
                        continue
                    value = effect["host_api"]
                    slot = tuple(value[key] for key in ("boot_id", "host_netns_device", "host_netns_inode", "nft_table_handle"))
                    policy = (value["policy_sha256"], value["baseline_sha256"])
                    require(slot not in host_slots and policy not in host_policies, "ledger-corrupt")
                    host_slots.add(slot)
                    host_policies.add(policy)
            for key, challenge in state["challenges"].items():
                require(key == digest(challenge["nonce"]) and HEX.fullmatch(challenge["nonce"])
                        and challenge["state"] in {"issued", "consumed"}
                        and type(challenge["issued_at"]) is int and type(challenge["expires_at"]) is int
                        and 0 < challenge["expires_at"] - challenge["issued_at"] <= 300, "ledger-corrupt")
                Worker(**challenge["worker"]).validate()
                runtime = challenge.get("runtime")
                if runtime is not None:
                    require(type(runtime) is dict and set(runtime) == {
                        "operation", "cell_sha256", "identity_policy_sha256"}
                        and runtime == _runtime_scope(**runtime), "ledger-corrupt")
                if challenge["state"] == "consumed":
                    lease = state["leases"][challenge["lease_id"]]
                    if "runtime_identity" in challenge:
                        who = Identity(**challenge["runtime_identity"])
                        require(runtime is not None and runtime["operation"] in {"status", "cancel", "recover"}
                                and who.policy_sha256 == runtime["identity_policy_sha256"]
                                and runtime["cell_sha256"] == lease["cell_sha256"]
                                and challenge["worker"] == lease["worker"]
                                and cls._immutable_identity(who) == cls._immutable_identity(Identity(**lease["identity"]))
                                and who.audience == AUDIENCE + challenge["nonce"]
                                and type(who.valid_until) is int and who.valid_until > challenge["issued_at"]
                                and type(who.token_id_sha256) is str and HEX.fullmatch(who.token_id_sha256)
                                and who.token_id_sha256 not in token_links, "ledger-corrupt")
                        token_links[who.token_id_sha256] = challenge["lease_id"]
                    else:
                        require(any(a["audience"] == AUDIENCE + challenge["nonce"]
                                    for a in lease["authorizations"]), "ledger-corrupt")
                        if runtime is not None:
                            require(runtime["operation"] in {"run", "heartbeat"}
                                    and runtime["cell_sha256"] == lease["cell_sha256"]
                                    and runtime["identity_policy_sha256"] == lease["identity"]["policy_sha256"],
                                    "ledger-corrupt")
                else:
                    require("runtime_identity" not in challenge and "lease_id" not in challenge, "ledger-corrupt")
            require(state["tokens"] == token_links, "ledger-corrupt")
        except (KeyError, TypeError, AttributeError, ValueError):
            raise Denied("ledger-corrupt") from None

    def archive_policy(self, policy):
        require(type(policy) is dict, "invalid-custody-policy")
        policy = copy.deepcopy(policy)
        self._validate_policy(policy)
        key = digest(policy)
        with self._transaction() as state:
            state["policies"].setdefault(key, copy.deepcopy(policy))
        return key

    def read_policy(self, policy_sha256):
        """Read an existing archive without creating policy or acceptance.

        A detached copy prevents registry consumers from mutating the ledger.
        Presence of archived references never establishes operating approval.
        """
        require(type(policy_sha256) is str and HEX.fullmatch(policy_sha256), "invalid-policy-digest")
        with self._transaction() as state:
            require(policy_sha256 in state["policies"], "unknown-custody-policy")
            return copy.deepcopy(state["policies"][policy_sha256])

    def challenge(self, worker, ttl=300):
        return self._challenge(worker, ttl, None)

    def runtime_challenge(self, worker, operation, cell_sha256, identity_policy_sha256, ttl=300):
        return self._challenge(worker, ttl, _runtime_scope(operation, cell_sha256, identity_policy_sha256))

    def _challenge(self, worker, ttl, runtime):
        require(type(worker) is Worker, "invalid-worker")
        worker.validate()
        require(type(ttl) is int and 0 < ttl <= 300, "invalid-challenge-ttl")
        now, binding = self._now(), asdict(worker)
        with self._transaction() as state:
            for record in state["challenges"].values():
                if (record["worker"] == binding and record.get("runtime") == runtime
                        and record["state"] == "issued" and record["expires_at"] > now):
                    return {"nonce": record["nonce"], "audience": AUDIENCE + record["nonce"],
                            "expires_at": record["expires_at"]}
            nonce = secrets.token_hex(32)
            state["challenges"][digest(nonce)] = {"nonce": nonce, "worker": binding, "issued_at": now,
                                                  "expires_at": now + ttl, "state": "issued"}
            if runtime is not None:
                state["challenges"][digest(nonce)]["runtime"] = runtime
            return {"nonce": nonce, "audience": AUDIENCE + nonce, "expires_at": now + ttl}

    def prepare(self, nonce, worker, identity, *, policy_sha256, cell_sha256, deadline):
        return self._prepare(nonce, worker, identity, policy_sha256=policy_sha256,
                             cell_sha256=cell_sha256, deadline=deadline, runtime=None)

    def runtime_prepare(self, nonce, worker, identity, *, policy_sha256, cell_sha256, deadline,
                        identity_policy_sha256):
        scope = _runtime_scope("run", cell_sha256, identity_policy_sha256)
        require(type(identity) is Identity and identity.policy_sha256 == identity_policy_sha256,
                "runtime-identity-policy")
        return self._prepare(nonce, worker, identity, policy_sha256=policy_sha256,
                             cell_sha256=cell_sha256, deadline=deadline, runtime=scope)

    def _prepare(self, nonce, worker, identity, *, policy_sha256, cell_sha256, deadline, runtime):
        require(type(nonce) is str and HEX.fullmatch(nonce), "invalid-challenge")
        require(type(worker) is Worker and type(identity) is Identity, "invalid-trusted-input")
        worker.validate()
        require(identity.policy_sha256 is None or (type(identity.policy_sha256) is str
                and HEX.fullmatch(identity.policy_sha256)), "invalid-identity-policy-digest")
        require(type(policy_sha256) is str and HEX.fullmatch(policy_sha256)
                and type(cell_sha256) is str and HEX.fullmatch(cell_sha256), "invalid-policy-digest")
        now = self._now()
        require(type(deadline) is int and deadline > now and identity.valid_until > now,
                "expired-admission")
        require(identity.service_uid == worker.uid and identity.runner_id == worker.runner_id
                and identity.audience == AUDIENCE + nonce and HEX.fullmatch(identity.token_id_sha256),
                "identity-worker-challenge")
        with self._transaction() as state:
            policy = state["policies"].get(policy_sha256)
            require(policy is not None and deadline <= now + policy["max_lease_seconds"], "lease-deadline")
            record = state["challenges"].get(digest(nonce))
            require(record is not None and record["state"] == "issued" and record["expires_at"] > now
                    and record["issued_at"] <= now and record["worker"] == asdict(worker)
                    and record.get("runtime") == runtime, "challenge-replay-or-worker")
            require(identity.token_id_sha256 not in state["tokens"], "token-replay")
            for lease in state["leases"].values():
                previous = lease["identity"]
                require(not (previous["run_id"] == identity.run_id
                             and previous["check_run_id"] == identity.check_run_id), "invocation-replay")
                require(lease["state"] == "closed" or (previous["runner_id"] != identity.runner_id
                        and previous["service_uid"] != identity.service_uid), "runner-lease-unsettled")
            if runtime is not None:
                self._require_exclusive_preparation(state)
            else:
                # A legacy admission must not create a competing lease after
                # a runtime run has already acquired exclusive ownership.
                require(not any(
                    (challenge.get("runtime") or {}).get("operation") == "run"
                    and challenge["state"] == "consumed"
                    and state["leases"][challenge["lease_id"]]["state"] != "closed"
                    for challenge in state["challenges"].values()
                ), "engine-other-pilot-lease-active")
            identifier = secrets.token_hex(16)
            record["state"] = "consumed"
            record["lease_id"] = identifier
            state["tokens"][identity.token_id_sha256] = identifier
            state["leases"][identifier] = {"state": "prepared", "worker": asdict(worker),
                "identity": asdict(identity), "policy_sha256": policy_sha256, "cell_sha256": cell_sha256,
                "created_at": now, "expires_at": deadline, "effects": {},
                "authorizations": [{"valid_until": identity.valid_until, "audience": identity.audience,
                                     "token_id_sha256": identity.token_id_sha256}]}
            return identifier

    @staticmethod
    def _immutable_identity(identity):
        return {key: value for key, value in asdict(identity).items()
                if key not in {"valid_until", "audience", "token_id_sha256"}}

    @staticmethod
    def _refresh_input(nonce, worker, identity, now):
        require(type(nonce) is str and HEX.fullmatch(nonce) and type(worker) is Worker
                and type(identity) is Identity, "invalid-trusted-input")
        worker.validate()
        require(type(identity.valid_until) is int and identity.valid_until > now
                and identity.audience == AUDIENCE + nonce and type(identity.token_id_sha256) is str
                and HEX.fullmatch(identity.token_id_sha256), "expired-admission")

    def _refresh_authorization(self, state, identifier, nonce, worker, identity, now, runtime=None):
        """Caller holds the sole transaction; update authorization, never effects."""
        lease = self._lease(state, identifier)
        require(lease["state"] == "prepared" and now < lease["expires_at"]
                and lease["worker"] == asdict(worker), "lease-not-active")
        require(self._immutable_identity(identity) == self._immutable_identity(Identity(**lease["identity"])),
                "identity-drift")
        challenge = state["challenges"].get(digest(nonce))
        require(challenge is not None and challenge["state"] == "issued"
                and challenge["issued_at"] <= now < challenge["expires_at"]
                and challenge["worker"] == asdict(worker)
                and challenge.get("runtime") == runtime, "challenge-replay-or-worker")
        require(identity.token_id_sha256 not in state["tokens"], "token-replay")
        challenge.update(state="consumed", lease_id=identifier)
        state["tokens"][identity.token_id_sha256] = identifier
        lease["authorizations"].append({"valid_until": identity.valid_until, "audience": identity.audience,
                                         "token_id_sha256": identity.token_id_sha256})

    def refresh_identity(self, identifier, nonce, worker, identity):
        """Fresh assertion for the same invocation; never extend the cell deadline."""
        now = self._now()
        self._refresh_input(nonce, worker, identity, now)
        with self._transaction() as state:
            self._refresh_authorization(state, identifier, nonce, worker, identity, now)

    def runtime_refresh_identity(self, identifier, nonce, worker, identity, *, cell_sha256, identity_policy_sha256):
        now = self._now()
        self._refresh_input(nonce, worker, identity, now)
        scope = _runtime_scope("heartbeat", cell_sha256, identity_policy_sha256)
        require(identity.policy_sha256 == identity_policy_sha256, "runtime-identity-policy")
        with self._transaction() as state:
            require(self._lease(state, identifier)["cell_sha256"] == cell_sha256, "runtime-root-binding")
            self._refresh_authorization(state, identifier, nonce, worker, identity, now, scope)

    def consume_runtime_proof(self, nonce, worker, identity, operation, *, cell_sha256,
                              identity_policy_sha256, policy_sha256, deadline, lease_id=None):
        """Consume one status/cancel/recover proof without changing live auth.

        Inputs are independently Root-acquired native facts. A fresh proof can
        locate retained expired/cancelled/closed state, but cannot grant effects,
        extend the fixed deadline, append authorizations or renew the fence.
        """
        now = self._now()
        self._refresh_input(nonce, worker, identity, now)
        scope = _runtime_scope(operation, cell_sha256, identity_policy_sha256)
        require(operation in {"status", "cancel", "recover"}
                and identity.policy_sha256 == identity_policy_sha256, "runtime-proof-operation")
        require(type(policy_sha256) is str and HEX.fullmatch(policy_sha256)
                and type(deadline) is int and deadline > 0, "runtime-root-binding")
        require((operation == "recover" and lease_id is None)
                or (operation != "recover" and type(lease_id) is str and ID.fullmatch(lease_id)),
                "runtime-proof-locator")
        with self._transaction() as state:
            require(policy_sha256 in state["policies"], "unknown-custody-policy")
            matches = [key for key, lease in state["leases"].items()
                       if lease["worker"] == asdict(worker)
                       and self._immutable_identity(Identity(**lease["identity"])) == self._immutable_identity(identity)]
            require(len(matches) == 1 and (lease_id is None or lease_id == matches[0]), "runtime-invocation-not-exact")
            identifier = matches[0]
            lease = state["leases"][identifier]
            require(lease["cell_sha256"] == cell_sha256 and lease["policy_sha256"] == policy_sha256
                    and lease["expires_at"] == deadline, "runtime-root-binding")
            challenge = state["challenges"].get(digest(nonce))
            require(challenge is not None and challenge["state"] == "issued"
                    and challenge["issued_at"] <= now < challenge["expires_at"]
                    and challenge["worker"] == asdict(worker) and challenge.get("runtime") == scope,
                    "challenge-replay-or-worker")
            require(identity.token_id_sha256 not in state["tokens"], "token-replay")
            challenge.update(state="consumed", lease_id=identifier, runtime_identity=asdict(identity))
            state["tokens"][identity.token_id_sha256] = identifier
            return RuntimeProof(identifier, operation, cell_sha256, identity_policy_sha256,
                                digest(asdict(worker)), digest(asdict(identity)), identity.valid_until)

    def recover(self, nonce, worker, identity, *, policy_sha256, cell_sha256, deadline):
        """Recover one lost lease locator with fresh complete native authority.

        No caller lease ID, new admission, effect retry or status PASS exists.
        Unknown effects stay unchanged and still block ordinary begin calls.
        """
        now = self._now()
        self._refresh_input(nonce, worker, identity, now)
        require(type(identity.policy_sha256) is str and HEX.fullmatch(identity.policy_sha256),
                "recovery-policy-scope-required")
        require(type(policy_sha256) is str and HEX.fullmatch(policy_sha256)
                and type(cell_sha256) is str and HEX.fullmatch(cell_sha256)
                and type(deadline) is int and deadline > now, "recovery-root-binding")
        immutable = self._immutable_identity(identity)
        with self._transaction() as state:
            require(policy_sha256 in state["policies"], "unknown-custody-policy")
            matches = [key for key, lease in state["leases"].items()
                       if lease["worker"] == asdict(worker)
                       and self._immutable_identity(Identity(**lease["identity"])) == immutable]
            require(len(matches) == 1, "recovery-lease-not-exact")
            identifier = matches[0]
            lease = self._lease(state, identifier)
            require(lease["policy_sha256"] == policy_sha256 and lease["cell_sha256"] == cell_sha256
                    and lease["expires_at"] == deadline, "recovery-root-binding")
            self._refresh_authorization(state, identifier, nonce, worker, identity, now)
            return identifier

    @staticmethod
    def _lease(state, identifier):
        require(type(identifier) is str and ID.fullmatch(identifier), "invalid-lease")
        require(identifier in state["leases"], "unknown-lease")
        return state["leases"][identifier]

    def read(self, identifier):
        with self._transaction() as state:
            return copy.deepcopy(self._lease(state, identifier))

    @staticmethod
    def _require_exclusive_preparation(state, identifier=None):
        require(all(key == identifier or lease["state"] == "closed"
                    for key, lease in state["leases"].items()), "engine-other-pilot-lease-active")

    def require_exclusive_preparation(self, identifier):
        with self._transaction() as state:
            self._lease(state, identifier)
            self._require_exclusive_preparation(state, identifier)

    def begin(self, identifier, operation, target):
        """Persist ONE intent before a Root executor acts; never run or retry it.

        Provisioning locators are Root-selected and must still be bound by the
        executor to its sealed cell and native readbacks. This journal alone
        does not prove ownership, resource absence, or operating acceptance.
        """
        require(type(operation) is str and operation in OPERATIONS and _target_valid(operation, target),
                "invalid-effect")
        now = self._now()
        with self._transaction() as state:
            lease = self._lease(state, identifier)
            require(lease["state"] != "closed", "lease-closed")
            effects = list(lease["effects"].values())
            owned_stop = operation == "engine-stop" and target == "engine:lit-lease-" + identifier and any(
                e["operation"] == "engine-start" and e["target"] == target and e["state"] == "verified"
                and "engine_process" in e and "engine_container_id" in e for e in effects)
            # A first exact-owned withdrawal is the sole unresolved-effect
            # exception: it cannot enable access or resolve any other effect.
            require(operation in WITHDRAWALS or owned_stop
                    or not any(e["state"] in {"intent", "unknown"} for e in effects),
                    "effect-unresolved")
            require(not any(e["operation"] == operation and e["target"] == target for e in effects), "effect-replay")
            if operation in ONCE:
                require(not any(e["operation"] == operation for e in effects), "provisioning-replay")
            if operation in {"engine-prepare", "engine-release"}:
                require(target == "engine:" + identifier, "engine-lease-target")
            if operation in {"engine-start", "engine-stop"}:
                require(target == "engine:lit-lease-" + identifier, "engine-lease-target")
            if operation == "engine-start":
                expected = "fence:" + identifier + ":" + lease["authorizations"][-1]["token_id_sha256"]
                require(any(e["operation"] == "fence-renew" and e["target"] == expected and e["state"] == "verified"
                            for e in effects), "fence-authorization-unverified")
            if operation in {"fence-create", "fence-remove", "fence-disable", "fence-renew"}:
                require(target == "fence:" + identifier if operation != "fence-renew" else (
                    target == "fence:" + identifier + ":" + lease["authorizations"][-1]["token_id_sha256"]),
                    "fence-lease-target")
            if operation in WITHDRAWALS:
                require(any(e["operation"] == "fence-create" and e["state"] == "verified"
                            and e["target"] == target for e in effects), "fence-not-owned")
            if operation == "context-publish":
                require(target == "context:" + lease["cell_sha256"]
                        and any(e["operation"] == "context-create" and e["state"] == "verified"
                                and e["target"] == target for e in effects), "context-publication-not-owned")
            if operation == "context-refresh":
                base = "context:" + lease["cell_sha256"]
                require(len(lease["authorizations"]) > 1
                        and target == base + ":" + lease["authorizations"][-1]["token_id_sha256"]
                        and all(any(e["operation"] == wanted and e["target"] == base and e["state"] == "verified"
                                    for e in effects) for wanted in ("context-create", "context-publish")),
                        "context-refresh-not-owned")
            if operation == "profile-configure":
                require(any(e["operation"] == "project-create" and e["state"] == "verified"
                            and target == "profile:" + e["target"].removeprefix("project:") + ":default"
                            for e in effects), "profile-project-not-owned")
            if operation in CLEANUPS:
                creator = next(k for k, v in CREATES.items() if v == operation)
                require(any(e["operation"] == creator and e["target"] == target
                            and e["state"] == "verified" for e in effects), "cleanup-not-owned")
            elif operation == "instance-stop":
                self._instance_stop_scope(identifier, target, effects)
            elif operation not in WITHDRAWALS:
                require(lease["state"] == "prepared" and now < lease["expires_at"]
                        and now < lease["authorizations"][-1]["valid_until"], "lease-not-active")
            self._effect_order(effects, operation)
            effect = secrets.token_hex(16)
            lease["effects"][effect] = {"operation": operation, "target": target, "state": "intent", "at": now}
            return effect

    @staticmethod
    def _instance_stop_scope(identifier, target, effects):
        """Journal prerequisite only; exact sealed VM/native ownership is executor IO."""
        require(_target_valid("instance-stop", target), "instance-stop-target")
        project = target.split(":")[1]
        required = {"project-create": "project:" + project,
                    "engine-stop": "engine:lit-lease-" + identifier,
                    "fence-disable": "fence:" + identifier}
        require(all(any(row["operation"] == operation and row["target"] == expected
                        and row["state"] == "verified" for row in effects)
                    for operation, expected in required.items()), "instance-stop-prerequisite")
        require(any(row["operation"] == "certificate-revoke" and row["state"] == "verified"
                    for row in effects), "instance-stop-certificate-live")

    @staticmethod
    def _effect_order(effects, operation):
        """Dependencies for the one Root-provisioned cell, not a generic DAG.

        Existing standalone certificate/instance journals stay valid. Once the
        new provisioning operations are used, parents cannot be torn down
        while known owned children remain. Revoke is deliberately unconditional
        on engine state: immediate access withdrawal must remain possible.
        """
        live = {creator for creator, cleanup in CREATES.items()
                if any(e["operation"] == creator and e["state"] == "verified"
                       and not any(other["operation"] == cleanup and other["target"] == e["target"]
                                   and other["state"] == "verified" for other in effects) for e in effects)}
        if "project-create" in live and any(e["operation"] == "profile-configure" and e["state"] == "verified"
                                           for e in effects):
            live.add("profile-configure")
        if "context-create" in live and any(e["operation"] == "context-publish" and e["state"] == "verified"
                                           for e in effects):
            live.add("context-publish")
        needed = {
            "project-create": {"network-create"},
            "profile-configure": {"network-create", "project-create"},
            "context-create": {"network-create", "project-create", "profile-configure"},
            "context-publish": {"network-create", "project-create", "profile-configure", "context-create", "certificate-create"},
            "context-refresh": {"network-create", "project-create", "profile-configure", "context-create",
                                "certificate-create", "context-publish"},
            "engine-prepare": {"context-create", "certificate-create"},
            "fence-disable": {"fence-create"},
            "fence-renew": {"fence-create"},
            "engine-start": {"network-create", "project-create", "profile-configure", "certificate-create", "context-create",
                             "context-publish", "engine-prepare", "fence-create"},
        }
        if operation in {"engine-start", "fence-renew", "context-refresh"}:
            require(not any(e["operation"] == "fence-disable" for e in effects), "fence-disabled")
        if any(e["operation"] in PROVISIONING for e in effects):
            if operation in {"certificate-create", "instance-create"}:
                needed[operation] = {"network-create", "project-create"}
            if operation == "certificate-create":
                needed[operation].add("context-create")
            if operation in CREATES or operation in {"profile-configure", "context-publish", "context-refresh", "fence-renew"}:
                require(not any(e["operation"] in CLEANUPS for e in effects), "provisioning-cleanup-started")
        require(needed.get(operation, set()) <= live, "effect-prerequisite")
        blockers = {
            "instance-destroy": {"engine-start"},
            "context-delete": {"engine-start", "engine-prepare", "certificate-create"},
            "engine-release": {"engine-start"},
            "fence-remove": {"engine-start"},
            "project-delete": {"engine-start", "instance-create", "certificate-create", "context-create"},
            "network-delete": {"engine-start", "instance-create", "project-create", "certificate-create"},
        }
        require(not (blockers.get(operation, set()) & live), "effect-dependent-resource")

    def _outcome(self, identifier, effect_id, outcome, evidence_sha256, *, reconcile):
        require(type(evidence_sha256) is str and HEX.fullmatch(evidence_sha256), "invalid-effect-evidence")
        with self._transaction() as state:
            lease = self._lease(state, identifier)
            require(lease["state"] != "closed", "lease-closed")
            effect = lease["effects"].get(effect_id)
            require(effect is not None and effect["state"] in ({"intent", "unknown"} if reconcile else {"intent"}),
                    "effect-outcome-conflict")
            allowed = {"verified", "not_applied"} if reconcile else {"verified", "not_applied", "unknown"}
            if not reconcile and effect["operation"] in OBSERVATIONS:
                allowed.add("failed")
            require(outcome in allowed, "invalid-effect-outcome")
            effect.update(state=outcome, evidence_sha256=evidence_sha256, observed_at=self._now())
            if reconcile:
                effect["reconciled"] = True

    def record(self, identifier, effect_id, outcome, *, evidence_sha256):
        self._outcome(identifier, effect_id, outcome, evidence_sha256, reconcile=False)

    def bind_certificate_scope(self, identifier, effect_id, *, initial_fingerprint, certificate_name,
                               project, baseline_inventory_sha256, authorizer_profile):
        """Retain Root's complete empty-scope inventory BEFORE original POST.

        The named pinned authorizer is an expected native protocol, not proof
        of platform admission or protection against another trusted Root admin.
        Only the sealed precreator may provide this independently acquired data.
        """
        value = {"initial_fingerprint": initial_fingerprint, "name": certificate_name,
                 "type": "client", "restricted": True, "projects": [project],
                 "baseline_inventory_sha256": baseline_inventory_sha256, "authorizer_profile": authorizer_profile}
        require(type(effect_id) is str and ID.fullmatch(effect_id), "invalid-effect")
        with self._transaction() as state:
            lease = self._lease(state, identifier)
            effect = lease["effects"].get(effect_id)
            require(lease["state"] != "closed" and effect is not None
                    and effect["state"] in {"intent", "unknown"}, "certificate-scope-effect")
            _certificate_scope(value, identifier, effect, list(lease["effects"].values()))
            if "certificate_scope" in effect:
                require(effect["certificate_scope"] == value, "certificate-scope-rebind")
                return
            require(effect["state"] == "intent" and "incus_operation_id" not in effect, "certificate-scope-after-send")
            effect["certificate_scope"] = value

    def bind_certificate_revocation(self, identifier, effect_id, *, current_fingerprint, scope_sha256, inventory_sha256):
        """Bind one actual current scope fingerprint to the ORIGINAL revoke intent.

        Does not create a new intent, allow another DELETE, adopt by name or
        resolve unknown. Root must prove the current complete scope inventory.
        """
        value = {"current_fingerprint": current_fingerprint, "scope_sha256": scope_sha256,
                 "inventory_sha256": inventory_sha256}
        require(type(effect_id) is str and ID.fullmatch(effect_id), "invalid-effect")
        with self._transaction() as state:
            lease = self._lease(state, identifier)
            effect = lease["effects"].get(effect_id)
            require(lease["state"] != "closed" and effect is not None and effect["state"] in {"intent", "unknown"},
                    "certificate-revocation-effect")
            _certificate_revocation(value, effect, list(lease["effects"].values()))
            if "certificate_revocation" in effect:
                require(effect["certificate_revocation"] == value, "certificate-revocation-rebind")
                return
            require(effect["state"] == "intent" and "incus_operation_id" not in effect,
                    "certificate-revocation-after-send")
            for other in state["leases"].values():
                for row in other["effects"].values():
                    retained = row.get("certificate_revocation")
                    require(retained is None or retained["current_fingerprint"] != current_fingerprint,
                            "certificate-revocation-reuse")
            effect["certificate_revocation"] = value

    def bind_native_operation(self, identifier, effect_id, operation_id):
        """Retain a received Incus async UUID before polling; grants no retry.

        Only Root's typed transport may supply this metadata. The same UUID
        binding is idempotent while unresolved; a different binding or UUID
        reuse is denied across the entire retained store, including closed
        leases. Outcome/readback remains a separate explicit journal step.
        """
        require(_native_uuid(operation_id), "invalid-native-operation")
        require(type(effect_id) is str and ID.fullmatch(effect_id), "invalid-effect")
        with self._transaction() as state:
            lease = self._lease(state, identifier)
            require(lease["state"] != "closed", "lease-closed")
            effect = lease["effects"].get(effect_id)
            require(effect is not None and effect["operation"] in INCUS_OPERATIONS
                    and effect["state"] in {"intent", "unknown"}, "native-operation-effect")
            if "incus_operation_id" in effect:
                require(effect["incus_operation_id"] == operation_id, "native-operation-rebind")
                return
            require(not any(other.get("incus_operation_id") == operation_id
                            for record in state["leases"].values() for other in record["effects"].values()),
                    "native-operation-reuse")
            effect["incus_operation_id"] = operation_id

    @classmethod
    def _engine_effect(cls, state, identifier, effect_id):
        require(type(effect_id) is str and ID.fullmatch(effect_id), "invalid-effect")
        lease = cls._lease(state, identifier)
        require(lease["state"] != "closed", "lease-closed")
        effect = lease["effects"].get(effect_id)
        require(effect is not None and effect["operation"] == "engine-start"
                and effect["target"] == "engine:lit-lease-" + identifier
                and effect["state"] in {"intent", "unknown"}, "engine-runtime-effect")
        return effect

    def bind_engine_process(self, identifier, effect_id, *, pid, start_ticks, boot_id,
                            exe_device, exe_inode, exe_sha256):
        """Retain Root's kernel-observed own Popen process before readback.

        The Root executor must independently collect the PID/start/boot tuple,
        verify actual /usr/bin/podman inode/device and its sealed executable
        digest. Never reconstruct this input from job JSON. This metadata does
        not attest those observations, prove liveness/completion, or authorize
        spawn/retry/adoption; the Popen-to-binding crash gap stays UNKNOWN.
        """
        process = {"pid": pid, "start_ticks": start_ticks, "boot_id": boot_id,
                   "executable": ENGINE_EXECUTABLE, "exe_device": exe_device,
                   "exe_inode": exe_inode, "exe_sha256": exe_sha256}
        _validate_engine_process(process)
        key = (boot_id, pid, start_ticks)
        with self._transaction() as state:
            effect = self._engine_effect(state, identifier, effect_id)
            if "engine_process" in effect:
                require(effect["engine_process"] == process, "engine-process-rebind")
                return
            require(not any((other["engine_process"]["boot_id"], other["engine_process"]["pid"],
                             other["engine_process"]["start_ticks"]) == key
                            for record in state["leases"].values() for other in record["effects"].values()
                            if "engine_process" in other), "engine-process-reuse")
            effect["engine_process"] = process

    def bind_engine_container(self, identifier, effect_id, container_id):
        """Retain the exact CID after Root's private cidfile+inspect comparison.

        No caller paths or container names are accepted; the engine effect's
        name is deterministic. Root must verify labels/image/name and current
        supervisor facts before subsequent status/cancel operations. CID alone
        grants no cleanup or completion claim. No replacement CID is permitted.
        """
        require(type(container_id) is str and HEX.fullmatch(container_id), "invalid-engine-container")
        with self._transaction() as state:
            effect = self._engine_effect(state, identifier, effect_id)
            require("engine_process" in effect, "engine-process-unbound")
            if "engine_container_id" in effect:
                require(effect["engine_container_id"] == container_id, "engine-container-rebind")
                return
            require(not any(other.get("engine_container_id") == container_id
                            for record in state["leases"].values() for other in record["effects"].values()),
                    "engine-container-reuse")
            effect["engine_container_id"] = container_id

    @classmethod
    def _engine_observation(cls, state, identifier, effect_id):
        require(type(effect_id) is str and ID.fullmatch(effect_id), "invalid-effect")
        lease = cls._lease(state, identifier)
        require(lease["state"] != "closed", "lease-closed")
        effect = lease["effects"].get(effect_id)
        require(effect is not None and effect["operation"] == "engine-start"
                and effect["target"] == "engine:lit-lease-" + identifier
                and effect["state"] in {"intent", "unknown", "verified"}, "engine-observation-effect")
        return lease, effect

    def bind_engine_capture(self, identifier, effect_id, *, manifest_sha256, cgroup_device, cgroup_inode,
                            stdout_device, stdout_inode, stderr_device, stderr_inode,
                            stdout_limit, stderr_limit, total_limit):
        """Bind Root's pre-Popen private capture/cgroup inventory, not authority.

        Root must acquire actual private regular single-link0600 stdout.log and
        stderr.log beneath the signed per-lease runroot, plus the original
        private cgroup FD. No path/name/policy blob is accepted. Ceilings must
        equal the compiled Root policy; this journal only validates their closed
        bounded shape. This is metadata on the start, never a pending capture
        effect through the run. It grants no Popen, retry or deadline extension.
        """
        capture = {"manifest_sha256": manifest_sha256, "cgroup_device": cgroup_device,
                   "cgroup_inode": cgroup_inode, "stdout_device": stdout_device, "stdout_inode": stdout_inode,
                   "stderr_device": stderr_device, "stderr_inode": stderr_inode,
                   "stdout_limit": stdout_limit, "stderr_limit": stderr_limit, "total_limit": total_limit}
        _validate_engine_capture(capture)
        with self._transaction() as state:
            lease, effect = self._engine_observation(state, identifier, effect_id)
            if "engine_capture" in effect:
                require(effect["engine_capture"] == capture, "engine-capture-rebind")
                return
            require(effect["state"] == "intent" and "engine_process" not in effect
                    and "engine_container_id" not in effect, "engine-capture-after-spawn")
            boot = lease["worker"]["boot_id"]
            streams = {(stdout_device, stdout_inode), (stderr_device, stderr_inode)}
            for record in state["leases"].values():
                if record["worker"]["boot_id"] != boot:
                    continue
                for other in record["effects"].values():
                    if "engine_capture" in other:
                        owned = other["engine_capture"]
                        require((cgroup_device, cgroup_inode) != (owned["cgroup_device"], owned["cgroup_inode"])
                                and not streams & {(owned["stdout_device"], owned["stdout_inode"]),
                                                   (owned["stderr_device"], owned["stderr_inode"])}, "engine-capture-reuse")
            effect["engine_capture"] = capture

    def record_engine_exit(self, identifier, effect_id, *, pid, start_ticks, boot_id, container_id,
                           manifest_sha256, exit_code, signal, observed_at,
                           stdout_bytes, stdout_sha256, stdout_state, stderr_bytes, stderr_sha256, stderr_state):
        """Retain the original owning Root parent's one actual wait/capture result.

        Caller must own that exact Popen/pidfd, complete the bounded private
        stream readback and prove the supplied process/CID/manifest. Missing
        tracking, a restarted parent, CID absence or a guessed wait result is
        never sufficient. This observation may arrive after expiry/cancel but
        cannot resolve an unknown start, verify cleanup or claim test PASS.
        A terminal response must be read back from this durable record.
        """
        value = {"pid": pid, "start_ticks": start_ticks, "boot_id": boot_id, "container_id": container_id,
                 "manifest_sha256": manifest_sha256, "exit_code": exit_code, "signal": signal,
                 "observed_at": observed_at, "stdout_bytes": stdout_bytes, "stdout_sha256": stdout_sha256,
                 "stdout_state": stdout_state, "stderr_bytes": stderr_bytes, "stderr_sha256": stderr_sha256,
                 "stderr_state": stderr_state}
        with self._transaction() as state:
            _, effect = self._engine_observation(state, identifier, effect_id)
            _validate_engine_exit(value, effect)
            if "engine_exit" in effect:
                require(effect["engine_exit"] == value, "engine-exit-rebind")
                return
            effect["engine_exit"] = value

    @classmethod
    def _fence_effect(cls, state, identifier, effect_id, operation):
        require(type(effect_id) is str and ID.fullmatch(effect_id), "invalid-effect")
        lease = cls._lease(state, identifier)
        require(lease["state"] != "closed", "lease-closed")
        effect = lease["effects"].get(effect_id)
        require(effect is not None and effect["operation"] == operation
                and effect["state"] in {"intent", "unknown"}, "fence-metadata-effect")
        return lease, effect

    def bind_fence(self, identifier, effect_id, *, policy_sha256, boot_id, netns_device, netns_inode,
                   host_ifindex, peer_ifindex, nft_table_handle):
        """Retain original Root-acquired deny-first namespace ownership only.

        The executor owes actual nsfs/veth aliases and sealed namespace-local
        nft rules readback. Names/paths are derived from the lease, never wire
        inputs. A metadata binding is not kernel proof or an access grant.
        Peer ifindices and nft handles belong to their individual namespace;
        equal numbers in distinct namespaces are legitimate, not borrowed.
        """
        fence = {"policy_sha256": policy_sha256, "boot_id": boot_id, "netns_device": netns_device,
                 "netns_inode": netns_inode, "host_ifindex": host_ifindex,
                 "peer_ifindex": peer_ifindex, "nft_table_handle": nft_table_handle}
        _validate_fence(fence)
        key = (boot_id, netns_device, netns_inode)
        with self._transaction() as state:
            _, effect = self._fence_effect(state, identifier, effect_id, "fence-create")
            if "fence" in effect:
                require(effect["fence"] == fence, "fence-metadata-rebind")
                return
            for record in state["leases"].values():
                for other in record["effects"].values():
                    if "fence" in other:
                        owned = other["fence"]
                        require((owned["boot_id"], owned["netns_device"], owned["netns_inode"]) != key
                                and (owned["boot_id"], owned["host_ifindex"]) != (boot_id, host_ifindex),
                                "fence-metadata-reuse")
            effect["fence"] = fence

    def bind_fence_authorization(self, identifier, effect_id, *, authorization_sha256, allow_expires_at,
                                 issued_boot_ns, expires_boot_ns):
        """Retain bounded Root clock/allow observation without enabling access.

        Target suffix is latest JTI SHA; authorization_sha256 is instead the
        canonical digest of that complete archived authorization dictionary.
        Actual wall/boot conversion and effective nft timeout verification
        belong to Root's kernel executor; these typed fields alone prove none.
        """
        value = {"authorization_sha256": authorization_sha256, "allow_expires_at": allow_expires_at,
                 "issued_boot_ns": issued_boot_ns, "expires_boot_ns": expires_boot_ns}
        with self._transaction() as state:
            lease, effect = self._fence_effect(state, identifier, effect_id, "fence-renew")
            expected = "fence:" + identifier + ":" + lease["authorizations"][-1]["token_id_sha256"]
            require(effect["target"] == expected, "fence-current-authorization")
            _validate_fence_authorization(value, lease, effect)
            if "fence_authorization" in effect:
                require(effect["fence_authorization"] == value, "fence-authorization-rebind")
                return
            effect["fence_authorization"] = value

    @staticmethod
    def _host_api_claimants(state, policy_sha256, baseline_sha256):
        result = []
        for identifier, lease in state["leases"].items():
            effects = list(lease["effects"].values())
            removed = any(row["operation"] == "fence-remove" and row["state"] == "verified" for row in effects)
            if not removed and any(row["operation"] == "fence-create" and row["state"] in {"intent", "unknown", "verified"}
                    and row.get("host_api", {}).get("policy_sha256") == policy_sha256
                    and row["host_api"]["baseline_sha256"] == baseline_sha256 for row in effects):
                result.append(identifier)
        return tuple(sorted(result))

    def host_api_claimants(self, policy_sha256, baseline_sha256):
        """Read-only retained-store claimant query; no kernel ownership claim.

        Expired/cancelled/unknown leases still occupy the one pilot baseline
        until actual verified namespace removal. UID/job labels never free it.
        """
        require(all(type(value) is str and HEX.fullmatch(value) for value in (policy_sha256, baseline_sha256)),
                "invalid-host-api-query")
        with self._transaction() as state:
            return self._host_api_claimants(state, policy_sha256, baseline_sha256)

    def bind_host_api_fence(self, identifier, effect_id, *, policy_sha256, baseline_sha256, boot_id,
                            host_netns_device, host_netns_inode, nft_table_handle):
        """Bind actual persistent baseline to the existing deny-first creator.

        Independent Root baseline journal/native readback is required upstream.
        No extra lease operation, bootstrap grant or endpoint activation follows.
        """
        value = {"policy_sha256": policy_sha256, "baseline_sha256": baseline_sha256, "boot_id": boot_id,
                 "host_netns_device": host_netns_device, "host_netns_inode": host_netns_inode,
                 "nft_table_handle": nft_table_handle}
        _validate_host_api(value)
        with self._transaction() as state:
            _, effect = self._fence_effect(state, identifier, effect_id, "fence-create")
            require("fence" in effect and effect["fence"]["boot_id"] == boot_id, "host-api-creator-unbound")
            if "host_api" in effect:
                require(effect["host_api"] == value, "host-api-metadata-rebind")
                return
            require(not self._host_api_claimants(state, policy_sha256, baseline_sha256), "host-api-baseline-busy")
            for lease in state["leases"].values():
                effects = list(lease["effects"].values())
                if any(row["operation"] == "fence-remove" and row["state"] == "verified" for row in effects):
                    continue
                for row in effects:
                    prior = row.get("host_api")
                    require(prior is None or (prior["boot_id"], prior["host_netns_device"], prior["host_netns_inode"],
                            prior["nft_table_handle"]) != (boot_id, host_netns_device, host_netns_inode, nft_table_handle),
                            "host-api-kernel-slot-busy")
            effect["host_api"] = value

    def bind_host_api_authorization(self, identifier, effect_id, *, baseline_sha256, host_ifindex, peer_ipv4,
                                    authorization_sha256, allow_expires_at, issued_boot_ns, expires_boot_ns):
        """Retain paired host grant metadata before possible kernel send.

        Exact current JTI remains in the existing fence-renew target; whole
        authorization digest and fixed deadline remain independently checked.
        """
        value = {"baseline_sha256": baseline_sha256, "host_ifindex": host_ifindex, "peer_ipv4": peer_ipv4,
                 "authorization_sha256": authorization_sha256, "allow_expires_at": allow_expires_at,
                 "issued_boot_ns": issued_boot_ns, "expires_boot_ns": expires_boot_ns}
        with self._transaction() as state:
            lease, effect = self._fence_effect(state, identifier, effect_id, "fence-renew")
            require(effect["target"] == "fence:" + identifier + ":" + lease["authorizations"][-1]["token_id_sha256"]
                    and "fence_authorization" in effect, "host-api-current-authorization")
            _validate_host_api_authorization(value, lease, effect)
            require(not any(row["operation"] == "fence-disable" for row in lease["effects"].values()), "fence-disabled")
            if "host_api_authorization" in effect:
                require(effect["host_api_authorization"] == value, "host-api-authorization-rebind")
                return
            effect["host_api_authorization"] = value

    def bind_host_api_withdrawal(self, identifier, effect_id, *, baseline_sha256):
        """Durable once marker BEFORE paired host cut, never a retry grant."""
        require(type(baseline_sha256) is str and HEX.fullmatch(baseline_sha256), "invalid-host-api-withdrawal")
        with self._transaction() as state:
            lease, effect = self._fence_effect(state, identifier, effect_id, "fence-disable")
            require(effect["state"] == "intent" and "host_api_withdrawal" not in effect,
                    "host-api-withdrawal-replay")
            require(any(row["operation"] == "fence-create" and row["state"] == "verified"
                        and row.get("host_api", {}).get("baseline_sha256") == baseline_sha256
                        for row in lease["effects"].values()), "host-api-withdrawal-not-owned")
            effect["host_api_withdrawal"] = {"baseline_sha256": baseline_sha256}

    def reconcile(self, identifier, effect_id, outcome, *, evidence_sha256):
        """Root-only verified readback, never an automatic retry authorization."""
        self._outcome(identifier, effect_id, outcome, evidence_sha256, reconcile=True)

    def cancel(self, identifier, reason):
        require(reason in {"cancelled", "job_ended", "runner_lost", "token_revoked"}, "invalid-cancel-reason")
        with self._transaction() as state:
            lease = self._lease(state, identifier)
            require(lease["state"] != "closed", "lease-closed")
            lease.update(state="cancelled", cancel_reason=reason, cancelled_at=self._now())

    @staticmethod
    def _cleanup_complete(effects):
        require(not any(e["state"] in {"intent", "unknown"} for e in effects), "effect-unresolved")
        for effect in effects:
            if effect["operation"] in CREATES and effect["state"] == "verified":
                require(any(other["operation"] == CREATES[effect["operation"]]
                            and other["target"] == effect["target"] and other["state"] == "verified"
                            for other in effects), "cleanup-unconfirmed")

    def close(self, identifier):
        """Confirm resource cleanup only. A failed test never becomes PASS."""
        with self._transaction() as state:
            lease = self._lease(state, identifier)
            require(lease["state"] != "closed", "lease-closed")
            self._cleanup_complete(list(lease["effects"].values()))
            lease.update(state="closed", closed_at=self._now())
