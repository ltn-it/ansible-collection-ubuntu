"""Root-internal expected-ID-only runner2.338.2 credential replacement component.

No handler, token minting, native-fence implementation, service migration or
operating acceptance exists here. A future root-native reader alone may issue
VerifiedTarget; job JSON and a dataclass are not native evidence. The private
issuance capability is an internal code boundary, not a privilege against root.

Pinned stock contracts (d1eb12d4b115c301201de27d667284e1a80f2ab5):
Runner.Listener/Configuration/{IRSAKeyManager,RSAFileKeyManager,CredentialManager,
ConfigurationManager}.cs and Runner.Common/RunnerDotcomServer.cs. The stock RSA
ISerializable keys are exactly d,dp,dq,exponent,inverseQ,modulus,p,q (base64 byte[]).
Actual CLR/stock-loader compatibility remains a separate required offline test.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import http.client
import json
import os
import re
import ssl
import stat
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric import rsa

from .identity import Denied, decode_json, require

VERSION = "2.338.2"
ORIGIN = "https://api.github.com"
AUTH_URL = ORIGIN + "/actions/runner-registration"
REPLACE_URL = ORIGIN + "/actions/runners/register"
MAX_BYTES = 65536
KEY_FILE = ".credentials_rsaparams"
STATE_FILE = "registration-state.json"
LOCK_FILE = "registration.lock"
MARKER_FILE = "registration.marker"
KEY_SIZES = {"d": 256, "dp": 128, "dq": 128, "exponent": 3,
             "inverseQ": 128, "modulus": 256, "p": 128, "q": 128}
HEX = re.compile(r"[0-9a-f]{64}\Z")
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_FENCE_AUTHORITY = object()


def _root():
    require(os.geteuid() == 0, "registration-root-required")


def _positive(value):
    return type(value) is int and 0 < value < 2 ** 63


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class VerifiedTarget:
    """Internal output contract of the NOT YET IMPLEMENTED root-native fence.

    Ordinary construction fails. No JSON factory or production issuer exists.
    Tests may supply the private issuance capability to model acquired facts;
    that models transport/state behavior and makes no native acceptance claim.
    """
    owner_id: int
    owner_login: str
    runner_id: int
    name: str
    group_id: int
    group_name: str
    architecture: str
    labels: tuple[tuple[str, str], ...]
    work_folder: str
    fence_sha256: str
    valid_until: int
    _authority: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        _root()
        require(self._authority is _FENCE_AUTHORITY, "registration-native-fence-required")
        _validate_target(self)


@dataclass(frozen=True)
class RegistrationResult:
    runner_id: int
    name: str
    public_key_sha256: str
    key_path: str
    settings_path: str
    credentials_path: str
    updates_disabled_requested: bool = True


@dataclass(frozen=True)
class RegistrationMaterial:
    """Root-memory-only handoff. Secret bytes never appear in repr/receipts."""
    runner_id: int
    name: str
    settings: bytes = field(repr=False)
    credentials: bytes = field(repr=False)
    private_key: bytes = field(repr=False)


def _validate_target(target):
    require(type(target) is VerifiedTarget and target._authority is _FENCE_AUTHORITY,
            "registration-native-fence-required")
    require(all(_positive(x) for x in (target.owner_id, target.runner_id, target.group_id)), "registration-target-id")
    require(target.group_id < 2 ** 31, "registration-target-id")
    require(type(target.owner_login) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", target.owner_login)
            and type(target.name) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", target.name), "registration-target-name")
    require(type(target.group_name) is str and 0 < len(target.group_name) <= 128
            and not any(ord(c) < 32 for c in target.group_name), "registration-target-group")
    require(target.architecture in ("arm64", "x64") and type(target.labels) is tuple
            and 1 <= len(target.labels) <= 32, "registration-target-labels")
    names = set()
    for label in target.labels:
        require(type(label) is tuple and len(label) == 2 and type(label[0]) is str
                and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", label[0]) and label[1] in ("system", "user"),
                "registration-target-labels")
        require(label[0].lower() not in names, "registration-target-labels")
        names.add(label[0].lower())
    _absolute(target.work_folder)
    require(type(target.fence_sha256) is str and HEX.fullmatch(target.fence_sha256)
            and type(target.valid_until) is int, "registration-target-fence")


def _fresh(target):
    _validate_target(target)
    now = int(time.time())
    require(now < target.valid_until <= now + 300, "registration-native-fence-expired")


def _identity(target):
    return {"owner_id": target.owner_id, "owner_login": target.owner_login, "runner_id": target.runner_id,
            "name": target.name, "group_id": target.group_id, "group_name": target.group_name,
            "architecture": target.architecture, "labels": [list(x) for x in target.labels],
            "work_folder": target.work_folder, "version": VERSION}


def _absolute(path):
    require(type(path) is str and 0 < len(path) <= 4096 and path.startswith("/")
            and path != "/" and not path.startswith("//") and str(PurePosixPath(path)) == path
            and ".." not in PurePosixPath(path).parts and not any(ord(c) < 32 or ord(c) == 127 for c in path),
            "registration-stage-path")
    return PurePosixPath(path).parts[1:]


@contextmanager
def _stage(path):
    _root()
    parts = _absolute(path)
    fd = os.open("/", DIR_FLAGS)
    try:
        for part in parts:
            next_fd = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    "registration-stage-ancestor")
        require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, "registration-stage-private")
        yield fd
    finally:
        os.close(fd)


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _private(info):
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600, "registration-private-file")


def _read(fd, name):
    handle = os.open(name, READ_FLAGS, dir_fd=fd)
    try:
        before = os.fstat(handle)
        _private(before)
        require(0 < before.st_size <= MAX_BYTES, "registration-file-size")
        raw = b""
        while len(raw) <= MAX_BYTES:
            part = os.read(handle, min(8192, MAX_BYTES + 1 - len(raw)))
            if not part:
                break
            raw += part
        require(len(raw) == before.st_size and _stamp(before) == _stamp(os.fstat(handle)),
                "registration-file-drift")
        require(_stamp(before) == _stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)), "registration-file-drift")
        return raw
    finally:
        os.close(handle)


def _write_new(fd, name, raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "registration-file-size")
    handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(handle)
    finally:
        os.close(handle)
    os.fsync(fd)


def _entries(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    return set(os.listdir(fd))


def _save(fd, payload):
    envelope = {"schema": 1, "payload": payload, "sha256": _sha(_canonical(payload))}
    name = ".state-" + uuid.uuid4().hex
    _write_new(fd, name, _canonical(envelope))
    os.replace(name, STATE_FILE, src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)


def _load(fd, target):
    envelope = decode_json(_read(fd, STATE_FILE))
    require(set(envelope) == {"schema", "payload", "sha256"} and envelope["schema"] == 1
            and type(envelope["payload"]) is dict and envelope["sha256"] == _sha(_canonical(envelope["payload"])),
            "registration-state-corrupt")
    payload = envelope["payload"]
    require(payload.get("target") == _identity(target) and payload.get("identity_sha256") == _sha(_canonical(_identity(target))),
            "registration-target-drift")
    marker = decode_json(_read(fd, MARKER_FILE))
    require(marker == {"schema": 1, "store_id": payload.get("store_id")}
            and type(payload.get("store_id")) is str and re.fullmatch(r"[0-9a-f]{32}", payload["store_id"]),
            "registration-store-binding")
    key_raw = _read(fd, KEY_FILE)
    require(payload.get("key_sha256") == _sha(key_raw), "registration-key-drift")
    key = private_key_from_json(key_raw)
    public = public_key_xml(key)
    require(payload.get("public_key_sha256") == _sha(public.encode()), "registration-key-drift")
    expected = {LOCK_FILE, MARKER_FILE, STATE_FILE, KEY_FILE}
    if payload.get("phase") == "complete":
        expected |= {".runner", ".credentials"}
    require(_entries(fd) == expected, "registration-stage-inventory")
    return payload, key


def _bytes(number, length):
    return number.to_bytes(length, "big")


def private_key_json(key):
    """Exact pinned ISerializable names, byte[] base64 and RSA export widths."""
    numbers = key.private_numbers()
    values = {"d": numbers.d, "dp": numbers.dmp1, "dq": numbers.dmq1, "exponent": numbers.public_numbers.e,
              "inverseQ": numbers.iqmp, "modulus": numbers.public_numbers.n, "p": numbers.p, "q": numbers.q}
    require(key.key_size == 2048 and numbers.public_numbers.e == 65537, "registration-key-parameters")
    return _canonical({name: base64.b64encode(_bytes(value, KEY_SIZES[name])).decode() for name, value in values.items()})


def private_key_from_json(raw):
    try:
        data = decode_json(raw)
        require(set(data) == set(KEY_SIZES), "registration-key-schema")
        numbers = {}
        for name, length in KEY_SIZES.items():
            value = data[name]
            require(type(value) is str and len(value) <= 344, "registration-key-encoding")
            binary = base64.b64decode(value, validate=True)
            require(len(binary) == length and base64.b64encode(binary).decode() == value, "registration-key-encoding")
            numbers[name] = int.from_bytes(binary, "big")
        require(numbers["exponent"] == 65537 and numbers["modulus"].bit_length() == 2048, "registration-key-parameters")
        return rsa.RSAPrivateNumbers(numbers["p"], numbers["q"], numbers["d"], numbers["dp"], numbers["dq"],
                                     numbers["inverseQ"], rsa.RSAPublicNumbers(numbers["exponent"], numbers["modulus"])).private_key()
    except Denied:
        raise
    except Exception:  # noqa: BLE001 -- redact private key, credential and wire exception data.
        raise Denied("registration-key-invalid") from None


def public_key_xml(key):
    numbers = key.public_key().public_numbers()
    require(key.key_size == 2048 and numbers.e == 65537, "registration-key-parameters")
    modulus = base64.b64encode(_bytes(numbers.n, 256)).decode()
    exponent = base64.b64encode(_bytes(numbers.e, 3)).decode()
    return "<RSAKeyValue><Modulus>" + modulus + "</Modulus><Exponent>" + exponent + "</Exponent></RSAKeyValue>"


def initialize(stage, target):
    """Explicit new-store operation; never regenerates a partial/existing key."""
    _root()
    _fresh(target)
    try:
        with _stage(stage) as fd:
            require(not _entries(fd), "registration-initialize-not-empty")
            _write_new(fd, LOCK_FILE, b"registration-lock-v1\n")
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            raw = private_key_json(key)
            _write_new(fd, KEY_FILE, raw)
            payload = {"store_id": uuid.uuid4().hex, "phase": "prepared", "target": _identity(target),
                       "identity_sha256": _sha(_canonical(_identity(target))), "key_sha256": _sha(raw),
                       "public_key_sha256": _sha(public_key_xml(key).encode())}
            _write_new(fd, MARKER_FILE, _canonical({"schema": 1, "store_id": payload["store_id"]}))
            _save(fd, payload)
    except Denied:
        raise
    except Exception:  # noqa: BLE001 -- redact private key, credential and wire exception data.
        raise Denied("registration-initialize-failed") from None


def _https_url(value):
    require(type(value) is str and 0 < len(value) <= 4096 and not any(ord(c) < 33 or ord(c) == 127 for c in value),
            "registration-response-url")
    parsed = urlsplit(value)
    require(parsed.scheme == "https" and parsed.username is None and parsed.password is None
            and parsed.port is None and not parsed.fragment and not parsed.query
            and parsed.hostname is not None and parsed.hostname.endswith(".actions.githubusercontent.com")
            and re.fullmatch(r"[a-z0-9.-]+", parsed.hostname), "registration-response-url")
    return value


def _wire(url, token, body):
    """One direct HTTPS request. No urllib proxies, redirects or wire retries."""
    require(url in (AUTH_URL, REPLACE_URL), "registration-http-origin")
    connection = None
    try:
        connection = http.client.HTTPSConnection("api.github.com", 443, timeout=20,
                                               context=ssl.create_default_context())
        connection.request("POST", urlsplit(url).path, body=body,
                           headers={"Authorization": "RemoteAuth " + token, "Content-Type": "application/json",
                                    "Accept": "application/json", "User-Agent": "lit-runner-root-registration/1"})
        response = connection.getresponse()
        raw = response.read(MAX_BYTES + 1)
        require(response.status in (200, 201) and 0 < len(raw) <= MAX_BYTES, "registration-http-response")
        return raw
    except Exception:  # noqa: BLE001 -- redact private key, credential and wire exception data.
        raise Denied("registration-http-unknown") from None
    finally:
        if connection is not None:
            connection.close()


def _auth(raw):
    data = decode_json(raw)
    require(set(data) == {"url", "token_schema", "token", "use_v2_flow"}
            and data["use_v2_flow"] is True and data["token_schema"] == "OAuthAccessToken"
            and type(data["token"]) is str and 0 < len(data["token"]) <= 16384, "registration-auth-flow")
    _https_url(data["url"])
    return data["url"]


def _response(raw, target):
    data = decode_json(raw)
    require({"id", "name", "authorization"} <= set(data)
            and set(data) <= {"id", "name", "authorization", "group_id", "owner_id", "updates_disabled"}
            and type(data["id"]) is int and data["id"] == target.runner_id and data["name"] == target.name,
            "registration-response-identity")
    for field_name, expected in (("group_id", target.group_id), ("owner_id", target.owner_id)):
        if field_name in data:
            require(type(data[field_name]) is int and data[field_name] == expected, "registration-response-binding")
    if "updates_disabled" in data:
        require(data["updates_disabled"] is True, "registration-response-binding")
    auth = data["authorization"]
    require(type(auth) is dict and {"authorization_url", "server_url", "client_id"} <= set(auth)
            and set(auth) <= {"authorization_url", "server_url", "client_id", "legacy_authorization_url"},
            "registration-response-authorization")
    _https_url(auth["authorization_url"])
    _https_url(auth["server_url"])
    if auth.get("legacy_authorization_url") is not None:
        _https_url(auth["legacy_authorization_url"])
    require(type(auth["client_id"]) is str and str(uuid.UUID(auth["client_id"])) == auth["client_id"]
            and uuid.UUID(auth["client_id"]).int != 0, "registration-response-client")
    return auth


def _result(stage, payload, target):
    return RegistrationResult(target.runner_id, target.name, payload["public_key_sha256"],
                              stage + "/" + KEY_FILE, stage + "/.runner", stage + "/.credentials")


def read_completed(stage, target):
    """Read the exact completed private store; no request, repair or rotation."""
    _root()
    _fresh(target)
    with _stage(stage) as fd:
        lock = os.open(LOCK_FILE, READ_FLAGS, dir_fd=fd)
        try:
            _private(os.fstat(lock))
            fcntl.flock(lock, fcntl.LOCK_SH)
            payload, _ = _load(fd, target)
            require(payload.get("phase") == "complete", "registration-not-complete")
            settings, credentials, key = (_read(fd, name) for name in (".runner", ".credentials", KEY_FILE))
            require(payload.get("settings_sha256") == _sha(settings)
                    and payload.get("credentials_sha256") == _sha(credentials)
                    and payload.get("key_sha256") == _sha(key), "registration-complete-drift")
            _fresh(target)
            return RegistrationMaterial(target.runner_id, target.name, settings, credentials, key)
        finally:
            os.close(lock)


def replace_registration(stage, target, token, *, _transport=None, _legacy_transport=None):
    """Internal root call only; _transport is an offline unit-test dependency.

    One auth intent/request and one credential-effect intent/request. An unknown
    phase is held on every later call; no new key, request or compensation.
    """
    _root()
    _fresh(target)
    require(type(token) is str and 0 < len(token) <= 8192
            and all(33 <= ord(c) <= 126 for c in token), "registration-token-input")
    transport = _wire if _transport is None else _transport
    try:
        with _stage(stage) as fd:
            lock = os.open(LOCK_FILE, READ_FLAGS, dir_fd=fd)
            try:
                _private(os.fstat(lock))
                fcntl.flock(lock, fcntl.LOCK_EX)
                payload, key = _load(fd, target)
                if payload["phase"] == "complete":
                    require(payload.get("settings_sha256") == _sha(_read(fd, ".runner"))
                            and payload.get("credentials_sha256") == _sha(_read(fd, ".credentials")),
                            "registration-complete-drift")
                    return _result(stage, payload, target)
                require(payload["phase"] == "prepared", "registration-unknown-held")
                owner_url = "https://github.com/" + target.owner_login
                auth_body = _canonical({"url": owner_url, "runner_event": "register"})
                payload.update(phase="auth-intent", auth_payload_sha256=_sha(auth_body),
                               auth_fence_sha256=target.fence_sha256)
                _save(fd, payload)
                auth_raw = transport(AUTH_URL, token, auth_body)
                if decode_json(auth_raw).get("use_v2_flow", False) is False:
                    return _finish_legacy(fd, stage, payload, key, target, auth_raw, _legacy_transport)
                tenant_url = _auth(auth_raw)
                payload.update(phase="authenticated", tenant_url_sha256=_sha(tenant_url.encode()))
                _save(fd, payload)
                _fresh(target)
                # Auth can take time. Reacquire the persisted key/state before
                # rotating credentials; cached key objects cannot cure loss.
                current, persisted_key = _load(fd, target)
                require(current == payload and private_key_json(persisted_key) == private_key_json(key),
                        "registration-key-drift")
                public = public_key_xml(key)
                body = _canonical({"url": owner_url, "group_id": target.group_id, "name": target.name,
                                   "version": VERSION, "updates_disabled": True, "ephemeral": False,
                                   "labels": [{"id": 0, "name": name, "type": kind} for name, kind in target.labels],
                                   "public_key": public, "runner_id": target.runner_id, "replace": True})
                payload.update(phase="replace-intent", replace_payload_sha256=_sha(body),
                               replace_fence_sha256=target.fence_sha256)
                _save(fd, payload)
                auth = _response(transport(REPLACE_URL, token, body), target)
                settings = {"agentId": target.runner_id, "agentName": target.name, "poolId": target.group_id,
                            "poolName": target.group_name, "serverUrl": tenant_url, "gitHubUrl": owner_url,
                            "workFolder": target.work_folder, "disableUpdate": True,
                            "useV2Flow": True, "useRunnerAdminFlow": True, "serverUrlV2": auth["server_url"]}
                credentials = {"scheme": "OAuth", "data": {"clientId": auth["client_id"],
                               "authorizationUrl": auth.get("legacy_authorization_url") or auth["authorization_url"],
                               "requireFipsCryptography": "True"}}
                if auth.get("legacy_authorization_url"):
                    credentials["data"].update(enableAuthMigrationByDefault="true", authorizationUrlV2=auth["authorization_url"])
                settings_raw, credentials_raw = _canonical(settings), _canonical(credentials)
                _write_new(fd, ".runner", settings_raw)
                _write_new(fd, ".credentials", credentials_raw)
                require(_read(fd, KEY_FILE) == private_key_json(key), "registration-key-drift")
                payload.update(phase="complete", settings_sha256=_sha(settings_raw), credentials_sha256=_sha(credentials_raw))
                _save(fd, payload)
                return _result(stage, payload, target)
            finally:
                os.close(lock)
    except Denied:
        raise
    except Exception:  # noqa: BLE001 -- redact private key, credential and wire exception data.
        # Never return HTTP bodies, auth data, token, key bytes or raw exceptions.
        raise Denied("registration-operation-held") from None


def _finish_legacy(fd, stage, payload, key, target, auth_raw, transport):
    """Root-held store lock; no new key, unjournaled PUT or wire retry."""
    from . import legacy_registration as legacy
    auth = legacy.session(auth_raw)
    payload.update(phase="authenticated", protocol="legacy", tenant_url_sha256=_sha(auth.tenant_url.encode()))
    _save(fd, payload)
    _fresh(target)
    current, persisted = _load(fd, target)
    require(current == payload and private_key_json(persisted) == private_key_json(key), "registration-key-drift")
    numbers = persisted.public_key().public_numbers()
    public = {"exponent": base64.b64encode(_bytes(numbers.e, 3)).decode(),
              "modulus": base64.b64encode(_bytes(numbers.n, 256)).decode()}
    prepared = legacy.prepare(auth, target, public, transport=transport)
    return _complete_legacy(fd, stage, payload, persisted, target, auth, public, prepared, transport)


def _complete_legacy(fd, stage, payload, persisted, target, auth, public, prepared, transport):
    from . import legacy_registration as legacy
    _fresh(target)
    payload.update(phase="replace-intent", replace_payload_sha256=_sha(prepared.body),
                   replace_fence_sha256=target.fence_sha256)
    _save(fd, payload)
    # This is the sole credential-effect request. Any unknown outcome is held.
    raw = legacy.replace(prepared, transport=transport)
    material = legacy.response(raw, target, auth.tenant_url, public)
    _write_new(fd, ".runner", material.settings)
    _write_new(fd, ".credentials", material.credentials)
    require(_read(fd, KEY_FILE) == private_key_json(persisted), "registration-key-drift")
    payload.update(phase="complete", settings_sha256=_sha(material.settings),
                   credentials_sha256=_sha(material.credentials))
    _save(fd, payload)
    return _result(stage, payload, target)


def _root_report(path, expected_sha256):
    parts = _absolute(path)
    require(type(expected_sha256) is str and HEX.fullmatch(expected_sha256), "registration-rejection-proof")
    parent = "/" + "/".join(parts[:-1])
    with _stage(parent) as directory:
        raw = _read(directory, parts[-1])
    require(_sha(raw) == expected_sha256, "registration-rejection-proof-drift")
    return decode_json(raw)


def resume_rejected_legacy_auth(stage, target, token, rejection_path, rejection_sha256,
                                *, _transport=None, _legacy_transport=None):
    """Explicit Root continuation of a proved rejected auth response only.

    The ordinary operation still refuses auth-intent/unknown phases. This path
    requires an independent Root-private operator rejection receipt, binds the
    original store and target, preserves the original key/intents and consumes
    one separate reconcile intent. It never resets a phase to prepared. A lost
    or attempted credential replacement can never enter this continuation.
    """
    _root()
    _fresh(target)
    require(type(token) is str and 0 < len(token) <= 8192
            and all(33 <= ord(c) <= 126 for c in token), "registration-token-input")
    report = _root_report(rejection_path, rejection_sha256)
    require(type(report) is dict and set(report) == {"schema", "stage", "store_id", "target_sha256",
            "operator_path", "operator_sha256"} and type(report["schema"]) is int and report["schema"] == 1
            and report["stage"] == stage and report["target_sha256"] == _sha(_canonical(_identity(target))),
            "registration-rejection-proof")
    operator = _root_report(report["operator_path"], report["operator_sha256"])
    require(operator.get("state") == "HANDOFF_HELD_NO_AUTOMATIC_RETRY"
            and operator.get("runner_id") == target.runner_id and type(operator.get("runner_id")) is int
            and operator.get("error_type") == "Denied" and operator.get("error_reason") == "registration-auth-flow"
            and operator.get("token_cleanup") is True, "registration-auth-rejection-not-proved")
    transport = _wire if _transport is None else _transport
    try:
        with _stage(stage) as directory:
            lock = os.open(LOCK_FILE, READ_FLAGS, dir_fd=directory)
            try:
                _private(os.fstat(lock))
                fcntl.flock(lock, fcntl.LOCK_EX)
                payload, key = _load(directory, target)
                require(payload["store_id"] == report["store_id"], "registration-rejection-store-drift")
                if payload["phase"] == "complete":
                    require(payload.get("settings_sha256") == _sha(_read(directory, ".runner"))
                            and payload.get("credentials_sha256") == _sha(_read(directory, ".credentials")),
                            "registration-complete-drift")
                    return _result(stage, payload, target)
                require(payload["phase"] == "auth-intent" and "replace_payload_sha256" not in payload
                        and "auth_reconciliation" not in payload, "registration-reconciliation-not-eligible")
                payload.update(phase="auth-reconcile-intent", auth_reconciliation={
                    "original_phase": "auth-intent", "evidence_sha256": rejection_sha256,
                    "fence_sha256": target.fence_sha256})
                _save(directory, payload)
                body = _canonical({"url": "https://github.com/"+target.owner_login, "runner_event": "register"})
                raw = transport(AUTH_URL, token, body)
                return _finish_legacy(directory, stage, payload, key, target, raw, _legacy_transport)
            finally:
                os.close(lock)
    except Denied:
        raise
    except Exception:  # noqa: BLE001 -- redact private key, credential and wire exception data.
        raise Denied("registration-reconciliation-held") from None


def resume_legacy_prewrite_rejection(stage, target, token, rejection_path, rejection_sha256,
                                     *, _transport=None, _legacy_transport=None):
    """Continue a proved read-only legacy preparation rejection, retaining all intents.

    Fresh authentication and complete preparation are read-only. The original
    authenticated phase is preserved until the sole credential-effect intent
    is committed. A missing/lost PUT reply or any materialized credential can
    never enter this route. No key is generated and no prior intent is reset.
    """
    from . import legacy_registration as legacy
    _root()
    _fresh(target)
    require(type(token) is str and 0 < len(token) <= 8192
            and all(33 <= ord(c) <= 126 for c in token), "registration-token-input")
    report = _root_report(rejection_path, rejection_sha256)
    require(type(report) is dict and set(report) == {"schema", "stage", "store_id", "target_sha256",
            "operator_path", "operator_sha256"} and type(report["schema"]) is int and report["schema"] == 1
            and report["stage"] == stage and report["target_sha256"] == _sha(_canonical(_identity(target))),
            "registration-rejection-proof")
    operator = _root_report(report["operator_path"], report["operator_sha256"])
    require(operator.get("state") == "LEGACY_RECOVERY_HELD_NO_AUTOMATIC_RETRY"
            and type(operator.get("runner_id")) is int and operator["runner_id"] == target.runner_id
            and operator.get("error_type") == "Denied" and operator.get("error_reason") == "legacy-agent-group"
            and operator.get("old_service_action") is False and operator.get("token_cleanup") is True,
            "registration-prewrite-rejection-not-proved")
    transport = _wire if _transport is None else _transport
    try:
        with _stage(stage) as directory:
            lock = os.open(LOCK_FILE, READ_FLAGS, dir_fd=directory)
            try:
                _private(os.fstat(lock))
                fcntl.flock(lock, fcntl.LOCK_EX)
                payload, key = _load(directory, target)
                require(payload["store_id"] == report["store_id"], "registration-rejection-store-drift")
                if payload["phase"] == "complete":
                    require(payload.get("settings_sha256") == _sha(_read(directory, ".runner"))
                            and payload.get("credentials_sha256") == _sha(_read(directory, ".credentials")),
                            "registration-complete-drift")
                    return _result(stage, payload, target)
                require(payload["phase"] == "authenticated" and payload.get("protocol") == "legacy"
                        and "replace_payload_sha256" not in payload and "prewrite_reconciliation" not in payload,
                        "registration-prewrite-reconciliation-not-eligible")
                require(not any(os.path.lexists(os.path.join(stage, name)) for name in (".runner", ".credentials")),
                        "registration-unexpected-material")
                raw = transport(AUTH_URL, token, _canonical({"url": "https://github.com/"+target.owner_login,
                                                           "runner_event": "register"}))
                auth = legacy.session(raw)
                require(payload.get("tenant_url_sha256") == _sha(auth.tenant_url.encode()),
                        "registration-tenant-drift")
                numbers = key.public_key().public_numbers()
                public = {"exponent": base64.b64encode(_bytes(numbers.e, 3)).decode(),
                          "modulus": base64.b64encode(_bytes(numbers.n, 256)).decode()}
                prepared = legacy.prepare(auth, target, public, transport=_legacy_transport)
                _fresh(target)
                current, persisted = _load(directory, target)
                require(current == payload and private_key_json(persisted) == private_key_json(key),
                        "registration-key-drift")
                payload["prewrite_reconciliation"] = {"original_phase": "authenticated",
                    "evidence_sha256": rejection_sha256, "fence_sha256": target.fence_sha256}
                return _complete_legacy(directory, stage, payload, persisted, target, auth, public,
                                        prepared, _legacy_transport)
            finally:
                os.close(lock)
    except Denied:
        raise
    except Exception:  # noqa: BLE001 -- redact private key, credential and wire exception data.
        raise Denied("registration-prewrite-reconciliation-held") from None
