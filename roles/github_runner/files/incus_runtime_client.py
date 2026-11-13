#!/usr/bin/python3 -I
"""Unprivileged RuntimeV2 host client, never operating/release authority.

Install this and incus_job_client.py together in the sealed Root directory.
Actual installation/socket activation/custody are separate prerequisites. No
engine, command, policy, URL, output path or credential is accepted in argv.
Run/recover exit0 requires complete sanitized evidence, exact Thin semantics,
actual exit0 and verified Root cleanup. Native artifact upload is still a
separate workflow requirement. GitHub tokens remain memory-only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import select
import signal
import socket
import stat
import struct
import sys
import tarfile
import time
import ssl
import urllib.request

CONFIG = "/etc/lightning-it/incus-runtime-client.json"
EXECUTABLE = "/usr/libexec/lightning-it/incus-runtime-client"
HEX = re.compile(r"[0-9a-f]{64}\Z")
LEASE = re.compile(r"[0-9a-f]{32}\Z")
SELECTOR = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
OBSERVER_OPS = frozenset({"observe-profile", "observe-operating"})
OPS = frozenset({"run", "heartbeat", "status", "cancel", "recover", "record-upload"}) | OBSERVER_OPS
_CONFIGURATIONS = {}  # Public Root-sealed locators only; never credentials.
STATES = frozenset({"preparing", "running", "execution-complete", "cancelling", "cleanup-hold", "closed", "unknown", "awaiting-native-end"})
MAX_EVIDENCE = 2 * 1024 ** 3  # Wire ceiling, not an assigned operating quota.
MAX_MEMBERS = 20000
EVIDENCE_POLICY_SHA256 = "0c1dc5877ecb93fd55a9418ff360383c51e356c82c0bdc9268613f7e3c35e2ab"
EVIDENCE_CATEGORIES = frozenset({"source", "collection", "matrix", "junit", "allure-results", "allure-report", "logs",
                               "screenshots", "playwright-traces", "configuration", "dependencies", "security", "checksums"})
MAX_EVIDENCE_FILES = 10000
MAX_EVIDENCE_FILE_BYTES = 256 * 1024 ** 2
MAX_EVIDENCE_TOTAL_BYTES = 512 * 1024 ** 2
FRAME_SECONDS = 5
AUTHENTICATION_IDLE_SECONDS = 60
INITIAL_AUTH_CAPABILITY = "initial-auth-idle-v1"
sys.dont_write_bytecode = True


class ClientDenied(ValueError):
    """No authenticated mutation request was sent; never a retry grant."""


class ClientUnknown(ValueError):
    """Possible consumed request/partial delivery; explicit recover required."""


class _BeforeIntent(ClientDenied):
    """Exact authenticated Root failure reply, never automatic retry consent."""


def require(value):
    if not value:
        raise ClientDenied("incus-runtime-client-denied")


def _parent(path):
    require(type(path) is str and path.startswith("/") and str(PurePosixPath(path)) == path
            and ".." not in PurePosixPath(path).parts and not any(ord(c) < 32 for c in path))
    # Root seals socket parents as search-only (0710); traversing them must
    # not require directory-listing permission. The same inode guards apply.
    fd = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in PurePosixPath(path).parts[1:-1]:
            following = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = following
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022)
        return fd, PurePosixPath(path).name
    except BaseException:
        os.close(fd)
        raise


def _stamp(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _root_file(path, limit):
    parent, leaf = _parent(path)
    fd = None
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o022 and 0 < before.st_size <= limit)
        raw = os.read(fd, limit + 1)
        require(len(raw) == before.st_size and _stamp(os.fstat(fd)) == _stamp(before)
                and _stamp(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == _stamp(before))
        return raw, _stamp(before)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _authentication():
    # Explicit Root-sealed sibling load even under Python-I, never PYTHONPATH or
    # the candidate checkout. The existing authv1 wire executor is NOT reused.
    path = str(Path(__file__).with_name("incus_job_client.py"))
    raw, before = _root_file(path, 65536)
    spec = importlib.util.spec_from_file_location("_lit_runtime_auth_helpers", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(_root_file(path, 65536) == (raw, before))
    return module


def _object(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value)
            value[key] = item
        return value
    def reject(_):
        raise ClientDenied("incus-runtime-client-denied")
    def finite(value):
        result = float(value)
        require(math.isfinite(result))
        return result
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=reject, parse_float=finite)
    require(type(value) is dict)
    return value


def _configuration():
    raw, stamp = _root_file(CONFIG, 2048)
    value = _object(raw)
    require(set(value) in ({"schema", "socket_path"}, {"schema", "socket_path", "signing_public_key_hex"})
            and ("signing_public_key_hex" not in value or type(value["signing_public_key_hex"]) is str
                 and HEX.fullmatch(value["signing_public_key_hex"])) and type(value["schema"]) is int and value["schema"] == 2
            and type(value["socket_path"]) is str and value["socket_path"].startswith("/run/")
            and len(value["socket_path"].encode()) < 108)
    _parent_check, _ = _parent(value["socket_path"])
    os.close(_parent_check)
    return value["socket_path"], hashlib.sha256(raw).hexdigest(), stamp


def _frame(value, maximum):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    require(0 < len(raw) <= maximum)
    return struct.pack("!I", len(raw)) + raw


def _exact(connected, length, deadline):
    result = bytearray()
    while len(result) < length:
        remaining = deadline - time.monotonic()
        require(remaining > 0)
        connected.settimeout(remaining)
        part = connected.recv(length - len(result))
        require(part)
        result.extend(part)
    return bytes(result)


def _receive(connected):
    deadline = time.monotonic() + FRAME_SECONDS
    length = struct.unpack("!I", _exact(connected, 4, deadline))[0]
    require(0 < length <= 8192)
    return _object(_exact(connected, length, deadline))


def _authenticated_reply(connected):
    # Native GitHub/Root authentication may occupy its sealed <=60s allowance.
    # Idle wait is distinct from the five-second bounded frame-read deadline;
    # neither extends authorization, the lease or a Root transition budget.
    ready, _, _ = select.select([connected], [], [], AUTHENTICATION_IDLE_SECONDS)
    require(ready)
    return _receive(connected)


def _connect():
    configuration = _configuration()
    path = configuration[0]
    parent, leaf = _parent(path)
    connected = None
    try:
        before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISSOCK(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) in {0o600, 0o660, 0o666})
        connected = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connected.settimeout(FRAME_SECONDS)
        connected.connect(path)
        pid, uid, _ = struct.unpack("3i", connected.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(pid > 0 and uid == 0 and _stamp(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == _stamp(before)
                and _configuration() == configuration)
        return connected, configuration, parent, leaf, _stamp(before)
    except BaseException:
        if connected is not None:
            connected.close()
        os.close(parent)
        raise


def _stable(connection):
    connected, configuration, parent, leaf, before = connection
    require(_configuration() == configuration
            and _stamp(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == before)


def _close(connection):
    connection[0].close()
    os.close(connection[2])


def check(required_capability=None):
    """Local config/code/Root-peer prerequisites only; no challenge/admission."""
    connection = None
    try:
        require(sys.platform == "linux" and required_capability in {None, INITIAL_AUTH_CAPABILITY})
        _authentication()
        connection = _connect()
        _stable(connection)
        return {"schema": 2, "operation": "check", "state": "local-prerequisites-only",
                "capabilities": [INITIAL_AUTH_CAPABILITY],
                "authentication_idle_seconds": AUTHENTICATION_IDLE_SECONDS, "frame_seconds": FRAME_SECONDS}
    except Exception:
        raise ClientDenied("incus-runtime-client-denied") from None
    finally:
        if connection is not None:
            _close(connection)


def _integer(value, minimum=0, maximum=2 ** 63 - 1):
    return type(value) is int and minimum <= value <= maximum


def _failure(reply, operation):
    if reply.get("type") != "failure":
        return False
    require(set(reply) == {"schema", "type", "operation", "disposition"}
            and type(reply["schema"]) is int and reply["schema"] == 2 and reply["operation"] == operation
            and reply["disposition"] in {"denied-before-intent", "busy-before-intent", "unknown-hold"})
    if reply["disposition"] == "unknown-hold":
        raise ClientUnknown("incus-runtime-outcome-unknown")
    raise _BeforeIntent("incus-runtime-client-denied")


def _authenticate(selector, operation, lease_id=None, *, artifact=None):
    require(sys.platform == "linux" and type(selector) is str and SELECTOR.fullmatch(selector) and operation in OPS)
    require((operation in {"heartbeat", "status", "cancel"} and type(lease_id) is str and LEASE.fullmatch(lease_id))
            or (operation in {"run", "recover", "record-upload"} | OBSERVER_OPS and lease_id is None))
    authentication, connection, sent = _authentication(), None, False
    try:
        api_token = authentication._secret(os.environ.get("GITHUB_TOKEN"))
        connection = _connect()
        connected = connection[0]
        locator = _CONFIGURATIONS.get(selector) if operation not in OBSERVER_OPS else None
        message = {"schema": 2, "cell": selector, "operation": operation}
        if locator is not None:
            require(type(locator) is str and HEX.fullmatch(locator))
            message["configuration"] = locator
        connected.sendall(_frame(message, 1024))
        # Root collects complete installed/process evidence before issuing its
        # nonce. Reuse the existing auth idle wait; frame/nonce deadlines stay fixed.
        challenge = _authenticated_reply(connected)
        _failure(challenge, operation)
        intake = challenge.get("phase") == "intake"
        observer = challenge.get("phase") == "observer"
        require(not observer or operation in OBSERVER_OPS)
        challenge_keys = {"schema", "type", "operation", "nonce", "audience", "expires_at"} | ({"phase"} if intake or observer else set())
        require(set(challenge) == challenge_keys
                and type(challenge["schema"]) is int and challenge["schema"] == 2 and challenge["type"] == "challenge"
                and challenge["operation"] == operation and type(challenge["nonce"]) is str and HEX.fullmatch(challenge["nonce"])
                and challenge["audience"] == authentication.AUDIENCE + challenge["nonce"]
                and _integer(challenge["expires_at"], int(time.time()) + 1, int(time.time()) + 300))
        token = authentication._oidc(challenge["audience"])
        require(int(time.time()) < challenge["expires_at"])
        request = {"schema": 2, "operation": operation, "nonce": challenge["nonce"], "token": token, "api_token": api_token}
        if lease_id is not None:
            request["lease_id"] = lease_id
        if operation == "record-upload":
            require(type(artifact) is dict and set(artifact) == {"id", "digest_sha256", "size_in_bytes"})
            request["artifact"] = artifact
        else:
            require(artifact is None)
        _stable(connection)
        sent = True  # Set BEFORE send: any partial authentication is uncertain.
        connected.sendall(_frame(request, 40960))
        connected.shutdown(socket.SHUT_WR)
        del request, token, api_token
        if intake:
            require(locator is None)
            require(select.select([connected], [], [], 600)[0])
            ready = _receive(connected)
            _failure(ready, operation)
            require(set(ready) == {"schema", "type", "operation", "cell", "configuration", "deadline", "lease_created"}
                    and type(ready["schema"]) is int and ready["schema"] == 2 and ready["type"] == "intake-ready"
                    and ready["operation"] == operation and ready["cell"] == selector and ready["lease_created"] is False
                    and type(ready["configuration"]) is str and HEX.fullmatch(ready["configuration"])
                    and _integer(ready["deadline"], int(time.time()) + 1 if operation == "run" else 1) and connected.recv(1) == b""
                    and len(_CONFIGURATIONS) < 16)
            _stable(connection)
            _CONFIGURATIONS[selector] = ready["configuration"]
            _close(connection)
            connection = None
            # Separate connection + newly minted nonce/OIDC/native assignment.
            # First phase's completed FS staging never authorizes a lease.
            return _authenticate(selector, operation, lease_id, artifact=artifact)
        return connection
    except ClientDenied:
        if connection is not None:
            _close(connection)
        if sent:
            raise ClientUnknown("incus-runtime-outcome-unknown") from None
        raise
    except Exception:
        if connection is not None:
            _close(connection)
        if sent:
            raise ClientUnknown("incus-runtime-outcome-unknown") from None
        raise ClientDenied("incus-runtime-client-denied") from None



def record_upload(selector, artifact_id, digest):
    """Read native size locally, then Root independently binds the full ZIP."""
    require(_integer(artifact_id, 1) and type(digest) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", digest))
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository))
    auth = _authentication()
    bearer = auth._secret(os.environ.get("GITHUB_TOKEN"))
    url = "https://api.github.com/repos/" + repository + "/actions/artifacts/" + str(artifact_id)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), auth._NoRedirect())
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + bearer,
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    with opener.open(request, timeout=10) as response:
        require(response.status == 200 and response.geturl() == url)
        raw = response.read(65537)
        require(len(raw) <= 65536)
    value = _object(raw)
    require(value.get("id") == artifact_id and value.get("digest") == digest and value.get("expired") is False
            and _integer(value.get("size_in_bytes"), 1, MAX_EVIDENCE))
    artifact = {"id": artifact_id, "digest_sha256": digest.removeprefix("sha256:"), "size_in_bytes": value["size_in_bytes"]}
    del bearer, request, raw, value
    connection = None
    try:
        connection = _authenticate(selector, "record-upload", artifact=artifact)
        result = _result(_authenticated_reply(connection[0]), "record-upload", None)
        require(result["state"] == "awaiting-native-end" and connection[0].recv(1) == b"")
        _stable(connection)
        return result
    finally:
        if connection is not None:
            _close(connection)


def _result(reply, operation, lease_id):
    _failure(reply, operation)
    require(set(reply) == {"schema", "type", "operation", "lease_id", "state", "expires_at", "authorization_expires_at", "receipt_sha256"}
            and type(reply["schema"]) is int and reply["schema"] == 2 and reply["type"] == "result"
            and reply["operation"] == operation and type(reply["lease_id"]) is str and LEASE.fullmatch(reply["lease_id"])
            and (lease_id is None or reply["lease_id"] == lease_id) and reply["state"] in STATES
            and _integer(reply["expires_at"], 1) and _integer(reply["authorization_expires_at"], 1, reply["expires_at"])
            and type(reply["receipt_sha256"]) is str and HEX.fullmatch(reply["receipt_sha256"]))
    return reply


def operation(selector, kind, lease_id=None):
    connection = None
    try:
        require(kind in {"heartbeat", "status", "cancel"})
        connection = _authenticate(selector, kind, lease_id)
        reply = _result(_authenticated_reply(connection[0]), kind, lease_id)
        require(connection[0].recv(1) == b"")
        _stable(connection)
        return reply
    except _BeforeIntent:
        raise
    except ClientDenied:
        if connection is not None:
            raise ClientUnknown("incus-runtime-outcome-unknown") from None
        raise
    except Exception:
        raise ClientUnknown("incus-runtime-outcome-unknown") from None
    finally:
        if connection is not None:
            _close(connection)


def _terminal(reply, operation, lease_id=None):
    require(set(reply) == {"schema", "type", "operation", "sequence", "lease_id", "state", "exit", "capture", "cleanup", "receipt_sha256"}
            and type(reply["schema"]) is int and reply["schema"] == 2 and reply["type"] == "terminal"
            and reply["operation"] == operation and type(reply["sequence"]) is int and reply["sequence"] == 1
            and type(reply["lease_id"]) is str and LEASE.fullmatch(reply["lease_id"])
            and (lease_id is None or reply["lease_id"] == lease_id) and reply["state"] in STATES
            and type(reply["receipt_sha256"]) is str and HEX.fullmatch(reply["receipt_sha256"]))
    exit = reply["exit"]
    require(type(exit) is dict and set(exit) == {"kind", "code", "signal"})
    require((exit["kind"] == "exited" and _integer(exit["code"], 0, 255) and exit["signal"] is None)
            or (exit["kind"] == "signalled" and exit["code"] is None and _integer(exit["signal"], 1, 64))
            or (exit["kind"] == "unknown" and exit["code"] is exit["signal"] is None))
    capture, cleanup = reply["capture"], reply["cleanup"]
    require(type(capture) is dict and set(capture) == {"state", "receipt_sha256"}
            and ((capture["state"] == "verified" and type(capture["receipt_sha256"]) is str and HEX.fullmatch(capture["receipt_sha256"]))
                 or (capture["state"] in {"unknown", "not-available"} and capture["receipt_sha256"] is None))
            and type(cleanup) is dict and set(cleanup) == {"state"} and cleanup["state"] in {"verified", "hold", "pending"})
    return reply


def _destination(lease):
    require(type(lease) is str and LEASE.fullmatch(lease))
    root = os.environ.get("RUNNER_TEMP", "")
    run, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    require(root.startswith("/") and str(PurePosixPath(root)) == root and ".." not in PurePosixPath(root).parts
            and re.fullmatch(r"[1-9][0-9]{0,19}", run) and attempt == "1")
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(os.fstat(parent).st_uid == os.getuid() and not os.fstat(parent).st_mode & 0o022)
        for name in ("lit-incus-runtime", run, attempt, lease):
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError:
                pass  # Reuse only the sealed locator directory, never a file.
            following = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = following
            info = os.fstat(parent)
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        transfer = "transfer-" + secrets.token_hex(16)
        os.mkdir(transfer, 0o700, dir_fd=parent)
        following = os.open(transfer, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        os.close(parent)
        parent = following
        return parent, str(Path(root) / "lit-incus-runtime" / run / attempt / lease / transfer)
    except BaseException:
        os.close(parent)
        raise


def _relative(name):
    require(type(name) is str and 0 < len(name) <= 1024 and not name.startswith("/")
            and str(PurePosixPath(name)) == name and len(PurePosixPath(name).parts) <= 32
            and all(part not in {"", ".", ".."} for part in name.split("/"))
            and not any(ord(character) < 32 or ord(character) == 127 for character in name))
    return name


def _semantic(manifest, lifecycle, policy, original_paths):
    """Decision checks only; Root's pinned static policy already rescanned and
    rederived all complete reports/attachments. Never execute candidate code.
    A fully verified failure remains publishable diagnostics, not success.
    """
    env = os.environ
    scenario, target = env.get("QUALITY_INPUT_SCENARIO", ""), env.get("QUALITY_INPUT_TARGET", "")
    profile, source = env.get("QUALITY_INPUT_PROFILE", "").replace("_", "-"), env.get("QUALITY_INPUT_SOURCE_SHA", "")
    roles = env.get("QUALITY_INPUT_ROLES", "").split(",")
    require(all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", value) for value in (scenario, target))
            and profile in {"heavy", "application-acceptance"} and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", source)
            and roles and all(re.fullmatch(r"[a-z][a-z0-9_]*", role) for role in roles) and len(set(roles)) == len(roles)
            and env.get("GITHUB_RUN_ATTEMPT") == "1" and re.fullmatch(r"[1-9][0-9]*", env.get("GITHUB_RUN_ID", "")))
    require(type(manifest.get("schema_version")) is int and manifest["schema_version"] == 2
            and manifest.get("repository") == env.get("GITHUB_REPOSITORY")
            and manifest.get("workflow_run_id") == env["GITHUB_RUN_ID"] and manifest.get("workflow_attempt") == "1"
            and manifest.get("commit_sha") == manifest.get("expected_commit_sha") == source
            and manifest.get("commit_consistent") is True)
    disposition = env.get("QUALITY_INPUT_TARGET_DISPOSITION")
    require(disposition in {"candidate", "supported"})
    require((disposition == "candidate" and manifest.get("mode") == "candidate" and manifest.get("release_eligible") is False)
            or (disposition == "supported" and manifest.get("mode") == "ci"))
    for name in ("JUNIT", "ALLURE"):
        value = env.get("QUALITY_INPUT_" + name + "_REQUIRED")
        require(value in {"true", "false"} and policy["required_" + name.lower()] is (value == "true"))
    pending = policy.get("root_finalization") == "pending"
    lifecycle_keys = {"schema_version", "scenario", "target", "run_attempt", "test_exit_code", "capture_exit_code",
                      "destroy_exit_code", "effective_exit_code", "infrastructure_error", "evidence_policy_complete"}
    if pending:
        lifecycle_keys.add("root_finalization")
        require(lifecycle.get("root_finalization") == "pending" and lifecycle.get("destroy_exit_code") is None
                and manifest.get("root_finalization") == "pending" and type(manifest.get("execution_success")) is bool
                and manifest.get("candidate_execution_passed") is False and manifest.get("release_eligible") is False)
    require(set(lifecycle) == lifecycle_keys
            and type(lifecycle["schema_version"]) is int and lifecycle["schema_version"] == 1
            and lifecycle["scenario"] == scenario and lifecycle["target"] == target and lifecycle["run_attempt"] == "1"
            and lifecycle["evidence_policy_complete"] is False and type(lifecycle["infrastructure_error"]) is bool)
    codes = [lifecycle[key] for key in (("test_exit_code", "capture_exit_code") if pending else
                                      ("test_exit_code", "capture_exit_code", "destroy_exit_code"))]
    require(all(_integer(code, 0, 255) for code in codes)
            and _integer(lifecycle["effective_exit_code"], 0, 255)
            and lifecycle["effective_exit_code"] == next((code for code in codes if code), 0)
            and lifecycle["infrastructure_error"] is (codes[1] != 0 or (not pending and codes[2] != 0)))
    results, matrix = manifest.get("results"), manifest.get("matrix")
    require(type(results) is list and len(results) == len(roles) and type(matrix) is dict
            and type(matrix.get("expected")) is list and len(matrix["expected"]) == 1
            and type(matrix.get("actual_count")) is int and matrix["actual_count"] == len(results))
    expected = matrix["expected"][0]
    require(type(expected) is dict and expected.get("profile") == profile and expected.get("scenario") == scenario
            and expected.get("target") == target and expected.get("run_attempt") == "1"
            and type(expected.get("roles")) is list and sorted(expected["roles"]) == sorted(roles))
    require(all(type(row) is dict for row in results) and sorted(row.get("role") for row in results) == sorted(roles))
    passed = not any(codes) and not lifecycle["infrastructure_error"] and expected.get("status") == "passed"
    totals = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
    for row in results:
        require(row.get("profile") == profile and row.get("scenario") == scenario and row.get("target") == target
                and row.get("run_attempt") == "1" and type(row.get("meaningful")) is bool)
        counts = row.get("totals")
        require(type(counts) is dict and set(counts) == set(totals) and all(_integer(value) for value in counts.values()))
        cases = row.get("test_cases")
        require(type(cases) is list and cases and all(type(case) is dict and case.get("roles") == [row["role"]]
                and case.get("status") in {"passed", "failure", "error", "skipped"} for case in cases))
        for key in totals:
            totals[key] += counts[key]
        for key, prefix in (("junit", "junit/"), ("allure_results", "allure-results/")):
            refs = row.get(key)
            require(type(refs) is list and refs and all(type(ref) is str and ref.startswith(prefix)
                    and _relative(ref) in original_paths for ref in refs))
        passed = passed and row.get("status") == "passed" and row["meaningful"] is True
    require(type(manifest.get("test_totals")) is dict and all(_integer(value) for value in manifest["test_totals"].values())
            and _integer(manifest.get("failures")) and _integer(manifest.get("skips"))
            and manifest.get("test_totals") == totals and manifest.get("failures") == totals["failures"] + totals["errors"]
            and manifest.get("skips") == totals["skipped"])
    scan, security, prerequisites = manifest.get("secret_scan"), manifest.get("security_evidence"), manifest.get("prerequisites")
    require(type(scan) is dict and type(security) is dict and type(prerequisites) is dict
            and type(manifest.get("blockers")) is list)
    if prerequisites:
        require(set(prerequisites) == {"lint", "build", "coverage", "tiny", "heavy", "acceptance", "cleanup", "destroy"})
    passed = passed and totals["tests"] > 0 and totals["failures"] == totals["errors"] == 0
    passed = passed and scan.get("clean") is True and not scan.get("findings") and not scan.get("errors")
    passed = passed and not security.get("external_secret_findings", 0) and not manifest["blockers"]
    passed = passed and all(value == "success" for key, value in prerequisites.items()
                            if not pending or key != "destroy")
    if pending:
        require(not prerequisites or prerequisites["destroy"] == "pending")
        passed = passed and manifest.get("execution_success") is True
    else:
        passed = passed and (manifest.get("candidate_execution_passed") is True if disposition == "candidate"
                            else manifest.get("release_eligible") is True)
    prefix = "candidate-quality-result" if disposition == "candidate" else "quality-result"
    return bool(passed), prefix + "-" + scenario + "-" + target + "-" + source + "-attempt-1"


def _archive(fd, size, directory=None, destination=None):
    os.lseek(fd, 0, os.SEEK_SET)
    names, total, summaries, originals, allure_documents = set(), 0, {}, {}, {}
    with os.fdopen(os.dup(fd), "rb") as source, tarfile.open(fileobj=source, mode="r:gz") as archive:
        for member in archive:
            name = _relative(member.name)
            normalized = name.removeprefix("normalized/")
            is_original = name.startswith("evidence/")
            relative = name.removeprefix("evidence/")
            require(len(names) < MAX_MEMBERS and (name in {"lifecycle.json", "cell.json", "runtime/evidence-policy.json"}
                    or re.fullmatch(r"(?:normalized/)?(?:junit|allure)-[0-9]{6}\.json", name)
                    or name in {"normalized/lifecycle.json", "normalized/cell.json"}
                    or (is_original and (relative in {"manifest.json", "role-coverage.yml", "environment.json"}
                         or relative.split("/")[0] in EVIDENCE_CATEGORIES)))
                    and member.name not in names and member.isfile() and not member.pax_headers
                    and member.uid == member.gid == 0 and member.mode == 0o600 and member.mtime == 0
                    and 0 <= member.size <= MAX_EVIDENCE)
            names.add(member.name)
            total += member.size
            require(total <= MAX_EVIDENCE)
            if is_original:
                require(len(originals) < MAX_EVIDENCE_FILES and member.size <= MAX_EVIDENCE_FILE_BYTES)
                hasher = hashlib.sha256()
                reader = archive.extractfile(member)
                while True:
                    chunk = reader.read(65536)
                    if not chunk:
                        break
                    hasher.update(chunk)
                originals[relative] = (member.size, hasher.hexdigest())
                if relative.startswith("allure-results/") and relative.endswith(".json"):
                    allure_documents[relative] = _object(archive.extractfile(member).read(member.size + 1))
            if normalized in {"lifecycle.json", "cell.json"} or name in {"runtime/evidence-policy.json", "evidence/manifest.json", "evidence/checksums/SHA256SUMS"}:
                require(member.size <= (MAX_EVIDENCE_FILE_BYTES if name.startswith("evidence/") else 65536))
                raw = archive.extractfile(member).read(member.size + 1)
                if name == "evidence/checksums/SHA256SUMS":
                    summaries[name] = raw
                    continue
                value = _object(raw)
                summaries[name] = value
            if normalized in {"lifecycle.json", "cell.json"}:
                require(0 < member.size <= 65536)
                require(summaries[name].get("evidence_policy_complete") is False)
    require(os.fstat(fd).st_size == size)
    full = "runtime/evidence-policy.json" in summaries
    cell_key = "normalized/cell.json" if full else "cell.json"
    lifecycle_key = "normalized/lifecycle.json" if full else "lifecycle.json"
    require(cell_key in summaries and lifecycle_key in summaries)
    cell = summaries[cell_key]
    for kind in ("junit", "allure"):
        count = cell.get(kind + "_report_count")
        prefix = "normalized/" if full else ""
        require(_integer(count, 0, MAX_MEMBERS) and {name for name in names if name.startswith(prefix + kind + "-")}
                == {prefix + kind + "-" + str(index).zfill(6) + ".json" for index in range(count)})
    if not full:
        require(not originals and "normalized/cell.json" not in names)
        return {"evidence_policy_complete": False, "execution_passed": False}
    require(names == {"runtime/evidence-policy.json", "normalized/lifecycle.json", "normalized/cell.json"}
            | {"evidence/" + name for name in originals}
            | {"normalized/" + kind + "-" + str(index).zfill(6) + ".json"
               for kind in ("junit", "allure") for index in range(cell[kind + "_report_count"])})
    require(directory is not None and destination is not None and originals and sum(row[0] for row in originals.values()) <= MAX_EVIDENCE_TOTAL_BYTES)
    policy = summaries["runtime/evidence-policy.json"]
    policy_keys = {"schema", "evidence_policy_complete", "scope", "source_policy_sha256", "source_manifest_sha256", "required_junit", "required_allure"}
    pending = policy.get("root_finalization") == "pending"
    if pending:
        policy_keys.add("root_finalization")
    require(set(policy) == policy_keys
            and type(policy["schema"]) is int and policy["schema"] == 1 and policy["evidence_policy_complete"] is True
            and policy["scope"] == "full-sanitized-cell-transfer" and policy["source_policy_sha256"] == EVIDENCE_POLICY_SHA256
            and type(policy["required_junit"]) is bool and type(policy["required_allure"]) is bool
            and "manifest.json" in originals and policy["source_manifest_sha256"] == originals["manifest.json"][1])
    checksums = {}
    for line in summaries["evidence/checksums/SHA256SUMS"].decode("utf-8").splitlines():
        sha, name = line.split("  ", 1)
        require(HEX.fullmatch(sha) and _relative(name) not in checksums)
        checksums[name] = sha
    require(set(checksums) == set(originals) - {"checksums/SHA256SUMS"}
            and all(originals[name][1] == digest for name, digest in checksums.items()))
    def attachments(value, parent):
        if type(value) is dict:
            if "attachments" in value:
                require(type(value["attachments"]) is list)
                for attachment in value["attachments"]:
                    require(type(attachment) is dict and type(attachment.get("source")) is str
                            and str(PurePosixPath(parent) / _relative(attachment["source"])) in originals)
            for item in value.values():
                attachments(item, parent)
        elif type(value) is list:
            for item in value:
                attachments(item, parent)
    for name, value in allure_documents.items():
        attachments(value, str(PurePosixPath(name).parent))
    manifest = summaries["evidence/manifest.json"]
    require(manifest.get("checksums") == {"algorithm": "sha256", "file": "checksums/SHA256SUMS", "entry_count": len(checksums)})
    passed, artifact = _semantic(manifest, summaries[lifecycle_key], policy, set(originals))
    os.mkdir("evidence", 0o700, dir_fd=directory)
    _extract_evidence(fd, directory, originals)
    return {"evidence_policy_complete": True, "execution_passed": passed, "package_directory": destination + "/evidence",
            "result_artifact": artifact, "source_manifest_sha256": policy["source_manifest_sha256"], "_evidence_files": originals,
            **({"root_finalization": "pending", "execution_state": "awaiting-native-end"} if pending else {})}


def _extract_evidence(archive_fd, directory, originals):
    os.lseek(archive_fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(archive_fd), "rb") as source, tarfile.open(fileobj=source, mode="r:gz") as archive:
        for member in archive:
            if not member.name.startswith("evidence/"):
                continue
            relative = _relative(member.name.removeprefix("evidence/"))
            require(relative in originals)
            parent = os.open("evidence", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            file = None
            try:
                parts = PurePosixPath(relative).parts
                for part in parts[:-1]:
                    try:
                        os.mkdir(part, 0o700, dir_fd=parent)
                    except FileExistsError:
                        pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                    os.close(parent)
                    parent = child
                    require(os.fstat(parent).st_uid == os.getuid() and stat.S_IMODE(os.fstat(parent).st_mode) == 0o700)
                file = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                reader, count, digest = archive.extractfile(member), 0, hashlib.sha256()
                while True:
                    chunk = reader.read(65536)
                    if not chunk:
                        break
                    require(os.write(file, chunk) == len(chunk))
                    digest.update(chunk)
                    count += len(chunk)
                    require(count <= originals[relative][0])
                require((count, digest.hexdigest()) == originals[relative])
                os.fsync(file)
            finally:
                if file is not None:
                    os.close(file)
                os.close(parent)


def _capture(connection, terminal):
    require(terminal["capture"]["state"] == "verified"
            and terminal["capture"]["receipt_sha256"] == terminal["receipt_sha256"])
    connected = connection[0]
    header = _receive(connected)
    require(set(header) == {"schema", "type", "lease_id", "sequence", "size", "sha256", "chunk_count", "content_type"}
            and type(header["schema"]) is int and header["schema"] == 2 and header["type"] == "capture-manifest"
            and header["lease_id"] == terminal["lease_id"] and type(header["sequence"]) is int and header["sequence"] == 2
            and _integer(header["size"], 1, MAX_EVIDENCE) and type(header["sha256"]) is str and HEX.fullmatch(header["sha256"])
            and type(header["chunk_count"]) is int and header["chunk_count"] == (header["size"] + 4095) // 4096
            and header["content_type"] == "application/gzip")
    directory, path = _destination(terminal["lease_id"])
    fd = None
    try:
        fd = os.open(".capture.partial", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        hasher, offset = hashlib.sha256(), 0
        for index in range(header["chunk_count"]):
            chunk = _receive(connected)
            require(set(chunk) == {"schema", "type", "lease_id", "sequence", "offset", "data"}
                    and type(chunk["schema"]) is int and chunk["schema"] == 2 and chunk["type"] == "capture-chunk"
                    and chunk["lease_id"] == terminal["lease_id"] and type(chunk["sequence"]) is int and chunk["sequence"] == index + 3
                    and type(chunk["offset"]) is int and chunk["offset"] == offset and type(chunk["data"]) is str
                    and re.fullmatch(r"[A-Za-z0-9_-]{1,5462}", chunk["data"]))
            raw = base64.urlsafe_b64decode(chunk["data"] + "=" * (-len(chunk["data"]) % 4))
            require(base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == chunk["data"]
                    and 0 < len(raw) <= 4096 and offset + len(raw) <= header["size"])
            require(os.write(fd, raw) == len(raw))
            hasher.update(raw)
            offset += len(raw)
        require(offset == header["size"] and hasher.hexdigest() == header["sha256"] and connected.recv(1) == b"")
        _stable(connection)
        os.fsync(fd)
        complete = _archive(fd, header["size"], directory, path)
        os.rename(".capture.partial", "capture.tar.gz", src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        return {"capture_path": path + "/capture.tar.gz", "capture_sha256": header["sha256"], "capture_size": offset, **complete}
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def run_cell(selector, *, recover=False):
    connection, previous, cancelled = None, {}, [None]
    operation_name = "recover" if recover else "run"
    try:
        connection = _authenticate(selector, operation_name)
        reply = _authenticated_reply(connection[0])
        _failure(reply, operation_name)
        lease, deadline, authorization = None, None, None
        if not recover:
            require(set(reply) == {"schema", "type", "operation", "sequence", "lease_id", "state", "expires_at", "authorization_expires_at"}
                    and type(reply["schema"]) is int and reply["schema"] == 2 and reply["type"] == "accepted"
                    and reply["operation"] == "run" and type(reply["sequence"]) is int and reply["sequence"] == 0
                    and type(reply["lease_id"]) is str and LEASE.fullmatch(reply["lease_id"]) and reply["state"] == "preparing"
                    and _integer(reply["expires_at"], int(time.time()) + 1, int(time.time()) + 5400)
                    and _integer(reply["authorization_expires_at"], int(time.time()) + 1, reply["expires_at"]))
            lease, deadline, authorization = reply["lease_id"], reply["expires_at"], reply["authorization_expires_at"]
            next_heartbeat = authorization - min(30, max(1, (authorization - int(time.time())) // 2))
            def requested(kind, _frame):
                cancelled[0] = cancelled[0] or kind
            for kind in (signal.SIGINT, signal.SIGTERM):
                previous[kind] = signal.signal(kind, requested)
            cancel_sent = False
            while True:
                require(time.time() < deadline + 1800)  # Protocol cleanup ceiling, never deadline extension.
                if cancelled[0] and not cancel_sent:
                    operation(selector, "cancel", lease)
                    cancel_sent = True
                if not cancel_sent and time.time() >= next_heartbeat:
                    refreshed = operation(selector, "heartbeat", lease)
                    require(refreshed["expires_at"] == deadline and refreshed["authorization_expires_at"] > time.time())
                    authorization = refreshed["authorization_expires_at"]
                    next_heartbeat = authorization - min(30, max(1, (authorization - int(time.time())) // 2))
                readable, _, _ = select.select([connection[0]], [], [], 1)
                if readable:
                    reply = _receive(connection[0])
                    break
        elif reply.get("type") == "result":
            result = _result(reply, "recover", None)
            require(connection[0].recv(1) == b"")
            _stable(connection)
            return result
        terminal = _terminal(reply, operation_name, lease)
        capture = _capture(connection, terminal)
        return {**terminal, **capture, "transport_only": True, "interrupted": cancelled[0] is not None}
    except _BeforeIntent:
        raise
    except ClientDenied:
        if connection is not None:
            raise ClientUnknown("incus-runtime-outcome-unknown") from None
        raise
    except Exception:
        raise ClientUnknown("incus-runtime-outcome-unknown") from None
    finally:
        for kind, handler in previous.items():
            signal.signal(kind, handler)
        if connection is not None:
            _close(connection)


def _publish(result):
    """Only verified complete diagnostic evidence gets native upload outputs.

    Root never receives this path. A command file may be0644 under the actual
    runner UMask; require owner/singlelink/no group-world WRITE, not invented600.
    Full failure diagnostics may publish, but cannot make the CLI exit0.
    """
    require(result.get("evidence_policy_complete") is True and result.get("transport_only") is True)
    package, artifact = result.get("package_directory"), result.get("result_artifact")
    require(type(package) is str and type(artifact) is str and 0 < len(package) <= 4096
            and not any(ord(c) < 32 or ord(c) == 127 for c in package)
            and re.fullmatch(r"(?:candidate-)?quality-result-[A-Za-z0-9._-]{1,400}", artifact))
    capture = Path(result["capture_path"])
    require(str(capture.parent / "evidence") == package and capture.name == "capture.tar.gz")
    root = os.environ.get("RUNNER_TEMP", "")
    require(type(result.get("lease_id")) is str and LEASE.fullmatch(result["lease_id"])
            and capture.parent.parent == Path(root) / "lit-incus-runtime" / os.environ.get("GITHUB_RUN_ID", "") / "1" / result["lease_id"]
            and re.fullmatch(r"transfer-[0-9a-f]{32}", capture.parent.name))
    require(digest_file(capture) == result["capture_sha256"])
    _package_inventory(package, result.get("_evidence_files"))
    phase = "execution-state=awaiting-native-end\n" if result.get("root_finalization") == "pending" else ""
    _command_output(("package-directory=" + package + "\nresult-artifact=" + artifact + "\n" + phase).encode())


def _command_output(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 8192)
    root = os.environ.get("RUNNER_TEMP", "")
    output = os.environ.get("GITHUB_OUTPUT", "")
    require(root.startswith("/") and output.startswith(root + "/_runner_file_commands/"))
    relative = output.removeprefix(root + "/_runner_file_commands/")
    require(re.fullmatch(r"set_output_[A-Za-z0-9_-]{1,128}", relative))
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    fd = None
    try:
        require(str(PurePosixPath(output)) == output and ".." not in PurePosixPath(output).parts)
        for part in PurePosixPath(output).parts[1:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = following
            info = os.fstat(parent)
            require(info.st_uid in {0, os.getuid()} and not info.st_mode & 0o022)
        fd = os.open(relative, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
                and not before.st_mode & 0o022 and before.st_size <= 65536
                and _stamp(before) == _stamp(os.stat(relative, dir_fd=parent, follow_symlinks=False)))
        require(os.write(fd, raw) == len(raw))
        os.fsync(fd)
        after = os.fstat(fd)
        require((after.st_dev, after.st_ino, after.st_uid, after.st_nlink, after.st_mode)
                == (before.st_dev, before.st_ino, before.st_uid, before.st_nlink, before.st_mode)
                and after.st_size == before.st_size + len(raw)
                and _stamp(after) == _stamp(os.stat(relative, dir_fd=parent, follow_symlinks=False)))
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _package_inventory(path, expected):
    require(type(expected) is dict and 0 < len(expected) <= MAX_EVIDENCE_FILES)
    root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    found = set()
    def walk(directory, prefix=""):
        info = os.fstat(directory)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700 and info.st_dev == os.fstat(root).st_dev)
        for name in os.listdir(directory):
            relative = _relative(prefix + name)
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(current.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                try:
                    walk(child, relative + "/")
                finally:
                    os.close(child)
            else:
                require(relative in expected and stat.S_ISREG(current.st_mode) and current.st_uid == os.getuid()
                        and current.st_nlink == 1 and stat.S_IMODE(current.st_mode) == 0o600)
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                try:
                    before, digest, count = os.fstat(fd), hashlib.sha256(), 0
                    require(_stamp(before) == _stamp(current))
                    while True:
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            break
                        count += len(chunk)
                        require(count <= expected[relative][0])
                        digest.update(chunk)
                    require((count, digest.hexdigest()) == tuple(expected[relative]) and _stamp(before) == _stamp(os.fstat(fd))
                            and _stamp(before) == _stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)))
                finally:
                    os.close(fd)
                found.add(relative)
    try:
        walk(root)
        require(found == set(expected))
    finally:
        os.close(root)


def digest_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= MAX_EVIDENCE)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digest.update(chunk)
        require(_stamp(before) == _stamp(os.fstat(fd)))
        return digest.hexdigest()
    finally:
        os.close(fd)


def profile_selector(profile, scenario, target):
    """Stable cell locator shared with trusted Root registry preparation.

    The locator carries no authority. Native identity, exact assigned job and
    Root-selected candidate/image/resource policy are checked by the server.
    """
    require(type(profile) is str and profile in {"heavy", "application_acceptance"})
    require(all(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", value)
                for value in (scenario, target)))
    raw = json.dumps([profile, scenario, target], separators=(",", ":"), ensure_ascii=True).encode()
    return "cell-" + hashlib.sha256(raw).hexdigest()


def _final_receipt(envelope, profile, scenario, target):
    """Verify the external installed public pin, not the receipt's own key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    raw, _ = _root_file(CONFIG, 2048)
    key_hex = _object(raw).get("signing_public_key_hex")
    require(type(key_hex) is str and HEX.fullmatch(key_hex))
    require(type(envelope) is dict and set(envelope) == {"schema", "receipt", "signature"}
            and type(envelope["schema"]) is int and envelope["schema"] == 1)
    token = envelope["signature"]
    require(type(token) is str and len(token) <= 16384 and token.count(".") == 2)
    parts = token.split(".")
    def decode(value):
        require(re.fullmatch(r"[A-Za-z0-9_-]+", value))
        result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        require(base64.urlsafe_b64encode(result).rstrip(b"=").decode() == value)
        return result
    key = bytes.fromhex(key_hex)
    require(_object(decode(parts[0])) == {"alg": "EdDSA", "typ": "lit-incus-final-quality+jwt",
                                        "kid": hashlib.sha256(key).hexdigest()})
    Ed25519PublicKey.from_public_bytes(key).verify(decode(parts[2]), (parts[0] + "." + parts[1]).encode("ascii"))
    payload = _object(decode(parts[1]))
    require(payload == envelope["receipt"] and decode(parts[1]) == json.dumps(payload, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode())
    fields = {"schema", "purpose", "state", "lease_id", "repository", "repository_id", "run_id", "run_attempt",
        "source_sha", "controller_sha", "profile", "scenario", "target", "execution", "artifact",
        "capture_receipt_sha256", "cleanup", "custody_policy_sha256", "cell_sha256", "engine_policy_sha256",
        "signer_public_key_hex", "issued_at"}
    require(set(payload) == fields and type(payload["schema"]) is int and payload["schema"] == 1
            and payload["purpose"] == "urn:lightning-it:g06:final-quality:v1" and payload["state"] == "closed"
            and payload["signer_public_key_hex"] == key_hex and type(payload["lease_id"]) is str
            and LEASE.fullmatch(payload["lease_id"]) and payload["repository"] == os.environ.get("GITHUB_REPOSITORY")
            and str(payload["repository_id"]) == os.environ.get("GITHUB_REPOSITORY_ID")
            and str(payload["run_id"]) == os.environ.get("GITHUB_RUN_ID") and type(payload["run_attempt"]) is int
            and payload["run_attempt"] == 1 and payload["source_sha"] == os.environ.get("GITHUB_SHA")
            and (payload["profile"], payload["scenario"], payload["target"]) == (profile, scenario, target))
    for key_name in ("repository_id", "run_id", "issued_at"):
        require(_integer(payload[key_name], 1))
    for key_name in ("capture_receipt_sha256", "custody_policy_sha256", "cell_sha256", "engine_policy_sha256"):
        require(type(payload[key_name]) is str and HEX.fullmatch(payload[key_name]))
    require(type(payload["controller_sha"]) is str and re.fullmatch(r"[0-9a-f]{40}", payload["controller_sha"]))
    execution, cleanup, artifact = payload["execution"], payload["cleanup"], payload["artifact"]
    require(type(execution) is dict and set(execution) == {"job_id", "check_run_id", "conclusion", "completed_at"}
            and execution["conclusion"] == "success" and all(_integer(execution[k], 1)
                for k in ("job_id", "check_run_id", "completed_at")))
    require(type(cleanup) is dict and set(cleanup) == {"state", "ledger_sha256", "closed_at", "resource_absence_sha256"}
            and cleanup["state"] == "verified" and _integer(cleanup["closed_at"], execution["completed_at"], payload["issued_at"])
            and payload["issued_at"] <= int(time.time()) and all(type(cleanup[k]) is str and HEX.fullmatch(cleanup[k])
                for k in ("ledger_sha256", "resource_absence_sha256")))
    require(type(artifact) is dict and set(artifact) == {"id", "name", "digest_sha256", "size_in_bytes"}
            and _integer(artifact["id"], 1) and _integer(artifact["size_in_bytes"], 1, MAX_EVIDENCE)
            and type(artifact["digest_sha256"]) is str and HEX.fullmatch(artifact["digest_sha256"])
            and type(artifact["name"]) is str and re.fullmatch(r"(?:candidate-)?quality-result-[A-Za-z0-9._-]{1,400}", artifact["name"]))
    return payload


def _public_receipt_file(lease_id, name, value):
    directory, path = _destination(lease_id)
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        require(0 < len(raw) <= 16384 and re.fullmatch(r"[a-z-]+\.json", name))
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            require(os.write(fd, raw) == len(raw))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory)
        result = path + "/" + name
        require(not any(ord(c) < 32 or ord(c) == 127 for c in result))
        return result
    finally:
        os.close(directory)


def observe_profile(profile, scenario, target):
    selector = profile_selector(profile, scenario, target)
    connection = None
    try:
        connection = _authenticate(selector, "observe-profile")
        require(select.select([connection[0]], [], [], 180)[0])
        outcome = _receive(connection[0])
        _failure(outcome, "observe-profile")
        require(set(outcome) == {"schema", "type", "operation", "cell", "receipt"}
                and type(outcome["schema"]) is int and outcome["schema"] == 2 and outcome["type"] == "final-receipt"
                and outcome["operation"] == "observe-profile" and outcome["cell"] == selector and connection[0].recv(1) == b"")
        _stable(connection)
        payload = _final_receipt(outcome["receipt"], profile, scenario, target)
        path = _public_receipt_file(payload["lease_id"], "final-quality-receipt.json", outcome["receipt"])
        artifact = "root-final-quality-" + str(payload["run_id"]) + "-" + selector
        _command_output(("final-quality-artifact=" + artifact + "\nfinal-quality-receipt=" + path + "\n").encode())
        return {"schema": 2, "state": "closed", "lease_id": payload["lease_id"], "final_quality_receipt": path,
                "final_quality_artifact": artifact}
    finally:
        if connection is not None:
            _close(connection)


OPERATING_CASES = frozenset({"failure", "broker-cancel", "expiry-controller-loss"})


def operating_selector(case):
    require(type(case) is str and case in OPERATING_CASES)
    return "operating-" + case


def _operating_receipt(value, case, *, retained, lease=None, uuid=None):
    fields = {"schema", "kind", "case", "selector", "run_id", "run_attempt", "source_sha", "controller_sha",
        "lease_id", "instance_uuid", "raw_exit", "vm_state", "access", "retention_seconds", "terminal_at", "retain_until", "cutoff", "state"}
    require(type(value) is dict and set(value) == fields and type(value["schema"]) is int and value["schema"] == 1
            and value["kind"] == "operating" and value["case"] == case and value["selector"] == operating_selector(case)
            and _integer(value["run_id"], 1) and str(value["run_id"]) == os.environ.get("GITHUB_RUN_ID")
            and type(value["run_attempt"]) is int and value["run_attempt"] == 1
            and value["source_sha"] == os.environ.get("GITHUB_SHA") and type(value["controller_sha"]) is str
            and re.fullmatch(r"[0-9a-f]{40}", value["controller_sha"]) and type(value["lease_id"]) is str
            and LEASE.fullmatch(value["lease_id"]) and (lease is None or value["lease_id"] == lease)
            and type(value["instance_uuid"]) is str and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["instance_uuid"])
            and (uuid is None or value["instance_uuid"] == uuid) and value["vm_state"] == "stopped"
            and value["access"] == "withdrawn" and type(value["retention_seconds"]) is int and value["retention_seconds"] == 14400)
    actual = value["raw_exit"]
    require(type(actual) is dict and set(actual) == {"code", "signal"}
            and ((actual["signal"] is None and _integer(actual["code"], 0, 255))
                 or (actual["code"] is None and _integer(actual["signal"], 1, 64))))
    require((case == "failure" and actual == {"code": 23, "signal": None})
            or (case != "failure" and (actual["signal"] is not None or actual["code"] != 0)))
    cutoff = value["cutoff"]
    if case == "expiry-controller-loss":
        require(type(cutoff) is dict and set(cutoff) == {"kind", "deadline", "observed_at"}
                and cutoff["kind"] in {"authorization", "lease"} and _integer(cutoff["deadline"], 1, int(time.time()))
                and _integer(cutoff["observed_at"], cutoff["deadline"], int(time.time())))
    else:
        require(cutoff is None)
    if retained:
        require(value["state"] == "retained" and _integer(value["terminal_at"], 1, int(time.time()))
                and _integer(value["retain_until"], value["terminal_at"] + 14400, value["terminal_at"] + 86400))
    else:
        require(value["state"] == "safety-proved-retention-armed" and value["terminal_at"] is None and value["retain_until"] is None)
    return value


def _publish_operating(value, case, *, retained):
    value = _operating_receipt(value, case, retained=retained)
    path = _public_receipt_file(value["lease_id"], "operating-receipt.json", value)
    artifact = "root-operating-" + str(value["run_id"]) + "-" + case + ("-retained" if retained else "-execution")
    _command_output(("operating-artifact=" + artifact + "\noperating-receipt=" + path
                     + "\noperating-state=" + value["state"] + "\n").encode())
    return {"schema": 2, "state": value["state"], "operating_receipt": path, "operating_artifact": artifact}


def run_operating(case):
    selector = operating_selector(case)
    connection, previous = None, {}
    interrupted = [False]
    try:
        connection = _authenticate(selector, "run")
        reply = _authenticated_reply(connection[0])
        _failure(reply, "run")
        require(set(reply) == {"schema", "type", "operation", "sequence", "lease_id", "state", "expires_at", "authorization_expires_at"}
                and type(reply["schema"]) is int and reply["schema"] == 2 and reply["type"] == "accepted"
                and reply["operation"] == "run" and type(reply["sequence"]) is int and reply["sequence"] == 0
                and type(reply["lease_id"]) is str and LEASE.fullmatch(reply["lease_id"]) and reply["state"] == "preparing"
                and _integer(reply["expires_at"], int(time.time()) + 1, int(time.time()) + 5400)
                and _integer(reply["authorization_expires_at"], int(time.time()) + 1, reply["expires_at"]))
        lease, deadline, authorization = reply["lease_id"], reply["expires_at"], reply["authorization_expires_at"]
        next_heartbeat = authorization - min(30, max(1, (authorization - int(time.time())) // 2))
        ready_uuid, cancelled = None, False
        def requested(_kind, _frame):
            interrupted[0] = True
        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.signal(number, requested)
        while True:
            require(time.time() < deadline + 1800)
            if interrupted[0] and not cancelled:
                operation(selector, "cancel", lease)
                cancelled = True
            if not cancelled and not (ready_uuid is not None and case == "expiry-controller-loss") and time.time() >= next_heartbeat:
                renewed = operation(selector, "heartbeat", lease)
                require(renewed["expires_at"] == deadline and renewed["authorization_expires_at"] > time.time())
                authorization = renewed["authorization_expires_at"]
                next_heartbeat = authorization - min(30, max(1, (authorization - int(time.time())) // 2))
            if not select.select([connection[0]], [], [], 1)[0]:
                continue
            frame = _receive(connection[0])
            _failure(frame, "run")
            if frame.get("type") == "operating-ready":
                require(ready_uuid is None and set(frame) == {"schema", "type", "operation", "lease_id", "case", "instance_uuid"}
                        and type(frame["schema"]) is int and frame["schema"] == 2 and frame["operation"] == "run"
                        and frame["lease_id"] == lease and frame["case"] == case and type(frame["instance_uuid"]) is str
                        and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", frame["instance_uuid"]))
                ready_uuid = frame["instance_uuid"]
                if case == "broker-cancel" and not cancelled:
                    operation(selector, "cancel", lease)
                    cancelled = True
                continue
            require(ready_uuid is not None and not interrupted[0] and set(frame) == {"schema", "type", "operation", "lease_id", "receipt"}
                    and type(frame["schema"]) is int and frame["schema"] == 2 and frame["type"] == "operating-terminal"
                    and frame["operation"] == "run" and frame["lease_id"] == lease and connection[0].recv(1) == b"")
            _stable(connection)
            receipt = _operating_receipt(frame["receipt"], case, retained=False, lease=lease, uuid=ready_uuid)
            return _publish_operating(receipt, case, retained=False)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        if connection is not None:
            _close(connection)


def observe_operating(case):
    selector = operating_selector(case)
    connection = None
    try:
        connection = _authenticate(selector, "observe-operating")
        require(select.select([connection[0]], [], [], 180)[0])
        reply = _receive(connection[0])
        _failure(reply, "observe-operating")
        require(set(reply) == {"schema", "type", "operation", "cell", "receipt"}
                and type(reply["schema"]) is int and reply["schema"] == 2 and reply["type"] == "operating-receipt"
                and reply["operation"] == "observe-operating" and reply["cell"] == selector and connection[0].recv(1) == b"")
        _stable(connection)
        return _publish_operating(reply["receipt"], case, retained=True)
    finally:
        if connection is not None:
            _close(connection)


def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self, _message):
            raise ClientDenied("incus-runtime-client-denied")
    parser = Parser(add_help=False)
    sub = parser.add_subparsers(dest="command", required=True)
    check_parser = sub.add_parser("check", add_help=False)
    check_parser.add_argument("--require-capability", choices=(INITIAL_AUTH_CAPABILITY,))
    run = sub.add_parser("run-cell", add_help=False)
    run.add_argument("--selector", required=True)
    profile = sub.add_parser("run-profile", add_help=False)
    for name in ("profile", "scenario", "target"):
        profile.add_argument("--" + name, required=True)
    observer = sub.add_parser("observe-profile", add_help=False)
    for name in ("profile", "scenario", "target"):
        observer.add_argument("--" + name, required=True)
    upload = sub.add_parser("record-upload", add_help=False)
    for name in ("profile", "scenario", "target", "artifact-id", "artifact-digest"):
        upload.add_argument("--" + name, required=True, **({"type": int} if name == "artifact-id" else {}))
    for command in ("run-operating", "observe-operating"):
        operating = sub.add_parser(command, add_help=False)
        operating.add_argument("--case", required=True)
    recovery = sub.add_parser("recover", add_help=False)
    recovery.add_argument("--selector", required=True)
    for command in ("status", "cancel"):
        child = sub.add_parser(command, add_help=False)
        child.add_argument("--selector", required=True)
        child.add_argument("--lease-id", required=True)
    try:
        supplied = sys.argv[1:] if argv is None else argv
        limit = 11 if supplied and supplied[0] == "record-upload" else (7 if supplied and supplied[0] in {"run-profile", "observe-profile"} else 5)
        require(len(supplied) <= limit and all(supplied.count(flag) <= 1 for flag in
            ("--selector", "--lease-id", "--profile", "--scenario", "--target", "--artifact-id", "--artifact-digest",
             "--case", "--require-capability")))
        args = parser.parse_args(supplied)
        if args.command == "check":
            result = check(args.require_capability)
        elif args.command == "run-operating":
            result = run_operating(args.case)
        elif args.command == "observe-operating":
            result = observe_operating(args.case)
        elif args.command == "observe-profile":
            result = observe_profile(args.profile, args.scenario, args.target)
        elif args.command == "record-upload":
            result = record_upload(profile_selector(args.profile, args.scenario, args.target), args.artifact_id, args.artifact_digest)
            print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
            return 0
        elif args.command in {"run-cell", "run-profile", "recover"}:
            selector = (profile_selector(args.profile, args.scenario, args.target)
                        if args.command == "run-profile" else args.selector)
            result = run_cell(selector, recover=args.command == "recover")
            if result.get("evidence_policy_complete") is True:
                _publish(result)
            pending = result.get("root_finalization") == "pending"
            passed = (result.get("evidence_policy_complete") is True and result.get("execution_passed") is True
                      and result.get("exit") == {"kind": "exited", "code": 0, "signal": None}
                      and (pending or result.get("cleanup") == {"state": "verified"}) and result.get("interrupted") is False)
            # This exit0 is execution/transfer only in the typed pending phase;
            # a distinct authenticated observer owns final quality acceptance.
            print(json.dumps({key: value for key, value in result.items() if key != "_evidence_files"},
                             sort_keys=True, separators=(",", ":"), allow_nan=False))
            return 0 if passed else 1
        else:
            result = operation(args.selector, args.command, args.lease_id)
        print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
        return 0
    except ClientDenied:
        print('{"schema":2,"state":"denied"}')
        return 2
    except Exception:
        print('{"schema":2,"state":"unknown-hold"}')
        return 3


if __name__ == "__main__":
    sys.exit(main())
