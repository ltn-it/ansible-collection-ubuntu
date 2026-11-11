"""Unprivileged host authentication transport, not an installed broker CLI.

The trusted host workflow obtains a fresh GitHub OIDC token for the issuer's
nonce. Tokens stay in memory and are sent only to the fixed Root-owned socket.
Nothing is forwarded to the untrusted EE. This component neither starts an
engine nor renews a network grant; the future Root dispatcher owns those steps.
There is no retry, automatic recover, request-policy override or token logging.
The public client is standalone so installation need not expose private server
modules. Deployment of its Root-owned configuration/entry point remains open.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import socket
import ssl
import stat
import struct
import sys
import time
import urllib.parse
import urllib.request

CONFIG = "/etc/lightning-it/incus-job-client.json"
AUDIENCE = "urn:lightning-it:legacy-incus:"
HEX = re.compile(r"[0-9a-f]{64}\Z")
LEASE = re.compile(r"[0-9a-f]{32}\Z")
SELECTOR = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
SECONDS = 5


class ClientDenied(ValueError):
    """No authenticated lease request was sent by this operation."""


class ClientUnknown(ValueError):
    """A lease request may have been consumed; never repeat it automatically."""


def require(condition):
    if not condition:
        raise ClientDenied("incus-client-denied")


def _object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    def invalid(_):
        raise ClientDenied("incus-client-denied")
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    require(type(value) is dict)
    return value


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _parent(path):
    require(type(path) is str and path.startswith("/") and str(PurePosixPath(path)) == path
            and ".." not in PurePosixPath(path).parts)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in PurePosixPath(path).parts[1:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = following
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022)
        return fd, PurePosixPath(path).name
    except BaseException:
        os.close(fd)
        raise


def _configuration():
    parent, leaf = _parent(CONFIG)
    fd = None
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o022 and 0 < before.st_size <= 2048)
        raw = os.read(fd, 2049)
        require(len(raw) == before.st_size and _stamp(os.fstat(fd)) == _stamp(before)
                and _stamp(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == _stamp(before))
        value = _object(raw)
        require(set(value) == {"schema", "socket_path"} and type(value["schema"]) is int
                and value["schema"] == 1 and type(value["socket_path"]) is str
                and value["socket_path"].startswith("/run/") and len(value["socket_path"].encode()) < 108)
        return value["socket_path"], hashlib.sha256(raw).hexdigest()
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _secret(value):
    require(type(value) is str and 0 < len(value) <= 16384 and all(33 <= ord(c) <= 126 for c in value))
    return value


def _frame(value, maximum):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    require(0 < len(raw) <= maximum)
    return struct.pack("!I", len(raw)) + raw


def _exact(connected, size, deadline):
    result = bytearray()
    while len(result) < size:
        remaining = deadline - time.monotonic()
        require(remaining > 0)
        connected.settimeout(remaining)
        part = connected.recv(size - len(result))
        require(part)
        result.extend(part)
    return bytes(result)


def _safe_result(value, operation):
    require(type(value) is dict and type(value.get("schema")) is int and value["schema"] == 1
            and value.get("operation") == operation and type(value.get("expires_at")) is int
            and value["expires_at"] > int(time.time()))
    if operation == "challenge":
        require(set(value) == {"schema", "operation", "nonce", "audience", "expires_at"}
                and type(value["nonce"]) is str and HEX.fullmatch(value["nonce"])
                and value["audience"] == AUDIENCE + value["nonce"]
                and value["expires_at"] <= int(time.time()) + 300)
    else:
        require(set(value) == {"schema", "operation", "lease_id", "expires_at"}
                and type(value["lease_id"]) is str and LEASE.fullmatch(value["lease_id"]))
    return dict(value)


def _exchange(selector, request):
    connected = parent = None
    sent = False
    try:
        require(sys.platform == "linux" and type(selector) is str and SELECTOR.fullmatch(selector))
        path, config_hash = _configuration()
        parent, leaf = _parent(path)
        before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISSOCK(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) in {0o600, 0o660, 0o666})
        frame = _frame({"schema": 1, "cell": selector}, 512) + _frame(request, 20480)
        connected = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connected.settimeout(SECONDS)
        connected.connect(path)
        pid, uid, _gid = struct.unpack("3i", connected.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(pid > 0 and uid == 0 and _stamp(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == _stamp(before)
                and _configuration() == (path, config_hash))
        deadline = time.monotonic() + SECONDS
        sent = True
        connected.sendall(frame)
        length = struct.unpack("!I", _exact(connected, 4, deadline))[0]
        require(0 < length <= 2048)
        reply = _object(_exact(connected, length, deadline))
        connected.settimeout(max(0.001, deadline - time.monotonic()))
        require(connected.recv(1) == b"" and _configuration() == (path, config_hash)
                and _stamp(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == _stamp(before))
        require(set(reply) == {"schema", "status", "result"} and type(reply["schema"]) is int
                and reply["schema"] == 1 and reply["status"] == "ok")
        return _safe_result(reply["result"], request["operation"])
    except Exception:
        if sent and request.get("operation") != "challenge":
            raise ClientUnknown("incus-client-outcome-unknown") from None
        raise ClientDenied("incus-client-denied") from None
    finally:
        if connected is not None:
            connected.close()
        if parent is not None:
            os.close(parent)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def _oidc(audience):
    require(os.environ.get("GITHUB_ACTIONS") == "true")
    bearer = _secret(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
    parsed = urllib.parse.urlsplit(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", ""))
    require(parsed.scheme == "https" and parsed.hostname and parsed.hostname.endswith(".actions.githubusercontent.com")
            and re.fullmatch(r"[A-Za-z0-9.-]+", parsed.hostname) and parsed.port in {None, 443}
            and not parsed.username and not parsed.password and not parsed.fragment)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    require(not any(key == "audience" for key, _ in query))
    url = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query + [("audience", audience)])))
    require(len(url) <= 16384)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + bearer,
                                                  "Accept": "application/json"}, method="GET")
    with opener.open(request, timeout=SECONDS) as response:
        require(response.status == 200 and response.geturl() == url)
        raw = response.read(65537)
        require(len(raw) <= 65536)
    value = _object(raw)
    require(set(value) == {"value"})
    return _secret(value["value"])


def authenticate(selector, operation, *, lease_id=None):
    """One fresh nonce/token and one explicit lease operation, with no retry.

    An unknown outcome requires an explicit later recover using a new nonce and
    token. This function never substitutes recover/admit or persists credentials.
    """
    try:
        require(operation in {"admit", "refresh", "recover"})
        require((operation == "refresh" and type(lease_id) is str and LEASE.fullmatch(lease_id))
                or (operation != "refresh" and lease_id is None))
        api_token = _secret(os.environ.get("GITHUB_TOKEN"))
        challenge = _exchange(selector, {"schema": 1, "operation": "challenge"})
        token = _oidc(challenge["audience"])
        require(challenge["expires_at"] > int(time.time()))
        request = {"schema": 1, "operation": operation, "nonce": challenge["nonce"],
                   "token": token, "api_token": api_token}
        if operation == "refresh":
            request["lease_id"] = lease_id
        result = _exchange(selector, request)
        if operation == "refresh" and result["lease_id"] != lease_id:
            raise ClientUnknown("incus-client-outcome-unknown")
        return result
    except ClientUnknown:
        raise
    except Exception:
        raise ClientDenied("incus-client-denied") from None
