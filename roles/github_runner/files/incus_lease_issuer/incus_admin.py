"""Root-only fixed-route read-only Incus Unix transport.

No caller URL, HTTP method/body, network proxy, redirect, retry, credential
issuance or daemon mutation exists. Internal project/network/pool/certificate
metadata is for trusted Root policy comparisons only: never expose it to jobs
or dump it into logs/artifacts. server/inspect returns a narrow projection and
never returns the server configuration. Version/extension checks do not prove
patched package provenance, binary integrity, platform trust or lease safety.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import PurePosixPath
import re
import socket
import stat
import struct
import time
from types import MappingProxyType
from urllib.parse import urlencode

from . import installation
from .identity import Denied, decode_json, require

MAX_BODY = 2 * 1024 * 1024
MAX_HEADERS = 16384
REQUEST_SECONDS = 5
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\Z")
FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
OPERATION_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
OPERATION_STATUS = {100: "Operation created", 101: "Started", 102: "Stopped", 103: "Running",
                    104: "Cancelling", 105: "Pending", 106: "Starting", 107: "Stopping", 108: "Aborting",
                    109: "Freezing", 110: "Frozen", 111: "Thawed", 112: "Error", 113: "Ready",
                    200: "Success", 400: "Failure", 401: "Cancelled"}


@dataclass(frozen=True)
class AdminTarget:
    socket_path: str
    project: str
    network: str
    network_project: str
    pool: str
    certificate_fingerprints: tuple[str, ...] = ()
    instance: str | None = None


def _root():
    require(os.geteuid() == 0, "incus-admin-root-required")


def _socket_proof(parent_fd, name):
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) in {0o600, 0o660}, "incus-admin-socket")
    return installation._stamp(info)


class _Response:
    def __init__(self, connected, deadline):
        self.socket, self.deadline, self.buffer = connected, deadline, b""
        self.headers = None

    def _receive(self):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "incus-admin-timeout")
        self.socket.settimeout(remaining)
        data = self.socket.recv(4096)
        require(data, "incus-admin-truncated")
        self.buffer += data

    def line(self, limit):
        while b"\r\n" not in self.buffer:
            require(len(self.buffer) <= limit, "incus-admin-header-limit")
            self._receive()
        index = self.buffer.index(b"\r\n")
        require(index <= limit, "incus-admin-header-limit")
        result, self.buffer = self.buffer[:index], self.buffer[index + 2:]
        return result

    def exact(self, count):
        require(0 <= count <= MAX_BODY, "incus-admin-body-limit")
        while len(self.buffer) < count:
            self._receive()
        result, self.buffer = self.buffer[:count], self.buffer[count:]
        return result

    def read_envelope(self):
        """Decode bounded framing only; HTTP/envelope success is not implied.

        Root mutation transport needs the original status and asynchronous
        operation envelope. It must classify attempted effects separately;
        parsing a reply never establishes absence or completion of an effect.
        """
        status = self.line(1024)
        match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2}) [\x20-\x7e]*", status)
        require(match is not None, "incus-admin-http-status")
        http_status = int(match[1])
        headers, total = {}, len(status) + 2
        for _ in range(33):
            line = self.line(4096)
            total += len(line) + 2
            require(total <= MAX_HEADERS, "incus-admin-header-limit")
            if not line:
                break
            require(len(headers) < 32 and re.fullmatch(rb"[A-Za-z0-9!#$%&'*+.^_`|~-]+:[\x20-\x7e]*", line),
                    "incus-admin-headers")
            name, value = line.split(b":", 1)
            name, value = name.lower(), value.strip()
            require(name not in headers, "incus-admin-headers")
            headers[name] = value
        else:
            raise Denied("incus-admin-header-limit")
        require(headers.get(b"content-type", b"").split(b";", 1)[0].lower() == b"application/json",
                "incus-admin-content-type")
        require(not (b"content-length" in headers and b"transfer-encoding" in headers), "incus-admin-framing")
        if b"content-length" in headers:
            value = headers[b"content-length"]
            require(re.fullmatch(rb"[0-9]{1,10}", value), "incus-admin-framing")
            raw = self.exact(int(value))
        else:
            require(headers.get(b"transfer-encoding") == b"chunked", "incus-admin-framing")
            chunks, size = [], 0
            while True:
                value = self.line(16)
                require(re.fullmatch(rb"[0-9a-fA-F]{1,16}", value), "incus-admin-framing")
                count = int(value, 16)
                if count == 0:
                    require(self.line(4096) == b"", "incus-admin-trailers")
                    break
                size += count
                require(size <= MAX_BODY, "incus-admin-body-limit")
                chunks.append(self.exact(count))
                require(self.exact(2) == b"\r\n", "incus-admin-framing")
            raw = b"".join(chunks)
        require(not self.buffer, "incus-admin-trailing-data")
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "incus-admin-timeout")
        self.socket.settimeout(remaining)
        require(self.socket.recv(1) == b"", "incus-admin-trailing-data")
        result = decode_json(raw)
        # Publish headers only after complete bounded framing and JSON decode.
        # Internal mutators may preserve the daemon's actual ETag for If-Match;
        # neither a header nor a parsed envelope establishes effect success.
        self.headers = MappingProxyType(dict(headers))
        return http_status, result

    def read(self):
        http_status, result = self.read_envelope()
        require(http_status == 200, "incus-admin-http-status")
        require(result.get("type") == "sync" and type(result.get("status_code")) is int
                and result["status_code"] == 200 and result.get("status") == "Success"
                and type(result.get("error_code", 0)) is int and result.get("error_code", 0) == 0
                and result.get("error", "") == ""
                and result.get("operation", "") == "" and "metadata" in result, "incus-admin-envelope")
        return result["metadata"]


class RootIncusAdmin:
    """Factory-selected Root targets; no per-request transport overrides."""
    def __init__(self, target):
        _root()
        try:
            require(type(target) is AdminTarget, "incus-admin-target")
            parts = installation._absolute(target.socket_path)
            require(parts and len(target.socket_path.encode()) < 108, "incus-admin-target")
            require(all(type(v) is str and NAME.fullmatch(v) for v in
                        (target.project, target.network, target.network_project, target.pool))
                    and target.network_project in {target.project, "default"}, "incus-admin-target")
            require(type(target.certificate_fingerprints) is tuple and len(target.certificate_fingerprints) <= 256
                    and len(set(target.certificate_fingerprints)) == len(target.certificate_fingerprints)
                    and all(type(v) is str and FINGERPRINT.fullmatch(v)
                            for v in target.certificate_fingerprints), "incus-admin-target")
            require(target.instance is None or (type(target.instance) is str and NAME.fullmatch(target.instance)),
                    "incus-admin-target")
            self._target = target
            self._parent = str(PurePosixPath(target.socket_path).parent)
            self._leaf = parts[-1]
            parent = installation._open_directory(self._parent)
            try:
                info = os.fstat(parent)
                self._parent_id = info.st_dev, info.st_ino
                self._proof = _socket_proof(parent, self._leaf)
            finally:
                os.close(parent)
        except Exception:
            raise Denied("incus-admin-target-denied") from None

    def _stable(self, fd):
        require(_socket_proof(fd, self._leaf) == self._proof, "incus-admin-socket-drift")
        current = installation._open_directory(self._parent)
        try:
            info = os.fstat(current)
            require((info.st_dev, info.st_ino) == self._parent_id
                    and _socket_proof(current, self._leaf) == self._proof, "incus-admin-socket-drift")
        finally:
            os.close(current)

    def _get(self, route, expected=dict):
        _root()
        parent = connected = None
        try:
            target = self._target
            routes = {"server": "/1.0", "resources": "/1.0/resources",
                      "project": "/1.0/projects/" + target.project,
                      "project-state": "/1.0/projects/" + target.project + "/state",
                      "instances": "/1.0/instances?" + urlencode({"project": target.project}),
                      "operations": "/1.0/operations?" + urlencode({"project": target.project, "recursion": 1}),
                      "network": "/1.0/networks/" + target.network + "?" + urlencode({"project": target.network_project}),
                      "pool": "/1.0/storage-pools/" + target.pool,
                      "pool-resources": "/1.0/storage-pools/" + target.pool + "/resources",
                      "pool-volumes": "/1.0/storage-pools/" + target.pool + "/volumes?recursion=1&all-projects=true",
                      "certificates": "/1.0/certificates?recursion=1"}
            routes.update({"certificate-" + fp: "/1.0/certificates/" + fp for fp in target.certificate_fingerprints})
            if target.instance is not None:
                selected = "/1.0/instances/" + target.instance
                routes["instance"] = selected + "?" + urlencode({"project": target.project})
                routes["instance-state"] = selected + "/state?" + urlencode({"project": target.project})
            require(route in routes, "incus-admin-route")
            deadline = time.monotonic() + REQUEST_SECONDS
            parent = installation._open_directory(self._parent)
            self._stable(parent)
            connected = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connected.settimeout(REQUEST_SECONDS)
            connected.connect(target.socket_path)
            pid, uid, _gid = struct.unpack("3i", connected.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(pid > 0 and uid == 0, "incus-admin-peer")
            self._stable(parent)
            remaining = deadline - time.monotonic()
            require(remaining > 0, "incus-admin-timeout")
            connected.settimeout(remaining)
            connected.sendall(("GET " + routes[route] + " HTTP/1.1\r\nHost: localhost\r\n"
                               "Accept: application/json\r\nConnection: close\r\n\r\n").encode("ascii"))
            metadata = _Response(connected, deadline).read()
            self._stable(parent)
            require(type(metadata) is expected, "incus-admin-metadata")
            return metadata
        except Denied:
            raise
        except Exception:
            raise Denied("incus-admin-read-denied") from None
        finally:
            if connected is not None:
                connected.close()
            if parent is not None:
                os.close(parent)

    def server(self):
        data = self._get("server")
        environment, extensions = data.get("environment"), data.get("api_extensions")
        require(type(environment) is dict and type(extensions) is list and len(extensions) <= 2048
                and all(type(v) is str and 0 < len(v) <= 128 for v in extensions)
                and len(set(extensions)) == len(extensions), "incus-admin-server-schema")
        result = {"server": environment.get("server"), "server_version": environment.get("server_version"),
                  "auth": data.get("auth"), "api_extensions": extensions}
        require(all(type(result[k]) is str and 0 < len(result[k]) <= 128
                    for k in ("server", "server_version", "auth")), "incus-admin-server-schema")
        return result

    def inspect(self):
        return self.server()

    def resources(self):
        return self._get("resources")

    def project(self):
        return self._get("project")

    def project_state(self):
        return self._get("project-state")

    def instances(self):
        """Complete fixed-project URL inventory; no instance mutation route."""
        rows = self._get("instances", list)
        require(len(rows) <= 4096 and all(type(row) is str and 0 < len(row) <= 4096 for row in rows)
                and len(set(rows)) == len(rows), "incus-admin-instances")
        return rows

    def instance(self):
        """Only the Root factory-selected instance; no caller locator."""
        return self._get("instance")

    def instance_state(self):
        return self._get("instance-state")

    def operations(self):
        """All status groups, including terminal/global operations returned by 7.6.

        The project filter is not a proof that every returned operation belongs
        exclusively to the lease. Finalization requires the whole map empty;
        no pending/running filter or unknown/foreign-operation exception exists.
        """
        groups = self._get("operations")
        require(len(groups) <= len(OPERATION_STATUS), "incus-admin-operations")
        seen = set()
        for name, rows in groups.items():
            require(type(name) is str and name in {value.lower() for value in OPERATION_STATUS.values()}
                    and type(rows) is list, "incus-admin-operations")
            for row in rows:
                require(type(row) is dict and type(row.get("id")) is str and OPERATION_ID.fullmatch(row["id"])
                        and row["id"] not in seen and type(row.get("status_code")) is int
                        and row["status_code"] in OPERATION_STATUS
                        and OPERATION_STATUS[row["status_code"]].lower() == name
                        and row.get("status") == OPERATION_STATUS[row["status_code"]]
                        and type(row.get("class")) is str and row["class"] in {"task", "websocket", "token"},
                        "incus-admin-operations")
                seen.add(row["id"])
                require(len(seen) <= 4096, "incus-admin-operations")
        return groups

    def network(self):
        return self._get("network")

    def pool(self):
        """Exact Root-selected pool descriptor; no per-call name override."""
        return self._get("pool")

    def pool_resources(self):
        return self._get("pool-resources")

    def pool_volumes(self):
        """Complete fixed-pool inventory; no job-supplied project filter."""
        values = self._get("pool-volumes", list)
        require(len(values) <= 4096 and all(type(value) is dict for value in values), "incus-admin-pool-volumes")
        return values

    def certificates(self):
        return self._get("certificates", list)

    def certificate(self, fingerprint):
        _root()
        require(type(fingerprint) is str and fingerprint in self._target.certificate_fingerprints,
                "incus-admin-certificate-target")
        return self._get("certificate-" + fingerprint)


def qualify_backend(observed, *, expected_version, expected_extensions):
    """Root policy comparison only; no patched-binary or operating proof."""
    _root()
    require(type(expected_version) is str and re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", expected_version)
            and type(expected_extensions) is frozenset and expected_extensions
            and all(type(v) is str and 0 < len(v) <= 128 for v in expected_extensions), "incus-admin-version-policy")
    require(type(observed) is dict and set(observed) == {"server", "server_version", "auth", "api_extensions"}
            and observed["server"] == "incus" and observed["server_version"] == expected_version
            and observed["auth"] == "trusted" and type(observed["api_extensions"]) is list
            and all(type(v) is str for v in observed["api_extensions"])
            and expected_extensions <= set(observed["api_extensions"]), "incus-admin-backend-denied")
    return {"server_version": expected_version, "required_extensions": sorted(expected_extensions)}
