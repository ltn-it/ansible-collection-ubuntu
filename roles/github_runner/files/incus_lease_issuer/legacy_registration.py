"""Bounded stock runner2.338.2 legacy protocol; caller owns fences and journal.

No token minting, key generation, persistence, retries or implicit registration.
The transport injection is exclusively a narrow offline test boundary.
"""
from __future__ import annotations

import base64
import http.client
import json
import re
import ssl
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .identity import Denied, decode_json, require

MAX_BYTES = 65536
VERSION = "2.338.2"
AGENTS = "e298ef32-5878-4cab-993c-043836571f42"
POOLS = "a8c47e17-4d56-4a56-92bb-de7ea7dc65be"
# Pinned TaskAgent + TaskAgentReference DataMembers. Stock JSON.NET discards
# unknown response fields; they are neither group authority nor PUT members.
TASK_AGENT_MEMBERS = frozenset({
    "id", "name", "version", "osDescription", "enabled", "ephemeral", "disableUpdate",
    "status", "provisioningState", "accessPoint", "_links", "maxParallelism", "createdOn",
    "statusChangedOn", "assignedRequest", "lastCompletedRequest", "authorization", "properties", "labels",
})


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _object(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "legacy-response-size")
    return decode_json(raw)


def _url(value):
    require(type(value) is str and 0 < len(value) <= 4096
            and re.fullmatch(r"https://[a-z0-9.-]+/[A-Za-z0-9/_-]*", value), "legacy-url")
    parsed = urlsplit(value)
    require(parsed.hostname.endswith(".actions.githubusercontent.com")
            and not any(part in (".", "..") for part in parsed.path.split("/"))
            and "//" not in parsed.path, "legacy-url")
    return parsed


@dataclass(frozen=True)
class LegacySession:
    tenant_url: str
    token: str = field(repr=False)


@dataclass(frozen=True)
class LegacyPrepared:
    tenant_url: str
    url: str
    token: str = field(repr=False)
    body: bytes = field(repr=False)


@dataclass(frozen=True)
class LegacyProjection:
    settings: bytes = field(repr=False)
    credentials: bytes = field(repr=False)


def session(raw):
    data = _object(raw)
    require({"url", "token_schema", "token"} <= set(data)
            and set(data) <= {"url", "token_schema", "token", "use_v2_flow"}
            and data.get("use_v2_flow", False) is False
            and data["token_schema"] == "OAuthAccessToken", "legacy-auth-flow")
    _url(data["url"])
    require(type(data["token"]) is str and 0 < len(data["token"]) <= 16384
            and all(33 <= ord(c) <= 126 for c in data["token"]), "legacy-auth-token")
    return LegacySession(data["url"], data["token"])


def _key(value):
    require(type(value) is dict and set(value) == {"exponent", "modulus"}, "legacy-public-key")
    for name, size in (("exponent", 3), ("modulus", 256)):
        encoded = value[name]
        require(type(encoded) is str and len(encoded) <= 344, "legacy-public-key")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            raise Denied("legacy-public-key") from None
        require(len(raw) == size and base64.b64encode(raw).decode() == encoded, "legacy-public-key")
        require(raw == b"\x01\x00\x01" if name == "exponent" else raw[0] >= 128, "legacy-public-key")
    return dict(value)


def _endpoint(tenant, suffix):
    _url(tenant)
    return tenant.rstrip("/") + "/" + suffix


def wire(method, url, token, body, version):
    """One direct HTTPS operation; callers must bind the URL to their session."""
    parsed = _url(url.split("?", 1)[0])
    require(method in ("OPTIONS", "GET", "PUT")
            and type(token) is str and 0 < len(token) <= 16384
            and all(33 <= ord(c) <= 126 for c in token), "legacy-http-input")
    require(version in (None, "5.1-preview.1", "6.0-preview.2"), "legacy-http-version")
    require(body is None if method != "PUT" else type(body) is bytes and 0 < len(body) <= MAX_BYTES,
            "legacy-http-body")
    connection = None
    try:
        connection = http.client.HTTPSConnection(parsed.hostname, 443, timeout=20,
                                               context=ssl.create_default_context())
        accept = "application/json" + (";api-version=" + version if version else "")
        headers = {"Authorization": "Bearer " + token, "Accept": accept,
                   "User-Agent": "GitHubActionsRunner/2.338.2"}
        if body is not None:
            headers["Content-Type"] = accept
        request_path = urlsplit(url).path
        if urlsplit(url).query:
            request_path += "?" + urlsplit(url).query
        connection.request(method, request_path, body=body, headers=headers)
        result = connection.getresponse()
        raw = result.read(MAX_BYTES + 1)
        require(result.status == 200 and 0 < len(raw) <= MAX_BYTES, "legacy-http-response")
        return raw
    except Exception:  # noqa: BLE001 -- transport exceptions may contain credentials.
        raise Denied("legacy-http-unknown") from None
    finally:
        if connection is not None:
            connection.close()


def _call(transport, method, url, token, body=None, version=None):
    try:
        return _object(transport(method, url, token, body, version))
    except Exception:  # noqa: BLE001 -- injected transports must not disclose secrets.
        raise Denied("legacy-request-held") from None


def _locations(data):
    values = data.get("value")
    require(type(values) is list and len(values) <= 1024, "legacy-resource-locations")
    for identifier, resource, template, revision in (
            (AGENTS, "agents", "_apis/{area}/pools/{poolId}/{resource}/{agentId}", 2),
            (POOLS, "pools", "_apis/{area}/{resource}/{poolId}", 1)):
        matches = [x for x in values if type(x) is dict and x.get("id") == identifier]
        require(len(matches) == 1, "legacy-resource-identity")
        item = matches[0]
        require(item.get("area") == "distributedtask" and item.get("resourceName") == resource
                and item.get("routeTemplate") == template
                and type(item.get("resourceVersion")) is int and item["resourceVersion"] == revision
                and item.get("minVersion") == "1.0" and item.get("maxVersion") == "6.0"
                and item.get("releasedVersion") == "5.1", "legacy-resource-contract")


def _identity(data, target):
    require(type(data.get("id")) is int and data["id"] == target.runner_id
            and data.get("name") == target.name, "legacy-agent-identity")


def prepare(auth, target, public_key, *, transport=None):
    require(type(auth) is LegacySession, "legacy-session")
    # Revalidate even manually constructed immutable sessions.
    session(_json({"url": auth.tenant_url, "token_schema": "OAuthAccessToken", "token": auth.token}))
    key = _key(public_key)
    require(type(target.group_id) is int and 0 < target.group_id < 2 ** 31
            and type(target.runner_id) is int and 0 < target.runner_id < 2 ** 63, "legacy-target")
    send = wire if transport is None else transport
    _locations(_call(send, "OPTIONS", _endpoint(auth.tenant_url, "_apis/"), auth.token))
    pools = _call(send, "GET", _endpoint(auth.tenant_url,
                  "_apis/distributedtask/pools?poolType=Automation&api-version=5.1-preview.1"),
                  auth.token, version="5.1-preview.1").get("value")
    require(type(pools) is list, "legacy-pools")
    matches = [p for p in pools if type(p) is dict and type(p.get("id")) is int
               and p["id"] == target.group_id]
    require(len(matches) == 1 and matches[0].get("name") == target.group_name
            and matches[0].get("isHosted") is False, "legacy-pool-identity")
    url = _endpoint(auth.tenant_url, "_apis/distributedtask/pools/" + str(target.group_id)
                    + "/agents/" + str(target.runner_id))
    agent = _call(send, "GET", url + "?api-version=6.0-preview.2", auth.token, version="6.0-preview.2")
    _identity(agent, target)
    require(agent.get("status") == "offline" and agent.get("enabled") is True
            and agent.get("version") == VERSION and agent.get("ephemeral") is False
            and not agent.get("assignedRequest"), "legacy-agent-precondition")
    # Group identity is established by the verified pool list and exact route,
    # alongside the caller's independent native fence, never informational extras.
    agent = {name: value for name, value in agent.items() if name in TASK_AGENT_MEMBERS}
    agent.update(authorization={"publicKey": key}, version=VERSION, ephemeral=False,
                 disableUpdate=True, maxParallelism=1,
                 labels=[{"id": 0, "name": name, "type": kind} for name, kind in target.labels])
    return LegacyPrepared(auth.tenant_url, url, auth.token, _json(agent))


def replace(prepared, *, transport=None):
    require(type(prepared) is LegacyPrepared, "legacy-prepared")
    parsed = _url(prepared.tenant_url)
    expected = prepared.tenant_url.rstrip("/") + "/_apis/distributedtask/pools/"
    require(prepared.url.startswith(expected)
            and re.fullmatch(r"[1-9][0-9]*/agents/[1-9][0-9]*", prepared.url[len(expected):])
            and urlsplit(prepared.url).netloc == parsed.netloc, "legacy-replace-url")
    agent = _object(prepared.body)
    route_agent = prepared.url[len(expected):].split("/agents/")[1]
    require(set(agent) <= TASK_AGENT_MEMBERS
            and type(agent.get("id")) is int and agent["id"] == int(route_agent)
            and type(agent.get("name")) is str and bool(agent["name"])
            and agent.get("version") == VERSION and agent.get("disableUpdate") is True
            and agent.get("ephemeral") is False and type(agent.get("maxParallelism")) is int
            and agent["maxParallelism"] == 1, "legacy-prepared-body")
    authorization = agent.get("authorization")
    require(type(authorization) is dict and set(authorization) == {"publicKey"}, "legacy-prepared-auth")
    _key(authorization["publicKey"])
    # The caller journals intent before this sole request and never retries it.
    send = wire if transport is None else transport
    try:
        raw = send("PUT", prepared.url + "?api-version=6.0-preview.2", prepared.token,
                   prepared.body, "6.0-preview.2")
        _object(raw)
        return raw
    except Exception:  # noqa: BLE001 -- uncertain mutation must redact all wire errors.
        raise Denied("legacy-replace-held") from None


def _property(properties, name, kind, default):
    value = properties.get(name, default)
    if type(value) is dict:
        require(set(value) == {"$type", "$value"}
                and value["$type"] == ("System.Boolean" if kind is bool else "System.String"),
                "legacy-property-type")
        value = value["$value"]
    require(type(value) is kind, "legacy-property-type")
    return value


def response(raw, target, tenant_url, public_key):
    _url(tenant_url)
    key = _key(public_key)
    data = _object(raw)
    _identity(data, target)
    require(data.get("disableUpdate") is True and data.get("ephemeral") is False
            and data.get("version") == VERSION and type(data.get("maxParallelism")) is int
            and data["maxParallelism"] == 1, "legacy-response-flags")
    auth = data.get("authorization")
    require(type(auth) is dict and type(auth.get("clientId")) is str, "legacy-response-auth")
    try:
        client = uuid.UUID(auth["clientId"])
        require(client.int != 0 and str(client) == auth["clientId"], "legacy-response-client")
    except (ValueError, AttributeError):
        raise Denied("legacy-response-client") from None
    _url(auth.get("authorizationUrl"))
    if "publicKey" in auth:
        require(_key(auth["publicKey"]) == key, "legacy-response-key")
    properties = data.get("properties", {})
    require(type(properties) is dict, "legacy-response-properties")
    credentials = {"scheme": "OAuth", "data": {
        "clientId": auth["clientId"], "authorizationUrl": auth["authorizationUrl"],
        "requireFipsCryptography": str(_property(properties, "RequireFipsCryptography", bool, True))}}
    if _property(properties, "EnableAuthMigrationByDefault", bool, False):
        v2auth = _property(properties, "AuthorizationUrlV2", str, "")
        require(bool(v2auth), "legacy-response-migration")
        _url(v2auth)
        credentials["data"].update(enableAuthMigrationByDefault="true", authorizationUrlV2=v2auth)
    settings = {"agentId": target.runner_id, "agentName": target.name, "poolId": target.group_id,
                "poolName": target.group_name, "serverUrl": tenant_url,
                "gitHubUrl": "https://github.com/" + target.owner_login,
                "workFolder": target.work_folder, "disableUpdate": True,
                "useV2Flow": False, "useRunnerAdminFlow": False}
    v2server = _property(properties, "ServerUrlV2", str, "")
    if v2server:
        _url(v2server)
    if _property(properties, "UseV2Flow", bool, False):
        require(bool(v2server), "legacy-response-v2-server")
        settings["useV2Flow"] = True
        settings["serverUrlV2"] = v2server
    return LegacyProjection(_json(settings), _json(credentials))
