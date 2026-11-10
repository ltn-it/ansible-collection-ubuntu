"""Synthetic offline legacy protocol tests; no credentials or root fixtures."""
import base64
import json
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import legacy_registration as legacy
from incus_lease_issuer.identity import Denied

TENANT = "https://pipelines.test.actions.githubusercontent.com/synthetic-tenant/"
SECRET = "synthetic-tenant-secret"
KEY = {"exponent": "AQAB", "modulus": base64.b64encode(b"\x80" + b"\x01" * 255).decode()}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def target():
    return SimpleNamespace(runner_id=78, name="incus-runner-01", group_id=6,
                           group_name="synthetic-maintenance", owner_login="synthetic-owner",
                           work_folder="/synthetic/work", labels=(("self-hosted", "system"), ("protected", "user")))


def auth(**overrides):
    return encoded({"url": TENANT, "token_schema": "OAuthAccessToken", "token": SECRET, **overrides})


def locations():
    return {"value": [
        {"id": legacy.AGENTS, "area": "distributedtask", "resourceName": "agents",
         "routeTemplate": "_apis/{area}/pools/{poolId}/{resource}/{agentId}",
         "resourceVersion": 2, "minVersion": "1.0", "maxVersion": "6.0", "releasedVersion": "5.1"},
        {"id": legacy.POOLS, "area": "distributedtask", "resourceName": "pools",
         "routeTemplate": "_apis/{area}/{resource}/{poolId}",
         "resourceVersion": 1, "minVersion": "1.0", "maxVersion": "6.0", "releasedVersion": "5.1"}]}


def agent(**overrides):
    return {"id": 78, "name": "incus-runner-01", "runnerGroupId": 6,
            "runnerGroupName": "synthetic-maintenance", "version": "2.338.2", "enabled": True,
            "status": "offline", "ephemeral": False, "disableUpdate": False, "maxParallelism": 1,
            "osDescription": "Synthetic Linux", "authorization": {"clientId": "old-synthetic-client"},
            "labels": [], "createdOn": "2026-01-01T00:00:00Z", **overrides}


def registration_response(**overrides):
    return encoded(agent(disableUpdate=True, authorization={
        "clientId": "1439e36e-994c-493c-8834-1e04ac799a21",
        "authorizationUrl": "https://vstoken.actions.githubusercontent.com/_apis/oauth2/token",
        "publicKey": KEY}, **overrides))


def prepare_transport(*, resource=None, pools=None, runner=None):
    responses = [encoded(locations() if resource is None else resource),
                 encoded({"value": [{"id": 6, "name": "synthetic-maintenance", "isHosted": False}]}
                         if pools is None else pools), encoded(agent() if runner is None else runner)]
    return mock.Mock(side_effect=responses)


class LegacyProtocolTests(unittest.TestCase):
    def test_missing_or_false_flow_and_secret_redaction_immutable(self):
        for raw in (auth(), auth(use_v2_flow=False)):
            result = legacy.session(raw)
            self.assertNotIn(SECRET, repr(result))
            with self.assertRaises(FrozenInstanceError):
                result.token = "changed"
        for raw in (auth(use_v2_flow=True), auth(use_v2_flow=0), auth(token_schema="Basic"),
                    auth(token="bad\r\nsecret"), auth(unexpected=True)):
            with self.assertRaises(Denied):
                legacy.session(raw)

    def test_auth_rejects_url_confusion_and_oversize(self):
        for url in ("https://evil.invalid/tenant/", "https://x.actions.githubusercontent.com:443/a/",
                    "https://x.actions.githubusercontent.com/a/../b/", TENANT + "?q=x",
                    "https://x.actions.githubusercontent.com//tenant/", TENANT + "%2f"):
            with self.assertRaises(Denied):
                legacy.session(auth(url=url))
        with self.assertRaises(Denied):
            legacy.session(b" " * 65537)
        with self.assertRaises(Denied):
            legacy.session(b'{"token":"x","token":"y"}')

    def test_prepare_only_reads_retains_tenant_path_and_freezes_full_body(self):
        send = prepare_transport()
        prepared = legacy.prepare(legacy.session(auth()), target(), KEY, transport=send)
        self.assertEqual([c.args[0] for c in send.call_args_list], ["OPTIONS", "GET", "GET"])
        self.assertEqual(send.call_args_list[0].args[1], TENANT + "_apis/")
        self.assertEqual(send.call_args_list[1].args[1], TENANT +
                         "_apis/distributedtask/pools?poolType=Automation&api-version=5.1-preview.1")
        self.assertEqual(send.call_args_list[2].args[1], TENANT +
                         "_apis/distributedtask/pools/6/agents/78?api-version=6.0-preview.2")
        body = json.loads(prepared.body)
        self.assertEqual(body["id"], 78)
        self.assertEqual(body["authorization"], {"publicKey": KEY})
        self.assertTrue(body["disableUpdate"])
        self.assertEqual(body["createdOn"], "2026-01-01T00:00:00Z")
        self.assertEqual(body["labels"][1], {"id": 0, "name": "protected", "type": "user"})
        self.assertNotIn(SECRET, repr(prepared))
        self.assertNotIn(KEY["modulus"], repr(prepared))
        with self.assertRaises(FrozenInstanceError):
            prepared.body = b"{}"

    def test_discovery_rejects_duplicate_guid_route_or_version_before_further_reads(self):
        variants = []
        value = locations()
        value["value"].append(dict(value["value"][0]))
        variants.append(value)
        for field, new in (("id", "wrong"), ("area", "other"), ("resourceName", "other"),
                           ("routeTemplate", "https://evil.invalid/{agentId}"),
                           ("maxVersion", "7.0"), ("resourceVersion", True)):
            value = locations()
            value["value"][0][field] = new
            variants.append(value)
        for value in variants:
            send = prepare_transport(resource=value)
            with self.subTest(value=value), self.assertRaises(Denied):
                legacy.prepare(legacy.session(auth()), target(), KEY, transport=send)
            self.assertEqual(send.call_count, 1)

    def test_unknown_group_metadata_dropped_and_declared_dto_fields_preserved(self):
        declared = {"provisioningState": "provisioned", "accessPoint": "synthetic-access",
                    "_links": {"self": {"href": "https://example.invalid/synthetic"}},
                    "statusChangedOn": "2026-01-01T00:00:00Z", "assignedRequest": None,
                    "lastCompletedRequest": {"requestId": 1},
                    "properties": {"SyntheticProperty": {"$type": "System.String", "$value": "retained"}}}
        extra = {"runnerGroupId": 6, "runnerGroupName": None, "currentParallelism": 0,
                 "owningTenant": "synthetic-untrusted", "isElastic": False, "isVirtual": False,
                 "lastConnectedOn": "2026-01-01T00:00:00Z", "queueName": "synthetic-queue",
                 "arbitraryFutureMetadata": {"mustNotRoundTrip": True}}
        fetched = agent(**declared, **extra)
        prepared = legacy.prepare(legacy.session(auth()), target(), KEY,
                                  transport=prepare_transport(runner=fetched))
        body = json.loads(prepared.body)
        self.assertEqual(set(body), legacy.TASK_AGENT_MEMBERS)
        for name, value in declared.items():
            self.assertEqual(body[name], value)
        for name in extra:
            self.assertNotIn(name, body)
        self.assertEqual(body["osDescription"], fetched["osDescription"])
        self.assertEqual(body["authorization"], {"publicKey": KEY})
        self.assertEqual(body["createdOn"], fetched["createdOn"])
        # Informational metadata cannot override the independently verified pool.
        changed = agent(runnerGroupId=999, runnerGroupName="untrusted-other")
        prepared = legacy.prepare(legacy.session(auth()), target(), KEY,
                                  transport=prepare_transport(runner=changed))
        self.assertEqual(prepared.url, TENANT + "_apis/distributedtask/pools/6/agents/78")
        self.assertNotIn("runnerGroupId", json.loads(prepared.body))
        result = legacy.response(registration_response(runnerGroupName=None), target(), TENANT, KEY)
        self.assertEqual(json.loads(result.settings)["poolName"], target().group_name)

    def test_prepare_rejects_wrong_pool_or_live_wrong_agent_without_put(self):
        for pool in ({"id": 6, "name": "wrong", "isHosted": False},
                     {"id": 6, "name": "synthetic-maintenance", "isHosted": True}):
            send = prepare_transport(pools={"value": [pool]})
            with self.assertRaises(Denied):
                legacy.prepare(legacy.session(auth()), target(), KEY, transport=send)
            self.assertEqual(send.call_count, 2)
        for change in ({"id": 79}, {"name": "wrong"}, {"status": "online"},
                       {"enabled": False}, {"ephemeral": True}, {"assignedRequest": {"id": 1}}):
            send = prepare_transport(runner=agent(**change))
            with self.assertRaises(Denied):
                legacy.prepare(legacy.session(auth()), target(), KEY, transport=send)
            self.assertEqual(send.call_count, 3)

    def test_replace_makes_exactly_one_put_and_holds_unknown(self):
        prepared = legacy.prepare(legacy.session(auth()), target(), KEY, transport=prepare_transport())
        send = mock.Mock(return_value=registration_response())
        self.assertEqual(legacy.replace(prepared, transport=send), registration_response())
        self.assertEqual(send.call_args.args, ("PUT", TENANT +
                         "_apis/distributedtask/pools/6/agents/78?api-version=6.0-preview.2",
                         SECRET, prepared.body, "6.0-preview.2"))
        self.assertEqual(send.call_count, 1)
        send = mock.Mock(side_effect=RuntimeError(SECRET))
        with self.assertRaisesRegex(Denied, "^legacy-replace-held$"):
            legacy.replace(prepared, transport=send)
        self.assertEqual(send.call_count, 1)

    def test_forged_prepared_origin_or_mismatched_id_never_put(self):
        prepared = legacy.prepare(legacy.session(auth()), target(), KEY, transport=prepare_transport())
        for changed in (replace(prepared, url="https://evil.invalid/agents/78"),
                        replace(prepared, body=encoded(agent(id=79))),
                        replace(prepared, body=encoded({**json.loads(prepared.body), "runnerGroupId": 6}))):
            send = mock.Mock()
            with self.assertRaises(Denied):
                legacy.replace(changed, transport=send)
            send.assert_not_called()

    def test_response_projects_stock_legacy_and_fips_default(self):
        projection = legacy.response(registration_response(), target(), TENANT, KEY)
        settings, credentials = json.loads(projection.settings), json.loads(projection.credentials)
        self.assertEqual(settings["serverUrl"], TENANT)
        self.assertEqual(settings["agentId"], 78)
        self.assertIs(settings["useV2Flow"], False)
        self.assertIs(settings["useRunnerAdminFlow"], False)
        self.assertEqual(credentials["data"]["requireFipsCryptography"], "True")
        self.assertNotIn("authorizationUrl", repr(projection))

    def test_response_typed_migration_and_server_overrides(self):
        properties = {"RequireFipsCryptography": {"$type": "System.Boolean", "$value": False},
                      "EnableAuthMigrationByDefault": {"$type": "System.Boolean", "$value": True},
                      "AuthorizationUrlV2": {"$type": "System.String", "$value":
                                             "https://vstoken.actions.githubusercontent.com/v2/token"},
                      "ServerUrlV2": {"$type": "System.String", "$value":
                                      "https://broker.actions.githubusercontent.com/"},
                      "UseV2Flow": {"$type": "System.Boolean", "$value": True}}
        projection = legacy.response(registration_response(properties=properties), target(), TENANT, KEY)
        self.assertTrue(json.loads(projection.settings)["useV2Flow"])
        data = json.loads(projection.credentials)["data"]
        self.assertEqual(data["requireFipsCryptography"], "False")
        self.assertEqual(data["enableAuthMigrationByDefault"], "true")

    def test_response_rejects_missing_authurl_wrong_key_flags_identity_and_properties(self):
        good = json.loads(registration_response())
        variants = [{**good, **change} for change in ({"id": 79}, {"disableUpdate": False},
                    {"ephemeral": True}, {"maxParallelism": True},
                    {"properties": {"UseV2Flow": "true"}},
                    {"properties": {"RequireFipsCryptography": {"$type": "System.String", "$value": True}}})]
        for change in ({"authorizationUrl": "https://evil.invalid/token"},
                       {"clientId": "00000000-0000-0000-0000-000000000000"},
                       {"publicKey": {**KEY, "exponent": "AAAB"}}):
            variants.append({**good, "authorization": {**good["authorization"], **change}})
        no_url = {**good, "authorization": dict(good["authorization"])}
        del no_url["authorization"]["authorizationUrl"]
        variants.append(no_url)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(Denied):
                legacy.response(encoded(value), target(), TENANT, KEY)

    def test_wire_direct_https_bearer_versioned_headers_no_redirect_retry(self):
        for status in (200, 301, 307, 429, 500):
            connection = mock.Mock()
            connection.getresponse.return_value.status = status
            connection.getresponse.return_value.read.return_value = b"{}"
            with mock.patch.object(legacy.http.client, "HTTPSConnection", return_value=connection) as constructor:
                if status == 200:
                    self.assertEqual(legacy.wire("PUT", TENANT + "_apis/test", SECRET, b"{}", "6.0-preview.2"), b"{}")
                else:
                    with self.assertRaisesRegex(Denied, "^legacy-http-unknown$"):
                        legacy.wire("PUT", TENANT + "_apis/test", SECRET, b"{}", "6.0-preview.2")
            self.assertEqual(constructor.call_args.args, ("pipelines.test.actions.githubusercontent.com", 443))
            self.assertEqual(connection.request.call_count, 1)
            self.assertEqual(connection.request.call_args.args, ("PUT", "/synthetic-tenant/_apis/test"))
            headers = connection.request.call_args.kwargs["headers"]
            self.assertEqual(headers["Authorization"], "Bearer " + SECRET)
            self.assertEqual(headers["Accept"], "application/json;api-version=6.0-preview.2")
            connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
