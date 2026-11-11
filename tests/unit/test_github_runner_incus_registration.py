"""Offline registration component contracts, not native target/fence acceptance.

Root fixtures require a private /run/proof tmpfs inside the official EE. Do not
run root cases on host. All tokens, keys, API responses and target fences below
are synthetic; the production filesystem root checks are never bypassed.
"""
import base64
from dataclasses import FrozenInstanceError, replace
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import registration as reg  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def auth_response(**overrides):
    return encoded({"url": "https://pipelines.test.actions.githubusercontent.com/tenant/",
                    "token_schema": "OAuthAccessToken", "token": "synthetic-tenant-secret",
                    "use_v2_flow": True, **overrides})


def replace_response(**overrides):
    return encoded({"id": 78, "name": "incus-runner-01", "authorization": {
        "authorization_url": "https://vstoken.actions.githubusercontent.com/_apis/oauth2/token",
        "server_url": "https://broker.actions.githubusercontent.com/",
        "client_id": "1439e36e-994c-493c-8834-1e04ac799a21"}, **overrides})


class PureCodecAndWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def test_stock_private_parameter_names_widths_and_public_xml_match(self):
        raw = reg.private_key_json(self.key)
        data = json.loads(raw)
        self.assertEqual(set(data), {"d", "dp", "dq", "exponent", "inverseQ", "modulus", "p", "q"})
        for name, width in reg.KEY_SIZES.items():
            self.assertEqual(len(base64.b64decode(data[name], validate=True)), width)
        self.assertEqual(data["exponent"], "AQAB")
        restored = reg.private_key_from_json(raw)
        self.assertEqual(restored.private_numbers(), self.key.private_numbers())
        xml = ET.fromstring(reg.public_key_xml(restored))
        self.assertEqual(xml.tag, "RSAKeyValue")
        self.assertEqual([node.tag for node in xml], ["Modulus", "Exponent"])
        self.assertEqual(xml.findtext("Modulus"), data["modulus"])
        self.assertEqual(xml.findtext("Exponent"), data["exponent"])
        public = rsa.RSAPublicNumbers(int.from_bytes(base64.b64decode(xml.findtext("Exponent")), "big"),
                                     int.from_bytes(base64.b64decode(xml.findtext("Modulus")), "big")).public_key()
        signature = restored.sign(b"offline codec consistency", padding.PKCS1v15(), hashes.SHA256())
        public.verify(signature, b"offline codec consistency", padding.PKCS1v15(), hashes.SHA256())

    def test_codec_rejects_wrong_case_duplicate_nonfinite_or_inconsistent_key(self):
        data = json.loads(reg.private_key_json(self.key))
        variants = [encoded({**data, "D": data["d"]}), b'{"d":"x","d":"y"}',
                    b'{"d":NaN}', b'{"d":1e999}', encoded({**data, "dp": base64.b64encode(b"\x00" * 128).decode()})]
        for raw in variants:
            with self.subTest(kind=len(raw)):
                with self.assertRaises(Denied):
                    reg.private_key_from_json(raw)

    def test_wire_fixed_origin_direct_https_and_remoteauth(self):
        connection = mock.Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = auth_response()
        with mock.patch.object(reg.http.client, "HTTPSConnection", return_value=connection) as ctor, \
             mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://example.invalid:9999", "HTTP_PROXY": "http://example.invalid:9999"}):
            self.assertEqual(reg._wire(reg.AUTH_URL, "synthetic-token", b"{}"), auth_response())
        self.assertEqual(ctor.call_args.args, ("api.github.com", 443))
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ("POST", "/actions/runner-registration"))
        self.assertEqual(kwargs["headers"]["Authorization"], "RemoteAuth synthetic-token")
        self.assertEqual(connection.request.call_count, 1)
        connection.close.assert_called_once()

    def test_wire_does_not_follow_redirect_retry_or_accept_other_origin(self):
        for status in (301, 302, 307, 429, 500):
            with self.subTest(status=status):
                connection = mock.Mock()
                connection.getresponse.return_value.status = status
                connection.getresponse.return_value.read.return_value = b"synthetic-secret-response"
                with mock.patch.object(reg.http.client, "HTTPSConnection", return_value=connection):
                    with self.assertRaises(Denied) as caught:
                        reg._wire(reg.REPLACE_URL, "synthetic-token", b"{}")
                self.assertNotIn("synthetic", str(caught.exception))
                self.assertEqual(connection.request.call_count, 1)
        with mock.patch.object(reg.http.client, "HTTPSConnection") as ctor:
            with self.assertRaises(Denied):
                reg._wire("https://example.invalid/actions/runners/register", "synthetic-token", b"{}")
            ctor.assert_not_called()

    def test_wire_lost_reply_has_one_attempt_and_safe_error(self):
        connection = mock.Mock()
        connection.getresponse.side_effect = OSError("synthetic-token in raw socket error")
        with mock.patch.object(reg.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaises(Denied) as caught:
                reg._wire(reg.REPLACE_URL, "synthetic-token", b"{}")
        self.assertEqual(connection.request.call_count, 1)
        self.assertNotIn("synthetic", str(caught.exception))

    def test_nonroot_entrypoints_deny_before_transport_or_state(self):
        if os.geteuid() == 0:
            self.skipTest("actual root guard runs in nonroot EE")
        with self.assertRaisesRegex(Denied, "registration-root-required"):
            reg.initialize("/untrusted", {})
        with self.assertRaisesRegex(Denied, "registration-root-required"):
            reg.read_completed("/untrusted", {})
        with self.assertRaisesRegex(Denied, "registration-root-required"):
            reg.replace_registration("/untrusted", {}, "synthetic-token", _transport=lambda *a: self.fail("wire"))


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux UID0 EE only")
class RootRegistrationTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires namespace-private root-owned0700 /run/proof")
        self.temp = tempfile.TemporaryDirectory(prefix="registration-", dir=base)
        self.stage = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.target = reg.VerifiedTarget(54334171, "example", 78, "incus-runner-01", 7, "Protected", "arm64",
                                        (("self-hosted", "system"), ("Linux", "system"), ("ARM64", "system"),
                                         ("incus", "user")), "/var/lib/example-runner/work", "a" * 64,
                                        int(time.time()) + 120, _authority=reg._FENCE_AUTHORITY)
        self.calls = []
        reg.initialize(str(self.stage), self.target)

    def transport(self, url, token, body):
        self.calls.append((url, token, json.loads(body)))
        state = json.loads((self.stage / reg.STATE_FILE).read_bytes())["payload"]
        expected = "auth-intent" if url == reg.AUTH_URL else "replace-intent"
        self.assertEqual(state["phase"], expected)
        self.assertEqual(stat.S_IMODE((self.stage / reg.KEY_FILE).stat().st_mode), 0o600)
        self.assertTrue((self.stage / reg.KEY_FILE).read_bytes())
        return auth_response() if url == reg.AUTH_URL else replace_response()

    def apply(self, transport=None, target=None, token="synthetic-token"):
        return reg.replace_registration(str(self.stage), target or self.target, token,
                                        _transport=transport or self.transport)

    def test_no_public_json_or_unissued_target_can_claim_a_native_fence(self):
        with self.assertRaisesRegex(Denied, "registration-native-fence-required"):
            reg.VerifiedTarget(54334171, "example", 78, "incus-runner-01", 7, "Protected", "arm64",
                               (("incus", "user"),), "/var/lib/example/work", "a" * 64, int(time.time()) + 60)
        with self.assertRaises(Denied):
            self.apply(target={"runner_id": 78})
        with self.assertRaises(FrozenInstanceError):
            self.target.runner_id = 79

    def test_completed_material_is_root_memory_only_and_read_does_not_rotate(self):
        with self.assertRaisesRegex(Denied, "registration-not-complete"):
            reg.read_completed(str(self.stage), self.target)
        self.assertEqual(self.calls, [])
        self.apply()
        material = reg.read_completed(str(self.stage), self.target)
        self.assertEqual(material.runner_id, 78)
        self.assertEqual(material.settings, (self.stage/".runner").read_bytes())
        self.assertEqual(material.credentials, (self.stage/".credentials").read_bytes())
        self.assertEqual(material.private_key, (self.stage/reg.KEY_FILE).read_bytes())
        self.assertNotIn("modulus", repr(material))
        self.assertNotIn("authorizationUrl", repr(material))
        self.assertEqual(len(self.calls), 2)
        (self.stage/".credentials").write_bytes(b"changed")
        with self.assertRaisesRegex(Denied, "registration-complete-drift"):
            reg.read_completed(str(self.stage), self.target)
        self.assertEqual(len(self.calls), 2)

    def test_exact_existing_id_replace_body_and_stock_settings(self):
        result = self.apply()
        self.assertEqual([x[0] for x in self.calls], [reg.AUTH_URL, reg.REPLACE_URL])
        self.assertEqual(self.calls[0][2], {"url": "https://github.com/example", "runner_event": "register"})
        body = self.calls[1][2]
        self.assertEqual(set(body), {"url", "group_id", "name", "version", "updates_disabled", "ephemeral",
                                     "labels", "public_key", "runner_id", "replace"})
        self.assertEqual((body["runner_id"], body["name"], body["group_id"], body["version"]),
                         (78, "incus-runner-01", 7, "2.338.2"))
        self.assertIs(body["replace"], True)
        self.assertIs(body["updates_disabled"], True)
        self.assertIs(body["ephemeral"], False)
        self.assertEqual(body["labels"][0], {"id": 0, "name": "self-hosted", "type": "system"})
        self.assertEqual(body["public_key"], reg.public_key_xml(reg.private_key_from_json((self.stage / reg.KEY_FILE).read_bytes())))
        settings = json.loads(Path(result.settings_path).read_bytes())
        self.assertEqual(settings["agentId"], 78)
        self.assertIs(settings["disableUpdate"], True)
        self.assertIs(settings["useRunnerAdminFlow"], True)
        self.assertIs(settings["useV2Flow"], True)
        credentials = json.loads(Path(result.credentials_path).read_bytes())
        self.assertEqual(credentials["scheme"], "OAuth")
        self.assertEqual(credentials["data"]["requireFipsCryptography"], "True")
        self.assertTrue(result.updates_disabled_requested)
        self.assertNotIn("server_echo", repr(result))

    def test_complete_reentry_is_read_only_and_retains_same_key(self):
        first = self.apply()
        key = (self.stage / reg.KEY_FILE).read_bytes()
        second = self.apply(transport=lambda *args: self.fail("wire replay"))
        self.assertEqual(first, second)
        self.assertEqual((self.stage / reg.KEY_FILE).read_bytes(), key)

    def test_existing_initialize_or_missing_state_never_regenerates_key(self):
        key = (self.stage / reg.KEY_FILE).read_bytes()
        with self.assertRaisesRegex(Denied, "registration-initialize-not-empty"):
            reg.initialize(str(self.stage), self.target)
        (self.stage / reg.STATE_FILE).unlink()
        with self.assertRaises(Denied):
            self.apply()
        with self.assertRaises(Denied):
            reg.initialize(str(self.stage), self.target)
        self.assertEqual((self.stage / reg.KEY_FILE).read_bytes(), key)
        self.assertEqual(self.calls, [])

    def test_missing_corrupt_or_hardlinked_key_denies_before_wire(self):
        key = self.stage / reg.KEY_FILE
        original = key.read_bytes()
        key.write_bytes(b"corrupt")
        with self.assertRaises(Denied):
            self.apply()
        key.write_bytes(original)
        other = self.stage / "borrowed-key"
        os.link(key, other)
        with self.assertRaises(Denied):
            self.apply()
        other.unlink()
        key.unlink()
        with self.assertRaises(Denied):
            self.apply()
        self.assertEqual(self.calls, [])

    def test_user_writable_or_symlinked_stage_cannot_acquire_root_state(self):
        self.stage.chmod(0o777)
        with self.assertRaises(Denied):
            self.apply()
        self.stage.chmod(0o700)
        link = self.stage / "stage-link"
        link.symlink_to(self.stage, target_is_directory=True)
        with self.assertRaises(Denied):
            reg.replace_registration(str(link), self.target, "synthetic-token", _transport=self.transport)
        link.unlink()
        self.assertEqual(self.calls, [])

    def test_target_identity_drift_or_expired_fence_denies_before_wire(self):
        for changed in (replace(self.target, runner_id=79), replace(self.target, group_id=8),
                        replace(self.target, owner_id=54334172), replace(self.target, owner_login="other"),
                        replace(self.target, valid_until=int(time.time()) - 1)):
            with self.subTest(target=changed.runner_id):
                with self.assertRaises(Denied):
                    self.apply(target=changed)
        self.assertEqual(self.calls, [])

    def test_latest_real_fence_receipt_bound_to_both_intents_without_changing_target(self):
        fresh = replace(self.target, fence_sha256="b" * 64, valid_until=int(time.time()) + 120)
        self.apply(target=fresh)
        payload = json.loads((self.stage / reg.STATE_FILE).read_bytes())["payload"]
        self.assertEqual(payload["auth_fence_sha256"], "b" * 64)
        self.assertEqual(payload["replace_fence_sha256"], "b" * 64)
        self.assertEqual(payload["target"]["runner_id"], 78)

    def test_auth_unknown_reply_held_without_next_auth_or_replace(self):
        def lost(url, token, body):
            self.calls.append((url, token, body))
            raise OSError("synthetic-token raw-auth-response")
        with self.assertRaises(Denied) as caught:
            self.apply(transport=lost)
        self.assertNotIn("synthetic", str(caught.exception))
        with self.assertRaisesRegex(Denied, "registration-unknown-held"):
            self.apply()
        self.assertEqual(len(self.calls), 1)

    def test_effective_replace_lost_reply_has_no_second_wire_or_key_rotation(self):
        key = (self.stage / reg.KEY_FILE).read_bytes()
        def lost(url, token, body):
            self.calls.append((url, token, body))
            if url == reg.AUTH_URL:
                return auth_response()
            raise OSError("synthetic-token raw-replace-response")
        with self.assertRaises(Denied):
            self.apply(transport=lost)
        with self.assertRaisesRegex(Denied, "registration-unknown-held"):
            self.apply()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual((self.stage / reg.KEY_FILE).read_bytes(), key)
        self.assertFalse((self.stage / ".runner").exists())

    def test_unsupported_auth_flow_never_calls_replace(self):
        def wrong(url, token, body):
            self.calls.append(url)
            return auth_response(use_v2_flow="false")
        with self.assertRaisesRegex(Denied, "registration-auth-flow"):
            self.apply(transport=wrong)
        self.assertEqual(self.calls, [reg.AUTH_URL])

    def test_key_loss_during_auth_prevents_credential_replace(self):
        def lost_key(url, token, body):
            self.calls.append(url)
            (self.stage / reg.KEY_FILE).unlink()
            return auth_response()
        with self.assertRaises(Denied):
            self.apply(transport=lost_key)
        self.assertEqual(self.calls, [reg.AUTH_URL])
        self.assertFalse((self.stage / ".runner").exists())

    def test_wrong_id_name_or_echoed_group_is_held_without_add_or_retry(self):
        for changed in ({"id": 79}, {"name": "other"}, {"group_id": 8}, {"owner_id": 1}):
            with self.subTest(changed=changed):
                with self.assertRaises(Denied):
                    reg._response(replace_response(**changed), self.target)
        def wrong(url, token, body):
            self.calls.append(url)
            return auth_response() if url == reg.AUTH_URL else replace_response(id=79)
        with self.assertRaisesRegex(Denied, "registration-response-identity"):
            self.apply(transport=wrong)
        with self.assertRaises(Denied):
            self.apply()
        self.assertEqual(self.calls, [reg.AUTH_URL, reg.REPLACE_URL])
        self.assertFalse((self.stage / ".runner").exists())

    def test_credentials_url_or_shape_cannot_route_secret_to_arbitrary_host(self):
        original = json.loads(replace_response())
        for url in ("http://vstoken.actions.githubusercontent.com/token", "https://example.invalid/token",
                    "https://evil@vstoken.actions.githubusercontent.com/token", "https://vstoken.actions.githubusercontent.com:444/token",
                    "https://vstoken.actions.githubusercontent.com/token?secret=synthetic"):
            data = {**original, "authorization": {**original["authorization"], "authorization_url": url}}
            with self.assertRaises(Denied):
                reg._response(encoded(data), self.target)

    def test_optional_legacy_auth_url_maps_to_exact_stock_credentials(self):
        def legacy(url, token, body):
            if url == reg.AUTH_URL:
                return auth_response()
            data = json.loads(replace_response())
            data["authorization"]["legacy_authorization_url"] = "https://pipelines.actions.githubusercontent.com/legacy/token"
            return encoded(data)
        result = self.apply(transport=legacy)
        credentials = json.loads(Path(result.credentials_path).read_bytes())["data"]
        self.assertEqual(credentials["authorizationUrl"], "https://pipelines.actions.githubusercontent.com/legacy/token")
        self.assertEqual(credentials["enableAuthMigrationByDefault"], "true")
        self.assertEqual(credentials["authorizationUrlV2"], "https://vstoken.actions.githubusercontent.com/_apis/oauth2/token")

    def test_token_not_in_journal_result_or_public_error_and_header_injection_denied(self):
        output = io.StringIO()
        with mock.patch("sys.stdout", output), mock.patch("sys.stderr", output):
            result = self.apply()
        journal = (self.stage / reg.STATE_FILE).read_text()
        self.assertNotIn("synthetic-token", journal)
        self.assertNotIn("synthetic-tenant-secret", journal)
        self.assertNotIn("synthetic", repr(result))
        self.assertEqual(output.getvalue(), "")
        with self.assertRaises(Denied):
            self.apply(token="synthetic\r\nInjected: header")
        self.assertEqual(len(self.calls), 2)

    def test_valid_json_state_corruption_and_completed_output_tamper_fail_closed(self):
        state = self.stage / reg.STATE_FILE
        original = state.read_bytes()
        data = json.loads(original)
        data["payload"]["phase"] = "complete"
        state.write_bytes(encoded(data))
        with self.assertRaisesRegex(Denied, "registration-state-corrupt"):
            self.apply()
        self.assertEqual(self.calls, [])
        state.write_bytes(original)
        self.apply()
        (self.stage / ".runner").write_text('{"agentId":79}')
        with self.assertRaisesRegex(Denied, "registration-complete-drift"):
            self.apply()
        self.assertEqual(len(self.calls), 2)


if __name__ == "__main__":
    unittest.main()
