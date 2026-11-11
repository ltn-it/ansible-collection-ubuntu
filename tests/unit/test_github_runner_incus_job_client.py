"""Real Unix framing, synthetic issuer/GitHub replies; no genuine job grant."""
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.parse

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
import incus_job_client as client  # noqa: E402

API = "synthetic-api-secret-do-not-log"
TOKEN = "synthetic-oidc-secret-do-not-log"
LEASE = "b" * 32


class OidcRequestTests(unittest.TestCase):
    def test_actual_environment_protocol_uses_one_encoded_audience_request_and_no_proxy(self):
        url = "https://pipelines.actions.githubusercontent.com/example/idtoken?api-version=2.0"
        audience = client.AUDIENCE + "a" * 64
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = json.dumps({"value": TOKEN}).encode()
        response.geturl.side_effect = lambda: opener.open.call_args.args[0].full_url
        opener = mock.MagicMock()
        opener.open.return_value = response
        env = {"GITHUB_ACTIONS": "true", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": API,
               "ACTIONS_ID_TOKEN_REQUEST_URL": url}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
                client.urllib.request, "build_opener", return_value=opener) as factory:
            self.assertEqual(client._oidc(audience), TOKEN)
        request = opener.open.call_args.args[0]
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)["audience"], [audience])
        self.assertEqual(request.get_header("Authorization"), "Bearer " + API)
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(opener.open.call_count, 1)
        handlers = factory.call_args.args
        self.assertEqual(next(h.proxies for h in handlers if isinstance(h, client.urllib.request.ProxyHandler)), {})
        self.assertTrue(any(isinstance(h, client._NoRedirect) for h in handlers))

    def test_untrusted_or_ambiguous_oidc_urls_deny_before_sending_the_bearer(self):
        urls = ["http://pipelines.actions.githubusercontent.com/idtoken?a=1",
                "https://actions.githubusercontent.com.evil.invalid/idtoken?a=1",
                "https://user@pipelines.actions.githubusercontent.com/idtoken?a=1",
                "https://pipelines.actions.githubusercontent.com:444/idtoken?a=1",
                "https://pipelines.actions.githubusercontent.com/idtoken?audience=borrowed",
                "https://pipelines.actions.githubusercontent.com/idtoken?a=1#fragment"]
        for url in urls:
            with self.subTest(url=url), mock.patch.dict(os.environ, {
                "GITHUB_ACTIONS": "true", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": API,
                "ACTIONS_ID_TOKEN_REQUEST_URL": url}, clear=True), mock.patch.object(
                    client.urllib.request, "build_opener") as opener:
                with self.assertRaises(client.ClientDenied):
                    client._oidc("audience")
                opener.assert_not_called()

    def test_duplicate_response_fields_and_nonfinite_json_are_denied(self):
        for raw in (b'{"value":"one","value":"two"}', b'{"value":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(client.ClientDenied):
                client._object(raw)

    def test_no_public_path_or_command_override(self):
        for kwargs in ({"socket_path": "/untrusted"}, {"command": "arbitrary"}, {"policy": {}}):
            with self.assertRaises(TypeError):
                client.authenticate("approved", "admit", **kwargs)


class UnixIssuer:
    def __init__(self, path):
        self.path, self.requests, self.errors = path, [], []
        self.reply = self.normal_reply
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(str(path))
        path.chmod(0o660)
        self.socket.listen(4)
        self.socket.settimeout(0.1)
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    @staticmethod
    def exact(connected, size):
        raw = b""
        while len(raw) < size:
            part = connected.recv(size - len(raw))
            if not part:
                raise ValueError("fixture-truncated")
            raw += part
        return raw

    def normal_reply(self, request):
        operation = request["operation"]
        result = {"schema": 1, "operation": operation, "expires_at": int(time.time()) + 120}
        if operation == "challenge":
            result.update(nonce="a" * 64, audience=client.AUDIENCE + "a" * 64)
        else:
            result["lease_id"] = LEASE
        return client._frame({"schema": 1, "status": "ok", "result": result}, 2048)

    def run(self):
        while not self.stopped.is_set():
            try:
                connected, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connected:
                connected.settimeout(1)
                try:
                    selector = json.loads(self.exact(connected, struct.unpack("!I", self.exact(connected, 4))[0]))
                    request = json.loads(self.exact(connected, struct.unpack("!I", self.exact(connected, 4))[0]))
                    self.requests.append((selector, request))
                    connected.sendall(self.reply(request))
                except Exception as error:
                    self.errors.append(type(error).__name__)

    def close(self):
        self.stopped.set()
        self.socket.close()
        self.thread.join(2)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Root EE Unix peer fixture only")
class RootUnixClientTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires private Root0700 tmpfs")
        self.temp = tempfile.TemporaryDirectory(prefix="job-client-", dir=base)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "client.json"
        self.server = UnixIssuer(self.root / "issuer.sock")
        self.addCleanup(self.server.close)
        self.config.write_text(json.dumps({"schema": 1, "socket_path": str(self.server.path)}))
        self.config.chmod(0o644)
        self.config_patch = mock.patch.object(client, "CONFIG", str(self.config))
        self.config_patch.start()
        self.addCleanup(self.config_patch.stop)
        self.environment = mock.patch.dict(os.environ, {"GITHUB_TOKEN": API}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.oidc = mock.patch.object(client, "_oidc", return_value=TOKEN)
        self.token_source = self.oidc.start()
        self.addCleanup(self.oidc.stop)

    def test_real_root_peer_two_frames_and_fresh_token_only_safe_metadata_returned(self):
        result = client.authenticate("approved", "admit")
        self.assertEqual(result["lease_id"], LEASE)
        self.assertEqual([r[1]["operation"] for r in self.server.requests], ["challenge", "admit"])
        selector, request = self.server.requests[-1]
        self.assertEqual(selector, {"schema": 1, "cell": "approved"})
        self.assertEqual(request, {"schema": 1, "operation": "admit", "nonce": "a" * 64,
                                   "token": TOKEN, "api_token": API})
        self.token_source.assert_called_once_with(client.AUDIENCE + "a" * 64)
        self.assertNotIn(API, repr(result))
        self.assertNotIn(TOKEN, repr(result))
        self.assertEqual(self.server.errors, [])

    def test_explicit_refresh_and_recover_have_distinct_closed_requests(self):
        client.authenticate("approved", "refresh", lease_id=LEASE)
        self.assertEqual(self.server.requests[-1][1]["lease_id"], LEASE)
        client.authenticate("approved", "recover")
        self.assertNotIn("lease_id", self.server.requests[-1][1])
        before = len(self.server.requests)
        with self.assertRaises(client.ClientDenied):
            client.authenticate("approved", "recover", lease_id=LEASE)
        self.assertEqual(len(self.server.requests), before)

    def test_lost_authenticated_reply_is_unknown_and_never_auto_retried_or_recovered(self):
        normal = self.server.normal_reply
        self.server.reply = lambda request: normal(request) if request["operation"] == "challenge" else b""
        with self.assertRaises(client.ClientUnknown) as error:
            client.authenticate("approved", "admit")
        self.assertEqual(str(error.exception), "incus-client-outcome-unknown")
        self.assertEqual([r[1]["operation"] for r in self.server.requests], ["challenge", "admit"])

    def test_confused_refresh_locator_is_unknown_after_authenticated_send(self):
        with self.assertRaises(client.ClientUnknown):
            client.authenticate("approved", "refresh", lease_id="c" * 32)
        self.assertEqual(len(self.server.requests), 2)

    def test_no_secret_from_provider_or_malformed_reply_reaches_public_error(self):
        self.token_source.side_effect = ValueError(TOKEN + API)
        with self.assertRaises(client.ClientDenied) as error:
            client.authenticate("approved", "admit")
        self.assertNotIn(TOKEN, str(error.exception))
        self.assertNotIn(API, str(error.exception))
        self.assertEqual(len(self.server.requests), 1)

    def test_unsafe_configuration_or_socket_is_rejected_before_request(self):
        for mode in (0o666, 0o664):
            self.config.chmod(mode)
            with self.assertRaises(client.ClientDenied):
                client.authenticate("approved", "admit")
        self.config.chmod(0o644)
        self.server.path.chmod(0o664)
        with self.assertRaises(client.ClientDenied):
            client.authenticate("approved", "admit")
        self.assertEqual(self.server.requests, [])

    def test_nonroot_server_uid_is_not_trusted_even_with_root_socket_path(self):
        # The socket itself is real and Root-owned; only the observed peer
        # credential is modeled to exercise the mandatory server identity gate.
        original = client.socket.socket
        class WrongPeer:
            def __init__(self, *args):
                self.real = original(*args)
            def __getattr__(self, name):
                return getattr(self.real, name)
            def getsockopt(self, *_args):
                return struct.pack("3i", 123, 2101, 2101)
        with mock.patch.object(client.socket, "socket", WrongPeer), self.assertRaises(client.ClientDenied):
            client.authenticate("approved", "admit")
        self.assertEqual(self.server.requests, [])
