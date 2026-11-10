"""Isolated Root AF_UNIX HTTP fixtures; no production daemon is contacted."""
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import incus_admin as admin  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


def envelope(metadata):
    return json.dumps({"type": "sync", "status": "Success", "status_code": 200,
                       "operation": "", "error_code": 0, "error": "", "metadata": metadata}).encode()


def response(raw, *, status=200, headers=None):
    fields = {"Content-Type": "application/json", "Content-Length": str(len(raw))}
    if headers:
        fields.update(headers)
    return (f"HTTP/1.1 {status} Fixture\r\n" + "".join(f"{k}: {v}\r\n" for k, v in fields.items())
            + "\r\n").encode() + raw


class UnixFixture:
    def __init__(self, path):
        self.path, self.requests, self.connections = path, [], 0
        self.reply = response(envelope({"selected": "synthetic"}))
        self.callback = None
        self.stop = threading.Event()
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(str(path))
        path.chmod(0o660)
        self.socket.listen(8)
        self.socket.settimeout(0.1)
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                connected, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections += 1
            with connected:
                connected.settimeout(1)
                raw = b""
                try:
                    while b"\r\n\r\n" not in raw and len(raw) < 16384:
                        part = connected.recv(4096)
                        if not part:
                            break
                        raw += part
                    if not raw:
                        continue
                    self.requests.append(raw)
                    if self.callback:
                        self.callback()
                    connected.sendall(self.reply)
                except OSError:
                    pass

    def close(self):
        self.stop.set()
        self.socket.close()
        self.thread.join(2)


class ResponseEnvelopeTests(unittest.TestCase):
    """Real socket framing shared by read-only and attempted-effect clients."""

    def decode(self, raw, *, strict=False):
        receiving, sending = socket.socketpair()
        try:
            sending.sendall(raw)
            sending.shutdown(socket.SHUT_WR)
            reader = admin._Response(receiving, time.monotonic() + 2)
            return reader.read() if strict else reader.read_envelope()
        finally:
            sending.close()
            receiving.close()

    def test_async_envelope_preserves_status_and_operation_without_claiming_success(self):
        body = {"type": "async", "status": "Operation created", "status_code": 100,
                "operation": "/1.0/operations/00000000-0000-4000-8000-000000000001",
                "error_code": 0, "error": "", "metadata": {"status": "Running"}}
        raw = response(json.dumps(body).encode(), status=202)
        self.assertEqual(self.decode(raw), (202, body))
        with self.assertRaises(Denied):
            self.decode(raw, strict=True)

    def test_error_envelope_is_decoded_but_readonly_api_still_denies(self):
        body = {"type": "error", "error_code": 409, "error": "fixture-conflict"}
        raw = response(json.dumps(body).encode(), status=409)
        self.assertEqual(self.decode(raw), (409, body))
        with self.assertRaises(Denied):
            self.decode(raw, strict=True)

    def test_new_envelope_reader_keeps_duplicate_json_and_trailing_data_denials(self):
        for raw in (response(b'{"type":"sync","type":"error"}'),
                    response(b'{}') + b'{}', response(b'{}', headers={"Transfer-Encoding": "chunked"})):
            with self.subTest(raw=raw), self.assertRaises(Denied):
                self.decode(raw)

    def test_response_headers_only_published_after_complete_decode_and_are_immutable(self):
        for valid in (True, False):
            receiving, sending = socket.socketpair()
            try:
                raw = response(b'{}' if valid else b'{', headers={"ETag": '"actual-daemon-etag"'})
                sending.sendall(raw)
                sending.shutdown(socket.SHUT_WR)
                reader = admin._Response(receiving, time.monotonic() + 2)
                self.assertIsNone(reader.headers)
                if valid:
                    self.assertEqual(reader.read_envelope(), (200, {}))
                    self.assertEqual(reader.headers[b"etag"], b'"actual-daemon-etag"')
                    with self.assertRaises(TypeError):
                        reader.headers[b"etag"] = b'"changed"'
                else:
                    with self.assertRaises(Denied):
                        reader.read_envelope()
                    self.assertIsNone(reader.headers)
            finally:
                sending.close()
                receiving.close()


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux UID0 EE only")
class RootIncusAdminTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires namespace-private Root700 /run/proof tmpfs")
        self.temp = tempfile.TemporaryDirectory(prefix="incus-admin-", dir=base)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = UnixFixture(self.root / "unix.socket")
        self.addCleanup(self.fixture.close)
        self.target = admin.AdminTarget(str(self.fixture.path), "lease-project", "lease-network", "default",
                                        "selected-pool", ("a" * 64,))
        self.client = admin.RootIncusAdmin(self.target)

    def deny(self, function, *args, **kwargs):
        with self.assertRaises(Denied) as caught:
            function(*args, **kwargs)
        self.assertNotIn("synthetic-secret", str(caught.exception))

    def server_reply(self, *, version="7.6", auth="trusted", extensions=None):
        metadata = {"environment": {"server": "incus", "server_version": version}, "auth": auth,
                    "api_extensions": ["certificate_project", "project_usage"] if extensions is None else extensions,
                    "config": {"user.secret": "synthetic-secret"},
                    "unselected_projects": ["synthetic-secret-other-project"]}
        self.fixture.reply = response(envelope(metadata))

    def test_real_root_peer_and_server_projection_excludes_config(self):
        self.server_reply()
        observed = self.client.inspect()
        self.assertEqual(set(observed), {"server", "server_version", "auth", "api_extensions"})
        self.assertNotIn("synthetic-secret", json.dumps(observed))
        self.assertEqual(admin.qualify_backend(observed, expected_version="7.6",
                         expected_extensions=frozenset({"certificate_project"})),
                         {"server_version": "7.6", "required_extensions": ["certificate_project"]})

    def test_old_version_untrusted_auth_and_missing_extension_denied(self):
        for values in ({"version": "6.0.0"}, {"auth": "untrusted"}, {"extensions": []}):
            self.server_reply(**values)
            self.deny(admin.qualify_backend, self.client.server(), expected_version="7.6",
                      expected_extensions=frozenset({"certificate_project"}))

    def test_exact_selected_routes_only_get_no_body(self):
        expected = [(self.client.resources, "/1.0/resources"),
                    (self.client.project, "/1.0/projects/lease-project"),
                    (self.client.project_state, "/1.0/projects/lease-project/state"),
                    (self.client.network, "/1.0/networks/lease-network?project=default"),
                    (self.client.pool_resources, "/1.0/storage-pools/selected-pool/resources"),
                    (lambda: self.client.certificate("a" * 64), "/1.0/certificates/" + "a" * 64)]
        for method, path in expected:
            self.assertEqual(method(), {"selected": "synthetic"})
            request = self.fixture.requests[-1]
            self.assertTrue(request.startswith(("GET " + path + " HTTP/1.1\r\n").encode()))
            self.assertTrue(request.endswith(b"\r\n\r\n"))
            self.assertNotIn(b"Content-Length", request)
        self.fixture.reply = response(envelope([{"fingerprint": "a" * 64}]))
        self.assertEqual(self.client.certificates(), [{"fingerprint": "a" * 64}])
        self.assertTrue(self.fixture.requests[-1].startswith(b"GET /1.0/certificates?recursion=1 "))
        before = len(self.fixture.requests)
        self.deny(self.client.certificate, "b" * 64)
        self.deny(self.client._get, "https://untrusted.example/")
        self.assertEqual(len(self.fixture.requests), before)

    def test_complete_fixed_project_instances_and_all_operation_groups_are_read_only(self):
        self.fixture.reply = response(envelope([]))
        self.assertEqual(self.client.instances(), [])
        self.assertTrue(self.fixture.requests[-1].startswith(b"GET /1.0/instances?project=lease-project "))
        operation = {"id": "12345678-1234-4234-8234-123456789abc", "class": "task",
                     "status": "Failure", "status_code": 400, "metadata": {"private": "not logged"}}
        value = {"failure": [operation], "pending": []}
        self.fixture.reply = response(envelope(value))
        self.assertEqual(self.client.operations(), value)
        self.assertTrue(self.fixture.requests[-1].startswith(
            b"GET /1.0/operations?project=lease-project&recursion=1 "))
        self.assertNotIn(b"filter", self.fixture.requests[-1])
        self.assertNotIn(b"POST", b"".join(self.fixture.requests))

    def test_instance_state_routes_are_root_factory_fixed_not_request_locators(self):
        selected = admin.RootIncusAdmin(replace(self.target, instance="declared-vm"))
        for method, path in ((selected.instance, "/1.0/instances/declared-vm?project=lease-project"),
                             (selected.instance_state, "/1.0/instances/declared-vm/state?project=lease-project")):
            self.assertEqual(method(), {"selected": "synthetic"})
            self.assertTrue(self.fixture.requests[-1].startswith(("GET "+path+" HTTP/1.1\r\n").encode()))
        before = len(self.fixture.requests)
        self.deny(self.client.instance)
        self.deny(self.client.instance_state)
        self.deny(admin.RootIncusAdmin, replace(self.target, instance="../foreign"))
        self.assertEqual(len(self.fixture.requests), before)

    def test_operation_inventory_rejects_unknown_status_duplicate_ids_and_incomplete_shapes(self):
        row = {"id": "12345678-1234-4234-8234-123456789abc", "class": "task",
               "status": "Running", "status_code": 103}
        for value in ({"running": [row, row]}, {"success": [row]}, {"unknown": []},
                      {"running": [row | {"status_code": True}]}, {"running": [row | {"class": "opaque"}]},
                      {"running": ["/1.0/operations/locator"]}, {"running": {}}):
            with self.subTest(value=value):
                self.fixture.reply = response(envelope(value))
                self.deny(self.client.operations)
        self.fixture.reply = response(envelope(["same", "same"]))
        self.deny(self.client.instances)

    def test_redirect_and_error_status_never_retried_or_followed(self):
        for status in (302, 401, 403, 500):
            self.fixture.reply = response(b"synthetic-secret", status=status,
                                          headers={"Location": "http://untrusted.example/"})
            before = len(self.fixture.requests)
            self.deny(self.client.project)
            self.assertEqual(len(self.fixture.requests), before + 1)

    def test_duplicate_nonfinite_truncated_json_and_async_envelope_denied(self):
        for raw in (b'{"metadata":{},"metadata":{}}', b'{"metadata":NaN}',
                    b'{"metadata":Infinity}', b'{"metadata":', envelope({}).replace(b'"sync"', b'"async"')):
            self.fixture.reply = response(raw)
            self.deny(self.client.project)

    def test_content_length_and_header_limits(self):
        for reply in (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999999999\r\n\r\n",
                      b"HTTP/1.1 200 OK\r\nX-Long: " + b"x" * 5000 + b"\r\n\r\n",
                      b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n{}",
                      b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
                      response(envelope({}), headers={"Transfer-Encoding": "chunked"})):
            self.fixture.reply = reply
            self.deny(self.client.project)

    def test_chunked_success_limits_and_malformed_terminator(self):
        raw = envelope({"selected": "chunked"})
        start = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
        self.fixture.reply = start + f"{len(raw):x}\r\n".encode() + raw + b"\r\n0\r\n\r\n"
        self.assertEqual(self.client.project(), {"selected": "chunked"})
        for suffix in (b"ffffff\r\n", b"1;extension=value\r\nx\r\n0\r\n\r\n",
                       b"0\r\nX-Trailer: denied\r\n\r\n", b"1\r\nxZZ0\r\n\r\n"):
            self.fixture.reply = start + suffix
            self.deny(self.client.project)

    def test_truncated_and_trailing_body_denied(self):
        raw = envelope({})
        self.fixture.reply = response(raw)[:-1]
        self.deny(self.client.project)
        self.fixture.reply = response(raw) + b"unexpected"
        self.deny(self.client.project)

    def test_peer_uid_nonzero_denied_with_real_unix_connection(self):
        # Test-only simulated kernel result over the actual Unix fixture;
        # production has no credential/reader injection parameter.
        with mock.patch.object(admin.struct, "unpack", return_value=(1, 2101, 2101)):
            self.deny(self.client.project)

    def test_socket_replacement_during_reply_denied(self):
        replacement = []

        def replace_socket():
            self.fixture.path.unlink()
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(str(self.fixture.path))
            self.fixture.path.chmod(0o660)
            replacement.append(sock)

        self.fixture.callback = replace_socket
        self.deny(self.client.project)
        for sock in replacement:
            sock.close()

    def test_root_socket_nonzero_gid_660_is_supported(self):
        os.chown(self.fixture.path, 0, 2101)
        client = admin.RootIncusAdmin(self.target)
        self.assertEqual(client.project(), {"selected": "synthetic"})

    def test_socket_multiple_links_denied(self):
        link = self.root / "socket-hardlink"
        os.link(self.fixture.path, link)
        try:
            self.deny(admin.RootIncusAdmin, self.target)
        finally:
            link.unlink()

    def test_socket_symlink_regularfile_mode_and_ancestor_denied(self):
        link = self.root / "socket-link"
        link.symlink_to(self.fixture.path)
        self.deny(admin.RootIncusAdmin, replace(self.target, socket_path=str(link)))
        regular = self.root / "not-socket"
        regular.write_bytes(b"synthetic")
        regular.chmod(0o600)
        self.deny(admin.RootIncusAdmin, replace(self.target, socket_path=str(regular)))
        self.fixture.path.chmod(0o666)
        self.deny(admin.RootIncusAdmin, self.target)
        self.fixture.path.chmod(0o660)
        self.root.chmod(0o777)
        self.deny(admin.RootIncusAdmin, self.target)
        self.root.chmod(0o700)

    def test_target_injection_nonroot_and_no_proxy(self):
        self.deny(admin.RootIncusAdmin, replace(self.target, project="lease?project=default"))
        self.deny(admin.RootIncusAdmin, replace(self.target, network_project="foreign"))
        self.deny(admin.RootIncusAdmin, replace(self.target, socket_path="http://example.test/socket"))
        with mock.patch.object(admin.os, "geteuid", return_value=2101):
            self.deny(admin.RootIncusAdmin, self.target)
            self.deny(self.client.project)
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://unreachable.invalid:1",
                                         "HTTPS_PROXY": "http://unreachable.invalid:1"}):
            self.assertEqual(self.client.project(), {"selected": "synthetic"})

    def test_request_timeout_is_bounded_and_not_retried(self):
        self.fixture.callback = lambda: time.sleep(0.15)
        with mock.patch.object(admin, "REQUEST_SECONDS", 0.05):
            before = len(self.fixture.requests)
            self.deny(self.client.project)
            self.assertEqual(len(self.fixture.requests), before + 1)


class NonrootAdminGuardTests(unittest.TestCase):
    def test_nonroot_constructor_fails_before_socket_access(self):
        if os.geteuid() == 0:
            self.skipTest("nonroot EE execution")
        with self.assertRaises(Denied):
            admin.RootIncusAdmin(admin.AdminTarget("/unreachable/never-used.socket", "p", "n", "default", "s"))


if __name__ == "__main__":
    unittest.main()
