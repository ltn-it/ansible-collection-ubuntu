"""Real stdlib HTTP framing on socketpair; TLS constructor alone is substituted.

No network, credential, Source host or candidate code is used. The actual
HTTPConnection/HTTPResponse owns and closes its socket file exactly as in HTTPS.
"""
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import generation_acquisition as acquisition  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402

PATH = "/repos/ltn-it/modulix-validation/branches/main"


def response(body, *, declared=None, headers=(), status=200):
    fields = [("Connection", "close"), *headers]
    if declared is not None:
        fields.append(("Content-Length", str(declared)))
    return (f"HTTP/1.1 {status} Fixture\r\n".encode()
            + b"".join(f"{k}: {v}\r\n".encode() for k, v in fields) + b"\r\n" + body)


@contextmanager
def wire(test, framed):
    client, peer = socket.socketpair()
    seen, connections, failures = [], [], []

    def serve():
        try:
            with peer:
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    block = peer.recv(4096)
                    if not block:
                        return
                    request.extend(block)
                    if len(request) > 16384:
                        raise AssertionError("fixture request bound")
                seen.append(bytes(request))
                peer.sendall(framed)
                peer.shutdown(socket.SHUT_WR)
        except (BrokenPipeError, ConnectionResetError):
            pass  # A size/origin/framing denial may close its reader early.
        except BaseException as error:
            failures.append(error)

    def factory(host, *, timeout, context):
        test.assertIsInstance(context, ssl.SSLContext)
        test.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        test.assertTrue(context.check_hostname)
        connection = http.client.HTTPConnection(host, timeout=timeout)
        connection.connect = lambda: setattr(connection, "sock", client)
        connections.append(connection)
        return connection

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with mock.patch.object(acquisition.http.client, "HTTPSConnection", side_effect=factory) as constructor:
            yield seen, connections, client, constructor
    finally:
        for connection in connections:
            connection.close()
        client.close()
        thread.join(2)
        peer.close()
        test.assertFalse(thread.is_alive(), "fixture peer must terminate")
        if failures:
            raise failures[0]


class HTTPBodyTests(unittest.TestCase):
    def test_small_content_length_json_completes_after_stdlib_closes_socket(self):
        body = b'{"ok":true}'
        with wire(self, response(body, declared=len(body))) as (seen, connections, client, constructor):
            self.assertEqual(acquisition._json(PATH, None, time.monotonic()+5), {"ok": True})
            self.assertEqual(client.fileno(), -1)
            self.assertEqual(constructor.call_count, 1)
            self.assertIsNone(connections[0].sock)
            self.assertEqual(len(seen), 1)
            self.assertIn(b"GET " + PATH.encode() + b" HTTP/1.1\r\n", seen[0])
            self.assertNotIn(b"Authorization:", seen[0])

    def test_multichunk_content_length_and_close_delimited_json(self):
        value = {"data": "x"*140000}
        body = json.dumps(value).encode()
        for declared in (len(body), None):
            with self.subTest(declared=declared), wire(self, response(body, declared=declared)):
                self.assertEqual(acquisition._json(PATH, None, time.monotonic()+5), value)

    def test_real_chunked_json_reads_final_chunk_and_closed_EOF(self):
        value = {"data": "x"*70000}
        body = json.dumps(value).encode()
        pieces = [body[:123], body[123:65536], body[65536:]]
        encoded = b"".join(f"{len(p):x}\r\n".encode()+p+b"\r\n" for p in pieces)+b"0\r\n\r\n"
        with wire(self, response(encoded, headers=(("Transfer-Encoding", "chunked"),))):
            self.assertEqual(acquisition._json(PATH, None, time.monotonic()+5), value)

    def test_valid_json_prefix_cannot_hide_truncated_content_length(self):
        body = b'{"ok":true}'
        with wire(self, response(body, declared=len(body)+1)):
            with self.assertRaises(http.client.IncompleteRead):
                acquisition._json(PATH, None, time.monotonic()+5)

    def test_truncated_chunked_framing_fails_closed(self):
        for encoded in (b'b\r\n{"ok":true}\r\n', b'20\r\n{"ok":true}'):
            with self.subTest(encoded=encoded), wire(self, response(encoded, headers=(("Transfer-Encoding", "chunked"),))):
                with self.assertRaises(http.client.IncompleteRead):
                    acquisition._json(PATH, None, time.monotonic()+5)

    def test_closed_body_EOF_keeps_both_deadline_checks_without_socket_IO(self):
        body = b"body"
        with wire(self, response(body, declared=len(body))):
            transport = acquisition._HTTP("https://api.github.com"+PATH, None, time.monotonic()+5)
            try:
                self.assertEqual(transport.read(65536), body)
                self.assertTrue(transport.response.isclosed())
                self.assertEqual(transport.socket.fileno(), -1)
                with mock.patch.object(acquisition, "_remaining", side_effect=[1, Denied("acquisition-deadline")]) as remaining:
                    with self.assertRaisesRegex(Denied, "acquisition-deadline"):
                        transport.read(65536)
                    self.assertEqual(remaining.call_count, 2)
                transport.deadline = time.monotonic()-1
                with self.assertRaisesRegex(Denied, "acquisition-deadline"):
                    transport.read(65536)
            finally:
                transport.close()

    def test_empty_framed_body_EOF_is_idempotent_but_not_JSON(self):
        with wire(self, response(b"", declared=0)):
            transport = acquisition._HTTP("https://api.github.com"+PATH, None, time.monotonic()+5)
            try:
                self.assertEqual(transport.read(65536), b"")
                self.assertEqual(transport.read(65536), b"")
                self.assertTrue(transport.response.isclosed())
            finally:
                transport.close()
        with wire(self, response(b"", declared=0)):
            with self.assertRaises(Denied):
                acquisition._json(PATH, None, time.monotonic()+5)

    def test_JSON_size_limit_and_API_status_still_deny(self):
        body = b'{"data":"xxxxxxxxxxxxxxxx"}'
        with mock.patch.object(acquisition, "MAX_JSON", 16), wire(self, response(body, declared=len(body))):
            with self.assertRaisesRegex(Denied, "acquisition-json-limit"):
                acquisition._json(PATH, None, time.monotonic()+5)
        with wire(self, response(b"{}", declared=2, status=302)):
            with self.assertRaisesRegex(Denied, "acquisition-api-status"):
                acquisition._json(PATH, None, time.monotonic()+5)

    def test_real_redirect_remains_explicit_single_origin_and_API_only_bearer(self):
        location = "https://codeload.github.com/ltn-it/modulix-validation/legacy.tar.gz/"+"a"*40
        with wire(self, response(b"", declared=0, status=302, headers=(("Location", location),))) as (seen, _, _, constructor):
            self.assertEqual(acquisition._redirect(PATH, "synthetic-fixture-token", time.monotonic()+5, archive=True), location)
            self.assertEqual(constructor.call_count, 1)
            self.assertIn(b"Authorization: Bearer synthetic-fixture-token\r\n", seen[0])
        with wire(self, response(b"", declared=0, status=302, headers=(("Location", "https://foreign.invalid/body"),))):
            with self.assertRaisesRegex(Denied, "acquisition-archive-origin"):
                acquisition._redirect(PATH, None, time.monotonic()+5, archive=True)
        for url, bearer in [("https://codeload.github.com/body", "synthetic-fixture-token"),
                            ("https://api.github.com/repos/foreign/repo/branches/main", None),
                            ("http://api.github.com"+PATH, None)]:
            with self.subTest(url=url), mock.patch.object(acquisition.http.client, "HTTPSConnection") as constructor:
                with self.assertRaisesRegex(Denied, "acquisition-origin"):
                    acquisition._HTTP(url, bearer, time.monotonic()+5)
                constructor.assert_not_called()


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class HTTPDownloadTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires private Root0700 /run/proof tmpfs")
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temp.cleanup)
        self.fd = os.open(Path(self.temp.name)/"archive", os.O_RDWR|os.O_CREAT|os.O_EXCL, 0o600)
        self.addCleanup(os.close, self.fd)

    def test_real_multichunk_download_verifies_final_size_digest_and_Root_FD(self):
        body = b"archive-fixture-"*10000
        with wire(self, response(body, declared=len(body))):
            digest, size = acquisition._download("https://codeload.github.com/fixture", self.fd, None,
                time.monotonic()+5, len(body), digest=hashlib.sha256(body).hexdigest(), size=len(body))
        self.assertEqual((digest, size), (hashlib.sha256(body).hexdigest(), len(body)))
        self.assertEqual(os.fstat(self.fd).st_size, len(body))
        self.assertEqual(stat.S_IMODE(os.fstat(self.fd).st_mode), 0o600)

    def test_truncated_download_retains_partial_bytes_without_success(self):
        body = b"archive-fixture"
        with wire(self, response(body, declared=len(body)+1)):
            with self.assertRaises(http.client.IncompleteRead):
                acquisition._download("https://codeload.github.com/fixture", self.fd, None,
                    time.monotonic()+5, len(body)+1, size=len(body)+1)
        self.assertEqual(os.fstat(self.fd).st_size, len(body))

    def test_wrong_download_digest_or_size_still_denies_and_retains_evidence(self):
        body = b"archive-fixture"
        with wire(self, response(body, declared=len(body))):
            with self.assertRaisesRegex(Denied, "acquisition-download-digest"):
                acquisition._download("https://codeload.github.com/fixture", self.fd, None,
                    time.monotonic()+5, len(body), digest="0"*64, size=len(body))
        self.assertEqual(os.fstat(self.fd).st_size, len(body))
        other = os.open(Path(self.temp.name)/"second", os.O_RDWR|os.O_CREAT|os.O_EXCL, 0o600)
        self.addCleanup(os.close, other)
        with wire(self, response(body, declared=len(body))):
            with self.assertRaisesRegex(Denied, "acquisition-content-length"):
                acquisition._download("https://codeload.github.com/fixture", other, None,
                    time.monotonic()+5, len(body)+1, size=len(body)+1)
        self.assertEqual(os.fstat(other).st_size, 0)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class FullHTTPAcquisitionTests(unittest.TestCase):
    def test_complete_real_HTTP_acquisition_retains_producer_consumer_and_token_guards(self):
        import test_github_runner_incus_generation_acquisition as original
        fixture = original.RootGenerationAcquisitionTests("runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        connections, peers, threads, failures = [], [], [], []

        def factory(host, *, timeout, context):
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
            client, peer = socket.socketpair()
            peers.append(peer)
            connection = http.client.HTTPConnection(host, timeout=timeout)
            connection.connect = lambda: setattr(connection, "sock", client)
            connections.append(connection)

            def serve():
                try:
                    with peer:
                        request = bytearray()
                        while b"\r\n\r\n" not in request:
                            block = peer.recv(4096)
                            if not block:
                                return
                            request.extend(block)
                            self.assertLessEqual(len(request), 16384)
                        lines = bytes(request).split(b"\r\n")
                        method, path, _ = lines[0].decode().split(" ")
                        headers = dict(line.decode().split(": ", 1) for line in lines[1:] if line)
                        fixture.calls.append((host, method, path, headers))
                        status, body, reply_headers = fixture.routes[(host, path)]
                        peer.sendall(response(body, declared=len(body), headers=tuple(reply_headers.items()), status=status))
                        peer.shutdown(socket.SHUT_WR)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except BaseException as error:
                    failures.append(error)
            thread = threading.Thread(target=serve, daemon=True)
            threads.append(thread)
            thread.start()
            return connection

        try:
            with mock.patch.object(acquisition.http.client, "HTTPSConnection", side_effect=factory):
                result = acquisition.acquire(fixture.request, artifact_fd=fixture.fds[0],
                    source_fd=fixture.fds[1], controller_fd=fixture.fds[2])
        finally:
            for connection in connections:
                connection.close()
            for thread in threads:
                thread.join(2)
                self.assertFalse(thread.is_alive())
            for peer in peers:
                peer.close()
        if failures:
            raise failures[0]
        self.assertEqual(result.artifact_sha256, original.sha(fixture.artifact))
        self.assertEqual(result.source.archive_sha256, original.sha(fixture.source_tar))
        self.assertEqual(result.controller.archive_sha256, original.sha(fixture.controller_tar))
        self.assertEqual({row.path: row.oid for row in result.source.files},
                         {path: original.blob(raw) for path, raw in fixture.source_files.items()})
        self.assertTrue(all(method == "GET" for _, method, _, _ in fixture.calls))
        for host, _, _, headers in fixture.calls:
            self.assertEqual("Authorization" in headers, host == acquisition.API)
        self.assertEqual(sum(path == fixture.run_path for _, _, path, _ in fixture.calls), 2)
        self.assertEqual(sum(host == "codeload.github.com" for host, _, _, _ in fixture.calls), 2)
        self.assertEqual(os.fstat(fixture.fds[0]).st_size, len(fixture.artifact))


if __name__ == "__main__":
    unittest.main()
