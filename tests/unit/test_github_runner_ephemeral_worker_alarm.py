"""Real Root spool, real mTLS sockets and a local Alertmanager API fixture.

The protocol fixture is not the actual Alertmanager image or recipient delivery.
Ephemeral test CA/key bytes stay in temporary files inside the test container.
"""
import copy
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'roles/github_runner/files'))
import ephemeral_worker_alarm as alarm
import ephemeral_worker_lease as lease
import ephemeral_worker_watchdog as watchdog
from test_github_runner_ephemeral_worker_lease import ticket


class ValidationTests(unittest.TestCase):
    def test_no_job_callback_or_nonroot_store_accepted(self):
        with self.assertRaises(lease.Held): alarm.Forwarder(Path('/unused'), object())

    def test_invalid_endpoint_fails_before_credential_lookup(self):
        for changes in ({'hostname': 'host\r\nHeader:x'}, {'address': 'dns.example.com'},
                        {'port': True}, {'receiver': 'x/y'}):
            with self.subTest(changes=changes), patch('os.geteuid', return_value=0):
                with self.assertRaises((lease.Held, ValueError)):
                    alarm.Receiver(**{'address': '127.0.0.1', 'hostname': 'receiver.example', 'port': 443,
                        'receiver': 'custodian', 'ca_file': '/absent', 'cert_file': '/absent',
                        'key_file': '/absent', **changes})


@unittest.skipUnless(os.geteuid() == 0, 'Root-private alarm forwarding')
class ForwarderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.credentials = tempfile.TemporaryDirectory()
        cls.certs = Path(cls.credentials.name)
        def openssl(*args):
            result = subprocess.run(['openssl', *args], cwd=cls.certs, capture_output=True, timeout=20)
            if result.returncode:
                raise AssertionError('synthetic TLS fixture generation failed')
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt',
            '-days', '1', '-subj', '/CN=synthetic-alarm-ca')
        for name, usage in [('server', 'serverAuth'), ('client', 'clientAuth')]:
            openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', name+'.key', '-out', name+'.csr',
                '-subj', '/CN='+name)
            (cls.certs/(name+'.ext')).write_text('extendedKeyUsage='+usage+'\nsubjectAltName=DNS:receiver.example\n')
            openssl('x509', '-req', '-in', name+'.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
                '-CAcreateserial', '-out', name+'.crt', '-days', '1', '-extfile', name+'.ext')
        for path in cls.certs.iterdir(): path.chmod(0o600)

    @classmethod
    def tearDownClass(cls): cls.credentials.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name); self.store = lease.Store(self.path); self.addCleanup(self.store.close)
        self.now = int(time.time()); self.record = self.store.claim(ticket(), now=self.now-10)
        self.event_id = watchdog.PendingAlarms(self.store).record(self.record, 'clock-rollback', now=self.now-5)
        self.event_path = self.path/('alarm-'+self.event_id+'.json')
        self.original = self.event_path.read_bytes(); self.active = (self.path/'active.json').read_bytes()
        self.machine_path = self.path/'machine-id'; self.machine_path.write_text('1'*32+'\n')
        self.calls = []; self.mode = 'ok'; self.payload = None; self.peer_cert_seen = False
        owner = self
        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *args): pass
            def reply(self, code, body, content_type='application/json'):
                self.send_response(code); self.send_header('Content-Type', content_type)
                self.send_header('Connection', 'close'); self.close_connection = True
                self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                owner.calls.append(('POST', self.path)); owner.peer_cert_seen = bool(self.connection.getpeercert())
                raw = self.rfile.read(int(self.headers['Content-Length'])); owner.payload = json.loads(raw)[0]
                if owner.mode == 'redirect':
                    self.send_response(302); self.send_header('Location', 'https://must-not-follow.example/')
                    self.send_header('Content-Length', '0'); self.end_headers(); return
                if owner.mode == 'post-error': self.reply(500, b'private-response-not-for-artifacts'); return
                if owner.mode == 'lost':
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR); self.connection.close(); return
                self.reply(200, b'')
            def do_GET(self):
                owner.calls.append(('GET', self.path))
                if owner.mode == 'slow':
                    self.send_response(200); self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'[')
                    self.wfile.flush(); time.sleep(0.3)
                    try: self.wfile.write(b']')
                    except (BrokenPipeError, ConnectionResetError, ssl.SSLError): pass
                    self.close_connection = True; return
                value = {**copy.deepcopy(owner.payload), 'fingerprint': 'a'*16, 'updatedAt': owner.payload['startsAt'],
                    'receivers': [{'name': 'custodian'}],
                    'status': {'state': 'active', 'silencedBy': [], 'inhibitedBy': [], 'mutedBy': []}}
                if owner.mode == 'wrong-label': value['labels']['kind'] = 'different'
                if owner.mode == 'wrong-note': value['annotations']['operation'] = 'different'
                if owner.mode == 'wrong-time': value['endsAt'] = value['startsAt']
                if owner.mode == 'wrong-route': value['receivers'] = [{'name': 'default'}]
                if owner.mode in {'suppressed', 'unprocessed'}: value['status']['state'] = owner.mode
                if owner.mode == 'muted': value['status']['mutedBy'] = ['mute']
                if owner.mode == 'duplicate': body = json.dumps([value, value]).encode()
                elif owner.mode == 'empty': body = b'[]'
                elif owner.mode == 'oversized': body = b' ' * 1048577
                elif owner.mode == 'duplicate-key': body = b'{"x":1,"x":2}'
                else: body = json.dumps([value]).encode()
                try: self.reply(200, body, 'text/html' if owner.mode == 'html' else 'application/json')
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError): pass
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.certs/'server.crt', self.certs/'server.key')
        context.load_verify_locations(cafile=self.certs/'ca.crt'); context.verify_mode = ssl.CERT_REQUIRED
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.stop_server)
        self.receiver = self.make_receiver(); self.forwarder = self.make_forwarder()

    def make_forwarder(self, receiver=None):
        return alarm.Forwarder(self.store, receiver or self.receiver, machine_path=self.machine_path)

    def stop_server(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)

    def make_receiver(self, **changes):
        return alarm.Receiver(**{'address': '127.0.0.1', 'hostname': 'receiver.example',
            'port': self.server.server_address[1], 'receiver': 'custodian',
            'ca_file': self.certs/'ca.crt', 'cert_file': self.certs/'client.crt',
            'key_file': self.certs/'client.key', **changes})

    def receipts(self): return list(self.path.glob('ingestion-*.json'))

    def unchanged(self):
        self.assertEqual(self.event_path.read_bytes(), self.original)
        self.assertEqual((self.path/'active.json').read_bytes(), self.active)
        with self.assertRaises(lease.Held): self.store.claim(ticket(), now=self.now+1000)

    def test_real_mtls_ingestion_readback_refresh_and_restart_preserve_capacity(self):
        first = self.forwarder.send(self.event_id, now=self.now)
        self.assertTrue(self.peer_cert_seen); self.assertTrue(first['ingested'])
        self.assertFalse(first['notification_delivered']); self.assertFalse(first['capacity_released'])
        labels = copy.deepcopy(self.payload['labels']); self.assertEqual(len(self.receipts()), 1)
        second = self.make_forwarder(self.make_receiver()).send(self.event_id, now=self.now+30)
        self.assertEqual(self.payload['labels'], labels); self.assertEqual(second['firing_until'], self.now+330)
        self.assertEqual(len(self.receipts()), 1); self.assertEqual(self.receipts()[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual([x[0] for x in self.calls], ['POST', 'GET', 'POST', 'GET']); self.unchanged()

    def test_readback_failures_do_not_create_receipt_or_release(self):
        for mode in ['wrong-label', 'wrong-note', 'wrong-time', 'wrong-route', 'suppressed', 'unprocessed',
                     'muted', 'duplicate', 'empty', 'oversized', 'duplicate-key', 'html']:
            with self.subTest(mode=mode):
                self.mode = mode
                with self.assertRaises((lease.Held, ValueError)): self.forwarder.send(self.event_id, now=self.now)
                self.assertEqual(self.receipts(), []); self.unchanged()

    def test_post_redirect_failure_or_lost_reply_never_followed_or_receipted(self):
        for mode in ['redirect', 'post-error', 'lost']:
            with self.subTest(mode=mode):
                self.mode = mode; self.calls.clear()
                with self.assertRaises((lease.Held, http.client.HTTPException, OSError)):
                    self.forwarder.send(self.event_id, now=self.now)
                self.assertEqual([x[0] for x in self.calls], ['POST']); self.assertEqual(self.receipts(), [])
                self.unchanged()

    def test_wrong_tls_server_identity_rejected_before_request(self):
        forwarder = self.make_forwarder(self.make_receiver(hostname='other.example'))
        with self.assertRaises(ssl.SSLCertVerificationError): forwarder.send(self.event_id, now=self.now)
        self.assertEqual(self.calls, []); self.assertEqual(self.receipts(), []); self.unchanged()

    def test_wrong_ca_or_client_identity_cannot_obtain_ingestion_receipt(self):
        for changes in ({'ca_file': self.certs/'client.crt'},
                        {'cert_file': self.certs/'server.crt', 'key_file': self.certs/'server.key'}):
            with self.subTest(changes=list(changes)):
                forwarder = self.make_forwarder(self.make_receiver(**changes))
                # TLS 1.3 may surface rejected client authentication as a peer reset
                # during the first write. Neither outcome may reach the HTTP handler.
                with self.assertRaises((ssl.SSLError, ConnectionResetError)):
                    forwarder.send(self.event_id, now=self.now)
                self.assertEqual(self.calls, []); self.assertEqual(self.receipts(), []); self.unchanged()

    def test_slow_response_is_bounded_by_request_deadline(self):
        self.mode = 'slow'; started = time.monotonic()
        with self.assertRaises(TimeoutError):
            self.receiver._request('GET', '/api/v2/alerts', None, started+0.1)
        self.assertLess(time.monotonic()-started, 1)
        self.assertEqual(self.receipts(), []); self.unchanged()

    def test_corrupt_event_untrusted_file_or_clock_rollback_prevents_network(self):
        for raw in [b'{"private":"not-forwarded"}', self.original.replace(b'"pending"', b'"delivered"')]:
            self.event_path.write_bytes(raw)
            with self.assertRaises(lease.Held): self.forwarder.send(self.event_id, now=self.now)
        self.event_path.write_bytes(self.original); self.event_path.chmod(0o644)
        with self.assertRaises(lease.Held): self.forwarder.send(self.event_id, now=self.now)
        self.event_path.chmod(0o600)
        with self.assertRaises(lease.Held): self.forwarder.send(self.event_id, now=self.now-6)
        self.assertEqual(self.calls, []); self.unchanged()

    def test_event_symlink_hardlink_and_digest_tamper_refused(self):
        original_file = self.path/'saved.json'; self.event_path.rename(original_file)
        self.event_path.symlink_to(original_file)
        with self.assertRaises(OSError): self.forwarder.send(self.event_id, now=self.now)
        self.event_path.unlink(); os.link(original_file, self.event_path)
        with self.assertRaises(lease.Held): self.forwarder.send(self.event_id, now=self.now)
        original_file.unlink(); value = json.loads(self.original); value['kind'] = 'native-stop-failed'
        self.event_path.write_text(json.dumps(value))
        with self.assertRaises(lease.Held): self.forwarder.send(self.event_id, now=self.now)
        self.assertEqual(self.calls, []); self.assertEqual(self.receipts(), [])

    def test_existing_receipt_tampering_or_rollback_refused_before_refresh(self):
        self.forwarder.send(self.event_id, now=self.now); self.calls.clear()
        path, = self.receipts(); original = path.read_bytes(); value = json.loads(original)
        value['notification_delivered'] = True; path.write_text(json.dumps(value))
        with self.assertRaises(lease.Held): self.forwarder.send(self.event_id, now=self.now+1)
        path.write_bytes(original)
        with self.assertRaises(lease.Held): self.forwarder.send(self.event_id, now=self.now-1)
        self.assertEqual(self.calls, []); self.unchanged()

    def test_failed_receipt_fsync_does_not_claim_local_ingestion_evidence(self):
        with patch('os.fsync', side_effect=OSError('synthetic full evidence disk')):
            with self.assertRaises(OSError): self.forwarder.send(self.event_id, now=self.now)
        self.assertEqual(self.receipts(), []); self.assertEqual(len(self.calls), 2); self.unchanged()
        self.forwarder.send(self.event_id, now=self.now+1)
        self.assertEqual(len(self.receipts()), 1); self.unchanged()

    def test_network_forwarding_does_not_hold_worker_or_alarm_writer_lock(self):
        original = self.receiver.ingest
        def ingest(payload):
            # Actual file locks, not flags: worker controller and watchdog remain live.
            with self.store.exclusive(): self.assertIsNotNone(self.store._read())
            watchdog.PendingAlarms(self.store).record(self.record, 'native-stop-failed', now=self.now)
            return original(payload)
        with patch.object(self.receiver, 'ingest', side_effect=ingest):
            self.forwarder.send(self.event_id, now=self.now)
        self.unchanged()

    def test_second_forwarder_is_held_by_actual_independent_lock(self):
        original = self.receiver.ingest
        def ingest(payload):
            with self.assertRaisesRegex(lease.Held, 'alarm-forwarder-busy'):
                self.make_forwarder().send(self.event_id, now=self.now)
            return original(payload)
        with patch.object(self.receiver, 'ingest', side_effect=ingest):
            self.forwarder.send(self.event_id, now=self.now)
        self.assertEqual(len(self.calls), 2); self.unchanged()

    def test_private_tls_file_guard_and_request_budget(self):
        public = self.path/'public.crt'; public.write_bytes(b'synthetic'); public.chmod(0o644)
        with self.assertRaises(lease.Held): self.make_receiver(ca_file=public)
        with self.assertRaises(lease.Held): self.receiver._request('GET', '/api/v2/alerts', None, time.monotonic()-1)
        self.assertEqual(self.calls, [])

    def test_native_source_drift_refuses_forwarding_and_sources_have_distinct_labels(self):
        value = json.loads(self.original)
        first = alarm.alert(value, now=self.now, ttl=300, source_machine_id='1'*32)
        second = alarm.alert(value, now=self.now, ttl=300, source_machine_id='2'*32)
        self.assertNotEqual(first['labels'], second['labels'])
        self.machine_path.write_text('2'*32+'\n')
        with self.assertRaises(lease.Held): self.forwarder.send(self.event_id, now=self.now)
        self.assertEqual(self.calls, []); self.assertEqual(self.receipts(), [])
