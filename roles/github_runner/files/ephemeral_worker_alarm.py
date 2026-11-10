"""Root alarm ingestion/readback; never notification acceptance or capacity release.

No default endpoint, automatic installation, job input, resolution or VM effect.
The separately supervised caller must refresh firing alerts and detect its own
outage externally: an Alertmanager endsAt timeout is not incident resolution.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import time
from urllib.parse import urlencode
import uuid

from ephemeral_worker_lease import Held, Store, require, unique_object
from ephemeral_worker_incus import machine_id, trusted_directory
from ephemeral_worker_watchdog import KINDS


def digest(value, size):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is not None


def event_fields(value):
    require(type(value) is dict and set(value) == {'schema', 'event_id', 'kind', 'operation',
        'vm_uuid', 'phase', 'ticket_sha256', 'observed_at', 'delivery'}, 'alarm-event-shape')
    require(type(value['schema']) is int and value['schema'] == 1 and value['kind'] in KINDS
        and type(value['observed_at']) is int and 0 < value['observed_at'] <= 253402300000
        and value['delivery'] == 'pending' and digest(value['event_id'], 64), 'alarm-event-fields')
    identity = {key: value[key] for key in ('kind', 'operation', 'vm_uuid', 'phase', 'ticket_sha256')}
    if value['operation'] is None:
        require(all(value[key] is None for key in ('vm_uuid', 'phase', 'ticket_sha256')), 'alarm-unbound-event')
    else:
        require(digest(value['operation'], 32) and digest(value['ticket_sha256'], 64)
            and type(value['phase']) is str and value['phase'] in {
                'CLAIMED', 'ALLOCATION_INTENT', 'ALLOCATION_DISPATCH_INTENT', 'ALLOCATION_EXECUTED',
                'ALLOCATED', 'START_DISPATCH_INTENT', 'START_EXECUTED', 'STARTED',
                'STOP_DISPATCH_INTENT', 'STOP_EXECUTED', 'STOPPED',
                'DELETE_DISPATCH_INTENT', 'DELETE_EXECUTED', 'REMOVED'}, 'alarm-bound-event')
        native_uuid = value['vm_uuid']
        require(native_uuid is None or (type(native_uuid) is str and re.fullmatch(
            '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', native_uuid)
            and uuid.UUID(native_uuid).int != 0), 'alarm-event-uuid')
    expected = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    require(value['event_id'] == expected, 'alarm-event-digest')
    return value


def timestamp(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace('+00:00', 'Z')


def seconds(value):
    require(type(value) is str, 'alarm-readback-time')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.tzinfo is not None, 'alarm-readback-time')
    return parsed.timestamp()


def alert(value, *, now, ttl, source_machine_id):
    event_fields(value)
    require(digest(source_machine_id, 32) and type(now) is int and value['observed_at'] <= now <= 253402299000
        and type(ttl) is int and 120 <= ttl <= 900, 'alarm-refresh-window')
    return {'labels': {'alertname': 'DisposableWorkerCleanupHeld', 'service': 'disposable-worker',
                'severity': 'critical', 'event_id': value['event_id'], 'kind': value['kind'],
                'source_machine_id': source_machine_id},
        'annotations': {key: str(value[key]) if value[key] is not None else 'unbound'
                        for key in ('operation', 'vm_uuid', 'phase', 'ticket_sha256')},
        'startsAt': timestamp(value['observed_at']), 'endsAt': timestamp(now + ttl)}


@contextmanager
def credential(path):
    """Keep exact Root-owned private inodes open for OpenSSL; no byte export."""
    path = Path(path)
    require(path.is_absolute(), 'alarm-tls-path')
    parent = trusted_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            value = os.fstat(fd)
            require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1
                and stat.S_IMODE(value.st_mode) in {0o400, 0o600}, 'alarm-tls-file')
            yield '/proc/self/fd/' + str(fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


class Receiver:
    """Explicit IP + verified DNS identity, mTLS, two fixed API calls, no redirects.

    The caller needs a separate process/service deadline as well as this request
    budget. Certificate rotation requires constructing a fresh Receiver.
    """

    def __init__(self, *, address, hostname, port, ca_file, cert_file, key_file, receiver):
        require(os.geteuid() == 0, 'alarm-root-required')
        self.address = str(ipaddress.ip_address(address))
        require(type(hostname) is str and len(hostname) <= 253
            and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', hostname)
            and '..' not in hostname and type(port) is int and 1 <= port <= 65535, 'alarm-endpoint')
        require(type(receiver) is str and re.fullmatch('[a-zA-Z0-9_-]{1,63}', receiver), 'alarm-route')
        self.hostname, self.port, self.receiver = hostname, port, receiver
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        with credential(ca_file) as ca, credential(cert_file) as cert, credential(key_file) as key:
            self.context.load_verify_locations(cafile=ca)
            self.context.load_cert_chain(certfile=cert, keyfile=key)
        self.identity = hashlib.sha256(json.dumps(
            [self.address, hostname, port, receiver], separators=(',', ':')).encode()).hexdigest()

    def _request(self, method, path, body, deadline):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'alarm-request-budget')
        connection = http.client.HTTPConnection(self.hostname, self.port, timeout=remaining)
        raw = socket.socket(socket.AF_INET6 if ':' in self.address else socket.AF_INET, socket.SOCK_STREAM)
        try:
            raw.settimeout(remaining)
            raw.connect((self.address, self.port))
            raw.settimeout(max(0.001, deadline - time.monotonic()))
            secure = self.context.wrap_socket(raw, server_hostname=self.hostname)
            connection.sock = secure
            connection.sock.settimeout(max(0.001, deadline - time.monotonic()))
            connection.request(method, path, body=body,
                headers={'Accept': 'application/json', 'Content-Type': 'application/json'})
            response = connection.getresponse()
            require(response.status == 200, 'alarm-http-status')
            if method == 'GET':
                require(response.getheader('Content-Type', '').split(';')[0].strip() == 'application/json',
                    'alarm-http-content-type')
            chunks, size = [], 0
            while not response.isclosed():
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'alarm-request-budget')
                # Keep our public socket reference: HTTPConnection detaches its
                # own reference on Connection: close while the response owns IO.
                secure.settimeout(remaining)
                chunk = response.read1(min(65536, 1048577 - size))
                if not chunk:
                    break
                size += len(chunk)
                require(size <= 1048576, 'alarm-response-size')
                chunks.append(chunk)
            return b''.join(chunks)
        finally:
            connection.close()
            raw.close()

    def ingest(self, payload):
        deadline = time.monotonic() + 10
        body = json.dumps([payload], sort_keys=True, separators=(',', ':')).encode()
        require(len(body) <= 16384, 'alarm-request-size')
        self._request('POST', '/api/v2/alerts', body, deadline)
        query = urlencode({'filter': 'event_id="' + payload['labels']['event_id'] + '"',
            'active': 'true', 'silenced': 'true', 'inhibited': 'true', 'unprocessed': 'true'})
        values = json.loads(self._request('GET', '/api/v2/alerts?' + query, None, deadline),
                            object_pairs_hook=unique_object)
        require(type(values) is list and len(values) == 1 and type(values[0]) is dict, 'alarm-readback-count')
        value = values[0]
        require(value.get('labels') == payload['labels'] and value.get('annotations') == payload['annotations']
            and seconds(value.get('startsAt')) == seconds(payload['startsAt'])
            and seconds(value.get('endsAt')) >= seconds(payload['endsAt']), 'alarm-readback-identity')
        status = value.get('status')
        require(type(status) is dict and status.get('state') == 'active'
            and all(status.get(key) == [] for key in ('silencedBy', 'inhibitedBy', 'mutedBy')),
            'alarm-route-not-active')
        routes = value.get('receivers')
        require(type(routes) is list and {'name': self.receiver} in routes, 'alarm-route-readback')
        require(digest(value.get('fingerprint'), 16), 'alarm-fingerprint')
        return value['fingerprint']


class Forwarder:
    """One existing alarm per call; no worker fence lock or mutation/release API."""

    def __init__(self, store, receiver, *, machine_path='/etc/machine-id'):
        require(type(store) is Store and type(receiver) is Receiver, 'alarm-trusted-dependencies')
        store._directory()
        self.store, self.receiver = store, receiver
        self.machine_path = machine_path
        self.machine = machine_id(machine_path)

    def _read(self, name, *, missing=False):
        self.store._directory()
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.store.fd)
        except FileNotFoundError:
            if missing:
                return None
            raise
        try:
            before = self.store._private_file(fd)
            require(0 < before.st_size <= 65536, 'alarm-file-size')
            raw = os.read(fd, 65537)
            after = self.store._private_file(fd)
            require(len(raw) == before.st_size and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'alarm-file-changed')
            return json.loads(raw, object_pairs_hook=unique_object)
        finally:
            os.close(fd)

    def send(self, event_id, *, now, ttl=300):
        require(digest(event_id, 64), 'alarm-event-id')
        require(machine_id(self.machine_path) == self.machine, 'alarm-source-drift')
        self.store._directory()
        fd = os.open('alarm-forward.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.store.fd)
        try:
            self.store._private_file(fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Held('alarm-forwarder-busy') from None
            value = event_fields(self._read('alarm-' + event_id + '.json'))
            require(value['event_id'] == event_id, 'alarm-file-identity')
            payload = alert(value, now=now, ttl=ttl, source_machine_id=self.machine)
            name = 'ingestion-' + event_id + '-' + self.receiver.identity + '.json'
            receipt = {'schema': 1, 'event_id': event_id, 'receiver_sha256': self.receiver.identity,
                'source_machine_id': self.machine,
                'confirmed_at': now, 'firing_until': now + ttl, 'fingerprint': '',
                'ingested': True, 'notification_delivered': False, 'capacity_released': False}
            previous = self._read(name, missing=True)
            if previous is not None:
                require(type(previous) is dict and set(previous) == set(receipt)
                    and type(previous['confirmed_at']) is int and value['observed_at'] <= previous['confirmed_at'] <= now
                    and type(previous['firing_until']) is int
                    and 120 <= previous['firing_until'] - previous['confirmed_at'] <= 900
                    and type(previous['schema']) is int and digest(previous['fingerprint'], 16)
                    and all(type(previous[key]) is bool for key in
                            ('ingested', 'notification_delivered', 'capacity_released'))
                    and previous == {**receipt, 'confirmed_at': previous['confirmed_at'],
                        'firing_until': previous['firing_until'], 'fingerprint': previous['fingerprint']},
                    'alarm-receipt-invalid')
            receipt['fingerprint'] = self.receiver.ingest(payload)
            require(digest(receipt['fingerprint'], 16), 'alarm-fingerprint')
            require(machine_id(self.machine_path) == self.machine, 'alarm-source-drift')
            self.store._directory()
            require(self._read('alarm-' + event_id + '.json') == value, 'alarm-event-changed')
            temporary = '.ingestion-' + uuid.uuid4().hex
            output_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                0o600, dir_fd=self.store.fd)
            with os.fdopen(output_fd, 'wb') as output:
                output.write(json.dumps(receipt, sort_keys=True).encode() + b'\n')
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, name, src_dir_fd=self.store.fd, dst_dir_fd=self.store.fd)
            os.fsync(self.store.fd)
            return receipt
        finally:
            os.close(fd)
