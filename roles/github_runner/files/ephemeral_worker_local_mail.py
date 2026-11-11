"""Root-only local alarm submission and mailbox confirmation.

A durable dispatch intent precedes submission. Ambiguous attempts are reconciled
against the local mailbox and never automatically submitted again. No lease,
pending alarm, capacity or personal acknowledgment is changed by this module.
Operational callers must supervise this bounded component independently.
"""
from email.message import EmailMessage
from email.parser import BytesParser
from email import policy
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import uuid

from ephemeral_worker_alarm import digest, event_fields
from ephemeral_worker_incus import machine_id, trusted_directory
from ephemeral_worker_lease import Held, Store, require, unique_object


def private_read(directory, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= maximum,
            'local-mail-private-file')
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        require(len(raw) == before.st_size and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'local-mail-file-changed')
        return json.loads(raw, object_pairs_hook=unique_object)
    finally:
        os.close(fd)


def owned_configuration():
    directory = trusted_directory('/var/lib/lit-local-mail')
    try:
        require(stat.S_IMODE(os.fstat(directory).st_mode) == 0o700, 'local-mail-ownership-directory')
        receipt = private_read(directory, 'ownership.json', 4096)
    finally:
        os.close(directory)
    require(type(receipt) is dict and set(receipt) == {'schema', 'main_cf_sha256', 'master_cf_sha256'}
        and type(receipt['schema']) is int and receipt['schema'] == 1, 'local-mail-ownership')
    directory = trusted_directory('/etc/postfix')
    try:
        for key, name in [('main_cf_sha256', 'main.cf'), ('master_cf_sha256', 'master.cf')]:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            try:
                value = os.fstat(fd)
                require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1
                    and stat.S_IMODE(value.st_mode) == 0o644 and 0 < value.st_size <= 65536,
                    'local-mail-config-file')
                raw = os.read(fd, 65537)
                require(digest(receipt[key], 64) and len(raw) == value.st_size
                    and hashlib.sha256(raw).hexdigest() == receipt[key], 'local-mail-config-drift')
            finally:
                os.close(fd)
    finally:
        os.close(directory)


def mailbox_contains(identity, body, *, path=Path('/var/mail/root')):
    """Read a bounded Root mailbox through one trusted inode, never a pathname reopen."""
    parent = trusted_directory(path.parent.parent)
    try:
        directory = os.open(path.parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
    finally:
        os.close(parent)
    try:
        value = os.fstat(directory)
        require(value.st_uid == 0 and not value.st_mode & 0o002
            and (not value.st_mode & 0o020 or (value.st_gid == grp.getgrnam('mail').gr_gid
                and stat.S_IMODE(value.st_mode) == 0o2775)), 'local-mail-mailbox-directory')
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        except FileNotFoundError:
            return False
        try:
            value = os.fstat(fd)
            require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1
                and value.st_gid in {0, grp.getgrnam('mail').gr_gid}
                and stat.S_IMODE(value.st_mode) in {0o600, 0o640}
                and value.st_size <= 16777216, 'local-mail-mailbox-file')
            raw = os.read(fd, value.st_size + 1)
            after = os.fstat(fd)
            require(len(raw) == value.st_size and (value.st_size, value.st_mtime_ns, value.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'local-mail-mailbox-changing')
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    matches = 0
    if raw:
        require(raw.startswith(b'From '), 'local-mail-mailbox-format')
    for part in raw.split(b'\nFrom ') if raw else []:
        part = part.partition(b'\n')[2]
        message = BytesParser(policy=policy.default).parsebytes(part)
        if message.get_all('Message-ID') == [identity]:
            require(message.get_content_type() == 'text/plain' and not message.is_multipart()
                and message.get_all('To') == ['root@localhost']
                and message.get_content().rstrip('\n') == body, 'local-mail-mailbox-content')
            matches += 1
    require(matches <= 1, 'local-mail-duplicate-message')
    return matches == 1


class LocalForwarder:
    """Fixed local recipient, independent lock and durable no-replay submission."""

    def __init__(self, store, *, machine_path='/etc/machine-id'):
        require(os.geteuid() == 0 and type(store) is Store, 'local-mail-root-store')
        store._directory()
        self.store = store
        self.machine_path = machine_path
        self.machine = machine_id(machine_path)

    def _read(self, name, *, missing=False):
        self.store._directory()
        try:
            return private_read(self.store.fd, name, 65536)
        except FileNotFoundError:
            if missing:
                return None
            raise

    def _save(self, name, value):
        self.store._directory()
        temporary = '.local-mail-' + uuid.uuid4().hex
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.store.fd)
        with os.fdopen(fd, 'wb') as output:
            output.write(json.dumps(value, sort_keys=True).encode() + b'\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, name, src_dir_fd=self.store.fd, dst_dir_fd=self.store.fd)
        os.fsync(self.store.fd)

    def _context(self, event_id, now):
        require(digest(event_id, 64) and type(now) is int and now > 0, 'local-mail-input')
        require(machine_id(self.machine_path) == self.machine, 'local-mail-source-drift')
        value = event_fields(self._read('alarm-' + event_id + '.json'))
        require(value['event_id'] == event_id and value['observed_at'] <= now, 'local-mail-event')
        body = json.dumps({'source_machine_id': self.machine, 'alarm': value}, sort_keys=True)
        identity = '<g06-cleanup-' + self.machine + '-' + event_id + '@localhost>'
        name = 'local-mail-' + event_id + '.json'
        expected = {'schema': 1, 'event_id': event_id, 'source_machine_id': self.machine,
            'message_id': identity, 'body_sha256': hashlib.sha256(body.encode()).hexdigest(),
            'recipient': 'root@localhost', 'dispatch_at': now, 'phase': 'DISPATCH_INTENT',
            'local_mailbox_confirmed': False, 'personal_acknowledged': False, 'capacity_released': False}
        previous = self._read(name, missing=True)
        if previous is not None:
            require(type(previous) is dict and set(previous) == set(expected)
                and type(previous['dispatch_at']) is int and value['observed_at'] <= previous['dispatch_at'] <= now
                and previous['phase'] in {'DISPATCH_INTENT', 'MAILBOX_CONFIRMED'}
                and type(previous['schema']) is int
                and all(type(previous[k]) is bool for k in
                    ['local_mailbox_confirmed', 'personal_acknowledged', 'capacity_released'])
                and previous == {**expected, 'dispatch_at': previous['dispatch_at'],
                    'phase': previous['phase'],
                    'local_mailbox_confirmed': previous['phase'] == 'MAILBOX_CONFIRMED'},
                'local-mail-receipt-invalid')
            expected = previous
        return value, body, identity, name, expected, previous

    def confirmed(self, event_id, *, now):
        """Validate the durable historical receipt without reopening an archived mailbox."""
        *_, previous = self._context(event_id, now)
        return previous is not None and previous['phase'] == 'MAILBOX_CONFIRMED'

    def send(self, event_id, *, now):
        require(digest(event_id, 64) and type(now) is int and now > 0, 'local-mail-input')
        require(machine_id(self.machine_path) == self.machine, 'local-mail-source-drift')
        self.store._directory()
        lock = os.open('local-mail.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=self.store.fd)
        try:
            self.store._private_file(lock)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Held('local-mail-forwarder-busy') from None
            value, body, identity, name, expected, previous = self._context(event_id, now)
            owned_configuration()
            if previous is None:
                self._save(name, expected)
                message = EmailMessage()
                message['From'] = message['To'] = 'root@localhost'
                message['Subject'] = 'Disposable worker cleanup requires attention'
                message['Message-ID'] = identity
                message.set_content(body)
                try:
                    result = subprocess.run(['/usr/sbin/sendmail', '-i', '-f', 'root@localhost', '--', 'root@localhost'],
                        input=message.as_bytes(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=5, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
                except (OSError, subprocess.TimeoutExpired):
                    raise Held('local-mail-submit-uncertain-no-replay') from None
                require(result.returncode == 0, 'local-mail-submit-failed-no-replay')
            for _ in range(6):
                if mailbox_contains(identity, body):
                    require(machine_id(self.machine_path) == self.machine
                        and self._read('alarm-' + event_id + '.json') == value, 'local-mail-source-event-drift')
                    expected = {**expected, 'phase': 'MAILBOX_CONFIRMED', 'local_mailbox_confirmed': True}
                    self._save(name, expected)
                    return expected
                time.sleep(0.5)
            raise Held('local-mail-mailbox-unconfirmed-no-replay')
        finally:
            os.close(lock)
