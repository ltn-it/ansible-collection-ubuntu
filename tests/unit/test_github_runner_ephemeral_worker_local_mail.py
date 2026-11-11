"""Real Root state/mailbox fixtures; submission fixtures are not an MTA proof."""
import hashlib
from email.parser import BytesParser
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'roles/github_runner/files'))
import ephemeral_worker_local_mail as mail
import ephemeral_worker_lease as lease
import ephemeral_worker_watchdog as watchdog
import ephemeral_worker_local_mail_entry as entry


class BoundaryTests(unittest.TestCase):
    def test_untrusted_dependency_refused(self):
        with self.assertRaises(lease.Held):
            mail.LocalForwarder(Path('/unused'))


@unittest.skipUnless(os.geteuid() == 0, 'Root-private controller files')
class DeliveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        self.spool = self.path / 'state'; self.spool.mkdir(mode=0o700)
        self.store = lease.Store(self.spool); self.addCleanup(self.store.close)
        self.event = watchdog.PendingAlarms(self.store).record(None, 'clock-rollback', now=100)
        self.alarm = self.spool / ('alarm-' + self.event + '.json')
        self.original = self.alarm.read_bytes()
        self.machine = self.path / 'machine-id'; self.machine.write_text('1' * 32 + '\n')
        self.sender = mail.LocalForwarder(self.store, machine_path=self.machine)
        self.boxdir = self.path / 'mail'; self.boxdir.mkdir(mode=0o700)
        self.box = self.boxdir / 'root'
        self.receipt = self.spool / ('local-mail-' + self.event + '.json')
        self.calls = []
        self.mode = 'ok'
        real_contains = mail.mailbox_contains
        self.configuration = mail.owned_configuration
        self.addCleanup(patch.stopall)
        patch.object(mail, 'owned_configuration').start()
        patch.object(mail, 'mailbox_contains', side_effect=lambda identity, body:
            real_contains(identity, body, path=self.box)).start()
        patch.object(mail.time, 'sleep').start()
        patch.object(mail.subprocess, 'run', side_effect=self.submit).start()

    def submit(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        message = BytesParser().parsebytes(kwargs['input'])
        event = re.fullmatch(r'<g06-cleanup-[0-9a-f]{32}-([0-9a-f]{64})@localhost>',
                            str(message['Message-ID'])).group(1)
        intent = json.loads((self.spool / ('local-mail-' + event + '.json')).read_text())
        self.assertEqual(intent['phase'], 'DISPATCH_INTENT')
        self.assertEqual(argv, ['/usr/sbin/sendmail', '-i', '-f', 'root@localhost', '--', 'root@localhost'])
        if self.mode in {'ok', 'lost'}:
            self.box.write_bytes(b'From root@localhost Mon Jan 1 00:00:00 2026\n' + kwargs['input'])
            self.box.chmod(0o600)
        if self.mode == 'lost':
            raise subprocess.TimeoutExpired(argv, 5)
        return subprocess.CompletedProcess(argv, 1 if self.mode == 'failed' else 0)

    def test_confirmed_mailbox_idempotent_pending_unchanged(self):
        result = self.sender.send(self.event, now=101)
        self.assertTrue(result['local_mailbox_confirmed'])
        self.assertFalse(result['capacity_released'])
        self.assertFalse(result['personal_acknowledged'])
        self.assertEqual(result, self.sender.send(self.event, now=102))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.alarm.read_bytes(), self.original)
        self.assertFalse((self.spool / 'active.json').exists())

    def test_lost_reply_reconciles_mailbox_without_resubmission(self):
        self.mode = 'lost'
        with self.assertRaisesRegex(lease.Held, 'uncertain-no-replay'):
            self.sender.send(self.event, now=101)
        self.assertEqual(self.sender.send(self.event, now=102)['phase'], 'MAILBOX_CONFIRMED')
        self.assertEqual(len(self.calls), 1)

    def test_zero_exit_without_mailbox_never_confirms_or_resubmits(self):
        self.mode = 'queued'
        for now in [101, 102]:
            with self.assertRaisesRegex(lease.Held, 'unconfirmed-no-replay'):
                self.sender.send(self.event, now=now)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(json.loads(self.receipt.read_text())['phase'], 'DISPATCH_INTENT')

    def test_nonzero_submission_keeps_intent_and_pending_alarm(self):
        self.mode = 'failed'
        with self.assertRaisesRegex(lease.Held, 'failed-no-replay'):
            self.sender.send(self.event, now=101)
        self.assertEqual(self.alarm.read_bytes(), self.original)
        with self.assertRaisesRegex(lease.Held, 'unconfirmed-no-replay'):
            self.sender.send(self.event, now=102)
        self.assertEqual(len(self.calls), 1)

    def test_private_receipt_and_mailbox_links_or_public_files_refused(self):
        self.sender.send(self.event, now=101)
        self.receipt.chmod(0o644)
        with self.assertRaises(lease.Held): self.sender.send(self.event, now=102)
        self.receipt.chmod(0o600)
        self.box.rename(self.boxdir / 'real')
        self.box.symlink_to(self.boxdir / 'real')
        with self.assertRaises(OSError): self.sender.send(self.event, now=102)
        self.box.unlink(); self.box.write_bytes((self.boxdir / 'real').read_bytes()); self.box.chmod(0o666)
        with self.assertRaises(lease.Held): self.sender.send(self.event, now=102)

    def test_wrong_message_body_does_not_confirm(self):
        self.sender.send(self.event, now=101)
        self.box.write_bytes(self.box.read_bytes().replace(b'clock-rollback', b'clock-rollforw'))
        with self.assertRaisesRegex(lease.Held, 'mailbox-content'):
            self.sender.send(self.event, now=102)
        self.assertEqual(len(self.calls), 1)

    def test_configuration_failure_precedes_durable_intent_and_submission(self):
        with patch.object(mail, 'owned_configuration', side_effect=lease.Held('drift')):
            with self.assertRaisesRegex(lease.Held, 'drift'): self.sender.send(self.event, now=101)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.calls, [])

    def test_other_forwarder_lock_does_not_block_alarm_writer(self):
        import fcntl
        fd = os.open(self.spool / 'local-mail.lock', os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd); fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with self.assertRaisesRegex(lease.Held, 'forwarder-busy'): self.sender.send(self.event, now=101)
        watchdog.PendingAlarms(self.store).record(None, 'clock-rollback', now=102)
        self.assertEqual(self.alarm.read_bytes(), self.original)

    def test_native_owned_configuration_bytes_and_receipt_are_required(self):
        ownership = self.path / 'owned'; ownership.mkdir(mode=0o700)
        config = self.path / 'postfix'; config.mkdir(mode=0o755)
        record = {'schema': 1}
        for key, name in [('main_cf_sha256', 'main.cf'), ('master_cf_sha256', 'master.cf')]:
            (config / name).write_text('synthetic configuration\n'); (config / name).chmod(0o644)
            record[key] = hashlib.sha256((config / name).read_bytes()).hexdigest()
        receipt = ownership / 'ownership.json'; receipt.write_text(json.dumps(record)); receipt.chmod(0o600)
        real_directory = mail.trusted_directory
        def directory(path):
            return real_directory({'/var/lib/lit-local-mail': ownership, '/etc/postfix': config}[path])
        with patch.object(mail, 'trusted_directory', side_effect=directory):
            self.configuration()
            (config / 'main.cf').write_text('changed outside role\n')
            with self.assertRaisesRegex(lease.Held, 'config-drift'): self.configuration()
            receipt.chmod(0o644)
            with self.assertRaisesRegex(lease.Held, 'private-file'): self.configuration()

    def test_full_mailbox_and_hardlinks_never_confirm_or_replay(self):
        self.sender.send(self.event, now=101)
        with self.box.open('r+b') as output: output.truncate(16777217)
        with self.assertRaisesRegex(lease.Held, 'mailbox-file'): self.sender.send(self.event, now=102)
        self.box.unlink(); self.box.write_text(''); self.box.chmod(0o600)
        os.link(self.box, self.boxdir / 'second-link')
        with self.assertRaisesRegex(lease.Held, 'mailbox-file'): self.sender.send(self.event, now=102)
        self.assertEqual(len(self.calls), 1)

    def test_duplicate_message_or_receipt_json_refused(self):
        self.sender.send(self.event, now=101)
        self.box.write_bytes(self.box.read_bytes() + b'\n' + self.box.read_bytes())
        with self.assertRaisesRegex(lease.Held, 'duplicate-message'): self.sender.send(self.event, now=102)
        self.receipt.write_text('{"schema":1,"schema":1}')
        with self.assertRaises((lease.Held, ValueError)): self.sender.send(self.event, now=102)
        self.assertEqual(len(self.calls), 1)

    def test_unpersisted_intent_never_submits(self):
        with patch.object(mail.os, 'fsync', side_effect=OSError('synthetic disk failure')):
            with self.assertRaises(OSError): self.sender.send(self.event, now=101)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.calls, [])

    def test_lost_confirmation_commit_reconciles_without_duplicate(self):
        save = self.sender._save
        def fail_confirmation(name, value):
            if value['phase'] == 'MAILBOX_CONFIRMED': raise OSError('synthetic receipt storage failure')
            return save(name, value)
        with patch.object(self.sender, '_save', side_effect=fail_confirmation):
            with self.assertRaises(OSError): self.sender.send(self.event, now=101)
        self.assertEqual(self.sender.send(self.event, now=102)['phase'], 'MAILBOX_CONFIRMED')
        self.assertEqual(len(self.calls), 1)

    def test_bound_controller_lease_and_pending_event_unchanged(self):
        from test_github_runner_ephemeral_worker_lease import ticket
        record = self.store.claim(ticket(), now=80)
        event = watchdog.PendingAlarms(self.store).record(record, 'clock-rollback', now=100)
        self.receipt = self.spool / ('local-mail-' + event + '.json')
        active = (self.spool / 'active.json').read_bytes()
        alarm = (self.spool / ('alarm-' + event + '.json')).read_bytes()
        self.sender.send(event, now=101)
        self.assertEqual(active, (self.spool / 'active.json').read_bytes())
        self.assertEqual(alarm, (self.spool / ('alarm-' + event + '.json')).read_bytes())

    def test_confirmed_history_survives_mailbox_archival_without_submission(self):
        self.sender.send(self.event, now=101)
        self.box.unlink()
        self.assertTrue(self.sender.confirmed(self.event, now=102))
        result = entry.tick(self.store, now=102, machine_path=self.machine)
        self.assertEqual(result['state'], 'LOCAL_MAIL_NO_UNCONFIRMED_EVENTS')
        self.assertEqual(len(self.calls), 1)

    def test_tick_rotates_past_uncertain_attempt_without_resubmission(self):
        second = watchdog.PendingAlarms(self.store).record(None, 'native-stop-failed', now=100)
        ordered = sorted([self.event, second])
        self.mode = 'queued'
        with self.assertRaises(lease.Held): entry.tick(self.store, now=101, machine_path=self.machine)
        self.assertEqual(json.loads((self.spool / 'local-mail-cursor.json').read_text())['last_event_id'], ordered[0])
        self.mode = 'ok'
        result = entry.tick(self.store, now=102, machine_path=self.machine)
        self.assertEqual(result['event_id'], ordered[1])
        self.assertTrue(result['local_mailbox_confirmed'])
        with self.assertRaises(lease.Held): entry.tick(self.store, now=103, machine_path=self.machine)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.alarm.read_bytes(), self.original)

    def test_tick_rejects_corrupt_cursor_before_dispatch(self):
        self.sender._save('local-mail-cursor.json', {'schema': 1, 'last_event_id': '../outside',
                                                   'source_machine_id': '1' * 32})
        with self.assertRaisesRegex(lease.Held, 'entry-cursor'):
            entry.tick(self.store, now=101, machine_path=self.machine)
        self.assertEqual(self.calls, [])

    def test_tick_bounds_spool_work_before_dispatch(self):
        for i in range(257):
            (self.spool / ('alarm-' + format(i, '064x') + '.json')).write_text('{}')
        with self.assertRaisesRegex(lease.Held, 'event-bound'):
            entry.tick(self.store, now=101, machine_path=self.machine)
        self.assertEqual(self.calls, [])
