"""Root filesystem/fence integration and explicit GitHub/evidence/approval fixtures."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'roles/github_runner/files'))
import ephemeral_worker_admission as admission
import ephemeral_worker_lease as lease
import ephemeral_worker_retention as retention
from test_github_runner_ephemeral_worker_admission import Client
from test_github_runner_ephemeral_worker_lease import plan

T = retention.epoch('2026-11-09T03:31:00Z')


def fixture():
    client = Client()
    client.job.update(status='completed', conclusion='failure', completed_at='2026-11-09T03:31:00Z',
                      runner_id=876, runner_group_id=95)
    ticket = admission.Ticket(999, 123, 95, 'a' * 40, 'b' * 40, 'd' * 64,
        'heavy', 0, 'lit-heavy-999-1-heavy-0', hashlib.sha256(client.job['name'].encode()).hexdigest())
    return client, ticket


class TerminalTests(unittest.TestCase):
    def test_exact_terminal_cell_does_not_require_moving_branch_or_empty_group(self):
        client, ticket = fixture()
        client.main['commit']['sha'] = 'f' * 40
        client.runners['total_count'] = 1
        value = retention.terminal(client, ticket, now=T+1)
        self.assertEqual(value['completed_at'], T)
        self.assertEqual(value['conclusion'], 'failure')
        self.assertEqual(len(client.calls), 3)
        self.assertFalse(any('branches' in path or 'runner-groups' in path for path in client.calls))

    def test_nonterminal_rerun_wrong_source_or_job_never_seal(self):
        client, ticket = fixture()
        for field, value in [('status', 'in_progress'), ('run_id', 1000), ('run_attempt', 2),
                             ('head_sha', 'f'*40), ('name', 'Foreign cell'), ('runner_group_id', 96),
                             ('conclusion', 'unknown'), ('conclusion', {}), ('runner_group_id', True)]:
            candidate = copy.deepcopy(client)
            candidate.job[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(lease.Held):
                retention.terminal(candidate, ticket, now=T+1)

    def test_foreign_repository_actor_request_and_callee_are_rejected(self):
        client, ticket = fixture()
        for field, value in [('display_title', 'another request'), ('actor', {}),
                             ('repository', {}), ('referenced_workflows', [])]:
            candidate = copy.deepcopy(client); candidate.run[field] = value
            with self.subTest(field=field), self.assertRaises(lease.Held):
                retention.terminal(candidate, ticket, now=T+1)

    def test_future_or_malformed_completion_time_is_not_a_terminal_receipt(self):
        client, ticket = fixture()
        for value in ['2026-11-09T03:32:00Z', '2026-11-9T03:31:00Z', None, True, '']:
            client.job['completed_at'] = value
            with self.subTest(value=value), self.assertRaises(lease.Held):
                retention.terminal(client, ticket, now=T+1)


@unittest.skipUnless(os.geteuid() == 0, 'Root retention sidecar')
class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.store = lease.Store(self.path); self.addCleanup(self.store.close)
        self.client, self.ticket = fixture()
        claimed = self.store.claim(self.ticket, now=T-60)
        intent = self.store.allocation_intent(claimed['operation'], now=T-59,
            plan=plan(), revalidate=lambda _: None)
        self.observation = {'machine_id': plan()['machine_id'], 'project': plan()['project'],
            'profile_sha256': plan()['profile_sha256'], 'instance': {'name': intent['vm_name'],
            'type': 'virtual-machine', 'status': 'Stopped', 'native_pid': 0, 'profiles': [plan()['profile']],
            'config': {**lease.owner_config(intent), 'volatile.base_image': plan()['image_sha256'],
                       'volatile.uuid': '22222222-2222-4222-8222-222222222222'}}}
        allocated = self.store.bind_allocation(intent['operation'], observe=lambda *a: self.observation)
        self.record = self.store.execute_stop_once(allocated['operation'], observe=lambda *a: self.observation,
            execute=lambda _: self.fail('stopped fixture must not mutate'))
        self.gate = retention.Retention(self.store, custodian_reference='synthetic:owner-not-real-approval')
        self.sidecar = self.path / ('retention-'+self.record['operation']+'.json')

    def seal(self):
        return self.gate.seal_terminal(self.record['operation'], client=self.client, now=T+1)

    def authorize(self, now, **changes):
        return self.gate.authorize(self.record, now=now,
            verify_evidence=changes.get('verify_evidence', lambda _: True))

    def test_four_hour_failure_retention_and_evidence_gate_never_release_capacity(self):
        receipt = self.seal(); self.assertEqual(receipt['retain_until'], T+14400)
        with self.assertRaisesRegex(lease.Held, 'retention-window-open'):
            self.authorize(T+14399, verify_evidence=lambda _: self.fail('too early'))
        for value in [False, 1, None]:
            with self.subTest(value=value), self.assertRaisesRegex(lease.Held, 'private-evidence-not-verified'):
                self.authorize(T+14400, verify_evidence=lambda _: value)
        self.assertTrue(self.authorize(T+14400))
        with self.assertRaises(lease.Held): self.store.claim(self.ticket, now=T+90000)

    def test_success_can_cleanup_after_evidence_but_missing_receipt_cannot(self):
        with self.assertRaises(lease.Held): self.authorize(T+1)
        self.client.job['conclusion'] = 'success'
        self.assertEqual(self.seal()['retain_until'], T)
        self.assertTrue(self.authorize(T+1))

    def test_terminal_reseal_is_idempotent_and_cannot_change_outcome(self):
        self.seal(); before = self.sidecar.read_bytes()
        self.assertEqual(self.seal(), json.loads(before)); self.assertEqual(self.sidecar.read_bytes(), before)
        self.client.job['conclusion'] = 'success'
        with self.assertRaisesRegex(lease.Held, 'terminal-receipt-drift'): self.seal()
        self.assertEqual(self.sidecar.read_bytes(), before)

    def test_extension_requires_exact_custodian_backend_and_cannot_exceed_24_hours(self):
        self.seal(); requests = []
        def approve(value): requests.append(value); return True
        for value in [False, None, 1]:
            with self.assertRaisesRegex(lease.Held, 'custodian-extension-not-approved'):
                self.gate.extend(self.record['operation'], now=T+100, until=T+20000,
                    approval_reference='fixture:decision', approve=lambda _: value)
        with self.assertRaisesRegex(lease.Held, 'retention-extension-window'):
            self.gate.extend(self.record['operation'], now=T+100, until=T+86401,
                approval_reference='fixture:decision', approve=approve)
        self.assertEqual(requests, [])
        value = self.gate.extend(self.record['operation'], now=T+100, until=T+86400,
            approval_reference='fixture:decision', approve=approve)
        self.assertEqual(value['retain_until'], T+86400)
        self.assertEqual(requests[0]['vm_uuid'], self.record['vm_uuid'])
        self.assertEqual(requests[0]['custodian_reference'], self.gate.custodian)
        with self.assertRaises(lease.Held): self.authorize(T+86399)
        self.assertTrue(self.authorize(T+86400))

    def test_shortened_window_wrong_uuid_or_duplicate_json_holds(self):
        self.seal(); original = self.sidecar.read_text()
        for field, value in [('retain_until', T), ('vm_uuid', '33333333-3333-4333-8333-333333333333')]:
            candidate = json.loads(original); candidate[field] = value
            self.sidecar.write_text(json.dumps(candidate))
            with self.subTest(field=field), self.assertRaises(lease.Held): self.authorize(T+90000)
        self.sidecar.write_text(original.rstrip()[:-1]+',"schema":1}')
        with self.assertRaises(lease.Held): self.authorize(T+90000)

    def test_symlink_hardlink_or_public_receipt_is_not_accepted(self):
        self.seal(); self.sidecar.chmod(0o644)
        with self.assertRaises(lease.Held): self.authorize(T+90000)
        self.sidecar.chmod(0o600)
        os.link(self.sidecar, self.path/'alias')
        with self.assertRaises(lease.Held): self.authorize(T+90000)
        (self.path/'alias').unlink(); self.sidecar.rename(self.path/'original')
        self.sidecar.symlink_to(self.path/'original')
        with self.assertRaises(OSError): self.authorize(T+90000)

    def test_failed_terminal_fsync_never_authorizes_deletion(self):
        with patch('os.fsync', side_effect=OSError('synthetic fsync')):
            with self.assertRaises(OSError): self.seal()
        self.assertFalse(self.sidecar.exists())
        with self.assertRaises(lease.Held): self.authorize(T+90000)

    def test_gate_runs_inside_real_delete_fence_without_deadlock_or_release(self):
        self.seal(); calls = []
        def effect(value):
            self.assertEqual(self.store._read()['phase'], 'DELETE_DISPATCH_INTENT')
            self.assertTrue(self.authorize(T+14400))
            calls.append(value)
            return 0
        result = self.store.execute_delete_once(self.record['operation'],
            authorize=lambda r: self.gate.authorize(r, now=T+14400, verify_evidence=lambda _: True),
            observe=lambda *a: self.observation, execute=effect,
            absent=lambda *a: True)
        self.assertEqual(result['phase'], 'REMOVED'); self.assertEqual(len(calls), 1)
        with self.assertRaises(lease.Held): self.store.claim(self.ticket, now=T+90000)


if __name__ == '__main__':
    unittest.main()
