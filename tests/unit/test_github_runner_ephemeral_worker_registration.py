"""Real private journal/fence fixtures; native transports are explicit doubles."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'roles/github_runner/files'))
import ephemeral_worker_admission as A
import ephemeral_worker_lease as L
import ephemeral_worker_registration as R


class BoundaryTests(unittest.TestCase):
    def test_policy_rejects_unbounded_or_ambiguous_inputs(self):
        for policy in (R.Policy('', 100000, 100000), R.Policy('custodian\n', 100000, 100000),
                       R.Policy('custodian', True, 100000), R.Policy('custodian', 100000, 2**32)):
            with self.assertRaises(L.Held):
                policy.check()

    def test_nonroot_cannot_create_registration_state(self):
        if os.geteuid() == 0:
            self.skipTest('nonroot consumer only')
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(L.Held, 'root-controller-required'):
                L.Store(directory)
            self.assertEqual(list(Path(directory).iterdir()), [])


@unittest.skipUnless(os.geteuid() == 0, 'Root private controller filesystem')
class RegistrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        self.store = L.Store(self.path)
        self.addCleanup(self.store.close)
        self.policy = R.Policy('test:accepted-custodian', 100000, 200000)
        self.registration = R.Registration(self.store, self.policy)
        ticket = A.Ticket(999, 123, 95, 'a' * 40, 'b' * 40, 'c' * 64,
                          'heavy', 0, 'lit-heavy-999-1-heavy-0', 'd' * 64)
        record = self.store.claim(ticket, now=100, duration=1000)
        plan = {'machine_id': 'e' * 32, 'project': 'isolated-heavy', 'image_sha256': 'f' * 64,
                'profile': 'qualified-worker', 'profile_sha256': '1' * 64}
        self.record = self.store.allocation_intent(record['operation'], now=101, plan=plan,
                                                  revalidate=lambda ticket: None)
        self.record = self.store.bind_allocation(record['operation'], observe=lambda *a: self.observed('Stopped'))
        self.record = self.store.execute_start_once(record['operation'], now=102,
            revalidate=lambda ticket: None,
            qualify=lambda plan: {k: plan[k] for k in ('machine_id', 'project', 'profile_sha256')},
            observe=lambda *a: self.observed('Stopped' if self.store._read()['phase'] == 'ALLOCATED' else 'Running'),
            execute=lambda value: 0)
        self.filename = self.path / ('registration-' + record['operation'] + '.json')
        self.before = (self.path / 'active.json').read_bytes()
        self.calls = []

    def observed(self, status='Running'):
        record = self.store._read()
        return {**{k: record['plan'][k] for k in ('machine_id', 'project', 'profile_sha256')},
                'instance': {'name': record['vm_name'], 'type': 'virtual-machine', 'status': status,
                             'native_pid': 455 if status == 'Running' else 0,
                             'profiles': [record['plan']['profile']], 'config': {
                                 **L.owner_config(record), 'volatile.base_image': record['plan']['image_sha256'],
                                 'volatile.uuid': '22222222-2222-4222-8222-222222222222'}}}

    def proof(self):
        return {'vm_uuid': self.record['vm_uuid'], 'operation_reference': 'g06-worker:' + self.record['operation'],
                'runner_id': 1234, 'runner_name': self.record['vm_name'], 'ephemeral': True,
                'service_state': 'stopped', 'service_start_issued': False, 'manifest_sha256': '5' * 64}

    def get(self, path):
        ticket = self.record['ticket']
        base = 'orgs/ltn-it/actions/runner-groups/95'
        row = {'id': 1234, 'name': self.record['vm_name'], 'os': 'linux', 'status': 'offline', 'busy': False,
               'labels': [{'name': name} for name in sorted(A.BASE_LABELS | {ticket['affinity_label']})]}
        replies = {base: {'id': 95, 'name': A.GROUP_NAME, 'inherited': False, 'default': False,
                         'visibility': 'selected', 'allows_public_repositories': True,
                         'restricted_to_workflows': True,
                         'selected_workflows': [f'{A.REPOSITORY}/{A.CALLEE}@' + ticket['callee_sha']]},
                   base + '/repositories?per_page=100&page=1': {
                       'total_count': 1, 'repositories': [{'id': A.REPOSITORY_ID}]},
                   base + '/runners?per_page=100&page=1': {'total_count': 1, 'runners': [row]},
                   'orgs/ltn-it/actions/runners/1234': row}
        return copy.deepcopy(replies[path])

    def execute(self, record, variables):
        self.calls.append((record, variables))
        self.assertEqual(json.loads(self.filename.read_bytes())['phase'], 'DISPATCH_INTENT')
        with self.assertRaisesRegex(L.Held, 'another-controller-active'):
            with self.store.exclusive():
                pass
        return 0

    def run_registration(self, **overrides):
        dependencies = {'now': 110, 'revalidate': lambda ticket: self.assertEqual(ticket.job_id, 123),
                        'observe': lambda *a: self.observed(), 'execute': self.execute,
                        'inspect_guest': lambda *a: self.proof(), 'github': self}
        return self.registration.execute_once(self.record['operation'], **{**dependencies, **overrides})

    def test_closed_role_selection_and_durable_success_preserve_global_fence(self):
        result = self.run_registration()
        self.assertEqual(result['phase'], 'REGISTERED_STOPPED')
        self.assertEqual(result['guest']['runner_id'], 1234)
        self.assertEqual((self.path / 'active.json').read_bytes(), self.before)
        self.assertEqual(self.filename.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(self.calls), 1)
        variables = self.calls[0][1]
        instance, = variables['github_runner_instances']
        self.assertTrue(instance['ephemeral'])
        self.assertEqual(instance['service_state'], 'stopped')
        self.assertEqual(instance['expected_guest_uuid'], self.record['vm_uuid'])
        self.assertEqual(instance['runner_group'], A.GROUP_NAME)
        self.assertEqual(set(instance['labels']), A.BASE_LABELS | {'lit-heavy-999-1-heavy-0'})
        self.assertNotIn('token', json.dumps(variables))
        self.assertNotIn('credentials', self.filename.read_text())
        with self.assertRaisesRegex(L.Held, 'already-dispatched'):
            self.run_registration()
        self.assertEqual(len(self.calls), 1)

    def test_lost_response_or_nonzero_leaves_intent_and_never_retries(self):
        def lost(record, variables):
            self.execute(record, variables)
            raise TimeoutError('synthetic lost native reply')
        with self.assertRaises(TimeoutError):
            self.run_registration(execute=lost)
        saved = self.filename.read_bytes()
        self.assertEqual(json.loads(saved)['phase'], 'DISPATCH_INTENT')
        with self.assertRaisesRegex(L.Held, 'already-dispatched'):
            self.run_registration()
        self.assertEqual(self.filename.read_bytes(), saved)
        self.assertEqual(len(self.calls), 1)

    def test_boolean_exit_is_unknown_not_success(self):
        with self.assertRaisesRegex(L.Held, 'native-outcome-unknown'):
            self.run_registration(execute=lambda *a: False)
        self.assertEqual(json.loads(self.filename.read_bytes())['phase'], 'DISPATCH_INTENT')

    def test_stale_ticket_or_expired_window_denies_before_dispatch(self):
        def stale(ticket):
            raise A.Denied('native job changed')
        with self.assertRaises(A.Denied):
            self.run_registration(revalidate=stale)
        with self.assertRaisesRegex(L.Held, 'registration-window'):
            self.run_registration(now=1100)
        self.assertFalse(self.filename.exists())
        self.assertEqual(self.calls, [])

    def test_replaced_uuid_or_stopped_native_vm_denies_before_dispatch(self):
        for kind in ('replaced', 'stopped', 'pid'):
            observed = self.observed('Stopped' if kind == 'stopped' else 'Running')
            if kind == 'replaced':
                observed['instance']['config']['volatile.uuid'] = '33333333-3333-4333-8333-333333333333'
            if kind == 'pid':
                observed['instance']['native_pid'] = 0
            with self.subTest(kind=kind), self.assertRaises(L.Held):
                self.run_registration(observe=lambda *a: observed)
        self.assertFalse(self.filename.exists())
        self.assertEqual(self.calls, [])

    def test_guest_mismatch_retains_executed_without_replay(self):
        proof = self.proof(); proof['service_start_issued'] = True
        with self.assertRaisesRegex(L.Held, 'guest-binding'):
            self.run_registration(inspect_guest=lambda *a: proof)
        self.assertEqual(json.loads(self.filename.read_bytes())['phase'], 'EXECUTED')
        with self.assertRaisesRegex(L.Held, 'already-dispatched'):
            self.run_registration()
        self.assertEqual(len(self.calls), 1)

    def test_wrong_group_policy_membership_or_labels_deny_completion(self):
        for target, change in [('group', {'visibility': 'all'}), ('members', {'total_count': 2}),
                               ('runner', {'labels': []}), ('runner', {'busy': True})]:
            class Client:
                def get(inner, path):
                    value = self.get(path)
                    if ((target == 'group' and path.endswith('/95')) or
                        (target == 'members' and '/runners?' in path) or
                        (target == 'runner' and path.endswith('/1234'))):
                        value.update(change)
                    return value
            with self.subTest(target=target), self.assertRaises(A.Denied):
                R.github_proof(Client(), self.record, self.proof())

    def test_input_derivation_rejects_unstarted_or_forged_lease(self):
        for field, value in [('phase', 'STOPPED'), ('operation', '../../foreign')]:
            changed = copy.deepcopy(self.record); changed[field] = value
            with self.subTest(field=field), self.assertRaises(L.Held):
                R.variables(changed, self.policy)
        self.assertFalse(self.filename.exists())

    def test_executor_cannot_rewrite_selected_inputs_or_lease_record(self):
        def mutate(record, selected):
            self.execute(record, selected)
            record['vm_uuid'] = '33333333-3333-4333-8333-333333333333'
            selected['github_runner_instances'][0]['service_state'] = 'started'
            return 0
        result = self.run_registration(execute=mutate)
        self.assertEqual(result['vm_uuid'], self.record['vm_uuid'])
        self.assertEqual((self.path / 'active.json').read_bytes(), self.before)

    def test_journal_symlink_never_adopted_and_foreign_file_unchanged(self):
        foreign = self.path / 'foreign'; foreign.write_text('preserve')
        self.filename.symlink_to(foreign)
        with self.assertRaises(OSError):
            self.run_registration()
        self.assertEqual(foreign.read_text(), 'preserve')
        self.assertEqual(self.calls, [])
