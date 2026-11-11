"""Execute the real role with a deterministic Incus CLI fixture, not a daemon.

This proves task ordering/arguments and refusal after an uncertain create. It
does not qualify Incus/KVM, a worker image or the complete external controller.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = r'''
import json, os, sys
from pathlib import Path
p = Path(__file__).parent
args = sys.argv[1:]
if args[:1] == ['--force-local']:
    args = args[1:]
if args[:1] == ['--project']:
    args = args[2:]
with (p / 'commands.jsonl').open('a') as output:
    output.write(json.dumps(args) + '\n')
mode = (p / 'mode').read_text()
state = json.loads((p / 'state.json').read_text())
if args[:1] == ['info']:
    sys.exit(0 if state else 1)
if args[:1] == ['list']:
    if mode == 'list-failure':
        sys.exit(2)
    if mode == 'invalid-list':
        print('{}')
    else:
        print(json.dumps([state] if state else []))
    sys.exit(0)
if args[:2] == ['image', 'info']:
    sys.exit(0)
if args[:1] == ['init']:
    if state:
        sys.exit(3)
    config = {}
    for index, arg in enumerate(args):
        if arg == '--config':
            key, value = args[index + 1].split('=', 1)
            config[key] = value
    state = {'name': args[2], 'status': 'Stopped', 'config': config}
    state.update(type='virtual-machine', profiles=['qualified-worker']
                 if '--profile=qualified-worker' in args else [])
    state['config'].update({'volatile.base_image': args[1],
                            'volatile.uuid': '22222222-2222-4222-8222-222222222222'})
    (p / 'state.json').write_text(json.dumps(state))
    sys.exit(2 if mode == 'lost-create-reply' else 0)
if args[:2] == ['config', 'get']:
    print(state['config'].get(args[3], ''))
    sys.exit(0)
sys.exit(99)
'''


class CreateOnlyRoleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.cli = self.directory / 'incus-fixture'
        self.cli.write_text('#!' + sys.executable + '\n' + FIXTURE)
        self.cli.chmod(0o700)
        (self.directory / 'mode').write_text('normal')
        self.state = self.directory / 'state.json'
        self.state.write_text('null')
        collection = self.directory / 'collections/ansible_collections/lit/ubuntu'
        collection.parent.mkdir(parents=True)
        collection.symlink_to(ROOT, target_is_directory=True)
        self.environment = dict(os.environ, ANSIBLE_COLLECTIONS_PATH=str(self.directory / 'collections'),
                                ANSIBLE_LOCAL_TEMP=str(self.directory / 'ansible-local'),
                                ANSIBLE_REMOTE_TEMP=str(self.directory / 'ansible-remote'),
                                ANSIBLE_NOCOLOR='1')

    def run_role(self, *, controller_inputs=None, **overrides):
        item = {'name': 'fresh-worker', 'image': 'a' * 64, 'type': 'vm', 'state': 'present',
                'profiles': [], 'create_only': True, 'cloud_init_enabled': False,
                'config': {'user.controller-operation': 'b' * 32}, **overrides}
        play = [{'name': 'Exercise create-only role boundary', 'hosts': 'all', 'gather_facts': False,
                 'vars': {'ansible_python_interpreter': sys.executable,
                          'incus_instance_items': [item], **(controller_inputs or {}),
                          # Only the native CLI transport is translated to the fixture.
                          'incus_instance_binary': str(self.cli)},
                 'roles': ['lit.ubuntu.incus_instance']}]
        book = self.directory / 'play.yml'
        book.write_text(yaml.safe_dump(play))
        result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(book)],
                                cwd=self.directory, env=self.environment, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
        return result

    def commands(self):
        path = self.directory / 'commands.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_owner_marker_is_in_the_initial_stopped_vm_request(self):
        result = self.run_role()
        self.assertEqual(result.returncode, 0, result.stdout)
        commands = self.commands()
        creation = next(c for c in commands if c[0] == 'init')
        self.assertIn('--vm', creation)
        self.assertIn('--no-profiles', creation)
        self.assertEqual(creation[creation.index('--config') + 1], 'user.controller-operation=' + 'b' * 32)
        self.assertLess(commands.index(['list', '--format', 'json']), commands.index(creation))
        self.assertFalse(any(c[0] in {'start', 'delete'} or c[:2] == ['config', 'set'] for c in commands))
        self.assertEqual(json.loads(self.state.read_text())['status'], 'Stopped')

    def test_matching_existing_resource_is_refused_without_any_mutation(self):
        existing = {'name': 'fresh-worker', 'status': 'Stopped',
                    'config': {'user.controller-operation': 'b' * 32}}
        self.state.write_text(json.dumps(existing))
        result = self.run_role()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.state.read_text()), existing)
        self.assertTrue(all(c[0] in {'info', 'list'} for c in self.commands()))

    def test_failed_or_malformed_native_inventory_cannot_authorize_creation(self):
        for mode in ['list-failure', 'invalid-list']:
            with self.subTest(mode=mode):
                (self.directory / 'mode').write_text(mode)
                result = self.run_role()
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(json.loads(self.state.read_text()))
                self.assertTrue(all(c[0] in {'info', 'list'} for c in self.commands()))

    def test_lost_create_reply_stops_and_a_second_invocation_refuses_adoption(self):
        (self.directory / 'mode').write_text('lost-create-reply')
        first = self.run_role()
        self.assertNotEqual(first.returncode, 0)
        self.assertIsNotNone(json.loads(self.state.read_text()))
        first_commands = self.commands()
        self.assertEqual(first_commands[-1][0], 'init')
        (self.directory / 'mode').write_text('normal')
        second = self.run_role()
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual(sum(c[0] == 'init' for c in self.commands()), 1)

    def test_create_only_cannot_start_delete_or_reconfigure(self):
        for override in [{'state': 'running'}, {'state': 'absent'}, {'reconfigure': True}]:
            with self.subTest(override=override):
                result = self.run_role(**override)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.commands(), [])

    def controller(self):
        sys.path.insert(0, str(ROOT / 'roles/github_runner/files'))
        import ephemeral_worker_admission as admission
        import ephemeral_worker_lease as lease
        private = self.directory / 'controller'
        private.mkdir(mode=0o700)
        store = lease.Store(private)
        self.addCleanup(store.close)
        ticket = admission.Ticket(999, 123, 95, 'a' * 40, 'b' * 40, 'c' * 64,
                                  'heavy', 0, 'lit-heavy-999-1-heavy-0', 'd' * 64)
        policy = {'machine_id': 'e' * 32, 'project': 'isolated-heavy', 'image_sha256': 'f' * 64,
                  'profile': 'qualified-worker', 'profile_sha256': '1' * 64}
        claim = store.claim(ticket, now=100)
        record = store.allocation_intent(claim['operation'], now=101, plan=policy, revalidate=lambda value: None)
        return lease, store, policy, record

    def through_provider(self, store, policy, record):
        def execute(variables):
            on_disk = json.loads((self.directory / 'controller/active.json').read_bytes())
            self.assertEqual(on_disk['phase'], 'ALLOCATION_DISPATCH_INTENT')
            self.assertEqual(variables['incus_instance_binary'], '/usr/bin/incus')
            self.assertTrue(variables['incus_instance_force_local'])
            result = self.run_role(controller_inputs=variables)
            # This is the actual Ansible exit status, not a fabricated native receipt.
            return result.returncode
        def observe(name, selected):
            self.assertEqual(name, record['vm_name'])
            self.assertEqual(selected, policy)
            return {'machine_id': policy['machine_id'], 'project': policy['project'],
                    'profile_sha256': policy['profile_sha256'], 'instance': json.loads(self.state.read_text())}
        return store.execute_allocation_once(record['operation'], now=102, revalidate=lambda value: None,
            qualify=lambda selected: {key: selected[key] for key in ('machine_id','project','profile_sha256')},
            execute=execute, observe=observe)

    @unittest.skipUnless(os.geteuid() == 0, 'Root store required; role-only cases still run nonroot')
    def test_persisted_ticket_drives_real_role_and_native_fixture_uuid_binding(self):
        lease, store, policy, record = self.controller()
        bound = self.through_provider(store, policy, record)
        self.assertEqual(bound['phase'], 'ALLOCATED')
        self.assertEqual(bound['vm_uuid'], '22222222-2222-4222-8222-222222222222')
        self.assertEqual(sum(c[0] == 'init' for c in self.commands()), 1)
        self.assertFalse(any(c[0] in {'start', 'delete'} for c in self.commands()))
        before = list(self.commands())
        with self.assertRaisesRegex(lease.Held, 'dispatch-not-fresh'):
            self.through_provider(store, policy, record)
        self.assertEqual(self.commands(), before)
        with self.assertRaisesRegex(lease.Held, 'capacity-held'):
            store.claim(lease.admission.Ticket(**record['ticket']), now=10000)

    @unittest.skipUnless(os.geteuid() == 0, 'Root store required; role-only cases still run nonroot')
    def test_real_role_uncertain_create_is_held_without_another_role_invocation(self):
        lease, store, policy, record = self.controller()
        (self.directory / 'mode').write_text('lost-create-reply')
        with self.assertRaisesRegex(lease.Held, 'provider-outcome-unknown'):
            self.through_provider(store, policy, record)
        self.assertEqual(store.status()['phase'], 'ALLOCATION_DISPATCH_INTENT')
        self.assertIsNotNone(json.loads(self.state.read_text()))
        before = list(self.commands())
        with self.assertRaisesRegex(lease.Held, 'dispatch-not-fresh'):
            self.through_provider(store, policy, record)
        self.assertEqual(self.commands(), before)
        self.assertEqual(sum(c[0] == 'init' for c in self.commands()), 1)
        with self.assertRaisesRegex(lease.Held, 'allocation-intent-required'):
            store.bind_allocation(record['operation'], observe=lambda *args: self.fail('unknown allocation adoption'))


if __name__ == '__main__':
    unittest.main()
