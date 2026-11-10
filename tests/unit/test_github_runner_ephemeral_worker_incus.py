"""Real Unix HTTP/peer/filesystem checks against fixture replies, not Incus/KVM."""
import copy
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import socketserver
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'roles/github_runner/files'))
import ephemeral_worker_admission as admission
import ephemeral_worker_lease as lease
import ephemeral_worker_incus as native


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.calls.append(('GET', self.path))
        index = len(self.server.calls)
        status, value = self.server.reply(self.path, index)
        raw = value if type(value) is bytes else json.dumps({
            'type': 'sync', 'status_code': 200, 'metadata': value}).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except BrokenPipeError:
            pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.calls.append(('POST', self.path))
        self.server.bodies.append(body)
        reply = self.server.post_reply(self.path, body)
        if reply is None:
            self.close_connection = True
            return
        status, value = reply
        raw = value if type(value) is bytes else json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_PUT(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.calls.append(('PUT', self.path))
        self.server.bodies.append(body)
        reply = self.server.put_reply(self.path, body)
        if reply is None:
            self.close_connection = True
            return
        status, value = reply
        raw = value if type(value) is bytes else json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_DELETE(self):
        self.server.calls.append(('DELETE', self.path))
        self.server.bodies.append(None)
        reply = self.server.delete_reply(self.path)
        if reply is None:
            self.close_connection = True
            return
        status, value = reply
        raw = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_args):
        pass


class PrivilegeTests(unittest.TestCase):
    def test_nonroot_is_refused_before_any_path_access(self):
        if os.geteuid() != 0:
            with self.assertRaisesRegex(lease.Held, 'native-inventory-root-required'):
                native.Inventory('/not-present/socket', '/not-present/machine-id')


@unittest.skipUnless(os.geteuid() == 0, 'Root-local peer adapter; nonroot refusal tested separately')
class NativeInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.machine = self.directory / 'machine-id'
        self.machine.write_text('e' * 32 + '\n')
        self.profile = {'name': 'qualified-worker', 'config': {}, 'devices': {
            'root': {'type': 'disk', 'pool': 'private-worker', 'path': '/', 'size': '32GiB'}},
            'used_by': []}
        self.plan = {'machine_id': 'e' * 32, 'project': 'isolated-heavy', 'image_sha256': 'f' * 64,
                     'profile': self.profile['name'], 'profile_sha256': native.profile_digest(self.profile, self.profile['name'])}
        self.instance = {'name': 'g06-heavy-' + 'a' * 32, 'type': 'virtual-machine', 'status': 'Stopped',
                         'profiles': [self.profile['name']], 'config': {
                             'cloud-init.user-data': 'fixture-sensitive-data', 'volatile.base_image': 'f' * 64,
                             'boot.autostart': 'false',
                             'volatile.uuid': '22222222-2222-4222-8222-222222222222',
                             'user.lit.worker-operation': 'a' * 32, 'user.lit.worker-ticket': 'b' * 64}}
        self.path = self.directory / 'incus.sock'
        self.server = socketserver.UnixStreamServer(str(self.path), Handler)
        self.path.chmod(0o600)
        self.server.calls = []
        self.server.reply = self.reply
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01})
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.client = native.Inventory(self.path, self.machine)
        self.addCleanup(self.client.close)

    def stop_server(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def reply(self, path, _index):
        if path == '/1.0/profiles/qualified-worker?project=isolated-heavy':
            return 200, self.profile
        if path == '/1.0/images/' + 'f' * 64 + '?project=isolated-heavy':
            return 200, {'fingerprint': 'f' * 64, 'type': 'virtual-machine', 'architecture': 'x86_64'}
        if path == '/1.0/instances/' + self.instance['name'] + '?project=isolated-heavy':
            return 200, self.instance
        return 404, b'not present'

    def test_actual_unix_peer_http_and_narrow_observation_never_use_tcp(self):
        with patch('socket.create_connection', side_effect=AssertionError('TCP forbidden')):
            observed = self.client.observe(self.instance['name'], self.plan)
        self.assertEqual(observed['machine_id'], self.plan['machine_id'])
        self.assertEqual(observed['instance']['config']['volatile.uuid'],
                         self.instance['config']['volatile.uuid'])
        self.assertNotIn('fixture-sensitive-data', json.dumps(observed))
        self.assertEqual([method for method, path in self.server.calls], ['GET'] * 4)

    def test_real_native_adapter_is_the_callback_for_durable_uuid_binding(self):
        private = self.directory / 'controller'
        private.mkdir(mode=0o700)
        store = lease.Store(private)
        self.addCleanup(store.close)
        ticket = admission.Ticket(999, 123, 95, 'a' * 40, 'b' * 40, 'c' * 64,
                                  'heavy', 0, 'lit-heavy-999-1-heavy-0', 'd' * 64)
        claim = store.claim(ticket, now=100)
        store.allocation_intent(claim['operation'], now=101, plan=self.plan, revalidate=lambda value: None)
        self.instance['name'] = claim['vm_name']
        self.instance['config'].update(lease.owner_config(store.status()))
        bound = store.bind_allocation(claim['operation'], observe=self.client.observe)
        self.assertEqual(bound['phase'], 'ALLOCATED')
        self.assertEqual(bound['vm_uuid'], self.instance['config']['volatile.uuid'])
        with self.assertRaisesRegex(lease.Held, 'capacity-held'):
            store.claim(ticket, now=10000)

    def test_profile_membership_changes_do_not_hide_config_drift(self):
        self.profile['used_by'] = ['/1.0/instances/other']
        self.assertEqual(self.client.qualify(self.plan)['profile_sha256'], self.plan['profile_sha256'])
        self.profile['config']['limits.memory'] = '1GiB'
        with self.assertRaisesRegex(lease.Held, 'native-profile-drift'):
            self.client.qualify(self.plan)

    def test_profile_change_during_instance_observation_is_refused(self):
        def changed(path, index):
            if index == 4:
                value = copy.deepcopy(self.profile)
                value['config']['limits.cpu'] = '8'
                return 200, value
            return self.reply(path, index)
        self.server.reply = changed
        with self.assertRaisesRegex(lease.Held, 'native-profile-drift'):
            self.client.observe(self.instance['name'], self.plan)

    def test_image_container_and_wrong_fingerprint_are_refused(self):
        for bad in [{'fingerprint': 'f' * 64, 'type': 'container', 'architecture': 'x86_64'},
                    {'fingerprint': '0' * 64, 'type': 'virtual-machine', 'architecture': 'x86_64'}]:
            def reply(path, index):
                return (200, bad) if '/images/' in path else self.reply(path, index)
            self.server.reply = reply
            with self.assertRaisesRegex(lease.Held, 'native-image-identity'):
                self.client.qualify(self.plan)

    def test_missing_malformed_duplicate_oversized_and_redirect_responses_are_not_retried(self):
        for status, value in [(404, b'missing'), (302, b'redirect'), (200, b'not-json'),
                              (200, b'{"type":"sync","type":"sync"}'),
                              (200, b'x' * (native.MAX_BYTES + 1))]:
            self.server.calls.clear()
            self.server.reply = lambda path, index: (status, value)
            with self.subTest(status=status, size=len(value)), self.assertRaises(lease.Held):
                self.client.qualify(self.plan)
            self.assertEqual(len(self.server.calls), 1)

    def test_missing_cached_image_preserves_safe_status_without_response_payload(self):
        def missing(path, index):
            return (404, b'fixture-sensitive-error') if '/images/' in path else self.reply(path, index)
        self.server.reply = missing
        with self.assertRaisesRegex(lease.Held, '^native-api-http-status-404$'):
            self.client.qualify(self.plan)
        self.assertEqual(len(self.server.calls), 2)

    def test_changed_machine_or_replaced_socket_refuses_before_request(self):
        self.machine.write_text('0' * 32 + '\n')
        with self.assertRaises(lease.Held):
            self.client.qualify(self.plan)
        self.assertEqual(self.server.calls, [])
        self.machine.write_text('e' * 32 + '\n')
        self.path.rename(self.directory / 'original.sock')
        self.path.write_text('foreign')
        with self.assertRaises(lease.Held):
            self.client.qualify(self.plan)
        self.assertEqual(self.path.read_text(), 'foreign')
        self.assertEqual(self.server.calls, [])

    def test_link_or_world_writable_socket_is_not_adopted(self):
        self.path.chmod(0o666)
        with self.assertRaisesRegex(lease.Held, 'native-socket-untrusted'):
            native.Inventory(self.path, self.machine)
        self.path.chmod(0o600)
        link = self.directory / 'socket-link'
        link.symlink_to(self.path)
        with self.assertRaisesRegex(lease.Held, 'native-socket-untrusted'):
            native.Inventory(link, self.machine)


@unittest.skipUnless(os.geteuid() == 0, 'Root-local create provider')
class NativeCreateTests(unittest.TestCase):
    setUp = NativeInventoryTests.setUp
    stop_server = NativeInventoryTests.stop_server
    reply = NativeInventoryTests.reply

    def controller(self):
        private = self.directory / 'controller'
        private.mkdir(mode=0o700)
        self.store = lease.Store(private)
        self.addCleanup(self.store.close)
        ticket = admission.Ticket(999, 123, 95, 'a' * 40, 'b' * 40, 'c' * 64,
                                  'heavy', 0, 'lit-heavy-999-1-heavy-0', 'd' * 64)
        self.record = self.store.claim(ticket, now=100)
        self.store.allocation_intent(self.record['operation'], now=101, plan=self.plan,
                                     revalidate=lambda value: None)
        self.provider = native.CreateOnly(self.path, self.machine)
        self.addCleanup(self.provider.close)
        self.server.bodies = []
        self.server.post_reply = self.post_reply
        self.server.reply = self.create_reply
        self.operation_id = '33333333-3333-4333-8333-333333333333'
        self.instance['name'] = self.record['vm_name']
        self.instance['config'].update(lease.owner_config(self.record))
        self.polls = 0

    def operation(self, code=200):
        return {'id': self.operation_id, 'class': 'task', 'status_code': code, 'err': '',
                'resources': {'instances': ['/1.0/instances/' + self.record['vm_name']
                                             + '?project=' + self.plan['project']]}}

    def post_reply(self, path, body):
        self.assertEqual(path, '/1.0/instances?project=isolated-heavy')
        return 202, {'type': 'async', 'status_code': 100,
                     'operation': '/1.0/operations/' + self.operation_id,
                     'metadata': self.operation(103)}

    def create_reply(self, path, index):
        if path == '/1.0/instances?project=isolated-heavy':
            return 200, []
        if path.startswith('/1.0/operations/'):
            self.polls += 1
            return 200, self.operation(103 if self.polls == 1 else 200)
        return self.reply(path, index)

    def allocate(self):
        return self.provider.allocate(self.store, self.record['operation'], now=102,
                                      revalidate=lambda value: None)

    def assert_held_once(self):
        self.assertEqual(self.store.status()['phase'], 'ALLOCATION_DISPATCH_INTENT')
        calls = list(self.server.calls)
        with self.assertRaises(lease.Held):
            self.allocate()
        self.assertEqual(self.server.calls, calls)
        self.assertEqual(len(self.server.bodies), 1)
        with self.assertRaises(lease.Held):
            self.store.bind_allocation(self.record['operation'], observe=self.provider.observe)

    def test_real_unix_post_and_same_operation_poll_bind_uuid_once(self):
        self.controller()
        with patch('socket.create_connection', side_effect=AssertionError('TCP forbidden')):
            result = self.allocate()
        self.assertEqual(result['phase'], 'ALLOCATED')
        self.assertEqual(result['vm_uuid'], self.instance['config']['volatile.uuid'])
        self.assertEqual(self.polls, 2)
        self.assertEqual(self.server.bodies, [{
            'name': self.record['vm_name'], 'type': 'virtual-machine',
            'source': {'type': 'image', 'fingerprint': 'f' * 64},
            'profiles': [self.profile['name']], 'config': lease.owner_config(self.record),
            'start': False, 'ephemeral': False}])
        calls = list(self.server.calls)
        with self.assertRaises(lease.Held):
            self.allocate()
        self.assertEqual(self.server.calls, calls)

    def test_lost_post_reply_never_resubmits_or_adopts(self):
        self.controller()
        self.server.post_reply = lambda path, body: None
        with self.assertRaisesRegex(lease.Held, 'native-read-unavailable'):
            self.allocate()
        self.assert_held_once()

    def test_foreign_or_redirected_receipt_never_followed(self):
        for change in ['path', 'resource', 'id', 'class', 'status', 'error', 'redirect']:
            with self.subTest(change=change):
                # Independent private fence and native fixture for each case.
                self.server.calls.clear()
                if hasattr(self, 'store'):
                    self.store.close()
                    self.store = None
                    # Closed Store cleanup remains idempotent.
                    (self.directory / 'controller/active.json').unlink()
                    (self.directory / 'controller/controller.lock').unlink()
                    (self.directory / 'controller').rmdir()
                self.controller()
                def bad(path, body):
                    status, value = self.post_reply(path, body)
                    if change == 'path':
                        value['operation'] = 'https://foreign.invalid/1.0/operations/' + self.operation_id
                    elif change == 'resource':
                        value['metadata']['resources']['instances'] = ['/1.0/instances/foreign']
                    elif change == 'id':
                        value['metadata']['id'] = '../foreign'
                    elif change == 'class':
                        value['metadata']['class'] = 'websocket'
                    elif change == 'status':
                        value['metadata']['status_code'] = True
                    elif change == 'error':
                        value['metadata']['err'] = 'sensitive fixture failure'
                    else:
                        status = 302
                    return status, value
                self.server.post_reply = bad
                with self.assertRaises(lease.Held) as error:
                    self.allocate()
                self.assertNotIn('sensitive', str(error.exception))
                self.assertEqual(self.polls, 0)
                self.assert_held_once()

    def test_nonempty_project_prevents_post_even_with_matching_owner(self):
        self.controller()
        self.server.reply = lambda path, index: ((200, ['/1.0/instances/' + self.record['vm_name']])
                                                 if path.startswith('/1.0/instances?')
                                                 else self.create_reply(path, index))
        with self.assertRaisesRegex(lease.Held, 'native-project-not-empty'):
            self.allocate()
        self.assertEqual(self.server.bodies, [])

    def test_operation_failure_after_post_holds_without_second_post(self):
        self.controller()
        def reply(path, index):
            return (200, self.operation(400)) if '/operations/' in path else self.create_reply(path, index)
        self.server.reply = reply
        with self.assertRaisesRegex(lease.Held, 'native-operation-not-successful'):
            self.allocate()
        self.assert_held_once()

    def test_pending_operation_deadline_holds_without_second_post(self):
        self.controller()
        clock = [0]
        def reply(path, index):
            if '/operations/' in path:
                clock[0] = 121
                return 200, self.operation(103)
            return self.create_reply(path, index)
        self.server.reply = reply
        with patch.object(native.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(lease.Held, 'native-operation-timeout'):
                self.allocate()
        self.assert_held_once()

    def test_slow_final_native_image_read_cannot_dispatch_create_after_deadline(self):
        self.controller(); clock = [0]; reads = []
        def delayed(path, index):
            value = self.create_reply(path, index)
            if path.startswith('/1.0/images/'):
                reads.append(path)
                if len(reads) == 3: clock[0] = 10000
            return value
        self.server.reply = delayed
        with patch.object(native.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(lease.Held, 'native-create-window'): self.allocate()
        self.assertEqual(self.server.bodies, [])
        self.assertEqual(self.store.status()['phase'], 'ALLOCATION_DISPATCH_INTENT')

    def test_profile_drift_at_final_qualification_prevents_post(self):
        self.controller()
        def drift(path, index):
            if index == 6:
                value = copy.deepcopy(self.profile)
                value['config']['limits.cpu'] = '100'
                return 200, value
            return self.create_reply(path, index)
        self.server.reply = drift
        with self.assertRaisesRegex(lease.Held, 'native-profile-drift'):
            self.allocate()
        self.assertEqual(len(self.server.calls), 6)
        self.assertEqual(self.server.bodies, [])

    def test_poll_wrong_operation_scope_never_binds(self):
        self.controller()
        def wrong(path, index):
            if '/operations/' in path:
                value = self.operation()
                value['id'] = '44444444-4444-4444-8444-444444444444'
                return 200, value
            return self.create_reply(path, index)
        self.server.reply = wrong
        with self.assertRaisesRegex(lease.Held, 'native-operation-identity'):
            self.allocate()
        self.assert_held_once()

    def test_cancellation_prevents_all_provider_calls(self):
        self.controller()
        def cancelled(_ticket):
            raise lease.Held('native-job-cancelled')
        with self.assertRaisesRegex(lease.Held, 'native-job-cancelled'):
            self.provider.allocate(self.store, self.record['operation'], now=102, revalidate=cancelled)
        self.assertEqual(self.server.calls, [])
        self.assertEqual(self.store.status()['phase'], 'ALLOCATION_INTENT')


@unittest.skipUnless(os.geteuid() == 0, 'Root-local one-shot start provider')
class NativeStartTests(unittest.TestCase):
    setUp = NativeInventoryTests.setUp
    stop_server = NativeInventoryTests.stop_server
    reply = NativeInventoryTests.reply

    def controller(self):
        private = self.directory/'controller'
        private.mkdir(mode=0o700)
        self.store = lease.Store(private)
        self.addCleanup(self.store.close)
        ticket = admission.Ticket(999,123,95,'a'*40,'b'*40,'c'*64,'heavy',0,
                                  'lit-heavy-999-1-heavy-0','d'*64)
        record = self.store.claim(ticket,now=100)
        self.store.allocation_intent(record['operation'],now=101,plan=self.plan,revalidate=lambda _:None)
        self.instance['name'] = record['vm_name']
        self.instance['config'].update(lease.owner_config(record))
        self.record = self.store.bind_allocation(record['operation'],observe=self.client.observe)
        self.provider = native.StartOnly(self.path,self.machine)
        self.addCleanup(self.provider.close)
        self.operation_id = '33333333-3333-4333-8333-333333333333'
        self.server.calls.clear()
        self.server.bodies = []
        self.server.put_reply = self.put_reply
        self.server.reply = self.start_reply

    def operation(self,code=200):
        return {'id':self.operation_id,'class':'task','status_code':code,'err':'',
            'resources':{'instances':['/1.0/instances/'+self.record['vm_name']+'?project='+self.plan['project']]}}

    def put_reply(self,path,body):
        self.assertEqual(path,'/1.0/instances/'+self.record['vm_name']+'/state?project='+self.plan['project'])
        self.instance['status'] = 'Running'
        return 202,{'type':'async','status_code':100,'operation':'/1.0/operations/'+self.operation_id,
                    'metadata':self.operation(103)}

    def start_reply(self,path,index):
        return (200,self.operation()) if '/operations/' in path else self.reply(path,index)

    def start(self,**changes):
        return self.provider.start(self.store,self.record['operation'],
            **{'now':102,'revalidate':lambda _:None,**changes})

    def assert_held_once(self):
        self.assertEqual(self.store.status()['phase'],'START_DISPATCH_INTENT')
        calls=list(self.server.calls)
        with self.assertRaises(lease.Held):self.start()
        self.assertEqual(self.server.calls,calls)
        with self.assertRaises(lease.Held):
            self.store.bind_started(self.record['operation'],observe=self.provider.observe)
        self.assertEqual(len(self.server.bodies),1)

    def test_real_unix_start_put_and_exact_operation_bind_running_once(self):
        self.controller()
        with patch('socket.create_connection',side_effect=AssertionError('TCP forbidden')):
            result=self.start()
        self.assertEqual(result['phase'],'STARTED')
        self.assertEqual(result['vm_uuid'],self.record['vm_uuid'])
        self.assertEqual(self.server.bodies,[{'action':'start','timeout':0,'force':False,'stateful':False}])
        self.assertTrue(all(method in {'GET','PUT'} for method,path in self.server.calls))
        calls=list(self.server.calls)
        with self.assertRaises(lease.Held):self.start()
        self.assertEqual(self.server.calls,calls)

    def test_lost_start_reply_never_resubmits_or_adopts_running(self):
        self.controller()
        def lost(path,body):
            self.put_reply(path,body)
            return None
        self.server.put_reply=lost
        with self.assertRaisesRegex(lease.Held,'native-read-unavailable'):self.start()
        self.assert_held_once()

    def test_foreign_start_operation_scope_refuses_before_poll(self):
        self.controller()
        def foreign(path,body):
            status,reply=self.put_reply(path,body)
            reply['metadata']['resources']['instances']=['/1.0/instances/foreign?project=other']
            return status,reply
        self.server.put_reply=foreign
        with self.assertRaisesRegex(lease.Held,'native-operation-identity'):self.start()
        self.assertFalse(any('/operations/' in path for method,path in self.server.calls))
        self.assert_held_once()

    def test_last_uuid_readback_drift_prevents_put(self):
        self.controller()
        reads=[]
        def drift(path,index):
            value=self.start_reply(path,index)
            if path.startswith('/1.0/instances/'):
                reads.append(path)
                if len(reads)==2:
                    value=copy.deepcopy(value)
                    value[1]['config']['volatile.uuid']='44444444-4444-4444-8444-444444444444'
            return value
        self.server.reply=drift
        with self.assertRaisesRegex(lease.Held,'native-instance-replaced'):self.start()
        self.assertEqual(self.server.bodies,[])
        self.assertEqual(self.store.status()['phase'],'START_DISPATCH_INTENT')

    def test_expired_or_cancelled_job_has_no_native_start_reads(self):
        self.controller()
        with self.assertRaisesRegex(lease.Held,'start-window'):self.start(now=self.record['deadline'])
        def cancelled(_):raise lease.Held('native-job-cancelled')
        with self.assertRaisesRegex(lease.Held,'native-job-cancelled'):self.start(revalidate=cancelled)
        self.assertEqual(self.server.calls,[])
        self.assertEqual(self.store.status()['phase'],'ALLOCATED')

    def test_missing_or_enabled_autostart_prevents_native_start(self):
        self.controller()
        for value in [None, 'true', True]:
            if value is None: self.instance['config'].pop('boot.autostart', None)
            else: self.instance['config']['boot.autostart'] = value
            with self.subTest(value=value), self.assertRaisesRegex(lease.Held, 'native-instance-provenance'):
                self.start()
        self.assertEqual(self.server.bodies, [])
        self.assertEqual(self.store.status()['phase'], 'ALLOCATED')

    def test_native_preflight_cannot_cross_deadline_before_put(self):
        self.controller()
        clock=[0]
        reads=[]
        def delayed(path,index):
            value=self.start_reply(path,index)
            if path.startswith('/1.0/instances/'):
                reads.append(path)
                if len(reads)==2:clock[0]=10000
            return value
        self.server.reply=delayed
        with patch.object(native.time,'monotonic',side_effect=lambda:clock[0]):
            with self.assertRaisesRegex(lease.Held,'native-start-window'):self.start()
        self.assertEqual(self.server.bodies,[])
        self.assertEqual(self.store.status()['phase'],'START_DISPATCH_INTENT')

    def test_native_start_failure_never_becomes_success(self):
        self.controller()
        def failed(path,index):
            return (200,self.operation(400)) if '/operations/' in path else self.start_reply(path,index)
        self.server.reply=failed
        with self.assertRaisesRegex(lease.Held,'native-operation-not-successful'):self.start()
        self.assert_held_once()


@unittest.skipUnless(os.geteuid() == 0, 'Root-local graceful stop provider')
class NativeStopTests(unittest.TestCase):
    setUp = NativeInventoryTests.setUp
    stop_server = NativeInventoryTests.stop_server
    reply = NativeInventoryTests.reply

    def controller(self):
        private=self.directory/'controller';private.mkdir(mode=0o700)
        self.store=lease.Store(private);self.addCleanup(self.store.close)
        ticket=admission.Ticket(999,123,95,'a'*40,'b'*40,'c'*64,'heavy',0,'lit-heavy-999-1-heavy-0','d'*64)
        r=self.store.claim(ticket,now=100);self.store.allocation_intent(r['operation'],now=101,plan=self.plan,revalidate=lambda _:None)
        self.instance['name']=r['vm_name'];self.instance['config'].update(lease.owner_config(r))
        allocated=self.store.bind_allocation(r['operation'],observe=self.client.observe)
        def fixture_start(_):self.instance['status']='Running';return 0
        self.record=self.store.execute_start_once(r['operation'],now=102,revalidate=lambda _:None,
            qualify=self.client.qualify,execute=fixture_start,observe=self.client.observe)
        self.provider=native.StopOnly(self.path,self.machine);self.addCleanup(self.provider.close)
        self.operation_id='33333333-3333-4333-8333-333333333333'
        self.server.calls.clear();self.server.bodies=[];self.server.put_reply=self.put_reply;self.server.reply=self.stop_reply

    def operation(self,code=200):
        return {'id':self.operation_id,'class':'task','status_code':code,'err':'',
            'resources':{'instances':['/1.0/instances/'+self.record['vm_name']+'?project='+self.plan['project']]}}

    def put_reply(self,path,body):
        self.assertEqual(path,'/1.0/instances/'+self.record['vm_name']+'/state?project='+self.plan['project'])
        self.instance['status']='Stopped'
        return 202,{'type':'async','status_code':100,'operation':'/1.0/operations/'+self.operation_id,
                    'metadata':self.operation(103)}

    def stop_reply(self,path,index):
        if path.endswith('/state?project='+self.plan['project']):
            return 200,{'status':self.instance['status'],'pid':123 if self.instance['status']=='Running' else 0}
        return (200,self.operation()) if '/operations/' in path else self.reply(path,index)

    def stop(self):return self.provider.stop(self.store,self.record['operation'])

    def test_one_real_unix_graceful_put_and_pid_zero_without_release(self):
        self.controller()
        with patch('socket.create_connection',side_effect=AssertionError('TCP forbidden')):result=self.stop()
        self.assertEqual(result['phase'],'STOPPED')
        self.assertEqual(self.server.bodies,[{'action':'stop','timeout':60,'force':False,'stateful':False}])
        calls=list(self.server.calls)
        with self.assertRaises(lease.Held):self.stop()
        self.assertEqual(self.server.calls,calls)
        with self.assertRaises(lease.Held):
            self.store.claim(admission.Ticket(**self.record['ticket']),now=10000)

    def test_already_stopped_has_no_put(self):
        self.controller();self.instance['status']='Stopped'
        self.assertEqual(self.stop()['phase'],'STOPPED');self.assertEqual(self.server.bodies,[])

    def test_lost_reply_reconciles_quiescence_readonly_never_reissues(self):
        self.controller()
        def lost(path,body):self.put_reply(path,body);return None
        self.server.put_reply=lost
        with self.assertRaises(lease.Held):self.stop()
        self.assertEqual(self.store.status()['phase'],'STOP_DISPATCH_INTENT')
        calls=list(self.server.calls)
        with self.assertRaises(lease.Held):self.stop()
        self.assertEqual(self.server.calls,calls)
        result=self.store.bind_stopped(self.record['operation'],observe=self.provider.observe_runtime)
        self.assertEqual(result['phase'],'STOPPED');self.assertEqual(len(self.server.bodies),1)

    def test_native_stop_failure_keeps_running_vm_and_capacity_held(self):
        self.controller()
        def reply(path,body):
            status,value=self.put_reply(path,body);self.instance['status']='Running';return status,value
        self.server.put_reply=reply
        self.server.reply=lambda path,index:((200,self.operation(400)) if '/operations/' in path else self.stop_reply(path,index))
        with self.assertRaisesRegex(lease.Held,'native-operation-not-successful'):self.stop()
        self.assertEqual(self.store.status()['phase'],'STOP_DISPATCH_INTENT')
        with self.assertRaises(lease.Held):self.store.bind_stopped(self.record['operation'],observe=self.provider.observe_runtime)
        self.assertEqual(len(self.server.bodies),1)

    def test_stale_or_boolean_pid_is_not_quiescence(self):
        self.controller();self.instance['status']='Stopped'
        self.server.reply=lambda path,index:((200,{'status':'Stopped','pid':False}) if '/state?' in path else self.stop_reply(path,index))
        with self.assertRaisesRegex(lease.Held,'native-runtime-state'):self.stop()
        self.assertEqual(self.server.bodies,[])

    def test_foreign_uuid_at_final_preflight_prevents_stop(self):
        self.controller();reads=[]
        def reply(path,index):
            value=self.stop_reply(path,index)
            if path.startswith('/1.0/instances/') and '/state?' not in path:
                reads.append(path)
                if len(reads)==2:
                    value=copy.deepcopy(value);value[1]['config']['volatile.uuid']='44444444-4444-4444-8444-444444444444'
            return value
        self.server.reply=reply
        with self.assertRaisesRegex(lease.Held,'native-instance-replaced'):self.stop()
        self.assertEqual(self.server.bodies,[])
        self.assertEqual(self.store.status()['phase'],'STOP_DISPATCH_INTENT')


@unittest.skipUnless(os.geteuid() == 0, 'Root-local removal provider')
class NativeRemoveTests(unittest.TestCase):
    setUp = NativeInventoryTests.setUp
    stop_server = NativeInventoryTests.stop_server
    reply = NativeInventoryTests.reply
    operation = NativeStopTests.operation
    put_reply = NativeStopTests.put_reply
    stop_reply = NativeStopTests.stop_reply

    def controller(self):
        NativeStopTests.controller(self)
        self.provider.stop(self.store,self.record['operation'])
        self.record=self.store.status()
        self.remover=native.RemoveOnly(self.path,self.machine);self.addCleanup(self.remover.close)
        self.present=True;self.allow=True;self.operations={}
        self.server.calls.clear();self.server.bodies=[]
        self.server.reply=self.remove_reply;self.server.delete_reply=self.delete_reply

    def remove_reply(self,path,index):
        if path.startswith('/1.0/operations?'):return 200,self.operations
        if path=='/1.0/instances?project='+self.plan['project']:
            return 200,['/1.0/instances/'+self.record['vm_name']] if self.present else []
        return self.stop_reply(path,index)

    def delete_reply(self,path):
        self.assertEqual(path,'/1.0/instances/'+self.record['vm_name']+'?project='+self.plan['project'])
        self.present=False
        return 202,{'type':'async','status_code':100,'operation':'/1.0/operations/'+self.operation_id,
                    'metadata':self.operation(103)}

    def remove(self,**kw):
        return self.remover.remove(self.store,self.record['operation'],authorize=kw.get('authorize',lambda _:self.allow))

    def test_one_native_delete_then_scoped_absence_without_release(self):
        self.controller()
        with patch('socket.create_connection',side_effect=AssertionError('TCP forbidden')):r=self.remove()
        self.assertEqual(r['phase'],'REMOVED');self.assertEqual(self.server.bodies,[None])
        before=list(self.server.calls)
        with self.assertRaises(lease.Held):self.remove()
        self.assertEqual(before,self.server.calls)
        with self.assertRaises(lease.Held):self.store.claim(admission.Ticket(**self.record['ticket']),now=10000)

    def test_retention_gate_denial_or_nonboolean_cannot_delete(self):
        self.controller()
        for value in [False,None,1,{},'approved']:
            with self.subTest(value=value),self.assertRaisesRegex(lease.Held,'retention-evidence-gate-required'):
                self.remove(authorize=lambda _:value)
        self.assertEqual(self.server.bodies,[]);self.assertEqual(self.store.status()['phase'],'STOPPED')

    def test_pending_project_operation_prevents_delete(self):
        self.controller();self.operations={'running':[{'status_code':103}]}
        with self.assertRaisesRegex(lease.Held,'native-pending-operation'):self.remove()
        self.assertEqual(self.server.bodies,[])
        self.assertEqual(self.store.status()['phase'],'STOPPED')
        self.operations={}
        self.assertEqual(self.remove()['phase'],'REMOVED')
        self.assertEqual(self.server.bodies,[None])

    def test_lost_delete_reply_can_only_read_back_absence(self):
        self.controller()
        def lost(path):self.delete_reply(path);return None
        self.server.delete_reply=lost
        with self.assertRaises(lease.Held):self.remove()
        self.assertEqual(self.store.status()['phase'],'DELETE_DISPATCH_INTENT')
        with self.assertRaises(lease.Held):self.remove()
        self.assertEqual(self.store.bind_removed(self.record['operation'],absent=self.remover.absent)['phase'],'REMOVED')
        self.assertEqual(self.server.bodies,[None])

    def test_replacement_uuid_or_running_vm_cannot_delete(self):
        self.controller();self.instance['config']['volatile.uuid']='44444444-4444-4444-8444-444444444444'
        with self.assertRaisesRegex(lease.Held,'native-instance-replaced'):self.remove()
        self.assertEqual(self.server.bodies,[])
        self.instance['config']['volatile.uuid']=self.record['vm_uuid'];self.instance['status']='Running'
        with self.assertRaisesRegex(lease.Held,'native-vm-not-stopped'):self.remove()
        self.assertEqual(self.server.bodies,[])

    def test_absence_requires_successful_wellformed_scoped_inventory(self):
        self.controller()
        self.server.reply=lambda path,index:((200,['/1.0/instances/foreign?project=other'])
            if path.startswith('/1.0/instances?') else self.remove_reply(path,index))
        with self.assertRaisesRegex(lease.Held,'native-instance-list-shape'):
            self.remover.absent(self.record['vm_name'],self.plan)


if __name__ == '__main__':
    unittest.main()
