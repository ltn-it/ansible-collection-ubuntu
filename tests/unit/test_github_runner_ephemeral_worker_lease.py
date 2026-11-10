"""Actual Linux flock/private-file checks; no VM or registration effects."""
from pathlib import Path
import json
import copy
import os
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "roles/github_runner/files"))
import ephemeral_worker_admission as A
import ephemeral_worker_lease as M


def ticket():
    return A.Ticket(999, 123, 95, "a" * 40, "b" * 40, "c" * 64,
                    "heavy", 0, "lit-heavy-999-1-heavy-0", "d" * 64)


def plan():
    return {"machine_id": "e" * 32, "project": "isolated-heavy", "image_sha256": "f" * 64,
            "profile": "qualified-worker", "profile_sha256": "1" * 64}


class PrivilegeTests(unittest.TestCase):
    def test_only_root_can_open_controller_state(self):
        with tempfile.TemporaryDirectory() as directory:
            if os.geteuid() == 0:
                store = M.Store(directory)
                self.addCleanup(store.close)
                self.assertIsNone(store.status())
            else:
                with self.assertRaisesRegex(M.Held, "root-controller-required"):
                    M.Store(directory)
                self.assertEqual(list(Path(directory).iterdir()), [])


@unittest.skipUnless(os.geteuid() == 0, "root-owned controller state requires root; nonroot refusal is tested separately")
class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.store = M.Store(self.path)
        self.addCleanup(self.store.close)

    def intent(self):
        claim = self.store.claim(ticket(), now=100)
        return self.store.allocation_intent(claim["operation"], now=101, plan=plan(), revalidate=lambda value: None)

    def observation(self, record):
        return {"machine_id": plan()["machine_id"], "project": plan()["project"],
                "profile_sha256": plan()["profile_sha256"], "instance": {
                    "name": record["vm_name"], "type": "virtual-machine", "status": "Stopped",
                    "profiles": [plan()["profile"]], "config": {
                        **M.owner_config(record), "volatile.base_image": plan()["image_sha256"],
                        "volatile.uuid": "22222222-2222-4222-8222-222222222222"}}}

    def test_creation_variables_are_closed_and_derived_from_persisted_intent(self):
        record = self.intent()
        item, = self.store.creation_variables(record["operation"])["incus_instance_items"]
        self.assertEqual(item["name"], record["vm_name"])
        self.assertEqual(item["config"], M.owner_config(record))
        self.assertEqual(item['config']['boot.autostart'], 'false')
        self.assertEqual(item["image"], plan()["image_sha256"])
        self.assertEqual(item["profiles"], [plan()["profile"]])
        self.assertTrue(item["create_only"])
        self.assertEqual(item["state"], "present")
        self.assertNotIn("job_name", json.dumps(item))
        self.assertEqual(self.store.status(), record)

    def dispatch(self, record, **changes):
        defaults = {'now': 102, 'revalidate': lambda ticket: None,
                    'qualify': lambda selected: {k: selected[k] for k in ('machine_id', 'project', 'profile_sha256')},
                    'execute': lambda variables: 0,
                    'observe': lambda name, selected: self.observation(record)}
        return self.store.execute_allocation_once(record['operation'], **{**defaults, **changes})

    def test_single_provider_call_sees_durable_intent_and_closed_local_inputs(self):
        record = self.intent()
        calls = []
        def execute(variables):
            on_disk = json.loads((self.path / 'active.json').read_bytes())
            self.assertEqual(on_disk['phase'], 'ALLOCATION_DISPATCH_INTENT')
            self.assertEqual(on_disk['schema'], 3)
            self.assertTrue(variables['incus_instance_enabled'])
            self.assertTrue(variables['incus_instance_force_local'])
            self.assertEqual(variables['incus_instance_inventory_path'], '')
            self.assertEqual(variables['incus_instance_results'], [])
            self.assertEqual(variables['incus_instance_binary'], '/usr/bin/incus')
            self.assertEqual(variables['incus_instance_command_user'], '')
            self.assertEqual(variables['incus_instance_default_devices'], {})
            self.assertEqual(variables['incus_instance_default_config'], {})
            item, = variables['incus_instance_items']
            self.assertEqual(item['config'], M.owner_config(record))
            self.assertTrue(item['create_only'])
            self.assertFalse(item['empty'])
            calls.append(variables)
            return 0
        result = self.dispatch(record, execute=execute)
        self.assertEqual(result['phase'], 'ALLOCATED')
        self.assertEqual(len(calls), 1)
        with self.assertRaisesRegex(M.Held, 'dispatch-not-fresh'):
            self.dispatch(record, execute=execute)
        self.assertEqual(len(calls), 1)

    def test_lost_provider_reply_and_failed_or_bool_result_are_never_replayed(self):
        record = self.intent()
        calls = []
        def lost(variables):
            calls.append(variables)
            raise TimeoutError('synthetic native reply lost')
        with self.assertRaises(TimeoutError):
            self.dispatch(record, execute=lost)
        self.assertEqual(self.store.status()['phase'], 'ALLOCATION_DISPATCH_INTENT')
        with self.assertRaisesRegex(M.Held, 'dispatch-not-fresh'):
            self.dispatch(record, execute=lost)
        with self.assertRaisesRegex(M.Held, 'allocation-intent-required'):
            self.store.bind_allocation(record['operation'], observe=lambda *args: self.fail('unconfirmed executor'))
        self.assertEqual(len(calls), 1)
        # Provider success must be the actual integer exit code, never bool.
        for result in (False, True, 1, None, {'rc': 0}):
            with self.subTest(result=result):
                other_path = self.path / ('case-' + str(len(list(self.path.iterdir()))))
                other_path.mkdir(mode=0o700)
                other = M.Store(other_path)
                try:
                    claim = other.claim(ticket(), now=100)
                    intent = other.allocation_intent(claim['operation'], now=101, plan=plan(), revalidate=lambda _: None)
                    with self.assertRaisesRegex(M.Held, 'provider-outcome-unknown'):
                        other.execute_allocation_once(intent['operation'], now=102, revalidate=lambda _: None,
                            qualify=lambda p: {k:p[k] for k in ('machine_id','project','profile_sha256')},
                            execute=lambda _: result, observe=lambda *args: self.fail('unconfirmed provider'))
                    self.assertEqual(other.status()['phase'], 'ALLOCATION_DISPATCH_INTENT')
                finally:
                    other.close()

    def test_proven_provider_completion_recovers_readback_without_second_create(self):
        record = self.intent()
        calls = []
        def execute(variables):
            calls.append(variables)
            return 0
        with self.assertRaisesRegex(M.Held, 'native-read-unavailable'):
            self.dispatch(record, execute=execute, observe=lambda *args: (_ for _ in ()).throw(M.Held('native-read-unavailable')))
        self.assertEqual(self.store.status()['phase'], 'ALLOCATION_EXECUTED')
        with self.assertRaisesRegex(M.Held, 'dispatch-not-fresh'):
            self.dispatch(record, execute=execute)
        bound = self.store.bind_allocation(record['operation'], observe=lambda *args: self.observation(record))
        self.assertEqual(bound['phase'], 'ALLOCATED')
        self.assertEqual(len(calls), 1)

    def test_job_or_scope_drift_and_persistence_failure_precede_provider_effect(self):
        record = self.intent()
        calls = []
        execute = lambda variables: calls.append(variables) or 0
        with self.assertRaisesRegex(A.Denied, 'cancelled'):
            self.dispatch(record, execute=execute, revalidate=lambda _: (_ for _ in ()).throw(A.Denied('cancelled')))
        with self.assertRaisesRegex(M.Held, 'native-provider-scope'):
            self.dispatch(record, execute=execute, qualify=lambda _: {'machine_id':'0'*32})
        self.assertEqual(self.store.status()['phase'], 'ALLOCATION_INTENT')
        from unittest.mock import patch
        with patch.object(self.store, '_write', side_effect=OSError('synthetic durable write failure')):
            with self.assertRaises(OSError):
                self.dispatch(record, execute=execute)
        self.assertEqual(calls, [])

    def test_actual_controller_process_exit_after_provider_effect_never_resubmits(self):
        record = self.intent()
        pid = os.fork()
        if pid == 0:
            child = M.Store(self.path)
            def effect(variables):
                with (self.path / 'synthetic-created.marker').open('xb') as output:
                    output.write(variables['incus_instance_items'][0]['name'].encode())
                    output.flush()
                    os.fsync(output.fileno())
                os._exit(23)
            child.execute_allocation_once(record['operation'], now=102, revalidate=lambda _: None,
                qualify=lambda p: {k:p[k] for k in ('machine_id','project','profile_sha256')},
                execute=effect, observe=lambda *args: self.observation(record))
            os._exit(99)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 23)
        self.assertEqual((self.path / 'synthetic-created.marker').read_text(), record['vm_name'])
        self.assertEqual(self.store.status()['phase'], 'ALLOCATION_DISPATCH_INTENT')
        with self.assertRaisesRegex(M.Held, 'dispatch-not-fresh'):
            self.dispatch(record, execute=lambda _: self.fail('second provider effect'))
        with self.assertRaisesRegex(M.Held, 'capacity-held'):
            self.store.claim(ticket(), now=10000)

    def test_old_schema_is_held_without_implicit_migration(self):
        record = self.intent()
        record['schema'] = 2
        raw = json.dumps(record).encode()
        (self.path / 'active.json').write_bytes(raw)
        with self.assertRaisesRegex(M.Held, 'lease-identity'):
            self.store.status()
        self.assertEqual((self.path / 'active.json').read_bytes(), raw)

    def test_native_uuid_bind_is_idempotent_and_still_holds_global_capacity(self):
        record = self.intent()
        observed = self.observation(record)
        calls = []
        def observe(name, actual_plan):
            calls.append((name, actual_plan))
            return copy.deepcopy(observed)
        bound = self.store.bind_allocation(record["operation"], observe=observe)
        self.assertEqual(bound["phase"], "ALLOCATED")
        self.assertEqual(bound["vm_uuid"], observed["instance"]["config"]["volatile.uuid"])
        self.assertEqual(self.store.bind_allocation(record["operation"], observe=observe), bound)
        self.assertEqual(calls, [(record["vm_name"], plan())] * 2)
        with self.assertRaisesRegex(M.Held, "capacity-held"):
            self.store.claim(ticket(), now=10000)
        with self.assertRaisesRegex(M.Held, "native-reconciliation-required"):
            self.store.abandon_before_effect(record["operation"])
        with self.assertRaisesRegex(M.Held, "allocation-intent-required"):
            self.store.creation_variables(record["operation"])

    def test_partial_or_wrong_native_provenance_never_binds(self):
        record = self.intent()
        baseline = self.observation(record)
        mutations = [
            lambda v: v.update(machine_id="0" * 32),
            lambda v: v.update(project="other"),
            lambda v: v.update(profile_sha256="0" * 64),
            lambda v: v["instance"].update(name="foreign"),
            lambda v: v["instance"].update(type="container"),
            lambda v: v["instance"].update(status="Running"),
            lambda v: v["instance"].update(profiles=["foreign"]),
            lambda v: v["instance"]["config"].update({"user.lit.worker-operation": "0" * 32}),
            lambda v: v["instance"]["config"].update({"user.lit.worker-ticket": "0" * 64}),
            lambda v: v["instance"]["config"].update({"volatile.base_image": "0" * 64}),
            lambda v: v["instance"]["config"].pop("volatile.uuid"),
            lambda v: v["instance"]["config"].update({"volatile.uuid": "00000000-0000-0000-0000-000000000000"}),
        ]
        for mutation in mutations:
            value = copy.deepcopy(baseline)
            mutation(value)
            with self.subTest(value=value), self.assertRaises(M.Held):
                self.store.bind_allocation(record["operation"], observe=lambda name, policy: value)
            self.assertEqual(self.store.status(), record)
        with self.assertRaises(TimeoutError):
            self.store.bind_allocation(record["operation"], observe=lambda name, policy: (_ for _ in []).throw(TimeoutError()))
        self.assertEqual(self.store.status(), record)

    def test_native_uuid_replacement_refuses_without_changing_original_binding(self):
        record = self.intent()
        value = self.observation(record)
        bound = self.store.bind_allocation(record["operation"], observe=lambda name, policy: value)
        value["instance"]["config"]["volatile.uuid"] = "33333333-3333-4333-8333-333333333333"
        with self.assertRaisesRegex(M.Held, "native-instance-replaced"):
            self.store.bind_allocation(record["operation"], observe=lambda name, policy: value)
        self.assertEqual(self.store.status(), bound)

    def test_invalid_plan_refuses_before_intent_or_revalidation(self):
        record = self.store.claim(ticket(), now=100)
        for key, value in [("profile", "{{ lookup('pipe', 'id') }}"), ("project", "../../default"),
                           ("image_sha256", "images:ubuntu/24.04"), ("machine_id", True)]:
            policy = dict(plan(), **{key: value})
            calls = []
            with self.subTest(key=key), self.assertRaises(M.Held):
                self.store.allocation_intent(record["operation"], now=101, plan=policy,
                                             revalidate=lambda value: calls.append(value))
            self.assertEqual(calls, [])
            self.assertEqual(self.store.status(), record)

    def test_claim_is_private_and_remains_held_after_close_and_expiry(self):
        claim = self.store.claim(ticket(), now=100, duration=10)
        self.assertEqual((self.path / "active.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(claim["vm_name"], "g06-heavy-" + claim["operation"])
        other = M.Store(self.path)
        self.addCleanup(other.close)
        self.assertEqual(other.status(), claim)
        with self.assertRaisesRegex(M.Held, "capacity-held"):
            other.claim(ticket(), now=10000)
        with self.assertRaisesRegex(M.Held, "allocation-window"):
            other.allocation_intent(claim["operation"], now=111, plan=plan(), revalidate=lambda value: None)
        self.assertEqual(other.status()["phase"], "CLAIMED")

    def test_kernel_flock_denies_a_second_process(self):
        read_fd, write_fd = os.pipe()
        with self.store.exclusive():
            pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                try:
                    other = M.Store(self.path)
                    try:
                        other.claim(ticket(), now=100)
                    except M.Held as error:
                        os.write(write_fd, str(error).encode())
                    else:
                        os.write(write_fd, b"UNEXPECTED_SECOND_CLAIM")
                    other.close()
                finally:
                    os.close(write_fd)
                    os._exit(0)
            os.close(write_fd)
            result = os.read(read_fd, 1024)
            os.close(read_fd)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(status, 0)
            self.assertEqual(result, b"another-controller-active")
        self.assertIsNone(self.store.status())

    def test_crashed_process_leaves_durable_allocation_intent(self):
        pid = os.fork()
        if pid == 0:
            other = M.Store(self.path)
            claim = other.claim(ticket(), now=100)
            other.allocation_intent(claim["operation"], now=101, plan=plan(), revalidate=lambda value: None)
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(status, 0)
        actual = self.store.status()
        self.assertEqual(actual["phase"], "ALLOCATION_INTENT")
        with self.assertRaisesRegex(M.Held, "capacity-held"):
            self.store.claim(ticket(), now=200)
        with self.assertRaisesRegex(M.Held, "native-reconciliation-required"):
            self.store.abandon_before_effect(actual["operation"])

    def test_revalidation_precedes_intent_and_failed_validation_keeps_claim(self):
        claim = self.store.claim(ticket(), now=100)
        calls = []
        def reject(value):
            calls.append(value)
            raise A.Denied("job-cancelled")
        with self.assertRaisesRegex(A.Denied, "job-cancelled"):
            self.store.allocation_intent(claim["operation"], now=101, plan=plan(), revalidate=reject)
        self.assertEqual(calls, [ticket()])
        self.assertEqual(self.store.status()["phase"], "CLAIMED")
        self.store.allocation_intent(claim["operation"], now=102, plan=plan(), revalidate=lambda value: calls.append(value))
        with self.assertRaisesRegex(M.Held, "allocation-not-fresh"):
            self.store.allocation_intent(claim["operation"], now=103, plan=plan(), revalidate=lambda value: calls.append(value))
        self.assertEqual(len(calls), 2)

    def test_only_a_claim_with_no_effect_intent_can_be_abandoned(self):
        claim = self.store.claim(ticket(), now=100)
        with self.assertRaisesRegex(M.Held, "native-reconciliation-required"):
            self.store.abandon_before_effect("f" * 32)
        self.store.abandon_before_effect(claim["operation"])
        self.assertIsNone(self.store.status())
        archive = self.path / (claim["operation"] + ".abandoned.json")
        self.assertEqual(json.loads(archive.read_text()), claim)
        self.assertNotEqual(self.store.claim(ticket(), now=101)["operation"], claim["operation"])

    def test_unknown_malformed_and_duplicate_state_blocks_capacity(self):
        for raw in [b"not json", b'{"schema":1,"schema":1}', b'{}']:
            with self.subTest(raw=raw):
                state = self.path / "active.json"
                state.write_bytes(raw)
                state.chmod(0o600)
                with self.assertRaises(ValueError):
                    self.store.claim(ticket(), now=100)
                self.assertEqual(state.read_bytes(), raw)
                state.unlink()

    def test_symlink_hardlink_and_public_state_are_not_adopted(self):
        target = self.path / "foreign"
        target.write_text("preserve")
        target.chmod(0o600)
        state = self.path / "active.json"
        state.symlink_to(target)
        with self.assertRaises(OSError):
            self.store.status()
        state.unlink()
        os.link(target, state)
        with self.assertRaisesRegex(M.Held, "file-identity"):
            self.store.status()
        state.unlink()
        claim = self.store.claim(ticket(), now=100)
        state.chmod(0o644)
        with self.assertRaisesRegex(M.Held, "file-identity"):
            self.store.status()
        self.assertEqual(target.read_text(), "preserve")
        self.assertEqual(json.loads(state.read_text())["operation"], claim["operation"])

    def test_replaced_directory_and_wrong_permissions_are_rejected(self):
        other = self.path.with_name(self.path.name + "-retained")
        self.path.rename(other)
        self.addCleanup(lambda: other.rmdir())
        self.path.mkdir(mode=0o700)
        with self.assertRaisesRegex(M.Held, "directory-drift"):
            self.store.status()
        self.path.chmod(0o755)
        with self.assertRaisesRegex(M.Held, "directory-drift"):
            M.Store(self.path)


    def test_slow_allocation_qualification_cannot_dispatch_after_deadline(self):
        from unittest.mock import patch
        record = self.intent(); calls = []
        with patch.object(M.time, 'monotonic', side_effect=[0, record['deadline']]):
            with self.assertRaisesRegex(M.Held, 'allocation-window'):
                self.dispatch(record, execute=lambda value: calls.append(value) or 0)
        self.assertEqual(calls, [])
        self.assertEqual(self.store.status()['phase'], 'ALLOCATION_INTENT')

    def test_allocation_intent_fsync_consumes_dispatch_window_without_replay(self):
        from unittest.mock import patch
        record = self.intent(); calls = []; clock = [0]; original = self.store._write
        def slow_write(value):
            original(value)
            if value['phase'] == 'ALLOCATION_DISPATCH_INTENT': clock[0] = 10000
        with patch.object(M.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(self.store, '_write', slow_write):
            with self.assertRaisesRegex(M.Held, 'allocation-window'):
                self.dispatch(record, execute=lambda value: calls.append(value) or 0)
        self.assertEqual(calls, [])
        self.assertEqual(self.store.status()['phase'], 'ALLOCATION_DISPATCH_INTENT')
        with self.assertRaises(M.Held): self.dispatch(record)


@unittest.skipUnless(os.geteuid() == 0, 'Root-owned start fence')
class StartTests(unittest.TestCase):
    setUp = LeaseTests.setUp
    intent = LeaseTests.intent
    observation = LeaseTests.observation
    dispatch = LeaseTests.dispatch

    def allocated(self):
        record = self.dispatch(self.intent())
        self.running = False
        self.start_calls = []
        return record

    def observe(self, record):
        value = self.observation(record)
        value['instance']['status'] = 'Running' if self.running else 'Stopped'
        return value

    def start(self, record, **changes):
        def execute(value):
            self.assertEqual(json.loads((self.path/'active.json').read_text())['phase'], 'START_DISPATCH_INTENT')
            self.start_calls.append(value)
            self.running = True
            return 0
        defaults = {'now': 103, 'revalidate': lambda _: None,
            'qualify': lambda selected: {k:selected[k] for k in ('machine_id','project','profile_sha256')},
            'execute': execute, 'observe': lambda *args: self.observe(record)}
        return self.store.execute_start_once(record['operation'], **{**defaults, **changes})

    def test_one_start_with_durable_intent_preserves_uuid_and_capacity(self):
        record = self.allocated()
        result = self.start(record)
        self.assertEqual(result['phase'], 'STARTED')
        self.assertEqual(result['vm_uuid'], record['vm_uuid'])
        self.assertEqual(self.start_calls, [{'name':record['vm_name'], 'project':plan()['project'],
            'vm_uuid':record['vm_uuid'], 'state':{'action':'start','timeout':0,'force':False,'stateful':False}}])
        with self.assertRaisesRegex(M.Held, 'start-dispatch-not-fresh'):
            self.start(record)
        self.assertEqual(len(self.start_calls), 1)
        with self.assertRaisesRegex(M.Held, 'capacity-held'):
            self.store.claim(ticket(), now=10000)
        with self.assertRaises(M.Held):
            self.store.abandon_before_effect(record['operation'])

    def test_expiry_cancellation_replacement_and_running_prevent_start(self):
        record = self.allocated()
        with self.assertRaisesRegex(M.Held, 'start-window'):
            self.start(record, now=record['deadline'])
        with self.assertRaisesRegex(M.Held, 'cancelled'):
            self.start(record, revalidate=lambda _: (_ for _ in ()).throw(M.Held('cancelled')))
        changed = self.observe(record)
        changed['instance']['config']['volatile.uuid'] = '33333333-3333-4333-8333-333333333333'
        with self.assertRaisesRegex(M.Held, 'native-instance-replaced'):
            self.start(record, observe=lambda *args: changed)
        self.running = True
        with self.assertRaisesRegex(M.Held, 'native-instance-identity'):
            self.start(record)
        self.assertEqual(self.start_calls, [])
        self.assertEqual(self.store.status()['phase'], 'ALLOCATED')

    def test_lost_reply_holds_without_replay_or_running_adoption(self):
        record = self.allocated()
        def lost(value):
            self.running = True
            self.start_calls.append(value)
            raise TimeoutError('fixture lost start result')
        with self.assertRaises(TimeoutError):
            self.start(record, execute=lost)
        self.assertEqual(self.store.status()['phase'], 'START_DISPATCH_INTENT')
        with self.assertRaisesRegex(M.Held, 'start-dispatch-not-fresh'):
            self.start(record)
        with self.assertRaisesRegex(M.Held, 'proven-start-completion-required'):
            self.store.bind_started(record['operation'], observe=lambda *args:self.observe(record))
        self.assertEqual(len(self.start_calls), 1)

    def test_provider_success_readback_failure_recovers_without_start(self):
        record = self.allocated()
        def read(*args):
            if self.running:
                raise TimeoutError('fixture readback unavailable')
            return self.observe(record)
        with self.assertRaises(TimeoutError):
            self.start(record, observe=read)
        self.assertEqual(self.store.status()['phase'], 'START_EXECUTED')
        result = self.store.bind_started(record['operation'], observe=lambda *args:self.observe(record))
        self.assertEqual(result['phase'], 'STARTED')
        self.assertEqual(len(self.start_calls), 1)
        self.assertEqual(self.store.bind_started(record['operation'], observe=lambda *args:self.observe(record)),result)

    def test_boolean_nonzero_and_missing_result_cannot_prove_start(self):
        for outcome in [True, 1, None, {}]:
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as path:
                self.store.close()
                self.path = Path(path)
                self.store = M.Store(self.path)
                self.addCleanup(self.store.close)
                record = self.allocated()
                with self.assertRaisesRegex(M.Held, 'start-provider-outcome-unknown'):
                    self.start(record, execute=lambda _:outcome)
                self.assertEqual(self.store.status()['phase'], 'START_DISPATCH_INTENT')

    def test_failed_intent_write_prevents_native_start(self):
        from unittest.mock import patch
        record = self.allocated()
        with patch.object(self.store, '_write', side_effect=OSError('fixture failed fsync')):
            with self.assertRaises(OSError):
                self.start(record)
        self.assertEqual(self.start_calls, [])
        self.assertEqual(self.store.status()['phase'], 'ALLOCATED')

    def test_slow_native_preflight_exhausts_window_before_start(self):
        from unittest.mock import patch
        record = self.allocated()
        with patch.object(M.time, 'monotonic', side_effect=[0, record['deadline']]):
            with self.assertRaisesRegex(M.Held, 'start-window'):
                self.start(record)
        self.assertEqual(self.start_calls, [])
        self.assertEqual(self.store.status()['phase'], 'ALLOCATED')

    def test_process_exit_after_effect_retains_start_fence(self):
        record = self.allocated()
        pid = os.fork()
        if pid == 0:
            child = M.Store(self.path)
            def effect(value):
                with (self.path/'synthetic-started.marker').open('xb') as output:
                    output.write(value['vm_uuid'].encode());output.flush();os.fsync(output.fileno())
                os._exit(23)
            child.execute_start_once(record['operation'],now=103,revalidate=lambda _:None,
                qualify=lambda selected:{k:selected[k] for k in ('machine_id','project','profile_sha256')},
                execute=effect,observe=lambda *args:self.observe(record))
            os._exit(99)
        _, status = os.waitpid(pid,0)
        self.assertEqual(os.waitstatus_to_exitcode(status),23)
        self.assertEqual((self.path/'synthetic-started.marker').read_text(),record['vm_uuid'])
        self.assertEqual(self.store.status()['phase'],'START_DISPATCH_INTENT')
        with self.assertRaises(M.Held):self.start(record)
        self.assertEqual(self.start_calls,[])


@unittest.skipUnless(os.geteuid() == 0, 'Root-owned stop fence')
class StopTests(unittest.TestCase):
    setUp = LeaseTests.setUp
    intent = LeaseTests.intent
    observation = LeaseTests.observation
    dispatch = LeaseTests.dispatch

    def observe(self,record):
        value=self.observation(record)
        value['instance'].update(status='Running' if self.running else 'Stopped',native_pid=123 if self.running else 0)
        return value

    def prepared(self):
        record=self.dispatch(self.intent());self.running=False;self.calls=[]
        def effect(_):self.running=True;return 0
        return self.store.execute_start_once(record['operation'],now=103,revalidate=lambda _:None,
            qualify=lambda selected:{k:selected[k] for k in ('machine_id','project','profile_sha256')},
            execute=effect,observe=lambda *args:self.observe(record))

    def stop(self,record,**changes):
        def execute(value):
            self.assertEqual(json.loads((self.path/'active.json').read_text())['phase'],'STOP_DISPATCH_INTENT')
            self.calls.append(value);self.running=False;return 0
        return self.store.execute_stop_once(record['operation'],**{
            'execute':execute,'observe':lambda *args:self.observe(record),**changes})

    def test_one_graceful_stop_records_pid_zero_but_never_releases_capacity(self):
        record=self.prepared();result=self.stop(record)
        self.assertEqual(result['phase'],'STOPPED')
        self.assertEqual(result['vm_uuid'],record['vm_uuid'])
        self.assertEqual(self.calls,[{'name':record['vm_name'],'project':plan()['project'],'vm_uuid':record['vm_uuid'],
            'state':{'action':'stop','timeout':60,'force':False,'stateful':False}}])
        with self.assertRaises(M.Held):self.stop(record)
        with self.assertRaises(M.Held):self.store.claim(ticket(),now=10000)
        with self.assertRaises(M.Held):self.store.abandon_before_effect(record['operation'])
        self.assertEqual(len(self.calls),1)

    def test_already_stopped_is_readonly_without_provider_or_job_refresh(self):
        record=self.prepared();self.running=False
        result=self.stop(record,execute=lambda _:self.fail('already stopped must not mutate'))
        self.assertEqual(result['phase'],'STOPPED');self.assertEqual(self.calls,[])

    def test_lost_stop_reply_reconciles_only_exact_native_stopped_pid_zero(self):
        record=self.prepared()
        def lost(value):self.calls.append(value);raise TimeoutError('fixture lost stop reply')
        with self.assertRaises(TimeoutError):self.stop(record,execute=lost)
        self.assertEqual(self.store.status()['phase'],'STOP_DISPATCH_INTENT')
        with self.assertRaises(M.Held):self.stop(record)
        with self.assertRaisesRegex(M.Held,'native-vm-not-stopped'):
            self.store.bind_stopped(record['operation'],observe=lambda *args:self.observe(record))
        self.running=False
        result=self.store.bind_stopped(record['operation'],observe=lambda *args:self.observe(record))
        self.assertEqual(result['phase'],'STOPPED');self.assertEqual(len(self.calls),1)
        with self.assertRaises(M.Held):self.store.claim(ticket(),now=10000)

    def test_wrong_uuid_and_nonzero_or_boolean_stopped_pid_never_confirm(self):
        record=self.prepared();self.running=False
        wrong=self.observe(record);wrong['instance']['config']['volatile.uuid']='33333333-3333-4333-8333-333333333333'
        with self.assertRaisesRegex(M.Held,'native-instance-replaced'):self.stop(record,observe=lambda *args:wrong)
        for pid in [True,False,123,-1,None]:
            wrong=self.observe(record);wrong['instance']['native_pid']=pid
            with self.subTest(pid=pid),self.assertRaisesRegex(M.Held,'native-runtime-state'):
                self.stop(record,observe=lambda *args:wrong)
        self.assertEqual(self.calls,[]);self.assertEqual(self.store.status()['phase'],'STARTED')

    def test_provider_success_then_failed_readback_can_recover_without_stop(self):
        record=self.prepared()
        def observe(*args):
            if not self.running:raise TimeoutError('fixture readback missing')
            return self.observe(record)
        with self.assertRaises(TimeoutError):self.stop(record,observe=observe)
        self.assertEqual(self.store.status()['phase'],'STOP_EXECUTED')
        self.assertEqual(self.store.bind_stopped(record['operation'],observe=lambda *args:self.observe(record))['phase'],'STOPPED')
        self.assertEqual(len(self.calls),1)

    def test_failed_intent_persistence_prevents_native_stop(self):
        from unittest.mock import patch
        record=self.prepared()
        with patch.object(self.store,'_write',side_effect=OSError('fixture failed fsync')):
            with self.assertRaises(OSError):self.stop(record)
        self.assertEqual(self.calls,[]);self.assertEqual(self.store.status()['phase'],'STARTED')

    def test_nonzero_or_false_success_holds_without_force_retry(self):
        for outcome in [True,1,None,{}]:
            with self.subTest(outcome=outcome),tempfile.TemporaryDirectory() as path:
                self.store.close();self.path=Path(path);self.store=M.Store(self.path);self.addCleanup(self.store.close)
                record=self.prepared()
                with self.assertRaisesRegex(M.Held,'stop-provider-outcome-unknown'):
                    self.stop(record,execute=lambda _:outcome)
                self.assertEqual(self.store.status()['phase'],'STOP_DISPATCH_INTENT')
                with self.assertRaises(M.Held):self.stop(record)

    def test_controller_process_exit_after_stop_effect_never_replays(self):
        record=self.prepared();pid=os.fork()
        if pid==0:
            child=M.Store(self.path)
            def effect(value):
                with (self.path/'synthetic-stopped.marker').open('xb') as f:
                    f.write(value['vm_uuid'].encode());f.flush();os.fsync(f.fileno())
                os._exit(23)
            child.execute_stop_once(record['operation'],execute=effect,observe=lambda *args:self.observe(record))
            os._exit(99)
        _,status=os.waitpid(pid,0);self.assertEqual(os.waitstatus_to_exitcode(status),23)
        self.assertEqual(self.store.status()['phase'],'STOP_DISPATCH_INTENT')
        with self.assertRaises(M.Held):self.stop(record)
        self.assertEqual(self.calls,[])


@unittest.skipUnless(os.geteuid() == 0, 'Root-owned removal fence')
class RemoveTests(unittest.TestCase):
    setUp = LeaseTests.setUp
    intent = LeaseTests.intent
    observation = LeaseTests.observation
    dispatch = LeaseTests.dispatch
    observe = StopTests.observe
    prepared = StopTests.prepared
    stop = StopTests.stop

    def ready(self):
        record=self.prepared();self.stop(record);self.deleted=False;self.delete_calls=[]
        return self.store.status()

    def remove(self,record,**changes):
        def effect(value):
            self.assertEqual(self.store._read()['phase'],'DELETE_DISPATCH_INTENT')
            self.delete_calls.append(value);self.deleted=True;return 0
        return self.store.execute_delete_once(record['operation'],**{
            'authorize':lambda _:True,'execute':effect,'observe':lambda *a:self.observe(record),
            'absent':lambda *a:self.deleted,**changes})

    def test_intent_before_delete_and_removed_still_holds_capacity(self):
        record=self.ready();self.assertEqual(self.remove(record)['phase'],'REMOVED')
        self.assertEqual(len(self.delete_calls),1)
        with self.assertRaises(M.Held):self.remove(record)
        with self.assertRaises(M.Held):self.store.claim(ticket(),now=10000)
        with self.assertRaises(M.Held):self.store.abandon_before_effect(record['operation'])

    def test_failed_intent_fsync_prevents_delete(self):
        from unittest.mock import patch
        record=self.ready()
        with patch.object(self.store,'_write',side_effect=OSError('fixture fsync')):
            with self.assertRaises(OSError):self.remove(record)
        self.assertEqual(self.delete_calls,[])

    def test_controller_exit_after_effect_cannot_replay(self):
        record=self.ready();pid=os.fork()
        if pid==0:
            child=M.Store(self.path)
            def effect(_):os._exit(24)
            child.execute_delete_once(record['operation'],authorize=lambda _:True,execute=effect,
                observe=lambda *a:self.observe(record),absent=lambda *a:True)
            os._exit(99)
        _,status=os.waitpid(pid,0);self.assertEqual(os.waitstatus_to_exitcode(status),24)
        self.assertEqual(self.store.status()['phase'],'DELETE_DISPATCH_INTENT')
        with self.assertRaises(M.Held):self.remove(record)
        with self.assertRaisesRegex(M.Held,'native-vm-not-absent'):
            self.store.bind_removed(record['operation'],absent=lambda *a:False)
        self.assertEqual(self.store.bind_removed(record['operation'],absent=lambda *a:True)['phase'],'REMOVED')
        self.assertEqual(self.delete_calls,[])


if __name__ == "__main__":
    unittest.main()
