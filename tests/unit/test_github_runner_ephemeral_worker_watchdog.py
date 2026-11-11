"""Real Root locks/durable spool with explicit native provider fixtures."""
import copy
import json
import os
import select
import shutil
import subprocess
import tempfile
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'roles/github_runner/files'))
import ephemeral_worker_lease as lease
import ephemeral_worker_watchdog as watchdog
import test_github_runner_ephemeral_worker_lease as lease_fixture
from test_github_runner_ephemeral_worker_lease import ticket


def copy_program(directory):
    library = directory / 'program'; library.mkdir(mode=0o700)
    for name in ['ephemeral_worker_watchdog_entry.py', 'ephemeral_worker_watchdog.py',
                 'ephemeral_worker_admission.py', 'ephemeral_worker_lease.py', 'ephemeral_worker_incus.py']:
        shutil.copyfile(ROOT / 'roles/github_runner/files' / name, library / name)
        (library / name).chmod(0o600)
    return library / 'ephemeral_worker_watchdog_entry.py'


class RootBoundaryTests(unittest.TestCase):
    def test_untrusted_store_is_rejected_without_side_effects(self):
        with self.assertRaises(lease.Held): watchdog.PendingAlarms(Path('/must-not-open'))

    def test_entry_refuses_nonroot_or_missing_state_without_creating_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); entry = copy_program(directory)
            target = directory / 'must-not-create'
            result = subprocess.run([sys.executable, '-I', '-B', str(entry), '--state-directory', str(target)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)['state'], 'WATCHDOG_UNAVAILABLE')
            self.assertFalse(target.exists())


@unittest.skipUnless(os.geteuid() == 0, 'Root watchdog/store integration')
class WatchdogTests(unittest.TestCase):
    setUp = lease_fixture.LeaseTests.setUp
    intent = lease_fixture.LeaseTests.intent
    observation = lease_fixture.LeaseTests.observation
    dispatch = lease_fixture.LeaseTests.dispatch
    observe = lease_fixture.StopTests.observe
    prepared = lease_fixture.StopTests.prepared

    def ready(self):
        self.record = self.prepared(); self.stop_calls = []; self.lost = False; self.bad_uuid = False
        self.native_absent = False
        owner = self
        class Stopper:
            def observe_runtime(self, name, plan):
                result = copy.deepcopy(owner.observe(owner.record))
                if owner.bad_uuid: result['instance']['config']['volatile.uuid'] = '33333333-3333-4333-8333-333333333333'
                return result
            def stop(self, store, operation):
                def effect(value):
                    owner.stop_calls.append(value); owner.running = False
                    if owner.lost: raise TimeoutError('synthetic lost native stop reply')
                    return 0
                return store.execute_stop_once(operation, execute=effect, observe=self.observe_runtime)
        class Remover:
            def absent(self, name, plan): return owner.native_absent
        self.stopper, self.remover = Stopper(), Remover()
        self.watcher = watchdog.Watchdog(self.store, stopper=self.stopper, remover=self.remover)
        return self.record

    def alarms(self): return sorted(self.path.glob('alarm-*.json'))

    def test_isolated_root_entry_handles_idle_and_expired_claim_without_incus(self):
        self.ready(); entry = copy_program(self.path)
        directory = self.path / 'cli-state'; directory.mkdir(mode=0o700)
        argv = [sys.executable, '-I', '-B', str(entry), '--state-directory', str(directory)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0); self.assertEqual(json.loads(result.stdout)['state'], 'IDLE')
        store = lease.Store(directory); self.addCleanup(store.close)
        record = store.claim(ticket(), now=100, duration=1)
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['state'], 'ABANDONED_BEFORE_EFFECT')
        self.assertTrue((directory / (record['operation']+'.abandoned.json')).is_file())
        self.assertIsNone(store.status()); self.assertEqual(self.stop_calls, [])

    def test_expiry_stops_once_and_preserves_claim_and_private_pending_state(self):
        record = self.ready()
        self.assertEqual(self.watcher.tick(now=record['deadline']-1)['state'], 'ACTIVE_WINDOW')
        self.assertEqual(self.stop_calls, [])
        result = self.watcher.tick(now=record['deadline'])
        self.assertEqual(result['state'], 'EXPIRED_STOPPED_HELD'); self.assertFalse(result['capacity_released'])
        self.assertEqual(len(self.stop_calls), 1)
        self.assertEqual(self.watcher.tick(now=record['deadline']+1)['state'], 'STOPPED_HELD')
        self.assertEqual(len(self.stop_calls), 1); self.assertEqual(self.alarms(), [])
        with self.assertRaises(lease.Held): self.store.claim(ticket(), now=record['deadline']+10000)

    def test_lost_stop_reply_spools_then_reconciles_readonly_without_retry_or_ack(self):
        record = self.ready(); self.lost = True
        result = self.watcher.tick(now=record['deadline'])
        self.assertEqual(result['state'], 'ALARM_PENDING'); self.assertFalse(result['alarm_delivered'])
        self.assertEqual(self.store.status()['phase'], 'STOP_DISPATCH_INTENT')
        self.assertEqual(len(self.stop_calls), 1)
        self.assertEqual(self.watcher.tick(now=record['deadline']+1)['state'], 'STOPPED_HELD')
        self.assertEqual(len(self.stop_calls), 1)
        self.assertEqual(json.loads(self.alarms()[0].read_text())['delivery'], 'pending')

    def test_uncertain_create_never_adopts_replays_or_releases(self):
        record = self.ready()
        with self.store.exclusive():
            current = self.store._read(); current.update(phase='ALLOCATION_DISPATCH_INTENT', vm_uuid=None)
            self.store._write(current)
        first = self.watcher.tick(now=record['deadline']); alarm = self.alarms()[0]; before = alarm.read_bytes()
        second = self.watcher.tick(now=record['deadline']+1)
        self.assertEqual(first['event_id'], second['event_id']); self.assertEqual(alarm.read_bytes(), before)
        self.assertEqual(alarm.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.stop_calls, [])
        self.assertEqual(self.store.status()['phase'], 'ALLOCATION_DISPATCH_INTENT')
        with self.assertRaises(lease.Held): self.store.claim(ticket(), now=record['deadline']+10000)

    def test_expired_claim_only_can_abandon_before_any_native_effect(self):
        self.ready()
        # Fresh independent empty Store; do not reset the active fixture lease.
        directory = self.path/'fresh-claim'; directory.mkdir(mode=0o700)
        store = lease.Store(directory); self.addCleanup(store.close)
        record = store.claim(ticket(), now=100, duration=1)
        watcher = watchdog.Watchdog(store, stopper=self.stopper, remover=self.remover)
        result = watcher.tick(now=101)
        self.assertEqual(result['state'], 'ABANDONED_BEFORE_EFFECT'); self.assertTrue(result['capacity_released'])
        self.assertIsNone(store.status()); self.assertEqual(self.stop_calls, [])
        self.assertTrue((directory/(record['operation']+'.abandoned.json')).exists())

    def test_stopped_vm_that_restarts_is_an_alarm_not_a_second_stop(self):
        record = self.ready(); self.watcher.tick(now=record['deadline']); self.running = True
        result = self.watcher.tick(now=record['deadline']+1)
        self.assertEqual(result['kind'], 'retained-resource-drift')
        self.assertEqual(len(self.stop_calls), 1); self.assertEqual(self.store.status()['phase'], 'STOPPED')

    def test_unknown_delete_only_reconciles_proven_absence_and_keeps_capacity(self):
        record = self.ready(); self.watcher.tick(now=record['deadline'])
        with self.store.exclusive():
            current = self.store._read(); current['phase'] = 'DELETE_DISPATCH_INTENT'; self.store._write(current)
        self.assertEqual(self.watcher.tick(now=record['deadline']+1)['state'], 'ALARM_PENDING')
        self.native_absent = True
        self.assertEqual(self.watcher.tick(now=record['deadline']+2)['state'], 'REMOVED_HELD')
        with self.assertRaises(lease.Held): self.store.claim(ticket(), now=record['deadline']+10000)
        self.native_absent = False
        self.assertEqual(self.watcher.tick(now=record['deadline']+3)['kind'], 'retained-resource-drift')
        self.assertEqual(len(self.stop_calls), 1)

    def test_uuid_drift_or_clock_rollback_never_mutates_native_vm(self):
        record = self.ready()
        self.assertEqual(self.watcher.tick(now=99)['kind'], 'clock-rollback')
        self.bad_uuid = True
        self.assertEqual(self.watcher.tick(now=record['deadline'])['state'], 'ALARM_PENDING')
        self.assertEqual(self.stop_calls, [])

    def test_corrupt_state_spools_no_error_payload_and_does_not_repair(self):
        self.ready(); raw = b'{"unparsed":"synthetic-sensitive-body"'
        (self.path/'active.json').write_bytes(raw)
        result = self.watcher.tick(now=10000)
        self.assertEqual(result['kind'], 'controller-state-invalid')
        self.assertIsNone(result['operation']); self.assertEqual(self.stop_calls, [])
        self.assertNotIn('synthetic-sensitive-body', self.alarms()[0].read_text())
        self.assertEqual((self.path/'active.json').read_bytes(), raw)

    def test_alarm_persistence_failure_is_not_reported_as_delivered_or_success(self):
        self.ready()
        with patch('os.fsync', side_effect=OSError('synthetic spool failure')):
            with self.assertRaises(OSError): self.watcher.tick(now=99)
        self.assertEqual(self.alarms(), []); self.assertEqual(self.stop_calls, [])

    def test_corrupt_or_public_alarm_is_not_overwritten(self):
        self.ready(); self.watcher.tick(now=99); alarm = self.alarms()[0]
        alarm.chmod(0o644)
        with self.assertRaises(lease.Held): self.watcher.tick(now=99)
        alarm.chmod(0o600); alarm.write_text('{"delivery":"pretend-delivered"}')
        with self.assertRaises(lease.Held): self.watcher.tick(now=99)
        self.assertEqual(alarm.read_text(), '{"delivery":"pretend-delivered"}')

    def test_busy_real_controller_does_not_block_independent_alarm_lock(self):
        record = self.ready(); ready_r, ready_w = os.pipe(); release_r, release_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(ready_r); os.close(release_w)
            child = lease.Store(self.path)
            with child.exclusive():
                os.write(ready_w, b'1'); os.read(release_r, 1)
            os._exit(0)
        os.close(ready_w); os.close(release_r)
        try:
            self.assertEqual(select.select([ready_r], [], [], 5)[0], [ready_r])
            self.assertEqual(os.read(ready_r, 1), b'1')
            self.assertEqual(self.watcher.tick(now=record['deadline']-1)['state'], 'CONTROLLER_BUSY')
            result = self.watcher.tick(now=record['deadline'])
            self.assertEqual(result['kind'], 'expired-controller-busy')
            self.assertTrue(self.alarms()[0].is_file()); self.assertEqual(self.stop_calls, [])
        finally:
            try: os.write(release_w, b'1')
            except BrokenPipeError: pass
            os.close(release_w); os.close(ready_r)
            _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)


if __name__ == '__main__':
    unittest.main()
