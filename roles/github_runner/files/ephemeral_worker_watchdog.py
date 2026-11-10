"""Root watchdog tick and durable pending alarms; no assumed delivery or release.

Scheduling, native hard expiry and the real alarm receiver are deployment gates.
The spool lock is independent of the worker lock: a stalled controller must not
prevent its watchdog from preserving an expiry alarm.
"""
import fcntl
import hashlib
import json
import os
import uuid

from ephemeral_worker_lease import Held, Store, record_fields, require, runtime_stopped, ticket_digest, unique_object

KINDS = frozenset({'controller-state-invalid', 'clock-rollback', 'uncertain-native-effect',
    'expired-controller-busy', 'native-stop-failed', 'native-stop-uncertain',
    'retained-resource-drift', 'native-observation-unavailable'})
FAILURES = (Held, OSError, ValueError, TypeError, KeyError, TimeoutError)


class PendingAlarms:
    """Root-private, idempotent local events; pending never means delivered."""

    def __init__(self, store):
        require(type(store) is Store, 'watchdog-root-store')
        store._directory()
        self.store = store

    def record(self, record, kind, *, now):
        require(type(kind) is str and kind in KINDS and type(now) is int and now > 0, 'watchdog-alarm-input')
        if record is not None:
            record_fields(record)
        identity = {'kind': kind, 'operation': record['operation'] if record else None,
            'vm_uuid': record['vm_uuid'] if record else None, 'phase': record['phase'] if record else None,
            'ticket_sha256': ticket_digest(record['ticket']) if record else None}
        event = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        expected = {'schema': 1, 'event_id': event, **identity, 'observed_at': now, 'delivery': 'pending'}
        self.store._directory()
        lock = os.open('watchdog-alarm.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=self.store.fd)
        try:
            self.store._private_file(lock)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Held('another-alarm-writer-active') from None
            self.store._directory()
            name = 'alarm-' + event + '.json'
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.store.fd)
            except FileNotFoundError:
                fd = None
            if fd is not None:
                try:
                    size = self.store._private_file(fd).st_size
                    require(0 < size <= 65536, 'watchdog-alarm-size')
                    raw = os.read(fd, 65537)
                    require(len(raw) == size, 'watchdog-alarm-changed')
                    value = json.loads(raw, object_pairs_hook=unique_object)
                    require(type(value) is dict and set(value) == set(expected)
                            and type(value['schema']) is int and type(value['observed_at']) is int
                            and value['observed_at'] > 0
                            and value == {**expected, 'observed_at': value['observed_at']},
                            'watchdog-alarm-identity')
                    os.fsync(fd)
                finally:
                    os.close(fd)
            else:
                temporary = '.alarm-' + uuid.uuid4().hex
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=self.store.fd)
                with os.fdopen(fd, 'wb') as output:
                    output.write(json.dumps(expected, sort_keys=True).encode() + b'\n')
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, name, src_dir_fd=self.store.fd, dst_dir_fd=self.store.fd)
            os.fsync(self.store.fd)
            return event
        finally:
            os.close(lock)


class Watchdog:
    """One tick with trusted Root native providers, never job-supplied callbacks."""

    def __init__(self, store, *, stopper, remover):
        require(type(store) is Store and callable(getattr(stopper, 'stop', None))
                and callable(getattr(stopper, 'observe_runtime', None))
                and callable(getattr(remover, 'absent', None)), 'watchdog-native-dependencies')
        self.store, self.stopper, self.remover = store, stopper, remover
        self.alarms = PendingAlarms(store)

    @staticmethod
    def _result(state, record=None, **fields):
        return {'state': state, 'operation': record['operation'] if record else None,
                'capacity_released': False, **fields}

    def _alarm(self, record, kind, now):
        event = self.alarms.record(record, kind, now=now)
        return self._result('ALARM_PENDING', record, kind=kind, event_id=event, alarm_delivered=False)

    def _snapshot(self, fallback):
        # Read-only snapshot for diagnostics, not authority for native effects.
        try:
            self.store._directory()
            value = self.store._read()
            if value is not None and value['operation'] == fallback['operation']:
                return value
        except FAILURES:
            pass
        return fallback

    def tick(self, *, now):
        require(type(now) is int and now > 0, 'watchdog-clock')
        try:
            record = self.store.status()
        except Held as error:
            if str(error) != 'another-controller-active':
                return self._alarm(None, 'controller-state-invalid', now)
            try:
                self.store._directory()
                record = self.store._read()
            except FAILURES:
                return self._alarm(None, 'controller-state-invalid', now)
            if record is None:
                return self._result('CONTROLLER_BUSY')
            if now < record['created_at']:
                return self._alarm(record, 'clock-rollback', now)
            if now >= record['deadline']:
                return self._alarm(record, 'expired-controller-busy', now)
            return self._result('CONTROLLER_BUSY', record)
        except FAILURES:
            return self._alarm(None, 'controller-state-invalid', now)
        if record is None:
            return self._result('IDLE')
        if now < record['created_at']:
            return self._alarm(record, 'clock-rollback', now)
        phase = record['phase']
        if phase in {'STOP_DISPATCH_INTENT', 'STOP_EXECUTED'}:
            try:
                stopped = self.store.bind_stopped(record['operation'], observe=self.stopper.observe_runtime)
                return self._result('STOPPED_HELD', stopped)
            except FAILURES:
                return self._alarm(self._snapshot(record), 'native-stop-uncertain', now)
        if phase in {'DELETE_DISPATCH_INTENT', 'DELETE_EXECUTED'}:
            try:
                removed = self.store.bind_removed(record['operation'], absent=self.remover.absent)
                return self._result('REMOVED_HELD', removed)
            except FAILURES:
                return self._alarm(self._snapshot(record), 'uncertain-native-effect', now)
        if phase == 'STOPPED':
            try:
                stopped = runtime_stopped(record, self.stopper.observe_runtime(record['vm_name'], record['plan']))
            except FAILURES:
                return self._alarm(record, 'native-observation-unavailable', now)
            if not stopped:
                return self._alarm(record, 'retained-resource-drift', now)
            return self._result('STOPPED_HELD', record)
        if phase == 'REMOVED':
            try:
                absent = self.remover.absent(record['vm_name'], record['plan']) is True
            except FAILURES:
                return self._alarm(record, 'native-observation-unavailable', now)
            if not absent:
                return self._alarm(record, 'retained-resource-drift', now)
            return self._result('REMOVED_HELD', record)
        if now < record['deadline']:
            if phase in {'ALLOCATION_DISPATCH_INTENT', 'ALLOCATION_EXECUTED', 'START_DISPATCH_INTENT'}:
                return self._alarm(record, 'uncertain-native-effect', now)
            return self._result('ACTIVE_WINDOW', record)
        if phase == 'CLAIMED':
            try:
                self.store.abandon_before_effect(record['operation'])
                return self._result('ABANDONED_BEFORE_EFFECT', record, capacity_released=True)
            except FAILURES:
                return self._alarm(self._snapshot(record), 'uncertain-native-effect', now)
        if phase in {'ALLOCATED', 'START_DISPATCH_INTENT', 'START_EXECUTED', 'STARTED'}:
            try:
                stopped = self.stopper.stop(self.store, record['operation'])
                require(stopped['phase'] == 'STOPPED', 'watchdog-stop-not-confirmed')
                return self._result('EXPIRED_STOPPED_HELD', stopped)
            except FAILURES:
                return self._alarm(self._snapshot(record), 'native-stop-failed', now)
        return self._alarm(record, 'uncertain-native-effect', now)
