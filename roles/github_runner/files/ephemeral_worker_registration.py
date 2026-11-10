"""One-shot stopped registration from a live controller-owned worker lease.

This joins Store's global fence to the protected github_runner role. Native
callbacks are trusted Root dependencies, never job-supplied transports. The
executor supplies its one-use token privately; neither token nor credentials
enter this module, the returned variables or the durable journal. A lost reply
leaves dispatch intent held. No service start, retry, unregister or release.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
import time
import uuid

import ephemeral_worker_admission as admission
from ephemeral_worker_lease import Store, record_fields, require, ticket_digest, unique_object, vm_identity


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@dataclass(frozen=True)
class Policy:
    custodian_reference: str
    subuid_start: int
    subgid_start: int

    def check(self):
        require(type(self.custodian_reference) is str and 0 < len(self.custodian_reference) <= 1024
                and not any(ord(c) < 32 for c in self.custodian_reference), 'registration-custodian')
        require(all(type(v) is int and 100000 <= v <= 2**32 - 65536
                    for v in (self.subuid_start, self.subgid_start)), 'registration-subids')


def variables(record, policy):
    """Closed nonsecret role input; reading it does not authorize dispatch."""
    record_fields(record)
    require(record['phase'] == 'STARTED', 'registration-started-lease-required')
    require(type(policy) is Policy, 'registration-policy-type')
    policy.check()
    operation = record['operation']
    base = '/var/lib/lightning-it/ephemeral-worker/' + operation
    account = 'ghw_' + operation[:24]
    return {'github_runner_enabled': True, 'github_runner_arch': 'x64',
            'github_runner_register': True, 'github_runner_replace': False,
            'github_runner_manage_service': True,
            'github_runner_instances': [{
                'name': record['vm_name'], 'protected': True, 'ephemeral': True,
                'state': 'present', 'replace': False, 'service_state': 'stopped',
                'expected_guest_uuid': record['vm_uuid'],
                'dir': '/opt/g06-workers/' + operation,
                'manifest_path': base + '/installation.json',
                'storage_dir': base + '/storage', 'work_dir': base + '/storage/work',
                'home': base + '/storage/home', 'user': account, 'group': account,
                'url': 'https://github.com/ltn-it', 'runner_group': admission.GROUP_NAME,
                'labels': sorted(admission.BASE_LABELS) + [record['ticket']['affinity_label']],
                'operation_reference': 'g06-worker:' + operation,
                'storage_reference': 'g06-worker-storage:' + operation,
                'custodian_reference': policy.custodian_reference,
                'rootless_engine': {'subuid_start': policy.subuid_start, 'subgid_start': policy.subgid_start}}]}


def guest_proof(value, record, instance):
    """Readback must come from the Root guest verifier over the bound agent."""
    require(type(value) is dict and set(value) == {
        'vm_uuid', 'operation_reference', 'runner_id', 'runner_name', 'ephemeral',
        'service_state', 'service_start_issued', 'manifest_sha256'}, 'registration-guest-proof')
    require(value['vm_uuid'] == record['vm_uuid']
            and value['operation_reference'] == instance['operation_reference']
            and value['runner_name'] == instance['name'] and admission.positive(value['runner_id'])
            and value['ephemeral'] is True and value['service_state'] == 'stopped'
            and value['service_start_issued'] is False
            and admission.digest(value['manifest_sha256'], 64), 'registration-guest-binding')
    return dict(value)


def github_proof(client, record, guest):
    """Reconcile the actual organization runner and its exact selected group."""
    runner_id = guest['runner_id']
    admission.group_access(client, record['ticket']['group_id'],
                           f"{admission.REPOSITORY}/{admission.CALLEE}@{record['ticket']['callee_sha']}")
    row = client.get(f'orgs/ltn-it/actions/runners/{runner_id}')
    group = client.get(f"orgs/ltn-it/actions/runner-groups/{record['ticket']['group_id']}/runners?per_page=100&page=1")
    require(type(group) is dict and type(group.get('total_count')) is int
            and group['total_count'] == 1 and type(group.get('runners')) is list
            and len(group['runners']) == 1, 'registration-group-membership')
    expected_labels = admission.BASE_LABELS | {record['ticket']['affinity_label']}
    for runner in (row, group['runners'][0]):
        require(type(runner) is dict and type(runner.get('id')) is int and runner['id'] == runner_id
                and runner.get('name') == record['vm_name'] and runner.get('os') == 'linux'
                and runner.get('status') == 'offline' and runner.get('busy') is False,
                'registration-native-runner')
        labels = runner.get('labels')
        require(type(labels) is list and len(labels) == len(expected_labels)
                and all(type(label) is dict and type(label.get('name')) is str for label in labels)
                and {label['name'].lower() for label in labels} == expected_labels,
                'registration-native-labels')
    return runner_id


class Registration:
    def __init__(self, store, policy):
        require(type(store) is Store and type(policy) is Policy, 'registration-controller-dependencies')
        policy.check()
        self.store, self.policy = store, policy

    def _read(self, name):
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.store.fd)
        except FileNotFoundError:
            return None
        try:
            size = Store._private_file(fd).st_size
            require(0 < size <= 65536, 'registration-journal-size')
            raw = os.read(fd, 65537)
            require(len(raw) == size, 'registration-journal-changing')
            value = json.loads(raw, object_pairs_hook=unique_object)
            require(type(value) is dict and set(value) == {
                'schema', 'operation', 'ticket_sha256', 'vm_uuid', 'policy_sha256',
                'variables_sha256', 'phase', 'guest'}, 'registration-journal-shape')
            require(type(value['schema']) is int and value['schema'] == 1
                    and value['phase'] in {'DISPATCH_INTENT', 'EXECUTED', 'REGISTERED_STOPPED'},
                    'registration-journal-phase')
            return value
        finally:
            os.close(fd)

    def _write(self, name, value):
        temporary = '.registration-pending-' + uuid.uuid4().hex
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.store.fd)
        with os.fdopen(fd, 'wb') as output:
            output.write(json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, name, src_dir_fd=self.store.fd, dst_dir_fd=self.store.fd)
        os.fsync(self.store.fd)

    def execute_once(self, operation, *, now, revalidate, observe, execute, inspect_guest, github):
        """Dispatch the existing protected role once inside Store's live fence.

        `execute` must use the closed variables and native UUID-bound Incus agent
        transport, privately supplying a fresh registration token. A synchronous
        integer zero is necessary, not sufficient: Root guest proof and native
        GitHub runner/group readbacks must agree before completion is recorded.
        """
        require(all(callable(f) for f in (revalidate, observe, execute, inspect_guest)),
                'registration-native-dependencies')
        require(callable(getattr(github, 'get', None)), 'registration-github-reader')
        began = time.monotonic()
        with self.store.exclusive():
            record = self.store._read()
            require(record is not None and record['operation'] == operation
                    and record['phase'] == 'STARTED', 'registration-started-lease-required')
            def live():
                require(type(now) is int and record['created_at'] <= now
                        and now + math.ceil(time.monotonic() - began) < record['deadline'],
                        'registration-window')
                observed = observe(record['vm_name'], dict(record['plan']))
                require(vm_identity(record, observed, status='Running') == record['vm_uuid']
                        and type(observed['instance'].get('native_pid')) is int
                        and observed['instance']['native_pid'] > 0, 'registration-live-vm')
            name = 'registration-' + record['operation'] + '.json'
            require(self._read(name) is None, 'registration-already-dispatched-reconcile-only')
            live()
            revalidate(admission.Ticket(**record['ticket']))
            selected = variables(record, self.policy)
            journal = {'schema': 1, 'operation': operation, 'ticket_sha256': ticket_digest(record['ticket']),
                       'vm_uuid': record['vm_uuid'], 'policy_sha256': digest(asdict(self.policy)),
                       'variables_sha256': digest(selected), 'phase': 'DISPATCH_INTENT', 'guest': None}
            live()
            self._write(name, journal)
            live()
            result = execute(json.loads(json.dumps(record)), json.loads(json.dumps(selected)))
            require(type(result) is int and result == 0, 'registration-native-outcome-unknown')
            journal['phase'] = 'EXECUTED'
            self._write(name, journal)
            live()
            guest = guest_proof(inspect_guest(json.loads(json.dumps(record)),
                                             json.loads(json.dumps(selected))), record,
                                variables(record, self.policy)['github_runner_instances'][0])
            github_proof(github, record, guest)
            live()
            journal.update(phase='REGISTERED_STOPPED', guest=guest)
            self._write(name, journal)
            return journal
