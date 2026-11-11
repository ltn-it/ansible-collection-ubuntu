"""Root-only terminal-job retention gate; no deletion or capacity release.

GitHub observations come from the controller's trusted read-only client. The
evidence verifier and extension approver are trusted Root dependencies, not job
callbacks. Their external backends and operating acceptance are separate.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import uuid

import ephemeral_worker_admission as admission
from ephemeral_worker_lease import Held, Store, record_fields, require, ticket_digest, ticket_fields, unique_object

FAILED_SECONDS = 14400
MAXIMUM_SECONDS = 86400
CONCLUSIONS = frozenset({'success', 'failure', 'neutral', 'cancelled', 'skipped',
                         'timed_out', 'action_required', 'stale', 'startup_failure'})


def epoch(value):
    require(type(value) is str and re.fullmatch(r'[0-9]{4}(-[0-9]{2}){2}T[0-9]{2}(:[0-9]{2}){2}Z', value),
            'terminal-completion-time')
    try:
        return int(datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp())
    except (TypeError, ValueError):
        raise Held('terminal-completion-time') from None


def terminal(client, ticket, *, now):
    """Read the exact admitted job; later branch movement does not block cleanup."""
    require(type(ticket) is admission.Ticket and type(now) is int and now > 0, 'terminal-input')
    ticket_fields(ticket.__dict__)
    repository = client.get(f'repos/{admission.REPOSITORY}')
    require(repository.get('id') == admission.REPOSITORY_ID
            and repository.get('full_name') == admission.REPOSITORY
            and repository.get('owner', {}).get('id') == admission.ORGANIZATION_ID,
            'terminal-repository')
    run = client.get(f'repos/{admission.REPOSITORY}/actions/runs/{ticket.run_id}')
    require(run.get('id') == ticket.run_id and type(run.get('run_attempt')) is int and run['run_attempt'] == 1
            and run.get('head_sha') == ticket.caller_sha and run.get('head_branch') == 'main'
            and run.get('path') == admission.CALLER and run.get('event') == 'workflow_dispatch'
            and run.get('status') in {'in_progress', 'completed'}, 'terminal-run')
    for key in ['repository', 'head_repository']:
        require(run.get(key, {}).get('id') == admission.REPOSITORY_ID
                and run[key].get('full_name') == admission.REPOSITORY, 'terminal-run-repository')
    for key in ['actor', 'triggering_actor']:
        actor = run.get(key, {})
        require(actor.get('id') == admission.ACTOR_ID and actor.get('login') == admission.ACTOR
                and actor.get('type') == 'Bot', 'terminal-run-actor')
    references = run.get('referenced_workflows')
    workflow = f'{admission.REPOSITORY}/{admission.CALLEE}@{ticket.callee_sha}'
    require(type(references) is list and 1 <= len(references) <= 2 and all(
        type(row) is dict and row.get('path') == workflow and row.get('sha') == ticket.callee_sha
        and row.get('ref') in {None, ticket.callee_sha} for row in references), 'terminal-callee')
    require(run.get('display_title') == 'MLX-90 collection candidate / ' + ticket.request_sha256,
            'terminal-request')
    job = client.get(f'repos/{admission.REPOSITORY}/actions/jobs/{ticket.job_id}')
    require(job.get('id') == ticket.job_id and job.get('run_id') == ticket.run_id
            and type(job.get('run_attempt')) is int and job['run_attempt'] == 1
            and job.get('head_sha') == ticket.caller_sha and job.get('head_branch') == 'main'
            and job.get('status') == 'completed' and type(job.get('conclusion')) is str
            and job['conclusion'] in CONCLUSIONS,
            'terminal-job')
    name, labels = job.get('name'), job.get('labels')
    require(type(name) is str and hashlib.sha256(name.encode()).hexdigest() == ticket.job_name_sha256
            and type(labels) is list and all(type(v) is str for v in labels)
            and len(labels) == len(admission.BASE_LABELS) + 1
            and set(labels) == admission.BASE_LABELS | {ticket.affinity_label}, 'terminal-job-identity')
    group = job.get('runner_group_id')
    require(group is None or type(group) is int and group in {0, ticket.group_id}, 'terminal-job-group')
    completed = epoch(job.get('completed_at'))
    require(0 < completed <= now, 'terminal-clock')
    return {'ticket_sha256': ticket_digest(ticket.__dict__), 'conclusion': job['conclusion'],
            'completed_at': completed, 'observed_at': now}


def reference(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9:._/-]{0,191}', value) is not None


class Retention:
    """Sidecar in the same Root-private Store, serialized by its global fence."""

    def __init__(self, store, *, custodian_reference):
        require(type(store) is Store and reference(custodian_reference), 'retention-root-configuration')
        store._directory()
        self.store, self.custodian = store, custodian_reference

    def _validate(self, value, record):
        require(type(value) is dict and set(value) == {
            'schema', 'operation', 'vm_uuid', 'ticket_sha256', 'completed_at', 'observed_at',
            'conclusion', 'retain_until', 'custodian_reference', 'extension'}, 'retention-shape')
        require(type(value['schema']) is int and value['schema'] == 1
                and value['operation'] == record['operation'] and value['vm_uuid'] == record['vm_uuid']
                and value['ticket_sha256'] == ticket_digest(record['ticket'])
                and value['custodian_reference'] == self.custodian, 'retention-identity')
        require(type(value['completed_at']) is int and type(value['observed_at']) is int
                and record['created_at'] <= value['completed_at'] <= value['observed_at']
                and type(value['conclusion']) is str and value['conclusion'] in CONCLUSIONS
                and type(value['retain_until']) is int,
                'retention-terminal')
        base = value['completed_at'] + (0 if value['conclusion'] == 'success' else FAILED_SECONDS)
        extension = value['extension']
        if extension is None:
            require(value['retain_until'] == base, 'retention-default-window')
        else:
            require(value['conclusion'] != 'success' and type(extension) is dict and set(extension) == {
                'reference', 'approved_at', 'until'} and reference(extension['reference'])
                and type(extension['approved_at']) is int and extension['approved_at'] >= value['observed_at']
                and type(extension['until']) is int and base < extension['until']
                <= value['completed_at'] + MAXIMUM_SECONDS
                and value['retain_until'] == extension['until'], 'retention-extension')
        return value

    def _read(self, record):
        self.store._directory()
        name = 'retention-' + record['operation'] + '.json'
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.store.fd)
        except FileNotFoundError:
            return None
        try:
            size = self.store._private_file(fd).st_size
            require(0 < size <= 65536, 'retention-size')
            raw = os.read(fd, 65537)
            require(len(raw) == size, 'retention-state-changed')
            try:
                return self._validate(json.loads(raw, object_pairs_hook=unique_object), record)
            except (ValueError, TypeError, KeyError):
                raise Held('retention-invalid-state') from None
        finally:
            os.close(fd)

    def _write(self, value, record):
        self._validate(value, record)
        self.store._directory()
        name = '.retention-' + uuid.uuid4().hex
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.store.fd)
        with os.fdopen(fd, 'wb') as output:
            output.write(json.dumps(value, sort_keys=True).encode() + b'\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, 'retention-' + record['operation'] + '.json',
                   src_dir_fd=self.store.fd, dst_dir_fd=self.store.fd)
        os.fsync(self.store.fd)

    def seal_terminal(self, operation, *, client, now):
        with self.store.exclusive():
            record = self.store._read()
            require(record is not None and record['operation'] == operation and record['vm_uuid'] is not None
                    and record['phase'] in {'ALLOCATED', 'START_DISPATCH_INTENT', 'START_EXECUTED', 'STARTED',
                                            'STOP_DISPATCH_INTENT', 'STOP_EXECUTED', 'STOPPED'},
                    'retention-owned-worker')
            receipt = terminal(client, admission.Ticket(**record['ticket']), now=now)
            current = self._read(record)
            if current is not None:
                require(all(current[k] == receipt[k] for k in ['ticket_sha256', 'conclusion', 'completed_at']),
                        'terminal-receipt-drift')
                return current
            value = {'schema': 1, 'operation': operation, 'vm_uuid': record['vm_uuid'], **receipt,
                     'retain_until': receipt['completed_at'] + (
                         0 if receipt['conclusion'] == 'success' else FAILED_SECONDS),
                     'custodian_reference': self.custodian, 'extension': None}
            self._write(value, record)
            return value

    def extend(self, operation, *, now, until, approval_reference, approve):
        """Root identity-verified approval backend must confirm this exact request."""
        require(type(now) is int and type(until) is int and reference(approval_reference) and callable(approve),
                'retention-extension-input')
        with self.store.exclusive():
            record = self.store._read()
            require(record is not None and record['operation'] == operation and record['phase'] == 'STOPPED',
                    'retention-stopped-worker')
            value = self._read(record)
            require(value is not None and value['conclusion'] != 'success'
                    and now >= value['observed_at'] and until > max(now, value['retain_until'])
                    and until <= value['completed_at'] + MAXIMUM_SECONDS, 'retention-extension-window')
            request = {'operation': operation, 'vm_uuid': record['vm_uuid'],
                       'custodian_reference': self.custodian, 'until': until, 'reference': approval_reference}
            require(approve(dict(request)) is True, 'custodian-extension-not-approved')
            value['extension'] = {'reference': approval_reference, 'approved_at': now, 'until': until}
            value['retain_until'] = until
            self._write(value, record)
            return value

    def authorize(self, record, *, now, verify_evidence):
        """Use inside RemoveOnly's global fence; true never means capacity release."""
        record_fields(record)
        require(record['phase'] == 'STOPPED' and type(now) is int and callable(verify_evidence),
                'retention-delete-input')
        current = self.store._read()
        # RemoveOnly rechecks authorization at the mutation boundary after the
        # Store has durably recorded its one-shot intent. No other phase or
        # identity change is permitted; this does not authorize intent replay.
        require(current is not None and current['phase'] in {'STOPPED', 'DELETE_DISPATCH_INTENT'}
                and current == {**record, 'phase': current['phase']}, 'retention-worker-drift')
        value = self._read(record)
        require(value is not None and now >= max(value['observed_at'], value['retain_until']),
                'retention-window-open')
        require(verify_evidence(json.loads(json.dumps(value))) is True, 'private-evidence-not-verified')
        os.fsync(self.store.fd)
        return True
