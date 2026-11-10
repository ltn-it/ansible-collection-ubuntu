"""Root-local Incus inventory and one-shot stopped-VM create/start/stop providers.

Inventory is read-only. CreateOnly adds one journal-fenced POST and exact native
operation completion readback. StartOnly adds one UUID-bound start.
No TCP/TLS fallback, subprocess, forced stop/deletion,
create retry or capacity release.
Socket peer credentials authenticate the local daemon; this is not a substitute
for fencing physical-host jobs, qualifying the worker image or the full service.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time

from ephemeral_worker_lease import Held, Store, plan_fields, record_fields, require, unique_object, vm_identity, runtime_stopped

MAX_BYTES = 2 * 1024 * 1024


def trusted_directory(path):
    """Open each parent without links; root-owned sticky /tmp is test-safe."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, "native-directory-path")
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            value = os.fstat(fd)
            require(value.st_uid == 0 and (not value.st_mode & 0o022 or value.st_mode & stat.S_ISVTX),
                    "native-directory-untrusted")
        return fd
    except BaseException:
        os.close(fd)
        raise


def machine_id(path):
    path = Path(path)
    parent = trusted_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            value = os.fstat(fd)
            require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and not value.st_mode & 0o022
                    and value.st_nlink == 1 and 0 < value.st_size <= 128, "native-machine-file")
            raw = os.read(fd, 129).decode('ascii').strip()
            require(re.fullmatch(r'[0-9a-f]{32}', raw) is not None, "native-machine-identity")
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def profile_digest(metadata, name):
    require(type(metadata) is dict and metadata.get('name') == name
            and type(metadata.get('config')) is dict and type(metadata.get('devices')) is dict,
            "native-profile-shape")
    canonical = {key: metadata[key] for key in ['name', 'config', 'devices']}
    return hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class Inventory:
    """Paths are selected by root configuration, never by a job or HTTP reply."""

    def __init__(self, socket_path='/var/lib/incus/unix.socket', machine_path='/etc/machine-id'):
        require(os.geteuid() == 0, "native-inventory-root-required")
        self.path = Path(socket_path)
        self.machine_path = Path(machine_path)
        self.machine = machine_id(self.machine_path)
        self.parent = trusted_directory(self.path.parent)
        try:
            self.identity = self._socket_identity()
        except BaseException:
            os.close(self.parent)
            raise

    def _socket_identity(self):
        parent = os.fstat(self.parent)
        named = os.stat(self.path.parent, follow_symlinks=False)
        require((parent.st_dev, parent.st_ino) == (named.st_dev, named.st_ino), "native-socket-parent-replaced")
        value = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        require(stat.S_ISSOCK(value.st_mode) and value.st_uid == 0 and not value.st_mode & 0o002,
                "native-socket-untrusted")
        return value.st_dev, value.st_ino

    def _get(self, resource, *, project):
        require(re.fullmatch(r'(profiles/[a-z][a-z0-9-]{0,62}|images/[0-9a-f]{64}|'
                             r'instances/[a-z][a-z0-9-]{0,62})', resource) is not None
                and re.fullmatch(r'[a-z][a-z0-9-]{0,62}', project) is not None, "native-resource-path")
        value = self._exchange('GET', '/1.0/' + resource + '?project=' + project)
        return self._sync(value, dict)

    @staticmethod
    def _sync(value, kind):
        require(type(value) is dict and value.get('type') == 'sync'
                and type(value.get('status_code')) is int and value['status_code'] == 200
                and type(value.get('metadata')) is kind, "native-api-envelope")
        return value['metadata']

    def _exchange(self, method, path, body=None, *, status=200):
        """Private transport; callers construct paths, never follow reply URLs."""
        require(machine_id(self.machine_path) == self.machine and self._socket_identity() == self.identity,
                "native-endpoint-replaced")
        connected = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection = http.client.HTTPConnection('localhost', timeout=5)
        connection.auto_open = 0
        try:
            connected.settimeout(5)
            connected.connect('/proc/self/fd/' + str(self.parent) + '/' + self.path.name)
            require(struct.unpack('3i', connected.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1] == 0,
                    "native-daemon-peer")
            require(self._socket_identity() == self.identity, "native-endpoint-replaced")
            connection.sock = connected
            headers = {'Accept': 'application/json', 'Connection': 'close'}
            if body is not None:
                headers['Content-Type'] = 'application/json'
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            require(response.status == status, 'native-api-http-status-' + str(response.status))
            require(response.getheader('Content-Encoding') in {None, 'identity'}, "native-api-encoding")
            raw = response.read(MAX_BYTES + 1)
            require(0 < len(raw) <= MAX_BYTES, "native-api-size")
            value = json.loads(raw, object_pairs_hook=unique_object)
            require(machine_id(self.machine_path) == self.machine and self._socket_identity() == self.identity,
                    "native-endpoint-replaced")
            return value
        except Held:
            raise
        except (OSError, http.client.HTTPException, ValueError):
            raise Held('native-read-unavailable') from None
        finally:
            connection.close()
            connected.close()

    @staticmethod
    def _operation(value, identifier, resource):
        require(type(value) is dict and value.get('id') == identifier and value.get('class') == 'task'
                and value.get('resources') == {'instances': [resource]}
                and type(value.get('status_code')) is int and value.get('err') == '',
                'native-operation-identity')
        require(value['status_code'] in {103, 105, 200}, 'native-operation-not-successful')
        return value['status_code'] == 200

    def _complete_operation(self, reply, *, name, project):
        require(type(reply) is dict and reply.get('type') == 'async'
                and type(reply.get('status_code')) is int and reply['status_code'] == 100,
                'native-operation-receipt')
        metadata = reply.get('metadata')
        identifier = metadata.get('id') if type(metadata) is dict else None
        require(type(identifier) is str and re.fullmatch(
            r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', identifier),
            'native-operation-id')
        operation_path = '/1.0/operations/' + identifier
        require(reply.get('operation') == operation_path, 'native-operation-path')
        resource = '/1.0/instances/' + name + '?project=' + project
        self._operation(metadata, identifier, resource)
        # Poll even if mutation receipt metadata already reports success: completion
        # must be read back from this exact daemon/operation, not inferred.
        deadline = time.monotonic() + 120
        while True:
            result = self._sync(self._exchange('GET', operation_path + '?project=' + project), dict)
            if self._operation(result, identifier, resource):
                return 0
            require(time.monotonic() < deadline, 'native-operation-timeout')
            time.sleep(0.25)

    def qualify(self, plan):
        """Read scope/profile/image identity; not capacity or operating approval."""
        plan_fields(plan)
        require(self.machine == plan['machine_id'], "native-machine-mismatch")
        profile = self._get('profiles/' + plan['profile'], project=plan['project'])
        actual = profile_digest(profile, plan['profile'])
        require(actual == plan['profile_sha256'], "native-profile-drift")
        image = self._get('images/' + plan['image_sha256'], project=plan['project'])
        require(image.get('fingerprint') == plan['image_sha256'] and image.get('type') == 'virtual-machine'
                and image.get('architecture') == 'x86_64', "native-image-identity")
        return {'machine_id': self.machine, 'project': plan['project'], 'profile_sha256': actual}

    def observe(self, name, plan):
        scope = self.qualify(plan)
        metadata = self._get('instances/' + name, project=plan['project'])
        require(type(metadata.get('config')) is dict, "native-instance-config")
        # Do not return cloud-init, devices, descriptions or other credentials.
        selected = {key: metadata.get(key) for key in ['name', 'type', 'status', 'profiles']}
        selected['config'] = {key: metadata['config'].get(key) for key in [
            'user.lit.worker-operation', 'user.lit.worker-ticket', 'boot.autostart',
            'volatile.base_image', 'volatile.uuid']}
        again = profile_digest(self._get('profiles/' + plan['profile'], project=plan['project']), plan['profile'])
        require(again == scope['profile_sha256'], "native-profile-drift")
        return {**scope, 'instance': selected}

    def observe_runtime(self, name, plan):
        observed = self.observe(name, plan)
        state = self._sync(self._exchange('GET', '/1.0/instances/' + name + '/state?project=' + plan['project']), dict)
        require(state.get('status') == observed['instance']['status'] and type(state.get('pid')) is int,
                'native-runtime-state')
        observed['instance']['native_pid'] = state['pid']
        return observed

    def close(self):
        parent, self.parent = self.parent, None
        if parent is not None:
            os.close(parent)


class CreateOnly(Inventory):
    """Root controller provider: one local stopped VM, no start/delete/retry.

    Uses the Store's durable one-shot dispatch. Only Root-owned controller code
    can supply dependencies; there is no job-facing callback or HTTP endpoint.
    Native project/image/profile provisioning and capacity qualification precede
    this component. Other Root administrators are outside its singleton fence.
    """

    def allocate(self, store, operation, *, now, revalidate):
        began = time.monotonic()
        record = record_fields(store.status())
        require(record['operation'] == operation and record['phase'] == 'ALLOCATION_INTENT',
                'allocation-intent-required')
        return store.execute_allocation_once(
            operation, now=now, revalidate=revalidate, qualify=self.qualify,
            execute=lambda variables: self._create(
                record, variables, expires_at=began + record['deadline'] - now - 1), observe=self.observe)

    def _create(self, record, variables, *, expires_at):
        require(variables == Store._creation_inputs(record), 'native-create-input-drift')
        plan = record['plan']
        # A dedicated initially empty project prevents adoption, even if a
        # journal has been lost. A foreign Root actor is not fenced by this read.
        require(plan['project'] != 'default', 'native-dedicated-project-required')
        self.qualify(plan)
        path = '/1.0/instances?project=' + plan['project']
        instances = self._sync(self._exchange('GET', path), list)
        require(instances == [], 'native-project-not-empty')
        # Re-read profile/image after inventory and immediately before POST.
        self.qualify(plan)
        item = variables['incus_instance_items'][0]
        body = json.dumps({'name': record['vm_name'], 'type': 'virtual-machine',
                           'source': {'type': 'image', 'fingerprint': plan['image_sha256']},
                           'profiles': [plan['profile']], 'config': item['config'],
                           'start': False, 'ephemeral': False}, separators=(',', ':')).encode()
        require(time.monotonic() < expires_at, 'native-create-window')
        reply = self._exchange('POST', path, body, status=202)
        return self._complete_operation(reply, name=record['vm_name'], project=plan['project'])


class StartOnly(Inventory):
    """Root-local one-shot start of an exact allocated UUID; no create/stop/delete."""

    def start(self, store, operation, *, now, revalidate):
        began = time.monotonic()
        record = record_fields(store.status())
        require(record['operation'] == operation and record['phase'] == 'ALLOCATED', 'owned-allocation-required')
        return store.execute_start_once(
            operation, now=now, revalidate=revalidate, qualify=self.qualify,
            execute=lambda variables: self._start(
                record, variables, expires_at=began + record['deadline'] - now - 1), observe=self.observe)

    def _start(self, record, variables, *, expires_at):
        require(variables == Store._start_inputs(record), 'native-start-input-drift')
        plan = record['plan']
        require(plan['project'] != 'default', 'native-dedicated-project-required')
        # Requalify exact template/UUID and stopped status immediately before PUT.
        require(vm_identity(record, self.observe(record['vm_name'], plan)) == record['vm_uuid'],
                'native-instance-replaced')
        path = '/1.0/instances/' + record['vm_name'] + '/state?project=' + plan['project']
        require(time.monotonic() < expires_at, 'native-start-window')
        reply = self._exchange('PUT', path, json.dumps(variables['state'], separators=(',', ':')).encode(), status=202)
        return self._complete_operation(reply, name=record['vm_name'], project=plan['project'])


class StopOnly(Inventory):
    """Root-only bounded graceful stop; no create/start/force/delete/release."""

    def stop(self, store, operation):
        record = record_fields(store.status())
        require(record['operation'] == operation and record['phase'] in {
            'ALLOCATED', 'START_DISPATCH_INTENT', 'START_EXECUTED', 'STARTED'}, 'owned-allocation-required')
        return store.execute_stop_once(operation,
            execute=lambda variables: self._stop(record, variables), observe=self.observe_runtime)

    def _stop(self, record, variables):
        require(variables == Store._stop_inputs(record), 'native-stop-input-drift')
        plan = record['plan']
        require(plan['project'] != 'default', 'native-dedicated-project-required')
        # A spontaneous shutdown during final preflight needs no mutation.
        if runtime_stopped(record, self.observe_runtime(record['vm_name'], plan)):
            return 0
        path = '/1.0/instances/' + record['vm_name'] + '/state?project=' + plan['project']
        reply = self._exchange('PUT', path, json.dumps(variables['state'], separators=(',', ':')).encode(), status=202)
        return self._complete_operation(reply, name=record['vm_name'], project=plan['project'])


class RemoveOnly(Inventory):
    """Delete one exact stopped VM after a Root operating gate; never release."""

    def _no_pending_operations(self, plan):
        self.qualify(plan)
        operations = self._sync(self._exchange(
            'GET', '/1.0/operations?project=' + plan['project'] + '&recursion=1'), dict)
        # Conservatively fence every active project operation, including exports
        # and snapshots. An empty inventory is not inferred from a failed query.
        for items in operations.values():
            require(type(items) is list, 'native-operations-shape')
            for item in items:
                require(type(item) is dict and type(item.get('status_code')) is int
                        and item['status_code'] in {200, 400, 401}, 'native-pending-operation')

    def absent(self, name, plan):
        require(type(name) is str and re.fullmatch(r'g06-heavy-[0-9a-f]{32}', name), 'native-owned-name')
        self._no_pending_operations(plan)
        instances = self._sync(self._exchange('GET', '/1.0/instances?project=' + plan['project']), list)
        pattern = r'/1.0/instances/([a-z][a-z0-9-]{0,62})(?:\?project=' + plan['project'] + r')?'
        names = []
        for path in instances:
            match = re.fullmatch(pattern, path) if type(path) is str else None
            require(match is not None, 'native-instance-list-shape')
            names.append(match.group(1))
        require(len(set(names)) == len(names), 'native-instance-list-duplicate')
        self._no_pending_operations(plan)
        return name not in names

    def remove(self, store, operation, *, authorize):
        require(callable(authorize), 'retention-evidence-gate-required')
        record = record_fields(store.status())
        require(record['operation'] == operation and record['phase'] == 'STOPPED', 'owned-stopped-vm-required')
        return store.execute_delete_once(operation, authorize=authorize,
            execute=lambda variables: self._remove(record, variables, authorize),
            observe=self._observe_removable, absent=self.absent)

    def _observe_removable(self, name, plan):
        # Ordinary busy/unavailable inventory must fail before durable dispatch
        # intent. Repeat the gate again after intent at the mutation boundary.
        self._no_pending_operations(plan)
        return self.observe_runtime(name, plan)

    def _remove(self, record, variables, authorize):
        require(variables == Store._delete_inputs(record), 'native-delete-input-drift')
        plan = record['plan']
        require(plan['project'] != 'default', 'native-dedicated-project-required')
        self._no_pending_operations(plan)
        require(runtime_stopped(record, self.observe_runtime(record['vm_name'], plan)), 'native-vm-not-stopped')
        require(authorize(json.loads(json.dumps(record))) is True, 'retention-evidence-gate-required')
        path = '/1.0/instances/' + record['vm_name'] + '?project=' + plan['project']
        reply = self._exchange('DELETE', path, status=202)
        return self._complete_operation(reply, name=record['vm_name'], project=plan['project'])
