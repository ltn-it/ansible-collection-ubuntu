"""Root-private single-worker fence and one-shot VM create/start/stop dispatch.

A closed/crashed controller does not free a durable claim. A dispatch intent is
never replayed. Registration, TLS and cleanup remain separate controller
steps; no generic release shortcut exists.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import math
import uuid

import ephemeral_worker_admission as admission


class Held(admission.Denied):
    """Global capacity remains reserved; never infer cleanup from process exit."""


def require(condition, message):
    if not condition:
        raise Held(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate-state-field")
        result[key] = value
    return result


def ticket_fields(value):
    require(type(value) is dict and set(value) == set(admission.Ticket.__dataclass_fields__), "ticket-shape")
    require(all(admission.positive(value[key]) for key in ["run_id", "job_id", "group_id"]), "ticket-identifiers")
    require(admission.digest(value["caller_sha"], 40) and admission.digest(value["callee_sha"], 40)
            and admission.digest(value["request_sha256"], 64), "ticket-sources")
    require(value["profile"] in {"heavy", "application_acceptance"}
            and type(value["matrix_index"]) is int and 0 <= value["matrix_index"] < 256, "ticket-profile")
    label = f"lit-heavy-{value['run_id']}-1-{value['profile']}-{value['matrix_index']}"
    require(value["affinity_label"] == label and admission.digest(value["job_name_sha256"], 64),
            "ticket-affinity")


def plan_fields(value):
    require(type(value) is dict and set(value) == {
        "machine_id", "project", "image_sha256", "profile", "profile_sha256"}, "allocation-plan-shape")
    require(admission.digest(value["machine_id"], 32) and admission.digest(value["image_sha256"], 64)
            and admission.digest(value["profile_sha256"], 64), "allocation-plan-digests")
    for key in ["project", "profile"]:
        require(type(value[key]) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,62}", value[key]),
                "allocation-plan-name")


def ticket_digest(ticket):
    return hashlib.sha256(json.dumps(ticket, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def owner_config(record):
    return {"user.lit.worker-operation": record["operation"],
            "user.lit.worker-ticket": ticket_digest(record["ticket"]),
            "boot.autostart": "false"}


def vm_identity(record, observed, *, status="Stopped"):
    """Validate an observation acquired by the trusted native adapter, not job JSON.

    The adapter must independently bind the local machine and canonical profile
    readback. A matching name or user marker alone never establishes ownership.
    """
    require(type(status) is str and status in {"Stopped", "Running"}, "native-expected-state")
    plan = record["plan"]
    require(type(observed) is dict and set(observed) == {"machine_id", "project", "profile_sha256", "instance"},
            "native-observation-shape")
    require(all(observed[key] == plan[key] for key in ["machine_id", "project", "profile_sha256"]),
            "native-allocation-scope")
    instance = observed["instance"]
    require(type(instance) is dict and instance.get("name") == record["vm_name"]
            and instance.get("type") == "virtual-machine" and instance.get("status") == status
            and instance.get("profiles") == [plan["profile"]], "native-instance-identity")
    config = instance.get("config")
    require(type(config) is dict and all(config.get(key) == value for key, value in owner_config(record).items())
            and config.get("volatile.base_image") == plan["image_sha256"], "native-instance-provenance")
    native_uuid = config.get("volatile.uuid")
    require(type(native_uuid) is str and re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", native_uuid)
        and uuid.UUID(native_uuid).int != 0, "native-instance-uuid")
    return native_uuid


def runtime_stopped(record, observed):
    """Exact known UUID plus native PID/state; does not release capacity."""
    require(type(observed) is dict and type(observed.get('instance')) is dict, 'native-observation-shape')
    status = observed['instance'].get('status')
    require(vm_identity(record, observed, status=status) == record['vm_uuid'], 'native-instance-replaced')
    pid = observed['instance'].get('native_pid')
    require(type(pid) is int and ((status == 'Stopped' and pid == 0) or (status == 'Running' and pid > 0)),
            'native-runtime-state')
    return status == 'Stopped'


def record_fields(value):
    require(type(value) is dict and set(value) == {
        "schema", "operation", "ticket", "phase", "created_at", "deadline", "vm_name", "plan", "vm_uuid"},
        "lease-shape")
    require(type(value["schema"]) is int and value["schema"] == 3
            and isinstance(value["operation"], str) and re.fullmatch(r"[0-9a-f]{32}", value["operation"])
            and value["phase"] in {"CLAIMED", "ALLOCATION_INTENT", "ALLOCATION_DISPATCH_INTENT",
                                   "ALLOCATION_EXECUTED", "ALLOCATED", "START_DISPATCH_INTENT",
                                   "START_EXECUTED", "STARTED", "STOP_DISPATCH_INTENT",
                                   "STOP_EXECUTED", "STOPPED", "DELETE_DISPATCH_INTENT",
                                   "DELETE_EXECUTED", "REMOVED"}, "lease-identity")
    require(type(value["created_at"]) is int and value["created_at"] > 0
            and type(value["deadline"]) is int
            and 1 <= value["deadline"] - value["created_at"] <= 7200, "lease-deadline")
    require(value["vm_name"] == "g06-heavy-" + value["operation"], "lease-vm-name")
    ticket_fields(value["ticket"])
    if value["phase"] == "CLAIMED":
        require(value["plan"] is None and value["vm_uuid"] is None, "unallocated-plan")
    else:
        plan_fields(value["plan"])
        if value["phase"] not in {"ALLOCATED", "START_DISPATCH_INTENT", "START_EXECUTED", "STARTED",
                                  "STOP_DISPATCH_INTENT", "STOP_EXECUTED", "STOPPED",
                                  "DELETE_DISPATCH_INTENT", "DELETE_EXECUTED", "REMOVED"}:
            require(value["vm_uuid"] is None, "unobserved-vm-uuid")
        else:
            require(type(value["vm_uuid"]) is str and re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value["vm_uuid"])
                and uuid.UUID(value["vm_uuid"]).int != 0, "allocated-vm-uuid")
    return value


class Store:
    """The configured directory must already exist, root-owned and mode 0700."""

    def __init__(self, path):
        require(os.geteuid() == 0, "root-controller-required")
        self.path = Path(path)
        require(self.path.is_absolute() and self.path != Path("/"), "lease-directory")
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.identity = self._directory()
        except BaseException:
            os.close(self.fd)
            raise

    def _directory(self):
        actual = os.fstat(self.fd)
        named = os.stat(self.path, follow_symlinks=False)
        require(stat.S_ISDIR(actual.st_mode) and actual.st_uid == 0 and stat.S_IMODE(actual.st_mode) == 0o700
                and (actual.st_dev, actual.st_ino) == (named.st_dev, named.st_ino), "lease-directory-drift")
        return actual.st_dev, actual.st_ino

    @staticmethod
    def _private_file(fd):
        value = os.fstat(fd)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == 0
                and stat.S_IMODE(value.st_mode) == 0o600 and value.st_nlink == 1, "lease-file-identity")
        return value

    @contextmanager
    def exclusive(self):
        require(self._directory() == self.identity, "lease-directory-replaced")
        fd = os.open("controller.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            self._private_file(fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Held("another-controller-active") from None
            require(self._directory() == self.identity, "lease-directory-replaced")
            yield
        finally:
            os.close(fd)

    def _read(self):
        try:
            fd = os.open("active.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        except FileNotFoundError:
            return None
        try:
            size = self._private_file(fd).st_size
            require(0 < size <= 65536, "lease-state-size")
            raw = os.read(fd, 65537)
            require(len(raw) == size, "lease-state-changed")
            return record_fields(json.loads(raw, object_pairs_hook=unique_object))
        finally:
            os.close(fd)

    def _write(self, record):
        record_fields(record)
        name = ".pending-" + uuid.uuid4().hex
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(name, "active.json", src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        except BaseException:
            # Keep an uncertain local write visible. No native operation may
            # proceed when persistence did not return successfully.
            raise

    def claim(self, ticket, *, now, duration=7200):
        require(type(ticket) is admission.Ticket, "admitted-ticket-required")
        ticket_fields(asdict(ticket))
        require(type(now) is int and now > 0 and type(duration) is int and 1 <= duration <= 7200,
                "claim-window")
        with self.exclusive():
            require(self._read() is None, "global-worker-capacity-held")
            operation = uuid.uuid4().hex
            record = {"schema": 3, "operation": operation, "ticket": asdict(ticket), "phase": "CLAIMED",
                      "created_at": now, "deadline": now + duration, "vm_name": "g06-heavy-" + operation,
                      "plan": None, "vm_uuid": None}
            self._write(record)
            return record

    def allocation_intent(self, operation, *, now, revalidate, plan):
        """Run trusted native revalidation inside the fence, then persist intent."""
        require(callable(revalidate), "native-revalidation-required")
        plan_fields(plan)
        with self.exclusive():
            record = self._read()
            require(record is not None and record["operation"] == operation and record["phase"] == "CLAIMED",
                    "allocation-not-fresh")
            require(type(now) is int and record["created_at"] <= now < record["deadline"], "allocation-window")
            revalidate(admission.Ticket(**record["ticket"]))
            record["plan"] = dict(plan)
            record["phase"] = "ALLOCATION_INTENT"
            self._write(record)
            return record

    def creation_variables(self, operation):
        """Return closed Ansible inputs only; do not issue or retry any effect.

        The trusted adapter must recheck machine/profile/image immediately before
        invoking the role. Re-reading these inputs is not permission to retry a
        possibly submitted allocation. The durable intent remains held.
        """
        with self.exclusive():
            record = self._read()
            require(record is not None and record["operation"] == operation
                    and record["phase"] == "ALLOCATION_INTENT", "allocation-intent-required")
            return self._creation_inputs(record)

    @staticmethod
    def _creation_inputs(record):
        record_fields(record)
        require(record['phase'] != 'CLAIMED', 'allocation-plan-required')
        return {
            'incus_instance_enabled': True, 'incus_instance_binary': '/usr/bin/incus',
            'incus_instance_force_local': True, 'incus_instance_inventory_path': '',
            'incus_instance_results': [],
            'incus_instance_command_user': '', 'incus_instance_default_config': {},
            'incus_instance_default_devices': {}, 'incus_instance_default_limits': {},
            'incus_instance_items': [{
                'name': record['vm_name'], 'type': 'vm', 'state': 'present', 'empty': False, 'create_only': True,
                'reconfigure': False, 'project': record['plan']['project'],
                'image': record['plan']['image_sha256'], 'image_candidates': [],
                'profiles': [record['plan']['profile']], 'config': owner_config(record),
                'cloud_init_enabled': False, 'wait_for_ip': False, 'wait_for_ssh': False}]}

    def execute_allocation_once(self, operation, *, now, revalidate, qualify, execute, observe):
        """Dispatch the trusted installed create-only role once, then bind its VM.

        All callbacks are Root controller dependencies, never job inputs. They
        run under the existing global fence and must not re-enter this Store.
        `execute` must return the actual synchronous provider exit status; a
        timeout, lost result or non-integer/failed result retains dispatch intent.
        No callback is retried here. Profile/image qualification and fresh native
        job admission precede the durable dispatch intent and the first effect.
        """
        require(all(callable(c) for c in (revalidate, qualify, execute, observe)), 'native-provider-required')
        began = time.monotonic()
        with self.exclusive():
            record = self._read()
            require(record is not None and record['operation'] == operation
                    and record['phase'] == 'ALLOCATION_INTENT', 'allocation-dispatch-not-fresh')
            require(type(now) is int and record['created_at'] <= now < record['deadline'], 'allocation-window')
            revalidate(admission.Ticket(**record['ticket']))
            expected = {k: record['plan'][k] for k in ('machine_id', 'project', 'profile_sha256')}
            require(qualify(dict(record['plan'])) == expected, 'native-provider-scope')
            require(now + math.ceil(time.monotonic() - began) < record['deadline'], 'allocation-window')
            record['phase'] = 'ALLOCATION_DISPATCH_INTENT'
            self._write(record)
            require(now + math.ceil(time.monotonic() - began) < record['deadline'], 'allocation-window')
            result = execute(self._creation_inputs(record))
            require(type(result) is int and result == 0, 'allocation-provider-outcome-unknown')
            record['phase'] = 'ALLOCATION_EXECUTED'
            self._write(record)
            native_uuid = vm_identity(record, observe(record['vm_name'], dict(record['plan'])))
            record.update(phase='ALLOCATED', vm_uuid=native_uuid)
            self._write(record)
            return record

    def bind_allocation(self, operation, *, observe):
        """Persist the first native UUID; replacement UUIDs permanently refuse.

        Read-only reconciliation can recover an interrupted allocation without
        another create. It does not release capacity or authorize start/delete.
        """
        require(callable(observe), "native-observation-required")
        with self.exclusive():
            record = self._read()
            require(record is not None and record["operation"] == operation
                    and record["phase"] in {"ALLOCATION_INTENT", "ALLOCATION_EXECUTED", "ALLOCATED"}, "allocation-intent-required")
            native_uuid = vm_identity(record, observe(record["vm_name"], dict(record["plan"])))
            if record["phase"] == "ALLOCATED":
                require(record["vm_uuid"] == native_uuid, "native-instance-replaced")
                return record
            record.update(phase="ALLOCATED", vm_uuid=native_uuid)
            self._write(record)
            return record

    @staticmethod
    def _start_inputs(record):
        record_fields(record)
        require(record['phase'] in {'ALLOCATED', 'START_DISPATCH_INTENT', 'START_EXECUTED', 'STARTED'},
                'owned-allocation-required')
        return {'name': record['vm_name'], 'project': record['plan']['project'], 'vm_uuid': record['vm_uuid'],
                'state': {'action': 'start', 'timeout': 0, 'force': False, 'stateful': False}}

    def execute_start_once(self, operation, *, now, revalidate, qualify, execute, observe):
        """Start only the previously bound stopped VM, once under the global lock.

        Native callbacks are trusted Root dependencies. A lost/nonzero result
        or process exit preserves START_DISPATCH_INTENT; there is no retry,
        registration, deadline extension or capacity release here.
        """
        require(all(callable(c) for c in (revalidate, qualify, execute, observe)), 'native-provider-required')
        began = time.monotonic()
        with self.exclusive():
            record = self._read()
            require(record is not None and record['operation'] == operation
                    and record['phase'] == 'ALLOCATED', 'start-dispatch-not-fresh')
            require(type(now) is int and record['created_at'] <= now < record['deadline'], 'start-window')
            revalidate(admission.Ticket(**record['ticket']))
            expected = {k: record['plan'][k] for k in ('machine_id', 'project', 'profile_sha256')}
            require(qualify(dict(record['plan'])) == expected, 'native-provider-scope')
            require(vm_identity(record, observe(record['vm_name'], dict(record['plan']))) == record['vm_uuid'],
                    'native-instance-replaced')
            require(now + math.ceil(time.monotonic() - began) < record['deadline'], 'start-window')
            record['phase'] = 'START_DISPATCH_INTENT'
            self._write(record)
            require(now + math.ceil(time.monotonic() - began) < record['deadline'], 'start-window')
            result = execute(self._start_inputs(record))
            require(type(result) is int and result == 0, 'start-provider-outcome-unknown')
            record['phase'] = 'START_EXECUTED'
            self._write(record)
            require(vm_identity(record, observe(record['vm_name'], dict(record['plan'])), status='Running')
                    == record['vm_uuid'], 'native-instance-replaced')
            record['phase'] = 'STARTED'
            self._write(record)
            return record

    def bind_started(self, operation, *, observe):
        """Read-only recovery after proven provider completion, never unknown start."""
        require(callable(observe), 'native-observation-required')
        with self.exclusive():
            record = self._read()
            require(record is not None and record['operation'] == operation
                    and record['phase'] in {'START_EXECUTED', 'STARTED'}, 'proven-start-completion-required')
            require(vm_identity(record, observe(record['vm_name'], dict(record['plan'])), status='Running')
                    == record['vm_uuid'], 'native-instance-replaced')
            if record['phase'] != 'STARTED':
                record['phase'] = 'STARTED'
                self._write(record)
            return record

    @staticmethod
    def _stop_inputs(record):
        record_fields(record)
        require(record['vm_uuid'] is not None, 'owned-allocation-required')
        return {'name': record['vm_name'], 'project': record['plan']['project'], 'vm_uuid': record['vm_uuid'],
                'state': {'action': 'stop', 'timeout': 60, 'force': False, 'stateful': False}}

    def execute_stop_once(self, operation, *, execute, observe):
        """Quiesce an exact owned VM once, including after cancellation/expiry.

        Root cleanup authority derives from the bound UUID, not a still-queued
        job. Unknown outcomes hold capacity. No forced stop, deletion or release.
        """
        require(callable(execute) and callable(observe), 'native-provider-required')
        with self.exclusive():
            record = self._read()
            require(record is not None and record['operation'] == operation and record['phase'] in {
                'ALLOCATED', 'START_DISPATCH_INTENT', 'START_EXECUTED', 'STARTED'}, 'stop-dispatch-not-fresh')
            if runtime_stopped(record, observe(record['vm_name'], dict(record['plan']))):
                record['phase'] = 'STOPPED'
                self._write(record)
                return record
            record['phase'] = 'STOP_DISPATCH_INTENT'
            self._write(record)
            result = execute(self._stop_inputs(record))
            require(type(result) is int and result == 0, 'stop-provider-outcome-unknown')
            record['phase'] = 'STOP_EXECUTED'
            self._write(record)
            require(runtime_stopped(record, observe(record['vm_name'], dict(record['plan']))),
                    'native-vm-not-stopped')
            record['phase'] = 'STOPPED'
            self._write(record)
            return record

    def bind_stopped(self, operation, *, observe):
        """Read-only quiescence confirmation, including uncertain stop replies.

        Unlike adoption after unknown creation/start, this UUID was already
        bound. Exact identity + Stopped/PID0 prove quiescence, not API success.
        Pending operation/runner/TLS/storage cleanup and capacity release remain
        separate; no state here authorizes another worker.
        """
        require(callable(observe), 'native-observation-required')
        with self.exclusive():
            record = self._read()
            require(record is not None and record['operation'] == operation
                    and record['phase'] in {'STOP_DISPATCH_INTENT', 'STOP_EXECUTED', 'STOPPED'},
                    'stop-intent-required')
            require(runtime_stopped(record, observe(record['vm_name'], dict(record['plan']))),
                    'native-vm-not-stopped')
            if record['phase'] != 'STOPPED':
                record['phase'] = 'STOPPED'
                self._write(record)
            return record

    @staticmethod
    def _delete_inputs(record):
        record_fields(record)
        require(record['vm_uuid'] is not None, 'owned-allocation-required')
        return {'name': record['vm_name'], 'project': record['plan']['project'], 'vm_uuid': record['vm_uuid']}

    def execute_delete_once(self, operation, *, authorize, execute, observe, absent):
        """Remove a known stopped VM after a trusted Root retention/evidence gate.

        The authorizer is controller code, never job input. It must independently
        establish retention expiry/approval and preserved private evidence. This
        component does not implement that operating gate or release capacity.
        """
        require(all(callable(c) for c in (authorize, execute, observe, absent)), 'native-provider-required')
        with self.exclusive():
            record = self._read()
            require(record is not None and record['operation'] == operation and record['phase'] == 'STOPPED',
                    'delete-dispatch-not-fresh')
            require(authorize(json.loads(json.dumps(record))) is True, 'retention-evidence-gate-required')
            require(runtime_stopped(record, observe(record['vm_name'], dict(record['plan']))),
                    'native-vm-not-stopped')
            record['phase'] = 'DELETE_DISPATCH_INTENT'
            self._write(record)
            result = execute(self._delete_inputs(record))
            require(type(result) is int and result == 0, 'delete-provider-outcome-unknown')
            record['phase'] = 'DELETE_EXECUTED'
            self._write(record)
            require(absent(record['vm_name'], dict(record['plan'])) is True, 'native-vm-not-absent')
            record['phase'] = 'REMOVED'
            self._write(record)
            return record

    def bind_removed(self, operation, *, absent):
        """Read-only absence confirmation; no deletion replay or capacity release."""
        require(callable(absent), 'native-observation-required')
        with self.exclusive():
            record = self._read()
            require(record is not None and record['operation'] == operation and record['phase'] in {
                'DELETE_DISPATCH_INTENT', 'DELETE_EXECUTED', 'REMOVED'}, 'delete-intent-required')
            require(absent(record['vm_name'], dict(record['plan'])) is True, 'native-vm-not-absent')
            if record['phase'] != 'REMOVED':
                record['phase'] = 'REMOVED'
                self._write(record)
            return record

    def abandon_before_effect(self, operation):
        with self.exclusive():
            record = self._read()
            require(record is not None and record["operation"] == operation and record["phase"] == "CLAIMED",
                    "native-reconciliation-required")
            fd = os.open(operation + ".abandoned.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.fd)
            with os.fdopen(fd, "wb") as output:
                output.write(json.dumps(record, sort_keys=True).encode() + b"\n")
                output.flush()
                os.fsync(output.fileno())
            os.unlink("active.json", dir_fd=self.fd)
            os.fsync(self.fd)

    def status(self):
        with self.exclusive():
            return self._read()

    def close(self):
        fd, self.fd = self.fd, None
        if fd is not None:
            os.close(fd)
