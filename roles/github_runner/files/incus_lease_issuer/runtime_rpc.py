"""Uninstalled Runtimev2 Root dispatcher; no listener, CLI or operating grant.

Fresh signed/native identity and the SAME accepted Unix peer are mandatory for
all operations. Read/cancel/recover proof consumption never renews authorization.
The run handler retains the original Popen owner until durable exit, including
when terminal delivery fails. Initial time caps are checked between individually bounded core calls; a
separate watchdog still must enforce a whole blocked-call deadline. Evidence
export and whole cleanup acceptance are not supplied by a process exit or this protocol.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import base64
import os
import re
import select
import socket
import struct
import time
from types import MappingProxyType

from . import (admission, cell_contract, engine_executor, engine_policy, identity, installation,
               ledger, network_fence, policy_registry, preparation, refresh, signed_context)
from .identity import Denied, require

OPERATIONS = frozenset({"run", "heartbeat", "status", "cancel", "recover", "record-upload"})
SELECTOR = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
MAX_AUTH = 40960
MAX_REPLY = 8192
IO_SECONDS = 5


@dataclass(frozen=True)
class _Configuration:
    path: str
    sha256: str
    registry_path: str
    registry_sha256: str
    preparation_config_path: str
    preparation_config_sha256: str
    authentication_timeout_seconds: int
    initial_transition_timeout_seconds: int
    heartbeat_lead_seconds: int
    cleanup_timeout_seconds: int
    capture: MappingProxyType
    capacity: MappingProxyType | None = None
    initial_transition_minimum_seconds: int | None = None


def _root():
    require(os.geteuid() == 0, "runtime-root-required")


def _capacity_policy(value):
    expected = {"schema": 1, "pool_total_bytes": 32 * 1024 ** 3, "pool_reserve_bytes": 1024 ** 3,
        "engine_total_bytes": 17 * 1024 ** 3, "engine_reserve_bytes": 512 * 1024 ** 2,
        "cold_engine_bytes": 8 * 1024 ** 3, "pool_accounting": "owned-dir-retained-v1"}
    refs = {"pool_quota_policy_path", "pool_quota_policy_sha256"}
    require(type(value) is dict and set(value) == set(expected) | refs
            and all(value[key] == actual and type(value[key]) is type(actual) for key, actual in expected.items()),
            "runtime-capacity-policy")
    engine_policy._path(value["pool_quota_policy_path"])
    engine_policy._hash(value["pool_quota_policy_sha256"])
    return MappingProxyType(dict(value))


def _configuration(path, sha):
    _root()
    engine_policy._path(path)
    engine_policy._hash(sha)
    proof, raw, _ = installation._file(path, 16384, private=True, keep=True)
    require(proof.sha256 == sha, "runtime-config-drift")
    data = identity.decode_json(raw)
    required = {"schema", "registry_path", "registry_sha256", "preparation_config_path",
        "preparation_config_sha256", "authentication_timeout_seconds", "initial_transition_timeout_seconds",
        "heartbeat_lead_seconds", "cleanup_timeout_seconds", "capture"}
    optional = {"capacity", "initial_transition_minimum_seconds"} & set(data)
    engine_policy._keys(data, required | optional)
    capacity = _capacity_policy(data["capacity"]) if "capacity" in data else None
    require(type(data["schema"]) is int and data["schema"] == 2, "runtime-config-schema")
    for key in ("registry_path", "preparation_config_path"):
        engine_policy._path(data[key])
    for key in ("registry_sha256", "preparation_config_sha256"):
        engine_policy._hash(data[key])
    for key, ceiling in (("authentication_timeout_seconds", 60), ("initial_transition_timeout_seconds", 300),
                         ("heartbeat_lead_seconds", 120), ("cleanup_timeout_seconds", 1800)):
        engine_policy._integer(data[key], 1, ceiling)
    if "initial_transition_minimum_seconds" in data:
        engine_policy._integer(data["initial_transition_minimum_seconds"], 1,
                               data["initial_transition_timeout_seconds"])
    capture = engine_policy._keys(data["capture"], {"stdout_limit", "stderr_limit", "total_limit",
                                                   "max_total_evidence_bytes", "max_members", "max_member_bytes"})
    for key in ("stdout_limit", "stderr_limit"):
        engine_policy._integer(capture[key], 1, engine_policy.MAX_CAPTURE_STREAM_BYTES)
    engine_policy._integer(capture["total_limit"], 1, capture["stdout_limit"] + capture["stderr_limit"])
    engine_policy._integer(capture["max_total_evidence_bytes"], 1, 2 ** 31)
    engine_policy._integer(capture["max_members"], 1, 20000)
    engine_policy._integer(capture["max_member_bytes"], 1, capture["max_total_evidence_bytes"])
    return _Configuration(path, sha, **{key: value for key, value in data.items() if key not in {"schema", "capture", "capacity"}},
                          capture=MappingProxyType(dict(capture)), capacity=capacity)



def _initial_transition_budget(config, valid_until, now):
    """Reduce a Root-sealed maximum; never extend signed authorization.

    Absent minimum preserves the legacy full-maximum requirement. A separately
    reviewed explicit floor authorizes a shorter bounded initialization attempt,
    not a promise that the complete native setup will finish within that floor.
    """
    require(type(config) is _Configuration and type(valid_until) is int
            and type(now) in {int, float} and math.isfinite(now), "runtime-initial-budget-input")
    maximum = config.initial_transition_timeout_seconds
    minimum = config.initial_transition_minimum_seconds
    minimum = maximum if minimum is None else minimum
    engine_policy._integer(maximum, 1, 300)
    engine_policy._integer(minimum, 1, maximum)
    # Keep the existing 31-second authorization reserve and one further second
    # for transition bookkeeping/unwind before the signed absolute boundary.
    effective = min(maximum, math.floor(valid_until - now - 31 - 1))
    require(effective >= minimum, "runtime-initial-authorization-budget")
    return effective, valid_until - 31


def _read(connected, maximum, seconds):
    admission._socket(connected)
    deadline = time.monotonic() + seconds
    length = struct.unpack("!I", admission._read_exact(connected, 4, deadline))[0]
    require(0 < length <= maximum, "runtime-frame-size")
    value = identity.decode_json(admission._read_exact(connected, length, deadline))
    require(type(value) is dict, "runtime-frame-object")
    return value


def _selector(connected):
    value = _read(connected, 512, IO_SECONDS)
    require(set(value) == {"schema", "cell", "operation"} and type(value["schema"]) is int
            and value["schema"] == 2 and type(value["cell"]) is str and SELECTOR.fullmatch(value["cell"])
            and type(value["operation"]) is str and value["operation"] in OPERATIONS, "runtime-selector")
    return value["cell"], value["operation"]


@identity._diagnostic_step("bootstrap-authentication")
def _authentication(connected, operation, nonce, seconds):
    value = _read(connected, MAX_AUTH, seconds)
    fields = {"schema", "operation", "nonce", "token", "api_token"}
    if operation in {"heartbeat", "status", "cancel"}:
        fields.add("lease_id")
        require(type(value.get("lease_id")) is str and ledger.ID.fullmatch(value["lease_id"]), "runtime-lease")
    if operation == "record-upload":
        fields.add("artifact")
        require(type(value.get("artifact")) is dict and set(value["artifact"]) == {"id", "digest_sha256", "size_in_bytes"},
                "runtime-upload-fields")
    require(set(value) == fields and type(value["schema"]) is int and value["schema"] == 2
            and value["operation"] == operation and value["nonce"] == nonce, "runtime-authentication")
    admission._secret(value["token"])
    admission._secret(value["api_token"])
    # Only a completed write half is accepted. Extra queued/later request bytes
    # cannot become a second operation on this authenticated connection.
    require(select.select([connected], [], [], IO_SECONDS)[0], "runtime-request-eof")
    require(connected.recv(1) == b"", "runtime-trailing-input")
    return value


def _write(connected, value):
    raw = engine_policy._canonical(value)
    require(len(raw) <= MAX_REPLY, "runtime-reply-size")
    framed = struct.pack("!I", len(raw)) + raw
    deadline = time.monotonic() + IO_SECONDS
    offset = 0
    while offset < len(framed):
        require(deadline > time.monotonic() and select.select([], [connected], [], max(0, deadline-time.monotonic()))[1],
                "runtime-reply-timeout")
        try:
            count = connected.send(framed[offset:], socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
        except BlockingIOError:
            continue
        require(count > 0, "runtime-reply-closed")
        offset += count


def _result(operation, lease_id, record, state):
    return {"schema": 2, "type": "result", "operation": operation, "lease_id": lease_id, "state": state,
            "expires_at": record["expires_at"], "authorization_expires_at": record["authorizations"][-1]["valid_until"],
            "receipt_sha256": ledger.digest(record)}


def _terminal(operation, lease_id, record, exported=None):
    starts = [effect for effect in record["effects"].values() if effect["operation"] == "engine-start"]
    actual = starts[0].get("engine_exit") if len(starts) == 1 else None
    exit_value = ({"kind": "exited" if actual["exit_code"] is not None else "signalled",
                   "code": actual["exit_code"], "signal": actual["signal"]} if actual is not None
                  else {"kind": "unknown", "code": None, "signal": None})
    # All fields are already durable Root Ledger metadata. A terminal transfer
    # receipt does not promote capture completeness to Thin/evidence acceptance.
    receipt = ledger.digest({"lease_id": lease_id, "exit": actual,
        "capture": starts[0].get("engine_capture") if len(starts) == 1 else None})
    capture = {"state": "unknown", "receipt_sha256": None}
    if exported is not None:
        from . import evidence_export
        require(type(exported) is evidence_export.ExportReceipt and type(exported.evidence_policy_complete) is bool,
                "runtime-export-receipt")
        capture = {"state": "verified", "receipt_sha256": exported.receipt_sha256}
        receipt = exported.receipt_sha256
    return {"schema": 2, "type": "terminal", "operation": operation, "sequence": 1,
            "lease_id": lease_id, "state": "execution-complete" if actual else "unknown", "exit": exit_value,
            "capture": capture,
            "cleanup": {"state": "verified" if record["state"] == "closed" else "hold"}, "receipt_sha256": receipt}


def _receipt(registry, selector, store, lease_id):
    selected = registry.select(selector)
    _, raw, _ = installation._file(selected.cell_config_path, 65536, private=True, keep=True)
    require(hashlib.sha256(raw).hexdigest() == selected.cell_sha256, "runtime-cell-drift")
    cell = identity.decode_json(raw)
    context = cell["engine"]["paths"]["context"] + "/" + lease_id
    raw, proof = signed_context._sealed(context + "/binding.json", 32768)
    binding = identity.decode_json(raw)
    parts = binding["admission"].split(".")
    require(len(parts) == 3, "runtime-binding-locator")
    # Untrusted locator only. Executor._retained authenticates the whole Root
    # signed binding, immutable inputs, Ledger and exact process/CID afterwards.
    claimed = identity.decode_json(identity.unbase(parts[1]))["engine_policy_sha256"]
    return preparation.PreparationReceipt(lease_id, selected.cell_sha256, claimed, proof.sha256,
                                           store.read(lease_id)["expires_at"])


def _stream(connected, lease_id, exported):
    from . import evidence_export
    require(type(exported) is evidence_export.ExportReceipt, "runtime-export-receipt")
    _write(connected, {"schema": 2, "type": "capture-manifest", "lease_id": lease_id, "sequence": 2,
        "size": exported.size, "sha256": exported.sha256, "chunk_count": exported.chunk_count,
        "content_type": "application/gzip"})
    offset, count, digest = 0, 0, hashlib.sha256()
    for raw in evidence_export.read_chunks(exported):
        require(type(raw) is bytes and 0 < len(raw) <= 4096 and offset + len(raw) <= exported.size,
                "runtime-export-chunk")
        _write(connected, {"schema": 2, "type": "capture-chunk", "lease_id": lease_id,
            "sequence": 3 + count, "offset": offset,
            "data": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")})
        offset += len(raw)
        count += 1
        digest.update(raw)
    require(offset == exported.size and count == exported.chunk_count and digest.hexdigest() == exported.sha256,
            "runtime-export-stream")


class RuntimeRPC:
    """Root-fixed factory; no transport/command/Worker/policy request hooks."""
    def __init__(self, root_config_path, expected_config_sha256, *, derived_configuration=None):
        _root()
        self._derived_configuration = derived_configuration
        self._origin = None
        if derived_configuration is not None:
            from . import run_factory
            self._origin = run_factory.read_configuration_origin(derived_configuration)
            require(derived_configuration.runtime_config_path == root_config_path
                    and derived_configuration.runtime_config_sha256 == expected_config_sha256, "runtime-derived-config")
        self._config = _configuration(root_config_path, expected_config_sha256)
        self._registry = policy_registry.load_registry(self._config.registry_path, self._config.registry_sha256)
        self._check()

    def _check(self):
        config = self._config
        require(_configuration(config.path, config.sha256) == config
                and policy_registry.load_registry(config.registry_path, config.registry_sha256) == self._registry,
                "runtime-root-drift")
        selected = preparation._config(config.preparation_config_path, config.preparation_config_sha256)[0]
        require(selected.registry_path == config.registry_path and selected.registry_sha256 == config.registry_sha256,
                "runtime-preparation-registry")
        return selected

    def _require_origin(self, who, selector):
        if self._derived_configuration is not None:
            from . import run_factory
            origin = run_factory.read_configuration_origin(self._derived_configuration)
            require(origin == self._origin and origin["selector"] == selector
                    and (who.run_id, who.job_id, who.check_run_id, who.caller_sha, who.reusable_sha)
                    == (origin["run_id"], origin["job_id"], origin["check_run_id"], origin["source_sha"], origin["reusable_sha"]),
                    "runtime-derived-invocation")

    @staticmethod
    def _abort_observed(record):
        """Root observations only; never a job-provided cleanup/acceptance flag."""
        now = int(time.time())
        if record["state"] == "cancelled" or now >= min(record["expires_at"],
                record["authorizations"][-1]["valid_until"]):
            return True
        return any(row["operation"] == "engine-start" and "engine_exit" in row
                   and any(row["engine_exit"][name+"_state"] != "complete" for name in ("stdout", "stderr"))
                   for row in record["effects"].values())

    def _stop_remote_after_abort(self, store, lease_id, selector):
        # This helper owns its finite Root session. Call only OUTSIDE the
        # initial session and after original local supervision, before evidence
        # export can hold. Missing real exit/stop/withdrawal/drain stays held.
        from . import emergency_stop
        try:
            return emergency_stop.RootEmergencyStop(self._config.path, self._config.sha256).stop(
                self._registry, selector, store, lease_id)
        except (emergency_stop.EmergencyStopDenied, emergency_stop.EmergencyStopUnknown):
            return None  # Never deletion, close, cleanup PASS or a retry.

    def _retain_after_failure(self, store, lease_id, selector, receipt):
        """Private original-owner failure boundary; no supplied owner hook."""
        owners = [owner for owner in engine_executor._PROCESSES.values()
                  if type(owner) is engine_executor.engine_supervision.OwnedRun
                  and owner.lease_id == lease_id and owner.store is store
                  and owner.owner_pid == os.getpid() and not owner.closed]
        try:
            if owners:
                # Exact original ownership; one journaled local stop then the
                # same authorization/deadline/capture/drain/actual-exit loop.
                engine_executor._abort_after_failure(self._config.preparation_config_path,
                    self._config.preparation_config_sha256, self._registry, selector,
                    store, lease_id, receipt)
        finally:
            # Strong remote factory independently denies absent original exit
            # or unverified local stop/paired withdrawal. No fabricated stop.
            self._stop_remote_after_abort(store, lease_id, selector)

    @identity._diagnostic_request(reuse=True)
    def handle(self, connected):
        return self._handle_selected(connected, None)

    @identity._diagnostic_step("runtime-selected")
    def _handle_selected(self, connected, selection):
        # Selection is only a locator parsed by the fixed bootstrap entry.
        # Fresh normal native authentication below grants all actual authority.
        _root()
        operation, lease_id, accepted, writing = None, None, False, False
        retention_attempted = False  # Request-local control flow, never authority or a retry permission.
        store, exported, receipt = None, None, None
        try:
            admission._socket(connected)
            selector, operation = _selector(connected) if selection is None else selection
            require(type(selector) is str and SELECTOR.fullmatch(selector) and operation in OPERATIONS, "runtime-selector")
            self._check()
            selected = self._registry.select(selector)
            admission._validate_policy(selected)
            _, cell_raw, _ = installation._file(selected.cell_config_path, cell_contract.MAX_CELL, private=True, keep=True)
            require(hashlib.sha256(cell_raw).hexdigest() == selected.cell_sha256, "runtime-cell-drift")
            capture = identity.decode_json(cell_raw)["engine"]["capture"]
            require(capture == {key: self._config.capture[key]
                    for key in ("stdout_limit", "stderr_limit", "total_limit")}, "runtime-capture-policy")
            controls = admission._controls(selected)[0]
            worker = admission._worker(connected, selected)
            store = ledger.Ledger(selected.ledger_path, clock=time.time)
            challenge = store.runtime_challenge(worker, operation, selected.cell_sha256,
                identity.policy_digest(selected.identity), ttl=self._config.authentication_timeout_seconds)
            writing = True
            _write(connected, {"schema": 2, "type": "challenge", "operation": operation, **challenge})
            writing = False
            request = _authentication(connected, operation, challenge["nonce"], self._config.authentication_timeout_seconds)
            if operation == "record-upload":
                from . import operating_upload
                ticket = admission.verify_intake_native(connected, selected, request["nonce"], request["token"], request["api_token"])
                current_worker, who, _ = admission.require_intake_native(ticket, connected, selected,
                                                                         request["token"], request["api_token"])
                self._require_origin(who, selector)
                joined = store.consume_runtime_proof(request["nonce"], current_worker, who, operation,
                    cell_sha256=selected.cell_sha256, identity_policy_sha256=identity.policy_digest(selected.identity),
                    policy_sha256=selected.custody_policy_sha256, deadline=selected.deadline, lease_id=None)
                lease_id = joined.lease_id
                upload = operating_upload.verify_uploaded_artifact(self._config.path, self._config.sha256,
                    self._registry, selector, store, lease_id, ticket, connected,
                    request["token"], request["api_token"], request["artifact"])
                del request["token"], request["api_token"]
                store.bind_uploaded_evidence(lease_id, upload)
                operating_upload.finish_transport(store, lease_id, upload)
                writing = True
                outcome = _result(operation, lease_id, store.read(lease_id), "awaiting-native-end")
                _write(connected, outcome)
                return outcome
            deferred_native = operation == "run" and self._derived_configuration is not None
            native = None if deferred_native else admission.verify_runtime_native(
                connected, selected, request["nonce"], request["token"], request["api_token"])
            if not deferred_native:
                del request["token"], request["api_token"]
            from . import root_session
            with root_session._session(self._config.preparation_config_path,
                                       self._config.preparation_config_sha256) as session:
                config = root_session._require_session(session)
                self._check()
                if deferred_native:
                    require(ledger.asdict(worker) == self._origin["worker"] and selector == self._origin["selector"],
                            "runtime-derived-original-worker")
                    from . import capacity
                    capacity.require_capacity(self._config.path, self._config.sha256,
                        self._registry, selector, store, session=session)
                    native = admission.verify_runtime_native(connected, selected, request["nonce"], request["token"], request["api_token"])
                    del request["token"], request["api_token"]
                # The original five-second native capability must STILL be
                # live after pre-admission reads. No timing allowance, token
                # expiry or running lease is silently stretched by preflight.
                current_worker, who = admission._require_native(native, connected, selected)
                require(current_worker == worker and admission._controls(selected)[0] == controls, "runtime-peer-drift")
                self._require_origin(who, selector)
                if operation in {"run", "heartbeat"}:
                    require(self._config.heartbeat_lead_seconds < who.valid_until - int(time.time()),
                            "runtime-renewal-budget")
                if operation == "run":
                    # The client can renew 30 seconds before authorization expires.
                    # Preparation holds the Root session, so reserve that lead
                    # outside the full initial transition before admitting effects.
                    initial_timeout, preparation_deadline = _initial_transition_budget(
                        self._config, who.valid_until, time.time())
                    require(who.valid_until <= selected.deadline, "runtime-initial-authorization-budget")
                    lease_id = store.runtime_prepare(native.nonce, current_worker, who,
                        policy_sha256=selected.custody_policy_sha256, cell_sha256=selected.cell_sha256,
                        deadline=selected.deadline, identity_policy_sha256=identity.policy_digest(selected.identity))
                    record = store.read(lease_id)
                    writing = True
                    _write(connected, {"schema": 2, "type": "accepted", "operation": "run", "sequence": 0,
                        "lease_id": lease_id, "state": "preparing", "expires_at": record["expires_at"],
                        "authorization_expires_at": record["authorizations"][-1]["valid_until"]})
                    writing, accepted = False, True
                    end = time.monotonic() + initial_timeout
                    def budget():
                        self._check()
                        root_session._require_session(session)
                        latest = store.read(lease_id)
                        require(time.monotonic() < end and int(time.time()) < min(latest["expires_at"],
                            preparation_deadline), "runtime-initial-budget")
                    from . import runtime_entry
                    with runtime_entry._initial_effects_deadline(initial_timeout,
                            min(record["expires_at"], preparation_deadline)):
                        budget()
                        receipt = preparation._prepare_locked(session, self._registry, selector, store, lease_id)
                        budget()
                        prepared = cell_contract.prepare_cell(self._registry, selector, store, lease_id)
                        manifest = engine_policy.compile_engine_policy(prepared.engine_descriptor_path, prepared.engine_descriptor_sha256)
                        details = identity.decode_json(manifest.canonical_bytes)
                        require(details["capture"] == {key: self._config.capture[key]
                                for key in ("stdout_limit", "stderr_limit", "total_limit")}, "runtime-capture-policy")
                        network_fence.create(config.network_fence_policy_path, config.network_fence_policy_sha256,
                                             prepared, store, current_worker, config)
                        budget()
                        network_fence.renew(config.network_fence_policy_path, config.network_fence_policy_sha256,
                                            prepared, store, current_worker, config)
                        budget()
                        engine_executor._start_locked(session, self._registry, selector, store, lease_id, receipt)
                elif operation == "heartbeat":
                    lease_id = request["lease_id"]
                    refresh._refresh_locked(session, connected, self._registry, selector, store, lease_id, native_proof=native)
                else:
                    proof = store.consume_runtime_proof(native.nonce, current_worker, who, operation,
                        cell_sha256=selected.cell_sha256, identity_policy_sha256=identity.policy_digest(selected.identity),
                        policy_sha256=selected.custody_policy_sha256, deadline=selected.deadline,
                        lease_id=None if operation == "recover" else request["lease_id"])
                    lease_id = proof.lease_id
                    if operation == "cancel":
                        store.cancel(lease_id, "cancelled")
                        current = store.read(lease_id)
                        if any(e["operation"] == "fence-create" and e["state"] == "verified"
                               for e in current["effects"].values()):
                            # Withdraw even if engine start never happened.
                            # Uncertainty still allows the narrowly owned
                            # stop; it never becomes overall cleanup PASS.
                            engine_executor._withdraw_retained(config, self._registry, selector, store, lease_id)
            # All long waits and nested public cleanup/status wrappers are
            # outside the session; they reacquire their own finite lock.
            if operation == "run":
                try:
                    engine_executor.wait_for_exit(self._config.preparation_config_path,
                        self._config.preparation_config_sha256, self._registry, selector, store, lease_id, receipt, notification_socket=connected)
                except engine_executor.EngineUnknown:
                    pass  # Retained actual exit may coexist with a cleanup hold.
                self._stop_remote_after_abort(store, lease_id, selector)
                _, cell_raw, _ = installation._file(selected.cell_config_path, cell_contract.MAX_CELL, private=True, keep=True)
                if identity.decode_json(cell_raw).get("kind") == "operating":
                    from . import operating_custody
                    result = operating_custody.operating_outcome(self._config.path, self._config.sha256,
                        self._registry, selector, store, lease_id)
                    outcome = {"schema": 2, "type": "operating-terminal", "operation": "run", "lease_id": lease_id, "receipt": result}
                    _write(connected, outcome)
                    return outcome
                try:
                    from . import evidence_export
                    exported = evidence_export.export_existing(self._config.path, self._config.sha256,
                        self._registry, selector, store, lease_id)
                except Denied:
                    exported = None
                if exported is not None:
                    from . import finalization
                    try:
                        finalization.RootFinalizer(self._config.path, self._config.sha256).finalize(
                            self._registry, selector, store, lease_id)
                    except (finalization.FinalizationDenied, finalization.FinalizationUnknown):
                        # Preserve the observed exit/evidence, but ONLY actual
                        # Ledger.close can make terminal cleanup verified. Keep
                        # the exact original owner safeguarded as the generic
                        # failure path did, even if its earlier drain held.
                        retention_attempted = True
                        try:
                            self._retain_after_failure(store, lease_id, selector, receipt)
                        except Exception:
                            pass  # Hold stays; no replacement waiter or UNKNOWN-effect retry.
                outcome = _terminal(operation, lease_id, store.read(lease_id), exported)
            elif operation == "cancel":
                receipt = _receipt(self._registry, selector, store, lease_id)
                try:
                    engine_executor.cancel(self._config.preparation_config_path, self._config.preparation_config_sha256,
                        self._registry, selector, store, lease_id, receipt)
                except engine_executor.EngineUnknown:
                    pass
                self._stop_remote_after_abort(store, lease_id, selector)
                outcome = _result(operation, lease_id, store.read(lease_id), "cleanup-hold")
            elif operation == "recover":
                try:
                    from . import evidence_export
                    retained = store.read(lease_id)
                    # Any raw-release attempt may have removed its inputs.
                    # Recover only reads the bound sibling receipt; no fallback
                    # publication, finalization or partial-effect retry exists.
                    released = retained["state"] == "closed" or any(
                        row["operation"] == "engine-release" for row in retained["effects"].values())
                    reader = evidence_export.read_existing if released else evidence_export.export_existing
                    exported = reader(self._config.path, self._config.sha256,
                        self._registry, selector, store, lease_id)
                except Denied:
                    exported = None
                outcome = _terminal(operation, lease_id, store.read(lease_id), exported)
            else:
                record = store.read(lease_id)
                state = "unknown"
                if record["state"] == "closed":
                    state = "closed"
                elif operation == "heartbeat":
                    state = "running" if any(e["operation"] == "engine-start" for e in record["effects"].values()) else "preparing"
                else:
                    starts = [e for e in record["effects"].values() if e["operation"] == "engine-start"]
                    if starts:
                        receipt = _receipt(self._registry, selector, store, lease_id)
                        observed = engine_executor.status(self._config.preparation_config_path,
                            self._config.preparation_config_sha256, self._registry, selector, store, lease_id, receipt)
                        state = "running" if observed.state == "owned-running-not-test-success" else "unknown"
                        if len(starts) == 1 and "engine_exit" in starts[0]:
                            state = "execution-complete"
                outcome = _result(operation, lease_id, record, state)
            writing = True
            _write(connected, outcome)
            if exported is not None:
                _stream(connected, lease_id, exported)
            return outcome
        except Exception as error:
            identity._diagnostic_failed("runtime-selected", error)
            if accepted and store is not None and not retention_attempted:
                # An error/failed terminal send NEVER abandons an original
                # child. No replay, replacement Popen or guessed wait status.
                retention_attempted = True
                try:
                    self._retain_after_failure(store, lease_id, selector, receipt)
                except Exception:
                    pass  # Unknown ownership/stop/exit is never success.
            if writing:
                # A partially delivered frame gets no second reply/effect retry.
                raise Denied("runtime-delivery-unknown") from None
            disposition = "unknown-hold" if lease_id is not None else "denied-before-intent"
            outcome = {"schema": 2, "type": "failure", "operation": operation, "disposition": disposition}
            _write(connected, outcome)
            return outcome
        finally:
            if store is not None:
                store.shutdown()


OBSERVER_OPERATIONS = frozenset({"observe-profile", "observe-operating"})


BOOTSTRAP_BINDINGS = "/var/lib/lightning-it/incus-operating-bindings"


class BootstrapRuntimeRPC:
    """Repeatable native Main intake, then separately fresh actual admission.

    No private per-run preparation is represented as a lease or running cell.
    The global base policy, signer, ledger and anchor are never republished.
    """
    def __init__(self, bootstrap_path, bootstrap_sha256):
        from . import run_factory
        self._bootstrap = run_factory.load_bootstrap(bootstrap_path, bootstrap_sha256)

    def _binding(self, configuration):
        from . import operating_watchdog
        value = {"schema": 1, "runtime_config_path": configuration.runtime_config_path,
            "runtime_config_sha256": configuration.runtime_config_sha256,
            "snapshot_manifest_sha256": configuration.manifest_sha256}
        directory = operating_watchdog._private_directory(BOOTSTRAP_BINDINGS)
        try:
            name = "binding-" + ledger.digest(value) + ".json"
            try:
                operating_watchdog._save_once(directory, name, value)
            except FileExistsError:
                require(operating_watchdog._read(directory, name)[0] == value, "runtime-bootstrap-binding-held")
        finally:
            os.close(directory)

    @identity._diagnostic_step("observer")
    def _observe(self, connected, bootstrap, selector, operation):
        from . import operating_custody, run_factory
        challenge = run_factory.challenge_bootstrap(connected, bootstrap, selector)
        _write(connected, {"schema": 2, "type": "challenge", "operation": operation,
                          "phase": "observer", **challenge})
        request = _authentication(connected, operation, challenge["nonce"],
                                  bootstrap.value["runtime"]["authentication_timeout_seconds"])
        proof = run_factory.verify_bootstrap_native(connected, bootstrap, selector, request["nonce"],
            request["token"], request["api_token"], purpose="observer")
        configuration = run_factory.find_existing_configuration(bootstrap, selector, proof)
        _, who, remaining = run_factory.require_bootstrap_native(proof, connected, proof.policy,
                                                                 request["token"], request["api_token"])
        origin = run_factory.read_configuration_origin(configuration)
        require((who.run_id, who.caller_sha, who.reusable_sha) ==
                (origin["run_id"], origin["source_sha"], origin["reusable_sha"])
                and who.check_run_id != origin["check_run_id"] and who.job_id != origin["job_id"],
                "runtime-observer-original-invocation")
        runtime = RuntimeRPC(configuration.runtime_config_path, configuration.runtime_config_sha256)
        selected = runtime._registry.select(selector)
        with ledger.Ledger(selected.ledger_path, clock=time.time) as store:
            matches = [lease_id for lease_id in store.lease_ids()
                if store.read(lease_id)["cell_sha256"] == selected.cell_sha256
                and all(store.read(lease_id)["identity"][field] == origin[field] for field in ("run_id", "job_id", "check_run_id"))]
            require(len(matches) == 1, "runtime-observer-original-lease")
            lease_id = matches[0]
            if "native_terminal" not in store.read(lease_id):
                terminal = operating_custody.observe_native_terminal(runtime._registry, selector, store, lease_id,
                                                                      api_token=request["api_token"])
                store.bind_native_terminal(lease_id, terminal)
            end = time.monotonic() + min(120, remaining)
            while True:
                require(time.monotonic() < end, "runtime-observer-wait-held")
                record = store.read(lease_id)
                if operation == "observe-operating" and record["state"] == "retained":
                    receipt = operating_custody.operating_outcome(configuration.runtime_config_path,
                        configuration.runtime_config_sha256, runtime._registry, selector, store, lease_id, retained=True)
                    kind = "operating-receipt"
                    break
                if operation == "observe-profile" and record["state"] == "closed":
                    run_factory.require_bootstrap_native(proof, connected, proof.policy, request["token"], request["api_token"])
                    config = runtime._check()
                    receipt = signed_context.RootSigner(config.signing_key_path, config.signing_public_key).issue_final_receipt(
                        runtime._registry, selector, store, lease_id)
                    kind = "final-receipt"
                    break
                require(not any(row["state"] == "unknown" for row in record["effects"].values()),
                        "runtime-observer-cleanup-unknown")
                time.sleep(min(1, max(0, end - time.monotonic())))
            # No new authority or renewal: original observer JWT, same socket,
            # same native job and Root controls are freshly rechecked at return.
            run_factory.require_bootstrap_native(proof, connected, proof.policy, request["token"], request["api_token"])
            del request["token"], request["api_token"]
            outcome = {"schema": 2, "type": kind, "operation": operation, "cell": selector, "receipt": receipt}
            _write(connected, outcome)
            return outcome

    @identity._diagnostic_request(reuse=True)
    def handle(self, connected):
        from . import run_factory
        operation, handed_off, staging = None, False, False
        try:
            admission._socket(connected)
            message = _read(connected, 1024, IO_SECONDS)
            require(set(message) in ({"schema", "cell", "operation"}, {"schema", "cell", "operation", "configuration"})
                    and type(message.get("schema")) is int and message["schema"] == 2
                    and type(message.get("cell")) is str and SELECTOR.fullmatch(message["cell"])
                    and message.get("operation") in OPERATIONS | OBSERVER_OPERATIONS, "runtime-bootstrap-selector")
            selector, operation = message["cell"], message["operation"]
            bootstrap = run_factory.load_bootstrap(self._bootstrap.path, self._bootstrap.sha256)
            if operation in OBSERVER_OPERATIONS:
                require("configuration" not in message, "runtime-observer-no-admission-locator")
                staging = True  # Native terminal readback may be durably recorded.
                return self._observe(connected, bootstrap, selector, operation)
            if "configuration" in message:
                run_factory._worker(connected, bootstrap)  # Cheap managed-peer proof before fixed-catalogue reads.
                configuration = run_factory.resolve_configuration(bootstrap, selector, message["configuration"])
                handed_off = True
                return RuntimeRPC(configuration.runtime_config_path, configuration.runtime_config_sha256,
                    derived_configuration=configuration)._handle_selected(connected, (selector, operation))
            challenge = run_factory.challenge_bootstrap(connected, bootstrap, selector)
            _write(connected, {"schema": 2, "type": "challenge", "operation": operation,
                              "phase": "intake", **challenge})
            request = _authentication(connected, operation, challenge["nonce"],
                                      bootstrap.value["runtime"]["authentication_timeout_seconds"])
            proof = run_factory.verify_bootstrap_native(connected, bootstrap, selector, request["nonce"],
                                                        request["token"], request["api_token"])
            if operation == "run":
                staging = True
                # This factory performs the single authoritative archive stage;
                # no redundant outer acquisition/readback or assumed receipt.
                configuration = run_factory.create_run_configuration(proof, connected, bootstrap, selector,
                    request["token"], request["api_token"])
            else:
                configuration = run_factory.find_existing_execution_configuration(bootstrap, selector, proof)
            run_factory.require_bootstrap_native(proof, connected, proof.policy, request["token"], request["api_token"])
            del request["token"], request["api_token"]
            self._binding(configuration)
            result = {"schema": 2, "type": "intake-ready", "operation": operation, "cell": selector,
                "configuration": configuration.manifest_sha256, "deadline": configuration.deadline,
                "lease_created": False}
            _write(connected, result)
            return result
        except Exception as error:
            identity._diagnostic_failed("bootstrap", error)
            if handed_off:
                return {"type": "failure"}  # Inner dispatcher owns the sole reply.
            failure = {"schema": 2, "type": "failure", "operation": operation,
                       "disposition": "unknown-hold" if staging else "denied-before-intent"}
            # FS intake intents can remain held, but no lease/workload authority
            # has been admitted. Never print input, URL, credential or errors.
            try:
                _write(connected, failure)
            except Exception:
                pass
            return failure
