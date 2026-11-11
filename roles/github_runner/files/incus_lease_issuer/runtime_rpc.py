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

OPERATIONS = frozenset({"run", "heartbeat", "status", "cancel", "recover"})
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


def _root():
    require(os.geteuid() == 0, "runtime-root-required")


def _configuration(path, sha):
    _root()
    engine_policy._path(path)
    engine_policy._hash(sha)
    proof, raw, _ = installation._file(path, 16384, private=True, keep=True)
    require(proof.sha256 == sha, "runtime-config-drift")
    data = identity.decode_json(raw)
    engine_policy._keys(data, {"schema", "registry_path", "registry_sha256", "preparation_config_path",
        "preparation_config_sha256", "authentication_timeout_seconds", "initial_transition_timeout_seconds",
        "heartbeat_lead_seconds", "cleanup_timeout_seconds", "capture"})
    require(type(data["schema"]) is int and data["schema"] == 2, "runtime-config-schema")
    for key in ("registry_path", "preparation_config_path"):
        engine_policy._path(data[key])
    for key in ("registry_sha256", "preparation_config_sha256"):
        engine_policy._hash(data[key])
    for key, ceiling in (("authentication_timeout_seconds", 60), ("initial_transition_timeout_seconds", 300),
                         ("heartbeat_lead_seconds", 120), ("cleanup_timeout_seconds", 1800)):
        engine_policy._integer(data[key], 1, ceiling)
    capture = engine_policy._keys(data["capture"], {"stdout_limit", "stderr_limit", "total_limit",
                                                   "max_total_evidence_bytes", "max_members", "max_member_bytes"})
    for key in ("stdout_limit", "stderr_limit"):
        engine_policy._integer(capture[key], 1, engine_policy.MAX_CAPTURE_STREAM_BYTES)
    engine_policy._integer(capture["total_limit"], 1, capture["stdout_limit"] + capture["stderr_limit"])
    engine_policy._integer(capture["max_total_evidence_bytes"], 1, 2 ** 31)
    engine_policy._integer(capture["max_members"], 1, 20000)
    engine_policy._integer(capture["max_member_bytes"], 1, capture["max_total_evidence_bytes"])
    return _Configuration(path, sha, **{key: value for key, value in data.items() if key not in {"schema", "capture"}},
                          capture=MappingProxyType(dict(capture)))


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


def _authentication(connected, operation, nonce, seconds):
    value = _read(connected, MAX_AUTH, seconds)
    fields = {"schema", "operation", "nonce", "token", "api_token"}
    if operation in {"heartbeat", "status", "cancel"}:
        fields.add("lease_id")
        require(type(value.get("lease_id")) is str and ledger.ID.fullmatch(value["lease_id"]), "runtime-lease")
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
    complete = actual is not None and all(actual[key + "_state"] == "complete" for key in ("stdout", "stderr"))
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
    def __init__(self, root_config_path, expected_config_sha256):
        _root()
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

    def handle(self, connected):
        _root()
        operation, lease_id, accepted, writing = None, None, False, False
        store, exported, receipt = None, None, None
        try:
            admission._socket(connected)
            selector, operation = _selector(connected)
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
            native = admission.verify_runtime_native(connected, selected, request["nonce"], request["token"], request["api_token"])
            del request["token"], request["api_token"]
            from . import root_session
            with root_session._session(self._config.preparation_config_path,
                                       self._config.preparation_config_sha256) as session:
                config = root_session._require_session(session)
                self._check()
                current_worker, who = admission._require_native(native, connected, selected)
                require(current_worker == worker and admission._controls(selected)[0] == controls, "runtime-peer-drift")
                if operation in {"run", "heartbeat"}:
                    require(self._config.heartbeat_lead_seconds < who.valid_until - int(time.time()),
                            "runtime-renewal-budget")
                if operation == "run":
                    # The client can renew 30 seconds before authorization expires.
                    # Preparation holds the Root session, so reserve that lead
                    # outside the full initial transition before admitting effects.
                    initial_timeout = self._config.initial_transition_timeout_seconds
                    # Leave one second for the session to unwind before renewal.
                    preparation_deadline = who.valid_until - 31
                    require(time.time() + initial_timeout < preparation_deadline
                            and who.valid_until <= selected.deadline,
                            "runtime-initial-authorization-budget")
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
                        self._config.preparation_config_sha256, self._registry, selector, store, lease_id, receipt)
                except engine_executor.EngineUnknown:
                    pass  # Retained actual exit may coexist with a cleanup hold.
                if self._abort_observed(store.read(lease_id)):
                    self._stop_remote_after_abort(store, lease_id, selector)
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
                        # Ledger.close can make terminal cleanup verified.
                        pass
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
        except Exception:
            if accepted and store is not None:
                # An error/failed terminal send NEVER abandons an original
                # child. No replay, replacement Popen or guessed wait status.
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
