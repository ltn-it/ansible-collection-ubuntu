"""Root-only custody gate; native terminal/upload proof is not test success.

Public job input cannot waive custody. Unknown outcome or missing independent
job completion holds all destructive release. Safety withdrawal is separate.
"""
from dataclasses import dataclass
import datetime as dt
import os
import threading
import time
import weakref

from . import identity, policy_registry

from . import ledger
from .identity import require


def require_cleanup_allowed(store, lease_id):
    """Deny destructive release until actual terminal policy is satisfied.

    The original actual execution job is authoritative, not a later observer.
    This gate never extends engine/job authority or retries an unknown effect.
    """
    require(os.geteuid() == 0 and type(store) is ledger.Ledger, "custody-root-required")
    record = store.read(lease_id)
    return cleanup_allowed_record(record, store.read_policy(record["policy_sha256"]), store._now())


def cleanup_allowed_record(record, policy, now):
    """Pure policy gate for the existing Root transaction; grants no effects."""
    require(not any(row["state"] in {"intent", "unknown"} for row in record["effects"].values()),
            "custody-unresolved-effect")
    require(record.get("upload_verification", {}).get("state") != "intent", "custody-upload-verification-held")
    terminal = record.get("native_terminal")
    require(type(terminal) is dict, "custody-native-terminal-required")
    starts = [row for row in record["effects"].values() if row["operation"] == "engine-start"]
    actual = starts[0].get("engine_exit") if len(starts) == 1 else None
    success = (record.get("cancel_reason") is None and actual is not None
               and actual["exit_code"] == 0 and actual["signal"] is None
               and all(actual[key + "_state"] == "complete" for key in ("stdout", "stderr"))
               and terminal.get("conclusion") == "success" and type(record.get("uploaded_evidence")) is dict
               and record["uploaded_evidence"].get("execution_success") is True
               and record.get("upload_transport", {}).get("state") == "verified")
    if not success:
        custody = record.get("custody")
        require(type(custody) is dict and custody["terminal_at"] == terminal["completed_at"]
                and custody["retain_until"] >= custody["terminal_at"] + policy["retention_seconds"]
                and custody["retain_until"] <= custody["terminal_at"] + 86400
                and now >= custody["retain_until"], "custody-retention-not-elapsed")
    return success


_TERMINAL_FIELDS = frozenset({"schema", "repository", "repository_id", "run_id", "run_attempt",
    "job_id", "check_run_id", "source_sha", "controller_sha", "conclusion", "completed_at", "observed_at",
    "native_sha256", "cell_sha256"})
_CONCLUSIONS = frozenset({"success", "failure", "cancelled", "timed_out", "action_required", "skipped",
                         "neutral", "stale", "startup_failure"})


def _terminal_record(value, record):
    who = record["identity"]
    require(type(value) is dict and set(value) == _TERMINAL_FIELDS and type(value["schema"]) is int
            and value["schema"] == 1 and value["run_attempt"] == 1
            and all(type(value[k]) is int and value[k] > 0 for k in
                ("repository_id", "run_id", "job_id", "check_run_id", "completed_at", "observed_at"))
            and value["run_id"] == who["run_id"] and value["job_id"] == who["job_id"]
            and value["check_run_id"] == who["check_run_id"] and value["source_sha"] == who["caller_sha"]
            and value["controller_sha"] == who["reusable_sha"] and value["cell_sha256"] == record["cell_sha256"]
            and value["conclusion"] in _CONCLUSIONS and value["completed_at"] <= value["observed_at"]
            and type(value["native_sha256"]) is str and ledger.HEX.fullmatch(value["native_sha256"]),
            "custody-native-terminal-binding")


@dataclass(frozen=True, eq=False)
class _NativeTerminalProof:
    lease_id: str
    lease_sha256: str
    payload: bytes
    pid: int
    thread: int
    until: float


_TERMINAL_PROOFS = weakref.WeakSet()
_TERMINAL_GUARD = threading.Lock()


def _completion(value, now):
    require(type(value) is str and len(value) == 20 and value.endswith("Z"), "custody-native-completion")
    try:
        stamp = int(dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp())
    except ValueError:
        raise ledger.Denied("custody-native-completion") from None
    require(0 < stamp <= now, "custody-native-completion")
    return stamp



class NativeJobPending(ledger.Denied):
    """Known original job has not ended; not an incident or a cleanup grant."""


def observe_native_terminal(registry, selector, store, lease_id, *, api_token=None):
    """Fixed public HTTPS readback of the ORIGINAL execution job, never a hint.

    No retained API credential, callback, job-selected URL, retry, or inference
    of terminal success on an inaccessible/rate-limited provider is permitted.
    """
    require(os.geteuid() == 0 and type(registry) is policy_registry.Registry
            and type(store) is ledger.Ledger, "custody-root-required")
    selected = registry.select(selector)
    record = store.read(lease_id)
    who, policy = record["identity"], selected.identity
    require(record["cell_sha256"] == selected.cell_sha256 and record["policy_sha256"] == selected.custody_policy_sha256
            and who["policy_sha256"] == identity.policy_digest(policy) and policy.visibility == "public",
            "custody-native-root-binding")
    if "native_terminal" in record:
        # Immutable original terminal is authenticated once and durably cached;
        # no new provider-read freshness is claimed by this registered locator.
        proof = _NativeTerminalProof(lease_id, ledger.digest(record), ledger.canonical(record["native_terminal"]),
            os.getpid(), threading.get_ident(), time.monotonic() + 5)
        with _TERMINAL_GUARD:
            _TERMINAL_PROOFS.add(proof)
        return proof
    if api_token is None and store._now() < record.get("native_poll_after", 0):
        raise NativeJobPending("custody-native-poll-deferred")
    prefix = identity.API + "/repos/" + policy.repository
    reader = identity.HTTPSReader()
    if api_token is not None:
        from . import admission
        admission._secret(api_token)
    def read(path):
        raw = reader.read(prefix + path) if api_token is None else reader.read(prefix + path, bearer=api_token)
        return identity.decode_json(raw)
    started = int(time.time())
    job = read("/actions/jobs/" + str(who["job_id"]))
    require(job.get("id") == who["job_id"] and job.get("run_id") == who["run_id"]
            and job.get("head_sha") == who["caller_sha"] and job.get("runner_id") == who["runner_id"]
            and job.get("name") == policy.required_native_job_name and job.get("run_attempt") == 1,
            "custody-native-job")
    if job.get("status") in {"queued", "in_progress"} and job.get("conclusion") is None:
        store.defer_terminal_poll(lease_id)
        raise NativeJobPending("custody-original-job-not-terminal")
    run = read("/actions/runs/" + str(who["run_id"]))
    check = read("/check-runs/" + str(who["check_run_id"]))
    repo = run.get("repository", {})
    owner = repo.get("owner", {})
    require(run.get("id") == who["run_id"] and type(run.get("run_attempt")) is int and run["run_attempt"] == 1
            and run.get("event") == "push" and run.get("head_branch") == "main"
            and run.get("head_sha") == policy.caller_sha == who["caller_sha"]
            and run.get("workflow_id") == policy.workflow_id and run.get("path") == policy.workflow_path
            and repo.get("id") == policy.repository_id and repo.get("full_name") == policy.repository
            and repo.get("private") is False and owner.get("id") == policy.owner_id,
            "custody-native-run")
    actors = [run.get(key, {}) for key in ("actor", "triggering_actor")]
    require(all(type(actor.get("id")) is int and actor["id"] in policy.actor_ids
                and actor.get("type") == "User" for actor in actors) and actors[0] == actors[1],
            "custody-native-actors")
    refs = run.get("referenced_workflows")
    expected_ref = policy.reusable_repository + "/" + policy.reusable_path + "@" + policy.reusable_sha
    require(type(refs) is list and len([r for r in refs if type(r) is dict and r.get("path") == expected_ref
            and r.get("sha") == policy.reusable_sha]) == 1, "custody-native-controller")
    require(job.get("id") == who["job_id"] and job.get("run_id") == who["run_id"]
            and type(job.get("run_attempt")) is int and job["run_attempt"] == 1
            and job.get("head_sha") == who["caller_sha"] and job.get("runner_id") == who["runner_id"]
            and job.get("name") == policy.required_native_job_name and job.get("status") == "completed"
            and job.get("conclusion") in _CONCLUSIONS
            and job.get("check_run_url") == prefix + "/check-runs/" + str(who["check_run_id"]),
            "custody-native-job")
    completed = _completion(job.get("completed_at"), started)
    require(check.get("id") == who["check_run_id"] and check.get("head_sha") == who["caller_sha"]
            and check.get("status") == "completed" and check.get("conclusion") == job["conclusion"],
            "custody-native-check")
    require(read("/actions/jobs/" + str(who["job_id"])) == job and int(time.time()) - started <= 45,
            "custody-native-terminal-drift")
    value = {"schema": 1, "repository": policy.repository, "repository_id": policy.repository_id,
        "run_id": who["run_id"], "run_attempt": 1, "job_id": who["job_id"], "check_run_id": who["check_run_id"],
        "source_sha": who["caller_sha"], "controller_sha": who["reusable_sha"], "conclusion": job["conclusion"],
        "completed_at": completed, "observed_at": started, "native_sha256": ledger.digest({"run": run, "job": job, "check": check}),
        "cell_sha256": record["cell_sha256"]}
    _terminal_record(value, record)
    proof = _NativeTerminalProof(lease_id, ledger.digest(record), ledger.canonical(value), os.getpid(),
                                threading.get_ident(), time.monotonic() + 5)
    with _TERMINAL_GUARD:
        _TERMINAL_PROOFS.add(proof)
    return proof


def require_terminal_proof(proof, lease_id, record):
    require(type(proof) is _NativeTerminalProof, "custody-native-proof")
    with _TERMINAL_GUARD:
        require(proof in _TERMINAL_PROOFS, "custody-native-proof")
    require(proof.lease_id == lease_id and proof.lease_sha256 == ledger.digest(record)
            and proof.pid == os.getpid() and proof.thread == threading.get_ident()
            and time.monotonic() < proof.until, "custody-native-proof-drift")
    value = identity.decode_json(proof.payload)
    _terminal_record(value, record)
    return value


def final_receipt_payload(registry, selector, store, lease_id, public_key_hex, *, issued_at=None):
    """Derive the final signed frame solely from closed original Root proof."""
    from . import cell_contract
    require(os.geteuid() == 0 and type(registry) is policy_registry.Registry and type(store) is ledger.Ledger,
            "final-receipt-root-required")
    record = store.read(lease_id)
    require(record["state"] == "closed", "final-receipt-not-closed")
    ledger.Ledger._cleanup_complete(list(record["effects"].values()))
    require(require_cleanup_allowed(store, lease_id), "final-receipt-execution-failed")
    selected = registry.select(selector)
    owner = cell_contract.owned_cell_for_cleanup(registry, selector, store, lease_id)
    descriptor = identity.decode_json(owner.engine_descriptor_bytes)
    env = descriptor["environment"]
    terminal, upload = record["native_terminal"], record["uploaded_evidence"]
    # Capture binding was verified against actual provider ZIP bytes before
    # upload recording; absence or arbitrary manifest flags cannot replace it.
    require(type(upload) is dict and upload["capture_receipt_sha256"] == record["capture_receipt_sha256"]
            and terminal["conclusion"] == "success" and record["closed_at"] >= terminal["completed_at"],
            "final-receipt-capture-native-binding")
    now = int(time.time())
    issued = now if issued_at is None else issued_at
    require(type(issued) is int and record["closed_at"] <= issued <= now
            and type(public_key_hex) is str and ledger.HEX.fullmatch(public_key_hex), "final-receipt-time-key")
    actual = next(row["engine_exit"] for row in record["effects"].values() if row["operation"] == "engine-start")
    clean = {key: value for key, value in record["effects"].items()
             if value["operation"] in ledger.CLEANUPS | ledger.WITHDRAWALS}
    return {"schema": 1, "purpose": "urn:lightning-it:g06:final-quality:v1", "state": "closed", "lease_id": lease_id,
        "repository": selected.identity.repository, "repository_id": selected.identity.repository_id,
        "run_id": record["identity"]["run_id"], "run_attempt": 1, "source_sha": record["identity"]["caller_sha"],
        "controller_sha": record["identity"]["reusable_sha"], "profile": env["QUALITY_INPUT_PROFILE"],
        "scenario": env["QUALITY_INPUT_SCENARIO"], "target": env["QUALITY_INPUT_TARGET"],
        "execution": {"job_id": terminal["job_id"], "check_run_id": terminal["check_run_id"],
                      "conclusion": terminal["conclusion"], "completed_at": terminal["completed_at"]},
        "artifact": {key: upload[key] for key in ("id", "name", "digest_sha256", "size_in_bytes")},
        "capture_receipt_sha256": upload["capture_receipt_sha256"],
        "cleanup": {"state": "verified", "ledger_sha256": ledger.digest(record), "closed_at": record["closed_at"],
                    "resource_absence_sha256": ledger.digest(clean)},
        "custody_policy_sha256": record["policy_sha256"], "cell_sha256": record["cell_sha256"],
        "engine_policy_sha256": actual["manifest_sha256"], "signer_public_key_hex": public_key_hex, "issued_at": issued}


_CUSTODY_FIELDS = frozenset({"schema", "terminal_at", "retain_until", "retained_at", "policy_sha256",
    "worker_released", "storage_reservation_bytes", "safety_sha256", "instance_uuid", "pool"})


def _custody_record(value, record, policy):
    require(type(value) is dict and set(value) == _CUSTODY_FIELDS and type(value["schema"]) is int
            and value["schema"] == 1 and record.get("native_terminal") is not None
            and all(type(value[k]) is int and value[k] > 0 for k in
                ("terminal_at", "retain_until", "retained_at", "storage_reservation_bytes"))
            and value["terminal_at"] == record["native_terminal"]["completed_at"]
            and value["terminal_at"] <= value["retained_at"]
            and value["terminal_at"] + policy["retention_seconds"] <= value["retain_until"]
            <= value["terminal_at"] + 86400 and value["policy_sha256"] == record["policy_sha256"]
            and type(value["pool"]) is str and 0 < len(value["pool"]) <= 63
            and value["worker_released"] is True and type(value["safety_sha256"]) is str
            and ledger.HEX.fullmatch(value["safety_sha256"]) and ledger._native_uuid(value["instance_uuid"]),
            "custody-retained-binding")
    require(record.get("upload_verification", {}).get("state") != "intent", "custody-retained-upload-held")
    effects = list(record["effects"].values())
    require(all(any(row["operation"] == name and row["state"] == "verified" for row in effects)
                for name in ("engine-stop", "fence-disable", "fence-remove", "certificate-revoke")),
            "custody-retained-safety-unconfirmed")
    starts = [row for row in effects if row["operation"] == "engine-start"]
    actual = starts[0].get("engine_exit") if len(starts) == 1 else None
    require(actual is not None and all(actual[key + "_state"] == "complete" for key in ("stdout", "stderr")),
            "custody-retained-exit-unconfirmed")


def known_retention(record):
    """Known private reservation is not an active/reattachable engine lease."""
    return (record["state"] == "retained" and record.get("upload_transport", {}).get("state") != "intent"
            and record.get("upload_verification", {}).get("state") != "intent"
            and not any(row["state"] in {"intent", "unknown"}
                                                    for row in record["effects"].values()))


@dataclass(frozen=True, eq=False)
class _RetainedProof:
    lease_id: str
    lease_sha256: str
    payload: bytes
    pid: int
    thread: int
    until: float


_RETAINED_PROOFS = weakref.WeakSet()


def retain_stopped(runtime_config_path, runtime_config_sha256, registry, selector, store, lease_id):
    """Stop/revoke now, retain only genuinely known stopped owned resources.

    No new authority is granted after job end. The native terminal observation
    and original process wait remain prerequisites; uncertainty quarantines.
    """
    from . import cell_contract, emergency_stop, incus_admin, incus_mutation, network_fence, root_session
    stop = emergency_stop.RootEmergencyStop(runtime_config_path, runtime_config_sha256).stop(registry, selector, store, lease_id)
    require(stop.disposition == "stopped_observed", "custody-failed-instance-not-retained")
    with root_session._session(*_preparation_reference(runtime_config_path, runtime_config_sha256)) as session:
        config = root_session._require_session(session)
        owner = cell_contract.owned_cell_for_cleanup(registry, selector, store, lease_id)
        record = store.read(lease_id)
        require("native_terminal" in record and record["state"] != "closed"
                and not any(row["state"] in {"intent", "unknown"} for row in record["effects"].values()),
                "custody-retained-unknown")
        worker = ledger.Worker(**record["worker"])
        network_fence.verify_disabled(owner, store, worker, config)
        target = owner.incus
        fingerprint = owner.creator_targets["certificate-create"].removeprefix("certificate:")
        client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path, target["project"],
            target["network"], "default", target["pool"], (fingerprint,), target["instance"]))
        cleanup = incus_mutation.RootIncusCleanup(client, owner, store)
        observed = cleanup.stop_inventory()
        require(observed["state"] == "stopped_observed" and cleanup.certificates_absent(), "custody-retained-not-safe")
        vm = client.instance()
        uuid = vm.get("config", {}).get("volatile.uuid")
        require(ledger._native_uuid(uuid), "custody-instance-uuid")
        require(cleanup.stop_inventory() == observed and client.instance() == vm, "custody-instance-drift")
        if "owned_instance" not in record:
            store.bind_observed_instance(lease_id, observe_owned_instance(config, registry, selector, store, lease_id))
        network_fence.remove(config.network_fence_policy_path, config.network_fence_policy_sha256,
                             owner, store, worker, config)
        record = store.read(lease_id)
        policy = store.read_policy(record["policy_sha256"])
        value = {"schema": 1, "terminal_at": record["native_terminal"]["completed_at"],
            "retain_until": record["native_terminal"]["completed_at"] + policy["retention_seconds"],
            "retained_at": store._now(), "policy_sha256": record["policy_sha256"], "worker_released": True,
            "storage_reservation_bytes": target["project_limits"]["disk_bytes"], "pool": target["pool"],
            "safety_sha256": ledger.digest({"stop": observed, "instance": vm, "certificate_absent": True}),
            "instance_uuid": uuid}
        _custody_record(value, record, policy)
        proof = _RetainedProof(lease_id, ledger.digest(record), ledger.canonical(value), os.getpid(),
                               threading.get_ident(), time.monotonic() + 5)
        with _TERMINAL_GUARD:
            _RETAINED_PROOFS.add(proof)
        return store.bind_retained_custody(lease_id, proof)


def _preparation_reference(path, sha):
    from . import runtime_rpc
    config = runtime_rpc._configuration(path, sha)
    return config.preparation_config_path, config.preparation_config_sha256


def require_retained_proof(proof, lease_id, record, policy):
    require(type(proof) is _RetainedProof, "custody-retained-proof")
    with _TERMINAL_GUARD:
        require(proof in _RETAINED_PROOFS, "custody-retained-proof")
    require(proof.lease_id == lease_id and proof.lease_sha256 == ledger.digest(record)
            and proof.pid == os.getpid() and proof.thread == threading.get_ident()
            and time.monotonic() < proof.until, "custody-retained-proof-drift")
    value = identity.decode_json(proof.payload)
    _custody_record(value, record, policy)
    return value


_INSTANCE_FIELDS = frozenset({"schema", "lease_id", "cell_sha256", "name", "project", "uuid", "observed_at", "inventory_sha256"})
_INSTANCE_PROOFS = weakref.WeakSet()


@dataclass(frozen=True, eq=False)
class _InstanceProof:
    lease_id: str
    lease_sha256: str
    payload: bytes
    pid: int
    thread: int
    until: float


def validate_instance_record(value, record, lease_id):
    require(type(value) is dict and set(value) == _INSTANCE_FIELDS and value["schema"] == 1
            and type(value["schema"]) is int and value["lease_id"] == lease_id and value["cell_sha256"] == record["cell_sha256"]
            and all(type(value[k]) is str and 0 < len(value[k]) <= 63 for k in ("name", "project"))
            and ledger._native_uuid(value["uuid"]) and type(value["observed_at"]) is int and value["observed_at"] > 0
            and type(value["inventory_sha256"]) is str and ledger.HEX.fullmatch(value["inventory_sha256"])
            and any(row["operation"] == "project-create" and row["state"] == "verified"
                    and row["target"] == "project:" + value["project"] for row in record["effects"].values()),
            "custody-owned-instance-binding")


def observe_owned_instance(config, registry, selector, store, lease_id):
    """Read exact live native VM ownership; never fabricate instance-create."""
    from . import cell_contract, incus_admin, incus_mutation, preparation
    require(type(config) is preparation.RootConfiguration, "custody-instance-root-config")
    record = store.read(lease_id)
    starts = [row for row in record["effects"].values() if row["operation"] == "engine-start"]
    live = len(starts) == 1 and "engine_exit" not in starts[0]
    factory = cell_contract.owned_cell_for_observation if live else cell_contract.owned_cell_for_cleanup
    owner = factory(registry, selector, store, lease_id)
    target = owner.incus
    fingerprint = owner.creator_targets["certificate-create"].removeprefix("certificate:")
    client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path, target["project"],
        target["network"], "default", target["pool"], (fingerprint,), target["instance"]))
    cleanup = incus_mutation.RootIncusCleanup(client, owner, store)
    observed = cleanup.stop_inventory()
    require(observed["state"] in {"running_observed", "stopped_observed"}, "custody-owned-instance-absent")
    vm = client.instance()
    uuid = vm.get("config", {}).get("volatile.uuid")
    require(ledger._native_uuid(uuid) and cleanup.stop_inventory() == observed and client.instance() == vm,
            "custody-owned-instance-drift")
    record = store.read(lease_id)
    value = {"schema": 1, "lease_id": lease_id, "cell_sha256": owner.cell_sha256, "name": target["instance"],
        "project": target["project"], "uuid": uuid, "observed_at": store._now(),
        "inventory_sha256": ledger.digest({"instance": vm, "state": observed})}
    validate_instance_record(value, record, lease_id)
    prior = record.get("owned_instance")
    if prior is not None:
        require(all(prior[k] == value[k] for k in ("lease_id", "cell_sha256", "name", "project", "uuid")),
                "custody-owned-instance-replaced")
    proof = _InstanceProof(lease_id, ledger.digest(record), ledger.canonical(value), os.getpid(),
                           threading.get_ident(), time.monotonic() + 5)
    with _TERMINAL_GUARD:
        _INSTANCE_PROOFS.add(proof)
    return proof


def require_instance_proof(proof, lease_id, record):
    require(type(proof) is _InstanceProof, "custody-owned-instance-proof")
    with _TERMINAL_GUARD:
        require(proof in _INSTANCE_PROOFS, "custody-owned-instance-proof")
    require(proof.lease_id == lease_id and proof.lease_sha256 == ledger.digest(record)
            and proof.pid == os.getpid() and proof.thread == threading.get_ident() and time.monotonic() < proof.until,
            "custody-owned-instance-proof-drift")
    value = identity.decode_json(proof.payload)
    validate_instance_record(value, record, lease_id)
    return value


def _prune_retained_graph(path, sha256, registry, selector, store, lease_id):
    from . import cell_contract, engine_graph_prune, root_session
    record = store.read(lease_id)
    previous = [row for row in record["effects"].values() if row["operation"] == "engine-graph-prune"]
    if previous:
        require(len(previous) == 1 and previous[0]["state"] == "verified", "custody-cache-prune-held")
        return  # Never replay a once effect or silently repair a changed cache.
    with root_session._session(*_preparation_reference(path, sha256)) as session:
        config = root_session._require_session(session)
        owner = cell_contract.owned_cell_for_cleanup(registry, selector, store, lease_id)
        descriptor = identity.decode_json(owner.engine_descriptor_bytes)
        if descriptor["environment"].get("QUALITY_INPUT_PROFILE") == "operating":
            engine_graph_prune.prune_graph(owner, store, config, session=session)


def tick_runtime(root_config_path, expected_sha256, snapshot_manifest_sha256):
    """One bounded independent pass over this immutable runtime's leases.

    Only the original live supervisor owns process wait/reap. Its absence never
    authorizes a replacement waiter, destruction, or a synthetic exit receipt.
    Locks remain nonblocking and every remote observation may fail closed.
    """
    from . import finalization, operating_watchdog, runtime_rpc
    require(os.geteuid() == 0 and type(snapshot_manifest_sha256) is str
            and ledger.HEX.fullmatch(snapshot_manifest_sha256), "custody-watchdog-root-binding")
    runtime_rpc._configuration(root_config_path, expected_sha256)
    machine, boot = operating_watchdog._machine_boot()
    events = []

    def alarm(kind, lease_id, state):
        events.append(operating_watchdog.alarm_envelope(source_machine_id=machine, source_boot_id=boot,
            runtime_config_sha256=expected_sha256, snapshot_manifest_sha256=snapshot_manifest_sha256,
            lease_id=lease_id, kind=kind, state_sha256=ledger.digest(state), observed_at=int(time.time())))

    try:
        runtime = runtime_rpc.RuntimeRPC(root_config_path, expected_sha256)
    except Exception:
        alarm("supervisor-observation-held", None, {"state": "bounded-runtime-observation-held"})
        return {"state": "HELD", "events": events, "native_acceptance": False}
    grouped = {}
    for selector, selected in runtime._registry.policies.items():
        grouped.setdefault(selected.ledger_path, []).append((selector, selected))
    require(len(grouped) <= 256, "custody-watchdog-runtime-bound")
    visited = 0
    for path, policies in grouped.items():
        try:
            with ledger.Ledger(path, clock=time.time) as store:
                for lease_id in store.lease_ids():
                    record = store.read(lease_id)
                    matches = [(selector, selected) for selector, selected in policies
                        if record["cell_sha256"] == selected.cell_sha256
                        and record["policy_sha256"] == selected.custody_policy_sha256]
                    if not matches or record["state"] == "closed":
                        continue
                    require(len(matches) == 1, "custody-watchdog-selector-ambiguous")
                    visited += 1
                    require(visited <= 256, "custody-watchdog-lease-bound")
                    selector, _ = matches[0]
                    starts = [row for row in record["effects"].values() if row["operation"] == "engine-start"]
                    actual_exit = starts[0].get("engine_exit") if len(starts) == 1 else None
                    if actual_exit is None:
                        if store._now() >= min(record["expires_at"], record["authorizations"][-1]["valid_until"]):
                            alarm("expired-supervisor-held", lease_id, {"state": "original-owner-exit-unavailable"})
                        continue
                    if any(row["state"] in {"intent", "unknown"} for row in record["effects"].values()):
                        alarm("cleanup-unknown", lease_id, {"effects": record["effects"]})
                        continue
                    verification = record.get("upload_verification")
                    if verification is not None and verification["state"] == "intent":
                        from . import operating_upload
                        if not operating_upload.verification_active(verification):
                            alarm("cleanup-unknown", lease_id, {"state": "private-upload-verification-held"})
                        continue
                    # No terminal API polling while the actual engine runs.
                    # The factory caches an authenticated completed snapshot and
                    # durably bounds anonymous known-pending polls to one/min.
                    if "native_terminal" not in record:
                        try:
                            proof = observe_native_terminal(runtime._registry, selector, store, lease_id)
                            store.bind_native_terminal(lease_id, proof)
                        except NativeJobPending:
                            continue
                        except Exception:
                            alarm("native-status-unavailable", lease_id, {"state": "original-terminal-unavailable"})
                            continue
                    record = store.read(lease_id)
                    try:
                        require_cleanup_allowed(store, lease_id)
                    except ledger.Denied:
                        if record.get("custody") is not None:
                            try:
                                _custody_record(record["custody"], record, store.read_policy(record["policy_sha256"]))
                                retained = record["custody"]
                            except Exception:
                                alarm("retention-state-drift", lease_id, {"state": "retention-binding-invalid"})
                                continue
                        else:
                            try:
                                retained = retain_stopped(root_config_path, expected_sha256, runtime._registry, selector, store, lease_id)
                            except Exception:
                                alarm("safety-withdrawal-held", lease_id, {"state": "stopped-retention-not-proven"})
                                continue
                        alarm("failed-cell-retained", lease_id, {"custody": retained})
                        try:
                            _prune_retained_graph(root_config_path, expected_sha256, runtime._registry, selector, store, lease_id)
                        except Exception:
                            alarm("cleanup-unknown", lease_id, {"state": "retained-cache-prune-not-proven"})
                        continue
                    try:
                        finalization.RootFinalizer(root_config_path, expected_sha256).finalize(
                            runtime._registry, selector, store, lease_id)
                    except Exception:
                        alarm("cleanup-unknown", lease_id, {"state": "destructive-finalization-not-proven"})
        except Exception:
            # In particular ledger-busy/root-session contention cannot make
            # this independent timer wait indefinitely or bypass the lock.
            alarm("supervisor-observation-held", None, {"state": "bounded-ledger-observation-held"})
    return {"state": "HELD" if any(event["kind"] != "failed-cell-retained" for event in events) else "CUSTODY_TICK_COMPLETE", "events": events,
            "native_acceptance": False}


def operating_outcome(root_config_path, expected_sha256, registry, selector, store, lease_id, *, retained=False):
    """Closed-case negative proof, never a business quality/PASS receipt."""
    from . import cell_contract, incus_admin, incus_mutation, network_fence, operating_cells, root_session
    require(type(retained) is bool, "operating-outcome-purpose")
    with root_session._session(*_preparation_reference(root_config_path, expected_sha256)) as session:
        config = root_session._require_session(session)
        owner = cell_contract.owned_cell_for_cleanup(registry, selector, store, lease_id)
        descriptor = identity.decode_json(owner.engine_descriptor_bytes)
        env = descriptor["environment"]
        require(env.get("QUALITY_INPUT_PROFILE") == "operating", "operating-outcome-kind")
        case = env["QUALITY_OPERATING_CASE"]
        require(selector == operating_cells.selector(case), "operating-outcome-selector")
        record = store.read(lease_id)
        require(not any(row["state"] in {"intent", "unknown"} for row in record["effects"].values()),
                "operating-outcome-unknown")
        starts = [row for row in record["effects"].values() if row["operation"] == "engine-start"]
        require(len(starts) == 1 and "engine_exit" in starts[0], "operating-outcome-original-exit")
        actual = starts[0]["engine_exit"]
        require(all(actual[name + "_state"] == "complete" for name in ("stdout", "stderr")),
                "operating-outcome-capture")
        if case == "failure":
            require(actual["exit_code"] == 23 and actual["signal"] is None
                    and record.get("cancel_reason") is None, "operating-outcome-not-expected-failure")
        elif case == "broker-cancel":
            require(record.get("cancel_reason") == "cancelled"
                    and record["cancelled_at"] < min(record["expires_at"], record["authorizations"][-1]["valid_until"])
                    and (actual["signal"] is not None or actual["exit_code"] != 0),
                    "operating-outcome-not-broker-cancel")
        else:
            require(case == "expiry-controller-loss" and record.get("cancel_reason") == "authorization_expired"
                    and record.get("authorization_expired_at") == min(record["expires_at"], record["authorizations"][-1]["valid_until"])
                    and store._now() >= record["authorization_expired_at"]
                    and (actual["signal"] is not None or actual["exit_code"] != 0),
                    "operating-outcome-not-real-expiry")
        require("owned_instance" in record, "operating-outcome-ready-not-bound")
        observed_owner = record["owned_instance"]
        validate_instance_record(observed_owner, record, lease_id)
        ready_frame = {"schema": 1, "state": "operating-ready", "case": case, "lease_id": lease_id,
                       "instance_uuid": observed_owner["uuid"]}
        require(any(row["operation"] == "operating-ready" and row["target"] == "operating:" + lease_id
                    and row["state"] == "verified" and row.get("evidence_sha256") == ledger.digest(ready_frame)
                    for row in record["effects"].values()), "operating-outcome-root-ready-required")
        target = owner.incus
        fingerprint = owner.creator_targets["certificate-create"].removeprefix("certificate:")
        client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path, target["project"],
            target["network"], "default", target["pool"], (fingerprint,), target["instance"]))
        cleanup = incus_mutation.RootIncusCleanup(client, owner, store)
        native = cleanup.stop_inventory()
        require(native["state"] == "stopped_observed" and cleanup.certificates_absent()
                and client.instance().get("config", {}).get("volatile.uuid") == observed_owner["uuid"],
                "operating-outcome-unsafe")
        network_fence.verify_disabled(owner, store, ledger.Worker(**record["worker"]), config)
        for operation, target_name in (("engine-stop", "engine:lit-lease-" + lease_id),
                                      ("fence-disable", "fence:" + lease_id)):
            require(any(row["operation"] == operation and row["target"] == target_name and row["state"] == "verified"
                        for row in record["effects"].values()), "operating-outcome-withdrawal")
        custody = record.get("custody")
        if retained:
            require(record["state"] == "retained" and custody is not None, "operating-outcome-not-retained")
            _custody_record(custody, record, store.read_policy(record["policy_sha256"]))
        else:
            require(record["state"] in {"prepared", "cancelled", "retained"}, "operating-outcome-closed")
        who = record["identity"]
        return {"schema": 1, "kind": "operating", "case": case, "selector": selector,
            "run_id": who["run_id"], "run_attempt": 1, "source_sha": who["caller_sha"],
            "controller_sha": who["reusable_sha"], "lease_id": lease_id,
            "instance_uuid": observed_owner["uuid"], "raw_exit": {"code": actual["exit_code"], "signal": actual["signal"]},
            "vm_state": "stopped", "access": "withdrawn", "retention_seconds": store.read_policy(record["policy_sha256"])["retention_seconds"],
            "terminal_at": custody["terminal_at"] if retained else None,
            "retain_until": custody["retain_until"] if retained else None,
            "cutoff": ({"kind": "authorization" if record["authorizations"][-1]["valid_until"] <= record["expires_at"] else "lease",
                        "deadline": record["authorization_expired_at"], "observed_at": record["cancelled_at"]}
                       if case == "expiry-controller-loss" else None),
            "state": "retained" if retained else "safety-proved-retention-armed"}


def operating_ready_tick(config_path, config_sha256, registry, selector, store, lease_id, receipt):
    """Synchronize only after independent Root reads of the created owned VM.

    The controller's exclusive create hint is a polling trigger, never proof.
    The Root-written ACK contains public identity metadata only.
    """
    import stat
    from . import cell_contract, engine_executor, engine_policy, evidence_export, incus_admin, incus_mutation, root_session
    with root_session._session(config_path, config_sha256) as session:
        config = root_session._require_session(session)
        manifest, _, _ = engine_executor._retained(config, registry, selector, store, lease_id, receipt)
        details = identity.decode_json(manifest.canonical_bytes)
        if details["environment"].get("QUALITY_INPUT_PROFILE") != "operating":
            return None
        owner = cell_contract.owned_cell_for_observation(registry, selector, store, lease_id)
        descriptor = identity.decode_json(owner.engine_descriptor_bytes)
        case = descriptor["environment"]["QUALITY_OPERATING_CASE"]
        output = engine_policy._directory(descriptor["output_path"], private=True)
        control = None
        effect = None
        try:
            try:
                control = os.open("control", engine_policy.DIR, dir_fd=output)
            except FileNotFoundError:
                return None
            info = os.fstat(control)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    "operating-ready-control-directory")
            try:
                raw = evidence_export._read(control, "operating-created.json", 4096)
            except FileNotFoundError:
                return None
            hint = identity.decode_json(raw)
            target = owner.incus
            require(type(hint) is dict and set(hint) == {"schema", "case", "instance_name", "instance_uuid"}
                    and type(hint["schema"]) is int and hint["schema"] == 1 and hint["case"] == case
                    and hint["instance_name"] == target["instance"] and ledger._native_uuid(hint["instance_uuid"]),
                    "operating-ready-untrusted-hint")
            record = store.read(lease_id)
            prior = [row for row in record["effects"].values() if row["operation"] == "operating-ready"]
            frame = {"schema": 1, "state": "operating-ready", "case": case, "lease_id": lease_id,
                     "instance_uuid": hint["instance_uuid"]}
            if prior:
                require(len(prior) == 1 and prior[0]["state"] == "verified"
                        and record.get("owned_instance", {}).get("uuid") == hint["instance_uuid"]
                        and evidence_export._read(control, "root-operating-ready.json", 4096) == ledger.canonical(frame),
                        "operating-ready-prior-held")
                return frame
            require(not os.path.lexists(descriptor["output_path"] + "/control/root-operating-ready.json"),
                    "operating-ready-ack-preexisting")
            fingerprint = owner.creator_targets["certificate-create"].removeprefix("certificate:")
            client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path, target["project"],
                target["network"], "default", target["pool"], (fingerprint,), target["instance"]))
            cleanup = incus_mutation.RootIncusCleanup(client, owner, store)
            observed = cleanup.stop_inventory()
            vm = client.instance()
            spec = identity.decode_json(descriptor["environment"]["QUALITY_OPERATING_SPEC"].encode())
            devices = vm.get("expanded_devices")
            expanded = vm.get("expanded_config")
            require(observed["state"] == "running_observed" and type(devices) is dict
                    and set(devices) == {"root", "eth0"} and type(expanded) is dict
                    and expanded.get("limits.cpu") == "1" and expanded.get("limits.memory") == "2GiB"
                    and vm.get("config", {}).get("volatile.base_image") == spec["image"]
                    and vm.get("config", {}).get("volatile.uuid") == hint["instance_uuid"],
                    "operating-ready-native-platform")
            root, nic = devices["root"], devices["eth0"]
            require(type(root) is dict and root.get("type") == "disk" and root.get("path") == "/"
                    and root.get("pool") == target["pool"] and root.get("size") == "5GiB"
                    and root.get("size.state", "500MiB") == "500MiB"
                    and type(nic) is dict and nic.get("type") == "nic" and nic.get("network") == target["network"],
                    "operating-ready-native-devices")
            require(client.instance() == vm and cleanup.stop_inventory() == observed, "operating-ready-native-drift")
            store.bind_observed_instance(lease_id, observe_owned_instance(config, registry, selector, store, lease_id))
            effect = store.begin(lease_id, "operating-ready", "operating:" + lease_id)
            fd = os.open("root-operating-ready.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=control)
            try:
                os.fchmod(fd, 0o600)
                content = memoryview(ledger.canonical(frame))
                while content:
                    count = os.write(fd, content)
                    require(count > 0, "operating-ready-short-write")
                    content = content[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(control)
            require(evidence_export._read(control, "root-operating-ready.json", 4096) == ledger.canonical(frame),
                    "operating-ready-readback")
            store.record(lease_id, effect, "verified", evidence_sha256=ledger.digest(frame))
            return frame
        except Exception:
            if effect is not None:
                try:
                    store.record(lease_id, effect, "unknown", evidence_sha256=ledger.digest({"state": "ready-ack-unknown"}))
                except Exception:
                    pass
            raise
        finally:
            if control is not None:
                os.close(control)
            os.close(output)
