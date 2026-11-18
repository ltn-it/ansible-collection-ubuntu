"""Root bootstrap verification and private per-job runtime configuration.

Unverified caller SHA is only a locator until genuine signed/native assignment
verification. No dummy admission cell, global anchor replacement, offline
publisher call, TLS/signing-key read, lease initialization or engine effect is
performed here. Existing native custody/lease admission remains mandatory.
"""
from dataclasses import asdict, dataclass
from concurrent.futures import ThreadPoolExecutor
import base64
import datetime as dt
import hashlib
import os
from pathlib import Path
import re
import threading
import time
import weakref

from . import (admission, collector, engine_policy as engine, identity, installation, ledger,
               cell_contract, generation_publisher as sealing, operating_cells, policy_registry, preparation, runtime_rpc, run_intake)
from .identity import Denied, require

ROOT = "/var/lib/lightning-it/incus-run-configurations"
MAX_POLICY = 4 * 1024 * 1024
SOURCE = "ltn-it/ansible-collection-supplementary"
VALIDATION = "ltn-it/modulix-validation"
PREPARATION_KEYS = frozenset({"incus_socket_path", "signing_key_path", "signing_public_key_hex", "publication_staging_parent",
    "lock_path", "operation_wait_seconds", "network_fence_policy_path", "network_fence_policy_sha256",
    "storage_quota_policy_path", "storage_quota_policy_sha256", "host_api_fence_policy_path", "host_api_fence_policy_sha256"})
RUNTIME_KEYS = frozenset({"authentication_timeout_seconds", "initial_transition_timeout_seconds",
                        "heartbeat_lead_seconds", "cleanup_timeout_seconds", "capture"})


@dataclass(frozen=True)
class RootBootstrapPolicy:
    path: str
    sha256: str
    canonical_bytes: bytes
    collector: collector.CollectorPolicy
    file_stamp: tuple

    @property
    def value(self):
        return identity.decode_json(self.canonical_bytes)


@dataclass(frozen=True)
class RootBootstrapSelection:
    bootstrap: RootBootstrapPolicy
    selector: str
    purpose: str
    identity: identity.Policy
    collector: collector.CollectorPolicy
    ledger_path: str
    custody_policy_sha256: str
    template_sha256: str
    template_bytes: bytes
    lease_seconds: int
    job_timeout_seconds: int


@dataclass(frozen=True, eq=False)
class BootstrapNativeProof:
    worker: ledger.Worker
    identity: identity.Identity
    nonce: str
    policy: RootBootstrapSelection
    controls_sha256: str
    challenge_sha256: str
    connected: object
    fd: int
    pid: int
    thread: int
    expires_monotonic: float
    job_started_at: int


@dataclass(frozen=True)
class RootRunConfiguration:
    directory: str
    runtime_config_path: str
    runtime_config_sha256: str
    registry_path: str
    registry_sha256: str
    preparation_config_path: str
    preparation_config_sha256: str
    deadline: int
    manifest_sha256: str


_PROOFS = weakref.WeakSet()
_GUARD = threading.Lock()


def _root():
    require(os.geteuid() == 0, "run-factory-root-required")


def load_bootstrap(path, expected_sha256):
    _root()
    proof, raw, stamp = installation._file(engine._path(path), MAX_POLICY, private=True, keep=True)
    require(proof.sha256 == engine._hash(expected_sha256), "bootstrap-policy-drift")
    value = identity.decode_json(raw)
    engine._keys(value, {"schema", "source_identity", "source_workflow_sha256", "collector", "ledger_path",
                        "custody_policy_sha256", "controller", "preparation", "runtime", "capacity", "cells"}
                        | ({"operating_continuation"} if "operating_continuation" in value else set()))
    require(type(value["schema"]) is int and value["schema"] == 1 and ledger.canonical(value) == raw,
            "bootstrap-policy-schema")
    base = engine._keys(value["source_identity"], policy_registry.IDENTITY_KEYS - {"caller_sha"})
    require(base["repository"] == SOURCE and base["repository_id"] == 1103407173 and base["owner_id"] == 54334171
            and base["workflow_id"] == 214182490 and base["workflow_path"] == ".github/workflows/collection-ci.yml"
            and base["visibility"] == "public" and base["reusable_repository"] == VALIDATION
            and base["reusable_path"] == ".github/workflows/collection-quality-profile-isolated.yml"
            and type(base["actor_ids"]) is list and set(base["actor_ids"]) == {76040632, 247824904}
            and len(base["actor_ids"]) == 2, "bootstrap-source-domain")
    engine._hash(value["source_workflow_sha256"])
    controller = engine._keys(value["controller"], {"repository", "repository_id", "reusable_path", "reusable_sha"})
    require(controller == {"repository": VALIDATION, "repository_id": 1269461997,
            "reusable_path": base["reusable_path"], "reusable_sha": base["reusable_sha"]}, "bootstrap-controller-domain")
    require(type(base["reusable_sha"]) is str and re.fullmatch("[0-9a-f]{40}", base["reusable_sha"])
            and base["reusable_sha"] != "0" * 40, "bootstrap-controller-sha")
    collected = policy_registry._collector(value["collector"])
    require(collected.service.installation.runner_id == base["runner_id"]
            and collected.service.installation.service_uid == base["service_uid"], "bootstrap-runner-domain")
    engine._path(value["ledger_path"])
    custody = engine._hash(value["custody_policy_sha256"])
    with ledger.Ledger(value["ledger_path"], clock=time.time) as store:
        require(store.read_policy(custody)["retention_seconds"] == 14400, "bootstrap-original-failure-retention")
    prep = engine._keys(value["preparation"], PREPARATION_KEYS)
    for key in PREPARATION_KEYS:
        if key.endswith("sha256") or key == "signing_public_key_hex": engine._hash(prep[key])
        elif key == "operation_wait_seconds": engine._integer(prep[key], 1, 60)
        else: engine._path(prep[key])
    runtime = engine._keys(value["runtime"], RUNTIME_KEYS | (
        {"initial_transition_minimum_seconds"} if "initial_transition_minimum_seconds" in value["runtime"] else set()))
    for key, maximum in (("authentication_timeout_seconds", 60), ("initial_transition_timeout_seconds", 300),
                         ("heartbeat_lead_seconds", 120), ("cleanup_timeout_seconds", 1800)):
        engine._integer(runtime[key], 1, maximum)
    if "initial_transition_minimum_seconds" in runtime:
        engine._integer(runtime["initial_transition_minimum_seconds"], 1,
                        runtime["initial_transition_timeout_seconds"])
    require(type(runtime["capture"]) is dict, "bootstrap-runtime-capture")
    runtime_rpc._capacity_policy(value["capacity"])
    cells = value["cells"]
    require(type(cells) is dict and 0 < len(cells) <= 256, "bootstrap-cells")
    names = set()
    for name, template in cells.items():
        require(type(name) is str and policy_registry.SELECTOR.fullmatch(name), "bootstrap-selector")
        kind = template.get("kind") if type(template) is dict else None
        keys = {"kind", "native_job_name", "native_observer_job_name", "github", "engine", "incus",
                "lease_seconds", "job_timeout_seconds", "operating" if kind == "operating" else "matrix"}
        engine._keys(template, keys)
        require(kind in {"business", "operating"}, "bootstrap-cell-kind")
        for field in ("native_job_name", "native_observer_job_name"):
            text = template[field]
            require(type(text) is str and 0 < len(text) <= 1024 and not any(ord(c) < 32 for c in text)
                    and text not in names, "bootstrap-native-name")
            names.add(text)
        engine._integer(template["lease_seconds"], 1, 5400)
        engine._integer(template["job_timeout_seconds"], 1, 5400)
        require(type(template["engine"]) is dict and "archives" not in template["engine"]
                and "trees" not in template["engine"], "bootstrap-engine-template")
        if kind == "operating":
            require(template["lease_seconds"] == 900 and template["engine"].get("limits", {}).get("timeout_seconds") == 600,
                    "bootstrap-operating-reviewed-budgets")
            case = template["operating"].get("case")
            require(name == operating_cells.selector(case), "bootstrap-operating-selector")
            suffix = "Operating result / " + case
        else:
            matrix = template["matrix"]
            require(type(matrix) is dict and name == policy_registry.profile_selector(
                matrix.get("profile"), matrix.get("scenario"), matrix.get("target")), "bootstrap-business-selector")
            suffix = "Final quality / " + matrix["profile"] + " / " + matrix["scenario"] + " / " + matrix["target"]
        observer = template["native_observer_job_name"]
        require(observer == suffix or observer.endswith(" / " + suffix), "bootstrap-observer-name")
    _continuation_receipt(value)
    return RootBootstrapPolicy(path, expected_sha256, raw, collected, stamp)


def derive_selection(bootstrap, selector, caller_sha_locator, *, purpose="execution"):
    _root()
    require(type(bootstrap) is RootBootstrapPolicy
            and load_bootstrap(bootstrap.path, bootstrap.sha256) == bootstrap, "bootstrap-trusted-policy")
    require(type(caller_sha_locator) is str and re.fullmatch("[0-9a-f]{40}", caller_sha_locator)
            and purpose in {"execution", "observer"}, "bootstrap-selection")
    value = bootstrap.value
    require(type(selector) is str and selector in value["cells"], "bootstrap-selector")
    template = value["cells"][selector]
    base = {**value["source_identity"], "caller_sha": caller_sha_locator}
    native = policy_registry._identity(base, template["native_job_name" if purpose == "execution" else "native_observer_job_name"])
    return RootBootstrapSelection(bootstrap, selector, purpose, native, bootstrap.collector, value["ledger_path"],
        value["custody_policy_sha256"], ledger.digest(template), ledger.canonical(template),
        template["lease_seconds"], template["job_timeout_seconds"])


@identity._diagnostic_step("native-worker")
def _worker(connected, bootstrap):
    admission._socket(connected)
    value = collector.collect_worker(connected, bootstrap.collector)
    require(type(value) is ledger.Worker, "bootstrap-native-worker")
    value.validate()
    base = bootstrap.value["source_identity"]
    require(value.runner_id == base["runner_id"] and value.uid == base["service_uid"], "bootstrap-native-worker")
    return value


@identity._diagnostic_step("native-controls")
def _controls(bootstrap):
    require(load_bootstrap(bootstrap.path, bootstrap.sha256) == bootstrap, "bootstrap-policy-changed")
    controls = {"bootstrap_sha256": bootstrap.sha256, "stamp": list(bootstrap.file_stamp),
        "collector": {key: asdict(value) for key, value in collector._controls(bootstrap.collector).items()}}
    qualified = _continuation_receipt(bootstrap.value)
    if qualified is not None:
        controls["operating_continuation"] = {"qualification_sha256": qualified[0]["qualification"]["sha256"],
                                             "file_stamp": list(qualified[3])}
    return ledger.digest(controls)


def challenge_bootstrap(connected, bootstrap, selector):
    _root()
    _controls(bootstrap)
    require(type(selector) is str and selector in bootstrap.value["cells"], "bootstrap-selector")
    worker = _worker(connected, bootstrap)
    with ledger.Ledger(bootstrap.value["ledger_path"], clock=time.time) as store:
        return store.challenge(worker, ttl=bootstrap.value["runtime"]["authentication_timeout_seconds"])


def _challenge(selection, nonce, worker):
    require(type(nonce) is str and ledger.HEX.fullmatch(nonce), "bootstrap-nonce")
    with ledger.Ledger(selection.ledger_path, clock=time.time) as store:
        with store._transaction() as state:
            value = state["challenges"].get(ledger.digest(nonce))
            require(type(value) is dict and value["state"] == "issued" and value["worker"] == asdict(worker)
                    and value.get("runtime") is None, "bootstrap-challenge")
            return dict(value)


def _continuation_receipt(value):
    descriptor = value.get("operating_continuation")
    if descriptor is None:
        require("operating_continuation" not in value, "continuation-null-descriptor")
        return None
    operating_cells.validate_continuation_descriptor(descriptor, value["source_workflow_sha256"],
                                                     value["source_identity"]["reusable_sha"])
    ref = descriptor["qualification"]
    proof, raw, stamp = installation._file(ref["path"], MAX_POLICY, private=True, keep=True)
    require(proof.sha256 == ref["sha256"], "continuation-qualification-drift")
    receipt = identity.decode_json(raw)
    require(raw == ledger.canonical(receipt), "continuation-qualification-canonical")
    counts = operating_cells.validate_continuation_qualification(receipt)
    return descriptor, receipt, counts, stamp


def _continuation_fifth_native(get):
    run = get("/actions/runs/" + str(operating_cells.FIFTH_RUN))
    path = "/actions/runs/" + str(operating_cells.FIFTH_RUN) + "/attempts/1/jobs?per_page=100&page=1"
    inventory = get(path)
    checks = [get("/check-runs/" + str(identifier)) for identifier in operating_cells.FIFTH_CHECKS]
    result = operating_cells.fifth_native_projection(run, inventory, checks)
    require(get(path) == inventory, "continuation-fifth-native-inventory-drift")
    return result


def _fifth_retired_entry(directory):
    # The two fixed Root-owned catalogue domains contain public intake/config
    # bytes, never ephemeral TLS contexts, signer keys or the separate Ledger.
    # Existing inventory protects every original inode/file; output is only its
    # aggregate digest. Unknown roots or supplied paths are never accepted.
    require(directory.parent in {Path(ROOT), Path(run_intake.ROOT)}, "continuation-fifth-catalogue-domain")
    require(not os.path.lexists(directory / "publish-intent.json")
            and not os.path.lexists(directory / "published.json"), "continuation-fifth-unexpected-publication")
    inventory = sealing._inventory(directory)
    seal = directory / "sealed-inventory.json"
    if os.path.lexists(seal):
        proof, _, stamp = installation._file(str(seal), MAX_POLICY, private=True, keep=False)
        inventory["sealed-inventory.json"] = {"sha256": proof.sha256, "stamp": list(stamp)}
    return ledger.digest(inventory)


def _fifth_closed_projection(successor_ledger_path, original_configuration):
    """Fresh original product readbacks; a JSON closed flag alone is no proof."""
    from . import incus_admin, incus_mutation, cleanup_storage
    original = engine._keys(original_configuration, {"directory", "manifest_sha256"})
    directory = Path(original["directory"])
    require(directory.parent == Path(ROOT) and re.fullmatch("[0-9a-f]{64}", directory.name),
            "continuation-fifth-original-configuration-domain")
    configuration, _ = _read_complete(directory)
    require(configuration.manifest_sha256 == original["manifest_sha256"], "continuation-fifth-original-manifest")
    origin = read_configuration_origin(configuration)
    require(origin["source_sha"] == operating_cells.FIFTH_MAIN and origin["run_id"] == operating_cells.FIFTH_RUN
            and origin["run_attempt"] == 1 and origin["job_id"] == operating_cells.FIFTH_JOB
            and origin["check_run_id"] == operating_cells.FIFTH_CHECK, "continuation-fifth-original-configuration")
    registry = policy_registry.load_registry(configuration.registry_path, configuration.registry_sha256)
    selected = registry.select(origin["selector"])
    require(selected.ledger_path != successor_ledger_path, "continuation-fifth-separate-store-required")
    if os.path.lexists(successor_ledger_path):
        old_fd = installation._open_directory(selected.ledger_path)
        try:
            new_fd = installation._open_directory(successor_ledger_path)
            try:
                old, new = os.fstat(old_fd), os.fstat(new_fd)
                require((old.st_dev, old.st_ino) != (new.st_dev, new.st_ino),
                        "continuation-fifth-aliased-original-store")
            finally:
                os.close(new_fd)
        finally:
            os.close(old_fd)
    with ledger.Ledger(selected.ledger_path, clock=time.time) as store:
        require(store.lease_ids() == (operating_cells.FIFTH_LEASE,), "continuation-fifth-original-store-scope")
        record = store.read(operating_cells.FIFTH_LEASE)
        require(record["state"] == "closed"
                and record["cell_sha256"] == operating_cells.FIFTH_CELL
                and record["policy_sha256"] == operating_cells.FIFTH_POLICY
                and record["identity"]["caller_sha"] == operating_cells.FIFTH_MAIN
                and record["identity"]["run_id"] == operating_cells.FIFTH_RUN
                and record["identity"]["job_id"] == operating_cells.FIFTH_JOB
                and record["identity"]["check_run_id"] == operating_cells.FIFTH_CHECK
                and record["identity"]["runner_id"] == operating_cells.FIFTH_RUNNER and record["worker"]["uid"] == operating_cells.FIFTH_UID
                and record["identity"]["reusable_sha"] == operating_cells.FOUR_HISTORY_REUSABLE
                and operating_cells.FIFTH_RETAIN_UNTIL <= record["closed_at"] <= int(time.time()),
                "continuation-fifth-original-not-verified-closed")
        ledger.Ledger._cleanup_complete(list(record["effects"].values()))
        owner = cell_contract.partial_preparation_owner(registry, origin["selector"], store,
                                                       operating_cells.FIFTH_LEASE)
        require(set(owner.creators) == {"network-create", "project-create", "profile-configure", "context-create",
                                       "certificate-create", "engine-prepare"}, "continuation-fifth-exact-six-creators")
        value = owner.incus
        fingerprint = owner.creator_targets["certificate-create"].removeprefix("certificate:")
        # The original platform socket is a sealed source property, not any
        # successor/caller endpoint. No current authorization is renewed here.
        config, _, _ = preparation._config(configuration.preparation_config_path,
                                            configuration.preparation_config_sha256)
        client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path,
            value["project"], value["network"], "default", value["pool"], (fingerprint,)))
        cleanup = incus_mutation.RootPartialPreparationCleanup(client, owner, store)
        snapshot = cleanup.certificate_inventory()
        require(not snapshot.fingerprints and cleanup.certificates_absent(),
                "continuation-fifth-native-certificate-returned")
        absent = {kind: cleanup.readback(kind) for kind in ("project", "bridge")}
        require(all(row["state"] == "absent_observed" for row in absent.values()),
                "continuation-fifth-native-resource-returned")
        # Later independent successor credentials are legitimate. Authenticate
        # the complete original scope, but seal only its continuing absence,
        # not the changing inventory of unrelated/current successor scopes.
        absent["certificate"] = {"state": "absent_observed", "scope_sha256": snapshot.scope_sha256,
                                 "original_fingerprint": snapshot.original_fingerprint}
        descriptor = identity.decode_json(owner.engine_descriptor_bytes)
        cleanup_storage._absent((descriptor["engine"]["storage_root"], descriptor["engine"]["runroot"],
            descriptor["output_path"], descriptor["context_path"], owner.engine_descriptor_path))
        require(store.read_policy(record["policy_sha256"])["retention_seconds"] == 14400
                and store.read(owner.lease_id) == record, "continuation-fifth-retirement-drift")
        return {"record_sha256": ledger.digest(record), "closed_at": record["closed_at"],
                "native_absence_sha256": ledger.digest(absent)}


def _fifth_catalogue_snapshot(directory, *, intake):
    root = installation._open_directory(directory)
    try:
        names = run_intake._entries(root)
        require(0 < len(names) <= 256 and all(re.fullmatch("[0-9a-f]{64}", name) for name in names),
                "continuation-fifth-retired-catalogue")
        rows = {}
        for name in names:
            child = os.open(name, installation.DIR_FLAGS, dir_fd=root)
            try:
                value = run_intake._read_at(child, "intent.json")[0]
                if intake:
                    source = value["binding"]["source"]
                    controller = value["binding"]["controller"]
                    who = value["original_job"]
                    require(source["repository"] == SOURCE and source["commit_sha"] == operating_cells.FIFTH_MAIN
                            and controller["repository"] == VALIDATION
                            and controller["commit_sha"] == operating_cells.FOUR_HISTORY_REUSABLE,
                            "continuation-fifth-retired-source")
                else:
                    configuration, _ = _read_complete(Path(directory) / name)
                    who = read_configuration_origin(configuration)
                    require(who["source_sha"] == operating_cells.FIFTH_MAIN
                            and who["reusable_sha"] == operating_cells.FOUR_HISTORY_REUSABLE,
                            "continuation-fifth-retired-configuration")
                require(who["run_id"] == operating_cells.FIFTH_RUN and who["job_id"] == operating_cells.FIFTH_JOB
                        and who["check_run_id"] == operating_cells.FIFTH_JOB, "continuation-fifth-retired-invocation")
                rows[name] = _fifth_retired_entry(Path(directory) / name)
            finally:
                os.close(child)
        require(run_intake._entries(root) == names, "continuation-fifth-retired-catalogue-drift")
        return rows
    finally:
        os.close(root)


def collect_partial_preparation_retirement(successor_ledger_path, original_configuration):
    """Root-only actual closed resource/catalogue readback, never a write or retry."""
    _root()
    engine._path(successor_ledger_path)
    before = _fifth_closed_projection(successor_ledger_path, original_configuration)
    catalogues = {"native_intake_catalogue": _fifth_catalogue_snapshot(run_intake.ROOT, intake=True),
        "native_run_configuration_catalogue": _fifth_catalogue_snapshot(ROOT, intake=False)}
    require(_fifth_closed_projection(successor_ledger_path, original_configuration) == before, "continuation-fifth-closed-drift")
    value = {"schema": 1, "kind": "original-fifth-partial-preparation-verified-closed",
             "lease_id": operating_cells.FIFTH_LEASE, "retain_until": operating_cells.FIFTH_RETAIN_UNTIL,
             **before, "catalogues": catalogues, "original_configuration": original_configuration}
    operating_cells._validate_partial_retirement(value)
    return value


def _revalidate_fifth_retirement(retirement, successor_ledger_path):
    operating_cells._validate_partial_retirement(retirement)
    current = _fifth_closed_projection(successor_ledger_path, retirement["original_configuration"])
    require(current == {key: retirement[key] for key in ("record_sha256", "closed_at", "native_absence_sha256")},
            "continuation-fifth-retirement-drift")
    # The complete parent catalogue reader separately proves all retired entries
    # unchanged and classifies every additional entry as this exact successor.
    # Recollecting the producer's original-only catalogue here would reject the
    # first legitimate new configuration and break its own later revalidation.


def _continuation_sixth_native(get):
    run = get("/actions/runs/" + str(operating_cells.SIXTH_RUN))
    path = "/actions/runs/" + str(operating_cells.SIXTH_RUN) + "/attempts/1/jobs?per_page=100&page=1"
    inventory = get(path)
    checks = [get("/check-runs/" + str(identifier)) for identifier in operating_cells.SIXTH_CHECKS]
    result = operating_cells.sixth_native_projection(run, inventory, checks)
    require(get(path) == inventory, "continuation-sixth-native-inventory-drift")
    return result


def _sixth_closed_projection(successor_ledger_path, original_configuration):
    """Fresh original product readbacks; a JSON closed flag alone is no proof."""
    from . import incus_admin, incus_mutation, cleanup_storage
    original = engine._keys(original_configuration, {"directory", "manifest_sha256"})
    directory = Path(original["directory"])
    require(directory.parent == Path(ROOT) and re.fullmatch("[0-9a-f]{64}", directory.name),
            "continuation-sixth-original-configuration-domain")
    configuration, _ = _read_complete(directory)
    require(configuration.manifest_sha256 == original["manifest_sha256"], "continuation-sixth-original-manifest")
    origin = read_configuration_origin(configuration)
    require(origin["source_sha"] == operating_cells.SIXTH_MAIN and origin["run_id"] == operating_cells.SIXTH_RUN
            and origin["run_attempt"] == 1 and origin["job_id"] == operating_cells.SIXTH_JOB
            and origin["check_run_id"] == operating_cells.SIXTH_CHECK, "continuation-sixth-original-configuration")
    registry = policy_registry.load_registry(configuration.registry_path, configuration.registry_sha256)
    selected = registry.select(origin["selector"])
    require(selected.ledger_path != successor_ledger_path, "continuation-sixth-separate-store-required")
    if os.path.lexists(successor_ledger_path):
        old_fd = installation._open_directory(selected.ledger_path)
        try:
            new_fd = installation._open_directory(successor_ledger_path)
            try:
                old, new = os.fstat(old_fd), os.fstat(new_fd)
                require((old.st_dev, old.st_ino) != (new.st_dev, new.st_ino),
                        "continuation-sixth-aliased-original-store")
            finally:
                os.close(new_fd)
        finally:
            os.close(old_fd)
    with ledger.Ledger(selected.ledger_path, clock=time.time) as store:
        require(store.lease_ids() == (operating_cells.SIXTH_LEASE,), "continuation-sixth-original-store-scope")
        record = store.read(operating_cells.SIXTH_LEASE)
        require(record["state"] == "closed"
                and record["cell_sha256"] == operating_cells.SIXTH_CELL
                and record["policy_sha256"] == operating_cells.SIXTH_POLICY
                and record["identity"]["caller_sha"] == operating_cells.SIXTH_MAIN
                and record["identity"]["run_id"] == operating_cells.SIXTH_RUN
                and record["identity"]["job_id"] == operating_cells.SIXTH_JOB
                and record["identity"]["check_run_id"] == operating_cells.SIXTH_CHECK
                and record["identity"]["runner_id"] == operating_cells.SIXTH_RUNNER and record["worker"]["uid"] == operating_cells.SIXTH_UID
                and record["identity"]["reusable_sha"] == operating_cells.SIXTH_REUSABLE
                and operating_cells.SIXTH_RETAIN_UNTIL <= record["closed_at"] <= int(time.time()),
                "continuation-sixth-original-not-verified-closed")
        store.require_cleanup_complete(operating_cells.SIXTH_LEASE)
        custody = record.get("partial_preparation_custody", {})
        require(custody.get("terminal_at") == operating_cells.SIXTH_TERMINAL
                and custody.get("retain_until") == operating_cells.SIXTH_RETAIN_UNTIL
                and record.get("native_terminal", {}).get("completed_at") == operating_cells.SIXTH_TERMINAL,
                "continuation-sixth-original-custody")
        owner = cell_contract.partial_preparation_owner(registry, origin["selector"], store,
                                                       operating_cells.SIXTH_LEASE)
        require(set(owner.creators) == {"network-create", "project-create", "profile-configure", "context-create",
                                       "certificate-create", "engine-prepare", "context-publish"}, "continuation-sixth-exact-seven-creators")
        value = owner.incus
        fingerprint = owner.creator_targets["certificate-create"].removeprefix("certificate:")
        # The original platform socket is a sealed source property, not any
        # successor/caller endpoint. No current authorization is renewed here.
        config, _, _ = preparation._config(configuration.preparation_config_path,
                                            configuration.preparation_config_sha256)
        client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path,
            value["project"], value["network"], "default", value["pool"], (fingerprint,)))
        cleanup = incus_mutation.RootPartialPreparationCleanup(client, owner, store)
        snapshot = cleanup.certificate_inventory()
        require(not snapshot.fingerprints and cleanup.certificates_absent(),
                "continuation-sixth-native-certificate-returned")
        absent = {kind: cleanup.readback(kind) for kind in ("project", "bridge")}
        require(all(row["state"] == "absent_observed" for row in absent.values()),
                "continuation-sixth-native-resource-returned")
        # Later independent successor credentials are legitimate. Authenticate
        # the complete original scope, but seal only its continuing absence,
        # not the changing inventory of unrelated/current successor scopes.
        absent["certificate"] = {"state": "absent_observed", "scope_sha256": snapshot.scope_sha256,
                                 "original_fingerprint": snapshot.original_fingerprint}
        descriptor = identity.decode_json(owner.engine_descriptor_bytes)
        cleanup_storage._absent((descriptor["engine"]["storage_root"], descriptor["engine"]["runroot"],
            descriptor["output_path"], descriptor["context_path"], owner.engine_descriptor_path))
        require(store.read_policy(record["policy_sha256"])["retention_seconds"] == 14400
                and store.read(owner.lease_id) == record, "continuation-sixth-retirement-drift")
        return {"record_sha256": ledger.digest(record), "closed_at": record["closed_at"],
                "native_absence_sha256": ledger.digest(absent)}


def _sixth_catalogue_snapshot(directory, previous, *, intake):
    root = installation._open_directory(directory)
    try:
        names = run_intake._entries(root)
        require(0 < len(names) <= 256 and all(re.fullmatch("[0-9a-f]{64}", name) for name in names),
                "continuation-sixth-retired-catalogue")
        require(type(previous) is dict and set(previous) < set(names),
                "continuation-sixth-original-catalogue-extension")
        rows = {}
        for name in names:
            if name in previous:
                require(_fifth_retired_entry(Path(directory) / name) == previous[name],
                        "continuation-sixth-previous-catalogue-drift")
                rows[name] = previous[name]
                continue
            child = os.open(name, installation.DIR_FLAGS, dir_fd=root)
            try:
                value = run_intake._read_at(child, "intent.json")[0]
                if intake:
                    source = value["binding"]["source"]
                    controller = value["binding"]["controller"]
                    who = value["original_job"]
                    require(source["repository"] == SOURCE and source["commit_sha"] == operating_cells.SIXTH_MAIN
                            and controller["repository"] == VALIDATION
                            and controller["commit_sha"] == operating_cells.SIXTH_REUSABLE,
                            "continuation-sixth-retired-source")
                else:
                    configuration, _ = _read_complete(Path(directory) / name)
                    who = read_configuration_origin(configuration)
                    require(who["source_sha"] == operating_cells.SIXTH_MAIN
                            and who["reusable_sha"] == operating_cells.SIXTH_REUSABLE,
                            "continuation-sixth-retired-configuration")
                require(who["run_id"] == operating_cells.SIXTH_RUN and who["job_id"] == operating_cells.SIXTH_JOB
                        and who["check_run_id"] == operating_cells.SIXTH_JOB, "continuation-sixth-retired-invocation")
                rows[name] = _fifth_retired_entry(Path(directory) / name)
            finally:
                os.close(child)
        require(run_intake._entries(root) == names, "continuation-sixth-retired-catalogue-drift")
        return rows
    finally:
        os.close(root)


def collect_sixth_preparation_retirement(successor_ledger_path, original_configuration, previous_qualification):
    """Read-only complete prior history and exact seventh-creator closure; never replay preparation."""
    _root()
    engine._path(successor_ledger_path)
    operating_cells._validate_partial_preparation_qualification(previous_qualification)
    require(ledger.digest(previous_qualification) == operating_cells.SIXTH_PREVIOUS_QUALIFICATION,
            "continuation-sixth-exact-previous-qualification")
    previous = previous_qualification["retirement"]
    _revalidate_fifth_retirement(previous, successor_ledger_path)
    before = _sixth_closed_projection(successor_ledger_path, original_configuration)
    catalogues = {"native_intake_catalogue": _sixth_catalogue_snapshot(run_intake.ROOT,
            previous["catalogues"]["native_intake_catalogue"], intake=True),
        "native_run_configuration_catalogue": _sixth_catalogue_snapshot(ROOT,
            previous["catalogues"]["native_run_configuration_catalogue"], intake=False)}
    _revalidate_fifth_retirement(previous, successor_ledger_path)
    require(_sixth_closed_projection(successor_ledger_path, original_configuration) == before,
            "continuation-sixth-closed-drift")
    value = {"schema": 1, "kind": "original-sixth-post-context-pre-fence-verified-closed",
             "lease_id": operating_cells.SIXTH_LEASE, "retain_until": operating_cells.SIXTH_RETAIN_UNTIL,
             **before, "catalogues": catalogues, "original_configuration": original_configuration}
    operating_cells._validate_sixth_retirement(value)
    return value


def _revalidate_sixth_retirement(retirement, successor_ledger_path):
    operating_cells._validate_sixth_retirement(retirement)
    current = _sixth_closed_projection(successor_ledger_path, retirement["original_configuration"])
    require(current == {key: retirement[key] for key in ("record_sha256", "closed_at", "native_absence_sha256")},
            "continuation-sixth-retirement-drift")


@identity._diagnostic_step("native-histories")
def _continuation_original_native(get, *, prior=False):
    origin = operating_cells.continuation_prior_origin() if prior else operating_cells.continuation_origin()
    prefix = "/actions/runs/" + str(origin["run_id"])
    run = get(prefix)
    rows, total = [], None
    for page in range(1, 5):
        data = get(prefix + "/attempts/1/jobs?per_page=100&page=" + str(page))
        count, batch = data.get("total_count"), data.get("jobs")
        require(type(count) is int and count == 24 and type(batch) is list and len(batch) <= 100
                and (total is None or count == total), "continuation-original-pagination")
        total = count; rows.extend(batch)
        if len(rows) >= count:
            break
    require(len(rows) == total, "continuation-original-pagination")
    checks = [get("/check-runs/" + str(row["check_run_id"]))
              for row in origin["jobs"]]
    commit = get("/git/commits/" + origin["source_sha"])
    project = operating_cells.prior_native_projection if prior else operating_cells.origin_native_projection
    return project(run, {"total_count": total, "jobs": rows}, checks, commit)


@identity._diagnostic_step("native-histories")
def _continuation_third_native(get):
    origin = operating_cells.continuation_third_origin()
    prefix = "/actions/runs/" + str(origin["run_id"])
    run = get(prefix)
    rows, total = [], None
    for page in range(1, 5):
        data = get(prefix + "/attempts/1/jobs?per_page=100&page=" + str(page))
        count, batch = data.get("total_count"), data.get("jobs")
        require(type(count) is int and count == 24 and type(batch) is list and len(batch) <= 100
                and (total is None or count == total), "continuation-original-pagination")
        total = count; rows.extend(batch)
        if len(rows) >= count:
            break
    require(len(rows) == total, "continuation-original-pagination")
    checks = [get("/check-runs/" + str(row["check_run_id"]))
              for row in origin["jobs"]]
    commit = get("/git/commits/" + origin["source_sha"])
    return operating_cells.third_native_projection(run, {"total_count": total, "jobs": rows}, checks, commit)

@identity._diagnostic_step("native-histories")
def _continuation_fourth_native(get):
    origin = operating_cells.continuation_fourth_origin()
    prefix = "/actions/runs/" + str(origin["run_id"])
    run = get(prefix)
    rows, total = [], None
    for page in range(1, 5):
        data = get(prefix + "/attempts/1/jobs?per_page=100&page=" + str(page))
        count, batch = data.get("total_count"), data.get("jobs")
        require(type(count) is int and count == 24 and type(batch) is list and len(batch) <= 100
                and (total is None or count == total), "continuation-original-pagination")
        total = count; rows.extend(batch)
        if len(rows) >= count:
            break
    require(len(rows) == total, "continuation-original-pagination")
    checks = [get("/check-runs/" + str(row["check_run_id"]))
              for row in origin["jobs"]]
    commit = get("/git/commits/" + origin["source_sha"])
    return operating_cells.fourth_native_projection(run, {"total_count": total, "jobs": rows}, checks, commit)


def _continuation_catalogue(directory, expected, descriptor, bootstrap_sha, templates, *, intake, retired=None):
    """Only exact successor metadata can follow the original empty catalogue."""
    root = installation._open_directory(directory)
    try:
        device, inode, *_ = run_intake._directory_identity(root)
        require((device, inode) == (expected["directory_device"], expected["directory_inode"]),
                "continuation-original-catalogue-identity")
        names = run_intake._entries(root)
        require(len(names) <= 256 and all(re.fullmatch("[0-9a-f]{64}", name) for name in names),
                "continuation-catalogue-unknown")
        successor = descriptor["successor"]
        require(retired is None or type(retired) is dict and set(retired) <= names,
                "continuation-fifth-retired-entry-missing")
        for name in names:
            if retired is not None and name in retired:
                require(_fifth_retired_entry(Path(directory) / name) == retired[name],
                        "continuation-fifth-retired-entry-drift")
                continue
            child = os.open(name, installation.DIR_FLAGS, dir_fd=root)
            try:
                run_intake._directory_identity(child)
                intent = run_intake._read_at(child, "intent.json")[0]
                if intake:
                    engine._keys(intent, {"schema", "binding", "original_job"})
                    binding = engine._keys(intent["binding"], {"schema", "identity_domain", "custody_policy_sha256",
                                                               "source", "controller", "artifact"})
                    who = engine._keys(intent["original_job"], {"worker_sha256", "run_id", "job_id", "check_run_id",
                                                               "native_job_name", "identity_policy_sha256"})
                    require(name == ledger.digest(binding), "continuation-intake-directory-binding")
                    source, controller, artifact = binding["source"], binding["controller"], binding["artifact"]
                    require(type(binding["schema"]) is int and binding["schema"] == 1
                        and source == {"repository": SOURCE, "repository_id": 1103407173,
                                       "commit_sha": successor["source_sha"]}
                        and controller == {"repository": VALIDATION, "repository_id": 1269461997,
                                           "commit_sha": successor["reusable_sha"]}
                        and type(binding["identity_domain"]) is dict
                        and binding["identity_domain"].get("repository") == SOURCE
                        and binding["identity_domain"].get("caller_sha") == successor["source_sha"]
                        and binding["identity_domain"].get("reusable_sha") == successor["reusable_sha"]
                        and type(artifact) is dict and artifact.get("head_sha") == successor["source_sha"]
                        and type(artifact.get("run_attempt")) is int and artifact["run_attempt"] == 1
                        and type(artifact.get("run_id")) is int and artifact["run_id"] == successor["run_id"]
                        and who["native_job_name"] in {row["native_job_name"] for row in templates.values()},
                        "continuation-intake-original-or-unknown")
                else:
                    engine._keys(intent, {"schema", "invocation", "snapshot_receipt_sha256", "created_at", "deadline",
                                          "worker", "job_started_at", "template_sha256"})
                    who = engine._keys(intent["invocation"], {"repository", "run_id", "run_attempt", "check_run_id",
                        "job_id", "source_sha", "reusable_sha", "selector", "bootstrap_sha256"})
                    require(name == ledger.digest({key: who[key] for key in ("repository", "run_id", "check_run_id", "selector")}),
                            "continuation-configuration-directory-binding")
                    require(who["repository"] == SOURCE and who["source_sha"] == successor["source_sha"]
                        and who["reusable_sha"] == successor["reusable_sha"]
                        and type(who["run_attempt"]) is int and who["run_attempt"] == 1
                        and who["selector"] in templates and who["bootstrap_sha256"] == bootstrap_sha,
                        "continuation-configuration-original-or-unknown")
                require(type(intent["schema"]) is int and intent["schema"] == 1
                        and type(who["run_id"]) is int and who["run_id"] == successor["run_id"]
                        and all(type(who[k]) is int and who[k] > 0 for k in ("job_id", "check_run_id")),
                        "continuation-catalogue-native-tuple")
            finally:
                os.close(child)
        require(run_intake._entries(root) == names, "continuation-catalogue-drift")
    finally:
        os.close(root)


def _continuation_origin_absent(bootstrap, qualified):
    """Product API reads only; call outside any nested Ledger transaction."""
    descriptor, receipt, counts, _ = qualified
    if descriptor["schema"] == 8:
        require(_eighth_failed_prefix_projection(bootstrap.value["ledger_path"],
                    receipt["failed_prefix"]["original_bootstrap"], receipt["previous_qualification"],
                    revalidating=True, defer_catalogues=True) == receipt["failed_prefix"],
                "continuation-eighth-failed-prefix-drift")
        retired = receipt["failed_prefix"]["catalogues"]
    else:
        seventh = descriptor["schema"] == 7
        history = receipt["previous_qualification"] if seventh else receipt
        schema = 6 if seventh else descriptor["schema"]
        retired = receipt["failed_prefix"]["catalogues"] if seventh else (
            history["retirement"]["catalogues"] if schema in {5, 6} else None)
        if seventh:
            require(_seventh_failed_prefix_projection(bootstrap.value["ledger_path"],
                        receipt["failed_prefix"]["original_bootstrap"], history, revalidating=True) == receipt["failed_prefix"],
                    "continuation-seventh-failed-prefix-drift")
        if schema == 6:
            previous = history["previous_qualification"]["retirement"]
            _revalidate_fifth_retirement(previous, bootstrap.value["ledger_path"])
            _revalidate_sixth_retirement(history["retirement"], bootstrap.value["ledger_path"])
            require(all(set(previous["catalogues"][kind]) < set(history["retirement"]["catalogues"][kind])
                        and all(history["retirement"]["catalogues"][kind].get(name) == digest for name, digest in previous["catalogues"][kind].items())
                        for kind in previous["catalogues"]), "continuation-sixth-previous-catalogue-drift")
        elif retired is not None:
            _revalidate_fifth_retirement(history["retirement"], bootstrap.value["ledger_path"])
    _continuation_catalogue(run_intake.ROOT, counts["native_intake_catalogue"], descriptor, bootstrap.sha256,
                            bootstrap.value["cells"], intake=True,
                            retired=retired["native_intake_catalogue"] if retired is not None else None)
    _continuation_catalogue(ROOT, counts["native_run_configuration_catalogue"], descriptor, bootstrap.sha256,
                            bootstrap.value["cells"], intake=False,
                            retired=retired["native_run_configuration_catalogue"] if retired is not None else None)
    successor = descriptor["successor"]
    with ledger.Ledger(bootstrap.value["ledger_path"], clock=time.time) as store:
        for identifier in store.lease_ids():
            who = store.read(identifier)["identity"]
            require(who["run_id"] == successor["run_id"] and who["caller_sha"] == successor["source_sha"]
                    and who["reusable_sha"] == successor["reusable_sha"], "continuation-original-or-unknown-lease")


@identity._diagnostic_step("native-histories")
def _continuation_native_histories(get, descriptor, receipt):
    """Overlap only independent terminal families; join before any proof escapes."""
    eighth = descriptor["schema"] == 8
    record = receipt["previous_qualification"] if eighth else receipt
    seventh = descriptor["schema"] in {7, 8}
    history = record["previous_qualification"] if seventh else record
    schema = 6 if seventh else descriptor["schema"]
    fifth = history["previous_qualification"] if schema == 6 else history
    four = fifth["previous_qualification"] if schema in {5, 6} else fifth
    three = four["previous_qualification"] if schema in {4, 5, 6} else four
    previous = three["previous_qualification"] if schema in {3, 4, 5, 6} else three
    legacy = previous["legacy_qualification"] if schema in {2, 3, 4, 5, 6} else previous
    families = [(_continuation_original_native, {}, legacy["native_origin"], "continuation-original-native-drift")]
    if schema in {2, 3, 4, 5, 6}:
        families.append((_continuation_original_native, {"prior": True}, previous["native_prior"],
                         "continuation-prior-native-drift"))
    if schema in {3, 4, 5, 6}:
        families.append((_continuation_third_native, {}, three["native_third"], "continuation-third-native-drift"))
    if schema in {4, 5, 6}:
        families.append((_continuation_fourth_native, {}, four["native_fourth"], "continuation-fourth-native-drift"))
    if schema in {5, 6}:
        families.append((_continuation_fifth_native, {}, fifth["native_fifth"], "continuation-fifth-native-drift"))
    if schema == 6:
        families.append((_continuation_sixth_native, {}, history["native_sixth"], "continuation-sixth-native-drift"))
    if seventh:
        families.append((_continuation_seventh_native, {}, record["native_seventh"],
                         "continuation-seventh-native-drift"))
    if eighth:
        families.append((_continuation_eighth_native, {}, receipt["native_eighth"],
                         "continuation-eighth-native-drift"))
    with ThreadPoolExecutor(max_workers=4) as executor:
        pending = [executor.submit(helper, get, **arguments) for helper, arguments, _, _ in families]
        # Declaration order decides the first failure, independently of finish
        # order. Executor exit also joins every later family on any failure.
        for future, (_, _, expected, reason) in zip(pending, families):
            require(future.result() == expected, reason)


@identity._diagnostic_step("native-current")
def _native(connected, selected, nonce, token, api_token, *, check_origin=True):
    admission._secret(token); admission._secret(api_token)
    controls = _controls(selected.bootstrap)
    admission._socket(connected)
    worker, acquisition = collector.begin_worker_acquisition(connected, selected.bootstrap.collector)
    try:
        require(type(worker) is ledger.Worker, "bootstrap-native-worker")
        worker.validate()
        base = selected.bootstrap.value["source_identity"]
        require(worker.runner_id == base["runner_id"] and worker.uid == base["service_uid"], "bootstrap-native-worker")
        who = identity.verify_github_assignment(token, selected.identity, audience=ledger.AUDIENCE + nonce,
            peer_uid=worker.uid, access_token=api_token, clock=time.time)
        reader = identity.HTTPSReader()
        prefix = identity.API + "/repos/" + SOURCE
        def get(path): return identity.decode_json(reader.read(prefix + path, bearer=api_token))
        workflow = get("/contents/.github/workflows/collection-ci.yml?ref=" + who.caller_sha)
        require(workflow.get("type") == "file" and workflow.get("path") == ".github/workflows/collection-ci.yml"
                and workflow.get("encoding") == "base64" and type(workflow.get("content")) is str
                and len(workflow["content"]) <= 524288, "bootstrap-workflow-file")
        raw = base64.b64decode("".join(workflow["content"].split()), validate=True)
        require(type(workflow.get("size")) is int and workflow["size"] == len(raw)
                and hashlib.sha256(raw).hexdigest() == selected.bootstrap.value["source_workflow_sha256"],
                "bootstrap-workflow-sha")
        job = get("/actions/jobs/" + str(who.job_id))
        require(job.get("id") == who.job_id and job.get("run_id") == who.run_id and job.get("head_sha") == who.caller_sha
                and job.get("status") == "in_progress" and job.get("conclusion") is None
                and job.get("name") == selected.identity.required_native_job_name, "bootstrap-native-job")
        started = job.get("started_at")
        require(type(started) is str and re.fullmatch("[0-9]{4}(?:-[0-9]{2}){2}T[0-9]{2}(?::[0-9]{2}){2}Z", started),
                "bootstrap-job-started")
        stamp = int(dt.datetime.strptime(started, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp())
        require(0 < stamp <= int(time.time()), "bootstrap-job-started")
        qualified = _continuation_receipt(selected.bootstrap.value)
        if qualified is not None:
            descriptor, receipt, _, _ = qualified
            successor = descriptor["successor"]
            require((who.caller_sha, who.run_id, who.reusable_sha) ==
                    (successor["source_sha"], successor["run_id"], successor["reusable_sha"]),
                    "continuation-exact-current-native-tuple")
            # Historical terminal qualification is minted once into this existing
            # opaque native proof. Current authorization and original absence are
            # still freshly checked on every revalidation; no shared cache exists.
            if check_origin:
                _continuation_native_histories(get, descriptor, receipt)
            _continuation_origin_absent(selected.bootstrap, qualified)
            if descriptor["schema"] in {3, 4, 5, 6, 7, 8} or identity.decode_json(selected.template_bytes)["kind"] == "operating":
                operating_cells.validate_continuation_commit(get("/git/commits/" + who.caller_sha), descriptor,
                                                             who.caller_sha, who.run_id, who.reusable_sha)
        elif identity.decode_json(selected.template_bytes)["kind"] == "operating":
            operating_cells.validate_initial_main(get("/git/commits/" + who.caller_sha), who.caller_sha)
        admission._socket(connected)
        require(collector.finish_worker_acquisition(acquisition, connected, selected.bootstrap.collector) == worker
                and _controls(selected.bootstrap) == controls,
                "bootstrap-native-drift")
        return worker, who, controls, stamp
    finally:
        collector.discard_worker_acquisition(acquisition)


@identity._diagnostic_step("bootstrap-initial-native")
def verify_bootstrap_native(connected, bootstrap, selector, nonce, token, api_token, *, purpose="execution"):
    _root()
    try:
        # Parse only a bounded locator. Signature, all claims and actual Main
        # assignment are verified independently by _native before registration.
        admission._secret(token)
        pieces = token.split(".")
        require(len(pieces) == 3, "bootstrap-token-shape")
        claims = identity.decode_json(identity.unbase(pieces[1]))
        selected = derive_selection(bootstrap, selector, claims.get("sha"), purpose=purpose)
        before = _worker(connected, bootstrap)
        challenge = _challenge(selected, nonce, before)
        require(challenge["issued_at"] <= int(time.time()) < challenge["expires_at"], "bootstrap-challenge-expired")
        worker, who, controls, started = _native(connected, selected, nonce, token, api_token)
        require(worker == before, "bootstrap-native-drift")
        remaining = min(600, who.valid_until - int(time.time()) - 31)
        require(remaining > 0, "bootstrap-native-expired")
        proof = BootstrapNativeProof(worker, who, nonce, selected, controls, ledger.digest(challenge), weakref.ref(connected),
            connected.fileno(), os.getpid(), threading.get_ident(), time.monotonic() + remaining, started)
        with _GUARD: _PROOFS.add(proof)
        return proof
    except Exception as error:
        identity._diagnostic_failed("bootstrap-initial-native", error)
        raise Denied("bootstrap-native-denied") from None


@identity._diagnostic_step("bootstrap-final-native")
def require_bootstrap_native(proof, connected, selected, token, api_token):
    _root()
    try:
        require(type(proof) is BootstrapNativeProof, "bootstrap-native-proof")
        with _GUARD: require(proof in _PROOFS, "bootstrap-native-proof")
        require(proof.pid == os.getpid() and proof.thread == threading.get_ident()
                and proof.connected() is connected and proof.fd == connected.fileno()
                and proof.policy == selected and time.monotonic() < proof.expires_monotonic,
                "bootstrap-native-proof")
        require(ledger.digest(_challenge(selected, proof.nonce, proof.worker)) == proof.challenge_sha256,
                "bootstrap-challenge-drift")
        worker, who, controls, started = _native(connected, selected, proof.nonce, token, api_token, check_origin=False)
        require((worker, who, controls, started) == (proof.worker, proof.identity, proof.controls_sha256, proof.job_started_at),
                "bootstrap-native-drift")
        remaining = min(600, int(proof.expires_monotonic - time.monotonic()), who.valid_until - int(time.time()) - 31)
        require(remaining > 0, "bootstrap-native-expired")
        return worker, who, remaining
    except Exception as error:
        identity._diagnostic_failed("bootstrap-final-native", error)
        raise Denied("bootstrap-native-denied") from None


def _invocation(bootstrap, selector, who):
    return {"repository": SOURCE, "run_id": who.run_id, "run_attempt": 1, "check_run_id": who.check_run_id,
            "job_id": who.job_id, "source_sha": who.caller_sha, "reusable_sha": who.reusable_sha, "selector": selector,
            "bootstrap_sha256": bootstrap.sha256}


def _inventory(directory):
    require(not os.path.lexists(directory / "publish-intent.json") and not os.path.lexists(directory / "published.json"),
            "run-config-foreign-receipt")
    return sealing._inventory(directory)


def _result(directory, value, digest):
    require(type(value) is dict and set(value) == {"schema", "scope", "invocation", "snapshot_receipt_sha256",
        "created_at", "deadline", "worker", "directory_identity", "runtime", "registry", "preparation", "inventory"}
        and type(value["schema"]) is int and value["schema"] == 1
        and value["scope"] == "private-job-configuration-only", "run-config-receipt")
    require(type(value["worker"]) is dict, "run-config-worker")
    ledger.Worker(**value["worker"]).validate()
    for key, name in (("runtime", "runtime.json"), ("registry", "registry.json"), ("preparation", "preparation.json")):
        ref = engine._keys(value[key], {"path", "sha256"})
        require(ref["path"] == str(directory / name), "run-config-receipt-path")
        engine._hash(ref["sha256"])
    require(type(value["created_at"]) is int and type(value["deadline"]) is int
            and 0 < value["deadline"] - value["created_at"] <= 5400, "run-config-deadline")
    fd = installation._open_directory(str(directory))
    try:
        require(list(run_intake._directory_identity(fd)) == value["directory_identity"], "run-config-directory-drift")
        intent = run_intake._read_at(fd, "intent.json")[0]
        require(intent["created_at"] == value["created_at"] and intent["deadline"] == value["deadline"]
                and intent["invocation"] == value["invocation"]
                and intent["snapshot_receipt_sha256"] == value["snapshot_receipt_sha256"]
                and intent["worker"] == value["worker"], "run-config-intent-drift")
    finally:
        os.close(fd)
    require(_inventory(directory) == value["inventory"], "run-config-inventory-drift")
    registry = policy_registry.load_registry(value["registry"]["path"], value["registry"]["sha256"])
    config, _, _ = preparation._config(value["preparation"]["path"], value["preparation"]["sha256"])
    runtime = runtime_rpc._configuration(value["runtime"]["path"], value["runtime"]["sha256"])
    require(config.registry_path == registry.path == runtime.registry_path
            and config.registry_sha256 == registry.sha256 == runtime.registry_sha256
            and runtime.preparation_config_path == config.path
            and runtime.preparation_config_sha256 == config.sha256, "run-config-reference-drift")
    require(set(registry.policies) == {value["invocation"]["selector"]}
            and registry.select(value["invocation"]["selector"]).deadline == value["deadline"], "run-config-cell-drift")
    native = registry.select(value["invocation"]["selector"]).identity
    require(native.caller_sha == value["invocation"]["source_sha"]
            and native.reusable_sha == value["invocation"]["reusable_sha"]
            and native.runner_id == value["worker"]["runner_id"] and native.service_uid == value["worker"]["uid"],
            "run-config-identity-drift")
    return RootRunConfiguration(str(directory), runtime.path, runtime.sha256, registry.path, registry.sha256,
                                config.path, config.sha256, value["deadline"], digest)


def _read_complete(directory):
    fd = installation._open_directory(str(directory))
    try:
        value, digest, stamp = run_intake._read_at(fd, "sealed-inventory.json")
        result = _result(directory, value, digest)
        require(run_intake._read_at(fd, "sealed-inventory.json")[2] == stamp, "run-config-receipt-drift")
        return result, value
    finally:
        os.close(fd)


def _build(directory, selected, who, snapshot, created_at, deadline):
    bootstrap = selected.bootstrap.value
    template = identity.decode_json(selected.template_bytes)
    acquired = snapshot.snapshot.acquisition
    fds = []
    try:
        for name in run_intake.ARCHIVES:
            fds.append(os.open(str(Path(snapshot.directory) / name), installation.FILE_FLAGS))
        tuples = ((acquired.artifact_sha256, acquired.artifact_size),
                  (acquired.source.archive_sha256, acquired.source.archive_size),
                  (acquired.controller.archive_sha256, acquired.controller.archive_size))
        raw = [run_intake._archive_bytes(fd, *item) for fd, item in zip(fds, tuples)]
        workspace = sealing._git_archive(raw[1], acquired.source)
        controller = sealing._git_archive(raw[2], acquired.controller)
        candidates, candidate_name, _ = sealing._candidate(raw[0], workspace)
        candidates["source-provenance.json"] = ledger.canonical(sealing._source_provenance(acquired.source))
        operating = template["kind"] == "operating"
        prefix = ".github/actions/run-operating-drill/" if operating else ".github/actions/run-quality-profile/"
        names = {"controller.py"} if operating else engine.CONTROLLER_FILES
        projected = {name: controller[prefix + name] for name in names}
        sealing._mkdir(directory / "trees")
        trees = {"workspace": sealing._tree(directory / "trees/workspace", workspace,
            executable={entry.path for entry in acquired.source.files if entry.mode == "100755"}),
            "candidate": sealing._tree(directory / "trees/candidate", candidates),
            "controller": sealing._tree(directory / "trees/controller", projected,
                executable={entry.path[len(prefix):] for entry in acquired.controller.files
                            if entry.mode == "100755" and entry.path.startswith(prefix) and entry.path[len(prefix):] in names})}
        sealing._mkdir(directory / "archives")
        candidate_sha = sealing._write(directory / "archives/candidate.tar.gz", candidates[candidate_name])
        payload = {"schema": 1, "candidate": {"repository": acquired.source.repository,
            "source_sha": acquired.source.commit_sha, "artifact": acquired.artifact.name, "archive_sha256": candidate_sha},
            "controller": {"repository": acquired.controller.repository, "source_sha": acquired.controller.commit_sha,
                "archive_sha256": acquired.controller.archive_sha256, "files": trees["controller"]["files"]},
            "github": template["github"], "engine": template["engine"], "incus": template["incus"]}
        payload["operating" if operating else "matrix"] = template["operating" if operating else "matrix"]
        if operating: payload["kind"] = "operating"
        payload["engine"]["trees"] = trees
        payload["engine"]["archives"] = {"candidate": {"path": str(directory / "archives/candidate.tar.gz"), "sha256": candidate_sha},
            "controller": {"path": str(Path(snapshot.directory) / "controller.tar.gz"), "sha256": acquired.controller.archive_sha256}}
        env = operating_cells.environment(payload, selected.identity, asdict(who)) if operating else cell_contract._environment(payload, selected.identity, asdict(who))
        cell_contract._validate_engine_template(payload["engine"], env, selected.identity, deadline, created_at)
        cell_contract._validate_incus_template(payload["incus"], env)
        require(all(bootstrap["runtime"]["capture"][key] == payload["engine"]["capture"][key]
                    for key in ("stdout_limit", "stderr_limit", "total_limit")), "run-config-capture-binding")
        cell_path = directory / "cell.json"
        cell_sha = sealing._json(cell_path, payload)
        native = {**bootstrap["source_identity"], "caller_sha": who.caller_sha}
        registry = {"schema": 1, "collector": bootstrap["collector"], "identity": native,
            "ledger_path": selected.ledger_path, "api_read_token_path": None,
            "cells": {selected.selector: {"native_job_name": selected.identity.required_native_job_name,
                "cell_config_path": str(cell_path), "cell_sha256": cell_sha,
                "custody_policy_sha256": selected.custody_policy_sha256, "deadline": deadline}}}
        registry_path = directory / "registry.json"
        registry_sha = sealing._json(registry_path, registry)
        prep = {"schema": 1, **bootstrap["preparation"], "registry_path": str(registry_path), "registry_sha256": registry_sha}
        prep_path = directory / "preparation.json"
        prep_sha = sealing._json(prep_path, prep)
        runtime = {"schema": 2, **bootstrap["runtime"], "capacity": bootstrap["capacity"], "registry_path": str(registry_path), "registry_sha256": registry_sha,
            "preparation_config_path": str(prep_path), "preparation_config_sha256": prep_sha}
        runtime_path = directory / "runtime.json"
        runtime_sha = sealing._json(runtime_path, runtime)
        return {"runtime": {"path": str(runtime_path), "sha256": runtime_sha},
                "registry": {"path": str(registry_path), "sha256": registry_sha},
                "preparation": {"path": str(prep_path), "sha256": prep_sha}}
    finally:
        for fd in fds: os.close(fd)


@identity._diagnostic_step("bootstrap-configuration")
def create_run_configuration(proof, connected, bootstrap, selector, token, api_token, sealed_snapshot=None):
    """One immutable original-job config. Unknown/partial directories stay held."""
    _root()
    root = None
    try:
        require(type(proof) is BootstrapNativeProof and proof.policy.purpose == "execution", "run-config-proof")
        selected = derive_selection(bootstrap, selector, proof.identity.caller_sha)
        worker, who, _ = require_bootstrap_native(proof, connected, selected, token, api_token)
        observed = run_intake.stage_run_snapshot(proof, connected, selected, token, api_token)
        require(sealed_snapshot is None or (type(sealed_snapshot) is run_intake.SealedRunSnapshot and observed == sealed_snapshot),
                "run-config-snapshot")
        require(observed.snapshot.acquisition.source.commit_sha == who.caller_sha
                and observed.snapshot.acquisition.controller.commit_sha == who.reusable_sha, "run-config-source")
        invocation = _invocation(bootstrap, selector, who)
        name = ledger.digest({key: invocation[key] for key in ("repository", "run_id", "check_run_id", "selector")})
        root = installation._open_directory(ROOT)
        run_intake._directory_identity(root)
        directory = Path(ROOT) / name
        try:
            os.mkdir(name, 0o700, dir_fd=root); os.fsync(root)
        except FileExistsError:
            result, receipt = _read_complete(directory)
            require(receipt["invocation"] == invocation and receipt["snapshot_receipt_sha256"] == observed.receipt_sha256,
                    "run-config-replay-drift")
            require_bootstrap_native(proof, connected, selected, token, api_token)
            require(_read_complete(directory)[0] == result, "run-config-final-drift")
            return result
        created = int(time.time())
        deadline = min(proof.job_started_at + selected.job_timeout_seconds, created + selected.lease_seconds)
        require(created < deadline <= created + 5400, "run-config-native-deadline")
        intent = {"schema": 1, "invocation": invocation, "snapshot_receipt_sha256": observed.receipt_sha256,
            "created_at": created, "deadline": deadline, "worker": asdict(worker), "job_started_at": proof.job_started_at,
            "template_sha256": selected.template_sha256}
        sealing._json(directory / "intent.json", intent)
        refs = _build(directory, selected, who, observed, created, deadline)
        current_worker, current_who, _ = require_bootstrap_native(proof, connected, selected, token, api_token)
        require((current_worker, current_who) == (worker, who), "run-config-native-drift")
        receipt = {"schema": 1, "scope": "private-job-configuration-only", "invocation": invocation,
            "snapshot_receipt_sha256": observed.receipt_sha256, "created_at": created, "deadline": deadline,
            "worker": asdict(worker), **refs, "inventory": _inventory(directory)}
        check = installation._open_directory(str(directory))
        try: receipt["directory_identity"] = list(run_intake._directory_identity(check))
        finally: os.close(check)
        sealing._json(directory / "sealed-inventory.json", receipt)
        result, again = _read_complete(directory)
        require(again == receipt, "run-config-readback")
        require_bootstrap_native(proof, connected, selected, token, api_token)
        require(_read_complete(directory)[0] == result, "run-config-final-drift")
        return result
    except Exception as error:
        identity._diagnostic_failed("bootstrap-configuration", error)
        raise Denied("run-configuration-held") from None
    finally:
        if root is not None: os.close(root)


def _current_configuration_catalogue(bootstrap, root):
    """Read current complete configs, preserving authenticated retired history.

    Retired entries are evidence, not runnable configurations. Their exact full
    history, inodes, bytes, original absence and every successor addition are
    revalidated on both sides of the read. An unqualified or current partial
    directory still fails closed; no missing-seal exception grants admission.
    """
    qualified = _continuation_receipt(bootstrap.value)
    retired = {}
    if qualified is not None:
        _continuation_origin_absent(bootstrap, qualified)
        descriptor, receipt, _, _ = qualified
        if descriptor["schema"] in {7, 8}:
            retired = receipt["failed_prefix"]["catalogues"]["native_run_configuration_catalogue"]
        elif descriptor["schema"] in {5, 6}:
            retired = receipt["retirement"]["catalogues"]["native_run_configuration_catalogue"]
    directory_identity = run_intake._directory_identity(root)
    names = run_intake._entries(root)
    require(len(names) <= 256 and all(re.fullmatch("[0-9a-f]{64}", name) for name in names)
            and set(retired) <= names, "run-config-catalogue-bound")
    rows = [_read_complete(Path(ROOT) / name) for name in sorted(names - set(retired))]
    if qualified is not None:
        _continuation_origin_absent(bootstrap, qualified)
    current = installation._open_directory(ROOT)
    try:
        require(run_intake._directory_identity(current) == directory_identity
                and run_intake._entries(root) == names, "run-config-catalogue-drift")
    finally:
        os.close(current)
    return rows


def find_existing_configuration(bootstrap, selector, observer_proof):
    return _find_existing_configuration(bootstrap, selector, observer_proof, purpose="observer")


def find_existing_execution_configuration(bootstrap, selector, execution_proof):
    """Read-only SAME job locator; no archive reacquisition or new admission."""
    return _find_existing_configuration(bootstrap, selector, execution_proof, purpose="execution")


@identity._diagnostic_step("observer-lookup")
def _find_existing_configuration(bootstrap, selector, observer_proof, *, purpose):
    """Read-only original-execution locator; caller freshly revalidates proof.

    This cannot create/renew a lease or reconfigure an execution. Historical
    observer admission remains subject to current-Main/in-progress checks.
    """
    _root()
    root = None
    try:
        require(type(observer_proof) is BootstrapNativeProof, "run-config-observer")
        with _GUARD: require(observer_proof in _PROOFS, "run-config-observer")
        selected = derive_selection(bootstrap, selector, observer_proof.identity.caller_sha, purpose=purpose)
        require(observer_proof.policy == selected and observer_proof.pid == os.getpid()
                and observer_proof.thread == threading.get_ident() and time.monotonic() < observer_proof.expires_monotonic
                and observer_proof.identity.valid_until > int(time.time()) + 31, "run-config-observer")
        connected = observer_proof.connected()
        require(connected is not None and connected.fileno() == observer_proof.fd
                and _worker(connected, bootstrap) == observer_proof.worker
                and _controls(bootstrap) == observer_proof.controls_sha256, "run-config-observer")
        root = installation._open_directory(ROOT); run_intake._directory_identity(root)
        found = []
        who = observer_proof.identity
        for result, receipt in _current_configuration_catalogue(bootstrap, root):
            row = receipt["invocation"]
            if ((row["repository"], row["run_id"], row["source_sha"], row["reusable_sha"], row["selector"])
                    == (SOURCE, who.run_id, who.caller_sha, who.reusable_sha, selector)):
                require(row["bootstrap_sha256"] == bootstrap.sha256, "run-config-lookup-policy")
                if purpose == "execution":
                    require((row["job_id"], row["check_run_id"]) == (who.job_id, who.check_run_id)
                            and receipt["worker"] == asdict(observer_proof.worker), "run-config-lookup-execution-job")
                found.append(result)
        require(len(found) == 1, "run-config-lookup-unique")
        require(time.monotonic() < observer_proof.expires_monotonic
                and observer_proof.identity.valid_until > int(time.time()) + 31
                and connected.fileno() == observer_proof.fd and _worker(connected, bootstrap) == observer_proof.worker,
                "run-config-observer")
        return found[0]
    except Exception as error:
        identity._diagnostic_failed("observer-lookup", error)
        raise Denied("run-configuration-lookup-held") from None
    finally:
        if root is not None: os.close(root)


def read_configuration_origin(configuration):
    """Re-read fixed private manifest before comparing fresh native Who.

    The returned tuple is metadata, never a replacement for native admission.
    RuntimeRPC must compare its actual verified run/job/check before ANY lease
    preparation or signer call. A dataclass or public manifest locator alone
    cannot grant that authority.
    """
    _root()
    try:
        require(type(configuration) is RootRunConfiguration, "run-config-locator")
        directory = Path(configuration.directory)
        require(directory.parent == Path(ROOT) and re.fullmatch("[0-9a-f]{64}", directory.name), "run-config-locator")
        actual, receipt = _read_complete(directory)
        require(actual == configuration, "run-config-locator-drift")
        return {**receipt["invocation"], "worker": dict(receipt["worker"])}
    except Exception:
        raise Denied("run-configuration-origin-held") from None


def resolve_configuration(bootstrap, selector, manifest_sha256):
    """Read-only catalogue selection; caller still performs fresh native auth."""
    _root()
    root = None
    try:
        require(type(bootstrap) is RootBootstrapPolicy
                and load_bootstrap(bootstrap.path, bootstrap.sha256) == bootstrap
                and type(selector) is str and selector in bootstrap.value["cells"], "run-config-resolver")
        engine._hash(manifest_sha256)
        root = installation._open_directory(ROOT); run_intake._directory_identity(root)
        found = []
        for configuration, receipt in _current_configuration_catalogue(bootstrap, root):
            if configuration.manifest_sha256 == manifest_sha256:
                require(receipt["invocation"]["bootstrap_sha256"] == bootstrap.sha256
                        and receipt["invocation"]["selector"] == selector, "run-config-resolver-domain")
                found.append(configuration)
        require(len(found) == 1, "run-config-resolver-unique")
        return found[0]
    except Exception:
        raise Denied("run-configuration-resolve-held") from None
    finally:
        if root is not None: os.close(root)


def _continuation_seventh_native(get):
    prefix = "/actions/runs/" + str(operating_cells.SEVENTH_RUN)
    path = prefix + "/attempts/1/jobs?per_page=100&page=1"
    run, inventory = get(prefix), get(path)
    checks = [get("/check-runs/" + str(identifier)) for identifier in operating_cells.SEVENTH_CHECKS]
    result = operating_cells.seventh_native_projection(run, inventory, checks)
    require(get(path) == inventory, "continuation-seventh-native-inventory-drift")
    return result


def _seventh_failed_prefix_projection(successor_ledger_path, original_bootstrap, previous_qualification, *,
                                      revalidating=False):
    """Authenticate immutable failed prelease history without sealing or adopting it."""
    operating_cells._validate_sixth_preparation_qualification(previous_qualification)
    require(ledger.digest(previous_qualification) == operating_cells.SEVENTH_PREVIOUS_QUALIFICATION,
            "continuation-seventh-exact-previous-qualification")
    old = load_bootstrap(original_bootstrap["path"], original_bootstrap["sha256"])
    require(old.sha256 == operating_cells.SEVENTH_BOOTSTRAP, "continuation-seventh-separate-bank-required")
    old_value = old.value
    require(old_value["ledger_path"] != successor_ledger_path, "continuation-seventh-separate-bank-required")
    qualified = _continuation_receipt(old_value)
    require(qualified is not None and qualified[0]["schema"] == 6 and qualified[1] == previous_qualification
            and qualified[0]["successor"]["source_sha"] == operating_cells.SEVENTH_MAIN
            and qualified[0]["successor"]["run_id"] == operating_cells.SEVENTH_RUN
            and qualified[0]["successor"]["reusable_sha"] == operating_cells.SEVENTH_REUSABLE,
            "continuation-seventh-original-bootstrap")
    with ledger.Ledger(old_value["ledger_path"], clock=time.time) as store:
        require(store.lease_ids() == (), "continuation-seventh-original-lease-present")
        info = os.fstat(store.fd)
        bank = {"path": old_value["ledger_path"], "device": info.st_dev, "inode": info.st_ino}
        if os.path.lexists(successor_ledger_path):
            new = installation._open_directory(successor_ledger_path)
            try:
                current = os.fstat(new)
                require((current.st_dev, current.st_ino) != (info.st_dev, info.st_ino),
                        "continuation-seventh-aliased-original-bank")
            finally: os.close(new)
    entries = {}
    for kind, parent, name, marker, fixed in (
            ("configuration", ROOT, operating_cells.SEVENTH_CONFIGURATION, "intent.json", operating_cells.SEVENTH_CONFIG_INTENT),
            ("intake", run_intake.ROOT, operating_cells.SEVENTH_INTAKE, "sealed.json", operating_cells.SEVENTH_INTAKE_RECEIPT)):
        directory = Path(parent) / name
        fd = installation._open_directory(str(directory))
        try:
            device, inode, *_ = run_intake._directory_identity(fd)
            names = run_intake._entries(fd)
            receipt, sha, stamp = run_intake._read_at(fd, marker)
            require(sha == fixed, "continuation-seventh-prefix-receipt")
            if kind == "configuration":
                require(names == {"archives", "trees", "intent.json", "cell.json", "preparation.json", "registry.json", "runtime.json"},
                        "continuation-seventh-partial-configuration-inventory")
                who = receipt["invocation"]
                require(who["source_sha"] == operating_cells.SEVENTH_MAIN
                        and who["reusable_sha"] == operating_cells.SEVENTH_REUSABLE
                        and who["run_id"] == operating_cells.SEVENTH_RUN and type(who["run_attempt"]) is int
                        and who["run_attempt"] == 1
                        and who["job_id"] == who["check_run_id"] == operating_cells.SEVENTH_JOB
                        and who["bootstrap_sha256"] == old.sha256
                        and receipt["snapshot_receipt_sha256"] == operating_cells.SEVENTH_INTAKE_RECEIPT,
                        "continuation-seventh-partial-configuration-origin")
            else:
                require(names == run_intake.INVENTORY, "continuation-seventh-intake-inventory")
                intent, intent_sha, _ = run_intake._read_at(fd, "intent.json")
                require(receipt["binding"] == intent["binding"] and receipt["intent_sha256"] == intent_sha,
                        "continuation-seventh-intake-intent")
                who = intent["original_job"]
                proven = run_intake._proven(receipt["snapshot"]["acquisition"])
                require(proven.source.commit_sha == operating_cells.SEVENTH_MAIN
                        and proven.controller.commit_sha == operating_cells.SEVENTH_REUSABLE
                        and proven.artifact.run_id == operating_cells.SEVENTH_RUN
                        and who["run_id"] == operating_cells.SEVENTH_RUN
                        and who["job_id"] == who["check_run_id"] == operating_cells.SEVENTH_JOB,
                        "continuation-seventh-intake-origin")
                current_stamps = {name: list(installation._stamp(os.stat(name,dir_fd=fd,follow_symlinks=False)))
                                  for name in run_intake.ARCHIVES}
                require(current_stamps == receipt["archive_stamps"], "continuation-seventh-intake-archive-drift")
            entries[kind] = {"name": name, "device": device, "inode": inode,
                             "receipt_sha256": sha, "inventory_sha256": _fifth_retired_entry(directory)}
            require(run_intake._read_at(fd, marker)[1:] == (sha, stamp)
                    and run_intake._entries(fd) == names, "continuation-seventh-prefix-drift")
        finally: os.close(fd)
    old_catalogues = previous_qualification["retirement"]["catalogues"]
    catalogues = {}
    for kind, parent, entry in (("native_intake_catalogue", run_intake.ROOT, entries["intake"]),
                                ("native_run_configuration_catalogue", ROOT, entries["configuration"])):
        root = installation._open_directory(parent)
        try:
            names = run_intake._entries(root)
            historical = set(old_catalogues[kind]) | {entry["name"]}
            # Collection fixes the entire original catalogue. Revalidation
            # rehashes that same history; _continuation_origin_absent separately
            # authenticates every addition through _continuation_catalogue.
            require(historical <= names if revalidating else historical == names,
                    "continuation-seventh-extra-catalogue-entry")
            rows = {name: _fifth_retired_entry(Path(parent) / name) for name in historical}
            require(all(rows[name] == sha for name, sha in old_catalogues[kind].items())
                    and rows[entry["name"]] == entry["inventory_sha256"]
                    and run_intake._entries(root) == names, "continuation-seventh-catalogue-drift")
            catalogues[kind] = rows
        finally: os.close(root)
    with ledger.Ledger(old_value["ledger_path"], clock=time.time) as store:
        info = os.fstat(store.fd)
        require(store.lease_ids() == () and (info.st_dev, info.st_ino) == (bank["device"], bank["inode"]),
                "continuation-seventh-original-bank-drift")
    result = {"schema": 1, "kind": "original-seventh-staged-prelease-no-lease-preserved",
              "original_bootstrap": original_bootstrap, "original_bank": bank,
              **entries, "catalogues": catalogues}
    operating_cells._validate_seventh_failed_prefix(result)
    return result


def collect_seventh_prelease_history(successor_ledger_path, original_bootstrap, previous_qualification):
    """Read-only exact failed prefix, preserving all six prior histories."""
    _root(); engine._path(successor_ledger_path)
    previous = previous_qualification["previous_qualification"]["retirement"]
    _revalidate_fifth_retirement(previous, successor_ledger_path)
    _revalidate_sixth_retirement(previous_qualification["retirement"], successor_ledger_path)
    value = _seventh_failed_prefix_projection(successor_ledger_path, original_bootstrap, previous_qualification)
    _revalidate_fifth_retirement(previous, successor_ledger_path)
    _revalidate_sixth_retirement(previous_qualification["retirement"], successor_ledger_path)
    require(_seventh_failed_prefix_projection(successor_ledger_path, original_bootstrap, previous_qualification) == value,
            "continuation-seventh-prefix-collection-drift")
    return value


def _continuation_eighth_native(get):
    prefix = "/actions/runs/" + str(operating_cells.EIGHTH_RUN)
    path = prefix + "/attempts/1/jobs?per_page=100&page=1"
    run, inventory = get(prefix), get(path)
    checks = [get("/check-runs/" + str(identifier)) for identifier in operating_cells.EIGHTH_CHECKS]
    result = operating_cells.eighth_native_projection(run, inventory, checks)
    require(get(path) == inventory, "continuation-eighth-native-inventory-drift")
    return result


def _eighth_failed_prefix_projection(successor_ledger_path, original_bootstrap, previous_qualification, *,
                                     revalidating=False, defer_catalogues=False):
    """Read exact complete prelease history; never reseal, renew or adopt it."""
    require(type(revalidating) is bool and type(defer_catalogues) is bool
            and (not defer_catalogues or revalidating), "continuation-eighth-catalogue-composition")
    operating_cells._validate_seventh_prelease_qualification(previous_qualification)
    require(ledger.digest(previous_qualification) == operating_cells.EIGHTH_PREVIOUS_QUALIFICATION,
            "continuation-eighth-exact-previous-qualification")
    old = load_bootstrap(original_bootstrap["path"], original_bootstrap["sha256"])
    require(old.sha256 == operating_cells.EIGHTH_BOOTSTRAP
            and old.file_stamp[:2] == operating_cells.EIGHTH_BOOTSTRAP_IDENTITY
            and original_bootstrap["path"].endswith(
                "/oidc-config-successor-18aec68429f14f8ea94a90217f9ffe70/immutable-bootstrap-locator-repair/candidate-bootstrap.json"),
            "continuation-eighth-immutable-original-bootstrap")
    old_value = old.value
    require(old_value["ledger_path"] != successor_ledger_path, "continuation-eighth-separate-bank-required")
    qualified = _continuation_receipt(old_value)
    require(qualified is not None and qualified[0]["schema"] == 7 and qualified[1] == previous_qualification
            and qualified[0]["successor"]["source_sha"] == operating_cells.EIGHTH_MAIN
            and qualified[0]["successor"]["run_id"] == operating_cells.EIGHTH_RUN
            and qualified[0]["successor"]["reusable_sha"] == operating_cells.EIGHTH_REUSABLE,
            "continuation-eighth-original-bootstrap")
    # Revalidate every older history while allowing only the outer current
    # descriptor to classify additions. Reusing old _continuation_origin_absent
    # here would incorrectly classify the next legitimate caller as old work.
    sixth = previous_qualification["previous_qualification"]
    _revalidate_fifth_retirement(sixth["previous_qualification"]["retirement"], successor_ledger_path)
    _revalidate_sixth_retirement(sixth["retirement"], successor_ledger_path)
    require(_seventh_failed_prefix_projection(old_value["ledger_path"],
                previous_qualification["failed_prefix"]["original_bootstrap"], sixth, revalidating=True)
            == previous_qualification["failed_prefix"], "continuation-eighth-preserved-seventh-prefix")
    with ledger.Ledger(old_value["ledger_path"], clock=time.time) as store:
        require(store.lease_ids() == (), "continuation-eighth-original-lease-present")
        info = os.fstat(store.fd)
        bank = {"path": old_value["ledger_path"], "device": info.st_dev, "inode": info.st_ino}
        if os.path.lexists(successor_ledger_path):
            new = installation._open_directory(successor_ledger_path)
            try:
                current = os.fstat(new)
                require((current.st_dev, current.st_ino) != (info.st_dev, info.st_ino),
                        "continuation-eighth-aliased-original-bank")
            finally: os.close(new)
    entries = {}
    for kind, parent, name, marker, fixed in (
            ("configuration", ROOT, operating_cells.EIGHTH_CONFIGURATION, "sealed-inventory.json", operating_cells.EIGHTH_CONFIG_RECEIPT),
            ("intake", run_intake.ROOT, operating_cells.EIGHTH_INTAKE, "sealed.json", operating_cells.EIGHTH_INTAKE_RECEIPT)):
        directory = Path(parent) / name
        fd = installation._open_directory(str(directory))
        try:
            device, inode, *_ = run_intake._directory_identity(fd)
            names = run_intake._entries(fd)
            receipt, sha, stamp = run_intake._read_at(fd, marker)
            require(sha == fixed, "continuation-eighth-prefix-receipt")
            if kind == "configuration":
                require(names == {"archives", "trees", "intent.json", "cell.json", "preparation.json", "registry.json", "runtime.json", "sealed-inventory.json"},
                        "continuation-eighth-complete-configuration-inventory")
                configuration, actual = _read_complete(directory)
                require(actual == receipt and configuration.manifest_sha256 == sha,
                        "continuation-eighth-complete-configuration-receipt")
                who = receipt["invocation"]
                require(who["source_sha"] == operating_cells.EIGHTH_MAIN
                        and who["reusable_sha"] == operating_cells.EIGHTH_REUSABLE
                        and who["run_id"] == operating_cells.EIGHTH_RUN and type(who["run_attempt"]) is int
                        and who["run_attempt"] == 1
                        and who["job_id"] == who["check_run_id"] == operating_cells.EIGHTH_JOB
                        and who["bootstrap_sha256"] == old.sha256
                        and receipt["snapshot_receipt_sha256"] == operating_cells.EIGHTH_INTAKE_RECEIPT
                        and receipt["worker"]["runner_id"] == old_value["source_identity"]["runner_id"]
                        and receipt["worker"]["uid"] == old_value["source_identity"]["service_uid"],
                        "continuation-eighth-complete-configuration-origin")
            else:
                require(names == run_intake.INVENTORY, "continuation-eighth-intake-inventory")
                intent, intent_sha, _ = run_intake._read_at(fd, "intent.json")
                require(receipt["binding"] == intent["binding"] and receipt["intent_sha256"] == intent_sha,
                        "continuation-eighth-intake-intent")
                who = intent["original_job"]
                proven = run_intake._proven(receipt["snapshot"]["acquisition"])
                require(proven.source.commit_sha == operating_cells.EIGHTH_MAIN
                        and proven.controller.commit_sha == operating_cells.EIGHTH_REUSABLE
                        and proven.artifact.run_id == operating_cells.EIGHTH_RUN
                        and type(proven.artifact.run_attempt) is int and proven.artifact.run_attempt == 1
                        and who["run_id"] == operating_cells.EIGHTH_RUN
                        and who["job_id"] == who["check_run_id"] == operating_cells.EIGHTH_JOB,
                        "continuation-eighth-intake-origin")
                fds = []
                try:
                    for archive in run_intake.ARCHIVES:
                        fds.append(os.open(archive, installation.FILE_FLAGS, dir_fd=fd))
                    require(len(set(fds)) == 3, "continuation-eighth-distinct-archive-fds")
                    stamps = [installation._stamp(os.fstat(archive)) for archive in fds]
                    require(stamps == [tuple(receipt["archive_stamps"][name]) for name in run_intake.ARCHIVES],
                            "continuation-eighth-intake-archive-stamps")
                    if revalidating:
                        # Strict collection has reconstructed these exact fixed
                        # bytes. Freshly verify every byte/FD again, without
                        # repeating inert semantic unpacking on each native
                        # proof. The seal, provenance and full inventory remain
                        # exact; no previous-call cache or pathname-only proof.
                        expected = ((proven.artifact_sha256, proven.artifact_size),
                                    (proven.source.archive_sha256, proven.source.archive_size),
                                    (proven.controller.archive_sha256, proven.controller.archive_size))
                        for archive, pair in zip(fds, expected): run_intake._archive_bytes(archive, *pair)
                    else:
                        snapshot = run_intake._validate_archives(proven,
                            **dict(zip(("artifact_fd", "source_fd", "controller_fd"), fds)))
                        require(ledger.canonical(asdict(snapshot)) == ledger.canonical(receipt["snapshot"]),
                                "continuation-eighth-intake-archives")
                    require([installation._stamp(os.fstat(archive)) for archive in fds] == stamps,
                            "continuation-eighth-intake-archive-drift")
                finally:
                    for archive in fds: os.close(archive)
                run_intake._sealed_state_unchanged(fd, sha)
            entries[kind] = {"name": name, "device": device, "inode": inode,
                             "receipt_sha256": sha, "inventory_sha256": _fifth_retired_entry(directory)}
            require(run_intake._read_at(fd, marker)[1:] == (sha, stamp)
                    and run_intake._entries(fd) == names, "continuation-eighth-prefix-drift")
        finally: os.close(fd)
    catalogues = {}
    old_catalogues = previous_qualification["failed_prefix"]["catalogues"]
    for kind, parent, entry in (("native_intake_catalogue", run_intake.ROOT, entries["intake"]),
                                ("native_run_configuration_catalogue", ROOT, entries["configuration"])):
        if defer_catalogues:
            # Only the composed origin check uses this path. The complete
            # seventh prefix and both exact eighth entries were freshly read
            # above; its following _continuation_catalogue must freshly verify
            # every historical digest, root identity, name and current entry.
            # Collection and standalone projection retain their full pass.
            catalogues[kind] = {**old_catalogues[kind], entry["name"]: entry["inventory_sha256"]}
            continue
        root = installation._open_directory(parent)
        try:
            names = run_intake._entries(root)
            historical = set(old_catalogues[kind]) | {entry["name"]}
            require(len(names) <= 256 and all(re.fullmatch("[0-9a-f]{64}", name) for name in names)
                    and (historical <= names if revalidating else historical == names),
                    "continuation-eighth-extra-catalogue-entry")
            rows = {name: _fifth_retired_entry(Path(parent) / name) for name in historical}
            require(all(rows[name] == sha for name, sha in old_catalogues[kind].items())
                    and rows[entry["name"]] == entry["inventory_sha256"]
                    and run_intake._entries(root) == names, "continuation-eighth-catalogue-drift")
            catalogues[kind] = rows
        finally: os.close(root)
    with ledger.Ledger(old_value["ledger_path"], clock=time.time) as store:
        info = os.fstat(store.fd)
        require(store.lease_ids() == () and (info.st_dev, info.st_ino) == (bank["device"], bank["inode"]),
                "continuation-eighth-original-bank-drift")
    result = {"schema": 1, "kind": "original-eighth-complete-prelease-no-lease-preserved",
              "original_bootstrap": original_bootstrap, "original_bank": bank,
              **entries, "catalogues": catalogues}
    operating_cells._validate_eighth_failed_prefix(result)
    return result


def collect_eighth_prelease_history(successor_ledger_path, original_bootstrap, previous_qualification):
    """Collect exact complete original history twice; no same-run resume or publication."""
    _root(); engine._path(successor_ledger_path)
    value = _eighth_failed_prefix_projection(successor_ledger_path, original_bootstrap, previous_qualification)
    require(_eighth_failed_prefix_projection(successor_ledger_path, original_bootstrap, previous_qualification) == value,
            "continuation-eighth-prefix-collection-drift")
    return value
