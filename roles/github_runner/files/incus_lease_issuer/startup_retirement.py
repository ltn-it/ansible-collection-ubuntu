"""Policy for a separate Root retirement after a proved pre-VM abort.

The cleanup journal and native proof reader call this policy after their own
fresh observations. The result does not grant a successful workload or change
any original ledger result.
"""

import hashlib
import os
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
import uuid

from . import identity, installation, ledger, policy_registry
from .identity import require


POLICY = "protected-pre-vm-journal-v1"
POST_ENGINE_POLICY_FIELD = "post_engine_failure_policy_sha256"
G06_NO_WAIT_POLICY_FIELD = "g06_no_minimum_wait_policy_sha256"
MAX_OBSERVATION_AGE = 120
FAILURES = frozenset({"failure", "startup_failure", "timed_out", "cancelled"})
ARCHIVE_MEMBERS = ("original", "terminal", "failure", "inventory")
MAX_ARCHIVE_MEMBER = 8 * 1024 * 1024
PRE_AUTHORITY_CREATORS = frozenset({"network-create", "project-create", "profile-configure"})
PRE_AUTHORITY_STAGES = frozenset({"project-create", "profile-configure", "bridge-readback", "context-materialize"})
START_BOUNDARY = "root-journal-before-vm-authority"


def business_policy(original):
    """Keep the same custody terms and opt in only the separately sealed business policy."""
    ledger.Ledger._validate_policy(original)
    require(not {"startup_retirement", "post_engine_failure_retirement"} & original.keys()
            and (original["retention_seconds"] == 14400 or ledger.G06_NO_WAIT_MARKER in original),
            "startup-retirement-original-policy")
    return original | {"startup_retirement": POLICY}


def bootstrap_with_business_policy(bootstrap, original):
    """Prepare the prospective manifest before the publisher seals its new bank."""
    require(bootstrap["custody_policy_sha256"] == ledger.digest(original)
            and "business_startup_policy_sha256" not in bootstrap, "startup-retirement-bootstrap-binding")
    business = business_policy(_bootstrap_base_policy(bootstrap, original))
    return bootstrap | {"business_startup_policy_sha256": ledger.digest(business)}, business


def _g06_no_wait_scope(bootstrap):
    from . import engine_policy, run_factory

    source = bootstrap["source_identity"]
    require(type(bootstrap["schema"]) is int and bootstrap["schema"] == 1 and type(source) is dict
            and (source.get("repository"), source.get("repository_id"), source.get("owner_id"),
                 source.get("workflow_id"), source.get("workflow_path"), source.get("reusable_repository"),
                 source.get("reusable_path")) == (run_factory.SOURCE, 1103407173, 54334171, 214182490,
                 ".github/workflows/collection-ci.yml", run_factory.VALIDATION,
                 ".github/workflows/collection-quality-profile-isolated.yml"), "g06-no-minimum-wait-source")
    return ledger.digest([source, engine_policy._hash(bootstrap["source_workflow_sha256"]),
                          engine_policy._path(bootstrap["ledger_path"])])


def _g06_no_wait_policy(bootstrap, original):
    return original | {"retention_seconds": 0, ledger.G06_NO_WAIT_MARKER: _g06_no_wait_scope(bootstrap)}


def bootstrap_with_g06_no_minimum_wait(bootstrap, original):
    """Bind the new policy to a separately commissioned protected G06 bank."""
    cells = bootstrap["cells"]
    require(G06_NO_WAIT_POLICY_FIELD not in bootstrap and "business_startup_policy_sha256" not in bootstrap
            and type(cells) is dict and all(type(row) is dict and POST_ENGINE_POLICY_FIELD not in row
                                             for row in cells.values()),
            "g06-no-minimum-wait-bootstrap-order")
    baseline = _bootstrap_base_policy(bootstrap, original)
    policy = _g06_no_wait_policy(bootstrap, baseline)
    return bootstrap | {G06_NO_WAIT_POLICY_FIELD: ledger.digest(policy)}, policy


def _bootstrap_base_policy(bootstrap, original):
    ledger.Ledger._validate_policy(original)
    require(bootstrap["custody_policy_sha256"] == ledger.digest(original)
            and original["retention_seconds"] == 14400
            and not {"startup_retirement", "post_engine_failure_retirement", ledger.G06_NO_WAIT_MARKER}
            & original.keys(), "bootstrap-original-failure-retention")
    if G06_NO_WAIT_POLICY_FIELD not in bootstrap:
        return original
    selected = _g06_no_wait_policy(bootstrap, original)
    require(bootstrap[G06_NO_WAIT_POLICY_FIELD] == ledger.digest(selected), "g06-no-minimum-wait-policy-binding")
    return selected


def _bootstrap_business_policy(bootstrap, base):
    if "business_startup_policy_sha256" not in bootstrap:
        return base
    business = business_policy(base)
    require(bootstrap["business_startup_policy_sha256"] == ledger.digest(business),
            "startup-retirement-bootstrap-business-binding")
    return business


def _post_engine_policy(business, selector, template):
    matrix = template.get("matrix")
    require(template.get("kind") == "business" and type(matrix) is dict and matrix.get("profile") == "heavy"
            and selector == policy_registry.profile_selector("heavy", matrix.get("scenario"), matrix.get("target")),
            "post-engine-retirement-heavy-selector")
    policy = business | {"post_engine_failure_retirement": {"schema": 1, "selector": selector}}
    ledger.Ledger._validate_policy(policy)
    return policy


def _bootstrap_custody_rows(bootstrap, original):
    base = _bootstrap_base_policy(bootstrap, original)
    business = _bootstrap_business_policy(bootstrap, base)
    policies = {ledger.digest(original): original, ledger.digest(base): base, ledger.digest(business): business}
    cells = bootstrap["cells"]
    require(type(cells) is dict and all(type(template) is dict for template in cells.values()), "bootstrap-cells")
    for selector, template in cells.items():
        if POST_ENGINE_POLICY_FIELD in template:
            policy = _post_engine_policy(business, selector, template)
            expected = ledger.digest(policy)
            require(template[POST_ENGINE_POLICY_FIELD] == expected, "post-engine-retirement-policy-binding")
            policies[expected] = policy
    return policies


def bootstrap_with_post_engine_failure_policy(bootstrap, selector, original):
    """Prepare a Root-only opt-in for this exact Heavy cell before sealing the bank."""
    business = _bootstrap_business_policy(bootstrap, _bootstrap_base_policy(bootstrap, original))
    cells = bootstrap["cells"]
    require(type(selector) is str and selector in cells and type(cells[selector]) is dict
            and POST_ENGINE_POLICY_FIELD not in cells[selector], "post-engine-retirement-new-selector")
    template = cells[selector]
    policy = _post_engine_policy(business, selector, template)
    return bootstrap | {"cells": cells | {selector: template | {POST_ENGINE_POLICY_FIELD: ledger.digest(policy)}}}, policy


def archive_bootstrap_policies(store, bootstrap, original):
    """Seal the base and exact opted-in policy rows in a fresh bank."""
    require(type(store) is ledger.Ledger and not store.lease_ids(), "startup-retirement-new-bank")
    if G06_NO_WAIT_POLICY_FIELD in bootstrap:
        require(str(store.path) == bootstrap["ledger_path"], "g06-no-minimum-wait-bank-binding")
    rows = _bootstrap_custody_rows(bootstrap, original)
    require(len(rows) > 1, "startup-retirement-opt-in-required")
    for digest, policy in rows.items():
        require(store.archive_policy(policy) == digest and store.read_policy(digest) == policy,
                "startup-retirement-policy-readback")


def archived_original(directory, manifest_sha256, record):
    """Read the protected original and failure archive without adopting a partial copy."""
    require(type(directory) is str and directory.startswith("/") and not directory.endswith("/")
            and directory == str(PurePosixPath(directory)) and ".." not in PurePosixPath(directory).parts,
            "startup-retirement-archive-path")
    manifest_path = directory + "/manifest.json"
    proof, raw, stamp = installation._file(manifest_path, 65536, private=True, keep=True)
    require(proof.sha256 == manifest_sha256, "startup-retirement-archive-manifest")
    manifest = identity.decode_json(raw)
    require(type(manifest) is dict and set(manifest) == set(ARCHIVE_MEMBERS)
            and raw == ledger.canonical(manifest), "startup-retirement-archive-shape")
    contents = {}
    for name in ARCHIVE_MEMBERS:
        member, data, _ = installation._file(directory + "/" + name + ".json",
                                              MAX_ARCHIVE_MEMBER, private=True, keep=True)
        require(member.sha256 == manifest[name] and member.size > 0, "startup-retirement-archive-member")
        contents[name] = data
    bound = record.get("partial_preparation_custody", {}).get("pre_vm_retirement")
    if bound is None:
        require(contents["original"] == ledger.canonical(record), "startup-retirement-archived-original-drift")
    else:
        original = identity.decode_json(contents["original"])
        require(manifest["original"] == bound["original_sha256"] and manifest["inventory"] == bound["inventory_sha256"]
                and manifest_sha256 == bound["archive_sha256"]
                and type(original) is dict and contents["original"] == ledger.canonical(original)
                and all(original[key] == record[key] for key in ("identity", "worker", "cell_sha256", "policy_sha256",
                                                               "native_terminal"))
                and all(record["effects"].get(effect) == value for effect, value in original["effects"].items()),
                "startup-retirement-armed-original-drift")
    require(contents["terminal"] == ledger.canonical(record["native_terminal"]),
            "startup-retirement-archived-terminal-drift")
    require(installation._file(manifest_path, 65536, private=True, keep=True) == (proof, raw, stamp),
            "startup-retirement-archive-replaced")
    return {**manifest, "sha256": manifest_sha256}


def effective_floor(record, policy, *, selector, profile, scenario, target, archive, observations, now):
    """Choose the minimum from the original sealed policy and the bound witnesses."""
    ledger.Ledger._validate_policy(policy)
    require(ledger.digest(policy) == record.get("policy_sha256"), "startup-retirement-policy-drift")
    terminal = record.get("native_terminal")
    from .operating_custody import _terminal_record

    _terminal_record(terminal, record)
    require(type(now) is int and terminal["completed_at"] <= now, "startup-retirement-clock")
    ordinary_floor = terminal["completed_at"] + policy["retention_seconds"]
    if (policy.get("startup_retirement") != POLICY or profile not in {"heavy", "application_acceptance"}
            or selector != policy_registry.profile_selector(profile, scenario, target)):
        return ordinary_floor
    require(record.get("state") in {"prepared", "cancelled"} and "owned_instance" not in record and "custody" not in record and terminal["conclusion"] in FAILURES,
            "startup-retirement-actual-abort")
    original = ledger.digest(record)
    require(type(archive) is dict and set(archive) == set(ARCHIVE_MEMBERS) | {"sha256"}
            and archive["original"] == original and archive["terminal"] == ledger.digest(terminal)
            and all(type(archive[key]) is str and ledger.HEX.fullmatch(archive[key])
                    for key in ("failure", "inventory", "sha256")),
            "startup-retirement-original-archive")
    require(type(observations) is dict and set(observations) == {"original", "inventory", "at", "startup_boundary",
            "start_effect", "exclusive_ownership", "never_started_vm", "active_consumers", "access_withdrawn"}
            and observations["original"] == original and observations["inventory"] == archive["inventory"]
            and type(observations["at"]) is int and terminal["observed_at"] <= observations["at"] <= now
            and now - observations["at"] <= MAX_OBSERVATION_AGE
            and observations["exclusive_ownership"] is True and observations["never_started_vm"] is True
            and type(observations["active_consumers"]) is int and observations["active_consumers"] == 0
            and observations["access_withdrawn"] is True
            and observations["startup_boundary"] == START_BOUNDARY,
            "startup-retirement-fresh-scope")
    require(observations["start_effect"] is None and all(
                row["state"] == "verified" and row["operation"] in PRE_AUTHORITY_CREATORS
                for row in record["effects"].values()), "startup-retirement-vm-history-unproved")
    return observations["at"]


def observe_before_context(owner, store, config, *, closed=False):
    """Observe the same pre-certificate resource scope before or after retirement."""
    from . import cell_contract, engine_executor, incus_admin, incus_mutation

    require(os.geteuid() == 0 and type(owner) is cell_contract.PartialPreparationOwner
            and type(store) is ledger.Ledger and store.owner_uid == 0
            and cell_contract.revalidate_partial_preparation(owner, store),
            "startup-retirement-root-owner")
    record = store.read(owner.lease_id)
    permitted = set(owner.creators)
    if closed:
        permitted |= {operation for creator, operation in (
            ("network-create", "network-delete"), ("project-create", "project-delete"),
        ) if creator in owner.creators}
    require((record["state"] == "closed") is closed and set(owner.creators) <= PRE_AUTHORITY_CREATORS
            and {row["operation"] for row in record["effects"].values()} == permitted
            and all(row["state"] == "verified" for row in record["effects"].values()),
            "startup-retirement-before-context")
    target = owner.incus
    admin = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path,
        target["project"], target["network"], "default", target["pool"], ()))
    cleanup = incus_mutation.RootPartialPreparationCleanup(admin, owner, store)
    require(cleanup.certificates_absent(), "startup-retirement-live-credential")
    resources = {}
    for kind, creator in (("project", "project-create"), ("bridge", "network-create")):
        value = cleanup.readback(kind)
        expected = "required_fields_match" if not closed and creator in owner.creators else "absent_observed"
        require(value["state"] == expected, "startup-retirement-foreign-resource")
        resources[kind] = value
    if not closed and "project-create" in owner.creators:
        resources["quiet"] = cleanup.quiet_project()
    require(all(type(row.get("project")) is str and row["project"] != target["project"]
                for row in admin.pool_volumes()), "startup-retirement-existing-or-ambiguous-volume")
    if not closed and "profile-configure" in owner.creators:
        resources["profile"] = cleanup.readback("profile")
        require(resources["profile"]["state"] == "required_fields_match", "startup-retirement-profile-drift")
    descriptor = identity.decode_json(owner.engine_descriptor_bytes)
    paths = [owner.engine_descriptor_path, descriptor["context_path"], descriptor["output_path"],
             descriptor["engine"]["storage_root"], descriptor["engine"]["runroot"],
             "/run/netns/lit-lease-" + owner.lease_id,
             engine_executor.CGROUP_ROOT + engine_executor.SLICE_PARENT + engine_executor._slice_name(owner.lease_id)]
    require(not any(os.path.lexists(path) for path in paths), "startup-retirement-worker-resource-present")
    require(cleanup.certificates_absent() and store.read(owner.lease_id) == record
            and cell_contract.revalidate_partial_preparation(owner, store),
            "startup-retirement-scope-drift")
    return {"schema": 1, "lease": owner.lease_id, "creator_identity": owner.creators,
            "descriptor_sha256": owner.engine_descriptor_sha256, "resources": resources,
            "uncreated_worker_paths": paths}


def private_archive_locator(store, lease_id):
    """Only a Root-provisioned immutable archive can opt a lease into the earlier lane."""
    require(type(lease_id) is str and ledger.ID.fullmatch(lease_id), "startup-retirement-lease")
    folder = Path(store.path).parent / "startup-retirement" / lease_id
    manifest = folder / "manifest.json"
    if not os.path.lexists(manifest):
        return None
    proof, _, _ = installation._file(str(manifest), 65536, private=True)
    return str(folder), proof.sha256


def _publish_staged(staged, target):
    """Commit a complete Root-private file or directory under the caller's lock."""
    require(staged.parent == target.parent and staged.name.startswith("."), "startup-retirement-stage-scope")
    parent = installation._open_directory(str(target.parent))
    try:
        require(not os.path.lexists(target), "startup-retirement-output-already-sealed")
        os.rename(staged.name, target.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def _publish_record(path, value):
    from . import generation_publisher

    require(not os.path.lexists(path), "startup-retirement-output-already-sealed")
    staged = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    generation_publisher._json(staged, value)
    _publish_staged(staged, path)


def _abort_path(store, lease_id):
    require(os.geteuid() == 0 and type(store) is ledger.Ledger and store.owner_uid == 0
            and type(lease_id) is str and ledger.ID.fullmatch(lease_id), "startup-retirement-root-abort")
    return Path(store.path).parent / ("pre-vm-abort-" + lease_id + ".json")


def _abort_record(lease_id, record, stage):
    effects = tuple(record["effects"].values())
    require(stage in PRE_AUTHORITY_STAGES and record["state"] in {"prepared", "cancelled"}
            and bool(effects) and all(row["state"] == "verified" and row["operation"] in PRE_AUTHORITY_CREATORS
                                      for row in effects), "startup-retirement-original-abort-scope")
    return {"schema": 1, "lease_id": lease_id, "identity_sha256": ledger.digest(record["identity"]),
            "effects_sha256": ledger.digest(record["effects"]), "stage": stage,
            "diagnostic": "preparation-unknown"}


def record_preparation_abort(store, lease_id, stage):
    """Persist the original normalized error where the Root preparation attempt ends."""
    path = _abort_path(store, lease_id)
    record = store.read(lease_id)
    policy = store.read_policy(record["policy_sha256"])
    if policy.get("startup_retirement") == POLICY:
        _publish_record(path, _abort_record(lease_id, record, stage))


def original_preparation_abort(store, lease_id, record):
    """Read the preparation failure sealed before native terminal reconciliation."""
    path = _abort_path(store, lease_id)
    if not os.path.lexists(path):
        return None
    _, raw, _ = installation._file(str(path), 65536, private=True, keep=True)
    value = identity.decode_json(raw)
    require(type(value) is dict and type(value.get("stage")) is str
            and raw == ledger.canonical(_abort_record(lease_id, record, value["stage"])),
            "startup-retirement-original-abort-binding")
    return value


def publish_original_archive(store, lease_id, record, failure, inventory):
    """Make the validated original archive durable before publishing its locator."""
    from . import generation_publisher

    terminal = record["native_terminal"]
    require(type(failure) is dict and set(failure) == {"schema", "native_terminal_sha256", "root_abort"}
            and type(failure["schema"]) is int and failure["schema"] == 1
            and failure["native_terminal_sha256"] == ledger.digest(terminal)
            and failure["root_abort"] is not None
            and failure["root_abort"] == original_preparation_abort(store, lease_id, record),
            "startup-retirement-native-diagnostic")
    require(store.read(lease_id) == record, "startup-retirement-original-drift")
    folder = Path(store.path).parent / "startup-retirement" / lease_id
    if not os.path.lexists(folder.parent):
        generation_publisher._mkdir(folder.parent)
    staged = folder.with_name("." + lease_id + "." + uuid.uuid4().hex)
    generation_publisher._mkdir(staged)
    members = {"original": record, "terminal": terminal, "failure": failure, "inventory": inventory}
    hashes = {name: generation_publisher._json(staged / (name + ".json"), value) for name, value in members.items()}
    require(store.read(lease_id) == record, "startup-retirement-original-drift")
    binding = generation_publisher._json(staged / "manifest.json", hashes)
    require(archived_original(str(staged), binding, record) == hashes | {"sha256": binding},
            "startup-retirement-staged-archive")
    _publish_staged(staged, folder)
    require(archived_original(str(folder), binding, record) == hashes | {"sha256": binding},
            "startup-retirement-archive-readback")
    return str(folder), binding


def _post_engine_control_path(store, lease_id):
    require(os.geteuid() == 0 and type(store) is ledger.Ledger and store.owner_uid == 0
            and type(lease_id) is str and ledger.ID.fullmatch(lease_id), "post-engine-archive-root")
    return Path(store.path).parent / "post-engine-failures" / lease_id


def _post_engine_archive_path(owner):
    from . import cell_contract, engine_policy

    require(type(owner) is cell_contract.OwnedCellForCleanup, "post-engine-archive-owner")
    runroot = Path(engine_policy._path(identity.decode_json(owner.engine_descriptor_bytes)["engine"]["runroot"]))
    require(runroot.name == owner.lease_id, "post-engine-archive-runroot")
    return runroot.with_name(runroot.name + ".post-engine-evidence")


def _post_engine_evidence_quota(config, path):
    from . import storage_quota

    return storage_quota.acquire_existing_evidence_quota(
        config.storage_quota_policy_path, config.storage_quota_policy_sha256, str(path))


def _require_post_engine_archive_space(parent, manifest, capture_limit):
    observed = os.fstatvfs(parent)
    require(observed.f_frsize > 0, "post-engine-archive-capacity")
    sizes = [len(ledger.canonical(manifest)), *(row["size"] for row in manifest["members"].values())]
    blocks = 1 + sum((size + observed.f_frsize - 1) // observed.f_frsize for size in sizes)
    reserve_blocks = 1 + (capture_limit + observed.f_frsize - 1) // observed.f_frsize
    require(observed.f_bavail >= blocks + reserve_blocks and observed.f_favail >= 2 * (len(sizes) + 1),
            "post-engine-archive-capacity")


def _post_engine_archive_inputs(lease_id, record):
    from .operating_custody import _terminal_record

    terminal = record.get("native_terminal")
    _terminal_record(terminal, record)
    starts = [row for row in record["effects"].values() if row["operation"] == "engine-start"]
    require(len(starts) == 1 and starts[0]["target"] == "engine:lit-lease-" + lease_id
            and starts[0]["state"] == "verified" and terminal["conclusion"] == "failure",
            "post-engine-archive-failed-start")
    start, actual = starts[0], starts[0].get("engine_exit")
    ledger._validate_engine_exit(actual, start)
    require(actual["signal"] is None and actual["exit_code"] > 0 and actual["observed_at"] <= terminal["completed_at"]
            and all(actual[stream + "_state"] == "complete" for stream in ("stdout", "stderr")),
            "post-engine-archive-complete-exit")
    documents = {"original.json": ledger.canonical(record), "terminal.json": ledger.canonical(terminal)}
    members = {name: {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} for name, raw in documents.items()}
    members.update({stream + ".log": {"size": actual[stream + "_bytes"], "sha256": actual[stream + "_sha256"]}
                    for stream in ("stdout", "stderr")})
    manifest = {"schema": 1, "kind": "post-engine-failure", "lease_id": lease_id, "members": members}
    return start, documents, manifest


def _verify_post_engine_archive(folder, manifest, expected_sha256):
    from . import engine_policy

    require(ledger.digest(manifest) == expected_sha256, "post-engine-archive-manifest-binding")
    files = manifest["members"] | {"manifest.json": {"size": len(ledger.canonical(manifest)), "sha256": expected_sha256}}
    directory = engine_policy._directory(str(folder), private=True)
    try:
        original = installation._stamp(os.fstat(directory))
        require(set(os.listdir(directory)) == set(files), "post-engine-archive-inventory")
        stamps = {}
        for name, expected in files.items():
            member = os.open(name, installation.FILE_FLAGS, dir_fd=directory)
            try:
                proof, _, stamps[name] = installation._hash_file(
                    member, str(folder / name), max(1, expected["size"]), private=True)
                require(proof.size == expected["size"] and proof.sha256 == expected["sha256"],
                        "post-engine-archive-member-drift")
            finally:
                os.close(member)
        named = engine_policy._directory(str(folder), private=True)
        try:
            require(installation._stamp(os.fstat(named)) == original
                    and all(installation._stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)) == stamp
                            for name, stamp in stamps.items()), "post-engine-archive-replaced")
        finally:
            os.close(named)
    finally:
        os.close(directory)
    return str(folder), expected_sha256


def _read_post_engine_archive(store, lease_id, expected_sha256, archive):
    """Read a sealed archive against the same original lease snapshot."""
    record = store.read(lease_id)
    _, _, manifest = _post_engine_archive_inputs(lease_id, record)
    receipt = _verify_post_engine_archive(archive, manifest, expected_sha256)
    require(store.read(lease_id) == record, "post-engine-archive-record-drift")
    return receipt


def _read_post_engine_cleanup_journal(store, lease_id, archive_sha256, archive, *, complete=True):
    """Accept only verified cleanup entries for the exact archived creators."""
    _, raw, _ = installation._file(str(archive / "original.json"), MAX_ARCHIVE_MEMBER, private=True, keep=True)
    original = identity.decode_json(raw)
    _, _, manifest = _post_engine_archive_inputs(lease_id, original)
    _verify_post_engine_archive(archive, manifest, archive_sha256)

    record = store.read(lease_id)
    creators = {"engine-prepare", "context-create", "project-create", "network-create", "fence-create", "slice-create"}
    prior_withdrawals = {"certificate-create", "certificate-revoke", "engine-start", "engine-stop", "fence-disable"}
    preparation = {"profile-configure", "context-publish", "context-refresh", "fence-renew"}
    original_effects = original["effects"]
    operations = {effect["operation"] for effect in original_effects.values()}
    if "image-copy" in operations:
        from . import operating_cells

        projects = [effect["target"] for effect in original_effects.values() if effect["operation"] == "project-create"]
        copies = [effect["target"] for effect in original_effects.values() if effect["operation"] == "image-copy"]
        require(len(projects) == 1 and copies == [
            "image:" + projects[0].removeprefix("project:") + ":" + operating_cells.IMAGE],
            "post-engine-cleanup-image-scope")
        creators.add("image-copy")
    require(original["state"] in {"prepared", "cancelled"}
            and not {"owned_instance", "custody", "partial_preparation_custody", "uploaded_evidence"} & original.keys()
            and original.get("upload_verification", {}).get("state") != "intent"
            and creators | prior_withdrawals <= operations <= creators | prior_withdrawals | preparation
            and all(effect["state"] == "verified" for effect in original_effects.values()),
            "post-engine-cleanup-original-scope")
    effects = record["effects"]
    require(record | {"effects": original_effects} == original
            and all(effects.get(identifier) == effect for identifier, effect in original_effects.items()),
            "post-engine-cleanup-original-drift")
    expected = {(ledger.CREATES[effect["operation"]], effect["target"])
                for effect in original_effects.values() if effect["operation"] in creators}
    completed = [effect for identifier, effect in effects.items() if identifier not in original_effects]
    observed = {(effect["operation"], effect["target"]) for effect in completed}
    require(len(expected) == len(creators) and len(observed) == len(completed)
            and observed <= expected and (not complete or observed == expected)
            and all(effect["state"] == "verified" and effect["at"] >= original["native_terminal"]["completed_at"]
                    for effect in completed), "post-engine-cleanup-journal-held")
    if complete:
        store.require_cleanup_complete(lease_id)
    require(store.read(lease_id) == record, "post-engine-cleanup-journal-drift")

    receipt = {"schema": 1, "state": "awaiting-independent-absence", "lease_id": lease_id,
            "archive_sha256": archive_sha256, "original_sha256": ledger.digest(original),
            "journal_sha256": ledger.digest(record), "native_acceptance": False}
    if not complete:
        receipt.update(state="verified-cleanup-progress", cleanup_started=bool(completed))
    return receipt


def _post_engine_readback_path(store, lease_id):
    return _post_engine_control_path(store, lease_id).parent.parent / "post-engine-readbacks" / (lease_id + ".json")


def _read_post_engine_readback(store, lease_id, readback_sha256):
    path = _post_engine_readback_path(store, lease_id)
    _, raw, _ = installation._file(str(path), 65536, private=True, keep=True)
    value = identity.decode_json(raw)
    require(ledger.canonical(value) == raw and ledger.digest(value) == readback_sha256,
            "post-engine-readback-drift")
    return value


def _publish_post_engine_readback(store, lease_id, value):
    from . import engine_policy, generation_publisher

    path = _post_engine_readback_path(store, lease_id)
    if not os.path.lexists(path.parent):
        generation_publisher._mkdir(path.parent)
    digest = ledger.digest(value)
    if not os.path.lexists(path):
        _publish_record(path, value)
    directory = engine_policy._directory(str(path.parent), private=True)
    try:
        parent = installation._open_directory(str(path.parent.parent))
        try:
            os.fsync(directory)
            os.fsync(parent)
            require(_read_post_engine_readback(store, lease_id, digest) == value, "post-engine-readback-drift")
        finally:
            os.close(parent)
    finally:
        os.close(directory)
    return digest


def _publish_post_engine_archive(session, owner, store):
    """Seal the already-bound terminal result and private captures under the existing Root lock."""
    from . import cell_contract, engine_executor, engine_policy, generation_publisher, root_session

    config = root_session._require_session(session)
    require(type(owner) is cell_contract.OwnedCellForCleanup and owner.registry.path == config.registry_path
            and owner.registry.sha256 == config.registry_sha256, "post-engine-archive-owner")
    lease_id = owner.lease_id
    folder = _post_engine_archive_path(owner)
    record = store.read(lease_id)
    require(cell_contract.owned_cell_for_cleanup(owner.registry, owner.selector, store, lease_id) == owner,
            "post-engine-archive-owner-drift")
    start, documents, manifest = _post_engine_archive_inputs(lease_id, record)
    require(start["engine_exit"]["manifest_sha256"] == owner.engine_policy_sha256
            and record["native_terminal"]["observed_at"] <= store._now(), "post-engine-archive-exit-binding")
    binding = ledger.digest(manifest)
    with _post_engine_evidence_quota(config, folder.parent):
        parent = engine_policy._directory(str(folder.parent), private=True)
        try:
            if os.path.lexists(folder):
                os.fsync(parent)
            else:
                prefix = "." + folder.name + "."
                require(not any(name.startswith(prefix) for name in os.listdir(parent)),
                        "post-engine-archive-staging-held")
                _require_post_engine_archive_space(parent, manifest, start["engine_capture"]["total_limit"])
                runroot = identity.decode_json(owner.engine_descriptor_bytes)["engine"]["runroot"]
                with TemporaryDirectory(prefix=prefix, dir=folder.parent) as temporary:
                    staged = Path(temporary)
                    for name, raw in documents.items():
                        generation_publisher._write(staged / name, raw)
                    sources = {}
                    for stream in ("stdout", "stderr"):
                        proof, raw, stamp = engine_executor._bound_capture_file(runroot, start, stream, keep=True)
                        generation_publisher._write(staged / (stream + ".log"), raw)
                        sources[stream] = proof, None, stamp
                        del raw
                    generation_publisher._json(staged / "manifest.json", manifest)
                    _verify_post_engine_archive(staged, manifest, binding)
                    require(all(engine_executor._bound_capture_file(runroot, start, name) == proof
                                for name, proof in sources.items()) and store.read(lease_id) == record
                            and root_session._require_session(session) == config, "post-engine-archive-source-drift")
                    _publish_staged(staged, folder)
            receipt = _verify_post_engine_archive(folder, manifest, binding)
            require(store.read(lease_id) == record, "post-engine-archive-record-drift")
            return receipt
        finally:
            os.close(parent)


_POST_ENGINE_OBSERVATION_FIELDS = frozenset({
    "lease_id", "original_sha256", "terminal_sha256", "scope_sha256", "census_sha256",
    "policy_sha256", "image_effect_sha256", "default_image_sha256", "observed_at",
})


def _post_engine_permit_path(store, lease_id):
    archive = _post_engine_control_path(store, lease_id)
    return archive.with_name(lease_id + ".permit.json")


def _post_engine_opt_in(store, record, selector):
    policy = store.read_policy(record["policy_sha256"])
    ledger.Ledger._validate_policy(policy)
    require(ledger.digest(policy) == record["policy_sha256"]
            and policy.get("post_engine_failure_retirement") == {"schema": 1, "selector": selector},
            "post-engine-permit-policy")


def _decode_post_engine_permit(store, lease_id, raw, permit_sha256, archive):
    permit = identity.decode_json(raw)
    image_digests = {"image_effect_sha256", "default_image_sha256"}
    require(type(permit) is dict and permit.keys() == _POST_ENGINE_OBSERVATION_FIELDS | {"schema", "archive_sha256"}
            and type(permit["schema"]) is int and permit["schema"] == 1 and permit["lease_id"] == lease_id
            and type(permit["observed_at"]) is int and 0 < permit["observed_at"] <= store._now()
            and all(type(permit[key]) is str and ledger.HEX.fullmatch(permit[key])
                    for key in permit if key.endswith("_sha256") and key not in image_digests)
            and (all(permit[key] is None for key in image_digests)
                 or all(type(permit[key]) is str and ledger.HEX.fullmatch(permit[key]) for key in image_digests))
            and raw == ledger.canonical(permit) and ledger.digest(permit) == permit_sha256,
            "post-engine-permit-content")
    proof, original_raw, _ = installation._file(str(archive / "original.json"), MAX_ARCHIVE_MEMBER, private=True, keep=True)
    original = identity.decode_json(original_raw)
    _, _, manifest = _post_engine_archive_inputs(lease_id, original)
    _verify_post_engine_archive(archive, manifest, permit["archive_sha256"])
    policy = store.read_policy(original["policy_sha256"])
    marker = policy.get("post_engine_failure_retirement")
    require(type(marker) is dict, "post-engine-permit-policy")
    _post_engine_opt_in(store, original, marker.get("selector"))
    image = [row for row in original["effects"].values() if row["operation"] == "image-copy"]
    require(proof.sha256 == permit["original_sha256"] and original["policy_sha256"] == permit["policy_sha256"]
            and permit["terminal_sha256"] == ledger.digest(original["native_terminal"])
            and original["native_terminal"]["observed_at"] <= permit["observed_at"]
            and (len(image) == 1 and image[0]["state"] == "verified" and ledger.digest(image[0]) == permit["image_effect_sha256"]
                 or not image and permit["image_effect_sha256"] is None), "post-engine-permit-original-binding")
    return permit


def _read_post_engine_permit(store, lease_id, permit_sha256, archive):
    """Validate immutable evidence against its original snapshot, even after cleanup progress."""
    path = _post_engine_permit_path(store, lease_id)
    proof, raw, stamp = installation._file(str(path), 65536, private=True, keep=True)
    require(proof.sha256 == permit_sha256, "post-engine-permit-digest")
    result = _decode_post_engine_permit(store, lease_id, raw, permit_sha256, archive)
    require(installation._file(str(path), 65536, private=True, keep=True) == (proof, raw, stamp),
            "post-engine-permit-replaced")
    return result


def _locate_post_engine_permit(store, lease_id, archive):
    """Read only the canonical locator; invalid committed or incomplete publishes hold."""
    path = _post_engine_permit_path(store, lease_id)
    try:
        os.lstat(path.parent)
    except FileNotFoundError:
        return None
    from . import engine_policy

    parent = engine_policy._directory(str(path.parent), private=True)
    try:
        prefix = "." + path.name + "."
        require(not any(name.startswith(prefix) for name in os.listdir(parent)), "post-engine-permit-staging-held")
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            # The process might have stopped between committing the archive
            # and issuing the permit. Adopt only its exact immutable original.
            if not os.path.lexists(archive):
                return None
            manifest, _, _ = installation._file(str(archive / "manifest.json"), 65536, private=True)
            _read_post_engine_archive(store, lease_id, manifest.sha256, archive)
            return None
        proof, _, _ = installation._file(str(path), 65536, private=True)
        result = _read_post_engine_permit(store, lease_id, proof.sha256, archive)
        return result | {"permit_sha256": proof.sha256}
    finally:
        os.close(parent)


def _confirm_durable_post_engine_permit(store, lease_id, expected, archive):
    from . import engine_policy

    path = _post_engine_permit_path(store, lease_id)
    parent = engine_policy._directory(str(path.parent), private=True)
    try:
        os.fsync(parent)  # The preceding publication may have completed its rename only.
        require(_locate_post_engine_permit(store, lease_id, archive) == expected, "post-engine-permit-recovery-drift")
    finally:
        os.close(parent)
    return expected


def _require_post_engine_observation(permit, observation, now):
    """A first effect requires a fresh live census and the very same original journal."""
    require(type(observation) is dict and observation.keys() == _POST_ENGINE_OBSERVATION_FIELDS
            and type(now) is int and type(observation["observed_at"]) is int
            and permit["observed_at"] <= observation["observed_at"] <= now
            and now - observation["observed_at"] <= MAX_OBSERVATION_AGE
            and all(observation[key] == permit[key] for key in _POST_ENGINE_OBSERVATION_FIELDS - {"observed_at"}),
            "post-engine-permit-observation-drift")


def _publish_post_engine_permit(session, owner, store, observation):
    """Archive first within the original Root session, then seal the bound permit."""
    from . import generation_publisher

    record = store.read(owner.lease_id)
    _post_engine_opt_in(store, record, owner.selector)
    require(observation["original_sha256"] == ledger.digest(record)
            and observation["scope_sha256"] == ledger.digest(owner.incus), "post-engine-permit-original-drift")
    archive, archive_sha256 = _publish_post_engine_archive(session, owner, store)
    archive = Path(archive)
    permit = observation | {"schema": 1, "archive_sha256": archive_sha256}
    _require_post_engine_observation(permit, observation, store._now())
    permit_sha256 = ledger.digest(permit)
    _decode_post_engine_permit(store, owner.lease_id, ledger.canonical(permit), permit_sha256, archive)
    require(store.read(owner.lease_id) == record, "post-engine-permit-original-drift")
    path = _post_engine_permit_path(store, owner.lease_id)
    if not os.path.lexists(path.parent):
        generation_publisher._mkdir(path.parent)
    parent = installation._open_directory(str(path.parent.parent))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    _publish_record(path, permit)
    require(_read_post_engine_permit(store, owner.lease_id, permit_sha256, archive) == permit,
            "post-engine-permit-publish-drift")
    return permit | {"permit_sha256": permit_sha256}


def publish_readback(directory, receipt):
    _publish_record(Path(directory) / "verified-absent.json", receipt)


def readback_confirmed(directory, lease_id, record, evidence):
    path = directory + "/verified-absent.json"
    if not os.path.lexists(path):
        return False
    _, raw, _ = installation._file(path, 65536, private=True, keep=True)
    value = identity.decode_json(raw)
    require(type(value) is dict and set(value) == {"schema", "lease_id", "closed_record_sha256",
            "archive_sha256", "resources", "native_acceptance"}
            and type(value["schema"]) is int and value["schema"] == 1 and record["state"] == "closed"
            and value["lease_id"] == lease_id and value["closed_record_sha256"] == ledger.digest(record)
            and value["archive_sha256"] == evidence["archive_sha256"] and value["native_acceptance"] is False
            and raw == ledger.canonical(value), "startup-retirement-archived-readback-drift")
    return True
