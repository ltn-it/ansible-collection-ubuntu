"""Policy for a separate Root retirement after a proved pre-VM abort.

The cleanup journal and native proof reader call this policy after their own
fresh observations. The result does not grant a successful workload or change
any original ledger result.
"""

import os
from pathlib import Path, PurePosixPath

from . import identity, installation, ledger, policy_registry
from .identity import require


POLICY = "protected-pre-vm-journal-v1"
MAX_OBSERVATION_AGE = 120
FAILURES = frozenset({"failure", "startup_failure", "timed_out", "cancelled"})
ARCHIVE_MEMBERS = ("original", "terminal", "failure", "inventory")
MAX_ARCHIVE_MEMBER = 8 * 1024 * 1024
PRE_AUTHORITY_CREATORS = frozenset({"network-create", "project-create", "profile-configure"})
START_BOUNDARY = "root-journal-before-vm-authority"


def business_policy(original):
    """Keep the same custody terms and opt in only the separately sealed business policy."""
    ledger.Ledger._validate_policy(original)
    require("startup_retirement" not in original and original["retention_seconds"] == 14400,
            "startup-retirement-original-policy")
    return original | {"startup_retirement": POLICY}


def bootstrap_with_business_policy(bootstrap, original):
    """Prepare the prospective manifest before the publisher seals its new bank."""
    require(bootstrap["custody_policy_sha256"] == ledger.digest(original)
            and "business_startup_policy_sha256" not in bootstrap, "startup-retirement-bootstrap-binding")
    business = business_policy(original)
    return bootstrap | {"business_startup_policy_sha256": ledger.digest(business)}, business


def archive_bootstrap_policies(store, bootstrap, original):
    """Seal both policy rows in a fresh bank before publishing the bootstrap."""
    require(type(store) is ledger.Ledger and not store.lease_ids(), "startup-retirement-new-bank")
    base = bootstrap["custody_policy_sha256"]
    require(base == ledger.digest(original), "startup-retirement-bootstrap-binding")
    business = business_policy(original)
    selected = bootstrap.get("business_startup_policy_sha256")
    require(selected == ledger.digest(business), "startup-retirement-bootstrap-business-binding")
    require(store.archive_policy(original) == base and store.archive_policy(business) == selected,
            "startup-retirement-policy-archive")
    require(store.read_policy(base) == original and store.read_policy(selected) == business,
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
    require(contents["original"] == ledger.canonical(record)
            and contents["terminal"] == ledger.canonical(record["native_terminal"]),
            "startup-retirement-archived-original-drift")
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


def publish_original_archive(store, lease_id, record, failure, inventory):
    """Make the validated original archive durable before publishing its locator."""
    from . import generation_publisher

    terminal = record["native_terminal"]
    require(type(failure) is dict and set(failure) == {"schema", "native_terminal_sha256", "diagnostic"}
            and type(failure["schema"]) is int and failure["schema"] == 1
            and failure["native_terminal_sha256"] == ledger.digest(terminal)
            and type(failure["diagnostic"]) is str and bool(failure["diagnostic"].strip()),
            "startup-retirement-native-diagnostic")
    require(store.read(lease_id) == record, "startup-retirement-original-drift")
    folder = Path(store.path).parent / "startup-retirement" / lease_id
    if not os.path.lexists(folder.parent):
        generation_publisher._mkdir(folder.parent)
    generation_publisher._mkdir(folder)
    members = {"original": record, "terminal": terminal, "failure": failure, "inventory": inventory}
    hashes = {name: generation_publisher._json(folder / (name + ".json"), value) for name, value in members.items()}
    require(store.read(lease_id) == record, "startup-retirement-original-drift")
    binding = generation_publisher._json(folder / "manifest.json", hashes)
    require(archived_original(str(folder), binding, record) == hashes | {"sha256": binding},
            "startup-retirement-archive-readback")
    return str(folder), binding
