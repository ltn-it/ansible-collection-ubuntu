"""Pure closed operating-drill semantics, separate from business cells.

These checks never authenticate native JSON, establish image availability or
capacity, construct a PreparedCell, or authorize TLS/engine operations. Root
must acquire the native initial-Main commit and job identity independently.
"""
from dataclasses import dataclass
import base64
import hashlib
from pathlib import PurePosixPath
import re

from . import cell_contract, engine_policy, identity, ledger
from .identity import require

CASES = frozenset({"failure", "broker-cancel", "expiry-controller-loss"})
INITIAL_MAIN = "90e7216b5d085ca4ac6238e44dcdbaa51e847d5f"
IMAGE = "38a97063887ebedb3596275e498ee5da4bb0508c28f14d247118d6205fc8cc9c"
TARGET = "ubuntu-24.04"
CPU = 1
MEMORY = 2 * 1024**3
ROOT_DISK = 5 * 1024**3
STATE_DISK = 500 * 1024**2
TOTAL_DISK = 6 * 1024**3
IMAGE_RESERVATION = 4 * 1024**3
PROJECT_RESERVATION = 10 * 1024**3
ENV_KEYS = engine_policy.ENV_KEYS | {"QUALITY_OPERATING_CASE", "QUALITY_OPERATING_SPEC"}

BUSINESS_VM_PROFILES = {
    ("heavy", "keycloak-heavy"),
    ("application_acceptance", "keycloak-application-acceptance"),
}


def uses_cached_vm_image(environment):
    """Apply the Root-only local copy to the sealed image and approved VM cases."""
    profile = environment.get("QUALITY_INPUT_PROFILE")
    if profile == "operating":
        return True
    return ((profile, environment.get("QUALITY_INPUT_SCENARIO")) in BUSINESS_VM_PROFILES
            and environment.get("QUALITY_INPUT_TARGET") == TARGET
            and environment.get("QUALITY_INPUT_INSTANCE_TYPE") == "vm"
            and environment.get("QUALITY_INPUT_IMAGE") == IMAGE)


@dataclass(frozen=True)
class OperatingCell:
    case: str
    target: str
    image: str
    instance_name: str
    spec_bytes: bytes

    @property
    def spec(self):
        return identity.decode_json(self.spec_bytes)


def selector(case):
    require(type(case) is str and case in CASES, "operating-case")
    return "operating-" + case


def instance_name(case, run_id):
    selector(case)
    require(type(run_id) is int and 0 < run_id < 2**63, "operating-run")
    return cell_contract._bounded("g06-operating-" + case + "-" + str(run_id) + "-1-" + TARGET, 63)



def spec(case, image, run_id):
    selector(case)
    require(image == IMAGE, "operating-platform")
    return {"schema": 1, "kind": "operating", "case": case, "image": IMAGE,
        "instance_name": instance_name(case, run_id), "cpu": CPU, "memory_bytes": MEMORY,
        "root_disk_bytes": ROOT_DISK, "state_disk_bytes": STATE_DISK, "total_disk_bytes": TOTAL_DISK,
        "image_reservation_bytes": IMAGE_RESERVATION, "project_reservation_bytes": PROJECT_RESERVATION}


def validate_initial_main(commit_native, caller_sha):
    """Check only this closed ancestry predicate, not native/protected authority."""
    cell_contract._commit(caller_sha)
    require(caller_sha != INITIAL_MAIN and type(commit_native) is dict
            and commit_native.get("sha") == caller_sha, "operating-initial-commit")
    parents = commit_native.get("parents")
    require(type(parents) is list and 1 <= len(parents) <= 2
            and all(type(parent) is dict and type(parent.get("sha")) is str
                    and re.fullmatch("[0-9a-f]{40}", parent["sha"]) for parent in parents)
            and parents[0]["sha"] == INITIAL_MAIN and len({parent["sha"] for parent in parents}) == len(parents)
            and caller_sha not in {parent["sha"] for parent in parents}, "operating-initial-parent")


# One explicitly reviewed follow-up to the unconsumed first physical run.
# These public native identifiers preserve history; they are never retry flags.
ORIGIN_MAIN = "14e3abd5d1fa0cfad14d52ec83483b761de207f0"
ORIGIN_RUN = 43242971437
ORIGIN_REUSABLE = "f6966a9b537e97b2ef5cea68286d60fd7d1a0696"
ORIGIN_WORKFLOW = "756643c79c70411808c29d088e0725e88cde6a9016fbb84fa3d7e9064f1cb3cd"
ORIGIN_CLIENTS = {
    "incus_job_client.py": "0f43367cc87afcc38dbf61a7dfd08cffef6f5bd4ac3bae49f13229ecfa5f51c7",
    "incus_runtime_client.py": "c7aa04bea8ccb0ffdbdd75939622b37f65693b29bf34d69befb8e4a400076d78",
}


def continuation_origin():
    prefix = "Heavy matrix / central protected validation / "
    return {"repository": "ltn-it/ansible-collection-supplementary", "repository_id": 1103407173,
        "workflow_id": 214182490, "workflow_path": ".github/workflows/collection-ci.yml",
        "source_sha": ORIGIN_MAIN, "run_id": ORIGIN_RUN, "run_attempt": 1,
        "first_parent": INITIAL_MAIN, "source_workflow_sha256": ORIGIN_WORKFLOW,
        "reusable_sha": ORIGIN_REUSABLE, "jobs": [
            {"job_id": 131273279158, "check_run_id": 131273279158,
             "name": prefix + "heavy / keycloak-heavy / ubuntu-24.04",
             "started_at": "2026-11-12T17:12:13Z", "completed_at": "2026-11-12T17:12:19Z", "conclusion": "failure"},
            {"job_id": 131352835063, "check_run_id": 131352835063,
             "name": prefix + "Final quality / heavy / keycloak-heavy / ubuntu-24.04",
             "started_at": "2026-11-12T17:12:25Z", "completed_at": "2026-11-12T17:12:31Z", "conclusion": "failure"}]}


def validate_continuation_descriptor(value, workflow_sha256, reusable_sha):
    """Pure exact descriptor shape; Root file/native/absence proofs are separate."""
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 27:
        return _validate_twenty_seventh_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 26:
        return _validate_twenty_sixth_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 25:
        return _validate_twenty_fifth_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 24:
        return _validate_twenty_fourth_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 23:
        return _validate_closed_vm_descriptor(value, workflow_sha256, reusable_sha, native_cleanup=True)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 22:
        return _validate_closed_vm_descriptor(value, workflow_sha256, reusable_sha, native_cleanup=False)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 21:
        return _validate_twenty_first_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 20:
        return _validate_twentieth_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 19:
        return _validate_nineteenth_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 18:
        return _validate_eighteenth_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 17:
        return _validate_seventeenth_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 16:
        return _validate_sixteenth_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 15:
        return _validate_fifteenth_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 14:
        return _validate_fourteenth_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 13:
        return _validate_thirteenth_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 12:
        return _validate_twelfth_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 11:
        return _validate_eleventh_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 10:
        return _validate_tenth_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 9:
        return _validate_ninth_retired_partial_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 8:
        return _validate_eighth_prelease_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 7:
        return _validate_seventh_prelease_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 6:
        return _validate_sixth_preparation_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 5:
        return _validate_partial_preparation_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 4:
        return _validate_four_history_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 3:
        return _validate_three_history_descriptor(value, workflow_sha256, reusable_sha)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 2:
        return _validate_two_history_descriptor(value, workflow_sha256, reusable_sha)
    engine_policy._keys(value, {"schema", "reason", "origin", "qualification", "successor"})
    require(type(value["schema"]) is int and value["schema"] == 1
            and value["reason"] == "original-client-precheck-denied"
            and ledger.canonical(value["origin"]) == ledger.canonical(continuation_origin()), "continuation-origin")
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"]); engine_policy._hash(ref["sha256"])
    row = engine_policy._keys(value["successor"], {"source_sha", "run_id", "run_attempt", "first_parent",
                                                 "source_workflow_sha256", "reusable_sha"})
    cell_contract._commit(row["source_sha"])
    engine_policy._integer(row["run_id"], 1, 2**63 - 1)
    require(row["source_sha"] not in {INITIAL_MAIN, ORIGIN_MAIN} and row["run_id"] != ORIGIN_RUN
            and type(row["run_attempt"]) is int and row["run_attempt"] == 1
            and row["first_parent"] == ORIGIN_MAIN, "continuation-exact-successor")
    engine_policy._hash(row["source_workflow_sha256"]); cell_contract._commit(row["reusable_sha"])
    require(row["source_workflow_sha256"] == workflow_sha256 != ORIGIN_WORKFLOW
            and row["reusable_sha"] == reusable_sha != ORIGIN_REUSABLE, "continuation-successor-contract")
    return value


@identity._diagnostic_step("continuation-commit")
def validate_continuation_commit(commit_native, value, caller_sha, run_id, reusable_sha):
    """Exact new run/commit/first parent; this does not authenticate native JSON."""
    row = value["successor"]
    validate_continuation_descriptor(value, row["source_workflow_sha256"], reusable_sha)
    require(caller_sha == row["source_sha"] and type(run_id) is int and run_id == row["run_id"]
            and type(commit_native) is dict and commit_native.get("sha") == caller_sha,
            "continuation-exact-native-tuple")
    parents = commit_native.get("parents")
    predecessors = {1: ORIGIN_MAIN, 2: PRIOR_MAIN, 3: THIRD_MAIN, 4: FOURTH_MAIN, 5: FIFTH_MAIN,
                    6: SIXTH_MAIN, 7: SEVENTH_MAIN, 8: EIGHTH_MAIN, 9: NINTH_MAIN, 10: TENTH_MAIN,
                    11: ELEVENTH_MAIN, 12: TWELFTH_MAIN, 13: THIRTEENTH_MAIN, 14: FOURTEENTH_MAIN,
                    15: FIFTEENTH_MAIN, 16: SIXTEENTH_MAIN, 17: SEVENTEENTH_MAIN, 18: EIGHTEENTH_MAIN,
                    19: NINETEENTH_MAIN, 20: TWENTIETH_MAIN, 21: TWENTY_FIRST_MAIN, 22: TWENTY_SECOND_MAIN,
                    23: TWENTY_THIRD_MAIN, 24: TWENTY_FOURTH_MAIN, 25: TWENTY_FIFTH_MAIN, 26: TWENTY_SIXTH_MAIN,
                    27: TWENTY_SEVENTH_MAIN}
    require(type(parents) is list and 1 <= len(parents) <= 2
            and all(type(p) is dict and type(p.get("sha")) is str and re.fullmatch("[0-9a-f]{40}", p["sha"])
                    for p in parents) and parents[0]["sha"] == predecessors[value["schema"]]
            and len({p["sha"] for p in parents}) == len(parents)
            and caller_sha not in {p["sha"] for p in parents}, "continuation-first-parent")


def origin_native_projection(run, inventory, checks, commit):
    """Validate original terminal provider data, retaining complete native job inventory."""
    origin = continuation_origin()
    require(type(run) is dict and all(run.get(k) == v and type(run.get(k)) is type(v) for k, v in {
        "id": ORIGIN_RUN, "run_attempt": 1, "head_sha": ORIGIN_MAIN, "event": "push", "head_branch": "main",
        "workflow_id": 214182490, "status": "completed", "conclusion": "failure"}.items()), "continuation-original-run")
    for field in ("repository", "head_repository"):
        require(type(run.get(field)) is dict and run[field].get("id") == 1103407173, "continuation-original-repository")
    actor = {"login": "litroc", "id": 76040632, "type": "User"}
    require(all(type(run.get(field)) is dict and all(run[field].get(k) == v for k, v in actor.items())
                for field in ("actor", "triggering_actor")), "continuation-original-actor")
    refs = run.get("referenced_workflows")
    expected_ref = "ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@" + ORIGIN_REUSABLE
    require(type(refs) is list and any(type(item) is dict and item.get("path") == expected_ref
            and item.get("sha") == ORIGIN_REUSABLE for item in refs), "continuation-original-reusable")
    require(type(commit) is dict and commit.get("sha") == ORIGIN_MAIN, "continuation-original-commit")
    validate_initial_main(commit, ORIGIN_MAIN)
    require(type(inventory) is dict and type(inventory.get("total_count")) is int
            and inventory["total_count"] == 24 and type(inventory.get("jobs")) is list
            and len(inventory["jobs"]) == 24, "continuation-original-complete-inventory")
    rows, ids = [], set()
    for job in inventory["jobs"]:
        require(type(job) is dict and type(job.get("id")) is int and job["id"] > 0 and job["id"] not in ids
                and job.get("run_id") == ORIGIN_RUN and type(job.get("run_attempt")) is int
                and job["run_attempt"] == 1 and job.get("head_sha") == ORIGIN_MAIN
                and job.get("status") == "completed" and type(job.get("conclusion")) is str
                and type(job.get("name")) is str, "continuation-original-job-inventory")
        ids.add(job["id"])
        rows.append({k: job[k] for k in ("id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion")})
    require(type(checks) is list and len(checks) == 2, "continuation-original-checks")
    for expected, check in zip(origin["jobs"], checks):
        job = next((j for j in inventory["jobs"] if j["id"] == expected["job_id"]), None)
        require(job is not None and all(job.get(k) == expected[k] for k in ("name", "started_at", "completed_at", "conclusion"))
                and job.get("runner_id") == 78 and job.get("runner_group_id") == 8
                and job.get("check_run_url") == "https://api.github.com/repos/" + origin["repository"]
                    + "/check-runs/" + str(expected["check_run_id"]), "continuation-original-terminal-job")
        require(type(check) is dict and check.get("id") == expected["check_run_id"]
                and check.get("name") == expected["name"] and check.get("head_sha") == ORIGIN_MAIN
                and check.get("status") == "completed" and check.get("conclusion") == "failure"
                and check.get("started_at") == expected["started_at"] and check.get("completed_at") == expected["completed_at"]
                and type(check.get("app")) is dict and check["app"].get("id") == 15368
                and check["app"].get("slug") == "github-actions", "continuation-original-terminal-check")
    return {"origin": origin, "actor": actor, "jobs": sorted(rows, key=lambda row: row["id"])}


ORIGIN_NO_INTAKE = "6019bd8ca2ee3b2784ed90a9c759a7585170a8e385f259e1f4727b308355b568"


def validate_continuation_qualification(value):
    """Root-private historical evidence only, never current native authority."""
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 27:
        return _validate_twenty_seventh_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 26:
        return _validate_twenty_sixth_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 25:
        return _validate_twenty_fifth_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 24:
        return _validate_twenty_fourth_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 23:
        return _validate_twenty_third_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 22:
        return _validate_twenty_second_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 21:
        return _validate_twenty_first_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 20:
        return _validate_twentieth_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 19:
        return _validate_nineteenth_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 18:
        return _validate_eighteenth_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 17:
        return _validate_seventeenth_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 16:
        return _validate_sixteenth_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 15:
        return _validate_fifteenth_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 14:
        return _validate_fourteenth_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 13:
        return _validate_thirteenth_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 12:
        return _validate_twelfth_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 11:
        return _validate_eleventh_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 10:
        return _validate_tenth_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 9:
        return _validate_ninth_retired_partial_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 8:
        return _validate_eighth_prelease_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 7:
        return _validate_seventh_prelease_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 6:
        return _validate_sixth_preparation_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 5:
        return _validate_partial_preparation_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 4:
        return _validate_four_history_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 3:
        return _validate_three_history_qualification(value)
    if type(value) is dict and type(value.get("schema")) is int and value["schema"] == 2:
        return _validate_two_history_qualification(value)
    engine_policy._keys(value, {"schema", "purpose", "origin", "native_origin", "no_intake_receipt_b64", "old_public_clients"})
    require(type(value["schema"]) is int and value["schema"] == 1
            and value["purpose"] == "g06-original-client-precheck-no-intake"
            and ledger.canonical(value["origin"]) == ledger.canonical(continuation_origin())
            and value["old_public_clients"] == ORIGIN_CLIENTS, "continuation-qualification-domain")
    encoded = value["no_intake_receipt_b64"]
    require(type(encoded) is str and len(encoded) <= 16384, "continuation-no-intake-bound")
    raw = base64.b64decode(encoded, validate=True)
    require(hashlib.sha256(raw).hexdigest() == ORIGIN_NO_INTAKE, "continuation-original-no-intake-receipt")
    observed = identity.decode_json(raw)
    engine_policy._keys(observed, {"rc", "observed", "stderr_bytes"})
    require(type(observed["rc"]) is int and observed["rc"] == 0
            and type(observed["stderr_bytes"]) is int and observed["stderr_bytes"] == 0, "continuation-no-intake-native")
    row = engine_policy._keys(observed["observed"], {"schema", "state", "at", "original_run", "original_attempt",
        "original_head", "counts", "no_challenge_or_job_request", "no_state_reset_or_cleanup",
        "operator_raw_ledger_or_signing_key_read_export_or_hash", "product_store_validation_and_lease_ids_only"})
    require(type(row["schema"]) is int and row["schema"] == 1
            and row["state"] == "ACTUAL_EXISTING_PRODUCT_STORE_AND_CATALOGUES_EMPTY_NO_INTAKE_OR_LEASE"
            and type(row["original_run"]) is int and row["original_run"] == ORIGIN_RUN
            and type(row["original_attempt"]) is int and row["original_attempt"] == 1
            and row["original_head"] == ORIGIN_MAIN and type(row["at"]) in (int, float)
            and 1794503551 <= row["at"] < 2**63
            and row["no_challenge_or_job_request"] is True and row["no_state_reset_or_cleanup"] is True
            and row["operator_raw_ledger_or_signing_key_read_export_or_hash"] is False
            and row["product_store_validation_and_lease_ids_only"] is True, "continuation-no-intake-observation")
    counts = engine_policy._keys(row["counts"], {"native_intake_catalogue", "native_run_configuration_catalogue", "runtime_lease_count"})
    require(type(counts["runtime_lease_count"]) is int and counts["runtime_lease_count"] == 0, "continuation-original-leases")
    for name in ("native_intake_catalogue", "native_run_configuration_catalogue"):
        item = engine_policy._keys(counts[name], {"directory_device", "directory_inode", "entries"})
        require(all(type(item[k]) is int and item[k] > 0 for k in ("directory_device", "directory_inode"))
                and type(item["entries"]) is int and item["entries"] == 0, "continuation-original-catalogues")
    native = engine_policy._keys(value["native_origin"], {"origin", "actor", "jobs"})
    require(native["origin"] == continuation_origin() and native["actor"] == {"login": "litroc", "id": 76040632, "type": "User"}
            and type(native["jobs"]) is list and len(native["jobs"]) == 24, "continuation-qualified-native-origin")
    ids = set()
    for job in native["jobs"]:
        engine_policy._keys(job, {"id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion"})
        require(type(job["id"]) is int and job["id"] > 0 and job["id"] not in ids
                and type(job["run_id"]) is int and job["run_id"] == ORIGIN_RUN
                and type(job["run_attempt"]) is int and job["run_attempt"] == 1 and job["head_sha"] == ORIGIN_MAIN
                and job["status"] == "completed" and type(job["name"]) is str and type(job["conclusion"]) is str,
                "continuation-qualified-native-jobs")
        ids.add(job["id"])
    require(ids >= {item["job_id"] for item in continuation_origin()["jobs"]}, "continuation-original-jobs-missing")
    return counts


def continuation_qualification(run, inventory, checks, commit, no_intake_raw, old_public_clients):
    """Pure receipt producer; Root must authenticate and privately seal inputs."""
    require(type(no_intake_raw) is bytes and len(no_intake_raw) <= 12288, "continuation-no-intake-bound")
    value = {"schema": 1, "purpose": "g06-original-client-precheck-no-intake", "origin": continuation_origin(),
        "native_origin": origin_native_projection(run, inventory, checks, commit),
        "no_intake_receipt_b64": base64.b64encode(no_intake_raw).decode("ascii"),
        "old_public_clients": old_public_clients}
    validate_continuation_qualification(value)
    return value


# Closed second-history contract. These identifiers are historical evidence,
# never permission to replay either failed run or extend a running lease.
PRIOR_MAIN = "f27c1d4edff75377f285275cec9bfec6bc3081f6"
PRIOR_RUN = 43317193171
PRIOR_REUSABLE = "1d88e96e9dd6fb5ccdb052b3e76685e538bf5c66"
PRIOR_WORKFLOW = "92b6c14a01972f9dcf2cb15b5f9d07ac128803931c960e128e92b16142fbfb49"
PRIOR_CLIENTS = {
    "incus_job_client.py": "01d70ce938ede0e6a7f5cbb094650c9d6560b350bab37a4a3e9d261322ccfb9e",
    "incus_runtime_client.py": "80ecc1883318e488b3f9d919cce70aaa94dad3488333194c64141e7358d2f3d9",
}
LEGACY_QUALIFICATION = "3ff4bbd29b74d14a92bb2be7cfd03faa15d688ca9da7ea24a0f52bfc0f8220ea"
PRIOR_NO_WORK = "a89d08dfa2c9992026750e24998ef4ffdd4eb2794424c797a4ede10b347f56af"
TWO_HISTORY_REUSABLE = "c6d9445151c2e3e3312949f27eb624964a7b644d"
TWO_HISTORY_WORKFLOW = "c1f44472b712ad72df4b49c448bf0aba31ecb2234682f394d5f72b6cb7af16fe"


def continuation_prior_origin():
    """Fixed second failed native run, distinct from the immutable first origin."""
    prefix = "Heavy matrix / central protected validation / "
    return {"repository": "ltn-it/ansible-collection-supplementary", "repository_id": 1103407173,
        "workflow_id": 214182490, "workflow_path": ".github/workflows/collection-ci.yml",
        "source_sha": PRIOR_MAIN, "run_id": PRIOR_RUN, "run_attempt": 1,
        "first_parent": ORIGIN_MAIN, "source_workflow_sha256": PRIOR_WORKFLOW,
        "reusable_sha": PRIOR_REUSABLE, "jobs": [
            {"job_id": 131529364095, "check_run_id": 131529364095,
             "name": prefix + "heavy / keycloak-heavy / ubuntu-24.04",
             "started_at": "2026-11-12T22:14:27Z", "completed_at": "2026-11-12T22:14:38Z", "conclusion": "failure"},
            {"job_id": 131531244775, "check_run_id": 131531244775,
             "name": prefix + "Final quality / heavy / keycloak-heavy / ubuntu-24.04",
             "started_at": "2026-11-12T22:14:43Z", "completed_at": "2026-11-12T22:14:53Z", "conclusion": "failure"}]}


def _validate_two_history_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "origin", "prior", "qualification", "successor"})
    require(value["reason"] == "prior-initial-preauth-denied"
            and ledger.canonical(value["origin"]) == ledger.canonical(continuation_origin())
            and ledger.canonical(value["prior"]) == ledger.canonical(continuation_prior_origin()),
            "continuation-two-history-origin")
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"]); engine_policy._hash(ref["sha256"])
    row = engine_policy._keys(value["successor"], {"source_sha", "run_id", "run_attempt", "first_parent",
                                                 "source_workflow_sha256", "reusable_sha"})
    cell_contract._commit(row["source_sha"])
    engine_policy._integer(row["run_id"], 1, 2**63 - 1)
    require(row["source_sha"] not in {INITIAL_MAIN, ORIGIN_MAIN, PRIOR_MAIN}
            and row["run_id"] not in {ORIGIN_RUN, PRIOR_RUN}
            and type(row["run_attempt"]) is int and row["run_attempt"] == 1
            and row["first_parent"] == PRIOR_MAIN, "continuation-two-history-successor")
    require(row["source_workflow_sha256"] == workflow_sha256 == TWO_HISTORY_WORKFLOW
            and row["reusable_sha"] == reusable_sha == TWO_HISTORY_REUSABLE,
            "continuation-two-history-contract")
    return value


def prior_native_projection(run, inventory, checks, commit):
    """Validate prior terminal provider data, retaining complete native job inventory."""
    origin = continuation_prior_origin()
    require(type(run) is dict and all(run.get(k) == v and type(run.get(k)) is type(v) for k, v in {
        "id": PRIOR_RUN, "run_attempt": 1, "head_sha": PRIOR_MAIN, "event": "push", "head_branch": "main",
        "workflow_id": 214182490, "status": "completed", "conclusion": "failure"}.items()), "continuation-prior-run")
    for field in ("repository", "head_repository"):
        require(type(run.get(field)) is dict and run[field].get("id") == 1103407173, "continuation-prior-repository")
    actor = {"login": "litroc", "id": 76040632, "type": "User"}
    require(all(type(run.get(field)) is dict and all(run[field].get(k) == v for k, v in actor.items())
                for field in ("actor", "triggering_actor")), "continuation-prior-actor")
    refs = run.get("referenced_workflows")
    expected_ref = "ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@" + PRIOR_REUSABLE
    require(type(refs) is list and any(type(item) is dict and item.get("path") == expected_ref
            and item.get("sha") == PRIOR_REUSABLE for item in refs), "continuation-prior-reusable")
    require(type(commit) is dict and commit.get("sha") == PRIOR_MAIN, "continuation-prior-commit")
    parents = commit.get("parents")
    require(type(parents) is list and 1 <= len(parents) <= 2
            and all(type(p) is dict and type(p.get("sha")) is str
                    and re.fullmatch("[0-9a-f]{40}", p["sha"]) for p in parents)
            and parents[0]["sha"] == ORIGIN_MAIN
            and len({p["sha"] for p in parents}) == len(parents)
            and PRIOR_MAIN not in {p["sha"] for p in parents}, "continuation-prior-parent")
    require(type(inventory) is dict and type(inventory.get("total_count")) is int
            and inventory["total_count"] == 24 and type(inventory.get("jobs")) is list
            and len(inventory["jobs"]) == 24, "continuation-prior-complete-inventory")
    rows, ids = [], set()
    for job in inventory["jobs"]:
        require(type(job) is dict and type(job.get("id")) is int and job["id"] > 0 and job["id"] not in ids
                and job.get("run_id") == PRIOR_RUN and type(job.get("run_attempt")) is int
                and job["run_attempt"] == 1 and job.get("head_sha") == PRIOR_MAIN
                and job.get("status") == "completed" and type(job.get("conclusion")) is str
                and type(job.get("name")) is str, "continuation-prior-job-inventory")
        ids.add(job["id"])
        rows.append({k: job[k] for k in ("id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion")})
    require(type(checks) is list and len(checks) == 2, "continuation-prior-checks")
    for expected, check in zip(origin["jobs"], checks):
        job = next((j for j in inventory["jobs"] if j["id"] == expected["job_id"]), None)
        require(job is not None and all(job.get(k) == expected[k] for k in ("name", "started_at", "completed_at", "conclusion"))
                and job.get("runner_id") == 78 and job.get("runner_group_id") == 8
                and job.get("check_run_url") == "https://api.github.com/repos/" + origin["repository"]
                    + "/check-runs/" + str(expected["check_run_id"]), "continuation-prior-terminal-job")
        require(type(check) is dict and check.get("id") == expected["check_run_id"]
                and check.get("name") == expected["name"] and check.get("head_sha") == PRIOR_MAIN
                and check.get("status") == "completed" and check.get("conclusion") == "failure"
                and check.get("started_at") == expected["started_at"] and check.get("completed_at") == expected["completed_at"]
                and type(check.get("app")) is dict and check["app"].get("id") == 15368
                and check["app"].get("slug") == "github-actions", "continuation-prior-terminal-check")
    return {"origin": origin, "actor": actor, "jobs": sorted(rows, key=lambda row: row["id"])}



def _validate_two_history_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "legacy_qualification", "prior", "native_prior",
                               "no_work_receipt_b64", "prior_public_clients"})
    require(value["purpose"] == "g06-two-history-preauth-no-work"
            and ledger.canonical(value["prior"]) == ledger.canonical(continuation_prior_origin())
            and value["prior_public_clients"] == PRIOR_CLIENTS, "continuation-two-history-qualification")
    legacy = value["legacy_qualification"]
    require(type(legacy) is dict and type(legacy.get("schema")) is int and legacy["schema"] == 1
            and ledger.digest(legacy) == LEGACY_QUALIFICATION, "continuation-legacy-qualification-seal")
    counts = validate_continuation_qualification(legacy)
    encoded = value["no_work_receipt_b64"]
    require(type(encoded) is str and len(encoded) <= 16384, "continuation-prior-no-work-bound")
    raw = base64.b64decode(encoded, validate=True)
    require(hashlib.sha256(raw).hexdigest() == PRIOR_NO_WORK, "continuation-prior-no-work-seal")
    observed = engine_policy._keys(identity.decode_json(raw), {"rc", "observed", "stderr_bytes"})
    require(type(observed["rc"]) is int and observed["rc"] == 0
            and type(observed["stderr_bytes"]) is int and observed["stderr_bytes"] == 0,
            "continuation-prior-native-no-work")
    row = engine_policy._keys(observed["observed"], {"schema", "state", "at", "boot_id", "machine_id",
        "bootstrap_sha256", "current_core_sha256", "counts", "nonce_history_absence_claimed",
        "operator_raw_ledger_or_signing_key_read_export_or_hash", "prior_attempt", "prior_head",
        "prior_public_clients", "prior_run", "probe_sent_no_challenge_or_job_request",
        "product_store_validation_and_lease_ids_only", "test_state_reset_or_cleanup_performed"})
    require(type(row["schema"]) is int and row["schema"] == 1
            and row["state"] == "ACTUAL_PRIOR_F27_PRODUCT_STORE_AND_CATALOGUES_EMPTY_NO_LEASE"
            and type(row["at"]) in (int, float) and 1794524418 <= row["at"] < 2**63
            and type(row["prior_run"]) is int and row["prior_run"] == PRIOR_RUN
            and type(row["prior_attempt"]) is int and row["prior_attempt"] == 1
            and row["prior_head"] == PRIOR_MAIN and row["prior_public_clients"] == PRIOR_CLIENTS
            and row["nonce_history_absence_claimed"] is False
            and row["operator_raw_ledger_or_signing_key_read_export_or_hash"] is False
            and row["probe_sent_no_challenge_or_job_request"] is True
            and row["product_store_validation_and_lease_ids_only"] is True
            and row["test_state_reset_or_cleanup_performed"] is False,
            "continuation-prior-no-work-observation")
    require(ledger.canonical(row["counts"]) == ledger.canonical(counts), "continuation-same-empty-catalogues")
    native = engine_policy._keys(value["native_prior"], {"origin", "actor", "jobs"})
    require(ledger.canonical(native["origin"]) == ledger.canonical(continuation_prior_origin())
            and native["actor"] == {"login": "litroc", "id": 76040632, "type": "User"}
            and type(native["jobs"]) is list and len(native["jobs"]) == 24, "continuation-qualified-native-prior")
    ids = set()
    expected = {job["job_id"]: job for job in continuation_prior_origin()["jobs"]}
    for job in native["jobs"]:
        engine_policy._keys(job, {"id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion"})
        require(type(job["id"]) is int and job["id"] > 0 and job["id"] not in ids
                and type(job["run_id"]) is int and job["run_id"] == PRIOR_RUN
                and type(job["run_attempt"]) is int and job["run_attempt"] == 1 and job["head_sha"] == PRIOR_MAIN
                and job["status"] == "completed" and type(job["name"]) is str and type(job["conclusion"]) is str,
                "continuation-qualified-prior-jobs")
        if job["id"] in expected:
            require(job["name"] == expected[job["id"]]["name"] and job["conclusion"] == "failure",
                    "continuation-qualified-prior-physical-job")
        ids.add(job["id"])
    require(ids >= expected.keys(), "continuation-prior-jobs-missing")
    return counts


def two_history_continuation_qualification(legacy_qualification, run, inventory, checks, commit,
                                         no_work_raw, prior_public_clients):
    """Pure receipt assembly, not authentication, private sealing or permission."""
    require(type(no_work_raw) is bytes and len(no_work_raw) <= 12288, "continuation-prior-no-work-bound")
    value = {"schema": 2, "purpose": "g06-two-history-preauth-no-work",
        "legacy_qualification": legacy_qualification, "prior": continuation_prior_origin(),
        "native_prior": prior_native_projection(run, inventory, checks, commit),
        "no_work_receipt_b64": base64.b64encode(no_work_raw).decode("ascii"),
        "prior_public_clients": prior_public_clients}
    validate_continuation_qualification(value)
    return value


# Exactly one bounded successor preserving all three original failed deliveries.
# These fixed identifiers never authorize a rerun, dispatch or nonce reset.
THIRD_MAIN = "3d84e26d90cc778fb8c4f462ce481584da57fb5a"
THIRD_RUN = 43351436938
THIRD_REUSABLE = TWO_HISTORY_REUSABLE
THIRD_WORKFLOW = TWO_HISTORY_WORKFLOW
THIRD_CLIENTS = {
    "incus_job_client.py": "01d70ce938ede0e6a7f5cbb094650c9d6560b350bab37a4a3e9d261322ccfb9e",
    "incus_runtime_client.py": "260a190c57ca146ab335ec93aa4e29dd3563003daa85e6b0773a063ed2013346",
}
TWO_HISTORY_QUALIFICATION = "99c1d6fe8b2ac39376af4bf558364b1452c66a0e8990783a4f8e214c330d5deb"
# Authenticated Root typed observation; its hash preserves evidence, not authority.
THIRD_NO_WORK = "c0a2c14336fe263bdebe43352455afb362a1f2f0f09d6b618503e865cfef349c"
THREE_HISTORY_WORKFLOW = "af6adf27e2be7551ff1c12090d06e6ff987cb8a8c456f0d308b84d08567eabe4"
THREE_HISTORY_REUSABLE = TWO_HISTORY_REUSABLE


def continuation_third_origin():
    """Fixed third failed native run, distinct from both earlier origins."""
    prefix = "Heavy matrix / central protected validation / "
    return {"repository": "ltn-it/ansible-collection-supplementary", "repository_id": 1103407173,
        "workflow_id": 214182490, "workflow_path": ".github/workflows/collection-ci.yml",
        "source_sha": THIRD_MAIN, "run_id": THIRD_RUN, "run_attempt": 1,
        "first_parent": PRIOR_MAIN, "source_workflow_sha256": THIRD_WORKFLOW,
        "reusable_sha": THIRD_REUSABLE, "jobs": [
            {"job_id": 131644158626, "check_run_id": 131644158626,
             "name": prefix + "heavy / keycloak-heavy / ubuntu-24.04",
             "started_at": "2026-11-13T02:23:25Z", "completed_at": "2026-11-13T02:24:37Z", "conclusion": "failure"},
            {"job_id": 131644930593, "check_run_id": 131644930593,
             "name": prefix + "Final quality / heavy / keycloak-heavy / ubuntu-24.04",
             "started_at": "2026-11-13T02:24:41Z", "completed_at": "2026-11-13T02:25:26Z", "conclusion": "failure"}]}


def third_native_projection(run, inventory, checks, commit):
    """Validate third terminal provider data, retaining complete native job inventory."""
    origin = continuation_third_origin()
    require(type(run) is dict and all(run.get(k) == v and type(run.get(k)) is type(v) for k, v in {
        "id": THIRD_RUN, "run_attempt": 1, "head_sha": THIRD_MAIN, "event": "push", "head_branch": "main",
        "workflow_id": 214182490, "status": "completed", "conclusion": "failure"}.items()), "continuation-third-run")
    for field in ("repository", "head_repository"):
        require(type(run.get(field)) is dict and run[field].get("id") == 1103407173, "continuation-third-repository")
    actor = {"login": "litroc", "id": 76040632, "type": "User"}
    require(all(type(run.get(field)) is dict and all(run[field].get(k) == v for k, v in actor.items())
                for field in ("actor", "triggering_actor")), "continuation-third-actor")
    refs = run.get("referenced_workflows")
    expected_ref = "ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@" + THIRD_REUSABLE
    require(type(refs) is list and any(type(item) is dict and item.get("path") == expected_ref
            and item.get("sha") == THIRD_REUSABLE for item in refs), "continuation-third-reusable")
    require(type(commit) is dict and commit.get("sha") == THIRD_MAIN, "continuation-third-commit")
    parents = commit.get("parents")
    require(type(parents) is list and 1 <= len(parents) <= 2
            and all(type(p) is dict and type(p.get("sha")) is str
                    and re.fullmatch("[0-9a-f]{40}", p["sha"]) for p in parents)
            and parents[0]["sha"] == PRIOR_MAIN
            and len({p["sha"] for p in parents}) == len(parents)
            and THIRD_MAIN not in {p["sha"] for p in parents}, "continuation-third-parent")
    require(type(inventory) is dict and type(inventory.get("total_count")) is int
            and inventory["total_count"] == 24 and type(inventory.get("jobs")) is list
            and len(inventory["jobs"]) == 24, "continuation-third-complete-inventory")
    rows, ids = [], set()
    for job in inventory["jobs"]:
        require(type(job) is dict and type(job.get("id")) is int and job["id"] > 0 and job["id"] not in ids
                and job.get("run_id") == THIRD_RUN and type(job.get("run_attempt")) is int
                and job["run_attempt"] == 1 and job.get("head_sha") == THIRD_MAIN
                and job.get("status") == "completed" and type(job.get("conclusion")) is str
                and type(job.get("name")) is str, "continuation-third-job-inventory")
        ids.add(job["id"])
        rows.append({k: job[k] for k in ("id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion")})
    require(type(checks) is list and len(checks) == 2, "continuation-third-checks")
    for expected, check in zip(origin["jobs"], checks):
        job = next((j for j in inventory["jobs"] if j["id"] == expected["job_id"]), None)
        require(job is not None and all(job.get(k) == expected[k] for k in ("name", "started_at", "completed_at", "conclusion"))
                and job.get("runner_id") == 78 and job.get("runner_group_id") == 8
                and job.get("check_run_url") == "https://api.github.com/repos/" + origin["repository"]
                    + "/check-runs/" + str(expected["check_run_id"]), "continuation-third-terminal-job")
        require(type(check) is dict and check.get("id") == expected["check_run_id"]
                and check.get("name") == expected["name"] and check.get("head_sha") == THIRD_MAIN
                and check.get("status") == "completed" and check.get("conclusion") == "failure"
                and check.get("started_at") == expected["started_at"] and check.get("completed_at") == expected["completed_at"]
                and type(check.get("app")) is dict and check["app"].get("id") == 15368
                and check["app"].get("slug") == "github-actions", "continuation-third-terminal-check")
    return {"origin": origin, "actor": actor, "jobs": sorted(rows, key=lambda row: row["id"])}



def _validate_three_history_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "origin", "prior", "third", "qualification", "successor"})
    require(value["reason"] == "third-runtime-failed-no-work-observed"
            and ledger.canonical(value["origin"]) == ledger.canonical(continuation_origin())
            and ledger.canonical(value["prior"]) == ledger.canonical(continuation_prior_origin())
            and ledger.canonical(value["third"]) == ledger.canonical(continuation_third_origin()),
            "continuation-three-history-origin")
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"]); engine_policy._hash(ref["sha256"])
    row = engine_policy._keys(value["successor"], {"source_sha", "run_id", "run_attempt", "first_parent",
                                                 "source_workflow_sha256", "reusable_sha"})
    cell_contract._commit(row["source_sha"])
    engine_policy._integer(row["run_id"], 1, 2**63 - 1)
    require(row["source_sha"] not in {INITIAL_MAIN, ORIGIN_MAIN, PRIOR_MAIN, THIRD_MAIN}
            and row["run_id"] not in {ORIGIN_RUN, PRIOR_RUN, THIRD_RUN}
            and type(row["run_attempt"]) is int and row["run_attempt"] == 1
            and row["first_parent"] == THIRD_MAIN, "continuation-three-history-successor")
    require(row["source_workflow_sha256"] == workflow_sha256 == THREE_HISTORY_WORKFLOW
            and row["reusable_sha"] == reusable_sha == THREE_HISTORY_REUSABLE,
            "continuation-three-history-contract")
    return value


def _validate_three_history_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "previous_qualification", "third", "native_third",
                               "no_work_receipt_b64", "third_public_clients"})
    require(value["purpose"] == "g06-three-history-runtime-failure-no-work"
            and ledger.canonical(value["third"]) == ledger.canonical(continuation_third_origin())
            and value["third_public_clients"] == THIRD_CLIENTS, "continuation-three-history-qualification")
    previous = value["previous_qualification"]
    require(type(previous) is dict and type(previous.get("schema")) is int and previous["schema"] == 2
            and ledger.digest(previous) == TWO_HISTORY_QUALIFICATION, "continuation-two-history-seal")
    counts = validate_continuation_qualification(previous)
    encoded = value["no_work_receipt_b64"]
    require(type(encoded) is str and len(encoded) <= 16384, "continuation-third-no-work-bound")
    raw = base64.b64decode(encoded, validate=True)
    require(type(THIRD_NO_WORK) is str and hashlib.sha256(raw).hexdigest() == THIRD_NO_WORK,
            "continuation-third-no-work-seal")
    observed = engine_policy._keys(identity.decode_json(raw), {"rc", "observed", "stderr_bytes"})
    require(type(observed["rc"]) is int and observed["rc"] == 0
            and type(observed["stderr_bytes"]) is int and observed["stderr_bytes"] == 0,
            "continuation-third-native-no-work")
    row = engine_policy._keys(observed["observed"], {"schema", "state", "at", "boot_id", "machine_id",
        "bootstrap_sha256", "current_core_sha256", "counts", "nonce_history_absence_claimed",
        "operator_raw_ledger_or_signing_key_read_export_or_hash", "third_attempt", "third_head",
        "third_public_clients", "third_run", "probe_sent_no_challenge_or_job_request",
        "product_store_validation_and_lease_ids_only", "test_state_reset_or_cleanup_performed"})
    require(type(row["schema"]) is int and row["schema"] == 1
            and row["state"] == "ACTUAL_THIRD_3D84_PRODUCT_STORE_AND_CATALOGUES_EMPTY_NO_LEASE"
            and type(row["at"]) in (int, float) and 1794537761 <= row["at"] < 2**63
            and type(row["third_run"]) is int and row["third_run"] == THIRD_RUN
            and type(row["third_attempt"]) is int and row["third_attempt"] == 1
            and row["third_head"] == THIRD_MAIN and row["third_public_clients"] == THIRD_CLIENTS
            and row["nonce_history_absence_claimed"] is False
            and row["operator_raw_ledger_or_signing_key_read_export_or_hash"] is False
            and row["probe_sent_no_challenge_or_job_request"] is True
            and row["product_store_validation_and_lease_ids_only"] is True
            and row["test_state_reset_or_cleanup_performed"] is False, "continuation-third-no-work-observation")
    require(ledger.canonical(row["counts"]) == ledger.canonical(counts), "continuation-same-empty-catalogues")
    native = engine_policy._keys(value["native_third"], {"origin", "actor", "jobs"})
    require(ledger.canonical(native["origin"]) == ledger.canonical(continuation_third_origin())
            and native["actor"] == {"login": "litroc", "id": 76040632, "type": "User"}
            and type(native["jobs"]) is list and len(native["jobs"]) == 24, "continuation-qualified-native-third")
    ids = set()
    expected = {job["job_id"]: job for job in continuation_third_origin()["jobs"]}
    for job in native["jobs"]:
        engine_policy._keys(job, {"id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion"})
        require(type(job["id"]) is int and job["id"] > 0 and job["id"] not in ids
                and type(job["run_id"]) is int and job["run_id"] == THIRD_RUN
                and type(job["run_attempt"]) is int and job["run_attempt"] == 1 and job["head_sha"] == THIRD_MAIN
                and job["status"] == "completed" and type(job["name"]) is str and type(job["conclusion"]) is str,
                "continuation-qualified-third-jobs")
        if job["id"] in expected:
            require(job["name"] == expected[job["id"]]["name"] and job["conclusion"] == "failure",
                    "continuation-qualified-third-physical-job")
        ids.add(job["id"])
    require(ids >= expected.keys(), "continuation-third-jobs-missing")
    return counts


def three_history_continuation_qualification(previous_qualification, run, inventory, checks, commit,
                                           no_work_raw, third_public_clients):
    """Pure fixed-three assembly; Root sealing and live native proofs remain mandatory."""
    require(type(no_work_raw) is bytes and len(no_work_raw) <= 12288, "continuation-third-no-work-bound")
    value = {"schema": 3, "purpose": "g06-three-history-runtime-failure-no-work",
        "previous_qualification": previous_qualification, "third": continuation_third_origin(),
        "native_third": third_native_projection(run, inventory, checks, commit),
        "no_work_receipt_b64": base64.b64encode(no_work_raw).decode("ascii"),
        "third_public_clients": third_public_clients}
    validate_continuation_qualification(value)
    return value

# One finite successor of the fourth failed native attempt; never a rerun grant.
FOURTH_MAIN = "f138a227d9eee41ea698b1a6f3b9a05f7ae3e18d"
FOURTH_RUN = 43375902417
FOURTH_REUSABLE = THREE_HISTORY_REUSABLE
FOURTH_WORKFLOW = THREE_HISTORY_WORKFLOW
FOURTH_CLIENTS = {
    "incus_job_client.py": "01d70ce938ede0e6a7f5cbb094650c9d6560b350bab37a4a3e9d261322ccfb9e",
    "incus_runtime_client.py": "260a190c57ca146ab335ec93aa4e29dd3563003daa85e6b0773a063ed2013346",
}
THREE_HISTORY_QUALIFICATION = "48d37b9551f8531c91605c151c1597808e7156a242db52f32f4913a909d49e6c"
FOURTH_NO_WORK = "57b2628ef03e87777b93bc66a1874b2c8d868de61d5b7058eea7332a0806b2eb"
FOURTH_RAW_SDK_RECEIPT = "e224135c9699b0bdb6a04cdeb0bcb6a6b6bd6e93d7300c6e3b2703f2139f3086"
FOUR_HISTORY_WORKFLOW = "c11d85264a1e492e1a16b76f78f54309584f649cdfdf64f6a335b38b80966e73"
FOUR_HISTORY_REUSABLE = "a94f4234ee6d14308e341d1c9d0d9ce9d2277e3a"


def continuation_fourth_origin():
    """Fixed fourth failed native run, preserving each of the three earlier histories."""
    prefix = "Heavy matrix / central protected validation / "
    return {"repository": "ltn-it/ansible-collection-supplementary", "repository_id": 1103407173,
        "workflow_id": 214182490, "workflow_path": ".github/workflows/collection-ci.yml",
        "source_sha": FOURTH_MAIN, "run_id": FOURTH_RUN, "run_attempt": 1,
        "first_parent": THIRD_MAIN, "source_workflow_sha256": FOURTH_WORKFLOW,
        "reusable_sha": FOURTH_REUSABLE, "jobs": [
            {"job_id": 131724534486, "check_run_id": 131724534486,
             "name": prefix + "heavy / keycloak-heavy / ubuntu-24.04",
             "started_at": "2026-11-13T11:41:29Z", "completed_at": "2026-11-13T11:42:32Z", "conclusion": "failure"},
            {"job_id": 131864664599, "check_run_id": 131864664599,
             "name": prefix + "Final quality / heavy / keycloak-heavy / ubuntu-24.04",
             "started_at": "2026-11-13T11:42:36Z", "completed_at": "2026-11-13T11:43:16Z", "conclusion": "failure"}]}


def fourth_native_projection(run, inventory, checks, commit):
    """Validate fourth terminal provider data, retaining complete native job inventory."""
    origin = continuation_fourth_origin()
    require(type(run) is dict and all(run.get(k) == v and type(run.get(k)) is type(v) for k, v in {
        "id": FOURTH_RUN, "run_attempt": 1, "head_sha": FOURTH_MAIN, "event": "push", "head_branch": "main",
        "workflow_id": 214182490, "status": "completed", "conclusion": "failure"}.items()), "continuation-fourth-run")
    for field in ("repository", "head_repository"):
        require(type(run.get(field)) is dict and run[field].get("id") == 1103407173, "continuation-fourth-repository")
    actor = {"login": "litroc", "id": 76040632, "type": "User"}
    require(all(type(run.get(field)) is dict and all(run[field].get(k) == v for k, v in actor.items())
                for field in ("actor", "triggering_actor")), "continuation-fourth-actor")
    refs = run.get("referenced_workflows")
    expected_ref = "ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@" + FOURTH_REUSABLE
    require(type(refs) is list and any(type(item) is dict and item.get("path") == expected_ref
            and item.get("sha") == FOURTH_REUSABLE for item in refs), "continuation-fourth-reusable")
    require(type(commit) is dict and commit.get("sha") == FOURTH_MAIN, "continuation-fourth-commit")
    parents = commit.get("parents")
    require(type(parents) is list and 1 <= len(parents) <= 2
            and all(type(p) is dict and type(p.get("sha")) is str
                    and re.fullmatch("[0-9a-f]{40}", p["sha"]) for p in parents)
            and parents[0]["sha"] == THIRD_MAIN
            and len({p["sha"] for p in parents}) == len(parents)
            and FOURTH_MAIN not in {p["sha"] for p in parents}, "continuation-fourth-parent")
    require(type(inventory) is dict and type(inventory.get("total_count")) is int
            and inventory["total_count"] == 24 and type(inventory.get("jobs")) is list
            and len(inventory["jobs"]) == 24, "continuation-fourth-complete-inventory")
    rows, ids = [], set()
    for job in inventory["jobs"]:
        require(type(job) is dict and type(job.get("id")) is int and job["id"] > 0 and job["id"] not in ids
                and job.get("run_id") == FOURTH_RUN and type(job.get("run_attempt")) is int
                and job["run_attempt"] == 1 and job.get("head_sha") == FOURTH_MAIN
                and job.get("status") == "completed" and type(job.get("conclusion")) is str
                and type(job.get("name")) is str, "continuation-fourth-job-inventory")
        ids.add(job["id"])
        rows.append({k: job[k] for k in ("id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion")})
    require(type(checks) is list and len(checks) == 2, "continuation-fourth-checks")
    for expected, check in zip(origin["jobs"], checks):
        job = next((j for j in inventory["jobs"] if j["id"] == expected["job_id"]), None)
        require(job is not None and all(job.get(k) == expected[k] for k in ("name", "started_at", "completed_at", "conclusion"))
                and job.get("runner_id") == 78 and job.get("runner_group_id") == 8
                and job.get("check_run_url") == "https://api.github.com/repos/" + origin["repository"]
                    + "/check-runs/" + str(expected["check_run_id"]), "continuation-fourth-terminal-job")
        require(type(check) is dict and check.get("id") == expected["check_run_id"]
                and check.get("name") == expected["name"] and check.get("head_sha") == FOURTH_MAIN
                and check.get("status") == "completed" and check.get("conclusion") == "failure"
                and check.get("started_at") == expected["started_at"] and check.get("completed_at") == expected["completed_at"]
                and type(check.get("app")) is dict and check["app"].get("id") == 15368
                and check["app"].get("slug") == "github-actions", "continuation-fourth-terminal-check")
    return {"origin": origin, "actor": actor, "jobs": sorted(rows, key=lambda row: row["id"])}



def _validate_four_history_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "origin", "prior", "third", "fourth", "qualification", "successor"})
    require(value["reason"] == "fourth-runtime-failed-no-work-observed"
            and ledger.canonical(value["origin"]) == ledger.canonical(continuation_origin())
            and ledger.canonical(value["prior"]) == ledger.canonical(continuation_prior_origin())
            and ledger.canonical(value["third"]) == ledger.canonical(continuation_third_origin())
            and ledger.canonical(value["fourth"]) == ledger.canonical(continuation_fourth_origin()),
            "continuation-four-history-origin")
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"]); engine_policy._hash(ref["sha256"])
    row = engine_policy._keys(value["successor"], {"source_sha", "run_id", "run_attempt", "first_parent",
                                                 "source_workflow_sha256", "reusable_sha"})
    cell_contract._commit(row["source_sha"])
    engine_policy._integer(row["run_id"], 1, 2**63 - 1)
    require(row["source_sha"] not in {INITIAL_MAIN, ORIGIN_MAIN, PRIOR_MAIN, THIRD_MAIN, FOURTH_MAIN}
            and row["run_id"] not in {ORIGIN_RUN, PRIOR_RUN, THIRD_RUN, FOURTH_RUN}
            and type(row["run_attempt"]) is int and row["run_attempt"] == 1
            and row["first_parent"] == FOURTH_MAIN, "continuation-four-history-successor")
    require(row["source_workflow_sha256"] == workflow_sha256 == FOUR_HISTORY_WORKFLOW
            and row["reusable_sha"] == reusable_sha == FOUR_HISTORY_REUSABLE,
            "continuation-four-history-contract")
    return value


def _validate_four_history_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "previous_qualification", "fourth", "native_fourth",
                               "no_work_receipt_b64", "fourth_public_clients"})
    require(value["purpose"] == "g06-four-history-runtime-failure-no-work"
            and ledger.canonical(value["fourth"]) == ledger.canonical(continuation_fourth_origin())
            and value["fourth_public_clients"] == FOURTH_CLIENTS, "continuation-four-history-qualification")
    previous = value["previous_qualification"]
    require(type(previous) is dict and type(previous.get("schema")) is int and previous["schema"] == 3
            and ledger.digest(previous) == THREE_HISTORY_QUALIFICATION, "continuation-three-history-seal")
    counts = validate_continuation_qualification(previous)
    encoded = value["no_work_receipt_b64"]
    require(type(encoded) is str and len(encoded) <= 16384, "continuation-fourth-no-work-bound")
    raw = base64.b64decode(encoded, validate=True)
    require(type(FOURTH_NO_WORK) is str and hashlib.sha256(raw).hexdigest() == FOURTH_NO_WORK,
            "continuation-fourth-no-work-seal")
    observed = engine_policy._keys(identity.decode_json(raw), {"rc", "observed", "stderr_bytes"})
    require(type(observed["rc"]) is int and observed["rc"] == 0
            and type(observed["stderr_bytes"]) is int and observed["stderr_bytes"] == 0,
            "continuation-fourth-native-no-work")
    row = engine_policy._keys(observed["observed"], {"schema", "state", "at", "boot_id", "machine_id",
        "bootstrap_sha256", "current_core_sha256", "counts", "nonce_history_absence_claimed",
        "operator_raw_ledger_or_signing_key_read_export_or_hash", "fourth_attempt", "fourth_head",
        "fourth_public_clients", "fourth_run", "probe_sent_no_challenge_or_job_request",
        "product_store_validation_and_lease_ids_only", "test_state_reset_or_cleanup_performed", "raw_sdk_receipt_sha256"})
    require(type(row["schema"]) is int and row["schema"] == 1
            and row["state"] == "ACTUAL_FOURTH_F138_PRODUCT_STORE_AND_CATALOGUES_EMPTY_NO_LEASE"
            and type(row["at"]) in (int, float) and 1794537761 <= row["at"] < 2**63
            and type(row["fourth_run"]) is int and row["fourth_run"] == FOURTH_RUN
            and type(row["fourth_attempt"]) is int and row["fourth_attempt"] == 1
            and row["fourth_head"] == FOURTH_MAIN and row["fourth_public_clients"] == FOURTH_CLIENTS
            and row["nonce_history_absence_claimed"] is False
            and row["operator_raw_ledger_or_signing_key_read_export_or_hash"] is False
            and row["probe_sent_no_challenge_or_job_request"] is True
            and row["product_store_validation_and_lease_ids_only"] is True
            and row["test_state_reset_or_cleanup_performed"] is False
            and row["raw_sdk_receipt_sha256"] == FOURTH_RAW_SDK_RECEIPT, "continuation-fourth-no-work-observation")
    require(ledger.canonical(row["counts"]) == ledger.canonical(counts), "continuation-same-empty-catalogues")
    native = engine_policy._keys(value["native_fourth"], {"origin", "actor", "jobs"})
    require(ledger.canonical(native["origin"]) == ledger.canonical(continuation_fourth_origin())
            and native["actor"] == {"login": "litroc", "id": 76040632, "type": "User"}
            and type(native["jobs"]) is list and len(native["jobs"]) == 24, "continuation-qualified-native-fourth")
    ids = set()
    expected = {job["job_id"]: job for job in continuation_fourth_origin()["jobs"]}
    for job in native["jobs"]:
        engine_policy._keys(job, {"id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion"})
        require(type(job["id"]) is int and job["id"] > 0 and job["id"] not in ids
                and type(job["run_id"]) is int and job["run_id"] == FOURTH_RUN
                and type(job["run_attempt"]) is int and job["run_attempt"] == 1 and job["head_sha"] == FOURTH_MAIN
                and job["status"] == "completed" and type(job["name"]) is str and type(job["conclusion"]) is str,
                "continuation-qualified-fourth-jobs")
        if job["id"] in expected:
            require(job["name"] == expected[job["id"]]["name"] and job["conclusion"] == "failure",
                    "continuation-qualified-fourth-physical-job")
        ids.add(job["id"])
    require(ids >= expected.keys(), "continuation-fourth-jobs-missing")
    return counts


def four_history_continuation_qualification(previous_qualification, run, inventory, checks, commit,
                                           no_work_raw, fourth_public_clients):
    """Pure fixed-four assembly; Root sealing and live native proofs remain mandatory."""
    require(type(no_work_raw) is bytes and len(no_work_raw) <= 12288, "continuation-fourth-no-work-bound")
    value = {"schema": 4, "purpose": "g06-four-history-runtime-failure-no-work",
        "previous_qualification": previous_qualification, "fourth": continuation_fourth_origin(),
        "native_fourth": fourth_native_projection(run, inventory, checks, commit),
        "no_work_receipt_b64": base64.b64encode(no_work_raw).decode("ascii"),
        "fourth_public_clients": fourth_public_clients}
    validate_continuation_qualification(value)
    return value


def validate(value, native, who):
    require(type(native) is identity.Policy, "operating-native-policy")
    native.validate()
    require(native.repository == "ltn-it/ansible-collection-supplementary"
            and native.repository_id == 1103407173 and native.reusable_repository == "ltn-it/modulix-validation"
            and native.workflow_id == 214182490 and native.workflow_path == ".github/workflows/collection-ci.yml",
            "operating-source-domain")
    engine_policy._keys(value, {"schema", "kind", "candidate", "controller", "operating", "github", "engine", "incus"})
    require(type(value["schema"]) is int and value["schema"] == 1 and value["kind"] == "operating",
            "operating-cell-schema")
    operating = engine_policy._keys(value["operating"], {"case", "target", "image"})
    case = operating["case"]
    selector(case)
    require(operating["target"] == TARGET and operating["image"] == IMAGE, "operating-platform")
    require(type(who) is dict and type(who.get("run_id")) is int and 0 < who["run_id"] < 2**63,
            "operating-run")
    expected = native.required_native_job_name
    suffix = "Operating custody / " + case
    require(type(expected) is str and (expected == suffix or expected.endswith(" / " + suffix)),
            "operating-native-job")
    candidate = engine_policy._keys(value["candidate"], {"repository", "source_sha", "artifact", "archive_sha256"})
    require(candidate["repository"] == native.repository and candidate["source_sha"] == native.caller_sha
            and candidate["artifact"] == "collection-candidate-" + native.caller_sha, "operating-candidate-binding")
    engine_policy._hash(candidate["archive_sha256"])
    controller = engine_policy._keys(value["controller"], {"repository", "source_sha", "archive_sha256", "files"})
    require(controller["repository"] == native.reusable_repository, "operating-controller-binding")
    # Root's action/controller commit and reusable workflow commit remain
    # independent bindings, as in the ordinary cell contract.
    cell_contract._commit(controller["source_sha"])
    engine_policy._hash(controller["archive_sha256"])
    require(type(controller["files"]) is dict and 0 < len(controller["files"]) <= 16
            and all(type(name) is str and re.fullmatch("[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", name)
                    for name in controller["files"]), "operating-controller-files")
    for digest in controller["files"].values():
        engine_policy._hash(digest)
    github = engine_policy._keys(value["github"], {"job", "workflow"})
    cell_contract._text(github["job"], 128)
    cell_contract._text(github["workflow"])
    require(type(value["engine"]) is dict and value["engine"] and type(value["incus"]) is dict and value["incus"],
            "operating-template")
    limits = engine_policy._keys(value["incus"].get("project_limits"),
        {"cpu", "memory_bytes", "disk_bytes", "instances", "virtual_machines", "containers"})
    required = {"cpu": CPU, "memory_bytes": MEMORY, "disk_bytes": PROJECT_RESERVATION,
                "instances": 1, "virtual_machines": 1, "containers": 0}
    require(all(type(limits[key]) is int and limits[key] == expected for key, expected in required.items()),
            "operating-project-reservation")
    instance = instance_name(case, who["run_id"])
    spec = {"schema": 1, "kind": "operating", "case": case, "image": IMAGE, "instance_name": instance,
            "cpu": CPU, "memory_bytes": MEMORY, "root_disk_bytes": ROOT_DISK,
            "state_disk_bytes": STATE_DISK, "total_disk_bytes": TOTAL_DISK,
            "image_reservation_bytes": IMAGE_RESERVATION, "project_reservation_bytes": PROJECT_RESERVATION}
    return OperatingCell(case, TARGET, IMAGE, instance, ledger.canonical(spec))


def environment(value, native, who):
    selected = validate(value, native, who)
    env = {"GITHUB_REPOSITORY": native.repository, "GITHUB_REPOSITORY_ID": str(native.repository_id),
           "GITHUB_RUN_ID": str(who["run_id"]), "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": native.caller_sha,
           "GITHUB_JOB": value["github"]["job"], "GITHUB_WORKFLOW": value["github"]["workflow"],
           "QUALITY_INPUT_PROFILE": "operating", "QUALITY_INPUT_SCENARIO": "g06-operating-" + selected.case,
           "QUALITY_INPUT_TARGET": TARGET, "QUALITY_INPUT_TARGET_DISPOSITION": "operating", "QUALITY_INPUT_ROLES": "",
           "QUALITY_INPUT_IMAGE": IMAGE, "QUALITY_INPUT_INSTANCE_TYPE": "vm",
           "QUALITY_INPUT_CANDIDATE_ARTIFACT": value["candidate"]["artifact"], "QUALITY_INPUT_SOURCE_SHA": native.caller_sha,
           "QUALITY_INPUT_JUNIT_REQUIRED": "false", "QUALITY_INPUT_ALLURE_REQUIRED": "false",
           "QUALITY_INPUT_CPU_LIMIT": "1", "QUALITY_INPUT_MEMORY_LIMIT": "2GiB", "QUALITY_INPUT_DISK_LIMIT": "6GiB",
           "QUALITY_OPERATING_CASE": selected.case, "QUALITY_OPERATING_SPEC": selected.spec_bytes.decode("ascii")}
    require(set(env) == ENV_KEYS, "operating-environment-keys")
    return env


# This fifth attempt DID create resources. Never reuse a no-work receipt or
# relabel its failed aggregate/Heavy/Tiny/fault graph as successful.
FIFTH_MAIN = "8926e7f535f158d4af89e4ac68149ff0b8ab740d"
FIFTH_RUN = 43616421593
FIFTH_LEASE = "fe9b6ca3b92fea0f01e0cf39b64b8844"
FIFTH_CELL = "ac1605abfe8d8f161725230142e62eded83f744f4fbbaae82669a9b95bc2424b"
FIFTH_POLICY = "4cc42e8494f27cc758bf859482678e68acc1a7dcfb734a1c5ea79caa24d01d1b"
FIFTH_TERMINAL = 1794675614
FIFTH_RETAIN_UNTIL = 1794690014
FIFTH_GRAPH = "9c80a2ae3c4e5f30d0b43b5a351c6a11acf9519357e83783a7e8a0f381e7ba2d"
FIFTH_CHECKS = (132512594125, 132512850572, 132519235539)
FIFTH_JOB = 132512850572
FIFTH_CHECK = 132512850572
FIFTH_RUNNER = 78
FIFTH_UID = 995



def fifth_native_projection(run, inventory, checks):
    require(type(run) is dict and type(inventory) is dict and type(inventory.get("total_count")) is int
            and inventory["total_count"] == 24 and type(inventory.get("jobs")) is list
            and len(inventory["jobs"]) == 24, "continuation-fifth-complete-inventory")
    repo = run.get("repository", {})
    require(repo.get("id") == 1103407173 and repo.get("full_name") == "ltn-it/ansible-collection-supplementary"
            and repo.get("private") is False and repo.get("owner", {}).get("id") == 54334171,
            "continuation-fifth-native-repository")
    refs = run.get("referenced_workflows")
    require(type(refs) is list and sum(type(v) is dict and v.get("sha") == FOUR_HISTORY_REUSABLE
            and v.get("path") == "ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@" + FOUR_HISTORY_REUSABLE
            for v in refs) == 1, "continuation-fifth-native-controller")
    fields = ("id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion", "runner_id",
              "runner_group_id", "started_at", "completed_at", "check_run_url")
    rows = [{k: row.get(k) for k in fields} for row in inventory["jobs"]]
    require(all(type(row["id"]) is int and row["id"] > 0 for row in rows)
            and len({row["id"] for row in rows}) == 24, "continuation-fifth-native-ids")
    actor = {"login": "litroc", "id": 76040632, "type": "User"}
    require(all(type(run.get(field)) is dict and all(type(run[field].get(k)) is type(v)
                and run[field][k] == v for k, v in actor.items())
                for field in ("actor", "triggering_actor")), "continuation-fifth-actor")
    graph = {"run": {**{k: run.get(k) for k in ("id", "run_attempt", "head_sha", "event", "head_branch",
             "workflow_id", "path", "status", "conclusion")},
             **{field: {k: run[field][k] for k in actor} for field in ("actor", "triggering_actor")}},
             "jobs": sorted(rows, key=lambda row: row["id"])}
    require(ledger.digest(graph) == FIFTH_GRAPH, "continuation-fifth-original-failed-graph")
    require(type(checks) is list and len(checks) == len(FIFTH_CHECKS), "continuation-fifth-native-checks")
    for identifier, check in zip(FIFTH_CHECKS, checks):
        job = next(row for row in rows if row["id"] == identifier)
        require(type(check) is dict and check.get("id") == identifier and check.get("head_sha") == FIFTH_MAIN
                and all(check.get(k) == job[k] for k in ("name", "status", "conclusion", "started_at", "completed_at"))
                and check.get("app", {}).get("id") == 15368 and check.get("app", {}).get("slug") == "github-actions",
                "continuation-fifth-native-check")
    return graph


def _validate_partial_preparation_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    require(value["schema"] == 5 and value["reason"] == "original-partial-preparation-failed-retired",
            "continuation-fifth-purpose")
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"]); engine_policy._hash(ref["sha256"])
    row = engine_policy._keys(value["successor"], {"source_sha", "run_id", "run_attempt", "first_parent",
                                                  "source_workflow_sha256", "reusable_sha"})
    cell_contract._commit(row["source_sha"])
    engine_policy._integer(row["run_id"], 1, 2**63 - 1)
    require(row["source_sha"] not in {INITIAL_MAIN, ORIGIN_MAIN, PRIOR_MAIN, THIRD_MAIN, FOURTH_MAIN, FIFTH_MAIN}
            and row["run_id"] not in {ORIGIN_RUN, PRIOR_RUN, THIRD_RUN, FOURTH_RUN, FIFTH_RUN}
            and type(row["run_attempt"]) is int and row["run_attempt"] == 1 and row["first_parent"] == FIFTH_MAIN
            and row["source_workflow_sha256"] == workflow_sha256
            and row["reusable_sha"] == reusable_sha
            and (workflow_sha256, reusable_sha) in {
                (FOUR_HISTORY_WORKFLOW, FOUR_HISTORY_REUSABLE),
                ("64e3d2ca0bd5e442233ec53b00d6f76fb7ba40064abea36237edeb783089b4ba",
                 "a94199c94fd00226e194613d0fb9d52705baa808"),
            }, "continuation-fifth-successor")
    return value


def _validate_partial_retirement(value):
    engine_policy._keys(value, {"schema", "kind", "lease_id", "record_sha256", "closed_at", "retain_until",
                               "native_absence_sha256", "catalogues", "original_configuration"})
    require(type(value["schema"]) is int and value["schema"] == 1
            and value["kind"] == "original-fifth-partial-preparation-verified-closed"
            and value["lease_id"] == FIFTH_LEASE and type(value["closed_at"]) is int
            and value["closed_at"] >= value["retain_until"] == FIFTH_RETAIN_UNTIL,
            "continuation-fifth-retirement-not-closed")
    for field in ("record_sha256", "native_absence_sha256"):
        engine_policy._hash(value[field])
    original = engine_policy._keys(value["original_configuration"], {"directory", "manifest_sha256"})
    engine_policy._path(original["directory"])
    engine_policy._hash(original["manifest_sha256"])

    catalogues = engine_policy._keys(value["catalogues"], {"native_intake_catalogue", "native_run_configuration_catalogue"})
    for entries in catalogues.values():
        require(type(entries) is dict and 0 < len(entries) <= 256, "continuation-fifth-retired-catalogue")
        for name, digest in entries.items():
            require(type(name) is str and re.fullmatch("[0-9a-f]{64}", name), "continuation-fifth-retired-entry")
            engine_policy._hash(digest)
    return value


def _validate_partial_preparation_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "previous_qualification", "native_fifth", "retirement"})
    require(type(value["schema"]) is int and value["schema"] == 5
            and value["purpose"] == "g06-fifth-failed-partial-preparation-with-effects",
            "continuation-fifth-qualification")
    previous = value["previous_qualification"]
    require(type(previous) is dict and type(previous.get("schema")) is int and previous["schema"] == 4,
            "continuation-fifth-preserved-four-history")
    counts = _validate_four_history_qualification(previous)
    require(ledger.digest(value["native_fifth"]) == FIFTH_GRAPH, "continuation-fifth-preserved-native-graph")
    _validate_partial_retirement(value["retirement"])
    return counts


def partial_preparation_continuation_qualification(previous, run, inventory, checks, retirement):
    """Root-sealed assembly only; real closed-store/native absence is re-proved at entry."""
    value = {"schema": 5, "purpose": "g06-fifth-failed-partial-preparation-with-effects",
             "previous_qualification": previous, "native_fifth": fifth_native_projection(run, inventory, checks),
             "retirement": retirement}
    validate_continuation_qualification(value)
    return value


# The original sixth push published a context but never journaled a fence/start.
# Preserve its failed native graph and actual closure; no replay or new budget.
SIXTH_MAIN = "086d039c8c58bc91edfeacadf508c207a03a58b5"
SIXTH_RUN = 43778415146
SIXTH_LEASE = "6853b45b11a3bfcc84370c57788258ba"
SIXTH_CELL = "5cba179a81a5d9a8d1aa3004e75a5f8c4dda68e19c05ca9541b7a7db02e8d631"
SIXTH_POLICY = "4cc42e8494f27cc758bf859482678e68acc1a7dcfb734a1c5ea79caa24d01d1b"
SIXTH_TERMINAL = 1794808083
SIXTH_RETAIN_UNTIL = 1794822483
SIXTH_GRAPH = "4a54b41ae5e95acf7703af177e9fa82f7bb29e66df24bb344b8b18601a59b53b"
SIXTH_CHECKS = (133010603431, 133010877404, 133117295957)
SIXTH_JOB = 133010877404
SIXTH_CHECK = 133010877404
SIXTH_RUNNER = 78
SIXTH_UID = 995
SIXTH_WORKFLOW = "64e3d2ca0bd5e442233ec53b00d6f76fb7ba40064abea36237edeb783089b4ba"
SIXTH_REUSABLE = "a94199c94fd00226e194613d0fb9d52705baa808"
SIXTH_PREVIOUS_QUALIFICATION = "3fcc132ce7c8b0e0530df1fc412f861dc2a9a34c5311813cb0fccaaccef5410b"
# Required late binding from the actual newly published callee and caller bytes.
# Neither pending value is a historical identity or an authorization fallback.
SIXTH_SUCCESSOR_WORKFLOW = '90e1bb3b99809605a3bce7258f81d6bf2922315250154ebea0ab4a7c46ab9865'
SIXTH_SUCCESSOR_REUSABLE = 'cb317a6d3b3e7b1b0549c3c62bb581e14de778c3'


def sixth_native_projection(run, inventory, checks):
    require(type(run) is dict and type(inventory) is dict and type(inventory.get("total_count")) is int
            and inventory["total_count"] == 24 and type(inventory.get("jobs")) is list
            and len(inventory["jobs"]) == 24, "continuation-sixth-complete-inventory")
    repo = run.get("repository", {})
    require(repo.get("id") == 1103407173 and repo.get("full_name") == "ltn-it/ansible-collection-supplementary"
            and repo.get("private") is False and repo.get("owner", {}).get("id") == 54334171,
            "continuation-sixth-native-repository")
    refs = run.get("referenced_workflows")
    require(type(refs) is list and sum(type(v) is dict and v.get("sha") == SIXTH_REUSABLE
            and v.get("path") == "ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@" + SIXTH_REUSABLE
            for v in refs) == 1, "continuation-sixth-native-controller")
    fields = ("id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion", "runner_id",
              "runner_group_id", "started_at", "completed_at", "check_run_url")
    rows = [{k: row.get(k) for k in fields} for row in inventory["jobs"]]
    require(all(type(row["id"]) is int and row["id"] > 0 for row in rows)
            and len({row["id"] for row in rows}) == 24, "continuation-sixth-native-ids")
    actor = {"login": "litroc", "id": 76040632, "type": "User"}
    require(all(type(run.get(field)) is dict and all(type(run[field].get(k)) is type(v)
                and run[field][k] == v for k, v in actor.items())
                for field in ("actor", "triggering_actor")), "continuation-sixth-actor")
    graph = {"run": {**{k: run.get(k) for k in ("id", "run_attempt", "head_sha", "event", "head_branch",
             "workflow_id", "path", "status", "conclusion")},
             **{field: {k: run[field][k] for k in actor} for field in ("actor", "triggering_actor")}},
             "jobs": sorted(rows, key=lambda row: row["id"])}
    require(ledger.digest(graph) == SIXTH_GRAPH, "continuation-sixth-original-failed-graph")
    require(type(checks) is list and len(checks) == len(SIXTH_CHECKS), "continuation-sixth-native-checks")
    for identifier, check in zip(SIXTH_CHECKS, checks):
        job = next(row for row in rows if row["id"] == identifier)
        require(type(check) is dict and check.get("id") == identifier and check.get("head_sha") == SIXTH_MAIN
                and all(check.get(k) == job[k] for k in ("name", "status", "conclusion", "started_at", "completed_at"))
                and check.get("app", {}).get("id") == 15368 and check.get("app", {}).get("slug") == "github-actions",
                "continuation-sixth-native-check")
    return graph


def _validate_sixth_retirement(value):
    engine_policy._keys(value, {"schema", "kind", "lease_id", "record_sha256", "closed_at", "retain_until",
                               "native_absence_sha256", "catalogues", "original_configuration"})
    require(type(value["schema"]) is int and value["schema"] == 1
            and value["kind"] == "original-sixth-post-context-pre-fence-verified-closed"
            and value["lease_id"] == SIXTH_LEASE and type(value["closed_at"]) is int
            and type(value["retain_until"]) is int
            and value["closed_at"] >= value["retain_until"] == SIXTH_RETAIN_UNTIL,
            "continuation-sixth-retirement-not-closed")
    for field in ("record_sha256", "native_absence_sha256"):
        engine_policy._hash(value[field])
    original = engine_policy._keys(value["original_configuration"], {"directory", "manifest_sha256"})
    engine_policy._path(original["directory"])
    engine_policy._hash(original["manifest_sha256"])

    catalogues = engine_policy._keys(value["catalogues"], {"native_intake_catalogue", "native_run_configuration_catalogue"})
    for entries in catalogues.values():
        require(type(entries) is dict and 0 < len(entries) <= 256, "continuation-sixth-retired-catalogue")
        for name, digest in entries.items():
            require(type(name) is str and re.fullmatch("[0-9a-f]{64}", name), "continuation-sixth-retired-entry")
            engine_policy._hash(digest)
    return value


def _validate_sixth_preparation_descriptor(value, workflow_sha256, reusable_sha):
    require(type(SIXTH_SUCCESSOR_WORKFLOW) is str
            and re.fullmatch("[0-9a-f]{64}", SIXTH_SUCCESSOR_WORKFLOW)
            and SIXTH_SUCCESSOR_WORKFLOW not in {SIXTH_WORKFLOW, "0" * 64}
            and type(SIXTH_SUCCESSOR_REUSABLE) is str
            and re.fullmatch("[0-9a-f]{40}", SIXTH_SUCCESSOR_REUSABLE)
            and SIXTH_SUCCESSOR_REUSABLE not in {SIXTH_REUSABLE, "0" * 40},
            "continuation-sixth-successor-pins-unbound")
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    require(type(value["schema"]) is int and value["schema"] == 6
            and value["reason"] == "original-post-context-pre-fence-failed-retired", "continuation-sixth-purpose")
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"]); engine_policy._hash(ref["sha256"])
    row = engine_policy._keys(value["successor"], {"source_sha", "run_id", "run_attempt", "first_parent",
                                                  "source_workflow_sha256", "reusable_sha"})
    cell_contract._commit(row["source_sha"])
    engine_policy._integer(row["run_id"], 1, 2**63 - 1)
    require(row["source_sha"] not in {INITIAL_MAIN, ORIGIN_MAIN, PRIOR_MAIN, THIRD_MAIN, FOURTH_MAIN, FIFTH_MAIN, SIXTH_MAIN}
            and row["run_id"] not in {ORIGIN_RUN, PRIOR_RUN, THIRD_RUN, FOURTH_RUN, FIFTH_RUN, SIXTH_RUN}
            and type(row["run_attempt"]) is int and row["run_attempt"] == 1 and row["first_parent"] == SIXTH_MAIN
            and row["source_workflow_sha256"] == workflow_sha256 == SIXTH_SUCCESSOR_WORKFLOW
            and row["reusable_sha"] == reusable_sha == SIXTH_SUCCESSOR_REUSABLE, "continuation-sixth-successor")
    return value


def _validate_sixth_preparation_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "previous_qualification", "native_sixth", "retirement"})
    require(type(value["schema"]) is int and value["schema"] == 6
            and value["purpose"] == "g06-sixth-failed-post-context-pre-fence-with-effects", "continuation-sixth-qualification")
    previous = value["previous_qualification"]
    require(type(previous) is dict and type(previous.get("schema")) is int and previous["schema"] == 5
            and ledger.digest(previous) == SIXTH_PREVIOUS_QUALIFICATION, "continuation-sixth-preserved-five-history")
    counts = _validate_partial_preparation_qualification(previous)
    require(ledger.digest(value["native_sixth"]) == SIXTH_GRAPH, "continuation-sixth-preserved-native-graph")
    _validate_sixth_retirement(value["retirement"])
    return counts


def sixth_preparation_continuation_qualification(previous, run, inventory, checks, retirement):
    """Root-only assembly; genuine closed original and native absence re-proved at entry."""
    value = {"schema": 6, "purpose": "g06-sixth-failed-post-context-pre-fence-with-effects",
             "previous_qualification": previous, "native_sixth": sixth_native_projection(run, inventory, checks),
             "retirement": retirement}
    validate_continuation_qualification(value)
    return value


# Original seventh run failed after immutable intake/config staging, before any
# lease. Its staged entries remain history; no same-run retry or adoption exists.
SEVENTH_MAIN = "cfd2e8ca4cbcf58a1a22cf37f2a8336bba19cb85"
SEVENTH_RUN = 43947870949
SEVENTH_JOB = 133584862472
SEVENTH_CHECKS = (133584862472, 133689573836, 133690106874)
SEVENTH_REUSABLE = "cb317a6d3b3e7b1b0549c3c62bb581e14de778c3"
SEVENTH_WORKFLOW = "90e1bb3b99809605a3bce7258f81d6bf2922315250154ebea0ab4a7c46ab9865"
SEVENTH_GRAPH = "77922e610222336f0a141a42396fb3fe8279f185677c00fb8256002b04f7bed2"
SEVENTH_PREVIOUS_QUALIFICATION = "ac77310e5f9689c6bc9f4ef9e665b82e1c6718f2e99509d8e1293488ee381108"
SEVENTH_CONFIGURATION = "f2bf2233351f72c25649a6205aa990526d80fd6c44b7deedd24dfb2c3be69012"
SEVENTH_INTAKE = "ecab33dec453b2d3d4b3ecb9e14295567e60612918216dc8dc2fd457758b14a2"
SEVENTH_CONFIG_INTENT = "597492b48ec2d29dd7efa8bad8fa47d3142f1f640cfa68015032e4cdfb1c5bf3"
SEVENTH_INTAKE_RECEIPT = "8cb863ba820105855901f1ad0c93884ad22c7799bcb89d892c39b4cadabeecf5"
SEVENTH_BOOTSTRAP = "f261a7d92eb0d3b393bc704a74689870020c3ce3c4d755d65379fa5a3606eaf9"
# Genuine future published caller/callee bytes are mandatory; unbound denies.
SEVENTH_BANK_IDENTITY = (64517, 1313166)
SEVENTH_CONFIGURATION_IDENTITY = (64517, 1313199)
SEVENTH_INTAKE_IDENTITY = (64517, 1313170)
SEVENTH_CONFIGURATION_INVENTORY = "4c512c7bc6342c378a6eb4e406c2c3c4535b7644937b0a74aa505de7126e604b"
SEVENTH_INTAKE_INVENTORY = "58b55ca43a4aaa5e4195ef59b85dd010551c457cc76a6653428b1129f46a4750"
SEVENTH_SUCCESSOR_WORKFLOW = "9df6727c7c63b996389d138f4478611404d938664e231fe3fd8b26324b4b1cdc"
SEVENTH_SUCCESSOR_REUSABLE = "1be871ceb82d977f9403e87554d2ade9dc9714e9"


def seventh_native_projection(run, inventory, checks):
    require(type(run) is dict and type(inventory) is dict and type(inventory.get("total_count")) is int
            and inventory["total_count"] == 24 and type(inventory.get("jobs")) is list
            and len(inventory["jobs"]) == 24, "continuation-seventh-complete-inventory")
    repo = run.get("repository", {})
    require(repo.get("id") == 1103407173 and repo.get("full_name") == "ltn-it/ansible-collection-supplementary"
            and repo.get("private") is False and repo.get("owner", {}).get("id") == 54334171,
            "continuation-seventh-native-repository")
    refs = run.get("referenced_workflows")
    require(type(refs) is list and sum(type(v) is dict and v.get("sha") == SEVENTH_REUSABLE
            and v.get("path") == "ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@" + SEVENTH_REUSABLE
            for v in refs) == 1, "continuation-seventh-native-controller")
    fields = ("id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion", "runner_id",
              "runner_group_id", "started_at", "completed_at", "check_run_url")
    rows = [{k: row.get(k) for k in fields} for row in inventory["jobs"]]
    require(all(type(row["id"]) is int and row["id"] > 0 for row in rows)
            and len({row["id"] for row in rows}) == 24, "continuation-seventh-native-ids")
    actor = {"login": "litroc", "id": 76040632, "type": "User"}
    require(all(type(run.get(field)) is dict and all(type(run[field].get(k)) is type(v)
                and run[field][k] == v for k, v in actor.items())
                for field in ("actor", "triggering_actor")), "continuation-seventh-actor")
    graph = {"run": {**{k: run.get(k) for k in ("id", "run_attempt", "head_sha", "event", "head_branch",
             "workflow_id", "path", "status", "conclusion")},
             **{field: {k: run[field][k] for k in actor} for field in ("actor", "triggering_actor")}},
             "jobs": sorted(rows, key=lambda row: row["id"])}
    require(ledger.digest(graph) == SEVENTH_GRAPH, "continuation-seventh-original-failed-graph")
    require(type(checks) is list and len(checks) == len(SEVENTH_CHECKS), "continuation-seventh-native-checks")
    for identifier, check in zip(SEVENTH_CHECKS, checks):
        job = next(row for row in rows if row["id"] == identifier)
        require(type(check) is dict and check.get("id") == identifier and check.get("head_sha") == SEVENTH_MAIN
                and all(check.get(k) == job[k] for k in ("name", "status", "conclusion", "started_at", "completed_at"))
                and check.get("app", {}).get("id") == 15368 and check.get("app", {}).get("slug") == "github-actions",
                "continuation-seventh-native-check")
    return graph



def _validate_seventh_failed_prefix(value):
    engine_policy._keys(value, {"schema", "kind", "original_bootstrap", "original_bank", "configuration",
                               "intake", "catalogues"})
    require(type(value["schema"]) is int and value["schema"] == 1
            and value["kind"] == "original-seventh-staged-prelease-no-lease-preserved",
            "continuation-seventh-prefix-kind")
    bootstrap = engine_policy._keys(value["original_bootstrap"], {"path", "sha256"})
    engine_policy._path(bootstrap["path"])
    require(bootstrap["sha256"] == SEVENTH_BOOTSTRAP, "continuation-seventh-original-bootstrap")
    bank = engine_policy._keys(value["original_bank"], {"path", "device", "inode"})
    engine_policy._path(bank["path"])
    require(bank["path"].endswith("/oidc-config-successor-b260217d0b354c5fa44493c092c45200/ledger"),
            "continuation-seventh-original-bank")
    for key in ("device", "inode"):
        engine_policy._integer(bank[key], 1, 2**63 - 1)
    require((bank["device"], bank["inode"]) == SEVENTH_BANK_IDENTITY, "continuation-seventh-original-bank-identity")
    for kind, name, fixed, inventory in (("configuration", SEVENTH_CONFIGURATION, SEVENTH_CONFIG_INTENT, SEVENTH_CONFIGURATION_INVENTORY),
                                         ("intake", SEVENTH_INTAKE, SEVENTH_INTAKE_RECEIPT, SEVENTH_INTAKE_INVENTORY)):
        row = engine_policy._keys(value[kind], {"name", "device", "inode", "receipt_sha256", "inventory_sha256"})
        require(row["name"] == name and row["receipt_sha256"] == fixed, "continuation-seventh-prefix-identity")
        expected_identity = SEVENTH_CONFIGURATION_IDENTITY if kind == "configuration" else SEVENTH_INTAKE_IDENTITY
        require((row["device"], row["inode"]) == expected_identity, "continuation-seventh-prefix-directory-identity")
        engine_policy._hash(inventory)
        require(row["inventory_sha256"] == inventory, "continuation-seventh-prefix-inventory")
        for key in ("device", "inode"):
            engine_policy._integer(row[key], 1, 2**63 - 1)
    catalogue = engine_policy._keys(value["catalogues"], {"native_intake_catalogue", "native_run_configuration_catalogue"})
    for kind, extra in (("native_intake_catalogue", value["intake"]),
                         ("native_run_configuration_catalogue", value["configuration"])):
        entries = catalogue[kind]
        require(type(entries) is dict and 0 < len(entries) <= 256
                and entries.get(extra["name"]) == extra["inventory_sha256"], "continuation-seventh-catalogue")
        for name, sha in entries.items():
            require(type(name) is str and re.fullmatch("[0-9a-f]{64}", name), "continuation-seventh-catalogue-name")
            engine_policy._hash(sha)
    return value


def _validate_seventh_prelease_descriptor(value, workflow_sha256, reusable_sha):
    require(type(SEVENTH_SUCCESSOR_WORKFLOW) is str and re.fullmatch("[0-9a-f]{64}", SEVENTH_SUCCESSOR_WORKFLOW)
            and SEVENTH_SUCCESSOR_WORKFLOW not in {SEVENTH_WORKFLOW, "0" * 64}
            and type(SEVENTH_SUCCESSOR_REUSABLE) is str and re.fullmatch("[0-9a-f]{40}", SEVENTH_SUCCESSOR_REUSABLE)
            and SEVENTH_SUCCESSOR_REUSABLE not in {SEVENTH_REUSABLE, "0" * 40},
            "continuation-seventh-successor-pins-unbound")
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    require(type(value["schema"]) is int and value["schema"] == 7
            and value["reason"] == "original-staged-prelease-expired-no-lease", "continuation-seventh-purpose")
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"]); engine_policy._hash(ref["sha256"])
    row = engine_policy._keys(value["successor"], {"source_sha", "run_id", "run_attempt", "first_parent",
                                                  "source_workflow_sha256", "reusable_sha"})
    cell_contract._commit(row["source_sha"])
    engine_policy._integer(row["run_id"], 1, 2**63 - 1)
    require(row["source_sha"] not in {INITIAL_MAIN, ORIGIN_MAIN, PRIOR_MAIN, THIRD_MAIN, FOURTH_MAIN, FIFTH_MAIN, SIXTH_MAIN, SEVENTH_MAIN}
            and row["run_id"] not in {ORIGIN_RUN, PRIOR_RUN, THIRD_RUN, FOURTH_RUN, FIFTH_RUN, SIXTH_RUN, SEVENTH_RUN}
            and type(row["run_attempt"]) is int and row["run_attempt"] == 1 and row["first_parent"] == SEVENTH_MAIN
            and row["source_workflow_sha256"] == workflow_sha256 == SEVENTH_SUCCESSOR_WORKFLOW
            and row["reusable_sha"] == reusable_sha == SEVENTH_SUCCESSOR_REUSABLE, "continuation-seventh-successor")
    return value


def _validate_seventh_prelease_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "previous_qualification", "native_seventh", "failed_prefix"})
    require(type(value["schema"]) is int and value["schema"] == 7
            and value["purpose"] == "g06-seventh-failed-prelease-staged-history", "continuation-seventh-qualification")
    previous = value["previous_qualification"]
    require(type(previous) is dict and type(previous.get("schema")) is int and previous["schema"] == 6
            and ledger.digest(previous) == SEVENTH_PREVIOUS_QUALIFICATION, "continuation-seventh-preserved-six-history")
    counts = _validate_sixth_preparation_qualification(previous)
    require(ledger.digest(value["native_seventh"]) == SEVENTH_GRAPH, "continuation-seventh-preserved-native-graph")
    prefix = _validate_seventh_failed_prefix(value["failed_prefix"])
    old = previous["retirement"]["catalogues"]
    for kind, extra in (("native_intake_catalogue", SEVENTH_INTAKE),
                         ("native_run_configuration_catalogue", SEVENTH_CONFIGURATION)):
        require(set(prefix["catalogues"][kind]) == set(old[kind]) | {extra}
                and extra not in old[kind]
                and all(prefix["catalogues"][kind][name] == sha for name, sha in old[kind].items()),
                "continuation-seventh-preserved-catalogues")
    return counts


def seventh_prelease_continuation_qualification(previous, run, inventory, checks, failed_prefix):
    """Root-only historical assembly; no lease or resource grant is created."""
    value = {"schema": 7, "purpose": "g06-seventh-failed-prelease-staged-history",
             "previous_qualification": previous, "native_seventh": seventh_native_projection(run, inventory, checks),
             "failed_prefix": failed_prefix}
    validate_continuation_qualification(value)
    return value


# The eighth original completed before any lease. Both intake and generated
# configuration are complete and remain immutable history, never adopted.
EIGHTH_MAIN = "8345d447e65609e66eac616afbeb3b5d4bc362be"
EIGHTH_RUN = 44153750769
EIGHTH_JOB = 134291739967
EIGHTH_CHECKS = (134291739967, 134338536637, 134339042918)
EIGHTH_REUSABLE = "1be871ceb82d977f9403e87554d2ade9dc9714e9"
EIGHTH_WORKFLOW = "9df6727c7c63b996389d138f4478611404d938664e231fe3fd8b26324b4b1cdc"
EIGHTH_GRAPH = "564c07affa2ff555e27eda5b59312d7759cdfa916b0f224ac6bf01187e69a470"
EIGHTH_PREVIOUS_QUALIFICATION = "ea6dbf15463c3c960b05ab0c07bf946b0edacd23204bcdc3631d8768723e8c71"
EIGHTH_CONFIGURATION = "612ca4d78616159f4765ee5271c54a5a5ca28a16d62473806349a39df5e0e413"
EIGHTH_INTAKE = "2b6415bacdde122ab2999e0b055483f0154b7355849353dd01e85e26bcc2c162"
EIGHTH_CONFIG_RECEIPT = "670794b93bab1d41e2fbf9e863ae440a407f48539c6169e01a116ff9721d60f2"
EIGHTH_INTAKE_RECEIPT = "7a423507892c7641d73dea23bd62b426fbfaca15395f2340ff32bc5645d807bb"
EIGHTH_BOOTSTRAP = "9f12437843c50f2ea050e32e6f4f438160fbb439a7df296dbbefc33581dc667e"
EIGHTH_BOOTSTRAP_IDENTITY = (64517, 1441916)
EIGHTH_BANK_IDENTITY = (64517, 1441904)
EIGHTH_CONFIGURATION_IDENTITY = (64517, 1441934)
EIGHTH_INTAKE_IDENTITY = (64517, 1441908)
EIGHTH_CONFIGURATION_INVENTORY = "5562e6cb46b450ecba6062e1d272c6ad51a6111cd675f407914648e1bd9d8492"
EIGHTH_INTAKE_INVENTORY = "b1438907dd14fc1fb89183276ef19f49e206d83e3d3cfc9707a1f45b5b8b247c"
# Exact local Source candidate bytes and genuinely published Validation Main.
# Installation still requires the accepted Source consumer and native gates.
EIGHTH_SUCCESSOR_WORKFLOW = "6d293f9e8a57942417acd651b35fb11aa5495dba7e0ae2f5e5e386d2ccec315e"
EIGHTH_SUCCESSOR_REUSABLE = "99efac0591dd9cd4df836d7d8d805ccdc3ec808f"


def eighth_native_projection(run, inventory, checks):
    require(type(run) is dict and type(inventory) is dict and type(inventory.get("total_count")) is int
            and inventory["total_count"] == 24 and type(inventory.get("jobs")) is list
            and len(inventory["jobs"]) == 24, "continuation-eighth-complete-inventory")
    repo = run.get("repository", {})
    require(repo.get("id") == 1103407173 and repo.get("full_name") == "ltn-it/ansible-collection-supplementary"
            and repo.get("private") is False and repo.get("owner", {}).get("id") == 54334171,
            "continuation-eighth-native-repository")
    refs = run.get("referenced_workflows")
    require(type(refs) is list and sum(type(v) is dict and v.get("sha") == EIGHTH_REUSABLE
            and v.get("path") == "ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@" + EIGHTH_REUSABLE
            for v in refs) == 1, "continuation-eighth-native-controller")
    fields = ("id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion", "runner_id",
              "runner_group_id", "started_at", "completed_at", "check_run_url")
    rows = [{k: row.get(k) for k in fields} for row in inventory["jobs"]]
    require(all(type(row["id"]) is int and row["id"] > 0 for row in rows)
            and len({row["id"] for row in rows}) == 24, "continuation-eighth-native-ids")
    actor = {"login": "litroc", "id": 76040632, "type": "User"}
    require(all(type(run.get(field)) is dict and all(type(run[field].get(k)) is type(v)
                and run[field][k] == v for k, v in actor.items())
                for field in ("actor", "triggering_actor")), "continuation-eighth-actor")
    graph = {"run": {**{k: run.get(k) for k in ("id", "run_attempt", "head_sha", "event", "head_branch",
             "workflow_id", "path", "status", "conclusion")},
             **{field: {k: run[field][k] for k in actor} for field in ("actor", "triggering_actor")}},
             "jobs": sorted(rows, key=lambda row: row["id"])}
    require(ledger.digest(graph) == EIGHTH_GRAPH, "continuation-eighth-original-failed-graph")
    require(type(checks) is list and len(checks) == len(EIGHTH_CHECKS), "continuation-eighth-native-checks")
    for identifier, check in zip(EIGHTH_CHECKS, checks):
        job = next(row for row in rows if row["id"] == identifier)
        require(type(check) is dict and check.get("id") == identifier and check.get("head_sha") == EIGHTH_MAIN
                and all(check.get(k) == job[k] for k in ("name", "status", "conclusion", "started_at", "completed_at"))
                and check.get("app", {}).get("id") == 15368 and check.get("app", {}).get("slug") == "github-actions",
                "continuation-eighth-native-check")
    return graph


def _validate_eighth_failed_prefix(value):
    engine_policy._keys(value, {"schema", "kind", "original_bootstrap", "original_bank", "configuration",
                               "intake", "catalogues"})
    require(type(value["schema"]) is int and value["schema"] == 1
            and value["kind"] == "original-eighth-complete-prelease-no-lease-preserved",
            "continuation-eighth-prefix-kind")
    bootstrap = engine_policy._keys(value["original_bootstrap"], {"path", "sha256"})
    engine_policy._path(bootstrap["path"])
    require(bootstrap["sha256"] == EIGHTH_BOOTSTRAP and bootstrap["path"].endswith(
        "/oidc-config-successor-18aec68429f14f8ea94a90217f9ffe70/immutable-bootstrap-locator-repair/candidate-bootstrap.json"),
        "continuation-eighth-original-bootstrap")
    bank = engine_policy._keys(value["original_bank"], {"path", "device", "inode"})
    engine_policy._path(bank["path"])
    require(bank["path"].endswith("/oidc-config-successor-18aec68429f14f8ea94a90217f9ffe70/ledger"),
            "continuation-eighth-original-bank")
    for key in ("device", "inode"):
        engine_policy._integer(bank[key], 1, 2**63 - 1)
    require((bank["device"], bank["inode"]) == EIGHTH_BANK_IDENTITY, "continuation-eighth-original-bank-identity")
    for kind, name, fixed, inventory in (("configuration", EIGHTH_CONFIGURATION, EIGHTH_CONFIG_RECEIPT, EIGHTH_CONFIGURATION_INVENTORY),
                                         ("intake", EIGHTH_INTAKE, EIGHTH_INTAKE_RECEIPT, EIGHTH_INTAKE_INVENTORY)):
        row = engine_policy._keys(value[kind], {"name", "device", "inode", "receipt_sha256", "inventory_sha256"})
        require(row["name"] == name and row["receipt_sha256"] == fixed, "continuation-eighth-prefix-identity")
        expected_identity = EIGHTH_CONFIGURATION_IDENTITY if kind == "configuration" else EIGHTH_INTAKE_IDENTITY
        require((row["device"], row["inode"]) == expected_identity, "continuation-eighth-prefix-directory-identity")
        engine_policy._hash(inventory)
        require(row["inventory_sha256"] == inventory, "continuation-eighth-prefix-inventory")
        for key in ("device", "inode"):
            engine_policy._integer(row[key], 1, 2**63 - 1)
    catalogue = engine_policy._keys(value["catalogues"], {"native_intake_catalogue", "native_run_configuration_catalogue"})
    for kind, extra in (("native_intake_catalogue", value["intake"]),
                         ("native_run_configuration_catalogue", value["configuration"])):
        entries = catalogue[kind]
        require(type(entries) is dict and 0 < len(entries) <= 256
                and entries.get(extra["name"]) == extra["inventory_sha256"], "continuation-eighth-catalogue")
        for name, sha in entries.items():
            require(type(name) is str and re.fullmatch("[0-9a-f]{64}", name), "continuation-eighth-catalogue-name")
            engine_policy._hash(sha)
    return value


def _validate_eighth_prelease_descriptor(value, workflow_sha256, reusable_sha):
    require(type(EIGHTH_SUCCESSOR_WORKFLOW) is str and re.fullmatch("[0-9a-f]{64}", EIGHTH_SUCCESSOR_WORKFLOW)
            and EIGHTH_SUCCESSOR_WORKFLOW not in {EIGHTH_WORKFLOW, "0" * 64}
            and type(EIGHTH_SUCCESSOR_REUSABLE) is str and re.fullmatch("[0-9a-f]{40}", EIGHTH_SUCCESSOR_REUSABLE)
            and EIGHTH_SUCCESSOR_REUSABLE not in {EIGHTH_REUSABLE, "0" * 40},
            "continuation-eighth-successor-pins-unbound")
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    require(type(value["schema"]) is int and value["schema"] == 8
            and value["reason"] == "original-complete-prelease-catalogue-reader-failed", "continuation-eighth-purpose")
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"]); engine_policy._hash(ref["sha256"])
    row = engine_policy._keys(value["successor"], {"source_sha", "run_id", "run_attempt", "first_parent",
                                                  "source_workflow_sha256", "reusable_sha"})
    cell_contract._commit(row["source_sha"])
    engine_policy._integer(row["run_id"], 1, 2**63 - 1)
    require(row["source_sha"] not in {INITIAL_MAIN, ORIGIN_MAIN, PRIOR_MAIN, THIRD_MAIN, FOURTH_MAIN, FIFTH_MAIN, SIXTH_MAIN, SEVENTH_MAIN, EIGHTH_MAIN}
            and row["run_id"] not in {ORIGIN_RUN, PRIOR_RUN, THIRD_RUN, FOURTH_RUN, FIFTH_RUN, SIXTH_RUN, SEVENTH_RUN, EIGHTH_RUN}
            and type(row["run_attempt"]) is int and row["run_attempt"] == 1 and row["first_parent"] == EIGHTH_MAIN
            and row["source_workflow_sha256"] == workflow_sha256 == EIGHTH_SUCCESSOR_WORKFLOW
            and row["reusable_sha"] == reusable_sha == EIGHTH_SUCCESSOR_REUSABLE, "continuation-eighth-successor")
    return value


def _validate_eighth_prelease_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "previous_qualification", "native_eighth", "failed_prefix"})
    require(type(value["schema"]) is int and value["schema"] == 8
            and value["purpose"] == "g06-eighth-failed-prelease-complete-history", "continuation-eighth-qualification")
    previous = value["previous_qualification"]
    require(type(previous) is dict and type(previous.get("schema")) is int and previous["schema"] == 7
            and ledger.digest(previous) == EIGHTH_PREVIOUS_QUALIFICATION, "continuation-eighth-preserved-seven-history")
    counts = _validate_seventh_prelease_qualification(previous)
    require(ledger.digest(value["native_eighth"]) == EIGHTH_GRAPH, "continuation-eighth-preserved-native-graph")
    prefix = _validate_eighth_failed_prefix(value["failed_prefix"])
    old = previous["failed_prefix"]["catalogues"]
    for kind, extra in (("native_intake_catalogue", EIGHTH_INTAKE),
                        ("native_run_configuration_catalogue", EIGHTH_CONFIGURATION)):
        require(set(prefix["catalogues"][kind]) == set(old[kind]) | {extra}
                and extra not in old[kind]
                and all(prefix["catalogues"][kind][name] == sha for name, sha in old[kind].items()),
                "continuation-eighth-preserved-catalogues")
    return counts


def eighth_prelease_continuation_qualification(previous, run, inventory, checks, failed_prefix):
    """Assemble genuine immutable history; never grant a retry or alter old stages."""
    value = {"schema": 8, "purpose": "g06-eighth-failed-prelease-complete-history",
             "previous_qualification": previous, "native_eighth": eighth_native_projection(run, inventory, checks),
             "failed_prefix": failed_prefix}
    validate_continuation_qualification(value)
    return value


# The ninth original stopped in partial preparation. Its immutable native graph
# is history only; a separate Root retirement never resolves its UNKNOWN effect.
NINTH_MAIN = "86f3cb46e5856c4066cac14e73f46c3cefb8453e"
NINTH_RUN = 44427583641
NINTH_JOB = 135238784600
NINTH_CHECKS = (135238784600, 135243414213, 135244015806, 135244063798,
                135248771736, 135249618294, 135249670392)
NINTH_REUSABLE = "99efac0591dd9cd4df836d7d8d805ccdc3ec808f"
NINTH_WORKFLOW = "6d293f9e8a57942417acd651b35fb11aa5495dba7e0ae2f5e5e386d2ccec315e"
NINTH_GRAPH = "6d8a5a1a3198e43bfe9e9712f1edc47fbcbc213991f16fb17948493730b27fc6"
NINTH_PREVIOUS_QUALIFICATION = "cedb33cf2c4914859f272a218f0fc96a8c1d3e48e3e1b8f14b62eb8b83706a2c"


def ninth_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, NINTH_REUSABLE, NINTH_GRAPH,
                                       NINTH_CHECKS, NINTH_MAIN)


def tenth_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, NINTH_SUCCESSOR_REUSABLE,
                                       TENTH_GRAPH, TENTH_CHECKS, TENTH_MAIN)


def _terminal_native_projection(run, inventory, checks, reusable, graph_digest, check_ids, main):
    require(type(run) is dict and type(inventory) is dict and type(inventory.get("total_count")) is int
            and inventory["total_count"] == 24 and type(inventory.get("jobs")) is list
            and len(inventory["jobs"]) == 24, "continuation-ninth-complete-inventory")
    repo = run.get("repository", {})
    require(repo.get("id") == 1103407173 and repo.get("full_name") == "ltn-it/ansible-collection-supplementary"
            and repo.get("private") is False and repo.get("owner", {}).get("id") == 54334171,
            "continuation-ninth-native-repository")
    refs = run.get("referenced_workflows")
    require(type(refs) is list and sum(type(v) is dict and v.get("sha") == reusable
            and v.get("path") == "ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@" + reusable
            for v in refs) == 1, "continuation-ninth-native-controller")
    fields = ("id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion", "runner_id",
              "runner_group_id", "started_at", "completed_at", "check_run_url")
    rows = [{k: row.get(k) for k in fields} for row in inventory["jobs"]]
    require(all(type(row["id"]) is int and row["id"] > 0 for row in rows)
            and len({row["id"] for row in rows}) == 24, "continuation-ninth-native-ids")
    actor = {"login": "litroc", "id": 76040632, "type": "User"}
    require(all(type(run.get(field)) is dict and all(type(run[field].get(k)) is type(v)
                and run[field][k] == v for k, v in actor.items())
                for field in ("actor", "triggering_actor")), "continuation-ninth-actor")
    graph = {"run": {**{k: run.get(k) for k in ("id", "run_attempt", "head_sha", "event", "head_branch",
             "workflow_id", "path", "status", "conclusion")},
             **{field: {k: run[field][k] for k in actor} for field in ("actor", "triggering_actor")}},
             "jobs": sorted(rows, key=lambda row: row["id"])}
    require(ledger.digest(graph) == graph_digest, "continuation-ninth-original-failed-graph")
    require(type(checks) is list and len(checks) == len(check_ids), "continuation-ninth-native-checks")
    for identifier, check in zip(check_ids, checks):
        job = next(row for row in rows if row["id"] == identifier)
        require(type(check) is dict and check.get("id") == identifier and check.get("head_sha") == main
                and all(check.get(k) == job[k] for k in ("name", "status", "conclusion", "started_at", "completed_at"))
                and check.get("app", {}).get("id") == 15368 and check.get("app", {}).get("slug") == "github-actions",
                "continuation-ninth-native-check")
    return graph



# Historical projection only. A Root factory must independently re-read these
# private objects and native absence; a matching JSON document grants nothing.
NINTH_RETIRED_PARTIAL = {'original_bootstrap': {'path': '/var/lib/lightning-it/g06-runtime-root-6848ed621bfd41cbae720bc576c6eeb4/oidc-config-successor-a2828109c3e24c0eac5b477c2e97e635/immutable-original-source86-8a386d83bcb54382a45ec3046a15331b/bootstrap.json',
                        'sha256': '1ba772ed0f7952f060b1cd981371ae8b798a882e72833e0679fd7afb131e101f',
                        'device': 64517,
                        'inode': 1446333},
 'original_bank': {'path': '/var/lib/lightning-it/g06-runtime-root-6848ed621bfd41cbae720bc576c6eeb4/oidc-config-successor-a2828109c3e24c0eac5b477c2e97e635/ledger',
                   'device': 64517,
                   'inode': 1444142,
                   'state_file_sha256': 'b8139214bba2863ef928872b65f54b4057c3f9a8577327c65b7021ecc9606f43'},
 'original_record': {'lease_id': '3e4a98952211426a1d317fd1757b3e67',
                     'sha256': '7a371958869bae94d251af131e92aaf0516ccbdf7b47ef65a31e78efd98d7878',
                     'state': 'prepared',
                     'unknown_effect_id': '838e147b15567fa3e2daf9f453b955f5',
                     'effects': {'426f0be0c6acad017fa74171628d37d9': {'operation': 'project-create',
                                                                      'state': 'verified',
                                                                      'effect_sha256': '7805f3be1bf4d756092e02008ba8d886f7d5bd44fef26d577c8ec0475de18df9'},
                                 '4e1cf648fc0508a76e153d89f011fdd5': {'operation': 'network-create',
                                                                      'state': 'verified',
                                                                      'effect_sha256': 'a2e42cb0f9556e831fc0b5be8880cd512a2cd0c07d487c3d3dfeb1643f6840d5'},
                                 '542eb06cc371d80180630aa427b48f4b': {'operation': 'context-publish',
                                                                      'state': 'verified',
                                                                      'effect_sha256': '451b7d03fff1b0cd7b3263fa999e8461fffec06f8cbca77dddce09e51e38f400'},
                                 '72a07506c9358ec0a7a0fdfb291b32fc': {'operation': 'context-create',
                                                                      'state': 'verified',
                                                                      'effect_sha256': '61081cffb7052b57205fa131981bff5853cb65d600d8f8e9397d47f58fca2e36'},
                                 '7d4d47e450670b17d89aa8016bd75c17': {'operation': 'engine-prepare',
                                                                      'state': 'verified',
                                                                      'effect_sha256': '19a900de760de1aa7b9634759bba14487481de9de8e9e009d795a11eed67d3d2'},
                                 '838e147b15567fa3e2daf9f453b955f5': {'operation': 'fence-create',
                                                                      'state': 'unknown',
                                                                      'effect_sha256': 'f62b5f5cc322428e3efc629bdfdd88e38dc73653a982485f06d8c77caf274b2b'},
                                 '85ba7dfd855ce9c93ad8fee99195dbca': {'operation': 'certificate-create',
                                                                      'state': 'verified',
                                                                      'effect_sha256': '042fdb0f9b31a47be0ce7994d1965f9888f84eebfa509a7dc1359671e1716f43'},
                                 'bf67f64928035b8b04432368c4bbd911': {'operation': 'profile-configure',
                                                                      'state': 'verified',
                                                                      'effect_sha256': 'e1cc9630b8950f67cb03648f81f7b11d0c4d3f1e6dcb3614eccee8aaa095bf1a'}}},
 'configuration': {'name': '8fc5f1b2a2f13e7379014f42172c4319091bf16946111cc7e786fbe0d72fd4ad',
                   'device': 64517,
                   'inode': 1444159,
                   'receipt_sha256': '0396baf7d45c72ab6d222b6f69819e11d9e0d5f0973371832c9c68e48dd03cd5',
                   'inventory_sha256': 'b2e3b9275ecf757326a7ad712ffb841e02c5d0e565f9351d047f8bc7402c5ae4'},
 'intake': {'name': 'b679e0a749b4f2f867d4b310ac5972349bea313ac58525788a141588681cd277',
            'device': 64517,
            'inode': 1444146,
            'receipt_sha256': '0338723f3b4fb941917bce0ce2bf0682639bd69984c403c732905c894d5f1bab',
            'inventory_sha256': '01e8f03415aab83919388fbd371bd2e0e113ae3a6e84fc4e385b1972366e6e6b'},
 'native_journal': {'path': '/var/lib/lightning-it/g06-runtime-root-6848ed621bfd41cbae720bc576c6eeb4/partial-retirement-ab89fd156df44bcca52d9be9f697f6fb',
                    'members': {'bridge-delete-intent.json': '665d804fab6fbb29587ccfcdf10440343d584b10a8577cf9dab6b089670cfadd',
                                'bridge-delete-receipt.json': '1206a251c6ae67220d38580fd362621eac8fcb81064f3f693c624fe0003f1150',
                                'complete-receipt.json': 'adfc9324eb25e9ecfd09cb31721e57f25a4df32e871d8c411c5496dfbf69ae94',
                                'descriptor-unlink-intent.json': '2e65522b0777238f4f85336d225c9483dbea46b1c05ee46be34460f4acd38ca0',
                                'descriptor-unlink-receipt.json': 'ee77d5e0940e06f8bbfdf990c0bf776be3eb79306731bd29a9ba729884727ef6',
                                'namespace-alias-unlink-intent.json': '9c971f45a681a0b304819550e35cd0535cff6dcf4b2985bd61e13b590257b682',
                                'namespace-alias-unlink-receipt.json': '584b43417f54e51433755aa8feb6bee0288f98276e00a060fedbe9e077e6f6df',
                                'private-tree-0-intent.json': 'cf4cfdd1e78794222168550393be1da8aa538a1ab86e17f49f7ce196f372f48d',
                                'private-tree-0-receipt.json': '951ad5ed73fcdd01ca7f36eca0b788a7c5422542cd89ec75e63e0b2090cc2c84',
                                'private-tree-1-intent.json': 'e65c6d2ed5e8310facd792c3c26728ba83db7cc9a35989726240d0266898565f',
                                'private-tree-1-receipt.json': '743c877bed83880913407b2b62d91021daf77db4f9865ed26d0fd24e13fee437',
                                'private-tree-2-intent.json': '06c2b87bff2afecdf8f54ae7bdf503309a57fc9284baa44ac8ad8f7f68ed3315',
                                'private-tree-2-receipt.json': '3956208da096c28ee116335ec159eea63a383e5b18cb43cc271168e6d8d64fec',
                                'private-tree-3-intent.json': 'ac4690423bc631a1c737b511f19a337078228d8dcb2f346ade59dc68ec7e0517',
                                'private-tree-3-receipt.json': '72994ae433e34a2230a0af786f31da2edc26144dc35f71b5e97c68d353836203',
                                'project-delete-intent.json': '45d6a916c229e6dd3e6c20528e80acf5d6c219a29e7340a6eb88acd07a6b33ea',
                                'project-delete-receipt.json': '2ab3caa3c03fd3c068df88fae9debadcac7140b7af74f09acefebc79d91a3f58'}},
 'prior_journal': {'path': '/var/lib/lightning-it/g06-runtime-root-6848ed621bfd41cbae720bc576c6eeb4/partial-retirement-d71dc962a0934be89a935b5fc94060d9',
                   'members': {'namespace-mount88-intent.json': 'c0dd63809ba49059a221a357cd5c5aab32698886c19e7693b5d4bb5f14ba9376',
                               'namespace-mount88-unknown.json': '3195af5cfa9f34d9699dd1efc6cb6b836d7d34fefb45cd3728120c0e60d9e798'}},
 'certificate_receipt': {'path': '/var/lib/lightning-it/g06-runtime-root-6848ed621bfd41cbae720bc576c6eeb4/certificate-withdrawal-24fdf580f89741efb0eb519cbf2efd37/certificate-withdrawal-receipt.json',
                         'sha256': '7ed820afe5f84b9cfced1453067eb6f108d39751b40282981637046a4c084fad'},
 'veth_receipt': {'path': '/var/lib/lightning-it/g06-runtime-root-6848ed621bfd41cbae720bc576c6eeb4/veth-withdrawal-efb501261f194cf58e17df7e3d8b9004/veth-withdrawal-receipt.json',
                  'sha256': 'b22fa4eeec89a4a02fac0e42101d7728f502d626b259a6d46ddbeccb45a12e5d'},
 'retain_until': 1795062671}


def _validate_ninth_retirement(value):
    engine_policy._keys(value, {"schema", "kind", *NINTH_RETIRED_PARTIAL, "catalogues"})
    require(type(value["schema"]) is int and value["schema"] == 1
            and value["kind"] == "original-ninth-partial-separately-retired-unknown-preserved",
            "continuation-ninth-retirement-purpose")
    # Canonical byte equality also rejects bool/int substitutions in fixed
    # device, inode, deadline and record fields. No old UNKNOWN becomes closed.
    for key, expected in NINTH_RETIRED_PARTIAL.items():
        require(ledger.canonical(value[key]) == ledger.canonical(expected),
                "continuation-ninth-retirement-fixed-history")
    catalogues = engine_policy._keys(value["catalogues"],
        {"native_intake_catalogue", "native_run_configuration_catalogue"})
    for kind, entry in (("native_intake_catalogue", value["intake"]),
                        ("native_run_configuration_catalogue", value["configuration"])):
        rows = catalogues[kind]
        require(type(rows) is dict and 0 < len(rows) <= 256
                and rows.get(entry["name"]) == entry["inventory_sha256"],
                "continuation-ninth-retirement-catalogue")
        for name, sha in rows.items():
            require(type(name) is str and re.fullmatch("[0-9a-f]{64}", name),
                    "continuation-ninth-retirement-catalogue-name")
            engine_policy._hash(sha)
    return value


def _validate_ninth_retired_partial_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "previous_qualification", "native_ninth", "retirement"})
    require(type(value["schema"]) is int and value["schema"] == 9
            and value["purpose"] == "g06-ninth-failed-partial-separate-retirement-complete-history",
            "continuation-ninth-qualification")
    previous = value["previous_qualification"]
    require(type(previous) is dict and type(previous.get("schema")) is int and previous["schema"] == 8
            and ledger.digest(previous) == NINTH_PREVIOUS_QUALIFICATION,
            "continuation-ninth-preserved-eight-history")
    counts = _validate_eighth_prelease_qualification(previous)
    require(ledger.digest(value["native_ninth"]) == NINTH_GRAPH,
            "continuation-ninth-preserved-native-graph")
    retirement = _validate_ninth_retirement(value["retirement"])
    old = previous["failed_prefix"]["catalogues"]
    for kind, entry in (("native_intake_catalogue", retirement["intake"]),
                        ("native_run_configuration_catalogue", retirement["configuration"])):
        actual = retirement["catalogues"][kind]
        require(entry["name"] not in old[kind]
                and set(actual) == set(old[kind]) | {entry["name"]}
                and all(actual[name] == sha for name, sha in old[kind].items()),
                "continuation-ninth-preserved-catalogues")
    return counts


# The isolated workflow on Validation Main and its exact Supplementary caller.
NINTH_SUCCESSOR_WORKFLOW = "68eac383ebec4462071398bef54831e7199d1e924482dc9c267809f993684fc3"
NINTH_SUCCESSOR_REUSABLE = "eeb932bf8a2a064a78161925182a3141df489790"


def _validate_ninth_retired_partial_descriptor(value, workflow_sha256, reusable_sha):
    require(type(NINTH_SUCCESSOR_WORKFLOW) is str and re.fullmatch("[0-9a-f]{64}", NINTH_SUCCESSOR_WORKFLOW)
            and NINTH_SUCCESSOR_WORKFLOW not in {NINTH_WORKFLOW, "0" * 64}
            and type(NINTH_SUCCESSOR_REUSABLE) is str and re.fullmatch("[0-9a-f]{40}", NINTH_SUCCESSOR_REUSABLE)
            and NINTH_SUCCESSOR_REUSABLE not in {NINTH_REUSABLE, "0" * 40},
            "continuation-ninth-successor-pins-unbound")
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    require(type(value["schema"]) is int and value["schema"] == 9
            and value["reason"] == "original-partial-preparation-separately-retired-unknown-preserved",
            "continuation-ninth-purpose")
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"]); engine_policy._hash(ref["sha256"])
    row = engine_policy._keys(value["successor"], {"source_sha", "run_id", "run_attempt", "first_parent",
                                                  "source_workflow_sha256", "reusable_sha"})
    cell_contract._commit(row["source_sha"])
    engine_policy._integer(row["run_id"], 1, 2**63 - 1)
    require(row["source_sha"] not in {INITIAL_MAIN, ORIGIN_MAIN, PRIOR_MAIN, THIRD_MAIN, FOURTH_MAIN,
                                    FIFTH_MAIN, SIXTH_MAIN, SEVENTH_MAIN, EIGHTH_MAIN, NINTH_MAIN}
            and row["run_id"] not in {ORIGIN_RUN, PRIOR_RUN, THIRD_RUN, FOURTH_RUN, FIFTH_RUN,
                                    SIXTH_RUN, SEVENTH_RUN, EIGHTH_RUN, NINTH_RUN}
            and type(row["run_attempt"]) is int and row["run_attempt"] == 1
            and row["first_parent"] == NINTH_MAIN
            and row["source_workflow_sha256"] == workflow_sha256 == NINTH_SUCCESSOR_WORKFLOW
            and row["reusable_sha"] == reusable_sha == NINTH_SUCCESSOR_REUSABLE,
            "continuation-ninth-successor")
    return value


def ninth_retired_partial_continuation_qualification(previous, run, inventory, checks, retirement):
    """Preserve all genuine history; never authorize replay of the failed run."""
    value = {"schema": 9, "purpose": "g06-ninth-failed-partial-separate-retirement-complete-history",
             "previous_qualification": previous, "native_ninth": ninth_native_projection(run, inventory, checks),
             "retirement": retirement}
    validate_continuation_qualification(value)
    return value

# A new protected-main push may follow the captured terminal attempt. The private
# qualification includes the exact earlier bootstrap bytes and its original bank.
TENTH_MAIN = "5604f19544f97b572272496fd61f5c4949d45fba"
TENTH_RUN = 44677270629
TENTH_CHECKS = (136092710776, 136093110422, 136092711591, 136092711786,
                136093566695, 136093593473, 136093593880, 136093593863)
TENTH_GRAPH = "b6adbcf86e247018cf8cfa4d323c2d714d67a4aa4cc790facf11856b0bd5bfe8"
TENTH_QUALIFICATION = "e3c4f3698863028ecab61b0566992cb09016d0e1e7945cd17138858adbc767a1"
TENTH_SUCCESSOR_WORKFLOW = "de43f184e7f11e8099176cf91250b2f51ad3d4578a56d431e9dd17d692e76e4a"
TENTH_SUCCESSOR_REUSABLE = "ade2ad12b4b6daa90332f1a7c087ed61ae6bed57"


def _validate_tenth_qualification(value):
    require(ledger.digest(value) == TENTH_QUALIFICATION, "continuation-tenth-history")
    previous = value["previous_qualification"]
    old = value["previous_bootstrap"]
    route = old["operating_continuation"]
    require(value["purpose"] == "terminal-original-push-without-lease-or-catalogue-addition"
            and ledger.digest(value["native_tenth"]) == TENTH_GRAPH
            and old["ledger_path"] == value["previous_bank"]["path"]
            and route["qualification"]["sha256"] == ledger.digest(previous)
            and route["successor"]["source_sha"] == TENTH_MAIN
            and route["successor"]["run_id"] == TENTH_RUN, "continuation-tenth-original")
    _validate_ninth_retired_partial_descriptor(route, old["source_workflow_sha256"],
                                              old["source_identity"]["reusable_sha"])
    return _validate_ninth_retired_partial_qualification(previous)


def _validate_tenth_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == "terminal-original-push-without-lease-or-catalogue-addition"
            and ref["sha256"] == TENTH_QUALIFICATION, "continuation-tenth-qualification")
    _validate_pinned_operating_successor(value["successor"], workflow_sha256, reusable_sha,
                                         first_parent=TENTH_MAIN, expected_workflow=TENTH_SUCCESSOR_WORKFLOW,
                                         expected_reusable=TENTH_SUCCESSOR_REUSABLE,
                                         reason="continuation-tenth-successor")
    return value


def _validate_pinned_operating_successor(value, workflow_sha256, reusable_sha, *, first_parent,
                                         expected_workflow, expected_reusable, reason):
    row = engine_policy._keys(value, {"source_sha", "run_id", "run_attempt", "first_parent",
                                     "source_workflow_sha256", "reusable_sha"})
    cell_contract._commit(row["source_sha"])
    engine_policy._integer(row["run_id"], 1, 2**63 - 1)
    require(first_parent != ELEVENTH_MAIN or (row["source_sha"] != ELEVENTH_MAIN and row["run_id"] != ELEVENTH_RUN),
            reason)
    require(row["source_sha"] not in {INITIAL_MAIN, ORIGIN_MAIN, PRIOR_MAIN, THIRD_MAIN, FOURTH_MAIN,
                                      FIFTH_MAIN, SIXTH_MAIN, SEVENTH_MAIN, EIGHTH_MAIN, NINTH_MAIN, TENTH_MAIN}
            and row["run_id"] not in {ORIGIN_RUN, PRIOR_RUN, THIRD_RUN, FOURTH_RUN, FIFTH_RUN,
                                      SIXTH_RUN, SEVENTH_RUN, EIGHTH_RUN, NINTH_RUN, TENTH_RUN}
            and type(row["run_attempt"]) is int and row["run_attempt"] == 1
            and row["first_parent"] == first_parent
            and row["source_workflow_sha256"] == workflow_sha256 == expected_workflow
            and row["reusable_sha"] == reusable_sha == expected_reusable, reason)


# The original push reached Runner01 but failed before creating an Incus VM.
# Its closed record and sealed archives must survive admission of a new push.
ELEVENTH_MAIN = "e403e0fffa9318be82718b29e854ab7a3a6da98c"
ELEVENTH_RUN = 44798038407
ELEVENTH_CHECKS = (136510803073, 136514056559)
ELEVENTH_GRAPH = "c7f0988cb252ff9a7203e9593ea3432502280f161c999700aa2abaf14f7f9b74"
ELEVENTH_QUALIFICATION = "0ceb1f233f79cca0f5f57cfb6a728ab06b6da3857dc724e170209f3dde95e491"
ELEVENTH_REASON = "terminal-original-push-with-verified-partial-cleanup"
ELEVENTH_SUCCESSOR_WORKFLOW = "d388b0bd45674d3034845a569458440edfbcc1e854e9ded7696a6287cd950950"
ELEVENTH_SUCCESSOR_REUSABLE = "45b0b8264d74d56ab9624d009541965e06d7693f"


def eleventh_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, TENTH_SUCCESSOR_REUSABLE,
                                       ELEVENTH_GRAPH, ELEVENTH_CHECKS, ELEVENTH_MAIN)


def _validate_eleventh_qualification(value):
    require(ledger.digest(value) == ELEVENTH_QUALIFICATION, "continuation-eleventh-history")
    engine_policy._keys(value, {"schema", "purpose", "previous_qualification", "native_eleventh", "retirement"})
    require(value["purpose"] == ELEVENTH_REASON and ledger.digest(value["native_eleventh"]) == ELEVENTH_GRAPH,
            "continuation-eleventh-original")
    previous = value["previous_qualification"]
    counts = _validate_tenth_qualification(previous)
    retirement = value["retirement"]
    old = previous["previous_qualification"]["retirement"]["catalogues"]
    for kind, entries in old.items():
        entry = retirement["new_entries"][kind]
        require(entry["name"] not in entries and len(entries) < 256
                and retirement["catalogues"][kind] == {**entries, entry["name"]: entry["inventory_sha256"]},
                "continuation-eleventh-preserved-catalogues")
    return counts


def _validate_eleventh_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == ELEVENTH_REASON and ref["sha256"] == ELEVENTH_QUALIFICATION,
            "continuation-eleventh-qualification")
    _validate_pinned_operating_successor(value["successor"], workflow_sha256, reusable_sha,
                                         first_parent=ELEVENTH_MAIN, expected_workflow=ELEVENTH_SUCCESSOR_WORKFLOW,
                                         expected_reusable=ELEVENTH_SUCCESSOR_REUSABLE,
                                         reason="continuation-eleventh-successor")
    return value


TWELFTH_MAIN = "69d2ccf034dfe5c64c0fda8fc037569fc9b96ff6"
TWELFTH_RUN = 44909796917
TWELFTH_CHECKS = (136864933655, 136866495868)
TWELFTH_GRAPH = "5381057a5ddd222401b10d1cd114d21eed602f2057154b19aa0fcca38acb569c"
TWELFTH_REASON = "terminal-original-push-with-unknown-engine-start-and-separate-retirement"
TWELFTH_LEASE = "7c988015f5e34b5486897abd918e03df"
TWELFTH_RETAIN_UNTIL = 1795283506
# The retired predecessor and exact source/reusable workflow bytes bind this release.
TWELFTH_QUALIFICATION = "c8711049f60a2eb3c5f9d0c7ec5523105599e9f1e7916ffcc4409597126cb322"
TWELFTH_SUCCESSOR_WORKFLOW = "5e0836f7f60a19cfd21ce5e66c709f4351f38a925dc02b639c74ab0194a1b446"
TWELFTH_SUCCESSOR_REUSABLE = "adad3057ede6e12a9a5ff02de8f762467f5fad60"


def twelfth_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, ELEVENTH_SUCCESSOR_REUSABLE,
                                       TWELFTH_GRAPH, TWELFTH_CHECKS, TWELFTH_MAIN)


def _validate_twelfth_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == TWELFTH_REASON
            and engine_policy._hash(ref["sha256"]) == TWELFTH_QUALIFICATION,
            "continuation-twelfth-qualification")
    _validate_pinned_operating_successor(value["successor"], workflow_sha256, reusable_sha,
                                         first_parent=TWELFTH_MAIN, expected_workflow=TWELFTH_SUCCESSOR_WORKFLOW,
                                         expected_reusable=TWELFTH_SUCCESSOR_REUSABLE,
                                         reason="continuation-twelfth-successor")
    row = value["successor"]
    require(row["source_sha"] not in {ELEVENTH_MAIN, TWELFTH_MAIN}
            and row["run_id"] not in {ELEVENTH_RUN, TWELFTH_RUN},
            "continuation-twelfth-replay")
    return value


def _validate_twelfth_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "previous_qualification", "native_twelfth", "retirement"})
    require(ledger.digest(value) == TWELFTH_QUALIFICATION, "continuation-twelfth-history")
    require(value["purpose"] == TWELFTH_REASON and ledger.digest(value["native_twelfth"]) == TWELFTH_GRAPH,
            "continuation-twelfth-original")
    previous = value["previous_qualification"]
    counts = _validate_eleventh_qualification(previous)
    retirement = engine_policy._keys(value["retirement"], {
        "schema", "kind", "original_bootstrap", "original_bank", "original_record",
        "new_entries", "catalogues", "journal", "retain_until",
    })
    require(type(retirement["schema"]) is int and retirement["schema"] == 1
            and retirement["kind"] == "separate-retirement-with-unknown-engine-start-preserved"
            and type(retirement["retain_until"]) is int and retirement["retain_until"] == TWELFTH_RETAIN_UNTIL,
            "continuation-twelfth-retirement")
    original = engine_policy._keys(retirement["original_record"], {"lease_id", "sha256", "unknown_effect_id"})
    require(original["lease_id"] == TWELFTH_LEASE and type(original["unknown_effect_id"]) is str
            and ledger.ID.fullmatch(original["unknown_effect_id"]), "continuation-twelfth-original-record")
    engine_policy._hash(original["sha256"])
    for name, digest_key in (("original_bootstrap", "sha256"), ("original_bank", "state_file_sha256")):
        pinned = engine_policy._keys(retirement[name], {"path", "device", "inode", digest_key})
        engine_policy._path(pinned["path"])
        engine_policy._hash(pinned[digest_key])
        engine_policy._integer(pinned["device"], 1, 2**63 - 1)
        engine_policy._integer(pinned["inode"], 1, 2**63 - 1)
    journal = retirement["journal"]
    has_continuation = type(journal) is dict and "continuation" in journal
    engine_policy._keys(journal, {"path", "members", "continuation"} if has_continuation else {"path", "members"})
    journals = [journal]
    if has_continuation:
        journals.append(engine_policy._keys(journal["continuation"], {"path", "members"}))
    for index, ref in enumerate(journals):
        engine_policy._path(ref["path"])
        members = ref["members"]
        required = "namespace-mounts-unknown.json" if has_continuation and index == 0 else "complete-receipt.json"
        require(type(members) is dict and required in members and 3 <= len(members) <= 64,
                "continuation-twelfth-journal-members")
        for name, digest in members.items():
            require(type(name) is str and re.fullmatch(r"[a-z0-9-]+\.json", name),
                    "continuation-twelfth-journal-member-name")
            engine_policy._hash(digest)
    old = previous["retirement"]["catalogues"]
    new_entries = engine_policy._keys(retirement["new_entries"], set(old))
    catalogues = engine_policy._keys(retirement["catalogues"], set(old))
    for kind, entries in old.items():
        entry = engine_policy._keys(new_entries[kind], {"name", "device", "inode", "receipt_sha256", "inventory_sha256"})
        engine_policy._hash(entry["name"])
        engine_policy._hash(entry["receipt_sha256"])
        engine_policy._hash(entry["inventory_sha256"])
        engine_policy._integer(entry["device"], 1, 2**63 - 1)
        engine_policy._integer(entry["inode"], 1, 2**63 - 1)
        require(entry["name"] not in entries and len(entries) < 256
                and catalogues[kind] == {**entries, entry["name"]: entry["inventory_sha256"]},
                "continuation-twelfth-preserved-catalogues")
    return counts


THIRTEENTH_MAIN = "e42b0cdd65536e3749f6c405ec23955e5aaa419b"
THIRTEENTH_RUN = 44976939672
THIRTEENTH_CHECKS = (137070844808, 137080117755)
THIRTEENTH_GRAPH = "3dfb6a35a49541edc808210ab237ca72e76501cd981b054715082bf3149d12c9"
THIRTEENTH_QUALIFICATION = "4ff9b14302933065d415ec9a5b4af80de05751f146124d37249767c5ce881462"
THIRTEENTH_REASON = "terminal-native-census-hold-with-sealed-intake-and-no-lease"
THIRTEENTH_SUCCESSOR_WORKFLOW = "2c1659c03115a856f4e532fab2d6a53c76cfb48d83e3cc630c1e0338bb8039e7"
THIRTEENTH_SUCCESSOR_REUSABLE = "a936e9ea75af84e6b47fc23cd8f11f8a000a52ed"


def thirteenth_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, TWELFTH_SUCCESSOR_REUSABLE,
                                       THIRTEENTH_GRAPH, THIRTEENTH_CHECKS, THIRTEENTH_MAIN)


def _validate_thirteenth_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == THIRTEENTH_REASON and ref["sha256"] == THIRTEENTH_QUALIFICATION,
            "continuation-thirteenth-qualification")
    successor = value["successor"]
    _validate_pinned_operating_successor(successor, workflow_sha256, reusable_sha,
                                         first_parent=THIRTEENTH_MAIN, expected_workflow=THIRTEENTH_SUCCESSOR_WORKFLOW,
                                         expected_reusable=THIRTEENTH_SUCCESSOR_REUSABLE,
                                         reason="continuation-thirteenth-successor")
    require(successor["source_sha"] not in {ELEVENTH_MAIN, TWELFTH_MAIN, THIRTEENTH_MAIN}
            and successor["run_id"] not in {ELEVENTH_RUN, TWELFTH_RUN, THIRTEENTH_RUN},
            "continuation-thirteenth-replay")
    return value


def _validate_thirteenth_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_thirteenth", "previous_qualification", "retirement"})
    require(ledger.digest(value) == THIRTEENTH_QUALIFICATION and value["purpose"] == THIRTEENTH_REASON
            and ledger.digest(value["native_thirteenth"]) == THIRTEENTH_GRAPH, "continuation-thirteenth-history")
    previous = value["previous_qualification"]
    counts = _validate_twelfth_qualification(previous)
    retirement = engine_policy._keys(value["retirement"], {
        "schema", "kind", "original_bootstrap", "original_bank", "intake", "catalogues",
    })
    require(type(retirement["schema"]) is int and retirement["schema"] == 1
            and retirement["kind"] == "sealed-source-intake-with-no-configuration-or-lease",
            "continuation-thirteenth-retirement")
    entry = retirement["intake"]
    old = previous["retirement"]["catalogues"]
    config_key, intake_key = "native_run_configuration_catalogue", "native_intake_catalogue"
    require(entry["name"] not in old[intake_key] and len(old[intake_key]) < 256
            and retirement["catalogues"] == {
                config_key: old[config_key], intake_key: old[intake_key] | {entry["name"]: entry["inventory_sha256"]},
            }, "continuation-thirteenth-preserved-catalogues")
    return counts


FOURTEENTH_MAIN = "8edd19c61a8faffe10d6c570cc3ad8338750f475"
FOURTEENTH_RUN = 44999213428
FOURTEENTH_CHECKS = (137138724568, 137141031693)
FOURTEENTH_GRAPH = "2f42e82a7fc41263547a47353b8213e0941cb3c202149be6e38e5bdcb6134e62"
FOURTEENTH_QUALIFICATION = "354c326a50f7a704e1139e2a25bdca2099c2c7f9eca99e09a73a23addfebe28f"
FOURTEENTH_REASON = "terminal-native-authorization-hold-with-sealed-stage-and-config"
FOURTEENTH_SUCCESSOR_WORKFLOW = "d5291cd73e5807721d3e85ae5b10b4037d2faa2b864a518afef0b64093353246"
FOURTEENTH_SUCCESSOR_REUSABLE = "bba96362be83c030e6813d9219744a54b296c4b3"


def fourteenth_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, THIRTEENTH_SUCCESSOR_REUSABLE,
                                       FOURTEENTH_GRAPH, FOURTEENTH_CHECKS, FOURTEENTH_MAIN)


def _validate_fourteenth_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == FOURTEENTH_REASON and ref["sha256"] == FOURTEENTH_QUALIFICATION,
            "continuation-fourteenth-qualification")
    successor = value["successor"]
    _validate_pinned_operating_successor(successor, workflow_sha256, reusable_sha,
        first_parent=FOURTEENTH_MAIN, expected_workflow=FOURTEENTH_SUCCESSOR_WORKFLOW,
        expected_reusable=FOURTEENTH_SUCCESSOR_REUSABLE, reason="continuation-fourteenth-successor")
    require(successor["source_sha"] not in {ELEVENTH_MAIN, TWELFTH_MAIN, THIRTEENTH_MAIN, FOURTEENTH_MAIN}
            and successor["run_id"] not in {ELEVENTH_RUN, TWELFTH_RUN, THIRTEENTH_RUN, FOURTEENTH_RUN},
            "continuation-fourteenth-replay")
    return value


def _validate_fourteenth_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_fourteenth", "previous_qualification", "retirement"})
    require(ledger.digest(value) == FOURTEENTH_QUALIFICATION and value["purpose"] == FOURTEENTH_REASON
            and ledger.digest(value["native_fourteenth"]) == FOURTEENTH_GRAPH, "continuation-fourteenth-history")
    previous = value["previous_qualification"]
    counts = _validate_thirteenth_qualification(previous)
    retirement = engine_policy._keys(value["retirement"], {
        "schema", "kind", "original_bootstrap", "original_bank", "new_entries", "catalogues",
    })
    require(type(retirement["schema"]) is int and retirement["schema"] == 1
            and retirement["kind"] == "sealed-source-intake-and-configuration-with-no-lease",
            "continuation-fourteenth-retirement")
    old = previous["retirement"]["catalogues"]
    new = engine_policy._keys(retirement["new_entries"], set(old))
    catalogues = engine_policy._keys(retirement["catalogues"], set(old))
    for kind, entries in old.items():
        entry = engine_policy._keys(new[kind], {"name", "device", "inode", "receipt_sha256", "inventory_sha256"})
        require(entry["name"] not in entries and len(entries) < 256
                and catalogues[kind] == {**entries, entry["name"]: entry["inventory_sha256"]},
                "continuation-fourteenth-preserved-catalogues")
    return counts

FIFTEENTH_MAIN = "5759a628d9fadb258036390483cb158c8ea36570"
FIFTEENTH_RUN = 45024203618
FIFTEENTH_CHECKS = (137215600784, 137218259302)
FIFTEENTH_GRAPH = "422b4c3b5dc294c50296463120d90cc0ee83099d1853c28ba30a7e6fb5d439d4"
FIFTEENTH_LEASE = "e28020f6802145fa92d3d1221edeb8a5"
FIFTEENTH_RETAIN_UNTIL = 1795367199
FIFTEENTH_REASON = "terminal-original-push-with-separate-engine-retirement"
FIFTEENTH_QUALIFICATION = "c725a4ebbf47a82ebdad7f962ba3122b2f1ecd5e572d3f055eb737315dac377d"
FIFTEENTH_SUCCESSOR_WORKFLOW = "b123611a65bc81aeed1692175f8a29010dab4366f268cabaa87cadd5d2fa24e8"
FIFTEENTH_SUCCESSOR_REUSABLE = "46d298f20ffb597477c23ee6262887b937e2c997"
FIFTEENTH_RETIREMENT_STEPS = {
    "overlay": ("overlay-unmount",),
    "quota": ("restore-quota-mode",),
    "network": (
        "fence-withdraw", "certificate-revoke", "veth-remove", "slice-stop",
        "namespace-mounts", "namespace-alias", "graph-remove", "runroot-remove",
        "output-remove", "context-remove", "descriptor-unlink",
        "restore-engine-parent-privacy", "project-delete", "bridge-delete",
    ),
}


def fifteenth_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, FOURTEENTH_SUCCESSOR_REUSABLE,
                                       FIFTEENTH_GRAPH, FIFTEENTH_CHECKS, FIFTEENTH_MAIN)


def _validate_fifteenth_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == FIFTEENTH_REASON
            and engine_policy._hash(ref["sha256"]) == FIFTEENTH_QUALIFICATION,
            "continuation-fifteenth-qualification")
    successor = value["successor"]
    _validate_pinned_operating_successor(successor, workflow_sha256, reusable_sha,
        first_parent=FIFTEENTH_MAIN, expected_workflow=FIFTEENTH_SUCCESSOR_WORKFLOW,
        expected_reusable=FIFTEENTH_SUCCESSOR_REUSABLE, reason="continuation-fifteenth-successor")
    require(successor["source_sha"] not in {
                ELEVENTH_MAIN, TWELFTH_MAIN, THIRTEENTH_MAIN, FOURTEENTH_MAIN, FIFTEENTH_MAIN}
            and successor["run_id"] not in {
                ELEVENTH_RUN, TWELFTH_RUN, THIRTEENTH_RUN, FOURTEENTH_RUN, FIFTEENTH_RUN},
            "continuation-fifteenth-replay")
    return value


def _validate_fifteenth_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_fifteenth", "previous_qualification", "retirement"})
    require(ledger.digest(value) == FIFTEENTH_QUALIFICATION and value["purpose"] == FIFTEENTH_REASON
            and ledger.digest(value["native_fifteenth"]) == FIFTEENTH_GRAPH, "continuation-fifteenth-history")
    previous = value["previous_qualification"]
    counts = _validate_fourteenth_qualification(previous)
    retirement = engine_policy._keys(value["retirement"], {
        "original_bootstrap", "original_bank", "original_record", "new_entries", "catalogues",
        "retain_until", "journals", "storage_unique_mount_id", "namespace_cookie",
    })
    require(type(retirement["retain_until"]) is int and retirement["retain_until"] == FIFTEENTH_RETAIN_UNTIL,
            "continuation-fifteenth-retention")
    for key in ("storage_unique_mount_id", "namespace_cookie"):
        engine_policy._integer(retirement[key], 1, 2**64 - 1)
    original = engine_policy._keys(retirement["original_record"], {"lease_id", "sha256", "unknown_effect_id"})
    require(original["lease_id"] == FIFTEENTH_LEASE and type(original["unknown_effect_id"]) is str
            and ledger.ID.fullmatch(original["unknown_effect_id"]), "continuation-fifteenth-record")
    engine_policy._hash(original["sha256"])
    for name, digest_key in (("original_bootstrap", "sha256"), ("original_bank", "state_file_sha256")):
        pin = engine_policy._keys(retirement[name], {"path", "device", "inode", digest_key})
        engine_policy._path(pin["path"])
        engine_policy._hash(pin[digest_key])
        engine_policy._integer(pin["device"], 1, 2**63 - 1)
        engine_policy._integer(pin["inode"], 1, 2**63 - 1)
    journals = engine_policy._keys(retirement["journals"], set(FIFTEENTH_RETIREMENT_STEPS))
    for phase, steps in FIFTEENTH_RETIREMENT_STEPS.items():
        ref = engine_policy._keys(journals[phase], {"path", "members"})
        engine_policy._path(ref["path"])
        names = {"complete-receipt.json"} | {
            step + "-" + event + ".json" for step in steps for event in ("intent", "receipt")}
        if phase == "network":
            names.add("storage-identities.json")
        for digest in engine_policy._keys(ref["members"], names).values():
            engine_policy._hash(digest)
    old = previous["retirement"]["catalogues"]
    new = engine_policy._keys(retirement["new_entries"], set(old))
    catalogues = engine_policy._keys(retirement["catalogues"], set(old))
    for kind, entries in old.items():
        entry = engine_policy._keys(new[kind], {"name", "device", "inode", "receipt_sha256", "inventory_sha256"})
        for key in ("name", "receipt_sha256", "inventory_sha256"):
            engine_policy._hash(entry[key])
        engine_policy._integer(entry["device"], 1, 2**63 - 1)
        engine_policy._integer(entry["inode"], 1, 2**63 - 1)
        require(entry["name"] not in entries and len(entries) < 256
                and catalogues[kind] == {**entries, entry["name"]: entry["inventory_sha256"]},
                "continuation-fifteenth-preserved-catalogues")
    return counts


SIXTEENTH_MAIN = "a2d4a7e906eec88b250af82375d82592f9b2380f"
SIXTEENTH_RUN = 45085259936
SIXTEENTH_CHECKS = (137404610169, 137405299914)
SIXTEENTH_REASON = "terminal-original-push-without-lease-or-catalogue-addition"
SIXTEENTH_GRAPH = "d650cb3b6fb878cd17c0b667fe7884804b468d88fe69cfda53cecc3008d095e7"
SIXTEENTH_QUALIFICATION = "ea9f386f158e637bc697a9788200d40b8d64940c3c97f604c8bb444258defa2d"
SIXTEENTH_SUCCESSOR_WORKFLOW = "3589b6749d089954300842fb14734c72ffae9c7222bc395a1c2cf898956e40be"
SIXTEENTH_SUCCESSOR_REUSABLE = "4cda41fb461c16450a32e7d3f3759a180709cb31"


def sixteenth_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, FIFTEENTH_SUCCESSOR_REUSABLE,
                                       SIXTEENTH_GRAPH, SIXTEENTH_CHECKS, SIXTEENTH_MAIN)


def _validate_sixteenth_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == SIXTEENTH_REASON and engine_policy._hash(ref["sha256"]) == SIXTEENTH_QUALIFICATION,
            "continuation-sixteenth-qualification")
    engine_policy._hash(SIXTEENTH_SUCCESSOR_WORKFLOW)
    cell_contract._commit(SIXTEENTH_SUCCESSOR_REUSABLE)
    successor = value["successor"]
    _validate_pinned_operating_successor(successor, workflow_sha256, reusable_sha,
        first_parent=SIXTEENTH_MAIN, expected_workflow=SIXTEENTH_SUCCESSOR_WORKFLOW,
        expected_reusable=SIXTEENTH_SUCCESSOR_REUSABLE, reason="continuation-sixteenth-successor")
    require(successor["source_sha"] not in {
                ELEVENTH_MAIN, TWELFTH_MAIN, THIRTEENTH_MAIN, FOURTEENTH_MAIN, FIFTEENTH_MAIN, SIXTEENTH_MAIN}
            and successor["run_id"] not in {
                ELEVENTH_RUN, TWELFTH_RUN, THIRTEENTH_RUN, FOURTEENTH_RUN, FIFTEENTH_RUN, SIXTEENTH_RUN},
            "continuation-sixteenth-replay")
    return value


def _validate_sixteenth_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_sixteenth", "previous_qualification",
                                "previous_bootstrap", "previous_bank"})
    require(value["purpose"] == SIXTEENTH_REASON and ledger.digest(value) == SIXTEENTH_QUALIFICATION
            and ledger.digest(value["native_sixteenth"]) == SIXTEENTH_GRAPH, "continuation-sixteenth-history")
    for field, digest in (("previous_bootstrap", "sha256"), ("previous_bank", "state_file_sha256")):
        pin = engine_policy._keys(value[field], {"path", "device", "inode", digest})
        engine_policy._path(pin["path"])
        engine_policy._hash(pin[digest])
        for identity_field in ("device", "inode"):
            engine_policy._integer(pin[identity_field], 1, 2**63 - 1)
    return _validate_fifteenth_qualification(value["previous_qualification"])


SEVENTEENTH_MAIN = "33c97bee9d37f3b1901765d5ffc59a79823c7534"
SEVENTEENTH_RUN = 45110790880
SEVENTEENTH_CHECKS = (137485730652, 137488932073)
SEVENTEENTH_GRAPH = "c2956fd4ebde1258a7d84d1718be5cee64c2c32225642762541bf58c972f1289"
SEVENTEENTH_LEASE = "8b087f520acebd1b443d6c11db2e5cee"
SEVENTEENTH_RETAIN_UNTIL = 1795422986
SEVENTEENTH_REASON = "terminal-original-push-after-podman-cid-retirement"
# Published from actual receipts and protected workflow bytes. The local
# preparation cannot admit a successor while any of these pins is absent.
SEVENTEENTH_QUALIFICATION = "44562a56aa673ff1d925796eca7ab984b6c6808f088a2880f9f5c1d9b25c5301"
SEVENTEENTH_SUCCESSOR_WORKFLOW = "074ebc19879525fb73cb50491a05d40bf2f5002192c34820210f4439de4f0244"
SEVENTEENTH_SUCCESSOR_REUSABLE = "39c83ce8bbfda2fbf3c702522c986ed3b993eee4"
SEVENTEENTH_RETIREMENT_STEPS = (
    "fence-withdraw", "certificate-revoke", "veth-remove", "slice-stop",
    "namespace-mounts", "namespace-alias", "graph-remove", "runroot-remove",
    "output-remove", "context-remove", "descriptor-unlink", "project-delete", "bridge-delete",
)


def seventeenth_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, SIXTEENTH_SUCCESSOR_REUSABLE,
                                       SEVENTEENTH_GRAPH, SEVENTEENTH_CHECKS, SEVENTEENTH_MAIN)


def _validate_seventeenth_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == SEVENTEENTH_REASON and engine_policy._hash(ref["sha256"]) == SEVENTEENTH_QUALIFICATION,
            "continuation-seventeenth-qualification")
    engine_policy._hash(SEVENTEENTH_SUCCESSOR_WORKFLOW)
    cell_contract._commit(SEVENTEENTH_SUCCESSOR_REUSABLE)
    successor = value["successor"]
    _validate_pinned_operating_successor(successor, workflow_sha256, reusable_sha,
        first_parent=SEVENTEENTH_MAIN, expected_workflow=SEVENTEENTH_SUCCESSOR_WORKFLOW,
        expected_reusable=SEVENTEENTH_SUCCESSOR_REUSABLE, reason="continuation-seventeenth-successor")
    require(successor["source_sha"] not in {
                ELEVENTH_MAIN, TWELFTH_MAIN, THIRTEENTH_MAIN, FOURTEENTH_MAIN,
                FIFTEENTH_MAIN, SIXTEENTH_MAIN, SEVENTEENTH_MAIN}
            and successor["run_id"] not in {
                ELEVENTH_RUN, TWELFTH_RUN, THIRTEENTH_RUN, FOURTEENTH_RUN,
                FIFTEENTH_RUN, SIXTEENTH_RUN, SEVENTEENTH_RUN},
            "continuation-seventeenth-replay")
    return value


def _validate_seventeenth_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_seventeenth", "previous_qualification", "retirement"})
    require(value["purpose"] == SEVENTEENTH_REASON and ledger.digest(value) == SEVENTEENTH_QUALIFICATION
            and ledger.digest(value["native_seventeenth"]) == SEVENTEENTH_GRAPH,
            "continuation-seventeenth-history")
    previous = value["previous_qualification"]
    catalogue_identities = _validate_sixteenth_qualification(previous)
    _validate_oci_retirement(value["retirement"], previous["previous_qualification"]["retirement"]["catalogues"],
                             SEVENTEENTH_LEASE, SEVENTEENTH_RETAIN_UNTIL)
    return catalogue_identities


def _validate_oci_retirement(retirement, old_catalogues, lease_id, retain_until, *, bound_exit=False,
                             verified_start=False, image_copy=False):
    retirement = engine_policy._keys(retirement, {
        "original_bootstrap", "original_bank", "original_record", "new_entries", "catalogues",
        "retain_until", "journal", "storage_unique_mount_id", "namespace_cookie",
    })
    require(type(retirement["retain_until"]) is int and retirement["retain_until"] == retain_until,
            "continuation-seventeenth-retention")
    for key in ("storage_unique_mount_id", "namespace_cookie"):
        engine_policy._integer(retirement[key], 1, 2**64 - 1)
    effect_field = "start_effect_id" if verified_start else "unknown_effect_id"
    origin_fields = {"lease_id", "sha256", effect_field}
    if bound_exit or verified_start:
        origin_fields.add("engine_exit_sha256")
    origin = engine_policy._keys(retirement["original_record"], origin_fields)
    require(origin["lease_id"] == lease_id and type(origin[effect_field]) is str
            and ledger.ID.fullmatch(origin[effect_field]), "continuation-seventeenth-record")
    engine_policy._hash(origin["sha256"])
    if bound_exit or verified_start:
        engine_policy._hash(origin["engine_exit_sha256"])
    for name, digest_key in (("original_bootstrap", "sha256"), ("original_bank", "state_file_sha256")):
        fields = {"path", "device", "inode", digest_key}
        if verified_start and name == "original_bank":
            fields.add("state_file_identity")
        pin = engine_policy._keys(retirement[name], fields)
        if "state_file_identity" in pin:
            physical = engine_policy._keys(pin["state_file_identity"], {"device", "inode", "stamp"})
            for key in ("device", "inode"):
                engine_policy._integer(physical[key], 1, 2**64 - 1)
            require(type(physical["stamp"]) is list and len(physical["stamp"]) >= 2
                    and all(type(part) is int for part in physical["stamp"])
                    and physical["stamp"][:2] == [physical["device"], physical["inode"]],
                    "continuation-nineteenth-file-identity")
        engine_policy._path(pin["path"])
        engine_policy._hash(pin[digest_key])
        engine_policy._integer(pin["device"], 1, 2**63 - 1)
        engine_policy._integer(pin["inode"], 1, 2**63 - 1)
    journal = engine_policy._keys(retirement["journal"], {"path", "members"})
    engine_policy._path(journal["path"])
    steps = NINETEENTH_RETIREMENT_STEPS if verified_start else SEVENTEENTH_RETIREMENT_STEPS
    if image_copy:
        require(verified_start is True, "continuation-twenty-first-image-proof-domain")
        steps = TWENTY_FIRST_RETIREMENT_STEPS
    names = {"complete-receipt.json", "storage-identities.json"} | {
        f"{step}-{phase}.json" for step in steps for phase in ("intent", "receipt")}
    if bound_exit or verified_start:
        names.add("podman-container-absence.json")
    if verified_start:
        names.add("diagnostic-archive.json")
    for digest in engine_policy._keys(journal["members"], names).values():
        engine_policy._hash(digest)
    additions = engine_policy._keys(retirement["new_entries"], set(old_catalogues))
    catalogues = engine_policy._keys(retirement["catalogues"], set(old_catalogues))
    for kind, entries in old_catalogues.items():
        entry = engine_policy._keys(additions[kind], {"name", "device", "inode", "receipt_sha256", "inventory_sha256"})
        for key in ("name", "receipt_sha256", "inventory_sha256"):
            engine_policy._hash(entry[key])
        engine_policy._integer(entry["device"], 1, 2**63 - 1)
        engine_policy._integer(entry["inode"], 1, 2**63 - 1)
        require(entry["name"] not in entries and len(entries) < 256
                and catalogues[kind] == {**entries, entry["name"]: entry["inventory_sha256"]},
                "continuation-seventeenth-preserved-catalogues")


EIGHTEENTH_MAIN = "d2490ec0841ff5c372840aae06ce75a3d5a3f627"
EIGHTEENTH_RUN = 45195208712
EIGHTEENTH_CHECKS = (137770183949, 137778977498)
EIGHTEENTH_GRAPH = "d14cdb29831c56d750fbb13d9448e46e526b214165adba61221f5237920c8c11"
EIGHTEENTH_LEASE = "1e53744b864f8c6d35e749cc448ed27e"
EIGHTEENTH_RETAIN_UNTIL = 1795460162
EIGHTEENTH_REASON = "terminal-original-push-after-podman-oci-retirement"
# The original retirement stays unqualified until independently verified.
EIGHTEENTH_QUALIFICATION = "513285fbafad0248ef7e961f812486b4cc775de35d457456add6b0a70971a710"
EIGHTEENTH_SUCCESSOR_WORKFLOW = "b42726d328d15e39794ee1c9cc1e6a252eb3810f42e50c1c124b078295c5d50f"
EIGHTEENTH_SUCCESSOR_REUSABLE = "8119a37204a97040f035f23ab94e3ca50345b736"


def eighteenth_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, SEVENTEENTH_SUCCESSOR_REUSABLE,
                                       EIGHTEENTH_GRAPH, EIGHTEENTH_CHECKS, EIGHTEENTH_MAIN)


def _validate_eighteenth_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == EIGHTEENTH_REASON and engine_policy._hash(ref["sha256"]) == EIGHTEENTH_QUALIFICATION,
            "continuation-eighteenth-qualification")
    engine_policy._hash(EIGHTEENTH_SUCCESSOR_WORKFLOW)
    cell_contract._commit(EIGHTEENTH_SUCCESSOR_REUSABLE)
    successor = value["successor"]
    _validate_pinned_operating_successor(successor, workflow_sha256, reusable_sha,
        first_parent=EIGHTEENTH_MAIN, expected_workflow=EIGHTEENTH_SUCCESSOR_WORKFLOW,
        expected_reusable=EIGHTEENTH_SUCCESSOR_REUSABLE, reason="continuation-eighteenth-successor")
    require(successor["source_sha"] not in {
                ELEVENTH_MAIN, TWELFTH_MAIN, THIRTEENTH_MAIN, FOURTEENTH_MAIN,
                FIFTEENTH_MAIN, SIXTEENTH_MAIN, SEVENTEENTH_MAIN, EIGHTEENTH_MAIN}
            and successor["run_id"] not in {
                ELEVENTH_RUN, TWELFTH_RUN, THIRTEENTH_RUN, FOURTEENTH_RUN,
                FIFTEENTH_RUN, SIXTEENTH_RUN, SEVENTEENTH_RUN, EIGHTEENTH_RUN},
            "continuation-eighteenth-replay")
    return value


def _validate_eighteenth_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_eighteenth", "previous_qualification", "retirement"})
    require(value["purpose"] == EIGHTEENTH_REASON and ledger.digest(value) == EIGHTEENTH_QUALIFICATION
            and ledger.digest(value["native_eighteenth"]) == EIGHTEENTH_GRAPH,
            "continuation-eighteenth-history")
    previous = value["previous_qualification"]
    catalogue_identities = _validate_seventeenth_qualification(previous)
    _validate_oci_retirement(value["retirement"], previous["retirement"]["catalogues"],
                             EIGHTEENTH_LEASE, EIGHTEENTH_RETAIN_UNTIL, bound_exit=True)
    return catalogue_identities


NINETEENTH_MAIN = "8cf199eedd68e653f97a4739a5d0b2e7235f91f5"
NINETEENTH_RUN = 45339727893
NINETEENTH_CHECKS = (138263805064, 138269327657)
NINETEENTH_GRAPH = "18971d57d2954e278d8afb8824c30d8a4cb6d119e90dbfd67475cc2fe518020c"
NINETEENTH_LEASE = "b9f09d76a80d25092db1e6da05e8c3d1"
NINETEENTH_RETAIN_UNTIL = 1795516989
NINETEENTH_REASON = "terminal-original-push-after-verified-workload-retirement"
NINETEENTH_RETIREMENT_STEPS = ("fence-baseline-normalize", *SEVENTEENTH_RETIREMENT_STEPS[2:])
NINETEENTH_QUALIFICATION = "6bd9ec82331372ca561655bef4f106aa416520d49f7a01a54b9a177d86b90603"
NINETEENTH_SUCCESSOR_WORKFLOW = "78cc4dc6ad628796d0c55a5ba76310790f8b99f516fdf8adbb880d77ee1ae1a6"
NINETEENTH_SUCCESSOR_REUSABLE = "69b7f805734e4d3b08d102e7d7a25108f78da247"


def nineteenth_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, EIGHTEENTH_SUCCESSOR_REUSABLE,
                                       NINETEENTH_GRAPH, NINETEENTH_CHECKS, NINETEENTH_MAIN)


def _validate_nineteenth_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == NINETEENTH_REASON and engine_policy._hash(ref["sha256"]) == NINETEENTH_QUALIFICATION,
            "continuation-nineteenth-qualification")
    engine_policy._hash(NINETEENTH_SUCCESSOR_WORKFLOW)
    cell_contract._commit(NINETEENTH_SUCCESSOR_REUSABLE)
    successor = value["successor"]
    _validate_pinned_operating_successor(successor, workflow_sha256, reusable_sha,
        first_parent=NINETEENTH_MAIN, expected_workflow=NINETEENTH_SUCCESSOR_WORKFLOW,
        expected_reusable=NINETEENTH_SUCCESSOR_REUSABLE, reason="continuation-nineteenth-successor")
    require(successor["source_sha"] not in {
                ELEVENTH_MAIN, TWELFTH_MAIN, THIRTEENTH_MAIN, FOURTEENTH_MAIN, FIFTEENTH_MAIN,
                SIXTEENTH_MAIN, SEVENTEENTH_MAIN, EIGHTEENTH_MAIN, NINETEENTH_MAIN}
            and successor["run_id"] not in {
                ELEVENTH_RUN, TWELFTH_RUN, THIRTEENTH_RUN, FOURTEENTH_RUN, FIFTEENTH_RUN,
                SIXTEENTH_RUN, SEVENTEENTH_RUN, EIGHTEENTH_RUN, NINETEENTH_RUN},
            "continuation-nineteenth-replay")
    return value


def _validate_nineteenth_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_nineteenth", "previous_qualification", "retirement"})
    require(value["purpose"] == NINETEENTH_REASON and ledger.digest(value) == NINETEENTH_QUALIFICATION
            and ledger.digest(value["native_nineteenth"]) == NINETEENTH_GRAPH,
            "continuation-nineteenth-history")
    previous = value["previous_qualification"]
    catalogue_identities = _validate_eighteenth_qualification(previous)
    _validate_oci_retirement(value["retirement"], previous["retirement"]["catalogues"],
                             NINETEENTH_LEASE, NINETEENTH_RETAIN_UNTIL, verified_start=True)
    return catalogue_identities


TWENTIETH_MAIN = "c688be79d061d797ddbb9b2ced680b4465788eea"
TWENTIETH_RUN = 45462116592
TWENTIETH_CHECKS = (138693753733, 138698308759)
TWENTIETH_GRAPH = "c5f74bc8f39e8f7b619b71dd4204b11abc0df5c787fc17c78e464b503f7d1574"
TWENTIETH_QUALIFICATION = "68c260b7e9588a76e1be02251f09394391d8487c2bbbfbd7da90d4acc743a522"
TWENTIETH_REASON = "terminal-original-push-after-sealed-intake-without-lease"


def twentieth_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, NINETEENTH_SUCCESSOR_REUSABLE,
                                       TWENTIETH_GRAPH, TWENTIETH_CHECKS, TWENTIETH_MAIN)


def _validate_twentieth_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == TWENTIETH_REASON and engine_policy._hash(ref["sha256"]) == TWENTIETH_QUALIFICATION,
            "continuation-twentieth-qualification")
    successor = value["successor"]
    _validate_pinned_operating_successor(successor, workflow_sha256, reusable_sha,
        first_parent=TWENTIETH_MAIN, expected_workflow=NINETEENTH_SUCCESSOR_WORKFLOW,
        expected_reusable=NINETEENTH_SUCCESSOR_REUSABLE, reason="continuation-twentieth-successor")
    require(successor["source_sha"] not in {
                ELEVENTH_MAIN, TWELFTH_MAIN, THIRTEENTH_MAIN, FOURTEENTH_MAIN, FIFTEENTH_MAIN,
                SIXTEENTH_MAIN, SEVENTEENTH_MAIN, EIGHTEENTH_MAIN, NINETEENTH_MAIN, TWENTIETH_MAIN}
            and successor["run_id"] not in {
                ELEVENTH_RUN, TWELFTH_RUN, THIRTEENTH_RUN, FOURTEENTH_RUN, FIFTEENTH_RUN,
                SIXTEENTH_RUN, SEVENTEENTH_RUN, EIGHTEENTH_RUN, NINETEENTH_RUN, TWENTIETH_RUN},
            "continuation-twentieth-replay")
    return value


def _validate_twentieth_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_twentieth", "previous_qualification",
                                "previous_bootstrap", "previous_bank", "sealed_intake", "catalogues"})
    require(value["purpose"] == TWENTIETH_REASON and ledger.digest(value) == TWENTIETH_QUALIFICATION
            and ledger.digest(value["native_twentieth"]) == TWENTIETH_GRAPH,
            "continuation-twentieth-history")
    previous = value["previous_qualification"]
    catalogue_identities = _validate_nineteenth_qualification(previous)
    for field, digest in (("previous_bootstrap", "sha256"), ("previous_bank", "state_file_sha256")):
        pin = engine_policy._keys(value[field], {"path", "device", "inode", digest})
        engine_policy._path(pin["path"])
        engine_policy._hash(pin[digest])
        for coordinate in ("device", "inode"):
            engine_policy._integer(pin[coordinate], 1, 2**63 - 1)
    intake = engine_policy._keys(value["sealed_intake"],
        {"name", "device", "inode", "seal_sha256", "intent_sha256", "catalogue_sha256"})
    engine_policy._hash(intake["name"])
    for coordinate in ("device", "inode"):
        engine_policy._integer(intake[coordinate], 1, 2**63 - 1)
    for key in ("seal_sha256", "intent_sha256", "catalogue_sha256"):
        engine_policy._hash(intake[key])
    old = previous["retirement"]["catalogues"]
    catalogues = engine_policy._keys(value["catalogues"], set(old))
    require(intake["name"] not in old["native_intake_catalogue"]
            and catalogues["native_intake_catalogue"] ==
                old["native_intake_catalogue"] | {intake["name"]: intake["catalogue_sha256"]}
            and catalogues["native_run_configuration_catalogue"] == old["native_run_configuration_catalogue"],
            "continuation-twentieth-catalogue-extension")
    return catalogue_identities


TWENTY_FIRST_MAIN = "3dd9d0071f3af477e2a560ce1add7b6f6954d8e7"
TWENTY_FIRST_RUN = 45485652188
TWENTY_FIRST_CHECKS = (138775231413, 138782155173)
TWENTY_FIRST_GRAPH = "bb66aef25f2c934d52e3e95823775b3d18ff238720c58ffe0e92951551dde1ad"
TWENTY_FIRST_LEASE = "79500cdfe5ff0bdfbbe7f5eab75e6579"
TWENTY_FIRST_RETAIN_UNTIL = 1795569267
TWENTY_FIRST_REASON = "terminal-original-push-after-private-image-retirement"
TWENTY_FIRST_RETIREMENT_STEPS = (*NINETEENTH_RETIREMENT_STEPS[:-2], "image-delete", *NINETEENTH_RETIREMENT_STEPS[-2:])
# This digest covers the original failure, sealed inputs, bank and journal path.
# The protected successor anchor binds the journal member digests after readback.
TWENTY_FIRST_SCOPE_SHA256 = "e95c1fb2e374bd46ad9e1a8d3aaf6640775068286eca623de35eabe56760cb93"


def twenty_first_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, NINETEENTH_SUCCESSOR_REUSABLE,
                                       TWENTY_FIRST_GRAPH, TWENTY_FIRST_CHECKS, TWENTY_FIRST_MAIN)


def _validate_twenty_first_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == TWENTY_FIRST_REASON, "continuation-twenty-first-qualification")
    engine_policy._hash(ref["sha256"])
    successor = value["successor"]
    _validate_pinned_operating_successor(successor, workflow_sha256, reusable_sha,
        first_parent=TWENTY_FIRST_MAIN, expected_workflow=NINETEENTH_SUCCESSOR_WORKFLOW,
        expected_reusable=NINETEENTH_SUCCESSOR_REUSABLE, reason="continuation-twenty-first-successor")
    require(successor["source_sha"] not in {
                ELEVENTH_MAIN, TWELFTH_MAIN, THIRTEENTH_MAIN, FOURTEENTH_MAIN, FIFTEENTH_MAIN,
                SIXTEENTH_MAIN, SEVENTEENTH_MAIN, EIGHTEENTH_MAIN, NINETEENTH_MAIN, TWENTIETH_MAIN,
                TWENTY_FIRST_MAIN}
            and successor["run_id"] not in {
                ELEVENTH_RUN, TWELFTH_RUN, THIRTEENTH_RUN, FOURTEENTH_RUN, FIFTEENTH_RUN,
                SIXTEENTH_RUN, SEVENTEENTH_RUN, EIGHTEENTH_RUN, NINETEENTH_RUN, TWENTIETH_RUN,
                TWENTY_FIRST_RUN}, "continuation-twenty-first-replay")
    return value


def twenty_first_scope_sha256(value):
    retirement = value["retirement"]
    return ledger.digest(value | {"retirement": retirement | {"journal": {"path": retirement["journal"]["path"]}}})


def _validate_twenty_first_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_twenty_first", "previous_qualification", "retirement"})
    require(value["purpose"] == TWENTY_FIRST_REASON and ledger.digest(value["native_twenty_first"]) == TWENTY_FIRST_GRAPH,
            "continuation-twenty-first-history")
    previous = value["previous_qualification"]
    catalogue_identities = _validate_twentieth_qualification(previous)
    _validate_oci_retirement(value["retirement"], previous["catalogues"], TWENTY_FIRST_LEASE,
                             TWENTY_FIRST_RETAIN_UNTIL, verified_start=True, image_copy=True)
    require(twenty_first_scope_sha256(value) == TWENTY_FIRST_SCOPE_SHA256, "continuation-twenty-first-original-scope")
    return catalogue_identities


TWENTY_SECOND_MAIN = "aca24665c7d0e192974e1bb030737a349c6b70db"
TWENTY_SECOND_RUN = 45524987335
TWENTY_SECOND_CHECKS = (138909370840, 138915980555)
TWENTY_SECOND_GRAPH = "55a96b7e3b9dcfac74ac9cd03f513284e1ab50cd49c938e36b7e4b5f9519b43a"
TWENTY_SECOND_LEASE = "3a6f55b37532c7746a78a2a29c3db0fc"
TWENTY_SECOND_BOOTSTRAP = "502420989d2009201ec8b322672694f5a534ce9c46c99bb751f4e1c8f5a03c52"
TWENTY_SECOND_CLOSED_RECORD = "707b664499f8a9212a7a8f32f87483a239b4d10df5f5158997c9c123efd60cfe"
TWENTY_SECOND_ARCHIVE = "0ce3aaf67724e0884a1062199a669bb39350213b74a97f19537bbc18c14fda81"
TWENTY_SECOND_REAUTHORIZATION = "e9d87d24d91594267deae0f37bcbbb9c74833fb2df76625127dcfa0f2eb63e79"
TWENTY_SECOND_REASON = "terminal-original-push-after-verified-stopped-vm-cleanup"
TWENTY_SECOND_SUCCESSOR_REUSABLE = "b25236cc594fee06854ee524d6ab87004255b70f"
TWENTY_SECOND_SUCCESSOR_WORKFLOW = "9260545a21eedf0cfc9f96b71632ab2bb04426495b7576d55d6267864e652567"
TWENTY_THIRD_MAIN = "af5a45eca7e7dcaa85af8bea3e6d77c775fd8b9a"
TWENTY_THIRD_RUN = 45634151997
TWENTY_THIRD_CHECKS = (139281015107, 139292701192)
TWENTY_THIRD_GRAPH = "a1451e46b3b14ce6c483f90b00832628f76f9c1e20016ed757e0f25026f093e3"
TWENTY_THIRD_LEASE = "f4807b68239e49b717d0a77623f87e59"
TWENTY_THIRD_BOOTSTRAP = "e5f41df9ea92c3d75500a37521035b0a4799ca21ffd2afc42bf3fb511433ab28"
TWENTY_THIRD_CLOSED_RECORD = "f0af286786b57b7cc57c26414b5c2191fd6f3bb4ebf0f18645ce4c78d4151264"
TWENTY_THIRD_ARCHIVE = "e6fe210b504b20159991640dedbf2c27aa72f1368634b3cc6900e3af749eec01"
TWENTY_THIRD_TERMINAL = "fedc4d83c09e62091943f1486c9d4dcfee036460a2f19d8bf01c4b5a7307d249"
TWENTY_THIRD_QUALIFICATION = "d0a4256e5b4df12b39baf2570094ac94e8c5b49e7303b375146981f9295dd5fa"
TWENTY_THIRD_REASON = "terminal-original-push-after-native-vm-cleanup"
TWENTY_THIRD_SUCCESSOR_REUSABLE = "14c9a0a00f64da5b531e0236c871f6a4eee8444c"
TWENTY_THIRD_SUCCESSOR_WORKFLOW = "3e209cbf72d0bd33db1734490e9556235d4b1c5cbb93dfb0ad4514fed4f4ef25"


def twenty_second_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, NINETEENTH_SUCCESSOR_REUSABLE,
                                       TWENTY_SECOND_GRAPH, TWENTY_SECOND_CHECKS, TWENTY_SECOND_MAIN)


def twenty_third_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, TWENTY_SECOND_SUCCESSOR_REUSABLE,
                                       TWENTY_THIRD_GRAPH, TWENTY_THIRD_CHECKS, TWENTY_THIRD_MAIN)


def _validate_closed_vm_descriptor(value, workflow_sha256, reusable_sha, *, native_cleanup):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    engine_policy._hash(ref["sha256"])
    if native_cleanup:
        require(ref["sha256"] == TWENTY_THIRD_QUALIFICATION, "continuation-twenty-third-qualification")
    reason = TWENTY_THIRD_REASON if native_cleanup else TWENTY_SECOND_REASON
    predecessor = TWENTY_THIRD_MAIN if native_cleanup else TWENTY_SECOND_MAIN
    expected_workflow = TWENTY_THIRD_SUCCESSOR_WORKFLOW if native_cleanup else TWENTY_SECOND_SUCCESSOR_WORKFLOW
    expected_reusable = TWENTY_THIRD_SUCCESSOR_REUSABLE if native_cleanup else TWENTY_SECOND_SUCCESSOR_REUSABLE
    require(value["reason"] == reason, "continuation-closed-vm-qualification")
    successor = value["successor"]
    _validate_pinned_operating_successor(successor, workflow_sha256, reusable_sha,
        first_parent=predecessor, expected_workflow=expected_workflow,
        expected_reusable=expected_reusable, reason="continuation-closed-vm-successor")
    require(successor["source_sha"] not in {
                ELEVENTH_MAIN, TWELFTH_MAIN, THIRTEENTH_MAIN, FOURTEENTH_MAIN, FIFTEENTH_MAIN, SIXTEENTH_MAIN,
                SEVENTEENTH_MAIN, EIGHTEENTH_MAIN, NINETEENTH_MAIN, TWENTIETH_MAIN, TWENTY_FIRST_MAIN,
                TWENTY_SECOND_MAIN}
            and successor["run_id"] not in {
                ELEVENTH_RUN, TWELFTH_RUN, THIRTEENTH_RUN, FOURTEENTH_RUN, FIFTEENTH_RUN, SIXTEENTH_RUN,
                SEVENTEENTH_RUN, EIGHTEENTH_RUN, NINETEENTH_RUN, TWENTIETH_RUN, TWENTY_FIRST_RUN,
                TWENTY_SECOND_RUN}, "continuation-closed-vm-replay")
    if native_cleanup:
        require(successor["source_sha"] != TWENTY_THIRD_MAIN and successor["run_id"] != TWENTY_THIRD_RUN,
                "continuation-twenty-third-replay")
    return value


def _validate_twenty_second_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_twenty_second", "previous_qualification", "retirement"})
    require(value["purpose"] == TWENTY_SECOND_REASON
            and ledger.digest(value["native_twenty_second"]) == TWENTY_SECOND_GRAPH,
            "continuation-twenty-second-history")
    previous = value["previous_qualification"]
    identities = _validate_twenty_first_qualification(previous)
    retired = engine_policy._keys(value["retirement"], {"original_bootstrap", "original_bank",
        "closed_record_sha256", "entries", "catalogues", "closure"})
    bootstrap = engine_policy._keys(retired["original_bootstrap"], {"path", "sha256", "device", "inode"})
    bank = engine_policy._keys(retired["original_bank"], {"path", "device", "inode", "state_file_sha256"})
    closure = engine_policy._keys(retired["closure"], {"path", "sha256"})
    for locator in (bootstrap, bank, closure):
        engine_policy._path(locator["path"])
    for locator in (bootstrap, bank):
        engine_policy._integer(locator["device"], 1, 2**63 - 1)
        engine_policy._integer(locator["inode"], 1, 2**63 - 1)
    engine_policy._hash(bank["state_file_sha256"])
    engine_policy._hash(closure["sha256"])
    require(bootstrap["sha256"] == TWENTY_SECOND_BOOTSTRAP
            and retired["closed_record_sha256"] == TWENTY_SECOND_CLOSED_RECORD
            and PurePosixPath(bootstrap["path"]).parent == PurePosixPath(bank["path"]).parent
            and PurePosixPath(closure["path"]) ==
                PurePosixPath(bootstrap["path"]).with_name("c21-no-fixed-wait-cleanup-done.json"),
            "continuation-twenty-second-original-locators")
    _validate_closed_vm_catalogues(retired, previous["retirement"]["catalogues"])
    return identities


def _validate_twenty_third_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_twenty_third", "previous_qualification", "retirement"})
    require(ledger.digest(value) == TWENTY_THIRD_QUALIFICATION and value["purpose"] == TWENTY_THIRD_REASON
            and ledger.digest(value["native_twenty_third"]) == TWENTY_THIRD_GRAPH,
            "continuation-twenty-third-history")
    previous = value["previous_qualification"]
    require(previous["schema"] == 22, "continuation-twenty-third-previous-schema")
    identities = _validate_twenty_second_qualification(previous)
    retired = engine_policy._keys(value["retirement"], {"original_bootstrap", "original_bank",
        "closed_record_sha256", "entries", "catalogues"})
    bootstrap = engine_policy._keys(retired["original_bootstrap"], {"path", "sha256", "device", "inode"})
    bank = engine_policy._keys(retired["original_bank"], {"path", "device", "inode", "state_file_sha256"})
    for locator in (bootstrap, bank):
        engine_policy._path(locator["path"])
        engine_policy._integer(locator["device"], 1, 2**63 - 1)
        engine_policy._integer(locator["inode"], 1, 2**63 - 1)
    engine_policy._hash(bank["state_file_sha256"])
    require(bootstrap["sha256"] == TWENTY_THIRD_BOOTSTRAP
            and retired["closed_record_sha256"] == TWENTY_THIRD_CLOSED_RECORD
            and PurePosixPath(bootstrap["path"]).parent == PurePosixPath(bank["path"]).parent,
            "continuation-twenty-third-original-locators")
    _validate_closed_vm_catalogues(retired, previous["retirement"]["catalogues"])
    return identities


def _validate_closed_vm_catalogues(retired, old_catalogues):
    entries = engine_policy._keys(retired["entries"], {"configuration", "intake"})
    require(set(retired["catalogues"]) == set(old_catalogues), "continuation-twenty-second-catalogues")
    for kind, catalogue in (("configuration", "native_run_configuration_catalogue"),
                            ("intake", "native_intake_catalogue")):
        entry = engine_policy._keys(entries[kind], {"name", "device", "inode", "receipt_sha256", "inventory_sha256"})
        for field in ("name", "receipt_sha256", "inventory_sha256"):
            engine_policy._hash(entry[field])
        engine_policy._integer(entry["device"], 1, 2**63 - 1)
        engine_policy._integer(entry["inode"], 1, 2**63 - 1)
        require(entry["name"] not in old_catalogues[catalogue]
                and retired["catalogues"][catalogue] ==
                    old_catalogues[catalogue] | {entry["name"]: entry["inventory_sha256"]},
                "continuation-twenty-second-catalogue-extension")


TWENTY_FOURTH_MAIN = "98157a078b130bc6daa61adb5bc76e17e4acac2c"
TWENTY_FOURTH_RUN = 45744340520
TWENTY_FOURTH_CHECKS = (139659621015, 139663517604)
TWENTY_FOURTH_GRAPH = "d878bbc303756474396a9c9542e13ac07e21df1f33c5c9c868628c3affe12007"
TWENTY_FOURTH_BOOTSTRAP = "67057bf660b69e44056e559b2182b07a4661a8ce8bbe508fff388e84d739fc95"
TWENTY_FOURTH_QUALIFICATION = "3faf1922825880df82c4fe244af13f71a87579e9d23a465c681fca8475f0e7b8"
TWENTY_FOURTH_REASON = "terminal-original-push-after-sealed-configuration-without-lease"
# Filled from the protected publication before this candidate ships.
TWENTY_FOURTH_SUCCESSOR_REUSABLE = "37a023a34f3d5e8d7b5f033c0caa06ae4f63c7f3"
TWENTY_FOURTH_SUCCESSOR_WORKFLOW = "5551752e1514190ca40fc17c7dee2f950e2f290241627c02cc97a3a32de1abb2"


def twenty_fourth_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, TWENTY_THIRD_SUCCESSOR_REUSABLE,
                                       TWENTY_FOURTH_GRAPH, TWENTY_FOURTH_CHECKS, TWENTY_FOURTH_MAIN)


def _validate_twenty_fourth_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == TWENTY_FOURTH_REASON and ref["sha256"] == TWENTY_FOURTH_QUALIFICATION,
            "continuation-twenty-fourth-qualification")
    successor = value["successor"]
    _validate_pinned_operating_successor(successor, workflow_sha256, reusable_sha,
        first_parent=TWENTY_FOURTH_MAIN, expected_workflow=TWENTY_FOURTH_SUCCESSOR_WORKFLOW,
        expected_reusable=TWENTY_FOURTH_SUCCESSOR_REUSABLE, reason="continuation-twenty-fourth-successor")
    require(successor["source_sha"] != TWENTY_FOURTH_MAIN and successor["run_id"] > TWENTY_FOURTH_RUN,
            "continuation-twenty-fourth-replay")
    return value


def _validate_twenty_fourth_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_twenty_fourth", "previous_qualification", "retirement"})
    require(value["purpose"] == TWENTY_FOURTH_REASON and ledger.digest(value) == TWENTY_FOURTH_QUALIFICATION
            and ledger.digest(value["native_twenty_fourth"]) == TWENTY_FOURTH_GRAPH,
            "continuation-twenty-fourth-history")
    previous = value["previous_qualification"]
    require(previous["schema"] == 23, "continuation-twenty-fourth-previous-schema")
    identities = _validate_twenty_third_qualification(previous)
    retired = engine_policy._keys(value["retirement"], {"original_bootstrap", "original_bank", "entries", "catalogues"})
    bootstrap = engine_policy._keys(retired["original_bootstrap"], {"path", "sha256", "device", "inode"})
    bank = engine_policy._keys(retired["original_bank"], {"path", "state_file_sha256", "device", "inode"})
    for locator in (bootstrap, bank):
        engine_policy._path(locator["path"])
        for coordinate in ("device", "inode"):
            engine_policy._integer(locator[coordinate], 1, 2**63 - 1)
    engine_policy._hash(bank["state_file_sha256"])
    require(bootstrap["sha256"] == TWENTY_FOURTH_BOOTSTRAP
            and PurePosixPath(bootstrap["path"]).parent == PurePosixPath(bank["path"]).parent,
            "continuation-twenty-fourth-original-locators")
    _validate_closed_vm_catalogues(retired, previous["retirement"]["catalogues"])
    return identities


TWENTY_FIFTH_MAIN = "e14d885efe872712030a144494b00df980acfa38"
TWENTY_FIFTH_RUN = 45786299482
TWENTY_FIFTH_CHECKS = (139797994663, 139807987143)
TWENTY_FIFTH_GRAPH = "7419656f4edbc4507557d13068a549e710d0179492e63d0a539ec8aad0088c53"
TWENTY_FIFTH_LEASE = "53cee9f417e8e69ba987c365ac027739"
TWENTY_FIFTH_BOOTSTRAP = "b48a02b15a282b671d7d7ef12b9d86fec8de654b1b9c1c2d47559763e00789e9"
TWENTY_FIFTH_CLOSED_RECORD = "8b14f7d003c0715b3b3a41cdf0b4b1a08c4eee02910b50760fef2f1694bfc3d9"
TWENTY_FIFTH_ARCHIVE = "9a6e9f60beb6934bc0a55d9bc1232eaca83188f93074b13e01e14ea4275de803"
TWENTY_FIFTH_TERMINAL = "a5de681b0ae22ab203925950bd7e376ed855c866f9555fb6c25fc253079676ae"
TWENTY_FIFTH_QUALIFICATION = "6f8f633a2308b1d5e05f0f24afa95d765f1978da5631cecd25f4a4a004e61b45"
TWENTY_FIFTH_REASON = "terminal-original-push-after-reconciled-owned-vm-cleanup"
# The local candidate cannot reserve a successor before its exact publication.
TWENTY_FIFTH_SUCCESSOR_REUSABLE = "ff6c4753af446077b1c0eedc3986c8b02bcb3159"
TWENTY_FIFTH_SUCCESSOR_WORKFLOW = "72a7a0a37a7f7b55c9205668faaa670f8cb66df26aecd480f0d5136cbae43993"


def twenty_fifth_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, TWENTY_FOURTH_SUCCESSOR_REUSABLE,
                                       TWENTY_FIFTH_GRAPH, TWENTY_FIFTH_CHECKS, TWENTY_FIFTH_MAIN)


def _validate_twenty_fifth_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == TWENTY_FIFTH_REASON and ref["sha256"] == TWENTY_FIFTH_QUALIFICATION,
            "continuation-twenty-fifth-qualification")
    successor = value["successor"]
    _validate_pinned_operating_successor(successor, workflow_sha256, reusable_sha,
        first_parent=TWENTY_FIFTH_MAIN, expected_workflow=TWENTY_FIFTH_SUCCESSOR_WORKFLOW,
        expected_reusable=TWENTY_FIFTH_SUCCESSOR_REUSABLE, reason="continuation-twenty-fifth-successor")
    require(successor["source_sha"] != TWENTY_FIFTH_MAIN and successor["run_id"] > TWENTY_FIFTH_RUN,
            "continuation-twenty-fifth-replay")
    return value


def _validate_twenty_fifth_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_twenty_fifth", "previous_qualification", "retirement"})
    require(value["purpose"] == TWENTY_FIFTH_REASON and ledger.digest(value) == TWENTY_FIFTH_QUALIFICATION
            and ledger.digest(value["native_twenty_fifth"]) == TWENTY_FIFTH_GRAPH,
            "continuation-twenty-fifth-history")
    previous = value["previous_qualification"]
    require(previous["schema"] == 24, "continuation-twenty-fifth-previous-schema")
    identities = _validate_twenty_fourth_qualification(previous)
    retired = engine_policy._keys(value["retirement"], {"original_bootstrap", "original_bank",
        "closed_record_sha256", "entries", "catalogues"})
    bootstrap = engine_policy._keys(retired["original_bootstrap"], {"path", "sha256", "device", "inode"})
    bank = engine_policy._keys(retired["original_bank"], {"path", "device", "inode", "state_file_sha256"})
    for locator in (bootstrap, bank):
        engine_policy._path(locator["path"])
        for coordinate in ("device", "inode"):
            engine_policy._integer(locator[coordinate], 1, 2**63 - 1)
    engine_policy._hash(bank["state_file_sha256"])
    require(bootstrap["sha256"] == TWENTY_FIFTH_BOOTSTRAP
            and retired["closed_record_sha256"] == TWENTY_FIFTH_CLOSED_RECORD
            and PurePosixPath(bootstrap["path"]).parent == PurePosixPath(bank["path"]).parent,
            "continuation-twenty-fifth-original-locators")
    _validate_closed_vm_catalogues(retired, previous["retirement"]["catalogues"])
    return identities


TWENTY_SIXTH_MAIN = "91f581f565ce21beb1b4ce3a59c71c8d332c951f"
TWENTY_SIXTH_RUN = 45835485677
TWENTY_SIXTH_CHECKS = (139969460344, 139980094233)
TWENTY_SIXTH_GRAPH = "4c06ef95134ed675ce609046a527dbab3164d0e58956c7549e564f852406b7bf"
TWENTY_SIXTH_LEASE = "c3cbfb0c56f1fee98d48f351226475a1"
TWENTY_SIXTH_BOOTSTRAP = "c8e7f398b90b30b7de247980fcadc4c751984a198e8552ff0a47cce94185fe67"
TWENTY_SIXTH_CLOSED_RECORD = "71ce45459438c94e989f24b60b969ec184d888d58698c73cf81c8a9b10bfdcbd"
TWENTY_SIXTH_ARCHIVE = "db3236db2009e2c83c33a69cf80966edcf28f988086c856087154d7052b44c17"
TWENTY_SIXTH_TERMINAL = "b53bec6aadd35164cdf3bb871797a6c3c2f5ae3a355be8925c5466c244e77e2c"
TWENTY_SIXTH_QUALIFICATION = "d35f77beaa1424f5ca4e5637ff0eb6168428f1d40412d333d3c411a44a9fb83d"
TWENTY_SIXTH_REASON = TWENTY_FIFTH_REASON
TWENTY_SIXTH_SUCCESSOR_REUSABLE = "0ee6d6410abaf5ceb8ceabeb5708ed2a1f112ade"
TWENTY_SIXTH_SUCCESSOR_WORKFLOW = "5461bdb0776899a271e5e251fd360737c95229c696860dc6002fc11c045f5421"


def twenty_sixth_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, TWENTY_FIFTH_SUCCESSOR_REUSABLE,
                                       TWENTY_SIXTH_GRAPH, TWENTY_SIXTH_CHECKS, TWENTY_SIXTH_MAIN)


def _validate_twenty_sixth_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    engine_policy._hash(TWENTY_SIXTH_SUCCESSOR_WORKFLOW)
    cell_contract._commit(TWENTY_SIXTH_SUCCESSOR_REUSABLE)
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == TWENTY_SIXTH_REASON and ref["sha256"] == TWENTY_SIXTH_QUALIFICATION,
            "continuation-twenty-sixth-qualification")
    successor = value["successor"]
    _validate_pinned_operating_successor(successor, workflow_sha256, reusable_sha,
        first_parent=TWENTY_SIXTH_MAIN, expected_workflow=TWENTY_SIXTH_SUCCESSOR_WORKFLOW,
        expected_reusable=TWENTY_SIXTH_SUCCESSOR_REUSABLE, reason="continuation-twenty-sixth-successor")
    require(successor["source_sha"] != TWENTY_SIXTH_MAIN and successor["run_id"] > TWENTY_SIXTH_RUN,
            "continuation-twenty-sixth-replay")
    return value


def _validate_twenty_sixth_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_twenty_sixth", "previous_qualification", "retirement"})
    require(value["purpose"] == TWENTY_SIXTH_REASON and ledger.digest(value) == TWENTY_SIXTH_QUALIFICATION
            and ledger.digest(value["native_twenty_sixth"]) == TWENTY_SIXTH_GRAPH,
            "continuation-twenty-sixth-history")
    previous = value["previous_qualification"]
    require(previous["schema"] == 25, "continuation-twenty-sixth-previous-schema")
    identities = _validate_twenty_fifth_qualification(previous)
    retired = engine_policy._keys(value["retirement"], {"original_bootstrap", "original_bank",
        "closed_record_sha256", "entries", "catalogues"})
    bootstrap = engine_policy._keys(retired["original_bootstrap"], {"path", "sha256", "device", "inode"})
    bank = engine_policy._keys(retired["original_bank"], {"path", "device", "inode", "state_file_sha256"})
    for locator in (bootstrap, bank):
        engine_policy._path(locator["path"])
        for coordinate in ("device", "inode"):
            engine_policy._integer(locator[coordinate], 1, 2**63 - 1)
    engine_policy._hash(bank["state_file_sha256"])
    require(bootstrap["sha256"] == TWENTY_SIXTH_BOOTSTRAP
            and retired["closed_record_sha256"] == TWENTY_SIXTH_CLOSED_RECORD
            and PurePosixPath(bootstrap["path"]).parent == PurePosixPath(bank["path"]).parent,
            "continuation-twenty-sixth-original-locators")
    _validate_closed_vm_catalogues(retired, previous["retirement"]["catalogues"])
    return identities


# Exact terminal source and unchanged, empty C26 bank, independently read on Runner01.
TWENTY_SEVENTH_MAIN = "462614f6c6f236383e51220828ee0b2d6af7d9c7"
TWENTY_SEVENTH_RUN = 45902045944
TWENTY_SEVENTH_CHECKS = (140194040525, 140194788856)
TWENTY_SEVENTH_GRAPH = "4ea2fae3d93b65fd85c98ba453c7a291cea8fff06ed19a52adb36652231cb37e"
TWENTY_SEVENTH_BOOTSTRAP = "44f416dc10660600813a172f41924071db07446e45378cd08031fea046afd000"
TWENTY_SEVENTH_QUALIFICATION = "0b604cb09cf45bf575686b74ea3ace157518e6dbd1cad11865f8b1a6c95f753d"
TWENTY_SEVENTH_REASON = "terminal-original-push-before-test-cell-configuration"

TWENTY_SEVENTH_SUCCESSOR_WORKFLOW = "ab4594da428e076f8ec74c318c79b60d9412a2c7683cc9442d5eb178eb09d908"
TWENTY_SEVENTH_SUCCESSOR_REUSABLE = "50f69a7c7705878eb84831516b9a3308faa6a3d3"


def twenty_seventh_native_projection(run, inventory, checks):
    return _terminal_native_projection(run, inventory, checks, TWENTY_SIXTH_SUCCESSOR_REUSABLE,
                                       TWENTY_SEVENTH_GRAPH, TWENTY_SEVENTH_CHECKS, TWENTY_SEVENTH_MAIN)


def _validate_twenty_seventh_descriptor(value, workflow_sha256, reusable_sha):
    engine_policy._keys(value, {"schema", "reason", "qualification", "successor"})
    engine_policy._hash(TWENTY_SEVENTH_SUCCESSOR_WORKFLOW)
    cell_contract._commit(TWENTY_SEVENTH_SUCCESSOR_REUSABLE)
    ref = engine_policy._keys(value["qualification"], {"path", "sha256"})
    engine_policy._path(ref["path"])
    require(value["reason"] == TWENTY_SEVENTH_REASON and ref["sha256"] == TWENTY_SEVENTH_QUALIFICATION,
            "continuation-twenty-seventh-qualification")
    successor = value["successor"]
    _validate_pinned_operating_successor(successor, workflow_sha256, reusable_sha,
        first_parent=TWENTY_SEVENTH_MAIN, expected_workflow=TWENTY_SEVENTH_SUCCESSOR_WORKFLOW,
        expected_reusable=TWENTY_SEVENTH_SUCCESSOR_REUSABLE, reason="continuation-twenty-seventh-successor")
    require(successor["source_sha"] != TWENTY_SEVENTH_MAIN and successor["run_id"] > TWENTY_SEVENTH_RUN,
            "continuation-twenty-seventh-replay")
    return value


def _validate_twenty_seventh_qualification(value):
    engine_policy._keys(value, {"schema", "purpose", "native_twenty_seventh", "previous_qualification",
                                "previous_bootstrap", "previous_bank"})
    require(value["purpose"] == TWENTY_SEVENTH_REASON and ledger.digest(value) == TWENTY_SEVENTH_QUALIFICATION
            and ledger.digest(value["native_twenty_seventh"]) == TWENTY_SEVENTH_GRAPH,
            "continuation-twenty-seventh-history")
    for field, digest in (("previous_bootstrap", "sha256"), ("previous_bank", "state_file_sha256")):
        pin = engine_policy._keys(value[field], {"path", "device", "inode", digest})
        engine_policy._path(pin["path"])
        engine_policy._hash(pin[digest])
        for coordinate in ("device", "inode"):
            engine_policy._integer(pin[coordinate], 1, 2**63 - 1)
    bootstrap, bank = value["previous_bootstrap"], value["previous_bank"]
    require(bootstrap["sha256"] == TWENTY_SEVENTH_BOOTSTRAP
            and PurePosixPath(bootstrap["path"]).parent == PurePosixPath(bank["path"]).parent
            and value["previous_qualification"]["schema"] == 26,
            "continuation-twenty-seventh-original-locators")
    return _validate_twenty_sixth_qualification(value["previous_qualification"])
