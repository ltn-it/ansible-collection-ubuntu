"""Pure closed operating-drill semantics, separate from business cells.

These checks never authenticate native JSON, establish image availability or
capacity, construct a PreparedCell, or authorize TLS/engine operations. Root
must acquire the native initial-Main commit and job identity independently.
"""
from dataclasses import dataclass
import base64
import hashlib
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


def validate_continuation_commit(commit_native, value, caller_sha, run_id, reusable_sha):
    """Exact new run/commit/first parent; this does not authenticate native JSON."""
    row = value["successor"]
    validate_continuation_descriptor(value, row["source_workflow_sha256"], reusable_sha)
    require(caller_sha == row["source_sha"] and type(run_id) is int and run_id == row["run_id"]
            and type(commit_native) is dict and commit_native.get("sha") == caller_sha,
            "continuation-exact-native-tuple")
    parents = commit_native.get("parents")
    require(type(parents) is list and 1 <= len(parents) <= 2
            and all(type(p) is dict and type(p.get("sha")) is str and re.fullmatch("[0-9a-f]{40}", p["sha"])
                    for p in parents) and parents[0]["sha"] == ({1: ORIGIN_MAIN, 2: PRIOR_MAIN, 3: THIRD_MAIN, 4: FOURTH_MAIN, 5: FIFTH_MAIN, 6: SIXTH_MAIN, 7: SEVENTH_MAIN}[value["schema"]])
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
