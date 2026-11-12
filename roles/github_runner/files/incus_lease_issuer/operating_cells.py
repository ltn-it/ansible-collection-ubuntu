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
                    for p in parents) and parents[0]["sha"] == ORIGIN_MAIN
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
