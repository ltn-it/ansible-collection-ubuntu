"""Pure closed operating-drill semantics, separate from business cells.

These checks never authenticate native JSON, establish image availability or
capacity, construct a PreparedCell, or authorize TLS/engine operations. Root
must acquire the native initial-Main commit and job identity independently.
"""
from dataclasses import dataclass
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
