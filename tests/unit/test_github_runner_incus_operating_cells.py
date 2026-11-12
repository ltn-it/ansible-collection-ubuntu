"""Pure operating-cell semantics; no native commit/image/capacity authority."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import sys
import unittest

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import cell_contract, engine_policy, identity, operating_cells as cells
from incus_lease_issuer.identity import Denied


def fixture(case="failure"):
    native = identity.Policy("ltn-it/ansible-collection-supplementary", 1103407173, 54334171, "a" * 40,
        214182490, ".github/workflows/collection-ci.yml", "ltn-it/modulix-validation",
        ".github/workflows/collection-quality-profile-isolated.yml", "b" * 40, 78, "incus-runner-01", 996,
        frozenset({76040632, 247824904}), "repo:ltn-it/ansible-collection-supplementary:environment:heavy-isolated-pilot",
        required_native_job_name="Source / Operating custody / " + case)
    value = {"schema": 1, "kind": "operating",
        "candidate": {"repository": native.repository, "source_sha": native.caller_sha,
            "artifact": "collection-candidate-" + native.caller_sha, "archive_sha256": "c" * 64},
        "controller": {"repository": native.reusable_repository, "source_sha": "d" * 40,
            "archive_sha256": "e" * 64, "files": {"controller.py": "f" * 64}},
        "operating": {"case": case, "target": cells.TARGET, "image": cells.IMAGE},
        "github": {"job": "operating-cells", "workflow": "Collection CI"}, "engine": {"template": "inert"},
        "incus": {"project_limits": {"cpu": 1, "memory_bytes": cells.MEMORY, "disk_bytes": cells.PROJECT_RESERVATION,
                                    "instances": 1, "virtual_machines": 1, "containers": 0}}}
    return value, native, {"run_id": 501}


class OperatingCellTests(unittest.TestCase):
    def test_all_three_closed_cases_exact_environment_and_sizes(self):
        for case in cells.CASES:
            value, native, who = fixture(case)
            selected = cells.validate(value, native, who)
            env = cells.environment(value, native, who)
            self.assertEqual(set(env), engine_policy.ENV_KEYS | {"QUALITY_OPERATING_CASE", "QUALITY_OPERATING_SPEC"})
            self.assertEqual(env["QUALITY_INPUT_ROLES"], "")
            self.assertEqual(env["QUALITY_INPUT_PROFILE"], "operating")
            self.assertEqual(env["QUALITY_INPUT_DISK_LIMIT"], "6GiB")
            self.assertEqual(env["QUALITY_INPUT_JUNIT_REQUIRED"], "false")
            self.assertEqual(env["QUALITY_INPUT_ALLURE_REQUIRED"], "false")
            self.assertEqual(selected.spec["root_disk_bytes"], 5368709120)
            self.assertEqual(selected.spec["state_disk_bytes"], 524288000)
            self.assertEqual(selected.spec["image_reservation_bytes"], 4294967296)
            self.assertEqual(selected.spec["project_reservation_bytes"], 10737418240)
            self.assertEqual(selected.spec["cpu"], 1)
            self.assertEqual(selected.spec["memory_bytes"], 2147483648)
            self.assertEqual(selected.spec["total_disk_bytes"], 6442450944)
            self.assertEqual(len(selected.spec), 12)
            self.assertEqual(cells.selector(case), "operating-" + case)
            self.assertEqual(selected.instance_name, cell_contract._bounded("g06-operating-" + case + "-501-1-ubuntu-24.04", 63))
            self.assertEqual(env["QUALITY_OPERATING_SPEC"].encode(), selected.spec_bytes)
            changed = selected.spec; changed["cpu"] = 99
            self.assertEqual(selected.spec["cpu"], 1)

    def test_unknown_case_business_kind_matrix_or_job_mismatch_cannot_use_empty_roles(self):
        original, native, who = fixture()
        for change in ({"kind": "business"}, {"matrix": {"roles": []}}, {"kind": True}):
            value = {**original, **change}
            with self.subTest(change=change), self.assertRaises(Denied): cells.validate(value, native, who)
        for case in ("heavy", "success", "failure/../heavy", True):
            value = deepcopy(original); value["operating"]["case"] = case
            with self.assertRaises(Denied): cells.validate(value, native, who)
        with self.assertRaises(Denied):
            cells.validate(original, replace(native, required_native_job_name="heavy / application / ubuntu-24.04"), who)

    def test_source_controller_candidate_and_native_domain_are_independent_exact_refs(self):
        original, native, who = fixture()
        self.assertNotEqual(original["controller"]["source_sha"], native.reusable_sha)
        cells.validate(original, native, who)
        for section, key, value in (("candidate", "source_sha", "9" * 40),
                                   ("candidate", "artifact", "other-candidate"),
                                   ("controller", "repository", "ltn-it/foreign")):
            bad = deepcopy(original); bad[section][key] = value
            with self.assertRaises(Denied): cells.validate(bad, native, who)
        with self.assertRaises(Denied): cells.validate(original, replace(native, repository_id=1269461997), who)
        with self.assertRaises(Denied): cells.validate(original, native, {"run_id": True})

    def test_plain_fixed_image_and_vm_vs_project_reservations_cannot_be_overridden(self):
        original, native, who = fixture()
        for image in ("quality:" + cells.IMAGE, "images:ubuntu/24.04", "9" * 64, ""):
            bad = deepcopy(original); bad["operating"]["image"] = image
            with self.assertRaises(Denied): cells.validate(bad, native, who)
        for key, number in (("cpu", True), ("cpu", 2), ("memory_bytes", 1),
                            ("disk_bytes", cells.TOTAL_DISK), ("virtual_machines", 2), ("containers", 1)):
            bad = deepcopy(original); bad["incus"]["project_limits"][key] = number
            with self.assertRaises(Denied): cells.validate(bad, native, who)
        bad = deepcopy(original); bad["operating"]["cpu"] = 1
        with self.assertRaises(Denied): cells.validate(bad, native, who)

    def test_initial_main_checks_actual_tuple_shape_not_an_approval_boolean(self):
        sha = "a" * 40
        cells.validate_initial_main({"sha": sha, "parents": [{"sha": cells.INITIAL_MAIN}, {"sha": "b" * 40}]}, sha)
        for commit in ({"sha": sha, "parents": [{"sha": "b" * 40}, {"sha": cells.INITIAL_MAIN}]},
                       {"sha": "b" * 40, "parents": [{"sha": cells.INITIAL_MAIN}]},
                       {"sha": sha, "parents": []}, {"approved": True},
                       {"sha": sha, "parents": [{"sha": cells.INITIAL_MAIN}] * 2}):
            with self.assertRaises(Denied): cells.validate_initial_main(commit, sha)

    def test_business_roles_guard_remains_required_in_existing_parser(self):
        _, native, who = fixture()
        matrix = {key: "supported" for key in cell_contract.MATRIX_KEYS}
        matrix.update(roles=[], junit=False, allure=False, instance_type="vm", profile="heavy",
                      scenario="keycloak-heavy", target="ubuntu-24.04")
        with self.assertRaisesRegex(Denied, "cell-roles"):
            cell_contract._environment({"matrix": matrix, "github": {"job": "heavy", "workflow": "CI"}}, native, who)
