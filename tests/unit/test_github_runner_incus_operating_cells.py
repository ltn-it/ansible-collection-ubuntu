"""Pure operating-cell semantics; no native commit/image/capacity authority."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import cell_contract, engine_policy, identity, ledger, operating_cells as cells
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
    def test_private_cached_image_is_only_requested_for_the_two_bound_business_vm_cases(self):
        for profile, scenario in (("heavy", "keycloak-heavy"),
                                  ("application_acceptance", "keycloak-application-acceptance")):
            env = {"QUALITY_INPUT_PROFILE": profile, "QUALITY_INPUT_SCENARIO": scenario,
                   "QUALITY_INPUT_TARGET": "ubuntu-24.04", "QUALITY_INPUT_INSTANCE_TYPE": "vm",
                   "QUALITY_INPUT_IMAGE": cells.IMAGE}
            self.assertTrue(cells.uses_cached_vm_image(env))
            for key, bad in (("PROFILE", "tiny"), ("SCENARIO", "keycloak-tiny"), ("TARGET", "rhel-9"),
                             ("INSTANCE_TYPE", "container"), ("IMAGE", "images:ubuntu/24.04"),
                             ("IMAGE", "0" * 64)):
                with self.subTest(profile=profile, key=key, bad=bad):
                    self.assertFalse(cells.uses_cached_vm_image(env | {"QUALITY_INPUT_" + key: bad}))
        self.assertTrue(cells.uses_cached_vm_image({"QUALITY_INPUT_PROFILE": "operating"}))

    def test_private_cache_adds_disk_quota_only_for_the_two_business_profiles(self):
        certificate = "a" * 64
        template = {
            "server": "https://192.0.2.11:8443",
            "server_certificate": {"path": "/unit/server.pem", "sha256": certificate},
            "pool": "test-pool", "project_prefix": "test-", "ipv4_address": "10.0.0.1/24",
            "dns_domain": "unit.test",
            "project_limits": {"cpu": 1, "memory_bytes": 2 * 1024**3, "disk_bytes": 0,
                               "instances": 1, "virtual_machines": 1, "containers": 0},
        }
        env = {"QUALITY_INPUT_TARGET": cells.TARGET, "QUALITY_INPUT_INSTANCE_TYPE": "vm",
               "QUALITY_INPUT_IMAGE": cells.IMAGE, "QUALITY_INPUT_DISK_LIMIT": "24GiB",
               "QUALITY_INPUT_CPU_LIMIT": "1", "QUALITY_INPUT_MEMORY_LIMIT": "2GiB"}
        guest = 24 * 1024**3
        with patch.object(cell_contract.installation, "_file",
                          return_value=(SimpleNamespace(sha256=certificate), b"", ())):
            for profile, scenario in sorted(cells.BUSINESS_VM_PROFILES):
                env.update(QUALITY_INPUT_PROFILE=profile, QUALITY_INPUT_SCENARIO=scenario)
                with self.subTest(profile=profile):
                    template["project_limits"]["disk_bytes"] = guest
                    with self.assertRaisesRegex(Denied, "cell-project-quota"):
                        cell_contract._validate_incus_template(template, env)
                    template["project_limits"]["disk_bytes"] = guest + cells.IMAGE_RESERVATION
                    self.assertEqual(cell_contract._validate_incus_template(template, env), template)
            template["project_limits"]["disk_bytes"] = guest
            self.assertEqual(cell_contract._validate_incus_template(template, env | {
                "QUALITY_INPUT_PROFILE": "heavy", "QUALITY_INPUT_SCENARIO": "other-heavy",
            }), template)
            value, native, who = fixture()
            operating = cells.environment(value, native, who)
            template["project_limits"] = value["incus"]["project_limits"]
            self.assertEqual(cell_contract._validate_incus_template(template, operating), template)
            self.assertEqual(template["project_limits"]["disk_bytes"], cells.PROJECT_RESERVATION)

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

    def test_closed_native_failure_accepts_only_a_new_exact_successor(self):
        self.assertNotEqual(cells.TWENTY_THIRD_SUCCESSOR_WORKFLOW, cells.TWENTY_SECOND_SUCCESSOR_WORKFLOW)
        self.assertNotEqual(cells.TWENTY_THIRD_SUCCESSOR_REUSABLE, cells.TWENTY_SECOND_SUCCESSOR_REUSABLE)
        original = {
            "schema": 23, "reason": cells.TWENTY_THIRD_REASON,
            "qualification": {"path": "/private/qualification.json", "sha256": cells.TWENTY_THIRD_QUALIFICATION},
            "successor": {"source_sha": "8" * 40, "run_id": 50000000000, "run_attempt": 1,
                          "first_parent": cells.TWENTY_THIRD_MAIN,
                          "source_workflow_sha256": cells.TWENTY_THIRD_SUCCESSOR_WORKFLOW,
                          "reusable_sha": cells.TWENTY_THIRD_SUCCESSOR_REUSABLE},
        }
        caller = original["successor"]["source_sha"]
        commit = {"sha": caller, "parents": [{"sha": cells.TWENTY_THIRD_MAIN}]}
        run = original["successor"]["run_id"]
        controller = original["successor"]["reusable_sha"]
        cells.validate_continuation_commit(commit, original, caller, run, controller)
        for field, bad in (("run_id", cells.TWENTY_THIRD_RUN), ("run_attempt", 2),
                           ("first_parent", cells.TWENTY_SECOND_MAIN), ("source_sha", cells.TWENTY_THIRD_MAIN),
                           ("source_workflow_sha256", cells.TWENTY_SECOND_SUCCESSOR_WORKFLOW),
                           ("reusable_sha", cells.TWENTY_SECOND_SUCCESSOR_REUSABLE)):
            changed = deepcopy(original)
            changed["successor"][field] = bad
            with self.subTest(field=field), self.assertRaises(Denied):
                cells.validate_continuation_commit(commit, changed, caller, run, controller)
        changed = deepcopy(original)
        changed["qualification"]["sha256"] = "9" * 64
        with self.assertRaisesRegex(Denied, "continuation-twenty-third-qualification"):
            cells.validate_continuation_commit(commit, changed, caller, run, controller)

        previous = deepcopy(original)
        previous.update(schema=22, reason=cells.TWENTY_SECOND_REASON)
        previous["successor"].update(source_sha=cells.TWENTY_THIRD_MAIN, run_id=cells.TWENTY_THIRD_RUN,
                                     first_parent=cells.TWENTY_SECOND_MAIN,
                                     source_workflow_sha256=cells.TWENTY_SECOND_SUCCESSOR_WORKFLOW,
                                     reusable_sha=cells.TWENTY_SECOND_SUCCESSOR_REUSABLE)
        previous_commit = {"sha": cells.TWENTY_THIRD_MAIN, "parents": [{"sha": cells.TWENTY_SECOND_MAIN}]}
        cells.validate_continuation_commit(previous_commit, previous, cells.TWENTY_THIRD_MAIN,
                                           cells.TWENTY_THIRD_RUN, cells.TWENTY_SECOND_SUCCESSOR_REUSABLE)
        with self.assertRaisesRegex(Denied, "continuation-closed-vm-successor"):
            cells.validate_continuation_commit(previous_commit, previous, cells.TWENTY_THIRD_MAIN,
                                               cells.TWENTY_THIRD_RUN, controller)

    def test_sealed_prelease_failure_accepts_only_the_bound_c24_successor(self):
        caller = "8" * 40
        run = cells.TWENTY_FOURTH_RUN + 1
        controller = cells.TWENTY_FOURTH_SUCCESSOR_REUSABLE
        original = {
            "schema": 24,
            "reason": cells.TWENTY_FOURTH_REASON,
            "qualification": {"path": "/private/qualification.json", "sha256": cells.TWENTY_FOURTH_QUALIFICATION},
            "successor": {
                "source_sha": caller,
                "run_id": run,
                "run_attempt": 1,
                "first_parent": cells.TWENTY_FOURTH_MAIN,
                "source_workflow_sha256": cells.TWENTY_FOURTH_SUCCESSOR_WORKFLOW,
                "reusable_sha": controller,
            },
        }
        commit = {"sha": caller, "parents": [{"sha": cells.TWENTY_FOURTH_MAIN}]}
        cells.validate_continuation_commit(commit, original, caller, run, controller)

        for field, bad in (
            ("first_parent", cells.TWENTY_THIRD_MAIN),
            ("source_workflow_sha256", cells.TWENTY_THIRD_SUCCESSOR_WORKFLOW),
            ("reusable_sha", cells.TWENTY_THIRD_SUCCESSOR_REUSABLE),
            ("run_attempt", 2),
            ("source_sha", cells.TWENTY_FOURTH_MAIN),
            ("run_id", cells.TWENTY_FOURTH_RUN),
        ):
            changed = deepcopy(original)
            changed["successor"][field] = bad
            with self.subTest(field=field), self.assertRaises(Denied):
                cells.validate_continuation_commit(commit, changed, caller, run, controller)
        changed = deepcopy(original)
        changed["qualification"]["sha256"] = cells.TWENTY_THIRD_QUALIFICATION
        with self.assertRaisesRegex(Denied, "continuation-twenty-fourth-qualification"):
            cells.validate_continuation_commit(commit, changed, caller, run, controller)

    def test_closed_c24_accepts_only_the_bound_c25_successor(self):
        caller = "9" * 40
        run = cells.TWENTY_FIFTH_RUN + 1
        controller = cells.TWENTY_FIFTH_SUCCESSOR_REUSABLE
        original = {
            "schema": 25,
            "reason": cells.TWENTY_FIFTH_REASON,
            "qualification": {"path": "/private/qualification.json", "sha256": cells.TWENTY_FIFTH_QUALIFICATION},
            "successor": {
                "source_sha": caller,
                "run_id": run,
                "run_attempt": 1,
                "first_parent": cells.TWENTY_FIFTH_MAIN,
                "source_workflow_sha256": cells.TWENTY_FIFTH_SUCCESSOR_WORKFLOW,
                "reusable_sha": controller,
            },
        }
        commit = {"sha": caller, "parents": [{"sha": cells.TWENTY_FIFTH_MAIN}]}
        cells.validate_continuation_commit(commit, original, caller, run, controller)

        for field, value in (
            ("first_parent", cells.TWENTY_FOURTH_MAIN),
            ("source_workflow_sha256", cells.TWENTY_FOURTH_SUCCESSOR_WORKFLOW),
            ("reusable_sha", cells.TWENTY_FOURTH_SUCCESSOR_REUSABLE),
            ("run_attempt", 2),
            ("source_sha", cells.TWENTY_FIFTH_MAIN),
            ("run_id", cells.TWENTY_FIFTH_RUN),
        ):
            changed = deepcopy(original)
            changed["successor"][field] = value
            with self.subTest(field=field), self.assertRaises(Denied):
                cells.validate_continuation_commit(commit, changed, caller, run, controller)

        changed = deepcopy(original)
        changed["qualification"]["sha256"] = cells.TWENTY_FOURTH_QUALIFICATION
        with self.assertRaisesRegex(Denied, "continuation-twenty-fifth-qualification"):
            cells.validate_continuation_commit(commit, changed, caller, run, controller)
        changed_commit = {"sha": caller, "parents": [{"sha": cells.TWENTY_FOURTH_MAIN}]}
        with self.assertRaises(Denied):
            cells.validate_continuation_commit(changed_commit, original, caller, run, controller)

    def test_c26_prelease_successor_binds_attempt_controller_and_first_parent(self):
        source = "a" * 40
        workflow_sha = "b" * 64
        reusable = "c" * 40
        successor = {
            "source_sha": source, "run_id": cells.TWENTY_SEVENTH_RUN + 1, "run_attempt": 1,
            "first_parent": cells.TWENTY_SEVENTH_MAIN, "source_workflow_sha256": workflow_sha,
            "reusable_sha": reusable,
        }
        descriptor = {
            "schema": 27, "reason": cells.TWENTY_SEVENTH_REASON,
            "qualification": {"path": "/private/prelease-proof.json", "sha256": cells.TWENTY_SEVENTH_QUALIFICATION},
            "successor": successor,
        }
        commit = {"sha": source, "parents": [{"sha": cells.TWENTY_SEVENTH_MAIN}]}
        with patch.object(cells, "TWENTY_SEVENTH_SUCCESSOR_WORKFLOW", workflow_sha), \
             patch.object(cells, "TWENTY_SEVENTH_SUCCESSOR_REUSABLE", reusable):
            cells.validate_continuation_commit(commit, descriptor, source, successor["run_id"], reusable)
            for field, value in (
                ("run_attempt", 2), ("source_sha", cells.TWENTY_SEVENTH_MAIN),
                ("run_id", cells.TWENTY_SEVENTH_RUN), ("reusable_sha", "d" * 40),
                ("first_parent", cells.TWENTY_SIXTH_MAIN), ("source_workflow_sha256", "d" * 64),
            ):
                wrong = descriptor | {"successor": successor | {field: value}}
                with self.subTest(field=field), self.assertRaises(Denied):
                    cells.validate_continuation_descriptor(wrong, workflow_sha, reusable)
            wrong_parent = commit | {"parents": [{"sha": cells.TWENTY_SIXTH_MAIN}]}
            with self.assertRaisesRegex(Denied, "continuation-first-parent"):
                cells.validate_continuation_commit(wrong_parent, descriptor, source, successor["run_id"], reusable)

    def test_c27_sealed_prelease_successor_binds_attempt_controller_and_first_parent(self):
        source = "a" * 40
        workflow_sha = "b" * 64
        reusable = "c" * 40
        successor = {
            "source_sha": source, "run_id": cells.TWENTY_EIGHTH_RUN + 1, "run_attempt": 1,
            "first_parent": cells.TWENTY_EIGHTH_MAIN, "source_workflow_sha256": workflow_sha,
            "reusable_sha": reusable,
        }
        descriptor = {
            "schema": 28, "reason": cells.TWENTY_EIGHTH_REASON,
            "qualification": {"path": "/private/prelease-proof.json", "sha256": cells.TWENTY_EIGHTH_QUALIFICATION},
            "successor": successor,
        }
        commit = {"sha": source, "parents": [{"sha": cells.TWENTY_EIGHTH_MAIN}]}
        with patch.object(cells, "TWENTY_EIGHTH_SUCCESSOR_WORKFLOW", workflow_sha), \
             patch.object(cells, "TWENTY_EIGHTH_SUCCESSOR_REUSABLE", reusable):
            cells.validate_continuation_commit(commit, descriptor, source, successor["run_id"], reusable)
            for field, value in (
                ("run_attempt", 2), ("source_sha", cells.TWENTY_EIGHTH_MAIN),
                ("run_id", cells.TWENTY_EIGHTH_RUN), ("reusable_sha", "d" * 40),
                ("first_parent", cells.TWENTY_SIXTH_MAIN), ("source_workflow_sha256", "d" * 64),
            ):
                wrong = descriptor | {"successor": successor | {field: value}}
                with self.subTest(field=field), self.assertRaises(Denied):
                    cells.validate_continuation_descriptor(wrong, workflow_sha, reusable)
            wrong_parent = commit | {"parents": [{"sha": cells.TWENTY_SIXTH_MAIN}]}
            with self.assertRaisesRegex(Denied, "continuation-first-parent"):
                cells.validate_continuation_commit(wrong_parent, descriptor, source, successor["run_id"], reusable)

    def test_closed_c25_accepts_only_the_bound_c26_successor(self):
        caller = "a" * 40
        run = cells.TWENTY_SIXTH_RUN + 1
        controller = cells.TWENTY_SIXTH_SUCCESSOR_REUSABLE
        workflow = cells.TWENTY_SIXTH_SUCCESSOR_WORKFLOW
        original = {
            "schema": 26,
            "reason": cells.TWENTY_SIXTH_REASON,
            "qualification": {"path": "/private/qualification.json", "sha256": cells.TWENTY_SIXTH_QUALIFICATION},
            "successor": {
                "source_sha": caller,
                "run_id": run,
                "run_attempt": 1,
                "first_parent": cells.TWENTY_SIXTH_MAIN,
                "source_workflow_sha256": workflow,
                "reusable_sha": controller,
            },
        }
        commit = {"sha": caller, "parents": [{"sha": cells.TWENTY_SIXTH_MAIN}]}
        cells.validate_continuation_descriptor(original, workflow, controller)
        cells.validate_continuation_commit(commit, original, caller, run, controller)

        for field, value, reason in (
            ("first_parent", cells.TWENTY_FIFTH_MAIN, "continuation-twenty-sixth-successor"),
            ("source_workflow_sha256", cells.TWENTY_FIFTH_SUCCESSOR_WORKFLOW, "continuation-twenty-sixth-successor"),
            ("reusable_sha", cells.TWENTY_FIFTH_SUCCESSOR_REUSABLE, "continuation-twenty-sixth-successor"),
            ("run_attempt", 2, "continuation-twenty-sixth-successor"),
            ("source_sha", cells.TWENTY_SIXTH_MAIN, "continuation-twenty-sixth-replay"),
            ("run_id", cells.TWENTY_SIXTH_RUN, "continuation-twenty-sixth-replay"),
        ):
            changed = deepcopy(original)
            changed["successor"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(Denied, reason):
                cells.validate_continuation_descriptor(changed, workflow, controller)

        altered = deepcopy(original)
        altered["qualification"]["sha256"] = cells.TWENTY_FIFTH_QUALIFICATION
        with self.assertRaisesRegex(Denied, "continuation-twenty-sixth-qualification"):
            cells.validate_continuation_descriptor(altered, workflow, controller)
        changed_commit = {"sha": caller, "parents": [{"sha": cells.TWENTY_FIFTH_MAIN}]}
        with self.assertRaises(Denied):
            cells.validate_continuation_commit(changed_commit, original, caller, run, controller)

    def test_unsealed_c29_requires_the_exact_c30_native_successor(self):
        caller = "a" * 40
        run = cells.THIRTIETH_RUN + 1
        workflow = cells.THIRTIETH_SUCCESSOR_WORKFLOW
        controller = cells.THIRTIETH_SUCCESSOR_REUSABLE
        successor = {
            "source_sha": caller, "run_id": run, "run_attempt": 1,
            "first_parent": cells.THIRTIETH_MAIN, "source_workflow_sha256": workflow,
            "reusable_sha": controller,
        }
        descriptor = {
            "schema": 30, "reason": cells.THIRTIETH_REASON,
            "qualification": {"path": "/private/c29-qualification.json", "sha256": cells.THIRTIETH_QUALIFICATION},
            "successor": successor,
        }
        commit = {"sha": caller, "parents": [{"sha": cells.THIRTIETH_MAIN}]}
        self.assertEqual(cells.validate_continuation_descriptor(descriptor, workflow, controller), descriptor)
        cells.validate_continuation_commit(commit, descriptor, caller, run, controller)

        for field, value in (
            ("first_parent", cells.TWENTY_NINTH_MAIN), ("source_workflow_sha256", "c" * 64),
            ("reusable_sha", "c" * 40), ("run_attempt", 2), ("source_sha", cells.THIRTIETH_MAIN),
            ("run_id", cells.THIRTIETH_RUN),
        ):
            changed = descriptor | {"successor": successor | {field: value}}
            with self.subTest(field=field), self.assertRaises(Denied):
                cells.validate_continuation_descriptor(changed, workflow, controller)
        for workflow_arg, controller_arg in ((workflow, "c" * 40), ("c" * 64, controller)):
            with self.assertRaisesRegex(Denied, "continuation-thirtieth-successor"):
                cells.validate_continuation_descriptor(descriptor, workflow_arg, controller_arg)

        changed = descriptor | {"qualification": descriptor["qualification"] | {"sha256": "c" * 64}}
        with self.assertRaisesRegex(Denied, "continuation-thirtieth-qualification"):
            cells.validate_continuation_descriptor(changed, workflow, controller)
        wrong_parent = commit | {"parents": [{"sha": cells.TWENTY_NINTH_MAIN}]}
        with self.assertRaisesRegex(Denied, "continuation-first-parent"):
            cells.validate_continuation_commit(wrong_parent, descriptor, caller, run, controller)
        with self.assertRaisesRegex(Denied, "continuation-exact-native-tuple"):
            cells.validate_continuation_commit(commit, descriptor, caller, cells.THIRTIETH_RUN, controller)

    def test_c30_qualification_retains_the_c29_intake_and_every_older_entry(self):
        native = {"test_projection": True}
        old_catalogues = {
            "native_intake_catalogue": {"a" * 64: "b" * 64},
            "native_run_configuration_catalogue": {"c" * 64: "d" * 64},
        }
        previous = {"schema": 29, "retirement": {"catalogues": old_catalogues}}
        name, inventory = "e" * 64, "f" * 64
        qualification = {
            "schema": 30, "purpose": cells.THIRTIETH_REASON,
            "native_thirtieth": native, "previous_qualification": previous,
            "retirement": {
                "original_bootstrap": {
                    "path": "/private/old/bootstrap.json", "sha256": cells.THIRTIETH_BOOTSTRAP,
                    "device": 1, "inode": 2,
                },
                "original_bank": {
                    "path": "/private/old/bank", "state_file_sha256": "1" * 64,
                    "device": 1, "inode": 3,
                },
                "intake_prefix": {
                    "name": name, "inventory_sha256": inventory, "intent_sha256": "2" * 64,
                    "device": 1, "inode": 4,
                },
                "catalogues": {
                    **old_catalogues,
                    "native_intake_catalogue": {**old_catalogues["native_intake_catalogue"], name: inventory},
                },
            },
        }
        with patch.object(cells, "THIRTIETH_GRAPH", ledger.digest(native)), \
             patch.object(cells, "THIRTIETH_QUALIFICATION", ledger.digest(qualification)), \
             patch.object(cells, "_validate_twenty_ninth_qualification", return_value=(1, 2)) as prior:
            self.assertEqual(cells.validate_continuation_qualification(qualification), (1, 2))
            prior.assert_called_once_with(previous)
            wrong = deepcopy(qualification)
            wrong["retirement"]["catalogues"]["native_intake_catalogue"][name] = "3" * 64
            with self.assertRaisesRegex(Denied, "continuation-thirtieth-history"):
                cells.validate_continuation_qualification(wrong)
            with patch.object(cells, "THIRTIETH_QUALIFICATION", ledger.digest(wrong)), \
                 self.assertRaisesRegex(Denied, "continuation-thirtieth-exact-prefix-extension"):
                cells.validate_continuation_qualification(wrong)

    def test_closed_c30_requires_the_exact_c31_native_successor(self):
        caller = "a" * 40
        run = cells.THIRTY_FIRST_RUN + 1
        workflow = cells.THIRTY_FIRST_SUCCESSOR_WORKFLOW
        controller = cells.THIRTY_FIRST_SUCCESSOR_REUSABLE
        successor = {
            "source_sha": caller, "run_id": run, "run_attempt": 1,
            "first_parent": cells.THIRTY_FIRST_MAIN, "source_workflow_sha256": workflow,
            "reusable_sha": controller,
        }
        descriptor = {
            "schema": 31, "reason": cells.THIRTY_FIRST_REASON,
            "qualification": {"path": "/private/c30-qualification.json", "sha256": cells.THIRTY_FIRST_QUALIFICATION},
            "successor": successor,
        }
        commit = {"sha": caller, "parents": [{"sha": cells.THIRTY_FIRST_MAIN}]}
        self.assertEqual(cells.validate_continuation_descriptor(descriptor, workflow, controller), descriptor)
        cells.validate_continuation_commit(commit, descriptor, caller, run, controller)

        for field, value in (
            ("first_parent", cells.THIRTIETH_MAIN), ("source_workflow_sha256", "c" * 64),
            ("reusable_sha", "c" * 40), ("run_attempt", 2), ("source_sha", cells.THIRTY_FIRST_MAIN),
            ("run_id", cells.THIRTY_FIRST_RUN),
        ):
            changed = descriptor | {"successor": successor | {field: value}}
            with self.subTest(field=field), self.assertRaises(Denied):
                cells.validate_continuation_descriptor(changed, workflow, controller)
        for workflow_arg, controller_arg in ((workflow, "c" * 40), ("c" * 64, controller)):
            with self.assertRaisesRegex(Denied, "continuation-thirty-first-successor"):
                cells.validate_continuation_descriptor(descriptor, workflow_arg, controller_arg)

        changed = descriptor | {"qualification": descriptor["qualification"] | {"sha256": "c" * 64}}
        with self.assertRaisesRegex(Denied, "continuation-thirty-first-qualification"):
            cells.validate_continuation_descriptor(changed, workflow, controller)
        wrong_parent = commit | {"parents": [{"sha": cells.THIRTIETH_MAIN}]}
        with self.assertRaisesRegex(Denied, "continuation-first-parent"):
            cells.validate_continuation_commit(wrong_parent, descriptor, caller, run, controller)
        with self.assertRaisesRegex(Denied, "continuation-exact-native-tuple"):
            cells.validate_continuation_commit(commit, descriptor, caller, cells.THIRTY_FIRST_RUN, controller)

    def test_c31_retirement_extends_both_catalogues_and_keeps_the_original_closure(self):
        native = {"test_projection": True}
        catalogue_keys = {"configuration": "native_run_configuration_catalogue", "intake": "native_intake_catalogue"}
        old_catalogues = {name: {"a" * 64: "b" * 64} for name in catalogue_keys.values()}
        previous = {"schema": 30, "retirement": {"catalogues": old_catalogues}}
        configuration = {"name": "c" * 64, "device": 1, "inode": 4,
                         "receipt_sha256": "d" * 64, "inventory_sha256": "e" * 64}
        intake = configuration | {"name": "f" * 64, "inode": 5}
        entries = {"configuration": configuration, "intake": intake}
        qualification = {
            "schema": 31, "purpose": cells.THIRTY_FIRST_REASON,
            "native_thirty_first": native, "previous_qualification": previous,
            "retirement": {
                "original_bootstrap": {
                    "path": "/private/old/bootstrap.json", "sha256": cells.THIRTY_FIRST_BOOTSTRAP,
                    "device": 1, "inode": 2,
                },
                "original_bank": {
                    "path": "/private/old/bank", "state_file_sha256": "1" * 64,
                    "device": 1, "inode": 3,
                },
                "closed_record_sha256": cells.THIRTY_FIRST_CLOSED_RECORD,
                "entries": entries,
                "catalogues": {name: old_catalogues[name] | {entries[kind]["name"]: entries[kind]["inventory_sha256"]}
                               for kind, name in catalogue_keys.items()},
            },
        }
        with patch.object(cells, "THIRTY_FIRST_GRAPH", ledger.digest(native)), \
             patch.object(cells, "_validate_thirtieth_qualification", return_value=(1, 2)) as prior:
            with patch.object(cells, "THIRTY_FIRST_QUALIFICATION", ledger.digest(qualification)):
                self.assertEqual(cells.validate_continuation_qualification(qualification), (1, 2))
            prior.assert_called_once_with(previous)
            for kind, name in catalogue_keys.items():
                for altered_name in ("a" * 64, entries[kind]["name"]):
                    wrong = deepcopy(qualification)
                    wrong["retirement"]["catalogues"][name][altered_name] = "3" * 64
                    with self.subTest(kind=kind, altered=altered_name), \
                         patch.object(cells, "THIRTY_FIRST_QUALIFICATION", ledger.digest(wrong)), \
                         self.assertRaisesRegex(Denied, "continuation-twenty-second-catalogue-extension"):
                        cells.validate_continuation_qualification(wrong)
            wrong = deepcopy(qualification)
            wrong["retirement"]["closed_record_sha256"] = "4" * 64
            with patch.object(cells, "THIRTY_FIRST_QUALIFICATION", ledger.digest(wrong)), \
                 self.assertRaisesRegex(Denied, "continuation-thirty-first-original-locators"):
                cells.validate_continuation_qualification(wrong)

    def test_business_roles_guard_remains_required_in_existing_parser(self):
        _, native, who = fixture()
        matrix = {key: "supported" for key in cell_contract.MATRIX_KEYS}
        matrix.update(roles=[], junit=False, allure=False, instance_type="vm", profile="heavy",
                      scenario="keycloak-heavy", target="ubuntu-24.04")
        with self.assertRaisesRegex(Denied, "cell-roles"):
            cell_contract._environment({"matrix": matrix, "github": {"job": "heavy", "workflow": "CI"}}, native, who)
