"""Read-only native input admission; no VM, registration or operating proof."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "ephemeral_worker_admission_test", ROOT / "roles/github_runner/files/ephemeral_worker_admission.py")
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)
NOW = datetime(2026, 11, 9, 3, 30, tzinfo=timezone.utc)


class Client:
    def __init__(self):
        self.body = b"candidate"
        self.policy = M.Policy("a" * 40, "b" * 40, hashlib.sha256(self.body).hexdigest(), 95)
        self.calls = []
        actor = {"id": M.ACTOR_ID, "login": M.ACTOR, "type": "Bot"}
        self.repository = {"id": M.REPOSITORY_ID, "full_name": M.REPOSITORY,
                           "owner": {"id": M.ORGANIZATION_ID}, "default_branch": "develop",
                           "private": False, "archived": False}
        self.main = {"name": "main", "protected": True, "commit": {"sha": self.policy.caller_sha}}
        self.develop = {"name": "develop", "protected": True, "commit": {"sha": "c" * 40}}
        self.comparison = {"status": "ahead", "base_commit": {"sha": self.policy.callee_sha},
                           "merge_base_commit": {"sha": self.policy.callee_sha}}
        self.entry = {"type": "file", "path": M.CALLEE, "encoding": "base64",
                      "content": base64.b64encode(self.body).decode(), "size": len(self.body)}
        self.run = {"id": 999, "run_attempt": 1, "head_sha": self.policy.caller_sha,
                    "head_branch": "main", "path": M.CALLER, "event": "workflow_dispatch",
                    "status": "in_progress", "conclusion": None,
                    "repository": self.repository, "head_repository": self.repository,
                    "actor": actor, "triggering_actor": copy.deepcopy(actor),
                    "referenced_workflows": [{"path": self.policy.workflow, "sha": self.policy.callee_sha}],
                    "display_title": "MLX-90 collection candidate / " + "d" * 64}
        self.job = {"id": 123, "run_id": 999, "run_attempt": 1, "head_sha": self.policy.caller_sha,
                    "head_branch": "main", "status": "queued", "conclusion": None,
                    "runner_id": 0, "runner_group_id": 0, "created_at": "2026-11-09T03:29:00Z",
                    "labels": ["self-hosted", "linux", "x64", "lit-pis", "prd", "isolated", "ciwkr01",
                               "lit-heavy-999-1-heavy-0"],
                    "name": "Heavy / heavy / scenario / target"}
        self.group = {"id": 95, "name": M.GROUP_NAME, "inherited": False, "default": False,
                      "visibility": "selected", "allows_public_repositories": True,
                      "restricted_to_workflows": True, "selected_workflows": [self.policy.workflow]}
        self.repositories = {"total_count": 1, "repositories": [{"id": M.REPOSITORY_ID}]}
        self.runners = {"total_count": 0, "runners": []}

    def get(self, path):
        self.calls.append(path)
        prefix = f"repos/{M.REPOSITORY}"
        rows = {prefix: self.repository, prefix + "/branches/main": self.main,
                prefix + "/branches/develop": self.develop,
                prefix + f"/compare/{self.policy.callee_sha}...{self.develop['commit']['sha']}": self.comparison,
                prefix + f"/contents/{M.CALLEE}?ref={self.policy.callee_sha}": self.entry,
                prefix + "/actions/runs/999": self.run, prefix + "/actions/jobs/123": self.job,
                "orgs/ltn-it/actions/runner-groups/95": self.group,
                "orgs/ltn-it/actions/runner-groups/95/repositories?per_page=100&page=1": self.repositories,
                "orgs/ltn-it/actions/runner-groups/95/runners?per_page=100&page=1": self.runners}
        if path not in rows:
            raise AssertionError(path)
        return copy.deepcopy(rows[path])


def admit(client, now=NOW):
    return M.admit(client, client.policy, 999, 123, now=now)


class AdmissionTests(unittest.TestCase):
    def test_exact_queued_job_produces_nonsecret_ticket_and_revalidates(self):
        client = Client()
        ticket = admit(client)
        self.assertEqual((ticket.run_id, ticket.job_id, ticket.group_id), (999, 123, 95))
        self.assertEqual(ticket.affinity_label, "lit-heavy-999-1-heavy-0")
        self.assertEqual(ticket.request_sha256, "d" * 64)
        M.revalidate(client, client.policy, ticket, now=NOW + timedelta(seconds=1))

    def test_unassigned_native_nullable_fields_and_application_profile(self):
        client = Client()
        client.job.update(runner_id=None, runner_group_id=None,
                          name="Application Acceptance / application_acceptance / scenario / target")
        client.job["labels"][-1] = "lit-heavy-999-1-application_acceptance-255"
        self.assertEqual(admit(client).matrix_index, 255)
        self.assertEqual(admit(client).profile, "application_acceptance")

    def test_privileged_ticket_contains_hash_not_untrusted_template_text(self):
        client = Client()
        client.job["name"] = "Heavy / heavy / {{ lookup('pipe', 'id') }} / target"
        ticket = admit(client)
        self.assertEqual(ticket.job_name_sha256, hashlib.sha256(client.job["name"].encode()).hexdigest())
        self.assertFalse(hasattr(ticket, "job_name"))
        self.assertNotIn("{{", str(ticket))

    def test_two_native_profile_calls_can_reference_the_same_immutable_callee(self):
        client = Client()
        client.run["referenced_workflows"] *= 2
        self.assertEqual(admit(client).callee_sha, client.policy.callee_sha)

    def test_identifiers_and_policy_types_fail_before_api_reads(self):
        for identity in [True, 0, -1, "999", 2**63]:
            client = Client()
            with self.subTest(identity=identity), self.assertRaises(M.Denied):
                M.admit(client, client.policy, identity, 123, now=NOW)
            self.assertEqual(client.calls, [])
        for group in [False, 0, "95"]:
            client = Client()
            with self.assertRaises(M.Denied):
                M.admit(client, M.Policy("a" * 40, "b" * 40, "c" * 64, group), 999, 123, now=NOW)
            self.assertEqual(client.calls, [])

    def test_main_event_actors_source_and_attempt_are_native_requirements(self):
        mutations = [("event", "pull_request"), ("event", "pull_request_target"),
                     ("run_attempt", 2), ("run_attempt", True), ("head_branch", "develop"),
                     ("head_sha", "f" * 40), ("path", ".github/workflows/other.yml"),
                     ("status", "completed"), ("conclusion", "success"), ("id", 998)]
        for key, value in mutations:
            client = Client()
            client.run[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(M.Denied):
                admit(client)
        for key in ["actor", "triggering_actor"]:
            client = Client()
            client.run[key] = {"id": 76040632, "login": "litroc", "type": "User"}
            with self.subTest(key=key), self.assertRaises(M.Denied):
                admit(client)

    def test_foreign_repository_callee_reference_and_request_identity_are_rejected(self):
        for mutation in ["fork", "missing-ref", "conflicting-ref", "mutable-ref", "request"]:
            client = Client()
            if mutation == "fork":
                client.run["head_repository"] = {"id": 42, "full_name": "foreign/fork"}
            elif mutation == "missing-ref":
                client.run["referenced_workflows"] = []
            elif mutation == "conflicting-ref":
                client.run["referenced_workflows"].append({"path": client.policy.workflow, "sha": "f" * 40})
            elif mutation == "mutable-ref":
                client.run["referenced_workflows"][0]["path"] = client.policy.workflow.replace("b" * 40, "develop")
            else:
                client.run["display_title"] = "manual input"
            with self.subTest(mutation=mutation), self.assertRaises(M.Denied):
                admit(client)

    def test_default_protection_ancestry_and_qualified_file_are_required(self):
        for mutation in ["main-tip", "protection", "diverged", "ancestor", "file", "symlink"]:
            client = Client()
            if mutation == "main-tip":
                client.main["commit"]["sha"] = "f" * 40
            elif mutation == "protection":
                client.develop["protected"] = False
            elif mutation == "diverged":
                client.comparison["status"] = "diverged"
            elif mutation == "ancestor":
                client.comparison["merge_base_commit"]["sha"] = "f" * 40
            elif mutation == "file":
                client.entry["content"] = base64.b64encode(b"old bytes").decode()
            else:
                client.entry["type"] = "symlink"
            with self.subTest(mutation=mutation), self.assertRaises(M.Denied):
                admit(client)

    def test_group_policy_repository_and_empty_inventory_cannot_be_widened(self):
        for mutation in ["name", "workflow", "all-repos", "extra-repo", "runner", "hidden", "boolean"]:
            client = Client()
            if mutation == "name":
                client.group["name"] = "Protected Incus"
            elif mutation == "workflow":
                client.group["selected_workflows"] = [client.policy.workflow.replace("b" * 40, "develop")]
            elif mutation == "all-repos":
                client.group["visibility"] = "all"
            elif mutation == "extra-repo":
                client.repositories["total_count"] = 2
            elif mutation == "runner":
                client.runners.update(total_count=1, runners=[{"id": 78}])
            elif mutation == "hidden":
                client.runners["runners"] = [{"id": 78}]
            else:
                client.repositories["total_count"] = True
            with self.subTest(mutation=mutation), self.assertRaises(M.Denied):
                admit(client)

    def test_job_must_be_queued_unassigned_same_run_attempt_and_source(self):
        for key, value in [("run_id", 998), ("run_attempt", 2), ("head_sha", "f" * 40),
                           ("head_branch", "develop"), ("status", "in_progress"), ("runner_id", 78),
                           ("runner_id", False), ("runner_group_id", 5), ("conclusion", "success")]:
            client = Client()
            client.job[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(M.Denied):
                admit(client)

    def test_job_affinity_rejects_other_run_attempt_profile_index_and_extra_labels(self):
        for label in ["lit-heavy-998-1-heavy-0", "lit-heavy-999-2-heavy-0", "lit-heavy-999-1-heavy-256",
                      "lit-heavy-999-1-heavy-00", "lit-heavy-999-1-custom-0", "incus"]:
            client = Client()
            client.job["labels"][-1] = label
            with self.subTest(label=label), self.assertRaises(M.Denied):
                admit(client)
        for labels in [sorted(M.BASE_LABELS), sorted(M.BASE_LABELS) + ["lit-heavy-999-1-heavy-0", "extra"]]:
            client = Client()
            client.job["labels"] = labels
            with self.assertRaises(M.Denied):
                admit(client)

    def test_documented_host_label_is_required_alongside_job_affinity(self):
        for replacement in [None, "atlas01"]:
            client = Client()
            client.job["labels"].remove("ciwkr01")
            if replacement is not None:
                client.job["labels"].append(replacement)
            with self.subTest(replacement=replacement), self.assertRaises(M.Denied):
                admit(client)

    def test_hosted_input_validation_is_not_a_worker_job(self):
        client = Client()
        client.job["name"] = "Heavy / Validate delegated profile contract"
        with self.assertRaisesRegex(M.Denied, "worker-cell"):
            admit(client)

    def test_job_age_and_controller_utc_clock_are_bounded(self):
        for now in [NOW - timedelta(minutes=2), NOW + timedelta(hours=3), NOW.replace(tzinfo=None)]:
            with self.subTest(now=now), self.assertRaises(M.Denied):
                admit(Client(), now=now)

    def test_revalidation_blocks_cancelled_job_or_a_runner_that_appears(self):
        for mutation in ["cancel", "runner"]:
            client = Client()
            ticket = admit(client)
            if mutation == "cancel":
                client.job.update(status="completed", conclusion="cancelled")
            else:
                client.runners.update(total_count=1, runners=[{"id": 95}])
            with self.subTest(mutation=mutation), self.assertRaises(M.Denied):
                M.revalidate(client, client.policy, ticket, now=NOW)


if __name__ == "__main__":
    unittest.main()
