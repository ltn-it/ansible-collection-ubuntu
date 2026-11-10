"""Read-only admission for a fresh VM worker, before allocation or registration.

This primitive is called only by the external trusted controller. It does not
create VMs, register runners, claim a global lease or establish operating
acceptance. The controller must serialize and revalidate before native effects.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re

REPOSITORY = "ltn-it/modulix-validation"
REPOSITORY_ID = 1269461997
ORGANIZATION_ID = 54334171
GROUP_NAME = "lit-pis-prd-isolated"
CALLER = ".github/workflows/mlx90-collection-candidate-validation.yml"
CALLEE = ".github/workflows/collection-quality-profile-isolated.yml"
ACTOR = "lightning-it-release-automation[bot]"
ACTOR_ID = 307565056
BASE_LABELS = frozenset({"self-hosted", "linux", "x64", "lit-pis", "prd", "isolated", "ciwkr01"})


class Denied(ValueError):
    """No worker effect is authorized by this observation."""


def require(condition, message):
    if not condition:
        raise Denied(message)


def positive(value):
    return type(value) is int and 0 < value < 2**63


def digest(value, length):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value) is not None


@dataclass(frozen=True)
class Policy:
    caller_sha: str
    callee_sha: str
    workflow_sha256: str
    group_id: int
    maximum_queue_seconds: int = 7200

    def check(self):
        require(digest(self.caller_sha, 40) and digest(self.callee_sha, 40)
                and digest(self.workflow_sha256, 64), "policy-source")
        require(positive(self.group_id), "policy-group")
        require(type(self.maximum_queue_seconds) is int
                and 1 <= self.maximum_queue_seconds <= 7200, "policy-queue-budget")

    @property
    def workflow(self):
        return f"{REPOSITORY}/{CALLEE}@{self.callee_sha}"


@dataclass(frozen=True)
class Ticket:
    run_id: int
    job_id: int
    group_id: int
    caller_sha: str
    callee_sha: str
    request_sha256: str
    profile: str
    matrix_index: int
    affinity_label: str
    job_name_sha256: str


def source(client, policy):
    repository = client.get(f"repos/{REPOSITORY}")
    require(repository.get("id") == REPOSITORY_ID
            and repository.get("full_name") == REPOSITORY
            and repository.get("owner", {}).get("id") == ORGANIZATION_ID
            and repository.get("default_branch") == "develop"
            and repository.get("private") is False and repository.get("archived") is False,
            "repository-identity")
    main = client.get(f"repos/{REPOSITORY}/branches/main")
    develop = client.get(f"repos/{REPOSITORY}/branches/develop")
    require(main.get("name") == "main" and main.get("protected") is True
            and main.get("commit", {}).get("sha") == policy.caller_sha, "current-main-source")
    tip = develop.get("commit", {}).get("sha")
    require(develop.get("name") == "develop" and develop.get("protected") is True
            and digest(tip, 40), "protected-default-source")
    comparison = client.get(f"repos/{REPOSITORY}/compare/{policy.callee_sha}...{tip}")
    require(comparison.get("status") in {"ahead", "identical"}
            and comparison.get("base_commit", {}).get("sha") == policy.callee_sha
            and comparison.get("merge_base_commit", {}).get("sha") == policy.callee_sha,
            "callee-default-ancestry")
    entry = client.get(f"repos/{REPOSITORY}/contents/{CALLEE}?ref={policy.callee_sha}")
    require(entry.get("type") == "file" and entry.get("path") == CALLEE
            and entry.get("encoding") == "base64" and isinstance(entry.get("content"), str)
            and len(entry["content"]) <= 262144, "callee-file")
    try:
        raw = base64.b64decode("".join(entry["content"].split()), validate=True)
    except ValueError:
        raise Denied("callee-encoding") from None
    require(type(entry.get("size")) is int and entry["size"] == len(raw)
            and hashlib.sha256(raw).hexdigest() == policy.workflow_sha256, "qualified-callee-bytes")


def group_access(client, group_id, workflow):
    """Recheck the selected repository/workflow grant independently of membership."""
    path = f"orgs/ltn-it/actions/runner-groups/{group_id}"
    group = client.get(path)
    require(group.get("id") == group_id and group.get("name") == GROUP_NAME
            and group.get("inherited") is False and group.get("default") is False
            and group.get("visibility") == "selected" and group.get("allows_public_repositories") is True
            and group.get("restricted_to_workflows") is True
            and group.get("selected_workflows") == [workflow], "group-policy")
    repositories = client.get(path + "/repositories?per_page=100&page=1")
    rows = repositories.get("repositories")
    require(type(repositories.get("total_count")) is int and repositories["total_count"] == 1
            and isinstance(rows, list) and len(rows) == 1 and rows[0].get("id") == REPOSITORY_ID,
            "group-repository-grant")


def empty_group(client, policy):
    group_access(client, policy.group_id, policy.workflow)
    path = f"orgs/ltn-it/actions/runner-groups/{policy.group_id}"
    runners = client.get(path + "/runners?per_page=100&page=1")
    require(type(runners.get("total_count")) is int and runners["total_count"] == 0
            and runners.get("runners") == [], "group-not-empty")


def admit(client, policy, run_id, job_id, *, now):
    """Validate fresh native observations; return only a nonsecret job ticket."""
    require(type(policy) is Policy, "policy-type")
    policy.check()
    require(positive(run_id) and positive(job_id), "native-identifiers")
    require(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset().total_seconds() == 0,
            "controller-utc-clock")
    source(client, policy)
    run = client.get(f"repos/{REPOSITORY}/actions/runs/{run_id}")
    require(run.get("id") == run_id and type(run.get("run_attempt")) is int and run["run_attempt"] == 1
            and run.get("head_sha") == policy.caller_sha and run.get("head_branch") == "main"
            and run.get("path") == CALLER and run.get("event") == "workflow_dispatch"
            and run.get("status") == "in_progress" and run.get("conclusion") is None,
            "native-main-run")
    for key in ["repository", "head_repository"]:
        require(run.get(key, {}).get("id") == REPOSITORY_ID
                and run[key].get("full_name") == REPOSITORY, "native-run-repository")
    for key in ["actor", "triggering_actor"]:
        actor = run.get(key, {})
        require(actor.get("id") == ACTOR_ID and actor.get("login") == ACTOR
                and actor.get("type") == "Bot", "native-run-actor")
    references = run.get("referenced_workflows")
    # Main calls this same immutable callee for two profiles. Identical native
    # entries represent one source identity; a different or mutable reference
    # is not another admissible authority.
    require(isinstance(references, list) and 1 <= len(references) <= 2 and all(
        isinstance(row, dict) and row.get("path") == policy.workflow
        and row.get("sha") == policy.callee_sha and row.get("ref") in {None, policy.callee_sha}
        for row in references), "native-callee-reference")
    title = run.get("display_title")
    request = re.fullmatch(r"MLX-90 collection candidate / ([0-9a-f]{64})", title) if isinstance(title, str) else None
    require(request is not None, "native-request-identity")
    job = client.get(f"repos/{REPOSITORY}/actions/jobs/{job_id}")
    require(job.get("id") == job_id and job.get("run_id") == run_id
            and type(job.get("run_attempt")) is int and job["run_attempt"] == 1
            and job.get("head_sha") == policy.caller_sha and job.get("head_branch") == "main"
            and job.get("status") == "queued" and job.get("conclusion") is None,
            "native-queued-job")
    require(job.get("runner_id") is None or type(job.get("runner_id")) is int and job["runner_id"] == 0,
            "job-already-assigned")
    require(job.get("runner_group_id") is None or type(job.get("runner_group_id")) is int
            and job["runner_group_id"] in {0, policy.group_id}, "job-other-group")
    try:
        created = datetime.strptime(job["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (KeyError, ValueError, TypeError):
        raise Denied("job-created-time") from None
    require(0 <= (now - created).total_seconds() <= policy.maximum_queue_seconds, "job-queue-expired")
    labels = job.get("labels")
    require(isinstance(labels, list) and all(isinstance(label, str) for label in labels)
            and len(labels) == len(BASE_LABELS) + 1 and len(set(labels)) == len(labels), "job-labels")
    extra = set(labels) - BASE_LABELS
    require(len(extra) == 1 and BASE_LABELS <= set(labels), "job-fixed-labels")
    label = next(iter(extra))
    affinity = re.fullmatch(rf"lit-heavy-{run_id}-1-(heavy|application_acceptance)-(0|[1-9][0-9]{{0,2}})", label)
    require(affinity is not None and int(affinity[2]) < 256, "job-affinity")
    profile, index = affinity[1], int(affinity[2])
    prefix = "Heavy / heavy / " if profile == "heavy" else "Application Acceptance / application_acceptance / "
    name = job.get("name")
    require(isinstance(name, str) and name.startswith(prefix) and len(name) <= 512, "native-worker-cell")
    empty_group(client, policy)
    return Ticket(run_id, job_id, policy.group_id, policy.caller_sha, policy.callee_sha,
                  request[1], profile, index, label, hashlib.sha256(name.encode()).hexdigest())


def revalidate(client, policy, ticket, *, now):
    require(type(ticket) is Ticket and admit(client, policy, ticket.run_id, ticket.job_id, now=now) == ticket,
            "admission-drift")
