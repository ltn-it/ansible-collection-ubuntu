"""Verify GitHub OIDC and its independently acquired current job assignment.

This component does not issue TLS credentials, create leases, or grant engine
access. A future root-owned issuer must additionally enforce its one-use
challenge/worker binding, replay ledger, cell policy, custody and cleanup.
Use verify_github_assignment at that boundary: request-body metadata must never
be supplied as the run/jobs arguments of the pure verification helper.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import hashlib
import json
import math
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from dataclasses import replace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ISSUER = "https://token.actions.githubusercontent.com"
JWKS_URL = ISSUER + "/.well-known/jwks"
API = "https://api.github.com"
SHA = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*\Z")
WORKFLOW = re.compile(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml\Z")


class Denied(ValueError):
    """Safe reason code only; never include token, key or HTTP response data."""


_DIAGNOSTIC_STAGES = frozenset({
    "bootstrap", "bootstrap-policy", "bootstrap-selector", "bootstrap-authentication",
    "bootstrap-initial-native", "bootstrap-configuration", "bootstrap-final-native",
    "collector", "installation", "native-controls", "native-worker", "native-assignment",
    "native-current", "native-histories", "intake-stage", "intake-discovery",
    "snapshot-acquisition", "snapshot-readback", "observer", "observer-lookup",
    "observer-native", "runtime-selected",
})
_DIAGNOSTIC_REASONS = frozenset({
    "bootstrap-challenge-expired", "bootstrap-native-denied", "bootstrap-native-drift",
    "bootstrap-native-expired", "bootstrap-policy-changed", "bootstrap-workflow-sha",
    "bootstrap-native-job", "collector-acquisition-denied", "collector-maps-changed",
    "collector-process-changed", "collector-peer-changed", "collector-trust-changed",
    "process-root-tree-changed", "process-root-inventory-mismatch", "process-root-file-mismatch",
    "process-root-directory-changed", "process-diagnostics-enabled", "process-privilege-state",
    "process-apparmor-profile", "jit-backing-changed", "io-uring-backing-changed",
    "installation-filesystem", "installation-file-hash", "installation-tree-changed",
    "installation-manifest-changed", "installation-root-changed", "installation-acquisition-denied", "installation-entry-changed", "installation-directory-changed",
    "installation-inventory-limit", "installation-hash-workers-not-joined",
    "https-read-failed", "https-status", "https-body-limit", "token-time", "invalid-signature",
    "issuer-or-audience", "stale-observation", "native-run-mismatch", "native-job-assignment",
    "native-job-cell-name", "native-check-job-join", "incomplete-job-inventory",
    "current-protected-main", "native-reusable-workflow", "native-repository-mismatch",
    "native-actor", "continuation-original-native-drift", "continuation-prior-native-drift",
    "continuation-exact-current-native-tuple", "continuation-original-or-unknown-lease",
    "intake-current-main", "intake-controller-main", "intake-controller-publication",
    "intake-artifact-inventory", "intake-artifact-unique", "intake-artifact-digest",
    "intake-memory-artifact-size", "intake-auth-budget", "intake-stage-native-drift",
    "intake-snapshot-held", "intake-stage-held", "run-configuration-held",
    "run-config-lookup-unique", "run-config-observer", "run-configuration-lookup-held", "runtime-observer-original-lease",
    "runtime-observer-original-invocation", "runtime-bootstrap-selector", "ledger-busy",
})


@dataclass(frozen=True)
class _Diagnostic:
    wall: float
    cpu: float
    owner_pid: int
    counts: tuple[tuple[str, int, int], ...] = ()
    stage: str | None = None
    reason: str = "unclassified"


_DIAGNOSTIC: ContextVar[_Diagnostic | None] = ContextVar("lit_root_runtime_diagnostic", default=None)


def _diagnostic_failed(stage, error):
    """Capture only a fixed code before a wrapper discards the original error.

    No exception formatting, cause traversal or caller data is permitted. State
    is immutable: copied contexts cannot mutate the originating request record.
    This record is observability only, never identity or admission evidence.
    """
    current = _DIAGNOSTIC.get()
    if current is None or current.stage is not None or type(stage) is not str or stage not in _DIAGNOSTIC_STAGES:
        return
    reason = "unclassified"
    if type(error) is Denied:
        args = error.args
        if len(args) == 1 and type(args[0]) is str and args[0] in _DIAGNOSTIC_REASONS:
            reason = args[0]
    _DIAGNOSTIC.set(replace(current, stage=stage, reason=reason))


def _diagnostic_count(stage, completed):
    current = _DIAGNOSTIC.get()
    if current is None:
        return
    counts = {name: (started, finished) for name, started, finished in current.counts}
    started, finished = counts.get(stage, (0, 0))
    counts[stage] = (min(1024, started + (not completed)), min(1024, finished + completed))
    _DIAGNOSTIC.set(replace(current, counts=tuple((name, *values) for name, values in sorted(counts.items()))))


def _diagnostic_step(stage):
    if type(stage) is not str or stage not in _DIAGNOSTIC_STAGES:
        raise ValueError("unknown-private-diagnostic-stage")
    def decorate(function):
        @wraps(function)
        def call(*args, **kwargs):
            if _DIAGNOSTIC.get() is None:
                return function(*args, **kwargs)
            _diagnostic_count(stage, False)
            try:
                result = function(*args, **kwargs)
            except Exception as error:
                _diagnostic_failed(stage, error)
                raise
            _diagnostic_count(stage, True)
            return result
        return call
    return decorate


@contextmanager
def _diagnostic_request(*, reuse=False):
    """One Root AUTHPRIV terminal record; no public framing or policy change.

    The existing journal attaches the real PID/UID/unit. Consumers must verify
    that provenance; the JSON is not an authentication or acceptance receipt.
    No durable request data or cross-request cache is introduced.
    """
    if reuse and _DIAGNOSTIC.get() is not None:
        yield
        return
    token = _DIAGNOSTIC.set(_Diagnostic(time.monotonic(), time.process_time(), os.getpid()))
    try:
        yield
    finally:
        current = _DIAGNOSTIC.get()
        _DIAGNOSTIC.reset(token)
        if current is not None and current.stage is not None and current.owner_pid == os.getpid() and os.geteuid() == 0:
            try:
                import syslog
                elapsed = lambda start, now: min(86400000, max(0, int((now - start) * 1000)))
                message = {"schema": 1, "component": "incus-runtime-v2", "stage": current.stage,
                    "reason": current.reason, "wall_ms": elapsed(current.wall, time.monotonic()),
                    "cpu_ms": elapsed(current.cpu, time.process_time()), "counts": current.counts}
                # One nonblocking datagram to the existing local journal socket.
                # syslog.syslog() may block on a full queue; diagnostics must not
                # extend a request's native deadline or hold its cleanup open.
                priority = syslog.LOG_AUTHPRIV | syslog.LOG_ERR
                payload = ("<" + str(priority) + ">lit-incus-runtime-v2: "
                           + json.dumps(message, separators=(",", ":"))).encode("ascii")
                with socket.socket(socket.AF_UNIX,
                                   socket.SOCK_DGRAM | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK) as output:
                    output.sendto(payload, "/dev/log")
            except Exception:
                # Diagnostic transport failure cannot convert a denial to success
                # or replace the original public response/exception.
                pass


def require(value, reason):
    if not value:
        raise Denied(reason)


def integer(value):
    """Explicit JSON integer/canonical ASCII decimal union; never coerce bool."""
    if type(value) is int and value > 0:
        return value
    if type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value):
        return int(value)
    raise Denied("invalid-id")


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def decode_json(raw):
    def reject_constant(_):
        raise Denied("invalid-json-number")

    def finite_float(value):
        number = float(value)
        require(math.isfinite(number), "invalid-json-number")
        return number

    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant, parse_float=finite_float)
    except Denied:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        raise Denied("invalid-json") from None
    require(type(result) is dict, "invalid-json-object")
    return result


def unbase(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]+", value), "invalid-base64url")
    try:
        result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        raise Denied("invalid-base64url") from None
    require(base64.urlsafe_b64encode(result).decode().rstrip("=") == value, "noncanonical-base64url")
    return result


@dataclass(frozen=True)
class Policy:
    repository: str
    repository_id: int
    owner_id: int
    caller_sha: str
    workflow_id: int
    workflow_path: str
    reusable_repository: str
    reusable_path: str
    reusable_sha: str
    runner_id: int
    runner_name: str
    service_uid: int
    actor_ids: frozenset[int]
    subject: str
    visibility: str = "public"
    # Optional for the standalone identity component. The production admission
    # bridge requires an exact Root-selected name from its immutable cell map.
    required_native_job_name: str | None = None

    def validate(self):
        require(REPOSITORY.fullmatch(self.repository) and REPOSITORY.fullmatch(self.reusable_repository),
                "invalid-policy-repository")
        require(WORKFLOW.fullmatch(self.workflow_path) and WORKFLOW.fullmatch(self.reusable_path),
                "invalid-policy-workflow")
        require(SHA.fullmatch(self.caller_sha) and SHA.fullmatch(self.reusable_sha), "invalid-policy-sha")
        for value in (self.repository_id, self.owner_id, self.workflow_id, self.runner_id, self.service_uid):
            require(type(value) is int and value > 0, "invalid-policy-id")
        require(type(self.actor_ids) is frozenset and self.actor_ids
                and all(type(v) is int and v > 0 for v in self.actor_ids), "invalid-policy-actors")
        require(type(self.runner_name) is str and 0 < len(self.runner_name) <= 256, "invalid-policy-runner")
        require(type(self.subject) is str and 0 < len(self.subject) <= 2048, "invalid-policy-subject")
        require(self.visibility in {"public", "private", "internal"}, "invalid-policy-visibility")
        require(self.required_native_job_name is None or (
            type(self.required_native_job_name) is str
            and 0 < len(self.required_native_job_name) <= 1024
            and not any(ord(c) < 32 or ord(c) == 127 for c in self.required_native_job_name)),
            "invalid-policy-native-job-name")


def validation_main_receiver(policy):
    """Separate closed invocation domain derived only from trusted Root policy.

    No request selector or relaxed legacy predicate. Keep the existing serialized
    policy/digest format: its complete immutable tuple already binds this domain.
    """
    return (policy.repository == "ltn-it/modulix-validation"
            and policy.repository_id == 1269461997 and policy.owner_id == 54334171
            and policy.workflow_path == ".github/workflows/mlx90-collection-candidate-validation.yml"
            and policy.reusable_repository == "ltn-it/modulix-validation"
            and policy.reusable_path == ".github/workflows/collection-quality-profile-isolated.yml"
            and policy.actor_ids == frozenset({307565056})
            and policy.subject == "repo:ltn-it/modulix-validation:environment:heavy-isolated-pilot"
            and policy.visibility == "public" and policy.required_native_job_name is not None)


def policy_digest(policy):
    """Bind the complete Root-selected verification domain, not just Git SHAs."""
    require(type(policy) is Policy, "invalid-policy-type")
    policy.validate()
    value = asdict(policy)
    value["actor_ids"] = sorted(policy.actor_ids)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class Identity:
    run_id: int
    job_id: int
    check_run_id: int
    runner_id: int
    service_uid: int
    caller_sha: str
    reusable_sha: str
    valid_until: int
    token_id_sha256: str
    audience: str
    # Standalone legacy fixtures may omit scope; production admission cannot.
    policy_sha256: str | None = None


def verify_claims(token, jwks_json, policy, audience, now):
    policy.validate()
    require(type(now) is int and now > 0, "invalid-clock")
    require(type(audience) is str and 0 < len(audience) <= 2048, "invalid-audience-policy")
    require(type(token) is str and len(token) <= 16384, "invalid-token")
    pieces = token.split(".")
    require(len(pieces) == 3, "invalid-token")
    header, claims = (decode_json(unbase(part)) for part in pieces[:2])
    require(set(header) <= {"alg", "kid", "typ", "x5t"} and header.get("alg") == "RS256"
            and header.get("typ", "JWT") == "JWT", "unsupported-jwt-header")
    if "x5t" in header:
        # GitHub documents this optional opaque thumbprint. It is never a
        # key source: only kid in the fixed-origin JWKS selects the RSA key.
        require(type(header["x5t"]) is str and 0 < len(header["x5t"]) <= 128
                and re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", header["x5t"]), "invalid-thumbprint")
    require(type(header.get("kid")) is str and 0 < len(header["kid"]) <= 256, "invalid-key-id")
    require(type(jwks_json) is bytes and len(jwks_json) <= 1048576, "invalid-jwks")
    keys = decode_json(jwks_json).get("keys")
    require(type(keys) is list and len(keys) <= 100 and all(type(k) is dict for k in keys), "invalid-jwks")
    matching = [k for k in keys if k.get("kid") == header["kid"]]
    require(len(matching) == 1, "unknown-or-ambiguous-key")
    key = matching[0]
    require(key.get("kty") == "RSA" and key.get("alg", "RS256") == "RS256"
            and key.get("use", "sig") == "sig"
            and ("key_ops" not in key or key["key_ops"] == ["verify"]), "unsupported-jwk")
    modulus, exponent = unbase(key.get("n")), unbase(key.get("e"))
    require(modulus[0] != 0 and exponent[0] != 0 and 256 <= len(modulus) <= 1024,
            "invalid-rsa-key")
    require(int.from_bytes(exponent, "big") == 65537, "unsupported-rsa-exponent")
    try:
        public = rsa.RSAPublicNumbers(65537, int.from_bytes(modulus, "big")).public_key()
        require(2048 <= public.key_size <= 8192, "invalid-rsa-key")
        public.verify(unbase(pieces[2]), (pieces[0] + "." + pieces[1]).encode("ascii"),
                      padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError):
        raise Denied("invalid-signature") from None
    require(claims.get("iss") == ISSUER and claims.get("aud") == audience, "issuer-or-audience")
    for field in ("exp", "iat", "nbf"):
        require(type(claims.get(field)) is int and claims[field] > 0, "invalid-token-time")
    require(now < claims["exp"] and claims["iat"] <= now and claims["nbf"] <= now
            and 0 < claims["exp"] - claims["iat"] <= 900 and claims["nbf"] < claims["exp"], "token-time")
    require(type(claims.get("jti")) is str
            and re.fullmatch(r"[A-Za-z0-9._:-]{1,256}", claims["jti"]), "missing-token-id")
    for field, wanted in {"repository": policy.repository, "repository_owner": policy.repository.split("/")[0],
                          "repository_visibility": policy.visibility, "sub": policy.subject,
                          "event_name": "workflow_dispatch" if validation_main_receiver(policy) else "push",
                          "ref": "refs/heads/main", "ref_type": "branch",
                          "sha": policy.caller_sha, "workflow_sha": policy.caller_sha,
                          "workflow_ref": policy.repository + "/" + policy.workflow_path + "@refs/heads/main",
                          "job_workflow_ref": policy.reusable_repository + "/" + policy.reusable_path
                          + "@" + policy.reusable_sha,
                          "job_workflow_sha": policy.reusable_sha, "runner_environment": "self-hosted"}.items():
        require(claims.get(field) == wanted, "claim-policy-mismatch")
    protected = claims.get("ref_protected")
    require(protected is True or (type(protected) is str and protected == "true"), "unprotected-ref")
    require(integer(claims.get("repository_id")) == policy.repository_id
            and integer(claims.get("repository_owner_id")) == policy.owner_id
            and integer(claims.get("actor_id")) in policy.actor_ids, "claim-identity")
    require(type(claims.get("actor")) is str and 0 < len(claims["actor"]) <= 256, "claim-actor")
    if validation_main_receiver(policy):
        require(claims["actor"] == "lightning-it-release-automation[bot]", "claim-receiver-actor")
    require(integer(claims.get("run_attempt")) == 1, "unsupported-attempt")
    integer(claims.get("run_id"))
    integer(claims.get("check_run_id"))
    return claims


def verify_current_job(token, jwks_json, policy, *, audience, peer_uid, run, jobs, observed_at, now):
    """Pure verifier for root-acquired snapshots, NOT a caller-metadata admission API."""
    claims = verify_claims(token, jwks_json, policy, audience, now)
    require(type(peer_uid) is int and peer_uid == policy.service_uid, "peer-uid")
    require(type(observed_at) is int and 0 <= now - observed_at <= 10, "stale-observation")
    run_id, check_id = integer(claims["run_id"]), integer(claims["check_run_id"])
    require(type(run) is dict and type(jobs) is dict, "invalid-native-snapshot")
    require(run.get("id") == run_id and type(run.get("id")) is int
            and type(run.get("run_attempt")) is int and run["run_attempt"] == 1
            and run.get("event") == ("workflow_dispatch" if validation_main_receiver(policy) else "push")
            and run.get("head_branch") == "main"
            and run.get("head_sha") == policy.caller_sha and run.get("status") == "in_progress"
            and run.get("conclusion") is None
            and type(run.get("workflow_id")) is int and run["workflow_id"] == policy.workflow_id
            and run.get("path") == policy.workflow_path,
            "native-run-mismatch")
    repo = run.get("repository", {})
    require(type(repo) is dict and type(repo.get("owner")) is dict, "invalid-native-repository")
    owner = repo["owner"]
    require(repo.get("id") == policy.repository_id and type(repo.get("id")) is int
            and repo.get("full_name") == policy.repository and type(owner.get("id")) is int
            and owner["id"] == policy.owner_id and owner.get("login") == policy.repository.split("/")[0]
            and repo.get("private") is (policy.visibility != "public"), "native-repository-mismatch")
    head_repo = run.get("head_repository")
    if head_repo is not None:
        require(type(head_repo) is dict and type(head_repo.get("id")) is int
                and head_repo["id"] == policy.repository_id, "forked-native-source")
    for field in ("actor", "triggering_actor"):
        actor = run.get(field, {})
        require(type(actor) is dict and type(actor.get("id")) is int and actor["id"] == integer(claims["actor_id"])
                and actor.get("login") == claims.get("actor")
                and actor.get("type") == ("Bot" if validation_main_receiver(policy) else "User"), "native-actor")
    referenced = run.get("referenced_workflows", [])
    if validation_main_receiver(policy):
        require(type(referenced) is list and 1 <= len(referenced) <= 2 and all(
            type(row) is dict and row.get("path") == claims["job_workflow_ref"]
            and row.get("sha") == policy.reusable_sha and row.get("ref") in {None, policy.reusable_sha}
            for row in referenced), "native-reusable-workflow")
    else:
        require(type(referenced) is list and len([r for r in referenced if type(r) is dict
                and r.get("path") == claims["job_workflow_ref"] and r.get("sha") == policy.reusable_sha]) == 1,
                "native-reusable-workflow")
    rows = jobs.get("jobs")
    require(type(rows) is list and type(jobs.get("total_count")) is int and len(rows) <= 1000
            and len(rows) == jobs["total_count"] and type(jobs.get("run_attempt")) is int
            and jobs["run_attempt"] == 1 and all(type(j) is dict for j in rows), "incomplete-job-inventory")
    ids = [j.get("id") for j in rows]
    require(all(type(v) is int and v > 0 for v in ids) and len(set(ids)) == len(ids), "ambiguous-job-inventory")
    url = API + "/repos/" + policy.repository + "/check-runs/" + str(check_id)
    matched = [j for j in rows if j.get("check_run_url") == url]
    require(len(matched) == 1, "native-check-job-join")
    job = matched[0]
    if policy.required_native_job_name is not None:
        require(type(job.get("name")) is str and job["name"] == policy.required_native_job_name,
                "native-job-cell-name")
    require(type(job.get("run_id")) is int and job["run_id"] == run_id
            and job.get("head_sha") == policy.caller_sha and job.get("status") == "in_progress"
            and job.get("conclusion") is None and type(job.get("runner_id")) is int
            and job["runner_id"] == policy.runner_id and job.get("runner_name") == policy.runner_name,
            "native-job-assignment")
    return Identity(run_id, job["id"], check_id, policy.runner_id, peer_uid, policy.caller_sha,
                    policy.reusable_sha, claims["exp"], hashlib.sha256(claims["jti"].encode()).hexdigest(), audience,
                    policy_digest(policy))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Denied("https-redirect-denied")


class HTTPSReader:
    """Fixed-origin reads, verified TLS, bounded bodies, no redirects or retries."""

    def read(self, url, *, bearer=None):
        require(url == JWKS_URL or url.startswith(API + "/repos/"), "https-origin-denied")
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "lit-incus-identity/1",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if bearer is not None:
            require(url.startswith(API + "/repos/") and type(bearer) is str
                    and 0 < len(bearer) <= 16384 and not any(c in bearer for c in "\r\n\x00"),
                    "invalid-api-credential")
            headers["Authorization"] = "Bearer " + bearer
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                                            NoRedirect())
        try:
            with opener.open(urllib.request.Request(url, headers=headers), timeout=10) as response:
                require(response.status == 200, "https-status")
                raw = response.read(8388609)
        except (OSError, urllib.error.URLError):
            raise Denied("https-read-failed") from None
        require(len(raw) <= 8388608, "https-body-limit")
        return raw


@_diagnostic_step("native-assignment")
def verify_github_assignment(token, policy, *, audience, peer_uid, access_token, reader=None, clock=time.time):
    """Server-side entry: no caller-provided run, job, runner or JWKS snapshots.

    reader is an internal dependency for offline tests, never a request option.
    The root service supplies policy, audience/challenge and kernel peer UID.
    It must still consume its worker-bound challenge and replay ledger before
    any lease/TLS effect; this function alone never grants such authority.
    """
    reader = reader or HTTPSReader()
    jwks = reader.read(JWKS_URL)
    claims = verify_claims(token, jwks, policy, audience, int(clock()))
    require(type(peer_uid) is int and peer_uid == policy.service_uid, "peer-uid")
    prefix = API + "/repos/" + policy.repository
    run_id = integer(claims["run_id"])
    run_url = prefix + "/actions/runs/" + str(run_id)

    def get(url):
        return decode_json(reader.read(url, bearer=access_token))

    started = int(clock())
    run = get(run_url)
    rows, total = [], None
    for page in range(1, 11):
        payload = get(run_url + "/attempts/1/jobs?per_page=100&page=" + str(page))
        count, batch = payload.get("total_count"), payload.get("jobs")
        require(type(count) is int and 0 <= count <= 1000 and type(batch) is list
                and len(batch) <= 100 and (total is None or count == total), "incomplete-job-inventory")
        total = count
        rows.extend(batch)
        require(len(rows) <= total, "incomplete-job-inventory")
        if len(rows) == total:
            break
        require(len(batch) == 100, "incomplete-job-inventory")
    require(total is not None and len(rows) == total, "incomplete-job-inventory")
    frame = {"run_attempt": 1, "total_count": total, "jobs": rows}
    first = verify_current_job(token, jwks, policy, audience=audience, peer_uid=peer_uid, run=run,
                               jobs=frame, observed_at=started, now=int(clock()))
    # Re-read the actual joined job and run, not latest-attempt or a name match.
    current_job = get(prefix + "/actions/jobs/" + str(first.job_id))
    require(type(current_job.get("id")) is int and current_job["id"] == first.job_id, "native-job-readback")
    current_run = get(run_url)
    branch = get(prefix + "/branches/main")
    require(branch.get("protected") is True and type(branch.get("commit")) is dict
            and branch["commit"].get("sha") == policy.caller_sha,
            "current-protected-main")
    refreshed = [{**j} if j["id"] != first.job_id else current_job for j in rows]
    return verify_current_job(token, jwks, policy, audience=audience, peer_uid=peer_uid,
                              run=current_run, jobs={**frame, "jobs": refreshed},
                              observed_at=started, now=int(clock()))
