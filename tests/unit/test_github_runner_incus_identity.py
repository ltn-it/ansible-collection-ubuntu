"""Credential-free component tests; native snapshots are trusted daemon inputs.

Synthetic signed tokens qualify the pure verifier, not GitHub token availability,
an installed issuer, service isolation, an Incus grant or Heavy acceptance.
"""
import base64
import copy
from dataclasses import replace
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "roles/github_runner/files/incus_lease_issuer/identity.py"
SPEC = importlib.util.spec_from_file_location("github_runner_incus_identity_under_test", MODULE_PATH)
identity = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = identity
SPEC.loader.exec_module(identity)

NOW = 1793772000
REPOSITORY = "ltn-it/ansible-collection-supplementary"
CALLER_SHA = "a" * 40
REUSABLE_SHA = "b" * 40
WORKFLOW_PATH = ".github/workflows/collection-ci.yml"
REUSABLE_REPOSITORY = "ltn-it/modulix-validation"
REUSABLE_PATH = ".github/workflows/collection-quality-profile.yml"
SUBJECT = (
    "repo:ltn-it@54334171/ansible-collection-supplementary@1103407173"
    ":environment:ansible-collection-runtime-protected"
)
AUDIENCE = "https://issuer.example.invalid/incus-pilot"


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def encoded_integer(value):
    return b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def json_bytes(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


class CurrentJobIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # No committed private material, credentials, subprocess or provider call.
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.policy = identity.Policy(
            repository=REPOSITORY, repository_id=1103407173, owner_id=54334171,
            caller_sha=CALLER_SHA, workflow_id=214182490, workflow_path=WORKFLOW_PATH,
            reusable_repository=REUSABLE_REPOSITORY, reusable_path=REUSABLE_PATH,
            reusable_sha=REUSABLE_SHA, runner_id=61, runner_name="isolated-runner-01",
            service_uid=2101, actor_ids=frozenset({76040632}), subject=SUBJECT,
            visibility="public",
        )
        self.claims = {
            "iss": "https://token.actions.githubusercontent.com", "aud": AUDIENCE,
            "sub": SUBJECT, "jti": "synthetic-one-use-token-id",
            "iat": NOW - 20, "nbf": NOW - 20, "exp": NOW + 300,
            "repository": REPOSITORY, "repository_id": "1103407173",
            "repository_owner": "ltn-it", "repository_owner_id": "54334171",
            "repository_visibility": "public", "run_id": "501", "run_attempt": "1",
            "check_run_id": "731", "actor": "litroc", "actor_id": "76040632",
            "event_name": "push", "ref": "refs/heads/main", "ref_type": "branch",
            "ref_protected": "true", "sha": CALLER_SHA,
            "workflow_ref": REPOSITORY + "/" + WORKFLOW_PATH + "@refs/heads/main",
            "workflow_sha": CALLER_SHA,
            "job_workflow_ref": REUSABLE_REPOSITORY + "/" + REUSABLE_PATH + "@" + REUSABLE_SHA,
            "job_workflow_sha": REUSABLE_SHA, "runner_environment": "self-hosted",
        }
        actor = {"login": "litroc", "id": 76040632, "type": "User"}
        self.run = {
            "id": 501, "run_attempt": 1, "event": "push", "head_branch": "main",
            "head_sha": CALLER_SHA, "workflow_id": 214182490, "path": WORKFLOW_PATH,
            "status": "in_progress", "conclusion": None,
            "repository": {"id": 1103407173, "full_name": REPOSITORY, "private": False,
                           "owner": {"login": "ltn-it", "id": 54334171, "type": "Organization"}},
            "actor": actor, "triggering_actor": dict(actor),
            "referenced_workflows": [{
                "path": REUSABLE_REPOSITORY + "/" + REUSABLE_PATH + "@" + REUSABLE_SHA,
                "sha": REUSABLE_SHA, "ref": REUSABLE_SHA,
            }],
        }
        self.job = {
            "id": 902, "run_id": 501, "head_sha": CALLER_SHA,
            "check_run_url": "https://api.github.com/repos/" + REPOSITORY + "/check-runs/731",
            "status": "in_progress", "conclusion": None,
            "runner_id": 61, "runner_name": "isolated-runner-01",
            "runner_group_id": 7, "runner_group_name": "isolated-pilot",
            "labels": ["self-hosted", "linux", "x64"],
        }
        distractor = {**self.job, "id": 903,
                      "check_run_url": "https://api.github.com/repos/" + REPOSITORY + "/check-runs/732",
                      "runner_id": 62, "runner_name": "other-runner"}
        self.jobs = {"total_count": 2, "jobs": [distractor, self.job], "run_attempt": 1}
        self.jwks = json_bytes({"keys": [self.public_key(self.key)]})

    @staticmethod
    def public_key(key, kid="synthetic-rsa-key"):
        numbers = key.public_key().public_numbers()
        return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
                "n": encoded_integer(numbers.n), "e": encoded_integer(numbers.e)}

    def token(self, claims=None, *, header=None, payload_bytes=None, key=None):
        header = header if header is not None else {"alg": "RS256", "kid": "synthetic-rsa-key", "typ": "JWT"}
        payload = payload_bytes if payload_bytes is not None else json_bytes(
            self.claims if claims is None else claims)
        body = b64url(json_bytes(header)) + "." + b64url(payload)
        signature = (key or self.key).sign(body.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return body + "." + b64url(signature)

    def verify(self, *, token=None, claims=None, jwks=None, run=None, jobs=None,
               observed_at=NOW, now=NOW, peer_uid=2101, audience=AUDIENCE):
        return identity.verify_current_job(
            self.token(claims) if token is None else token,
            self.jwks if jwks is None else jwks, self.policy,
            audience=audience, peer_uid=peer_uid,
            run=self.run if run is None else run, jobs=self.jobs if jobs is None else jobs,
            observed_at=observed_at, now=now,
        )

    def deny(self, **kwargs):
        # Public reason codes must be deterministic and contain no JWT/claim data.
        messages = []
        for _ in range(2):
            with self.assertRaises(identity.Denied) as caught:
                self.verify(**kwargs)
            self.assertIsInstance(caught.exception, ValueError)
            message = str(caught.exception)
            self.assertRegex(message, r"^[a-z][a-z0-9_-]{0,95}$")
            self.assertNotIn("synthetic-one-use-token-id", message)
            messages.append(message)
        self.assertEqual(messages[0], messages[1])

    def receiver_fixture(self):
        self.policy = replace(self.policy, repository="ltn-it/modulix-validation", repository_id=1269461997,
            workflow_path=".github/workflows/mlx90-collection-candidate-validation.yml",
            reusable_repository="ltn-it/modulix-validation",
            reusable_path=".github/workflows/collection-quality-profile-isolated.yml",
            actor_ids=frozenset({307565056}),
            subject="repo:ltn-it/modulix-validation:environment:heavy-isolated-pilot",
            required_native_job_name="heavy / kernel / ubuntu24")
        self.claims.update(repository=self.policy.repository, repository_id=str(self.policy.repository_id),
            sub=self.policy.subject, actor="lightning-it-release-automation[bot]", actor_id="307565056",
            event_name="workflow_dispatch", workflow_ref=self.policy.repository + "/" + self.policy.workflow_path + "@refs/heads/main",
            job_workflow_ref=self.policy.reusable_repository + "/" + self.policy.reusable_path + "@" + self.policy.reusable_sha)
        actor = {"id": 307565056, "login": "lightning-it-release-automation[bot]", "type": "Bot"}
        self.run.update(event="workflow_dispatch", path=self.policy.workflow_path, actor=actor, triggering_actor=dict(actor))
        self.run["repository"].update(id=self.policy.repository_id, full_name=self.policy.repository)
        reference = {"path": self.claims["job_workflow_ref"], "sha": self.policy.reusable_sha, "ref": self.policy.reusable_sha}
        self.run["referenced_workflows"] = [reference, dict(reference)]
        for job in self.jobs["jobs"]:
            if job["id"] == self.job["id"]:
                job.update(name=self.policy.required_native_job_name,
                           check_run_url="https://api.github.com/repos/" + self.policy.repository + "/check-runs/731")

    def test_root_bound_validation_main_app_dispatch_keeps_native_physical_assignment(self):
        self.receiver_fixture()
        result = self.verify()
        self.assertEqual((result.runner_id, result.service_uid), (61, 2101))
        self.assertEqual(result.policy_sha256, identity.policy_digest(self.policy))
        changed = copy.deepcopy(self.jobs)
        changed["jobs"][-1]["runner_id"] = 999
        self.deny(jobs=changed)

    def test_receiver_domain_rejects_human_rerun_push_and_fork(self):
        self.receiver_fixture()
        for claims in ({**self.claims, "actor_id": "76040632", "actor": "litroc"},
                       {**self.claims, "run_attempt": "2"}, {**self.claims, "event_name": "push"}):
            self.deny(claims=claims)
        self.deny(run={**self.run, "head_repository": {"id": 1}})
        self.deny(run={**self.run, "triggering_actor": {"id": 76040632, "login": "litroc", "type": "User"}})

    def test_dispatch_cannot_switch_trusted_root_policy_or_borrow_other_callee(self):
        self.receiver_fixture()
        original = self.policy
        for change in ({"actor_ids": frozenset({307565056, 76040632})},
                       {"repository_id": 1}, {"required_native_job_name": None},
                       {"subject": "repo:ltn-it/modulix-validation:ref:refs/heads/main"}):
            self.policy = replace(original, **change)
            self.deny()
        self.policy = original
        reference = copy.deepcopy(self.run["referenced_workflows"])
        reference[-1]["sha"] = "f" * 40
        self.deny(run={**self.run, "referenced_workflows": reference})

    def test_legacy_main_push_does_not_gain_release_app_dispatch_authority(self):
        self.deny(claims={**self.claims, "actor": "lightning-it-release-automation[bot]",
                          "actor_id": "307565056", "event_name": "workflow_dispatch"})

    def test_signed_check_matches_exact_native_job_without_equating_ids(self):
        result = self.verify()
        self.assertEqual((result.run_id, result.job_id, result.check_run_id), (501, 902, 731))
        self.assertEqual((result.runner_id, result.service_uid), (61, 2101))
        self.assertEqual((result.caller_sha, result.reusable_sha), (CALLER_SHA, REUSABLE_SHA))
        self.assertGreater(result.valid_until, NOW)
        self.assertLessEqual(result.valid_until, self.claims["exp"])
        self.assertEqual(result.token_id_sha256,
                         hashlib.sha256(self.claims["jti"].encode()).hexdigest())

    def test_root_cell_name_binds_joined_native_job_without_request_locator(self):
        from dataclasses import replace
        name = "synthetic-heavy / profile-cells (keycloak-vm)"
        self.policy = replace(self.policy, required_native_job_name=name)
        self.job["name"] = name
        self.assertEqual(self.verify().job_id, 902)
        for wrong in (None, "", name + " ", "other-cell", True, [name]):
            jobs = copy.deepcopy(self.jobs)
            jobs["jobs"][1]["name"] = wrong
            with self.subTest(wrong=wrong):
                self.deny(jobs=jobs)
        # A genuine matching name on another native check cannot transfer it.
        jobs = copy.deepcopy(self.jobs)
        jobs["jobs"][0]["name"] = name
        jobs["jobs"][1].pop("name")
        self.deny(jobs=jobs)

    def test_root_native_job_name_policy_rejects_coercion_and_control_text(self):
        from dataclasses import replace
        for wrong in ("", True, 17, [], "line\nbreak", "delete\x7f", "x" * 1025):
            with self.subTest(wrong=wrong):
                self.policy = replace(self.policy, required_native_job_name=wrong)
                self.deny()

    def test_canonical_numeric_claims_and_explicit_protected_boolean(self):
        claims = dict(self.claims)
        for name in ("repository_id", "repository_owner_id", "run_id", "run_attempt", "check_run_id", "actor_id"):
            claims[name] = int(claims[name])
        claims["ref_protected"] = True
        self.assertEqual(self.verify(claims=claims, observed_at=NOW - 10).job_id, 902)

    def test_verified_identity_records_complete_root_policy_domain(self):
        from dataclasses import asdict, replace
        value = asdict(self.policy)
        value["actor_ids"] = sorted(self.policy.actor_ids)
        expected = hashlib.sha256(json_bytes(value)).hexdigest()
        self.assertEqual(self.verify().policy_sha256, expected)
        for changes in ({"repository": "other/repository"}, {"owner_id": 123},
                        {"subject": "different-subject"}, {"actor_ids": frozenset({76040632, 247824904})},
                        {"required_native_job_name": "different-cell"}):
            with self.subTest(changes=changes):
                self.assertNotEqual(identity.policy_digest(replace(self.policy, **changes)), expected)

    def test_configured_litdeg_identity_is_equal_without_aliasing_litroc(self):
        self.policy = replace(self.policy, actor_ids=frozenset({76040632, 247824904}))
        claims = {**self.claims, "actor": "litdeg", "actor_id": "247824904"}
        run = copy.deepcopy(self.run)
        run["actor"] = {"login": "litdeg", "id": 247824904, "type": "User"}
        run["triggering_actor"] = dict(run["actor"])
        self.assertEqual(self.verify(claims=claims, run=run).job_id, 902)
        self.deny(claims=claims, run=self.run)

    def test_identity_numbers_reject_coercion_and_noncanonical_text(self):
        cases = {"bool": True, "float": 501.0, "leading-zero": "0501",
                 "unicode": "５０１", "space": " 501", "zero": 0, "negative": -1}
        for label, value in cases.items():
            with self.subTest(case=label):
                self.deny(claims={**self.claims, "run_id": value})
        # True compares equal to the expected attempt1 in Python; value matching
        # alone must not admit a JSON boolean as a provider identity number.
        self.deny(claims={**self.claims, "run_attempt": True})

    def test_numeric_date_claims_reject_bool_float_and_text(self):
        for name in ("iat", "nbf", "exp"):
            for value in (True, float(self.claims[name]), str(self.claims[name])):
                with self.subTest(claim=name, value_type=type(value).__name__):
                    self.deny(claims={**self.claims, name: value})

    def test_protected_ref_does_not_accept_truthy_values(self):
        for value in (1, "1", "True", False, "false", None):
            with self.subTest(value=value):
                self.deny(claims={**self.claims, "ref_protected": value})

    def test_issuer_audience_subject_and_reusable_provenance_are_exact(self):
        changes = {
            "iss": "https://attacker.example.invalid", "aud": AUDIENCE + "/other",
            "sub": "repo:" + REPOSITORY + ":ref:refs/heads/main",
            "job_workflow_ref": REUSABLE_REPOSITORY + "/" + REUSABLE_PATH + "@refs/heads/main",
            "job_workflow_sha": "c" * 40, "workflow_sha": "c" * 40,
            "sha": "c" * 40, "repository_visibility": "private",
            "repository_id": "1103407174", "repository_owner_id": "54334172",
            "repository": "ltn-it/other", "runner_environment": "github-hosted",
            "actor_id": "247824904", "event_name": "pull_request", "run_attempt": "2",
            "ref": "refs/heads/develop",
        }
        for name, value in changes.items():
            with self.subTest(claim=name):
                self.deny(claims={**self.claims, name: value})

    def test_absent_required_signed_identity_is_not_reconstructed_from_api(self):
        for name in ("jti", "exp", "sub", "check_run_id", "job_workflow_ref", "job_workflow_sha"):
            claims = dict(self.claims)
            del claims[name]
            with self.subTest(claim=name):
                self.deny(claims=claims)

    def test_expiry_and_future_token_reject_at_the_boundary(self):
        for changes in ({"exp": NOW}, {"exp": NOW - 1}, {"nbf": NOW + 1}, {"iat": NOW + 1}):
            with self.subTest(changes=changes):
                self.deny(claims={**self.claims, **changes})

    def test_snapshot_stale_or_future_and_foreign_local_uid_deny(self):
        self.deny(observed_at=NOW - 11)
        self.deny(observed_at=NOW + 1)
        self.deny(peer_uid=2102)
        self.deny(peer_uid=True)

    def test_signature_cannot_be_bypassed_with_another_key_or_algorithm(self):
        self.deny(token=self.token(key=self.foreign_key))
        for algorithm in ("none", "HS256", "RS512"):
            with self.subTest(algorithm=algorithm):
                self.deny(token=self.token(header={"alg": algorithm, "kid": "synthetic-rsa-key"}))
        parts = self.token().split(".")
        signature = bytearray(base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4)))
        signature[0] ^= 1
        self.deny(token=".".join(parts[:2] + [b64url(bytes(signature))]))

    def test_unknown_or_ambiguous_jwks_key_is_not_guessed(self):
        self.deny(token=self.token(header={"alg": "RS256", "kid": "unknown"}))
        key = self.public_key(self.key)
        self.deny(jwks=json_bytes({"keys": [key, self.public_key(self.foreign_key)]}))
        self.deny(jwks=json_bytes({"keys": [{**key, "use": "enc"}]}))

    def test_jwks_rotation_can_include_an_unrelated_key(self):
        jwks = json_bytes({"keys": [self.public_key(self.foreign_key, "other-key"),
                                    self.public_key(self.key)]})
        self.assertEqual(self.verify(jwks=jwks).check_run_id, 731)

    def test_documented_thumbprint_is_opaque_and_cannot_supply_a_key_url(self):
        header = {"alg": "RS256", "kid": "synthetic-rsa-key", "typ": "JWT", "x5t": b64url(b"x" * 20)}
        self.assertEqual(self.verify(token=self.token(header=header)).job_id, 902)
        self.deny(token=self.token(header={**header, "jku": "https://attacker.example.invalid/keys"}))
        self.deny(token=self.token(header={**header, "x5t": "https://attacker.example.invalid/keys"}))

    def test_duplicate_json_cannot_change_the_verified_meaning(self):
        payload = json_bytes(self.claims)
        duplicate = b'{"run_id":"999",' + payload[1:]
        self.deny(token=self.token(payload_bytes=duplicate))
        header = b'{"alg":"none","alg":"RS256","kid":"synthetic-rsa-key"}'
        body = b64url(header) + "." + b64url(payload)
        signed = self.key.sign(body.encode(), padding.PKCS1v15(), hashes.SHA256())
        self.deny(token=body + "." + b64url(signed))
        key = json_bytes(self.public_key(self.key))
        self.deny(jwks=b'{"keys":[],"keys":[' + key + b']}')

    def test_malformed_compact_tokens_raise_safe_denials(self):
        for token in ("", "not-a-token", "a.b.c.d", "*.e30.invalid", "é.e30.invalid"):
            with self.subTest(token_shape=len(token)):
                self.deny(token=token)

    def test_nonfinite_json_extension_is_rejected_even_when_not_a_used_claim(self):
        for literal in (b"NaN", b"Infinity", b"-Infinity", b"1e999"):
            payload = b'{"unused_extension":' + literal + b"," + json_bytes(self.claims)[1:]
            with self.subTest(literal=literal):
                self.deny(token=self.token(payload_bytes=payload))

    def test_complete_exact_attempt_snapshot_is_mandatory(self):
        for jobs in (
            self.jobs["jobs"], {**self.jobs, "total_count": 3},
            {**self.jobs, "total_count": True}, {**self.jobs, "run_attempt": 2},
            {"total_count": 2, "jobs": self.jobs["jobs"]},
            {**self.jobs, "jobs": []},
        ):
            with self.subTest(shape=type(jobs).__name__):
                self.deny(jobs=jobs)

    def test_ambiguous_check_assignment_or_duplicate_job_id_denies(self):
        duplicate_check = {**self.job, "id": 904}
        self.deny(jobs={"total_count": 2, "run_attempt": 1,
                        "jobs": [self.job, duplicate_check]})
        duplicate_id = {**self.jobs["jobs"][0], "id": self.job["id"]}
        self.deny(jobs={"total_count": 2, "run_attempt": 1,
                        "jobs": [self.job, duplicate_id]})

    def test_check_url_must_be_exact_canonical_api_repository_path(self):
        urls = (
            "http://api.github.com/repos/" + REPOSITORY + "/check-runs/731",
            "https://attacker.invalid/repos/" + REPOSITORY + "/check-runs/731",
            "https://api.github.com/repos/ltn-it/other/check-runs/731",
            self.job["check_run_url"] + "?ignored=1", self.job["check_run_url"] + "/",
            "https://api.github.com/repos/" + REPOSITORY + "/check-runs/0731",
        )
        for url in urls:
            jobs = copy.deepcopy(self.jobs)
            jobs["jobs"][1]["check_run_url"] = url
            with self.subTest(url_shape=url.rsplit("/", 1)[-1]):
                self.deny(jobs=jobs)

    def test_job_assignment_must_still_be_live_and_on_accepted_listener(self):
        changes = ({"run_id": 502}, {"head_sha": "c" * 40}, {"status": "queued"},
                   {"status": "completed", "conclusion": "success"}, {"conclusion": "failure"},
                   {"runner_id": 0}, {"runner_id": 62}, {"runner_id": True},
                   {"runner_name": "other-runner"})
        for change in changes:
            jobs = copy.deepcopy(self.jobs)
            jobs["jobs"][1].update(change)
            with self.subTest(change=change):
                self.deny(jobs=jobs)

    def test_run_snapshot_must_match_current_protected_caller(self):
        changes = ({"id": 502}, {"run_attempt": 2}, {"event": "workflow_dispatch"},
                   {"head_branch": "develop"}, {"head_sha": "c" * 40},
                   {"workflow_id": 214182491}, {"path": ".github/workflows/other.yml"},
                   {"status": "completed", "conclusion": "success"},
                   {"actor": {"login": "litroc", "id": 76040632, "type": "Bot"}},
                   {"actor": {"login": "foreign", "id": 42, "type": "User"}},
                   {"referenced_workflows": []})
        for change in changes:
            with self.subTest(change=change):
                self.deny(run={**self.run, **change})
        run = copy.deepcopy(self.run)
        run["repository"]["owner"]["id"] = 1
        self.deny(run=run)
        run = copy.deepcopy(self.run)
        run["repository"]["full_name"] = "ltn-it/other"
        self.deny(run=run)


if __name__ == "__main__":
    unittest.main()
