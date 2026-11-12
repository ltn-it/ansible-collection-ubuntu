"""Actual Root FS/RS256/Ledger; provider, collector and Root trust realm modeled.

No fixture grants native Source authority. Actual historical input qualification
is separately exercised without modifying the production receipt hash anchor.
"""
import hashlib
import os
import sys
import time
import unittest
from copy import deepcopy
from dataclasses import replace
from unittest import mock

import test_github_runner_incus_run_factory as baseline
from incus_lease_issuer import identity, ledger
from incus_lease_issuer import operating_cells as cells
from incus_lease_issuer import run_factory as factory
from incus_lease_issuer.identity import Denied


def original_native():
    origin = cells.continuation_origin()
    actor = {"login": "litroc", "id": 76040632, "type": "User"}
    run = {"id": cells.ORIGIN_RUN, "run_attempt": 1, "head_sha": cells.ORIGIN_MAIN, "event": "push",
        "head_branch": "main", "workflow_id": 214182490, "status": "completed", "conclusion": "failure",
        "repository": {"id": 1103407173}, "head_repository": {"id": 1103407173}, "actor": actor,
        "triggering_actor": dict(actor), "referenced_workflows": [{"sha": cells.ORIGIN_REUSABLE,
            "path": "ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@" + cells.ORIGIN_REUSABLE}]}
    jobs = [{"id": 1000 + i, "name": "hosted fixture " + str(i), "run_id": cells.ORIGIN_RUN, "run_attempt": 1,
             "head_sha": cells.ORIGIN_MAIN, "status": "completed", "conclusion": "success"} for i in range(22)]
    checks = []
    for row in origin["jobs"]:
        common = {k: row[k] for k in ("name", "started_at", "completed_at", "conclusion")}
        jobs.append({**common, "id": row["job_id"], "run_id": cells.ORIGIN_RUN, "run_attempt": 1,
            "head_sha": cells.ORIGIN_MAIN, "status": "completed", "runner_id": 78, "runner_group_id": 8,
            "check_run_url": identity.API + "/repos/" + factory.SOURCE + "/check-runs/" + str(row["check_run_id"])})
        checks.append({**common, "id": row["check_run_id"], "head_sha": cells.ORIGIN_MAIN, "status": "completed",
                       "app": {"id": 15368, "slug": "github-actions"}})
    return run, {"total_count": 24, "jobs": jobs}, checks, {"sha": cells.ORIGIN_MAIN, "parents": [{"sha": cells.INITIAL_MAIN}]}


class PureContinuationTests(unittest.TestCase):
    def test_original_complete_native_failure_and_negative_metadata(self):
        args = original_native(); self.assertEqual(len(cells.origin_native_projection(*args)["jobs"]), 24)
        for index, change in ((0, lambda x: x.update(run_attempt=2)), (1, lambda x: x["jobs"].pop()),
            (2, lambda x: x[0].update(conclusion="success")), (3, lambda x: x["parents"][0].update(sha="f" * 40))):
            bad = deepcopy(args); change(bad[index])
            with self.subTest(index=index), self.assertRaises(Denied): cells.origin_native_projection(*bad)

    def test_historical_initial_predicate_is_unchanged(self):
        self.assertEqual(cells.INITIAL_MAIN, "90e7216b5d085ca4ac6238e44dcdbaa51e847d5f")
        with self.assertRaises(Denied):
            cells.validate_initial_main({"sha": "a" * 40, "parents": [{"sha": cells.ORIGIN_MAIN}]}, "a" * 40)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootContinuationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): baseline.RootBootstrapTests.setUpClass()

    def setUp(self):
        self.helper = baseline.RootBootstrapTests(methodName="runTest")
        self.helper.setUp(); self.addCleanup(self.helper.doCleanups)
        self.root = self.helper.root
        base_identity = self.helper.value["source_identity"]
        base_identity.update(runner_id=78, runner_name="incus-runner-01", service_uid=995)
        self.helper.value["collector"]["service"]["installation"].update(runner_id=78, service_uid=995)
        self.helper.worker = replace(self.helper.worker, uid=995, runner_id=78)
        self.helper.collected.return_value = self.helper.worker
        self.helper.native.job.update(runner_id=78, runner_name="incus-runner-01", runner_group_id=8)
        self.intakes = self.root / "intakes"; self.intakes.mkdir(mode=0o700)
        self.configs = self.root / "configurations"; self.configs.mkdir(mode=0o700)
        mock.patch.object(factory.run_intake, "ROOT", str(self.intakes)).start()
        mock.patch.object(factory, "ROOT", str(self.configs)).start()
        counts = {name: {"directory_device": path.stat().st_dev, "directory_inode": path.stat().st_ino, "entries": 0}
            for name, path in (("native_intake_catalogue", self.intakes), ("native_run_configuration_catalogue", self.configs))}
        counts["runtime_lease_count"] = 0
        raw = ledger.canonical({"rc": 0, "stderr_bytes": 0, "observed": {"schema": 1,
            "state": "ACTUAL_EXISTING_PRODUCT_STORE_AND_CATALOGUES_EMPTY_NO_INTAKE_OR_LEASE", "at": 1800000000,
            "original_run": cells.ORIGIN_RUN, "original_attempt": 1, "original_head": cells.ORIGIN_MAIN, "counts": counts,
            "no_challenge_or_job_request": True, "no_state_reset_or_cleanup": True,
            "operator_raw_ledger_or_signing_key_read_export_or_hash": False, "product_store_validation_and_lease_ids_only": True}})
        # Bind the genuine temporary Root catalogue realm, never transplant
        # Source host device/inodes or claim this synthetic receipt is native.
        mock.patch.object(cells, "ORIGIN_NO_INTAKE", hashlib.sha256(raw).hexdigest()).start()
        self.origin = original_native()
        self.qualification = cells.continuation_qualification(*self.origin, raw, cells.ORIGIN_CLIENTS)
        self.receipt = self.root / "qualified.json"
        self.receipt.write_bytes(ledger.canonical(self.qualification)); self.receipt.chmod(0o600)
        self.descriptor = {"schema": 1, "reason": "original-client-precheck-denied", "origin": cells.continuation_origin(),
            "qualification": {"path": str(self.receipt), "sha256": ledger.digest(self.qualification)}, "successor": {
                "source_sha": self.helper.native.claims["sha"], "run_id": self.helper.native.run["id"], "run_attempt": 1,
                "first_parent": cells.ORIGIN_MAIN, "source_workflow_sha256": self.helper.value["source_workflow_sha256"],
                "reusable_sha": self.helper.value["source_identity"]["reusable_sha"]}}
        self.helper.value["operating_continuation"] = self.descriptor
        old = deepcopy(next(iter(self.helper.value["cells"].values())))
        self.helper.value["cells"][factory.policy_registry.profile_selector("application_acceptance", "example", "ubuntu-24.04")] = {
            **old, "native_job_name": "application_acceptance / example / ubuntu-24.04",
            "native_observer_job_name": "Final quality / application_acceptance / example / ubuntu-24.04",
            "matrix": {"profile": "application_acceptance", "scenario": "example", "target": "ubuntu-24.04"}}
        for case in sorted(cells.CASES):
            self.helper.value["cells"][cells.selector(case)] = {"kind": "operating", "native_job_name": "Operating custody / " + case,
                "native_observer_job_name": "Operating result / " + case, "lease_seconds": 900, "job_timeout_seconds": 1800,
                "github": {}, "engine": {"limits": {"timeout_seconds": 600}}, "incus": {}, "operating": {"case": case}}
        self.parent = cells.ORIGIN_MAIN
        original_reader = identity.HTTPSReader()
        self.http_reads = []
        def read(url, *, bearer=None):
            self.http_reads.append(url)
            prefix = identity.API + "/repos/" + factory.SOURCE
            routes = {prefix + "/actions/runs/" + str(cells.ORIGIN_RUN): self.origin[0],
                prefix + "/actions/runs/" + str(cells.ORIGIN_RUN) + "/attempts/1/jobs?per_page=100&page=1": self.origin[1],
                prefix + "/git/commits/" + cells.ORIGIN_MAIN: self.origin[3],
                **{prefix + "/check-runs/" + str(row["id"]): row for row in self.origin[2]}}
            if url == prefix + "/git/commits/" + self.helper.native.claims["sha"]:
                return ledger.canonical({"sha": self.helper.native.claims["sha"], "parents": [{"sha": self.parent}]})
            if self.helper.native.run["id"] == cells.ORIGIN_RUN and "/actions/" in url:
                return original_reader.read(url, bearer=bearer)
            if url in routes: return ledger.canonical(deepcopy(routes[url]))
            return original_reader.read(url, bearer=bearer)
        mock.patch.object(identity, "HTTPSReader", return_value=type("Reader", (), {"read": staticmethod(read)})()).start()
        self.helper.seal()

    def mint(self, selector=None, purpose="execution"):
        selector = selector or self.helper.selector
        row = self.helper.value["cells"][selector]
        self.helper.native.job["name"] = row["native_job_name" if purpose == "execution" else "native_observer_job_name"]
        challenge = factory.challenge_bootstrap(self.helper.server, self.helper.bootstrap, selector)
        self.helper.native.claims["aud"] = challenge["audience"]
        token = self.helper.native.token()
        return factory.verify_bootstrap_native(self.helper.server, self.helper.bootstrap, selector,
            challenge["nonce"], token, "synthetic-job-token", purpose=purpose), token

    def test_all_five_cells_and_observers_use_real_signature_and_opaque_proof(self):
        self.assertEqual(len(self.helper.value["cells"]), 5)
        for selector in self.helper.value["cells"]:
            for purpose in ("execution", "observer"):
                with self.subTest(selector=selector, purpose=purpose):
                    proof, token = self.mint(selector, purpose)
                    _, who, _ = factory.require_bootstrap_native(proof, self.helper.server, proof.policy, token, "synthetic-job-token")
                    self.assertEqual(who.run_id, self.descriptor["successor"]["run_id"])
        with ledger.Ledger(self.helper.store_path) as store: self.assertEqual(store.lease_ids(), ())

    def test_wrong_attempt_run_actor_ref_controller_or_parent_is_denied(self):
        original = deepcopy(self.helper.native.claims)
        for key, value in (("run_attempt", "2"), ("run_id", "502"), ("actor_id", "307565056"),
                           ("ref", "refs/heads/develop"), ("job_workflow_sha", cells.ORIGIN_REUSABLE)):
            self.helper.native.claims[key] = value
            with self.subTest(key=key), self.assertRaises(Denied): self.mint("operating-failure")
            self.helper.native.claims.clear(); self.helper.native.claims.update(original)
        self.parent = "f" * 40
        with self.assertRaises(Denied): self.mint("operating-failure")

    def test_qualification_hash_mode_and_closed_descriptor_are_enforced(self):
        raw = self.receipt.read_bytes(); self.receipt.write_bytes(raw + b" ")
        with self.assertRaises(Denied): self.helper.seal()
        self.receipt.write_bytes(raw); self.receipt.chmod(0o644)
        with self.assertRaises(Denied): self.helper.seal()
        self.receipt.chmod(0o600); self.descriptor["successor"]["run_attempt"] = True
        with self.assertRaises(Denied): self.helper.seal()
        self.descriptor["successor"]["run_attempt"] = 1; self.descriptor["extra"] = True
        with self.assertRaises(Denied): self.helper.seal()

    def test_changed_original_check_or_unknown_partial_intake_denies(self):
        self.origin[2][0]["conclusion"] = "success"
        with self.assertRaises(Denied): self.mint()
        self.origin[2][0]["conclusion"] = "failure"
        (self.intakes / ("a" * 64)).mkdir(mode=0o700)
        with self.assertRaises(Denied): self.mint()

    def test_partial_original_configuration_and_catalogue_replacement_deny(self):
        partial = self.configs / ("b" * 64); partial.mkdir(mode=0o700)
        (partial / "intent.json").write_bytes(ledger.canonical({"schema": 1, "invocation": {"run_id": cells.ORIGIN_RUN}}))
        (partial / "intent.json").chmod(0o600)
        with self.assertRaises(Denied): self.mint()
        (partial / "intent.json").unlink(); partial.rmdir()
        self.configs.rename(self.configs.with_name("preserved-configs")); self.configs.mkdir(mode=0o700)
        with self.assertRaises(Denied): self.mint()

    def test_missing_descriptor_keeps_legacy_business_but_refuses_followup_operating(self):
        self.helper.value.pop("operating_continuation"); self.helper.seal()
        self.mint()
        with self.assertRaises(Denied): self.mint("operating-failure")

    def test_other_genuine_current_run_is_not_the_exact_successor(self):
        self.helper.native.claims["run_id"] = "502"
        self.helper.native.run["id"] = 502
        for job in self.helper.native.jobs["jobs"]: job["run_id"] = 502
        with self.assertRaises(Denied): self.mint()

    def test_known_successor_intake_and_configuration_intents_do_not_block_new_cells(self):
        successor = self.descriptor["successor"]
        domain = {**self.helper.value["source_identity"], "caller_sha": successor["source_sha"]}
        binding = {"schema": 1, "identity_domain": domain, "custody_policy_sha256": "a" * 64,
            "source": {"repository": factory.SOURCE, "repository_id": 1103407173, "commit_sha": successor["source_sha"]},
            "controller": {"repository": factory.VALIDATION, "repository_id": 1269461997, "commit_sha": successor["reusable_sha"]},
            "artifact": {"run_id": successor["run_id"], "run_attempt": 1, "head_sha": successor["source_sha"]}}
        original_job = {"worker_sha256": "b" * 64, "run_id": successor["run_id"], "job_id": 902, "check_run_id": 731,
            "native_job_name": self.helper.value["cells"][self.helper.selector]["native_job_name"], "identity_policy_sha256": "c" * 64}
        path = self.intakes / ledger.digest(binding); path.mkdir(mode=0o700)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            factory.run_intake._write_at(fd, "intent.json",
                                        {"schema": 1, "binding": binding, "original_job": original_job})
        finally: os.close(fd)
        invocation = {"repository": factory.SOURCE, "run_id": successor["run_id"], "run_attempt": 1,
            "check_run_id": 731, "job_id": 902, "source_sha": successor["source_sha"],
            "reusable_sha": successor["reusable_sha"], "selector": self.helper.selector,
            "bootstrap_sha256": self.helper.bootstrap.sha256}
        name = ledger.digest({key: invocation[key] for key in ("repository", "run_id", "check_run_id", "selector")})
        path = self.configs / name; path.mkdir(mode=0o700)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            factory.run_intake._write_at(fd, "intent.json", {"schema": 1, "invocation": invocation,
                "snapshot_receipt_sha256": "d" * 64, "created_at": 1, "deadline": 2, "worker": {},
                "job_started_at": 1, "template_sha256": "e" * 64})
        finally: os.close(fd)
        self.mint("operating-failure")
        invocation["run_id"] = cells.ORIGIN_RUN
        (path / "intent.json").write_bytes(ledger.canonical({"schema": 1, "invocation": invocation,
            "snapshot_receipt_sha256": "d" * 64, "created_at": 1, "deadline": 2, "worker": {},
            "job_started_at": 1, "template_sha256": "e" * 64}))
        with self.assertRaises(Denied): self.mint()

    def test_byte_identical_receipt_inode_change_invalidates_existing_native_proof(self):
        proof, token = self.mint()
        raw = self.receipt.read_bytes()
        self.receipt.rename(self.receipt.with_name("preserved-qualified.json"))
        self.receipt.write_bytes(raw); self.receipt.chmod(0o600)
        with self.assertRaises(Denied):
            factory.require_bootstrap_native(proof, self.helper.server, proof.policy, token, "synthetic-job-token")

    def test_original_source_or_false_no_intake_receipt_cannot_be_substituted(self):
        self.descriptor["origin"]["run_id"] += 1
        with self.assertRaises(Denied): self.helper.seal()
        self.descriptor["origin"] = cells.continuation_origin()
        self.qualification["no_intake_receipt_b64"] += "AA=="
        self.receipt.write_bytes(ledger.canonical(self.qualification))
        self.descriptor["qualification"]["sha256"] = ledger.digest(self.qualification)
        with self.assertRaises((Denied, ValueError)): self.helper.seal()

    def test_historical_origin_is_qualified_once_per_opaque_proof_not_globally_cached(self):
        with mock.patch.object(factory, "_continuation_original_native", wraps=factory._continuation_original_native) as read:
            proof, token = self.mint()
            for _ in range(2):
                factory.require_bootstrap_native(proof, self.helper.server, proof.policy, token, "synthetic-job-token")
            self.assertEqual(read.call_count, 1)
            self.origin[2][0]["conclusion"] = "success"
            with self.assertRaises(Denied): self.mint()
            self.assertEqual(read.call_count, 2)

    def test_current_native_and_origin_absence_remain_fresh_after_historical_proof(self):
        with mock.patch.object(factory, "_continuation_original_native", wraps=factory._continuation_original_native) as read:
            proof, token = self.mint()
            self.helper.native.job["status"] = "completed"
            with self.assertRaises(Denied):
                factory.require_bootstrap_native(proof, self.helper.server, proof.policy, token, "synthetic-job-token")
            self.helper.native.job["status"] = "in_progress"
            (self.intakes / ("c" * 64)).mkdir(mode=0o700)
            with self.assertRaises(Denied):
                factory.require_bootstrap_native(proof, self.helper.server, proof.policy, token, "synthetic-job-token")
            self.assertEqual(read.call_count, 1)

    def test_genuinely_prepared_original_invocation_invalidates_the_zero_receipt(self):
        saved_value = deepcopy(self.helper.value)
        saved_claims = deepcopy(self.helper.native.claims)
        saved_run = deepcopy(self.helper.native.run)
        saved_jobs = deepcopy(self.helper.native.jobs)
        saved_job = deepcopy(self.helper.native.job)
        self.helper.value.pop("operating_continuation")
        self.helper.value["source_identity"]["reusable_sha"] = cells.ORIGIN_REUSABLE
        self.helper.value["controller"]["reusable_sha"] = cells.ORIGIN_REUSABLE
        original = cells.continuation_origin()["jobs"][0]
        ref = factory.VALIDATION + "/.github/workflows/collection-quality-profile-isolated.yml@" + cells.ORIGIN_REUSABLE
        self.helper.native.claims.update(run_id=str(cells.ORIGIN_RUN), sha=cells.ORIGIN_MAIN,
            workflow_sha=cells.ORIGIN_MAIN, job_workflow_sha=cells.ORIGIN_REUSABLE, job_workflow_ref=ref,
            check_run_id=str(original["check_run_id"]))
        self.helper.native.run.update(id=cells.ORIGIN_RUN, head_sha=cells.ORIGIN_MAIN,
            referenced_workflows=[{"path": ref, "sha": cells.ORIGIN_REUSABLE}])
        self.helper.native.job.update(id=original["job_id"], run_id=cells.ORIGIN_RUN, head_sha=cells.ORIGIN_MAIN,
            check_run_url=identity.API + "/repos/" + factory.SOURCE + "/check-runs/" + str(original["check_run_id"]))
        self.helper.seal()
        proof, _ = self.mint()
        with ledger.Ledger(self.helper.store_path, clock=factory.time.time) as store:
            identifier = store.prepare(proof.nonce, proof.worker, proof.identity,
                policy_sha256=self.helper.value["custody_policy_sha256"], cell_sha256="f" * 64,
                deadline=int(factory.time.time()) + 120)
            self.assertEqual(store.read(identifier)["identity"]["run_id"], cells.ORIGIN_RUN)
        self.helper.value = saved_value
        self.helper.native.claims.clear(); self.helper.native.claims.update(saved_claims)
        self.helper.native.run.clear(); self.helper.native.run.update(saved_run)
        self.helper.native.job.clear(); self.helper.native.job.update(saved_job)
        self.helper.native.jobs = saved_jobs
        self.helper.native.jobs["jobs"] = [self.helper.native.job if j["id"] == saved_job["id"] else j
                                           for j in saved_jobs["jobs"]]
        self.helper.seal()
        with self.assertRaises(Denied): self.mint()
        with ledger.Ledger(self.helper.store_path) as store:
            self.assertEqual(store.lease_ids(), (identifier,))

    def test_actual_native_producer_http_cardinality_and_fixture_elapsed(self):
        started = time.perf_counter()
        proof, token = self.mint()
        self.assertEqual(len(self.http_reads), 13)
        factory.require_bootstrap_native(proof, self.helper.server, proof.policy, token, "synthetic-job-token")
        self.assertEqual(len(self.http_reads), 21)
        business_elapsed = time.perf_counter() - started
        self.http_reads.clear(); started = time.perf_counter()
        proof, token = self.mint("operating-failure")
        self.assertEqual(len(self.http_reads), 14)
        factory.require_bootstrap_native(proof, self.helper.server, proof.policy, token, "synthetic-job-token")
        self.assertEqual(len(self.http_reads), 23)
        print("MODELED_HTTP_REAL_FS_CRYPTO_BUDGET", {"business_proof_plus_recheck_calls": 21,
            "operating_proof_plus_recheck_calls": 23, "historical_gets_per_proof": 5,
            "business_seconds": business_elapsed, "operating_seconds": time.perf_counter() - started}, flush=True)

    def test_existing_ledger_replay_does_not_extend_the_first_deadline(self):
        proof, _ = self.mint(); now = int(factory.time.time())
        with ledger.Ledger(self.helper.store_path, clock=factory.time.time) as store:
            lease = store.prepare(proof.nonce, proof.worker, proof.identity,
                policy_sha256=self.helper.value["custody_policy_sha256"], cell_sha256="f" * 64, deadline=now + 120)
            before = store.read(lease)
        second, _ = self.mint()
        with ledger.Ledger(self.helper.store_path, clock=factory.time.time) as store:
            with self.assertRaises(Denied): store.prepare(second.nonce, second.worker, second.identity,
                policy_sha256=self.helper.value["custody_policy_sha256"], cell_sha256="f" * 64, deadline=now + 240)
            self.assertEqual(store.read(lease), before)
