"""Real Root files/ledger/socket/RS256; native Worker/HTTPS snapshots modeled.

Synthetic keys and public fixtures only. These tests never prove native running
code, accepted custody, source publication, capacity, or operating activation.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import socket
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock

import test_github_runner_incus_identity as crypto
from test_github_runner_incus_flow import FixtureReader

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import admission, collector, identity, ledger, policy_registry, run_factory as factory
from incus_lease_issuer.identity import Denied


class BoundaryTests(unittest.TestCase):
    def test_root_only_before_policy_or_token_read(self):
        with mock.patch.object(factory.os, "geteuid", return_value=501):
            for call in (lambda: factory.load_bootstrap("/not-read", "a" * 64),
                         lambda: factory.verify_bootstrap_native(None, None, "x", "x", "x", "x")):
                with self.assertRaisesRegex(Denied, "run-factory-root-required"): call()

    def test_installation_rejects_invalid_base_fields_even_with_matching_policy_hashes(self):
        from incus_lease_issuer import startup_retirement
        from test_github_runner_runtime_v2_installation import probe

        original = {"custodian_ref": "fixture:owner", "storage_ref": "fixture:storage", "approval_ref": "fixture:review",
                    "retention_seconds": 14400, "max_lease_seconds": 900}
        matrix = {"profile": "heavy", "scenario": "example_heavy", "target": "ubuntu-24.04"}
        selector = policy_registry.profile_selector(matrix["profile"], matrix["scenario"], matrix["target"])
        field = startup_retirement.POST_ENGINE_POLICY_FIELD
        for key, value in (("custodian_ref", ""), ("max_lease_seconds", 0)):
            unsafe = original | {key: value}
            opted_in = unsafe | {"post_engine_failure_retirement": {"schema": 1, "selector": selector}}
            base, post = ledger.digest(unsafe), ledger.digest(opted_in)
            runtime = {"custody_policy_sha256": base, "cells": {selector: {"kind": "business", "matrix": matrix, field: post}}}
            with self.subTest(field=key), self.assertRaises(ValueError):
                probe.bootstrap_custody_policies(runtime, {"policies": {base: unsafe, post: opted_in}})


    def test_c22_cannot_reuse_the_old_controller_or_run(self):
        from incus_lease_issuer import operating_cells as cases

        successor = {
            "source_sha": "a" * 40, "run_id": cases.TWENTY_SECOND_RUN + 1, "run_attempt": 1,
            "first_parent": cases.TWENTY_SECOND_MAIN,
            "source_workflow_sha256": cases.TWENTY_SECOND_SUCCESSOR_WORKFLOW,
            "reusable_sha": cases.TWENTY_SECOND_SUCCESSOR_REUSABLE,
        }
        descriptor = {
            "schema": 22, "reason": cases.TWENTY_SECOND_REASON,
            "qualification": {"path": "/private/qualification.json", "sha256": "b" * 64},
            "successor": successor,
        }
        self.assertEqual(cases.validate_continuation_descriptor(
            descriptor, successor["source_workflow_sha256"], successor["reusable_sha"]), descriptor)
        for changes in ({"run_id": cases.TWENTY_SECOND_RUN},
                        {"reusable_sha": cases.NINETEENTH_SUCCESSOR_REUSABLE},
                        {"source_workflow_sha256": cases.NINETEENTH_SUCCESSOR_WORKFLOW},
                        {"first_parent": cases.TWENTY_FIRST_MAIN}):
            with self.subTest(changes=changes), self.assertRaises(Denied):
                candidate = successor | changes
                cases.validate_continuation_descriptor(descriptor | {"successor": candidate},
                    candidate["source_workflow_sha256"], candidate["reusable_sha"])

    def test_g06_zero_wait_requires_marker_and_exact_sealed_policy(self):
        from incus_lease_issuer import startup_retirement
        from test_github_runner_runtime_v2_installation import probe

        original = {"custodian_ref": "fixture:owner", "storage_ref": "fixture:storage", "approval_ref": "fixture:review",
                    "retention_seconds": 14400, "max_lease_seconds": 900}
        source = {"repository": factory.SOURCE, "repository_id": 1103407173, "owner_id": 54334171,
                  "workflow_id": 214182490, "workflow_path": ".github/workflows/collection-ci.yml",
                  "reusable_repository": factory.VALIDATION,
                  "reusable_path": ".github/workflows/collection-quality-profile-isolated.yml"}
        legacy = {"schema": 1, "custody_policy_sha256": ledger.digest(original), "source_identity": source,
                  "source_workflow_sha256": "a" * 64, "ledger_path": "/proof/fresh/ledger", "cells": {}}
        g06, policy = startup_retirement.bootstrap_with_g06_no_minimum_wait(legacy, original)
        state = {"policies": startup_retirement._bootstrap_custody_rows(g06, original)}
        self.assertEqual(state["policies"][legacy["custody_policy_sha256"]], original)
        self.assertEqual(policy["retention_seconds"], 0)
        probe.bootstrap_custody_policies(g06, state)
        probe.bootstrap_custody_policies(legacy, {"policies": {ledger.digest(original): original}})

        ordinary_zero = original | {"retention_seconds": 0}
        with self.assertRaisesRegex(Denied, "invalid-custody-limits"):
            ledger.Ledger._validate_policy(ordinary_zero)
        with self.assertRaises(ValueError):
            probe.bootstrap_custody_policies(legacy | {"custody_policy_sha256": ledger.digest(ordinary_zero)},
                                             {"policies": {ledger.digest(ordinary_zero): ordinary_zero}})
        for altered in ({"source_workflow_sha256": "b" * 64}, {"ledger_path": "/proof/other/ledger"},
                        {"source_identity": source | {"repository_id": 1}}):
            with self.subTest(altered=altered):
                with self.assertRaisesRegex(Denied, "g06-no-minimum-wait-(source|policy-binding)"):
                    startup_retirement._bootstrap_custody_rows(g06 | altered, original)
                with self.assertRaises(ValueError):
                    probe.bootstrap_custody_policies(g06 | altered, state)
        with self.assertRaises(ValueError):
            probe.bootstrap_custody_policies(g06, {"policies": {ledger.digest(original): original}})


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        crypto.CurrentJobIdentityTests.setUpClass()

    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("private Root0700 /run/proof required")
        self.temp = tempfile.TemporaryDirectory(dir=base, prefix="run-factory-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store_path = self.root / "ledger"; self.store_path.mkdir(mode=0o700)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(factory.time, "time", return_value=crypto.NOW).start()
        ledger.Ledger.initialize(self.store_path, clock=factory.time.time)
        with ledger.Ledger(self.store_path, clock=factory.time.time) as store:
            custody = store.archive_policy({"custodian_ref": "fixture:owner", "storage_ref": "fixture:storage",
                "approval_ref": "fixture:not-native-acceptance", "retention_seconds": 14400, "max_lease_seconds": 5400})
        self.native = crypto.CurrentJobIdentityTests(); self.native.setUp()
        base_identity = asdict(self.native.policy)
        base_identity.pop("caller_sha"); base_identity.pop("required_native_job_name", None)
        base_identity["actor_ids"] = [76040632, 247824904]
        base_identity["reusable_path"] = ".github/workflows/collection-quality-profile-isolated.yml"
        self.native.claims["job_workflow_ref"] = base_identity["reusable_repository"] + "/" + base_identity["reusable_path"] + "@" + crypto.REUSABLE_SHA
        self.native.run["referenced_workflows"] = [{"path": self.native.claims["job_workflow_ref"], "sha": crypto.REUSABLE_SHA, "ref": crypto.REUSABLE_SHA}]
        self.job_name = "heavy / example_heavy / ubuntu-24.04"
        self.native.job.update(name=self.job_name, started_at=dt.datetime.fromtimestamp(crypto.NOW - 30, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.worker = ledger.Worker(2101, 61, 23456, 777, "12345678-1234-4234-8234-123456789abc")
        self.profile = self.root / "profile"; self.profile.write_bytes(b"inert confinement fixture"); self.profile.chmod(0o600)
        self.collect_config = self.root / "collector.json"; self.collect_config.write_bytes(b"inert Root collector descriptor"); self.collect_config.chmod(0o600)
        self.workflow = b"public fixed Source workflow contract fixture"
        collected = {"service": {"unit": "actions.runner.fixture.service", "service_user": "fixture_runner",
            "installation": {"root": str(self.root / "runner"), "manifest_path": str(self.root / "runner-manifest.json"),
                "runner_id": 61, "service_uid": 2101, "runner_version": "2.338.2"},
            "fragment_path": str(self.root / "runner.service"), "fragment_sha256": "a" * 64, "dropins": []},
            "profile_name": "lit-gh-fixture-0123456789abcdef", "profile_path": str(self.profile),
            "profile_sha256": hashlib.sha256(self.profile.read_bytes()).hexdigest(), "config_path": str(self.collect_config),
            "config_sha256": hashlib.sha256(self.collect_config.read_bytes()).hexdigest()}
        self.selector = policy_registry.profile_selector("heavy", "example_heavy", "ubuntu-24.04")
        template = {"kind": "business", "native_job_name": self.job_name,
            "native_observer_job_name": "Final quality / heavy / example_heavy / ubuntu-24.04",
            "lease_seconds": 1200, "job_timeout_seconds": 1800, "github": {"job": "heavy", "workflow": "CI"},
            "matrix": {"profile": "heavy", "scenario": "example_heavy", "target": "ubuntu-24.04"},
            "engine": {"inert_template": True}, "incus": {"inert_template": True}}
        prep = {key: str(self.root / key) for key in factory.PREPARATION_KEYS}
        for key in factory.PREPARATION_KEYS:
            if key.endswith("sha256") or key == "signing_public_key_hex": prep[key] = "a" * 64
        prep["operation_wait_seconds"] = 5
        self.value = {"schema": 1, "source_identity": base_identity,
            "source_workflow_sha256": hashlib.sha256(self.workflow).hexdigest(), "collector": collected,
            "ledger_path": str(self.store_path), "custody_policy_sha256": custody,
            "controller": {"repository": factory.VALIDATION, "repository_id": 1269461997,
                "reusable_path": base_identity["reusable_path"], "reusable_sha": base_identity["reusable_sha"]},
            "preparation": prep, "runtime": {"authentication_timeout_seconds": 30, "initial_transition_timeout_seconds": 60,
                "heartbeat_lead_seconds": 30, "cleanup_timeout_seconds": 600, "capture": {"fixture": True}},
            "capacity": {"schema": 1, "pool_total_bytes": 32 * 1024 ** 3, "pool_reserve_bytes": 1024 ** 3,
                "engine_total_bytes": 17 * 1024 ** 3, "engine_reserve_bytes": 512 * 1024 ** 2,
                "cold_engine_bytes": 8 * 1024 ** 3, "pool_accounting": "owned-dir-retained-v1",
                "pool_quota_policy_path": str(self.root / "pool-quota.json"), "pool_quota_policy_sha256": "a" * 64},
            "cells": {self.selector: template}}
        self.path = self.root / "bootstrap.json"
        self.seal()
        self.server, self.client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.server.close); self.addCleanup(self.client.close)
        self.collected = mock.patch.object(collector, "collect_worker", return_value=self.worker).start()
        # Native acquisition is modeled here; real collector epochs have their
        # own kernel/FS tests. Preserve worker drift injection at both boundaries.
        mock.patch.object(collector, "begin_worker_acquisition",
            side_effect=lambda connected, policy, **kwargs: (self.collected(connected, policy), object())).start()
        mock.patch.object(collector, "finish_worker_acquisition",
            side_effect=lambda token, connected, policy: self.collected(connected, policy)).start()
        mock.patch.object(collector, "discard_worker_acquisition").start()
        reader = FixtureReader(self.native)
        def read(url, *, bearer=None):
            prefix = identity.API + "/repos/" + crypto.REPOSITORY
            dynamic = {prefix + "/actions/runs/" + str(self.native.run["id"]): self.native.run,
                prefix + "/actions/runs/" + str(self.native.run["id"]) + "/attempts/1/jobs?per_page=100&page=1": self.native.jobs,
                prefix + "/actions/jobs/" + str(self.native.job["id"]): self.native.job,
                prefix + "/branches/main": {"name": "main", "protected": True, "commit": {"sha": self.native.run["head_sha"]}}}
            if url in dynamic: return ledger.canonical(deepcopy(dynamic[url]))
            if url == prefix + "/contents/.github/workflows/collection-ci.yml?ref=" + self.native.claims["sha"]:
                return ledger.canonical({"type": "file", "path": ".github/workflows/collection-ci.yml", "encoding": "base64",
                    "content": base64.b64encode(self.workflow).decode(), "size": len(self.workflow), "sha": "e" * 40})
            if url == prefix + "/git/commits/" + self.native.claims["sha"]:
                return ledger.canonical({"sha": self.native.claims["sha"], "parents": [{"sha": factory.operating_cells.INITIAL_MAIN}]})
            return reader.read(url, bearer=bearer)
        mock.patch.object(identity, "HTTPSReader", return_value=type("Reader", (), {"read": staticmethod(read)})()).start()

    def seal(self):
        self.path.write_bytes(ledger.canonical(self.value)); self.path.chmod(0o600)
        self.sha = ledger.digest(self.value)
        self.bootstrap = factory.load_bootstrap(str(self.path), self.sha)

    def mint(self):
        challenge = factory.challenge_bootstrap(self.server, self.bootstrap, self.selector)
        self.native.claims["aud"] = challenge["audience"]
        token = self.native.token()
        proof = factory.verify_bootstrap_native(self.server, self.bootstrap, self.selector,
            challenge["nonce"], token, "synthetic-job-token")
        return proof, token

    def publish_and_verify_startup_bootstrap(self):
        from test_github_runner_runtime_v2_installation import probe
        from incus_lease_issuer import startup_retirement

        def private(path, raw=b"{}"):
            file = Path(path)
            file.write_bytes(raw)
            file.chmod(0o600)
            return hashlib.sha256(raw).hexdigest()

        prep = self.value["preparation"]
        for name in ("network_fence_policy", "host_api_fence_policy", "storage_quota_policy"):
            prep[name + "_sha256"] = private(prep[name + "_path"])
        private(prep["signing_key_path"], b"private test fixture")
        private(prep["lock_path"], b"")
        service = self.value["collector"]["service"]
        service["fragment_sha256"] = private(service["fragment_path"])
        private(service["installation"]["manifest_path"])
        operating = {}
        for case in factory.operating_cells.CASES:
            name = factory.operating_cells.selector(case)
            operating[name] = {"kind": "operating", "native_job_name": "Operating custody / " + case,
                "native_observer_job_name": "Operating result / " + case,
                "lease_seconds": 900, "job_timeout_seconds": 900, "github": {"job": "operating", "workflow": "CI"},
                "operating": {"case": case}, "engine": {"limits": {"timeout_seconds": 600}}, "incus": {}}
        self.value["cells"].update(operating)
        baseline_sha = self.value["custody_policy_sha256"]
        with ledger.Ledger(self.store_path, clock=factory.time.time) as store:
            original = store.read_policy(baseline_sha)
            self.value, business = startup_retirement.bootstrap_with_business_policy(self.value, original)
            with self.assertRaises(Denied):
                self.seal()
            startup_retirement.archive_bootstrap_policies(store, self.value, original)
            self.seal()
        account = SimpleNamespace(pw_uid=2101, pw_gid=2101, pw_name=service["service_user"])
        group = SimpleNamespace(gr_gid=2101, gr_mem=[])
        def group_info(name):
            if name == "fixture_group":
                return group
            raise KeyError(name)
        with mock.patch.object(probe.pwd, "getpwnam", return_value=account), \
             mock.patch.object(probe.pwd, "getpwall", return_value=[account]), \
             mock.patch.object(probe.grp, "getgrnam", side_effect=group_info), \
             mock.patch.object(probe.os, "getgrouplist", return_value=[2101]):
            self.assertEqual(probe.configurations(str(self.path), self.sha, "fixture_group",
                                                 prep["signing_public_key_hex"]), self.value)
            bad = self.value | {"business_startup_policy_sha256": baseline_sha}
            self.path.write_bytes(ledger.canonical(bad))
            with self.assertRaises(ValueError):
                probe.configurations(str(self.path), ledger.digest(bad), "fixture_group", prep["signing_public_key_hex"])
            self.seal()
        for purpose in ("execution", "observer"):
            selected = factory.derive_selection(self.bootstrap, self.selector, crypto.CALLER_SHA, purpose=purpose)
            self.assertEqual(selected.custody_policy_sha256, ledger.digest(business))
            for name in operating:
                selected = factory.derive_selection(self.bootstrap, name, crypto.CALLER_SHA, purpose=purpose)
                self.assertEqual(selected.custody_policy_sha256, baseline_sha)
        proof, _ = self.mint()
        self.assertEqual(proof.policy.custody_policy_sha256, ledger.digest(business))
        return proof.policy, business


    def test_g06_scope_selects_all_new_cells_and_blocks_other_admission(self):
        from incus_lease_issuer import startup_retirement
        from test_github_runner_runtime_v2_installation import probe

        case = next(iter(factory.operating_cells.CASES))
        operating = factory.operating_cells.selector(case)
        self.value["cells"][operating] = {"kind": "operating", "native_job_name": "Operating custody / " + case,
            "native_observer_job_name": "Operating result / " + case, "lease_seconds": 900, "job_timeout_seconds": 900,
            "github": {}, "operating": {"case": case}, "engine": {"limits": {"timeout_seconds": 600}}, "incus": {}}
        original_sha = self.value["custody_policy_sha256"]
        with ledger.Ledger(self.store_path, clock=factory.time.time) as store:
            original = store.read_policy(original_sha)
            self.value, new_base = startup_retirement.bootstrap_with_g06_no_minimum_wait(self.value, original)
            self.value, business = startup_retirement.bootstrap_with_business_policy(self.value, original)
            self.value, heavy = startup_retirement.bootstrap_with_post_engine_failure_policy(
                self.value, self.selector, original)
            with self.assertRaisesRegex(Denied, "unknown-custody-policy"):
                self.seal()
            startup_retirement.archive_bootstrap_policies(store, self.value, original)
            self.seal()
            state = identity.decode_json((self.store_path / "state.json").read_bytes())
            probe.bootstrap_custody_policies(self.value, state)
            self.assertEqual(store.read_policy(original_sha), original)
            self.assertEqual(store.read_policy(ledger.digest(business)), business)
            for purpose in ("execution", "observer"):
                for selector, expected in ((self.selector, heavy), (operating, new_base)):
                    selected = factory.derive_selection(self.bootstrap, selector, crypto.CALLER_SHA, purpose=purpose)
                    self.assertEqual(store.read_policy(selected.custody_policy_sha256), expected)
                    self.assertEqual(expected["retention_seconds"], 0)
            proof, _ = self.mint()
            scope = new_base[ledger.G06_NO_WAIT_MARKER]
            self.assertEqual(proof.policy.custody_policy_sha256, ledger.digest(heavy))
            args = {"policy_sha256": proof.policy.custody_policy_sha256, "cell_sha256": proof.policy.template_sha256,
                    "deadline": crypto.NOW + 120}
            with self.assertRaisesRegex(Denied, "g06-no-minimum-wait-admission-scope"):
                store.prepare(proof.nonce, proof.worker, proof.identity, **args)
            args["identity_policy_sha256"] = proof.identity.policy_sha256
            for invalid in (None, "b" * 64):
                with self.assertRaisesRegex(Denied, "g06-no-minimum-wait-admission-scope"):
                    store.runtime_prepare(proof.nonce, proof.worker, proof.identity, **args, g06_no_wait_scope_sha256=invalid)
            challenge = store.runtime_challenge(proof.worker, "run", proof.policy.template_sha256,
                                                proof.identity.policy_sha256)
            actual = replace(proof.identity, audience=challenge["audience"])
            admitted = store.runtime_prepare(challenge["nonce"], proof.worker, actual, **args,
                                             g06_no_wait_scope_sha256=scope)
            self.assertEqual(store.read(admitted)["policy_sha256"], ledger.digest(heavy))
            with self.assertRaisesRegex(Denied, "startup-retirement-new-bank"):
                startup_retirement.archive_bootstrap_policies(store, self.value, original)

    def test_post_engine_opt_in_binds_only_the_exact_heavy_cell_for_both_purposes(self):
        from incus_lease_issuer import startup_retirement
        from test_github_runner_runtime_v2_installation import probe

        field = startup_retirement.POST_ENGINE_POLICY_FIELD
        other = policy_registry.profile_selector("heavy", "other_heavy", "ubuntu-24.04")
        second = deepcopy(self.value["cells"][self.selector])
        second["matrix"]["scenario"] = "other_heavy"
        second["native_job_name"] = "heavy / other_heavy / ubuntu-24.04"
        second["native_observer_job_name"] = "Final quality / heavy / other_heavy / ubuntu-24.04"
        case = next(iter(factory.operating_cells.CASES))
        operating = factory.operating_cells.selector(case)
        self.value["cells"].update({other: second, operating: {"kind": "operating",
            "native_job_name": "Operating custody / " + case, "native_observer_job_name": "Operating result / " + case,
            "lease_seconds": 900, "job_timeout_seconds": 900, "github": {"job": "operating", "workflow": "CI"},
            "operating": {"case": case}, "engine": {"limits": {"timeout_seconds": 600}}, "incus": {}}})
        base = self.value["custody_policy_sha256"]
        initial = deepcopy(self.value)
        with ledger.Ledger(self.store_path, clock=factory.time.time) as store:
            original = store.read_policy(base)
            for with_pre_vm in (False, True):
                with self.subTest(with_pre_vm=with_pre_vm):
                    self.value = deepcopy(initial)
                    business = original
                    if with_pre_vm:
                        self.value, business = startup_retirement.bootstrap_with_business_policy(self.value, original)
                    with self.assertRaisesRegex(Denied, "post-engine-retirement-heavy-selector"):
                        startup_retirement.bootstrap_with_post_engine_failure_policy(self.value, operating, original)
                    self.value, policy = startup_retirement.bootstrap_with_post_engine_failure_policy(
                        self.value, self.selector, original)
                    self.assertEqual(policy, business | {"post_engine_failure_retirement": {"schema": 1, "selector": self.selector}})
                    post_engine = ledger.digest(policy)
                    with self.assertRaises(Denied):
                        self.seal()
                    startup_retirement.archive_bootstrap_policies(store, self.value, original)
                    self.seal()
                    state = identity.decode_json((self.store_path / "state.json").read_bytes())
                    probe.bootstrap_custody_policies(self.value, state)
                    altered = deepcopy(state)
                    altered["policies"][post_engine]["post_engine_failure_retirement"]["schema"] = True
                    with self.assertRaises(ValueError):
                        probe.bootstrap_custody_policies(self.value, altered)
                    for purpose in ("execution", "observer"):
                        for selector, expected in ((self.selector, post_engine), (other, ledger.digest(business)), (operating, base)):
                            selected = factory.derive_selection(self.bootstrap, selector, crypto.CALLER_SHA, purpose=purpose)
                            self.assertEqual(selected.custody_policy_sha256, expected)
                            self.assertEqual(store.read_policy(expected)["retention_seconds"], 14400)
                            if selector != self.selector:
                                self.assertEqual(selected.template_sha256, ledger.digest(initial["cells"][selector]))
                    for selector, forbidden in ((self.selector, base), (self.selector, ledger.digest(business)),
                                                (other, post_engine), (operating, post_engine)):
                        bad = deepcopy(self.value)
                        bad["cells"][selector][field] = forbidden
                        self.path.write_bytes(ledger.canonical(bad))
                        with self.assertRaisesRegex(Denied, "post-engine-retirement-(heavy-selector|policy-binding)"):
                            factory.load_bootstrap(str(self.path), ledger.digest(bad))
                        with self.assertRaises(ValueError):
                            probe.bootstrap_custody_policies(bad, state)
                    self.seal()
        proof, _ = self.mint()
        self.assertEqual(proof.policy.custody_policy_sha256, post_engine)
        self.native.job["name"] = self.value["cells"][self.selector]["native_observer_job_name"]
        self.native.claims["check_run_id"] = "735"
        self.native.job.update(id=906, check_run_url=identity.API + "/repos/" + crypto.REPOSITORY + "/check-runs/735")
        challenge = factory.challenge_bootstrap(self.server, self.bootstrap, self.selector)
        self.native.claims["aud"] = challenge["audience"]
        observer = factory.verify_bootstrap_native(self.server, self.bootstrap, self.selector, challenge["nonce"],
            self.native.token(), "synthetic-job-token", purpose="observer")
        self.assertEqual(observer.policy.custody_policy_sha256, post_engine)

    def test_real_signature_socket_nonce_ledger_and_opaque_proof_without_fake_cell(self):
        proof, token = self.mint()
        self.assertEqual(proof.identity.job_id, 902)
        self.assertEqual(proof.policy.identity.caller_sha, crypto.CALLER_SHA)
        self.assertFalse(hasattr(proof.policy, "cell_config_path"))
        worker, who, remaining = factory.require_bootstrap_native(proof, self.server, proof.policy, token, "synthetic-job-token")
        self.assertEqual(worker, self.worker)
        self.assertEqual(who, proof.identity)
        self.assertTrue(0 < remaining < 300)
        self.assertNotIn(token, repr(proof))
        with ledger.Ledger(self.store_path, clock=factory.time.time) as store:
            with store._transaction() as state: self.assertEqual(state["leases"], {})

    def test_snapshot_seal_can_resample_with_the_original_worker_deadline(self):
        proof, token = self.mint()
        with mock.patch.object(collector, "begin_worker_acquisition",
                               wraps=collector.begin_worker_acquisition) as begin:
            worker, who, _ = admission.require_intake_seal_native(proof, self.server, proof.policy,
                token, "synthetic-job-token")
        begin.assert_called_once_with(self.server, self.bootstrap.collector,
                                      maps_retry_until=proof.expires_monotonic)
        self.assertEqual((worker, who), (proof.worker, proof.identity))

    def test_configuration_requires_distinct_nonce_for_exact_snapshot(self):
        snapshot = "a" * 64
        stage = factory.challenge_bootstrap(self.server, self.bootstrap, self.selector)
        config = factory.challenge_bootstrap(self.server, self.bootstrap, self.selector,
                                             snapshot_receipt_sha256=snapshot)
        self.assertNotEqual(config["nonce"], stage["nonce"])
        self.native.claims["aud"] = config["audience"]
        token = self.native.token()
        for other in (None, "b" * 64):
            with self.assertRaisesRegex(Denied, "^bootstrap-native-denied$"):
                factory.verify_bootstrap_native(self.server, self.bootstrap, self.selector,
                    config["nonce"], token, "synthetic-job-token", snapshot_receipt_sha256=other)
        proof = factory.verify_bootstrap_native(self.server, self.bootstrap, self.selector, config["nonce"],
            token, "synthetic-job-token", snapshot_receipt_sha256=snapshot)
        self.assertEqual(proof.snapshot_receipt_sha256, snapshot)
        self.assertEqual(factory.require_bootstrap_native(proof, self.server, proof.policy, token,
            "synthetic-job-token")[1], proof.identity)

    def test_invalid_workflow_cannot_trigger_final_job_read(self):
        challenge = factory.challenge_bootstrap(self.server, self.bootstrap, self.selector)
        self.native.claims["aud"] = challenge["audience"]
        selected = factory.derive_selection(self.bootstrap, self.selector, self.native.claims["sha"])
        reader = identity.HTTPSReader()
        original = reader.read
        job_reads = []

        def invalid_workflow(url, **kwargs):
            if "/actions/jobs/" in url:
                job_reads.append(url)
            if "/contents/" in url:
                return b'{}'
            return original(url, **kwargs)

        with mock.patch.object(reader, "read", side_effect=invalid_workflow):
            with self.assertRaisesRegex(Denied, "bootstrap-workflow-file"):
                factory._native(self.server, selected, challenge["nonce"], self.native.token(), "synthetic-job-token")
        self.assertEqual(len(job_reads), 1)
        collector.discard_worker_acquisition.assert_called_once()
        collector.finish_worker_acquisition.assert_not_called()

    def test_failed_origin_stops_before_commit_read_or_validation(self):
        challenge = factory.challenge_bootstrap(self.server, self.bootstrap, self.selector)
        self.native.claims["aud"] = challenge["audience"]
        selected = factory.derive_selection(self.bootstrap, self.selector, self.native.claims["sha"])
        successor = {"source_sha": selected.identity.caller_sha, "run_id": self.native.run["id"],
                     "reusable_sha": selected.identity.reusable_sha}
        qualification = ({"schema": 9, "successor": successor, "qualification": {"sha256": "a" * 64}}, {}, None, (1,))
        commit_reads = []
        reader = identity.HTTPSReader()
        read = reader.read

        def read_commit(url, **kwargs):
            if "/git/commits/" in url:
                commit_reads.append(url)
            return read(url, **kwargs)

        def fail_origin(*args):
            raise Denied("origin-drift")

        with mock.patch.object(reader, "read", side_effect=read_commit), \
             mock.patch.object(factory, "_continuation_receipt", return_value=qualification), \
             mock.patch.object(factory, "_continuation_origin_absent", side_effect=fail_origin), \
             mock.patch.object(factory.operating_cells, "validate_continuation_commit") as validate:
            with self.assertRaisesRegex(Denied, "origin-drift"):
                factory._native(self.server, selected, challenge["nonce"], self.native.token(),
                                "synthetic-job-token", check_origin=False)
        self.assertEqual(commit_reads, [])
        validate.assert_not_called()
        collector.finish_worker_acquisition.assert_not_called()
        collector.discard_worker_acquisition.assert_called_once()

    def test_unverified_sha_locator_or_forged_dataclass_is_not_authority(self):
        selected = factory.derive_selection(self.bootstrap, self.selector, "9" * 40)
        self.assertEqual(selected.identity.caller_sha, "9" * 40)
        proof, token = self.mint()
        forged = replace(proof)
        for invalid, connected in ((forged, self.server), (proof, self.client), (object(), self.server)):
            with self.assertRaisesRegex(Denied, "^bootstrap-native-denied$"):
                factory.require_bootstrap_native(invalid, connected, proof.policy, token, "synthetic-job-token")

    def test_native_completed_job_wrong_actor_ref_or_unsigned_workflow_drift_deny(self):
        original = deepcopy(self.native.job)
        self.native.job["status"] = "completed"
        with self.assertRaises(Denied): self.mint()
        self.native.job.update(original)
        self.workflow += b" changed but not approved"
        with self.assertRaises(Denied): self.mint()
        self.workflow = b"public fixed Source workflow contract fixture"
        self.native.claims["ref"] = "refs/pull/1/merge"
        with self.assertRaises(Denied): self.mint()

    def test_original_token_expiry_worker_and_policy_drift_hold(self):
        proof, token = self.mint()
        self.collected.return_value = replace(self.worker, pid=23457)
        with self.assertRaises(Denied): factory.require_bootstrap_native(proof, self.server, proof.policy, token, "synthetic-job-token")
        self.collected.return_value = self.worker
        with mock.patch.object(factory.time, "time", return_value=crypto.NOW + 300):
            with self.assertRaises(Denied): factory.require_bootstrap_native(proof, self.server, proof.policy, token, "synthetic-job-token")
        self.path.chmod(0o644)
        with self.assertRaises(Denied): factory.require_bootstrap_native(proof, self.server, proof.policy, token, "synthetic-job-token")

    def test_wrong_nonce_or_claimed_started_timestamp_cannot_mint(self):
        self.native.claims["aud"] = ledger.AUDIENCE + "f" * 64
        with self.assertRaises(Denied):
            factory.verify_bootstrap_native(self.server, self.bootstrap, self.selector, "f" * 64,
                                             self.native.token(), "synthetic-job-token")
        self.native.job["started_at"] = "future or untrusted timestamp"
        with self.assertRaises(Denied): self.mint()

    def test_root_policy_cannot_supply_caller_sha_old_cell_or_unknown_controller_domain(self):
        original = deepcopy(self.value)
        for modify in (lambda v: v["source_identity"].update(caller_sha="a" * 40),
                       lambda v: v["cells"][self.selector]["engine"].update(archives={}),
                       lambda v: v["controller"].update(repository="ltn-it/foreign")):
            self.value = deepcopy(original); modify(self.value)
            self.path.write_bytes(ledger.canonical(self.value)); self.path.chmod(0o600)
            with self.assertRaises(Denied): factory.load_bootstrap(str(self.path), ledger.digest(self.value))

    def test_purpose_selects_exact_observer_job_not_execution_capability(self):
        selected = factory.derive_selection(self.bootstrap, self.selector, crypto.CALLER_SHA, purpose="observer")
        self.assertEqual(selected.identity.required_native_job_name, "Final quality / heavy / example_heavy / ubuntu-24.04")
        challenge = factory.challenge_bootstrap(self.server, self.bootstrap, self.selector)
        self.native.claims["aud"] = challenge["audience"]
        with self.assertRaises(Denied):
            factory.verify_bootstrap_native(self.server, self.bootstrap, self.selector, challenge["nonce"],
                                             self.native.token(), "synthetic-job-token", purpose="observer")

    def test_future_ordinary_role_main_head_with_same_workflow_contract_needs_no_policy_edit(self):
        original = self.path.read_bytes()
        head = "9" * 40
        self.native.claims.update(sha=head, workflow_sha=head, run_id="502", check_run_id="733")
        self.native.run.update(id=502, head_sha=head)
        for job in self.native.jobs["jobs"]: job.update(run_id=502, head_sha=head)
        self.native.job.update(id=904, check_run_url=identity.API + "/repos/" + crypto.REPOSITORY + "/check-runs/733")
        self.worker = replace(self.worker, pid=23458, start_ticks=780)
        self.collected.return_value = self.worker
        proof, token = self.mint()
        self.assertEqual(proof.identity.run_id, 502)
        self.assertEqual(proof.policy.identity.caller_sha, head)
        factory.require_bootstrap_native(proof, self.server, proof.policy, token, "synthetic-job-token")
        self.assertEqual(self.path.read_bytes(), original)

    def test_foreign_signing_key_cannot_turn_same_locator_into_authority(self):
        challenge = factory.challenge_bootstrap(self.server, self.bootstrap, self.selector)
        self.native.claims["aud"] = challenge["audience"]
        with self.assertRaisesRegex(Denied, "^bootstrap-native-denied$"):
            factory.verify_bootstrap_native(self.server, self.bootstrap, self.selector, challenge["nonce"],
                self.native.token(key=self.native.foreign_key), "synthetic-job-token")


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootConfigurationTests(unittest.TestCase):
    """Real compiler/readers/Root FS. Acquisition/native OS observations modeled."""

    @classmethod
    def setUpClass(cls):
        import test_github_runner_incus_generation_publisher as source
        source.RootPublisherTests.setUpClass()
        RootBootstrapTests.setUpClass()

    def setUp(self):
        import test_github_runner_incus_generation_publisher as source
        self.pub = source.RootPublisherTests(methodName="runTest")
        self.pub.setUp(); self.addCleanup(self.pub.doCleanups)
        RootBootstrapTests.setUpClass()
        self.helper = RootBootstrapTests(methodName="runTest")
        self.helper.setUp(); self.addCleanup(self.helper.doCleanups)
        self.root = self.helper.root
        self.directory = self.root / "configurations"; self.directory.mkdir(mode=0o700)
        patch = mock.patch.object(factory, "ROOT", str(self.directory)); patch.start(); self.addCleanup(patch.stop)
        self.helper.native.claims.update(sha=self.pub.source.commit_sha, workflow_sha=self.pub.source.commit_sha,
            job_workflow_sha=self.pub.controller.commit_sha,
            job_workflow_ref=factory.VALIDATION + "/.github/workflows/collection-quality-profile-isolated.yml@" + self.pub.controller.commit_sha)
        self.helper.native.run.update(head_sha=self.pub.source.commit_sha,
            referenced_workflows=[{"path": self.helper.native.claims["job_workflow_ref"], "sha": self.pub.controller.commit_sha,
                                   "ref": self.pub.controller.commit_sha}])
        for job in self.helper.native.jobs["jobs"]: job.update(head_sha=self.pub.source.commit_sha)
        matrix = self.pub.cell["matrix"]
        self.selector = policy_registry.profile_selector(matrix["profile"], matrix["scenario"], matrix["target"])
        self.helper.native.job["name"] = matrix["profile"] + " / " + matrix["scenario"] + " / " + matrix["target"]
        self.helper.selector = self.selector
        base = self.helper.value["source_identity"]
        base["reusable_sha"] = self.pub.controller.commit_sha
        self.helper.value["controller"]["reusable_sha"] = self.pub.controller.commit_sha
        old = self.helper.value["cells"][next(iter(self.helper.value["cells"]))]
        template = deepcopy(self.pub.cell["engine"])
        template.pop("archives"); template.pop("trees")
        old.update(native_job_name=self.helper.native.job["name"],
            native_observer_job_name="Final quality / " + matrix["profile"] + " / " + matrix["scenario"] + " / " + matrix["target"],
            matrix=deepcopy(matrix), engine=template, incus=deepcopy(self.pub.cell["incus"]), github=deepcopy(self.pub.cell["github"]))
        self.helper.value["cells"] = {self.selector: old}
        self.helper.value["preparation"] = {key: value for key, value in self.pub.base.value.items() if key in factory.PREPARATION_KEYS}
        runtime = source.publisher._read(self.pub.runtime_ref["path"], self.pub.runtime_ref["sha256"])
        self.helper.value["runtime"] = {key: value for key, value in runtime.items() if key in factory.RUNTIME_KEYS}
        self.helper.seal()
        self.bootstrap = self.helper.bootstrap
        self.proof, self.token = self.helper.mint()
        stage = self.root / "genuine-stage-fixture"; stage.mkdir(mode=0o700)
        fds = []
        try:
            for name, raw in zip(factory.run_intake.ARCHIVES, (self.pub.artifact_raw, self.pub.source_raw, self.pub.controller_raw)):
                fd = os.open(stage / name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                fds.append(fd); os.write(fd, raw); os.fsync(fd)
            artifact = replace(self.pub.artifact, workflow_id=214182490)
            acquired = replace(self.pub.acquired, artifact=artifact)
            snapshot = factory.run_intake._validate_archives(acquired,
                **dict(zip(("artifact_fd", "source_fd", "controller_fd"), fds)))
        finally:
            for fd in fds: os.close(fd)
        self.snapshot = factory.run_intake.SealedRunSnapshot(str(stage), stage.stat().st_dev, stage.stat().st_ino, "7" * 64, snapshot)
        self.stage = mock.patch.object(factory.run_intake, "stage_run_snapshot", return_value=self.snapshot)
        self.staged = self.stage.start(); self.addCleanup(self.stage.stop)

    def create(self, snapshot=None):
        return factory.create_run_configuration(self.proof, self.helper.server, self.bootstrap, self.selector,
            self.token, "synthetic-job-token", self.snapshot if snapshot is None else snapshot)

    def test_real_private_config_consumed_by_registry_preparation_and_runtime_without_anchor(self):
        original_anchor = self.pub.anchor.exists()
        result = self.create()
        runtime = factory.runtime_rpc.RuntimeRPC(result.runtime_config_path, result.runtime_config_sha256)
        native = runtime._registry.select(self.selector).identity
        self.assertEqual(native.caller_sha, self.proof.identity.caller_sha)
        self.assertEqual(native.reusable_sha, self.proof.identity.reusable_sha)
        self.assertEqual(result.deadline, min(self.proof.job_started_at + 1800, crypto.NOW + 1200))
        self.assertEqual(self.pub.anchor.exists(), original_anchor)
        self.assertFalse((Path(result.directory) / "published.json").exists())
        with ledger.Ledger(self.helper.store_path, clock=factory.time.time) as store:
            with store._transaction() as state: self.assertEqual(state["leases"], {})

    def test_split_intake_preserves_real_snapshot_and_resolves_config_with_separate_authenticated_proof(self):
        intake = factory.run_intake
        rpc = factory.runtime_rpc
        acquisition = intake.acquisition
        staged = self.root / "split-intake"
        bindings = self.root / "split-bindings"
        for path in (staged, bindings):
            path.mkdir(mode=0o700)
        acquired = self.snapshot.snapshot.acquisition
        commit_requests = tuple(acquisition.CommitRequest(item.repository, item.repository_id, item.commit_sha)
                                for item in (acquired.source, acquired.controller))
        request = intake.MemoryRequest(*commit_requests, acquired.artifact, acquisition.MAX_ARCHIVE, 20000,
                                       512 * 1024 * 1024, 240)
        native = {"fixture": "native artifact projection"}
        proven = replace(acquired, provenance_sha256=hashlib.sha256(repr(native).encode("ascii")).hexdigest())

        def download(_request, _api, *, artifact_fd, source_fd, controller_fd, **_):
            for fd, raw in zip((artifact_fd, source_fd, controller_fd),
                               (self.pub.artifact_raw, self.pub.source_raw, self.pub.controller_raw)):
                with os.fdopen(os.dup(fd), "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            return proven

        def read_tree(commit, *_):
            original = acquired.source if commit.repository == factory.SOURCE else acquired.controller
            return original.tree_sha, original.files, original.directories

        dispatcher = rpc.BootstrapRuntimeRPC(self.bootstrap.path, self.bootstrap.sha256)
        phases = []
        factory_returned = False
        sealed_checks = []
        create_configuration = factory.create_run_configuration
        require_native = factory.require_bootstrap_native

        def create_then_record(*args, **kwargs):
            nonlocal factory_returned
            configuration = create_configuration(*args, **kwargs)
            factory_returned = True
            return configuration

        def check_native(*args, **kwargs):
            self.assertFalse(factory_returned, "RPC repeated the factory's final host check")
            for directory in self.directory.iterdir():
                if (directory / "sealed-inventory.json").is_file():
                    sealed_checks.append(directory)
            return require_native(*args, **kwargs)

        def round_trip(snapshot):
            received, errors = [], []
            server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            with server, client:
                def participate():
                    try:
                        rpc._write(client, {"schema": 2, "cell": self.selector,
                                            "operation": "run", "snapshot": snapshot})
                        challenge = rpc._read(client, rpc.MAX_REPLY, 8)
                        phases.append(challenge["nonce"])
                        issued_at = int(factory.time.time())
                        self.helper.native.claims.update(aud=challenge["audience"], jti="split-fixture-" + str(len(phases)),
                                                         iat=issued_at, nbf=issued_at, exp=issued_at + 300)
                        rpc._write(client, {"schema": 2, "operation": "run", "nonce": challenge["nonce"],
                            "token": self.helper.native.token(), "api_token": "synthetic-job-token"})
                        client.shutdown(socket.SHUT_WR)
                        received.append(rpc._read(client, rpc.MAX_REPLY, 8))
                    except Exception as error:
                        errors.append(error)

                thread = threading.Thread(target=participate)
                thread.start()
                try:
                    outcome = dispatcher.handle(server)
                finally:
                    thread.join(9)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(received, [outcome])
                return outcome

        self.stage.stop()  # Use the actual archived-file writer and reader.
        with mock.patch.object(intake, "ROOT", str(staged)), mock.patch.object(rpc, "BOOTSTRAP_BINDINGS", str(bindings)), \
             mock.patch.object(factory, "create_run_configuration", side_effect=create_then_record), \
             mock.patch.object(factory, "require_bootstrap_native", side_effect=check_native), \
             mock.patch.object(intake, "_native_request", return_value=request), \
             mock.patch.object(intake, "_acquire_memory", side_effect=download) as writer, \
             mock.patch.object(acquisition, "_tree", side_effect=read_tree), mock.patch.object(acquisition, "_native", return_value=native):
            snapshot = round_trip(None)
            self.assertEqual(snapshot["type"], "snapshot-ready")
            self.assertEqual(list(self.directory.iterdir()), [])
            self.assertEqual(list(bindings.iterdir()), [])
            failed = round_trip("0" * 64)
            self.assertEqual(failed["disposition"], "unknown-hold")
            self.assertEqual(list(self.directory.iterdir()), [])
            ready = round_trip(snapshot["snapshot"])
            self.assertEqual(ready["type"], "intake-ready")
            result = factory.resolve_configuration(self.bootstrap, self.selector, ready["configuration"])
            self.assertEqual(result.manifest_sha256, ready["configuration"])
            self.assertEqual(len(list(bindings.iterdir())), 1)
            self.assertEqual(writer.call_count, 1)
            self.assertEqual(sealed_checks, [Path(result.directory)])
        self.assertEqual(len(set(phases)), 3)
        with ledger.Ledger(self.helper.store_path, clock=factory.time.time) as store:
            self.assertEqual(store.lease_ids(), ())

    def test_same_job_reuses_original_deadline_and_inodes_never_extends(self):
        first = self.create()
        inventory = factory._inventory(Path(first.directory))
        with mock.patch.object(factory.time, "time", return_value=crypto.NOW + 100):
            again = self.create()
        self.assertEqual(first, again)
        self.assertEqual(factory._inventory(Path(first.directory)), inventory)

    def test_partial_write_intent_retained_and_never_rebuilt(self):
        with mock.patch.object(factory, "_build", side_effect=OSError("synthetic write fault")) as build:
            with self.assertRaisesRegex(Denied, "^run-configuration-held$"): self.create()
            with self.assertRaisesRegex(Denied, "^run-configuration-held$"): self.create()
            self.assertEqual(build.call_count, 1)
        path = next(self.directory.iterdir())
        self.assertEqual({entry.name for entry in path.iterdir()}, {"intent.json"})

    def test_forged_snapshot_or_private_config_tamper_not_adopted(self):
        with self.assertRaises(Denied): self.create(replace(self.snapshot, receipt_sha256="9" * 64))
        self.assertEqual(list(self.directory.iterdir()), [])
        result = self.create()
        path = Path(result.runtime_config_path)
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        with self.assertRaises(Denied): self.create()
        self.assertEqual(path.read_bytes(), original + b" ")

    def test_registered_observer_finds_original_execution_without_config_or_deadline_write(self):
        result = self.create()
        inventory = factory._inventory(Path(result.directory))
        self.helper.native.job["name"] = self.helper.value["cells"][self.selector]["native_observer_job_name"]
        self.helper.native.claims["check_run_id"] = "735"
        self.helper.native.job.update(id=906, check_run_url=identity.API + "/repos/" + crypto.REPOSITORY + "/check-runs/735")
        self.helper.worker = replace(self.helper.worker, pid=23459, start_ticks=781)
        self.helper.collected.return_value = self.helper.worker
        challenge = factory.challenge_bootstrap(self.helper.server, self.bootstrap, self.selector)
        self.helper.native.claims["aud"] = challenge["audience"]
        token = self.helper.native.token()
        observer = factory.verify_bootstrap_native(self.helper.server, self.bootstrap, self.selector,
            challenge["nonce"], token, "synthetic-job-token", purpose="observer")
        factory.require_bootstrap_native(observer, self.helper.server, observer.policy, token, "synthetic-job-token")
        self.assertEqual(factory.find_existing_configuration(self.bootstrap, self.selector, observer), result)
        with mock.patch.object(factory, "_native", wraps=factory._native) as native:
            _, current, _ = factory.require_bootstrap_observer_reader(
                observer, self.helper.server, observer.policy, token, "synthetic-job-token")
            self.assertEqual(current, observer.identity)
            self.assertIs(native.call_args.kwargs["check_host_resources"], False)
            with self.assertRaisesRegex(Denied, "bootstrap-native-proof"):
                factory.require_bootstrap_observer_reader(
                    self.proof, self.helper.server, self.proof.policy, token, "synthetic-job-token")
        self.helper.native.job["status"] = "completed"
        with self.assertRaises(Denied):
            factory.require_bootstrap_observer_reader(
                observer, self.helper.server, observer.policy, token, "synthetic-job-token")
        self.helper.native.job["status"] = "in_progress"
        self.assertEqual(factory._inventory(Path(result.directory)), inventory)
        with self.assertRaises(Denied):
            factory.create_run_configuration(observer, self.helper.server, self.bootstrap, self.selector,
                token, "synthetic-job-token", self.snapshot)
        self.helper.server.close()
        with self.assertRaises(Denied):
            factory.find_existing_configuration(self.bootstrap, self.selector, observer)

    def test_manifest_locator_resolves_readonly_and_origin_is_separately_bound(self):
        result = self.create()
        before = factory._inventory(Path(result.directory))
        self.assertEqual(factory.resolve_configuration(self.bootstrap, self.selector, result.manifest_sha256), result)
        origin = factory.read_configuration_origin(result)
        self.assertEqual((origin["run_id"], origin["job_id"], origin["check_run_id"]),
                         (self.proof.identity.run_id, self.proof.identity.job_id, self.proof.identity.check_run_id))
        self.assertEqual(origin["source_sha"], self.proof.identity.caller_sha)
        self.assertEqual(factory._inventory(Path(result.directory)), before)
        with self.assertRaises(Denied): factory.resolve_configuration(self.bootstrap, self.selector, "9" * 64)
        with self.assertRaises(Denied): factory.read_configuration_origin(replace(result, manifest_sha256="9" * 64))

    def test_resolver_rejects_catalogue_root_replacement_after_complete_read(self):
        result = self.create()
        read = factory._read_complete
        replaced = False
        def replace_root(directory):
            nonlocal replaced
            value = read(directory)
            if not replaced:
                replaced = True
                self.directory.rename(self.directory.with_name("preserved-original-configurations"))
                self.directory.mkdir(mode=0o700)
            return value
        with mock.patch.object(factory, "_read_complete", side_effect=replace_root):
            with self.assertRaisesRegex(Denied, "run-configuration-resolve-held"):
                factory.resolve_configuration(self.bootstrap, self.selector, result.manifest_sha256)
        self.assertTrue(replaced)

    def test_runtime_fresh_native_origin_cannot_borrow_another_run_or_check_same_head(self):
        result = self.create()
        runtime = factory.runtime_rpc.RuntimeRPC(result.runtime_config_path, result.runtime_config_sha256,
                                                derived_configuration=result)
        runtime._require_origin(self.proof.identity, self.selector)
        for field in ("run_id", "job_id", "check_run_id"):
            with self.subTest(field=field), self.assertRaises(Denied):
                runtime._require_origin(replace(self.proof.identity, **{field: getattr(self.proof.identity, field) + 1}),
                                        self.selector)
        # The independently sealed original per-job config is unchanged.
        self.assertEqual(factory.read_configuration_origin(result)["check_run_id"], self.proof.identity.check_run_id)

    def test_same_execution_lookup_reuses_original_config_without_public_archive_reacquisition(self):
        result = self.create()
        before = factory._inventory(Path(result.directory))
        self.staged.reset_mock()
        self.assertEqual(factory.find_existing_execution_configuration(self.bootstrap, self.selector, self.proof), result)
        self.staged.assert_not_called()
        self.assertEqual(factory._inventory(Path(result.directory)), before)
        # A different real check cannot borrow another job's source snapshot.
        self.helper.native.claims["check_run_id"] = "733"
        self.helper.native.job["check_run_url"] = identity.API + "/repos/" + crypto.REPOSITORY + "/check-runs/733"
        proof, _ = self.helper.mint()
        with self.assertRaises(Denied):
            factory.find_existing_execution_configuration(self.bootstrap, self.selector, proof)
        self.staged.assert_not_called()

    def test_native_job_start_bound_wins_over_larger_root_lease_window(self):
        self.helper.value["cells"][self.selector]["lease_seconds"] = 5400
        self.helper.seal(); self.bootstrap = self.helper.bootstrap
        self.proof, self.token = self.helper.mint()
        result = self.create()
        self.assertEqual(result.deadline, self.proof.job_started_at + 1800)
        self.assertLess(result.deadline, crypto.NOW + 5400)

    def test_later_real_job_after_retention_gets_own_clock_without_extending_original(self):
        old = self.helper.value["cells"][self.selector]
        new = deepcopy(old); new["matrix"]["scenario"] = "example_late"
        next_selector = policy_registry.profile_selector(new["matrix"]["profile"], "example_late", new["matrix"]["target"])
        new["native_job_name"] = "heavy / example_late / " + new["matrix"]["target"]
        new["native_observer_job_name"] = "Final quality / " + new["native_job_name"]
        self.helper.value["cells"][next_selector] = new
        self.helper.seal(); self.bootstrap = self.helper.bootstrap
        self.proof, self.token = self.helper.mint()
        first = self.create()
        original = Path(first.directory, "sealed-inventory.json").read_bytes()
        late = crypto.NOW + 14400
        with mock.patch.object(factory.time, "time", return_value=late):
            self.selector = next_selector; self.helper.selector = next_selector
            self.helper.native.claims.update(check_run_id="735", iat=late - 20, nbf=late - 20,
                                            exp=late + 300, jti="synthetic-later-job-token")
            self.helper.native.job.update(id=906, name=new["native_job_name"],
                check_run_url=identity.API + "/repos/" + crypto.REPOSITORY + "/check-runs/735",
                started_at=dt.datetime.fromtimestamp(late - 10, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
            self.helper.worker = replace(self.helper.worker, pid=23459, start_ticks=781)
            self.helper.collected.return_value = self.helper.worker
            self.proof, self.token = self.helper.mint()
            second = self.create()
        self.assertNotEqual(first.directory, second.directory)
        self.assertEqual(second.deadline, late + 1200)
        self.assertEqual(Path(first.directory, "sealed-inventory.json").read_bytes(), original)
