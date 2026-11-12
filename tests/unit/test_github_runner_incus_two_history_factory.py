"""Production Root factory composition; provider/collector/trust realm modeled.

Actual private no-work receipts are never repository fixtures. Hash-anchor
patches bind only this test's genuine temporary Root catalogue identities.
"""
from copy import deepcopy
import os
import sys
import unittest
from unittest import mock

import test_github_runner_incus_operating_continuation as legacy
from test_github_runner_incus_operating_two_history_continuation import prior_native
from incus_lease_issuer import identity, ledger, operating_cells as cells, run_factory as factory
from incus_lease_issuer.identity import Denied


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootTwoHistoryFactoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        legacy.RootContinuationTests.setUpClass()

    def setUp(self):
        self.base = legacy.RootContinuationTests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        helper = self.base.helper
        counts = cells.validate_continuation_qualification(self.base.qualification)
        raw = ledger.canonical({"rc": 0, "stderr_bytes": 0, "observed": {"schema": 1,
            "state": "ACTUAL_PRIOR_F27_PRODUCT_STORE_AND_CATALOGUES_EMPTY_NO_LEASE", "at": 1800000001,
            "boot_id": "synthetic-private-boot", "machine_id": "synthetic-private-machine",
            "bootstrap_sha256": "1" * 64, "current_core_sha256": "2" * 64, "counts": counts,
            "nonce_history_absence_claimed": False, "operator_raw_ledger_or_signing_key_read_export_or_hash": False,
            "prior_attempt": 1, "prior_head": cells.PRIOR_MAIN, "prior_public_clients": cells.PRIOR_CLIENTS,
            "prior_run": cells.PRIOR_RUN, "probe_sent_no_challenge_or_job_request": True,
            "product_store_validation_and_lease_ids_only": True, "test_state_reset_or_cleanup_performed": False}})
        for name, value in (("LEGACY_QUALIFICATION", ledger.digest(self.base.qualification)),
                            ("PRIOR_NO_WORK", ledger.digest(identity.decode_json(raw))),
                            ("TWO_HISTORY_WORKFLOW", helper.value["source_workflow_sha256"]),
                            ("TWO_HISTORY_REUSABLE", helper.value["source_identity"]["reusable_sha"])):
            patcher = mock.patch.object(cells, name, value)
            patcher.start(); self.addCleanup(patcher.stop)
        self.prior = prior_native()
        qualification = cells.two_history_continuation_qualification(self.base.qualification,
            *self.prior, raw, cells.PRIOR_CLIENTS)
        self.base.receipt.write_bytes(ledger.canonical(qualification))
        self.base.descriptor = {"schema": 2, "reason": "prior-initial-preauth-denied",
            "origin": cells.continuation_origin(), "prior": cells.continuation_prior_origin(),
            "qualification": {"path": str(self.base.receipt), "sha256": ledger.digest(qualification)},
            "successor": {**self.base.descriptor["successor"], "first_parent": cells.PRIOR_MAIN}}
        helper.value["operating_continuation"] = self.base.descriptor
        self.base.parent = cells.PRIOR_MAIN
        original = identity.HTTPSReader()
        prefix = identity.API + "/repos/" + factory.SOURCE
        def read(url, *, bearer=None):
            routes = {prefix + "/actions/runs/" + str(cells.PRIOR_RUN): self.prior[0],
                prefix + "/actions/runs/" + str(cells.PRIOR_RUN) + "/attempts/1/jobs?per_page=100&page=1": self.prior[1],
                prefix + "/git/commits/" + cells.PRIOR_MAIN: self.prior[3],
                **{prefix + "/check-runs/" + str(row["id"]): row for row in self.prior[2]}}
            if url in routes:
                return ledger.canonical(deepcopy(routes[url]))
            return original.read(url, bearer=bearer)
        patcher = mock.patch.object(identity, "HTTPSReader", return_value=type("Reader", (), {"read": staticmethod(read)})())
        patcher.start(); self.addCleanup(patcher.stop)
        helper.seal()

    def test_all_five_cells_and_observers_join_both_histories_once_per_proof(self):
        self.assertEqual(len(self.base.helper.value["cells"]), 5)
        for selector in self.base.helper.value["cells"]:
            for purpose in ("execution", "observer"):
                with self.subTest(selector=selector, purpose=purpose), mock.patch.object(
                        factory, "_continuation_original_native", wraps=factory._continuation_original_native) as history:
                    proof, token = self.base.mint(selector, purpose)
                    for _ in range(2):
                        factory.require_bootstrap_native(proof, self.base.helper.server, proof.policy, token, "synthetic-job-token")
                    self.assertEqual(history.call_count, 2)
                    self.assertEqual([call.kwargs for call in history.call_args_list], [{}, {"prior": True}])
        with ledger.Ledger(self.base.helper.store_path) as store:
            self.assertEqual(store.lease_ids(), ())

    def test_either_changed_history_current_native_or_unknown_intake_denies(self):
        for history in (self.base.origin, self.prior):
            history[2][0]["conclusion"] = "success"
            with self.assertRaises(Denied): self.base.mint()
            history[2][0]["conclusion"] = "failure"
        proof, token = self.base.mint()
        self.base.helper.native.job["status"] = "completed"
        with self.assertRaises(Denied):
            factory.require_bootstrap_native(proof, self.base.helper.server, proof.policy, token, "synthetic-job-token")
        self.base.helper.native.job["status"] = "in_progress"
        (self.base.intakes / ("a" * 64)).mkdir(mode=0o700)
        with self.assertRaises(Denied):
            factory.require_bootstrap_native(proof, self.base.helper.server, proof.policy, token, "synthetic-job-token")

    def test_root_receipt_inode_remains_bound_after_both_histories_are_verified(self):
        self.base.test_byte_identical_receipt_inode_change_invalidates_existing_native_proof()

    def test_genuinely_consumed_legacy_invocation_still_blocks_two_history_successor(self):
        self.base.test_genuinely_prepared_original_invocation_invalidates_the_zero_receipt()
