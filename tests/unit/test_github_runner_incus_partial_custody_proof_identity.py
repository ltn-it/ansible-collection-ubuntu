"""Real partial-retention producer and Ledger consumer; native facts modeled."""
import copy
from dataclasses import replace
import os
import sys
import unittest
from unittest import mock

import test_github_runner_incus_partial_preparation as fixtures
from incus_lease_issuer import operating_custody as custody
from incus_lease_issuer.identity import Denied


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class PartialCustodyProofIdentityTests(unittest.TestCase):
    def issued(self):
        fixture = fixtures.PartialPreparationTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUpClass()
        fixture.setUp()
        fixture.fail_after_six()
        fixture.finalizer.withdraw_partial_preparation(fixture.registry, "approved", fixture.store, fixture.lease)
        fixture.terminal()
        captured = []
        def capture(lease, proof):
            self.assertEqual(lease, fixture.lease)
            captured.append(proof)
            return proof
        with mock.patch.object(fixture.store, "bind_partial_preparation_custody", side_effect=capture):
            custody.retain_partial_preparation(fixture.registry, "approved", fixture.store, fixture.lease)
        self.assertEqual(len(captured), 1)
        return fixture, captured[0]

    def test_unregistered_copies_cannot_bind_or_consume_actual_issued_proof(self):
        fixture, proof = self.issued()
        before = fixture.store.read(fixture.lease)
        for clone in (replace(proof), copy.copy(proof), copy.deepcopy(proof)):
            with self.subTest(copy_type=type(clone).__name__):
                self.assertIsNot(clone, proof)
                with self.assertRaisesRegex(Denied, "^partial-custody-proof$"):
                    fixture.store.bind_partial_preparation_custody(fixture.lease, clone)
                self.assertEqual(fixture.store.read(fixture.lease), before)
                self.assertIn(proof, custody._PARTIAL_PROOFS)
        value = fixture.store.bind_partial_preparation_custody(fixture.lease, proof)
        self.assertEqual(value["kind"], "failed-partial-preparation")
        self.assertEqual(fixture.store.read(fixture.lease)["partial_preparation_custody"], value)
        self.assertNotIn(proof, custody._PARTIAL_PROOFS)
        policy = fixture.store.read_policy(before["policy_sha256"])
        with self.assertRaisesRegex(Denied, "^partial-custody-proof$"):
            custody.require_partial_retained_proof(proof, fixture.lease, before, policy)
        with self.assertRaises(Denied):
            fixture.store.bind_partial_preparation_custody(fixture.lease, proof)

    def test_actual_issued_proof_keeps_pid_thread_and_lifetime_guards(self):
        for field in ("pid", "thread", "expiry"):
            with self.subTest(field=field):
                fixture, proof = self.issued()
                before = fixture.store.read(fixture.lease)
                guard = (mock.patch.object(custody.os, "getpid", return_value=proof.pid + 1) if field == "pid" else
                         mock.patch.object(custody.threading, "get_ident", return_value=proof.thread + 1) if field == "thread" else
                         mock.patch.object(custody.time, "monotonic", return_value=proof.expires))
                with guard, self.assertRaisesRegex(Denied, "^partial-custody-proof-drift$"):
                    fixture.store.bind_partial_preparation_custody(fixture.lease, proof)
                self.assertEqual(fixture.store.read(fixture.lease), before)
                self.assertNotIn(proof, custody._PARTIAL_PROOFS)
                with self.assertRaisesRegex(Denied, "^partial-custody-proof$"):
                    fixture.store.bind_partial_preparation_custody(fixture.lease, proof)
