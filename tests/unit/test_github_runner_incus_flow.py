"""Couple real synthetic RS256 verification with the real private ledger.

The scripted GitHub metadata and Worker are fixtures, never native admission.
No credential, certificate, VM or live endpoint is created by these tests.
"""
import copy
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

import test_github_runner_incus_identity as fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import identity, ledger  # noqa: E402


class FixtureReader:
    def __init__(self, fixture):
        self.fixture = fixture
        self.calls = []

    def read(self, url, *, bearer=None):
        self.calls.append((url, bearer))
        if url == identity.JWKS_URL:
            if bearer is not None:
                raise AssertionError("credential on fixture JWKS")
            return self.fixture.jwks
        prefix = identity.API + "/repos/" + fixtures.REPOSITORY
        routes = {
            prefix + "/actions/runs/501": self.fixture.run,
            prefix + "/actions/runs/501/attempts/1/jobs?per_page=100&page=1": self.fixture.jobs,
            prefix + "/actions/jobs/902": self.fixture.job,
            prefix + "/branches/main": {"protected": True, "commit": {"sha": fixtures.CALLER_SHA}},
        }
        return json.dumps(copy.deepcopy(routes[url])).encode()


class VerifiedLedgerFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.CurrentJobIdentityTests.setUpClass()

    def setUp(self):
        self.fixture = fixtures.CurrentJobIdentityTests()
        self.fixture.setUp()
        # The fixture module loads identity in an isolated namespace. Cross the
        # internal test boundary explicitly; production requires its own type.
        self.identity_policy = identity.Policy(**asdict(self.fixture.policy))
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "store"
        self.path.mkdir(mode=0o700)
        ledger.Ledger.initialize(self.path, owner_uid=os.getuid(), clock=lambda: fixtures.NOW)
        self.store = ledger.Ledger(self.path, owner_uid=os.getuid(), clock=lambda: fixtures.NOW)
        self.addCleanup(self.store.shutdown)
        self.worker = ledger.Worker(2101, 61, 23456, 777,
                                    "12345678-1234-4234-8234-123456789abc")
        self.policy = self.store.archive_policy({
            "custodian_ref": "fixture:custodian", "storage_ref": "fixture:private-store",
            "approval_ref": "fixture:not-operating-acceptance", "retention_seconds": 3600,
            "max_lease_seconds": 1800,
        })

    def verified(self, challenge, *, foreign=False):
        self.fixture.claims["aud"] = challenge["audience"]
        reader = FixtureReader(self.fixture)
        result = identity.verify_github_assignment(
            self.fixture.token(key=self.fixture.foreign_key if foreign else self.fixture.key),
            self.identity_policy, audience=challenge["audience"], peer_uid=2101,
            access_token="synthetic-noncredential", reader=reader, clock=lambda: fixtures.NOW,
        )
        return result

    def test_verified_audience_and_native_job_are_consumed_once(self):
        challenge = self.store.challenge(self.worker)
        who = self.verified(challenge)
        lease = self.store.prepare(challenge["nonce"], self.worker, who,
                                   policy_sha256=self.policy, cell_sha256="e" * 64,
                                   deadline=fixtures.NOW + 120)
        record = self.store.read(lease)
        self.assertEqual((record["identity"]["job_id"], record["identity"]["check_run_id"]), (902, 731))
        self.assertEqual(record["identity"]["audience"], challenge["audience"])
        with self.assertRaises(identity.Denied):
            self.store.prepare(challenge["nonce"], self.worker, who,
                               policy_sha256=self.policy, cell_sha256="e" * 64,
                               deadline=fixtures.NOW + 120)

    def test_invalid_signature_cannot_change_ledger_or_borrow_a_new_nonce(self):
        challenge = self.store.challenge(self.worker)
        before = (self.path / "state.json").read_bytes()
        with self.assertRaises(identity.Denied):
            self.verified(challenge, foreign=True)
        self.assertEqual((self.path / "state.json").read_bytes(), before)
        who = self.verified(challenge)
        other = self.store.challenge(ledger.Worker(2101, 61, 23457, 778, self.worker.boot_id))
        with self.assertRaises(identity.Denied):
            self.store.prepare(other["nonce"], self.worker, who,
                               policy_sha256=self.policy, cell_sha256="e" * 64,
                               deadline=fixtures.NOW + 120)
