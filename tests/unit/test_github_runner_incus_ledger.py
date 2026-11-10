"""Real private-filesystem ledger tests, with synthetic trusted worker facts.

No live kernel collector, socket, credential, Incus executor, custody acceptance
or test PASS is established by preparing/closing these component fixtures.
"""
from dataclasses import asdict, replace
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import ledger  # noqa: E402
from incus_lease_issuer.identity import Identity, Denied  # noqa: E402


NOW = 1793772000
CELL = "e" * 64
EVIDENCE = "f" * 64
POLICY = {
    "custodian_ref": "synthetic-custodian-reference",
    "storage_ref": "synthetic-private-store-reference",
    "approval_ref": "synthetic-policy-reference-not-operating-acceptance",
    "retention_seconds": 3600,
    "max_lease_seconds": 1800,
}
WORKER = {"uid": 2101, "runner_id": 61, "pid": 12345, "start_ticks": 987654,
          "boot_id": "12345678-1234-4234-8234-123456789abc"}


def synthetic_identity(audience_value, **changes):
    values = {
        "run_id": 501, "job_id": 902, "check_run_id": 731,
        "runner_id": 61, "service_uid": 2101,
        "caller_sha": "a" * 40, "reusable_sha": "b" * 40,
        "valid_until": NOW + 300,
        "token_id_sha256": hashlib.sha256(b"synthetic-ledger-token").hexdigest(),
        "audience": audience_value,
    }
    return Identity(**(values | changes))


def concurrent_prepare(path, policy_sha, challenge, worker_values, identity_values, start, replies):
    """Spawn-safe process entry; no caller/provider transport is involved."""
    replies.put(("ready", os.getpid()))
    if not start.wait(10):
        return
    try:
        with ledger.Ledger(path, owner_uid=os.getuid(), clock=lambda: NOW) as store:
            lease = store.prepare(challenge["nonce"], ledger.Worker(**worker_values),
                                  Identity(**identity_values), policy_sha256=policy_sha,
                                  cell_sha256=CELL, deadline=NOW + 120)
        replies.put(("prepared", lease))
    except Denied as error:
        replies.put(("denied", str(error)))


def crash_after_intent(path, lease, connection):
    # Bypass context exit deliberately: process death must release the kernel
    # lock while the fsynced effect intent survives for reconciliation.
    with ledger.Ledger(path, owner_uid=os.getuid(), clock=lambda: NOW) as store:
        effect = store.begin(lease, "certificate-create", "synthetic-cert")
        connection.send(effect)
        connection.close()
        os._exit(0)


class IncusLedgerTests(unittest.TestCase):
    def remote_stop_ready(self, store, lease):
        targets = self.provision(store, lease)
        for operation, target in (("engine-stop", targets["engine-start"]),
                                  ("fence-disable", targets["fence-create"]),
                                  ("certificate-revoke", targets["certificate-create"])):
            effect = store.begin(lease, operation, target)
            store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
        return "instance:lit-owned-lease:declared-vm"

    def test_remote_stop_requires_owned_project_local_stop_withdrawal_and_revocation(self):
        with self.open() as store:
            lease, *_ = self.prepare(store)
            self.deny(store.begin, lease, "instance-stop", "instance:lit-owned-lease:declared-vm")
            target = self.remote_stop_ready(store, lease)
            self.deny(store.begin, lease, "instance-stop", "instance:foreign:declared-vm")
            self.deny(store.begin, lease, "instance-stop", "instance:lit-owned-lease:../foreign")
            effect = store.begin(lease, "instance-stop", target)
            self.assertEqual(store.read(lease)["effects"][effect]["state"], "intent")
            self.deny(store.begin, lease, "instance-stop", target)

    def test_remote_stop_unknown_uuid_survives_restart_without_resend_or_adoption(self):
        with self.open() as store:
            lease, *_ = self.prepare(store)
            target = self.remote_stop_ready(store, lease)
            effect = store.begin(lease, "instance-stop", target)
            operation = "12345678-1234-4234-8234-123456789abc"
            store.bind_native_operation(lease, effect, operation)
            store.record(lease, effect, "unknown", evidence_sha256=EVIDENCE)
            expected = store.read(lease)
        with self.open() as store:
            self.assertEqual(store.read(lease), expected)
            self.assertEqual(store.read(lease)["effects"][effect]["incus_operation_id"], operation)
            self.deny(store.begin, lease, "instance-stop", target)
            self.deny(store.begin, lease, "instance-stop", "instance:lit-owned-lease:other-vm")
            self.deny(store.close, lease)

    def test_remote_stop_after_cancel_and_expiry_is_once_withdrawal_not_new_authority(self):
        with self.open() as store:
            lease, *_ = self.prepare(store)
            target = self.remote_stop_ready(store, lease)
            before = store.read(lease)
            store.cancel(lease, "cancelled")
            self.now += 121
            effect = store.begin(lease, "instance-stop", target)
            store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            after = store.read(lease)
            self.assertEqual(after["expires_at"], before["expires_at"])
            self.assertEqual(after["authorizations"], before["authorizations"])
            self.assertEqual(after["state"], "cancelled")
            self.deny(store.begin, lease, "instance-stop", target)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "private-ledger"
        self.path.mkdir(mode=0o700)
        self.now = NOW
        ledger.Ledger.initialize(self.path, owner_uid=os.getuid(), clock=lambda: self.now)
        self.worker = ledger.Worker(**WORKER)

    def open(self, path=None):
        return ledger.Ledger(self.path if path is None else path,
                             owner_uid=os.getuid(), clock=lambda: self.now)

    def prepare(self, store, *, worker=None, identity_changes=None, deadline=None):
        worker = self.worker if worker is None else worker
        policy_sha = store.archive_policy(dict(POLICY))
        challenge = store.challenge(worker)
        who = synthetic_identity(challenge["audience"], **(identity_changes or {}))
        lease = store.prepare(challenge["nonce"], worker, who, policy_sha256=policy_sha,
                              cell_sha256=CELL, deadline=NOW + 120 if deadline is None else deadline)
        return lease, challenge, who, policy_sha

    def deny(self, callable_, *args, **kwargs):
        with self.assertRaises(Denied) as caught:
            callable_(*args, **kwargs)
        self.assertIsInstance(caught.exception, ValueError)
        self.assertRegex(str(caught.exception), r"^[a-z][a-z0-9_-]{0,95}$")

    def test_challenge_is_pending_worker_idempotent_and_lease_survives_restart(self):
        with self.open() as store:
            first = store.challenge(self.worker)
            self.assertEqual(store.challenge(self.worker), first)
            self.assertGreater(first["expires_at"], NOW)
            self.assertLessEqual(first["expires_at"], NOW + 300)
            self.assertTrue(first["nonce"])
            lease, challenge, who, policy_sha = self.prepare(store)
            before = store.read(lease)
            self.assertEqual(before["state"], "prepared")
            self.assertEqual(before["policy_sha256"], policy_sha)
            before["state"] = "closed"
            before["identity"]["runner_id"] = 62
            self.assertEqual(store.read(lease)["state"], "prepared")
            self.assertEqual(store.read(lease)["identity"]["runner_id"], 61)
            expected = store.read(lease)
        with self.open() as store:
            self.assertEqual(store.read(lease), expected)
            self.deny(store.prepare, challenge["nonce"], self.worker, who,
                      policy_sha256=policy_sha, cell_sha256=CELL, deadline=NOW + 120)

    def test_real_state_and_lock_files_have_private_regular_single_link_metadata(self):
        with self.open() as store:
            self.prepare(store)
        for name in ("state.json", "lock"):
            info = (self.path / name).lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_uid, os.getuid())
            self.assertEqual(info.st_nlink, 1)

    def test_worker_pid_start_or_boot_swap_cannot_consume_pending_nonce(self):
        with self.open() as store:
            policy_sha = store.archive_policy(dict(POLICY))
            challenge = store.challenge(self.worker)
            who = synthetic_identity(challenge["audience"])
            for change in ({"pid": 12346}, {"start_ticks": 987655},
                           {"boot_id": "22345678-1234-4234-8234-123456789abc"}):
                with self.subTest(change=change):
                    self.deny(store.prepare, challenge["nonce"], replace(self.worker, **change), who,
                              policy_sha256=policy_sha, cell_sha256=CELL, deadline=NOW + 120)
            store.prepare(challenge["nonce"], self.worker, who, policy_sha256=policy_sha,
                          cell_sha256=CELL, deadline=NOW + 120)

    def test_identity_audience_and_worker_binding_are_required_before_consumption(self):
        with self.open() as store:
            policy_sha = store.archive_policy(dict(POLICY))
            challenge = store.challenge(self.worker)
            for change in ({"audience": "https://other.example.invalid"}, {"service_uid": 2102},
                           {"runner_id": 62}, {"valid_until": NOW}):
                with self.subTest(change=change):
                    self.deny(store.prepare, challenge["nonce"], self.worker,
                              synthetic_identity(challenge["audience"], **change),
                              policy_sha256=policy_sha, cell_sha256=CELL, deadline=NOW + 120)
            store.prepare(challenge["nonce"], self.worker, synthetic_identity(challenge["audience"]),
                          policy_sha256=policy_sha, cell_sha256=CELL, deadline=NOW + 120)

    def test_expired_challenge_or_overlong_deadline_denies(self):
        with self.open() as store:
            policy_sha = store.archive_policy(dict(POLICY))
            challenge = store.challenge(self.worker)
            who = synthetic_identity(challenge["audience"], valid_until=NOW + 600)
            for deadline in (NOW, NOW - 1, NOW + 1801, True, float(NOW + 120)):
                with self.subTest(deadline=deadline):
                    self.deny(store.prepare, challenge["nonce"], self.worker, who,
                              policy_sha256=policy_sha, cell_sha256=CELL, deadline=deadline)
            self.now = challenge["expires_at"]
            self.deny(store.prepare, challenge["nonce"], self.worker, who,
                      policy_sha256=policy_sha, cell_sha256=CELL, deadline=self.now + 120)

    def test_single_unclosed_lease_is_enforced_by_runner_and_uid(self):
        with self.open() as store:
            self.prepare(store)
            for changes in ({"pid": 99999}, {"uid": 2102}, {"runner_id": 62}):
                with self.subTest(changes=changes):
                    worker = replace(self.worker, **changes)
                    # Denial may occur at challenge or prepare, but no second
                    # active lease for either occupied dimension may result.
                    def prepare_another():
                        self.prepare(store, worker=worker,
                                     identity_changes={"service_uid": worker.uid,
                                                       "runner_id": worker.runner_id,
                                                       "check_run_id": 732,
                                                       "job_id": 903,
                                                       "token_id_sha256": "d" * 64})
                    self.deny(prepare_another)

    def test_token_and_native_check_stay_consumed_after_cleanup_close(self):
        with self.open() as store:
            lease, _, old_identity, policy_sha = self.prepare(store)
            store.close(lease)
            self.assertEqual(store.read(lease)["state"], "closed")
        with self.open() as store:
            for changes in ({}, {"token_id_sha256": "d" * 64},
                            {"run_id": 502, "check_run_id": 732, "job_id": 903}):
                challenge = store.challenge(self.worker)
                who = replace(old_identity, audience=challenge["audience"], **changes)
                with self.subTest(changes=changes):
                    self.deny(store.prepare, challenge["nonce"], self.worker, who,
                              policy_sha256=policy_sha, cell_sha256=CELL, deadline=NOW + 120)

    def test_policy_archive_is_content_bound_and_copied_before_input_mutation(self):
        policy = dict(POLICY)
        with self.open() as store:
            old_sha = store.archive_policy(policy)
            self.assertEqual(store.archive_policy(dict(policy)), old_sha)
            policy["custodian_ref"] = "different-synthetic-reference"
            new_sha = store.archive_policy(policy)
            self.assertNotEqual(old_sha, new_sha)
            self.assertEqual(store.archive_policy(dict(POLICY)), old_sha)
            challenge = store.challenge(self.worker)
            lease = store.prepare(challenge["nonce"], self.worker,
                                  synthetic_identity(challenge["audience"]),
                                  policy_sha256=old_sha, cell_sha256=CELL, deadline=NOW + 120)
            self.assertEqual(store.read(lease)["policy_sha256"], old_sha)

    def test_policy_read_is_detached_and_never_initializes_or_changes_archive(self):
        with self.open() as store:
            key = store.archive_policy(dict(POLICY))
            before = (self.path / "state.json").read_bytes()
            result = store.read_policy(key)
            self.assertEqual(result, POLICY)
            result["custodian_ref"] = "changed-local-copy"
            self.assertEqual(store.read_policy(key), POLICY)
            for wrong in ("f" * 64, "short", None, True):
                with self.subTest(digest=wrong):
                    self.deny(store.read_policy, wrong)
            self.assertEqual((self.path / "state.json").read_bytes(), before)

    def test_refresh_preserves_original_verified_policy_domain(self):
        from dataclasses import replace
        with self.open() as store:
            lease, _, _, _ = self.prepare(store, identity_changes={"policy_sha256": "a" * 64})
            fresh = store.challenge(self.worker)
            who = synthetic_identity(fresh["audience"], policy_sha256="a" * 64,
                                     token_id_sha256=hashlib.sha256(b"fresh-domain-token").hexdigest())
            before = (self.path / "state.json").read_bytes()
            self.deny(store.refresh_identity, lease, fresh["nonce"], self.worker,
                      replace(who, policy_sha256="b" * 64))
            self.assertEqual((self.path / "state.json").read_bytes(), before)
            store.refresh_identity(lease, fresh["nonce"], self.worker, who)
            self.assertEqual(store.read(lease)["identity"]["policy_sha256"], "a" * 64)

    def test_policy_archive_requires_exact_bounded_nonsecret_reference_contract(self):
        cases = ({**POLICY, "extra": "unexpected"},
                 {key: value for key, value in POLICY.items() if key != "approval_ref"},
                 {**POLICY, "custodian_ref": ""}, {**POLICY, "approval_ref": True},
                 {**POLICY, "retention_seconds": 0}, {**POLICY, "retention_seconds": 86401},
                 {**POLICY, "retention_seconds": True}, {**POLICY, "max_lease_seconds": 5401})
        with self.open() as store:
            for policy in cases:
                with self.subTest(policy=policy):
                    self.deny(store.archive_policy, policy)

    def test_crash_intent_is_retained_and_never_blindly_retried(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
        context = multiprocessing.get_context("spawn")
        receive, send = context.Pipe(duplex=False)
        process = context.Process(target=crash_after_intent, args=(str(self.path), lease, send))
        process.start()
        send.close()
        try:
            self.assertTrue(receive.poll(15), "child did not persist its intent")
            effect = receive.recv()
            process.join(15)
            self.assertEqual(process.exitcode, 0)
        finally:
            receive.close()
            if process.is_alive():
                process.terminate()
                process.join(5)
        with self.open() as store:
            self.assertEqual(store.read(lease)["effects"][effect]["state"], "intent")
            self.deny(store.begin, lease, "certificate-create", "synthetic-cert")
            self.deny(store.begin, lease, "test", "cell")
            self.deny(store.close, lease)
            store.reconcile(lease, effect, "not_applied", evidence_sha256=EVIDENCE)
            # A known not-applied result is still an attempted effect identity;
            # callers must not convert it into an automatic second attempt.
            self.deny(store.begin, lease, "certificate-create", "synthetic-cert")
            store.close(lease)

    def test_unknown_requires_reconciliation_before_other_effect_or_close(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            effect = store.begin(lease, "instance-create", "owned-instance")
            store.record(lease, effect, "unknown", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "test", "cell")
            self.deny(store.close, lease)
            self.deny(store.reconcile, lease, effect, "failed", evidence_sha256=EVIDENCE)
            store.reconcile(lease, effect, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.reconcile, lease, effect, "not_applied", evidence_sha256=EVIDENCE)
            destroy = store.begin(lease, "instance-destroy", "owned-instance")
            store.record(lease, destroy, "verified", evidence_sha256=EVIDENCE)
            store.close(lease)

    def test_cancel_blocks_normal_work_and_foreign_cleanup_but_allows_owned_cleanup(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            certificate = store.begin(lease, "certificate-create", "owned-cert")
            store.record(lease, certificate, "verified", evidence_sha256=EVIDENCE)
            instance = store.begin(lease, "instance-create", "owned-instance")
            store.record(lease, instance, "verified", evidence_sha256=EVIDENCE)
            store.cancel(lease, "cancelled")
            self.deny(store.begin, lease, "test", "cell")
            self.deny(store.begin, lease, "instance-create", "new-instance")
            self.deny(store.begin, lease, "instance-destroy", "foreign-instance")
            self.deny(store.begin, lease, "certificate-revoke", "foreign-cert")
            self.deny(store.close, lease)
            for operation, target in (("instance-destroy", "owned-instance"),
                                      ("certificate-revoke", "owned-cert")):
                effect = store.begin(lease, operation, target)
                store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            store.close(lease)
            self.assertEqual(store.read(lease)["state"], "closed")

    def test_expiry_stops_normal_work_while_known_owned_cleanup_remains_possible(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            effect = store.begin(lease, "instance-create", "owned-instance")
            store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            self.now = NOW + 121
            self.deny(store.begin, lease, "test", "cell")
            destroy = store.begin(lease, "instance-destroy", "owned-instance")
            store.record(lease, destroy, "verified", evidence_sha256=EVIDENCE)
            store.close(lease)

    def test_failed_is_not_a_valid_mutation_outcome_but_test_failure_can_close(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            effect = store.begin(lease, "certificate-create", "synthetic-cert")
            self.deny(store.record, lease, effect, "failed", evidence_sha256=EVIDENCE)
            store.record(lease, effect, "not_applied", evidence_sha256=EVIDENCE)
            for operation in ("test", "capture", "evidence-upload"):
                effect = store.begin(lease, operation, "cell")
                store.record(lease, effect, "failed", evidence_sha256=EVIDENCE)
            store.close(lease)
            # Cleanup closure must not be interpreted as test success.
            self.assertEqual(store.read(lease)["state"], "closed")

    def test_two_processes_can_consume_one_pending_challenge_only_once(self):
        with self.open() as store:
            policy_sha = store.archive_policy(dict(POLICY))
            challenge = store.challenge(self.worker)
        context = multiprocessing.get_context("spawn")
        start, replies = context.Event(), context.Queue()
        processes = [context.Process(target=concurrent_prepare,
                     args=(str(self.path), policy_sha, challenge, WORKER,
                           asdict(synthetic_identity(challenge["audience"])), start, replies))
                     for _ in range(2)]
        for process in processes:
            process.start()
        try:
            self.assertEqual([replies.get(timeout=15)[0] for _ in processes], ["ready", "ready"])
            start.set()
            outcomes = [replies.get(timeout=15) for _ in processes]
            self.assertEqual(sorted(kind for kind, _ in outcomes), ["denied", "prepared"])
            for process in processes:
                process.join(15)
                self.assertEqual(process.exitcode, 0)
            lease = next(value for kind, value in outcomes if kind == "prepared")
            with self.open() as store:
                self.assertEqual(store.read(lease)["state"], "prepared")
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(5)
            replies.close()
            replies.join_thread()

    def test_root_directory_must_preexist_and_remain_private_and_owned(self):
        self.deny(lambda: self.open(self.path / "missing").__enter__())
        self.path.chmod(0o755)
        try:
            self.deny(lambda: self.open().__enter__())
        finally:
            self.path.chmod(0o700)
        self.deny(lambda: ledger.Ledger(self.path, owner_uid=os.getuid() + 1).__enter__())
        link = self.path.parent / "ledger-link"
        link.symlink_to(self.path, target_is_directory=True)
        self.deny(lambda: self.open(link).__enter__())

    def test_state_and_lock_reject_symlink_hardlink_and_public_mode(self):
        for name in ("state.json", "lock"):
            for kind in ("symlink", "hardlink", "mode"):
                with self.subTest(name=name, kind=kind):
                    directory = self.path.parent / (name.replace(".", "-") + "-" + kind)
                    directory.mkdir(mode=0o700)
                    ledger.Ledger.initialize(directory, owner_uid=os.getuid(), clock=lambda: self.now)
                    with self.open(directory) as store:
                        store.archive_policy(dict(POLICY))
                    target = directory / name
                    if kind == "mode":
                        target.chmod(0o644)
                    else:
                        outside = directory.parent / (directory.name + "-outside")
                        outside.write_bytes(target.read_bytes())
                        outside.chmod(0o600)
                        target.unlink()
                        if kind == "symlink":
                            target.symlink_to(outside)
                        else:
                            os.link(outside, target)
                    def read_corrupted_store():
                        with self.open(directory) as store:
                            store.archive_policy(dict(POLICY))
                    self.deny(read_corrupted_store)

    def test_missing_initialized_state_never_resets_replay_or_pending_intents(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            store.begin(lease, "certificate-create", "owned-cert")
        lock_inode = (self.path / "lock").stat().st_ino
        marker = (self.path / ".initialized").read_bytes()
        (self.path / "state.json").unlink()
        self.deny(self.open)
        self.deny(ledger.Ledger.initialize, self.path, owner_uid=os.getuid())
        self.assertFalse((self.path / "state.json").exists())
        self.assertEqual((self.path / "lock").stat().st_ino, lock_inode)
        self.assertEqual((self.path / ".initialized").read_bytes(), marker)

    def test_partial_initialization_is_not_automatically_repaired(self):
        path = self.path.parent / "interrupted-initialization"
        path.mkdir(mode=0o700)
        (path / "lock").touch(mode=0o600)
        self.deny(self.open, path)
        self.deny(ledger.Ledger.initialize, path, owner_uid=os.getuid())
        self.assertEqual([p.name for p in path.iterdir()], ["lock"])

    def test_short_authorization_stops_ordinary_effects_but_not_owned_cleanup(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store, identity_changes={"valid_until": NOW + 30})
            self.assertEqual(store.read(lease)["expires_at"], NOW + 120)
            effect = store.begin(lease, "instance-create", "owned-short-auth")
            store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            self.now = NOW + 31
            self.deny(store.begin, lease, "test", "expired-authorization")
            cleanup = store.begin(lease, "instance-destroy", "owned-short-auth")
            store.record(lease, cleanup, "verified", evidence_sha256=EVIDENCE)
            store.close(lease)
            self.assertEqual(store.read(lease)["state"], "closed")

    def test_fresh_authorization_resumes_work_without_extending_hard_deadline(self):
        with self.open() as store:
            lease, _, original, _ = self.prepare(store, identity_changes={"valid_until": NOW + 30})
            self.now = NOW + 31
            self.deny(store.begin, lease, "test", "before-refresh")
            challenge = store.challenge(self.worker)
            fresh = replace(original, audience=challenge["audience"], valid_until=NOW + 300,
                            token_id_sha256="c" * 64)
            store.refresh_identity(lease, challenge["nonce"], self.worker, fresh)
            record = store.read(lease)
            self.assertEqual(record["expires_at"], NOW + 120)
            self.assertEqual(record["identity"], asdict(original))
            self.assertEqual([a["token_id_sha256"] for a in record["authorizations"]],
                             [original.token_id_sha256, fresh.token_id_sha256])
            effect = store.begin(lease, "test", "after-refresh")
            store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
        with self.open() as store:
            self.assertEqual(store.read(lease)["expires_at"], NOW + 120)
            self.assertEqual(len(store.read(lease)["authorizations"]), 2)
            self.now = NOW + 121
            self.deny(store.begin, lease, "capture", "past-hard-deadline")
            another = store.challenge(self.worker)
            self.deny(store.refresh_identity, lease, another["nonce"], self.worker,
                      replace(fresh, audience=another["audience"], valid_until=NOW + 600,
                              token_id_sha256="d" * 64))
            self.assertEqual(store.read(lease)["expires_at"], NOW + 120)

    def test_refresh_consumes_new_nonce_and_jti_and_keeps_old_tokens_consumed(self):
        with self.open() as store:
            lease, original_challenge, original, _ = self.prepare(store)
            new_challenge = store.challenge(self.worker)
            self.assertNotEqual(new_challenge["nonce"], original_challenge["nonce"])
            self.deny(store.refresh_identity, lease, new_challenge["nonce"], self.worker,
                      replace(original, audience=new_challenge["audience"]))
            fresh = replace(original, audience=new_challenge["audience"], token_id_sha256="c" * 64)
            store.refresh_identity(lease, new_challenge["nonce"], self.worker, fresh)
            self.deny(store.refresh_identity, lease, new_challenge["nonce"], self.worker,
                      replace(fresh, token_id_sha256="d" * 64))
            next_challenge = store.challenge(self.worker)
            for consumed in (original, fresh):
                with self.subTest(token_digest=consumed.token_id_sha256[:1]):
                    self.deny(store.refresh_identity, lease, next_challenge["nonce"], self.worker,
                              replace(consumed, audience=next_challenge["audience"]))
            self.assertEqual(len(store.read(lease)["authorizations"]), 2)

    def test_refresh_cannot_change_worker_or_native_invocation_identity(self):
        with self.open() as store:
            lease, _, original, _ = self.prepare(store)
            for change in ({"pid": 12346}, {"start_ticks": 987655},
                           {"boot_id": "22345678-1234-4234-8234-123456789abc"},
                           {"uid": 2102}, {"runner_id": 62}):
                worker = replace(self.worker, **change)
                challenge = store.challenge(worker)
                who = replace(original, audience=challenge["audience"], token_id_sha256="c" * 64,
                              service_uid=worker.uid, runner_id=worker.runner_id)
                with self.subTest(worker_change=change):
                    self.deny(store.refresh_identity, lease, challenge["nonce"], worker, who)
            challenge = store.challenge(self.worker)
            for change in ({"run_id": 502}, {"job_id": 903}, {"check_run_id": 732},
                           {"caller_sha": "c" * 40}, {"reusable_sha": "c" * 40},
                           {"service_uid": 2102}, {"runner_id": 62}):
                who = replace(original, audience=challenge["audience"], token_id_sha256="c" * 64,
                              **change)
                with self.subTest(identity_change=change):
                    self.deny(store.refresh_identity, lease, challenge["nonce"], self.worker, who)
            self.assertEqual(store.read(lease)["identity"], asdict(original))
            self.assertEqual(len(store.read(lease)["authorizations"]), 1)
            # Rejected drift must not accidentally consume the good challenge.
            store.refresh_identity(lease, challenge["nonce"], self.worker,
                                   replace(original, audience=challenge["audience"], token_id_sha256="c" * 64))

    def test_cancelled_or_closed_lease_cannot_be_reactivated_by_fresh_identity(self):
        with self.open() as store:
            lease, _, original, _ = self.prepare(store)
            challenge = store.challenge(self.worker)
            fresh = replace(original, audience=challenge["audience"], token_id_sha256="c" * 64)
            store.cancel(lease, "cancelled")
            self.deny(store.refresh_identity, lease, challenge["nonce"], self.worker, fresh)
            self.assertEqual(store.read(lease)["state"], "cancelled")
            store.close(lease)
            self.deny(store.refresh_identity, lease, challenge["nonce"], self.worker, fresh)
            self.assertEqual(store.read(lease)["state"], "closed")
            self.assertEqual(len(store.read(lease)["authorizations"]), 1)

    @staticmethod
    def write_corrupted_snapshot(path, state, *, recompute_checksum=False):
        # This deliberately models root-readable stored-byte corruption. The
        # checksum is public corruption detection, never a root-tamper MAC.
        if recompute_checksum:
            unsigned = {key: value for key, value in state.items() if key != "checksum"}
            canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                                   allow_nan=False).encode()
            state["checksum"] = hashlib.sha256(canonical).hexdigest()
        (path / "state.json").write_text(json.dumps(state))

    def test_valid_json_policy_change_denies_even_with_recomputed_outer_checksum(self):
        for recalculate in (False, True):
            with self.subTest(recomputed_outer_checksum=recalculate):
                path = self.path.parent / ("policy-corruption-" + str(recalculate))
                path.mkdir(mode=0o700)
                ledger.Ledger.initialize(path, owner_uid=os.getuid(), clock=lambda: self.now)
                with self.open(path) as store:
                    policy_sha = store.archive_policy(dict(POLICY))
                    challenge = store.challenge(self.worker)
                state = json.loads((path / "state.json").read_text())
                # Both values remain within the accepted numeric bounds; the
                # old content-addressed archive key must still reject them.
                state["policies"][policy_sha]["retention_seconds"] += 1
                state["policies"][policy_sha]["max_lease_seconds"] += 1
                self.write_corrupted_snapshot(path, state, recompute_checksum=recalculate)
                before = (path / "state.json").read_bytes()
                self.deny(self.open, path)
                self.assertEqual((path / "state.json").read_bytes(), before)
                saved = json.loads(before)
                self.assertEqual(next(iter(saved["challenges"].values()))["state"], "issued")
                self.assertEqual(saved["tokens"], {})
                self.assertTrue(challenge["nonce"])

    def test_valid_json_snapshot_change_without_checksum_update_denies(self):
        state = json.loads((self.path / "state.json").read_text())
        state["generation"] += 1
        self.write_corrupted_snapshot(self.path, state)
        before = (self.path / "state.json").read_bytes()
        self.deny(self.open)
        self.assertEqual((self.path / "state.json").read_bytes(), before)

    def test_other_stores_valid_snapshot_cannot_replace_local_store_identity(self):
        other = self.path.parent / "independent-private-store"
        other.mkdir(mode=0o700)
        ledger.Ledger.initialize(other, owner_uid=os.getuid(), clock=lambda: self.now)
        with self.open(other) as store:
            store.archive_policy(dict(POLICY))
        original_marker = (self.path / ".initialized").read_bytes()
        other_marker = (other / ".initialized").read_bytes()
        self.assertNotEqual(json.loads(original_marker)["store_id"],
                            json.loads(other_marker)["store_id"])
        foreign = (other / "state.json").read_bytes()
        (self.path / "state.json").write_bytes(foreign)
        self.deny(self.open)
        self.assertEqual((self.path / "state.json").read_bytes(), foreign)
        self.assertEqual((self.path / ".initialized").read_bytes(), original_marker)


    def test_recover_lost_locator_keeps_one_lease_deadline_identity_and_unknown_effects(self):
        with self.open() as store:
            lease, _, original, custody = self.prepare(store, identity_changes={"policy_sha256": "d" * 64})
            effect = store.begin(lease, "certificate-create", "owned-unknown")
            store.record(lease, effect, "unknown", evidence_sha256=EVIDENCE)
            original_record = store.read(lease)
        with self.open() as store:
            for token_digest in ("c" * 64, "b" * 64):
                challenge = store.challenge(self.worker)
                fresh = replace(original, audience=challenge["audience"], token_id_sha256=token_digest)
                recovered = store.recover(challenge["nonce"], self.worker, fresh,
                                          policy_sha256=custody, cell_sha256=CELL, deadline=NOW + 120)
                self.assertEqual(recovered, lease)
                record = store.read(recovered)
                self.assertEqual(record["identity"], original_record["identity"])
                self.assertEqual(record["effects"], original_record["effects"])
                self.assertEqual(record["expires_at"], original_record["expires_at"])
                self.deny(store.begin, recovered, "test", "unknown-is-not-retry")
            self.assertEqual(len(store.read(lease)["authorizations"]), 3)
        state = json.loads((self.path / "state.json").read_text())
        self.assertEqual(set(state["leases"]), {lease})

    def test_recover_requires_new_nonce_and_jti_not_old_consumed_authority(self):
        with self.open() as store:
            lease, consumed, original, custody = self.prepare(store, identity_changes={"policy_sha256": "d" * 64})
            self.deny(store.recover, consumed["nonce"], self.worker,
                      replace(original, token_id_sha256="c" * 64),
                      policy_sha256=custody, cell_sha256=CELL, deadline=NOW + 120)
            fresh = store.challenge(self.worker)
            self.deny(store.recover, fresh["nonce"], self.worker,
                      replace(original, audience=fresh["audience"]),
                      policy_sha256=custody, cell_sha256=CELL, deadline=NOW + 120)
            self.assertEqual(len(store.read(lease)["authorizations"]), 1)

    def test_recover_rejects_worker_and_complete_native_or_policy_domain_drift(self):
        with self.open() as store:
            lease, _, original, custody = self.prepare(store, identity_changes={"policy_sha256": "d" * 64})
            challenge = store.challenge(self.worker)
            fresh = replace(original, audience=challenge["audience"], token_id_sha256="c" * 64)
            for change in ({"pid": 12346}, {"start_ticks": 987655},
                           {"boot_id": "22345678-1234-4234-8234-123456789abc"}):
                with self.subTest(worker=change):
                    self.deny(store.recover, challenge["nonce"], replace(self.worker, **change), fresh,
                              policy_sha256=custody, cell_sha256=CELL, deadline=NOW + 120)
            for change in ({"run_id": 502}, {"job_id": 903}, {"check_run_id": 732},
                           {"runner_id": 62}, {"service_uid": 2102}, {"caller_sha": "c" * 40},
                           {"reusable_sha": "c" * 40}, {"policy_sha256": "e" * 64}, {"policy_sha256": None}):
                with self.subTest(identity=change):
                    self.deny(store.recover, challenge["nonce"], self.worker, replace(fresh, **change),
                              policy_sha256=custody, cell_sha256=CELL, deadline=NOW + 120)
            self.assertEqual(len(store.read(lease)["authorizations"]), 1)

    def test_recover_rejects_root_cell_custody_and_deadline_drift_without_consuming(self):
        with self.open() as store:
            lease, _, original, custody = self.prepare(store, identity_changes={"policy_sha256": "d" * 64})
            different = store.archive_policy({**POLICY, "custodian_ref": "other-synthetic-reference"})
            challenge = store.challenge(self.worker)
            fresh = replace(original, audience=challenge["audience"], token_id_sha256="c" * 64)
            before = (self.path / "state.json").read_bytes()
            for changes in ({"cell_sha256": "c" * 64}, {"policy_sha256": different},
                            {"policy_sha256": "0" * 64}, {"deadline": NOW + 121}):
                arguments = {"policy_sha256": custody, "cell_sha256": CELL, "deadline": NOW + 120} | changes
                with self.subTest(changes=changes):
                    self.deny(store.recover, challenge["nonce"], self.worker, fresh, **arguments)
                    self.assertEqual((self.path / "state.json").read_bytes(), before)
            self.assertEqual(store.read(lease)["state"], "prepared")

    def test_recover_missing_cancelled_closed_or_expired_never_prepares_a_fallback(self):
        with self.open() as store:
            custody = store.archive_policy(dict(POLICY))
            challenge = store.challenge(self.worker)
            who = synthetic_identity(challenge["audience"], policy_sha256="d" * 64)
            self.deny(store.recover, challenge["nonce"], self.worker, who,
                      policy_sha256=custody, cell_sha256=CELL, deadline=NOW + 120)
            self.assertEqual(json.loads((self.path / "state.json").read_text())["leases"], {})
            lease = store.prepare(challenge["nonce"], self.worker, who,
                                  policy_sha256=custody, cell_sha256=CELL, deadline=NOW + 120)
            challenge = store.challenge(self.worker)
            fresh = replace(who, audience=challenge["audience"], token_id_sha256="c" * 64)
            store.cancel(lease, "cancelled")
            self.deny(store.recover, challenge["nonce"], self.worker, fresh,
                      policy_sha256=custody, cell_sha256=CELL, deadline=NOW + 120)
            store.close(lease)
            self.deny(store.recover, challenge["nonce"], self.worker, fresh,
                      policy_sha256=custody, cell_sha256=CELL, deadline=NOW + 120)
            self.now = NOW + 121
            self.deny(store.recover, challenge["nonce"], self.worker, fresh,
                      policy_sha256=custody, cell_sha256=CELL, deadline=NOW + 120)
            self.assertEqual(store.read(lease)["state"], "closed")

    def test_ambiguous_stored_native_identity_is_corrupt_not_recoverable(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store, identity_changes={"policy_sha256": "d" * 64})
        state = json.loads((self.path / "state.json").read_text())
        state["leases"]["f" * 32] = json.loads(json.dumps(state["leases"][lease]))
        self.write_corrupted_snapshot(self.path, state, recompute_checksum=True)
        before = (self.path / "state.json").read_bytes()
        self.deny(self.open)
        self.assertEqual((self.path / "state.json").read_bytes(), before)

    def provision(self, store, lease, *, through=None):
        targets = {
            "network-create": "network:default:lit0123456789ab",
            "project-create": "project:lit-owned-lease",
            "profile-configure": "profile:lit-owned-lease:default",
            "context-create": "context:" + CELL,
            "certificate-create": "certificate:" + "a" * 64,
            "engine-prepare": "engine:" + lease,
            "fence-create": "fence:" + lease,
            "fence-renew": "fence:" + lease + ":" + store.read(lease)["authorizations"][-1]["token_id_sha256"],
            "context-publish": "context:" + CELL,
            "engine-start": "engine:lit-lease-" + lease,
        }
        for operation, target in targets.items():
            effect = store.begin(lease, operation, target)
            store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            if operation == through:
                break
        return targets

    def cleanup(self, store, lease, targets):
        for creator in ("engine-start", "fence-create", "certificate-create", "engine-prepare", "context-create", "project-create", "network-create"):
            effect = store.begin(lease, ledger.CREATES[creator], targets[creator])
            store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)

    def test_root_provisioning_journal_survives_restart_and_all_resources_must_close(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            targets = self.provision(store, lease)
            self.deny(store.close, lease)
            before = store.read(lease)
        with self.open() as store:
            self.assertEqual(store.read(lease), before)
            self.cleanup(store, lease, targets)
            store.close(lease)
            result = store.read(lease)
            self.assertEqual(result["state"], "closed")
            self.assertEqual(len(result["effects"]), 17)
            self.assertTrue(all(effect["state"] == "verified" for effect in result["effects"].values()))

    def test_root_provisioning_requires_verified_prerequisites_and_single_exact_resource(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            self.deny(store.begin, lease, "project-create", "project:lit-owned-lease")
            self.deny(store.begin, lease, "context-create", "context:" + CELL)
            self.deny(store.begin, lease, "engine-start", "engine:lit-owned-cell")
            network = store.begin(lease, "network-create", "network:default:lit0123456789ab")
            store.record(lease, network, "not_applied", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "project-create", "project:lit-owned-lease")
            self.deny(store.begin, lease, "network-create", "network:default:lit0123456789ab")
            self.deny(store.begin, lease, "network-create", "network:default:litbbbbbbbbbbbb")
            self.assertEqual(len(store.read(lease)["effects"]), 1)
            store.close(lease)  # Proven not applied, never a retry authorization.

    def test_publish_exact_context_requires_certificate_and_holds_cleanup_until_reconciled(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            targets = self.provision(store, lease, through="context-create")
            self.deny(store.begin, lease, "context-publish", targets["context-create"])
            certificate = store.begin(lease, "certificate-create", targets["certificate-create"])
            store.record(lease, certificate, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "context-publish", "context:" + "d" * 64)
            directories = store.begin(lease, "engine-prepare", targets["engine-prepare"])
            store.record(lease, directories, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "engine-start", targets["engine-start"])
            published = store.begin(lease, "context-publish", targets["context-create"])
            store.record(lease, published, "unknown", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "engine-start", targets["engine-start"])
            self.deny(store.begin, lease, "certificate-revoke", targets["certificate-create"])
            self.now = NOW + 121
            store.cancel(lease, "job_ended")
            store.reconcile(lease, published, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "context-publish", targets["context-create"])
            self.deny(store.begin, lease, "engine-start", targets["engine-start"])
            for creator in ("certificate-create", "engine-prepare", "context-create", "project-create", "network-create"):
                effect = store.begin(lease, ledger.CREATES[creator], targets[creator])
                store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            store.close(lease)

    def test_expired_unpublished_context_cannot_publish_and_can_be_cleaned(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            targets = self.provision(store, lease, through="certificate-create")
            self.now = NOW + 121
            self.deny(store.begin, lease, "context-publish", targets["context-create"])
            self.deny(store.begin, lease, "engine-prepare", targets["engine-prepare"])
            store.cancel(lease, "cancelled")
            self.deny(store.begin, lease, "context-publish", targets["context-create"])
            for creator in ("certificate-create", "context-create", "project-create", "network-create"):
                effect = store.begin(lease, ledger.CREATES[creator], targets[creator])
                store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            store.close(lease)

    def test_not_applied_publication_does_not_authorize_retry_or_engine_start(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            targets = self.provision(store, lease, through="engine-prepare")
            published = store.begin(lease, "context-publish", targets["context-create"])
            self.deny(store.record, lease, published, "failed", evidence_sha256=EVIDENCE)
            store.record(lease, published, "not_applied", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "context-publish", targets["context-create"])
            self.deny(store.begin, lease, "context-publish", "context:" + "d" * 64)
            self.deny(store.begin, lease, "engine-start", targets["engine-start"])

    def test_engine_directory_resource_is_exact_lease_and_retained_until_release(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            self.deny(store.begin, lease, "engine-prepare", "engine:" + lease)
            targets = self.provision(store, lease, through="certificate-create")
            self.deny(store.begin, lease, "engine-prepare", "engine:" + "b" * 32)
            prepared = store.begin(lease, "engine-prepare", targets["engine-prepare"])
            store.record(lease, prepared, "verified", evidence_sha256=EVIDENCE)
            revoked = store.begin(lease, "certificate-revoke", targets["certificate-create"])
            store.record(lease, revoked, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "context-delete", targets["context-create"])
            self.deny(store.close, lease)
            release = store.begin(lease, "engine-release", targets["engine-prepare"])
            store.record(lease, release, "unknown", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "context-delete", targets["context-create"])
            store.reconcile(lease, release, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "engine-prepare", targets["engine-prepare"])
            for creator in ("context-create", "project-create", "network-create"):
                effect = store.begin(lease, ledger.CREATES[creator], targets[creator])
                store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            store.close(lease)

    def test_persisted_publication_and_engine_directory_targets_cannot_cross_context_or_lease(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            self.provision(store, lease, through="context-publish")
        original = json.loads((self.path / "state.json").read_text())
        for operation, foreign in (("context-publish", "context:" + "d" * 64),
                                   ("engine-prepare", "engine:" + "b" * 32)):
            state = json.loads(json.dumps(original))
            effect = next(effect for effect in state["leases"][lease]["effects"].values()
                          if effect["operation"] == operation)
            effect["target"] = foreign
            self.write_corrupted_snapshot(self.path, state, recompute_checksum=True)
            self.deny(self.open)
        self.write_corrupted_snapshot(self.path, original, recompute_checksum=True)

    def test_native_async_operation_id_is_durable_once_metadata_not_verified_or_retry(self):
        native = "12345678-1234-4234-8234-123456789abc"
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            effect = store.begin(lease, "network-create", "network:default:lit0123456789ab")
            store.bind_native_operation(lease, effect, native)
            store.bind_native_operation(lease, effect, native)
            self.assertEqual(store.read(lease)["effects"][effect]["state"], "intent")
            self.deny(store.bind_native_operation, lease, effect, "22345678-1234-4234-8234-123456789abc")
            store.record(lease, effect, "unknown", evidence_sha256=EVIDENCE)
        with self.open() as store:
            self.assertEqual(store.read(lease)["effects"][effect]["incus_operation_id"], native)
            self.deny(store.begin, lease, "network-create", "network:default:lit0123456789ab")
            store.reconcile(lease, effect, "verified", evidence_sha256=EVIDENCE)
            self.assertEqual(store.read(lease)["effects"][effect]["incus_operation_id"], native)
            self.deny(store.bind_native_operation, lease, effect, native)
            cleanup = store.begin(lease, "network-delete", "network:default:lit0123456789ab")
            self.deny(store.bind_native_operation, lease, cleanup, native)
            store.bind_native_operation(lease, cleanup, "32345678-1234-4234-8234-123456789abc")
            store.record(lease, cleanup, "verified", evidence_sha256=EVIDENCE)
            store.close(lease)
            self.deny(store.bind_native_operation, lease, cleanup, "32345678-1234-4234-8234-123456789abc")
        state = json.loads((self.path / "state.json").read_text())
        state["leases"][lease]["effects"][cleanup]["incus_operation_id"] = native
        self.write_corrupted_snapshot(self.path, state, recompute_checksum=True)
        self.deny(self.open)

    def test_native_operation_uuid_rejects_wrong_effect_schema_and_cross_lease_reuse(self):
        native = "12345678-1234-4234-8234-123456789abc"
        with self.open() as store:
            first, _, _, _ = self.prepare(store)
            effect = store.begin(first, "network-create", "network:default:lit0123456789ab")
            for value in (None, True, "not-uuid", native.upper(), "00000000-0000-0000-0000-000000000000"):
                self.deny(store.bind_native_operation, first, effect, value)
            store.bind_native_operation(first, effect, native)
            store.record(first, effect, "not_applied", evidence_sha256=EVIDENCE)
            store.close(first)
            other_worker = replace(self.worker, uid=2102, runner_id=62, pid=12346)
            second, _, _, _ = self.prepare(store, worker=other_worker, identity_changes={
                "service_uid": 2102, "runner_id": 62, "run_id": 502, "job_id": 903,
                "check_run_id": 732, "token_id_sha256": "c" * 64})
            observation = store.begin(second, "capture", "cell")
            self.deny(store.bind_native_operation, second, observation, native)
            store.record(second, observation, "verified", evidence_sha256=EVIDENCE)
            other = store.begin(second, "network-create", "network:default:litbbbbbbbbbbbb")
            self.deny(store.bind_native_operation, second, other, native)

    @staticmethod
    def supervisor(**changes):
        # Synthetic trusted Root acquisition result, not a live Podman proof.
        return {"pid": 32101, "start_ticks": 1234567,
                "boot_id": "12345678-1234-4234-8234-123456789abc",
                "exe_device": 2050, "exe_inode": 1234, "exe_sha256": "a" * 64} | changes

    def engine_intent(self, store, lease):
        targets = self.provision(store, lease, through="context-publish")
        return targets, store.begin(lease, "engine-start", targets["engine-start"])

    def test_engine_process_and_cid_survive_restart_without_completion_or_respawn_authority(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            targets, effect = self.engine_intent(store, lease)
            store.bind_engine_process(lease, effect, **self.supervisor())
            store.bind_engine_process(lease, effect, **self.supervisor())
            store.bind_engine_container(lease, effect, "b" * 64)
            store.bind_engine_container(lease, effect, "b" * 64)
            self.assertEqual(store.read(lease)["effects"][effect]["state"], "intent")
            store.record(lease, effect, "unknown", evidence_sha256=EVIDENCE)
        with self.open() as store:
            retained = store.read(lease)["effects"][effect]
            self.assertEqual(retained["engine_process"]["pid"], self.supervisor()["pid"])
            self.assertEqual(retained["engine_process"]["executable"], "/usr/bin/podman")
            self.assertEqual(retained["engine_container_id"], "b" * 64)
            self.assertEqual(retained["state"], "unknown")
            self.deny(store.begin, lease, "engine-start", targets["engine-start"])
            self.deny(store.begin, lease, "certificate-revoke", targets["certificate-create"])
            self.deny(store.close, lease)
            self.now = NOW + 121
            store.cancel(lease, "job_ended")
            # Retaining the same locator after cancellation is metadata only.
            store.bind_engine_process(lease, effect, **self.supervisor())
            store.bind_engine_container(lease, effect, "b" * 64)
            store.reconcile(lease, effect, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.bind_engine_process, lease, effect, **self.supervisor())
            self.cleanup(store, lease, targets)
            store.close(lease)
            self.assertEqual(store.read(lease)["effects"][effect]["engine_container_id"], "b" * 64)
            self.deny(store.bind_engine_container, lease, effect, "b" * 64)

    def test_engine_metadata_requires_exact_lease_target_process_first_and_immutable_typed_fields(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            self.provision(store, lease, through="context-publish")
            self.deny(store.begin, lease, "engine-start", "engine:lit-lease-" + "b" * 32)
            effect = store.begin(lease, "engine-start", "engine:lit-lease-" + lease)
            self.deny(store.bind_engine_container, lease, effect, "b" * 64)
            for changes in ({"pid": True}, {"start_ticks": 1.5}, {"boot_id": "not-a-boot-id"},
                            {"exe_device": -1}, {"exe_inode": 0}, {"exe_sha256": "not-a-digest"}):
                with self.subTest(changes=changes):
                    self.deny(store.bind_engine_process, lease, effect, **self.supervisor(**changes))
            store.bind_engine_process(lease, effect, **self.supervisor())
            for changes in ({"pid": 32102}, {"start_ticks": 1234568},
                            {"boot_id": "22345678-1234-4234-8234-123456789abc"},
                            {"exe_device": 2051}, {"exe_inode": 1235}, {"exe_sha256": "c" * 64}):
                self.deny(store.bind_engine_process, lease, effect, **self.supervisor(**changes))
            for value in (True, "short", "B" * 64, "../cid", {"cid": "b" * 64}):
                self.deny(store.bind_engine_container, lease, effect, value)
            store.bind_engine_container(lease, effect, "b" * 64)
            self.deny(store.bind_engine_container, lease, effect, "c" * 64)
            with self.assertRaises(TypeError):
                store.bind_engine_process(lease, effect, **self.supervisor(), path="/untrusted")
            with self.assertRaises(TypeError):
                store.bind_engine_container(lease, effect, "b" * 64, container_name="foreign")

    def test_engine_metadata_cannot_attach_to_unrelated_effect(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            effect = store.begin(lease, "capture", "cell")
            self.deny(store.bind_engine_process, lease, effect, **self.supervisor())
            self.deny(store.bind_engine_container, lease, effect, "b" * 64)
            self.assertNotIn("engine_process", store.read(lease)["effects"][effect])

    def test_closed_lease_engine_process_and_container_identity_cannot_be_borrowed(self):
        with self.open() as store:
            first, _, _, _ = self.prepare(store)
            targets, effect = self.engine_intent(store, first)
            store.bind_engine_process(first, effect, **self.supervisor())
            store.bind_engine_container(first, effect, "b" * 64)
            store.record(first, effect, "verified", evidence_sha256=EVIDENCE)
            self.cleanup(store, first, targets)
            store.close(first)
            second, _, _, _ = self.prepare(store, identity_changes={"run_id": 502, "job_id": 903,
                "check_run_id": 732, "token_id_sha256": "c" * 64})
            _, other = self.engine_intent(store, second)
            self.deny(store.bind_engine_process, second, other, **self.supervisor())
            # PID reuse with another start tick is a distinct kernel identity;
            # it still cannot adopt the old container or mutate either tuple.
            store.bind_engine_process(second, other, **self.supervisor(start_ticks=1234568))
            self.deny(store.bind_engine_container, second, other, "b" * 64)
            store.bind_engine_container(second, other, "c" * 64)
        state = json.loads((self.path / "state.json").read_text())
        original = json.loads(json.dumps(state))
        state["leases"][second]["effects"][other]["engine_process"] = state["leases"][first]["effects"][effect]["engine_process"]
        self.write_corrupted_snapshot(self.path, state, recompute_checksum=True)
        self.deny(self.open)
        state = original
        state["leases"][second]["effects"][other]["engine_container_id"] = "b" * 64
        self.write_corrupted_snapshot(self.path, state, recompute_checksum=True)
        self.deny(self.open)

    @staticmethod
    def fence_metadata(**changes):
        # Synthetic Root kernel readback, not a live nsfs/nft proof.
        return {"policy_sha256": "d" * 64, "boot_id": WORKER["boot_id"], "netns_device": 4,
                "netns_inode": 4026533001, "host_ifindex": 301, "peer_ifindex": 2,
                "nft_table_handle": 1} | changes

    def fence_authorization(self, store, lease, **changes):
        record = store.read(lease)
        auth = record["authorizations"][-1]
        expiry = min(auth["valid_until"], record["expires_at"])
        return {"authorization_sha256": ledger.digest(auth), "allow_expires_at": expiry,
                "issued_boot_ns": 1000000000,
                "expires_boot_ns": 1000000000 + (expiry - self.now) * 1000000000} | changes

    @staticmethod
    def host_api_metadata(**changes):
        return {"policy_sha256": "a" * 64, "baseline_sha256": "b" * 64, "boot_id": WORKER["boot_id"],
                "host_netns_device": 4, "host_netns_inode": 4026531992, "nft_table_handle": 42} | changes

    def host_creator(self, store, lease, **changes):
        targets = self.provision(store, lease, through="engine-prepare")
        created = store.begin(lease, "fence-create", targets["fence-create"])
        store.bind_fence(lease, created, **self.fence_metadata(**changes))
        return created, targets

    def test_host_baseline_binding_is_immutable_and_single_pilot_until_actual_removal(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            created, targets = self.host_creator(store, lease)
            value = self.host_api_metadata()
            store.bind_host_api_fence(lease, created, **value)
            store.bind_host_api_fence(lease, created, **value)
            self.assertEqual(store.host_api_claimants(value["policy_sha256"], value["baseline_sha256"]), (lease,))
            self.deny(store.bind_host_api_fence, lease, created, **(value | {"nft_table_handle": 43}))
            store.record(lease, created, "unknown", evidence_sha256=EVIDENCE)
            self.now += 200
            self.assertEqual(store.host_api_claimants(value["policy_sha256"], value["baseline_sha256"]), (lease,))
            self.now = NOW
            other_worker = ledger.Worker(**(WORKER | {"uid": 2102, "runner_id": 62, "pid": 12346,
                                                     "start_ticks": 987655}))
            second, _, _, _ = self.prepare(store, worker=other_worker, identity_changes={
                "run_id": 502, "job_id": 903, "check_run_id": 732, "runner_id": 62,
                "service_uid": 2102, "token_id_sha256": "c" * 64})
            other, _ = self.host_creator(store, second, netns_inode=4026533002, host_ifindex=302)
            self.deny(store.bind_host_api_fence, second, other, **value)
            self.deny(store.bind_host_api_fence, second, other, **(value | {"policy_sha256": "c" * 64}))
            self.assertNotIn("host_api", store.read(second)["effects"][other])
        with self.open() as store:
            self.assertEqual(store.host_api_claimants(value["policy_sha256"], value["baseline_sha256"]), (lease,))

    def test_host_authorization_binds_current_whole_auth_creator_tuple_and_fixed_expiry(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            created, targets = self.host_creator(store, lease)
            host_value = self.host_api_metadata()
            store.bind_host_api_fence(lease, created, **host_value)
            store.record(lease, created, "verified", evidence_sha256=EVIDENCE)
            published = store.begin(lease, "context-publish", targets["context-publish"])
            store.record(lease, published, "verified", evidence_sha256=EVIDENCE)
            renewal = store.begin(lease, "fence-renew", targets["fence-renew"])
            auth = self.fence_authorization(store, lease)
            value = auth | {"baseline_sha256": host_value["baseline_sha256"], "host_ifindex": 301, "peer_ipv4": "10.250.23.2"}
            self.deny(store.bind_host_api_authorization, lease, renewal, **value)
            store.bind_fence_authorization(lease, renewal, **auth)
            for changes in ({"authorization_sha256": "a" * 64}, {"allow_expires_at": NOW + 121},
                            {"host_ifindex": 302}, {"baseline_sha256": "a" * 64}, {"peer_ipv4": "127.0.0.1"},
                            {"peer_ipv4": "::1"}, {"issued_boot_ns": True}):
                self.deny(store.bind_host_api_authorization, lease, renewal, **(value | changes))
            store.bind_host_api_authorization(lease, renewal, **value)
            store.bind_host_api_authorization(lease, renewal, **value)
            self.deny(store.bind_host_api_authorization, lease, renewal, **(value | {"peer_ipv4": "10.250.23.3"}))
            store.record(lease, renewal, "unknown", evidence_sha256=EVIDENCE)
        with self.open() as store:
            self.assertEqual(store.read(lease)["effects"][renewal]["host_api_authorization"], value)

    def test_host_withdrawal_marker_is_once_durable_even_unknown_and_cancelled(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            created, _ = self.host_creator(store, lease)
            value = self.host_api_metadata()
            store.bind_host_api_fence(lease, created, **value)
            store.record(lease, created, "verified", evidence_sha256=EVIDENCE)
            store.cancel(lease, "cancelled")
            cut = store.begin(lease, "fence-disable", "fence:" + lease)
            self.deny(store.bind_host_api_withdrawal, lease, cut, baseline_sha256="a" * 64)
            store.bind_host_api_withdrawal(lease, cut, baseline_sha256=value["baseline_sha256"])
            self.deny(store.bind_host_api_withdrawal, lease, cut, baseline_sha256=value["baseline_sha256"])
            store.record(lease, cut, "unknown", evidence_sha256=EVIDENCE)
        with self.open() as store:
            self.assertEqual(store.read(lease)["effects"][cut]["host_api_withdrawal"],
                             {"baseline_sha256": value["baseline_sha256"]})
            self.deny(store.bind_host_api_withdrawal, lease, cut, baseline_sha256=value["baseline_sha256"])
            self.deny(store.begin, lease, "fence-disable", "fence:" + lease)

    def test_deny_first_fence_requires_verified_current_auth_allow_before_engine_start(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            targets = self.provision(store, lease, through="fence-create")
            published = store.begin(lease, "context-publish", targets["context-publish"])
            store.record(lease, published, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "engine-start", targets["engine-start"])
            allowed = store.begin(lease, "fence-renew", targets["fence-renew"])
            store.bind_fence_authorization(lease, allowed, **self.fence_authorization(store, lease))
            store.bind_fence_authorization(lease, allowed, **self.fence_authorization(store, lease))
            self.assertEqual(store.read(lease)["effects"][allowed]["state"], "intent")
            self.deny(store.begin, lease, "engine-start", targets["engine-start"])
            store.record(lease, allowed, "verified", evidence_sha256=EVIDENCE)
            effect = store.begin(lease, "engine-start", targets["engine-start"])
            self.assertEqual(store.read(lease)["effects"][effect]["state"], "intent")

    def test_first_owned_disable_can_withdraw_during_unknown_engine_and_never_resolve_or_retry_it(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            targets, engine = self.engine_intent(store, lease)
            store.record(lease, engine, "unknown", evidence_sha256=EVIDENCE)
            self.now = NOW + 121
            store.cancel(lease, "job_ended")
            disabled = store.begin(lease, "fence-disable", targets["fence-create"])
            self.assertEqual(store.read(lease)["effects"][disabled]["state"], "intent")
            self.assertEqual(store.read(lease)["effects"][engine]["state"], "unknown")
            self.deny(store.begin, lease, "fence-disable", targets["fence-create"])
            self.deny(store.begin, lease, "certificate-revoke", targets["certificate-create"])
            self.deny(store.close, lease)
            store.record(lease, disabled, "unknown", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "fence-disable", targets["fence-create"])
            store.reconcile(lease, disabled, "verified", evidence_sha256=EVIDENCE)
            self.assertEqual(store.read(lease)["effects"][engine]["state"], "unknown")
            self.deny(store.begin, lease, "engine-stop", targets["engine-start"])
            # Explicit synthetic Root readback still owes real process/CID proof.
            store.reconcile(lease, engine, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "fence-remove", targets["fence-create"])
            self.cleanup(store, lease, targets)
            store.close(lease)

    def test_unknown_or_foreign_fence_create_never_authorizes_emergency_disable(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            effect = store.begin(lease, "fence-create", "fence:" + lease)
            self.deny(store.begin, lease, "fence-disable", "fence:" + lease)
            store.record(lease, effect, "unknown", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "fence-disable", "fence:" + lease)
            store.reconcile(lease, effect, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "fence-disable", "fence:" + "b" * 32)
            disabled = store.begin(lease, "fence-disable", "fence:" + lease)
            store.record(lease, disabled, "not_applied", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "fence-disable", "fence:" + lease)
            self.deny(store.begin, lease, "fence-renew", "fence:" + lease + ":" +
                      store.read(lease)["authorizations"][-1]["token_id_sha256"])

    def test_fence_renewal_is_latest_jti_once_and_metadata_binds_full_authorization_deadline(self):
        with self.open() as store:
            lease, _, who, _ = self.prepare(store)
            targets = self.provision(store, lease, through="fence-create")
            renewal = store.begin(lease, "fence-renew", targets["fence-renew"])
            self.deny(store.bind_fence_authorization, lease, renewal,
                      **self.fence_authorization(store, lease, authorization_sha256=who.token_id_sha256))
            self.deny(store.bind_fence_authorization, lease, renewal,
                      **self.fence_authorization(store, lease, allow_expires_at=NOW + 121))
            self.deny(store.bind_fence_authorization, lease, renewal,
                      **self.fence_authorization(store, lease, expires_boot_ns=1000000000 + 121000000000))
            value = self.fence_authorization(store, lease)
            store.bind_fence_authorization(lease, renewal, **value)
            self.deny(store.bind_fence_authorization, lease, renewal, **(value | {"issued_boot_ns": 2}))
            store.record(lease, renewal, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "fence-renew", targets["fence-renew"])
            published = store.begin(lease, "context-publish", targets["context-publish"])
            store.record(lease, published, "verified", evidence_sha256=EVIDENCE)
            challenge = store.challenge(self.worker)
            fresh = replace(who, audience=challenge["audience"], token_id_sha256="c" * 64, valid_until=NOW + 600)
            store.refresh_identity(lease, challenge["nonce"], self.worker, fresh)
            self.deny(store.begin, lease, "engine-start", targets["engine-start"])
            self.deny(store.begin, lease, "fence-renew", targets["fence-renew"])
            renewal = store.begin(lease, "fence-renew", "fence:" + lease + ":" + fresh.token_id_sha256)
            self.deny(store.bind_fence_authorization, lease, renewal, **value)
            store.bind_fence_authorization(lease, renewal, **self.fence_authorization(store, lease))
            store.record(lease, renewal, "verified", evidence_sha256=EVIDENCE)
            self.assertEqual(store.read(lease)["expires_at"], NOW + 120)
            started = store.begin(lease, "engine-start", targets["engine-start"])
            self.assertEqual(store.read(lease)["effects"][started]["state"], "intent")
        state = json.loads((self.path / "state.json").read_text())
        state["leases"][lease]["effects"][renewal]["fence_authorization"]["allow_expires_at"] += 1
        self.write_corrupted_snapshot(self.path, state, recompute_checksum=True)
        self.deny(self.open)

    def test_fence_kernel_locator_is_durable_immutable_and_namespace_scoped(self):
        with self.open() as store:
            first, _, _, _ = self.prepare(store)
            effect = store.begin(first, "fence-create", "fence:" + first)
            store.bind_fence(first, effect, **self.fence_metadata())
            store.bind_fence(first, effect, **self.fence_metadata())
            for changes in ({"netns_inode": 4026533002}, {"host_ifindex": 302},
                            {"nft_table_handle": 2}, {"policy_sha256": "e" * 64}):
                self.deny(store.bind_fence, first, effect, **self.fence_metadata(**changes))
            store.record(first, effect, "unknown", evidence_sha256=EVIDENCE)
        with self.open() as store:
            self.assertEqual(store.read(first)["effects"][effect]["fence"], self.fence_metadata())
            second, _, _, _ = self.prepare(store, worker=replace(self.worker, uid=2102, runner_id=62, pid=12346),
                identity_changes={"service_uid": 2102, "runner_id": 62, "run_id": 502,
                                  "job_id": 903, "check_run_id": 732, "token_id_sha256": "c" * 64})
            other = store.begin(second, "fence-create", "fence:" + second)
            self.deny(store.bind_fence, second, other, **self.fence_metadata(host_ifindex=302))
            self.deny(store.bind_fence, second, other, **self.fence_metadata(netns_inode=4026533002))
            # Peer ifindex2 and namespace-local nft handle1 legitimately repeat
            # in a distinct namespace, with another Root-host interface.
            store.bind_fence(second, other, **self.fence_metadata(netns_inode=4026533002, host_ifindex=302))
            self.assertEqual(store.read(second)["effects"][other]["state"], "intent")
        state = json.loads((self.path / "state.json").read_text())
        state["leases"][second]["effects"][other]["fence"] = self.fence_metadata()
        self.write_corrupted_snapshot(self.path, state, recompute_checksum=True)
        self.deny(self.open)

    def test_fence_metadata_rejects_untyped_fields_and_unrelated_effects(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            observation = store.begin(lease, "capture", "cell")
            self.deny(store.bind_fence, lease, observation, **self.fence_metadata())
            store.record(lease, observation, "verified", evidence_sha256=EVIDENCE)
            created = store.begin(lease, "fence-create", "fence:" + lease)
            for changes in ({"netns_device": True}, {"netns_inode": 0}, {"host_ifindex": -1},
                            {"peer_ifindex": False}, {"nft_table_handle": 1.5},
                            {"boot_id": "untrusted-boot"}, {"policy_sha256": "not-a-hash"}):
                self.deny(store.bind_fence, lease, created, **self.fence_metadata(**changes))
            self.deny(store.bind_fence_authorization, lease, created, **self.fence_authorization(store, lease))
            self.assertNotIn("fence", store.read(lease)["effects"][created])

    def test_context_refresh_requires_owned_published_context_and_new_current_authorization(self):
        with self.open() as store:
            lease, _, who, _ = self.prepare(store)
            original = "context:" + CELL + ":" + who.token_id_sha256
            self.deny(store.begin, lease, "context-refresh", original)
            targets = self.provision(store, lease, through="context-publish")
            self.deny(store.begin, lease, "context-refresh", original)
            challenge = store.challenge(self.worker)
            fresh = replace(who, audience=challenge["audience"], token_id_sha256="c" * 64)
            store.refresh_identity(lease, challenge["nonce"], self.worker, fresh)
            self.deny(store.begin, lease, "context-refresh", original)
            self.deny(store.begin, lease, "context-refresh", "context:" + "d" * 64 + ":" + fresh.token_id_sha256)
            target = "context:" + CELL + ":" + fresh.token_id_sha256
            update = store.begin(lease, "context-refresh", target)
            store.record(lease, update, "unknown", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "fence-renew", "fence:" + lease + ":" + fresh.token_id_sha256)
            self.deny(store.begin, lease, "certificate-revoke", targets["certificate-create"])
            self.deny(store.begin, lease, "context-refresh", target)
            store.reconcile(lease, update, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "context-refresh", target)

    def test_context_refresh_retains_fixed_expiry_and_cannot_publish_after_cancel_or_withdrawal(self):
        with self.open() as store:
            lease, _, who, _ = self.prepare(store)
            targets = self.provision(store, lease, through="context-publish")
            challenge = store.challenge(self.worker)
            fresh = replace(who, audience=challenge["audience"], token_id_sha256="c" * 64, valid_until=NOW + 600)
            store.refresh_identity(lease, challenge["nonce"], self.worker, fresh)
            disabled = store.begin(lease, "fence-disable", targets["fence-create"])
            store.record(lease, disabled, "verified", evidence_sha256=EVIDENCE)
            target = "context:" + CELL + ":" + fresh.token_id_sha256
            self.deny(store.begin, lease, "context-refresh", target)
            self.now = NOW + 121
            self.deny(store.begin, lease, "context-refresh", target)
            store.cancel(lease, "cancelled")
            self.deny(store.begin, lease, "context-refresh", target)
            self.assertEqual(store.read(lease)["expires_at"], NOW + 120)

    def test_persisted_context_refresh_cannot_borrow_initial_or_foreign_authorization(self):
        with self.open() as store:
            lease, _, who, _ = self.prepare(store)
            self.provision(store, lease, through="context-publish")
            challenge = store.challenge(self.worker)
            fresh = replace(who, audience=challenge["audience"], token_id_sha256="c" * 64)
            store.refresh_identity(lease, challenge["nonce"], self.worker, fresh)
            effect = store.begin(lease, "context-refresh", "context:" + CELL + ":" + fresh.token_id_sha256)
        original = json.loads((self.path / "state.json").read_text())
        for token in (who.token_id_sha256, "d" * 64):
            state = json.loads(json.dumps(original))
            state["leases"][lease]["effects"][effect]["target"] = "context:" + CELL + ":" + token
            self.write_corrupted_snapshot(self.path, state, recompute_checksum=True)
            self.deny(self.open)

    def test_private_context_is_journaled_before_certificate_post_and_retained_until_revocation(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            for operation, target in (("network-create", "network:default:lit0123456789ab"),
                                      ("project-create", "project:lit-owned-lease"),
                                      ("profile-configure", "profile:lit-owned-lease:default")):
                effect = store.begin(lease, operation, target)
                store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            certificate_target = "certificate:" + "a" * 64
            self.deny(store.begin, lease, "certificate-create", certificate_target)
            context = store.begin(lease, "context-create", "context:" + CELL)
            self.deny(store.begin, lease, "certificate-create", certificate_target)
            store.record(lease, context, "verified", evidence_sha256=EVIDENCE)
            # Root can now persist private key/cert/config before sending DER.
            certificate = store.begin(lease, "certificate-create", certificate_target)
            store.record(lease, certificate, "unknown", evidence_sha256=EVIDENCE)
            store.cancel(lease, "job_ended")
            self.now = NOW + 121
            self.deny(store.begin, lease, "context-delete", "context:" + CELL)
            store.reconcile(lease, certificate, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "context-delete", "context:" + CELL)
            revoked = store.begin(lease, "certificate-revoke", certificate_target)
            store.record(lease, revoked, "verified", evidence_sha256=EVIDENCE)
            for operation, target in (("context-delete", "context:" + CELL),
                                      ("project-delete", "project:lit-owned-lease"),
                                      ("network-delete", "network:default:lit0123456789ab")):
                effect = store.begin(lease, operation, target)
                store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            store.close(lease)

    def test_default_profile_configuration_is_owned_once_and_precedes_context_or_grant(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            self.deny(store.begin, lease, "profile-configure", "profile:lit-owned-lease:default")
            for operation, target in (("network-create", "network:default:lit0123456789ab"),
                                      ("project-create", "project:lit-owned-lease")):
                effect = store.begin(lease, operation, target)
                store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            for target in ("profile:default:default", "profile:foreign:default", "profile:lit-owned-lease:other"):
                self.deny(store.begin, lease, "profile-configure", target)
            self.deny(store.begin, lease, "context-create", "context:" + CELL)
            effect = store.begin(lease, "profile-configure", "profile:lit-owned-lease:default")
            store.record(lease, effect, "unknown", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "context-create", "context:" + CELL)
            self.deny(store.begin, lease, "profile-configure", "profile:lit-owned-lease:default")
            store.reconcile(lease, effect, "verified", evidence_sha256=EVIDENCE)
            context = store.begin(lease, "context-create", "context:" + CELL)
            store.record(lease, context, "verified", evidence_sha256=EVIDENCE)
            store.cancel(lease, "cancelled")
            for operation, target in (("context-delete", "context:" + CELL),
                                      ("project-delete", "project:lit-owned-lease"),
                                      ("network-delete", "network:default:lit0123456789ab")):
                cleanup = store.begin(lease, operation, target)
                store.record(lease, cleanup, "verified", evidence_sha256=EVIDENCE)
            store.close(lease)

    def test_new_effect_targets_are_typed_bounded_and_never_paths_or_foreign_domains(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            for operation, target in (
                ("project-create", "project:default"), ("project-create", "project:foreign:lease"),
                ("network-create", "network:foreign:lit0123456789ab"),
                ("network-create", "network:default:arbitrary"),
                ("context-create", "/run/private/context"), ("context-create", "context:short"),
                ("engine-start", "engine:../../foreign"), ("engine-start", "engine:" + "a" * 129),
                ("kernel-fence-create", "unqualified"), ("execute", "arbitrary"),
            ):
                with self.subTest(operation=operation, target=target):
                    self.deny(store.begin, lease, operation, target)
            self.assertEqual(store.read(lease)["effects"], {})

    def test_partial_project_unknown_blocks_writes_until_root_reconciles_and_never_retries(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            network = store.begin(lease, "network-create", "network:default:lit0123456789ab")
            store.record(lease, network, "verified", evidence_sha256=EVIDENCE)
            project = store.begin(lease, "project-create", "project:lit-owned-lease")
            store.record(lease, project, "unknown", evidence_sha256=EVIDENCE)
            store.cancel(lease, "job_ended")
            self.deny(store.begin, lease, "network-delete", "network:default:lit0123456789ab")
            self.deny(store.begin, lease, "project-create", "project:lit-owned-lease")
            self.deny(store.close, lease)
            store.reconcile(lease, project, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "network-delete", "network:default:lit0123456789ab")
            self.deny(store.begin, lease, "project-delete", "project:foreign")
            cleanup = store.begin(lease, "project-delete", "project:lit-owned-lease")
            store.record(lease, cleanup, "verified", evidence_sha256=EVIDENCE)
            cleanup = store.begin(lease, "network-delete", "network:default:lit0123456789ab")
            store.record(lease, cleanup, "verified", evidence_sha256=EVIDENCE)
            store.close(lease)

    def test_new_cleanup_is_exact_target_and_dependency_ordered(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            targets = self.provision(store, lease)
            instance = store.begin(lease, "instance-create", "owned-vm")
            store.record(lease, instance, "verified", evidence_sha256=EVIDENCE)
            for operation, target in (("context-delete", targets["context-create"]),
                                      ("project-delete", targets["project-create"]),
                                      ("network-delete", targets["network-create"]),
                                      ("instance-destroy", "owned-vm"),
                                      ("engine-stop", "engine:foreign")):
                self.deny(store.begin, lease, operation, target)
            stop = store.begin(lease, "engine-stop", targets["engine-start"])
            store.record(lease, stop, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "project-delete", targets["project-create"])
            destroyed = store.begin(lease, "instance-destroy", "owned-vm")
            store.record(lease, destroyed, "verified", evidence_sha256=EVIDENCE)
            for creator in ("certificate-create", "fence-create", "engine-prepare", "context-create", "project-create", "network-create"):
                effect = store.begin(lease, ledger.CREATES[creator], targets[creator])
                store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "instance-create", "replacement-vm")
            store.close(lease)

    def test_expired_cancelled_lease_can_revoke_before_engine_stop_then_cleanup_all(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            targets = self.provision(store, lease)
            self.now = NOW + 121
            store.cancel(lease, "token_revoked")
            self.deny(store.begin, lease, "test", "cell")
            revoked = store.begin(lease, "certificate-revoke", targets["certificate-create"])
            store.record(lease, revoked, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "context-delete", targets["context-create"])
            for creator in ("engine-start", "fence-create", "engine-prepare", "context-create", "project-create", "network-create"):
                effect = store.begin(lease, ledger.CREATES[creator], targets[creator])
                store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            store.close(lease)
            self.assertEqual(store.read(lease)["state"], "closed")

    def test_cleanup_unknown_survives_restart_and_only_readonly_reconcile_can_finish(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            create = store.begin(lease, "network-create", "network:default:lit0123456789ab")
            store.record(lease, create, "verified", evidence_sha256=EVIDENCE)
            delete = store.begin(lease, "network-delete", "network:default:lit0123456789ab")
        with self.open() as store:
            self.assertEqual(store.read(lease)["effects"][delete]["state"], "intent")
            self.deny(store.close, lease)
            self.deny(store.begin, lease, "network-delete", "network:default:lit0123456789ab")
            store.record(lease, delete, "unknown", evidence_sha256=EVIDENCE)
            self.deny(store.reconcile, lease, delete, "unknown", evidence_sha256=EVIDENCE)
            store.reconcile(lease, delete, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "network-create", "network:default:litbbbbbbbbbbbb")
            store.close(lease)

    def test_new_mutations_never_accept_failed_or_cross_target_persisted_cleanup(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            create = store.begin(lease, "network-create", "network:default:lit0123456789ab")
            self.deny(store.record, lease, create, "failed", evidence_sha256=EVIDENCE)
            store.record(lease, create, "verified", evidence_sha256=EVIDENCE)
            delete = store.begin(lease, "network-delete", "network:default:lit0123456789ab")
            store.record(lease, delete, "verified", evidence_sha256=EVIDENCE)
        state = json.loads((self.path / "state.json").read_text())
        state["leases"][lease]["effects"][delete]["target"] = "network:default:litbbbbbbbbbbbb"
        self.write_corrupted_snapshot(self.path, state, recompute_checksum=True)
        self.deny(self.open)

    def test_known_not_applied_cleanup_is_not_absence_or_automatic_retry_authority(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            created = store.begin(lease, "network-create", "network:default:lit0123456789ab")
            store.record(lease, created, "verified", evidence_sha256=EVIDENCE)
            deletion = store.begin(lease, "network-delete", "network:default:lit0123456789ab")
            store.record(lease, deletion, "unknown", evidence_sha256=EVIDENCE)
            store.reconcile(lease, deletion, "not_applied", evidence_sha256=EVIDENCE)
            self.deny(store.close, lease)
            self.deny(store.begin, lease, "network-delete", "network:default:lit0123456789ab")
            self.deny(store.reconcile, lease, deletion, "verified", evidence_sha256=EVIDENCE)
            self.assertEqual(store.read(lease)["state"], "prepared")

    def test_other_lease_cannot_borrow_verified_resource_ownership(self):
        with self.open() as store:
            first, _, _, _ = self.prepare(store)
            created = store.begin(first, "network-create", "network:default:lit0123456789ab")
            store.record(first, created, "verified", evidence_sha256=EVIDENCE)
            other_worker = replace(self.worker, uid=2102, runner_id=62, pid=12346)
            second, _, _, _ = self.prepare(store, worker=other_worker, identity_changes={
                "service_uid": 2102, "runner_id": 62, "run_id": 502, "job_id": 903,
                "check_run_id": 732, "token_id_sha256": "c" * 64})
            self.deny(store.begin, second, "network-delete", "network:default:lit0123456789ab")
            self.assertEqual(store.read(second)["effects"], {})
            self.assertEqual(len(store.read(first)["effects"]), 1)

    def test_recover_expired_prepared_lease_cannot_extend_or_replace_it(self):
        with self.open() as store:
            lease, _, original, custody = self.prepare(store, identity_changes={"policy_sha256": "d" * 64})
            self.now = NOW + 121
            challenge = store.challenge(self.worker)
            fresh = replace(original, audience=challenge["audience"], valid_until=NOW + 600,
                            token_id_sha256="c" * 64)
            before = (self.path / "state.json").read_bytes()
            self.deny(store.recover, challenge["nonce"], self.worker, fresh,
                      policy_sha256=custody, cell_sha256=CELL, deadline=NOW + 120)
            self.deny(store.recover, challenge["nonce"], self.worker, fresh,
                      policy_sha256=custody, cell_sha256=CELL, deadline=NOW + 240)
            self.assertEqual((self.path / "state.json").read_bytes(), before)
            self.assertEqual(store.read(lease)["state"], "prepared")
            self.assertEqual(store.read(lease)["expires_at"], NOW + 120)


    def scoped_certificate(self, store, lease):
        targets = self.provision(store, lease, through="context-create")
        effect = store.begin(lease, "certificate-create", targets["certificate-create"])
        scope = {"initial_fingerprint": "a" * 64, "certificate_name": "lit-lease-" + lease,
                 "project": "lit-owned-lease", "baseline_inventory_sha256": "b" * 64,
                 "authorizer_profile": ledger.CERTIFICATE_AUTHORIZER_PROFILE}
        store.bind_certificate_scope(lease, effect, **scope)
        return effect, scope

    def test_certificate_scope_and_actual_rotated_revoke_binding_survive_restart_after_expiry(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            create, scope = self.scoped_certificate(store, lease)
            store.bind_certificate_scope(lease, create, **scope)
            store.record(lease, create, "verified", evidence_sha256=EVIDENCE)
            before = store.read(lease)
            self.now = NOW + 121
            store.cancel(lease, "job_ended")
            revoke = store.begin(lease, "certificate-revoke", "certificate:" + "a" * 64)
            values = {"current_fingerprint": "c" * 64,
                      "scope_sha256": ledger.digest(before["effects"][create]["certificate_scope"]),
                      "inventory_sha256": "d" * 64}
            store.bind_certificate_revocation(lease, revoke, **values)
            store.bind_certificate_revocation(lease, revoke, **values)
            store.record(lease, revoke, "unknown", evidence_sha256=EVIDENCE)
        with self.open() as store:
            retained = store.read(lease)
            self.assertEqual(retained["effects"][revoke]["certificate_revocation"], values)
            self.assertEqual(retained["effects"][revoke]["target"], "certificate:" + "a" * 64)
            self.assertEqual(retained["effects"][revoke]["state"], "unknown")
            self.assertEqual(retained["authorizations"], before["authorizations"])
            self.assertEqual(retained["expires_at"], before["expires_at"])
            self.deny(store.begin, lease, "certificate-revoke", "certificate:" + "a" * 64)
            self.deny(store.bind_certificate_revocation, lease, revoke, **(values | {"current_fingerprint": "e" * 64}))
            self.deny(store.close, lease)

    def test_certificate_scope_requires_original_intent_exact_name_project_and_pinned_protocol(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            create, scope = self.scoped_certificate(store, lease)
            for changes in ({"initial_fingerprint": True}, {"initial_fingerprint": "c" * 64},
                            {"certificate_name": "foreign"}, {"project": "foreign"},
                            {"baseline_inventory_sha256": "invalid"}, {"authorizer_profile": "approved"}):
                self.deny(store.bind_certificate_scope, lease, create, **(scope | changes))
            store.record(lease, create, "verified", evidence_sha256=EVIDENCE)
            self.deny(store.bind_certificate_scope, lease, create, **scope)
            revoke = store.begin(lease, "certificate-revoke", "certificate:" + "a" * 64)
            self.deny(store.bind_certificate_scope, lease, revoke, **scope)
            for values in ({"current_fingerprint": "c" * 64, "scope_sha256": "e" * 64, "inventory_sha256": "d" * 64},
                           {"current_fingerprint": True, "scope_sha256": "e" * 64, "inventory_sha256": "d" * 64}):
                self.deny(store.bind_certificate_revocation, lease, revoke, **values)

    def test_certificate_scope_is_not_backfilled_after_unknown_send_or_without_project_creator(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            effect = store.begin(lease, "certificate-create", "certificate:" + "a" * 64)
            values = {"initial_fingerprint": "a" * 64, "certificate_name": "lit-lease-" + lease,
                      "project": "foreign", "baseline_inventory_sha256": "b" * 64,
                      "authorizer_profile": ledger.CERTIFICATE_AUTHORIZER_PROFILE}
            self.deny(store.bind_certificate_scope, lease, effect, **values)
            store.record(lease, effect, "unknown", evidence_sha256=EVIDENCE)
            self.deny(store.bind_certificate_scope, lease, effect, **values)

    def test_certificate_scope_snapshot_tampering_fails_even_with_valid_outer_checksum(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            create, _ = self.scoped_certificate(store, lease)
        state = json.loads((self.path / "state.json").read_text())
        state["leases"][lease]["effects"][create]["certificate_scope"]["projects"] = ["foreign"]
        self.write_corrupted_snapshot(self.path, state, recompute_checksum=True)
        self.deny(self.open)

    def runtime_identity(self, store, operation, token="c" * 64, **changes):
        challenge = store.runtime_challenge(self.worker, operation, CELL, "d" * 64)
        who = synthetic_identity(challenge["audience"], policy_sha256="d" * 64,
                                 token_id_sha256=token, **changes)
        return challenge, who

    def runtime_lease(self, store):
        policy = store.archive_policy(dict(POLICY))
        challenge, who = self.runtime_identity(store, "run", token="a" * 64)
        lease = store.runtime_prepare(challenge["nonce"], self.worker, who, policy_sha256=policy,
                    cell_sha256=CELL, deadline=NOW + 120, identity_policy_sha256="d" * 64)
        return lease, policy

    def runtime_proof(self, store, lease, policy, operation="status", token="c" * 64, **changes):
        challenge, who = self.runtime_identity(store, operation, token=token)
        values = {"cell_sha256": CELL, "identity_policy_sha256": "d" * 64, "policy_sha256": policy,
                  "deadline": NOW + 120, "lease_id": None if operation == "recover" else lease} | changes
        return store.consume_runtime_proof(challenge["nonce"], self.worker, who, operation, **values)

    def test_runtime_challenge_domains_and_atomic_run_preparation(self):
        with self.open() as store:
            policy = store.archive_policy(dict(POLICY))
            challenge, who = self.runtime_identity(store, "run", token="a" * 64)
            self.assertEqual(challenge, store.runtime_challenge(self.worker, "run", CELL, "d" * 64))
            ordinary = store.challenge(self.worker)
            heartbeat = store.runtime_challenge(self.worker, "heartbeat", CELL, "d" * 64)
            foreign_cell = store.runtime_challenge(self.worker, "run", "f" * 64, "d" * 64)
            self.assertEqual(len({item["nonce"] for item in (challenge, ordinary, heartbeat, foreign_cell)}), 4)
            self.deny(store.prepare, challenge["nonce"], self.worker, who, policy_sha256=policy,
                      cell_sha256=CELL, deadline=NOW + 120)
            self.deny(store.runtime_prepare, ordinary["nonce"], self.worker,
                      replace(who, audience=ordinary["audience"]), policy_sha256=policy,
                      cell_sha256=CELL, deadline=NOW + 120, identity_policy_sha256="d" * 64)
            lease = store.runtime_prepare(challenge["nonce"], self.worker, who, policy_sha256=policy,
                      cell_sha256=CELL, deadline=NOW + 120, identity_policy_sha256="d" * 64)
            self.deny(store.runtime_prepare, challenge["nonce"], self.worker, who, policy_sha256=policy,
                      cell_sha256=CELL, deadline=NOW + 120, identity_policy_sha256="d" * 64)
            self.assertEqual(store.read(lease)["identity"], asdict(who))

    def test_runtime_and_legacy_admission_cannot_create_competing_leases(self):
        other = replace(self.worker, uid=2102, runner_id=62, pid=12346)
        with self.open() as store:
            legacy, _, _, policy = self.prepare(store)
            challenge = store.runtime_challenge(other, "run", CELL, "d" * 64)
            who = synthetic_identity(challenge["audience"], policy_sha256="d" * 64,
                service_uid=2102, runner_id=62, run_id=502, job_id=903,
                check_run_id=732, token_id_sha256="c" * 64)
            args = dict(policy_sha256=policy, cell_sha256=CELL, deadline=NOW + 120,
                        identity_policy_sha256="d" * 64)
            with self.assertRaisesRegex(Denied, "engine-other-pilot-lease-active"):
                store.runtime_prepare(challenge["nonce"], other, who, **args)
            self.assertEqual(store.read(legacy)["effects"], {})
            store.close(legacy)
            active = store.runtime_prepare(challenge["nonce"], other, who, **args)
            with self.assertRaisesRegex(Denied, "engine-other-pilot-lease-active"):
                self.prepare(store, identity_changes={"run_id": 503, "token_id_sha256": "e" * 64})
            self.assertEqual(store.read(active)["effects"], {})

    def test_runtime_status_cancel_recover_consume_once_without_renewal_and_survive_restart(self):
        with self.open() as store:
            lease, policy = self.runtime_lease(store)
            before = store.read(lease)
            for index, operation in enumerate(("status", "cancel", "recover")):
                proof = self.runtime_proof(store, lease, policy, operation, token=str(index + 3) * 64)
                self.assertIs(type(proof), ledger.RuntimeProof)
                self.assertEqual(proof.lease_id, lease)
                self.assertEqual(proof.operation, operation)
                self.assertEqual(proof.worker_sha256, ledger.digest(asdict(self.worker)))
                self.assertEqual(store.read(lease), before)
                with self.assertRaises(AttributeError):
                    proof.lease_id = "f" * 32
        with self.open() as store:
            self.assertEqual(store.read(lease), before)
            # Even a newly issued challenge cannot reuse a consumed native JTI.
            self.deny(self.runtime_proof, store, lease, policy, token="3" * 64)

    def test_runtime_heartbeat_alone_appends_authorization_without_extending_deadline(self):
        with self.open() as store:
            lease, _ = self.runtime_lease(store)
            challenge, who = self.runtime_identity(store, "heartbeat", valid_until=NOW + 600)
            before = store.read(lease)
            self.deny(store.refresh_identity, lease, challenge["nonce"], self.worker, who)
            self.deny(store.runtime_refresh_identity, lease, challenge["nonce"], self.worker, who,
                      cell_sha256="e" * 63 + "f", identity_policy_sha256="d" * 64)
            store.runtime_refresh_identity(lease, challenge["nonce"], self.worker, who,
                                          cell_sha256=CELL, identity_policy_sha256="d" * 64)
            after = store.read(lease)
            self.assertEqual(after["expires_at"], before["expires_at"])
            self.assertEqual(after["effects"], before["effects"])
            self.assertEqual(len(after["authorizations"]), 2)
            self.assertEqual(after["authorizations"][-1]["token_id_sha256"], who.token_id_sha256)
            self.deny(store.runtime_refresh_identity, lease, challenge["nonce"], self.worker, who,
                      cell_sha256=CELL, identity_policy_sha256="d" * 64)

    def test_runtime_proof_rejects_borrowed_scope_locator_worker_and_native_identity(self):
        with self.open() as store:
            lease, policy = self.runtime_lease(store)
            challenge, who = self.runtime_identity(store, "status")
            args = {"cell_sha256": CELL, "identity_policy_sha256": "d" * 64,
                    "policy_sha256": policy, "deadline": NOW + 120, "lease_id": lease}
            before = (self.path / "state.json").read_bytes()
            for change in ({"cell_sha256": "b" * 64}, {"identity_policy_sha256": "b" * 64},
                           {"policy_sha256": "b" * 64}, {"deadline": NOW + 121},
                           {"lease_id": "b" * 32}, {"lease_id": None}):
                self.deny(store.consume_runtime_proof, challenge["nonce"], self.worker, who, "status", **(args | change))
            for identity_change in ({"job_id": 999}, {"check_run_id": 999}, {"caller_sha": "c" * 40},
                                    {"reusable_sha": "c" * 40}, {"policy_sha256": None}, {"valid_until": NOW}):
                self.deny(store.consume_runtime_proof, challenge["nonce"], self.worker,
                          replace(who, **identity_change), "status", **args)
            self.deny(store.consume_runtime_proof, challenge["nonce"], replace(self.worker, start_ticks=999),
                      who, "status", **args)
            for operation in ("cancel", "recover", "run", "heartbeat"):
                self.deny(store.consume_runtime_proof, challenge["nonce"], self.worker, who, operation, **args)
            self.assertEqual((self.path / "state.json").read_bytes(), before)
            store.consume_runtime_proof(challenge["nonce"], self.worker, who, "status", **args)
            self.deny(store.consume_runtime_proof, challenge["nonce"], self.worker, who, "status", **args)

    def test_runtime_read_proof_after_expiry_cancel_close_does_not_reactivate_lease(self):
        with self.open() as store:
            lease, policy = self.runtime_lease(store)
            self.now = NOW + 121
            store.cancel(lease, "job_ended")
            store.close(lease)
            before = store.read(lease)
            proof = self.runtime_proof(store, lease, policy, "recover")
            self.assertEqual(proof.lease_id, lease)
            self.assertEqual(store.read(lease), before)
            self.deny(store.begin, lease, "test", "cell")
            challenge, who = self.runtime_identity(store, "heartbeat", token="e" * 64)
            self.deny(store.runtime_refresh_identity, lease, challenge["nonce"], self.worker, who,
                      cell_sha256=CELL, identity_policy_sha256="d" * 64)

    def test_runtime_proof_snapshot_crossbinding_is_detected_with_recomputed_checksum(self):
        with self.open() as store:
            lease, policy = self.runtime_lease(store)
            self.runtime_proof(store, lease, policy)
        state = json.loads((self.path / "state.json").read_text())
        consumed = next(item for item in state["challenges"].values() if "runtime_identity" in item)
        consumed["runtime"]["cell_sha256"] = "b" * 64
        self.write_corrupted_snapshot(self.path, state, recompute_checksum=True)
        self.deny(self.open)

    def test_known_owned_stop_withdraws_once_despite_unknown_fence_cut(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            targets, effect = self.captured_engine(store, lease)
            store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            disable = store.begin(lease, "fence-disable", "fence:" + lease)
            store.record(lease, disable, "unknown", evidence_sha256=EVIDENCE)
            self.now = NOW + 121
            store.cancel(lease, "job_ended")
            self.deny(store.begin, lease, "engine-stop", "engine:lit-lease-" + "a" * 32)
            stop = store.begin(lease, "engine-stop", targets["engine-start"])
            store.record(lease, stop, "unknown", evidence_sha256=EVIDENCE)
            self.deny(store.begin, lease, "engine-stop", targets["engine-start"])
            self.deny(store.begin, lease, "certificate-revoke", targets["certificate-create"])
            self.deny(store.begin, lease, "test", "cell")
            self.deny(store.close, lease)
            self.assertEqual(store.read(lease)["effects"][disable]["state"], "unknown")

    def test_unknown_or_untracked_start_cannot_bypass_unknown_effect_for_stop(self):
        for missing in ("process", "container", "verified"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "ledger"
                path.mkdir(mode=0o700)
                ledger.Ledger.initialize(path, owner_uid=os.getuid(), clock=lambda: NOW)
                with self.open(path) as store:
                    lease, _, _, _ = self.prepare(store)
                    targets, start = self.engine_intent(store, lease)
                    if missing != "process":
                        store.bind_engine_process(lease, start, **self.supervisor())
                    if missing not in {"process", "container"}:
                        store.bind_engine_container(lease, start, "b" * 64)
                    store.record(lease, start, "unknown" if missing == "verified" else "verified",
                                 evidence_sha256=EVIDENCE)
                    disable = store.begin(lease, "fence-disable", "fence:" + lease)
                    store.record(lease, disable, "unknown", evidence_sha256=EVIDENCE)
                    self.deny(store.begin, lease, "engine-stop", targets["engine-start"])

    @staticmethod
    def capture_observation(**changes):
        # Synthetic Root FD observations, not proof of native cgroup/log files.
        return {"manifest_sha256": "d" * 64, "cgroup_device": 11, "cgroup_inode": 100,
                "stdout_device": 22, "stdout_inode": 101, "stderr_device": 22, "stderr_inode": 102,
                "stdout_limit": 1024, "stderr_limit": 512, "total_limit": 700} | changes

    def exit_observation(self, **changes):
        process = self.supervisor()
        return {"pid": process["pid"], "start_ticks": process["start_ticks"], "boot_id": process["boot_id"],
                "container_id": "b" * 64, "manifest_sha256": "d" * 64, "exit_code": 0, "signal": None,
                "observed_at": self.now, "stdout_bytes": 3, "stdout_sha256": hashlib.sha256(b"out").hexdigest(),
                "stdout_state": "complete", "stderr_bytes": 3, "stderr_sha256": hashlib.sha256(b"err").hexdigest(),
                "stderr_state": "complete"} | changes

    def captured_engine(self, store, lease):
        targets, effect = self.engine_intent(store, lease)
        store.bind_engine_capture(lease, effect, **self.capture_observation())
        store.bind_engine_process(lease, effect, **self.supervisor())
        store.bind_engine_container(lease, effect, "b" * 64)
        return targets, effect

    def test_engine_capture_and_exit_restart_preserve_receipt_without_new_effect_or_pass(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            _, effect = self.captured_engine(store, lease)
            store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            before = store.read(lease)
            store.record_engine_exit(lease, effect, **self.exit_observation())
            store.record_engine_exit(lease, effect, **self.exit_observation())
            store.bind_engine_capture(lease, effect, **self.capture_observation())
            expected = store.read(lease)
            self.assertEqual(set(before["effects"]), set(expected["effects"]))
            self.assertEqual(expected["effects"][effect]["state"], "verified")
            self.assertEqual(expected["state"], "prepared")
            # Capturing exit does not introduce an unresolved long-lived effect.
            capture = store.begin(lease, "capture", "cell")
            store.record(lease, capture, "verified", evidence_sha256=EVIDENCE)
            expected = store.read(lease)
        with self.open() as store:
            self.assertEqual(store.read(lease), expected)
            self.assertEqual(expected["effects"][effect]["engine_exit"]["exit_code"], 0)

    def test_exit_after_expiry_and_cancel_is_observation_only_and_closed_receipt_is_immutable(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            targets, effect = self.captured_engine(store, lease)
            store.record(lease, effect, "verified", evidence_sha256=EVIDENCE)
            self.now = NOW + 121
            store.cancel(lease, "job_ended")
            value = self.exit_observation(exit_code=None, signal=15, stdout_state="limited", stderr_state="incomplete")
            store.record_engine_exit(lease, effect, **value)
            self.deny(store.begin, lease, "test", "cell")
            self.cleanup(store, lease, targets)
            store.close(lease)
            self.assertEqual(store.read(lease)["effects"][effect]["engine_exit"], value)
            self.deny(store.record_engine_exit, lease, effect, **value)

    def test_exit_on_unknown_start_never_reconciles_or_authorizes_retry(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            targets, effect = self.captured_engine(store, lease)
            store.record(lease, effect, "unknown", evidence_sha256=EVIDENCE)
            store.record_engine_exit(lease, effect, **self.exit_observation(exit_code=137))
            self.assertEqual(store.read(lease)["effects"][effect]["state"], "unknown")
            self.deny(store.begin, lease, "engine-start", targets["engine-start"])
            self.deny(store.begin, lease, "engine-stop", targets["engine-start"])
            self.deny(store.close, lease)

    def test_capture_requires_pre_spawn_intent_and_closed_typed_limits(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            _, effect = self.engine_intent(store, lease)
            for changes in ({"cgroup_inode": True}, {"stdout_device": -1}, {"stderr_inode": 101},
                            {"stdout_limit": 0}, {"stderr_limit": 64 * 1024 * 1024 + 1},
                            {"total_limit": 0}, {"total_limit": 1537}, {"manifest_sha256": "invalid"}):
                with self.subTest(changes=changes):
                    self.deny(store.bind_engine_capture, lease, effect, **self.capture_observation(**changes))
            maximum = 64 * 1024 * 1024
            value = self.capture_observation(stdout_limit=maximum, stderr_limit=maximum, total_limit=1)
            store.bind_engine_capture(lease, effect, **value)
            self.deny(store.bind_engine_capture, lease, effect, **self.capture_observation())
            store.bind_engine_process(lease, effect, **self.supervisor())
            store.bind_engine_capture(lease, effect, **value)
            with self.assertRaises(TypeError):
                store.bind_engine_capture(lease, effect, **value, stdout_path="/job-controlled")

    def test_capture_cannot_be_added_after_process_or_to_non_engine_effect(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            other = store.begin(lease, "capture", "cell")
            self.deny(store.bind_engine_capture, lease, other, **self.capture_observation())
            self.deny(store.record_engine_exit, lease, other, **self.exit_observation())
            store.record(lease, other, "verified", evidence_sha256=EVIDENCE)
            _, effect = self.engine_intent(store, lease)
            self.deny(store.record_engine_exit, lease, effect, **self.exit_observation())
            store.bind_engine_process(lease, effect, **self.supervisor())
            self.deny(store.bind_engine_capture, lease, effect, **self.capture_observation())
            store.bind_engine_container(lease, effect, "b" * 64)
            self.deny(store.record_engine_exit, lease, effect, **self.exit_observation())

    def test_exit_binds_status_process_container_manifest_stream_caps_and_immutable_receipt(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            _, effect = self.captured_engine(store, lease)
            for changes in ({"pid": 32102}, {"start_ticks": True}, {"boot_id": "other"},
                            {"container_id": "c" * 64}, {"manifest_sha256": "c" * 64},
                            {"exit_code": 0, "signal": 9}, {"exit_code": None}, {"exit_code": True},
                            {"exit_code": 256}, {"exit_code": None, "signal": 65}, {"observed_at": NOW - 1},
                            {"stdout_bytes": 1025}, {"stdout_bytes": 699}, {"stderr_bytes": True},
                            {"stdout_bytes": 0}, {"stdout_sha256": "invalid"}, {"stderr_state": "success"}):
                with self.subTest(changes=changes):
                    self.deny(store.record_engine_exit, lease, effect, **self.exit_observation(**changes))
            value = self.exit_observation(stdout_bytes=0, stdout_sha256=hashlib.sha256(b"").hexdigest())
            store.record_engine_exit(lease, effect, **value)
            self.deny(store.record_engine_exit, lease, effect, **(value | {"exit_code": 1}))
            self.deny(store.record_engine_exit, lease, effect, **(value | {"stderr_sha256": "e" * 64}))
            self.deny(store.record_engine_exit, lease, effect, **(value | {"observed_at": NOW + 1}))

    def test_capture_ownership_cannot_be_borrowed_across_retained_leases(self):
        with self.open() as store:
            first, _, _, _ = self.prepare(store)
            targets, effect = self.captured_engine(store, first)
            store.record(first, effect, "verified", evidence_sha256=EVIDENCE)
            self.cleanup(store, first, targets)
            store.close(first)
            second, _, _, _ = self.prepare(store, identity_changes={"run_id": 502, "job_id": 903,
                "check_run_id": 732, "token_id_sha256": "c" * 64})
            _, other = self.engine_intent(store, second)
            self.deny(store.bind_engine_capture, second, other, **self.capture_observation())
            self.deny(store.bind_engine_capture, second, other,
                      **self.capture_observation(cgroup_inode=200, stderr_inode=202))
            store.bind_engine_capture(second, other,
                **self.capture_observation(cgroup_inode=200, stdout_inode=201, stderr_inode=202))

    def test_valid_checksum_cannot_hide_exit_binding_corruption(self):
        with self.open() as store:
            lease, _, _, _ = self.prepare(store)
            _, effect = self.captured_engine(store, lease)
            store.record_engine_exit(lease, effect, **self.exit_observation())
        state = json.loads((self.path / "state.json").read_text())
        state["leases"][lease]["effects"][effect]["engine_exit"]["container_id"] = "c" * 64
        self.write_corrupted_snapshot(self.path, state, recompute_checksum=True)
        self.deny(self.open)


if __name__ == "__main__":
    unittest.main()
