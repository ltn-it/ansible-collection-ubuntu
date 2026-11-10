"""Real isolated Root filesystem publication tests; synthetic signing keys only.

No broker, native assignment, network grant, TLS issuer or VM PASS is implied.
"""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_github_runner_incus_signed_context as fixtures  # noqa: E402
from incus_lease_issuer import context_publisher as publisher, signed_context  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux UID0 EE only")
class RootContextPublisherTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RootSignedContextTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.staging = self.fixture.root / "publisher-staging"
        self.staging.mkdir(mode=0o700)
        self.publisher = publisher.RootContextPublisher(self.fixture.signer, self.fixture.pub,
                                                        str(self.fixture.directory), str(self.staging))

    def raw(self):
        return (self.fixture.directory / "binding.json").read_bytes()

    def digest(self):
        return hashlib.sha256(self.raw()).hexdigest()

    def publish(self, old=None):
        f = self.fixture
        return self.publisher.publish(f.store, f.lease, f.worker, f.policy,
                                      expected_old_binding_sha256=self.digest() if old is None else old)

    def verify_live(self):
        body = json.loads(self.raw())
        return self.fixture.verify(body["admission"])

    def refresh(self):
        f = self.fixture
        challenge = f.store.challenge(f.worker)
        renewed = replace(f.who, valid_until=fixtures.NOW + 110, audience=challenge["audience"],
                          token_id_sha256=hashlib.sha256(b"synthetic-publisher-refresh").hexdigest())
        f.store.refresh_identity(f.lease, challenge["nonce"], f.worker, renewed)

    def tls_snapshot(self):
        return {name: ((self.fixture.directory / name).read_bytes(),
                       (self.fixture.directory / name).stat().st_ino)
                for name in signed_context.FILES}

    def test_initial_publish_changes_binding_only_and_returns_digest_only(self):
        before = self.tls_snapshot()
        inode = self.fixture.directory.stat().st_ino
        old = self.digest()
        result = self.publish()
        self.assertEqual(result, {"binding_sha256": self.digest()})
        self.assertNotEqual(result["binding_sha256"], old)
        self.assertEqual(self.tls_snapshot(), before)
        self.assertEqual(self.fixture.directory.stat().st_ino, inode)
        self.assertEqual(list(self.staging.iterdir()), [])
        self.assertEqual((self.fixture.directory / "binding.json").stat().st_mode & 0o777, 0o600)
        self.verify_live()

    def test_repeated_inventory_on_same_directory_fd_rewinds_cursor(self):
        fd = publisher.installation._open_directory(str(self.fixture.directory))
        try:
            first = self.publisher._snapshot(fd)
            self.assertEqual(self.publisher._snapshot(fd), first)
            self.assertEqual(self.publisher._snapshot(fd), first)
        finally:
            os.close(fd)

    def test_refresh_keeps_old_admission_present_until_atomic_replace(self):
        self.publish()
        old_raw, tls = self.raw(), self.tls_snapshot()
        old_body = json.loads(old_raw)
        inode = self.fixture.directory.stat().st_ino
        self.refresh()
        with self.assertRaises(Denied):
            self.verify_live()
        real_replace = publisher.os.replace
        observations = []

        def inspect_then_replace(source, target, **kwargs):
            observations.append((source, target))
            self.assertEqual(self.raw(), old_raw)
            self.assertEqual(set(p.name for p in self.fixture.directory.iterdir()),
                             {"binding.json", "config.yml", "client.crt", "client.key", "servercerts"})
            return real_replace(source, target, **kwargs)

        with mock.patch.object(publisher.os, "replace", side_effect=inspect_then_replace):
            result = self.publish()
        self.assertEqual(observations, [("binding.json", "binding.json")])
        self.assertEqual(self.fixture.directory.stat().st_ino, inode)
        self.assertEqual(self.tls_snapshot(), tls)
        new_body = json.loads(self.raw())
        self.assertNotEqual(new_body["admission"], old_body["admission"])
        self.assertEqual({k: v for k, v in new_body.items() if k != "admission"},
                         {k: v for k, v in old_body.items() if k != "admission"})
        self.assertEqual(result, {"binding_sha256": self.digest()})
        self.verify_live()

    def test_wrong_old_digest_denies_without_staging_or_live_change(self):
        before = self.raw()
        with self.assertRaises(publisher.PublicationDenied):
            self.publish("0" * 64)
        self.assertEqual(self.raw(), before)
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_same_bytes_binding_inode_replaced_during_signing_denies_cas(self):
        before = self.raw()
        issue = self.fixture.signer.issue

        def mutate(*args):
            token = issue(*args)
            temp = self.fixture.root / "replacement-binding"
            self.fixture.write(temp, before)
            os.replace(temp, self.fixture.directory / "binding.json")
            return token

        with mock.patch.object(self.fixture.signer, "issue", side_effect=mutate):
            with self.assertRaises(publisher.PublicationDenied):
                self.publish()
        self.assertEqual(self.raw(), before)
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_live_tls_file_drift_during_signing_denies_before_replace(self):
        before = self.raw()
        issue = self.fixture.signer.issue

        def mutate(*args):
            token = issue(*args)
            self.fixture.write(self.fixture.directory / "client.crt", b"synthetic-drift")
            return token

        with mock.patch.object(self.fixture.signer, "issue", side_effect=mutate):
            with self.assertRaises(publisher.PublicationDenied):
                self.publish()
        self.assertEqual(self.raw(), before)
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_signing_failure_before_replace_preserves_live_admission(self):
        self.publish()
        self.refresh()
        before = self.raw()
        with mock.patch.object(self.fixture.signer, "issue", side_effect=RuntimeError("synthetic-secret")):
            with self.assertRaises(publisher.PublicationDenied) as caught:
                self.publish()
        self.assertEqual(str(caught.exception), "publication-denied")
        self.assertEqual(self.raw(), before)
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_replace_failure_is_unknown_without_rollback_or_blind_retry(self):
        before = self.raw()
        with mock.patch.object(publisher.os, "replace", side_effect=OSError("synthetic-secret")) as replace_mock:
            with self.assertRaises(publisher.PublicationUnknown) as caught:
                self.publish()
        self.assertEqual(str(caught.exception), "publication-unknown")
        self.assertEqual(replace_mock.call_count, 1)
        self.assertEqual(self.raw(), before)

    def test_lost_rename_ack_is_unknown_new_live_binding_not_rolled_back(self):
        before = self.raw()
        actual = publisher.os.replace

        def rename_then_fail(*args, **kwargs):
            actual(*args, **kwargs)
            raise OSError("synthetic-secret-after-rename")

        with mock.patch.object(publisher.os, "replace", side_effect=rename_then_fail) as replace_mock:
            with self.assertRaises(publisher.PublicationUnknown) as caught:
                self.publish()
        self.assertEqual(str(caught.exception), "publication-unknown")
        self.assertEqual(replace_mock.call_count, 1)
        self.assertNotEqual(self.raw(), before)
        self.verify_live()

    def test_original_view_verifier_failure_is_unknown(self):
        before = self.raw()
        actual = signed_context.verify

        def fail_original(*args):
            if args[-1] == str(self.fixture.directory):
                raise Denied("synthetic-secret-verifier-error")
            return actual(*args)

        with mock.patch.object(signed_context, "verify", side_effect=fail_original):
            with self.assertRaises(publisher.PublicationUnknown) as caught:
                self.publish()
        self.assertEqual(str(caught.exception), "publication-unknown")
        self.assertNotEqual(self.raw(), before)
        self.verify_live()

    def test_foreign_stage_entry_never_deleted_and_cleanup_uncertainty_is_unknown(self):
        issue = self.fixture.signer.issue
        foreign = []

        def inject(*args):
            token = issue(*args)
            path = Path(args[-1]) / "foreign-file"
            self.fixture.write(path, b"synthetic-foreign")
            foreign.append(path)
            return token

        with mock.patch.object(self.fixture.signer, "issue", side_effect=inject):
            with self.assertRaises(publisher.PublicationUnknown):
                self.publish()
        self.assertEqual(foreign[0].read_bytes(), b"synthetic-foreign")

    def test_foreign_staging_parent_entries_preserved(self):
        foreign = self.staging / "foreign"
        self.fixture.write(foreign, b"synthetic-foreign")
        self.publish()
        self.assertEqual(foreign.read_bytes(), b"synthetic-foreign")
        self.assertEqual(list(self.staging.iterdir()), [foreign])

    def test_changed_context_directory_identity_denied(self):
        path = self.fixture.directory
        old_hash = self.digest()
        old = self.fixture.root / "old-context"
        os.rename(path, old)
        path.mkdir(mode=0o700)
        with self.assertRaises(publisher.PublicationDenied):
            self.publish(old_hash)
        self.assertFalse((path / "binding.json").exists())

    def test_fsync_failure_after_replace_is_unknown_without_rollback(self):
        before = self.raw()
        replace_real, fsync_real = publisher.os.replace, publisher.os.fsync
        renamed = [False]

        def replace_and_mark(*args, **kwargs):
            replace_real(*args, **kwargs)
            renamed[0] = True

        def fail_first_postrename(fd):
            if renamed[0]:
                renamed[0] = False
                raise OSError("synthetic-secret-fsync-error")
            return fsync_real(fd)

        with mock.patch.object(publisher.os, "replace", side_effect=replace_and_mark), \
                mock.patch.object(publisher.os, "fsync", side_effect=fail_first_postrename):
            with self.assertRaises(publisher.PublicationUnknown) as caught:
                self.publish()
        self.assertEqual(str(caught.exception), "publication-unknown")
        self.assertNotEqual(self.raw(), before)
        self.verify_live()

    def test_expired_authorization_does_not_publish_or_extend_deadline(self):
        before = self.raw()
        self.fixture.clock = fixtures.NOW + 90
        with self.assertRaises(publisher.PublicationDenied):
            self.publish()
        self.assertEqual(self.raw(), before)
        self.assertEqual(self.fixture.store.read(self.fixture.lease)["expires_at"], fixtures.NOW + 120)
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_insecure_mode_symlink_and_context_nested_stage_denied(self):
        f = self.fixture
        self.staging.chmod(0o755)
        with self.assertRaises(publisher.PublicationDenied):
            publisher.RootContextPublisher(f.signer, f.pub, str(f.directory), str(self.staging))
        self.staging.chmod(0o700)
        link = f.root / "stage-link"
        link.symlink_to(self.staging)
        with self.assertRaises(publisher.PublicationDenied):
            publisher.RootContextPublisher(f.signer, f.pub, str(f.directory), str(link))
        with self.assertRaises(publisher.PublicationDenied):
            publisher.RootContextPublisher(f.signer, f.pub, str(f.directory), str(f.directory / "servercerts"))

    def test_nonroot_calls_denied_and_no_secret_receipt(self):
        f = self.fixture
        with mock.patch.object(publisher.os, "geteuid", return_value=2101):
            with self.assertRaises(Denied):
                publisher.RootContextPublisher(f.signer, f.pub, str(f.directory), str(self.staging))
            with self.assertRaises(publisher.PublicationDenied):
                self.publish()
        result = json.dumps(self.publish())
        self.assertNotIn("admission", result)
        self.assertNotIn("synthetic", result)
        self.assertNotIn(str(self.fixture.root), result)
        self.assertEqual(set(json.loads(result)), {"binding_sha256"})


if __name__ == "__main__":
    unittest.main()
