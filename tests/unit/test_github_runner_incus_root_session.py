"""Actual private Root lock FD lifetime and capability binding in isolated EE."""
from dataclasses import replace
import fcntl
import os
import sys
import threading
import unittest

import test_github_runner_incus_preparation as fixtures
from incus_lease_issuer import root_session
from incus_lease_issuer.identity import Denied


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Root Linux EE only")
class RootSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.RootPreparationTests.setUpClass()

    def setUp(self):
        self.fixture = fixtures.RootPreparationTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def session(self):
        return root_session._session(str(self.fixture.config), self.fixture.sha)

    def test_actual_lock_owned_until_scope_exit_and_cannot_be_reentered(self):
        with self.session() as session:
            self.assertEqual(root_session._require_session(session).lock_path, str(self.fixture.lock))
            with self.assertRaises(BlockingIOError):
                with self.session():
                    self.fail("second independent flock acquired")
        with self.assertRaises(Denied):
            root_session._require_session(session)
        with self.session() as fresh:
            self.assertNotEqual(fresh, session)

    def test_reconstructed_or_other_thread_capability_denied(self):
        with self.session() as session:
            with self.assertRaises(Denied):
                root_session._require_session(replace(session))
            errors = []
            def other_thread():
                try:
                    root_session._require_session(session)
                except Denied as error:
                    errors.append(str(error))
            thread = threading.Thread(target=other_thread)
            thread.start()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, ["root-session-owner"])

    def test_replaced_lock_path_denied_even_with_original_fd(self):
        with self.session() as session:
            self.fixture.lock.rename(self.fixture.lock.with_suffix(".old"))
            self.fixture.lock.write_bytes(b"")
            self.fixture.lock.chmod(0o600)
            with self.assertRaisesRegex(Denied, "root-session-lock-drift"):
                root_session._require_session(session)

    def test_inherited_fd_does_not_transfer_session_to_forked_process(self):
        with self.session() as session:
            pid = os.fork()
            if pid == 0:
                try:
                    root_session._require_session(session)
                except Denied:
                    os._exit(0)
                except BaseException:
                    os._exit(2)
                os._exit(1)
            observed, status = os.waitpid(pid, 0)
            self.assertEqual(observed, pid)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            root_session._require_session(session)

    def test_config_drift_denied_under_held_lock(self):
        with self.session() as session:
            self.fixture.config.write_bytes(b"{}")
            with self.assertRaises(Denied):
                root_session._require_session(session)

    def test_open_but_unlocked_fd_is_not_an_owned_lock(self):
        with self.session() as session:
            fcntl.flock(session.fd, fcntl.LOCK_UN)
            with self.assertRaisesRegex(Denied, "root-session-lock-not-held"):
                root_session._require_session(session)
