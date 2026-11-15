"""Actual private fixture-parent checks; no operating or cleanup authority."""
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

import test_github_runner_incus_ledger as fixtures


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux fixture only")
class FixtureParentTests(unittest.TestCase):
    def setUp(self):
        base = fixtures.validated_fixture_parent(Path("/run/proof"), private=True)
        self.directory = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_explicit_parent_is_the_actual_allocation_parent_and_initializes_real_ledger(self):
        fixture = fixtures.IncusLedgerTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp(parent=self.root)
        self.assertEqual(Path(fixture.directory.name).parent, self.root)
        self.assertEqual(stat.S_IMODE(fixture.path.stat().st_mode), 0o700)
        with fixture.open() as store:
            self.assertEqual(store.lease_ids(), ())

    def test_default_selected_parent_is_validated_and_passed_to_allocation(self):
        fixture = fixtures.IncusLedgerTests()
        self.addCleanup(fixture.doCleanups)
        with mock.patch.object(fixtures.tempfile, "gettempdir", return_value=str(self.root)):
            fixture.setUp()
        self.assertEqual(Path(fixture.directory.name).parent, self.root)

    def test_root_default_writable_tmp_skips_before_temporary_directory_allocation(self):
        fixture = fixtures.IncusLedgerTests()
        self.addCleanup(fixture.doCleanups)
        with mock.patch.object(fixtures.tempfile, "gettempdir", return_value="/tmp"), \
             mock.patch.object(fixtures.tempfile, "TemporaryDirectory") as allocation:
            with self.assertRaises(unittest.SkipTest):
                fixture.setUp()
            allocation.assert_not_called()

    def test_missing_symlink_and_writable_ancestor_skip_before_allocation(self):
        safe = self.root / "safe"
        safe.mkdir(mode=0o700)
        link = self.root / "alias"
        link.symlink_to(safe, target_is_directory=True)
        writable = self.root / "writable"
        writable.mkdir(mode=0o777)
        writable.chmod(0o777)
        child = writable / "private-child"
        child.mkdir(mode=0o700)
        for parent in (self.root / "missing", link, child):
            with self.subTest(parent=parent), mock.patch.object(fixtures.tempfile, "TemporaryDirectory") as allocation:
                fixture = fixtures.IncusLedgerTests()
                self.addCleanup(fixture.doCleanups)
                with self.assertRaises(unittest.SkipTest):
                    fixture.setUp(parent=parent)
                allocation.assert_not_called()

    def test_private_parent_requires_owner0700_and_rejects_foreign_ancestry(self):
        mode = self.root / "mode755"
        mode.mkdir(mode=0o755)
        mode.chmod(0o755)
        with self.assertRaises(unittest.SkipTest):
            fixtures.validated_fixture_parent(mode, private=True)
        foreign = self.root / "foreign"
        foreign.mkdir(mode=0o700)
        try:
            os.chown(foreign, 65534, -1)
        except PermissionError:
            self.skipTest("requires isolated fixture CHOWN capability")
        self.addCleanup(os.chown, foreign, 0, -1)
        with mock.patch.object(fixtures.tempfile, "TemporaryDirectory") as allocation:
            fixture = fixtures.IncusLedgerTests()
            self.addCleanup(fixture.doCleanups)
            with self.assertRaises(unittest.SkipTest):
                fixture.setUp(parent=foreign)
            allocation.assert_not_called()


if __name__ == "__main__":
    unittest.main()
