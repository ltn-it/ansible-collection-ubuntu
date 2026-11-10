"""Offline native-fence fixtures. No genuine quarantine/window acceptance claim.

Only root FS cases use /run/proof in an isolated official EE; never host. Native
GET/systemd fixtures model transport, not production reader trust or authority.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import native_fence as fence  # noqa: E402
from incus_lease_issuer import registration, kernel  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


def policy():
    unit = "actions.runner.lightning-it.incus-runner-01.service"
    return fence.NativeFencePolicy(54334171, "example", 78, "incus-runner-01", 7, "Quarantine",
        (("self-hosted", "read-only"), ("Linux", "read-only"), ("ARM64", "read-only"), ("incus", "custom")),
        "arm64", "/var/lib/protected-example/work", unit, "/srv/github-actions-runner/incus-runner-01",
        "github-runner", "/system.slice/" + unit, "/etc/systemd/system/" + unit, "a" * 64, (),
        "/etc/github-runner-protected/read-token", "test:root-managed-read-reference",
        "test:external-window-reference-is-not-acceptance")


def unit_properties(policy, active=False):
    return {"Id": policy.old_unit, "LoadState": "loaded", "ActiveState": "active" if active else "inactive",
            "SubState": "running" if active else "dead", "MainPID": "120" if active else "0",
            "ControlGroup": policy.old_cgroup if active else "", "FragmentPath": policy.old_fragment,
            "DropInPaths": "", "NeedDaemonReload": "no", "WorkingDirectory": policy.old_root,
            "User": policy.old_user, "Transient": "no", "Group": "", "SupplementaryGroups": "",
            "UnitFileState": "enabled" if active else "disabled"}


class NativeFixtureReader:
    def __init__(self, policy, online=False, busy=False):
        self.policy, self.calls = policy, []
        self.owner = {"id": policy.owner_id, "login": policy.owner_login, "type": "Organization"}
        # Actual runner78 GET uses Linux, zero labelIDs, no ephemeral field.
        # Fixture values/status/quarantine remain synthetic, not native proof.
        self.runner = {"id": policy.runner_id, "name": policy.runner_name, "os": "Linux",
                       "status": "online" if online else "offline", "busy": busy,
                       "labels": [{"id": 0, "name": name, "type": kind} for name, kind in policy.labels]}
        self.group = {"id": policy.group_id, "name": policy.group_name, "visibility": "selected",
                      "inherited": False, "default": False, "allows_public_repositories": False,
                      "selected_repositories_url": "https://example.invalid/must-never-follow"}
        self.runners, self.groups, self.members, self.repositories = [self.runner], [self.group], [self.runner], []

    def get(self, path):
        self.calls.append(path)
        prefix = "/orgs/" + self.policy.owner_login
        direct = {prefix: self.owner, prefix + "/actions/runners/78": self.runner,
                  prefix + "/actions/runner-groups/7": self.group}
        if path in direct:
            return deepcopy(direct[path])
        base, query = path.split("?", 1)
        page = int(query.split("page=")[-1])
        options = {prefix + "/actions/runners": ("runners", self.runners),
                   prefix + "/actions/runner-groups": ("runner_groups", self.groups),
                   prefix + "/actions/runner-groups/7/runners": ("runners", self.members),
                   prefix + "/actions/runner-groups/7/repositories": ("repositories", self.repositories)}
        name, entries = options[base]
        return {"total_count": len(entries), name: deepcopy(entries[(page - 1) * 100:page * 100])}


class NonrootAndWireTests(unittest.TestCase):
    def test_legacy_group_criterion_checks_primary_supplementary_and_explicit_root_membership(self):
        user = SimpleNamespace(pw_name="synthetic-runner", pw_uid=2101, pw_gid=2101)
        root = SimpleNamespace(gr_gid=0, gr_mem=[])
        with mock.patch.object(fence.pwd, "getpwnam", return_value=user), \
             mock.patch.object(fence.grp, "getgrgid", return_value=root), \
             mock.patch.object(fence.os, "getgrouplist", return_value=[2101]) as groups:
            self.assertEqual(fence._legacy_group_binding("synthetic-runner"), (2101, 2101, (2101,)))
            groups.return_value = [2101, 0]
            with self.assertRaises(Denied):
                fence._legacy_group_binding("synthetic-runner")
            groups.return_value = [2101]
            user.pw_gid = 0
            with self.assertRaises(Denied):
                fence._legacy_group_binding("synthetic-runner")
            user.pw_gid = 2101
            root.gr_mem = ["synthetic-runner"]
            with self.assertRaises(Denied):
                fence._legacy_group_binding("synthetic-runner")
        with mock.patch.object(fence.pwd, "getpwnam", side_effect=KeyError("unobserved")):
            with self.assertRaisesRegex(Denied, "native-fence-root-group-unknown"):
                fence._legacy_group_binding("synthetic-runner")

    def test_loaded_systemd_groups_cannot_restore_root_group_outside_nss(self):
        root = SimpleNamespace(gr_gid=0)
        with mock.patch.object(fence, "_legacy_group_binding", return_value=(2101, 2101, (2101,))), \
             mock.patch.object(fence.grp, "getgrnam", return_value=root):
            for values in ({"Group": "root", "SupplementaryGroups": ""},
                           {"Group": "", "SupplementaryGroups": "root"},
                           {"Group": "0", "SupplementaryGroups": ""},
                           {"Group": "", "SupplementaryGroups": "0"}):
                with self.subTest(values=values), self.assertRaises(Denied):
                    fence._loaded_groups(values, "synthetic-runner")
            with mock.patch.object(fence.grp, "getgrnam", side_effect=KeyError("unknown")):
                with self.assertRaises(Denied):
                    fence._loaded_groups({"Group": "", "SupplementaryGroups": "unknown"}, "synthetic-runner")

    def test_nonroot_public_entrypoints_cannot_issue_or_inspect_targets(self):
        if os.geteuid() == 0:
            self.skipTest("nonroot guard exercised separately in official EE")
        with self.assertRaisesRegex(Denied, "native-fence-root-required"):
            fence.issue_after_stop(policy())
        with self.assertRaisesRegex(Denied, "native-fence-root-required"):
            fence.inspect_before_stop(policy())

    def test_fixed_reader_uses_get_only_and_never_response_urls_or_proxies(self):
        connection = mock.Mock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read.return_value = b'{"id":54334171}'
        with mock.patch.object(fence, "_read_token", return_value="synthetic-read-secret"), \
             mock.patch.object(fence.http.client, "HTTPSConnection", return_value=connection) as ctor, \
             mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://example.invalid/proxy"}):
            reader = fence._Reader(policy())
            self.assertEqual(reader.get("/orgs/example"), {"id": 54334171})
        self.assertEqual(ctor.call_args.args, ("api.github.com", 443))
        self.assertEqual(connection.request.call_args.args, ("GET", "/orgs/example"))
        self.assertEqual(connection.request.call_args.kwargs["headers"]["Authorization"], "Bearer synthetic-read-secret")
        self.assertEqual(connection.request.call_count, 1)
        self.assertNotIn("synthetic-read-secret", repr(reader))

    def test_reader_rejects_other_routes_redirects_and_retries(self):
        with mock.patch.object(fence, "_read_token", return_value="synthetic-read-secret"):
            reader = fence._Reader(policy())
            with mock.patch.object(fence.http.client, "HTTPSConnection") as ctor:
                for path in ("https://example.invalid/", "/orgs/other/actions/runners", "/orgs/example/actions/runners/79",
                             "/orgs/example/actions/runners?per_page=100&page=0"):
                    with self.assertRaises(Denied):
                        reader.get(path)
                ctor.assert_not_called()
            for status in (301, 302, 307, 429, 500):
                connection = mock.Mock()
                connection.getresponse.return_value.status = status
                connection.getresponse.return_value.read.return_value = b"synthetic-read-secret"
                with mock.patch.object(fence.http.client, "HTTPSConnection", return_value=connection):
                    with self.assertRaises(Denied) as caught:
                        reader.get("/orgs/example")
                self.assertNotIn("synthetic", str(caught.exception))
                self.assertEqual(connection.request.call_count, 1)

    def test_pagination_requires_complete_terminal_page_and_rejects_duplicates(self):
        reader = mock.Mock()
        reader.get.side_effect = [{"total_count": 2, "runners": [{"id": 1}]},
                                  {"total_count": 2, "runners": []}]
        with self.assertRaisesRegex(Denied, "native-fence-incomplete-pagination"):
            fence._pages(reader, "/orgs/example/actions/runners", "runners")
        reader.get.side_effect = [{"total_count": 2, "runners": [{"id": 1}]},
                                  {"total_count": 2, "runners": [{"id": 1}]}]
        with self.assertRaisesRegex(Denied, "native-fence-page-duplicate"):
            fence._pages(reader, "/orgs/example/actions/runners", "runners")
        reader.get.side_effect = [{"total_count": 1, "runners": [{"id": 1}]},
                                  {"total_count": 1, "runners": []}]
        self.assertEqual(fence._pages(reader, "/orgs/example/actions/runners", "runners"), [{"id": 1}])


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux UID0 EE only")
class RootNativeFenceFixtureTests(unittest.TestCase):
    def setUp(self):
        self.policy = policy()
        self.reader = NativeFixtureReader(self.policy)
        self.unit = unit_properties(self.policy)
        self.empty = {"original_cgroup": self.policy.old_cgroup, "tree_pids": [], "proc_members": [],
                      "hierarchy_present": False, "mount": [("/", "cgroup2")]}
        self.boot = mock.patch.object(kernel, "read_boot_id", return_value="a8bc83ca-9ce9-4d43-ad49-419e913ffb66")
        self.boot.start()
        self.addCleanup(self.boot.stop)

    def issue(self, reader=None, unit=None, empty=None):
        return fence.issue_after_stop(self.policy, _reader=reader or self.reader,
                    _unit_reader=lambda policy: deepcopy(self.unit if unit is None else unit),
                    _empty_reader=(lambda policy: deepcopy(self.empty)) if empty is None else empty)

    def test_two_pass_fixture_issues_only_exact_frozen_target_and_raw_label_mapping(self):
        target = self.issue()
        self.assertIs(type(target), registration.VerifiedTarget)
        self.assertEqual((target.runner_id, target.group_id, target.owner_id), (78, 7, 54334171))
        self.assertEqual(target.labels, (("self-hosted", "system"), ("Linux", "system"), ("ARM64", "system"), ("incus", "user")))
        self.assertEqual(len(target.fence_sha256), 64)
        self.assertLessEqual(target.valid_until - int(fence.time.time()), 30)
        self.assertEqual(self.reader.calls.count("/orgs/example"), 2)
        self.assertEqual(self.reader.calls.count("/orgs/example/actions/runners?per_page=100&page=2"), 2)
        self.assertEqual(self.reader.calls.count("/orgs/example/actions/runner-groups/7/repositories?per_page=100&page=1"), 2)
        self.assertFalse(any("example.invalid" in path for path in self.reader.calls))
        with self.assertRaises(FrozenInstanceError):
            target.runner_id = 79

    def test_before_stop_returns_planning_facts_even_busy_but_never_effect_target(self):
        reader = NativeFixtureReader(self.policy, online=True, busy=True)
        plan = fence.inspect_before_stop(self.policy, _reader=reader,
                                        _unit_reader=lambda policy: unit_properties(policy, active=True))
        self.assertIs(type(plan), fence.PlanningFacts)
        self.assertTrue(plan.busy)
        self.assertTrue(plan.online)
        self.assertNotIsInstance(plan, registration.VerifiedTarget)
        with self.assertRaises(Denied):
            registration._validate_target(plan)

    def test_busy_or_online_target_is_not_an_after_stop_fence(self):
        for online, busy in ((True, False), (False, True), (True, True)):
            with self.subTest(online=online, busy=busy):
                with self.assertRaisesRegex(Denied, "native-fence-runner-not-idle-offline"):
                    self.issue(reader=NativeFixtureReader(self.policy, online=online, busy=busy))

    def test_active_old_unit_or_mainpid_alone_cannot_issue_target(self):
        with self.assertRaisesRegex(Denied, "native-fence-old-unit-not-stopped"):
            self.issue(unit=unit_properties(self.policy, active=True))
        def descendants_remain(policy):
            raise Denied("native-fence-original-cgroup-has-pids")
        with self.assertRaisesRegex(Denied, "native-fence-original-cgroup-has-pids"):
            self.issue(empty=descendants_remain)

    def test_stopped_but_boot_enabled_or_unknown_listener_cannot_issue_target(self):
        for state in ("enabled", "enabled-runtime", "linked", "static", "indirect", "masked", "", None):
            values = deepcopy(self.unit)
            if state is None:
                values.pop("UnitFileState")
            else:
                values["UnitFileState"] = state
            with self.subTest(state=state), mock.patch.object(registration, "VerifiedTarget") as target:
                with self.assertRaisesRegex(Denied, "native-fence-old-unit-autostart"):
                    self.issue(unit=values, empty=lambda policy: self.fail("empty proof acquired before boot fence"))
                target.assert_not_called()

    def test_boot_enable_drift_on_second_native_pass_never_issues_target(self):
        values = iter((self.unit, {**self.unit, "UnitFileState": "enabled"}))
        with mock.patch.object(registration, "VerifiedTarget") as target:
            with self.assertRaisesRegex(Denied, "native-fence-old-unit-autostart"):
                fence.issue_after_stop(self.policy, _reader=self.reader,
                    _unit_reader=lambda policy: deepcopy(next(values)),
                    _empty_reader=lambda policy: deepcopy(self.empty))
            target.assert_not_called()

    def test_group_must_be_owned_selected_and_empty_of_repositories(self):
        for field, value in (("inherited", True), ("visibility", "all"), ("visibility", "private")):
            with self.subTest(field=field, value=value):
                reader = NativeFixtureReader(self.policy)
                reader.group[field] = value
                with self.assertRaisesRegex(Denied, "native-fence-group-not-quarantined"):
                    self.issue(reader=reader)
        self.reader.repositories = [{"id": 91, "name": "real-dispatch-source"}]
        with self.assertRaisesRegex(Denied, "native-fence-group-repositories-not-empty"):
            self.issue()

    def test_group_membership_must_be_exact_selected_runner_only(self):
        self.reader.members = []
        with self.assertRaisesRegex(Denied, "native-fence-group-membership"):
            self.issue()
        self.reader.members = [self.reader.runner, {**self.reader.runner, "id": 79, "name": "other"}]
        with self.assertRaisesRegex(Denied, "native-fence-group-membership"):
            self.issue()

    def test_full_org_inventory_prevents_borrowed_id_or_ambiguous_name(self):
        self.reader.runners.append({**self.reader.runner, "id": 79})
        with self.assertRaisesRegex(Denied, "native-fence-ambiguous-runner-name"):
            self.issue()
        self.reader.runners = [{**self.reader.runner, "id": 79, "name": "other"}]
        with self.assertRaisesRegex(Denied, "native-fence-runner-identity"):
            self.issue()

    def test_wrong_owner_os_labels_and_direct_read_drift_deny(self):
        variants = [("owner", "id", 1), ("runner", "os", "windows"), ("runner", "labels", []),
                    ("runner", "ephemeral", True)]
        for attribute, field, value in variants:
            with self.subTest(field=field):
                reader = NativeFixtureReader(self.policy)
                getattr(reader, attribute)[field] = value
                with self.assertRaises(Denied):
                    self.issue(reader=reader)
        self.reader.runners = [deepcopy(self.reader.runner)]
        self.reader.runner["busy"] = True
        with self.assertRaises(Denied):
            self.issue()

    def test_actual_projection_omits_ephemeral_without_claiming_server_persistence(self):
        self.assertEqual(set(self.reader.runner), {"id", "name", "os", "status", "busy", "labels"})
        self.assertEqual(self.reader.runner["os"], "Linux")
        self.assertTrue(all(label["id"] == 0 for label in self.reader.runner["labels"]))
        target = self.issue()
        self.assertEqual(target.runner_id, 78)
        self.assertFalse(hasattr(target, "persistent"))
        self.assertNotIn("ephemeral", target.__dict__)

    def test_os_case_only_is_canonicalized_and_wrong_types_or_ephemeral_deny(self):
        for value in ("linux", "LINUX", "Linux"):
            reader = NativeFixtureReader(self.policy)
            reader.runner["os"] = value
            self.assertEqual(self.issue(reader=reader).runner_id, 78)
        for field, value in (("os", None), ("os", 1), ("os", "Linux "), ("ephemeral", True),
                             ("ephemeral", None), ("ephemeral", 0), ("ephemeral", "false")):
            with self.subTest(field=field, value=value):
                reader = NativeFixtureReader(self.policy)
                reader.runner[field] = value
                with self.assertRaises(Denied):
                    self.issue(reader=reader)
        reader = NativeFixtureReader(self.policy)
        reader.runner["ephemeral"] = False
        self.assertEqual(self.issue(reader=reader).runner_id, 78)

    def test_zero_native_label_ids_are_integers_and_invalid_types_are_rejected(self):
        for value in (-1, False, "0", None):
            with self.subTest(value=value):
                reader = NativeFixtureReader(self.policy)
                reader.runner["labels"][0]["id"] = value
                with self.assertRaises(Denied):
                    self.issue(reader=reader)

    def test_metadata_or_systemd_drift_between_complete_passes_denies(self):
        original = self.reader.get
        count = 0
        def drift(path):
            nonlocal count
            if path == "/orgs/example":
                count += 1
                self.reader.owner["description"] = "snapshot" + str(count)
            return original(path)
        self.reader.get = drift
        with self.assertRaisesRegex(Denied, "native-fence-observations-drift"):
            self.issue()
        reader = NativeFixtureReader(self.policy)
        units = iter((self.unit, {**self.unit, "NeedDaemonReload": "yes"}))
        with self.assertRaisesRegex(Denied, "native-fence-observations-drift"):
            fence.issue_after_stop(self.policy, _reader=reader, _unit_reader=lambda policy: next(units),
                                   _empty_reader=lambda policy: self.empty)

    def test_native_error_is_secret_redacted_and_no_target_returned(self):
        self.reader.get = mock.Mock(side_effect=OSError("synthetic-read-secret"))
        output = io.StringIO()
        with mock.patch("sys.stdout", output), mock.patch("sys.stderr", output):
            with self.assertRaises(Denied) as caught:
                self.issue()
        self.assertNotIn("synthetic", str(caught.exception))
        self.assertEqual(output.getvalue(), "")

    def test_real_root_private_token_file_and_permission_guard(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires private /run/proof tmpfs")
        with tempfile.TemporaryDirectory(prefix="native-fence-", dir=base) as directory:
            path = Path(directory) / "read-token"
            path.write_text("synthetic-read-secret\n")
            path.chmod(0o600)
            self.assertEqual(fence._read_token(str(path)), "synthetic-read-secret")
            path.chmod(0o644)
            with self.assertRaisesRegex(Denied, "native-fence-token-private"):
                fence._read_token(str(path))
            path.chmod(0o600)
            link = Path(directory) / "read-link"
            link.symlink_to(path)
            with self.assertRaises((Denied, OSError)):
                fence._read_token(str(link))

    def test_systemd_reader_rejects_wrong_unit_while_never_using_old_scripts(self):
        raw = "".join(key + "=" + value + "\n" for key, value in {**self.unit, "Id": "other.service"}.items()).encode()
        expected = [(self.policy.old_fragment, self.policy.old_fragment_sha256)]
        with mock.patch.object(fence, "trusted_file"), mock.patch.object(fence, "_unit_files", return_value=expected), \
             mock.patch.object(fence.service, "_command", return_value=raw) as command:
            with self.assertRaisesRegex(Denied, "native-fence-unit-binding"):
                fence._read_unit(self.policy)
        argv = command.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/systemctl")
        self.assertEqual(argv[-1], self.policy.old_unit)
        self.assertFalse(any("svc.sh" in arg or "config.sh" in arg for arg in argv))

    def test_production_unit_reader_rechecks_legacy_files_around_loaded_groups(self):
        raw = "".join(key + "=" + value + "\n" for key, value in self.unit.items()).encode()
        expected = [(self.policy.old_fragment, self.policy.old_fragment_sha256)]
        with mock.patch.object(fence, "trusted_file"), \
             mock.patch.object(fence, "_unit_files", side_effect=[expected, expected]) as files, \
             mock.patch.object(fence, "_legacy_group_binding", return_value=(2101, 2101, (2101,))), \
             mock.patch.object(fence.service, "_command", return_value=raw):
            result = fence._read_unit(self.policy)
            self.assertEqual(files.call_count, 2)
            self.assertEqual((result["Group"], result["SupplementaryGroups"]), ("", ""))
        changed = [(self.policy.old_fragment, "b" * 64)]
        with mock.patch.object(fence, "trusted_file"), \
             mock.patch.object(fence, "_unit_files", side_effect=[expected, changed]), \
             mock.patch.object(fence, "_legacy_group_binding", return_value=(2101, 2101, (2101,))), \
             mock.patch.object(fence.service, "_command", return_value=raw):
            with self.assertRaisesRegex(Denied, "native-fence-unit-files-drift"):
                fence._read_unit(self.policy)

    def test_real_kernel_current_cgroup_cannot_be_claimed_empty(self):
        # No production policy override: call the private read-only guard with
        # this fixture's real cgroup solely to exercise a negative sysfs path.
        actual = kernel.parse_cgroup(Path("/proc/self/cgroup").read_bytes())
        with self.assertRaises((Denied, OSError)):
            fence._cgroup_processes(replace(self.policy, old_cgroup=actual))


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux UID0 EE filesystem only")
class LegacyUnitFileTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires private /run/proof tmpfs")
        directory = tempfile.TemporaryDirectory(prefix="legacy-unit-", dir=base)
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "synthetic.service"
        self.path.write_bytes(b"[Service]\nUser=synthetic-runner\nExecStart=/unexecuted/legacy/runsvc.sh\n")
        os.chown(self.path, 0, 0)
        self.path.chmod(0o664)
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(fence.pwd, "getpwnam", return_value=SimpleNamespace(
            pw_name="synthetic-runner", pw_uid=2101, pw_gid=2101)))
        stack.enter_context(mock.patch.object(fence.grp, "getgrgid", return_value=SimpleNamespace(gr_gid=0, gr_mem=[])))
        stack.enter_context(mock.patch.object(fence.os, "getgrouplist", return_value=[2101]))

    def read(self, path=None, digest=None):
        return fence._legacy_unit_file(str(self.path if path is None else path),
                                       self.digest if digest is None else digest, "synthetic-runner")

    def test_exact_root_group_0664_and_0644_are_readonly_legacy_observations(self):
        original = self.path.stat()
        self.assertEqual(self.read(), self.digest)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o664)
        self.assertEqual(self.path.stat().st_ino, original.st_ino)
        self.path.chmod(0o644)
        self.assertEqual(self.read(), self.digest)
        with self.assertRaises(Denied):
            fence.trusted_file(str(self.path.parent / "missing"))
        self.path.chmod(0o664)
        # The general new-installation file reader remains strict.
        with self.assertRaises(Denied):
            fence.trusted_file(str(self.path))

    def test_wrong_gid_world_write_execution_or_special_mode_deny(self):
        os.chown(self.path, 0, 1)
        with self.assertRaises(Denied):
            self.read()
        os.chown(self.path, 0, 0)
        for mode in (0o666, 0o777, 0o664 | stat.S_ISUID, 0o664 | stat.S_ISGID, 0o600):
            self.path.chmod(mode)
            with self.subTest(mode=oct(mode)), self.assertRaises(Denied):
                self.read()

    def test_symlink_hardlink_and_writable_ancestor_deny(self):
        link = self.path.parent / "alias.service"
        link.symlink_to(self.path)
        with self.assertRaises(Denied):
            self.read(link)
        link.unlink()
        os.link(self.path, link)
        with self.assertRaises(Denied):
            self.read()
        link.unlink()
        self.path.parent.chmod(0o770)
        with self.assertRaises(Denied):
            self.read()
        self.path.parent.chmod(0o700)

    def test_hash_mismatch_and_in_read_content_drift_deny(self):
        with self.assertRaises(Denied):
            self.read(digest="0" * 64)
        actual_read = fence.os.read
        changed = False
        def drift(fd, size):
            nonlocal changed
            content = actual_read(fd, size)
            if content and not changed:
                changed = True
                self.path.write_bytes(b"changed-but-never-executed")
            return content
        with mock.patch.object(fence.os, "read", side_effect=drift):
            with self.assertRaises(Denied):
                self.read()

    def test_membership_drift_during_0664_read_denies(self):
        with mock.patch.object(fence, "_legacy_group_binding", side_effect=[(2101, 2101, (2101,)),
                                                                           (2101, 2101, (2101, 5))]):
            with self.assertRaisesRegex(Denied, "native-fence-unit-group-drift"):
                self.read()


if __name__ == "__main__":
    unittest.main()
