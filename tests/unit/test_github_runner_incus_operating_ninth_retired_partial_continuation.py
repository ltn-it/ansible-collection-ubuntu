"""Exact ninth terminal provider history; no Root or Heavy acceptance."""
from contextlib import ExitStack, nullcontext
from copy import deepcopy
import json
import hashlib
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
import sys
import threading
import unittest
from unittest import mock

from test_github_runner_incus_ledger import validated_fixture_parent

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import operating_cells as cells, run_factory as factory, ledger
from incus_lease_issuer.identity import Denied


def native():
    graph = json.loads((Path(__file__).parent / "fixtures/g06-ninth-failed-native-graph.json").read_bytes())
    run = graph["run"]
    run["repository"] = {"id": 1103407173, "full_name": factory.SOURCE,
                         "private": False, "owner": {"id": 54334171}}
    run["referenced_workflows"] = [{"sha": cells.NINTH_REUSABLE,
        "path": factory.VALIDATION + "/.github/workflows/collection-quality-profile-isolated.yml@" + cells.NINTH_REUSABLE}]
    checks = []
    for identifier in cells.NINTH_CHECKS:
        job = next(row for row in graph["jobs"] if row["id"] == identifier)
        checks.append({"id": identifier, "head_sha": cells.NINTH_MAIN,
            **{key: job[key] for key in ("name", "status", "conclusion", "started_at", "completed_at")},
            "app": {"id": 15368, "slug": "github-actions"}})
    return run, {"total_count": 24, "jobs": graph["jobs"]}, checks


class NinthTerminalHistoryTests(unittest.TestCase):
    def test_full_native_graph_including_all_seven_failed_checks(self):
        self.assertEqual(ledger.digest(cells.ninth_native_projection(*native())), cells.NINTH_GRAPH)

    def test_missing_failed_check_or_drifted_job_cannot_admit_history(self):
        mutations = (
            lambda r, j, c: c.pop(),
            lambda r, j, c: j["jobs"].pop(),
            lambda r, j, c: c[0].update(conclusion="success"),
            lambda r, j, c: c[-1]["app"].update(id=1),
            lambda r, j, c: r.update(run_attempt=2),
            lambda r, j, c: r["actor"].update(id=247824904),
            lambda r, j, c: r.update(head_sha=cells.EIGHTH_MAIN),
            lambda r, j, c: j["jobs"][0].update(runner_id=78),
        )
        for mutate in mutations:
            run, jobs, checks = deepcopy(native())
            mutate(run, jobs, checks)
            with self.subTest(mutate=mutate), self.assertRaises(Denied):
                cells.ninth_native_projection(run, jobs, checks)


    def test_all_seven_checks_and_second_complete_inventory_read_are_required(self):
        run, inventory, checks = native()
        prefix = "/actions/runs/" + str(cells.NINTH_RUN)
        path = prefix + "/attempts/1/jobs?per_page=100&page=1"
        responses = {prefix: run, path: inventory,
                     **{"/check-runs/" + str(check["id"]): check for check in checks}}
        calls = []
        def get(key):
            calls.append(key)
            return deepcopy(responses[key])
        self.assertEqual(factory._continuation_ninth_native(get), cells.ninth_native_projection(*native()))
        self.assertEqual(len(calls), 10)
        self.assertEqual(calls.count(path), 2)
        self.assertEqual(calls[-1], path)
        calls.clear()
        def drift(key):
            value = get(key)
            if key == path and calls.count(path) == 2:
                value["jobs"].pop()
            return value
        with self.assertRaisesRegex(Denied, "native-inventory-drift"):
            factory._continuation_ninth_native(drift)


class RecycledNamespaceGenerationTests(unittest.TestCase):
    def test_current_owned_generation_can_pin_recycled_inode_without_blaming_old_run(self):
        from contextlib import contextmanager
        from incus_lease_issuer import kernel, network_fence

        coordinates = factory._NINTH_NAMESPACE
        lease_id = "a" * 32
        boot = "12345678-1234-1234-1234-123456789abc"
        successor = {"run_id": 120, "source_sha": "b" * 40, "reusable_sha": "c" * 40}
        row = {"state": "prepared", "identity": {
            "run_id": 120, "caller_sha": "b" * 40, "reusable_sha": "c" * 40}, "effects": {
            "e" * 32: {"operation": "fence-create", "state": "verified", "target": "fence:" + lease_id,
                       "host_api": {}, "fence": {"boot_id": boot, "netns_device": coordinates[0],
                                                  "netns_inode": coordinates[1]}}}}
        store = mock.MagicMock()
        store.__enter__.return_value = store
        store.lease_ids.return_value = (lease_id,)
        store.read.return_value = row
        held = []

        @contextmanager
        def witness(name):
            self.assertEqual(name, "lit-lease-" + lease_id)
            held.append(name)
            try:
                yield 23, SimpleNamespace(st_dev=coordinates[0], st_ino=coordinates[1])
            finally:
                held.pop()

        with mock.patch.object(ledger, "Ledger", return_value=store), \
             mock.patch.object(kernel, "read_boot_id", return_value=boot), \
             mock.patch.object(network_fence, "_namespace_witness", side_effect=witness), \
             mock.patch.object(network_fence, "_namespace_cookie", return_value=888) as cookie:
            with factory._historical_namespace_coordinates("/unused", successor) as observed:
                self.assertIsNone(observed)
                self.assertEqual(held, ["lit-lease-" + lease_id])
            self.assertFalse(held)
            cookie.return_value = factory._NINTH_NAMESPACE_COOKIE
            with self.assertRaisesRegex(Denied, "continuation-namespace-kernel-generation"):
                with factory._historical_namespace_coordinates("/unused", successor):
                    self.fail("present historical namespace")
            cookie.return_value = 888
            row["effects"]["e" * 32]["state"] = "unknown"
            with self.assertRaisesRegex(Denied, "continuation-namespace-successor-fence"):
                with factory._historical_namespace_coordinates("/unused", successor):
                    self.fail("unverified successor generation")

class NinthSeparateRetirementTests(unittest.TestCase):
    def retirement(self):
        value = {"schema": 1, "kind": "original-ninth-partial-separately-retired-unknown-preserved",
                 **deepcopy(cells.NINTH_RETIRED_PARTIAL), "catalogues": {}}
        for kind, entry in (("native_intake_catalogue", value["intake"]),
                            ("native_run_configuration_catalogue", value["configuration"])):
            value["catalogues"][kind] = {"a" * 64: "b" * 64, entry["name"]: entry["inventory_sha256"]}
        return value

    def test_exact_historical_separate_retirement_keeps_prepared_unknown(self):
        value = self.retirement()
        self.assertEqual(cells._validate_ninth_retirement(value), value)
        self.assertEqual(value["original_record"]["state"], "prepared")
        self.assertEqual(sum(row["state"] == "unknown" for row in value["original_record"]["effects"].values()), 1)

    def test_history_relabelled_closed_missing_journal_or_changed_boundaries_denies(self):
        mutations = (
            lambda v: v["original_record"].update(state="closed"),
            lambda v: v["original_record"]["effects"]["838e147b15567fa3e2daf9f453b955f5"].update(state="verified"),
            lambda v: v["prior_journal"]["members"].pop("namespace-mount88-unknown.json"),
            lambda v: v["native_journal"]["members"].pop("complete-receipt.json"),
            lambda v: v.update(retain_until=True),
            lambda v: v.update(retain_until=v["retain_until"] - 1),
            lambda v: v["original_bank"].update(inode=v["original_bank"]["inode"] + 1),
            lambda v: v["catalogues"]["native_intake_catalogue"].pop(v["intake"]["name"]),
            lambda v: v.update(extra="unclassified"),
        )
        for mutate in mutations:
            value = self.retirement(); mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(Denied):
                cells._validate_ninth_retirement(value)

    def test_qualification_adds_only_exact_retired_entries_and_keeps_all_previous_history(self):
        # Old native/Root qualification is explicitly modeled here; existing
        # Eighth complete-stage tests exercise its actual readers separately.
        previous = {"schema": 8, "failed_prefix": {"catalogues": {
            "native_intake_catalogue": {"a" * 64: "b" * 64},
            "native_run_configuration_catalogue": {"a" * 64: "b" * 64}}}}
        value = {"schema": 9, "purpose": "g06-ninth-failed-partial-separate-retirement-complete-history",
                 "previous_qualification": previous, "native_ninth": cells.ninth_native_projection(*native()),
                 "retirement": self.retirement()}
        with mock.patch.object(cells, "NINTH_PREVIOUS_QUALIFICATION", ledger.digest(previous)), \
             mock.patch.object(cells, "_validate_eighth_prelease_qualification", return_value={"old": "unchanged"}) as old:
            self.assertEqual(cells._validate_ninth_retired_partial_qualification(value), {"old": "unchanged"})
            old.assert_called_once_with(previous)
            for mutate in (
                lambda v: v["retirement"]["catalogues"]["native_intake_catalogue"].update({"c" * 64: "d" * 64}),
                lambda v: v["retirement"]["catalogues"]["native_run_configuration_catalogue"].update({"a" * 64: "e" * 64}),
                lambda v: v["previous_qualification"].update(schema=7),
                lambda v: v["native_ninth"]["run"].update(run_attempt=2),
            ):
                changed = deepcopy(value); mutate(changed)
                with self.subTest(mutate=mutate), self.assertRaises(Denied):
                    cells._validate_ninth_retired_partial_qualification(changed)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "trusted root-owned netns parent")
class NinthNetworkWithdrawalTests(unittest.TestCase):
    def test_readonly_link_inventory_and_root_owned_namespace_parent(self):
        from incus_lease_issuer import network_fence as fence
        fixed = cells.NINTH_RETIRED_PARTIAL
        lease = fixed["original_record"]["lease_id"]
        name = "lth" + lease[:12]
        config = SimpleNamespace(network_fence_policy_path="/policy", network_fence_policy_sha256="f"*64)
        metadata = {"host": name, "lease_id": lease, "host_ifindex": 12250}
        receipt = (SimpleNamespace(sha256=fixed["veth_receipt"]["sha256"]), ledger.canonical({"metadata": metadata}), None)
        with tempfile.TemporaryDirectory(dir=validated_fixture_parent(Path("/run/proof"), private=True)) as directory, ExitStack() as stack:
            parent = Path(directory) / "netns"
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)
            open_directory = factory.installation._open_directory
            def open_parent(path):
                self.assertEqual(path, "/run/netns")
                return open_directory(str(parent))
            stack.enter_context(mock.patch.object(factory.installation, "_open_directory", side_effect=open_parent))
            stack.enter_context(mock.patch.object(factory.installation, "_file", return_value=receipt))
            bound = stack.enter_context(mock.patch.object(fence, "_bound_policy"))
            inventory = stack.enter_context(mock.patch.object(fence, "_ip"))
            visible = [{"ifname": "lo", "ifindex": 1}]
            inventory.return_value = visible
            factory._ninth_host_network_absent(config, lease)
            bound.assert_called_once_with(config.network_fence_policy_path, config.network_fence_policy_sha256, config)
            inventory.assert_called_once_with(bound.return_value, "link", "show")
            for rows in ([], [{"ifname": name, "ifindex": 77}], [{"ifname": "renamed", "ifindex": 12250}], [{}]):
                inventory.return_value = rows
                with self.subTest(rows=rows), self.assertRaisesRegex(Denied, "host-link-returned"):
                    factory._ninth_host_network_absent(config, lease)
            inventory.return_value = visible
            alias = parent / ("lit-lease-" + lease)
            alias.symlink_to("absent-target")
            with self.assertRaisesRegex(Denied, "alias-returned"):
                factory._ninth_host_network_absent(config, lease)
            alias.unlink()
            parent.chmod(0o777)
            with self.assertRaisesRegex(Denied, "untrusted-directory"):
                factory._ninth_host_network_absent(config, lease)


class NinthVolumeCensusTests(unittest.TestCase):
    def test_only_the_censused_mount_and_filesystem_are_accepted(self):
        from incus_lease_issuer import cleanup_storage, storage_quota
        config = SimpleNamespace(storage_quota_policy_path="/fixture/policy",
            storage_quota_policy_sha256="7d5c3d95206f6ee455867b2038488bd442f7b44f86b17ac16b251c963135bccb")
        uuid = bytes.fromhex("2215e2cb23e44c78ac688bc469dfe575")
        policy = {"mount": {"path": "/fixture/mount"}, "loop_device": "/fixture/loop"}
        with ExitStack() as stack:
            acquire = stack.enter_context(mock.patch.object(storage_quota, "_acquire_paths", side_effect=lambda *a: nullcontext()))
            stack.enter_context(mock.patch.object(storage_quota, "_policy", return_value=(policy, None, None)))
            stack.enter_context(mock.patch.object(factory.installation, "_open_directory", return_value=88))
            stack.enter_context(mock.patch.object(storage_quota, "_open_file", return_value=89))
            stack.enter_context(mock.patch.object(os, "close"))
            mount = stack.enter_context(mock.patch.object(cleanup_storage, "_unique_mount_id", return_value=4323289150))
            read = stack.enter_context(mock.patch.object(os, "pread", return_value=uuid))
            factory._ninth_storage_census_continuity(config)
            acquire.assert_called_once_with(config.storage_quota_policy_path, config.storage_quota_policy_sha256, ())
            for mount_id, fs_uuid in ((371, uuid), (4323289150, bytes(16)), (4323289150, b"")):
                mount.return_value, read.return_value = mount_id, fs_uuid
                with self.subTest(mount_id=mount_id, fs_uuid=fs_uuid), self.assertRaisesRegex(Denied, "census-volume"):
                    factory._ninth_storage_census_continuity(config)
            acquire.side_effect = Denied("storage-quota-acquisition-denied")
            with self.assertRaisesRegex(Denied, "storage-quota"):
                factory._ninth_storage_census_continuity(config)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class NinthCollectorTests(unittest.TestCase):
    """Exercise both projections with actual ledger bytes and catalogue directories."""
    def setUp(self):
        from test_github_runner_runtime_v2_retired_preparation import RetiredPreparationInstallTests
        fixture = RetiredPreparationInstallTests("runTest")
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.fixture = fixture
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        def patch(obj, name, **kw):
            return self.stack.enter_context(mock.patch.object(obj, name, **kw))
        fixed = {k: deepcopy(fixture.fixed[k]) for k in cells.NINTH_RETIRED_PARTIAL}
        ref = fixed["original_bootstrap"]
        info = fixture.bootstrap.stat()
        ref.update(device=info.st_dev, inode=info.st_ino)
        old = SimpleNamespace(path=ref["path"], sha256=ref["sha256"],
                              file_stamp=(info.st_dev, info.st_ino), value=fixture.runtime)
        self.ref = ref
        self.next_bank = fixture.root / "successor"
        self.next_bank.mkdir(mode=0o700)
        self.previous = {"failed_prefix": {"original_bootstrap": {}, "catalogues": {
            "native_intake_catalogue": {}, "native_run_configuration_catalogue": {}}}, "previous_qualification": {}}
        patch(cells, "NINTH_RETIRED_PARTIAL", new=fixed)
        patch(cells, "_validate_eighth_prelease_qualification", return_value={})
        patch(cells, "NINTH_PREVIOUS_QUALIFICATION", new=ledger.digest(self.previous))
        patch(factory, "load_bootstrap", return_value=old)
        patch(factory, "_continuation_receipt", return_value=({"schema": 8, "successor": {
            "source_sha": cells.NINTH_MAIN, "run_id": cells.NINTH_RUN, "reusable_sha": cells.NINTH_REUSABLE}}, self.previous))
        patch(factory, "_eighth_failed_prefix_projection", return_value=self.previous["failed_prefix"])
        patch(factory, "_ninth_preserved_journals", return_value={k: fixed[k] for k in (
            "native_journal", "prior_journal", "veth_receipt", "certificate_receipt")})
        patch(factory, "_ninth_original_entries",
              return_value=({k: fixed[k] for k in ("intake", "configuration")}, object(), None))
        self.observe = patch(factory, "_ninth_original_resources_absent")
        for key, module in (("intake", factory.run_intake), ("configuration", factory)):
            root = fixture.root / key
            root.mkdir(mode=0o700)
            (root / fixed[key]["name"]).write_text(fixed[key]["inventory_sha256"])
            patch(module, "ROOT", new=str(root))
        patch(factory, "_fifth_retired_entry", side_effect=lambda p: p.read_text())

    def collect(self):
        return factory.collect_ninth_retired_partial_history(str(self.next_bank), self.ref, self.previous)

    def test_both_projections_retain_real_bank_bytes(self):
        self.assertEqual(self.collect()["original_bank"]["state_file_sha256"], hashlib.sha256(self.fixture.raw).hexdigest())
        self.assertEqual(self.observe.call_count, 4)
        self.assertEqual((self.fixture.path / "state.json").read_bytes(), self.fixture.raw)

    def test_live_origin_revalidation_allows_concurrent_historical_readers(self):
        import fcntl
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        retirement = self.collect()
        receipt = {"retirement": retirement, "previous_qualification": self.previous}
        qualified = ({"schema": 9, "successor": {}}, receipt,
                     {"native_intake_catalogue": {}, "native_run_configuration_catalogue": {}}, None)
        bootstrap = SimpleNamespace(sha256="a" * 64, value={"ledger_path": str(self.next_bank), "cells": {}})
        barrier = Barrier(2, timeout=5)
        class Projected(Exception):
            pass
        def revalidate():
            barrier.wait()
            with self.assertRaises(Projected):
                factory._continuation_origin_absent(bootstrap, qualified)
        with (self.fixture.path / "lock").open("rb") as original, \
                mock.patch.object(factory, "_continuation_catalogue", side_effect=Projected), ThreadPoolExecutor(max_workers=2) as pool:
            fcntl.flock(original, fcntl.LOCK_SH | fcntl.LOCK_NB)
            readers = [pool.submit(revalidate) for _ in range(2)]
            for reader in readers:
                reader.result()
        self.assertEqual((self.fixture.path / "state.json").read_bytes(), self.fixture.raw)

    def test_alias_to_same_bank_is_rejected_by_inode(self):
        real = factory.installation._open_directory
        def open_directory(path):
            return real(str(self.fixture.path) if path == str(self.next_bank) else path)
        with mock.patch.object(factory.installation, "_open_directory", side_effect=open_directory):
            with self.assertRaisesRegex(Denied, "aliased-original-bank"):
                self.collect()
        self.observe.assert_not_called()

    def test_resource_returning_on_second_projection_stops_collection(self):
        self.observe.side_effect = [None, None, Denied("continuation-ninth-original-resource-returned")]
        with self.assertRaisesRegex(Denied, "resource-returned"):
            self.collect()
        self.assertEqual(self.observe.call_count, 3)

    def test_catalogue_change_between_projections_is_rejected(self):
        def change(*args):
            if self.observe.call_count == 2:
                (self.fixture.root / "intake" / ("f" * 64)).touch()
        self.observe.side_effect = change
        with self.assertRaisesRegex(Denied, "extra-catalogue-entry"):
            self.collect()


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class NinthRealPrivateJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=validated_fixture_parent(Path("/run/proof"), private=True))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fixed = deepcopy(cells.NINTH_RETIRED_PARTIAL)
        for group in ("native_journal", "prior_journal"):
            parent = self.root / group; parent.mkdir(mode=0o700)
            values = {}
            for leaf in self.fixed[group]["members"]:
                value = {"operation": "ab89fd156df44bcca52d9be9f697f6fb"}
                if leaf == "complete-receipt.json":
                    value.update(retention_deadline=self.fixed["retain_until"], at=1795063199.6655662,
                        original_unknown_resolved=False, prior_retirement_unknown_preserved=True,
                        native_case_acceptance=False, all_original_paths_absent=True,
                        own_project_bridge_absent=True, owned_namespace_alias_mounts_absent=True)
                elif leaf.endswith("-receipt.json"):
                    value.update(state="separate-effect-verified", original_unknown_resolved=False)
                values[leaf] = self.write(parent / leaf, value)
            self.fixed[group] = {"path": str(parent), "members": values}
        for name in ("certificate_receipt", "veth_receipt"):
            path = self.root / (name + ".json")
            sha = self.write(path, {"original_unknown_resolved": False,
                "metadata": {"lease_id": self.fixed["original_record"]["lease_id"],
                             "original_record_sha256": self.fixed["original_record"]["sha256"]}})
            self.fixed[name] = {"path": str(path), "sha256": sha}
        patcher = mock.patch.object(cells, "NINTH_RETIRED_PARTIAL", self.fixed)
        patcher.start(); self.addCleanup(patcher.stop)

    def write(self, path, value):
        raw = ledger.canonical(value) + b"\n"
        path.write_bytes(raw); path.chmod(0o600)
        return hashlib.sha256(raw).hexdigest()

    def test_actual_root_private_files_require_all_members_and_canonical_newline(self):
        result = factory._ninth_preserved_journals()
        self.assertEqual(result, {key: self.fixed[key] for key in (
            "native_journal", "prior_journal", "certificate_receipt", "veth_receipt")})
        self.assertEqual(len(result["native_journal"]["members"]), 17)

    def test_prior_unknown_member_cannot_disappear(self):
        (Path(self.fixed["prior_journal"]["path"]) / "namespace-mount88-unknown.json").unlink()
        with self.assertRaisesRegex(Denied, "journal-member-scope"):
            factory._ninth_preserved_journals()

    def test_replaced_complete_file_or_extra_member_is_not_accepted(self):
        parent = Path(self.fixed["native_journal"]["path"])
        self.write(parent / "complete-receipt.json", {"operation": "foreign"})
        with self.assertRaisesRegex(Denied, "journal-member-drift"):
            factory._ninth_preserved_journals()

    def test_noncanonical_receipt_bytes_deny_even_with_mode_and_semantic_fields(self):
        path = Path(self.fixed["veth_receipt"]["path"])
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaises(Denied):
            factory._ninth_preserved_journals()


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class NinthOriginalEntryReaderTests(unittest.TestCase):
    def test_real_complete_entry_reader_keeps_fixed_mapping_separate_from_receipt_digest(self):
        from contextlib import ExitStack
        from test_github_runner_incus_operating_eighth_prelease_continuation import EighthCompleteStageTests
        stage = EighthCompleteStageTests("runTest")
        self.addCleanup(stage.doCleanups)
        stage.setUp()
        old = factory.load_bootstrap(stage.original["path"], stage.original["sha256"])
        expected = {key: stage.prefix[key] for key in ("configuration", "intake")}
        fixed = deepcopy(cells.NINTH_RETIRED_PARTIAL); fixed.update(expected)
        with ExitStack() as stack:
            for name, value in {
                "NINTH_RETIRED_PARTIAL": fixed, "NINTH_MAIN": cells.EIGHTH_MAIN,
                "NINTH_REUSABLE": cells.EIGHTH_REUSABLE, "NINTH_RUN": cells.EIGHTH_RUN,
                "NINTH_JOB": cells.EIGHTH_JOB,
            }.items():
                stack.enter_context(mock.patch.object(cells, name, value))
            for revalidating in (False, True):
                entries, config, receipt = factory._ninth_original_entries(old, revalidating=revalidating)
                self.assertEqual(entries, expected)
                self.assertEqual(config.manifest_sha256, expected["configuration"]["receipt_sha256"])
                self.assertEqual(receipt["invocation"]["job_id"], cells.EIGHTH_JOB)


class NinthNativeDispatchTests(unittest.TestCase):
    def test_whole_native_dispatch_preserves_eight_then_checks_ninth(self):
                from contextlib import ExitStack
                from types import SimpleNamespace as NS
                import base64
                import hashlib
                import socket
                from test_github_runner_incus_operating_sixth_factory import SixthFactoryTests
                history_helper = SixthFactoryTests()
                self.addCleanup(history_helper.doCleanups)
                fifth = history_helper.previous_history_model()
                four = fifth["previous_qualification"]; three = four["previous_qualification"]
                two = three["previous_qualification"]; legacy = two["legacy_qualification"]
                six = {"previous_qualification": fifth, "native_sixth": {"model": "sixth"}}
                from test_github_runner_incus_operating_seventh_prelease_continuation import native as seventh_native
                seven = {"previous_qualification": six, "native_seventh": cells.seventh_native_projection(*seventh_native())}
                from test_github_runner_incus_operating_eighth_prelease_continuation import native as eighth_native
                eight = {"previous_qualification": seven, "native_eighth": cells.eighth_native_projection(*eighth_native())}
                receipt = {"previous_qualification": eight, "native_ninth": cells.ninth_native_projection(*native())}
                successor = {"source_sha": "e" * 40, "run_id": cells.NINTH_RUN + 1, "reusable_sha": "f" * 40}
                qualified = ({"schema": 9, "successor": successor}, receipt, {}, None)
                raw = b"modeled-future-workflow-not-publication"
                worker = ledger.Worker(995, 78, 1234, 5678, "12345678-1234-4234-8234-123456789abc")
                selected = NS(bootstrap=NS(collector=object(), value={
                                  "source_workflow_sha256": hashlib.sha256(raw).hexdigest(),
                                  "source_identity": {"runner_id": worker.runner_id, "service_uid": worker.uid}}),
                              identity=NS(required_native_job_name="modeled-native-job"), template_bytes=b"{}")
                who = NS(caller_sha=successor["source_sha"], run_id=successor["run_id"], reusable_sha=successor["reusable_sha"], job_id=123)
                job_state = {"status": "in_progress", "cancel_on_workflow": False}
                def get(url, **kwargs):
                    if "/contents/" in url:
                        if job_state["cancel_on_workflow"]:
                            job_state["status"] = "completed"
                        return ledger.canonical({"type": "file", "path": ".github/workflows/collection-ci.yml", "encoding": "base64", "content": base64.b64encode(raw).decode(), "size": len(raw)})
                    if "/actions/jobs/" in url:
                        return ledger.canonical({"id": 123, "run_id": who.run_id, "head_sha": who.caller_sha, "status": job_state["status"], "conclusion": None, "name": "modeled-native-job", "started_at": "2026-11-16T23:18:15Z"})
                    return ledger.canonical({"sha": who.caller_sha, "parents": [{"sha": cells.NINTH_MAIN}]})
                order, completed = [], []
                expected_history = ["origin", "prior", "third", "fourth", "fifth", "sixth", "seventh", "eighth", "ninth"]
                def older(get, *, prior=False):
                    label = "prior" if prior else "origin"
                    order.append(label); completed.append(label)
                    return two["native_prior"] if prior else legacy["native_origin"]
                def historical(label, value):
                    def read(get):
                        order.append(label); completed.append(label); return value
                    return read
                def barrier(label):
                    self.assertCountEqual(completed, expected_history)
                    order.append(label)
                def finish_worker(*args):
                    barrier("worker-finish")
                    return worker
                original_threads = set(threading.enumerate())
                def check_origin_absent(*args):
                    self.assertEqual(set(threading.enumerate()), original_threads)
                    barrier("fresh-absence")
                history_submissions = []
                class RecordingPool(factory.ThreadPoolExecutor):
                    def submit(self, helper, *args, **kwargs):
                        if helper is factory._continuation_ninth_native or helper is factory._continuation_original_native:
                            history_submissions.append(helper)
                        return super().submit(helper, *args, **kwargs)

                with ExitStack() as stack:
                    stack.enter_context(mock.patch.object(factory, "ThreadPoolExecutor", RecordingPool))
                    connected, peer = socket.socketpair()
                    stack.callback(connected.close)
                    stack.callback(peer.close)
                    # Provider and kernel acquisition remain explicitly modeled. The
                    # integrated native entry still checks a real connected Unix socket.
                    begin = mock.Mock(side_effect=lambda *_: (worker, object()))
                    finish = mock.Mock(side_effect=finish_worker)
                    discard = mock.Mock()
                    for obj, name, value in [
                        (factory.admission, "_secret", lambda _: None), (factory, "_controls", lambda _: "controls"),
                        (factory.collector, "begin_worker_acquisition", begin),
                        (factory.collector, "finish_worker_acquisition", finish),
                        (factory.collector, "discard_worker_acquisition", discard),
                        (factory.identity, "verify_github_workflow_assignment", lambda *a, **k: (who, json.loads(get("/contents/.github/workflows/collection-ci.yml?ref=" + who.caller_sha)))),
                        (factory.identity, "HTTPSReader", lambda **_: NS(read=get)),
                        (factory, "_continuation_receipt", lambda _: qualified),
                        (factory, "_continuation_original_native", older),
                        (factory, "_continuation_third_native", historical("third", three["native_third"])),
                        (factory, "_continuation_fourth_native", historical("fourth", four["native_fourth"])),
                        (factory, "_continuation_fifth_native", historical("fifth", fifth["native_fifth"])),
                        (factory, "_continuation_sixth_native", historical("sixth", six["native_sixth"])),
                        (factory, "_continuation_seventh_native", historical("seventh", seven["native_seventh"])),
                        (factory, "_continuation_eighth_native", historical("eighth", eight["native_eighth"])),
                        (factory, "_continuation_ninth_native", historical("ninth", receipt["native_ninth"])),
                        (factory, "_continuation_origin_absent", check_origin_absent),
                        (cells, "validate_continuation_commit", lambda *_: barrier("current-commit"))]:
                        stack.enter_context(mock.patch.object(obj, name, value))
                    factory._native(connected, selected, "nonce", "modeled-auth", "modeled-api")
                    self.assertIs(history_submissions[0], factory._continuation_ninth_native)
                    self.assertCountEqual(order[:-3], expected_history)
                    self.assertEqual(order[-3:], ["fresh-absence", "current-commit", "worker-finish"])
                    order.clear(); completed.clear(); expected_history.clear()
                    factory._native(connected, selected, "nonce", "modeled-auth", "modeled-api", check_origin=False)
                    self.assertEqual(order, ["fresh-absence", "current-commit", "worker-finish"])
                    self.assertEqual((begin.call_count, finish.call_count, discard.call_count), (2, 2, 2))
                    self.assertTrue(all(call.args[0] is connected for call in begin.call_args_list))
                    job_state["cancel_on_workflow"] = True
                    with self.assertRaisesRegex(Denied, "bootstrap-native-job"):
                        factory._native(connected, selected, "nonce", "modeled-auth", "modeled-api", check_origin=False)
                    self.assertEqual(finish.call_count, 2)



    def test_unbound_live_descriptor_denies_and_modeled_pins_keep_exact_first_parent_attempt(self):
        value = {"schema": 9, "reason": "original-partial-preparation-separately-retired-unknown-preserved",
                 "qualification": {"path": "/qualified/ninth.json", "sha256": "9" * 64},
                 "successor": {"source_sha": "a" * 40, "run_id": cells.NINTH_RUN + 1, "run_attempt": 1,
                    "first_parent": cells.NINTH_MAIN, "source_workflow_sha256": "b" * 64, "reusable_sha": "c" * 40}}
        with mock.patch.object(cells, "NINTH_SUCCESSOR_WORKFLOW", None), \
             mock.patch.object(cells, "NINTH_SUCCESSOR_REUSABLE", None):
            with self.assertRaisesRegex(Denied, "successor-pins-unbound"):
                cells.validate_continuation_descriptor(value, "b" * 64, "c" * 40)
        with mock.patch.object(cells, "NINTH_SUCCESSOR_WORKFLOW", "b" * 64), \
             mock.patch.object(cells, "NINTH_SUCCESSOR_REUSABLE", "c" * 40):
            self.assertEqual(cells.validate_continuation_descriptor(value, "b" * 64, "c" * 40), value)
            cells.validate_continuation_commit({"sha": "a" * 40, "parents": [{"sha": cells.NINTH_MAIN}]},
                value, "a" * 40, cells.NINTH_RUN + 1, "c" * 40)
            for key, bad in (("run_attempt", 2), ("run_attempt", True), ("source_sha", cells.NINTH_MAIN),
                             ("run_id", cells.NINTH_RUN), ("first_parent", cells.EIGHTH_MAIN),
                             ("source_workflow_sha256", cells.NINTH_WORKFLOW), ("reusable_sha", cells.NINTH_REUSABLE)):
                changed = deepcopy(value); changed["successor"][key] = bad
                with self.subTest(key=key), self.assertRaises(Denied):
                    cells.validate_continuation_descriptor(changed, "b" * 64, "c" * 40)
        workflow = cells.NINTH_SUCCESSOR_WORKFLOW
        reusable = cells.NINTH_SUCCESSOR_REUSABLE
        live = deepcopy(value)
        live["successor"].update(source_workflow_sha256=workflow, reusable_sha=reusable)
        self.assertEqual(cells.validate_continuation_descriptor(live, workflow, reusable), live)
        with self.assertRaises(Denied):
            cells.validate_continuation_descriptor(live, workflow, cells.NINTH_REUSABLE)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class NinthCurrentCatalogueTests(unittest.TestCase):
    def test_retired_partial_is_never_loaded_as_current_and_unknown_extra_holds(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory(dir=validated_fixture_parent(Path("/run/proof"), private=True)) as temporary:
            root = Path(temporary)
            retired, current, unknown = "a" * 64, "b" * 64, "c" * 64
            (root / retired).mkdir(mode=0o700); (root / current).mkdir(mode=0o700)
            qualified = ({"schema": 9}, {"retirement": {"catalogues": {
                "native_run_configuration_catalogue": {retired: "d" * 64}}}}, {}, None)
            bootstrap = SimpleNamespace(value={})
            fd = factory.installation._open_directory(str(root))
            def read(directory):
                if directory.name != current:
                    raise Denied("unqualified-extra-or-retired-entry-read")
                return "current-configuration", "current-receipt"
            try:
                with mock.patch.object(factory, "ROOT", str(root)), \
                     mock.patch.object(factory, "_continuation_receipt", return_value=qualified), \
                     mock.patch.object(factory, "_continuation_origin_absent") as absence, \
                     mock.patch.object(factory, "_read_complete", side_effect=read) as complete:
                    self.assertEqual(factory._current_configuration_catalogue(bootstrap, fd),
                                     [("current-configuration", "current-receipt")])
                    self.assertEqual(absence.call_count, 2)
                    complete.assert_called_once_with(root / current)
                    (root / unknown).mkdir(mode=0o700)
                    with self.assertRaisesRegex(Denied, "unqualified-extra"):
                        factory._current_configuration_catalogue(bootstrap, fd)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
