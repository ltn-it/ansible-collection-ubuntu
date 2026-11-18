"""Exact original staged prelease history; future source tuple remains unbound."""
from copy import deepcopy
from contextlib import ExitStack
from dataclasses import asdict
import hashlib
import os
import shutil
import tempfile
from types import SimpleNamespace as NS
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import operating_cells as cells, ledger, run_factory as factory
from incus_lease_issuer.identity import Denied


def native():
    graph = json.loads((Path(__file__).parent / "fixtures/g06-seventh-failed-native-graph.json").read_bytes())
    run = graph["run"]
    run["repository"] = {"id": 1103407173, "full_name": factory.SOURCE, "private": False, "owner": {"id": 54334171}}
    run["referenced_workflows"] = [{"sha": cells.SEVENTH_REUSABLE,
        "path": "ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@" + cells.SEVENTH_REUSABLE}]
    inventory = {"total_count": 24, "jobs": graph["jobs"]}
    checks = []
    for identifier in cells.SEVENTH_CHECKS:
        job = next(row for row in graph["jobs"] if row["id"] == identifier)
        checks.append({"id": identifier, "head_sha": cells.SEVENTH_MAIN,
            **{key: job[key] for key in ("name", "status", "conclusion", "started_at", "completed_at")},
            "app": {"id": 15368, "slug": "github-actions"}})
    return run, inventory, checks


class SeventhPreleaseHistoryTests(unittest.TestCase):
    def descriptor(self):
        return {"schema": 7, "reason": "original-staged-prelease-expired-no-lease",
                "qualification": {"path": "/qualified/seventh.json", "sha256": "9" * 64},
                "successor": {"source_sha": "a" * 40, "run_id": cells.SEVENTH_RUN + 1,
                    "run_attempt": 1, "first_parent": cells.SEVENTH_MAIN,
                    "source_workflow_sha256": "b" * 64, "reusable_sha": "c" * 40}}

    def prefix(self):
        return {"schema": 1, "kind": "original-seventh-staged-prelease-no-lease-preserved",
            "original_bootstrap": {"path": "/sealed/original/bootstrap.json", "sha256": cells.SEVENTH_BOOTSTRAP},
            "original_bank": {"path": "/sealed/oidc-config-successor-b260217d0b354c5fa44493c092c45200/ledger",
                **dict(zip(("device", "inode"), cells.SEVENTH_BANK_IDENTITY))},
            "configuration": {"name": cells.SEVENTH_CONFIGURATION,
                **dict(zip(("device", "inode"), cells.SEVENTH_CONFIGURATION_IDENTITY)),
                "receipt_sha256": cells.SEVENTH_CONFIG_INTENT, "inventory_sha256": cells.SEVENTH_CONFIGURATION_INVENTORY},
            "intake": {"name": cells.SEVENTH_INTAKE,
                **dict(zip(("device", "inode"), cells.SEVENTH_INTAKE_IDENTITY)),
                "receipt_sha256": cells.SEVENTH_INTAKE_RECEIPT, "inventory_sha256": cells.SEVENTH_INTAKE_INVENTORY},
            "catalogues": {"native_run_configuration_catalogue": {cells.SEVENTH_CONFIGURATION: cells.SEVENTH_CONFIGURATION_INVENTORY},
                           "native_intake_catalogue": {cells.SEVENTH_INTAKE: cells.SEVENTH_INTAKE_INVENTORY}}}

    def test_prefix_is_bound_to_original_identities_and_bytes(self):
        value = self.prefix()
        self.assertEqual(cells._validate_seventh_failed_prefix(value), value)
        for section, field, bad in (("configuration", "inode", cells.SEVENTH_CONFIGURATION_IDENTITY[1] + 1),
                ("configuration", "inventory_sha256", "0" * 64),
                ("intake", "inode", cells.SEVENTH_INTAKE_IDENTITY[1] + 1),
                ("original_bank", "inode", cells.SEVENTH_BANK_IDENTITY[1] + 1), ("intake", "receipt_sha256", "0" * 64),
                ("original_bank", "device", True), ("original_bank", "inode", 1313166.0),
                ("original_bootstrap", "sha256", "0" * 64)):
            changed = deepcopy(value); changed[section][field] = bad
            with self.subTest(section=section, field=field), self.assertRaises(Denied):
                cells._validate_seventh_failed_prefix(changed)

    def test_original_native_full_graph_and_all_three_checks(self):
        run, inventory, checks = native()
        graph = cells.seventh_native_projection(run, inventory, checks)
        self.assertEqual(ledger.digest(graph), cells.SEVENTH_GRAPH)
        for mutate in (lambda r, i, c: i["jobs"].pop(),
                       lambda r, i, c: c[1].update(conclusion="success"),
                       lambda r, i, c: r.update(run_attempt=2),
                       lambda r, i, c: r["actor"].update(id=1),
                       lambda r, i, c: c[0]["app"].update(slug="foreign")):
            r, i, c = deepcopy((run, inventory, checks)); mutate(r, i, c)
            with self.subTest(mutate=mutate), self.assertRaises(Denied):
                cells.seventh_native_projection(r, i, c)

    def test_future_pins_are_required_and_never_authorize_same_original(self):
        d = self.descriptor()
        with self.assertRaises(Denied):
            cells.validate_continuation_descriptor(d, "b" * 64, "c" * 40)
        with mock.patch.object(cells, "SEVENTH_SUCCESSOR_WORKFLOW", "b" * 64), mock.patch.object(cells, "SEVENTH_SUCCESSOR_REUSABLE", "c" * 40):
            self.assertEqual(cells.validate_continuation_descriptor(d, "b" * 64, "c" * 40), d)
            for key, value in (("run_attempt", 2), ("run_attempt", True), ("source_sha", cells.SEVENTH_MAIN),
                               ("run_id", cells.SEVENTH_RUN), ("first_parent", cells.SIXTH_MAIN),
                               ("source_workflow_sha256", cells.SEVENTH_WORKFLOW), ("reusable_sha", cells.SEVENTH_REUSABLE)):
                bad = deepcopy(d); bad["successor"][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(Denied):
                    cells.validate_continuation_descriptor(bad, "b" * 64, "c" * 40)

    def test_native_reader_rechecks_complete_inventory(self):
        run, inventory, checks = native()
        base = "/actions/runs/" + str(cells.SEVENTH_RUN)
        path = base + "/attempts/1/jobs?per_page=100&page=1"
        rows = {base: run, path: inventory,
                **{"/check-runs/" + str(v["id"]): v for v in checks}}
        called = []
        def get(p):
            called.append(p); return deepcopy(rows[p])
        self.assertEqual(factory._continuation_seventh_native(get), cells.seventh_native_projection(run, inventory, checks))
        self.assertEqual(called.count(path), 2)
        called.clear()
        def drift(p):
            value = get(p)
            if p == path and called.count(path) > 1: value["jobs"][0]["conclusion"] = "foreign"
            return value
        with self.assertRaises(Denied): factory._continuation_seventh_native(drift)

    def test_whole_native_dispatch_preserves_six_then_checks_seventh(self):
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
        receipt = {"previous_qualification": six, "native_seventh": cells.seventh_native_projection(*native())}
        successor = {"source_sha": "e" * 40, "run_id": cells.SEVENTH_RUN + 1, "reusable_sha": "f" * 40}
        qualified = ({"schema": 7, "successor": successor}, receipt, {}, None)
        raw = b"modeled-future-workflow-not-publication"
        worker = ledger.Worker(995, 78, 1234, 5678, "12345678-1234-4234-8234-123456789abc")
        selected = NS(bootstrap=NS(collector=object(), value={
                          "source_workflow_sha256": hashlib.sha256(raw).hexdigest(),
                          "source_identity": {"runner_id": worker.runner_id, "service_uid": worker.uid}}),
                      identity=NS(required_native_job_name="modeled-native-job"), template_bytes=b"{}")
        who = NS(caller_sha=successor["source_sha"], run_id=successor["run_id"], reusable_sha=successor["reusable_sha"], job_id=123)
        def get(url, **kwargs):
            if "/contents/" in url:
                return ledger.canonical({"type": "file", "path": ".github/workflows/collection-ci.yml", "encoding": "base64", "content": base64.b64encode(raw).decode(), "size": len(raw)})
            if "/actions/jobs/" in url:
                return ledger.canonical({"id": 123, "run_id": who.run_id, "head_sha": who.caller_sha, "status": "in_progress", "conclusion": None, "name": "modeled-native-job", "started_at": "2026-11-16T23:18:15Z"})
            return ledger.canonical({"sha": who.caller_sha, "parents": [{"sha": cells.SEVENTH_MAIN}]})
        order, completed = [], []
        expected_history = ["origin", "prior", "third", "fourth", "fifth", "sixth", "seventh"]
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
        with ExitStack() as stack:
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
                (factory.identity, "verify_github_assignment", lambda *a, **k: who),
                (factory.identity, "HTTPSReader", lambda: NS(read=get)),
                (factory, "_continuation_receipt", lambda _: qualified),
                (factory, "_continuation_original_native", older),
                (factory, "_continuation_third_native", historical("third", three["native_third"])),
                (factory, "_continuation_fourth_native", historical("fourth", four["native_fourth"])),
                (factory, "_continuation_fifth_native", historical("fifth", fifth["native_fifth"])),
                (factory, "_continuation_sixth_native", historical("sixth", six["native_sixth"])),
                (factory, "_continuation_seventh_native", historical("seventh", receipt["native_seventh"])),
                (factory, "_continuation_origin_absent", lambda *_: barrier("fresh-absence")),
                (cells, "validate_continuation_commit", lambda *_: barrier("current-commit"))]:
                stack.enter_context(mock.patch.object(obj, name, value))
            factory._native(connected, selected, "nonce", "modeled-auth", "modeled-api")
            self.assertCountEqual(order[:-3], expected_history)
            self.assertEqual(order[-3:], ["fresh-absence", "current-commit", "worker-finish"])
            order.clear(); completed.clear(); expected_history.clear()
            factory._native(connected, selected, "nonce", "modeled-auth", "modeled-api", check_origin=False)
            self.assertEqual(order, ["fresh-absence", "current-commit", "worker-finish"])
            self.assertEqual((begin.call_count, finish.call_count, discard.call_count), (2, 2, 2))
            self.assertTrue(all(call.args[0] is connected for call in begin.call_args_list))


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class SeventhStagedCatalogueTests(unittest.TestCase):
    """Real prefix/catalogue/Ledger reads; older closed proofs and constants are modeled.

    No native authorization or historical host identity is manufactured. Fixture
    constants bind the real temporary inode/hash values; all seventh filesystem
    projection and current-successor catalogue checks execute unchanged.
    """

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = tempfile.TemporaryDirectory(dir="/run/proof", prefix="seventh-stage-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.configs = self.root / "configurations"
        self.intakes = self.root / "intakes"
        self.configs.mkdir(mode=0o700)
        self.intakes.mkdir(mode=0o700)
        self.stack.enter_context(mock.patch.object(factory, "ROOT", str(self.configs)))
        self.stack.enter_context(mock.patch.object(factory.run_intake, "ROOT", str(self.intakes)))
        self.old_bank = self.root / "oidc-config-successor-b260217d0b354c5fa44493c092c45200" / "ledger"
        self.old_bank.parent.mkdir(mode=0o700)
        self.old_bank.mkdir(mode=0o700)
        self.bank = self.root / "successor-bank"
        self.bank.mkdir(mode=0o700)
        for path in (self.old_bank, self.bank):
            ledger.Ledger.initialize(str(path))
        self.bootstrap = NS(value={"ledger_path": str(self.bank), "cells": {"next": {"native_job_name": "Heavy fixture"}}},
                            sha256="b" * 64)
        self.successor = {"source_sha": "a" * 40, "run_id": 501, "reusable_sha": "b" * 40}
        self.descriptor = {"schema": 7, "successor": self.successor}
        self.real_load_bootstrap = factory.load_bootstrap
        self.configure_history()

    def write(self, path, value):
        path.write_bytes(ledger.canonical(value))
        path.chmod(0o600)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def configure_history(self):
        from test_github_runner_incus_generation_publisher import git_input
        from incus_lease_issuer import generation_acquisition as acquisition
        prior, retired = {}, {}
        for kind, parent, name in (("native_run_configuration_catalogue", self.configs, "1" * 64),
                                    ("native_intake_catalogue", self.intakes, "2" * 64)):
            old = parent / name
            old.mkdir(mode=0o700)
            self.write(old / "intent.json", {"fixture": "previous closed history"})
            self.write(old / "sealed-inventory.json", {"fixture": "preserved seal"})
            prior[kind] = {name: factory._fifth_retired_entry(old)}
            newer = parent / ("3" * 64)
            newer.mkdir(mode=0o700)
            self.write(newer / "intent.json", {"fixture": "sixth closed history"})
            retired[kind] = {**prior[kind], newer.name: factory._fifth_retired_entry(newer)}
        self.history = {"retirement": {"catalogues": retired},
                        "previous_qualification": {"retirement": {"catalogues": prior}}}
        self.old_config = self.configs / cells.SEVENTH_CONFIGURATION
        self.old_config.mkdir(mode=0o700)
        for name in ("trees", "archives"):
            (self.old_config / name).mkdir(mode=0o700)
        for name in ("cell.json", "preparation.json", "registry.json", "runtime.json"):
            self.write(self.old_config / name, {"fixture": name})
        self.old_intake = self.intakes / cells.SEVENTH_INTAKE
        self.old_intake.mkdir(mode=0o700)
        source_raw, source = git_input(factory.SOURCE, 1103407173, cells.SEVENTH_MAIN, {"README.md": b"history"})
        controller_raw, controller = git_input(factory.VALIDATION, 1269461997, cells.SEVENTH_REUSABLE, {"README.md": b"controller"})
        artifact = acquisition.ArtifactRequest(cells.SEVENTH_RUN, 1, cells.SEVENTH_MAIN, 214182490,
            ".github/workflows/collection-ci.yml", 601, "fixture", "c" * 64, 8)
        acquired = acquisition.Acquisition(source, controller, artifact, "c" * 64, 8, "d" * 64)
        for name, raw in zip(factory.run_intake.ARCHIVES, (b"artifact", source_raw, controller_raw)):
            path = self.old_intake / name
            path.write_bytes(raw)
            path.chmod(0o600)
        binding = {"fixture": "immutable original intake"}
        intent_sha = self.write(self.old_intake / "intent.json", {"binding": binding,
            "original_job": {"run_id": cells.SEVENTH_RUN, "job_id": cells.SEVENTH_JOB, "check_run_id": cells.SEVENTH_JOB}})
        intake_sha = self.write(self.old_intake / "sealed.json", {"binding": binding, "intent_sha256": intent_sha,
            "snapshot": {"acquisition": asdict(acquired)}, "archive_stamps": {
                name: list(factory.installation._stamp((self.old_intake / name).stat())) for name in factory.run_intake.ARCHIVES}})
        config_sha = self.write(self.old_config / "intent.json", {"invocation": {
            "source_sha": cells.SEVENTH_MAIN, "reusable_sha": cells.SEVENTH_REUSABLE,
            "run_id": cells.SEVENTH_RUN, "run_attempt": 1, "job_id": cells.SEVENTH_JOB,
            "check_run_id": cells.SEVENTH_JOB, "bootstrap_sha256": cells.SEVENTH_BOOTSTRAP},
            "snapshot_receipt_sha256": intake_sha})
        constants = {"SEVENTH_PREVIOUS_QUALIFICATION": ledger.digest(self.history),
            "SEVENTH_CONFIG_INTENT": config_sha, "SEVENTH_INTAKE_RECEIPT": intake_sha,
            "SEVENTH_BANK_IDENTITY": (self.old_bank.stat().st_dev, self.old_bank.stat().st_ino),
            "SEVENTH_CONFIGURATION_IDENTITY": (self.old_config.stat().st_dev, self.old_config.stat().st_ino),
            "SEVENTH_INTAKE_IDENTITY": (self.old_intake.stat().st_dev, self.old_intake.stat().st_ino),
            "SEVENTH_CONFIGURATION_INVENTORY": factory._fifth_retired_entry(self.old_config),
            "SEVENTH_INTAKE_INVENTORY": factory._fifth_retired_entry(self.old_intake)}
        for name, value in constants.items():
            self.stack.enter_context(mock.patch.object(cells, name, value))
        # Earlier qualification decoding/native closure are already tested by
        # their own families; model only these external old-proof boundaries.
        self.stack.enter_context(mock.patch.object(cells, "_validate_sixth_preparation_qualification"))
        old = NS(sha256=cells.SEVENTH_BOOTSTRAP, value={"ledger_path": str(self.old_bank)})
        self.stack.enter_context(mock.patch.object(factory, "load_bootstrap", return_value=old))
        self.stack.enter_context(mock.patch.object(factory, "_continuation_receipt", return_value=(
            {"schema": 6, "successor": {"source_sha": cells.SEVENTH_MAIN, "run_id": cells.SEVENTH_RUN,
                                        "reusable_sha": cells.SEVENTH_REUSABLE}}, self.history)))
        self.old_fifth = self.stack.enter_context(mock.patch.object(factory, "_revalidate_fifth_retirement"))
        self.old_sixth = self.stack.enter_context(mock.patch.object(factory, "_revalidate_sixth_retirement"))
        self.original = {"path": str(self.root / "old-bootstrap.json"), "sha256": cells.SEVENTH_BOOTSTRAP}
        self.prefix = factory.collect_seventh_prelease_history(str(self.bank), self.original, self.history)
        self.counts = {kind: {"directory_device": parent.stat().st_dev, "directory_inode": parent.stat().st_ino}
            for kind, parent in (("native_intake_catalogue", self.intakes), ("native_run_configuration_catalogue", self.configs))}
        self.qualified = (self.descriptor, {"previous_qualification": self.history, "failed_prefix": self.prefix}, self.counts, None)
        self.preserved = {kind: {name: factory._fifth_retired_entry(parent / name) for name in names}
            for kind, parent, names in (("config", self.configs, self.prefix["catalogues"]["native_run_configuration_catalogue"]),
                                      ("intake", self.intakes, self.prefix["catalogues"]["native_intake_catalogue"]))}

    def check(self):
        factory._continuation_origin_absent(self.bootstrap, self.qualified)

    def stage(self, kind):
        if kind == "configuration":
            who = factory._invocation(self.bootstrap, "next", NS(run_id=self.successor["run_id"], job_id=551,
                check_run_id=651, caller_sha=self.successor["source_sha"], reusable_sha=self.successor["reusable_sha"]))
            name = ledger.digest({key: who[key] for key in ("repository", "run_id", "check_run_id", "selector")})
            value = {"schema": 1, "invocation": who, "snapshot_receipt_sha256": "c" * 64,
                "created_at": 1, "deadline": 2, "worker": {}, "job_started_at": 1, "template_sha256": "d" * 64}
            parent = self.configs
        else:
            binding = {"schema": 1, "identity_domain": {"repository": factory.SOURCE,
                "caller_sha": self.successor["source_sha"], "reusable_sha": self.successor["reusable_sha"]},
                "custody_policy_sha256": "d" * 64,
                "source": {"repository": factory.SOURCE, "repository_id": 1103407173, "commit_sha": self.successor["source_sha"]},
                "controller": {"repository": factory.VALIDATION, "repository_id": 1269461997, "commit_sha": self.successor["reusable_sha"]},
                "artifact": {"head_sha": self.successor["source_sha"], "run_id": self.successor["run_id"], "run_attempt": 1}}
            name = ledger.digest(binding)
            value = {"schema": 1, "binding": binding, "original_job": {"worker_sha256": "e" * 64,
                "run_id": self.successor["run_id"], "job_id": 551, "check_run_id": 651,
                "native_job_name": "Heavy fixture", "identity_policy_sha256": "f" * 64}}
            parent = self.intakes
        directory = parent / name
        directory.mkdir(mode=0o700)
        fd = factory.installation._open_directory(str(directory))
        try:
            factory.run_intake._write_at(fd, "intent.json", value)
        finally:
            os.close(fd)
        return directory, value

    def test_before_and_after_intake_configuration_or_both_revalidate(self):
        self.check()
        for kind in ("intake", "configuration"):
            self.stage(kind)
            self.check()
        for kind, parent in (("config", self.configs), ("intake", self.intakes)):
            self.assertEqual({name: factory._fifth_retired_entry(parent / name) for name in self.preserved[kind]},
                             self.preserved[kind])
        self.old_fifth.assert_called_with(self.history["previous_qualification"]["retirement"], str(self.bank))
        self.old_sixth.assert_called_with(self.history["retirement"], str(self.bank))

    def test_configuration_only_revalidates_but_strict_collection_still_denies_additions(self):
        self.stage("configuration")
        self.check()
        with self.assertRaisesRegex(Denied, "continuation-seventh-extra-catalogue-entry"):
            factory.collect_seventh_prelease_history(str(self.bank), self.original, self.history)

    def test_actual_intake_stager_revalidates_before_and_after_exclusive_creation(self):
        from test_github_runner_incus_run_intake import RootStageTests
        staged = RootStageTests("runTest")
        staged.setUp()
        self.addCleanup(staged.doCleanups)
        self.bootstrap.value["cells"]["next"]["native_job_name"] = staged.selected.identity.required_native_job_name
        observed = []
        def ticket(*args):
            # The real stager invokes current-native authentication on both
            # sides of mkdir, acquisition, and the full archive readback.
            self.check()
            observed.append(set(path.name for path in self.intakes.iterdir()))
            return staged.ticket(*args)
        with mock.patch.object(factory.run_intake, "ROOT", str(self.intakes)):
            self.check()
            result = staged.stage(ticket)
            self.check()
        self.assertEqual(Path(result.directory).parent, self.intakes)
        self.assertEqual(set(path.name for path in self.intakes.iterdir()),
                         set(self.prefix["catalogues"]["native_intake_catalogue"]) | {Path(result.directory).name})
        self.assertGreater(len(observed), 2)
        self.assertEqual(observed[0], set(self.prefix["catalogues"]["native_intake_catalogue"]))
        self.assertIn(Path(result.directory).name, observed[-1])

    def test_actual_configuration_creator_then_current_origin_revalidation(self):
        from test_github_runner_incus_run_factory import RootConfigurationTests
        RootConfigurationTests.setUpClass()
        created = RootConfigurationTests("runTest")
        # Its ordinary native and signed acquisition fixture remains separate
        # from modeled old qualification decoding. Config compilation, seal,
        # registry/readback and the final origin/catalogue check are real.
        with mock.patch.object(factory, "load_bootstrap", self.real_load_bootstrap), \
             mock.patch.object(factory, "_continuation_receipt", return_value=None):
            created.setUp()
        self.addCleanup(created.doCleanups)
        who = created.proof.identity
        self.successor.update(source_sha=who.caller_sha, run_id=who.run_id, reusable_sha=who.reusable_sha)
        self.bootstrap.sha256 = created.bootstrap.sha256
        self.bootstrap.value["cells"] = created.bootstrap.value["cells"]
        with mock.patch.object(factory, "ROOT", str(self.configs)), \
             mock.patch.object(factory.run_intake, "ROOT", str(self.intakes)), \
             mock.patch.object(factory, "_continuation_receipt", return_value=None), \
             mock.patch.object(factory, "load_bootstrap", self.real_load_bootstrap):
            result = created.create()
        with mock.patch.object(factory, "ROOT", str(self.configs)), \
             mock.patch.object(factory.run_intake, "ROOT", str(self.intakes)):
            self.check()
            self.assertEqual(Path(result.directory).parent, self.configs)
            self.assertEqual(factory._read_complete(Path(result.directory))[0], result)
            # The creator/readback alone missed the real failure: downstream
            # lookup must traverse current complete + authenticated old partial
            # together, preserving the entire older catalogue and empty bank.
            current = created.bootstrap
            before = {name: factory._fifth_retired_entry(self.configs / name)
                      for name in self.prefix["catalogues"]["native_run_configuration_catalogue"]}
            original_load = factory.load_bootstrap
            original_receipt = factory._continuation_receipt
            def load(path, sha):
                if (path, sha) == (current.path, current.sha256):
                    return current
                return original_load(path, sha)
            def qualified(value):
                if value["ledger_path"] == current.value["ledger_path"]:
                    return self.qualified
                return original_receipt(value)
            # External collector/control identity remains modeled, as in the
            # creator fixture; full retired filesystem/absence checks do not.
            with mock.patch.object(factory, "load_bootstrap", side_effect=load), \
                 mock.patch.object(factory, "_continuation_receipt", side_effect=qualified), \
                 mock.patch.object(factory, "_controls", return_value=created.proof.controls_sha256):
                self.assertEqual(factory.resolve_configuration(current, created.selector,
                    result.manifest_sha256), result)
                self.assertEqual(factory.find_existing_execution_configuration(current,
                    created.selector, created.proof), result)
                helper = created.helper
                helper.native.job["name"] = helper.value["cells"][created.selector]["native_observer_job_name"]
                helper.native.claims["check_run_id"] = "735"
                helper.native.job.update(id=906, check_run_url=factory.identity.API + "/repos/" + factory.SOURCE + "/check-runs/735")
                challenge = factory.challenge_bootstrap(helper.server, current, created.selector)
                helper.native.claims["aud"] = challenge["audience"]
                # This fixture models the historical native HTTP family, not
                # the registered observer proof or its fresh current signature.
                with mock.patch.object(factory, "_continuation_receipt", return_value=None):
                    observer = factory.verify_bootstrap_native(helper.server, current, created.selector,
                        challenge["nonce"], helper.native.token(), "synthetic-job-token", purpose="observer")
                self.assertEqual(factory.find_existing_configuration(current, created.selector, observer), result)
                unknown = self.configs / ("e" * 64)
                unknown.mkdir(mode=0o700)
                self.write(unknown / "intent.json", {"schema": 1})
                for read in (lambda: factory.resolve_configuration(current, created.selector, result.manifest_sha256),
                             lambda: factory.find_existing_configuration(current, created.selector, observer)):
                    with self.assertRaises(Denied): read()
            self.assertEqual({name: factory._fifth_retired_entry(self.configs / name) for name in before}, before)

    def catalogue(self):
        historical = factory._continuation_receipt
        def qualified(value):
            return self.qualified if value["ledger_path"] == str(self.bank) else historical(value)
        with mock.patch.object(factory, "_continuation_receipt", side_effect=qualified):
            root = factory.installation._open_directory(str(self.configs))
            try:
                return factory._current_configuration_catalogue(self.bootstrap, root)
            finally:
                os.close(root)

    def test_catalogue_authenticates_retired_partial_instead_of_reading_it_as_complete(self):
        self.assertEqual(self.catalogue(), [])
        self.assertFalse((self.old_config / "sealed-inventory.json").exists())
        self.old_fifth.assert_called()
        self.old_sixth.assert_called()

    def test_catalogue_never_skips_unsealed_current_or_unknown_entries(self):
        self.stage("configuration")
        with self.assertRaises(FileNotFoundError): self.catalogue()

    def test_catalogue_rejects_changed_retired_bytes_before_exclusion(self):
        self.write(self.old_config / "runtime.json", {"fixture": "changed retired runtime"})
        with self.assertRaises(Denied): self.catalogue()

    def test_catalogue_rechecks_retired_bytes_after_current_read(self):
        self.stage("configuration")
        def read(directory):
            self.write(self.old_config / "runtime.json", {"fixture": "history changed during current read"})
            return object(), {}
        with mock.patch.object(factory, "_read_complete", side_effect=read), self.assertRaises(Denied):
            self.catalogue()

    def test_catalogue_rejects_missing_retired_directory(self):
        self.old_config.rename(self.configs / ("f" * 64))
        with self.assertRaises((Denied, OSError)): self.catalogue()

    def test_foreign_successor_fields_and_names_deny(self):
        for kind in ("intake", "configuration"):
            directory, value = self.stage(kind)
            original = deepcopy(value)
            if kind == "configuration":
                cases = [("source_sha", "e" * 40), ("run_id", 502), ("reusable_sha", "f" * 40),
                         ("bootstrap_sha256", "a" * 64), ("run_attempt", 2)]
                target = "invocation"
            else:
                cases = [("run_id", 502)]
                target = "original_job"
            for key, bad in cases:
                changed = deepcopy(original)
                changed[target][key] = bad
                self.write(directory / "intent.json", changed)
                with self.subTest(kind=kind, key=key), self.assertRaises(Denied):
                    self.check()
            self.write(directory / "intent.json", original)
            if kind == "intake":
                for section, key, bad in (("source", "commit_sha", "e" * 40),
                        ("controller", "commit_sha", "f" * 40), ("artifact", "run_id", 502),
                        ("identity_domain", "caller_sha", "e" * 40)):
                    changed = deepcopy(original)
                    changed["binding"][section][key] = bad
                    renamed = directory.with_name(ledger.digest(changed["binding"]))
                    directory.rename(renamed)
                    self.write(renamed / "intent.json", changed)
                    with self.subTest(kind=kind, section=section, key=key), self.assertRaises(Denied):
                        self.check()
                    renamed.rename(directory)
                    self.write(directory / "intent.json", original)
            foreign = directory.with_name("e" * 64)
            directory.rename(foreign)
            with self.subTest(kind=kind, key="name"), self.assertRaises(Denied):
                self.check()
            foreign.rename(directory)
        self.check()

    def test_historical_missing_hash_seal_and_live_drift_deny(self):
        self.stage("configuration")
        old = self.configs / ("1" * 64)
        file = old / "sealed-inventory.json"
        original = file.read_bytes()
        self.write(file, {"fixture": "changed seal"})
        with self.assertRaises(Denied): self.check()
        file.write_bytes(original)
        # Even restored bytes have changed metadata; never adopt replacement.
        with self.assertRaises(Denied): self.check()

    def test_original_partial_must_remain_unsealed_and_exact(self):
        self.write(self.old_config / "sealed-inventory.json", {"fixture": "unauthorized completion"})
        with self.assertRaisesRegex(Denied, "continuation-seventh-partial-configuration-inventory"):
            self.check()

    def test_replaced_original_directory_with_identical_bytes_denies(self):
        preserved = self.old_intake.with_name("d" * 64)
        self.old_intake.rename(preserved)
        shutil.copytree(preserved, self.old_intake)
        with self.assertRaises(Denied): self.check()

    def test_historical_change_during_projection_is_not_adopted(self):
        real = factory._fifth_retired_entry
        changed = False
        def read(directory):
            nonlocal changed
            value = real(directory)
            if directory == self.old_intake and not changed:
                changed = True
                self.write(self.old_intake / "intent.json", {"fixture": "concurrent drift"})
            return value
        with mock.patch.object(factory, "_fifth_retired_entry", side_effect=read), self.assertRaises(Denied):
            self.check()
        self.assertTrue(changed)

    def test_unknown_catalogue_and_missing_historical_entry_deny(self):
        unknown = self.intakes / ("f" * 64)
        unknown.mkdir(mode=0o700)
        self.write(unknown / "intent.json", {"schema": 1})
        with self.assertRaises(Denied): self.check()
        (unknown / "intent.json").unlink()
        unknown.rmdir()
        missing = self.old_config.with_name("e" * 64)
        self.old_config.rename(missing)
        with self.assertRaises((Denied, OSError)): self.check()


if __name__ == "__main__":
    unittest.main()
