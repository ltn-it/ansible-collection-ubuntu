"""Exact complete prelease predecessor; no retry/adoption or native acceptance.

Native provider graphs are public historical fixtures. Root tests execute real
intake/config writers, archive readers, private files and Ledgers. Prior native
closure and provider responses are explicitly modeled; live proof stays native.
"""
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace as NS
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import operating_cells as cells, run_factory as factory, ledger
from incus_lease_issuer import generation_acquisition as acquisition
from incus_lease_issuer.identity import Denied


def native():
    graph = json.loads((Path(__file__).parent / "fixtures/g06-eighth-failed-native-graph.json").read_bytes())
    run = graph["run"]
    run["repository"] = {"id": 1103407173, "full_name": factory.SOURCE, "private": False, "owner": {"id": 54334171}}
    run["referenced_workflows"] = [{"sha": cells.EIGHTH_REUSABLE,
        "path": factory.VALIDATION + "/.github/workflows/collection-quality-profile-isolated.yml@" + cells.EIGHTH_REUSABLE}]
    checks = []
    for identifier in cells.EIGHTH_CHECKS:
        job = next(row for row in graph["jobs"] if row["id"] == identifier)
        checks.append({"id": identifier, "head_sha": cells.EIGHTH_MAIN,
            **{key: job[key] for key in ("name", "status", "conclusion", "started_at", "completed_at")},
            "app": {"id": 15368, "slug": "github-actions"}})
    return run, {"total_count": 24, "jobs": graph["jobs"]}, checks


class EighthPureHistoryTests(unittest.TestCase):
    def test_actual_complete_terminal_graph_and_all_three_checks(self):
        run, jobs, checks = native()
        self.assertEqual(ledger.digest(cells.eighth_native_projection(run, jobs, checks)), cells.EIGHTH_GRAPH)
        for mutate in (lambda r, j, c: j["jobs"].pop(),
                       lambda r, j, c: c[0].update(conclusion="success"),
                       lambda r, j, c: r.update(run_attempt=2),
                       lambda r, j, c: r["actor"].update(id=247824904),
                       lambda r, j, c: c[1]["app"].update(slug="foreign")):
            r, j, c = deepcopy((run, jobs, checks)); mutate(r, j, c)
            with self.subTest(mutate=mutate), self.assertRaises(Denied):
                cells.eighth_native_projection(r, j, c)

    def descriptor(self):
        return {"schema": 8, "reason": "original-complete-prelease-catalogue-reader-failed",
            "qualification": {"path": "/qualified/eighth.json", "sha256": "9" * 64},
            "successor": {"source_sha": "a" * 40, "run_id": cells.EIGHTH_RUN + 1, "run_attempt": 1,
                "first_parent": cells.EIGHTH_MAIN, "source_workflow_sha256": "b" * 64, "reusable_sha": "c" * 40}}

    def test_unpublished_future_pair_denies_and_model_pair_does_not_allow_old_run_or_attempt2(self):
        value = self.descriptor()
        with mock.patch.object(cells, "EIGHTH_SUCCESSOR_WORKFLOW", None), \
             mock.patch.object(cells, "EIGHTH_SUCCESSOR_REUSABLE", None), \
             self.assertRaisesRegex(Denied, "successor-pins-unbound"):
            cells.validate_continuation_descriptor(value, "b" * 64, "c" * 40)
        old_pair = (cells.SEVENTH_SUCCESSOR_WORKFLOW, cells.SEVENTH_SUCCESSOR_REUSABLE)
        with mock.patch.object(cells, "EIGHTH_SUCCESSOR_WORKFLOW", "b" * 64), \
             mock.patch.object(cells, "EIGHTH_SUCCESSOR_REUSABLE", "c" * 40):
            self.assertEqual(cells.validate_continuation_descriptor(value, "b" * 64, "c" * 40), value)
            for key, bad in (("run_attempt", 2), ("run_attempt", True), ("source_sha", cells.EIGHTH_MAIN),
                             ("run_id", cells.EIGHTH_RUN), ("first_parent", cells.SEVENTH_MAIN),
                             ("source_workflow_sha256", cells.EIGHTH_WORKFLOW), ("reusable_sha", cells.EIGHTH_REUSABLE)):
                changed = deepcopy(value); changed["successor"][key] = bad
                with self.subTest(key=key), self.assertRaises(Denied):
                    cells.validate_continuation_descriptor(changed, "b" * 64, "c" * 40)
            cells.validate_continuation_commit({"sha": "a" * 40, "parents": [{"sha": cells.EIGHTH_MAIN}]},
                value, "a" * 40, cells.EIGHTH_RUN + 1, "c" * 40)
        self.assertEqual((cells.SEVENTH_SUCCESSOR_WORKFLOW, cells.SEVENTH_SUCCESSOR_REUSABLE), old_pair)

    def test_native_inventory_is_re_read_without_an_effect(self):
        run, jobs, checks = native(); base = "/actions/runs/" + str(cells.EIGHTH_RUN)
        path = base + "/attempts/1/jobs?per_page=100&page=1"
        rows = {base: run, path: jobs, **{"/check-runs/" + str(v["id"]): v for v in checks}}
        calls = []
        def get(key):
            calls.append(key); return deepcopy(rows[key])
        self.assertEqual(factory._continuation_eighth_native(get), cells.eighth_native_projection(run, jobs, checks))
        self.assertEqual(calls.count(path), 2)
        calls.clear()
        def drift(key):
            result = get(key)
            if key == path and calls.count(path) > 1: result["jobs"].pop()
            return result
        with self.assertRaises(Denied): factory._continuation_eighth_native(drift)


    def test_whole_native_dispatch_preserves_seven_then_checks_eighth(self):
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
            receipt = {"previous_qualification": seven, "native_eighth": cells.eighth_native_projection(*native())}
            successor = {"source_sha": "e" * 40, "run_id": cells.EIGHTH_RUN + 1, "reusable_sha": "f" * 40}
            qualified = ({"schema": 8, "successor": successor}, receipt, {}, None)
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
                return ledger.canonical({"sha": who.caller_sha, "parents": [{"sha": cells.EIGHTH_MAIN}]})
            order, completed = [], []
            expected_history = ["origin", "prior", "third", "fourth", "fifth", "sixth", "seventh", "eighth"]
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
                    (factory, "_continuation_seventh_native", historical("seventh", seven["native_seventh"])),
                    (factory, "_continuation_eighth_native", historical("eighth", receipt["native_eighth"])),
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
class EighthCompleteStageTests(unittest.TestCase):
    def cleanup(self):
        # Close the outer bindings before the nested helpers restore theirs.
        # Reversing that order leaks the old modeled loader/engine into the
        # next case; it must not be papered over by weakening product readers.
        self.stack.close()
        if hasattr(self, "created"): self.created.doCleanups()
        if hasattr(self, "history"): self.history.doCleanups()

    def setUp(self):
        from test_github_runner_incus_operating_seventh_prelease_continuation import SeventhStagedCatalogueTests
        from test_github_runner_incus_run_factory import RootConfigurationTests
        self.stack = ExitStack(); self.addCleanup(self.cleanup)
        self.real_stage = factory.run_intake.stage_run_snapshot
        self.history = SeventhStagedCatalogueTests("runTest")
        self.history.setUp()
        RootConfigurationTests.setUpClass()
        self.created = RootConfigurationTests("runTest")
        with mock.patch.object(factory, "load_bootstrap", self.history.real_load_bootstrap), \
             mock.patch.object(factory, "_continuation_receipt", return_value=None):
            self.created.setUp()
        self.configs, self.intakes = self.history.configs, self.history.intakes
        self.stack.enter_context(mock.patch.object(factory, "ROOT", str(self.configs)))
        self.stack.enter_context(mock.patch.object(factory.run_intake, "ROOT", str(self.intakes)))
        old_parent = self.history.root / "oidc-config-successor-18aec68429f14f8ea94a90217f9ffe70"
        old_parent.mkdir(mode=0o700)
        self.old_bank = old_parent / "ledger"
        self.created.helper.store_path.rename(self.old_bank)
        self.created.helper.store_path = self.old_bank
        self.created.helper.value["ledger_path"] = str(self.old_bank)
        self.created.helper.native.claims["check_run_id"] = str(self.created.helper.native.job["id"])
        self.created.helper.native.job["check_run_url"] = (factory.identity.API + "/repos/" + factory.SOURCE
            + "/check-runs/" + str(self.created.helper.native.job["id"]))
        with mock.patch.object(factory, "load_bootstrap", self.history.real_load_bootstrap), \
             mock.patch.object(factory, "_continuation_receipt", return_value=None):
            self.created.helper.seal()
            self.created.bootstrap = self.created.helper.bootstrap
            self.created.proof, self.created.token = self.created.helper.mint()
            self.stage = self.stage_intake()
            self.created.snapshot = self.stage
            self.created.staged.return_value = self.stage
            self.configuration = self.created.create()
        immutable = old_parent / "immutable-bootstrap-locator-repair"
        immutable.mkdir(mode=0o700)
        self.original = {"path": str(immutable / "candidate-bootstrap.json"), "sha256": self.created.bootstrap.sha256}
        self.write(Path(self.original["path"]), self.created.bootstrap.value)
        old = self.history.real_load_bootstrap(self.original["path"], self.original["sha256"])
        who = self.created.proof.identity
        self.previous = {"schema": 7, "purpose": "modeled earlier native qualification; Root prefix reads remain real",
            "previous_qualification": self.history.history, "failed_prefix": self.history.prefix,
            "native_seventh": {"external native family": "modeled"}}
        self.counts = self.history.counts
        self.stack.enter_context(mock.patch.object(cells, "_validate_seventh_prelease_qualification", return_value=self.counts))
        constants = {"EIGHTH_PREVIOUS_QUALIFICATION": ledger.digest(self.previous),
            "EIGHTH_MAIN": who.caller_sha, "EIGHTH_REUSABLE": who.reusable_sha, "EIGHTH_RUN": who.run_id,
            "EIGHTH_JOB": who.job_id, "EIGHTH_BOOTSTRAP": old.sha256,
            "EIGHTH_BOOTSTRAP_IDENTITY": old.file_stamp[:2],
            "EIGHTH_BANK_IDENTITY": (self.old_bank.stat().st_dev, self.old_bank.stat().st_ino),
            "EIGHTH_CONFIGURATION": Path(self.configuration.directory).name,
            "EIGHTH_CONFIGURATION_IDENTITY": (Path(self.configuration.directory).stat().st_dev, Path(self.configuration.directory).stat().st_ino),
            "EIGHTH_INTAKE": Path(self.stage.directory).name,
            "EIGHTH_INTAKE_IDENTITY": (self.stage.device, self.stage.inode),
            "EIGHTH_CONFIG_RECEIPT": self.configuration.manifest_sha256,
            "EIGHTH_INTAKE_RECEIPT": self.stage.receipt_sha256,
            "EIGHTH_CONFIGURATION_INVENTORY": factory._fifth_retired_entry(Path(self.configuration.directory)),
            "EIGHTH_INTAKE_INVENTORY": factory._fifth_retired_entry(Path(self.stage.directory))}
        for name, value in constants.items(): self.stack.enter_context(mock.patch.object(cells, name, value))
        historical_load, historical_receipt = factory.load_bootstrap, factory._continuation_receipt
        def load(path, sha):
            if path == self.original["path"]: return self.history.real_load_bootstrap(path, sha)
            return historical_load(path, sha)
        def receipt(value):
            if value["ledger_path"] == str(self.old_bank):
                return ({"schema": 7, "successor": {"source_sha": who.caller_sha,
                    "run_id": who.run_id, "reusable_sha": who.reusable_sha}}, self.previous, self.counts, None)
            return historical_receipt(value)
        self.stack.enter_context(mock.patch.object(factory, "load_bootstrap", side_effect=load))
        self.stack.enter_context(mock.patch.object(factory, "_continuation_receipt", side_effect=receipt))
        self.next_bank = self.history.bank
        self.prefix = self.collect()
        self.successor = {"source_sha": "e" * 40, "run_id": who.run_id + 1, "reusable_sha": "f" * 40}
        self.next_bootstrap = NS(value={"ledger_path": str(self.next_bank),
            "cells": {"next": {"native_job_name": "Next exact fixture"}}}, sha256="e" * 64)
        self.qualified = ({"schema": 8, "successor": self.successor},
            {"previous_qualification": self.previous, "failed_prefix": self.prefix}, self.counts, None)

    def write(self, path, value):
        path.write_bytes(ledger.canonical(value)); path.chmod(0o600)

    def stage_intake(self):
        request = NS(source=acquisition.CommitRequest(self.created.pub.source.repository,
            self.created.pub.source.repository_id, self.created.pub.source.commit_sha),
            controller=acquisition.CommitRequest(self.created.pub.controller.repository,
            self.created.pub.controller.repository_id, self.created.pub.controller.commit_sha),
            artifact=self.created.snapshot.snapshot.acquisition.artifact)
        native = {"provider boundary": "modeled, never native acceptance"}
        proven = replace(self.created.snapshot.snapshot.acquisition,
            provenance_sha256=hashlib.sha256(repr(native).encode("ascii")).hexdigest())
        def acquire(*args, **kwargs):
            fds = [kwargs[key] for key in ("artifact_fd", "source_fd", "controller_fd")]
            for fd, raw in zip(fds, (self.created.pub.artifact_raw, self.created.pub.source_raw, self.created.pub.controller_raw)):
                os.write(fd, raw); os.fsync(fd)
            return factory.run_intake._validate_archives(proven,
                **dict(zip(("artifact_fd", "source_fd", "controller_fd"), fds)))
        def tree(commit, *args):
            row = proven.source if commit.repository == factory.SOURCE else proven.controller
            return row.tree_sha, row.files, row.directories
        # Use the original product writer captured before the outer fixture's
        # transport mock. Every durable write/archive/readback remains real.
        function = self.real_stage
        with mock.patch.object(factory.run_intake.admission, "require_intake_native", create=True,
                 return_value=(self.created.proof.worker, self.created.proof.identity, 240)), \
             mock.patch.object(factory.run_intake, "_native_request", return_value=request), \
             mock.patch.object(factory.run_intake, "acquire_run_snapshot", side_effect=acquire), \
             mock.patch.object(acquisition, "_tree", side_effect=tree), \
             mock.patch.object(acquisition, "_native", return_value=native):
            return function(self.created.proof, self.created.helper.server, self.created.proof.policy,
                            self.created.token, "synthetic-job-token")

    def collect(self):
        return factory.collect_eighth_prelease_history(str(self.history.bank), self.original, self.previous)

    def check(self):
        factory._continuation_origin_absent(self.next_bootstrap, self.qualified)

    def test_complete_history_is_preserved_and_current_catalogue_excludes_only_authenticated_retired(self):
        self.check()
        self.assertEqual(self.prefix["configuration"]["receipt_sha256"], self.configuration.manifest_sha256)
        self.assertTrue((Path(self.configuration.directory) / "sealed-inventory.json").exists())
        old = factory._continuation_receipt
        with mock.patch.object(factory, "_continuation_receipt", side_effect=lambda value:
                self.qualified if value["ledger_path"] == str(self.next_bank) else old(value)):
            fd = factory.installation._open_directory(str(self.configs))
            try: self.assertEqual(factory._current_configuration_catalogue(self.next_bootstrap, fd), [])
            finally: os.close(fd)
        self.assertEqual(self.collect(), self.prefix)

    def test_complete_seal_is_required_and_never_reconstructed(self):
        path = Path(self.configuration.directory) / "sealed-inventory.json"; path.unlink()
        with self.assertRaises((Denied, OSError)): self.check()
        self.assertFalse(path.exists())

    def test_strict_collection_semantically_checks_both_full_archive_passes(self):
        read = factory.run_intake._validate_archives
        with mock.patch.object(factory.run_intake, "_validate_archives", wraps=read) as parsed:
            self.assertEqual(self.collect(), self.prefix)
        self.assertEqual(parsed.call_count, 2)

    def test_revalidation_checks_every_original_archive_byte_without_reparsing_fixed_semantics(self):
        read = factory.run_intake._archive_bytes
        with mock.patch.object(factory.run_intake, "_archive_bytes", wraps=read) as reads, \
             mock.patch.object(factory.run_intake, "_validate_archives", side_effect=AssertionError("semantic parse after exact strict qualification")):
            self.check()
        self.assertGreaterEqual(reads.call_count, 3)

    def test_strict_collection_cannot_defer_its_catalogue_validation(self):
        with self.assertRaisesRegex(Denied, "catalogue-composition"):
            factory._eighth_failed_prefix_projection(str(self.next_bank), self.original,
                                                     self.previous, defer_catalogues=True)

    def require_outer_freshness(self, mutate):
        original = factory._eighth_failed_prefix_projection
        def projection(*args, **kwargs):
            value = original(*args, **kwargs)
            mutate()
            return value
        with mock.patch.object(factory, "_eighth_failed_prefix_projection", side_effect=projection):
            with self.assertRaises(Denied): self.check()

    def test_composed_origin_rejects_older_history_changed_after_prefix(self):
        path = self.history.old_config / "cell.json"
        self.require_outer_freshness(lambda: self.write(path, {"changed": "after prefix validation"}))

    def test_composed_origin_rejects_eighth_archive_changed_after_prefix(self):
        path = Path(self.stage.directory) / "source.tar.gz"
        self.require_outer_freshness(lambda: path.write_bytes(path.read_bytes() + b"changed after prefix"))

    def test_composed_origin_rejects_missing_history_after_prefix(self):
        self.require_outer_freshness(lambda: self.history.old_config.rename(self.history.root / "retired-moved"))

    def test_composed_origin_rejects_catalogue_root_replaced_after_prefix(self):
        def replace_root():
            self.configs.rename(self.history.root / "configurations-old")
            self.configs.mkdir(mode=0o700)
        self.require_outer_freshness(replace_root)

    def test_composed_origin_rejects_unknown_entry_after_prefix(self):
        def add_unknown():
            path = self.configs / ("a" * 64)
            path.mkdir(mode=0o700)
            self.write(path / "intent.json", {"schema": 1})
        self.require_outer_freshness(add_unknown)

    def test_replaced_archive_with_identical_bytes_fails_original_stamp(self):
        path = Path(self.stage.directory) / "source.tar.gz"
        replacement = path.with_name("replacement")
        replacement.write_bytes(path.read_bytes()); replacement.chmod(0o600); replacement.replace(path)
        with self.assertRaises(Denied): self.check()

    def test_modified_intake_archive_denies_without_reacquisition(self):
        path = Path(self.stage.directory) / "source.tar.gz"; path.write_bytes(path.read_bytes() + b"changed")
        with self.assertRaises(Denied): self.check()

    def test_original_mutable_locator_is_rejected_even_for_identical_bytes(self):
        self.original["path"] = self.created.bootstrap.path
        with self.assertRaisesRegex(Denied, "immutable-original-bootstrap"): self.collect()

    def test_same_bank_cannot_become_a_new_generation(self):
        with self.assertRaisesRegex(Denied, "separate-bank-required"):
            factory.collect_eighth_prelease_history(str(self.old_bank), self.original, self.previous)

    def prepare_model_lease(self, path, *, current):
        who = self.created.proof.identity
        with ledger.Ledger(path, clock=factory.time.time) as store:
            policy = store.archive_policy({"custodian_ref": "fixture:owner", "storage_ref": "fixture:storage",
                "approval_ref": "fixture:not-native-acceptance", "retention_seconds": 14400, "max_lease_seconds": 5400})
            challenge = store.challenge(self.created.proof.worker)
            if current:
                who = replace(who, run_id=self.successor["run_id"], caller_sha=self.successor["source_sha"],
                              reusable_sha=self.successor["reusable_sha"])
            who = replace(who, audience=challenge["audience"])
            return store.prepare(challenge["nonce"], self.created.proof.worker, who,
                policy_sha256=policy, cell_sha256="a" * 64, deadline=int(factory.time.time()) + 120)

    def test_original_lease_blocks_qualification_without_reset(self):
        identifier = self.prepare_model_lease(self.old_bank, current=False)
        with self.assertRaisesRegex(Denied, "original-lease-present"): self.check()
        with ledger.Ledger(self.old_bank, clock=factory.time.time) as store:
            self.assertEqual(store.lease_ids(), (identifier,))

    def test_exact_current_lease_in_separate_bank_is_preserved_not_required_empty(self):
        identifier = self.prepare_model_lease(self.next_bank, current=True)
        self.check()
        with ledger.Ledger(self.next_bank, clock=factory.time.time) as store:
            self.assertEqual(store.lease_ids(), (identifier,))

    def test_foreign_current_bank_lease_denies(self):
        self.prepare_model_lease(self.next_bank, current=False)
        with self.assertRaisesRegex(Denied, "original-or-unknown-lease"): self.check()

    def test_exact_next_partial_is_revalidated_but_not_adopted_as_complete(self):
        who = factory._invocation(self.next_bootstrap, "next", NS(run_id=self.successor["run_id"], job_id=552,
            check_run_id=652, caller_sha=self.successor["source_sha"], reusable_sha=self.successor["reusable_sha"]))
        name = ledger.digest({key: who[key] for key in ("repository", "run_id", "check_run_id", "selector")})
        directory = self.configs / name; directory.mkdir(mode=0o700)
        self.write(directory / "intent.json", {"schema": 1, "invocation": who, "snapshot_receipt_sha256": "c" * 64,
            "created_at": 1, "deadline": 2, "worker": {}, "job_started_at": 1, "template_sha256": "d" * 64})
        self.check()
        with self.assertRaisesRegex(Denied, "extra-catalogue-entry"): self.collect()
        old = factory._continuation_receipt
        with mock.patch.object(factory, "_continuation_receipt", side_effect=lambda value:
                self.qualified if value["ledger_path"] == str(self.next_bank) else old(value)):
            fd = factory.installation._open_directory(str(self.configs))
            try:
                with self.assertRaises(FileNotFoundError): factory._current_configuration_catalogue(self.next_bootstrap, fd)
            finally: os.close(fd)
        self.assertFalse((directory / "sealed-inventory.json").exists())


if __name__ == "__main__": unittest.main()
