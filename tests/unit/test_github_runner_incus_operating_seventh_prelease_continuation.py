"""Exact original staged prelease history; future source tuple remains unbound."""
from copy import deepcopy
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
        order = []
        def older(get, *, prior=False):
            order.append("prior" if prior else "origin")
            return two["native_prior"] if prior else legacy["native_origin"]
        def historical(label, value):
            def read(get):
                order.append(label); return value
            return read
        with ExitStack() as stack:
            connected, peer = socket.socketpair()
            stack.callback(connected.close)
            stack.callback(peer.close)
            # Provider and kernel acquisition remain explicitly modeled. The
            # integrated native entry still checks a real connected Unix socket.
            begin = mock.Mock(side_effect=lambda *_: (worker, object()))
            finish = mock.Mock(return_value=worker)
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
                (factory, "_continuation_origin_absent", lambda *_: order.append("fresh-absence")),
                (cells, "validate_continuation_commit", lambda *_: order.append("current-commit"))]:
                stack.enter_context(mock.patch.object(obj, name, value))
            factory._native(connected, selected, "nonce", "modeled-auth", "modeled-api")
            self.assertEqual(order, ["origin", "prior", "third", "fourth", "fifth", "sixth", "seventh", "fresh-absence", "current-commit"])
            order.clear()
            factory._native(connected, selected, "nonce", "modeled-auth", "modeled-api", check_origin=False)
            self.assertEqual(order, ["fresh-absence", "current-commit"])
            self.assertEqual((begin.call_count, finish.call_count, discard.call_count), (2, 2, 2))
            self.assertTrue(all(call.args[0] is connected for call in begin.call_args_list))


if __name__ == "__main__":
    unittest.main()
