"""Pinned stock GenerateScripts compatibility; no native service effects.

The verbatim shell fixture is actions/runner (MIT), commit
d1eb12d4b115c301201de27d667284e1a80f2ab5,
src/Misc/layoutbin/systemd.svc.sh.template. Root target objects below are
synthetic acquired-fact models, never operating acceptance.
"""
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import json
import os
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "roles/github_runner/files"))
from incus_lease_issuer import registration as reg  # noqa: E402
from incus_lease_issuer import registration_service as svc  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402

TEMPLATE = Path(__file__).with_name("github_runner_2_338_2_systemd.svc.sh.template").read_bytes()


class EntryBoundary(unittest.TestCase):
    def test_job_mapping_is_not_a_native_target(self):
        with self.assertRaises(Denied):
            svc.generate(TEMPLATE, {"runner_id": 78, "approved": True}, {})

    def test_nonroot_entry_denies_before_settings_or_template(self):
        if os.geteuid() == 0:
            self.skipTest("actual nonroot EE required")
        with self.assertRaisesRegex(Denied, "registration-root-required"):
            svc.generate(None, None, None)


@unittest.skipUnless(os.geteuid() == 0, "actual isolated Root EE required")
class StockServiceScript(unittest.TestCase):
    def setUp(self):
        self.target = reg.VerifiedTarget(54334171, "Example-Org", 78, "incus-runner-01", 7, "Protected", "x64",
            (("self-hosted", "system"), ("Linux", "system"), ("X64", "system")),
            "/var/lib/example-runner/work", "a" * 64, int(time.time()) + 120, _authority=reg._FENCE_AUTHORITY)
        self.settings = {"agentId": 78, "agentName": "incus-runner-01", "poolId": 7, "poolName": "Protected",
            "serverUrl": "https://pipelines.fixture.actions.githubusercontent.com/tenant/",
            "serverUrlV2": "https://broker.fixture.actions.githubusercontent.com/", "gitHubUrl": "https://github.com/Example-Org",
            "workFolder": self.target.work_folder, "disableUpdate": True, "useV2Flow": True, "useRunnerAdminFlow": True}

    def test_exact_stock_two_token_substitution_and_no_settings_mutation(self):
        before = json.dumps(self.settings, sort_keys=True)
        result = svc.generate(TEMPLATE, self.target, self.settings)
        self.assertEqual(result.service_name, "actions.runner.Example-Org.incus-runner-01.service")
        self.assertEqual(result.display_name, "GitHub Actions Runner (Example-Org.incus-runner-01)")
        # Compare the complete script, including the original install/uninstall
        # routines and still-literal unit-template placeholders, not a prefix.
        expected = TEMPLATE.replace(b"{{SvcNameVar}}", result.service_name.encode())
        expected = expected.replace(b"{{SvcDescription}}", result.display_name.encode())
        self.assertEqual(result.content, expected)
        self.assertIn(b"{{RunnerRoot}}", result.content)
        self.assertIn(b"{{User}}", result.content)
        self.assertEqual(json.dumps(self.settings, sort_keys=True), before)
        with self.assertRaises(FrozenInstanceError):
            result.service_name = "foreign.service"

    def test_legacy_registration_generates_same_identity_without_broker_route(self):
        settings = {**self.settings, "useV2Flow": False, "useRunnerAdminFlow": False}
        settings.pop("serverUrlV2")
        result = svc.generate(TEMPLATE, self.target, settings)
        self.assertEqual(result.content, svc.generate(TEMPLATE, self.target, self.settings).content)
        with self.assertRaises(Denied):
            svc.generate(TEMPLATE, self.target, {**settings, "serverUrlV2": self.settings["serverUrlV2"]})
        with self.assertRaises(Denied):
            svc.generate(TEMPLATE, self.target, {**settings, "useRunnerAdminFlow": True})

    def test_wrong_or_mutated_stock_template_denied(self):
        for raw in (b"#!/bin/sh\n", TEMPLATE + b"\n", TEMPLATE.replace(b"#!/bin/bash", b"#!/bin/zshx"),
                    TEMPLATE.decode()):
            with self.subTest(kind=type(raw).__name__), self.assertRaises(Denied):
                svc.generate(raw, self.target, self.settings)

    def test_identity_scope_group_url_or_work_drift_denied(self):
        changes = {"agentId": 79, "agentName": "incus-runner-02", "poolId": 8, "poolName": "Default",
                   "gitHubUrl": "https://github.com/foreign", "workFolder": "/foreign"}
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(Denied):
                svc.generate(TEMPLATE, self.target, {**self.settings, key: value})
        with self.assertRaises(Denied):
            svc.generate(TEMPLATE, self.target, {**self.settings, "gitHubUrl": "https://github.com/Example-Org/repo"})

    def test_boolean_id_disabled_updates_and_flow_types_are_exact(self):
        for key, value in (("agentId", True), ("poolId", True), ("disableUpdate", False),
                           ("disableUpdate", "true"), ("useV2Flow", 1), ("useRunnerAdminFlow", "false")):
            with self.subTest(key=key), self.assertRaises(Denied):
                svc.generate(TEMPLATE, self.target, {**self.settings, key: value})

    def test_unknown_setting_and_untrusted_server_origins_denied(self):
        with self.assertRaises(Denied):
            svc.generate(TEMPLATE, self.target, {**self.settings, "service_name": "foreign.service"})
        for url in ("http://broker.fixture.actions.githubusercontent.com/", "https://example.com/",
                    "https://broker.fixture.actions.githubusercontent.com:443/", "https://user@broker.actions.githubusercontent.com/"):
            for key in ("serverUrl", "serverUrlV2"):
                with self.subTest(key=key, url=url), self.assertRaises(Denied):
                    svc.generate(TEMPLATE, self.target, {**self.settings, key: url})

    def test_expired_fence_does_not_generate_a_service_script(self):
        with self.assertRaises(Denied):
            svc.generate(TEMPLATE, replace(self.target, valid_until=int(time.time()) - 1), self.settings)


if __name__ == "__main__":
    unittest.main()
