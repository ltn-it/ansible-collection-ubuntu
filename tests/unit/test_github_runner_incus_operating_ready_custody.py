"""Generated operating cell + real Root Ledger/Unix API/ELF exit regressions.

HTTPS identity, Podman inspection, cgroup/fence acquisition and the retained
synthetic engine's native-policy acquisition are models. No native VM, image
copy, custody window or operating acceptance is proved by this suite.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

import test_github_runner_incus_cell_contract as cell_fixtures
import test_github_runner_incus_engine_executor as executor_fixtures
import test_github_runner_incus_engine_supervision as supervisor_fixtures
import test_github_runner_incus_mutation as mutation_fixtures
import test_github_runner_incus_preparation as preparation_fixtures
from incus_lease_issuer import (cell_contract, engine_policy, engine_executor,
    identity, incus_admin, incus_mutation, ledger, network_fence, operating_cells, operating_custody as custody,
    policy_registry, preparation)
from incus_lease_issuer.identity import Denied

CASE = "failure"
SELECTOR = operating_cells.selector(CASE)
UUID = "12345678-1234-4234-8234-123456789abc"


def operating_semantic_fixture():
    """Transform the template BEFORE its first real admission/prepare record."""
    class Fixture(cell_fixtures.RootCellContractTests):
        def seal(self):
            if "matrix" in self.value:
                del self.value["matrix"]
                self.value["kind"] = "operating"
                self.value["operating"] = {"case": CASE, "target": operating_cells.TARGET,
                                           "image": operating_cells.IMAGE}
                self.value["candidate"]["source_sha"] = self.registry_value["identity"]["caller_sha"]
                self.value["candidate"]["artifact"] = "collection-candidate-" + self.value["candidate"]["source_sha"]
                self.value["incus"]["project_limits"] = {"cpu": 1, "memory_bytes": operating_cells.MEMORY,
                    "disk_bytes": operating_cells.PROJECT_RESERVATION, "instances": 1,
                    "virtual_machines": 1, "containers": 0}
                tree = self.value["engine"]["trees"]["controller"]
                for name in tree["files"]:
                    (Path(tree["path"]) / name).unlink()
                controller = Path(tree["path"]) / "controller.py"
                controller.write_bytes(b"# synthetic immutable operating controller\n")
                controller.chmod(0o644)
                tree["files"] = {"controller.py": hashlib.sha256(controller.read_bytes()).hexdigest()}
                tree["directories"] = []
                self.value["controller"]["files"] = deepcopy(tree["files"])
                row = self.registry_value["cells"].pop("approved")
                row["native_job_name"] = "Operating custody / " + CASE
                self.registry_value["cells"][SELECTOR] = row
            digest = self.io.write(self.io.fixture.cell, self.value)
            self.registry_value["cells"][SELECTOR]["cell_sha256"] = digest
            self.io.registry_sha = self.io.write(self.io.registry, self.registry_value)
            self.registry = policy_registry.load_registry(str(self.io.registry), self.io.registry_sha)

        def new_lease(self):
            # The established native identity/Worker fixture is explicitly
            # synthetic; the nonce, scope and Ledger.prepare are actual.
            selected = self.registry.select(SELECTOR)
            nonce = self.store.challenge(self.io.fixture.worker)["nonce"]
            who = identity.Identity(501, 902, 731, selected.identity.runner_id, selected.identity.service_uid,
                selected.identity.caller_sha, selected.identity.reusable_sha,
                int(cell_contract.time.time()) + 300, "7" * 64, ledger.AUDIENCE + nonce,
                identity.policy_digest(selected.identity))
            return self.store.prepare(nonce, self.io.fixture.worker, who,
                policy_sha256=selected.custody_policy_sha256, cell_sha256=selected.cell_sha256,
                deadline=selected.deadline)

        def prepare(self):
            return cell_contract.prepare_cell(self.registry, SELECTOR, self.store, self.lease)

    return Fixture


def operating_preparation_fixture():
    class Fixture(preparation_fixtures.RootPreparationTests):
        def run_prepare(self):
            return preparation.prepare(str(self.config), self.sha, self.fixture.registry,
                                       SELECTOR, self.store, self.lease)
    return Fixture


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootOperatingReadyCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        supervisor_fixtures.RootSupervisionTests.setUpClass()

    def setUp(self):
        original = mutation_fixtures.MutationFixture.handle
        def image_routes(server, method, path, body):
            # Real AF_UNIX transport exercises production copy and readback;
            # the remote daemon/image store itself is an explicit model.
            if path.startswith("/1.0/images"):
                if method == "GET" and path == "/1.0/images/" + operating_cells.IMAGE + "?project=default":
                    return mutation_fixtures.reply(mutation_fixtures.envelope(
                        {"fingerprint": operating_cells.IMAGE, "type": "virtual-machine"}))
                if path.startswith("/1.0/images?project="):
                    if method == "POST":
                        # Native Incus7.6 rejected an omitted protocol with
                        # Invalid protocol: ''. This model must not hide that
                        # now-observed backend prerequisite again.
                        self.assertEqual(body, {"public": False, "auto_update": False, "source": {
                            "type": "image", "project": "default", "fingerprint": operating_cells.IMAGE,
                            "protocol": "incus", "mode": "pull"}})
                        project = path.split("=", 1)[1]
                        key = "/1.0/images/" + operating_cells.IMAGE + "?project=" + project
                        server.resources[key] = {"fingerprint": operating_cells.IMAGE, "type": "virtual-machine",
                            "public": False, "auto_update": False, "aliases": []}
                        server.resources[path] = ["/1.0/images/" + operating_cells.IMAGE]
                        return mutation_fixtures.reply(mutation_fixtures.envelope({}))
                    if method == "GET" and path not in server.resources:
                        return mutation_fixtures.reply(mutation_fixtures.envelope([]))
            return original(server, method, path, body)
        with mock.patch.object(cell_fixtures, "RootCellContractTests", operating_semantic_fixture()), \
             mock.patch.object(preparation_fixtures, "RootPreparationTests", operating_preparation_fixture()), \
             mock.patch.object(mutation_fixtures.MutationFixture, "handle", image_routes):
            self.supervisor = supervisor_fixtures.RootSupervisionTests()
            self.supervisor.setUp()
        self.addCleanup(self.supervisor.doCleanups)
        self.engine = self.supervisor.fixture
        self.io = self.engine.fixture
        self.registry = self.io.fixture.registry
        self.store, self.lease = self.supervisor.store, self.supervisor.lease
        self.descriptor = identity.decode_json(self.engine.prepared.engine_descriptor_bytes)
        self.assertEqual(self.descriptor["environment"]["QUALITY_INPUT_PROFILE"], "operating")
        self.assertEqual(self.descriptor["environment"]["QUALITY_OPERATING_SPEC"],
            ledger.canonical(operating_cells.spec(CASE, operating_cells.IMAGE, 501)).decode())
        self.control = Path(self.descriptor["output_path"]) / "control"
        self.control.mkdir(mode=0o700)
        self.hint = {"schema": 1, "case": CASE,
            "instance_name": self.engine.prepared.incus["instance"], "instance_uuid": UUID}
        self.write(self.control / "operating-created.json", self.hint)
        self.server = self.io.server
        self.target = self.engine.prepared.incus
        self.url = "/1.0/instances/" + self.target["instance"] + "?project=" + self.target["project"]
        labels = self.target["ownership"]
        self.vm = {"name": self.target["instance"], "type": "virtual-machine", "config": {
            "volatile.uuid": UUID, "volatile.base_image": operating_cells.IMAGE,
            "user.lit-molecule-owner": labels["owner"], "user.lit-molecule-repository": labels["repository"],
            "user.lit-molecule-run-id": str(labels["run_id"]), "user.lit-molecule-attempt": str(labels["run_attempt"]),
            "user.lit-molecule-scenario": labels["scenario"], "user.lit-molecule-target": labels["target"]},
            "expanded_config": {"limits.cpu": "1", "limits.memory": "2GiB"},
            "expanded_devices": {"root": {"type": "disk", "path": "/", "pool": self.target["pool"],
                "size": "5GiB", "size.state": "500MiB"},
                "eth0": {"type": "nic", "network": self.target["network"]}}}
        self.server.resources[self.url] = self.vm
        self.server.resources["/1.0/instances?project=" + self.target["project"]] = [self.url]
        self.server.resources["/1.0/operations?project=" + self.target["project"] + "&recursion=1"] = {}
        self.state(True)
        self.runtime = self.io.root / "operating-runtime.json"
        capture = self.descriptor["capture"]
        self.write(self.runtime, {"schema": 2, "registry_path": self.registry.path,
            "registry_sha256": self.registry.sha256, "preparation_config_path": str(self.io.config),
            "preparation_config_sha256": self.io.sha, "authentication_timeout_seconds": 5,
            "initial_transition_timeout_seconds": 60, "heartbeat_lead_seconds": 30, "cleanup_timeout_seconds": 60,
            "capture": {**capture, "max_total_evidence_bytes": 1048576, "max_members": 100,
                        "max_member_bytes": 1048576}})
        self.runtime_sha = hashlib.sha256(self.runtime.read_bytes()).hexdigest()

    @staticmethod
    def write(path, value):
        path.write_bytes(ledger.canonical(value))
        path.chmod(0o600)

    def state(self, running):
        state_url = "/1.0/instances/" + self.target["instance"] + "/state?project=" + self.target["project"]
        self.server.resources[state_url] = {"status": "Running" if running else "Stopped",
            "status_code": 103 if running else 102, "pid": 4321 if running else 0}

    def launch(self):
        # Real original ELF waits for the actual Root-created ACK then exits23.
        self.supervisor.program("from pathlib import Path; import sys; "
            "ack=Path(" + repr(str(self.control / "root-operating-ready.json")) + "); "
            "exec('while not ack.exists():\\n time.sleep(0.01)'); sys.exit(23)")
        self.owned = self.supervisor.launch()

    @contextmanager
    def retained_model(self):
        effect_id, effect = self.engine.engine_effect()
        # Existing private supervisor manifest contains a real ELF, not Podman.
        # Reuse its actually bound retained bytes; semantic cell validation and
        # every Unix read, READY write, instance proof and Ledger effect stay real.
        with mock.patch.object(engine_policy, "ENGINE", self.engine.original), \
             mock.patch.object(engine_executor, "_retained", return_value=(self.engine.manifest, effect_id, effect)):
            yield

    def ready(self):
        with self.retained_model():
            return custody.operating_ready_tick(str(self.io.config), self.io.sha, self.registry,
                SELECTOR, self.store, self.lease, self.engine.receipt)

    def outcome(self):
        with mock.patch.object(engine_policy, "ENGINE", self.engine.original), \
             mock.patch.object(network_fence, "verify_disabled"):
            return custody.operating_outcome(str(self.runtime), self.runtime_sha, self.registry,
                                             SELECTOR, self.store, self.lease)

    def stopped_and_withdrawn(self):
        self.state(False)
        # Explicit modeled kernel withdrawal, AFTER real ELF terminal readback.
        self.assertIsNotNone(self.owned.returncode)
        for operation, target in (("engine-stop", "engine:lit-lease-" + self.lease),
                                  ("fence-disable", "fence:" + self.lease)):
            effect = self.store.begin(self.lease, operation, target)
            self.store.record(self.lease, effect, "verified", evidence_sha256="d" * 64)
        for key in list(self.server.resources):
            if key.startswith("/1.0/certificates/"):
                del self.server.resources[key]

    def test_live_observation_owner_does_not_enable_cleanup_or_any_native_write(self):
        self.launch()
        with mock.patch.object(engine_policy, "ENGINE", self.engine.original):
            with self.assertRaisesRegex(Denied, "cell-cleanup-engine-untracked"):
                cell_contract.owned_cell_for_cleanup(self.registry, SELECTOR, self.store, self.lease)
            owner = cell_contract.owned_cell_for_observation(self.registry, SELECTOR, self.store, self.lease)
            self.assertIs(type(owner), cell_contract.OwnedCellForObservation)
            fingerprint = owner.creator_targets["certificate-create"].removeprefix("certificate:")
            client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(str(self.server.path),
                self.target["project"], self.target["network"], "default", self.target["pool"],
                (fingerprint,), self.target["instance"]))
            observer = incus_mutation.RootIncusCleanup(client, owner, self.store)
            self.assertEqual(observer.stop_inventory()["state"], "running_observed")
            requests = list(self.server.requests)
            before = self.store.read(self.lease)
            # Fixed internal mutation boundary is shared by all transport writes;
            # even a prequalified observation handle cannot acquire that power.
            with self.assertRaisesRegex(Denied, "mutation-live-observation-read-only"):
                observer._mutate("certificate-revoke", "certificate:" + fingerprint, "DELETE",
                                 "/1.0/certificates/" + fingerprint)
            self.assertEqual(self.server.requests, requests)
            self.assertEqual(self.store.read(self.lease), before)

    def test_root_ack_precedes_actual_exit23_and_exact_stopped_outcome(self):
        self.launch()
        self.assertIsNone(self.owned.proc.poll())
        self.assertNotIn("owned_instance", self.store.read(self.lease))
        frame = self.ready()
        self.assertEqual(frame["instance_uuid"], UUID)
        self.assertEqual(self.store.read(self.lease)["owned_instance"]["uuid"], UUID)
        ack = self.control / "root-operating-ready.json"
        self.assertEqual(ack.read_bytes(), ledger.canonical(frame))
        before = self.store.read(self.lease)
        inode = ack.stat().st_ino
        self.assertEqual(self.ready(), frame)
        self.assertEqual(self.store.read(self.lease), before)
        self.assertEqual(ack.stat().st_ino, inode)
        self.assertEqual(self.supervisor.finish(self.owned).exit_code, 23)
        self.stopped_and_withdrawn()
        result = self.outcome()
        self.assertEqual(result["raw_exit"], {"code": 23, "signal": None})
        self.assertEqual(result["state"], "safety-proved-retention-armed")
        self.assertNotIn("quality_pass", result)
        self.assertIsNone(result["terminal_at"])
        self.assertIsNone(result["retain_until"])

    def test_wrong_uuid_or_devices_or_foreign_inventory_never_writes_ack(self):
        self.launch()
        original = deepcopy(self.vm)
        cases = (
            ("uuid", lambda: self.vm["config"].update({"volatile.uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}),
             "operating-ready-native-platform"),
            ("root-size", lambda: self.vm["expanded_devices"]["root"].update(size="4GiB"),
             "operating-ready-native-devices"),
            ("extra-device", lambda: self.vm["expanded_devices"].update(extra={"type": "disk", "path": "/foreign"}),
             "operating-ready-native-platform"),
            ("owner", lambda: self.vm["config"].update({"user.lit-molecule-owner": "foreign"}),
             "mutation-instance-owner"))
        for name, mutation, reason in cases:
            with self.subTest(field=name):
                mutation()
                with self.assertRaisesRegex(Denied, reason):
                    self.ready()
                self.assertNotIn("owned_instance", self.store.read(self.lease))
                self.assertFalse((self.control / "root-operating-ready.json").exists())
                self.vm.clear(); self.vm.update(deepcopy(original))
        self.server.resources["/1.0/instances?project=" + self.target["project"]].append("/1.0/instances/foreign")
        with self.assertRaisesRegex(Denied, "mutation-instance-inventory"):
            self.ready()
        self.assertFalse((self.control / "root-operating-ready.json").exists())

    def test_exit23_without_ready_cannot_become_operating_safety(self):
        self.supervisor.program("import sys; sys.exit(23)")
        self.owned = self.supervisor.launch()
        self.assertEqual(self.supervisor.finish(self.owned).exit_code, 23)
        self.stopped_and_withdrawn()
        with self.assertRaisesRegex(Denied, "operating-outcome-ready-not-bound"):
            self.outcome()

    def test_no_hint_is_readonly_and_stopped_vm_cannot_ack(self):
        self.launch()
        (self.control / "operating-created.json").unlink()
        before = self.store.read(self.lease)
        self.assertIsNone(self.ready())
        self.assertEqual(self.store.read(self.lease), before)
        self.write(self.control / "operating-created.json", self.hint)
        self.state(False)
        with self.assertRaisesRegex(Denied, "operating-ready-native-platform"):
            self.ready()
        self.assertFalse((self.control / "root-operating-ready.json").exists())

    def test_post_ready_replaced_instance_is_not_the_bound_owned_vm(self):
        self.launch()
        self.ready()
        self.supervisor.finish(self.owned)
        self.stopped_and_withdrawn()
        self.vm["config"]["volatile.uuid"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        with self.assertRaisesRegex(Denied, "operating-outcome-unsafe"):
            self.outcome()


if __name__ == "__main__":
    unittest.main()
