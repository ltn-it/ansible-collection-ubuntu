"""Root semantic fixtures, not operating approval or native artifact provenance."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

import test_github_runner_incus_socket_entry as socket_fixtures
import test_github_runner_incus_engine_policy as engine_fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import cell_contract as cell, engine_policy as engine, identity, ledger, policy_registry  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class CellAPIGuards(unittest.TestCase):
    def test_root_guard_precedes_registry_store_or_descriptor(self):
        with mock.patch.object(cell.os, "geteuid", return_value=2101):
            with self.assertRaisesRegex(Denied, "cell-root-required"):
                cell.prepare_cell(None, None, None, None)
            with self.assertRaisesRegex(Denied, "cell-root-required"):
                cell.bind_engine(None, None, None)

    def test_no_caller_identity_or_independent_policy_parameters(self):
        with self.assertRaises(TypeError):
            cell.prepare_cell(None, None, None, None, identity={})
        with self.assertRaises(TypeError):
            cell.bind_engine(None, None, None, deadline=9999999999)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootCellContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        socket_fixtures.RootSocketEntryTests.setUpClass()

    def setUp(self):
        self.io = socket_fixtures.RootSocketEntryTests()
        self.io.setUp()
        self.addCleanup(self.io.doCleanups)
        self.fs = engine_fixtures.RootEngineCompilerTests()
        self.fs.setUp()
        self.addCleanup(self.fs.doCleanups)
        data = self.fs.data
        template = {key: deepcopy(data[key]) for key in
                    ("image", "runner_gid", "cell_uid", "cell_gid", "uid_map", "gid_map", "limits", "archives", "trees", "capture")}
        template["engine"] = {key: data["engine"][key] for key in ("executable", "executable_sha256")}
        template["paths"] = {}
        for key in cell.PATH_KEYS:
            path = self.fs.root / ("prefix-" + key)
            path.mkdir(mode=0o700)
            template["paths"][key] = str(path)
        pin = self.fs.root / "server-pin.pem"
        pin.write_bytes(b"synthetic pinned bytes, no TLS runtime proof")
        pin.chmod(0o600)
        self.value = {"schema": 1,
                     "candidate": {"repository": "ltn-it/ansible-collection-supplementary", "source_sha": "e" * 40,
                                   "artifact": "fixture-candidate", "archive_sha256": template["archives"]["candidate"]["sha256"]},
                     "controller": {"repository": "ltn-it/modulix-validation", "source_sha": "f" * 40,
                                    "archive_sha256": template["archives"]["controller"]["sha256"],
                                    "files": template["trees"]["controller"]["files"]},
                     "matrix": {"profile": "heavy", "scenario": "example_heavy", "target": "ubuntu24.04",
                                "target_disposition": "candidate", "roles": ["example"],
                                "image": "images:ubuntu/24.04/cloud", "instance_type": "vm", "junit": True,
                                "allure": False, "cpu_limit": "2", "memory_limit": "4GiB", "disk_limit": "20GiB"},
                     "github": {"job": "profile-cells", "workflow": "Collection CI"}, "engine": template,
                     "incus": {"server": "https://incus.private.example:8443",
                               "server_certificate": {"path": str(pin), "sha256": hashlib.sha256(pin.read_bytes()).hexdigest()},
                               "pool": "approved-pool",
                               "project_prefix": "lit-", "ipv4_address": "10.77.2.1/24", "dns_domain": "lease.invalid",
                               "project_limits": {"cpu": 4, "memory_bytes": 8 * 1024 ** 3, "disk_bytes": 30 * 1024 ** 3,
                                                  "instances": 1, "virtual_machines": 1, "containers": 0}}}
        self.registry_value = json.loads(self.io.registry.read_bytes())
        self.registry_value["cells"]["approved"]["native_job_name"] = "Heavy matrix / heavy / example_heavy / ubuntu24.04"
        self.seal()
        self.store = ledger.Ledger(self.io.fixture.store_path, clock=cell.time.time)
        self.addCleanup(self.store.shutdown)
        self.lease = self.new_lease()

    def seal(self):
        digest = self.io.write(self.io.fixture.cell, self.value)
        self.registry_value["cells"]["approved"]["cell_sha256"] = digest
        self.io.registry_sha = self.io.write(self.io.registry, self.registry_value)
        self.registry = policy_registry.load_registry(str(self.io.registry), self.io.registry_sha)

    def test_receiver_environment_requires_the_prepared_native_run(self):
        from dataclasses import replace
        native = replace(self.registry.select("approved").identity,
            repository="ltn-it/modulix-validation", repository_id=1269461997, owner_id=54334171,
            workflow_path=".github/workflows/mlx90-collection-candidate-validation.yml",
            reusable_repository="ltn-it/modulix-validation",
            reusable_path=".github/workflows/collection-quality-profile-isolated.yml",
            actor_ids=frozenset({307565056}),
            subject="repo:ltn-it/modulix-validation:environment:heavy-isolated-pilot", visibility="public")
        value = deepcopy(self.value)
        value["github"]["run_id"] = 501
        self.assertEqual(cell._environment(value, native, {"run_id": 501})["GITHUB_RUN_ID"], "501")
        with self.assertRaisesRegex(Denied, "cell-receiver-run-binding"):
            cell._environment(value, native, {"run_id": 502})
        del value["github"]["run_id"]
        with self.assertRaises(Denied):
            cell._environment(value, native, {"run_id": 501})

    def new_lease(self):
        selected = self.registry.select("approved")
        nonce = self.store.challenge(self.io.fixture.worker)["nonce"]
        who = identity.Identity(501, 902, 731, selected.identity.runner_id, selected.identity.service_uid,
                                selected.identity.caller_sha, selected.identity.reusable_sha, int(cell.time.time()) + 300,
                                "7" * 64, ledger.AUDIENCE + nonce, identity.policy_digest(selected.identity))
        return self.store.prepare(nonce, self.io.fixture.worker, who, policy_sha256=selected.custody_policy_sha256,
                                  cell_sha256=selected.cell_sha256, deadline=selected.deadline)

    def prepare(self):
        return cell.prepare_cell(self.registry, "approved", self.store, self.lease)

    def rejected_changed(self, mutate):
        # Re-sealing changes the original admission digest. Borrowing that new
        # source against an old lease MUST fail, before any effect.
        mutate(self.value)
        self.seal()
        with self.assertRaises(Denied):
            self.prepare()

    def materialize(self, prepared):
        path = Path(prepared.engine_descriptor_path)
        path.write_bytes(prepared.engine_descriptor_bytes)
        path.chmod(0o600)
        value = identity.decode_json(prepared.engine_descriptor_bytes)
        for key in ("storage_root", "runroot"):
            Path(value["engine"][key]).mkdir(mode=0o700)
        context = Path(value["context_path"])
        context.mkdir(mode=0o700)
        (context / "servercerts").mkdir(mode=0o700)
        for name in engine.CONTEXT_FILES:
            path = context / name
            path.write_bytes(("synthetic private TLS file: " + name).encode())
            path.chmod(0o600)
        Path(value["output_path"]).mkdir(mode=0o700)
        return engine.compile_engine_policy(prepared.engine_descriptor_path, prepared.engine_descriptor_sha256)

    def test_static_template_validation_needs_no_lease_identity_or_writes(self):
        native = self.registry.select("approved").identity
        # An acquired native run identifier/environment is sufficient; no
        # fabricated Identity, lease ID, prepare_cell or descriptor is supplied.
        env = cell._environment(self.value, native, {"run_id": 501})
        before = (Path(self.io.fixture.store_path) / "state.json").read_bytes()
        directories = {path: tuple(sorted(os.listdir(path))) for path in self.value["engine"]["paths"].values()}
        original_open = os.open
        def readonly_open(path, flags, *args, **kwargs):
            self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            return original_open(path, flags, *args, **kwargs)
        now = int(cell.time.time())
        with mock.patch.object(cell, "_lease", side_effect=AssertionError("no lease lookup")), \
             mock.patch.object(cell, "prepare_cell", side_effect=AssertionError("no preparation")), \
             mock.patch.object(os, "open", side_effect=readonly_open):
            binary, paths = cell._validate_engine_template(self.value["engine"], env, native,
                                                          now+5400, now)
        self.assertEqual(binary, self.value["engine"]["engine"])
        self.assertEqual(paths, self.value["engine"]["paths"])
        self.assertEqual((Path(self.io.fixture.store_path) / "state.json").read_bytes(), before)
        self.assertEqual({path: tuple(sorted(os.listdir(path))) for path in paths.values()}, directories)

    def test_descriptor_projection_unchanged_after_static_validation_extraction(self):
        selected = self.registry.select("approved")
        record = self.store.read(self.lease)
        env = cell._environment(self.value, selected.identity, record["identity"])
        template = self.value["engine"]
        binary, paths = template["engine"], template["paths"]
        expected = {"schema": 1, **{key: template[key] for key in
            ("image", "runner_gid", "cell_uid", "cell_gid", "uid_map", "gid_map", "limits", "archives", "trees", "capture")},
            "runner_uid": selected.identity.service_uid,
            "network_namespace_path": "/run/netns/lit-lease-"+self.lease,
            "cgroup_parent": "lit-lease-"+self.lease+".slice",
            "engine": {**binary, "storage_root": paths["storage"]+"/"+self.lease,
                       "runroot": paths["runroot"]+"/"+self.lease},
            "context_path": paths["context"]+"/"+self.lease,
            "output_path": paths["output"]+"/"+self.lease, "environment": env}
        with mock.patch.object(cell, "_validate_engine_template", wraps=cell._validate_engine_template) as validate:
            actual = cell._descriptor(template, env, selected.identity, self.lease,
                                      record["expires_at"], record["created_at"])
        validate.assert_called_once_with(template, env, selected.identity, record["expires_at"], record["created_at"])
        self.assertEqual(actual, expected)
        self.assertEqual(engine._canonical(actual), engine._canonical(expected))

    def test_static_template_denies_short_real_publication_budget_and_tree_drift(self):
        selected = self.registry.select("approved")
        env = cell._environment(self.value, selected.identity, {"run_id": 501})
        now = int(cell.time.time())
        budget = self.value["engine"]["limits"]["timeout_seconds"]
        with self.assertRaisesRegex(Denied, "cell-engine-deadline"):
            cell._validate_engine_template(self.value["engine"], env, selected.identity,
                                           now+budget-1, now)
        altered = deepcopy(self.value["engine"])
        one = next(iter(altered["trees"]["workspace"]["files"]))
        altered["trees"]["workspace"]["files"][one] = "0"*64
        with self.assertRaises(Denied):
            cell._validate_engine_template(altered, env, selected.identity, now+5400, now)

    def test_pre_tls_has_no_context_dependency_or_effect_and_binds_distinct_sources(self):
        before = (Path(self.io.fixture.store_path) / "state.json").read_bytes()
        prepared = self.prepare()
        value = identity.decode_json(prepared.engine_descriptor_bytes)
        self.assertFalse(Path(value["context_path"]).exists())
        self.assertEqual((Path(self.io.fixture.store_path) / "state.json").read_bytes(), before)
        self.assertEqual(value["environment"]["QUALITY_INPUT_SOURCE_SHA"], "e" * 40)
        self.assertEqual(value["environment"]["GITHUB_SHA"], self.registry.select("approved").identity.caller_sha)
        details = identity.decode_json(prepared.canonical_bytes)
        self.assertEqual(details["controller"]["source_sha"], "f" * 40)
        self.assertEqual(prepared.identity_policy_sha256, identity.policy_digest(self.registry.select("approved").identity))
        self.assertEqual(value["network_namespace_path"], "/run/netns/lit-lease-" + self.lease)
        self.assertEqual(value["cgroup_parent"], "lit-lease-" + self.lease + ".slice")

    def test_exact_legacy_owner_instance_network_and_frozen_projection(self):
        result = self.prepare()
        target = result.incus
        owner = cell._bounded("ltn-it/ansible-collection-supplementary-Collection CI-501-1-example_heavy-ubuntu24.04", 255, True)
        self.assertEqual(target["ownership"]["owner"], owner)
        self.assertEqual(target["network"], "lit" + hashlib.sha256(owner.encode()).hexdigest()[:12])
        self.assertEqual(target["project"], "lit-" + self.lease)
        self.assertEqual(target["network_project"], "default")
        self.assertEqual(target["ownership"]["run_attempt"], 1)
        target["project"] = "foreign"
        self.assertNotEqual(result.incus["project"], "foreign")
        with self.assertRaises(FrozenInstanceError):
            result.expires_at += 1

    def test_late_engine_compile_matches_without_binding_signature_cycle(self):
        prepared = self.prepare()
        manifest = self.materialize(prepared)
        bound = cell.bind_engine(prepared, self.store, manifest)
        self.assertEqual(bound.engine_policy_sha256, manifest.sha256)
        value = identity.decode_json(prepared.engine_descriptor_bytes)
        binding = Path(value["context_path"]) / "binding.json"
        binding.write_bytes(b'{"synthetic":"signature-created-after-engine-digest"}')
        binding.chmod(0o600)
        again = engine.compile_engine_policy(prepared.engine_descriptor_path, prepared.engine_descriptor_sha256)
        self.assertEqual(again, manifest)
        self.assertEqual(cell.bind_engine(prepared, self.store, again), bound)

    def test_borrowed_manifest_or_tampered_prepared_object_denied(self):
        prepared = self.prepare()
        manifest = self.materialize(prepared)
        with self.assertRaises(Denied):
            cell.bind_engine(prepared, self.store, replace(manifest, sha256="a" * 64))
        with self.assertRaises(Denied):
            cell.bind_engine(replace(prepared, cell_sha256="a" * 64), self.store, manifest)

    def test_descriptor_drift_and_tls_file_drift_deny_final_binding(self):
        prepared = self.prepare()
        manifest = self.materialize(prepared)
        value = identity.decode_json(prepared.engine_descriptor_bytes)
        (Path(value["context_path"]) / "client.key").write_bytes(b"changed private bytes")
        with self.assertRaises(Denied):
            cell.bind_engine(prepared, self.store, manifest)
        Path(prepared.engine_descriptor_path).write_bytes(b"{}")
        with self.assertRaises(Denied):
            cell.bind_engine(prepared, self.store, manifest)

    def test_original_cell_digest_cannot_be_replaced_by_resealed_descriptor(self):
        self.rejected_changed(lambda value: value["matrix"].update(target="other"))

    def test_wrong_store_cannot_supply_another_lease(self):
        other = self.fs.root / "other-ledger"
        other.mkdir(mode=0o700)
        ledger.Ledger.initialize(str(other))
        with ledger.Ledger(str(other)) as store:
            with self.assertRaisesRegex(Denied, "cell-ledger-path"):
                cell.prepare_cell(self.registry, "approved", store, self.lease)

    def verified_fence(self):
        effect = self.store.begin(self.lease, "fence-create", "fence:" + self.lease)
        self.store.bind_fence(self.lease, effect, policy_sha256="d" * 64,
                             boot_id=self.io.fixture.worker.boot_id, netns_device=4,
                             netns_inode=4026533001, host_ifindex=301, peer_ifindex=2, nft_table_handle=1)
        self.store.record(self.lease, effect, "verified", evidence_sha256="d" * 64)
        return effect

    def test_cleanup_fence_locator_survives_expiry_cancel_without_new_authority(self):
        self.verified_fence()
        before = self.store.read(self.lease)
        with mock.patch.object(cell.time, "time", return_value=before["expires_at"] + 1):
            with self.assertRaises(Denied):
                self.prepare()
            owner = cell.owned_fence_for_cleanup(self.registry, "approved", self.store, self.lease)
        self.assertIs(type(owner), cell.OwnedFenceForCleanup)
        self.assertFalse(hasattr(owner, "engine_descriptor_path"))
        self.assertFalse(hasattr(owner, "incus"))
        self.assertEqual(self.store.read(self.lease), before)
        self.store.cancel(self.lease, "cancelled")
        cancelled = self.store.read(self.lease)
        self.assertEqual(cell.owned_fence_for_cleanup(self.registry, "approved", self.store, self.lease), owner)
        self.assertEqual(self.store.read(self.lease), cancelled)

    def test_cleanup_locator_requires_verified_exact_fence_creator(self):
        with self.assertRaisesRegex(Denied, "cell-cleanup-fence-not-owned"):
            cell.owned_fence_for_cleanup(self.registry, "approved", self.store, self.lease)
        effect = self.store.begin(self.lease, "fence-create", "fence:" + self.lease)
        self.store.record(self.lease, effect, "unknown", evidence_sha256="d" * 64)
        before = self.store.read(self.lease)
        with self.assertRaisesRegex(Denied, "cell-cleanup-fence-not-owned"):
            cell.owned_fence_for_cleanup(self.registry, "approved", self.store, self.lease)
        self.assertEqual(self.store.read(self.lease), before)

    def test_cleanup_locator_denies_removed_closed_and_source_drift(self):
        self.verified_fence()
        original = self.io.fixture.cell.read_bytes()
        self.io.fixture.cell.write_bytes(b"changed sealed source")
        with self.assertRaises(Denied):
            cell.owned_fence_for_cleanup(self.registry, "approved", self.store, self.lease)
        self.io.fixture.cell.write_bytes(original)
        remove = self.store.begin(self.lease, "fence-remove", "fence:" + self.lease)
        self.store.record(self.lease, remove, "verified", evidence_sha256="c" * 64)
        with self.assertRaises(Denied):
            cell.owned_fence_for_cleanup(self.registry, "approved", self.store, self.lease)
        self.store.close(self.lease)
        with self.assertRaises(Denied):
            cell.owned_fence_for_cleanup(self.registry, "approved", self.store, self.lease)
        self.io.fixture.cell.write_bytes(b"changed sealed source")
        with self.assertRaises(Denied):
            cell.owned_fence_for_cleanup(self.registry, "approved", self.store, self.lease)

    def test_elapsed_time_preserves_immutable_cell_with_live_authorization(self):
        before = self.prepare()
        with mock.patch.object(cell.time, "time", return_value=int(cell.time.time()) + 1):
            # Original timeout equals the full lease in this fixture. A live
            # recheck after one second must not ask for that budget a second time.
            after = self.prepare()
        self.assertEqual(after, before)
        self.assertEqual(self.store.read(self.lease)["effects"], {})

    def test_current_auth_and_fixed_timeout_are_independent(self):
        with mock.patch.object(cell.time, "time", return_value=int(cell.time.time()) + 301):
            with self.assertRaisesRegex(Denied, "cell-lease-inactive"):
                self.prepare()

    def test_semantic_negative_cases_against_newly_bound_lease(self):
        cases = [lambda v: v.update(extra="caller-override"),
                 lambda v: v["matrix"].update(instance_type="container"),
                 lambda v: v["matrix"].update(scenario="borrowed-cell"),
                 lambda v: v["matrix"].update(roles=["example", "example"]),
                 lambda v: v["candidate"].update(archive_sha256="0" * 64),
                 lambda v: v["controller"].update(repository="foreign/controller"),
                 lambda v: v["controller"]["files"].update({"run-cell.py": "0" * 64}),
                 lambda v: v["incus"]["project_limits"].update(memory_bytes=1),
                 lambda v: v["incus"]["project_limits"].update(containers=1),
                 lambda v: v["incus"].update(project_prefix="default"),
                 lambda v: v["incus"].update(server="https://user:password@private.example"),
                 lambda v: v["engine"]["limits"].update(timeout_seconds=1201),
                 lambda v: v["engine"]["capture"].update(stdout_limit=True),
                 lambda v: v["engine"]["capture"].update(total_limit=v["engine"]["capture"]["stdout_limit"] + v["engine"]["capture"]["stderr_limit"] + 1),
                 lambda v: v["engine"]["capture"].update(path="/caller/log"),
                 lambda v: v["engine"]["uid_map"].update(host_base=2101),
                 lambda v: v["engine"]["paths"].update(context=v["engine"]["paths"]["output"])]
        original = deepcopy(self.value)
        for index, change in enumerate(cases):
            with self.subTest(case=index):
                self.value = deepcopy(original)
                change(self.value)
                self.seal()
                # No ledger JSON tampering: a different fixture store models a
                # genuinely newly admitted bad Root cell, with a valid scope.
                selected = self.registry.select("approved")
                path = self.fs.root / ("case-ledger-" + str(index))
                path.mkdir(mode=0o700)
                ledger.Ledger.initialize(str(path), clock=cell.time.time)
                with ledger.Ledger(str(path), clock=cell.time.time) as store:
                    with ledger.Ledger(self.io.fixture.store_path, clock=cell.time.time) as original_store:
                        policy = original_store.read_policy(selected.custody_policy_sha256)
                    digest = store.archive_policy(policy)
                    nonce = store.challenge(self.io.fixture.worker)["nonce"]
                    who = identity.Identity(501, 902, 731, 61, 2101, selected.identity.caller_sha,
                                            selected.identity.reusable_sha, int(cell.time.time()) + 300,
                                            "7" * 64, ledger.AUDIENCE + nonce, identity.policy_digest(selected.identity))
                    lease_id = store.prepare(nonce, self.io.fixture.worker, who, policy_sha256=digest,
                                             cell_sha256=selected.cell_sha256, deadline=selected.deadline)
                    # Correctly point a newly sealed real registry at that store.
                    self.registry_value["ledger_path"] = str(path)
                    self.seal()
                    with self.assertRaises(Denied):
                        cell.prepare_cell(self.registry, "approved", store, lease_id)

    def test_policy_scope_digest_and_native_job_matrix_are_both_required(self):
        selected = self.registry.select("approved")
        path = self.fs.root / "wrong-scope-ledger"
        path.mkdir(mode=0o700)
        ledger.Ledger.initialize(str(path), clock=cell.time.time)
        with ledger.Ledger(str(path), clock=cell.time.time) as store:
            digest = store.archive_policy(self.store.read_policy(selected.custody_policy_sha256))
            nonce = store.challenge(self.io.fixture.worker)["nonce"]
            who = identity.Identity(501, 902, 731, 61, 2101, selected.identity.caller_sha,
                                    selected.identity.reusable_sha, int(cell.time.time()) + 300, "7" * 64,
                                    ledger.AUDIENCE + nonce,
                                    identity.policy_digest(replace(selected.identity, caller_sha="0" * 40)))
            identifier = store.prepare(nonce, self.io.fixture.worker, who, policy_sha256=digest,
                                       cell_sha256=selected.cell_sha256, deadline=selected.deadline)
            self.registry_value["ledger_path"] = str(path)
            self.seal()
            with self.assertRaisesRegex(Denied, "cell-identity-binding"):
                cell.prepare_cell(self.registry, "approved", store, identifier)

    def test_server_pin_drift_denies_before_preparation(self):
        Path(self.value["incus"]["server_certificate"]["path"]).write_bytes(b"replaced pin")
        with self.assertRaisesRegex(Denied, "cell-server-certificate"):
            self.prepare()



@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootCleanupSemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_github_runner_incus_engine_supervision as supervisor
        supervisor.RootSupervisionTests.setUpClass()

    def setUp(self):
        import test_github_runner_incus_engine_supervision as supervisor
        self.io = supervisor.RootSupervisionTests()
        self.io.setUp()
        self.addCleanup(self.io.doCleanups)
        self.io.program("pass")
        self.run = self.io.launch()
        self.io.finish(self.run)
        self.engine_fixture = self.io.fixture
        self.registry = self.engine_fixture.fixture.fixture.registry
        self.store, self.lease = self.io.store, self.io.lease

    def owner(self):
        # Synthetic supervisor uses a real private ELF. Root semantic descriptor
        # still binds the production constant; no native Podman is claimed.
        with mock.patch.object(cell.engine, "ENGINE", self.engine_fixture.original):
            return cell.owned_cell_for_cleanup(self.registry, "approved", self.store, self.lease)

    def test_cleanup_distinct_type_exact_original_prepared_and_stable_after_raw_deletion(self):
        import shutil
        original = self.engine_fixture.prepared
        owner = self.owner()
        self.assertIs(type(owner), cell.OwnedCellForCleanup)
        self.assertNotIsInstance(owner, cell.PreparedCell)
        self.assertEqual(owner.prepared_sha256, original.sha256)
        self.assertEqual(owner.canonical_bytes, original.canonical_bytes)
        self.assertEqual(owner.engine_descriptor_bytes, original.engine_descriptor_bytes)
        self.assertEqual(owner.incus, original.incus)
        descriptor = identity.decode_json(owner.engine_descriptor_bytes)
        for path in (descriptor["context_path"], descriptor["engine"]["storage_root"],
                     descriptor["engine"]["runroot"], descriptor["output_path"]):
            shutil.rmtree(path)
        Path(owner.engine_descriptor_path).unlink()
        with mock.patch.object(cell.time, "time", return_value=owner.expires_at+10):
            self.assertEqual(self.owner(), owner)
            with self.assertRaises(Denied):
                cell.prepare_cell(self.registry, "approved", self.store, self.lease)
        # Receiving a distinct cleanup locator can never grant TLS materialization.
        from incus_lease_issuer import context_materializer
        with self.assertRaises(Denied):
            context_materializer.materialize(owner, self.store)

    def test_borrowed_project_target_rejected_by_journal_before_cleanup_adoption(self):
        original = self.owner()
        with self.assertRaises(Denied):
            with self.store._transaction() as state:
                record = state["leases"][self.lease]
                project = next(row for row in record["effects"].values() if row["operation"] == "project-create")
                project["target"] = "project:foreign-protected"
        self.assertEqual(self.owner(), original)  # Invalid transaction never committed.


if __name__ == "__main__":
    unittest.main()
