"""Credential-free producer tests. Root cases run ONLY in private EE /run/proof.

Synthetic package pins and native transports are test doubles, not GitHub,
systemd or AppArmor qualification. Real filesystem owner/no-follow checks and
production installation verifier are retained. Never run root fixtures on host.
"""
from dataclasses import asdict, replace
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import time
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "roles/github_runner/files"))
from incus_lease_issuer.identity import Denied  # noqa: E402
from incus_lease_issuer import installation  # noqa: E402

# This template contains literal Python, no Jinja substitutions or owner bypass.
producer = types.ModuleType("protected_provision")
exec(compile((ROOT / "roles/github_runner/templates/protected_provision.py.j2").read_text(),
             "protected_provision.py.j2", "exec"), producer.__dict__)


class ProducerGuardTests(unittest.TestCase):
    def test_nonroot_entry_cannot_apply_even_an_empty_configuration(self):
        if os.geteuid() == 0:
            self.skipTest("production nonroot guard runs in the nonroot EE")
        with self.assertRaisesRegex(Denied, "protected-root-required"):
            producer.configuration(b"{}")

    def test_official_architecture_pins_are_distinct_and_immutable_in_config(self):
        self.assertEqual(set(producer.ARCHIVES), {"arm64", "x64"})
        self.assertNotEqual(producer.ARCHIVES["arm64"], producer.ARCHIVES["x64"])
        self.assertEqual(producer.VERSION, "2.338.2")

    def test_nonroot_cannot_decode_a_maintenance_handoff(self):
        if os.geteuid() == 0:
            self.skipTest("production nonroot guard runs in the nonroot EE")
        with self.assertRaisesRegex(Denied, "protected-root-required"):
            producer.handoff_input(b"{}", "handoff-apply-input")

    def test_dropin_has_no_optional_bypass_and_no_privileged_service_capabilities(self):
        text = producer.dropin({"profile": "lit-gh-example-0123456789abcdef"}).decode()
        self.assertIn("NoNewPrivileges=yes\n", text)
        self.assertIn("CapabilityBoundingSet=\nAmbientCapabilities=\n", text)
        self.assertIn("Environment=DOTNET_EnableDiagnostics=0\n", text)
        self.assertIn("AppArmorProfile=lit-gh-example-0123456789abcdef\n", text)
        self.assertNotIn("AppArmorProfile=-", text)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux UID0 EE only")
class ProtectedProducerFilesystemTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires private root-owned0700 /run/proof in the EE")
        self.temp = tempfile.TemporaryDirectory(prefix="producer-", dir=base)
        self.parent = Path(self.temp.name)
        self.addCleanup(self.cleanup)
        lock_patch = mock.patch.object(producer, "PROVISION_LOCK", self.parent/"provision.lock")
        lock_patch.start()
        self.addCleanup(lock_patch.stop)
        self.root = self.parent / "runner"
        self.archive = self.parent / "package.tar.gz"
        self.manifest = self.parent / "manifest.json"
        self.user = SimpleNamespace(pw_uid=2101, pw_gid=2101)
        self.config = {"name": "example", "root": str(self.root), "manifest": str(self.manifest),
                       "storage": str(self.parent / "storage"), "work": str(self.parent / "storage/work"),
                       "home": str(self.parent / "storage/home"), "user": "protected_example", "group": "protected_example",
                       "url": "https://github.com/example", "labels": ["self-hosted", "linux", "arm64"],
                       "runner_group": "Protected", "arch": "arm64", "version": "2.338.2",
                       "archive": str(self.archive), "service_state": "stopped", "operation_reference": "test:operation",
                       "storage_reference": "test:private-storage", "custodian_reference": "test:custodian-reference-only",
                       "profile": "lit-gh-example-0123456789abcdef", "profile_path": "/etc/apparmor.d/lit-gh-example-0123456789abcdef",
                       "profile_sha256": "f" * 64}
        self.make_archive()
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.pin = mock.patch.dict(producer.ARCHIVES, {"arm64": digest})
        self.pin.start()
        self.addCleanup(self.pin.stop)

    def cleanup(self):
        def restore(path):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                return
            os.chown(path, 0, 0)
            if stat.S_ISDIR(info.st_mode):
                path.chmod(0o700)
                for child in path.iterdir():
                    restore(child)
        if self.parent.exists():
            restore(self.parent)
        self.temp.cleanup()

    def make_archive(self, extra=None):
        names = set(installation.REQUIRED_FILES) - {".runner", "runsvc.sh"}
        names.add("bin/systemd.svc.sh.template")
        for source, target in producer.LINKS.items():
            names.add(os.path.normpath(str(Path(source).parent / target)))
        with tarfile.open(self.archive, "w:gz") as archive:
            for name in sorted(names):
                data = (Path(__file__).with_name("github_runner_2_338_2_systemd.svc.sh.template").read_bytes()
                        if name == "bin/systemd.svc.sh.template" else ("synthetic package: " + name).encode())
                member = tarfile.TarInfo(name)
                member.mode, member.size = 0o755, len(data)
                archive.addfile(member, io.BytesIO(data))
            for name, target in producer.LINKS.items():
                member = tarfile.TarInfo(name)
                member.type, member.linkname = tarfile.SYMTYPE, target
                archive.addfile(member)
            if extra:
                archive.addfile(extra, io.BytesIO(b"x") if extra.isfile() else None)
        self.archive.chmod(0o600)

    def stage(self):
        self.root.mkdir(mode=0o700)
        producer.extract(self.archive, self.root, "arm64")

    def settings(self, disabled=True, ephemeral=None):
        value = {"agentId": 61, "agentName": "example", "disableUpdate": disabled, "workFolder": self.config["work"]}
        if ephemeral is not None:
            value["ephemeral"] = ephemeral
        (self.root / ".runner").write_bytes(b"\xef\xbb\xbf" + json.dumps(value).encode())
        (self.root / ".credentials").write_text("synthetic nonsecret credentials fixture")
        (self.root / ".service").write_text("actions.runner.example.service\n")

    def finish(self, ephemeral=None, started=False):
        self.stage()
        self.settings(ephemeral=ephemeral)
        producer.seal(self.root, self.user)
        producer.atomic_json(self.manifest, producer.manifest_for(self.root, self.config, self.user, 61))
        producer.atomic_json(Path(str(self.manifest) + ".transaction"),
                             {"schema": 1, "root": str(self.root), "phase": "complete", "runner_id": 61,
                              "profile_sha256": self.config["profile_sha256"],
                              "ephemeral": ephemeral if ephemeral is not None else False,
                              "service_start_issued": started})

    def test_bound_registration_rejects_cloned_guest_before_native_command(self):
        self.config.update(ephemeral=True, expected_guest_uuid="11111111-1111-4111-8111-111111111111")
        from ephemeral_worker_bootstrap_readiness import NotReady
        with mock.patch("ephemeral_worker_bootstrap_readiness.identity", side_effect=NotReady("bootstrap-guest-uuid")), \
             mock.patch.object(producer, "account", return_value=self.user):
            with self.assertRaisesRegex(Denied, "protected-guest-identity"):
                producer.apply(self.config, "synthetic-token", command=lambda *a, **k: self.fail("native effect"))
        self.assertFalse(self.manifest.exists())
        self.assertFalse(self.root.exists())

    def test_bound_registration_requires_persisted_vm_and_operation(self):
        guest = "11111111-1111-4111-8111-111111111111"
        self.config.update(ephemeral=True, expected_guest_uuid=guest)
        self.finish(ephemeral=True)
        journal = Path(str(self.manifest) + ".transaction")
        original = json.loads(journal.read_bytes())
        cases = ({}, {"expected_guest_uuid": guest, "operation_reference": "other"},
                 {"expected_guest_uuid": "22222222-2222-4222-8222-222222222222",
                  "operation_reference": self.config["operation_reference"]})
        with mock.patch("ephemeral_worker_bootstrap_readiness.identity"), \
             mock.patch.object(producer, "account", return_value=self.user):
            for fields in cases:
                producer.atomic_json(journal, {**original, **fields})
                with self.assertRaisesRegex(Denied, "protected-guest-journal-binding"):
                    producer.apply(self.config, "", command=lambda *a, **k: self.fail("native effect"))
            producer.atomic_json(journal, {**original, **producer.guest_binding(self.config)})
            self.assertTrue(producer.inspect(self.config)["existing"])
            del self.config["expected_guest_uuid"]
            with self.assertRaisesRegex(Denied, "protected-guest-journal-binding"):
                producer.inspect(self.config)

    def test_bound_fresh_registration_persists_binding_through_all_intents(self):
        self.config["expected_guest_uuid"] = "11111111-1111-4111-8111-111111111111"
        records = []
        original = producer.atomic_json
        def record(path, value):
            if str(path).endswith(".transaction"):
                records.append(dict(value))
            return original(path, value)
        with mock.patch("ephemeral_worker_bootstrap_readiness.identity"), \
             mock.patch.object(producer, "atomic_json", side_effect=record):
            self.fresh_apply(True)
        self.assertGreaterEqual(len(records), 6)
        for saved in records:
            self.assertEqual(saved["expected_guest_uuid"], self.config["expected_guest_uuid"])
            self.assertEqual(saved["operation_reference"], self.config["operation_reference"])

    def test_registration_proof_requires_native_stopped_unused_bound_installation(self):
        self.config.update(ephemeral=True, expected_guest_uuid="11111111-1111-4111-8111-111111111111")
        self.finish(ephemeral=True)
        journal = Path(str(self.manifest) + ".transaction")
        saved = json.loads(journal.read_bytes())
        producer.atomic_json(journal, {**saved, **producer.guest_binding(self.config)})
        with mock.patch("ephemeral_worker_bootstrap_readiness.identity"), \
             mock.patch.object(producer, "account", return_value=self.user), \
             mock.patch.object(producer, "confinement"), \
             mock.patch.object(producer, "read_service_state", return_value="stopped") as state:
            receipt = producer.registration_proof(self.config)
            self.assertEqual(receipt["vm_uuid"], self.config["expected_guest_uuid"])
            self.assertEqual(receipt["manifest_sha256"], hashlib.sha256(self.manifest.read_bytes()).hexdigest())
            self.assertEqual(receipt["runner_id"], 61)
            state.return_value = "started"
            with self.assertRaisesRegex(Denied, "stopped-registration-required"):
                producer.registration_proof(self.config)
            state.return_value = "stopped"
            producer.atomic_json(journal, {**saved, **producer.guest_binding(self.config), "service_start_issued": True})
            with self.assertRaisesRegex(Denied, "stopped-registration-required"):
                producer.registration_proof(self.config)

    def test_stdin_envelope_separates_token_from_validated_configuration(self):
        raw = json.dumps({"configuration": self.config, "registration_token": "synthetic-token"}).encode()
        config, token = producer.input_configuration(raw, "apply-input")
        self.assertEqual(token, "synthetic-token")
        self.assertNotIn("registration_token", config)
        for envelope in ({"configuration": self.config},
                         {"configuration": self.config, "registration_token": 5},
                         {"configuration": self.config, "registration_token": "x", "extra": True}):
            with self.assertRaises(Denied):
                producer.input_configuration(json.dumps(envelope).encode(), "apply-input")

    def test_bound_vm_requires_ephemeral_before_identity_collection(self):
        self.config["expected_guest_uuid"] = "11111111-1111-4111-8111-111111111111"
        with mock.patch("ephemeral_worker_bootstrap_readiness.identity") as identity:
            with self.assertRaisesRegex(Denied, "protected-guest-ephemeral-required"):
                producer.configuration(json.dumps(self.config).encode())
        identity.assert_not_called()

    def test_full_synthetic_package_seal_is_accepted_by_real_installation_reader(self):
        self.finish()
        proof = installation.verify_installation(installation.InstallationPolicy(
            str(self.root), str(self.manifest), 61, self.user.pw_uid))
        self.assertEqual(len(proof.symlinks), 6)
        self.assertEqual(proof.runner_version, "2.338.2")
        self.assertEqual((self.root / "_diag").stat().st_uid, 2101)
        self.assertEqual(stat.S_IMODE((self.root / "_diag").stat().st_mode), 0o700)
        self.assertEqual((self.root / ".credentials").stat().st_uid, 0)
        self.assertEqual(stat.S_IMODE((self.root / ".credentials").stat().st_mode), 0o640)

    def test_archive_wrong_pin_denies_before_extracting_any_file(self):
        self.root.mkdir()
        with mock.patch.dict(producer.ARCHIVES, {"arm64": "0" * 64}):
            with self.assertRaisesRegex(Denied, "protected-archive-sha256"):
                producer.extract(self.archive, self.root, "arm64")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_official_archive_root_directory_marker_keeps_private_stage(self):
        marker = tarfile.TarInfo(".")
        marker.type = tarfile.DIRTYPE
        self.make_archive(marker)
        self.root.mkdir(mode=0o700)
        with mock.patch.dict(producer.ARCHIVES, {"arm64": hashlib.sha256(self.archive.read_bytes()).hexdigest()}):
            producer.extract(self.archive, self.root, "arm64")
        self.assertTrue((self.root / "bin/runsvc.sh").is_file())
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)

    def test_non_directory_archive_root_marker_denies_before_writes(self):
        marker = tarfile.TarInfo(".")
        marker.size = 1
        self.make_archive(marker)
        self.root.mkdir(mode=0o700)
        with mock.patch.dict(producer.ARCHIVES, {"arm64": hashlib.sha256(self.archive.read_bytes()).hexdigest()}):
            with self.assertRaisesRegex(Denied, "protected-archive-entry"):
                producer.extract(self.archive, self.root, "arm64")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_archive_escape_and_hardlink_are_rejected_before_extract(self):
        for name, kind in (("../outside", tarfile.REGTYPE), ("bin/borrowed", tarfile.LNKTYPE)):
            with self.subTest(name=name):
                extra = tarfile.TarInfo(name)
                extra.type, extra.size, extra.linkname = kind, (1 if kind == tarfile.REGTYPE else 0), "bin/Runner.Listener"
                self.make_archive(extra)
                self.root.mkdir(exist_ok=True)
                with mock.patch.dict(producer.ARCHIVES, {"arm64": hashlib.sha256(self.archive.read_bytes()).hexdigest()}):
                    with self.assertRaises(Denied):
                        producer.extract(self.archive, self.root, "arm64")
                self.assertEqual(list(self.root.iterdir()), [])

    def test_bom_settings_are_supported_but_false_or_missing_disableupdate_denied(self):
        self.root.mkdir()
        self.settings()
        self.assertEqual(producer.settings(self.root)["agentId"], 61)
        self.settings(False)
        with self.assertRaisesRegex(Denied, "protected-existing-registration-not-disabled"):
            producer.settings(self.root)
        (self.root / ".runner").write_text('{"agentId":61}')
        with self.assertRaises(Denied):
            producer.settings(self.root)

    def test_existing_user_owned_legacy_registration_denied_without_mutation(self):
        self.root.mkdir()
        self.settings()
        path = self.root / ".runner"
        original = path.read_bytes()
        os.chown(path, 2101, 2101)
        with mock.patch.object(producer, "account", return_value=self.user):
            with self.assertRaises(Denied):
                producer.apply(self.config, "not-a-real-token", command=lambda *args, **kwargs: self.fail("native write"))
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse(self.manifest.exists())

    def test_root_ancestor_symlink_or_writable_directory_denied(self):
        real = self.parent / "real"
        real.mkdir()
        link = self.parent / "link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(Denied):
            producer.root_directory(link)
        real.chmod(0o777)
        with self.assertRaises(Denied):
            producer.root_directory(real)

    def test_missing_state_or_config_drift_is_not_an_adoption_route(self):
        self.finish()
        self.manifest.unlink()
        with mock.patch.object(producer, "account", return_value=self.user):
            with self.assertRaises((Denied, OSError)):
                producer.inspect(self.config)
        self.assertTrue(self.root.exists())

    def test_same_state_is_no_native_write_and_changed_false(self):
        self.finish()
        descriptor = self.parent / "manifest.json.collector.json"
        producer.atomic_json(descriptor, {"fixture": "descriptor"})
        with mock.patch.object(producer, "account", return_value=self.user), \
             mock.patch.object(producer, "confinement"), \
             mock.patch.object(producer, "collector_descriptor", return_value={"fixture": "descriptor"}):
            result = producer.apply(self.config, "", command=lambda *args, **kwargs: self.fail("native write"),
                                    state=lambda unit: "stopped")
        self.assertFalse(result["changed"])

    def test_necessary_state_transition_is_writeahead_readback_and_changed_true(self):
        self.finish()
        self.config["service_state"] = "started"
        calls = []
        states = iter(("stopped", "started"))
        def command(argv, **kwargs):
            saved = json.loads(Path(str(self.manifest) + ".transaction").read_bytes())
            self.assertEqual(saved["phase"], "service-state-intent")
            calls.append(argv)
        with mock.patch.object(producer, "account", return_value=self.user), \
             mock.patch.object(producer, "confinement"), \
             mock.patch.object(producer, "write_descriptor", return_value={}):
            result = producer.apply(self.config, "", command=command, state=lambda unit: next(states))
        self.assertTrue(result["changed"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], "start")

    def test_effective_start_lost_reply_is_not_retried(self):
        self.finish()
        self.config["service_state"] = "started"
        calls = []
        def lost(argv, **kwargs):
            calls.append(argv)
            raise Denied("lost-native-response")
        with mock.patch.object(producer, "account", return_value=self.user), mock.patch.object(producer, "confinement"):
            with self.assertRaises(Denied):
                producer.apply(self.config, "", command=lost, state=lambda unit: "stopped")
            with self.assertRaisesRegex(Denied, "protected-uncertain-transaction"):
                producer.apply(self.config, "", command=lost, state=lambda unit: "started")
        self.assertEqual(len(calls), 1)

    def test_fresh_registration_lost_response_retains_stage_and_refuses_replay(self):
        calls = []
        def lost(argv, **kwargs):
            calls.append(argv)
            self.assertNotIn("synthetic-token", " ".join(argv))
            self.assertEqual(kwargs["environment"]["ACTIONS_RUNNER_INPUT_TOKEN"], "synthetic-token")
            raise Denied("lost-registration-response")
        with mock.patch.object(producer, "account", return_value=self.user), mock.patch.object(producer, "confinement"):
            with self.assertRaises(Denied):
                producer.apply(self.config, "synthetic-token", command=lost)
            journal = json.loads(Path(str(self.manifest) + ".transaction").read_bytes())
            self.assertEqual(journal["phase"], "registration-intent")
            self.assertTrue(Path(journal["stage"]).is_dir())
            with self.assertRaisesRegex(Denied, "protected-uncertain-transaction"):
                producer.apply(self.config, "synthetic-token", command=lost)
        self.assertEqual(len(calls), 1)

    def fresh_apply(self, ephemeral):
        self.config["ephemeral"] = ephemeral
        calls = []
        units = self.parent / "systemd"
        units.mkdir(mode=0o755)
        generated_unit = units / "actions.runner.example.service"
        def native(argv, **kwargs):
            calls.append(argv)
            self.assertNotIn("synthetic-token", " ".join(argv))
            if "--disableupdate" in argv:
                self.assertEqual("--ephemeral" in argv, ephemeral)
                stage = Path(kwargs["cwd"])
                value = {"agentId": 61, "agentName": "example", "disableUpdate": True,
                         "workFolder": self.config["work"]}
                if ephemeral:
                    value["ephemeral"] = True
                (stage / ".runner").write_bytes(b"\xef\xbb\xbf" + json.dumps(value).encode())
                (stage / ".credentials").write_text("synthetic nonsecret fixture")
                self.assertEqual(kwargs["environment"]["ACTIONS_RUNNER_INPUT_TOKEN"], "synthetic-token")
            elif "install" in argv:
                (self.root / ".service").write_text("actions.runner.example.service\n")
                os.chown(self.root / "runsvc.sh", 2101, 2101)
                os.chown(self.root / ".service", 2101, 2101)
                generated_unit.write_bytes(b"[Service]\nExecStart=/synthetic/runsvc.sh\n")
                generated_unit.chmod(0o664)
            elif "stop" in argv:
                # Final root ownership must already be restored before start/stop.
                self.assertEqual((self.root / "runsvc.sh").stat().st_uid, 0)
                self.assertEqual((self.root / ".service").stat().st_uid, 0)
                self.assertEqual(stat.S_IMODE(generated_unit.stat().st_mode), 0o644)
                self.assertTrue(self.manifest.exists())
        with mock.patch.object(producer, "account", return_value=self.user), \
             mock.patch.object(producer, "SYSTEMD_DIRECTORY", units), \
             mock.patch.object(producer, "confinement"), mock.patch.object(producer, "install_dropin"), \
             mock.patch.object(producer, "write_descriptor", return_value={"config_sha256": "a" * 64}):
            result = producer.apply(self.config, "synthetic-token", command=native, state=lambda unit: "stopped")
        self.assertTrue(result["changed"])
        self.assertEqual(len(calls), 4)
        self.assertEqual((self.root / "runsvc.sh").stat().st_uid, 0)
        saved = json.loads(Path(str(self.manifest) + ".transaction").read_bytes())
        self.assertEqual(saved["phase"], "complete")
        self.assertIs(saved["ephemeral"], ephemeral)
        self.assertIs(saved["service_start_issued"], False)

    def test_fresh_apply_keeps_token_out_of_argv_and_seals_after_upstream_chown(self):
        self.fresh_apply(False)

    def test_fresh_ephemeral_registration_is_read_back_before_service_install(self):
        self.fresh_apply(True)

    def handoff_fixture(self, lost=False):
        from incus_lease_issuer import native_fence, registration
        import test_github_runner_incus_native_fence as fences
        import test_github_runner_incus_registration as wire
        self.config.update(name="incus-runner-01", labels=["self-hosted", "Linux", "ARM64", "incus"])
        old = self.parent/"legacy"
        old.mkdir(mode=0o755)
        (old/".credentials").write_bytes(b"unchanged opaque legacy fixture")
        os.chown(old/".credentials", 2102, 2102)
        policy = replace(fences.policy(), old_root=str(old), group_name=self.config["runner_group"],
                         target_work_folder=self.config["work"])
        target = registration.VerifiedTarget(policy.owner_id, policy.owner_login, policy.runner_id,
            policy.runner_name, policy.group_id, policy.group_name, policy.target_architecture,
            tuple((name, "system" if kind == "read-only" else "user") for name, kind in policy.labels),
            policy.target_work_folder, "a"*64, int(time.time())+120,
            _authority=registration._FENCE_AUTHORITY)
        units = self.parent/"systemd"
        units.mkdir(mode=0o755)
        unit = "actions.runner.example.incus-runner-01.service"
        store = self.parent/"registration-store"
        self.handoff_commands, self.handoff_requests, self.handoff_disabled = [], [], False
        def wire_call(url, token, body):
            request = json.loads(body)
            self.handoff_requests.append((url, request))
            self.assertEqual(token, "synthetic-token")
            if url == registration.AUTH_URL:
                return wire.auth_response()
            self.assertEqual((request["runner_id"], request["replace"], request["ephemeral"]), (78, True, False))
            if lost:
                raise OSError("modeled lost response")
            return wire.replace_response()
        def query(argv):
            self.assertNotIn(policy.old_unit, argv)
            if "list-units" in argv:
                return b"[]"
            self.assertIn("--property=UnitFileState", argv)
            return b"disabled\n" if self.handoff_disabled else b"enabled\n"
        def command(argv, **kwargs):
            self.handoff_commands.append(argv)
            self.assertNotIn(policy.old_unit, argv)
            self.assertNotIn("synthetic-token", repr(argv)+repr(kwargs))
            self.assertNotIn("start", argv)
            self.assertNotIn("enable", argv)
            self.assertNotIn("--disableupdate", argv)  # Stock config.sh must never register a new ID.
            if "install" in argv:
                self.assertEqual(json.loads((self.root/".runner").read_bytes())["agentId"], 78)
                (self.root/".service").write_text(unit+"\n")
                os.chown(self.root/"runsvc.sh", 2101, 2101)
                os.chown(self.root/".service", 2101, 2101)
                (units/unit).write_bytes(b"[Service]\nExecStart=/synthetic/runsvc.sh\n")
                (units/unit).chmod(0o664)
            if "disable" in argv:
                self.handoff_disabled = True
        stack = ExitStack();self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(producer, "account", return_value=self.user))
        stack.enter_context(mock.patch.object(producer, "SYSTEMD_DIRECTORY", units))
        stack.enter_context(mock.patch.object(producer, "confinement"))
        stack.enter_context(mock.patch.object(producer, "install_dropin"))
        descriptor = {"fixture": "descriptor"}
        def write_descriptor(config, user, runner_id, unit):
            path = Path(config["manifest"]+".collector.json")
            producer.atomic_json(path, descriptor)
            return {"config_path": str(path), "config_sha256": installation.trusted_file(str(path)).sha256}
        stack.enter_context(mock.patch.object(producer, "write_descriptor", side_effect=write_descriptor))
        stack.enter_context(mock.patch.object(producer, "collector_descriptor", return_value=descriptor))
        stack.enter_context(mock.patch.object(native_fence, "issue_after_stop", return_value=target))
        stack.enter_context(mock.patch.object(native_fence.service, "_command", side_effect=query))
        stack.enter_context(mock.patch.object(registration, "_wire", side_effect=wire_call))
        return policy, target, store, old, units, unit, command

    def test_provision_lock_denies_apply_and_handoff_before_any_native_effect(self):
        policy, target, store, old, units, unit, command = self.handoff_fixture()
        with producer.provision_lock():
            with self.assertRaisesRegex(Denied, "protected-provision-busy"):
                producer.apply(self.config, "synthetic-token", command=command)
            with self.assertRaisesRegex(Denied, "protected-provision-busy"):
                producer.migrate_stopped(self.config, policy, str(store), "synthetic-token", command=command)
        self.assertEqual(self.handoff_requests, [])
        self.assertEqual(self.handoff_commands, [])
        self.assertFalse(store.exists())
        self.assertFalse(self.root.exists())
        inode = producer.PROVISION_LOCK.stat().st_ino
        with producer.provision_lock():
            self.assertEqual(producer.PROVISION_LOCK.stat().st_ino, inode)

    def handoff_cli(self, action, envelope):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", ["protected_provision.py", action]), \
             mock.patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(envelope).encode()))), \
             redirect_stdout(out), redirect_stderr(err):
            code = producer.main()
        return code, out.getvalue(), err.getvalue()

    def test_maintenance_cli_inspection_is_readonly_and_apply_uses_the_same_request(self):
        policy, target, store, old, units, unit, command = self.handoff_fixture()
        envelope = {"configuration": self.config, "native_fence": asdict(policy), "registration_stage": str(store)}
        before = set(self.parent.rglob("*"))
        code, out, err = self.handoff_cli("handoff-inspect-input", envelope)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["runner_id"], 78)
        self.assertIs(json.loads(out)["changed"], False)
        self.assertEqual(set(self.parent.rglob("*")), before)
        self.assertFalse(producer.PROVISION_LOCK.exists())
        self.assertEqual((self.handoff_requests, self.handoff_commands), ([], []))
        original = producer.migrate_stopped
        def apply(config, fence, stage, token):
            return original(config, fence, stage, token, command=command, state=lambda unit: "stopped")
        with mock.patch.object(producer, "migrate_stopped", side_effect=apply):
            code, out, err = self.handoff_cli("handoff-apply-input", {**envelope, "registration_token": "synthetic-token"})
            self.assertEqual((code, err), (0, ""))
            self.assertIs(json.loads(out)["changed"], True)
            self.assertNotIn("synthetic-token", out+err)
            self.assertNotIn("private_key", out+err)
            code, out, err = self.handoff_cli("handoff-apply-input", {**envelope, "registration_token": ""})
            self.assertEqual((code, err), (0, ""))
            self.assertIs(json.loads(out)["changed"], False)
        self.assertEqual(len(self.handoff_requests), 2)

    def test_maintenance_envelope_rejects_extra_fields_and_token_in_inspection(self):
        policy, target, store, old, units, unit, command = self.handoff_fixture()
        envelope = {"configuration": self.config, "native_fence": asdict(policy), "registration_stage": str(store)}
        for value in ({**envelope, "registration_token": "synthetic-token"},
                      {**envelope, "native_fence": {**asdict(policy), "_reader": "not-an-input"}},
                      {**envelope, "_register": "not-an-input"}):
            code, out, err = self.handoff_cli("handoff-inspect-input", value)
            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertNotIn("synthetic-token", err)
        self.assertFalse(store.exists())
        self.assertFalse(producer.PROVISION_LOCK.exists())
        self.assertEqual((self.handoff_requests, self.handoff_commands), ([], []))

    def test_provision_lock_rejects_shared_or_unsafe_inode_without_repair(self):
        lock = producer.PROVISION_LOCK
        lock.write_bytes(b"preserve")
        lock.chmod(0o644)
        with self.assertRaisesRegex(Denied, "protected-provision-lock-integrity"):
            with producer.provision_lock():
                self.fail("unsafe lock accepted")
        self.assertEqual(lock.read_bytes(), b"preserve")
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o644)
        lock.chmod(0o600)
        os.link(lock, self.parent/"alias")
        with self.assertRaisesRegex(Denied, "protected-provision-lock-integrity"):
            with producer.provision_lock():
                self.fail("hardlinked lock accepted")

    def test_stopped_expected_id_handoff_seals_fresh_package_and_disables_new_unit(self):
        policy, target, store, old, units, unit, command = self.handoff_fixture()
        before = (old/".credentials").stat()
        result = producer.migrate_stopped(self.config, policy, str(store), "synthetic-token",
                                          command=command, state=lambda unit: "stopped")
        self.assertEqual(result["runner_id"], 78)
        self.assertEqual(len(self.handoff_requests), 2)
        self.assertTrue(self.handoff_disabled)
        self.assertEqual([row[1] for row in self.handoff_commands],
                         [str(self.root/"svc.sh"), "daemon-reload", "disable", "stop"])
        self.assertEqual((old/".credentials").read_bytes(), b"unchanged opaque legacy fixture")
        self.assertEqual((old/".credentials").stat().st_uid, before.st_uid)
        self.assertEqual((self.root/".credentials").read_bytes(), (store/".credentials").read_bytes())
        self.assertEqual(stat.S_IMODE((self.root/".credentials").stat().st_mode), 0o640)
        self.assertEqual((self.root/".credentials").stat().st_uid, 0)
        installation.verify_installation(installation.InstallationPolicy(str(self.root), str(self.manifest), 78, 2101))
        saved = json.loads(Path(str(self.manifest)+".transaction").read_bytes())
        self.assertEqual({k: v for k, v in saved["handoff"].items() if k != "request_sha256"},
                         {"runner_id": 78, "old_unit": policy.old_unit,
                          "new_unit": unit, "registration_stage": str(store)})
        self.assertRegex(saved["handoff"]["request_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(saved["phase"], "complete")
        self.assertIs(saved["service_start_issued"], False)

    def registered_stage_interruption(self):
        from incus_lease_issuer import registration
        policy, target, store, old, units, unit, command = self.handoff_fixture()
        original = registration.replace_registration
        def interrupt_after_registration(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("modeled local interruption after completed registration")
        with mock.patch.object(registration, "replace_registration", side_effect=interrupt_after_registration):
            with self.assertRaises(OSError):
                producer.migrate_stopped(self.config, policy, str(store), "synthetic-token",
                                         command=command, state=lambda unit: "stopped")
        saved = json.loads(Path(str(self.manifest)+".transaction").read_bytes())
        self.assertEqual(saved["phase"], "registration-intent")
        self.assertEqual(json.loads((store/registration.STATE_FILE).read_bytes())["payload"]["phase"], "complete")
        self.assertEqual(self.handoff_commands, [])
        return policy, store, old, command, Path(saved["stage"])

    def test_explicit_completed_registration_stage_publishes_without_new_requests(self):
        policy, store, old, command, stage = self.registered_stage_interruption()
        count = len(self.handoff_requests)
        result = producer.complete_registered_handoff(self.config, policy, str(store),
                                                     command=command, state=lambda unit: "stopped")
        self.assertEqual(result["runner_id"], 78)
        self.assertFalse(stage.exists())
        self.assertEqual(len(self.handoff_requests), count)
        self.assertEqual((old/".credentials").read_bytes(), b"unchanged opaque legacy fixture")
        again = producer.migrate_stopped(self.config, policy, str(store), "",
                                         command=command, state=lambda unit: "stopped")
        self.assertIs(again["changed"], False)
        self.assertEqual(len(self.handoff_requests), count)
        self.assertTrue(self.handoff_disabled)

    def test_completed_registration_stage_matches_restrictive_native_umask(self):
        previous = os.umask(0o027)
        try:
            policy, store, old, command, stage = self.registered_stage_interruption()
            directories = [p for p in stage.rglob("*") if p.is_dir() and not p.is_symlink()]
            self.assertTrue(directories)
            self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o750 for p in directories))
            count = len(self.handoff_requests)
            result = producer.complete_registered_handoff(self.config, policy, str(store),
                                                         command=command, state=lambda unit: "stopped")
            self.assertEqual(result["runner_id"], 78)
            self.assertEqual(len(self.handoff_requests), count)
        finally:
            os.umask(previous)

    def test_retained_registration_stage_drift_denies_without_repair_or_publication(self):
        policy, store, old, command, stage = self.registered_stage_interruption()
        (stage/"foreign").write_bytes(b"preserve unknown bytes")
        before = Path(str(self.manifest)+".transaction").read_bytes()
        with self.assertRaisesRegex(Denied, "protected-completion-stage-drift"):
            producer.complete_registered_handoff(self.config, policy, str(store), command=command)
        self.assertEqual(Path(str(self.manifest)+".transaction").read_bytes(), before)
        self.assertEqual((stage/"foreign").read_bytes(), b"preserve unknown bytes")
        self.assertEqual(self.handoff_commands, [])
        self.assertFalse(self.root.exists())
        self.assertEqual(list(self.parent.glob(".protected-verify-*")), [])

    def test_completed_handoff_reentry_is_readonly_and_drift_is_not_repaired(self):
        policy, target, store, old, units, unit, command = self.handoff_fixture()
        producer.migrate_stopped(self.config, policy, str(store), "synthetic-token",
                                 command=command, state=lambda unit: "stopped")
        commands, requests = len(self.handoff_commands), len(self.handoff_requests)
        before = {path: path.read_bytes() for path in (self.manifest, Path(str(self.manifest)+".transaction"),
                                                      self.root/".credentials", store/".credentials")}
        result = producer.migrate_stopped(self.config, policy, str(store), "",
                                          command=command, state=lambda unit: "stopped")
        self.assertIs(result["changed"], False)
        self.assertEqual(result["runner_id"], 78)
        self.assertEqual({path: path.read_bytes() for path in before}, before)
        with self.assertRaisesRegex(Denied, "protected-handoff-completed-binding"):
            producer.migrate_stopped({**self.config, "operation_reference": "other:operation"}, policy, str(store), "",
                                     command=command, state=lambda unit: "stopped")
        with self.assertRaisesRegex(Denied, "protected-handoff-completed-binding"):
            producer.migrate_stopped(self.config, replace(policy, operations_window_reference="other:window"),
                                     str(store), "", command=command, state=lambda unit: "stopped")
        with self.assertRaisesRegex(Denied, "protected-handoff-completed-service"):
            producer.migrate_stopped(self.config, policy, str(store), "",
                                     command=command, state=lambda unit: "started")
        self.assertEqual((len(self.handoff_commands), len(self.handoff_requests)), (commands, requests))

    def test_handoff_lost_remote_response_keeps_both_journals_and_never_replays(self):
        policy, target, store, old, units, unit, command = self.handoff_fixture(lost=True)
        with self.assertRaises(Denied):
            producer.migrate_stopped(self.config, policy, str(store), "synthetic-token", command=command)
        saved = json.loads(Path(str(self.manifest)+".transaction").read_bytes())
        self.assertEqual(saved["phase"], "registration-intent")
        self.assertEqual(saved["handoff"]["registration_stage"], str(store))
        self.assertTrue(Path(saved["stage"]).is_dir())
        state = json.loads((store/"registration-state.json").read_bytes())
        self.assertEqual(state["payload"]["phase"], "replace-intent")
        with self.assertRaisesRegex(Denied, "protected-handoff-store-exists"):
            producer.migrate_stopped(self.config, policy, str(store), "synthetic-token", command=command)
        self.assertEqual(len(self.handoff_requests), 2)
        self.assertEqual(self.handoff_commands, [])
        self.assertFalse(self.root.exists())
        self.assertFalse((units/unit).exists())

    def test_handoff_wrong_service_marker_never_seals_or_changes_old_unit(self):
        policy, target, store, old, units, unit, command = self.handoff_fixture()
        previous = units/policy.old_unit
        previous.write_bytes(b"retained legacy unit fixture")
        previous.chmod(0o664)
        def wrong_marker(argv, **kwargs):
            command(argv, **kwargs)
            if "install" in argv:
                # Model the installer's wrong marker before its stock chown,
                # without adding DAC_OVERRIDE to the isolated test container.
                os.chown(self.root/".service", 0, 0)
                (self.root/".service").write_text(policy.old_unit+"\n")
                os.chown(self.root/".service", 2101, 2101)
        with self.assertRaisesRegex(Denied, "protected-handoff-installed-unit"):
            producer.migrate_stopped(self.config, policy, str(store), "synthetic-token",
                                     command=wrong_marker, state=lambda unit: "stopped")
        self.assertEqual(previous.read_bytes(), b"retained legacy unit fixture")
        self.assertEqual(stat.S_IMODE(previous.stat().st_mode), 0o664)
        self.assertEqual(len(self.handoff_requests), 2)
        self.assertFalse(self.handoff_disabled)
        saved = json.loads(Path(str(self.manifest)+".transaction").read_bytes())
        self.assertEqual(saved["phase"], "service-install-intent")
        self.assertTrue(store.is_dir())

    def test_handoff_lost_disable_reply_is_held_without_registration_or_service_replay(self):
        policy, target, store, old, units, unit, command = self.handoff_fixture()
        def lost_disable(argv, **kwargs):
            command(argv, **kwargs)
            if "disable" in argv:
                raise Denied("modeled lost disable reply")
        with self.assertRaises(Denied):
            producer.migrate_stopped(self.config, policy, str(store), "synthetic-token",
                                     command=lost_disable, state=lambda unit: "stopped")
        saved = json.loads(Path(str(self.manifest)+".transaction").read_bytes())
        self.assertEqual(saved["phase"], "service-disable-intent")
        count = len(self.handoff_commands)
        with self.assertRaisesRegex(Denied, "protected-uncertain-transaction"):
            producer.migrate_stopped(self.config, policy, str(store), "synthetic-token", command=command)
        self.assertEqual(len(self.handoff_commands), count)
        self.assertEqual(len(self.handoff_requests), 2)
        self.assertIs(saved["service_start_issued"], False)

    def test_handoff_hooks_are_not_accepted_as_cli_configuration(self):
        for key, value in (("_register", "ignored"), ("_handoff", {}), ("registration_stage", "/tmp/ignored")):
            with self.subTest(key=key), self.assertRaisesRegex(Denied, "protected-config-schema"):
                producer.configuration(json.dumps({**self.config, key: value}).encode())

    def test_handoff_new_unit_collision_and_old_tree_overlap_deny_before_remote_write(self):
        policy, target, store, old, units, unit, command = self.handoff_fixture()
        (units/unit).write_bytes(b"foreign service fixture")
        with self.assertRaisesRegex(Denied, "protected-handoff-unit-collision"):
            producer.migrate_stopped(self.config, policy, str(store), "synthetic-token", command=command)
        self.config["root"] = str(old)
        with self.assertRaisesRegex(Denied, "protected-handoff-old-tree-overlap"):
            producer.migrate_stopped(self.config, policy, str(store), "synthetic-token", command=command)
        self.assertEqual(self.handoff_requests, [])
        self.assertEqual(self.handoff_commands, [])
        self.assertFalse(store.exists())
        self.assertEqual((units/unit).read_bytes(), b"foreign service fixture")

    def test_generated_unit_seal_is_no_follow_root_only_and_keeps_content(self):
        units = self.parent / "systemd"
        units.mkdir(mode=0o755)
        path = units / "actions.runner.example.service"
        payload = b"[Service]\nExecStart=/synthetic/runsvc.sh\n"
        path.write_bytes(payload)
        path.chmod(0o664)
        with mock.patch.object(producer, "SYSTEMD_DIRECTORY", units):
            proof = producer.seal_generated_unit(path.name)
            self.assertEqual(proof.sha256, hashlib.sha256(payload).hexdigest())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            alias = units / "actions.runner.alias.service"
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                producer.seal_generated_unit(alias.name)
            os.chown(path, 2101, 2101)
            with self.assertRaises(Denied):
                producer.seal_generated_unit(path.name)

    def test_mismatching_service_readback_retains_unknown_intent(self):
        self.finish()
        self.config["service_state"] = "started"
        with mock.patch.object(producer, "account", return_value=self.user), mock.patch.object(producer, "confinement"):
            with self.assertRaisesRegex(Denied, "protected-service-state-readback"):
                producer.apply(self.config, "", command=lambda *args, **kwargs: None, state=lambda unit: "stopped")
        saved = json.loads(Path(str(self.manifest) + ".transaction").read_bytes())
        self.assertEqual(saved["phase"], "service-state-intent")

    def test_changed_immutable_file_or_added_code_denies_before_native_calls(self):
        self.finish()
        for name in ("bin/Runner.Worker", "unlisted-code"):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes() if path.exists() else None
                path.write_bytes(b"changed")
                with mock.patch.object(producer, "account", return_value=self.user):
                    with self.assertRaises(Denied):
                        producer.apply(self.config, "", command=lambda *args, **kwargs: self.fail("native write"))
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)

    def test_configuration_rejects_relative_workdir_or_unpinned_version(self):
        for key, value in (("work", "_work"), ("version", "2.335.1"), ("home", self.config["root"])):
            with self.subTest(key=key):
                config = {**self.config, key: value}
                with self.assertRaises(Denied):
                    producer.configuration(json.dumps(config).encode())

    def test_ephemeral_request_requires_a_boolean_without_string_coercion(self):
        for value in ("true", 1, [], None):
            with self.subTest(value=value), self.assertRaisesRegex(Denied, "protected-ephemeral-type"):
                producer.configuration(json.dumps({**self.config, "ephemeral": value}).encode())
        self.assertIs(producer.configuration(json.dumps(self.config).encode())["ephemeral"], False)
        self.assertIs(producer.configuration(json.dumps({**self.config, "ephemeral": True}).encode())["ephemeral"], True)

    def test_rootless_configuration_requires_explicit_ranges_stopped_ephemeral_and_fixed_path(self):
        selected = {**self.config, 'ephemeral': True, 'rootless_engine':
                    {'subuid_start': 100000, 'subgid_start': 100000}}
        self.assertEqual(producer.configuration(json.dumps(selected).encode())['rootless_engine'],
                         selected['rootless_engine'])
        for changed in ({'ephemeral': False}, {'service_state': 'started'}, {'name': 'bad_name'},
                        {'rootless_engine': {'subuid_start': True, 'subgid_start': 100000}},
                        {'rootless_engine': {'subuid_start': 100000}}, {'rootless_engine': None}):
            with self.subTest(changed=changed), self.assertRaises(Denied):
                producer.configuration(json.dumps({**selected, **changed}).encode())
        text = producer.dropin(selected).decode()
        self.assertIn('NoNewPrivileges=yes\n', text)
        self.assertIn('CapabilityBoundingSet=\nAmbientCapabilities=\n', text)
        self.assertIn('Environment=WUNDER_CONTAINER_ENGINE=podman\n', text)
        self.assertIn('Environment=PATH=/usr/local/libexec/lit-runner-engine:', text)

    def test_engine_bridge_reuses_actual_installation_and_one_use_registration_proof(self):
        import rootless_engine
        self.config.update(ephemeral=True, rootless_engine={'subuid_start': 100000, 'subgid_start': 100000})
        self.finish(ephemeral=True)
        source = self.parent / 'rootless_podman_client.py'
        source.write_bytes(b'#!/usr/bin/python3\n# synthetic nonsecret client fixture\n')
        source.chmod(0o600)
        with mock.patch.object(producer, '__file__', str(self.parent / 'protected_provision.py'), create=True), \
                mock.patch.object(producer, 'account', return_value=self.user), \
                mock.patch.object(producer, 'confinement'), mock.patch.object(rootless_engine, 'prepare') as prepare:
            producer.prepare_engine(self.config)
            binding, ranges, payload, command, recheck = prepare.call_args.args
            self.assertEqual(binding['runner_id'], 61)
            self.assertEqual(binding['uid'], 2101)
            self.assertEqual(binding['manifest_sha256'], installation.trusted_file(str(self.manifest)).sha256)
            self.assertEqual(payload, source.read_bytes())
            self.assertEqual(recheck()['runner_id'], 61)
            transaction = Path(str(self.manifest) + '.transaction')
            saved = json.loads(transaction.read_bytes())
            saved['service_start_issued'] = True
            producer.atomic_json(transaction, saved)
            with self.assertRaisesRegex(Denied, 'runner-already-used'):
                recheck()
            with self.assertRaisesRegex(Denied, 'runner-already-used'):
                producer.prepare_engine(self.config)
            self.assertEqual(prepare.call_count, 1)

    def test_existing_persistent_runner_cannot_be_converted_to_ephemeral(self):
        self.finish()
        self.config["ephemeral"] = True
        with mock.patch.object(producer, "account", return_value=self.user):
            with self.assertRaisesRegex(Denied, "protected-lifecycle-drift"):
                producer.apply(self.config, "synthetic-token", command=lambda *a, **k: self.fail("native effect"))

    def test_ephemeral_runner_can_start_once_then_refuses_restart_after_exit(self):
        self.config["ephemeral"] = True
        self.finish(ephemeral=True)
        self.config["service_state"] = "started"
        descriptor = Path(str(self.manifest) + ".collector.json")
        producer.atomic_json(descriptor, {"fixture": "descriptor"})
        state = {"value": "stopped"}
        calls = []
        def native(argv, **kwargs):
            calls.append(argv)
            state["value"] = "started"
        with mock.patch.object(producer, "account", return_value=self.user), \
             mock.patch.object(producer, "confinement"), \
             mock.patch.object(producer, "write_descriptor", return_value={"config_sha256": "a" * 64}), \
             mock.patch.object(producer, "collector_descriptor", return_value={"fixture": "descriptor"}):
            self.assertTrue(producer.apply(self.config, "", command=native,
                                          state=lambda unit: state["value"])["changed"])
            self.assertFalse(producer.apply(self.config, "", command=native,
                                           state=lambda unit: state["value"])["changed"])
            state["value"] = "stopped"
            with self.assertRaisesRegex(Denied, "protected-ephemeral-start-already-issued"):
                producer.apply(self.config, "", command=native, state=lambda unit: state["value"])
        self.assertEqual(len(calls), 1)
        self.assertIs(json.loads(Path(str(self.manifest) + ".transaction").read_bytes())["service_start_issued"], True)

    def test_ephemeral_registration_must_persist_true_before_publish_or_service_install(self):
        self.config["ephemeral"] = True
        calls = []
        def persistent_reply(argv, **kwargs):
            calls.append(argv)
            self.assertIn("--ephemeral", argv)
            self.assertNotIn("synthetic-token", " ".join(argv))
            stage = Path(kwargs["cwd"])
            (stage / ".runner").write_text(json.dumps({"agentId": 61, "agentName": "example",
                "disableUpdate": True, "workFolder": self.config["work"]}))
        with mock.patch.object(producer, "account", return_value=self.user), mock.patch.object(producer, "confinement"):
            with self.assertRaisesRegex(Denied, "protected-lifecycle-drift"):
                producer.apply(self.config, "synthetic-token", command=persistent_reply)
            with self.assertRaisesRegex(Denied, "protected-uncertain-transaction"):
                producer.apply(self.config, "synthetic-token", command=persistent_reply)
        self.assertEqual(len(calls), 1)
        self.assertFalse(self.root.exists())
        saved = json.loads(Path(str(self.manifest) + ".transaction").read_bytes())
        self.assertEqual(saved["phase"], "registration-intent")
        self.assertTrue(Path(saved["stage"]).exists())


if __name__ == "__main__":
    unittest.main()
