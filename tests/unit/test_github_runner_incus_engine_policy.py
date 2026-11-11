"""Root compiler contracts; no Podman/namespace/image execution or authority.

Filesystem cases run only in private /run/proof in the official Root EE. Only
fixed /usr/bin/podman's package-read result is modeled: actual executor lacks
Podman. All remaining ownership/inventory/file reads are real. Synthetic archive
and tree bytes are separately pinned, not a claim of archive extraction proof.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
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
from incus_lease_issuer import engine_policy as engine, identity  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class RootGuardTests(unittest.TestCase):
    def test_literal_systemd_template_marker_preserves_relative_path_boundaries(self):
        relative = "roles/dhcp_deploy/templates/podman-kube@.service.j2"
        self.assertEqual(engine._relative(relative), relative)
        self.assertEqual(engine._path("/sealed/" + relative), "/sealed/" + relative)
        for invalid in ("/" + relative, "../" + relative, "roles/../" + relative,
                        "roles//podman@.service", "roles/./podman@.service", "roles/podman@.service/",
                        "roles/podman@\x00.service", "roles/podman@\n.service", "roles/podman@\x7f.service",
                        "roles/podman@\\.service", "roles/podman@;id.service", "roles/podman@$(id).service",
                        "/".join(["directory"] * 32 + ["podman@.service"]), "a" * 1025):
            with self.subTest(path=invalid), self.assertRaisesRegex(Denied, "engine-relative-path"):
                engine._relative(invalid)
        for invalid in ("/sealed/../podman@.service", "/sealed//podman@.service",
                        "/sealed/podman@\n.service", "/sealed/podman@;id.service"):
            with self.subTest(path=invalid), self.assertRaisesRegex(Denied, "engine-path"):
                engine._path(invalid)

    def test_nonroot_cannot_supply_a_compiler_descriptor(self):
        if os.geteuid() == 0:
            self.skipTest("production Root guard runs separately in nonroot EE")
        with self.assertRaisesRegex(Denied, "engine-policy-root-required"):
            engine.compile_engine_policy("/untrusted", "a" * 64)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux UID0 EE only")
class RootEngineCompilerTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires namespace-private Root0700 /run/proof tmpfs")
        self.temp = tempfile.TemporaryDirectory(prefix="engine-policy-", dir=base)
        self.root = Path(self.temp.name)
        self.addCleanup(self.cleanup)
        self.descriptor = self.root / "engine.json"
        self.context = self.root / "context"
        self.output = self.root / "output"
        for path in (self.context, self.output, self.root / "storage", self.root / "runroot"):
            path.mkdir(mode=0o700)
        (self.context / "servercerts").mkdir(mode=0o700)
        for name in engine.CONTEXT_FILES:
            path = self.context / name
            path.write_bytes(("synthetic context fixture: " + name).encode())
            path.chmod(0o600)
        trees = {}
        for key, names in (("controller", engine.CONTROLLER_FILES), ("workspace", {"source.yml", ".git/HEAD"}),
                           ("candidate", {"MANIFEST.json", "roles/example/tasks/main.yml"})):
            root = self.root / key
            root.mkdir(mode=0o700)
            dirs, files = set(), {}
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                path.write_bytes(("synthetic immutable fixture: " + key + "/" + name).encode())
                path.chmod(0o644)
                files[name] = digest(path.read_bytes())
                for parent in path.relative_to(root).parents:
                    if str(parent) != ".":
                        dirs.add(str(parent))
            trees[key] = {"path": str(root), "files": files, "directories": sorted(dirs)}
        archives = {}
        for key in ("controller", "candidate"):
            path = self.root / (key + ".tar.gz")
            path.write_bytes(("synthetic pinned archive: " + key).encode())
            path.chmod(0o600)
            archives[key] = {"path": str(path), "sha256": digest(path.read_bytes())}
        values = {"PROFILE": "heavy", "SCENARIO": "example_heavy", "TARGET": "ubuntu24.04",
                  "TARGET_DISPOSITION": "candidate", "ROLES": "example", "IMAGE": "images:ubuntu/24.04/cloud",
                  "INSTANCE_TYPE": "container", "CANDIDATE_ARTIFACT": "fixture-package", "SOURCE_SHA": "a" * 40,
                  "JUNIT_REQUIRED": "false", "ALLURE_REQUIRED": "false", "CPU_LIMIT": "2", "MEMORY_LIMIT": "4GiB", "DISK_LIMIT": "20GiB"}
        environment = {"GITHUB_REPOSITORY": "ltn-it/ansible-collection-supplementary", "GITHUB_REPOSITORY_ID": "1103407173",
                       "GITHUB_RUN_ID": "501", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "fixture_cell", "GITHUB_SHA": "a" * 40,
                       "GITHUB_WORKFLOW": "Synthetic approved fixture"}
        environment.update({"QUALITY_INPUT_" + key: value for key, value in values.items()})
        self.data = {"schema": 1, "image": {"index_sha256": engine.IMAGE_INDEX, "manifest_sha256": engine.IMAGE_CHILD,
                    "platform": "linux/amd64"}, "runner_uid": 2101, "runner_gid": 2102, "cell_uid": 1000, "cell_gid": 1001,
                    "uid_map": {"host_base": 200000, "size": 65536}, "gid_map": {"host_base": 300000, "size": 65536},
                    "limits": {"cpu_millis": 1500, "memory_bytes": 2147483648, "timeout_seconds": 1200},
                    "network_namespace_path": "/run/netns/lit-lease-" + "a" * 32, "cgroup_parent": "lit-lease-" + "a" * 32 + ".slice",
                    "engine": {"executable": "/usr/bin/podman", "executable_sha256": "e" * 64,
                               "storage_root": str(self.root / "storage"), "runroot": str(self.root / "runroot")},
                    "archives": archives, "trees": trees, "context_path": str(self.context), "output_path": str(self.output),
                    "environment": environment}
        self.data["capture"] = {"stdout_limit": 1048576, "stderr_limit": 1048576, "total_limit": 2097152}
        real_file = engine._file
        def fixed_package_read(path, expected=None, **kwargs):
            if path == engine.ENGINE:
                if expected != "e" * 64:
                    raise Denied("fixture-fixed-package-hash")
                return SimpleNamespace(path=path, sha256="e" * 64)
            return real_file(path, expected, **kwargs)
        self.mock_file = mock.patch.object(engine, "_file", side_effect=fixed_package_read)
        self.mock_file.start()
        self.addCleanup(self.mock_file.stop)

    def test_actual_systemd_template_paths_are_hashed_and_still_reject_links_and_drift(self):
        tree = deepcopy(self.data["trees"]["workspace"])
        for role in ("dhcp_deploy", "semaphore_deploy"):
            relative = "roles/" + role + "/templates/podman-kube@.service.j2"
            path = Path(tree["path"]) / relative
            path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
            path.write_bytes(b"synthetic systemd template fixture\n")
            path.chmod(0o644)
            tree["files"][relative] = digest(path.read_bytes())
            for parent in Path(relative).parents:
                if parent != Path(".") and str(parent) not in tree["directories"]:
                    tree["directories"].append(str(parent))
        self.assertEqual(engine._tree(tree)["files"], tree["files"])
        path.write_bytes(b"changed template\n")
        with self.assertRaisesRegex(Denied, "engine-file-drift"):
            engine._tree(tree)
        path.unlink()
        path.symlink_to("/etc/passwd")
        with self.assertRaisesRegex(Denied, "engine-inventory-owner"):
            engine._tree(tree)

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
        if self.root.exists():
            restore(self.root)
        self.temp.cleanup()

    def compile(self, data=None):
        raw = json.dumps(self.data if data is None else data, sort_keys=True, separators=(",", ":")).encode()
        self.descriptor.write_bytes(raw)
        self.descriptor.chmod(0o600)
        return engine.compile_engine_policy(str(self.descriptor), digest(raw))

    def retain(self):
        original = self.compile()
        path = Path(self.data["engine"]["runroot"]) / "engine-manifest.json"
        path.write_bytes(original.canonical_bytes)
        path.chmod(0o600)
        return original, path

    def validate_retained(self, original):
        return engine.validate_retained_policy(str(self.descriptor), original.descriptor_sha256, original.sha256)

    def test_running_output_contents_do_not_replace_original_signed_manifest(self):
        original, path = self.retain()
        (self.output / "artifacts").mkdir()
        (self.output / "artifacts/results.xml").write_bytes(b"actual mutable output fixture")
        (self.output / "untrusted-link").symlink_to("/etc/shadow")
        self.assertEqual(self.validate_retained(original), original)
        self.assertEqual(path.read_bytes(), original.canonical_bytes)
        with self.assertRaises(Denied):
            engine.compile_engine_policy(str(self.descriptor), original.descriptor_sha256)

    def test_running_output_directory_identity_cannot_be_replaced(self):
        original, _ = self.retain()
        self.output.rename(self.output.with_name("old-output"))
        self.output.mkdir(mode=0o700)
        with self.assertRaisesRegex(Denied, "engine-retained-output-replaced"):
            self.validate_retained(original)

    def test_retained_root_manifest_tampering_and_wrong_digest_deny(self):
        original, path = self.retain()
        changed = json.loads(path.read_bytes())
        changed["argv"] = ["sh", "-c", "untrusted"]
        path.write_bytes(engine._canonical(changed))
        with self.assertRaises(Denied):
            self.validate_retained(original)
        path.write_bytes(original.canonical_bytes)
        with self.assertRaises(Denied):
            engine.validate_retained_policy(str(self.descriptor), original.descriptor_sha256, "f" * 64)

    def test_running_immutable_controller_and_tls_files_still_revalidated(self):
        original, _ = self.retain()
        for path in (Path(self.data["trees"]["controller"]["path"]) / "run-cell.py", self.context / "client.key"):
            before = path.read_bytes()
            path.write_bytes(b"changed immutable bytes")
            with self.assertRaises(Denied):
                self.validate_retained(original)
            path.write_bytes(before)
        self.assertEqual(self.validate_retained(original), original)

    def test_output_identity_is_present_in_prestart_signed_canonical_bytes(self):
        original = self.compile()
        output = json.loads(original.canonical_bytes)["output"]
        info = self.output.stat()
        self.assertEqual((output["device"], output["inode"], output["uid"], output["gid"], output["mode"]),
                         (info.st_dev, info.st_ino, info.st_uid, info.st_gid, 0o700))

    def test_exact_fixed_argv_actual_targets_image_and_sandbox(self):
        result = self.compile()
        details = json.loads(result.canonical_bytes)
        name = "lit-lease-" + "a" * 32
        self.assertIn("--name=" + name, result.argv)
        self.assertIn("--cidfile=" + self.data["engine"]["runroot"] + "/container.cid", result.argv)
        self.assertIn("--label=io.lightning-it.lease=" + "a" * 32, result.argv)
        self.assertIn("--label=io.lightning-it.descriptor=" + result.descriptor_sha256, result.argv)
        self.assertEqual(details["runtime"]["name"], name)
        self.assertEqual(details["runtime"]["labels"]["io.lightning-it.descriptor"], result.descriptor_sha256)
        for flag in ("--pid=private", "--ipc=private", "--uts=private", "--cgroupns=private"):
            self.assertIn(flag, result.argv)
        self.assertEqual(result.argv[0], "/usr/bin/podman")
        self.assertEqual(result.argv[-3:], (engine.PODMAN_IMAGE, "python3", "/controller/run-cell.py"))
        self.assertEqual(result.environment["QUALITY_DEVTOOLS_IMAGE"], engine.IMAGE)
        self.assertEqual(engine.PODMAN_IMAGE.split("@", 1)[1], engine.IMAGE.split("@", 1)[1])
        self.assertNotIn(":", engine.PODMAN_IMAGE.split("@", 1)[0])
        for value in ("--platform=linux/amd64", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
                      "--pids-limit=512", "--read-only-tmpfs=false", "--user=1000:1001", "--cpus=1.500", "--memory=2147483648"):
            self.assertIn(value, result.argv)
        mounts = [result.argv[i + 1] for i, value in enumerate(result.argv[:-1]) if value == "--mount"]
        self.assertEqual(len(mounts), 5)
        for target in ("/workspace", "/candidate", "/controller", "/incus", "/quality"):
            self.assertTrue(any("destination=" + target + "," in value for value in mounts))
        self.assertTrue(all("readonly" in value for value in mounts if "destination=/quality," not in value))
        self.assertFalse(any(value in ("--privileged", "--network=host", "--user=0:0", "--device") for value in result.argv))
        self.assertFalse(any("docker.sock" in value or "incus.sock" in value for value in result.argv))

    def test_root_context_maps_to_reserved_host_then_nonroot_cell_without_chown(self):
        before = {name: (self.context / name).stat().st_uid for name in engine.CONTEXT_FILES}
        result = self.compile()
        context_mount = next(value for value in result.argv if "destination=/incus," in value)
        self.assertIn("idmap=uids=0-201000-1;gids=0-301001-1", context_mount)
        self.assertEqual(before, {name: (self.context / name).stat().st_uid for name in engine.CONTEXT_FILES})
        self.assertTrue(all(owner == 0 for owner in before.values()))
        self.assertNotIn(":U", " ".join(result.argv))
        self.assertEqual(result.environment["QUALITY_HOST_UID"], "2101")
        self.assertEqual(result.environment["QUALITY_EFFECTIVE_UID"], "1000")
        self.assertEqual(result.environment["QUALITY_EFFECTIVE_GID"], "1001")

    def test_capture_limits_are_required_closed_and_bound_before_engine_signing(self):
        result = self.compile()
        self.assertEqual(identity.decode_json(result.canonical_bytes)["capture"], self.data["capture"])
        self.assertIn("--events-backend=none", result.argv)
        self.assertIn("--log-driver=passthrough", result.argv)
        self.assertIn("--tmpdir=" + self.data["engine"]["runroot"], result.argv)
        original = dict(self.data["capture"])
        for capture in ({}, {**original, "stdout_limit": True},
                        {**original, "stderr_limit": engine.MAX_CAPTURE_STREAM_BYTES + 1},
                        {**original, "total_limit": sum(original[key] for key in ("stdout_limit", "stderr_limit")) + 1},
                        {**original, "path": "/untrusted"}):
            with self.subTest(capture=capture):
                self.data["capture"] = capture
                with self.assertRaises(Denied):
                    self.compile()
        self.data["capture"] = {**original, "total_limit": 1}
        self.assertEqual(identity.decode_json(self.compile().canonical_bytes)["capture"]["total_limit"], 1)

    def test_manifest_is_immutable_and_digest_covers_archives_argv_maps_limits(self):
        first = self.compile()
        self.assertEqual(digest(first.canonical_bytes), first.sha256)
        with self.assertRaises(FrozenInstanceError):
            first.sha256 = "a" * 64
        with self.assertRaises(TypeError):
            first.environment["HOME"] = "/other"
        changed = deepcopy(self.data)
        changed["limits"]["cpu_millis"] = 2000
        self.assertNotEqual(self.compile(changed).sha256, first.sha256)
        changed = deepcopy(self.data)
        changed["uid_map"]["host_base"] = 400000
        self.assertNotEqual(self.compile(changed).sha256, first.sha256)

    def test_context_late_binding_does_not_create_digest_cycle_or_validate_signature(self):
        first = self.compile()
        binding = self.context / "binding.json"
        binding.write_bytes(b'{"fixture":"signature-not-validated-by-compiler"}')
        binding.chmod(0o600)
        second = self.compile()
        self.assertEqual(first.sha256, second.sha256)
        self.assertIn(b"late-Root-signed-context-not-validated-here", second.canonical_bytes)

    def test_namespace_is_structural_only_not_fabricated_regular_file_proof(self):
        result = self.compile()
        details = json.loads(result.canonical_bytes)
        self.assertEqual(details["network_namespace"]["proof"], "structural-only-native-nsfs-preflight-required")
        self.assertNotIn("inode", details["network_namespace"])
        self.assertNotIn("nsfs_verified", details["network_namespace"])
        changed = deepcopy(self.data)
        changed["network_namespace_path"] = str(self.root / "ordinary-regular-file")
        with self.assertRaises(Denied):
            self.compile(changed)

    def test_closed_schema_no_job_commands_flags_environment_or_mount_injection(self):
        for key, value in (("argv", ["sh", "-c", "untrusted"]), ("privileged", True), ("devices", ["/dev/kvm"]),
                           ("mounts", ["/run/podman.sock:/var/run/docker.sock"])):
            with self.subTest(key=key):
                with self.assertRaises(Denied):
                    self.compile({**self.data, key: value})
        for name in ("LD_PRELOAD", "BASH_ENV", "CONTAINER_HOST", "DOCKER_HOST", "WUNDER_DEVTOOLS_PRIVILEGED"):
            changed = deepcopy(self.data)
            changed["environment"][name] = "untrusted"
            with self.assertRaises(Denied):
                self.compile(changed)
        changed = deepcopy(self.data)
        changed["context_path"] = str(self.context) + ",destination=/host"
        with self.assertRaises(Denied):
            self.compile(changed)

    def test_wrong_image_arch_platform_or_executable_denies(self):
        for field, value in (("index_sha256", "3174f45c1f8c769d9309612382758b8599cedf892e81b796d7e5b2d8cf24d4db"),
                             ("manifest_sha256", "e4a5a28e75e5b355640ad768047497e102fe1216620c97ee388cced8fa087c63"),
                             ("platform", "linux/arm64")):
            changed = deepcopy(self.data)
            changed["image"][field] = value
            with self.assertRaises(Denied):
                self.compile(changed)
        changed = deepcopy(self.data)
        changed["engine"]["executable"] = "/tmp/untrusted-podman"
        with self.assertRaises(Denied):
            self.compile(changed)

    def test_nonroot_cell_and_nonoverlapping_uid_gid_maps_required(self):
        variants = []
        for field, value in (("cell_uid", 0), ("cell_gid", 0), ("cell_uid", 2101), ("cell_gid", 2102)):
            variants.append({**self.data, field: value})
        changed = deepcopy(self.data)
        changed["uid_map"] = {"host_base": 200000, "size": 65536}
        changed["runner_uid"] = 200001
        variants.append(changed)
        changed = deepcopy(self.data)
        changed["runner_gid"] = 300001
        variants.append(changed)
        changed = deepcopy(self.data)
        changed["gid_map"]["size"] = 1024
        changed["cell_gid"] = 2000
        variants.append(changed)
        for data in variants:
            with self.assertRaises(Denied):
                self.compile(data)

    def test_explicit_finite_cpu_memory_runtime_limits_not_remote_vm_quotas(self):
        for field, value in (("cpu_millis", 0), ("cpu_millis", True), ("memory_bytes", -1),
                             ("timeout_seconds", 5401), ("timeout_seconds", "1200")):
            changed = deepcopy(self.data)
            changed["limits"][field] = value
            with self.assertRaises(Denied):
                self.compile(changed)
        changed = deepcopy(self.data)
        del changed["limits"]["memory_bytes"]
        with self.assertRaises(Denied):
            self.compile(changed)

    def test_archive_or_materialized_file_drift_and_missing_entry_deny(self):
        candidate = Path(self.data["archives"]["candidate"]["path"])
        original = candidate.read_bytes()
        candidate.write_bytes(b"changed archive")
        with self.assertRaises(Denied):
            self.compile()
        candidate.write_bytes(original)
        entry = self.root / "controller/run-cell.py"
        original = entry.read_bytes()
        entry.write_bytes(b"changed controller")
        with self.assertRaises(Denied):
            self.compile()
        entry.write_bytes(original)
        entry.unlink()
        with self.assertRaises(Denied):
            self.compile()

    def test_symlink_hardlink_extra_file_or_writable_tree_denies(self):
        path = self.root / "workspace/unlisted"
        path.symlink_to(self.root / "controller/run-cell.py")
        with self.assertRaises(Denied):
            self.compile()
        path.unlink()
        original = self.root / "controller/run-cell.py"
        os.link(original, path)
        with self.assertRaises(Denied):
            self.compile()
        path.unlink()
        path.write_bytes(b"unlisted")
        with self.assertRaises(Denied):
            self.compile()
        path.unlink()
        (self.root / "candidate").chmod(0o777)
        with self.assertRaises(Denied):
            self.compile()

    def test_nested_inventory_denial_closes_every_scandir_and_directory_fd(self):
        (self.root / "candidate/roles/example/tasks/unlisted").write_bytes(b"unlisted nested data")
        real_scandir = os.scandir
        scans = []
        class ObservedScan:
            def __init__(self, fd):
                self.fd = fd
                self.iterator = real_scandir(fd)
                self.closed = False
                scans.append(self)

            def __iter__(self):
                return self.iterator

            def __enter__(self):
                return self.iterator

            def __exit__(self, *_):
                self.iterator.close()
                self.closed = True

        try:
            with mock.patch.object(engine.os, "scandir", side_effect=ObservedScan):
                with self.assertRaises(Denied):
                    self.compile()
            self.assertGreaterEqual(len(scans), 4)
            self.assertTrue(all(scan.closed for scan in scans))
            for scan in scans:
                with self.assertRaises(OSError):
                    os.fstat(scan.fd)
        finally:
            # Keep the regression fixture clean even against the old leaking
            # implementation; this does not hide the failed closure assertion.
            for scan in scans:
                scan.iterator.close()

    def test_private_context_root_owner_mode_inventory_and_fresh_output_required(self):
        key = self.context / "client.key"
        key.chmod(0o640)
        with self.assertRaises(Denied):
            self.compile()
        key.chmod(0o600)
        os.chown(key, 2101, 2101)
        with self.assertRaises(Denied):
            self.compile()
        os.chown(key, 0, 0)
        (self.output / "control").mkdir()
        with self.assertRaises(Denied):
            self.compile()

    def test_path_overlap_and_wrong_native_source_tuple_denies(self):
        changed = deepcopy(self.data)
        changed["output_path"] = changed["context_path"]
        with self.assertRaises(Denied):
            self.compile(changed)
        for field, value in (("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_SHA", "invalid"), ("GITHUB_REPOSITORY_ID", "0")):
            changed = deepcopy(self.data)
            changed["environment"][field] = value
            with self.assertRaises(Denied):
                self.compile(changed)

    def test_controller_and_candidate_source_shas_are_separate_root_boundaries(self):
        changed = deepcopy(self.data)
        changed["environment"]["QUALITY_INPUT_SOURCE_SHA"] = "b" * 40
        result = self.compile(changed)
        self.assertEqual(result.environment["GITHUB_SHA"], "a" * 40)
        self.assertEqual(result.environment["QUALITY_INPUT_SOURCE_SHA"], "b" * 40)

    def test_typed_thin_profile_inputs_cannot_smuggle_unsupported_values(self):
        for field, value in (("PROFILE", "ordinary"), ("ROLES", "example;sh"), ("CPU_LIMIT", "0"),
                             ("MEMORY_LIMIT", "unlimited"), ("DISK_LIMIT", "-1GiB"), ("SCENARIO", "../other")):
            changed = deepcopy(self.data)
            changed["environment"]["QUALITY_INPUT_" + field] = value
            with self.assertRaises(Denied):
                self.compile(changed)

    def test_descriptor_wrong_hash_duplicate_keys_and_nonprivate_mode_deny(self):
        self.compile()
        with self.assertRaises(Denied):
            engine.compile_engine_policy(str(self.descriptor), "0" * 64)
        raw = b'{"schema":1,"schema":1}'
        self.descriptor.write_bytes(raw)
        with self.assertRaises(Denied):
            engine.compile_engine_policy(str(self.descriptor), digest(raw))
        self.compile()
        self.descriptor.chmod(0o644)
        with self.assertRaises(Denied):
            engine.compile_engine_policy(str(self.descriptor), digest(self.descriptor.read_bytes()))


if __name__ == "__main__":
    unittest.main()
