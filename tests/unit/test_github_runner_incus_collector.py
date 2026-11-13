"""Collector tests: integrated mocks are NOT a real service/profile pilot proof."""
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import inspect
import mmap
import os
from pathlib import Path
import sys
import tempfile
from types import MappingProxyType
import unittest
from unittest.mock import patch

import test_github_runner_incus_worker as lineage_fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import collector, installation, kernel, service  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class CollectorInputTests(unittest.TestCase):
    def test_only_managed_roles_accept_exact_observed_shared_jit_coordinates(self):
        raw = (b"1000-2000 ---s 0 00:01 31 /memfd:doublemapper (deleted)\n"
               b"2000-3000 r-xs 0 00:01 31 /memfd:doublemapper (deleted)\n"
               b"3000-4000 rw-s 0 00:01 31 /memfd:doublemapper (deleted)\n")
        for role in ("listener", "worker"):
            self.assertEqual(collector.parse_maps(raw, role=role),
                             (collector.MappedFile(collector.JIT_NAME, 0, 1, 31, True),))
        for role in (None, "main", "node", "job"):
            with self.subTest(role=role), self.assertRaises(Denied):
                collector.parse_maps(raw, role=role)
        for changed in (raw.replace(b"rw-s", b"rw-p"), raw.replace(b"r-xs", b"rwxp"),
                        raw.replace(b"doublemapper", b"untrusted"), raw.replace(b"00:01", b"00:02")):
            with self.assertRaises(Denied):
                collector.parse_maps(changed, role="worker")

    def test_maps_accepts_regular_coordinates_and_anonymous_jit_bss_without_file_claim(self):
        raw = (b"1000-2000 r-xp 00000000 08:01 123 /usr/lib/synthetic.so\n"
               b"2000-3000 rw-p 00001000 08:01 123 /usr/lib/synthetic.so\n"
               b"3000-4000 rw-p 00000000 00:00 0\n"
               b"4000-5000 rwxp 00000000 00:00 0 [anon:JIT]\n")
        self.assertEqual(collector.parse_maps(raw),
                         (collector.MappedFile("/usr/lib/synthetic.so", 8, 1, 123),))

    def test_named_deleted_memfd_unknown_or_conflicting_backing_denies(self):
        paths = ("/memfd:doublemapper (deleted)", "/usr/lib/old.so (deleted)",
                 "[unknown-file]", "/tmp/has space.so", "/tmp/../escape.so")
        for path in paths:
            with self.subTest(path_kind=path[:8]), self.assertRaises(Denied):
                collector.parse_maps(("1000-2000 r-xp 0 08:01 123 " + path + "\n").encode())
        with self.assertRaises(Denied):
            collector.parse_maps(b"1000-2000 r-xp 0 08:01 123 /usr/lib/a.so\n"
                                 b"2000-3000 r-xp 0 08:01 124 /usr/lib/a.so\n")

    def test_maps_malformed_or_oversized_input_denies(self):
        for raw in (b"", b"bad row\n", b"2000-1000 r-xp 0 08:01 1 /a\n",
                    b"1000-2000 rwqz 0 08:01 1 /a\n", b"x" * (collector.MAPS_LIMIT + 1)):
            with self.subTest(length=len(raw)), self.assertRaises(Denied):
                collector.parse_maps(raw)

    def test_only_selected_diagnostic_flag_is_returnless_and_exactly_disabled(self):
        self.assertIsNone(collector.diagnostics_disabled(b"PRIVATE_SENTINEL=not-logged\x00DOTNET_EnableDiagnostics=0\x00"))
        for raw in (b"OTHER=1\x00", b"DOTNET_EnableDiagnostics=1\x00",
                    b"DOTNET_EnableDiagnostics=0\x00DOTNET_EnableDiagnostics=0\x00",
                    b"DOTNET_EnableDiagnostics=0", b"DOTNET_EnableDiagnostics=00\x00"):
            with self.subTest(length=len(raw)), self.assertRaises(Denied) as error:
                collector.diagnostics_disabled(raw)
            self.assertNotIn("PRIVATE_SENTINEL", str(error.exception))

    def test_effective_profile_requires_exact_enforce_not_complain_or_stacked_label(self):
        collector.enforce_label(b"synthetic-profile (enforce)\n", "synthetic-profile")
        for raw in (b"unconfined\n", b"synthetic-profile (complain)\n",
                    b"synthetic-profile//hat (enforce)\n", b"other (enforce)\n"):
            with self.assertRaises(Denied):
                collector.enforce_label(raw, "synthetic-profile")

    def test_process_privilege_state_requires_actual_nnp_and_zero_effective_caps(self):
        collector.restrict_status(b"Name:\tfixture\nNoNewPrivs:\t1\nCapEff:\t0000000000000000\n")
        for raw in (b"NoNewPrivs:\t0\nCapEff:\t0000000000000000\n",
                    b"NoNewPrivs:\t1\nCapEff:\t0000000000000001\n",
                    b"NoNewPrivs:\t1\n", b"NoNewPrivs:\t1\nNoNewPrivs:\t1\nCapEff:\t0000000000000000\n"):
            with self.assertRaises(Denied):
                collector.restrict_status(raw)


class CollectorCompositionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = lineage_fixtures.WorkerLineageTests()
        self.fixture.setUp()
        f = self.fixture
        install = installation.InstallationPolicy(lineage_fixtures.RUNNER_ROOT, "/etc/synthetic-manifest", 61, 2101)
        unit = "actions.runner.synthetic.service"
        self.policy = collector.CollectorPolicy(
            service.ServicePolicy(unit, "synthetic-runner", install, "/etc/systemd/system/" + unit, "a" * 64),
            "lit-gh-synthetic-0123456789abcdef", "/etc/apparmor.d/synthetic-runner", "b" * 64,
            "/etc/synthetic-collector-policy", "c" * 64)
        self.service = service.ServiceSnapshot(unit, 101, 2101, lineage_fixtures.CGROUP, "d" * 64, ())
        self.proof = installation.InstallationProof(
            install.root, f.policy.main, f.policy.node, f.policy.listener, f.policy.worker,
            MappingProxyType({install.root + "/runsvc.sh": "e" * 64}), MappingProxyType({}), (),
            (install.root + "/_diag",), install.manifest_path, "f" * 64, "1" * 64, "2.338.2",
            MappingProxyType({install.root + "/runsvc.sh": installation.TrustedFile(
                install.root + "/runsvc.sh", 1, 42, "e" * 64, 123)}),
            MappingProxyType({install.root + "/runsvc.sh": (1, 42, 0o100644, 0, 0, 1, 123, 0, 0)}),
            MappingProxyType({".": (1, 41, 0o40755, 0, 0, 2, 4096, 0, 0),
                "runsvc.sh": (1, 42, 0o100644, 0, 0, 1, 123, 0, 0)}),
            MappingProxyType({"_diag": (1, 43, 0o40700, 2101, 2101)}))
        self.peer = kernel.Peer(106, 2101, 2101)

    def compose(self, **changes):
        defaults = {
            "service": [self.service, self.service], "proof": [self.proof, self.proof],
            "peer": [self.peer, self.peer], "boot": [lineage_fixtures.BOOT, lineage_fixtures.BOOT],
            "chains": [self.fixture.snapshots, dict(self.fixture.snapshots)],
        }
        defaults.update(changes)
        with ExitStack() as stack:
            stack.enter_context(patch.object(collector.os, "geteuid", return_value=0))
            controls = stack.enter_context(patch.object(collector, "_controls", return_value={}))
            stack.enter_context(patch.object(service, "read_service", side_effect=defaults["service"]))
            stack.enter_context(patch.object(installation, "verify_installation", side_effect=defaults["proof"]))
            stack.enter_context(patch.object(kernel, "read_peer", side_effect=defaults["peer"]))
            stack.enter_context(patch.object(kernel, "read_boot_id", side_effect=defaults["boot"]))
            chain = stack.enter_context(patch.object(kernel, "read_chain", side_effect=defaults["chains"]))
            closure = stack.enter_context(patch.object(collector, "_closure", return_value=()))
            result = collector.collect_worker(object(), self.policy)
            return result, controls, chain, closure

    def test_actual_entry_composes_readers_and_real_lineage_with_two_closure_passes(self):
        # Only acquisition boundaries are mocked; the actual fixed-layout
        # verifier executes. This is explicitly not systemd/AppArmor proof.
        result, controls, chain, closure = self.compose()
        self.assertEqual((result.pid, result.start_ticks, result.runner_id, result.uid), (104, 10400, 61, 2101))
        for call in closure.call_args_list:
            self.assertEqual({key: call.args[4][key] for key in self.proof.files}, dict(self.proof.trusted_files))
        self.assertEqual(len({id(call.args[5]) for call in closure.call_args_list}), 1)
        self.assertIs(closure.call_args_list[0].args[5].proof, self.proof)
        self.assertEqual(chain.call_count, 2)
        self.assertEqual(controls.call_count, 2)
        self.assertEqual([call.args[0] for call in closure.call_args_list], [104, 103, 102, 101] * 2)

    def test_missing_or_partial_same_call_stock_file_evidence_is_not_reusable(self):
        for changed in (replace(self.proof, trusted_files=MappingProxyType({})),
                        replace(self.proof, file_stamps=MappingProxyType({}))):
            with self.subTest(changed=changed), self.assertRaises(Denied):
                self.compose(proof=[changed, changed])

    def test_peer_boot_service_or_manifest_change_denies(self):
        cases = ({"peer": [self.peer, replace(self.peer, pid=107)]},
                 {"boot": [lineage_fixtures.BOOT, "22345678-1234-4234-8234-123456789abc"]},
                 {"service": [self.service, replace(self.service, main_pid=201)]},
                 {"proof": [self.proof, replace(self.proof, manifest_sha256="2" * 64)]})
        for changes in cases:
            with self.subTest(changed=next(iter(changes))), self.assertRaises(Denied):
                self.compose(**changes)

    def test_replaced_worker_and_uid_mismatch_deny(self):
        changed = dict(self.fixture.snapshots)
        changed[104] = replace(changed[104], stat=replace(changed[104].stat, start_ticks=999))
        with self.assertRaises(Denied):
            self.compose(chains=[self.fixture.snapshots, changed])
        with self.assertRaises(Denied):
            self.compose(peer=[replace(self.peer, uid=2102)])

    def test_public_entry_requires_root_and_has_no_snapshot_or_skip_parameters(self):
        self.assertEqual(list(inspect.signature(collector.collect_worker).parameters),
                         ["connected_unix_socket", "policy"])
        with patch.object(collector.os, "geteuid", return_value=2101):
            with patch.object(collector, "_controls", side_effect=AssertionError("must deny first")):
                with self.assertRaises(Denied):
                    collector.collect_worker(object(), self.policy)


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "memfd_create"), "Requires Linux memfd in pinned EE")
class CollectorRetainedJitTests(unittest.TestCase):
    def make_jit(self, name="doublemapper"):
        fd = os.memfd_create(name, os.MFD_CLOEXEC)
        self.addCleanup(os.close, fd)
        # Real observed backing is sparse2TiB, not2TiB resident memory. Map
        # only one page; this must bypass neither ownership nor FD matching.
        os.ftruncate(fd, 2 * 1024 ** 4)
        region = mmap.mmap(fd, 4096, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        self.addCleanup(region.close)
        info = os.fstat(fd)
        item = collector.MappedFile(collector.JIT_NAME, os.major(info.st_dev), os.minor(info.st_dev),
                                    info.st_ino, True)
        return fd, item

    def test_actual_sparse_memfd_matches_same_process_retained_object_for_managed_role(self):
        _, item = self.make_jit()
        raw = Path("/proc/self/maps").read_bytes()
        self.assertIn(item, collector.parse_maps(raw, role="listener"))
        self.assertIn(item, collector.parse_maps(raw, role="worker"))
        with collector._proc(os.getpid()) as fd:
            stamp = collector._retained_jit(fd, item, os.getuid())
            self.assertEqual((stamp[0], stamp[1], stamp[2], stamp[3]),
                             (os.makedev(item.major, item.minor), item.inode, os.getuid(), 0))
            self.assertEqual(collector._retained_jit(fd, item, os.getuid()), stamp)

    def test_wrong_backing_inode_owner_or_unknown_name_is_not_retained_proof(self):
        _, item = self.make_jit()
        with collector._proc(os.getpid()) as fd:
            for changed, uid in ((replace(item, inode=item.inode + 1), os.getuid()),
                                 (item, os.getuid() + 1),
                                 (replace(item, path="/memfd:unknown (deleted)"), os.getuid())):
                with self.subTest(inode=changed.inode, uid=uid), self.assertRaises(Denied):
                    collector._retained_jit(fd, changed, uid)

    def test_foreign_process_memfd_does_not_supply_this_process_retained_fd(self):
        # A genuine memfd mapping coordinate cannot be accepted merely by its
        # name: inspect another same-UID process which never inherited the FD.
        import subprocess
        descriptor, item = self.make_jit()
        child = subprocess.Popen([sys.executable, "-I", "-B", "-c", "import time; time.sleep(30)"],
                                 close_fds=True)
        try:
            with collector._proc(child.pid) as fd:
                with self.assertRaises(Denied):
                    collector._retained_jit(fd, item, os.getuid())
            self.assertGreaterEqual(descriptor, 0)
        finally:
            child.terminate()
            child.wait(timeout=10)

    def test_mapping_without_any_retained_descriptor_denies(self):
        fd = os.memfd_create("doublemapper", os.MFD_CLOEXEC)
        os.ftruncate(fd, 4096)
        region = mmap.mmap(fd, 4096, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        info = os.fstat(fd)
        item = collector.MappedFile(collector.JIT_NAME, os.major(info.st_dev), os.minor(info.st_dev),
                                    info.st_ino, True)
        # Retire both Python's mmap duplicate and the original descriptor. Old
        # coordinates alone must not authorize a no-longer-retained object.
        region.close()
        os.close(fd)
        with collector._proc(os.getpid()) as process:
            with self.assertRaises(Denied):
                collector._retained_jit(process, item, os.getuid())


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "Requires isolated root Linux EE filesystem")
class CollectorRealFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir="/root")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "sealed"
        self.path.write_bytes(b"synthetic immutable component bytes")
        self.path.chmod(0o600)

    def test_real_host_file_matches_actual_self_process_root_inode(self):
        trusted = installation.trusted_file(str(self.path))
        root = os.open("/proc/self/root", os.O_RDONLY | os.O_DIRECTORY)
        try:
            collector._same_file(root, str(self.path), trusted)
            with self.assertRaises(Denied):
                collector._same_file(root, str(self.path), replace(trusted, inode=trusted.inode + 1))
        finally:
            os.close(root)

    def test_writable_or_symlink_host_file_is_not_sealed_code(self):
        self.path.chmod(0o666)
        with self.assertRaises(Denied):
            installation.trusted_file(str(self.path))
        self.path.chmod(0o600)
        linked = self.path.parent / "link"
        linked.symlink_to(self.path)
        with self.assertRaises(Denied):
            installation.trusted_file(str(linked))

    def test_real_proc_maps_and_stat_acquisition_does_not_claim_service_proof(self):
        with collector._proc(os.getpid()) as fd:
            parsed = kernel.worker.parse_proc_stat(kernel.bounded_file(fd, "stat", kernel.worker.MAX_STAT_BYTES))
            mapped = collector.parse_maps(kernel.bounded_file(fd, "maps", collector.MAPS_LIMIT))
        self.assertEqual(parsed.pid, os.getpid())
        self.assertTrue(mapped)

    def test_root_selected_policy_and_profile_bytes_are_actually_hashed(self):
        install = installation.InstallationPolicy("/opt/synthetic-runner", "/etc/synthetic-manifest", 61, 2101)
        unit = "actions.runner.synthetic.service"
        other = self.path.parent / "profile"
        other.write_bytes(b"synthetic profile bytes; not a loaded AppArmor profile")
        other.chmod(0o600)
        policy = collector.CollectorPolicy(
            service.ServicePolicy(unit, "synthetic-runner", install, "/etc/systemd/system/" + unit, "a" * 64),
            "lit-gh-synthetic-0123456789abcdef", str(other), hashlib.sha256(other.read_bytes()).hexdigest(),
            str(self.path), hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(set(collector._controls(policy)), {str(other), str(self.path)})
        with self.assertRaises(Denied):
            collector._controls(replace(policy, profile_sha256="0" * 64))


if __name__ == "__main__":
    unittest.main()
