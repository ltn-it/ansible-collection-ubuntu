"""Root FS/ABI/closed-routing fixtures; NO loop creation or native quota PASS.

Positive kernel observations are explicitly modeled. Actual unbounded tmpfs and
regular-file pseudo-loop negatives remain real. Only Parent runs proper EE.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace, ModuleType
import unittest
from unittest import mock

import test_github_runner_incus_engine_policy as engine_fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import storage_quota as quota, engine_policy as engine, ledger  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class QuotaBoundaryTests(unittest.TestCase):
    def test_nonroot_guard_precedes_any_path_or_manifest(self):
        with mock.patch.object(quota.os, "geteuid", return_value=2101):
            with self.assertRaisesRegex(Denied, "storage-quota-root-required"):
                with quota.acquire_existing_quota(None, None, None):
                    self.fail("nonroot cannot acquire quota")

    def test_no_proof_flag_path_hooks_or_reader_injection(self):
        for extra in ({"qualified": True}, {"reader": lambda: None}, {"mount": "/job"}, {"create": True}):
            with self.assertRaises(TypeError):
                quota.acquire_existing_quota(None, None, None, **extra)

    def test_mountinfo_parser_exact_shape_duplicate_and_escape_limits(self):
        valid = b"99 2 7:8 / /slot rw,nosuid,nodev - ext4 /dev/loop8 rw\n"
        self.assertEqual(quota._mounts(valid)[0]["source"], "/dev/loop8")
        for raw in (valid + valid, b"99 2 7:8 / /slot\\077 rw - ext4 /dev/loop8 rw\n",
                    b"99 2 7:8 / /slot rw ext4 /dev/loop8 rw\n"):
            with self.assertRaises(Denied):
                quota._mounts(raw)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux proper EE only")
class RootFilesystemStatTests(unittest.TestCase):
    def test_one_symbol_resolution_preserves_every_actual_syscall_proc_check_and_failure(self):
        """Real proc/tmpfs descriptors and EBADF; no cached observations."""
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("private Root0700 /run/proof required")
        temporary = tempfile.TemporaryDirectory(dir=base, prefix="fstatfs-cache-")
        self.addCleanup(temporary.cleanup)
        ordinary = Path(temporary.name) / "ordinary"
        ordinary.write_bytes(b"not procfs")
        proc = os.open("/proc/self/mountinfo", quota.installation.FILE_FLAGS)
        regular = os.open(ordinary, quota.installation.FILE_FLAGS)
        self.addCleanup(os.close, proc); self.addCleanup(os.close, regular)
        expected_regular = quota._fs_type(regular)
        self.assertNotEqual(expected_regular, quota.PROCFS)
        actual = quota.ctypes.CDLL(None, use_errno=True).fstatfs
        counts = {"library": 0, "symbol": 0, "calls": 0}
        def invoke(fd, buffer):
            counts["calls"] += 1
            return actual(fd, buffer)
        class Library:
            @property
            def fstatfs(self):
                counts["symbol"] += 1
                return invoke
        def library(*args, **kwargs):
            self.assertEqual((args, kwargs), ((None,), {"use_errno": True}))
            counts["library"] += 1
            return Library()
        name = "incus_lease_issuer._actual_fstatfs_cache_fixture"
        module = ModuleType(name)
        module.__package__ = "incus_lease_issuer"
        module.__file__ = quota.__file__
        with mock.patch.dict(sys.modules, {name: module}), \
             mock.patch.object(quota.ctypes, "CDLL", new=library):
            exec(compile(Path(quota.__file__).read_bytes(), quota.__file__, "exec"), module.__dict__)
            for _ in range(16):
                self.assertEqual(module._fs_type(proc), quota.PROCFS)
                self.assertEqual(module._fs_type(regular), expected_regular)
            self.assertIn(b"mnt_id:", module._read_proc("/proc/self/fdinfo/" + str(regular), 8192))
            with self.assertRaisesRegex(Denied, "storage-quota-procfs"):
                module._read_proc(str(ordinary), 8192)
            closed = os.dup(proc); os.close(closed)
            with self.assertRaisesRegex(Denied, "storage-quota-filesystem-stat"):
                module._fs_type(closed)
        self.assertEqual(counts["calls"], 35)
        self.assertEqual(counts["library"], 1)
        self.assertEqual(counts["symbol"], 1)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux proper EE only")
class RootStorageQuotaTests(unittest.TestCase):
    def setUp(self):
        self.io = engine_fixtures.RootEngineCompilerTests()
        self.io.setUp()
        self.addCleanup(self.io.doCleanups)
        self.root = self.io.root
        self.mount = self.root / "bounded-slot"
        self.mount.mkdir(mode=0o700)
        for key, name in (("storage_root", "graph"), ("runroot", "run")):
            path = self.mount / name
            path.mkdir(mode=0o700)
            self.io.data["engine"][key] = str(path)
        output = self.mount / "output"
        output.mkdir(mode=0o700)
        self.io.data["output_path"] = str(output)
        self.manifest = self.io.compile()
        self.backing = self.root / "sparse-fixture-backing.img"
        with self.backing.open("wb") as stream:
            stream.truncate(32 * 1024 ** 2)
        self.backing.chmod(0o600)
        self.fake_loop = self.root / "regular-file-not-a-loop"
        self.fake_loop.write_bytes(b"regular file, not block device")
        self.fake_loop.chmod(0o600)
        ns = self.observed_namespace()
        try:
            namespace = os.fstat(ns)
        finally:
            os.close(ns)
        mounted, backing = self.mount.stat(), self.backing.stat()
        self.value = {"schema": 1, "boot_id": quota.kernel.read_boot_id(),
                      "mount_namespace": {"device": namespace.st_dev, "inode": namespace.st_ino},
                      "mount": {"path": str(self.mount), "mount_id": 900, "device": mounted.st_dev,
                                "inode": mounted.st_ino, "fstype": "ext4"},
                      "loop_device": "/dev/loop777", "backing_file": {"path": str(self.backing),
                          "device": backing.st_dev, "inode": backing.st_ino, "bytes": backing.st_size},
                      "max_bytes": 32 * 1024 ** 2, "max_inodes": 1024}
        self.path = self.root / "quota-policy.json"
        self.seal()
        self.rows = self.row()
        self.vfs = SimpleNamespace(f_frsize=4096, f_blocks=8000, f_files=1024, f_flag=0)

    @staticmethod
    def observed_namespace():
        # keep-id logical UID0 does not imply ownership of its real namespace:
        # hostRoot can appear as unmapped65534. Acquire actual kernel identity
        # for fixtures without claiming the production UID0 guard succeeded.
        fd = os.open("/proc/self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
        try:
            if quota._fs_type(fd) != quota.NSFS or quota.fcntl.ioctl(fd, quota.NS_GET_NSTYPE) != quota.CLONE_NEWNS:
                raise AssertionError("fixture requires an actual kernel mount namespace")
            return fd
        except Exception:
            os.close(fd)
            raise

    def seal(self):
        self.path.write_bytes(ledger.canonical(self.value))
        self.path.chmod(0o600)
        self.sha = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def row(self, *, mount_id=900, path=None, device=None, fstype="ext4", source="/dev/loop777", flags="rw,nosuid,nodev"):
        dev = self.mount.stat().st_dev
        device = device or str(os.major(dev)) + ":" + str(os.minor(dev))
        return f"{mount_id} 2 {device} / {path or self.mount} {flags} - {fstype} {source} rw\n".encode()

    def acquire(self):
        return quota.acquire_existing_quota(str(self.path), self.sha, self.manifest)

    @contextmanager
    def modeled_kernel(self):
        # Native loop/block/sysfs/FIEMAP/ext4/vfs/mountinfo and namespaceOWNER
        # acceptance are modeled. Namespace dev/inode/type/ioctl and Root
        # paths/files/lifetime are real; this is NOT Root native qualification.
        actual_type, actual_open = quota._fs_type, quota._open_file
        mounted = self.mount.stat()
        def filesystem(fd):
            info = os.fstat(fd)
            return quota.EXT4 if (info.st_dev, info.st_ino) == (mounted.st_dev, mounted.st_ino) else actual_type(fd)
        def open_file(path):
            return actual_open(str(self.fake_loop) if path == self.value["loop_device"] else path)
        self.loop_fds = []
        def loop(loop_fd, backing_fd, policy):
            self.loop_fds.append(loop_fd)
            self.assertEqual(os.fstat(backing_fd).st_ino, self.backing.stat().st_ino)
            return mounted.st_dev
        with mock.patch.object(quota, "_fs_type", side_effect=filesystem), \
             mock.patch.object(quota, "_namespace", side_effect=self.observed_namespace), \
             mock.patch.object(quota, "_open_file", side_effect=open_file), \
             mock.patch.object(quota, "_loop", side_effect=loop), \
             mock.patch.object(quota, "_mount_id", return_value=900), \
             mock.patch.object(quota, "_read_proc", side_effect=lambda path, limit: self.rows), \
             mock.patch.object(quota.os, "fstatvfs", side_effect=lambda fd: self.vfs):
            yield

    def test_modeled_kernel_positive_retains_actual_fds_and_rechecks_after_use(self):
        with self.modeled_kernel():
            with self.acquire() as observation:
                self.assertEqual(observation.policy_sha256, self.sha)
                self.assertEqual((observation.mount_id, observation.total_inodes), (900, 1024))
                os.fstat(self.loop_fds[-1])
                Path(self.io.data["output_path"], "capture.txt").write_bytes(b"bounded-output-fixture")
            self.assertGreaterEqual(len(self.loop_fds), 2)
            with self.assertRaises(OSError):
                os.fstat(self.loop_fds[-1])

    def test_actual_unbounded_tmpfs_denies_before_loop_attestation(self):
        mount = quota.engine._directory(str(self.mount), private=True)
        ns = self.observed_namespace()
        loop = quota._open_file(str(self.fake_loop))
        backing = quota._open_file(str(self.backing))
        try:
            # Namespace owner admission is modeled independently; the tmpfs
            # filesystem type/device/mode remain actual and must deny.
            with mock.patch.object(quota, "_namespace", side_effect=self.observed_namespace), \
                 mock.patch.object(quota, "_loop") as called:
                with self.assertRaisesRegex(Denied, "storage-quota-mount-binding"):
                    quota._check(self.value, mount, ns, loop, backing, ())
                called.assert_not_called()
        finally:
            for fd in (mount, ns, loop, backing):
                os.close(fd)

    def test_actual_or_modeled_foreign_namespace_owner_is_denied_by_production_guard(self):
        fd = self.observed_namespace()
        try:
            actual = os.fstat(fd)
        finally:
            os.close(fd)
        if actual.st_uid != 0:
            with self.assertRaisesRegex(Denied, "storage-quota-real-mount-namespace"):
                quota._namespace()
        else:
            real_stat = os.fstat
            def foreign_owner(descriptor):
                value = real_stat(descriptor)
                return SimpleNamespace(st_uid=65534) if (value.st_dev, value.st_ino) == (actual.st_dev, actual.st_ino) else value
            with mock.patch.object(quota.os, "fstat", side_effect=foreign_owner):
                with self.assertRaisesRegex(Denied, "storage-quota-real-mount-namespace"):
                    quota._namespace()

    def test_actual_regular_file_cannot_impersonate_loop_block_device(self):
        loop, backing = quota._open_file(str(self.fake_loop)), quota._open_file(str(self.backing))
        try:
            with self.assertRaisesRegex(Denied, "storage-quota-real-loop-device"):
                quota._loop(loop, backing, self.value)
        finally:
            os.close(loop)
            os.close(backing)

    def test_real_sparse_file_fails_reservation_even_when_policy_claims_capacity(self):
        fd = quota._open_file(str(self.backing))
        try:
            self.assertLess(os.fstat(fd).st_blocks * 512, os.fstat(fd).st_size)
            with self.assertRaises((Denied, OSError)):
                quota._reservation(fd, self.backing.stat().st_size)
        finally:
            os.close(fd)

    def test_loop_get_status_abi_binds_backing_identity_size_and_sysfs(self):
        loop, backing = quota._open_file(str(self.fake_loop)), quota._open_file(str(self.backing))
        self.addCleanup(os.close, loop)
        self.addCleanup(os.close, backing)
        real_stat = quota.os.fstat
        original_loop, original_backing = real_stat(loop), real_stat(backing)
        def fields(info):
            return {key: getattr(info, key) for key in dir(info) if key.startswith("st_")}
        loop_info = SimpleNamespace(**{**fields(original_loop), "st_mode": stat.S_IFBLK | 0o600,
                                      "st_rdev": os.makedev(7, 777)})
        backing_info = SimpleNamespace(**{**fields(original_backing), "st_blocks": original_backing.st_size // 512})
        values = [original_backing.st_dev, original_backing.st_ino, 0, 0, 0, 777, 0, 0, 0]
        data = bytearray(232)
        def ioctl(fd, request, raw):
            if request == quota.LOOP_GET_STATUS64:
                struct.pack_into("=QQQQQIIII", data, 0, *values)
                return bytes(data)
            self.assertEqual((fd, request), (loop, quota.BLKGETSIZE64))
            return struct.pack("=Q", original_backing.st_size)
        sysfs = {"loop/backing_file": str(self.backing), "loop/offset": "0", "loop/sizelimit": "0",
                 "size": str(original_backing.st_size // 512)}
        # Fixed-name reopen identity is independently exercised by the real
        # directory/replacement tests; here only ABI observations are modeled.
        def reopened(path):
            return os.dup(loop if path == self.value["loop_device"] else backing)
        def descriptor_stat(fd):
            actual = real_stat(fd)
            if actual.st_ino == original_loop.st_ino:
                return loop_info
            if actual.st_ino == original_backing.st_ino:
                return backing_info
            return actual
        with mock.patch.object(quota.os, "fstat", side_effect=descriptor_stat), \
             mock.patch.object(quota, "_open_file", side_effect=reopened), \
             mock.patch.object(quota.fcntl, "ioctl", side_effect=ioctl), \
             mock.patch.object(quota, "_sysfs", side_effect=lambda number, key: sysfs[key]), \
             mock.patch.object(quota, "_reservation") as reservation:
            self.assertEqual(quota._loop(loop, backing, self.value), os.makedev(7, 777))
            reservation.assert_called_once_with(backing, original_backing.st_size)
            for index, replacement in ((0, 123), (1, 123), (3, 4096), (4, 1024), (5, 778), (8, 4), (8, 1)):
                old = values[index]
                values[index] = replacement
                with self.assertRaisesRegex(Denied, "storage-quota-loop-binding"):
                    quota._loop(loop, backing, self.value)
                values[index] = old
            sysfs["loop/backing_file"] = "/foreign/loop.img"
            with self.assertRaisesRegex(Denied, "storage-quota-loop-sysfs"):
                quota._loop(loop, backing, self.value)

    def test_policy_private_digest_schema_and_unbounded_expectations_deny(self):
        original = deepcopy(self.value)
        for changes in ({"schema": True}, {"max_bytes": self.backing.stat().st_size + 1}, {"max_inodes": 0},
                        {"qualified": True}, {"loop_device": "/dev/sda"}, {"boot_id": "caller"}):
            self.value = {**original, **changes}
            self.seal()
            with self.assertRaises(Denied):
                quota._policy(str(self.path), self.sha)
        self.value = original
        self.seal()
        self.path.chmod(0o644)
        with self.assertRaises(Denied):
            quota._policy(str(self.path), self.sha)
        self.path.chmod(0o600)
        self.path.write_bytes(b"private secret body must not escape")
        with self.assertRaisesRegex(Denied, "storage-quota-acquisition-denied") as caught:
            with self.acquire():
                self.fail("wrong digest must deny")
        self.assertNotIn("secret body", str(caught.exception))

    def test_mount_replacement_bind_source_foreign_mount_and_shared_propagation_deny(self):
        original = self.rows
        for rows in (self.row(mount_id=901), self.row(device="8:1"), self.row(fstype="overlay"),
                     self.row(source="/dev/sda1"), self.row(flags="ro,nosuid,nodev"), original + original,
                     original.replace(b" - ", b" shared:12 - ")):
            self.rows = rows
            with self.modeled_kernel():
                with self.assertRaises(Denied):
                    with self.acquire():
                        self.fail("foreign or replaced mount")

    def test_filesystem_byte_and_inode_hardceilings_not_free_space_observations(self):
        for changes in ({"f_blocks": 9000}, {"f_files": 1025}, {"f_files": 0}, {"f_frsize": 0}, {"f_flag": os.ST_RDONLY}):
            self.vfs = SimpleNamespace(**{**vars(self.vfs), **changes})
            with self.modeled_kernel():
                with self.assertRaises(Denied):
                    with self.acquire():
                        self.fail("not a bounded writable filesystem")
            self.vfs = SimpleNamespace(f_frsize=4096, f_blocks=8000, f_files=1024, f_flag=0)

    def test_path_and_policy_drift_after_yield_deny_without_cleanup_or_retry(self):
        with self.modeled_kernel():
            with self.assertRaises(Denied):
                with self.acquire():
                    graph = Path(self.io.data["engine"]["storage_root"])
                    graph.rename(graph.with_name("original-graph"))
                    graph.mkdir(mode=0o700)
            self.assertTrue((self.mount / "original-graph").exists())
            with self.assertRaises(Denied):
                with self.acquire():
                    self.path.write_bytes(b"changed Root policy")

    def test_nested_mount_escape_and_mutable_path_outside_slot_deny(self):
        self.rows += self.row(mount_id=901, path=self.io.data["engine"]["storage_root"])
        with self.modeled_kernel():
            with self.assertRaises(Denied):
                with self.acquire():
                    self.fail("nested storage mount")
        self.rows = self.row()
        outside = self.root / "outside-output"
        outside.mkdir(mode=0o700)
        self.io.data["output_path"] = str(outside)
        self.manifest = self.io.compile()
        with self.modeled_kernel():
            with self.assertRaises(Denied):
                with self.acquire():
                    self.fail("foreign output")

    def changed_manifest(self, mutate):
        data = quota.identity.decode_json(self.manifest.canonical_bytes)
        mutate(data)
        raw = ledger.canonical(data)
        return replace(self.manifest, argv=tuple(data["argv"]), canonical_bytes=raw, sha256=hashlib.sha256(raw).hexdigest())

    def test_log_event_tmpdir_extra_rw_and_capture_routing_are_required_in_signed_argv(self):
        def replace_arg(data, old, new):
            data["argv"][data["argv"].index(old)] = new
        changes = [lambda d: replace_arg(d, "--events-backend=none", "--events-backend=journald"),
                   lambda d: replace_arg(d, "--log-driver=passthrough", "--log-driver=k8s-file"),
                   lambda d: replace_arg(d, "--tmpdir=" + d["engine"]["runroot"], "--tmpdir=/var/tmp"),
                   lambda d: d["argv"].insert(1, "--syslog"),
                   lambda d: d["argv"].insert(-1, "--tty"),
                   lambda d: d["argv"].extend(["--mount", "type=bind,source=/var/tmp,destination=/escape,rw"]),
                   lambda d: d["capture"].update(stdout_limit=0)]
        self.assertEqual(len(quota._manifest(self.manifest)), 3)
        for change in changes:
            with self.assertRaises(Denied):
                quota._manifest(self.changed_manifest(change))

    def test_fiemap_rejects_holes_shared_delalloc_unknown_or_incomplete_extents(self):
        fd = quota._open_file(str(self.backing))
        self.addCleanup(os.close, fd)
        size = self.backing.stat().st_size
        def kernel_extents(logical=0, physical=4096, length=None, flags=1):
            def ioctl(descriptor, request, data, mutate):
                self.assertEqual((descriptor, request, mutate), (fd, quota.FS_IOC_FIEMAP, True))
                struct.pack_into("=QQIIII", data, 0, 0, size, 0, 1, 4096, 0)
                struct.pack_into("=QQQQQIIII", data, 32, logical, physical, length or size, 0, 0, flags, 0, 0, 0)
            return ioctl
        for flags in (1, 1 | 0x800):
            with mock.patch.object(quota.fcntl, "ioctl", side_effect=kernel_extents(flags=flags)):
                quota._reservation(fd, size)
        for values in ({"logical": 4096}, {"physical": 0}, {"flags": 0x2001}, {"flags": 5},
                       {"flags": 3}, {"length": size - 4096}, {"flags": 0}):
            with mock.patch.object(quota.fcntl, "ioctl", side_effect=kernel_extents(**values)):
                with self.assertRaises(Denied):
                    quota._reservation(fd, size)


if __name__ == "__main__":
    unittest.main()
