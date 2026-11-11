"""Linux EE kernel component checks; never service or startup acceptance."""
from dataclasses import FrozenInstanceError, replace
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import kernel  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class ProcInputTests(unittest.TestCase):
    def test_status_requires_one_exact_uid_quartet(self):
        self.assertEqual(kernel.parse_status_uids(b"Name:\tfixture\nUid:\t2101\t2101\t2101\t2101\n"),
                         (2101, 2101, 2101, 2101))
        for raw in (b"", b"Uid:\t1\t1\t1\n", b"Uid:\t1\t1\t1\t1\nUid:\t2\t2\t2\t2\n",
                    b"Uid:\t01\t1\t1\t1\n", b"Uid:\t-1\t1\t1\t1\n", b"x" * 65537):
            with self.subTest(length=len(raw)), self.assertRaises(Denied):
                kernel.parse_status_uids(raw)

    def test_only_single_normalized_unified_cgroup_is_supported(self):
        self.assertEqual(kernel.parse_cgroup(b"0::/system.slice/runner.service\n"),
                         "/system.slice/runner.service")
        for raw in (b"1:cpu:/service\n", b"0::/one\n0::/two\n", b"0::/a/../b\n",
                    b"0:://lookalike\n", b"0::/trailing/\n", b"0::/a\r\n", b"0::relative\n"):
            with self.subTest(raw_length=len(raw)), self.assertRaises(Denied):
                kernel.parse_cgroup(raw)

    def test_cmdline_requires_bounded_utf8_nul_arguments(self):
        self.assertEqual(kernel.parse_cmdline("python3\x00test with spaces.py\x00".encode()),
                         ("python3", "test with spaces.py"))
        for raw in (b"", b"python3", b"python3\x00\x00", b"bad\xff\x00",
                    b"arg\x00" * 33, b"x" * 8192 + b"\x00", b"arg\n\x00"):
            with self.subTest(length=len(raw)), self.assertRaises(Denied):
                kernel.parse_cmdline(raw)


@unittest.skipUnless(sys.platform == "linux", "Requires Linux procfs and SO_PEERCRED in the pinned EE")
class LinuxKernelTests(unittest.TestCase):
    def test_real_process_snapshot_matches_pid_parent_uid_and_running_image(self):
        snapshot = kernel.read_process(os.getpid())
        self.assertEqual((snapshot.stat.pid, snapshot.stat.ppid), (os.getpid(), os.getppid()))
        self.assertGreater(snapshot.stat.start_ticks, 0)
        self.assertEqual(snapshot.uids, (os.getuid(), os.geteuid(), os.geteuid(), os.geteuid()))
        image = os.stat("/proc/self/exe")
        self.assertEqual((snapshot.exe_device, snapshot.exe_inode), (image.st_dev, image.st_ino))
        self.assertTrue(Path(snapshot.executable).is_absolute())
        self.assertTrue(snapshot.argv)
        self.assertEqual(kernel.read_boot_id(), Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        with self.assertRaises(FrozenInstanceError):
            snapshot.exe_inode = 1

    def connected_child(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        address = str(Path(directory.name) / "peer.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.settimeout(10)
        server.bind(address)
        server.listen(1)
        script = ("import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); "
                  "s.connect(sys.argv[1]); s.sendall(b'999999'); s.recv(1)")
        child = subprocess.Popen([sys.executable, "-I", "-B", "-c", script, address],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def cleanup_child():
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=10)
        self.addCleanup(cleanup_child)
        connection, _ = server.accept()
        connection.settimeout(10)
        self.addCleanup(connection.close)
        self.assertEqual(connection.recv(6), b"999999")
        return child, connection

    @unittest.skipUnless(os.getuid() > 0 and os.getgid() > 0, "Positive runner peer credentials require nonroot EE UID/GID")
    def test_actual_unix_peer_is_child_kernel_pid_not_claimed_payload(self):
        child, connection = self.connected_child()
        peer = kernel.read_peer(connection)
        self.assertEqual((peer.pid, peer.uid, peer.gid), (child.pid, os.getuid(), os.getgid()))
        self.assertNotEqual(peer.pid, 999999)
        self.assertNotEqual(peer.pid, os.getpid())
        with self.assertRaises(FrozenInstanceError):
            peer.pid = 999999

    def test_actual_child_ancestry_ends_at_parent_without_service_inference(self):
        child, _ = self.connected_child()
        rows = kernel.read_chain(child.pid, os.getpid())
        self.assertEqual(set(rows), {child.pid, os.getpid()})
        self.assertEqual(rows[child.pid].stat.ppid, os.getpid())
        self.assertGreater(rows[child.pid].stat.start_ticks, 0)
        with self.assertRaises(Denied):
            kernel.read_chain(child.pid, os.getpid(), max_depth=1)

    def test_nonconnected_datagram_foreign_family_and_closed_socket_deny(self):
        for family, kind in ((socket.AF_UNIX, socket.SOCK_STREAM),
                             (socket.AF_UNIX, socket.SOCK_DGRAM), (socket.AF_INET, socket.SOCK_STREAM)):
            with socket.socket(family, kind) as candidate:
                with self.subTest(family=family, kind=kind), self.assertRaises(Denied):
                    kernel.read_peer(candidate)
        candidate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        candidate.close()
        with self.assertRaises(Denied):
            kernel.read_peer(candidate)
        with self.assertRaises(Denied):
            kernel.read_peer({"pid": 999999, "uid": 2101, "gid": 2101})

    def test_invalid_pid_is_not_an_alternate_proc_path(self):
        for pid in (True, 0, -1, "self", "../self", 1.0):
            with self.subTest(type_name=type(pid).__name__), self.assertRaises(Denied):
                kernel.read_process(pid)

    def test_changed_parent_or_start_between_stat_reads_denies(self):
        parsed = kernel.worker.parse_proc_stat(Path("/proc/self/stat").read_bytes())
        for changed in (replace(parsed, ppid=parsed.ppid + 1),
                        replace(parsed, start_ticks=parsed.start_ticks + 1)):
            with self.subTest(parent=changed.ppid):
                with mock.patch.object(kernel.worker, "parse_proc_stat", side_effect=[parsed, changed]):
                    with self.assertRaises(Denied):
                        kernel.read_process(os.getpid())

    def test_reaped_child_has_no_reusable_process_snapshot(self):
        child, _ = self.connected_child()
        child.terminate()
        child.wait(timeout=10)
        with self.assertRaises(Denied):
            kernel.read_process(child.pid)

    def test_fixture_cycle_and_missing_process_fail_closed_without_public_reader_option(self):
        sample = kernel.read_process(os.getpid())
        first = replace(sample, stat=replace(sample.stat, pid=101, ppid=102))
        second = replace(sample, stat=replace(sample.stat, pid=102, ppid=101))
        with mock.patch.object(kernel, "read_process", side_effect=lambda pid: {101: first, 102: second}[pid]):
            with self.assertRaises(Denied):
                kernel.read_chain(101, 103)
        with mock.patch.object(kernel, "read_process", side_effect=Denied("process-read-failed")):
            with self.assertRaises(Denied):
                kernel.read_chain(101, 103)
        with self.assertRaises(TypeError):
            kernel.read_process(os.getpid(), proc_root="/tmp/caller-proc")


if __name__ == "__main__":
    unittest.main()
