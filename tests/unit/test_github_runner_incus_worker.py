"""Synthetic two-read lineage fixtures; not a kernel collector or startup proof."""
from dataclasses import FrozenInstanceError, replace
import os
from pathlib import Path
import sys
import unittest


FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import worker  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402
from incus_lease_issuer.ledger import Worker  # noqa: E402


BOOT = "12345678-1234-4234-8234-123456789abc"
RUNNER_ROOT = "/srv/synthetic-runner"
CGROUP = "/system.slice/actions.runner.synthetic.service"


def proc_stat(pid, ppid, *, comm="runner (test) with spaces", state="S", start=9876):
    tail = [state] + ["0"] * 49
    tail[1], tail[19] = str(ppid), str(start)
    return (str(pid) + " (" + comm + ") " + " ".join(tail) + "\n").encode()


class ProcStatTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "Requires procfs in the pinned Linux EE")
    def test_real_self_stat_matches_kernel_pid_and_parent_without_service_proof(self):
        parsed = worker.parse_proc_stat(Path("/proc/self/stat").read_bytes())
        self.assertEqual(parsed.pid, os.getpid())
        self.assertEqual(parsed.ppid, os.getppid())
        self.assertGreater(parsed.start_ticks, 0)

    def test_comm_parentheses_and_spaces_do_not_shift_ppid_or_starttime(self):
        for comm in ("runner (job) with spaces", "a)b(c) d", ") tricky ( comm"):
            with self.subTest(comm=comm):
                parsed = worker.parse_proc_stat(proc_stat(104, 103, comm=comm, start=456789))
                self.assertEqual((parsed.pid, parsed.ppid, parsed.start_ticks), (104, 103, 456789))
                self.assertEqual(parsed.comm, comm)
                with self.assertRaises(FrozenInstanceError):
                    parsed.ppid = 1

    def test_malformed_truncated_and_unbounded_stat_deny(self):
        cases = (b"", b"104 (worker) S 103", b"104 worker S 103", b"x (worker) S 1",
                 proc_stat(104, 103) + b"\n", b"x" * 4097,
                 proc_stat(104, 103, comm="bad\ncomm"), proc_stat(104, 103).replace(b"104 (", b"0104 (", 1),
                 proc_stat(104, -1), proc_stat(104, 103, start=0),
                 proc_stat(104, 103, start="1.5"), proc_stat(104, 103, start="１２３"))
        for raw in cases:
            with self.subTest(length=len(raw)):
                with self.assertRaises(Denied):
                    worker.parse_proc_stat(raw)

    def test_zombie_and_dead_states_are_not_live_processes(self):
        for state in ("Z", "X", "x", "?", "SS"):
            with self.subTest(state=state):
                with self.assertRaises(Denied):
                    worker.parse_proc_stat(proc_stat(104, 103, state=state))


class WorkerLineageTests(unittest.TestCase):
    def setUp(self):
        main = worker.ExecutablePolicy("/usr/bin/bash", 8, 10,
                                       ("/bin/bash", RUNNER_ROOT + "/runsvc.sh"))
        node = worker.ExecutablePolicy(RUNNER_ROOT + "/externals/node24/bin/node", 8, 11,
                                       ("./externals/node24/bin/node", "./bin/RunnerService.js"))
        listener = worker.ExecutablePolicy(RUNNER_ROOT + "/bin/Runner.Listener", 8, 12,
                                           (RUNNER_ROOT + "/bin/Runner.Listener", "run", "--startuptype", "service"))
        runner_worker = worker.ExecutablePolicy(RUNNER_ROOT + "/bin/Runner.Worker", 8, 13)
        self.policy = worker.LineagePolicy(101, 2101, 61, CGROUP, main, node, listener, runner_worker)
        specs = ((101, 1, main, main.argv), (102, 101, node, node.argv),
                 (103, 102, listener, listener.argv),
                 (104, 103, runner_worker, (runner_worker.path, "spawnclient", "pipe-1", "pipe-2")))
        self.snapshots = {}
        for pid, ppid, spec, argv in specs:
            self.snapshots[pid] = worker.ProcessSnapshot(
                worker.parse_proc_stat(proc_stat(pid, ppid, start=pid * 100)),
                (2101, 2101, 2101, 2101), CGROUP, spec.path, spec.device, spec.inode, argv)
        self.snapshots[105] = worker.ProcessSnapshot(
            worker.parse_proc_stat(proc_stat(105, 104, comm="job shell", start=10500)),
            (2101, 2101, 2101, 2101), CGROUP, "/usr/bin/bash", 8, 10, ("bash", "step.sh"))
        self.snapshots[106] = replace(self.snapshots[105],
                                      stat=worker.parse_proc_stat(proc_stat(106, 105, start=10600)),
                                      executable="/usr/bin/python3", exe_inode=20, argv=("python3", "caller.py"))

    def verify(self, *, snapshots=None, confirmed=None, policy=None, **kwargs):
        snapshots = self.snapshots if snapshots is None else snapshots
        arguments = {"peer_pid": 106, "peer_uid": 2101, "boot_id": BOOT,
                     "snapshots": snapshots, "confirmed_snapshots": dict(snapshots) if confirmed is None else confirmed,
                     "confirmed_boot_id": BOOT}
        arguments.update(kwargs)
        return worker.verify_lineage(self.policy if policy is None else policy, **arguments)

    def deny(self, **kwargs):
        with self.assertRaises(Denied) as caught:
            self.verify(**kwargs)
        self.assertRegex(str(caught.exception), r"^[a-z][a-z0-9_-]{0,95}$")

    def test_standard_main_bash_node_listener_worker_and_peer_descendants_pass(self):
        binding = self.verify()
        self.assertIs(type(binding), Worker)
        self.assertEqual((binding.pid, binding.start_ticks, binding.uid, binding.runner_id, binding.boot_id),
                         (104, 10400, 2101, 61, BOOT))
        self.assertNotEqual(binding.pid, 106)
        self.assertNotEqual(self.policy.main_pid, 103)
        with self.assertRaises(FrozenInstanceError):
            self.snapshots[104].executable = "/tmp/replacement"

    def test_main_pid_is_not_a_listener_layout_fallback(self):
        self.deny(policy=replace(self.policy, main_pid=103))

    def test_previous_node20_service_layout_is_not_a_fallback(self):
        old_node = replace(self.policy.node,
                           path=RUNNER_ROOT + "/externals/node20/bin/node",
                           argv=("./externals/node20/bin/node", "./bin/RunnerService.js"))
        snapshots = dict(self.snapshots)
        snapshots[102] = replace(snapshots[102], executable=old_node.path, argv=old_node.argv)
        self.deny(policy=replace(self.policy, node=old_node), snapshots=snapshots)

    def test_missing_or_reparented_process_cannot_be_repaired_by_same_uid(self):
        missing = dict(self.snapshots)
        del missing[103]
        self.deny(snapshots=missing)
        orphan = dict(self.snapshots)
        orphan[104] = replace(orphan[104], stat=replace(orphan[104].stat, ppid=1))
        self.deny(snapshots=orphan)

    def test_cycles_and_bounded_depth_deny(self):
        cycle = dict(self.snapshots)
        cycle[105] = replace(cycle[105], stat=replace(cycle[105].stat, ppid=106))
        self.deny(snapshots=cycle)
        self.deny(policy=replace(self.policy, max_depth=4))

    def test_second_observation_must_preserve_parent_start_image_and_argv(self):
        original = self.snapshots[104]
        changes = (replace(original, stat=replace(original.stat, ppid=102)),
                   replace(original, stat=replace(original.stat, start_ticks=10401)),
                   replace(original, exe_inode=999), replace(original, argv=original.argv + ("unexpected",)))
        for changed in changes:
            confirmed = dict(self.snapshots)
            confirmed[104] = changed
            with self.subTest(changed=changed.exe_inode):
                self.deny(confirmed=confirmed)
        missing = dict(self.snapshots)
        del missing[105]
        self.deny(confirmed=missing)

    def test_same_path_replaced_image_or_deleted_executable_denies(self):
        for change in ({"exe_inode": 999}, {"exe_device": 9},
                       {"executable": self.policy.worker.path + " (deleted)"}):
            snapshots = dict(self.snapshots)
            snapshots[104] = replace(snapshots[104], **change)
            with self.subTest(change=change):
                self.deny(snapshots=snapshots)

    def test_exact_uid_and_cgroup_prevent_same_prefix_or_other_uid(self):
        for uid_tuple, cgroup in (((2101, 2102, 2101, 2101), CGROUP),
                                  ((2101, 2101, 2101, 2101), CGROUP + "-lookalike"),
                                  ((2101, 2101, 2101, 2101), CGROUP + "/unapproved-child")):
            snapshots = dict(self.snapshots)
            snapshots[105] = replace(snapshots[105], uids=uid_tuple, cgroup=cgroup)
            self.deny(snapshots=snapshots)
        self.deny(peer_uid=2102)
        self.deny(peer_uid=True)

    def test_fake_job_launched_node_cannot_replace_the_service_parent_chain(self):
        snapshots = dict(self.snapshots)
        # Same Node image/argv and same UID/cgroup, but under a job shell.
        snapshots[107] = replace(snapshots[102], stat=worker.parse_proc_stat(proc_stat(107, 105)))
        snapshots[103] = replace(snapshots[103], stat=replace(snapshots[103].stat, ppid=107))
        self.deny(snapshots=snapshots)

    def test_role_names_alone_and_changed_script_or_listener_arguments_deny(self):
        for pid, argv in ((101, ("/bin/bash", "/tmp/fake-runsvc.sh")),
                          (102, ("node", "attacker.js")),
                          (103, (self.policy.listener.path, "run")),
                          (104, (self.policy.worker.path, "spawnclient", "one-pipe"))):
            snapshots = dict(self.snapshots)
            snapshots[pid] = replace(snapshots[pid], argv=argv)
            with self.subTest(pid=pid):
                self.deny(snapshots=snapshots)

    def test_zombie_snapshot_and_changed_boot_identity_deny(self):
        snapshots = dict(self.snapshots)
        snapshots[104] = replace(snapshots[104], stat=replace(snapshots[104].stat, state="Z"))
        self.deny(snapshots=snapshots)
        self.deny(confirmed_boot_id="22345678-1234-4234-8234-123456789abc")
        self.deny(boot_id="not-a-boot-uuid", confirmed_boot_id="not-a-boot-uuid")

    def test_snapshot_and_argv_input_bounds_deny(self):
        snapshots = dict(self.snapshots)
        snapshots[105] = replace(snapshots[105], argv=("x" * 8193,))
        self.deny(snapshots=snapshots)
        self.deny(snapshots=[])
        self.deny(policy=replace(self.policy, max_depth=65))
        self.deny(policy=replace(self.policy, cgroup="/system.slice/../service"))


if __name__ == "__main__":
    unittest.main()
