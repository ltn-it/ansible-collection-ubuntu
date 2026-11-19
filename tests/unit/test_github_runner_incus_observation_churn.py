"""Scheduling changes are not generations; failed scans never become proof."""
import sys
import unittest
from pathlib import Path
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / 'roles/github_runner/files'
sys.path.insert(0, str(FILES))
from incus_lease_issuer import cleanup_storage, network_fence
from incus_lease_issuer.identity import Denied


class ObservationChurnTests(unittest.TestCase):
    def test_observed_qemu_running_sleeping_transition_is_same_generation(self):
        self.assertTrue(cleanup_storage._same_live_process((b'1027352896', b'R'), (b'1027352896', b'S')))
        self.assertTrue(cleanup_storage._same_live_process((b'1027352896', b'S'), (b'1027352896', b'R')))

    def test_replaced_or_terminal_or_unknown_live_task_is_not_admitted(self):
        for before, after in [((b'1', b'R'), (b'2', b'R')),
                              ((b'1', b'R'), (b'1', b'Z')),
                              ((b'1', b'Z'), (b'1', b'R')),
                              ((b'1', b'?'), (b'1', b'?'))]:
            with self.subTest(before=before, after=after):
                self.assertFalse(cleanup_storage._same_live_process(before, after))

    def test_complete_network_reacquire_uses_the_original_deadline(self):
        with mock.patch.object(network_fence.time, 'monotonic', side_effect=[10, 10, 11, 12]), \
             mock.patch.object(network_fence, '_namespace_refs_drained_once',
                               side_effect=[Denied('fence-proc-fds-changed'), None]) as acquire:
            network_fence._namespace_refs_drained(3, 'actual-info', 25882)
        self.assertEqual(acquire.call_args_list, [mock.call(3, 'actual-info', 25882, 20)] * 2)

    def test_live_reference_and_unknown_permission_never_retry(self):
        for reason in ['fence-namespace-fd-live', 'cleanup-consumers-fd-table-unavailable',
                       'fence-proc-bounds', 'foreign-unclassified-error']:
            with self.subTest(reason=reason), \
                 mock.patch.object(network_fence, '_namespace_refs_drained_once', side_effect=Denied(reason)) as acquire:
                with self.assertRaises(Denied):
                    network_fence._namespace_refs_drained(3, 'info', 25882)
                self.assertEqual(acquire.call_count, 1)

    def test_reacquisition_exhaustion_is_a_hold(self):
        with mock.patch.object(network_fence, '_namespace_refs_drained_once',
                               side_effect=Denied('fence-proc-fds-changed')) as acquire:
            with self.assertRaisesRegex(Denied, 'fence-proc-acquire-unstable'):
                network_fence._namespace_refs_drained(3, 'info', 25882)
        self.assertEqual(acquire.call_count, 8)

    def test_deadline_expiry_prevents_another_complete_acquire(self):
        with mock.patch.object(network_fence.time, 'monotonic', side_effect=[10, 10, 20]), \
             mock.patch.object(network_fence, '_namespace_refs_drained_once',
                               side_effect=FileNotFoundError()) as acquire:
            with self.assertRaisesRegex(Denied, 'fence-proc-bounds'):
                network_fence._namespace_refs_drained(3, 'info', 25882)
        self.assertEqual(acquire.call_count, 1)

    def test_final_close_and_readback_must_finish_before_original_end(self):
        with mock.patch.object(network_fence.time, 'monotonic', side_effect=[10, 10, 20]), \
             mock.patch.object(network_fence, '_namespace_refs_drained_once', return_value=None) as acquire:
            with self.assertRaisesRegex(Denied, 'fence-proc-bounds'):
                network_fence._namespace_refs_drained(3, 'info', 25882)
        self.assertEqual(acquire.call_count, 1)

class StorageConsumerChurnTests(unittest.TestCase):
    def invoke(self, end=100):
        return cleanup_storage._no_consumers('data', 'descriptor', 'lease', (), end, set(), (),
                                             forbidden_namespace=(4, 4026532529))

    def test_whole_storage_reacquisition_preserves_original_end(self):
        with mock.patch.object(cleanup_storage.time, 'monotonic', return_value=10), \
             mock.patch.object(cleanup_storage, '_no_consumers_once',
                               side_effect=[Denied('cleanup-consumers-task-inventory-changed'), None]) as scan:
            self.invoke()
        self.assertEqual(scan.call_args_list, [mock.call('data', 'descriptor', 'lease', (), 100,
            set(), (), None, forbidden_namespace=(4, 4026532529))] * 2)

    def test_real_consumers_visibility_and_bounds_never_retry(self):
        for reason in ['cleanup-consumers-open-reference', 'cleanup-consumers-mapped-reference',
                       'cleanup-consumers-fd-table-unavailable', 'cleanup-consumers-task-bound',
                       'cleanup-consumers-fd-bound', 'cleanup-consumers-namespace-bound',
                       'cleanup-consumers-terminal-changed', 'unknown-error']:
            with self.subTest(reason=reason), \
                 mock.patch.object(cleanup_storage.time, 'monotonic', return_value=10), \
                 mock.patch.object(cleanup_storage, '_no_consumers_once', side_effect=Denied(reason)) as scan:
                with self.assertRaisesRegex(Denied, reason):
                    self.invoke()
                self.assertEqual(scan.call_count, 1)
        with mock.patch.object(cleanup_storage, '_no_consumers_once', side_effect=PermissionError()) as scan:
            with self.assertRaises(PermissionError):
                self.invoke(end=float('inf'))
            self.assertEqual(scan.call_count, 1)

    def test_eighth_unstable_full_scan_remains_a_hold(self):
        with mock.patch.object(cleanup_storage.time, 'monotonic', return_value=10), \
             mock.patch.object(cleanup_storage, '_no_consumers_once',
                               side_effect=Denied('cleanup-consumers-process-replaced')) as scan:
            with self.assertRaisesRegex(Denied, 'cleanup-consumers-acquire-unstable'):
                self.invoke()
            self.assertEqual(scan.call_count, 8)

    def test_original_expiry_stops_another_scan_and_final_success(self):
        for sequence in ([Denied('cleanup-consumers-observation-race')], [None]):
            with self.subTest(sequence=sequence), \
                 mock.patch.object(cleanup_storage.time, 'monotonic', side_effect=[10, 100]), \
                 mock.patch.object(cleanup_storage, '_no_consumers_once', side_effect=sequence) as scan:
                with self.assertRaisesRegex(Denied, 'cleanup-storage-budget'):
                    self.invoke()
                self.assertEqual(scan.call_count, 1)

    def test_real_task_growth_restarts_complete_scan_instead_of_false_global_bound(self):
        import tempfile
        import time
        original_path = Path
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            leader = root / '123'
            tasks = leader / 'task'
            tasks.mkdir(parents=True)
            def process(folder):
                folder.mkdir(exist_ok=True)
                (folder / 'stat').write_bytes(b'1 (fixture) Z ' + b'0 ' * 18 + b'7\n')
                (folder / 'maps').write_bytes(b'')
                (folder / 'fd').mkdir(exist_ok=True)
            process(leader)
            process(tasks / '1')
            actual_inventory = cleanup_storage._consumer_tasks
            inventories = []
            def changing_inventory(path, maximum, end):
                if len(inventories) == 1:
                    process(tasks / '2')
                result = actual_inventory(path, maximum, end)
                inventories.append((maximum, {p.name for p in result}))
                return result
            with mock.patch.object(cleanup_storage, 'Path',
                                   side_effect=lambda name: root if name == '/proc' else original_path(name)), \
                 mock.patch.object(cleanup_storage, '_consumer_tasks', side_effect=changing_inventory):
                cleanup_storage._no_consumers({'engine': {'storage_root': '/unused/storage',
                    'runroot': '/unused/run'}, 'output_path': '/unused/output',
                    'context_path': '/unused/context'}, '/unused/descriptor', 'lease', (),
                    time.monotonic() + 10, set(), ())
            self.assertEqual(inventories, [(65536, {'1'}), (65536, {'1', '2'}),
                                           (65536, {'1', '2'}), (65536, {'1', '2'})])

    def test_real_task_inventory_still_rejects_actual_limit_and_malformed_names(self):
        import tempfile
        import time
        with tempfile.TemporaryDirectory() as directory:
            leader = Path(directory)
            (leader / 'task').mkdir()
            (leader / 'task/1').mkdir()
            (leader / 'task/2').mkdir()
            with self.assertRaisesRegex(Denied, 'cleanup-consumers-task-bound'):
                cleanup_storage._consumer_tasks(leader, 1, time.monotonic() + 10)
            (leader / 'task/2').rmdir()
            (leader / 'task/unclassified').mkdir()
            with self.assertRaisesRegex(Denied, 'cleanup-consumers-task-bound'):
                cleanup_storage._consumer_tasks(leader, 65536, time.monotonic() + 10)
