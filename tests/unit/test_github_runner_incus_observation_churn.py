"""Scheduling changes are not generations; failed scans never become proof."""
from pathlib import Path
import sys
import unittest
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
