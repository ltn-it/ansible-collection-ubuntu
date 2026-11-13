"""Pure two-history counterfactuals; modeled provider/Root receipts grant no authority.

Temporary receipt hash anchors model an isolated Root test realm. Qualification
of the actual private receipts is separate and uses unmodified production pins.
"""
import base64
import hashlib
from pathlib import Path
import sys
import unittest
from copy import deepcopy
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))

from incus_lease_issuer import identity, ledger
from incus_lease_issuer import operating_cells as cells
from incus_lease_issuer.identity import Denied
from test_github_runner_incus_operating_continuation import original_native


def prior_native():
    """Native-shaped DTOs, preserving the exact fixed physical job facts."""
    prior = cells.continuation_prior_origin()
    run, inventory, checks, commit = original_native()
    run.update(id=cells.PRIOR_RUN, head_sha=cells.PRIOR_MAIN)
    run['referenced_workflows'][0].update(sha=cells.PRIOR_REUSABLE,
        path='ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@' + cells.PRIOR_REUSABLE)
    for job in inventory['jobs'][:22]:
        job.update(run_id=cells.PRIOR_RUN, head_sha=cells.PRIOR_MAIN)
    for job, check, fixed in zip(inventory['jobs'][22:], checks, prior['jobs']):
        common = {k: fixed[k] for k in ('name', 'started_at', 'completed_at', 'conclusion')}
        job.update(common, id=fixed['job_id'], run_id=cells.PRIOR_RUN, head_sha=cells.PRIOR_MAIN,
            check_run_url=identity.API + '/repos/' + prior['repository'] + '/check-runs/' + str(fixed['check_run_id']))
        check.update(common, id=fixed['check_run_id'], head_sha=cells.PRIOR_MAIN)
    commit.update(sha=cells.PRIOR_MAIN, parents=[{'sha': cells.ORIGIN_MAIN}, {'sha': 'd' * 40}])
    return run, inventory, checks, commit


class TwoHistoryContinuationTests(unittest.TestCase):
    def setUp(self):
        self.counts = {name: {'directory_device': 7, 'directory_inode': ino, 'entries': 0}
            for name, ino in [('native_intake_catalogue', 123), ('native_run_configuration_catalogue', 124)]}
        self.counts['runtime_lease_count'] = 0
        legacy_raw = ledger.canonical({'rc': 0, 'stderr_bytes': 0, 'observed': {'schema': 1,
            'state': 'ACTUAL_EXISTING_PRODUCT_STORE_AND_CATALOGUES_EMPTY_NO_INTAKE_OR_LEASE', 'at': 1800000000,
            'original_run': cells.ORIGIN_RUN, 'original_attempt': 1, 'original_head': cells.ORIGIN_MAIN,
            'counts': self.counts, 'no_challenge_or_job_request': True, 'no_state_reset_or_cleanup': True,
            'operator_raw_ledger_or_signing_key_read_export_or_hash': False,
            'product_store_validation_and_lease_ids_only': True}})
        self.patch('ORIGIN_NO_INTAKE', hashlib.sha256(legacy_raw).hexdigest())
        self.legacy = cells.continuation_qualification(*original_native(), legacy_raw, cells.ORIGIN_CLIENTS)
        self.patch('LEGACY_QUALIFICATION', ledger.digest(self.legacy))
        self.raw = {'rc': 0, 'stderr_bytes': 0, 'observed': {'schema': 1,
            'state': 'ACTUAL_PRIOR_F27_PRODUCT_STORE_AND_CATALOGUES_EMPTY_NO_LEASE', 'at': 1800000001,
            'boot_id': 'modeled-private-boot', 'machine_id': 'modeled-private-machine',
            'bootstrap_sha256': '1' * 64, 'current_core_sha256': '2' * 64, 'counts': self.counts,
            'nonce_history_absence_claimed': False, 'operator_raw_ledger_or_signing_key_read_export_or_hash': False,
            'prior_attempt': 1, 'prior_head': cells.PRIOR_MAIN, 'prior_public_clients': cells.PRIOR_CLIENTS,
            'prior_run': cells.PRIOR_RUN, 'probe_sent_no_challenge_or_job_request': True,
            'product_store_validation_and_lease_ids_only': True, 'test_state_reset_or_cleanup_performed': False}}
        self.patch('PRIOR_NO_WORK', ledger.digest(self.raw))
        self.native = prior_native()
        self.value = cells.two_history_continuation_qualification(self.legacy, *self.native,
            ledger.canonical(self.raw), cells.PRIOR_CLIENTS)
        self.descriptor = {'schema': 2, 'reason': 'prior-initial-preauth-denied', 'origin': cells.continuation_origin(),
            'prior': cells.continuation_prior_origin(), 'qualification': {'path': '/root/qualified.json',
                'sha256': ledger.digest(self.value)}, 'successor': {'source_sha': 'e' * 40,
                'run_id': cells.PRIOR_RUN + 1, 'run_attempt': 1, 'first_parent': cells.PRIOR_MAIN,
                'source_workflow_sha256': cells.TWO_HISTORY_WORKFLOW, 'reusable_sha': cells.TWO_HISTORY_REUSABLE}}

    def patch(self, name, value):
        patcher = mock.patch.object(cells, name, value)
        patcher.start(); self.addCleanup(patcher.stop)

    def validate_descriptor(self, value):
        return cells.validate_continuation_descriptor(value, cells.TWO_HISTORY_WORKFLOW, cells.TWO_HISTORY_REUSABLE)

    def test_exact_two_history_receipt_retains_legacy_and_same_empty_catalogues(self):
        self.assertEqual(cells.validate_continuation_qualification(self.value), self.counts)
        self.assertEqual(self.value['legacy_qualification'], self.legacy)
        self.assertEqual(cells.validate_continuation_qualification(self.legacy), self.counts)
        self.assertEqual(len(self.value['native_prior']['jobs']), 24)
        self.assertEqual(self.validate_descriptor(self.descriptor), self.descriptor)
        cells.validate_continuation_commit({'sha': 'e' * 40, 'parents': [{'sha': cells.PRIOR_MAIN}]},
            self.descriptor, 'e' * 40, cells.PRIOR_RUN + 1, cells.TWO_HISTORY_REUSABLE)

    def test_descriptor_rejects_replay_future_parent_wrong_contract_and_extra_fields(self):
        mutations = [lambda v: v.update(schema=True), lambda v: v.update(reason='retry'),
            lambda v: v.pop('origin'), lambda v: v['origin'].update(run_id=cells.PRIOR_RUN),
            lambda v: v['prior'].update(run_attempt=2), lambda v: v['successor'].update(run_attempt=2),
            lambda v: v['successor'].update(run_attempt=True), lambda v: v['successor'].update(first_parent='a' * 40),
            lambda v: v['successor'].update(first_parent=cells.ORIGIN_MAIN),
            lambda v: v['successor'].update(source_sha=cells.PRIOR_MAIN),
            lambda v: v['successor'].update(run_id=cells.PRIOR_RUN),
            lambda v: v['successor'].update(run_id=cells.ORIGIN_RUN),
            lambda v: v['successor'].update(reusable_sha=cells.PRIOR_REUSABLE),
            lambda v: v['successor'].update(source_workflow_sha256=cells.PRIOR_WORKFLOW),
            lambda v: v.update(retry=True)]
        for i, change in enumerate(mutations):
            value = deepcopy(self.descriptor); change(value)
            with self.subTest(i=i), self.assertRaises(Denied): self.validate_descriptor(value)

    def test_native_projection_rejects_each_authority_neighbor(self):
        mutations = [(0, lambda v: v.update(run_attempt=2)), (0, lambda v: v.update(head_sha=cells.ORIGIN_MAIN)),
            (0, lambda v: v['actor'].update(id=1)), (0, lambda v: v['repository'].update(id=1)),
            (0, lambda v: v['referenced_workflows'][0].update(sha=cells.ORIGIN_REUSABLE)),
            (1, lambda v: v['jobs'].pop()), (1, lambda v: v['jobs'][-1].update(runner_id=79)),
            (1, lambda v: v['jobs'][-1].update(runner_group_id=7)),
            (1, lambda v: v['jobs'][-1].update(completed_at='2026-11-12T22:14:54Z')),
            (2, lambda v: v[0].update(conclusion='success')), (2, lambda v: v[0]['app'].update(id=1)),
            (3, lambda v: v['parents'][0].update(sha=cells.INITIAL_MAIN))]
        for i, (index, change) in enumerate(mutations):
            args = deepcopy(self.native); change(args[index])
            with self.subTest(i=i), self.assertRaises(Denied): cells.prior_native_projection(*args)

    def test_qualification_rejects_missing_or_modified_history_and_native_inventory(self):
        mutations = [lambda v: v['legacy_qualification']['origin'].update(run_attempt=2),
            lambda v: v['legacy_qualification']['native_origin']['jobs'].pop(),
            lambda v: v['prior'].update(first_parent=cells.INITIAL_MAIN),
            lambda v: v['native_prior']['jobs'].pop(),
            lambda v: v['native_prior']['jobs'][-1].update(conclusion='success'),
            lambda v: v['prior_public_clients'].update({'incus_job_client.py': '0' * 64}),
            lambda v: v.update(no_work_receipt_b64=base64.b64encode(b'{}').decode()),
            lambda v: v.update(nonce_absence=True)]
        for i, change in enumerate(mutations):
            value = deepcopy(self.value); change(value)
            with self.subTest(i=i), self.assertRaises(Denied): cells.validate_continuation_qualification(value)

    def test_no_work_semantics_remain_strict_even_in_modeled_hash_realm(self):
        mutations = [lambda v: v['observed']['counts']['native_intake_catalogue'].update(entries=1),
            lambda v: v['observed']['counts']['native_run_configuration_catalogue'].update(directory_inode=125),
            lambda v: v['observed']['counts'].update(runtime_lease_count=1),
            lambda v: v['observed'].update(nonce_history_absence_claimed=True),
            lambda v: v['observed'].update(test_state_reset_or_cleanup_performed=True),
            lambda v: v['observed'].update(probe_sent_no_challenge_or_job_request=False),
            lambda v: v['observed'].update(prior_attempt=2), lambda v: v.update(rc=1)]
        for i, change in enumerate(mutations):
            raw = deepcopy(self.raw); change(raw)
            value = deepcopy(self.value); value['no_work_receipt_b64'] = base64.b64encode(ledger.canonical(raw)).decode()
            with self.subTest(i=i), mock.patch.object(cells, 'PRIOR_NO_WORK', ledger.digest(raw)), self.assertRaises(Denied):
                cells.validate_continuation_qualification(value)

    def test_actual_successor_native_commit_cannot_swap_tuple_or_parent(self):
        for parent in (cells.INITIAL_MAIN, cells.ORIGIN_MAIN, 'a' * 40):
            with self.subTest(parent=parent), self.assertRaises(Denied):
                cells.validate_continuation_commit({'sha': 'e' * 40, 'parents': [{'sha': parent}]},
                    self.descriptor, 'e' * 40, cells.PRIOR_RUN + 1, cells.TWO_HISTORY_REUSABLE)
        with self.assertRaises(Denied):
            cells.validate_continuation_commit({'sha': 'e' * 40, 'parents': [{'sha': cells.PRIOR_MAIN}]},
                self.descriptor, 'e' * 40, cells.PRIOR_RUN, cells.TWO_HISTORY_REUSABLE)


if __name__ == '__main__': unittest.main()
