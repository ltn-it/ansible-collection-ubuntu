"""Fixed-three modeled contracts; fixtures never grant native Source authority.

Receipt pins are patched only for the synthetic isolated realm. Production
qualification99c remains unchanged and actual Root sealing is separate.
"""
import base64
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import identity, ledger, operating_cells as cells, run_factory as factory
from incus_lease_issuer.identity import Denied
import test_github_runner_incus_operating_continuation as legacy_tests
import test_github_runner_incus_operating_two_history_continuation as two_tests


def third_native():
    """Modeled complete provider DTOs with the actual fixed third-run tuple."""
    args = deepcopy(two_tests.prior_native())
    run, inventory, checks, commit = args
    run.update(id=cells.THIRD_RUN, head_sha=cells.THIRD_MAIN)
    run['referenced_workflows'][0].update(sha=cells.THIRD_REUSABLE,
        path='ltn-it/modulix-validation/.github/workflows/collection-quality-profile-isolated.yml@' + cells.THIRD_REUSABLE)
    for job in inventory['jobs']:
        job.update(run_id=cells.THIRD_RUN, head_sha=cells.THIRD_MAIN)
    for job, check, fixed in zip(inventory['jobs'][22:], checks, cells.continuation_third_origin()['jobs']):
        common = {k: fixed[k] for k in ('name', 'started_at', 'completed_at', 'conclusion')}
        job.update(common, id=fixed['job_id'],
            check_run_url=identity.API + '/repos/' + factory.SOURCE + '/check-runs/' + str(fixed['check_run_id']))
        check.update(common, id=fixed['check_run_id'], head_sha=cells.THIRD_MAIN)
    commit.update(sha=cells.THIRD_MAIN, parents=[{'sha': cells.PRIOR_MAIN}, {'sha': 'd' * 40}])
    return args


def third_observation(counts):
    return {'rc': 0, 'stderr_bytes': 0, 'observed': {'schema': 1,
        'state': 'ACTUAL_THIRD_3D84_PRODUCT_STORE_AND_CATALOGUES_EMPTY_NO_LEASE', 'at': 1800000002,
        'boot_id': 'modeled-private-boot', 'machine_id': 'modeled-private-machine',
        'bootstrap_sha256': '1' * 64, 'current_core_sha256': '2' * 64, 'counts': counts,
        'nonce_history_absence_claimed': False, 'operator_raw_ledger_or_signing_key_read_export_or_hash': False,
        'third_attempt': 1, 'third_head': cells.THIRD_MAIN, 'third_public_clients': cells.THIRD_CLIENTS,
        'third_run': cells.THIRD_RUN, 'probe_sent_no_challenge_or_job_request': True,
        'product_store_validation_and_lease_ids_only': True, 'test_state_reset_or_cleanup_performed': False}}


class ThreeHistoryTests(unittest.TestCase):
    def setUp(self):
        self.two = two_tests.TwoHistoryContinuationTests('runTest'); self.two.setUp()
        self.addCleanup(self.two.doCleanups)
        self.patch('TWO_HISTORY_QUALIFICATION', ledger.digest(self.two.value))
        self.native = third_native()
        self.raw = third_observation(deepcopy(self.two.counts))
        self.patch('THIRD_NO_WORK', ledger.digest(self.raw))
        self.value = cells.three_history_continuation_qualification(self.two.value, *self.native,
            ledger.canonical(self.raw), cells.THIRD_CLIENTS)
        self.descriptor = {'schema': 3, 'reason': 'third-runtime-failed-no-work-observed',
            'origin': cells.continuation_origin(), 'prior': cells.continuation_prior_origin(),
            'third': cells.continuation_third_origin(), 'qualification': {'path': '/root/qualified.json',
                'sha256': ledger.digest(self.value)}, 'successor': {'source_sha': 'e' * 40,
                'run_id': cells.THIRD_RUN + 1, 'run_attempt': 1, 'first_parent': cells.THIRD_MAIN,
                'source_workflow_sha256': cells.THREE_HISTORY_WORKFLOW, 'reusable_sha': cells.THREE_HISTORY_REUSABLE}}

    def patch(self, name, value):
        patcher = mock.patch.object(cells, name, value); patcher.start(); self.addCleanup(patcher.stop)

    def validate(self, value):
        return cells.validate_continuation_descriptor(value, cells.THREE_HISTORY_WORKFLOW, cells.THREE_HISTORY_REUSABLE)

    def test_all_three_histories_and_exact_two_history_receipt_are_preserved(self):
        self.assertEqual(self.value['previous_qualification'], self.two.value)
        self.assertEqual(self.value['previous_qualification']['legacy_qualification'], self.two.legacy)
        self.assertEqual(cells.validate_continuation_qualification(self.value), self.two.counts)
        self.assertEqual(cells.validate_continuation_qualification(self.two.value), self.two.counts)
        self.assertEqual(cells.validate_continuation_qualification(self.two.legacy), self.two.counts)
        self.assertEqual(self.validate(self.descriptor), self.descriptor)
        cells.validate_continuation_commit({'sha': 'e' * 40, 'parents': [{'sha': cells.THIRD_MAIN}]},
            self.descriptor, 'e' * 40, cells.THIRD_RUN + 1, cells.THREE_HISTORY_REUSABLE)

    def test_descriptor_denies_history_loss_relabel_replay_and_wrong_contract(self):
        changes = [lambda v: v.update(schema=True), lambda v: v.update(reason='retry'),
            lambda v: v.pop('origin'), lambda v: v.pop('prior'), lambda v: v.pop('third'),
            lambda v: v.update(extra=True), lambda v: v['third'].update(run_attempt=2),
            lambda v: v['prior'].update(source_sha=cells.THIRD_MAIN),
            lambda v: v['successor'].update(run_attempt=True), lambda v: v['successor'].update(run_attempt=2),
            lambda v: v['successor'].update(run_id=cells.THIRD_RUN),
            lambda v: v['successor'].update(source_sha=cells.THIRD_MAIN),
            lambda v: v['successor'].update(first_parent=cells.PRIOR_MAIN),
            lambda v: v['successor'].update(source_workflow_sha256=cells.THIRD_WORKFLOW),
            lambda v: v['successor'].update(reusable_sha=cells.PRIOR_REUSABLE)]
        for change in changes:
            value = deepcopy(self.descriptor); change(value)
            with self.subTest(change=change), self.assertRaises(Denied): self.validate(value)
        for parent in (cells.INITIAL_MAIN, cells.ORIGIN_MAIN, cells.PRIOR_MAIN, 'a' * 40):
            with self.subTest(parent=parent), self.assertRaises(Denied):
                cells.validate_continuation_commit({'sha': 'e' * 40, 'parents': [{'sha': parent}]},
                    self.descriptor, 'e' * 40, cells.THIRD_RUN + 1, cells.THREE_HISTORY_REUSABLE)

    def test_each_history_and_qualification_seal_cannot_be_removed_or_modified(self):
        changes = [lambda v: v['previous_qualification'].pop('legacy_qualification'),
            lambda v: v['previous_qualification']['legacy_qualification']['native_origin']['jobs'].pop(),
            lambda v: v['previous_qualification']['native_prior']['jobs'].pop(),
            lambda v: v['native_third']['jobs'].pop(), lambda v: v['native_third']['jobs'][-1].update(conclusion='success'),
            lambda v: v['third'].update(first_parent=cells.ORIGIN_MAIN),
            lambda v: v['third_public_clients'].update({'incus_runtime_client.py': '0' * 64}),
            lambda v: v.update(no_work_receipt_b64=base64.b64encode(b'{}').decode()),
            lambda v: v.update(nonce_absence=True)]
        for change in changes:
            value = deepcopy(self.value); change(value)
            with self.subTest(change=change), self.assertRaises(Denied): cells.validate_continuation_qualification(value)
        with mock.patch.object(cells, 'THIRD_NO_WORK', None), self.assertRaises(Denied):
            cells.validate_continuation_qualification(self.value)

    def test_real_no_work_predicates_remain_strict_in_modeled_hash_realm(self):
        changes = [lambda v: v['observed']['counts'].update(runtime_lease_count=1),
            lambda v: v['observed']['counts']['native_intake_catalogue'].update(entries=1),
            lambda v: v['observed']['counts']['native_run_configuration_catalogue'].update(directory_inode=125),
            lambda v: v['observed'].update(nonce_history_absence_claimed=True),
            lambda v: v['observed'].update(test_state_reset_or_cleanup_performed=True),
            lambda v: v['observed'].update(probe_sent_no_challenge_or_job_request=False),
            lambda v: v['observed'].update(operator_raw_ledger_or_signing_key_read_export_or_hash=True),
            lambda v: v['observed'].update(third_attempt=2), lambda v: v['observed'].update(at=True),
            lambda v: v.update(rc=1), lambda v: v.update(stderr_bytes=1)]
        for change in changes:
            raw = deepcopy(self.raw); change(raw); value = deepcopy(self.value)
            value['no_work_receipt_b64'] = base64.b64encode(ledger.canonical(raw)).decode()
            with self.subTest(change=change), mock.patch.object(cells, 'THIRD_NO_WORK', ledger.digest(raw)), self.assertRaises(Denied):
                cells.validate_continuation_qualification(value)

    def test_third_native_projection_denies_neighbors(self):
        changes = [(0, lambda v: v.update(run_attempt=2)), (0, lambda v: v.update(status='in_progress')),
            (0, lambda v: v['actor'].update(id=1)), (0, lambda v: v['triggering_actor'].update(login='other')),
            (0, lambda v: v['referenced_workflows'][0].update(sha=cells.PRIOR_REUSABLE)),
            (1, lambda v: v['jobs'].pop()), (1, lambda v: v['jobs'][-1].update(runner_id=79)),
            (1, lambda v: v['jobs'][-1].update(runner_group_id=7)),
            (1, lambda v: v['jobs'][-1].update(completed_at='2026-11-13T02:25:27Z')),
            (2, lambda v: v[0]['app'].update(id=1)), (2, lambda v: v[0].update(conclusion='success')),
            (3, lambda v: v['parents'][0].update(sha=cells.ORIGIN_MAIN))]
        for index, change in changes:
            args = deepcopy(self.native); change(args[index])
            with self.subTest(index=index, change=change), self.assertRaises(Denied): cells.third_native_projection(*args)


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'isolated Linux UID0 EE only')
class RootThreeHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): legacy_tests.RootContinuationTests.setUpClass()

    def setUp(self):
        self.old = legacy_tests.RootContinuationTests('runTest'); self.old.setUp(); self.addCleanup(self.old.doCleanups)
        self.helper = self.old.helper
        self.counts = cells.validate_continuation_qualification(self.old.qualification)
        two = two_tests.TwoHistoryContinuationTests('runTest'); two.setUp(); self.addCleanup(two.doCleanups)
        # Rebuild the prior proof for these real temporary Root directory identities.
        self.patch('ORIGIN_NO_INTAKE', hashlib.sha256(base64.b64decode(self.old.qualification['no_intake_receipt_b64'])).hexdigest())
        self.patch('LEGACY_QUALIFICATION', ledger.digest(self.old.qualification))
        prior_raw = deepcopy(two.raw); prior_raw['observed']['counts'] = self.counts
        self.patch('PRIOR_NO_WORK', ledger.digest(prior_raw)); self.prior = two_tests.prior_native()
        previous = cells.two_history_continuation_qualification(self.old.qualification, *self.prior,
            ledger.canonical(prior_raw), cells.PRIOR_CLIENTS)
        self.patch('TWO_HISTORY_QUALIFICATION', ledger.digest(previous))
        raw = third_observation(self.counts); self.patch('THIRD_NO_WORK', ledger.digest(raw))
        self.third = third_native()
        value = cells.three_history_continuation_qualification(previous, *self.third, ledger.canonical(raw), cells.THIRD_CLIENTS)
        self.old.receipt.write_bytes(ledger.canonical(value)); self.old.receipt.chmod(0o600)
        self.patch('THREE_HISTORY_WORKFLOW', self.helper.value['source_workflow_sha256'])
        self.patch('THREE_HISTORY_REUSABLE', self.helper.value['source_identity']['reusable_sha'])
        self.old.descriptor.clear(); self.old.descriptor.update({'schema': 3, 'reason': 'third-runtime-failed-no-work-observed',
            'origin': cells.continuation_origin(), 'prior': cells.continuation_prior_origin(),
            'third': cells.continuation_third_origin(), 'qualification': {'path': str(self.old.receipt),
                'sha256': ledger.digest(value)}, 'successor': {'source_sha': self.helper.native.claims['sha'],
                'run_id': self.helper.native.run['id'], 'run_attempt': 1, 'first_parent': cells.THIRD_MAIN,
                'source_workflow_sha256': self.helper.value['source_workflow_sha256'],
                'reusable_sha': self.helper.value['source_identity']['reusable_sha']}})
        self.old.parent = cells.THIRD_MAIN
        original_reader = identity.HTTPSReader()
        self.historical_reads = []
        def read(url, *, bearer=None):
            prefix = identity.API + '/repos/' + factory.SOURCE
            routes = {}
            for native, origin in ((self.prior, cells.continuation_prior_origin()), (self.third, cells.continuation_third_origin())):
                routes.update({prefix + '/actions/runs/' + str(origin['run_id']): native[0],
                    prefix + '/actions/runs/' + str(origin['run_id']) + '/attempts/1/jobs?per_page=100&page=1': native[1],
                    prefix + '/git/commits/' + origin['source_sha']: native[3],
                    **{prefix + '/check-runs/' + str(row['id']): row for row in native[2]}})
            if url in routes:
                self.historical_reads.append(url)
                return ledger.canonical(deepcopy(routes[url]))
            return original_reader.read(url, bearer=bearer)
        self.enterContext(mock.patch.object(identity, 'HTTPSReader', return_value=type('Reader', (), {'read': staticmethod(read)})()))
        self.helper.seal()

    def patch(self, name, value): self.enterContext(mock.patch.object(cells, name, value))

    def test_three_native_histories_once_per_proof_and_no_cross_proof_cache(self):
        with mock.patch.object(factory, '_continuation_original_native', wraps=factory._continuation_original_native) as earlier, \
                mock.patch.object(factory, '_continuation_third_native', wraps=factory._continuation_third_native) as third:
            proof, token = self.old.mint()
            for _ in range(2): factory.require_bootstrap_native(proof, self.helper.server, proof.policy, token, 'synthetic-job-token')
            self.assertEqual((earlier.call_count, third.call_count), (2, 1))
            self.assertEqual(len(self.historical_reads), 10)  # Five prior + five third, none on revalidation.
            self.third[2][0]['conclusion'] = 'success'
            with self.assertRaises(Denied): self.old.mint()
            self.assertEqual((earlier.call_count, third.call_count), (4, 2))
            self.assertEqual(len(self.historical_reads), 20)

    def test_all_business_and_operating_cells_keep_fresh_three_history_proofs(self):
        for selector in self.helper.value['cells']:
            for purpose in ('execution', 'observer'):
                with self.subTest(selector=selector, purpose=purpose):
                    proof, token = self.old.mint(selector, purpose)
                    _, who, _ = factory.require_bootstrap_native(
                        proof, self.helper.server, proof.policy, token, 'synthetic-job-token')
                    self.assertEqual(who.run_id, self.old.descriptor['successor']['run_id'])
        with ledger.Ledger(self.helper.store_path) as store:
            self.assertEqual(store.lease_ids(), ())

    def test_every_historical_check_is_still_compared(self):
        for native in (self.old.origin, self.prior, self.third):
            native[2][0]['conclusion'] = 'success'
            with self.subTest(origin=native[0]['id']), self.assertRaises(Denied): self.old.mint()
            native[2][0]['conclusion'] = 'failure'

    def test_current_job_and_absence_checks_remain_fresh(self):
        proof, token = self.old.mint()
        self.helper.native.job['status'] = 'completed'
        with self.assertRaises(Denied):
            factory.require_bootstrap_native(proof, self.helper.server, proof.policy, token, 'synthetic-job-token')
        self.helper.native.job['status'] = 'in_progress'
        (self.old.intakes / ('c' * 64)).mkdir(mode=0o700)
        with self.assertRaises(Denied):
            factory.require_bootstrap_native(proof, self.helper.server, proof.policy, token, 'synthetic-job-token')


if __name__ == '__main__': unittest.main()
