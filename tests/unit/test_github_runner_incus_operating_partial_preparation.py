"""Operating pre-engine prefix through real Root Ledger/Unix mutation fixtures.

Incus replies and native terminal identity are modeled; no actual VM or grant.
"""
from contextlib import nullcontext
import copy
import hashlib
import os
import sys
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import test_github_runner_incus_partial_preparation as partial
import test_github_runner_incus_operating_ready_custody as operating
import test_github_runner_incus_cell_contract as cells
import test_github_runner_incus_preparation as prep_fixtures
import test_github_runner_incus_mutation as mutations
from incus_lease_issuer import (cell_contract, cleanup_storage, context_publisher,
    identity, ledger, operating_cells, operating_custody, preparation)
from incus_lease_issuer.identity import Denied


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'proper Root Linux EE only')
class OperatingPartialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        partial.PartialPreparationTests.setUpClass()

    def setUp(self):
        # Transform sealed semantics BEFORE the original admission/prepare.
        semantic = operating.operating_semantic_fixture()
        fixture = operating.operating_preparation_fixture()
        for module, name, value in ((operating, 'SELECTOR', 'approved'),
                (cells, 'RootCellContractTests', semantic),
                (prep_fixtures, 'RootPreparationTests', fixture)):
            patch = mock.patch.object(module, name, value)
            patch.start(); self.addCleanup(patch.stop)
        original = mutations.MutationFixture.handle
        def images(server, method, path, body):
            route, query = urlsplit(path).path, parse_qs(urlsplit(path).query)
            if route == '/1.0/images' and query.get('project'):
                project = query['project'][0]
                target = '/1.0/images/' + operating_cells.IMAGE + '?project=' + project
                if method == 'POST':
                    server.resources[target] = {'fingerprint': operating_cells.IMAGE,
                        'type': 'virtual-machine', 'public': False, 'auto_update': False, 'aliases': []}
                    return mutations.reply(mutations.envelope({}))
                if method == 'GET':
                    return mutations.reply(mutations.envelope(
                        sorted(k.split('?',1)[0] for k in server.resources if k.startswith('/1.0/images/') and k.endswith('?project=' + project))))
            if method == 'GET' and path == '/1.0/images/' + operating_cells.IMAGE + '?project=default':
                return mutations.reply(mutations.envelope({'fingerprint': operating_cells.IMAGE,
                    'type': 'virtual-machine'}))
            return original(server, method, path, body)
        patch = mock.patch.object(mutations.MutationFixture, 'handle', images)
        patch.start(); self.addCleanup(patch.stop)
        self.f = partial.PartialPreparationTests(); self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.store, self.lease = self.f.store, self.f.lease

    def failed(self, after_certificate=False):
        module, name = (preparation, '_engine_directories') if after_certificate else (context_publisher, 'RootContextPublisher')
        with mock.patch.object(module, name, side_effect=Denied('fixture-after-certificate')):
            with self.assertRaises(preparation.PreparationUnknown): self.f.io.run_prepare()
        owner = cell_contract.partial_preparation_owner(self.f.registry, 'approved', self.store, self.lease)
        effects = list(self.store.read(self.lease)['effects'].values())
        expected = {'network-create','project-create','profile-configure','image-copy','context-create','certificate-create'}
        if not after_certificate: expected.add('engine-prepare')
        self.assertEqual({e['operation'] for e in effects}, expected)
        self.assertTrue(all(e['state'] == 'verified' for e in effects))
        project = owner.incus['project']
        self.image = '/1.0/images/' + operating_cells.IMAGE + '?project=' + project
        self.f.io.server.resources['/1.0/instances?project=' + project] = []
        self.f.io.server.resources['/1.0/operations?project=' + project + '&recursion=1'] = {}
        return owner

    def retained(self, after_certificate=False):
        owner = self.failed(after_certificate)
        self.f.finalizer.withdraw_partial_preparation(self.f.registry,'approved',self.store,self.lease)
        self.f.terminal()
        receipt = operating_custody.retain_partial_preparation(self.f.registry,'approved',self.store,self.lease)
        self.f.now = receipt['retain_until']
        return owner, receipt

    def cleanup(self):
        with mock.patch.object(cleanup_storage,'_cleanup_limits',return_value=(100000,30)), \
                mock.patch.object(cleanup_storage.storage_quota,'acquire_existing_evidence_quota',side_effect=lambda *a:nullcontext()):
            return self.f.finalizer.finalize_partial_preparation(self.f.registry,'approved',self.store,self.lease)

    def test_operating_after_certificate_withdraw_four_hour_image_cleanup_and_close(self):
        owner, receipt = self.retained()
        self.assertIn('image-copy', owner.creators)
        self.assertIn(self.image, self.f.io.server.resources)
        self.assertEqual(receipt['retain_until'], self.store.read(self.lease)['native_terminal']['completed_at'] + 14400)
        self.f.now -= 1
        with self.assertRaises(Denied): self.cleanup()
        self.assertIn(self.image,self.f.io.server.resources)
        self.f.now += 1
        result = self.cleanup()
        self.assertEqual(result['state'],'FAILED_PARTIAL_PREPARATION_CLOSED')
        self.assertNotIn(self.image,self.f.io.server.resources)
        record = self.store.read(self.lease)
        self.assertEqual(record['state'],'closed')
        self.assertNotIn('owned_instance',record); self.assertNotIn('custody',record)
        self.assertFalse(any(e['operation'] in {'engine-start','instance-create','context-publish','fence-create'} for e in record['effects'].values()))
        deleted = [r[1] for r in self.f.io.server.requests if r[0] == 'DELETE']
        self.assertEqual(deleted.count(self.image),1)
        self.assertLess(deleted.index(self.image),deleted.index('/1.0/projects/' + owner.incus['project']))
        ledger.Ledger._cleanup_complete(list(record['effects'].values()))

    def test_foreign_or_changed_image_denies_before_image_delete_or_parent_delete(self):
        owner,_ = self.retained()
        self.f.io.server.resources[self.image]['aliases'] = [{'name':'foreign'}]
        with self.assertRaises(Denied): self.cleanup()
        self.assertIn(self.image,self.f.io.server.resources)
        self.assertFalse(any(r[0]=='DELETE' and (r[1]==self.image or r[1].startswith('/1.0/projects/')) for r in self.f.io.server.requests))
        self.assertNotEqual(self.store.read(self.lease)['state'],'closed')

    def test_missing_owned_image_is_not_adopted_as_success(self):
        self.retained(); self.f.io.server.resources.pop(self.image)
        with self.assertRaises(Denied): self.cleanup()
        self.assertNotEqual(self.store.read(self.lease)['state'],'closed')
        self.assertFalse(any(r[0]=='DELETE' and r[1].startswith('/1.0/projects/') for r in self.f.io.server.requests))

    def test_unverified_or_wrong_target_copy_still_denies_owner(self):
        self.failed(); record = self.store.read(self.lease)
        image_id = next(k for k,e in record['effects'].items() if e['operation']=='image-copy')
        for change in ({'state':'unknown'},{'target':'image:foreign:' + operating_cells.IMAGE}):
            changed = copy.deepcopy(record); changed['effects'][image_id].update(change)
            with mock.patch.object(self.store,'read',return_value=changed), self.assertRaises(Denied):
                cell_contract.partial_preparation_owner(self.f.registry,'approved',self.store,self.lease)

    def test_failure_immediately_after_certificate_without_engine_cleans_exact_image(self):
        owner, _ = self.retained(after_certificate=True)
        self.assertNotIn('engine-prepare', owner.creators)
        self.assertIn('image-copy', owner.creators)
        result = self.cleanup()
        self.assertEqual(result['state'], 'FAILED_PARTIAL_PREPARATION_CLOSED')
        self.assertNotIn(self.image, self.f.io.server.resources)
        self.assertNotIn('owned_instance', self.store.read(self.lease))

    def test_replaced_parent_project_never_authorizes_image_or_project_delete(self):
        owner, _ = self.retained()
        self.f.io.server.resources['/1.0/projects/' + owner.incus['project']]['description'] = 'foreign replacement'
        with self.assertRaises(Denied): self.cleanup()
        self.assertIn(self.image, self.f.io.server.resources)
        self.assertFalse(any(r[0] == 'DELETE' and (r[1] == self.image or r[1].startswith('/1.0/projects/')) for r in self.f.io.server.requests))

    def test_watchdog_accepts_operating_prefix_withdraws_and_retains_original_clock(self):
        self.failed(after_certificate=True); terminal = self.f.terminal()
        result = operating_custody.tick_runtime(str(self.f.runtime), hashlib.sha256(self.f.runtime.read_bytes()).hexdigest(), 'f'*64)
        record = self.store.read(self.lease)
        self.assertEqual([e['kind'] for e in result['events']], ['failed-cell-retained'])
        self.assertEqual(record['partial_preparation_custody']['retain_until'], terminal['completed_at'] + 14400)
        self.assertTrue(any(e['operation'] == 'certificate-revoke' and e['state'] == 'verified' for e in record['effects'].values()))
        self.assertIn(self.image, self.f.io.server.resources)
