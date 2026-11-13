"""Complete private materialization/readback; only provider/archive IO is modeled.

Real signature/native predicates, repeated collector entrypoints, three Root
archive descriptors, archive validation, policy generation and readback remain.
Real stdlib HTTP framing is exercised separately by test_incus_http_body.
"""
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

FILES=Path(__file__).resolve().parents[2]/"roles/github_runner/files"
sys.path.insert(0,str(FILES))
from incus_lease_issuer import ledger,run_factory as factory,run_intake as intake
import test_github_runner_incus_run_factory as original
import test_github_runner_incus_http_body as http_body
import test_github_runner_incus_runtime_diagnostics as diagnostics


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'private Root Linux EE only')
class Materialization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):original.RootConfigurationTests.setUpClass()
    def test_complete_stage_and_config_keep_all_repeated_native_checks(self):
        fx=original.RootConfigurationTests('runTest');fx.setUp();self.addCleanup(fx.doCleanups)
        # Restore the actual stage producer; model only authenticated provider IO.
        fx.stage.stop()
        root=fx.root/'full-intakes';root.mkdir(mode=0o700)
        artifact=replace(fx.pub.artifact,workflow_id=214182490)
        provider={'MODELED_PROVIDER':'exact-original-run'}
        acquired=replace(fx.pub.acquired,artifact=artifact,
            provenance_sha256=hashlib.sha256(repr(provider).encode('ascii')).hexdigest())
        request=intake.MemoryRequest(
            intake.acquisition.CommitRequest(fx.pub.source.repository,fx.pub.source.repository_id,fx.pub.source.commit_sha),
            intake.acquisition.CommitRequest(fx.pub.controller.repository,fx.pub.controller.repository_id,fx.pub.controller.commit_sha),
            artifact,16*1024**2,20000,16*1024**2,300)
        def acquire(request,api_token,*,artifact_fd,source_fd,controller_fd,_absolute_deadline=None):
            for fd,raw in zip([artifact_fd,source_fd,controller_fd],[fx.pub.artifact_raw,fx.pub.source_raw,fx.pub.controller_raw]):
                self.assertEqual(os.fstat(fd).st_size,0);self.assertEqual(os.write(fd,raw),len(raw));os.fsync(fd)
            return acquired
        with mock.patch.object(intake,'ROOT',str(root)), \
                mock.patch.object(intake,'_native_request',return_value=request) as discovery, \
                mock.patch.object(intake,'_acquire_memory',side_effect=acquire) as download, \
                mock.patch.object(intake.acquisition,'_native',return_value=provider), \
                mock.patch.object(intake.acquisition,'_tree',side_effect=lambda item,*args: next(
                    (row.tree_sha,row.files,row.directories) for row in (acquired.source,acquired.controller)
                    if row.commit_sha==item.commit_sha)), \
                mock.patch.object(factory,'_native',wraps=factory._native) as native, \
                mock.patch.object(factory,'_controls',wraps=factory._controls) as controls:
            fx.helper.collected.reset_mock()
            proof,token=fx.helper.mint()
            configured=factory.create_run_configuration(proof,fx.helper.server,fx.helper.bootstrap,fx.selector,
                token,'synthetic-job-token')
            factory.require_bootstrap_native(proof,fx.helper.server,proof.policy,token,'synthetic-job-token')
            # A new proof is authenticated once; all later current checks remain fresh.
            self.assertEqual(native.call_count,12)
            self.assertEqual(fx.helper.collected.call_count,26)
            self.assertEqual(discovery.call_count,2);self.assertEqual(download.call_count,1)
            self.assertGreaterEqual(controls.call_count,24)
            origin=factory.read_configuration_origin(configured)
            self.assertEqual(origin['run_id'],proof.identity.run_id)
            self.assertEqual(origin['job_id'],proof.identity.job_id)
            self.assertEqual(len(list(root.iterdir())),1)
            self.assertTrue((Path(configured.directory)/'sealed-inventory.json').is_file())
            with ledger.Ledger(fx.helper.store_path)as store:self.assertEqual(store.lease_ids(),())

    def test_real_acquisition_failure_survives_all_sanitizing_wrappers_without_reflection(self):
        class ForeignError(Exception):
            def __getattribute__(self,name):
                raise AssertionError('foreign exception inspected')
            def __str__(self):
                raise AssertionError('foreign exception formatted')
            def __repr__(self):
                raise AssertionError('foreign exception represented')
        class ForeignFraming(intake.acquisition.http.client.IncompleteRead):
            def __getattribute__(self,name):
                raise AssertionError('foreign framing exception inspected')
            def __str__(self):
                raise AssertionError('foreign framing exception formatted')
        marker=b'synthetic-credential-body-and-signed-query'
        cases=[('framing','acquisition-framing'),('deadline','acquisition-deadline'),
               ('api','acquisition-api-status'),('foreign','unclassified'),('forged','unclassified'),
               ('foreign-framing','unclassified')]
        for kind,reason in cases:
            with self.subTest(kind=kind),ExitStack() as stack:
                fx=original.RootConfigurationTests('runTest');fx.setUp();stack.callback(fx.doCleanups)
                fx.stage.stop();root=fx.root/'full-intakes';root.mkdir(mode=0o700)
                item=replace(fx.pub.artifact,workflow_id=214182490)
                request=intake.MemoryRequest(
                    intake.acquisition.CommitRequest(fx.pub.source.repository,fx.pub.source.repository_id,fx.pub.source.commit_sha),
                    intake.acquisition.CommitRequest(fx.pub.controller.repository,fx.pub.controller.repository_id,fx.pub.controller.commit_sha),
                    item,16*1024**2,20000,16*1024**2,300)
                framed=http_body.response(marker,declared=len(marker)+(1 if kind=='framing' else 0),
                    status=503 if kind=='api' else 200)
                stack.enter_context(http_body.wire(self,framed))
                diag=diagnostics.DiagnosticsTests('runTest')
                diag.socket=mock.MagicMock();diag.log=diag.socket.return_value.__enter__.return_value.sendto
                # Replace only identity's diagnostic transport namespace. The
                # real peer socket class remains intact for native admission.
                real_socket=factory.identity.socket
                diagnostic_socket=SimpleNamespace(socket=diag.socket,**{key:getattr(real_socket,key) for key in
                    ['AF_UNIX','SOCK_DGRAM','SOCK_CLOEXEC','SOCK_NONBLOCK']})
                stack.enter_context(mock.patch.object(factory.identity,'socket',diagnostic_socket))
                stack.enter_context(mock.patch.object(intake,'ROOT',str(root)))
                stack.enter_context(mock.patch.object(intake,'_native_request',return_value=request))
                if kind=='deadline':
                    remaining=intake.acquisition._remaining
                    stack.enter_context(mock.patch.object(intake.acquisition,'_remaining',side_effect=lambda deadline:remaining(-1)))
                if kind in {'foreign','forged','foreign-framing'}:
                    error=(ForeignError() if kind=='foreign' else ForeignFraming(marker) if kind=='foreign-framing'
                           else factory.identity.Denied('acquisition-deadline '+marker.decode()))
                    stack.enter_context(mock.patch.object(intake.acquisition,'_repository',side_effect=error))
                with self.assertRaisesRegex(factory.identity.Denied,'^run-configuration-held$') as caught:
                    with factory.identity._diagnostic_request():
                        factory.create_run_configuration(fx.proof,fx.helper.server,fx.bootstrap,fx.selector,
                            fx.token,'synthetic-job-token')
                self.assertEqual(caught.exception.args,('run-configuration-held',))
                diag.log.assert_called_once()
                record=diag.record()
                self.assertEqual((record['stage'],record['reason']),('snapshot-acquisition',reason))
                self.assertNotIn(marker,diag.log.call_args.args[0])
                self.assertNotIn(b'synthetic-job-token',diag.log.call_args.args[0])
                self.assertIsNone(factory.identity._DIAGNOSTIC.get())

if __name__=='__main__':unittest.main()
