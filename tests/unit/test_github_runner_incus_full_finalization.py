"""Staged full Root CORE fixture, NOT native Podman/VM/custody qualification.

Compile/execute only centrally in proper3174 EE. All actual Root FS, signatures,
Unix Incus transport, journal, fixed compiled argv and process exit are retained.
Only unavailable host/private kernel, runtime/image and idmap acquisition is
modeled. Fresh native socket admission is separately exercised by entry tests.
"""
from contextlib import contextmanager, nullcontext
import hashlib
import ctypes
import json
import os
from pathlib import Path
import re
import sys
import unittest
from unittest import mock

import test_github_runner_incus_finalization as compiled_fixtures
import test_github_runner_incus_refresh as refresh_fixtures
import test_github_runner_incus_engine_policy as compiler_fixtures
from incus_lease_issuer import (cell_contract, cleanup_storage, engine_executor, engine_policy,
    evidence_export, evidence_policy, finalization, identity, ledger, network_fence,
    preparation, root_session, runtime_entry, runtime_rpc, storage_quota)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if type(value) is bytes else ledger.canonical(value))
    path.chmod(0o600)


def fixture_evidence(details):
    """Synthetic test observations in the real full Thin report/checksum shape."""
    env = details["environment"]
    scenario, target, profile = (env["QUALITY_INPUT_SCENARIO"], env["QUALITY_INPUT_TARGET"], env["QUALITY_INPUT_PROFILE"])
    roles = env["QUALITY_INPUT_ROLES"]
    output = Path(details["output"]["path"])
    suffix = scenario+"/"+target+"/attempt-1"
    base = output/"artifacts/cell-evidence"/suffix
    write(output/"artifacts/raw"/suffix/"configuration/lifecycle-result.json", {
        "schema_version": 1, "scenario": scenario, "target": target, "run_attempt": "1",
        "test_exit_code": 0, "capture_exit_code": 0, "destroy_exit_code": 0,
        "effective_exit_code": 0, "infrastructure_error": False})
    props = {"commit_sha": env["QUALITY_INPUT_SOURCE_SHA"], "profile": profile, "scenario": scenario,
             "target": target, "run_attempt": "1", "roles": roles}
    xml = "<testsuite><properties>"+"".join('<property name="'+key+'" value="'+value+'"/>' for key,value in props.items())
    xml += '</properties><testcase classname="fixture" name="observed" time="0.01"/></testsuite>'
    write(base/"junit/report.xml", xml.encode())
    labels = {"commit-sha": env["QUALITY_INPUT_SOURCE_SHA"], "profile": profile, "scenario": scenario,
              "target": target, "run-attempt": "1", "role": roles}
    write(base/"allure-results/one-result.json", {"uuid": "fixture-observation", "name": "observed",
        "fullName": "fixture.observed", "status": "passed", "start": 1000, "stop": 1010,
        "labels": [{"name":key,"value":value} for key,value in labels.items()]})
    report = evidence_policy.parse_junit(base/"junit/report.xml")
    results = evidence_policy._aggregate_reports([{"identity": evidence_policy.Identity(roles,profile,scenario,target,"1"),
        "report":report,"junit":"junit/report.xml","allure_results":["allure-results/one-result.json"],"allure_complete":True}])
    source = {"schema_version":2,"repository":env["GITHUB_REPOSITORY"],"workflow_run_id":env["GITHUB_RUN_ID"],
        "workflow_attempt":"1","commit_sha":env["QUALITY_INPUT_SOURCE_SHA"],"expected_commit_sha":env["QUALITY_INPUT_SOURCE_SHA"],
        "mode":"ci","commit_consistent":True,"test_totals":report["totals"],"failures":0,"skips":0,"results":results,
        "matrix":{"actual_count":1,"expected":[{"profile":profile,"scenario":scenario,"target":target,
            "run_attempt":"1","status":"passed","roles":roles.split(",")}]},
        "secret_scan":{"canary_detected_before_redaction":True,"clean":True,"files_scanned":2,
            "archive_members_scanned":0,"findings":[],"errors":[]},
        "security_evidence":{"required_for_release":[],"missing":[],"external_secret_findings":0,
            "vulnerability_blocking_findings":0,"semantic_valid":False},"prerequisites":{},"blockers":[],"release_eligible":False}
    files = sorted(path for path in base.rglob("*") if path.is_file())
    source["checksums"]={"algorithm":"sha256","file":"checksums/SHA256SUMS","entry_count":len(files)+1}
    write(base/"manifest.json",source)
    files.append(base/"manifest.json")
    write(base/"checksums/SHA256SUMS", "".join(hashlib.sha256(path.read_bytes()).hexdigest()+"  "+path.relative_to(base).as_posix()+"\n"
                                              for path in sorted(files)).encode())


@unittest.skipUnless(sys.platform=="linux" and os.geteuid()==0,"private proper-EE Root only")
class RootFullCoreFinalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        refresh_fixtures.RootRefreshTests.setUpClass()

    def setUp(self):
        self.cpp=compiled_fixtures.RootCompiledFixedEngineTests()
        self.cpp.setUp()
        self.addCleanup(self.cpp.doCleanups)
        binary=str(self.cpp.binary)
        digest=hashlib.sha256(self.cpp.binary.read_bytes()).hexdigest()
        original=compiler_fixtures.RootEngineCompilerTests.setUp
        def actual_package(instance):
            original(instance)
            instance.mock_file.stop()
            instance.data["engine"]={**instance.data["engine"],"executable":binary,"executable_sha256":digest}
        with mock.patch.object(compiler_fixtures.RootEngineCompilerTests,"setUp",actual_package):
            self.model=refresh_fixtures.RootRefreshTests()
            self.model.setUp()
        self.addCleanup(self.model.doCleanups)
        patch=mock.patch.object(ledger,"ENGINE_EXECUTABLE",binary)
        patch.start();self.addCleanup(patch.stop)
        self.io,self.store,self.lease,self.registry=self.model.io,self.model.store,self.model.lease,self.model.registry
        project=self.io.prepared.incus["project"]
        self.io.server.resources["/1.0/instances?project="+project]=[]
        self.io.server.resources["/1.0/operations?project="+project+"&recursion=1"]={}
        self.runtime=self.io.root/"full-runtime.json"
        capture=identity.decode_json(self.io.prepared.engine_descriptor_bytes)["capture"]
        values={"schema":2,"registry_path":self.registry.path,"registry_sha256":self.registry.sha256,
            "preparation_config_path":str(self.io.config),"preparation_config_sha256":self.io.sha,
            "authentication_timeout_seconds":5,"initial_transition_timeout_seconds":60,"heartbeat_lead_seconds":30,
            "cleanup_timeout_seconds":60,"capture":{**capture,"max_total_evidence_bytes":8*1024*1024,
                "max_members":128,"max_member_bytes":1024*1024}}
        write(self.runtime,values);self.sha=hashlib.sha256(self.runtime.read_bytes()).hexdigest()
        self.private_ttl,self.private_deadline=0,0
        self.cgroup=self.io.root/"modeled-kernel-cgroup"
        self.cgroup.mkdir(mode=0o700)
        write(self.cgroup/"cgroup.events",b"populated 0\nfrozen 0\n")
        write(self.cgroup/"cgroup.procs",b"")

    @contextmanager
    def native_kernel_model(self):
        """Syscall/native acquisition observations ONLY; no whole cleanup mocks."""
        info=os.stat(self.model.fence.path)
        cgroup_info=os.stat(self.cgroup)
        actual_libc=ctypes.CDLL(None,use_errno=True)
        class LibcObservation:
            def __getattr__(self,name):return getattr(actual_libc,name)
            def fstatfs(inner,fd,buffer):
                observed=os.fstat(fd)
                if (observed.st_dev,observed.st_ino)==(cgroup_info.st_dev,cgroup_info.st_ino):
                    ctypes.c_long.from_buffer(buffer).value=engine_executor.CGROUP2_MAGIC
                    return 0
                return actual_libc.fstatfs(fd,buffer)
        @contextmanager
        def namespace(_):
            fd=os.open(self.model.fence.path,os.O_RDONLY|os.O_NOFOLLOW)
            try:yield fd,info
            finally:os.close(fd)
        @contextmanager
        def acquired(*args,**kwargs):
            yield
        def nft(policy,prepared,*args,payload=None):
            if payload is None:
                return ledger.canonical(self.model.fence.readback(ttl=self.private_ttl,deadline=self.private_deadline))
            text=payload.decode()
            match=re.search(r"meta time < ([0-9]+) accept",text)
            if match:
                self.private_deadline=int(match[1])
                timeout=re.search(r"timeout ([0-9]+)s",text)
                assert timeout is not None
                # Actual generated integer-second TTL, floored native output.
                self.private_ttl=int(timeout[1])-1
            elif "flush set" in text:self.private_ttl=0
            return b""
        original_open=network_fence.installation._open_directory
        def native_directory(path):
            if path=="/run/netns":return original_open(str(self.io.root))
            if path.startswith("/sys/fs/cgroup/lit.slice/lit-lease.slice/"):
                assert path.endswith("lit-lease-"+self.lease+".slice")
                return original_open(str(self.cgroup))
            return original_open(path)
        with self.model.host_kernel(), mock.patch.object(network_fence,"_worker"), \
             mock.patch.object(network_fence,"_backend"),mock.patch.object(network_fence,"_namespace",side_effect=namespace), \
             mock.patch.object(network_fence,"_links",return_value=(100,2)),mock.patch.object(network_fence,"_nft",side_effect=nft), \
             mock.patch.object(network_fence,"_run",return_value=b"[]"), \
             mock.patch.object(network_fence,"_removal_witness",side_effect=namespace), \
             mock.patch.object(network_fence,"_namespace_cookie",return_value=42), \
             mock.patch.object(network_fence,"_namespace_refs_drained"), \
             mock.patch.object(network_fence.installation,"_open_directory",side_effect=native_directory), \
             mock.patch.object(ctypes,"CDLL",return_value=LibcObservation()), \
             mock.patch.object(engine_executor,"_preflight",side_effect=acquired), \
             mock.patch.object(engine_executor,"_idmapped_preflight"), \
             mock.patch.object(engine_executor,"_cgroup",return_value=(cgroup_info.st_dev,cgroup_info.st_ino)), \
             mock.patch.object(storage_quota,"acquire_existing_evidence_quota",side_effect=acquired), \
             mock.patch.object(cleanup_storage,"_cleanup_limits",side_effect=lambda cfg:(4096,cfg.operation_wait_seconds)):
            yield

    def test_actual_signed_fixed_engine_exit_public_evidence_and_owned_cleanup_close(self):
        # Parent hosts the actual Unix fixture, child has ONE Python thread.
        child=os.fork()
        if child==0:
            try:
                with self.native_kernel_model():
                    with root_session._session(str(self.io.config),self.io.sha) as session:
                        cfg=root_session._require_session(session)
                        with runtime_entry._initial_effects_deadline(60,self.io.prepared.expires_at):
                            network_fence.renew(cfg.network_fence_policy_path,cfg.network_fence_policy_sha256,
                                self.io.prepared,self.store,self.model.worker,cfg)
                            engine_executor._start_locked(session,self.registry,"approved",self.store,self.lease,self.model.initial)
                    raw=(Path(identity.decode_json(self.io.prepared.engine_descriptor_bytes)["engine"]["runroot"])/"engine-manifest.json").read_bytes()
                    details=identity.decode_json(raw)
                    fixture_evidence(details)
                    observed=engine_executor.wait_for_exit(str(self.io.config),self.io.sha,self.registry,"approved",
                        self.store,self.lease,self.model.initial)
                    assert observed.exit_code==0
                    exported=evidence_export.export_existing(str(self.runtime),self.sha,self.registry,"approved",self.store,self.lease)
                    assert exported.evidence_policy_complete is True
                    result=finalization.RootFinalizer(str(self.runtime),self.sha).finalize(self.registry,"approved",self.store,self.lease)
                    assert self.store.read(self.lease)["state"]=="closed"
                    retained=evidence_export.read_existing(str(self.runtime),self.sha,self.registry,"approved",self.store,self.lease)
                    assert retained==exported and result.evidence_receipt_sha256==retained.receipt_sha256
                    assert b"".join(evidence_export.read_chunks(retained))
                    terminal=runtime_rpc._terminal("recover",self.lease,self.store.read(self.lease),retained)
                    assert terminal["cleanup"]=={"state":"verified"}
                    write(self.io.root/"full-flow-result.json",{"exit":observed.exit_code,"closed":True,
                        "evidence_sha256":retained.sha256,"native_podman_qualified":False})
                os._exit(0)
            except BaseException as error:
                import traceback
                from incus_lease_issuer.identity import Denied
                write(self.io.root/"full-flow-failure.json",{"type":type(error).__name__,
                    "reason":str(error) if isinstance(error,Denied) else None,
                    "sites":[{"file":Path(row.filename).name,"line":row.lineno,"function":row.name}
                             for row in traceback.extract_tb(error.__traceback__)[-8:]]})
                os._exit(92)
        code=os.waitstatus_to_exitcode(os.waitpid(child,0)[1])
        failure=self.io.root/"full-flow-failure.json"
        self.assertEqual(code,0,"proper-EE fixed-engine fullcore; native acquisitions modeled; "+
                         (failure.read_text() if failure.exists() else "no diagnostic"))
        result=json.loads((self.io.root/"full-flow-result.json").read_bytes())
        self.assertEqual(result["exit"],0);self.assertTrue(result["closed"]);self.assertFalse(result["native_podman_qualified"])
        self.assertEqual(self.store.read(self.lease)["state"],"closed")


if __name__=="__main__":unittest.main()
