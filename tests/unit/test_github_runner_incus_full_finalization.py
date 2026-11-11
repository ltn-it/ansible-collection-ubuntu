"""Staged full Root CORE fixture, NOT native Podman/VM/custody qualification.

Compile/execute only centrally in proper3174 EE. All actual Root FS, signatures,
Unix Incus transport, journal, fixed compiled argv and process exit are retained.
Only unavailable host/private kernel, runtime/image and idmap acquisition is
modeled. Fresh native socket admission is separately exercised by entry tests.
"""
from contextlib import contextmanager, nullcontext
import hashlib
import datetime as dt
import io
import tarfile
import zipfile
import time
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
    admission, generation_acquisition as acquisition, operating_custody, operating_upload,
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
        "test_exit_code": 0, "capture_exit_code": 0, "destroy_exit_code": None,
        "root_finalization": "pending",
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
            "vulnerability_blocking_findings":0,"semantic_valid":False},"prerequisites":{},"blockers":[],"release_eligible":False,
        "root_finalization":"pending","execution_success":True,"candidate_execution_passed":False}
    write(base/"environment.json", {"generated_at":"2026-11-11T00:00:00Z", "repository":env["GITHUB_REPOSITORY"],
        "commit_sha":env["QUALITY_INPUT_SOURCE_SHA"], "workflow_run_id":env["GITHUB_RUN_ID"], "workflow_attempt":"1",
        "roles":sorted(roles.split(",")), "profiles":[profile.replace("_","-")], "scenarios":[scenario],
        "targets":[target], "tool_versions":{}, "application_versions":{}})
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

    def bind_original_terminal_and_upload(self, exported):
        """Actual opaque factories/content verification; only native HTTPS/auth acquisition modeled."""
        selected = self.registry.select("approved")
        record = self.store.read(self.lease)
        who, worker = identity.Identity(**record["identity"]), ledger.Worker(**record["worker"])
        raw = io.BytesIO()
        with tarfile.open(exported.path, "r:gz") as source, zipfile.ZipFile(raw, "w") as target:
            for member in source:
                if member.name.startswith("evidence/"):
                    target.writestr(member.name.removeprefix("evidence/"), source.extractfile(member).read())
        payload = raw.getvalue()
        env=identity.decode_json(self.io.prepared.engine_descriptor_bytes)["environment"]
        prefix="candidate-quality-result" if env["QUALITY_INPUT_TARGET_DISPOSITION"]=="candidate" else "quality-result"
        artifact = {"id":81, "name":prefix+"-"+env["QUALITY_INPUT_SCENARIO"]+"-"+env["QUALITY_INPUT_TARGET"]+
            "-"+who.caller_sha+"-attempt-1",
            "digest":"sha256:"+hashlib.sha256(payload).hexdigest(),"size_in_bytes":len(payload),"expired":False,
            "workflow_run":{"id":who.run_id,"repository_id":selected.identity.repository_id,
                "head_repository_id":selected.identity.repository_id,"head_sha":who.caller_sha,"head_branch":"main"}}
        supplied={"id":81,"digest_sha256":hashlib.sha256(payload).hexdigest(),"size_in_bytes":len(payload)}
        def provider(path,*_args):
            return {"total_count":1,"artifacts":[artifact]} if "/artifacts?" in path else artifact
        def download(_url,fd,_unused,_deadline,_maximum,*,digest,size):
            assert digest==hashlib.sha256(payload).hexdigest() and size==len(payload)
            os.write(fd,payload);os.fsync(fd)
        with mock.patch.object(admission,"require_intake_native",return_value=(worker,who,120)), \
             mock.patch.object(acquisition,"_json",side_effect=provider), \
             mock.patch.object(acquisition,"_redirect",return_value="https://offline-provider.invalid/fixture"), \
             mock.patch.object(acquisition,"_download",side_effect=download):
            proof=operating_upload.verify_uploaded_artifact(str(self.runtime),self.sha,self.registry,"approved",
                self.store,self.lease,object(),object(),"offline-oidc","offline-api",supplied)
            self.store.bind_uploaded_evidence(self.lease,proof)
            operating_upload.finish_transport(self.store,self.lease,proof)
        prefix=identity.API+"/repos/"+selected.identity.repository
        actor={"id":next(iter(selected.identity.actor_ids)),"type":"User","login":"offline-fixture"}
        job={"id":who.job_id,"run_id":who.run_id,"run_attempt":1,"head_sha":who.caller_sha,
            "runner_id":who.runner_id,"name":selected.identity.required_native_job_name,"status":"completed",
            "conclusion":"success","check_run_url":prefix+"/check-runs/"+str(who.check_run_id),
            "completed_at":dt.datetime.fromtimestamp(int(time.time())-1,dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        run={"id":who.run_id,"run_attempt":1,"event":"push","head_branch":"main","head_sha":who.caller_sha,
            "workflow_id":selected.identity.workflow_id,"path":selected.identity.workflow_path,
            "repository":{"id":selected.identity.repository_id,"full_name":selected.identity.repository,
                "private":False,"owner":{"id":selected.identity.owner_id}},"actor":actor,"triggering_actor":actor,
            "referenced_workflows":[{"path":selected.identity.reusable_repository+"/"+selected.identity.reusable_path+
                "@"+selected.identity.reusable_sha,"sha":selected.identity.reusable_sha}]}
        check={"id":who.check_run_id,"head_sha":who.caller_sha,"status":"completed","conclusion":"success"}
        routes={prefix+"/actions/runs/"+str(who.run_id):run,prefix+"/actions/jobs/"+str(who.job_id):job,
            prefix+"/check-runs/"+str(who.check_run_id):check}
        with mock.patch.object(identity,"HTTPSReader",return_value=mock.Mock(read=lambda url:ledger.canonical(routes[url]))):
            terminal=operating_custody.observe_native_terminal(self.registry,"approved",self.store,self.lease)
        self.store.bind_native_terminal(self.lease,terminal)

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
                    self.bind_original_terminal_and_upload(exported)
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


from contextlib import ExitStack
from copy import deepcopy
from dataclasses import replace
import subprocess
import tempfile
import test_github_runner_incus_capacity as cap_fixtures
import test_github_runner_incus_run_factory as factories
import test_github_runner_incus_generation_publisher as archives
import test_github_runner_incus_finalization as engines
import test_github_runner_incus_mutation as mutations
from incus_lease_issuer import (capacity, engine_graph_prune, operating_cells, operating_watchdog,
    policy_registry, run_factory)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def _operating_native_terminal(registry, selector, store, lease):
    record = store.read(lease); who, p = record["identity"], registry.select(selector).identity
    prefix = identity.API + "/repos/" + p.repository
    actor = {"id": next(iter(p.actor_ids)), "type": "User", "login": "offline-fixture"}
    job = {"id": who["job_id"], "run_id": who["run_id"], "run_attempt": 1, "head_sha": who["caller_sha"],
        "runner_id": who["runner_id"], "name": p.required_native_job_name, "status": "completed", "conclusion": "failure",
        "check_run_url": prefix + "/check-runs/" + str(who["check_run_id"]),
        "completed_at": dt.datetime.fromtimestamp(store._now() - 1, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    run = {"id": who["run_id"], "run_attempt": 1, "event": "push", "head_branch": "main", "head_sha": p.caller_sha,
        "workflow_id": p.workflow_id, "path": p.workflow_path,
        "repository": {"id": p.repository_id, "full_name": p.repository, "private": False, "owner": {"id": p.owner_id}},
        "actor": actor, "triggering_actor": actor,
        "referenced_workflows": [{"path": p.reusable_repository + "/" + p.reusable_path + "@" + p.reusable_sha, "sha": p.reusable_sha}]}
    check = {"id": who["check_run_id"], "head_sha": who["caller_sha"], "status": "completed", "conclusion": "failure"}
    routes = {prefix + "/actions/runs/" + str(who["run_id"]): run,
              prefix + "/actions/jobs/" + str(who["job_id"]): job,
              prefix + "/check-runs/" + str(who["check_run_id"]): check}
    with mock.patch.object(identity, "HTTPSReader", return_value=mock.Mock(read=lambda u: ledger.canonical(routes[u]))):
        proof = operating_custody.observe_native_terminal(registry, selector, store, lease)
    store.bind_native_terminal(lease, proof)


def _operating_snapshot(io):
    directory = io.root / "operating-archive-stage"
    directory.mkdir(mode=0o700)
    fds = []
    try:
        for name, raw in zip(run_factory.run_intake.ARCHIVES,
                             (io.pub.artifact_raw, io.pub.source_raw, io.pub.controller_raw)):
            fd = os.open(directory / name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            fds.append(fd); os.write(fd, raw); os.fsync(fd)
        acquired = replace(io.pub.acquired, artifact=replace(io.pub.artifact, workflow_id=214182490))
        snapshot = run_factory.run_intake._validate_archives(acquired,
            **dict(zip(("artifact_fd", "source_fd", "controller_fd"), fds)))
    finally:
        for fd in fds: os.close(fd)
    return run_factory.run_intake.SealedRunSnapshot(str(directory), directory.stat().st_dev,
                                                   directory.stat().st_ino, "7" * 64, snapshot)


def operating_cleanup_fixture(mode):
    """Actual factory/ELF/READY/opaque proof/retention/finalizer; native HTTP/kernel modeled."""
    real_time=time.time
    termination=mode.startswith("termination:")
    phase=mode.removeprefix("termination:")
    CASE=("expiry-controller-loss" if phase.startswith("expiry") else
          "broker-cancel" if any(part in phase for part in ("cancel","previous","ready-then")) else "failure") if termination else "failure"
    CASE2="failure" if CASE!="failure" else "broker-cancel"
    UUID = "12345678-1234-4234-8234-123456789abc"
    with ExitStack() as stack:
        if termination:
            stack.enter_context(mock.patch.object(factories.crypto,"NOW",int(real_time())))
        cap_fixtures.RootCapacityTests.setUpClass()
        quota = cap_fixtures.RootCapacityTests(); stack.callback(quota.doCleanups); quota.setUp()
        factories.RootConfigurationTests.setUpClass()
        io = factories.RootConfigurationTests(); stack.callback(io.doCleanups); io.setUp()
        # Every engine/Incus input is set BEFORE the actual per-job factory seals its first config.
        tmp = stack.enter_context(tempfile.TemporaryDirectory(dir="/run/executable-proof"))
        source, binary = Path(tmp) / "engine.c", Path(tmp) / "fixed-operating-engine"
        code = engines.FIXED_ENGINE_C.replace('usleep(1000000);\n    return 0;', '''
        const char *out=0;
        for(int i=1;i<argc;i++) if(!strncmp(argv[i],"type=bind,source=",17) && strstr(argv[i],",destination=/quality")) out=argv[i]+17;
        if(!out) return 90;
        char ack[4096]; size_t size=strcspn(out,",");
        if(size+40>=sizeof(ack)) return 91;
        memcpy(ack,out,size);ack[size]=0;strcat(ack,"/control/root-operating-ready.json");
        for(int n=0;n<1000 && access(ack,F_OK);n++) usleep(10000);
        return access(ack,F_OK)==0?23:92;''')
        if termination:
            code=code.replace('for(int n=0;n<1000 && access(ack,F_OK);n++) usleep(10000);',
                'for(int n=0;n<10000;n++) {if(!access(ack,F_OK) || !access(stopped,F_OK)) {usleep(500000);return 23;}usleep(10000);}')
            code=code.replace('return access(ack,F_OK)==0?23:92;','return 92;')
            if phase!="normal-ready":
                code=code.replace('if(!strcmp(argv[i],"stop")) { if(access(stopped,F_OK)) put(stopped,"stopped");return 0; }',
                    'if(!strcmp(argv[i],"stop")) { if(access(stopped,F_OK)) put(stopped,"stopped");return 1; }')
        if termination and phase=="capture-failure-normal":
            code=code.replace('write(1,"fixed-root-fixture-output\\n",26);','write(1,"fixed-root-fixture-output\\n",26);write(1,"fixed-root-fixture-output\\n",26);')
        source.write_text(code)
        subprocess.run(["/usr/bin/cc", "-std=c11", "-D_DEFAULT_SOURCE", "-O2", str(source), "-o", str(binary)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        binary.chmod(0o700)
        # Unwind the nested unavailable-Podman file mocks in reverse setup order.
        for q in (quota.pool_quota, quota.quota): q.io.mock_file.stop()
        quota.io.fixture.fs.mock_file.stop()
        stack.enter_context(mock.patch.object(engine_policy, "ENGINE", str(binary)))
        stack.enter_context(mock.patch.object(ledger, "ENGINE_EXECUTABLE", str(binary)))
        controller_files = archives.publisher._git_archive(io.pub.controller_raw, io.pub.controller)
        controller_files[".github/actions/run-operating-drill/controller.py"] = b'"""Offline immutable controller archive; execution is the fixed ELF fixture."""\n'
        io.pub.controller_raw, io.pub.controller = archives.git_input(archives.acquisition.VALIDATION,
            1269461997, io.pub.controller.commit_sha, controller_files)
        io.pub.acquired = replace(io.pub.acquired, controller=io.pub.controller)
        snapshot = _operating_snapshot(io)
        io.stage.stop()
        stack.enter_context(mock.patch.object(run_factory.run_intake, "stage_run_snapshot", return_value=snapshot))
        template = deepcopy(next(iter(io.helper.value["cells"].values())))
        template.pop("matrix")
        template.update(kind="operating", lease_seconds=900, job_timeout_seconds=5400)
        template["engine"]["engine"] = {"executable": str(binary), "executable_sha256": digest(binary.read_bytes())}
        template["engine"]["limits"]["timeout_seconds"] = 600
        if termination and phase=="capture-failure-normal":
            template["engine"]["capture"]={"stdout_limit":32,"stderr_limit":32,"total_limit":64}
            io.helper.value["runtime"]["capture"]={**io.helper.value["runtime"]["capture"],
                "stdout_limit":32,"stderr_limit":32,"total_limit":64}
        template["engine"]["paths"].update(storage=str(quota.quota.mount / "graph"),
            runroot=str(quota.quota.mount / "run"), output=str(quota.quota.mount / "output"))
        template["incus"]["project_limits"] = {"cpu": 1, "memory_bytes": operating_cells.MEMORY,
            "disk_bytes": operating_cells.PROJECT_RESERVATION, "instances": 1, "virtual_machines": 1, "containers": 0}
        io.helper.value["preparation"]["operation_wait_seconds"] = 1
        io.helper.value["preparation"]["storage_quota_policy_path"] = str(quota.quota.path)
        io.helper.value["preparation"]["storage_quota_policy_sha256"] = quota.quota.sha
        io.helper.value["capacity"] = {**capacity.PROFILE, "pool_quota_policy_path": str(quota.pool_quota.path),
                                      "pool_quota_policy_sha256": quota.pool_quota.sha}
        rows = {}
        for case in (CASE, CASE2):
            row = deepcopy(template)
            row.update(native_job_name="Operating custody / " + case, native_observer_job_name="Operating result / " + case,
                       operating={"case": case, "target": operating_cells.TARGET, "image": operating_cells.IMAGE})
            rows[operating_cells.selector(case)] = row
        io.helper.value["cells"] = rows
        io.helper.selector = operating_cells.selector(CASE)
        io.helper.native.job["name"] = "Operating custody / " + CASE
        io.helper.seal(); io.bootstrap = io.helper.bootstrap; io.selector = io.helper.selector
        io.proof, io.token = io.helper.mint()
        if termination:
            time.time=real_time
            if phase.startswith("expiry"):
                io.helper.native.claims["exp"]=int(real_time())+40
        configuration = io.create(snapshot)
        registry = policy_registry.load_registry(configuration.registry_path, configuration.registry_sha256)
        store = ledger.Ledger(io.helper.store_path, clock=run_factory.time.time); stack.callback(store.shutdown)
        proof, _token = io.helper.mint()
        selected = registry.select(io.selector)
        lease = store.prepare(proof.nonce, proof.worker, proof.identity, policy_sha256=selected.custody_policy_sha256,
                              cell_sha256=selected.cell_sha256, deadline=selected.deadline)
        original_handle = mutations.MutationFixture.handle
        def image_routes(server, method, path, body):
            if path.startswith("/1.0/images"):
                if method == "GET" and path == "/1.0/images/" + operating_cells.IMAGE + "?project=default":
                    return mutations.reply(mutations.envelope({"fingerprint": operating_cells.IMAGE, "type": "virtual-machine"}))
                if path.startswith("/1.0/images?project="):
                    if method == "POST":
                        assert body["source"]["protocol"] == "incus"
                        key = "/1.0/images/" + operating_cells.IMAGE + "?project=" + path.split("=", 1)[1]
                        server.resources[key] = {"fingerprint": operating_cells.IMAGE, "type": "virtual-machine",
                            "public": False, "auto_update": False, "aliases": []}
                        server.resources[path] = ["/1.0/images/" + operating_cells.IMAGE]
                        return mutations.reply(mutations.envelope({}))
                    if path not in server.resources:
                        return mutations.reply(mutations.envelope([]))
            result=original_handle(server, method, path, body)
            if method=="DELETE" and path.startswith("/1.0/instances/"):
                project=path.split("?project=",1)[1]
                server.resources["/1.0/instances?project="+project]=[]
                server.resources.pop(path.replace("?project=","/state?project="),None)
            if method=="DELETE" and path.startswith("/1.0/images/"):
                server.resources["/1.0/images?project="+path.split("?project=",1)[1]]=[]
            return result
        stack.enter_context(mock.patch.object(mutations.MutationFixture, "handle", image_routes))
        receipt = preparation.prepare(configuration.preparation_config_path, configuration.preparation_config_sha256,
                                      registry, io.selector, store, lease)
        prepared = cell_contract.prepare_cell(registry, io.selector, store, lease)
        descriptor = identity.decode_json(prepared.engine_descriptor_bytes)
        manifest = engine_policy.compile_engine_policy(prepared.engine_descriptor_path, prepared.engine_descriptor_sha256)
        server = io.pub.base.server
        target = prepared.incus
        vm_url = "/1.0/instances/" + target["instance"] + "?project=" + target["project"]
        labels = target["ownership"]
        vm = {"name": target["instance"], "type": "virtual-machine", "config": {
            "volatile.uuid": UUID, "volatile.base_image": operating_cells.IMAGE,
            **{"user.lit-molecule-" + key: str(labels[value]) for key, value in
               (("owner", "owner"), ("repository", "repository"), ("run-id", "run_id"),
                ("attempt", "run_attempt"), ("scenario", "scenario"), ("target", "target"))}},
            "expanded_config": {"limits.cpu": "1", "limits.memory": "2GiB"},
            "expanded_devices": {"root": {"type": "disk", "path": "/", "pool": target["pool"], "size": "5GiB", "size.state": "500MiB"},
                                 "eth0": {"type": "nic", "network": target["network"]}}}
        server.resources[vm_url] = vm
        server.resources["/1.0/instances?project=" + target["project"]] = [vm_url]
        server.resources["/1.0/operations?project=" + target["project"] + "&recursion=1"] = {}
        state_url = "/1.0/instances/" + target["instance"] + "/state?project=" + target["project"]
        server.resources[state_url] = {"status": "Running", "status_code": 103, "pid": 4321}
        control = Path(descriptor["output_path"]) / "control"; control.mkdir(mode=0o700)
        (control / "operating-created.json").write_bytes(ledger.canonical({"schema": 1, "case": CASE,
            "instance_name": target["instance"], "instance_uuid": UUID}))
        (control / "operating-created.json").chmod(0o600)
        for operation in ("fence-create",):
            e = store.begin(lease, operation, "fence:" + lease)
            store.bind_fence(lease, e, policy_sha256="d" * 64, boot_id=engine_executor.kernel.read_boot_id(),
                            netns_device=4, netns_inode=4026533001, host_ifindex=301, peer_ifindex=2, nft_table_handle=1)
            store.record(lease, e, "verified", evidence_sha256="d" * 64)
        auth = store.read(lease)["authorizations"][-1]
        e = store.begin(lease, "fence-renew", "fence:" + lease + ":" + auth["token_id_sha256"])
        expiry = min(auth["valid_until"], prepared.expires_at)
        store.bind_fence_authorization(lease, e, authorization_sha256=ledger.digest(auth), allow_expires_at=expiry,
            issued_boot_ns=1000000000, expires_boot_ns=1000000000 + (expiry - int(time.time())) * 1000000000)
        store.record(lease, e, "verified", evidence_sha256="d" * 64)
        st = io.root.stat()
        stack.enter_context(mock.patch.object(engine_executor, "_cgroup", return_value=(st.st_dev, st.st_ino)))
        engine_executor._spawn(prepared, manifest, store)
        if termination:
            return observe_original_termination(phase,stack,configuration,registry,store,lease,io,receipt,quota,vm,real_time)
        ready = operating_custody.operating_ready_tick(configuration.preparation_config_path,
            configuration.preparation_config_sha256, registry, io.selector, store, lease, receipt)
        assert ready["instance_uuid"] == UUID
        start = next(r for r in store.read(lease)["effects"].values() if r["operation"] == "engine-start")
        owned = engine_executor._PROCESSES[start["engine_process"]["pid"]]
        end = time.monotonic() + 5
        while (owned.returncode is None or not owned.eof) and time.monotonic() < end: owned.pump(.01)
        assert owned.returncode == 23 and owned.eof
        owned.record_exit()
        for operation, name in (("engine-stop", "engine:lit-lease-" + lease), ("fence-disable", "fence:" + lease)):
            e = store.begin(lease, operation, name); store.record(lease, e, "verified", evidence_sha256="d" * 64)
        server.resources[state_url] = {"status": "Stopped", "status_code": 102, "pid": 0}
        _operating_native_terminal(registry, io.selector, store, lease)
        def fence_remove(_path, _sha, owner, journal, _worker, _config):
            if any(r["operation"]=="fence-remove" and r["state"]=="verified" for r in journal.read(lease)["effects"].values()): return
            e = journal.begin(lease, "fence-remove", "fence:" + lease)
            journal.record(lease, e, "verified", evidence_sha256="e" * 64)
        stack.enter_context(mock.patch.object(engine_executor, "_drained"))
        stack.enter_context(mock.patch.object(network_fence, "verify_disabled"))
        stack.enter_context(mock.patch.object(network_fence, "remove", side_effect=fence_remove))
        stack.enter_context(mock.patch.object(cleanup_storage, "_cleanup_limits", return_value=(4096, 20)))
        operating_custody.retain_stopped(configuration.runtime_config_path, configuration.runtime_config_sha256,
                                          registry, io.selector, store, lease)
        graph = Path(descriptor["engine"]["storage_root"])
        (graph / "modeled-layer").write_bytes(b"immutable public image fixture content")
        with root_session._session(configuration.preparation_config_path, configuration.preparation_config_sha256) as session:
            config = root_session._require_session(session)
            owner = cell_contract.owned_cell_for_cleanup(registry, io.selector, store, lease)
            engine_graph_prune.prune_graph(owner, store, config, session=session)
        assert store.read(lease)["state"] == "retained" and not list(graph.iterdir())
        # A distinct genuine native job proof produces the next config, sharing the same Root platform refs.
        io.helper.selector = operating_cells.selector(CASE2)
        io.helper.native.job.update(id=904, name="Operating custody / " + CASE2,
            check_run_url=identity.API + "/repos/" + io.helper.native.policy.repository + "/check-runs/733")
        io.helper.native.claims["check_run_id"] = "733"
        io.selector = io.helper.selector
        io.proof, io.token = io.helper.mint()
        next_config = io.create(snapshot)
        next_registry = policy_registry.load_registry(next_config.registry_path, next_config.registry_sha256)
        server.extensions += ["resources", "storage"]
        server.resources["/1.0/storage-pools/" + target["pool"]] = {"name": target["pool"], "driver": "dir", "status": "Created",
            "config": {"source": str(quota.pool_quota.mount)}}
        server.resources["/1.0/storage-pools/" + target["pool"] + "/resources"] = quota.resource
        server.resources["/1.0/storage-pools/" + target["pool"] + "/volumes?recursion=1&all-projects=true"] = [
            {"type": "virtual-machine", "content_type": "block", "project": target["project"], "name": target["instance"]}]
        before = store.read(lease)
        with quota.modeled_kernel(), root_session._session(next_config.preparation_config_path,
                                                         next_config.preparation_config_sha256) as session:
            observed = capacity.require_capacity(next_config.runtime_config_path, next_config.runtime_config_sha256,
                                                 next_registry, io.selector, store, session=session)
        assert observed.retained_reservation_bytes == 10 * capacity.GIB and observed.requested_pool_bytes == 10 * capacity.GIB
        assert store.read(lease) == before
        negatives = {}
        try:
            vm["config"]["volatile.uuid"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
            with quota.modeled_kernel(), root_session._session(next_config.preparation_config_path,
                                                             next_config.preparation_config_sha256) as session:
                try:
                    capacity.require_capacity(next_config.runtime_config_path, next_config.runtime_config_sha256,
                                              next_registry, io.selector, store, session=session)
                except identity.Denied as error:
                    negatives["original_owned_uuid_drift"] = str(error)
                else:
                    raise AssertionError("borrowed retained VM UUID accepted")
        finally:
            vm["config"]["volatile.uuid"] = UUID
        assert store.read(lease)==before
        assert negatives=={"original_owned_uuid_drift":"capacity-retained-native-unsafe"}
        # Actual 4h Root custody policy, no synthetic business exporter/receipt.
        binding={"schema":1,"runtime_config_path":configuration.runtime_config_path,"runtime_config_sha256":configuration.runtime_config_sha256,"snapshot_manifest_sha256":configuration.manifest_sha256}
        assert operating_watchdog._closed_binding(binding) is False
        retained=store.read(lease); assert retained["custody"]["retain_until"]>=retained["native_terminal"]["completed_at"]+14400
        original_clock=store.clock
        store.clock=lambda:retained["custody"]["retain_until"]-1
        deletes_before=[r for r in server.requests if r[0]=="DELETE"]
        with mock.patch.object(evidence_export,"export_existing",side_effect=AssertionError("operating is not business evidence")):
            try: finalization.RootFinalizer(configuration.runtime_config_path,configuration.runtime_config_sha256).finalize(registry,operating_cells.selector(CASE),store,lease)
            except identity.Denied: pass
            else: raise AssertionError("early retention cleanup permitted")
        assert [r for r in server.requests if r[0]=="DELETE"]==deletes_before
        store.clock=lambda:retained["custody"]["retain_until"]
        # A same-case controller diagnostic with a foreign Source commit cannot
        # authorize raw deletion, even though the original Root custody elapsed.
        wrong_report=Path(descriptor["output_path"])/"operating-result.json"
        wrong_report.write_bytes(ledger.canonical({"schema":1,"kind":"operating","case":CASE,
            "run_id":retained["identity"]["run_id"],"run_attempt":1,"source_sha":"f"*40,
            "controller_sha":retained["identity"]["reusable_sha"],"execution":{"raw_exit_code":23,"signal":None},
            "instance":{"name":target["instance"],"uuid":UUID,"state":"Stopped"},
            "observations":{"workload_failed":True,"broker_cancel_sent":False,"controller_heartbeat_ceased":False},
            "root_finalization":"pending"}));wrong_report.chmod(0o600)
        with quota.modeled_kernel():
            try:finalization.RootFinalizer(configuration.runtime_config_path,configuration.runtime_config_sha256).finalize(registry,operating_cells.selector(CASE),store,lease)
            except identity.Denied:pass
            else:raise AssertionError("foreign operating diagnostic accepted")
        assert store.read(lease)["state"]=="retained" and [r for r in server.requests if r[0]=="DELETE"]==deletes_before
        assert not Path(descriptor["engine"]["runroot"]+".public-evidence").exists()
        wrong_report.unlink() # Only this test's rejected untrusted fixture data; no unknown effect or spool existed.
        from incus_lease_issuer import incus_admin, incus_mutation
        op="22222222-3333-4444-8555-666666666666"
        ops_url="/1.0/operations?project="+target["project"]+"&recursion=1"
        old_handler=server.handle
        leaf={"image_deleted":False,"operations_reads":0,"native_operation_reads":0}
        def async_leaf(method,path,body):
            if method=="DELETE" and path.startswith("/1.0/images/"):
                reply=old_handler(method,path,body)
                leaf["image_deleted"]=True
                if mode=="unknown-delete":
                    return b"HTTP/1.1 200 Fixture\r\nContent-Length: 3\r\n\r\nbad"
                return mutations.reply(mutations.envelope({"id":op,"class":"task","status_code":103},
                    type="async",status="Operation created",status_code=100,operation="/1.0/operations/"+op),202)
            if method=="GET" and path=="/1.0/operations/"+op:
                leaf["native_operation_reads"]+=1
                return mutations.reply(mutations.envelope({"id":op,"class":"task","status_code":200,"err":""}))
            if method=="GET" and path==ops_url and leaf["image_deleted"]:
                leaf["operations_reads"]+=1
                if (mode=="late-first-empty" and leaf["operations_reads"]==1 or
                    mode=="late-final-empty" and leaf["operations_reads"]==3):
                    time.sleep(1.1)
                visible=mode in {"linger","persistent","foreign-active","pending-own"}
                if mode=="linger" and leaf["operations_reads"]>=3:visible=False
                row={"id":op if mode!="foreign-active" else "99999999-9999-4999-8999-999999999999",
                    "class":"task","status_code":103 if mode in {"foreign-active","pending-own"} else 200,
                    "status":"Running" if mode in {"foreign-active","pending-own"} else "Success","err":""}
                return mutations.reply(mutations.envelope({row["status"].lower():[row]} if visible else {}))
            return old_handler(method,path,body)
        server.handle=async_leaf
        error=None
        try:
            with quota.modeled_kernel(), mock.patch.object(evidence_export,"export_existing",side_effect=AssertionError("operating not business evidence")):
                finalization.RootFinalizer(configuration.runtime_config_path,configuration.runtime_config_sha256).finalize(registry,operating_cells.selector(CASE),store,lease)
        except identity.Denied as e:error=type(e).__name__+":"+str(e)
        record=store.read(lease)
        effects=[{"operation":e["operation"],"state":e["state"],"target":e["target"],"incus_operation_id":e.get("incus_operation_id")} for e in record["effects"].values()]
        writes=[(m,p) for m,p,_ in server.requests if m!="GET"]
        project_deletes=[p for m,p in writes if m=="DELETE" and p=="/1.0/projects/"+target["project"]]
        reentry_error=None
        if error and any(row["state"]=="unknown" for row in record["effects"].values()):
            before_retry=list(writes)
            with quota.modeled_kernel():
                try:finalization.RootFinalizer(configuration.runtime_config_path,configuration.runtime_config_sha256).finalize(registry,operating_cells.selector(CASE),store,lease)
                except identity.Denied as e:reentry_error=type(e).__name__+":"+str(e)
                else:raise AssertionError("unknown effect reentry accepted")
            assert before_retry==[(m,p) for m,p,_ in server.requests if m!="GET"]
        wait_result=None
        capacity_result=None
        if error is None:
            # Closed reentry is read-only even though its image/project/raw data
            # are gone; capacity releases the FULL old reservation only now.
            before_closed_reentry=list(server.requests)
            with quota.modeled_kernel():
                finalization.RootFinalizer(configuration.runtime_config_path,configuration.runtime_config_sha256).finalize(
                    registry,operating_cells.selector(CASE),store,lease)
            assert not any(m!="GET" for m,_p,_b in server.requests[len(before_closed_reentry):])
            server.resources["/1.0/storage-pools/"+target["pool"]+"/volumes?recursion=1&all-projects=true"]=[]
            with quota.modeled_kernel(),root_session._session(next_config.preparation_config_path,next_config.preparation_config_sha256) as session:
                observed_after=capacity.require_capacity(next_config.runtime_config_path,next_config.runtime_config_sha256,
                    next_registry,io.selector,store,session=session)
            assert observed_after.retained_reservation_bytes==0
            capacity_result={"retained_reservation_bytes":0}
        if error:
            with quota.modeled_kernel(),root_session._session(next_config.preparation_config_path,next_config.preparation_config_sha256) as session:
                try:capacity.require_capacity(next_config.runtime_config_path,next_config.runtime_config_sha256,next_registry,io.selector,store,session=session)
                except identity.Denied as e:capacity_result={"denied":str(e)}
                else:raise AssertionError("held cleanup released capacity")
        if mode=="immediate":assert record["state"]=="closed" and error is None
        elif mode == "linger":
            assert record["state"] == "closed" and error is None
        elif mode in {"persistent","foreign-active","pending-own","late-first-empty","late-final-empty"}:
            assert error and not any(e["operation"]=="project-delete" for e in effects)
            assert any(e["operation"]=="image-delete" and e["state"]=="verified" for e in effects)
        else:
            assert any(e["operation"]=="image-delete" and e["state"]=="unknown" for e in effects)
            assert not any(e["operation"]=="project-delete" for e in effects)
        result={"mode":mode,"actual_finalizer_error":error,"ledger_state":record["state"],"effects":effects,
            "leaf_observations":leaf,"project_DELETE_requests":project_deletes,"supported_wait_quiet":wait_result,
            "supported_wait_seconds":locals().get("wait_elapsed"),"capacity":capacity_result,"reentry_error":reentry_error,
            "no_retry_writes":True,"native_acceptance":False,"source_model":"actual factory/RootREADY/ELF23/opaque terminal/4h policy/retention/prune/next capacity; only HTTP operation lifecycle modeled"}
        stack.close()
        return result

def observe_original_termination(mode,stack,configuration,registry,store,lease,io,receipt,quota,vm,real_time):
    """Real original owner/live-policy/Unix frame; only host/provider/kernel leaves modeled."""
    from incus_lease_issuer import runtime_rpc
    import socket,struct
    MODE=mode
    _REAL_TIME=real_time
    UUID="12345678-1234-4234-8234-123456789abc"
    notify,receiver=socket.socketpair()
    stack.callback(notify.close);stack.callback(receiver.close)
    selector=io.selector
    start_id,start=next((k,v) for k,v in store.read(lease)["effects"].items() if v["operation"]=="engine-start")
    owned=engine_executor._PROCESSES[start["engine_process"]["pid"]]
    initial=store.read(lease); pid=owned.process["pid"]
    commands=[]
    real_command=engine_executor._command
    def command(*args,**kwargs):
        result=real_command(*args,**kwargs)
        commands.append({"arguments":args[1],"rc":result[0]})
        return result
    stack.enter_context(mock.patch.object(engine_executor,"_command",side_effect=command))
    def kernel_withdraw(_path,_sha,owner,journal,_worker,_config):
        # Only unavailable kernel nft/fence I/O is modeled; actual Ledger effect remains once-only.
        effect=journal.begin(lease,"fence-disable","fence:"+lease)
        journal.record(lease,effect,"verified",evidence_sha256="d"*64)
    stack.enter_context(mock.patch.object(network_fence,"disable",side_effect=kernel_withdraw))
    stack.enter_context(mock.patch.object(network_fence,"verify_disabled"))
    stack.enter_context(mock.patch.object(engine_executor,"_drained"))
    ready_calls=[]; original_ready=operating_custody.operating_ready_tick
    def readiness(*args,**kwargs):
        if MODE=="ready-race-cancel" and not ready_calls:
            store.cancel(lease,"cancelled")
        if MODE=="wrong-ready-owner":
            vm["config"]["user.lit-molecule-owner"]="foreign-owner"
        try:
            value=original_ready(*args,**kwargs)
            ready_calls.append({"state":"returned","ready":value is not None,"lease_state":store.read(lease)["state"]})
            return value
        except identity.Denied as e:
            ready_calls.append({"state":"denied","category":str(e),"lease_state":store.read(lease)["state"]})
            raise
    stack.enter_context(mock.patch.object(operating_custody,"operating_ready_tick",side_effect=readiness))
    if MODE=="ready-then-abort":
        assert original_ready(configuration.preparation_config_path,configuration.preparation_config_sha256,
            registry,io.selector,store,lease,receipt)["instance_uuid"]==UUID
    if MODE in {"cancel-before-ready","previous-stop-before-ready","ready-then-abort","normal-cancel-before-ready","previous-stop-child-exited"}:
        store.cancel(lease,"cancelled")
    previous_stop_error=None
    if MODE in {"previous-stop-before-ready","previous-stop-child-exited"}:
        try:engine_executor.cancel(configuration.preparation_config_path,configuration.preparation_config_sha256,registry,io.selector,store,lease,receipt)
        except identity.Denied as e:previous_stop_error=type(e).__name__+":"+str(e)
    if MODE=="previous-stop-child-exited":
        end=time.monotonic()+2
        while (owned.returncode is None or not owned.eof) and time.monotonic()<end:owned.pump(.01)
        assert owned.returncode==23 and owned.eof
    if MODE.startswith("expiry"):
        cutoff=min(initial["expires_at"],initial["authorizations"][-1]["valid_until"])
        while _REAL_TIME()<cutoff+.01:time.sleep(min(.05,cutoff+.01-_REAL_TIME()))
        assert time.time is _REAL_TIME
    error=None; observed=None
    try:
        if MODE in {"normal-ready","expiry-before-ready","normal-cancel-before-ready","previous-stop-child-exited","ready-race-cancel","wrong-ready-owner","capture-failure-normal"}:
            observed=engine_executor.wait_for_exit(configuration.preparation_config_path,configuration.preparation_config_sha256,
                registry,io.selector,store,lease,receipt,notification_socket=notify)
        else:
            observed=engine_executor._abort_after_failure(configuration.preparation_config_path,configuration.preparation_config_sha256,
                registry,io.selector,store,lease,receipt)
    except identity.Denied as e:error=type(e).__name__+":"+str(e)
    notify.shutdown(socket.SHUT_WR)
    frames=[]
    receiver.settimeout(1)
    raw=b""
    while True:
        part=receiver.recv(65536)
        if not part:break
        raw+=part
    while raw:
        size=struct.unpack("!I",raw[:4])[0];frames.append(identity.decode_json(raw[4:4+size]));raw=raw[4+size:]
    after=store.read(lease); child_live=owned.returncode is None
    receipt_before_teardown="engine_exit" in after["effects"][start_id]
    before_commands=list(commands)
    stop_at_return=owned.stop_attempted
    wall_at_return=_REAL_TIME()
    downstream={}
    if error:
        rpc=runtime_rpc.RuntimeRPC(configuration.runtime_config_path,configuration.runtime_config_sha256)
        try:rpc._retain_after_failure(store,lease,io.selector,receipt)
        except identity.Denied as e:downstream["original_owner_retention_error"]=type(e).__name__+":"+str(e)
        try:operating_custody.retain_stopped(configuration.runtime_config_path,configuration.runtime_config_sha256,registry,io.selector,store,lease)
        except identity.Denied as e:downstream["custody_error"]=type(e).__name__+":"+str(e)
        try:finalization.RootFinalizer(configuration.runtime_config_path,configuration.runtime_config_sha256).finalize(registry,io.selector,store,lease)
        except identity.Denied as e:downstream["finalization_error"]=type(e).__name__+":"+str(e)
    final=store.read(lease)
    result={"mode":MODE,"production_error":error,"observed_exit":None if observed is None else observed.exit_code,
        "original_pid":pid,"actual_owner_pid_unchanged":owned.process["pid"]==pid,
        "child_still_live_at_return":child_live,"original_exit_proof_at_return":receipt_before_teardown,
        "initial_state":initial["state"],"state_at_return":after["state"],"stop_attempted":owned.stop_attempted,"stop_attempted_at_return":stop_at_return,"commands_at_return":before_commands,
        "authorization_deadline":min(initial["expires_at"],initial["authorizations"][-1]["valid_until"]),"real_wall_at_return":wall_at_return,
        "readiness_calls":ready_calls,"actual_Unix_notifications":frames,"previous_stop_error":previous_stop_error,"commands":commands,
        "engine_stop_effects":[{"state":e["state"],"id":k} for k,e in final["effects"].items() if e["operation"]=="engine-stop"],
        "downstream":downstream,"exit_proof_after_retention":"engine_exit" in final["effects"][start_id],
        "recorded_exit_states":{key:final["effects"][start_id].get("engine_exit",{}).get(key) for key in ("stdout_state","stderr_state")},"authorization_unchanged":initial["authorizations"]==final["authorizations"],
        "deadline_unchanged":initial["expires_at"]==final["expires_at"],
        "no_new_process":[e["engine_process"]["pid"] for e in final["effects"].values() if e["operation"]=="engine-start"]==[pid],
        "real_wall_clock_during_wait":time.time is _REAL_TIME,"native_acceptance":False}
    # TEST-ONLY teardown AFTER recording the product result; never claimed as automatic recovery.
    if not owned.closed:
        if owned.returncode is None:owned.proc.terminate()
        end=time.monotonic()+3
        while (owned.returncode is None or not owned.eof) and time.monotonic()<end:owned.pump(.01)
        if owned.returncode is not None and owned.eof:
            owned.record_exit();owned.release()
    return result


@unittest.skipUnless(sys.platform=="linux" and os.geteuid()==0,"private proper-EE Root only")
class RootAsyncImageFinalizationTests(unittest.TestCase):
    def test_immediate_async_image_success_closes(self):
        self.assertEqual(operating_cleanup_fixture("immediate")["ledger_state"], "closed")

    def test_lingering_owned_success_disappears_before_project_intent_and_closes(self):
        self.assertEqual(operating_cleanup_fixture("linger")["ledger_state"], "closed")

    def test_foreign_active_operation_holds_before_project_intent_or_delete(self):
        result=operating_cleanup_fixture("foreign-active")
        self.assertEqual(result["project_DELETE_requests"], [])

    def test_own_completed_operation_timeout_holds_before_project_intent_or_delete(self):
        result=operating_cleanup_fixture("persistent")
        self.assertEqual(result["project_DELETE_requests"], [])

    def test_late_first_empty_response_never_authorizes_project_intent(self):
        result=operating_cleanup_fixture("late-first-empty")
        self.assertEqual(result["project_DELETE_requests"], [])

    def test_late_final_empty_snapshot_never_authorizes_project_intent(self):
        result=operating_cleanup_fixture("late-final-empty")
        self.assertEqual(result["project_DELETE_requests"], [])

    def test_pending_owned_operation_is_not_adopted_as_quiet(self):
        result=operating_cleanup_fixture("pending-own")
        self.assertEqual(result["project_DELETE_requests"], [])

    def test_unknown_applied_image_delete_is_never_retried(self):
        result=operating_cleanup_fixture("unknown-delete")
        self.assertTrue(result["no_retry_writes"])


if __name__=="__main__":unittest.main()
