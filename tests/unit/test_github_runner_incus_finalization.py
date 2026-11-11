"""Actual owned semantic/Unix cleanup boundary; native engine/kernel modeled.

Root creator state comes from real preparation, crypto, Ledger and fixed ELF
supervision fixtures. This is not an Incus7.6 binary, namespace or custody PASS.
"""
import hashlib
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

import test_github_runner_incus_cell_contract as cell_fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import (cell_contract, engine_policy, finalization, identity, incus_admin,
                                incus_mutation, ledger, root_session)
from incus_lease_issuer.identity import Denied


class GuardTests(unittest.TestCase):
    def test_no_job_targets_policies_or_acceptance_flag(self):
        with mock.patch.object(os, "geteuid", return_value=2101):
            with self.assertRaisesRegex(Denied, "finalization-root-required"):
                finalization.RootFinalizer(None, None)
        with self.assertRaises(TypeError):
            finalization.RootFinalizer(None, None, approved=True)
        instance = object.__new__(finalization.RootFinalizer)
        with self.assertRaises(TypeError):
            instance.finalize(None, None, None, None, project="foreign")


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootFinalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cell_fixtures.RootCleanupSemanticTests.setUpClass()

    def setUp(self):
        self.fixture = cell_fixtures.RootCleanupSemanticTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.owner = self.fixture.owner()
        self.store, self.lease, self.registry = self.fixture.store, self.fixture.lease, self.fixture.registry
        self.engine = self.fixture.engine_fixture
        self.io = self.engine.fixture
        self.server = self.io.server
        # Complete native inventory routes, not filtered status shortcuts.
        project = self.owner.incus["project"]
        self.server.resources["/1.0/instances?project="+project] = []
        self.server.resources["/1.0/operations?project="+project+"&recursion=1"] = {}
        self.runtime = self.io.root / "finalizer-runtime.json"
        capture = identity.decode_json(self.owner.engine_descriptor_bytes)["capture"]
        value = {"schema": 2, "registry_path": self.registry.path, "registry_sha256": self.registry.sha256,
            "preparation_config_path": str(self.io.config), "preparation_config_sha256": self.io.sha,
            "authentication_timeout_seconds": 5, "initial_transition_timeout_seconds": 60,
            "heartbeat_lead_seconds": 30, "cleanup_timeout_seconds": 60,
            "capture": {**capture, "max_total_evidence_bytes": 1048576, "max_members": 100, "max_member_bytes": 1048576}}
        self.runtime.write_bytes(ledger.canonical(value))
        self.runtime.chmod(0o600)
        self.sha = hashlib.sha256(self.runtime.read_bytes()).hexdigest()
        self.finalizer = finalization.RootFinalizer(str(self.runtime), self.sha)
        # Explicit kernel-stop observations only: the fixed ELF really exited;
        # this private EE has no native Podman/cgroup/namespace delegation.
        for operation, target in (("engine-stop", "engine:lit-lease-"+self.lease),
                                  ("fence-disable", "fence:"+self.lease)):
            effect = self.store.begin(self.lease, operation, target)
            self.store.record(self.lease, effect, "verified", evidence_sha256="d"*64)

    def cleanup(self, config):
        target = self.owner.incus
        fingerprint = self.owner.creator_targets["certificate-create"].removeprefix("certificate:")
        client = incus_admin.RootIncusAdmin(incus_admin.AdminTarget(config.incus_socket_path,
            target["project"], target["network"], "default", target["pool"], (fingerprint,)))
        return incus_mutation.RootIncusCleanup(client, self.owner, self.store)

    def deletes(self):
        return [request for request in self.server.requests if request[0] == "DELETE"]

    def revoke(self, cleanup, session):
        return self.finalizer._remote_delete(session, self.registry, "approved", self.store, self.owner,
            cleanup, "certificate-revoke", self.owner.creator_targets["certificate-create"],
            "certificate", cleanup.certificate_delete)

    def test_cancelled_real_entry_revokes_access_but_does_not_release_retained_storage(self):
        """Real finalizer/Ledger/Unix Incus boundary; kernel/export are models.

        Cancellation is recorded by the existing Root Ledger API. This is an
        offline failure-policy regression, never native job/VM acceptance.
        """
        from incus_lease_issuer import cleanup_storage, engine_executor, evidence_export, network_fence
        self.store.cancel(self.lease, "cancelled")
        descriptor = identity.decode_json(self.owner.engine_descriptor_bytes)
        exported = evidence_export.ExportReceipt(
            descriptor["engine"]["runroot"] + ".public-evidence/evidence.zip",
            "a" * 64, 100, 1, "b" * 64, True)
        start = self.store.read(self.lease)["effects"][self.owner.creators["engine-start"]["id"]]
        with mock.patch.object(engine_policy, "ENGINE", self.engine.original), \
             mock.patch.object(evidence_export, "export_existing", return_value=exported), \
             mock.patch.object(network_fence, "verify_disabled"), \
             mock.patch.object(engine_executor, "_retained", return_value=(object(), None, start)), \
             mock.patch.object(engine_executor, "_drained"), \
             mock.patch.object(cleanup_storage, "release_engine", side_effect=RuntimeError("destructive-release-observed")) as release:
            with self.assertRaises(Denied):
                self.finalizer.finalize(self.registry, "approved", self.store, self.lease)
        self.assertEqual(release.call_count, 0, "cancelled cell storage released before custody elapsed")
        self.assertNotEqual(self.store.read(self.lease)["state"], "closed")
        # Certificate withdrawal is allowed immediately; retained storage is not.
        self.assertTrue(any(row["operation"] == "certificate-revoke" and row["state"] == "verified"
                            for row in self.store.read(self.lease)["effects"].values()))

    def test_actual_vm_stops_and_is_privately_bound_before_pending_terminal_hold(self):
        """Real Unix VM inventory and durable ledger, not native acceptance."""
        from incus_lease_issuer import cleanup_storage, engine_executor, evidence_export, network_fence
        value = self.owner.incus
        url = "/1.0/instances/" + value["instance"] + "?project=" + value["project"]
        state_url = "/1.0/instances/" + value["instance"] + "/state?project=" + value["project"]
        own = value["ownership"]
        uuid = "12345678-1234-1234-1234-123456789abc"
        self.server.resources["/1.0/instances?project=" + value["project"]] = [url]
        self.server.resources[url] = {"name": value["instance"], "type": "virtual-machine", "config": {
            "volatile.uuid": uuid, "user.lit-molecule-owner": own["owner"],
            "user.lit-molecule-repository": own["repository"], "user.lit-molecule-run-id": str(own["run_id"]),
            "user.lit-molecule-attempt": str(own["run_attempt"]), "user.lit-molecule-scenario": own["scenario"],
            "user.lit-molecule-target": own["target"]}}
        self.server.resources[state_url] = {"status": "Stopped", "status_code": 102, "pid": 0}
        descriptor = identity.decode_json(self.owner.engine_descriptor_bytes)
        exported = evidence_export.ExportReceipt(descriptor["engine"]["runroot"] + ".public-evidence/evidence.zip",
            "a" * 64, 100, 1, "b" * 64, True)
        start = self.store.read(self.lease)["effects"][self.owner.creators["engine-start"]["id"]]
        with mock.patch.object(engine_policy, "ENGINE", self.engine.original), \
             mock.patch.object(evidence_export, "export_existing", return_value=exported), \
             mock.patch.object(network_fence, "verify_disabled"), \
             mock.patch.object(engine_executor, "_retained", return_value=(object(), None, start)), \
             mock.patch.object(engine_executor, "_drained"), \
             mock.patch.object(cleanup_storage, "release_engine") as release:
            with self.assertRaises(Denied):
                self.finalizer.finalize(self.registry, "approved", self.store, self.lease)
        record = self.store.read(self.lease)
        self.assertEqual(record["owned_instance"]["uuid"], uuid)
        self.assertFalse(any(row["operation"] == "instance-create" for row in record["effects"].values()))
        self.assertFalse(any(row[0] == "DELETE" and row[1] == url for row in self.server.requests))
        self.assertFalse(release.called)
        self.assertTrue(any(row["operation"] == "certificate-revoke" and row["state"] == "verified"
                            for row in record["effects"].values()))
        # A fabricated request-shaped ownership record is never accepted.
        with self.assertRaises(Denied):
            self.store.bind_observed_instance(self.lease, record["owned_instance"])

    def test_real_original_certificate_scope_revoke_and_read_only_verified_reentry(self):
        with mock.patch.object(engine_policy, "ENGINE", self.engine.original), \
             root_session._session(str(self.io.config), self.io.sha) as session:
            cleanup = self.cleanup(root_session._require_session(session))
            self.assertEqual(cleanup.quiet_project()["state"], "quiet_observed")
            self.revoke(cleanup, session)
            self.assertTrue(cleanup.certificates_absent())
            self.assertEqual(len(self.deletes()), 1)
            self.revoke(cleanup, session)  # Readback only, not a second DELETE.
            self.assertEqual(len(self.deletes()), 1)
        matches = [effect for effect in self.store.read(self.lease)["effects"].values()
                   if effect["operation"] == "certificate-revoke"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["state"], "verified")
        self.assertIn("certificate_revocation", matches[0])

    def test_completed_own_native_task_must_actually_disappear_before_quiet_project(self):
        import test_github_runner_incus_mutation as transport
        self.server.async_mode, self.server.operation_code = True, 200
        with mock.patch.object(engine_policy, "ENGINE", self.engine.original), \
             root_session._session(str(self.io.config), self.io.sha) as session:
            cleanup = self.cleanup(root_session._require_session(session))
            self.revoke(cleanup, session)
            writes = len(self.deletes())
            path = "/1.0/operations?project=" + self.owner.incus["project"] + "&recursion=1"
            own = {"success": [{"id": transport.OPERATION, "class": "task", "status_code": 200, "status": "Success", "err": ""}]}
            self.server.resources[path] = own
            original = self.server.handle
            polls = []
            def observe(method, url, body):
                if method == "GET" and url == path:
                    polls.append(1)
                    if len(polls) >= 3:
                        self.server.resources[path] = {}
                return original(method, url, body)
            self.server.handle = observe
            self.assertEqual(cleanup.wait_quiet(1)["state"], "quiet_observed")
            self.assertGreaterEqual(len(polls), 3)
            self.assertEqual(len(self.deletes()), writes)
            self.server.resources[path] = {"success": [{**own["success"][0], "id": "99999999-9999-9999-9999-999999999999"}]}
            self.server.handle = original
            with self.assertRaisesRegex(Denied, "mutation-project-operation-held"):
                cleanup.wait_quiet(1)
            self.assertEqual(len(self.deletes()), writes)

    def test_actual_applied_delete_with_lost_response_remains_unknown_no_retry(self):
        self.server.mutation_reply = b"HTTP/1.1 200 Fixture\r\nContent-Length: 3\r\n\r\nbad"
        with mock.patch.object(engine_policy, "ENGINE", self.engine.original), \
             root_session._session(str(self.io.config), self.io.sha) as session:
            cleanup = self.cleanup(root_session._require_session(session))
            with self.assertRaises(finalization.FinalizationUnknown):
                self.revoke(cleanup, session)
            first = len(self.deletes())
            self.assertEqual(first, 1)
            with self.assertRaises(Denied):
                self.revoke(cleanup, session)
            self.assertEqual(len(self.deletes()), first)
        self.assertNotEqual(self.store.read(self.lease)["state"], "closed")

    def test_foreign_project_scope_cannot_be_deleted_or_closed(self):
        fingerprint = self.owner.creator_targets["certificate-create"].removeprefix("certificate:")
        self.server.resources["/1.0/certificates/"+fingerprint]["projects"] = ["foreign-protected"]
        with mock.patch.object(engine_policy, "ENGINE", self.engine.original), \
             root_session._session(str(self.io.config), self.io.sha) as session:
            cleanup = self.cleanup(root_session._require_session(session))
            with self.assertRaises(Denied):
                self.revoke(cleanup, session)
        self.assertEqual(self.deletes(), [])
        self.assertNotEqual(self.store.read(self.lease)["state"], "closed")

    def test_forged_session_denies_before_any_native_delete(self):
        with self.assertRaises(Denied):
            self.finalizer._remote_delete(object(), self.registry, "approved", self.store, self.owner,
                None, "project-delete", "project:"+self.owner.incus["project"], "project", None)
        self.assertEqual(self.deletes(), [])


# This fixed, inert ELF is compiled only by the central proper-EE test runner.
# It does not implement Podman, start a container or claim image qualification.
# Unlike changing argv after compilation, it accepts the EXACT compiled argv so
# Root descriptor -> manifest -> JWS -> kernel process -> exit remain aligned.
FIXED_ENGINE_C = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
static const char *cid="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static void path(char *out, const char *root, const char *leaf) {
  if (snprintf(out,4096,"%s/%s",root,leaf)>=4096) exit(80);
}
static void put(const char *p,const char *v) {
  int fd=open(p,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
  if(fd<0 || write(fd,v,strlen(v))!=(ssize_t)strlen(v) || fsync(fd)) exit(81);
  close(fd);
}
int main(int argc,char **argv) {
  const char *root=0,*name=0,*cidfile=0,*lease=0,*descriptor=0;
  int run=0;
  for(int i=1;i<argc;i++) {
    if(!strcmp(argv[i],"--runroot") && i+1<argc) root=argv[++i];
    else if(!strcmp(argv[i],"run")) run=1;
    else if(!strncmp(argv[i],"--name=",7)) name=argv[i]+7;
    else if(!strncmp(argv[i],"--cidfile=",10)) cidfile=argv[i]+10;
    else if(!strncmp(argv[i],"--label=io.lightning-it.lease=",30)) lease=argv[i]+30;
    else if(!strncmp(argv[i],"--label=io.lightning-it.descriptor=",35)) descriptor=argv[i]+35;
  }
  if(!root) return 82;
  char state[4096],stopped[4096]; path(state,root,"fixture-container.json");path(stopped,root,"fixture-stopped");
  if(run) {
    if(!name||!cidfile||!lease||!descriptor) return 83;
    char data[2048];
    snprintf(data,sizeof(data),"[{\"Id\":\"%s\",\"Name\":\"%s\",\"ImageDigest\":\"sha256:58955457d3410706520f34fa7ea9823d5650aa4844c562cd5c0107024d825711\",\"Image\":\"sha256:5b4ca16538abccb297f565dda30c511203fade0e30ff14adb439c6d2b06550fd\",\"Config\":{\"Labels\":{\"io.lightning-it.lease\":\"%s\",\"io.lightning-it.descriptor\":\"%s\"}},\"State\":{\"Running\":true}}]",cid,name,lease,descriptor);
    put(state,data); put(cidfile,cid);
    write(1,"fixed-root-fixture-output\n",26);
    usleep(1000000);
    return 0;
  }
  for(int i=1;i<argc;i++) {
    if(!strcmp(argv[i],"exists")) return access(state,F_OK)==0?0:1;
    if(!strcmp(argv[i],"stop")) { if(access(stopped,F_OK)) put(stopped,"stopped");return 0; }
    if(!strcmp(argv[i],"inspect")) {
      FILE *f=fopen(state,"r"); if(!f)return 84;
      char data[2048];size_t n=fread(data,1,sizeof(data)-1,f);data[n]=0;fclose(f);
      if(!access(stopped,F_OK)) {char *p=strstr(data,"\"Running\":true");if(p && n+1<sizeof(data)){memmove(p+15,p+14,strlen(p+14)+1);memcpy(p+10,"false",5);}}
      fputs(data,stdout);return 0;
    }
  }
  return 85;
}
'''


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootCompiledFixedEngineTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        import subprocess
        import test_github_runner_incus_engine_policy as compiler_fixtures
        base = Path("/run/executable-proof")
        if not base.is_dir() or base.stat().st_uid != 0:
            self.skipTest("requires private Root exec tmpfs /run/executable-proof")
        self.temp = tempfile.TemporaryDirectory(prefix="compiled-fixed-engine-", dir=base)
        self.addCleanup(self.temp.cleanup)
        self.binary = Path(self.temp.name) / "fixed-engine"
        source = Path(self.temp.name) / "fixture.c"
        source.write_text(FIXED_ENGINE_C)
        source.chmod(0o600)
        compiled = subprocess.run(["/usr/bin/cc", "-std=c11", "-D_DEFAULT_SOURCE", "-O2", str(source), "-o", str(self.binary)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "TMPDIR": self.temp.name}, timeout=15, check=False)
        self.assertEqual(compiled.returncode, 0, compiled.stderr[:4096].decode("utf-8", "replace"))
        self.binary.chmod(0o700)
        self.assertEqual(self.binary.read_bytes()[:4], b"\x7fELF")
        self.fixture = compiler_fixtures.RootEngineCompilerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        # This is an actual fixture binary, so remove the absent-Podman package
        # read model. All compiler file/owner/hash reads now execute unchanged.
        self.fixture.mock_file.stop()
        self.fixture.data["engine"]["executable"] = str(self.binary)
        self.fixture.data["engine"]["executable_sha256"] = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        patch = mock.patch.object(engine_policy, "ENGINE", str(self.binary))
        patch.start()
        self.addCleanup(patch.stop)

    def test_exact_compiled_argv_real_elf_pid_cid_exit_and_metadata_without_argv_rewrite(self):
        import json
        import subprocess
        import time
        from incus_lease_issuer import engine_executor
        manifest = self.fixture.compile()
        actual = identity.decode_json(manifest.canonical_bytes)
        self.assertEqual(tuple(actual["argv"]), manifest.argv)
        proc = subprocess.Popen(manifest.argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=engine_executor._environment(manifest), close_fds=True, umask=0o077)
        pidfd = os.pidfd_open(proc.pid)
        try:
            observed = engine_executor._stable_process(proc.pid, manifest, pidfd)
            self.assertEqual(observed["exe_sha256"], actual["engine_executable_sha256"])
            self.assertGreater(len(manifest.argv), 32)
            deadline = time.monotonic()+0.5
            while not Path(actual["runtime"]["cidfile"]).exists() and time.monotonic()<deadline:
                time.sleep(0.005)
            self.assertEqual(engine_executor._cid(actual["runtime"]["cidfile"]), "c"*64)
            row = engine_executor._inspect(manifest, "c"*64)
            self.assertTrue(row["State"]["Running"])
            code, _ = engine_executor._command(manifest, ["container", "stop", "--time=10", "c"*64])
            self.assertEqual(code, 0)
            self.assertFalse(engine_executor._inspect(manifest, "c"*64)["State"]["Running"])
            stdout, stderr = proc.communicate(timeout=3)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(stdout, b"fixed-root-fixture-output\n")
            self.assertEqual(stderr, b"")
        finally:
            os.close(pidfd)
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)
            proc.stdout.close()
            proc.stderr.close()


if __name__ == "__main__":
    unittest.main()
