"""Real Root-private migration reader; past provider authority is explicitly modeled.

No service, network, signing key, native grant or actual host resource is used.
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0,str(FILES))
from incus_lease_issuer import identity, ledger
from incus_lease_issuer import operating_cells as cells
from test_github_runner_incus_operating_ninth_retired_partial_continuation import native

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "roles/github_runner/templates/runtime_v2/install_probe.py.j2"
NOW = 1793772000


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,"Root Linux private-filesystem fixture")
class RetiredPreparationInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/run")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = {"__name__":"fixture_readonly_install_probe"}
        exec(compile(PROBE.read_bytes(),str(PROBE),"exec"),self.scope)
        self.path = self.root / "bank"; self.path.mkdir(mode=0o700)
        ledger.Ledger.initialize(self.path,clock=lambda:NOW)
        worker = ledger.Worker(995,78,12345,987654,"12345678-1234-4234-8234-123456789abc")
        policy = {"custodian_ref":"synthetic-custodian","storage_ref":"synthetic-store",
                  "approval_ref":"fixture-not-native-acceptance","retention_seconds":14400,"max_lease_seconds":1800}
        with ledger.Ledger(self.path,clock=lambda:NOW) as store:
            policy_sha = store.archive_policy(policy); challenge = store.challenge(worker)
            who = identity.Identity(run_id=cells.NINTH_RUN,job_id=cells.NINTH_JOB,check_run_id=cells.NINTH_JOB,
                runner_id=78,service_uid=995,caller_sha=cells.NINTH_MAIN,reusable_sha=cells.NINTH_REUSABLE,
                valid_until=NOW+300,token_id_sha256="a"*64,audience=challenge["audience"])
            self.lease = store.prepare(challenge["nonce"],worker,who,policy_sha256=policy_sha,cell_sha256="e"*64,deadline=NOW+120)
            targets = [("network-create","network:default:lit0123456789ab"),
                       ("project-create","project:lit-owned-lease"),("profile-configure","profile:lit-owned-lease:default"),
                       ("context-create","context:"+"e"*64),("certificate-create","certificate:"+"a"*64),
                       ("context-publish","context:"+"e"*64),("engine-prepare","engine:"+self.lease)]
            for operation,target in targets:
                effect = store.begin(self.lease,operation,target);store.record(self.lease,effect,"verified",evidence_sha256="f"*64)
            self.unknown = store.begin(self.lease,"fence-create","fence:"+self.lease)
            store.record(self.lease,self.unknown,"unknown",evidence_sha256="f"*64)
            # Model the prior native authority only. The production reader,
            # actual canonical bank bytes and all Root files are unmodified.
            with store._transaction() as state:
                row = state["leases"][self.lease]
                row["native_terminal"] = dict(schema=1,repository="ltn-it/ansible-collection-supplementary",repository_id=1103407173,
                    run_id=cells.NINTH_RUN,run_attempt=1,job_id=cells.NINTH_JOB,check_run_id=cells.NINTH_JOB,
                    source_sha=cells.NINTH_MAIN,controller_sha=cells.NINTH_REUSABLE,conclusion="failure",
                    completed_at=1795048271,observed_at=1795048272,native_sha256="f"*64,cell_sha256=row["cell_sha256"])
            row = store.read(self.lease);info = os.fstat(store.fd)
        self.raw = self.path.joinpath("state.json").read_bytes();self.state = json.loads(self.raw)
        self.runtime = {"schema":1,"ledger_path":str(self.path),"source_identity":{"reusable_sha":cells.NINTH_REUSABLE}}
        self.bootstrap = self.root / "original.json";self.bootstrap.write_bytes(ledger.canonical(self.runtime));self.bootstrap.chmod(0o600)
        self.fixed = deepcopy(cells.NINTH_RETIRED_PARTIAL)
        self.fixed.update(schema=1,kind="original-ninth-partial-separately-retired-unknown-preserved")
        self.fixed["original_bootstrap"] = {"path":str(self.bootstrap),"sha256":digest(self.bootstrap.read_bytes())}
        self.fixed["original_bank"] = dict(path=str(self.path),device=info.st_dev,inode=info.st_ino,state_file_sha256=digest(self.raw))
        self.fixed["original_record"] = dict(lease_id=self.lease,sha256=ledger.digest(row),state="prepared",unknown_effect_id=self.unknown,
            effects={key:dict(operation=e["operation"],state=e["state"],effect_sha256=ledger.digest(e))for key,e in row["effects"].items()})
        for label in ("native_journal","prior_journal"):
            parent = self.root / label;parent.mkdir(mode=0o700);members = {}
            for leaf in self.fixed[label]["members"]:
                body = {"fixture":"no-native-effect"}
                if leaf == "complete-receipt.json":
                    body.update(retention_deadline=self.fixed["retain_until"],at=self.fixed["retain_until"]+1,
                        original_unknown_resolved=False,prior_retirement_unknown_preserved=True,native_case_acceptance=False,
                        all_original_paths_absent=True,own_project_bridge_absent=True,owned_namespace_alias_mounts_absent=True)
                path = parent / leaf;raw = ledger.canonical(body)+b"\n";path.write_bytes(raw);path.chmod(0o600);members[leaf]=digest(raw)
            self.fixed[label] = {"path":str(parent),"members":members}
        for label in ("certificate_receipt","veth_receipt"):
            path = self.root / (label+".json");raw=ledger.canonical({"original_unknown_resolved":False,
                "metadata":{"lease_id":self.lease,"original_record_sha256":self.fixed["original_record"]["sha256"]}})+b"\n"
            path.write_bytes(raw);path.chmod(0o600);self.fixed[label]={"path":str(path),"sha256":digest(raw)}
        self.q = {"schema":9,"purpose":"g06-ninth-failed-partial-separate-retirement-complete-history",
                  "retirement":self.fixed,"native_ninth":cells.ninth_native_projection(*native())}
        self.qualification = self.root / "qualification.json";self.save_qualification()
    def save_qualification(self):
        raw = ledger.canonical(self.q);self.qualification.write_bytes(raw);self.qualification.chmod(0o600)
        self.reference = {"path":str(self.qualification),"sha256":digest(raw)}
    def invoke(self):
        return self.scope["retired_preparation"](self.runtime,digest(self.bootstrap.read_bytes()),self.state,self.raw,self.reference)
    def test_exact_retired_prepared_unknown_passes_without_changing_one_byte(self):
        before = {p:(p.read_bytes(),p.stat().st_ino)for p in self.root.rglob("*")if p.is_file()}
        self.invoke()
        self.assertEqual(before,{p:(p.read_bytes(),p.stat().st_ino)for p in self.root.rglob("*")if p.is_file()})
        self.assertEqual(self.state["leases"][self.lease]["state"],"prepared")
        self.assertEqual(self.state["leases"][self.lease]["effects"][self.unknown]["state"],"unknown")
    def test_actual_configuration_default_refuses_same_bank_and_explicit_proof_preserves_it(self):
        def file(name,raw):
            path=self.root/name;path.write_bytes(raw);path.chmod(0o600);return str(path),digest(raw)
        profile,profile_sha=file("profile.json",b"{}")
        config,config_sha=file("collector.json",b"{}")
        fragment,fragment_sha=file("unit.service",b"fixture")
        manifest,_=file("runner-manifest.json",b"{}")
        signer,_=file("metadata-only-signer",b"synthetic private sentinel not to read")
        lock,_=file("prepare.lock",b"")
        prep={"signing_public_key_hex":"a"*64,"signing_key_path":signer,"lock_path":lock}
        for key in ("network_fence_policy","host_api_fence_policy","storage_quota_policy"):
            path,sha=file(key+".json",b"{}")
            prep[key+"_path"],prep[key+"_sha256"]=path,sha
        self.runtime.update(source_workflow_sha256="b"*64,custody_policy_sha256=self.state["leases"][self.lease]["policy_sha256"],
                            controller={},runtime={},capacity={},cells={})
        self.runtime.update(preparation=prep,collector={"profile_path":profile,"profile_sha256":profile_sha,
            "config_path":config,"config_sha256":config_sha,"service":{"service_user":"fixture",
            "fragment_path":fragment,"fragment_sha256":fragment_sha,"dropins":[],"installation":{"service_uid":995,"manifest_path":manifest}}})
        self.bootstrap.write_bytes(ledger.canonical(self.runtime))
        self.fixed["original_bootstrap"]["sha256"]=digest(self.bootstrap.read_bytes());self.save_qualification()
        account=SimpleNamespace(pw_name="fixture",pw_uid=995,pw_gid=996)
        def group(name):
            if name=="fixture":return SimpleNamespace(gr_gid=996,gr_mem=[])
            raise KeyError(name)
        with mock.patch("pwd.getpwnam",return_value=account),mock.patch("pwd.getpwall",return_value=[account]), \
             mock.patch("grp.getgrnam",side_effect=group),mock.patch("os.getgrouplist",return_value=[996]):
            for reference in (None,{},False):
                with self.subTest(reference=reference),self.assertRaises(ValueError):
                    self.scope["configurations"](str(self.bootstrap),digest(self.bootstrap.read_bytes()),"fixture","a"*64,reference)
            result=self.scope["configurations"](str(self.bootstrap),digest(self.bootstrap.read_bytes()),"fixture","a"*64,self.reference)
            self.assertEqual(result,self.runtime)
            self.assertEqual(self.path.joinpath("state.json").read_bytes(),self.raw)

    def test_reference_hash_permissions_or_foreign_bank_identity_fail(self):
        mutations = (
            lambda:self.reference.update(sha256="0"*64),
            lambda:self.qualification.chmod(0o644),
            lambda:self.q["retirement"]["original_bank"].update(inode=True),
            lambda:self.q["retirement"]["original_record"].update(state="closed"),
            lambda:self.q["retirement"]["original_bootstrap"].update(sha256="0"*64),
        )
        for mutate in mutations:
            oldq,oldref=deepcopy(self.q),deepcopy(self.reference)
            try:
                mutate()
                if self.q != oldq:self.save_qualification()
                with self.subTest(mutate=mutate),self.assertRaises((ValueError,KeyError)):self.invoke()
            finally:
                self.q,self.reference=oldq,oldref;self.qualification.chmod(0o600);self.save_qualification()
    def test_incomplete_journal_or_unknown_reclassification_does_not_admit(self):
        for mutate in (
            lambda:self.q["retirement"]["native_journal"]["members"].pop("complete-receipt.json"),
            lambda:self.q["retirement"]["prior_journal"]["members"].pop("namespace-mount88-unknown.json"),
            lambda:self.q["retirement"]["original_record"]["effects"][self.unknown].update(state="verified"),
            lambda:self.q["native_ninth"]["run"].update(run_attempt=2),
        ):
            prior=deepcopy(self.q)
            try:
                mutate();self.save_qualification()
                with self.subTest(mutate=mutate),self.assertRaises((ValueError,KeyError)):self.invoke()
            finally:self.q=prior;self.save_qualification()
    def test_full_four_hour_deadline_must_have_elapsed(self):
        with mock.patch("time.time",return_value=self.fixed["retain_until"]-1),self.assertRaises(ValueError):self.invoke()
    def test_live_bank_change_during_proof_read_fails_final_double_read(self):
        real=self.scope["sealed"]
        def read(path,*args,**kwargs):
            raw=real(path,*args,**kwargs)
            if path==self.fixed["veth_receipt"]["path"]:
                self.path.joinpath("state.json").write_bytes(self.raw+b"\n")
            return raw
        self.scope["sealed"]=read
        with self.assertRaises(ValueError):self.invoke()
    def test_identical_byte_bank_replacement_cannot_detach_pinned_directory(self):
        import shutil
        real=self.scope["sealed"]
        def read(path,*args,**kwargs):
            raw=real(path,*args,**kwargs)
            if path==self.fixed["veth_receipt"]["path"]:
                saved=self.path.with_name("original-preserved")
                self.path.rename(saved)
                shutil.copytree(saved,self.path)
                self.assertEqual(self.path.joinpath("state.json").read_bytes(),self.raw)
            return raw
        self.scope["sealed"]=read
        with self.assertRaises(ValueError):self.invoke()

    def test_extra_lease_or_started_instance_is_never_a_retired_partial(self):
        for mutate in (
            lambda:self.state["leases"].update({"f"*32:self.state["leases"][self.lease]}),
            lambda:self.state["leases"][self.lease].update(owned_instance={"name":"foreign"}),
        ):
            prior=deepcopy(self.state)
            try:
                mutate()
                with self.subTest(mutate=mutate),self.assertRaises(ValueError):self.invoke()
            finally:self.state=prior

if __name__=="__main__":unittest.main()
