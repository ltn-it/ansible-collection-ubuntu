"""Offline Root publisher FS/archives/closed readers; no runtime authority.

Only authenticated acquisition and systemctl transport are modeled. The fixed
engine path is a Root-owned inert fixture file (never executed / never Podman).
Git blob contents, Galaxy checksums, Root filesystem, Ledger, readers and CAS
are real. Existing policy archives are fixtures, not operating acceptance.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace, MappingProxyType
import unittest
from unittest import mock
import zipfile

import test_github_runner_incus_preparation as fixtures

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import (generation_publisher as publisher, generation_acquisition as acquisition,
                               engine_policy as engine, identity, ledger, policy_registry, preparation, runtime_entry, runtime_rpc)
from incus_lease_issuer.identity import Denied


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def tar_bytes(files, *, prefix=None, extra=None, executable=()):
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode="w:gz") as archive:
        directories = set()
        for name in files:
            directories.update(str(parent) for parent in Path(name).parents if str(parent) != ".")
        if prefix:
            directories.add("")
        for name in sorted(directories, key=lambda item: (item.count("/"), item)):
            entry = tarfile.TarInfo((prefix+"/" if prefix else "")+name)
            entry.type, entry.mode = tarfile.DIRTYPE, 0o755
            archive.addfile(entry)
        for name, raw in sorted(files.items()):
            entry = tarfile.TarInfo((prefix+"/" if prefix else "")+name)
            entry.size, entry.mode = len(raw), 0o755 if name in executable else 0o644
            archive.addfile(entry, io.BytesIO(raw))
        if extra is not None:
            archive.addfile(extra)
    return target.getvalue()


def git_input(repository, repository_id, sha, files, *, executable=()):
    raw = tar_bytes(files, prefix="fixture-"+sha, executable=executable)
    entries = tuple(acquisition.TreeEntry(name, "100755" if name in executable else "100644",
        hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest(), len(body))
        for name, body in sorted(files.items()))
    dirs = sorted({str(parent) for name in files for parent in Path(name).parents if str(parent) != "."})
    proven = acquisition.CommitAcquisition(repository, repository_id, sha, "9"*40,
                                           entries, tuple(dirs), digest(raw), len(raw))
    return raw, proven


def candidate_zip(payload, version="1.2.3"):
    index = {"files": [{"name":name,"ftype":"file","chksum_type":"sha256","chksum_sha256":digest(raw)}
                       for name, raw in sorted(payload.items())]}
    index_raw = ledger.canonical(index)
    manifest = {"collection_info":{"namespace":"lit","name":"supplementary","version":version},
                "file_manifest_file":{"name":"FILES.json","chksum_type":"sha256","chksum_sha256":digest(index_raw)}}
    collection = tar_bytes({**payload,"MANIFEST.json":ledger.canonical(manifest),"FILES.json":index_raw})
    dependencies = tar_bytes({"ansible_collections/example/dependency/README.md":b"inert dependency fixture"})
    candidate_name="lit-supplementary-"+version+".tar.gz"
    checks = (digest(collection)+"  "+candidate_name+"\n"+
              digest(dependencies)+"  runtime-collections.tar.gz\n").encode()
    raw = io.BytesIO()
    with zipfile.ZipFile(raw,"w",zipfile.ZIP_DEFLATED) as archive:
        for name, body in {candidate_name:collection,
                           "runtime-collections.tar.gz":dependencies,"candidate-SHA256SUMS":checks}.items():
            archive.writestr(name,body)
    return raw.getvalue(), collection


class ArchiveGuards(unittest.TestCase):
    def test_source_archive_provenance_records_real_blob_inventory_without_git_checkout(self):
        files={"README.md":b"original", "run.sh":b"#!/bin/sh\nexit 0\n"}
        raw,proven=git_input(acquisition.SUPPLEMENTARY,1103407173,"a"*40,files,executable={"run.sh"})
        publisher._git_archive(raw,proven)
        value=publisher._source_provenance(proven)
        self.assertEqual(value["commit_sha"],proven.commit_sha)
        self.assertEqual(value["tree_sha"],proven.tree_sha)
        self.assertEqual([row["path"] for row in value["files"]],sorted(files))
        self.assertEqual(value["files"][1]["mode"],"100755")
        self.assertFalse(any(row["path"].startswith(".git/") for row in value["files"]))
        with self.assertRaisesRegex(Denied,"generation-source-provenance"):
            publisher._source_provenance(replace(proven,repository=acquisition.VALIDATION))

    def test_git_blob_content_and_executable_mode_are_authenticated(self):
        raw, proven = git_input(acquisition.SUPPLEMENTARY,1103407173,"a"*40,{"README.md":b"original"})
        self.assertEqual(publisher._git_archive(raw,proven),{"README.md":b"original"})
        for altered in (tar_bytes({"README.md":b"different"},prefix="fixture-"+"a"*40),
                        tar_bytes({"README.md":b"original","extra":b"unlisted"},prefix="fixture-"+"a"*40)):
            with self.assertRaises(Denied):publisher._git_archive(altered,proven)

    def test_tar_links_traversal_duplicate_and_zip_extra_member_deny(self):
        for name, kind, link in (("link",tarfile.SYMTYPE,"README.md"),("../outside",tarfile.REGTYPE,""),
                                 ("README.md",tarfile.REGTYPE,"")):
            extra=tarfile.TarInfo(name);extra.type=kind;extra.linkname=link
            with self.assertRaises((Denied,ValueError)):
                publisher._tar(tar_bytes({"README.md":b"public"},extra=extra))
        raw,_=candidate_zip({"README.md":b"public"})
        target=io.BytesIO(raw)
        with zipfile.ZipFile(target,"a") as archive:archive.writestr("extra",b"unlisted")
        with self.assertRaises(Denied):publisher._candidate(target.getvalue())

    def test_candidate_self_checksums_cannot_replace_authenticated_source_content(self):
        raw,_=candidate_zip({"README.md":b"internally consistent but wrong source"})
        with self.assertRaisesRegex(Denied,"generation-candidate-source"):
            publisher._candidate(raw,{"galaxy.yml":b"version: 1.2.3\n","README.md":b"authenticated Git blob"})
        with self.assertRaisesRegex(Denied,"generation-candidate-source"):
            publisher._candidate(raw,{"galaxy.yml":b"version: 1.2.3\n","other-file":b"internally consistent but wrong source"})
        publisher._candidate(raw,{"galaxy.yml":b"version: 1.2.3\n","README.md":b"internally consistent but wrong source"})

    def test_inert_runtime_links_are_confined_and_never_become_member_ancestors(self):
        root="ansible_collections/example/dependency/"
        good=tarfile.TarInfo(root+"readme-link");good.type=tarfile.SYMTYPE;good.linkname="README.md"
        publisher._runtime_bundle(tar_bytes({root+"README.md":b"inert"},extra=good))
        for target in ("../../../../outside","../../lit/supplementary/README.md","/etc/shadow"):
            with self.subTest(target=target):
                bad=tarfile.TarInfo(root+"readme-link");bad.type=tarfile.SYMTYPE;bad.linkname=target
                with self.assertRaises(Denied):
                    publisher._runtime_bundle(tar_bytes({root+"README.md":b"inert"},extra=bad))
        ancestor=tarfile.TarInfo(root+"alias");ancestor.type=tarfile.SYMTYPE;ancestor.linkname="README.md"
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode="w:gz") as archive:
            archive.addfile(ancestor)
            child=tarfile.TarInfo(root+"alias/child");child.size=9;child.mode=0o644
            archive.addfile(child,io.BytesIO(b"no follow"))
        with self.assertRaisesRegex(Denied,"generation-runtime-ancestor"):
            publisher._runtime_bundle(raw.getvalue())

    def test_source_version_closed_scalar_quotes_and_comment_boundary(self):
        for scalar in ("1.2.3", "'1.2.3'", '\"1.2.3\"', "1.2.3 # producer comment", "'1.2.3' # comment"):
            with self.subTest(scalar=scalar):
                self.assertEqual(publisher._source_version({"galaxy.yml":("version: "+scalar+"\n").encode()}),"1.2.3")
        for raw in (b"version: 1.2.3#different\n",b"version: 1.2.3\nversion: 1.2.4\n",b"version: [1,2,3]\n"):
            with self.subTest(raw=raw), self.assertRaises(Denied):
                publisher._source_version({"galaxy.yml":raw})

    def test_selfconsistent_candidate_version_must_match_authenticated_galaxy(self):
        raw,_=candidate_zip({"README.md":b"same source payload"},version="1.2.4")
        with self.assertRaisesRegex(Denied,"generation-candidate-version"):
            publisher._candidate(raw,{"galaxy.yml":b"version: 1.2.3\n","README.md":b"same source payload"})

    def test_authenticated_git_executable_bit_cannot_be_downgraded(self):
        files={"run.sh":b"#!/bin/sh\nexit 0\n"}
        raw,proof=git_input(acquisition.SUPPLEMENTARY,1103407173,"a"*40,files,executable={"run.sh"})
        self.assertEqual(publisher._git_archive(raw,proof),files)
        with self.assertRaisesRegex(Denied,"generation-git-blob"):
            publisher._git_archive(tar_bytes(files,prefix="fixture-"+"a"*40),proof)

    def test_main_bad_arguments_and_nonroot_emit_only_constant_denial(self):
        for args in ([],["secret-input"],"secret-input"):
            with self.subTest(args=args), mock.patch("sys.stdout",new_callable=io.StringIO) as out, \
                 mock.patch("sys.stderr",new_callable=io.StringIO) as err:
                self.assertEqual(publisher.main(args),1)
                self.assertEqual(out.getvalue(),"")
                self.assertEqual(err.getvalue(),"generation-publish-held\n")
        with mock.patch.object(os,"geteuid",return_value=2101), \
             mock.patch("sys.stdout",new_callable=io.StringIO) as out, \
             mock.patch("sys.stderr",new_callable=io.StringIO) as err:
            self.assertEqual(publisher.main(["secret-path","secret-hash"]),1)
            self.assertEqual(out.getvalue(),"")
            self.assertEqual(err.getvalue(),"generation-publish-held\n")

    def test_root_guard_before_any_request_or_filesystem(self):
        with mock.patch.object(os,"geteuid",return_value=2101):
            with self.assertRaisesRegex(Denied,"generation-root-required"):
                publisher.RootGenerationPublisher(None,None)


@unittest.skipUnless(sys.platform=="linux" and os.geteuid()==0,"private proper-EE Root only")
class RootPublisherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixtures.RootPreparationTests.setUpClass()

    def setUp(self):
        self.base=fixtures.RootPreparationTests();self.base.setUp();self.addCleanup(self.base.doCleanups)
        # Empty-effect synthetic admission fixture is genuinely closed, not
        # deleted/rewritten. Publisher itself must never create any admission.
        if self._testMethodName != "test_open_lease_blocks_anchor_and_retains_partial_generation_without_reuse":
            self.base.store.close(self.base.lease)
        self.base.fixture.fs.mock_file.stop()
        self.root=self.base.root/"publisher";self.root.mkdir(mode=0o700)
        (self.root/"publisher.lock").write_bytes(b"");(self.root/"publisher.lock").chmod(0o600)
        self.anchor=self.base.root/"fixed-anchor.json"
        for owner, name, value in ((publisher,"ROOT",str(self.root)),(publisher,"ANCHOR",str(self.anchor)),
                                   (runtime_entry,"ANCHOR",str(self.anchor))):
            patch=mock.patch.object(owner,name,value);patch.start();self.addCleanup(patch.stop)
        binary=self.base.root/"inert-fixed-engine";binary.write_bytes(b"not executed; static file proof only");binary.chmod(0o700)
        patch=mock.patch.object(engine,"ENGINE",str(binary));patch.start();self.addCleanup(patch.stop)
        self.cell=deepcopy(self.base.fixture.value)
        self.cell["engine"]["engine"]={"executable":str(binary),"executable_sha256":digest(binary.read_bytes())}
        self.source_raw,self.source=git_input(acquisition.SUPPLEMENTARY,1103407173,self.cell["candidate"]["source_sha"],
                                              {"README.md":b"source-authenticated candidate payload",
                                               "galaxy.yml":b"namespace: lit\nname: supplementary\nversion: 1.2.3\n",
                                               "run.sh":b"#!/bin/sh\nexit 0\n"}, executable={"run.sh"})
        prefix=".github/actions/run-quality-profile/"
        controller_files={prefix+name:("inert controller "+name).encode() for name in engine.CONTROLLER_FILES}
        self.controller_raw,self.controller=git_input(acquisition.VALIDATION,1269461997,
                                                      self.cell["controller"]["source_sha"],controller_files)
        self.artifact_raw,self.collection=candidate_zip({"README.md":b"source-authenticated candidate payload"})
        self.artifact=acquisition.ArtifactRequest(501,1,self.source.commit_sha,731,
            ".github/workflows/collection-ci.yml",9001,"collection-candidate-"+self.source.commit_sha,
            digest(self.artifact_raw),len(self.artifact_raw))
        self.cell["candidate"]["artifact"]=self.artifact.name
        registry=deepcopy(self.base.fixture.registry_value)
        # Caller SHA remains independently Root-selected, distinct from source.
        self.assertNotEqual(registry["identity"]["caller_sha"],self.source.commit_sha)
        collected=deepcopy(registry["collector"])
        descriptor={key:collected[key] for key in ("service","profile_name","profile_path","profile_sha256")}
        descriptor["service"]["dropins"]=[[row["path"],row["sha256"]] for row in collected["service"]["dropins"]]
        descriptor.update(schema=1,operation_reference="opaque fixture window, not acceptance",
                          storage_reference="opaque storage",custodian_reference="opaque custodian")
        self.collector_ref=self.reference("collector.json",descriptor)
        self.registry_ref=self.reference("registry-input.json",registry)
        self.cell_ref=self.reference("cell-input.json",self.cell)
        self.prep_ref=self.reference("preparation-input.json",self.base.value)
        limits=self.cell["engine"]["capture"]
        runtime={"schema":2,"registry_path":self.base.fixture.registry.path,
            "registry_sha256":self.base.fixture.registry.sha256,
            "preparation_config_path":str(self.base.config),"preparation_config_sha256":self.base.sha,
            "authentication_timeout_seconds":5,"initial_transition_timeout_seconds":60,
            "heartbeat_lead_seconds":30,"cleanup_timeout_seconds":60,
            "capture":{**limits,"max_total_evidence_bytes":1048576,"max_members":100,"max_member_bytes":1048576}}
        self.runtime_ref=self.reference("runtime-input.json",runtime)
        credential=self.base.root/"unused-transport-token";credential.write_bytes(b"synthetic-never-read-token");credential.chmod(0o600)
        acquire=acquisition.AcquisitionRequest(acquisition.CommitRequest(self.source.repository,self.source.repository_id,self.source.commit_sha),
            acquisition.CommitRequest(self.controller.repository,self.controller.repository_id,self.controller.commit_sha),self.artifact,
            str(credential),digest(credential.read_bytes()),1048576,100,1048576,60)
        self.request={"schema":1,"generation_id":"a"*32,"expected_anchor_sha256":None,
            "acquisition":asdict(acquire),"collector":self.collector_ref,"registry":self.registry_ref,
            "cells":{"approved":self.cell_ref},"preparation":self.prep_ref,"runtime":self.runtime_ref}
        self.request_path=self.base.root/"publisher-request.json"
        self.acquired=acquisition.Acquisition(self.source,self.controller,self.artifact,digest(self.artifact_raw),
                                            len(self.artifact_raw),"8"*64)
        self.acquire_calls=[];self.system_calls=[]

    def reference(self,name,value):
        path=self.base.root/name;path.write_bytes(ledger.canonical(value));path.chmod(0o600)
        return {"path":str(path),"sha256":digest(path.read_bytes())}

    def acquire(self,request,*,artifact_fd,source_fd,controller_fd):
        self.acquire_calls.append(request)
        for fd,raw in ((artifact_fd,self.artifact_raw),(source_fd,self.source_raw),(controller_fd,self.controller_raw)):
            self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode),0o600)
            os.write(fd,raw);os.fsync(fd)
        return self.acquired

    def systemctl(self,argv,**kwargs):
        self.system_calls.append(tuple(argv))
        self.assertEqual(argv[0],"/usr/bin/systemctl")
        if argv[1]=="show":return SimpleNamespace(returncode=0,stdout=b"ActiveState=inactive\nSubState=dead\n")
        if argv[1]=="list-units":return SimpleNamespace(returncode=0,stdout=b"[]")
        raise AssertionError("no state-changing systemctl")

    def publish(self,*,acquire=None,systemctl=None):
        self.request_path.write_bytes(ledger.canonical(self.request));self.request_path.chmod(0o600)
        sha=digest(self.request_path.read_bytes())
        with mock.patch.object(acquisition,"acquire",side_effect=acquire or self.acquire), \
             mock.patch.object(publisher.subprocess,"run",side_effect=systemctl or self.systemctl):
            return publisher.RootGenerationPublisher(str(self.request_path),sha).publish()

    def test_full_offline_root_publication_uses_real_closed_readers_and_no_admission(self):
        before=self.base.store.read(self.base.lease)
        result=self.publish()
        anchor=identity.decode_json(self.anchor.read_bytes())
        self.assertEqual(anchor,{"schema":1,"config_path":result.runtime_path,"config_sha256":result.runtime_sha256})
        runtime=runtime_rpc._configuration(result.runtime_path,result.runtime_sha256)
        registry=policy_registry.load_registry(runtime.registry_path,runtime.registry_sha256)
        config=preparation._config(runtime.preparation_config_path,runtime.preparation_config_sha256)[0]
        self.assertEqual(config.registry_path,registry.path)
        selected=registry.select("approved")
        cell=identity.decode_json(Path(selected.cell_config_path).read_bytes())
        self.assertEqual(cell["candidate"]["archive_sha256"],digest(self.collection))
        workspace=cell["engine"]["trees"]["workspace"]
        self.assertEqual(workspace["files"],{
            "README.md":digest(b"source-authenticated candidate payload"),
            "galaxy.yml":digest(b"namespace: lit\nname: supplementary\nversion: 1.2.3\n"),
            "run.sh":digest(b"#!/bin/sh\nexit 0\n")})
        self.assertEqual(stat.S_IMODE((Path(workspace["path"])/"run.sh").stat().st_mode),0o700)
        candidate_tree=cell["engine"]["trees"]["candidate"]
        provenance=Path(candidate_tree["path"])/"source-provenance.json"
        self.assertEqual(digest(provenance.read_bytes()),candidate_tree["files"]["source-provenance.json"])
        self.assertEqual(identity.decode_json(provenance.read_bytes()),publisher._source_provenance(self.source))
        self.assertFalse((Path(workspace["path"])/".git").exists())
        self.assertEqual(stat.S_IMODE((Path(workspace["path"])/"README.md").stat().st_mode),0o600)
        self.assertEqual(set(cell["controller"]["files"]),engine.CONTROLLER_FILES)
        self.assertEqual(selected.collector.config_path,self.collector_ref["path"])
        self.assertEqual(selected.collector.config_sha256,self.collector_ref["sha256"])
        self.assertEqual(self.base.store.read(self.base.lease),before)
        self.assertTrue((Path(result.generation_path)/"published.json").is_file())
        self.assertGreaterEqual(len(self.system_calls),4)

    def test_two_main_cells_cross_real_installer_without_anchor_rollover(self):
        # All Main/acquisition/account values below remain component fixtures.
        # No synthetic Identity, current native job or lease acceptance is claimed.
        import runpy
        actual_publish = self.publish
        observed = []

        def publish_pair():
            registry = json.loads(Path(self.request["registry"]["path"]).read_bytes())
            first = next(iter(registry["cells"]))
            application = deepcopy(self.cell)
            application["matrix"]["profile"] = "application_acceptance"
            application["github"]["job"] = "application"
            matrix = application["matrix"]
            second = policy_registry.profile_selector(matrix["profile"], matrix["scenario"], matrix["target"])
            entry = deepcopy(registry["cells"][first])
            entry["native_job_name"] = "Application Acceptance / " + " / ".join(
                (matrix["profile"], matrix["scenario"], matrix["target"]))
            registry["cells"][second] = entry
            self.request["registry"] = self.reference("registry-pair.json", registry)
            self.request["cells"][second] = self.reference("application-cell-input.json", application)
            result = actual_publish()
            config = runtime_rpc._configuration(result.runtime_path, result.runtime_sha256)
            loaded = policy_registry.load_registry(config.registry_path, config.registry_sha256)
            self.assertEqual(set(loaded.policies), {first, second})
            self.assertEqual(loaded.select(first).identity.runner_id, loaded.select(second).identity.runner_id)
            anchor_before = self.anchor.read_bytes()
            probe = runpy.run_path(str(FILES.parent / "templates/runtime_v2/install_probe.py.j2"))
            service = json.loads(Path(config.registry_path).read_bytes())["collector"]["service"]
            account = SimpleNamespace(pw_name=service["service_user"],
                pw_uid=service["installation"]["service_uid"], pw_gid=23456)
            group = SimpleNamespace(gr_gid=account.pw_gid, gr_mem=[account.pw_name])
            namespace = probe["configurations"].__globals__
            pwd_model = SimpleNamespace(getpwnam=lambda name: account, getpwall=lambda: [account])

            def group_lookup(name):
                if name == "fixture-protected":
                    return group
                raise KeyError(name)

            real_sealed = probe["sealed"]
            service_paths = {service["fragment_path"], service["installation"]["manifest_path"],
                             *[row["path"] for row in service["dropins"]]}

            def sealed_service(path, expected=None, *, private=True):
                if path in service_paths:
                    return b"component service installation transport, not native acceptance"
                return real_sealed(path, expected, private=private)

            # Generation, registry, cells, policies, key and Ledger reads are real.
            # Host service installation and account lookups remain models.
            with mock.patch.dict(namespace, {"pwd": pwd_model,
                    "grp": SimpleNamespace(getgrnam=group_lookup), "sealed": sealed_service}), \
                 mock.patch.object(probe["os"], "getgrouplist", return_value=[account.pw_gid]):
                read = probe["configurations"](result.runtime_path, result.runtime_sha256, "fixture-protected")
            self.assertEqual(read["registry_sha256"], config.registry_sha256)
            for count in (0, 3):
                outside = json.loads(Path(config.registry_path).read_bytes())
                outside["cells"] = {"fixture-" + str(i): next(iter(outside["cells"].values())) for i in range(count)}

                def outside_registry(path, expected=None, *, private=True):
                    if path == config.registry_path:
                        return ledger.canonical(outside)
                    return real_sealed(path, expected, private=private)

                with mock.patch.dict(namespace, {"sealed": outside_registry}):
                    with self.assertRaisesRegex(ValueError, "runtime-v2-installation-denied"):
                        probe["configurations"](result.runtime_path, result.runtime_sha256, "fixture-protected")
            self.assertEqual(self.anchor.read_bytes(), anchor_before)
            self.assertNotEqual(loaded.select(first).cell_sha256, loaded.select(second).cell_sha256)
            # Continue through the actual Ledger and semantic cell consumer.
            # Existing trusted model identities are test vectors, never OIDC proof.
            seed = self.base.store.read(self.base.lease)
            worker = ledger.Worker(**seed["worker"])
            model_identity = identity.Identity(**seed["identity"])

            def model_admission(selector, offset):
                selected = loaded.select(selector)
                policy_sha = identity.policy_digest(selected.identity)
                challenge = self.base.store.runtime_challenge(worker, "run", selected.cell_sha256, policy_sha)
                who = replace(model_identity, run_id=self.artifact.run_id,
                    job_id=model_identity.job_id + offset, check_run_id=model_identity.check_run_id + offset,
                    caller_sha=selected.identity.caller_sha, reusable_sha=selected.identity.reusable_sha,
                    audience=challenge["audience"], policy_sha256=policy_sha,
                    token_id_sha256=digest(("model-serial-token:" + selector).encode()))
                return selected, challenge, who, policy_sha

            def admit(values):
                selected, challenge, who, policy_sha = values
                return self.base.store.runtime_prepare(challenge["nonce"], worker, who,
                    policy_sha256=selected.custody_policy_sha256, cell_sha256=selected.cell_sha256,
                    deadline=selected.deadline, identity_policy_sha256=policy_sha)

            heavy = admit(model_admission(first, 0))
            heavy_cell = publisher.cell_contract.prepare_cell(loaded, first, self.base.store, heavy)
            application_values = model_admission(second, 1)
            with self.assertRaisesRegex(Denied, "runner-lease-unsettled"):
                admit(application_values)
            # No effects are modelled here: close is real, but not VM finalization.
            self.base.store.close(heavy)
            application_lease = admit(application_values)
            application_cell = publisher.cell_contract.prepare_cell(loaded, second, self.base.store, application_lease)
            self.assertNotEqual(heavy, application_lease)
            self.assertNotEqual(heavy_cell.engine_descriptor_path, application_cell.engine_descriptor_path)
            self.assertNotEqual(heavy_cell.incus["project"], application_cell.incus["project"])
            # Same run/scenario/target uses one deterministic bridge name.
            # Real Heavy cleanup must prove it absent before Application creates it.
            self.assertEqual(heavy_cell.incus["network"], application_cell.incus["network"])
            self.assertNotEqual(heavy_cell.incus["ownership"]["lease_id"],
                                application_cell.incus["ownership"]["lease_id"])
            self.base.store.close(application_lease)
            self.assertEqual(self.anchor.read_bytes(), anchor_before)
            observed.append((first, second))
            return result

        with mock.patch.object(self, "publish", side_effect=publish_pair):
            self.test_main_readback_artifact_binds_consumer_independently_of_source()
        self.assertEqual(len(observed), 1)

    def test_main_readback_artifact_binds_consumer_independently_of_source(self):
        from incus_runtime_client import profile_selector
        registry = json.loads(Path(self.registry_ref["path"]).read_bytes())
        registry["identity"].update(
            repository="ltn-it/modulix-validation", repository_id=1269461997, owner_id=54334171,
            workflow_path=".github/workflows/mlx90-collection-candidate-validation.yml",
            reusable_repository="ltn-it/modulix-validation",
            reusable_path=".github/workflows/collection-quality-profile-isolated.yml",
            actor_ids=[307565056],
            subject="repo:ltn-it/modulix-validation:environment:heavy-isolated-pilot", visibility="public")
        self.assertEqual(self.artifact.run_id, 501)  # Original source producer fixture.
        self.artifact = acquisition.MainArtifactRequest(601, 1, registry["identity"]["caller_sha"],
            registry["identity"]["workflow_id"], registry["identity"]["workflow_path"], 9001,
            "mlx90-candidate-"+"9"*64, digest(self.artifact_raw), len(self.artifact_raw), "9"*64)
        self.acquired = replace(self.acquired, artifact=self.artifact)
        self.request["acquisition"]["artifact"] = asdict(self.artifact)
        self.cell["github"]["run_id"] = 601
        self.cell["candidate"]["artifact"] = self.artifact.name
        matrix = self.cell["matrix"]
        selector = profile_selector(matrix["profile"], matrix["scenario"], matrix["target"])
        registry["cells"] = {selector: registry["cells"]["approved"]}
        self.request["registry"] = self.reference("registry-input.json", registry)
        self.request["cells"] = {selector: self.reference("cell-input.json", self.cell)}
        before = self.base.store.read(self.base.lease)
        result = self.publish()
        runtime = runtime_rpc._configuration(result.runtime_path, result.runtime_sha256)
        loaded = policy_registry.load_registry(runtime.registry_path, runtime.registry_sha256)
        selected = loaded.select(selector)
        sealed = identity.decode_json(Path(selected.cell_config_path).read_bytes())
        self.assertEqual(sealed["github"]["run_id"], 601)
        self.assertNotEqual(self.artifact.head_sha, self.source.commit_sha)
        self.assertTrue(identity.validation_main_receiver(selected.identity))
        self.assertEqual(self.base.store.read(self.base.lease), before)
        # Native deployment has only the private issuer package on sys.path;
        # the public job executable has a hyphenated name elsewhere. A source
        # package mount must not hide a missing Root-library dependency.
        private_library = self.base.root/"private-runtime-library"
        private_library.mkdir(mode=0o700)
        shutil.copytree(FILES/"incus_lease_issuer", private_library/"incus_lease_issuer")
        native = asdict(selected.identity)
        native["actor_ids"] = sorted(native["actor_ids"])
        metadata = self.reference("private-runtime-metadata.json", {
            "identity": native, "selector": selector, "path": selected.cell_config_path,
            "sha256": selected.cell_sha256, "artifact": asdict(self.artifact)})
        script = """import importlib.util,json,sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,sys.argv[1])
assert importlib.util.find_spec('incus_runtime_client') is None
from incus_lease_issuer import generation_publisher as p, generation_acquisition as a, identity
m=json.loads(Path(sys.argv[2]).read_text());m['identity']['actor_ids']=frozenset(m['identity']['actor_ids'])
native=identity.Policy(**m['identity'])
selected=SimpleNamespace(identity=native,cell_config_path=m['path'],cell_sha256=m['sha256'])
p._acquired_receiver(SimpleNamespace(policies={m['selector']:selected}),a.MainArtifactRequest(**m['artifact']))
print('private Root library selected Main artifact without public client module')
"""
        standalone = subprocess.run([sys.executable, "-I", "-B", "-c", script,
            str(private_library), metadata["path"]], capture_output=True, text=True, timeout=20, check=False)
        self.assertEqual(standalone.returncode, 0, standalone.stderr)
        self.assertIn("without public client module", standalone.stdout)
        with self.assertRaisesRegex(Denied, "cell-receiver-run-binding"):
            publisher.cell_contract._environment(sealed, selected.identity, {"run_id": 501})
        for value in (True, 0, -1, "601", 2**63):
            changed = deepcopy(sealed)
            changed["github"]["run_id"] = value
            with self.subTest(run_id=value), mock.patch.object(publisher, "_read", return_value=changed):
                with self.assertRaisesRegex(Denied, "generation-receiver-run"):
                    publisher._static_cells(loaded, self.artifact.run_id)
        for artifact in (replace(self.artifact, run_id=501),
                         replace(self.artifact, head_sha=self.source.commit_sha),
                         replace(self.artifact, workflow_id=self.artifact.workflow_id+1),
                         replace(self.artifact, name="mlx90-candidate-"+"8"*64)):
            with self.subTest(artifact=artifact), self.assertRaisesRegex(Denied, "generation-main-consumer-binding"):
                publisher._acquired_receiver(loaded, artifact)
        legacy = acquisition.ArtifactRequest(501, 1, self.source.commit_sha, 731,
            ".github/workflows/collection-ci.yml", 9001, "collection-candidate-"+self.source.commit_sha,
            digest(self.artifact_raw), len(self.artifact_raw))
        with self.assertRaisesRegex(Denied, "generation-artifact-domain"):
            publisher._acquired_receiver(loaded, legacy)
        wrong_selector = policy_registry.Registry(loaded.path, loaded.sha256,
            MappingProxyType({"approved": selected}))
        with self.assertRaisesRegex(Denied, "generation-main-profile-selector"):
            publisher._acquired_receiver(wrong_selector, self.artifact)

    def test_second_generation_retains_previous_bytes_and_stale_cas_has_no_effect(self):
        first=self.publish();old_runtime=Path(first.runtime_path).read_bytes();old_anchor=self.anchor.read_bytes()
        self.request.update(generation_id="b"*32,expected_anchor_sha256=digest(old_anchor))
        second=self.publish()
        self.assertNotEqual(second.runtime_path,first.runtime_path)
        self.assertEqual(Path(first.runtime_path).read_bytes(),old_runtime)
        current=self.anchor.read_bytes()
        self.request.update(generation_id="c"*32,expected_anchor_sha256=digest(old_anchor))
        with self.assertRaises(Denied):self.publish()
        self.assertEqual(self.anchor.read_bytes(),current)
        self.assertFalse((self.root/("c"*32)).exists())

    def test_active_service_denies_before_acquisition_or_generation_creation(self):
        def active(argv,**kwargs):return SimpleNamespace(returncode=0,stdout=b"ActiveState=active\nSubState=listening\n")
        with self.assertRaises(Denied):self.publish(systemctl=active)
        self.assertEqual(self.acquire_calls,[])
        self.assertFalse((self.root/self.request["generation_id"]).exists())
        self.assertFalse(self.anchor.exists())

    def test_open_lease_blocks_anchor_and_retains_partial_generation_without_reuse(self):
        self.assertEqual(self.base.store.read(self.base.lease)["state"],"prepared")
        with self.assertRaises(Denied):self.publish()
        partial=self.root/self.request["generation_id"]
        self.assertTrue((partial/"intent.json").exists())
        self.assertFalse((partial/"published.json").exists())
        self.assertFalse(self.anchor.exists())
        acquired=len(self.acquire_calls)
        with self.assertRaises(Denied):self.publish()
        self.assertEqual(len(self.acquire_calls),acquired)

    def test_wrong_authenticated_blob_retains_downloads_without_anchor_or_retry(self):
        self.source_raw=tar_bytes({"README.md":b"tampered"},prefix="fixture-"+self.source.commit_sha)
        with self.assertRaises(Denied):self.publish()
        partial=self.root/self.request["generation_id"]
        self.assertEqual((partial/"downloads/source.tar.gz").read_bytes(),self.source_raw)
        self.assertFalse(self.anchor.exists())
        with self.assertRaises(Denied):self.publish()
        self.assertEqual(len(self.acquire_calls),1)

    def test_sealed_tree_mutation_before_cas_retains_old_anchor_and_generation(self):
        first=self.publish()
        original_anchor=self.anchor.read_bytes()
        old_runtime=Path(first.runtime_path).read_bytes()
        self.request.update(generation_id="b"*32,expected_anchor_sha256=digest(original_anchor))
        shows=0
        def mutate_at_precas(argv,**kwargs):
            nonlocal shows
            if argv[1]=="show":
                shows+=1
                if shows==2:
                    sealed=self.root/self.request["generation_id"]/"trees/workspace/README.md"
                    self.assertTrue((sealed.parents[2]/"sealed-inventory.json").exists())
                    sealed.write_bytes(b"mutation after full validation/staging")
            return self.systemctl(argv,**kwargs)
        with self.assertRaises(Denied):self.publish(systemctl=mutate_at_precas)
        self.assertEqual(shows,2)
        self.assertEqual(self.anchor.read_bytes(),original_anchor)
        self.assertEqual(Path(first.runtime_path).read_bytes(),old_runtime)
        partial=self.root/self.request["generation_id"]
        self.assertTrue((partial/"sealed-inventory.json").exists())
        self.assertFalse((partial/"published.json").exists())

    def test_accepted_unit_becoming_active_at_precas_keeps_anchor_missing(self):
        lists=0
        def newly_active(argv,**kwargs):
            nonlocal lists
            if argv[1]=="list-units":
                lists+=1
                if lists==2:
                    return SimpleNamespace(returncode=0,stdout=json.dumps([{
                        "unit":"lit-incus-runtime-v2@native-peer.service","active":"active","sub":"running"}]).encode())
            return self.systemctl(argv,**kwargs)
        before=self.base.store.read(self.base.lease)
        with self.assertRaises(Denied):self.publish(systemctl=newly_active)
        self.assertEqual(lists,2)
        self.assertFalse(self.anchor.exists())
        self.assertEqual(self.base.store.read(self.base.lease),before)
        self.assertTrue((self.root/self.request["generation_id"]/"sealed-inventory.json").exists())

    def test_static_invalid_incus_denies_without_admission_or_anchor(self):
        before=(Path(self.base.fixture.io.fixture.store_path)/"state.json").read_bytes()
        changed=deepcopy(self.cell);changed["incus"]["project_limits"]["containers"]=1
        self.request["cells"]["approved"]=self.reference("invalid-incus-cell.json",changed)
        with self.assertRaises(Denied):self.publish()
        self.assertFalse(self.anchor.exists())
        self.assertEqual((Path(self.base.fixture.io.fixture.store_path)/"state.json").read_bytes(),before)
        self.assertEqual(self.base.store.read(self.base.lease)["effects"],{})

    def test_static_budget_shorter_than_execution_denies_without_admission_or_anchor(self):
        before=(Path(self.base.fixture.io.fixture.store_path)/"state.json").read_bytes()
        registry=identity.decode_json(Path(self.registry_ref["path"]).read_bytes())
        budget=self.cell["engine"]["limits"]["timeout_seconds"]
        registry["cells"]["approved"]["deadline"]=int(publisher.time.time())+budget-1
        self.request["registry"]=self.reference("short-budget-registry.json",registry)
        with self.assertRaises(Denied):self.publish()
        self.assertFalse(self.anchor.exists())
        self.assertEqual((Path(self.base.fixture.io.fixture.store_path)/"state.json").read_bytes(),before)
        self.assertEqual(self.base.store.read(self.base.lease)["effects"],{})

    def test_runtime_capture_mismatch_denies_before_anchor_or_ledger_mutation(self):
        before=(Path(self.base.fixture.io.fixture.store_path)/"state.json").read_bytes()
        runtime=identity.decode_json(Path(self.runtime_ref["path"]).read_bytes())
        runtime["capture"]["stdout_limit"]+=1
        self.request["runtime"]=self.reference("mismatched-runtime.json",runtime)
        with self.assertRaises(Denied):self.publish()
        self.assertFalse(self.anchor.exists())
        self.assertEqual((Path(self.base.fixture.io.fixture.store_path)/"state.json").read_bytes(),before)
        self.assertEqual(self.base.store.read(self.base.lease)["effects"],{})

    def test_main_actual_offline_success_json_matches_real_fixed_anchor_and_redacts_inputs(self):
        self.request_path.write_bytes(ledger.canonical(self.request));self.request_path.chmod(0o600)
        sha=digest(self.request_path.read_bytes())
        before=self.base.store.read(self.base.lease)
        with mock.patch.object(acquisition,"acquire",side_effect=self.acquire), \
             mock.patch.object(publisher.subprocess,"run",side_effect=self.systemctl), \
             mock.patch("sys.stdout",new_callable=io.StringIO) as out, \
             mock.patch("sys.stderr",new_callable=io.StringIO) as err:
            self.assertEqual(publisher.main([str(self.request_path),sha]),0)
        result=json.loads(out.getvalue())
        self.assertEqual(set(result),{"generation_path","runtime_path","runtime_sha256","anchor_sha256","provenance_sha256"})
        self.assertEqual(err.getvalue(),"")
        anchor=identity.decode_json(self.anchor.read_bytes())
        self.assertEqual(anchor["config_path"],result["runtime_path"])
        self.assertEqual(anchor["config_sha256"],result["runtime_sha256"])
        self.assertEqual(digest(self.anchor.read_bytes()),result["anchor_sha256"])
        self.assertNotIn("synthetic-never-read-token",out.getvalue())
        self.assertNotIn(str(self.request_path),out.getvalue())
        self.assertEqual(self.base.store.read(self.base.lease),before)


if __name__=="__main__":unittest.main()
