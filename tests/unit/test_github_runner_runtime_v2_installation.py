"""Default-off installation/source contract; Root FS cases only in proper EE.

Systemd observations are modeled, never native service/host qualification.
The fresh private launcher/package import is an actual isolated subprocess.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import types
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "roles/github_runner"
TEMPLATES = ROLE / "templates/runtime_v2"
probe = types.ModuleType("runtime_v2_install_probe")
exec(compile((TEMPLATES / "install_probe.py.j2").read_text(), "runtime_v2_install_probe", "exec"), probe.__dict__)


class InstallationContractTests(unittest.TestCase):
    def test_default_off_and_source_pins_have_no_guessed_live_values(self):
        defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
        self.assertIs(defaults["github_runner_runtime_v2_install"], False)
        self.assertIs(defaults["github_runner_runtime_v2_bootstrap"], False)
        self.assertIs(defaults["github_runner_runtime_v2_operating_install"], False)
        self.assertEqual(defaults["github_runner_runtime_v2_mail_helper_sha256"], {})
        for key in ("configuration_path", "configuration_sha256", "socket_group", "signing_public_key_hex",
                    "watchdog_configuration_path", "watchdog_configuration_sha256", "mail_configuration_path", "mail_configuration_sha256"):
            self.assertEqual(defaults["github_runner_runtime_v2_"+key], "")
        self.assertEqual(defaults["github_runner_runtime_v2_module_sha256"], {})
        self.assertEqual(defaults["github_runner_runtime_v2_client_sha256"], {})
        main = (ROLE / "tasks/main.yml").read_text()
        self.assertLess(main.index("runtime_v2.yml"), main.index("Ensure GitHub runner packages"))
        self.assertIn("github_runner_runtime_v2_install or github_runner_runtime_v2_operating_install", main)

    def test_no_activation_stop_group_creation_or_credential_generation(self):
        tasks = yaml.safe_load((ROLE / "tasks/runtime_v2.yml").read_text())
        changes = tasks[1]["block"]
        systemd = [task["ansible.builtin.systemd_service"] for task in changes if "ansible.builtin.systemd_service" in task]
        self.assertEqual(systemd, [{"daemon_reload": True}])
        self.assertFalse(any("ansible.builtin.group" in task or "ansible.builtin.user" in task for task in changes))
        self.assertLess(next(i for i,t in enumerate(changes) if "before copying" in t["name"]),
                        next(i for i,t in enumerate(changes) if "ansible.builtin.file" in t))
        self.assertIn("install_probe.py.j2", changes[-1]["ansible.builtin.command"]["argv"][4])

    def test_fixed_launcher_socket_and_service_contract(self):
        launcher = (TEMPLATES / "entry.py.j2").read_text()
        unit = (TEMPLATES / "service.j2").read_text()
        self.assertIn('sys.path.insert(0, "/usr/local/lib/lit-incus-runtime-v2")', launcher)
        self.assertIn("runtime_entry import main", launcher)
        self.assertNotIn("getenv", launcher)
        self.assertIn("/usr/bin/python3 -I -B /usr/local/lib/lit-incus-runtime-v2/runtime_v2_entry.py", unit)
        self.assertIn("StandardInput=socket", unit)
        self.assertIn("StandardOutput=null", unit)
        self.assertNotIn("PrivateNetwork", unit)
        self.assertNotIn("Watchdog", unit)
        self.assertNotIn("RuntimeMaxSec", unit)
        self.assertIn("Accept=yes", (TEMPLATES / "socket.j2").read_text())

    def test_active_unknown_enabled_or_dropin_units_deny_without_mutation(self):
        base = {"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","UnitFileState":"disabled",
                "FragmentPath":"/etc/systemd/system/lit-incus-runtime-v2.socket","DropInPaths":""}
        def observed(data):
            return SimpleNamespace(returncode=0,stdout="".join(key+"="+value+"\n" for key,value in data.items()).encode())
        with mock.patch.object(probe.subprocess,"run",return_value=observed(base)):
            probe.state("lit-incus-runtime-v2.socket")
        for change in ({"ActiveState":"active"},{"LoadState":"error"},{"UnitFileState":"enabled"},
                       {"DropInPaths":"/etc/systemd/system/foreign.conf"},{"FragmentPath":"/run/generator/foreign"}):
            with self.subTest(change=change), mock.patch.object(probe.subprocess,"run",return_value=observed({**base,**change})):
                with self.assertRaises(ValueError):probe.state("lit-incus-runtime-v2.socket")

    def test_strict_json_duplicates_nonfinite_and_nonroot_entry_deny(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1e999}'):
            with self.assertRaises(ValueError):probe.decode(raw)
        with mock.patch.object(probe.os,"geteuid",return_value=2101), mock.patch.object(probe,"inactive",side_effect=AssertionError("no state query")), \
             mock.patch.object(probe.sys,"argv",["probe"]):
            with mock.patch("sys.stderr"):
                self.assertEqual(probe.main(),1)


class RealAnsibleInstallationBoundary(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.directory=Path(self.temp.name)
        collection=self.directory/"collections/ansible_collections/lit/ubuntu"
        collection.parent.mkdir(parents=True);collection.symlink_to(ROOT,target_is_directory=True)
        self.environment=dict(os.environ,ANSIBLE_COLLECTIONS_PATH=str(self.directory/"collections"),
            ANSIBLE_LOCAL_TEMP=str(self.directory/"local"),ANSIBLE_REMOTE_TEMP=str(self.directory/"remote"),ANSIBLE_NOCOLOR="1")

    def invoke(self, variables):
        book=self.directory/"boundary.json"
        book.write_text(json.dumps([{"hosts":"all","gather_facts":False,
            "vars":{"ansible_python_interpreter":sys.executable,**variables},
            "tasks":[{"ansible.builtin.include_role":{"name":"lit.ubuntu.github_runner","tasks_from":"runtime_v2"}}]}]))
        return subprocess.run(["ansible-playbook","-i","localhost,","-c","local",str(book)],
            cwd=self.directory,env=self.environment,capture_output=True,text=True,timeout=90)

    def test_actual_bootstrap_and_observer_anchor_bytes_are_canonical(self):
        outputs={}
        tasks=[]
        variables={"ansible_python_interpreter":sys.executable,"github_runner_runtime_v2_bootstrap":True,
            "github_runner_runtime_v2_configuration_path":"/var/lib/g06/bootstrap.json",
            "github_runner_runtime_v2_configuration_sha256":"a"*64}
        for label in ("watchdog","mail"):
            variables["github_runner_runtime_v2_"+label+"_configuration_path"]="/var/lib/g06/"+label+".json"
            variables["github_runner_runtime_v2_"+label+"_configuration_sha256"]="b"*64
        for label,template in (("bootstrap","anchor.json.j2"),("watchdog","operating_watchdog_anchor.json.j2"),
                               ("mail","operating_mail_anchor.json.j2")):
            outputs[label]=self.directory/(label+"-anchor.json")
            tasks.append({"name":"Render "+label,"ansible.builtin.template":{
                "src":str(TEMPLATES/template),"dest":str(outputs[label]),"mode":"0600"}})
        play=[{"hosts":"all","gather_facts":False,"vars":variables,"tasks":tasks}]
        book=self.directory/"anchors.json";book.write_text(json.dumps(play))
        result=subprocess.run(["ansible-playbook","-i","localhost,","-c","local",str(book)],
            cwd=self.directory,env=self.environment,capture_output=True,text=True,timeout=60)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        for label,file in outputs.items():
            raw=file.read_bytes();value=json.loads(raw)
            self.assertEqual(raw,json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode())
            self.assertEqual(stat.S_IMODE(file.stat().st_mode),0o600)
            if label=="bootstrap":
                self.assertEqual(value,{"schema":2,"bootstrap_path":"/var/lib/g06/bootstrap.json","bootstrap_sha256":"a"*64})
            else:
                self.assertEqual(value,{"schema":1,"config_path":"/var/lib/g06/"+label+".json","config_sha256":"b"*64})

    def test_default_off_has_no_effects(self):
        result=self.invoke({})
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn("changed=0",result.stdout)

    def test_operating_install_requires_explicit_bootstrap_before_effects(self):
        result=self.invoke({"github_runner_runtime_v2_install":True,"github_runner_runtime_v2_operating_install":True})
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn("Create sealed runtime-v2 installation directories",result.stdout)
        self.assertIn("Runtime-v2 installation must be explicitly selected",result.stdout)

    def test_real_role_renders_complete_bootstrap_operating_assets_then_denies_missing_native_state(self):
        value={"github_runner_enabled":True,"github_runner_runtime_v2_install":True,
            "github_runner_runtime_v2_bootstrap":True,"github_runner_runtime_v2_operating_install":True,
            "github_runner_runtime_v2_configuration_path":"/var/lib/nonexistent-g06-fixture/bootstrap.json",
            "github_runner_runtime_v2_configuration_sha256":"a"*64,"github_runner_runtime_v2_socket_group":"g06fixture",
            "github_runner_runtime_v2_signing_public_key_hex":"b"*64,
            "github_runner_runtime_v2_module_sha256":{f.name:hashlib.sha256(f.read_bytes()).hexdigest()
                for f in (ROLE/"files/incus_lease_issuer").glob("*.py")},
            "github_runner_runtime_v2_client_sha256":{name:hashlib.sha256((ROLE/"files"/source).read_bytes()).hexdigest()
                for name,source in (("incus-runtime-client","incus_runtime_client.py"),("incus_job_client.py","incus_job_client.py"))},
            "github_runner_runtime_v2_mail_helper_sha256":{name:hashlib.sha256((ROLE/"files"/name).read_bytes()).hexdigest()
                for name in probe.HELPERS}}
        for label in ("watchdog","mail"):
            value["github_runner_runtime_v2_"+label+"_configuration_path"]="/var/lib/nonexistent-g06-fixture/"+label+".json"
            value["github_runner_runtime_v2_"+label+"_configuration_sha256"]="c"*64
        result=self.invoke(value)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("Refuse active unknown foreign or unsealed target state before copying",result.stdout)
        self.assertNotIn("Create sealed runtime-v2 installation directories",result.stdout)
        self.assertNotIn("undefined",result.stdout+result.stderr)
        self.assertNotIn("Syntax error",result.stdout+result.stderr)


@unittest.skipUnless(sys.platform=="linux" and os.geteuid()==0,"private proper-EE Root only")
class RootInstalledRuntimeTests(unittest.TestCase):
    def setUp(self):
        base=Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid!=0 or stat.S_IMODE(base.stat().st_mode)!=0o700:
            self.skipTest("requires private Root0700 /run/proof")
        self.temp=tempfile.TemporaryDirectory(prefix="runtime-install-",dir=base)
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def test_signer_installation_metadata_never_reads_or_hashes_private_bytes(self):
        file = self.root / "signer.key"
        file.write_bytes(b"synthetic-private-file")
        file.chmod(0o600)
        info = file.stat()
        with mock.patch.object(probe.os, "read", side_effect=AssertionError("private bytes must not be read")), \
             mock.patch.object(probe.hashlib, "sha256", side_effect=AssertionError("private bytes must not be hashed")):
            self.assertEqual(probe.private_metadata(str(file)), (info.st_dev, info.st_ino, info.st_size))
        link = self.root / "symlink-key"
        link.symlink_to(file)
        with self.assertRaises((ValueError, OSError)):
            probe.private_metadata(str(link))
        file.chmod(0o644)
        with self.assertRaises(ValueError):
            probe.private_metadata(str(file))

    def test_real_operating_configs_bind_host_and_same_private_spool_without_effects(self):
        binding = self.root / "bindings";binding.mkdir(mode=0o700)
        spool = self.root / "spool";spool.mkdir(mode=0o700)
        helpers = {name: "a"*64 for name in probe.HELPERS}
        common = {"schema":1,"source_machine_id":Path("/etc/machine-id").read_text().strip(),
                  "source_boot_id":Path("/proc/sys/kernel/random/boot_id").read_text().strip(),"spool_directory":str(spool)}
        watchdog = {**common,"bindings_directory":str(binding),"max_entries":256}
        mail = {**common,"helper_sha256":helpers}
        selected = {"helper_sha256":helpers}
        for label,config in (("watchdog",watchdog),("mail",mail)):
            file = self.root / (label+".json")
            raw=json.dumps(config,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
            file.write_bytes(raw);file.chmod(0o600)
            selected[label+"_path"]=str(file);selected[label+"_sha256"]=hashlib.sha256(raw).hexdigest()
        with mock.patch.object(probe,"HELPER_ROOT",str(self.root/"not-installed")), \
             mock.patch.object(probe,"BINDINGS_ROOT",str(binding),create=True), \
             mock.patch.object(probe.subprocess,"run",side_effect=AssertionError("no service or mail effects")):
            self.assertEqual(probe.operating_configuration(selected),[watchdog,mail])
            other = self.root / "unpublished-bindings";other.mkdir(mode=0o700)
            file=Path(selected["watchdog_path"])
            wrong={**watchdog,"bindings_directory":str(other)}
            raw=json.dumps(wrong,sort_keys=True,separators=(",",":")).encode()
            file.write_bytes(raw);selected["watchdog_sha256"]=hashlib.sha256(raw).hexdigest()
            with self.assertRaises(ValueError):probe.operating_configuration(selected)
            raw=json.dumps(watchdog,sort_keys=True,separators=(",",":")).encode()
            file.write_bytes(raw);selected["watchdog_sha256"]=hashlib.sha256(raw).hexdigest()
            changed={**mail,"source_boot_id":"0"*36}
            file=Path(selected["mail_path"]);raw=json.dumps(changed,sort_keys=True,separators=(",",":")).encode()
            file.write_bytes(raw);selected["mail_sha256"]=hashlib.sha256(raw).hexdigest()
            with self.assertRaises(ValueError):probe.operating_configuration(selected)
        self.assertEqual(list(binding.iterdir()),[]);self.assertEqual(list(spool.iterdir()),[])

    def test_fixed_operating_launchers_import_real_private_package_without_effects(self):
        private=self.root/"operating-private";private.mkdir(mode=0o700)
        library=private/"incus_lease_issuer";library.mkdir(mode=0o700)
        for source in (ROLE/"files/incus_lease_issuer").glob("*.py"):
            target=library/source.name;shutil.copyfile(source,target);target.chmod(0o600)
        for name in ("watchdog","mail"):
            with self.subTest(name=name):
                launcher=private/("operating_"+name+"_entry.py")
                launcher.write_text((TEMPLATES/("operating_"+name+"_entry.py.j2")).read_text().replace(
                    '"/usr/local/lib/lit-incus-runtime-v2"',json.dumps(str(private))))
                launcher.chmod(0o600)
                result=subprocess.run([sys.executable,"-I","-B",str(launcher)],stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={"PATH":"/usr/bin:/bin","LANG":"C"},timeout=5,check=False)
                self.assertEqual(result.returncode,1)  # Missing fixed Root anchor denies, without a tick.
                self.assertEqual((result.stdout,result.stderr),(b"",b""))
        self.assertFalse((library/"__pycache__").exists())

    def test_real_private_file_symlink_hardlink_writable_and_hash_guards(self):
        file=self.root/"sealed.json";file.write_bytes(b"{}");file.chmod(0o600)
        digest=hashlib.sha256(file.read_bytes()).hexdigest()
        self.assertEqual(probe.sealed(str(file),digest),b"{}")
        link=self.root/"symlink";link.symlink_to(file)
        with self.assertRaises((ValueError,OSError)):probe.sealed(str(link),digest)
        hard=self.root/"hardlink";os.link(file,hard)
        with self.assertRaises(ValueError):probe.sealed(str(file),digest)
        hard.unlink();file.chmod(0o666)
        with self.assertRaises(ValueError):probe.sealed(str(file),digest)
        file.chmod(0o600)
        with self.assertRaises(ValueError):probe.sealed(str(file),"0"*64)

    def test_fresh_isolated_launcher_imports_copied_package_without_pythonpath_or_traceback(self):
        package=self.root/"private";package.mkdir(mode=0o700)
        library=package/"incus_lease_issuer";library.mkdir(mode=0o700)
        modules=list((ROLE/"files/incus_lease_issuer").glob("*.py"))
        self.assertGreater(len(modules),25)
        for source in modules:
            target=library/source.name;shutil.copyfile(source,target);target.chmod(0o600)
        launcher=package/"runtime_v2_entry.py"
        launcher.write_text((TEMPLATES/"entry.py.j2").read_text().replace(
            '"/usr/local/lib/lit-incus-runtime-v2"',json.dumps(str(package))))
        launcher.chmod(0o700)
        result=subprocess.run([sys.executable,"-I","-B",str(launcher)],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={"PATH":"/usr/bin:/bin","LANG":"C"},timeout=5,check=False)
        self.assertEqual(result.returncode,1)  # Non-socket stdin denies AFTER actual package import.
        self.assertEqual(result.stdout,b"");self.assertEqual(result.stderr,b"")
        self.assertFalse((library/"__pycache__").exists())


if __name__=="__main__":unittest.main()
