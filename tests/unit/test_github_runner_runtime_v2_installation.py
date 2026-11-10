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
        for key in ("configuration_path", "configuration_sha256", "socket_group"):
            self.assertEqual(defaults["github_runner_runtime_v2_"+key], "")
        self.assertEqual(defaults["github_runner_runtime_v2_module_sha256"], {})
        self.assertEqual(defaults["github_runner_runtime_v2_client_sha256"], {})
        main = (ROLE / "tasks/main.yml").read_text()
        self.assertLess(main.index("runtime_v2.yml"), main.index("Ensure GitHub runner packages"))
        self.assertIn("when: github_runner_runtime_v2_install", main)

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


@unittest.skipUnless(sys.platform=="linux" and os.geteuid()==0,"private proper-EE Root only")
class RootInstalledRuntimeTests(unittest.TestCase):
    def setUp(self):
        base=Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid!=0 or stat.S_IMODE(base.stat().st_mode)!=0o700:
            self.skipTest("requires private Root0700 /run/proof")
        self.temp=tempfile.TemporaryDirectory(prefix="runtime-install-",dir=base)
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

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
