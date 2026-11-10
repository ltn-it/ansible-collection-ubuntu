"""RootFS boundary and modeled APT tests; never run native APT or change services."""
import importlib.util
import io
import errno
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import yaml


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "roles/incus/files/runtime_packages.py"
SPEC = importlib.util.spec_from_file_location("incus_runtime_packages", SOURCE)
TX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TX)
REAL_RUN = TX.run
PUBLIC_CANDIDATE_SHA256 = TX.CANDIDATE_SHA256
SOURCE32_FIXTURE = Path(__file__).with_name("incus_runtime_packages_candidate32.json")


def apt_v3_quote_fixture(value, bad="\n"):
    # Independent reference: official APT2.8 strutl.cc QuoteString, used by
    # dpkgpm.cc SendPkgsInfo. No production encoder call or native execution.
    result = []
    for byte in value.encode("utf-8"):
        if chr(byte) in bad or byte <= 0x20 or byte >= 0x7f or byte == 0x25:
            result.append("%%%02x" % byte)
        else:
            result.append(chr(byte))
    return "".join(result)


class EntryTests(unittest.TestCase):
    def test_default_main_has_no_alternate_entry_or_helper_effect(self):
        main = (ROOT / "roles/incus/tasks/main.yml").read_text()
        self.assertNotIn("runtime_packages", main)
        self.assertNotIn("incus-maintenance", main)
        tasks = yaml.safe_load((ROOT / "roles/incus/tasks/runtime_packages.yml").read_text())
        self.assertEqual(next(key for key in tasks[0] if key.startswith("ansible.builtin.")),
                         "ansible.builtin.fail")
        self.assertEqual(tasks[0]["when"], "ansible_check_mode")
        for task in tasks:
            self.assertFalse(any(key.endswith(("import_tasks", "include_tasks", "include_role", "systemd_service"))
                                 for key in task))
        command = tasks[-1]["ansible.builtin.command"]["argv"]
        self.assertEqual(command[:5], ["/usr/bin/python3", "-I", "-B", TX.HELPER, "install"])
        self.assertEqual(len(command), 7)
        specs = yaml.safe_load((ROOT / "roles/incus/meta/argument_specs.yml").read_text())
        self.assertEqual(set(specs["argument_specs"]["runtime_packages"]["options"]),
                         {"incus_runtime_packages_request_path", "incus_runtime_packages_request_sha256"})

    def test_nonroot_is_denied_before_request_io(self):
        with patch.object(TX.os, "geteuid", return_value=501), patch.object(TX, "read") as reader:
            with self.assertRaisesRegex(TX.Denied, "root-and-request-digest"):
                TX.load_request("/nonexistent", "a" * 64)
            reader.assert_not_called()

    def test_request_reference_does_not_gain_data_filename_tilde_grammar(self):
        with patch.object(TX.os, "geteuid", return_value=0), patch.object(TX, "read") as reader:
            with self.assertRaisesRegex(TX.Denied, "canonical-root-file-path"):
                TX.load_request("/root/request~.json", "a" * 64)
            reader.assert_not_called()

    def test_strict_json_duplicate_and_nonfinite_deny(self):
        for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(TX.Denied):
                TX.strict_json(raw)


class Source32ProducerTests(unittest.TestCase):
    """Actual selected public32 data; private acquisition modeled, no native APT."""
    def setUp(self):
        self.raw = SOURCE32_FIXTURE.read_bytes()
        self.fixture = json.loads(self.raw)
        self.assertEqual(self.fixture["source_candidate_sha256"], PUBLIC_CANDIDATE_SHA256)
        self.assertEqual(len(self.fixture["packages"]), 32)
        self.request = {"candidate_path": "/root/public32/candidate.json", "payload_directory": "/root/public32/direct",
                        "archive_directory": "/root/public32/archives", "reviewed_simulation_path": "/root/public32/reviewed.stdout",
                        "_path": "/root/public32/request.json", "_sha256": "a" * 64,
                        "_configuration": {"profile": "ubuntu-debconf-1.5.86ubuntu1",
                                           "path": "/root/public32/.apt-invocation-reference/apt.conf"}}
        self.plan = self.fixture["plan"].encode()
        self.request["reviewed_simulation_sha256"] = TX.digest(self.plan)
        with patch.object(TX, "read", return_value=(self.raw, ())), \
             patch.object(TX, "CANDIDATE_SHA256", TX.digest(self.raw)):
            self.inventory = TX.packages(self.request)
        fixed = {"Debug::NoLocking": "false", "pkgCacheFile::Generate": "true", "APT::Update": "false",
                 "APT::Get::Download-Only": "false", "APT::Get::Print-URIs": "false", "APT::Get::Simulate": "false",
                 "DPkg::Tools::Options::" + TX.HELPER + "::Version": "3",
                 "DPkg::Tools::Options::" + TX.HELPER + "::InfoFD": "0",
                 "DPkg::Tools::Options::/usr/sbin/dpkg-preconfigure::Version": "1",
                 "DPkg::Tools::Options::/usr/sbin/dpkg-preconfigure::InfoFD": "0",
                 "Dir::Cache::archives": self.request["archive_directory"], "DPkg::Path": TX.ENV["PATH"]}
        fixed.update(TX.invocation_paths(self.request))
        self.header = [apt_v3_quote_fixture(k, '=\"\n') + "=" + apt_v3_quote_fixture(v) for k,v in fixed.items() if v]
        literal_hooks = [TX.HELPER + " pre-install " + self.request["_path"] + " " + self.request["_sha256"],
                         "/usr/sbin/dpkg-preconfigure --apt || true"]
        self.hooks = ["DPkg::Pre-Install-Pkgs::=" + apt_v3_quote_fixture(value) for value in literal_hooks]
        self.header += self.hooks
        self.actions = []
        for line in self.fixture["plan"].splitlines():
            phase,name = line.split(" ",2)[:2]
            new = self.fixture["controls"][name]
            old = self.fixture["current_packages"].get(name,{})
            action = self.inventory[name]["archive_path"] if phase == "Inst" else "**CONFIGURE**"
            # Primary SendPkgsInfo prints action versions/paths RAW, not quoted.
            self.actions.append(" ".join((name,old.get("Version","-"),old.get("Architecture","-"),
                                          old.get("Multi-Arch","none"),"<",new["Version"],new["Architecture"],
                                          new.get("Multi-Arch","none"),action)))

    def wire(self, header=None, actions=None):
        return ("VERSION 3\n" + "\n".join(self.header if header is None else header) + "\n\n"
                + "\n".join(self.actions if actions is None else actions) + "\n").encode()

    def consume(self, raw):
        with patch.object(TX,"read",return_value=(self.plan,())), \
             patch.object(TX,"status_fields",return_value=("b"*64,self.fixture["current_packages"])), \
             patch.object(TX,"control",side_effect=lambda request,name,item:self.fixture["controls"][name]):
            TX.parse_hook(raw,self.request,self.inventory)

    def test_actual32_declared_paths_and_official_wire_contract(self):
        self.assertEqual(len(self.actions),64)
        self.assertIn("~git20240220", "\n".join(self.actions))
        self.assertIn("%20", self.hooks[0])
        self.assertIn("1:7.6-ubuntu24.04", "\n".join(self.actions))
        self.consume(self.wire())
        dependency_paths = {name:Path(item["path"]) for name,item in self.inventory.items() if name not in TX.DIRECT}
        self.assertEqual(len(dependency_paths),26)
        for name,path in dependency_paths.items():
            item = self.inventory[name]
            # Exact primary acquire-item.cc native filename algorithm. Actual
            # public deps have no epochs; their declared URL basename matches.
            native_name = (apt_v3_quote_fixture(name,"_:") + "_" + apt_v3_quote_fixture(item["version"],"_:")
                           + "_" + apt_v3_quote_fixture(item["architecture"],"_:.") + ".deb")
            self.assertEqual(path.parent,Path(self.request["archive_directory"]))
            self.assertEqual(path.name,native_name)
        cache_names = {Path(item["archive_path"]).name for item in self.inventory.values()}
        self.assertEqual(len(cache_names),32)
        for name in TX.DIRECT:
            item = self.inventory[name]
            self.assertEqual(Path(item["path"]).parent,Path(self.request["payload_directory"]))
            native_name = (apt_v3_quote_fixture(name,"_:") + "_" + apt_v3_quote_fixture(item["version"],"_:")
                           + "_" + apt_v3_quote_fixture(item["architecture"],"_:.") + ".deb")
            # --no-download needs all32 cache entries, including direct-six.
            self.assertIn(native_name,cache_names)
            self.assertEqual(Path(item["archive_path"]).name,native_name)

    def test_known_hook_raw_double_escape_scalar_duplicate_and_order_deny(self):
        prefix=self.header[:-2]
        variants=[prefix+[value.replace("%20"," ") for value in self.hooks],
                  prefix+[value.replace("%20","%2520") for value in self.hooks],
                  prefix+list(reversed(self.hooks)),prefix+self.hooks+[self.hooks[0]],
                  prefix+[self.hooks[0].replace("Pkgs::=","Pkgs="),self.hooks[1]],
                  prefix+[self.hooks[0].replace("=/usr","=%2fusr"),self.hooks[1]]]
        for header in variants:
            with self.subTest(header_sha=TX.digest("\n".join(header).encode())),self.assertRaises(TX.Denied):
                self.consume(self.wire(header=header))

    def test_declared_raw_action_paths_old_fields_order_and_completeness_deny(self):
        variants=[]
        changed=list(self.actions)
        index=next(i for i,row in enumerate(changed) if row.startswith("passt ") and not row.endswith("**CONFIGURE**"))
        changed[index]=changed[index].replace("~git","%7egit");variants.append(changed)
        changed=list(self.actions)
        index=next(i for i,row in enumerate(changed) if row.startswith("incus ") and not row.endswith("**CONFIGURE**"))
        fields=changed[index].split(" ");fields[-1]=self.inventory["incus"]["path"]
        changed[index]=" ".join(fields);variants.append(changed)
        changed=list(self.actions)
        changed[index]=changed[index].replace("6.0.0-1ubuntu0.3 amd64 none","6.0.0-1ubuntu0.3 arm64 none",1)
        variants.append(changed)
        indexes=[i for i,row in enumerate(self.actions) if not row.endswith("**CONFIGURE**")]
        changed=list(self.actions);changed[indexes[0]],changed[indexes[1]]=changed[indexes[1]],changed[indexes[0]]
        variants.append(changed);variants.append(self.actions[:-1])
        for actions in variants:
            with self.subTest(actions_sha=TX.digest("\n".join(actions).encode())),self.assertRaises(TX.Denied):
                self.consume(self.wire(actions=actions))



class SourceMixedPlanTests(unittest.TestCase):
    """Public package metadata observed on ciwkr01; APT remains modeled.

    The fresh Source observation has sixteen installed closure members. Fourteen
    already match; only the two Incus upgrades and sixteen absent members need
    work. No native acceptance is inferred from this fixture.
    """
    INSTALLED = (('aardvark-dns', '1.4.0-5', 'amd64'), ('buildah', '1.33.7+ds1-1ubuntu0.24.04.3', 'amd64'), ('catatonit', '0.1.7-1', 'amd64'), ('conmon', '2.1.10+ds1-1build2', 'amd64'), ('containernetworking-plugins', '1.1.1+ds1-3ubuntu0.24.04.3', 'amd64'), ('crun', '1.14.1-1', 'amd64'), ('fuse-overlayfs', '1.13-1', 'amd64'), ('golang-github-containers-common', '0.57.4+ds1-2ubuntu0.2', 'all'), ('golang-github-containers-image', '5.29.2-2', 'all'), ('incus', '6.0.0-1ubuntu0.3', 'amd64'), ('incus-client', '6.0.0-1ubuntu0.3', 'amd64'), ('libgpgme11t64', '1.18.0-4.1ubuntu4', 'amd64'), ('netavark', '1.4.0-4', 'amd64'), ('passt', '0.0~git20240220.1e6f92b-1', 'amd64'), ('podman', '4.9.3+ds1-1ubuntu0.2', 'amd64'), ('slirp4netns', '1.2.1-1build2', 'amd64'))
    wire = Source32ProducerTests.wire
    consume = Source32ProducerTests.consume

    def setUp(self):
        Source32ProducerTests.setUp(self)
        current = {name: {"Status": "install ok installed", "Version": version,
                         "Architecture": architecture}
                   for name, version, architecture in self.INSTALLED}
        unchanged = {name for name, prior in current.items()
                     if prior["Version"] == self.inventory[name]["version"]}
        self.assertEqual(len(unchanged), 14)
        self.fixture["current_packages"] = current
        self.plan = ("\n".join(line for line in self.fixture["plan"].splitlines()
                                if line.split(" ", 2)[1] not in unchanged) + "\n").encode()
        self.request["reviewed_simulation_sha256"] = TX.digest(self.plan)
        self.actions = []
        for line in self.plan.decode().splitlines():
            phase, name = line.split(" ", 2)[:2]
            new = self.fixture["controls"][name]
            prior = current.get(name, {})
            action = self.inventory[name]["archive_path"] if phase == "Inst" else "**CONFIGURE**"
            self.actions.append(" ".join((name, prior.get("Version", "-"),
                prior.get("Architecture", "-"), prior.get("Multi-Arch", "none"), "<",
                new["Version"], new["Architecture"], new.get("Multi-Arch", "none"), action)))

    def test_actual_current_metadata_requires_eighteen_changes_and_full32_closure(self):
        result = TX.parse_plan(self.plan, self.inventory, self.fixture["current_packages"])
        self.assertEqual(len(result["Inst"]), 18)
        self.assertEqual(len(result["Conf"]), 18)
        self.assertEqual(len(self.inventory), 32)
        self.assertFalse({"podman", "crun", "conmon"} & {row[0] for row in result["Inst"]})
        self.assertEqual({row[0]: row[1] for row in result["Inst"] if row[1]},
                         {"incus": "6.0.0-1ubuntu0.3", "incus-client": "6.0.0-1ubuntu0.3"})
        self.consume(self.wire())

    def test_missing_duplicate_unchanged_or_wrong_old_version_plan_denied(self):
        lines = self.plan.splitlines(keepends=True)
        variants = [b"".join(lines[1:]), self.plan + lines[0],
                    self.plan + b"Inst podman [4.9.3+ds1-1ubuntu0.2] (4.9.3+ds1-1ubuntu0.2 fixture [amd64])\n",
                    self.plan.replace(b"[6.0.0-1ubuntu0.3]", b"[5.0.0-foreign]", 1),
                    self.plan + b"Remv foreign [5]\n"]
        for raw in variants:
            with self.subTest(plan_sha=TX.digest(raw)), self.assertRaises(TX.Denied):
                TX.parse_plan(raw, self.inventory, self.fixture["current_packages"])

    def test_unchanged_or_missing_or_reordered_final_actions_denied(self):
        unchanged = "podman 4.9.3+ds1-1ubuntu0.2 amd64 none = 4.9.3+ds1-1ubuntu0.2 amd64 none "
        variants = [self.actions + [unchanged + self.inventory["podman"]["archive_path"]],
                    self.actions[:-1], [self.actions[1], self.actions[0], *self.actions[2:]]]
        for actions in variants:
            with self.subTest(actions_sha=TX.digest("\n".join(actions).encode())), self.assertRaises(TX.Denied):
                self.consume(self.wire(actions=actions))

    def test_newer_or_wrong_architecture_or_residual_state_denied(self):
        for prior, reason in (({"Status": "install ok installed", "Version": "9:99", "Architecture": "amd64"},
                               "plan-downgrade"),
                              ({"Status": "install ok installed", "Version": "6.0.0", "Architecture": "arm64"},
                               "plan-old-architecture-drift"),
                              ({"Status": "deinstall ok config-files", "Version": "6.0.0"},
                               "plan-old-package-state")):
            current = dict(self.fixture["current_packages"], incus=prior)
            with self.subTest(reason=reason), self.assertRaisesRegex(TX.Denied, reason):
                TX.parse_plan(self.plan, self.inventory, current)

    def test_debian_epoch_tilde_revision_and_numeric_order(self):
        pairs = [("6.0.0-1ubuntu0.3", "1:7.6-ubuntu24.04-202611021330"),
                 ("1.0~rc1", "1.0"), ("1.0~~", "1.0~"), ("1.0-9", "1.0-10"),
                 ("1.0-1ubuntu0.2", "1.0-1ubuntu0.12"), ("1.0a", "1.0+"),
                 ("1.0~git9", "1.0~git10"), ("0:9", "1:0"), ("1.0-1", "1.0-1+b1")]
        for first, second in pairs:
            with self.subTest(first=first, second=second):
                self.assertLess(TX.version_compare(first, second), 0)
                self.assertGreater(TX.version_compare(second, first), 0)
        for first, second in (("1.00", "1.0"), ("1.0", "1.0-0"), ("0:1.0", "1.0")):
            self.assertEqual(TX.version_compare(first, second), 0)


@unittest.skipUnless(os.geteuid() == 0, "Actual Root-owned private filesystem fixture required")
class RootPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="incus-package-proof-", dir="/var/lib")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        os.chmod(self.base, 0o700)
        self.payload = self.base / "direct"
        self.cache = self.base / "archives"
        self.lists = self.base / "lists"
        self.config = self.base / "apt"
        self.updates = self.base / "updates"
        for path in (self.payload, self.cache, self.lists, self.config, self.updates):
            path.mkdir(mode=0o700)
        self.sealed(self.lists / "Packages", b"signed fixture index")
        self.sealed(self.config / "policy", b"fixture config")
        self.status = self.base / "status"
        self.machine = self.base / "machine-id"
        self.extended = self.base / "extended_states"
        self.sealed(self.machine, ("a" * 32 + "\n").encode())
        self.sealed(self.extended, b"fixture auto states\n")
        self.sealed(self.status, b"Package: foreign\nVersion: 5\nStatus: install ok installed\nArchitecture: amd64\n\n")
        self.entries = []
        for index, name in enumerate((*TX.DIRECT, *("dependency-" + str(i) for i in range(26)))):
            version = "1.0-1"
            filename = TX.DIRECT_FILES[index] if index < 6 else name + "_1.0-1_amd64.deb"
            raw = ("synthetic .deb bytes " + name).encode()
            target = self.payload if index < 6 else self.cache
            self.sealed(target / filename, raw)
            if index < 6:
                self.sealed(self.cache / (name+"_1.0-1_amd64.deb"), raw)
            self.entries.append({"package": name, "version": version, "architecture": "amd64",
                                 "size": len(raw), "sha256": TX.digest(raw),
                                 "url": "https://archive.ubuntu.com/ubuntu/pool/fixture/" + filename})
        self.candidate = self.base / "candidate.json"
        self.sealed_json(self.candidate, {"schema": 1, "packages": self.entries})
        self.reviewed = self.base / "reviewed.stdout"
        self.plan = "".join(phase + " " + entry["package"] + " (1.0-1 fixture [amd64])\n"
                            for phase in ("Inst", "Conf") for entry in self.entries).encode()
        self.sealed(self.reviewed, self.plan)
        self.request_path = self.base / "request.json"
        self.request = {"schema": 2, "hostname": socket.gethostname(), "machine_id": "a" * 32,
                        "expires_at": int(time.time()) + 600, "candidate_path": str(self.candidate),
                        "payload_directory": str(self.payload), "archive_directory": str(self.cache),
                        "reviewed_simulation_path": str(self.reviewed),
                        "reviewed_simulation_sha256": TX.digest(self.plan),
                        "dpkg_status_sha256": TX.digest(self.status.read_bytes()),
                        "apt_lists_sha256": TX.tree_hash(str(self.lists)),
                        "apt_config_sha256": TX.tree_hash(str(self.config)),
                        "extended_states_sha256": TX.digest(self.extended.read_bytes()),
                        "apt_get_sha256": "b" * 64, "dpkg_deb_sha256": "c" * 64,
                        "apt_config_tool_sha256": "d" * 64, "apt_version": "apt fixture (amd64)"}
        self.commit_request()
        for name, value in (("STATUS", str(self.status)), ("MACHINE", str(self.machine)),
                            ("LISTS", str(self.lists)), ("CONFIG", str(self.config)),
                            ("EXTENDED", str(self.extended)),
                            ("UPDATES", str(self.updates)),
                            ("NATIVE_APT_SHA256", "b" * 64), ("NATIVE_APT_VERSION", "apt fixture (amd64)"),
                            ("CANDIDATE_SHA256", TX.digest(self.candidate.read_bytes()))):
            patcher = patch.object(TX, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.calls = []
        self.native_dump = b'APT::Architecture "amd64";\n'
        self.live_request = None
        self.effects = []
        self.drift_guard = False
        self.child_drift = False
        self.install_error = False
        self.skip_hook = False
        self.drift_plan = False
        patcher = patch.object(TX, "run", side_effect=self.modeled_native)
        self.native = patcher.start()
        self.addCleanup(patcher.stop)

    def sealed(self, path, raw):
        path.write_bytes(raw)
        os.chmod(path, 0o600)

    def sealed_json(self, path, value):
        self.sealed(path, (json.dumps(value, sort_keys=True) + "\n").encode())

    def commit_request(self):
        self.sealed_json(self.request_path, self.request)
        self.request_sha = TX.digest(self.request_path.read_bytes())

    def configured(self):
        names = {entry["package"] for entry in self.entries}
        paragraphs = self.status.read_text().split("\n\n")
        raw = "\n\n".join(paragraph for paragraph in paragraphs if paragraph.strip()
                            and not any(line == "Package: " + name for line in paragraph.splitlines()
                                        for name in names)).encode() + b"\n\n"
        raw += "".join("Package: " + entry["package"] + "\nVersion: 1.0-1\n"
                       "Status: install ok installed\nArchitecture: amd64\n\n" for entry in self.entries).encode()
        self.sealed(self.status, raw)

    def modeled_native(self, argv, tool_sha256, install=False, output_prefix=None, configuration=None):
        # Models native semantics only. No source-request injection or real APT.
        TX.configuration_env(configuration)
        self.calls.append((argv, install))
        if argv[0] == TX.DEB:
            inventory = TX.packages(self.request)
            name = next(name for name, item in inventory.items() if item["path"] == argv[2])
            return ("Package: " + name + "\nVersion: 1.0-1\nArchitecture: amd64\n").encode(), b""
        if argv[0] == TX.APT_CONFIG:
            if argv[1] == "shell":
                return self.config_shell_bytes(configuration), b""
            if configuration:
                return self.model_dump(configuration), b""
            return self.native_dump, b""
        if "--version" in argv:
            return b"apt fixture (amd64)\n", b""
        if "--simulate" in argv:
            return (self.plan.replace(b"dependency-25", b"foreign") if self.drift_plan else self.plan), b""
        self.assertTrue(install)
        self.assertEqual([value for value in argv if value.endswith(".deb")],
                         [str(self.payload / filename) for filename in TX.DIRECT_FILES])
        self.assertIn("--no-download", argv)
        self.assertIn("--no-remove", argv)
        if self.install_error:
            raise TX.Denied("modeled-uncertain-install")
        if not self.skip_hook:
            self.effects.append("guard-start")
            with patch.dict(os.environ, TX.configuration_env(configuration), clear=True):
                header = self.hook_bytes(configuration)
                if self.drift_guard:
                    header = header.replace(b"**CONFIGURE**", b"**REMOVE**", 1)
                TX.pre_install(str(self.request_path), self.request_sha, io.BytesIO(header))
            self.effects.append("guard-complete")
            if self.live_request["_configuration"]["profile"] != "guard-only":
                # Model exact protocol1 input, not execution of Perl/Debconf.
                paths = [item["archive_path"] for item in TX.packages(self.request).values()]
                self.debconf_input = ("\n".join(paths) + "\n").encode()
                self.effects.append("debconf-modeled")
        self.configured()
        return b"modeled native install", b""

    def ensure_configuration(self):
        if self.live_request is None:
            self.live_request = dict(self.request, _path=str(self.request_path), _sha256=self.request_sha)
            TX.compile_configuration(self.live_request, *TX.inherited_hooks(self.live_request))
        return self.live_request

    def model_dump(self, configuration):
        # Minimal independent flat APT grammar fixture, including its exact
        # list-clear behavior; never evaluate or execute any config text.
        rows = []
        for line in Path(configuration[0]).read_text().splitlines():
            if line == "#clear DPkg::Pre-Install-Pkgs;":
                rows = [(key, value) for key, value in rows
                        if not key.lower().startswith("dpkg::pre-install-pkgs")]
                continue
            match = re.fullmatch(r'([^ ]+) (".*");', line)
            if match:
                key, value = match[1], json.loads(match[2])
                if not key.endswith("::"):
                    rows = [(old_key, old_value) for old_key, old_value in rows if old_key.lower() != key.lower()]
                rows.append((key, value))
        raw = "".join(key + " " + json.dumps(value) + ";\n" for key, value in rows).encode()
        if self.child_drift:
            raw = raw.replace(b'Dir::Cache::pkgcache "";', b'Dir::Cache::pkgcache "/foreign/cache";')
        return raw

    def hook_bytes(self, configuration=None):
        if configuration:
            journal = json.loads(self.intent().read_bytes())
            self.live_request = dict(self.request, _path=str(self.request_path), _sha256=self.request_sha,
                                     _configuration=journal["configuration"])
        else:
            self.ensure_configuration()
            configuration = TX.configuration_tuple(self.live_request)
        inventory = TX.packages(self.request)
        header = "VERSION 3\n"
        for line in self.model_dump(configuration).decode().splitlines():
            match = re.fullmatch(r'([^ ]+) (".*");', line)
            key, value = match[1], json.loads(match[2])
            if value:
                header += apt_v3_quote_fixture(key, "=\"\n") + "=" + apt_v3_quote_fixture(value) + "\n"
        header += "APT::Get::Download-Only=false\nAPT::Get::Print-URIs=false\nAPT::Get::Simulate=false\n\n"
        actions = []
        _unused, current = TX.status_fields(inventory)
        for line in self.plan.decode().splitlines():
            phase, name = line.split(" ", 2)[:2]
            action = inventory[name]["archive_path"] if phase == "Inst" else "**CONFIGURE**"
            prior = current.get(name, {})
            actions.append(" ".join((name, prior.get("Version", "-"), prior.get("Architecture", "-"),
                prior.get("Multi-Arch", "none"), "<", "1.0-1", "amd64", "none", action)) + "\n")
        return (header + "".join(actions)).encode()

    def config_shell_bytes(self, configuration=None):
        values = {}
        raw = self.model_dump(configuration) if configuration else self.native_dump
        for line in raw.decode().splitlines():
            match = re.fullmatch(r'([^ ]+) (".*");', line)
            if match:
                values[match[1]] = json.loads(match[2])
        root = values.get("RootDir", "")
        update = values.get("APT::Update", "false").lower()
        update = "false" if update in ("", "false", "0", "no") else "true"
        paths = TX.standard_paths()
        paths.update({key: value for key, value in values.items() if key in paths})
        return ("ROOTDIR='" + root + "'\nUPDATE='" + update + "'\n"
                + "".join("K" + str(index) + "='" + value + "'\n"
                          for index, value in enumerate(paths.values()))).encode()

    def execute(self):
        return TX.execute(str(self.request_path), self.request_sha)

    def intent(self):
        return Path(str(self.request_path) + ".intent.json")

    def write_intent(self):
        self.ensure_configuration()
        inventory = TX.packages(self.request)
        identities = TX.verify_payloads(self.request, inventory)
        unused, request_stamp = TX.load_request(str(self.request_path), self.request_sha)
        TX.write_new(str(self.intent()), {"schema": 1, "state": "INSTALL_INTENT", "request_sha256": self.request_sha,
                                         "request_stamp": list(request_stamp),
                                         "configuration": self.live_request["_configuration"],
                                         "archives_sha256": TX.digest(json.dumps(identities, sort_keys=True).encode())})

    def run_guard(self, raw):
        request = self.ensure_configuration()
        with patch.dict(os.environ, TX.configuration_env(TX.configuration_tuple(request)), clear=True):
            TX.pre_install(str(self.request_path), self.request_sha, io.BytesIO(raw))

    def enable_debconf(self):
        # Real Root files/101-module inventory; synthetic hashes only. No Perl,
        # Debconf DB or real package manager is executed by this fixture.
        public = self.base / "public-debconf"
        public.mkdir(mode=0o700)
        self.root_home = self.base / "passwd-root-home"
        self.root_home.mkdir(mode=0o700)
        modules = self.base / "Debconf"
        modules.mkdir(mode=0o700)
        profile = {"schema": 1, "candidate_sha256": TX.CANDIDATE_SHA256, "hook_literal": TX.DEBCONF_HOOK,
                   "protocol": 1, "config_present_count": 0, "templates_present_count": 0,
                   "module_root": str(modules), "module_directories": [], "modules": {},
                   "public_files": {}, "packages": {}}
        for index, name in enumerate(("debconf.conf", "apt-extracttemplates", "dpkg-deb", "perl", "dpkg-preconfigure")):
            target = public / name
            content = ("isolated public fixture " + str(index)).encode()
            self.sealed(target, content)
            target.chmod(0o700)
            links = 2 if name == "perl" else 1
            if links == 2:
                os.link(target, public / "known-perl-hardlink")
            profile["public_files"][str(target)] = {"size": len(content), "sha256": TX.digest(content), "links": links}
        for index in range(101):
            name = "Module" + str(index) + ".pm"
            raw = ("isolated Perl module " + str(index)).encode()
            self.sealed(modules / name, raw)
            profile["modules"][name] = {"size": len(raw), "sha256": TX.digest(raw)}
        status = self.status.read_bytes()
        for name in ("debconf", "debconf-i18n", "apt-utils", "dpkg", "perl", "perl-base"):
            profile["packages"][name] = {"version": "fixture-1", "architecture": "all"}
            status += ("Package: " + name + "\nVersion: fixture-1\nStatus: install ok installed\nArchitecture: all\n\n").encode()
        self.sealed(self.status, status)
        self.request["dpkg_status_sha256"] = TX.digest(status)
        self.commit_request()
        self.debconf_profile_path = self.base / "debconf-profile.json"
        self.sealed_json(self.debconf_profile_path, profile)
        for key, value in (("DEBCONF_PROFILE", str(self.debconf_profile_path)),
                           ("DEBCONF_PROFILE_SHA256", TX.digest(self.debconf_profile_path.read_bytes()))):
            patcher = patch.object(TX, key, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(TX.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(self.root_home)))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.native_dump += ('DPkg::Pre-Install-Pkgs "";\nDPkg::Pre-Install-Pkgs:: "'
                             + TX.DEBCONF_HOOK + '";\n').encode()
        self.synthetic_profile = profile

    def test_actual_public32_paths_use_private_fd_reads_and_keep_closed32_cache(self):
        raw=SOURCE32_FIXTURE.read_bytes();fixture=json.loads(raw)
        self.assertEqual(fixture["source_candidate_sha256"],PUBLIC_CANDIDATE_SHA256)
        parent=self.base/"actual32";parent.mkdir(mode=0o700)
        direct=parent/"direct";cache=parent/"archives"
        direct.mkdir(mode=0o700);cache.mkdir(mode=0o700)
        candidate=parent/"candidate.json";self.sealed(candidate,raw)
        request=dict(self.request,candidate_path=str(candidate),payload_directory=str(direct),archive_directory=str(cache))
        with patch.object(TX,"CANDIDATE_SHA256",TX.digest(raw)):
            inventory=TX.packages(request)
        for name,item in inventory.items():
            content=("path-fixture:"+name).encode()
            self.sealed(Path(item["path"]),content)
            if item["archive_path"]!=item["path"]:self.sealed(Path(item["archive_path"]),content)
            observed,identity=TX.read(item["path"],private=True)
            self.assertEqual(observed,content)
            self.assertEqual(identity[2],0);self.assertEqual(identity[5],1)
        self.assertEqual(len(list(cache.iterdir())),32)
        self.assertEqual(len(list(direct.iterdir())),6)
        passt=Path(inventory["passt"]["path"])
        self.assertIn("~git20240220",passt.name)
        for path in (str(parent/"bad~ancestor"/passt.name),str(parent)+"/archives/../candidate.json","~/candidate.json"):
            with self.subTest(path=path),self.assertRaises(TX.Denied):TX.read(path,private=True)
        alias=parent/"linked~.deb";alias.symlink_to(passt)
        with self.assertRaises((TX.Denied,OSError)):TX.read(str(alias),private=True)
        alias.unlink();os.link(passt,alias)
        with self.assertRaises(TX.Denied):TX.read(str(passt),private=True)

    def test_real_rootfs_once_install_and_verified_idempotence(self):
        original = {path: path.read_bytes() for path in (*self.payload.iterdir(), *self.cache.iterdir())}
        first = self.execute()
        self.assertTrue(first["changed"])
        self.assertFalse(first["operating_acceptance"])
        self.assertEqual(json.loads(self.intent().read_bytes())["state"], "PACKAGE_STATE_VERIFIED")
        self.assertFalse(self.execute()["changed"])
        self.assertEqual(sum(install for unused, install in self.calls), 1)
        self.assertEqual(original, {path: path.read_bytes() for path in original})

    def partial_installed_state(self):
        installed = {"podman", "crun", "conmon", "dependency-0"}
        raw = self.status.read_bytes() + "".join(
            "Package: " + name + "\nVersion: 1.0-1\nStatus: install ok installed\nArchitecture: amd64\n\n"
            for name in sorted(installed)).encode()
        self.sealed(self.status, raw)
        self.plan = b"".join(line for line in self.plan.splitlines(keepends=True)
                             if line.split()[1].decode() not in installed)
        self.sealed(self.reviewed, self.plan)
        self.request.update(dpkg_status_sha256=TX.digest(raw), reviewed_simulation_sha256=TX.digest(self.plan))
        self.commit_request()

    def test_partial_installed_closure_one_effect_final_all32_and_readonly_reentry(self):
        self.partial_installed_state()
        self.assertTrue(self.execute()["changed"])
        self.assertTrue(TX.state(TX.packages(self.request))[1])
        self.assertFalse(self.execute()["changed"])
        self.assertEqual(sum(install for unused, install in self.calls), 1)

    def test_partial_unknown_install_outcome_never_replays(self):
        self.partial_installed_state(); self.install_error = True
        with self.assertRaisesRegex(TX.Denied, "modeled-uncertain-install"):
            self.execute()
        self.configured()
        with self.assertRaisesRegex(TX.Denied, "prior-install-requires-reconciliation"):
            self.execute()
        self.assertEqual(sum(install for unused, install in self.calls), 1)

    def test_unknown_intent_holds_even_after_all32_now_match(self):
        self.install_error = True
        with self.assertRaisesRegex(TX.Denied, "modeled-uncertain-install"):
            self.execute()
        self.configured()
        with self.assertRaisesRegex(TX.Denied, "prior-install-requires-reconciliation"):
            self.execute()
        self.assertEqual(sum(install for unused, install in self.calls), 1)
        self.assertEqual(json.loads(self.intent().read_bytes())["state"], "INSTALL_INTENT")

    def test_unrelated_exact_configured_state_is_readonly_not_operating_pass(self):
        self.configured()
        result = self.execute()
        self.assertEqual(result["state"], "ALREADY_CONFIGURED_READONLY")
        self.assertFalse(result["operating_acceptance"])
        self.assertFalse(self.intent().exists())
        self.assertEqual(self.calls, [])

    def test_missing_final_hook_keeps_install_intent_despite_versions_matching(self):
        self.skip_hook = True
        with self.assertRaises(FileNotFoundError):
            self.execute()
        self.assertEqual(json.loads(self.intent().read_bytes())["state"], "INSTALL_INTENT")
        with self.assertRaisesRegex(TX.Denied, "prior-install-requires-reconciliation"):
            self.execute()

    def test_changed_status_lists_config_or_auto_state_denies_before_install(self):
        for path in (self.status, self.lists / "Packages", self.config / "policy", self.extended):
            with self.subTest(path=path):
                before = path.read_bytes()
                self.sealed(path, before + b"changed")
                with self.assertRaises(TX.Denied):
                    self.execute()
                self.sealed(path, before)
                self.assertFalse(self.intent().exists())
        self.assertFalse(any(install for unused, install in self.calls))

    def test_digest_candidate_and_extra_request_field_denied(self):
        with self.assertRaisesRegex(TX.Denied, "request-digest"):
            TX.execute(str(self.request_path), "f" * 64)
        self.request["extra_args"] = ["--force-yes"]
        self.commit_request()
        with self.assertRaisesRegex(TX.Denied, "request-schema"):
            self.execute()
        self.assertFalse(self.intent().exists())

    def test_expired_request_denied(self):
        self.request["expires_at"] = int(time.time()) - 1
        self.commit_request()
        with self.assertRaisesRegex(TX.Denied, "request-expiry"):
            self.execute()

    def test_wrong_machine_or_hostname_denied(self):
        for key in ("machine_id", "hostname"):
            with self.subTest(key=key):
                old = self.request[key]
                self.request[key] = "b" * 32
                self.commit_request()
                with self.assertRaisesRegex(TX.Denied, "native-target"):
                    self.execute()
                self.request[key] = old
        self.commit_request()

    def test_payload_wrong_bytes_symlink_and_extra_cache_entry_deny(self):
        path = self.cache / "dependency-0_1.0-1_amd64.deb"
        original = path.read_bytes()
        self.sealed(path, b"wrong")
        with self.assertRaisesRegex(TX.Denied, "payload-byte-binding"):
            self.execute()
        path.unlink()
        path.symlink_to(self.machine)
        with self.assertRaises(OSError):
            self.execute()
        path.unlink()
        self.sealed(path, original)
        self.sealed(self.cache / "unreviewed.deb", b"unreviewed")
        with self.assertRaisesRegex(TX.Denied, "payload-directory-inventory"):
            self.execute()
        self.assertFalse(self.intent().exists())

    def test_group_writable_or_hardlinked_request_deny(self):
        os.chmod(self.request_path, 0o620)
        with self.assertRaisesRegex(TX.Denied, "root-regular-file"):
            self.execute()
        os.chmod(self.request_path, 0o600)
        os.link(self.request_path, self.base / "linked-request")
        with self.assertRaisesRegex(TX.Denied, "root-regular-file"):
            self.execute()

    def test_shell_metacharacter_in_request_filename_denied(self):
        path = self.base / "request;not-a-command.json"
        self.sealed(path, self.request_path.read_bytes())
        with self.assertRaisesRegex(TX.Denied, "canonical-root-file-path"):
            TX.execute(str(path), self.request_sha)

    def test_full_plan_drift_denies_before_intent(self):
        self.drift_plan = True
        with self.assertRaisesRegex(TX.Denied, "plan-package-drift"):
            self.execute()
        self.assertFalse(self.intent().exists())

    def test_plan_missing_duplicate_removal_and_other_architecture_deny(self):
        inventory = TX.packages(self.request)
        for raw in (self.plan.replace(b"Inst dependency-25 (1.0-1 fixture [amd64])\n", b""),
                    self.plan + b"Inst incus (1.0-1 fixture [amd64])\n",
                    self.plan + b"Remv foreign [5]\n",
                    self.plan.replace(b"[amd64]", b"[arm64]", 1)):
            with self.subTest(raw=raw[:30]), self.assertRaises(TX.Denied):
                TX.parse_plan(raw, inventory)

    def test_simulation_uses_same_cache_but_no_download_only_on_install(self):
        request = self.ensure_configuration()
        inventory = TX.packages(request)
        simulate, install = TX.argv(request, inventory, True), TX.argv(request, inventory, False)
        self.assertNotIn("--no-download", simulate)
        self.assertIn("--no-download", install)
        self.assertIn("Dir::Cache::archives=" + str(self.cache), simulate)
        self.assertIn("Dir::Cache::archives=" + str(self.cache), install)
        self.assertEqual(sum(arg.endswith(".deb") for arg in simulate), 6)
        self.assertEqual(sum(arg.endswith(".deb") for arg in install), 6)
        self.assertFalse(any(arg.startswith("DPkg::Pre-Install-Pkgs") for arg in install))
        self.assertIn(TX.guard_command(request), Path(request["_configuration"]["path"]).read_text())

    def test_hook_rejects_unknown_protocol_missing_extra_and_duplicate_paths(self):
        self.write_intent()
        valid = self.hook_bytes()
        actions = valid.split(b"\n\n", 1)[1].splitlines(keepends=True)
        for raw in (valid.replace(b"VERSION 3", b"VERSION 1", 1),
                    valid[:-len(actions[-1])], valid + actions[0],
                    valid.replace(actions[-1], actions[0]),
                    valid.replace(b"**CONFIGURE**", b"**REMOVE**", 1),
                    valid.replace(b"**CONFIGURE**", b"**ERROR**", 1),
                    valid.replace(b"< 1.0-1 amd64 none", b"< 1.0-2 amd64 none", 1),
                    valid.replace(b"< 1.0-1 amd64 none", b"< 1.0-1 arm64 none", 1)):
            with self.subTest(raw=raw[:20]), self.assertRaises(TX.Denied):
                self.run_guard(raw)
        self.assertFalse(Path(str(self.request_path) + ".hook.json").exists())

    def test_pending_updates_and_unconfigured_or_trigger_state_deny(self):
        self.sealed(self.updates / "0000", b"pending status update")
        with self.assertRaisesRegex(TX.Denied, "pending-dpkg-updates"):
            self.execute()
        (self.updates / "0000").unlink()
        original = self.status.read_bytes()
        for raw in (original.replace(b"install ok installed", b"install ok half-configured"),
                    original + b"Triggers-Pending: ldconfig\n"):
            self.sealed(self.status, raw)
            self.request["dpkg_status_sha256"] = TX.digest(raw)
            self.commit_request()
            with self.assertRaises(TX.Denied):
                self.execute()
        self.assertFalse(self.intent().exists())

    def test_v3_old_version_architecture_and_multiarch_are_bound(self):
        old = b"Package: incus\nVersion: 0.9-1\nStatus: install ok installed\nArchitecture: amd64\nMulti-Arch: foreign\n\n"
        self.sealed(self.status, self.status.read_bytes() + old)
        self.request["dpkg_status_sha256"] = TX.digest(self.status.read_bytes())
        self.plan = self.plan.replace(b"Inst incus (", b"Inst incus [0.9-1] (")
        self.sealed(self.reviewed, self.plan)
        self.request["reviewed_simulation_sha256"] = TX.digest(self.plan)
        self.commit_request()
        raw = self.hook_bytes().replace(b"incus - - none <", b"incus 0.9-1 amd64 foreign <")
        inventory = TX.packages(self.request)
        TX.parse_hook(raw, self.ensure_configuration(), inventory)
        for altered in (raw.replace(b"incus 0.9-1 amd64 foreign", b"incus 0.8-1 amd64 foreign", 1),
                        raw.replace(b"incus 0.9-1 amd64 foreign", b"incus 0.9-1 arm64 foreign", 1),
                        raw.replace(b"incus 0.9-1 amd64 foreign", b"incus 0.9-1 amd64 none", 1),
                        raw.replace(b"< 1.0-1", b"> 1.0-1", 1)):
            with self.assertRaises(TX.Denied):
                TX.parse_hook(altered, self.ensure_configuration(), inventory)

    def test_apt_partial_is_empty_administrative_state_never_a_payload(self):
        partial = self.cache / "partial"
        partial.mkdir(mode=0o700)
        TX.verify_payloads(self.request, TX.packages(self.request))
        self.sealed(partial / "unreviewed.deb", b"not an archive input")
        with self.assertRaisesRegex(TX.Denied, "apt-auxiliary-not-empty-or-owned"):
            TX.verify_payloads(self.request, TX.packages(self.request))

    def test_missing_direct_cache_copy_cannot_reach_install(self):
        (self.cache / "incus_1.0-1_amd64.deb").unlink()
        with self.assertRaises((TX.Denied, OSError)):
            self.execute()
        self.assertFalse(self.intent().exists())
        self.assertFalse(any(install for unused, install in self.calls))

    def test_direct_cache_copy_must_match_authenticated_source_bytes(self):
        self.sealed(self.cache / "incus_1.0-1_amd64.deb", b"different bytes")
        with self.assertRaisesRegex(TX.Denied, "payload-byte-binding"):
            self.execute()
        self.assertFalse(self.intent().exists())
        self.assertFalse(any(install for unused, install in self.calls))

    def test_schema1_cannot_reuse_the_old_cache_contract(self):
        self.request["schema"] = 1
        self.commit_request()
        with self.assertRaisesRegex(TX.Denied, "request-schema"):
            TX.load_request(str(self.request_path), self.request_sha)

    def test_config_header_is_not_retained_in_hook_receipt(self):
        self.write_intent()
        raw = self.hook_bytes().replace(b"\n\n", b"\nPrivate::Fixture=never-export-this-value\n\n", 1)
        self.run_guard(raw)
        receipt = Path(str(self.request_path) + ".hook.json").read_bytes()
        self.assertNotIn(b"never-export-this-value", receipt)
        self.assertNotIn(b"Private::Fixture", receipt)

    def test_same_bytes_new_archive_inode_after_intent_is_not_adopted(self):
        self.write_intent()
        target = self.cache / "dependency-0_1.0-1_amd64.deb"
        original = target.read_bytes()
        replacement = self.base / "replacement.deb"
        self.sealed(replacement, original)
        os.replace(replacement, target)
        with self.assertRaisesRegex(TX.Denied, "hook-original-archive-inode-drift"):
            self.run_guard(self.hook_bytes())
        self.assertFalse(Path(str(self.request_path) + ".hook.json").exists())

    def test_critical_header_keys_are_case_insensitive_and_unique(self):
        inventory = TX.packages(self.request)
        raw = self.hook_bytes().replace(b"Debug::NoLocking", b"debug::nolocking")
        TX.parse_hook(raw, self.ensure_configuration(), inventory)
        raw = raw.replace(b"\n\n", b"\nDEBUG::NOLOCKING=false\n\n", 1)
        with self.assertRaisesRegex(TX.Denied, "hook-fixed-configuration"):
            TX.parse_hook(raw, self.ensure_configuration(), inventory)

    def test_hook_status_race_denies_and_cannot_repeat_hook(self):
        self.write_intent()
        stdin = self.hook_bytes()
        original = self.status.read_bytes()
        self.sealed(self.status, original + b"foreign package change\n")
        with self.assertRaisesRegex(TX.Denied, "reviewed-dpkg-state-drift"):
            self.run_guard(stdin)
        self.sealed(self.status, original)
        self.run_guard(stdin)
        with self.assertRaises(FileExistsError):
            self.run_guard(stdin)

    def test_inherited_pre_hooks_are_refused_not_cleared(self):
        for raw in (b'DPkg::Pre-Invoke:: "host-command";\n',
                    b'DPkg::Pre-Install-Pkgs:: "/usr/sbin/dpkg-preconfigure --apt || false";\n'):
            with patch.object(TX, "run", return_value=(raw, b"")):
                with self.assertRaisesRegex(TX.Denied, "unsupported-inherited-pre-hook"):
                    TX.inherited_hooks(self.request)

    def test_real_fixed_executable_pinning_and_bounded_child(self):
        # Actual executable in a dedicated Root exec tmpfs; never a package tool.
        tool = Path("/usr/libexec/lightning-it/incus-maintenance") / ("fixture-" + self.base.name)
        self.addCleanup(lambda: tool.unlink(missing_ok=True))
        tool.write_text("#!/usr/bin/python3\nprint('bounded real child')\n")
        tool.chmod(0o700)
        pinned = TX.digest(tool.read_bytes())
        with patch.object(TX, "APT", str(tool)), patch.object(TX, "run", REAL_RUN):
            output, error = TX.run([str(tool)], pinned)
            self.assertEqual(output, b"bounded real child\n")
            self.assertEqual(error, b"")
            with self.assertRaisesRegex(TX.Denied, "tool-digest"):
                TX.run([str(tool)], "f" * 64)

    def test_real_install_child_capture_fault_waits_for_original_terminal(self):
        tool = Path("/usr/libexec/lightning-it/incus-maintenance") / ("fault-" + self.base.name)
        self.addCleanup(lambda: tool.unlink(missing_ok=True))
        tool.write_text("#!/usr/bin/python3 -IB\nimport os,sys,time\n"
                        "os.write(1,b'first output\\n')\ntime.sleep(0.1)\n"
                        "for i in range(12):\n os.write(1,b'x'*65536)\n os.write(2,b'y'*65536)\n"
                        "time.sleep(0.1)\nopen(sys.argv[1],'w').write('original child reached terminal')\n")
        tool.chmod(0o700)
        pinned = TX.digest(tool.read_bytes())
        original_write, original_read, original_popen = os.write, os.read, subprocess.Popen
        for fault in ("capture-enospc", "pipe-read", "selector-register"):
            with self.subTest(fault=fault):
                marker = self.base / (fault + ".terminal")
                prefix = str(self.base / fault)
                children = []
                injected = []
                def popen(*args, **kwargs):
                    child = original_popen(*args, **kwargs)
                    children.append(child)
                    return child
                def write(fd, raw):
                    if not injected and stat.S_ISREG(os.fstat(fd).st_mode):
                        injected.append(True)
                        raise OSError(errno.ENOSPC, "synthetic capture full")
                    return original_write(fd, raw)
                def read(fd, size):
                    if children and not injected and stat.S_ISFIFO(os.fstat(fd).st_mode):
                        injected.append(True)
                        raise OSError(errno.EIO, "synthetic pipe capture fault")
                    return original_read(fd, size)
                selector = Mock()
                selector.register.side_effect = OSError(errno.EIO, "synthetic selector fault")
                with patch.object(TX, "APT", str(tool)), patch.object(TX, "run", REAL_RUN), \
                        patch.object(TX.subprocess, "Popen", side_effect=popen), \
                        patch.object(TX.os, "write", side_effect=write if fault == "capture-enospc" else original_write), \
                        patch.object(TX.os, "read", side_effect=read if fault == "pipe-read" else original_read):
                    if fault == "selector-register":
                        with patch.object(TX.selectors, "DefaultSelector", return_value=selector):
                            with self.assertRaises(OSError):
                                TX.run([str(tool), str(marker)], pinned, install=True, output_prefix=prefix)
                    else:
                        with self.assertRaises(OSError):
                            TX.run([str(tool), str(marker)], pinned, install=True, output_prefix=prefix)
                self.assertEqual(len(children), 1)
                self.assertEqual(children[0].poll(), 0)
                self.assertEqual(marker.read_text(), "original child reached terminal")
                self.assertTrue(all(pipe.closed for pipe in (children[0].stdout, children[0].stderr)))
                self.assertTrue(injected or fault == "selector-register")

    def test_real_install_child_partial_capture_writes_are_completed(self):
        tool = Path("/usr/libexec/lightning-it/incus-maintenance") / ("partial-" + self.base.name)
        self.addCleanup(lambda: tool.unlink(missing_ok=True))
        tool.write_text("#!/usr/bin/python3 -IB\nimport os\nos.write(1,b'complete capture bytes')\n")
        tool.chmod(0o700)
        pinned = TX.digest(tool.read_bytes())
        original_write = os.write
        def partial_write(fd, raw):
            return original_write(fd, raw[:max(1, len(raw) // 2)])
        prefix = str(self.base / "partial-log")
        with patch.object(TX, "APT", str(tool)), patch.object(TX, "run", REAL_RUN), \
                patch.object(TX.os, "write", side_effect=partial_write):
            output, unused = TX.run([str(tool)], pinned, install=True, output_prefix=prefix)
        self.assertEqual(output, b"complete capture bytes")
        self.assertEqual(Path(prefix + ".stdout").read_bytes(), output)

    def test_rootdir_and_nonstandard_effective_paths_are_denied(self):
        normal = self.config_shell_bytes()
        status_label = "K" + str(list(TX.standard_paths()).index("Dir::State::status"))
        for raw in (normal.replace(b"ROOTDIR=''", b"ROOTDIR='/foreign-root'"),
                    normal.replace((status_label + "='" + TX.STATUS + "'").encode(),
                                   (status_label + "='/foreign/status'").encode())):
            with patch.object(TX, "run", return_value=(raw, b"")):
                with self.assertRaises(TX.Denied):
                    TX.effective_paths(self.request)
        with patch.object(TX, "run", return_value=(normal, b"")):
            TX.effective_paths(self.request)

    def test_actual_header_rejects_root_and_dpkg_redirects(self):
        inventory = TX.packages(self.request)
        for raw in (self.hook_bytes().replace(b"\n\n", b"\nRootDir=/foreign-root\n\n", 1),
                    self.hook_bytes().replace(b"\n\n", b"\nDPkg::Options::=--admindir=/foreign\n\n", 1),
                    self.hook_bytes().replace(("Dir::State::status=" + TX.STATUS).encode(),
                                             b"Dir::State::status=/foreign/status"),
                    self.hook_bytes().replace(b"Dir::Bin::dpkg=/usr/bin/dpkg", b"Dir::Bin::dpkg=/foreign/dpkg")):
            with self.assertRaises(TX.Denied):
                TX.parse_hook(raw, self.ensure_configuration(), inventory)

    def test_inherited_dpkg_options_or_path_are_never_cleared(self):
        for raw in (b'DPkg::Options:: "--root=/foreign";\n', b'DPkg::Path "/foreign/bin";\n'):
            with patch.object(TX, "run", return_value=(raw, b"")):
                with self.assertRaises(TX.Denied):
                    TX.inherited_hooks(self.request)

    def test_hook_locking_and_shortcut_config_must_match_fixed_values(self):
        inventory = TX.packages(self.request)
        for raw in (self.hook_bytes().replace(b"Debug::NoLocking=false", b"Debug::NoLocking=true"),
                    self.hook_bytes().replace(b"APT::Get::Download-Only=false", b"APT::Get::Download-Only=true"),
                    self.hook_bytes().replace(b"APT::Get::Simulate=false\n", b""),
                    self.hook_bytes().replace(b"InfoFD=0", b"InfoFD=3")):
            with self.subTest(raw=raw[:30]), self.assertRaisesRegex(TX.Denied, "hook-fixed-configuration"):
                TX.parse_hook(raw, self.ensure_configuration(), inventory)

    def test_qualified_debconf_once_after_guard_uses_plain_protocol1_input(self):
        self.enable_debconf()
        self.assertTrue(self.execute()["changed"])
        self.assertEqual(self.effects, ["guard-start", "guard-complete", "debconf-modeled"])
        self.assertEqual(len(self.debconf_input.splitlines()), 32)
        self.assertTrue(all(line.startswith(b"/") for line in self.debconf_input.splitlines()))
        self.assertNotIn(b"VERSION", self.debconf_input)
        request = self.live_request
        compiled = self.model_dump(TX.configuration_tuple(request)).decode()
        hook_lines = [line for line in compiled.splitlines() if line.startswith("DPkg::Pre-Install-Pkgs:: ")]
        self.assertEqual(len(hook_lines), 2)
        self.assertIn(TX.guard_command(request), hook_lines[0])
        self.assertIn(TX.DEBCONF_HOOK, hook_lines[1])
        self.assertIn('::/usr/sbin/dpkg-preconfigure::Version "1";', compiled)
        self.assertIn('::/usr/sbin/dpkg-preconfigure::InfoFD "0";', compiled)
        self.assertFalse(self.execute()["changed"])
        self.assertEqual(self.effects.count("debconf-modeled"), 1)

    def test_guard_failure_never_reaches_modeled_debconf(self):
        self.enable_debconf()
        self.drift_guard = True
        with self.assertRaises(TX.Denied):
            self.execute()
        self.assertEqual(self.effects, ["guard-start"])
        self.assertEqual(json.loads(self.intent().read_bytes())["state"], "INSTALL_INTENT")

    def test_unknown_duplicate_and_wrong_protocol_debconf_are_denied(self):
        literal = ('DPkg::Pre-Install-Pkgs:: "' + TX.DEBCONF_HOOK + '";\n').encode()
        for raw in (literal + literal,
                    literal + b'DPkg::Tools::Options::/usr/sbin/dpkg-preconfigure::Version "3";\n',
                    literal + b'DPkg::Tools::Options::/usr/sbin/dpkg-preconfigure::InfoFD "2";\n',
                    literal + b'DPkg::Pre-Install-Pkgs:: "/foreign/script";\n'):
            self.native_dump = raw
            with self.assertRaises(TX.Denied):
                TX.inherited_hooks(self.request)

    def test_passwd_root_debconfrc_even_dangling_is_denied_without_reading_it(self):
        self.enable_debconf()
        target = self.root_home / ".debconfrc"
        target.symlink_to(self.base / "nonexistent")
        with self.assertRaisesRegex(TX.Denied, "root-debconfrc-present"):
            TX.inherited_hooks(self.request)
        self.assertFalse(self.intent().exists())

    def test_fixed_public_profile_module_and_script_drift_deny(self):
        self.enable_debconf()
        TX.verify_debconf_profile()
        module = Path(self.synthetic_profile["module_root"]) / "Module0.pm"
        original = module.read_bytes()
        self.sealed(module, b"mutated module")
        with self.assertRaisesRegex(TX.Denied, "debconf-module-drift"):
            TX.verify_debconf_profile()
        self.sealed(module, original)
        public = Path(next(iter(self.synthetic_profile["public_files"])))
        original_public = public.read_bytes()
        self.sealed(public, b"\x00" + original_public[1:])
        self.assertEqual(public.stat().st_size, len(original_public))
        with self.assertRaisesRegex(TX.Denied, "debconf-public-file-drift"):
            TX.verify_debconf_profile()

    def test_real_large_public_perl_exact_size_hash_and_two_links(self):
        self.enable_debconf()
        perl = next(Path(path) for path in self.synthetic_profile["public_files"] if path.endswith("/perl"))
        raw = b"\x7fELF" + b"x" * (4023408 - 4)
        self.sealed(perl, raw)
        perl.chmod(0o700)
        self.assertGreater(perl.stat().st_size, TX.LIMIT)
        self.assertEqual(perl.stat().st_nlink, 2)
        self.synthetic_profile["public_files"][str(perl)].update(size=len(raw), sha256=TX.digest(raw))
        self.sealed_json(self.debconf_profile_path, self.synthetic_profile)
        with patch.object(TX, "DEBCONF_PROFILE_SHA256", TX.digest(self.debconf_profile_path.read_bytes())):
            self.assertRegex(TX.verify_debconf_profile(), r"^[0-9a-f]{64}$")
            with perl.open("ab") as stream:
                stream.write(b"extra")
            with self.assertRaisesRegex(TX.Denied, "root-regular-file"):
                TX.verify_debconf_profile()
            self.sealed(perl, b"\x7fELF" + b"y" * (len(raw) - 4))
            perl.chmod(0o700)
            with self.assertRaisesRegex(TX.Denied, "debconf-public-file-drift"):
                TX.verify_debconf_profile()
        self.assertEqual(TX.LIMIT, 2 * 1024 * 1024)

    def test_authenticated_public_size_still_has_an_absolute_hard_ceiling(self):
        self.enable_debconf()
        perl = next(path for path in self.synthetic_profile["public_files"] if path.endswith("/perl"))
        self.synthetic_profile["public_files"][perl]["size"] = 32 * 1024 * 1024 + 1
        self.sealed_json(self.debconf_profile_path, self.synthetic_profile)
        with patch.object(TX, "DEBCONF_PROFILE_SHA256", TX.digest(self.debconf_profile_path.read_bytes())):
            with self.assertRaisesRegex(TX.Denied, "debconf-public-file-size-bound"):
                TX.verify_debconf_profile()

    def test_compiled_config_mutation_replacement_and_extra_parts_deny(self):
        request = self.ensure_configuration()
        value = request["_configuration"]
        path = Path(value["path"])
        original = path.read_bytes()
        self.sealed(path, original + b"changed")
        with self.assertRaisesRegex(TX.Denied, "private-config-drift"):
            TX.attach_configuration(request, value)
        replacement = self.base / "replacement-config"
        self.sealed(replacement, original)
        os.replace(replacement, path)
        with self.assertRaisesRegex(TX.Denied, "private-config-drift"):
            TX.attach_configuration(request, value)

    def test_env_only_child_profile_drift_stops_before_install_intent(self):
        self.child_drift = True
        with self.assertRaisesRegex(TX.Denied, "child-common-profile-drift"):
            self.execute()
        self.assertFalse(self.intent().exists())
        self.assertFalse(any(install for unused, install in self.calls))

    def test_update_empty_root_and_inactive_children_are_not_update_true(self):
        self.native_dump = b'APT::Update "";\nAPT::Update::Post-Invoke:: "inactive fixture command";\n'
        TX.inherited_hooks(self.request)
        self.native_dump = b'APT::Update "true";\n'
        with self.assertRaisesRegex(TX.Denied, "unsupported-update-root"):
            TX.inherited_hooks(self.request)

    def test_common_private_config_no_simulate_false_or_runtime_binary_and_clean_env(self):
        self.native_dump += b'Binary "apt-config";\nCommandLine::AsString "apt-config dump";\n'
        request = self.ensure_configuration()
        raw = Path(request["_configuration"]["path"]).read_text()
        self.assertNotIn('Binary "apt-config"', raw)
        self.assertNotIn("CommandLine::AsString", raw)
        self.assertNotIn('APT::Get::Simulate "false"', raw)
        self.assertIn('Dir::Cache::pkgcache "";', raw)
        self.assertIn('Dir::Cache::srcpkgcache "";', raw)
        with patch.dict(os.environ, {"PERL5OPT": "unsafe", "DEBCONF_SYSTEMRC": "/foreign", "DPKG_ROOT": "/foreign"}):
            environment = TX.configuration_env(TX.configuration_tuple(request))
        self.assertEqual(environment["APT_CONFIG"], request["_configuration"]["path"])
        self.assertFalse(any(key.startswith(("PERL", "DEBCONF_", "DPKG_")) for key in environment))

    def test_future_binary_specific_profiles_are_not_inherited(self):
        for binary in ("apt-get", "apt-extracttemplates", "apt-config"):
            self.native_dump = ('Binary::' + binary + '::Dir::State::status "/foreign/status";\n').encode()
            with self.assertRaisesRegex(TX.Denied, "unsupported-binary-specific-configuration"):
                TX.inherited_hooks(self.request)


if __name__ == "__main__":
    unittest.main()
