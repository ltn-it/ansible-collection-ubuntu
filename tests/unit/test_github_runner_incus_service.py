"""Service property fixtures, not a live systemd or operating acceptance test."""
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import installation, service  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


class ServicePropertiesTests(unittest.TestCase):
    def setUp(self):
        self.install = installation.InstallationPolicy("/opt/synthetic-runner", "/etc/synthetic/manifest.json", 61, 2101)
        self.policy = service.ServicePolicy("actions.runner.synthetic.service", "synthetic-runner", self.install,
                                            "/etc/systemd/system/actions.runner.synthetic.service", "a" * 64)
        self.properties = {key: "" for key in service.PROPERTIES}
        self.properties.update(Id=self.policy.unit, LoadState="loaded", ActiveState="active", SubState="running",
                               MainPID="101", User="synthetic-runner", DynamicUser="no",
                               ControlGroup="/system.slice/" + self.policy.unit,
                               FragmentPath=self.policy.fragment_path, NeedDaemonReload="no",
                               WorkingDirectory=self.install.root,
                               ExecStart="{ path=/opt/synthetic-runner/runsvc.sh ; argv[]=/opt/synthetic-runner/runsvc.sh ; ignore_errors=no ; start_time=[fixture] ; pid=101 ; code=(null) ; status=0/0 }")

    def raw(self, properties=None):
        values = self.properties if properties is None else properties
        return ("\n".join(key + "=" + value for key, value in values.items()) + "\n").encode()

    def test_stock_service_properties_do_not_equate_mainpid_with_listener(self):
        parsed = service.parse_properties(self.raw())
        self.assertEqual(service.qualify_properties(parsed, self.policy),
                         (101, "/system.slice/" + self.policy.unit))

    def test_duplicate_missing_extra_and_oversized_properties_deny(self):
        invalid = (self.raw() + b"MainPID=102\n", self.raw() + b"Unexpected=yes\n",
                   b"Id=only\n", b"x" * (service.MAX_OUTPUT + 1), self.raw() + b"\x00",
                   self.raw().replace(b"MainPID=101", b"MainPID=101\r"))
        for raw in invalid:
            with self.subTest(size=len(raw)), self.assertRaises(Denied):
                service.parse_properties(raw)

    def test_notrunning_or_wrong_service_identity_deny(self):
        changes = {"Id": "foreign.service", "LoadState": "not-found", "ActiveState": "inactive",
                   "SubState": "exited", "User": "other-runner", "DynamicUser": "yes", "NeedDaemonReload": "yes",
                   "MainPID": "0", "ControlGroup": "/", "WorkingDirectory": "/tmp/fake"}
        for key, value in changes.items():
            data = dict(self.properties, **{key: value})
            with self.subTest(key=key), self.assertRaises(Denied):
                service.qualify_properties(data, self.policy)

    def test_unit_fragment_and_exact_dropins_are_bound(self):
        data = dict(self.properties, FragmentPath="/tmp/replaced.service")
        with self.assertRaises(Denied):
            service.qualify_properties(data, self.policy)
        path = "/etc/systemd/system/actions.runner.synthetic.service.d/10-isolation.conf"
        policy = replace(self.policy, dropins=((path, "b" * 64),))
        data = dict(self.properties, DropInPaths=path)
        self.assertEqual(service.qualify_properties(data, policy)[0], 101)
        for raw in (path + " /tmp/extra.conf", '"' + path + '"', path + " "):
            with self.assertRaises(Denied):
                service.qualify_properties(dict(data, DropInPaths=raw), policy)

    def test_alternate_command_arguments_or_multiple_commands_deny(self):
        command = self.properties["ExecStart"]
        for altered in (command.replace("argv[]=/opt/synthetic-runner/runsvc.sh ;", "argv[]=/opt/synthetic-runner/runsvc.sh evil ;"),
                        command.replace("path=/opt/synthetic-runner/runsvc.sh", "path=/tmp/evil.sh"),
                        command + " { path=/tmp/extra.sh ; argv[]=/tmp/extra.sh ; ignore_errors=no ; }"):
            with self.assertRaises(Denied):
                service.qualify_properties(dict(self.properties, ExecStart=altered), self.policy)

    def test_unqualified_external_startup_inputs_deny(self):
        for key in ("EnvironmentFiles", "PassEnvironment", "RootDirectory", "RootImage"):
            with self.subTest(key=key), self.assertRaises(Denied):
                service.qualify_properties(dict(self.properties, **{key: "/tmp/unqualified"}), self.policy)

    def test_unit_globs_options_and_duplicate_file_policy_deny(self):
        for unit in ("*.service", "--system", "../runner.service", "runner\n.service"):
            with self.assertRaises(Denied):
                service.validate_policy(replace(self.policy, unit=unit))
        with self.assertRaises(Denied):
            service.validate_policy(replace(self.policy, dropins=((self.policy.fragment_path, "b" * 64),)))

    def test_missing_structured_cli_value_is_not_inferred_empty(self):
        raw = self.raw().replace(b"EnvironmentFiles=\n", b"")
        with self.assertRaises(Denied):
            service.parse_properties(raw)
        obj = json.dumps({"type": "o", "data": ["/org/freedesktop/systemd1/unit/synthetic_2eservice"]}).encode()
        empty = json.dumps({"type": "a(sb)", "data": []}).encode()
        with patch.object(service, "_command", side_effect=[obj, empty, raw]) as command:
            parsed = service.parse_properties(service._show(self.policy.unit))
            self.assertEqual(parsed["EnvironmentFiles"], "")
            self.assertEqual(command.call_count, 3)
        for data in ([], ["/tmp/foreign"], ["/org/freedesktop/systemd1/unit/a", "/extra"]):
            wrong = json.dumps({"type": "o", "data": data}).encode()
            with patch.object(service, "_command", return_value=wrong), self.assertRaises(Denied):
                service._environment_files_empty(self.policy.unit)

    def test_dbus_environment_files_must_be_typed_and_proven_empty(self):
        obj = json.dumps({"type": "o", "data": ["/org/freedesktop/systemd1/unit/synthetic_2eservice"]}).encode()
        for value in ({"type": "a(sb)", "data": [["/tmp/untrusted.env", False]]},
                      {"type": "as", "data": []}, {"type": "a(sb)", "data": [] , "extra": True}):
            with patch.object(service, "_command", side_effect=[obj, json.dumps(value).encode()]):
                with self.assertRaises(Denied):
                    service._environment_files_empty(self.policy.unit)

    def test_command_caps_actual_pipe_output_and_reaps_producer(self):
        # Fixed helper subprocesses inside the EE, never a production API for
        # caller-selected executables. Oversized output must fail during read.
        good = service._command([sys.executable, "-I", "-B", "-c", "import sys; sys.stdout.write('bounded')"])
        self.assertEqual(good, b"bounded")
        script = "import os,time; os.write(1,b'x'*131073); time.sleep(5)"
        with self.assertRaisesRegex(Denied, "service-query-output-limit"):
            service._command([sys.executable, "-I", "-B", "-c", script])
        with self.assertRaisesRegex(Denied, "service-query-failed"):
            service._command([sys.executable, "-I", "-B", "-c", "raise SystemExit(7)"])

    @unittest.skipIf(os.geteuid() == 0, "Nonroot production denial checked in the nonroot EE pass")
    def test_nonroot_reader_cannot_supply_properties_instead_of_root_acquisition(self):
        with patch.object(service, "_show", side_effect=AssertionError("must deny before systemctl")):
            with self.assertRaisesRegex(Denied, "root-service-reader-required"):
                service.read_service(self.policy)


if __name__ == "__main__":
    unittest.main()
