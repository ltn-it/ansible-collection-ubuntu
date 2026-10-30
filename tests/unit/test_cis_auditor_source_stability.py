"""Exercise the real checked-byte/copy boundary with a mutable offline source."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.geteuid() == 0, "Requires the isolated root-target Devtools witness")
class RootAuditorSourceTests(unittest.TestCase):
    def test_untrusted_writer_cannot_replace_bytes_between_admission_and_vendor_copy(self):
        role = ROOT / "roles/cis_ubuntu24"
        tasks = yaml.safe_load((role / "tasks/auditor.yml").read_text())
        start = next(i for i, task in enumerate(tasks) if task["name"] in (
            "Validate protected controller auditor bytes before vendor use",
            "Inspect actual auditor bytes without following a supplied link"))
        defaults = yaml.safe_load((role / "defaults/main.yml").read_text())
        # Isolate the actual final byte/copy boundary with a known synthetic
        # digest. Production's fixed release admission is tested separately;
        # no fixture is claimed to be a valid published Goss executable.
        for writable in (True, False):
            with self.subTest(writable=writable), tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
                root = Path(directory)
                root.chmod(0o755)
                source = root / "source-goss"
                source.write_text("#!/bin/sh\nexit 0\n")
                source.chmod(0o666 if writable else 0o600)
                marker = root / "unchecked-code-executed"
                target = root / "target-goss"
                after = [{"name": "Model an untrusted writer after the completed checksum",
                          "ansible.builtin.copy": {"dest": str(source),
                              "content": "#!/bin/sh\nprintf unchecked > '" + str(marker) + "'\n", "mode": "0666"},
                          "when": writable},
                         {"name": "Model vendor copy of the effective selected source",
                          "ansible.builtin.copy": {"src": "{{ audit_bin_copy_location }}",
                              "dest": str(target), "mode": "0700"}},
                         {"name": "Model vendor root execution of copied bytes",
                          "ansible.builtin.command": {"argv": [str(target)]}, "changed_when": False}]
                book = root / "case.yml"
                book.write_text(yaml.safe_dump([{"hosts": "all", "gather_facts": False, "vars": {
                    **defaults, "role_path": str(role), "cis_ubuntu24_auditor_controller_file": str(source),
                    "cis_ubuntu24_auditor_sha256": hashlib.sha256(source.read_bytes()).hexdigest()},
                    "tasks": tasks[start:] + after}]))
                env = {**os.environ, "ANSIBLE_LOCAL_TEMP": str(root / "local"),
                       "ANSIBLE_REMOTE_TEMP": str(root / "remote")}
                env.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
                done = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(book)],
                                      env=env, capture_output=True, text=True, timeout=45)
                self.assertFalse(marker.exists(), done.stdout + done.stderr)
                self.assertEqual(done.returncode, 2 if writable else 0, done.stdout + done.stderr)
                if writable:
                    self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
