"""Real private filesystem probes; no registration, service or native API effects."""
from pathlib import Path
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.geteuid() == 0 and Path('/run/proof').is_dir(), 'private Root EE only')
class PhysicalLibraryProbeTests(unittest.TestCase):
    def setUp(self):
        proof = Path('/run/proof').stat()
        self.assertEqual((0, 0o700), (proof.st_uid, stat.S_IMODE(proof.st_mode)))
        self.temporary = tempfile.TemporaryDirectory(dir='/run/proof')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)/'library'
        play = yaml.safe_load((ROOT/'playbooks/github_runner_physical_helper_library.yml').read_text())[0]
        facts = next(t['ansible.builtin.set_fact'] for t in play['tasks']
                     if t['name'] == 'Bind the preparation receipt and read-only verifier')
        self.probe = facts['github_runner_physical_library_probe'].replace(
            "Path('/usr/local/lib/github-runner-protected')", 'Path(' + repr(str(self.base)) + ')'
        )
        self.contents = {'protected_provision.py': b'fixture provisioner\n',
                         'incus_lease_issuer/native_fence.py': b'fixture module\n'}
        self.binding = {'schema': 1, 'machine_id': Path('/etc/machine-id').read_text().strip(),
                        'operation_reference': 'fixture-only',
                        'files': {name: hashlib.sha256(raw).hexdigest()
                                  for name, raw in self.contents.items()}}

    def invoke(self, phase):
        return subprocess.run(['python3', '-I', '-B', '-c', self.probe, phase],
            input=json.dumps(self.binding), text=True, capture_output=True, timeout=10)

    def populate(self, receipt=False):
        self.base.mkdir(mode=0o700)
        for name, raw in self.contents.items():
            p = self.base/name
            p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            p.write_bytes(raw)
            p.chmod(0o700 if name == 'protected_provision.py' else 0o600)
        if receipt:
            p = self.base/'.library-binding.json'
            p.write_text(json.dumps(self.binding))
            p.chmod(0o600)

    def test_fresh_before_and_exact_completed_reentry_are_readonly(self):
        first = self.invoke('before')
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertFalse(self.base.exists())
        self.populate()
        after = self.invoke('after')
        self.assertEqual(0, after.returncode, after.stderr)
        self.assertFalse((self.base/'.library-binding.json').exists())
        p = self.base/'.library-binding.json'
        p.write_text(json.dumps(self.binding)); p.chmod(0o600)
        again = self.invoke('before')
        self.assertEqual(0, again.returncode, again.stderr)
        self.assertEqual(2, json.loads(again.stdout)['files_verified'])

    def test_existing_unbound_partial_library_is_preserved_and_refused(self):
        self.populate()
        result = self.invoke('before')
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(self.contents['protected_provision.py'],
                         (self.base/'protected_provision.py').read_bytes())
        self.assertFalse((self.base/'.library-binding.json').exists())

    def test_changed_extra_or_linked_module_denies(self):
        for case in ('changed', 'extra', 'linked'):
            with self.subTest(case=case):
                self.populate(receipt=True)
                module = self.base/'incus_lease_issuer/native_fence.py'
                if case == 'changed':
                    module.write_text('changed\n')
                elif case == 'extra':
                    (self.base/'foreign').write_text('foreign')
                else:
                    module.unlink(); module.symlink_to(self.base/'protected_provision.py')
                self.assertNotEqual(0, self.invoke('before').returncode)
                import shutil
                shutil.rmtree(self.base)


if __name__ == '__main__':
    unittest.main()
