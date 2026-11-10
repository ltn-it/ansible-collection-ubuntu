"""Fresh asset guards use real private Root filesystem and verified helper code."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('physical_asset_guard', ROOT/'roles/github_runner/files/physical_assets.py')
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


@unittest.skipUnless(os.geteuid() == 0 and Path('/run/proof').is_dir(), 'private Root EE only')
class PhysicalAssetGuards(unittest.TestCase):
    def setUp(self):
        info = Path('/run/proof').stat()
        self.assertEqual((0, 0o700), (info.st_uid, stat.S_IMODE(info.st_mode)))
        self.temporary = tempfile.TemporaryDirectory(dir='/run/proof')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        profiles = mock.patch.object(GUARD, 'loaded_profiles', return_value=[])
        profiles.start()
        self.addCleanup(profiles.stop)
        self.library = self.root/'library';self.library.mkdir(mode=0o700)
        shutil.copytree(ROOT/'roles/github_runner/files/incus_lease_issuer', self.library/'incus_lease_issuer',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copyfile(ROOT/'roles/github_runner/templates/protected_provision.py.j2',
                        self.library/'protected_provision.py')
        (self.library/'protected_provision.py').chmod(0o700)
        files = {p.relative_to(self.library).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in self.library.rglob('*.py')}
        machine = Path('/etc/machine-id').read_text().strip()
        receipt = self.library/'.library-binding.json'
        receipt.write_text(json.dumps({'schema': 1, 'machine_id': machine,
                                      'operation_reference': 'fixture', 'files': files}))
        receipt.chmod(0o600)
        config = {'name': 'fixture', 'root': str(self.root/'program/runner'),
                  'manifest': str(self.root/'admin/runner.json'), 'storage': str(self.root/'data'),
                  'work': str(self.root/'data/work'), 'home': str(self.root/'data/home'),
                  'archive': str(self.root/'admin/package.tar.gz'),
                  'user': 'gh_asset_fixture', 'group': 'gh_asset_fixture',
                  'url': 'https://github.com/example', 'labels': ['self-hosted', 'linux', 'x64'],
                  'runner_group': 'fixture', 'arch': 'x64', 'version': '2.338.2',
                  'service_state': 'stopped', 'ephemeral': False,
                  'operation_reference': 'fixture', 'storage_reference': 'fixture',
                  'custodian_reference': 'fixture', 'profile': 'lit-gh-assets-fixture',
                  'profile_path': '/etc/apparmor.d/lit-gh-assets-fixture', 'profile_sha256': 'f'*64}
        self.value = {'machine_id': machine, 'library_files': files, 'configuration': config}

    def test_fresh_probe_creates_no_asset_or_account(self):
        result = GUARD.inspect_assets(self.value, base=self.library)
        self.assertEqual('fresh-assets-only', result['state'])
        self.assertEqual({'library'}, {p.name for p in self.root.iterdir()})

    def test_unsafe_or_nonphysical_request_denies(self):
        for changed in ({'service_state': 'started'}, {'ephemeral': True}, {'user': 'root', 'group': 'root'},
                        {'user': 'nobody', 'group': 'nobody'}):
            with self.subTest(changed=changed):
                value = {**self.value, 'configuration': {**self.value['configuration'], **changed}}
                with self.assertRaises(Exception):
                    GUARD.inspect_assets(value, base=self.library)

    def test_existing_unbound_storage_and_changed_library_deny(self):
        Path(self.value['configuration']['storage']).mkdir()
        with self.assertRaisesRegex(ValueError, 'unbound-existing-asset'):
            GUARD.inspect_assets(self.value, base=self.library)
        Path(self.value['configuration']['storage']).rmdir()
        (self.library/'incus_lease_issuer/identity.py').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'library-source-drift'):
            GUARD.inspect_assets(self.value, base=self.library)


if __name__ == '__main__':
    unittest.main()
