"""Target-policy preservation, signed payload binding and collector isolation."""
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

DATA = load("payload_data", ROOT / "roles/automatic_updates/files/apt_staged_bundle.py")
ACQUIRE = load("payload_acquire", ROOT / "roles/automatic_updates/files/apt_staged_acquire.py")
OLD = load("metadata_fixture", Path(__file__).with_name("test_apt_staged_bundle.py"))


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.deb = self.root / "example_2_amd64.deb"
        self.deb.write_bytes(b"signed-index-bound-fixture-payload")
        self.index = self.root / "Packages"
        self.index.write_text("fixture index")
        self.item = {"file": self.deb.name, "target_name": self.deb.name, "package": "example", "version": "2",
                     "architecture": "amd64", "sha256": DATA.digest(self.deb), "bytes": self.deb.stat().st_size,
                     "list_prefix": "archive_dists_noble", "meta_key": "main/binary-amd64/Packages",
                     "repository_filename": "pool/main/e/example/example_2_amd64.deb"}
        self.indexes = [{"file": self.index.name, "list_prefix": self.item["list_prefix"], "meta_key": self.item["meta_key"]}]
        self.record = {"Package": "example", "Version": "2", "Architecture": "amd64", "SHA256": self.item["sha256"],
                       "Size": str(self.item["bytes"]), "Filename": self.item["repository_filename"]}

    def verify(self, items=None, records=None):
        return DATA.verify_packages(self.root, [self.item] if items is None else items, self.indexes, "amd64",
                                    records=lambda path: iter([self.record] if records is None else records))

    def test_payload_requires_actual_byte_hash_and_signed_package_record(self):
        self.assertEqual(self.verify(), 1)
        self.deb.write_bytes(self.deb.read_bytes()[:-1])
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.verify()

    def test_missing_wrong_version_architecture_origin_hash_size_or_path_fails(self):
        for field, value in (("Version", "1"), ("Architecture", "arm64"), ("SHA256", "0" * 64),
                             ("Size", "1"), ("Filename", "pool/other.deb")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(records=[{**self.record, field: value}])
        with self.assertRaises(ValueError):
            self.verify(records=[])
        self.indexes[0]["list_prefix"] = "other-origin"
        with self.assertRaises(ValueError):
            self.verify()

    def test_duplicate_unsafe_target_or_wrong_declared_architecture_fails(self):
        for items in ([self.item, self.item], [{**self.item, "target_name": "../escape.deb"}],
                      [{**self.item, "architecture": "arm64"}], [{**self.item, "file": "../escape.deb"}]):
            with self.subTest(items=items), self.assertRaises(ValueError):
                self.verify(items=items)

    def test_signed_record_cannot_supply_a_traversing_repository_path(self):
        self.item["repository_filename"] = "pool/../escape.deb"
        self.record["Filename"] = self.item["repository_filename"]
        with self.assertRaisesRegex(ValueError, "Unsafe repository"):
            self.verify()

    def test_empty_plan_does_not_claim_installed_updates_or_scan_unneeded_indexes(self):
        self.assertEqual(DATA.verify_packages(self.root, [], self.indexes, "amd64",
                         records=lambda path: self.fail("No payload scan needed")), 0)

    def test_control_records_handle_continuations_and_reject_duplicate_fields(self):
        text = "Package: example\nVersion: 2\nDescription: line one\n line two\n\nPackage: other\nVersion: 3\n"
        records = list(DATA.control_records(text.splitlines()))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["Description"], "line one\nline two")
        for invalid in ("Package: one\nPackage: two", " orphan", "not-a-field"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                list(DATA.control_records(invalid.splitlines()))


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def test_effective_config_is_only_hashed_never_stored_as_raw_transport_values(self):
        full = b'synthetic-private-transport-option\n'
        def run(argv, **kwargs):
            self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            if argv[0].endswith("apt-get"):
                return SimpleNamespace(stdout=b"apt 2.8.3 (amd64)\nrest\n")
            return SimpleNamespace(stdout=b"RECOMMENDS='1'\nSUGGESTS='0'\n" if argv[1] == "shell" else full)
        result = DATA.apt_policy(run=run)
        self.assertEqual(result["effective_config_sha256"], hashlib.sha256(full).hexdigest())
        self.assertNotIn(full.decode().strip(), json.dumps(result))
        self.assertTrue(result["settings"]["RECOMMENDS"])
        self.assertFalse(result["settings"]["ALWAYS_PHASED"])
        self.assertEqual(result["apt_version"], "apt 2.8.3 (amd64)")

    def test_invalid_boolean_or_conflicting_phasing_policy_fails(self):
        for text in (b"RECOMMENDS='unknown'\n", b"ALWAYS_PHASED='true'\nNEVER_PHASED='true'\n",
                     b"UNKNOWN='1'\n", b"RECOMMENDS='1'\nRECOMMENDS='0'\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                DATA.apt_policy(run=lambda *args, **kwargs: SimpleNamespace(stdout=text))

    def test_sources_retain_order_keyring_and_architecture_without_authentication_overrides(self):
        source = self.root / "source.sources"
        content = "# comment\nTypes: deb\nURIs: https://archive.example.org/ubuntu\nSuites: noble noble-updates\nComponents: main universe\nSigned-By: /keyring\n"
        source.write_text(content)
        result = DATA.parse_sources([source], Path('/keyring'), "amd64")
        self.assertEqual([row["suite"] for row in result], ["noble", "noble-updates"])
        for invalid in (content + "Trusted: yes\n", content.replace('/keyring', '/other'),
                        content.replace('https://archive.', 'https://fixture@archive.'),
                        content + 'Architectures: arm64\n', content.replace('Types: deb', 'Types: deb deb-src')):
            source.write_text(invalid)
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                DATA.parse_sources([source], Path('/keyring'), "amd64")

    def test_active_legacy_sources_fail_instead_of_losing_policy(self):
        source = self.root / "source.list"
        source.write_text('deb https://archive.example.org/ubuntu noble main\n')
        with self.assertRaisesRegex(ValueError, "legacy"):
            DATA.parse_sources([source], Path('/keyring'), 'amd64')

    def test_unused_empty_source_and_preference_files_remain_hash_bound(self):
        empty = self.root / 'empty.list'
        empty.touch()
        source = self.root / 'base.sources'
        source.write_text('Types: deb\nURIs: https://archive.example.org/ubuntu\nSuites: noble\nComponents: main\nSigned-By: /keyring\n')
        self.assertEqual(len(DATA.parse_sources([empty, source], Path('/keyring'), 'amd64')), 1)
        preference = self.root / 'preference'
        preference.touch()
        extended = self.root / 'extended'
        extended.touch()
        context = DATA.patch_context([preference], extended, policy=lambda: {})
        self.assertEqual(context['preferences'][str(preference)], hashlib.sha256(b'').hexdigest())
        self.assertEqual(context['extended_states_sha256'], hashlib.sha256(b'').hexdigest())

    def test_wrong_target_capture_fails_before_creating_any_private_snapshot(self):
        destination = self.root / 'not-created'
        with patch.object(DATA.os, 'geteuid', return_value=0), \
             patch.object(DATA.subprocess, 'check_output', side_effect=[b'amd64\n', b'', b'']), \
             patch.object(DATA.shutil, 'which', return_value=None), \
             patch.object(DATA.Path, 'read_text', return_value='a' * 32):
            with self.assertRaisesRegex(ValueError, 'independently admitted machine'):
                DATA.capture(destination, 'b' * 32)
        self.assertFalse(destination.exists())

    def test_schema2_binds_live_policy_and_extended_state_before_import(self):
        fixture = OLD.BundleTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        context = {"preferences": {}, "extended_states_sha256": None,
                   "apt_policy": {"settings": {}, "effective_config_sha256": "0" * 64},
                   "upgrade_mode": "apt-get upgrade --with-new-pkgs"}
        fixture.manifest.update(schema=2, patch_context=deepcopy(context))
        fixture.request.update(schema=2, patch_context=deepcopy(context))
        fixture.seal()
        with patch.object(OLD.APT, 'patch_context', return_value=context):
            self.assertTrue(fixture.verify()['package_payloads_verified'])
        with patch.object(OLD.APT, 'patch_context', return_value={**context, 'extended_states_sha256': 'f' * 64}):
            with self.assertRaisesRegex(ValueError, 'resolver policy'):
                fixture.verify()


class CollectorTests(unittest.TestCase):
    def test_uri_plan_is_not_a_payload_integrity_authority(self):
        text = "Reading package lists...\n'https://archive.example.org/pool/example.deb' example_2_amd64.deb 123 SHA256:ignored\n"
        plan = ACQUIRE.print_uri_plan(text)
        self.assertEqual(plan['example_2_amd64.deb']['bytes'], 123)
        for invalid in (text + text, text.replace(' 123 ', ' wrong '), text.replace('example_2_amd64.deb', '../escape.deb'),
                        text.replace('https://archive.', 'https://fixture@archive.')):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                ACQUIRE.print_uri_plan(invalid)

    def test_configuration_uses_target_identity_policy_and_only_private_package_state(self):
        request = {'architecture': 'amd64', 'machine_id': 'a' * 32,
                   'patch_context': {'apt_policy': {'settings': {'DEFAULT_RELEASE': '', 'RECOMMENDS': True,
                     'SUGGESTS': False, 'ALWAYS_PHASED': False, 'NEVER_PHASED': False}}}}
        text = ACQUIRE.apt_configuration(Path('/private'), request, 'fixture-user')
        for expected in ('APT::Machine-ID "' + 'a' * 32 + '";', 'Dir::State::status "/private/state/status";',
                         'Dir::Etc::netrc "/dev/null";', 'Dir::Etc::preferencesparts "/private/preferences";',
                         'APT::Install-Recommends "true";', '#clear DPkg::Pre-Install-Pkgs;'):
            self.assertIn(expected, text)
        self.assertNotIn('/var/lib/dpkg/status', text)
        self.assertNotIn('/etc/apt/preferences.d', text)

    def test_root_acquisition_is_rejected_before_any_input_or_destination_mutation(self):
        with patch.object(ACQUIRE.os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(ValueError, 'unprivileged'):
                ACQUIRE.acquire(Path('/unused'), '0' * 64, Path('/unused-output'), 'a' * 32)

    def test_real_private_command_success_failure_and_deadline_are_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = {'PATH': '/usr/bin:/bin'}
            result = ACQUIRE.run_apt(root/'success.log', [sys.executable, '-c', 'print("fixture-data")'], env, root, 5)
            self.assertIn('fixture-data', result)
            with self.assertRaisesRegex(ValueError, 'operation failed'):
                ACQUIRE.run_apt(root/'failure.log', [sys.executable, '-c', 'raise SystemExit(7)'], env, root, 5)
            with self.assertRaisesRegex(ValueError, 'deadline'):
                ACQUIRE.run_apt(root/'timeout.log', [sys.executable, '-c', 'import time;time.sleep(20)'], env, root, 0.01)
            self.assertTrue((root/'failure.log').is_file())
            self.assertTrue((root/'timeout.log').is_file())


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        key = self.root / 'keyring'
        key.write_bytes(b'public-keyring-fixture')
        files = {'/var/lib/dpkg/status': ('status', 'Package: example\nVersion: 1\n'),
                 '/etc/apt/sources.list.d/base.sources': ('source-0.sources',
                   'Types: deb\nURIs: https://archive.example.org/ubuntu\nSuites: noble\n'
                   'Components: main\nSigned-By: ' + str(key) + '\n'),
                 '/etc/apt/preferences.d/pin': ('preference-0', 'Package: example\nPin-Priority: 510\n'),
                 '/var/lib/apt/extended_states': ('extended-states', 'Package: example\nAuto-Installed: 1\n')}
        payload = {}
        for original, (name, content) in files.items():
            (self.root / name).write_text(content)
            payload[original] = {'file': name, 'sha256': DATA.digest(self.root / name)}
        self.capture = {'schema': 2, 'machine_id': 'a' * 32, 'architecture': 'amd64',
                        'status_sha256': payload['/var/lib/dpkg/status']['sha256'],
                        'sources': {'/etc/apt/sources.list.d/base.sources': payload['/etc/apt/sources.list.d/base.sources']['sha256']},
                        'keyring': {'path': str(key), 'sha256': DATA.digest(key)}, 'payload_files': payload,
                        'repositories': [{'uri': 'https://archive.example.org/ubuntu', 'suite': 'noble', 'components': ['main']}],
                        'patch_context': {'upgrade_mode': 'apt-get upgrade --with-new-pkgs',
                          'preferences': {'/etc/apt/preferences.d/pin': payload['/etc/apt/preferences.d/pin']['sha256']},
                          'extended_states_sha256': payload['/var/lib/apt/extended_states']['sha256']}}
        self.seal()

    def seal(self):
        (self.root / 'capture.json').write_text(json.dumps(self.capture))
        self.checksum = DATA.digest(self.root / 'capture.json')

    def test_authentication_binds_each_public_snapshot_to_exact_target_policy(self):
        request, mapped = ACQUIRE.snapshot_inputs(self.root, self.checksum)
        self.assertEqual(request['machine_id'], 'a' * 32)
        self.assertEqual(len(mapped), 4)

    def test_changed_capture_or_payload_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Capture changed'):
            ACQUIRE.snapshot_inputs(self.root, '0' * 64)
        (self.root / 'status').write_text('changed installed package state')
        with self.assertRaisesRegex(ValueError, 'payload changed'):
            ACQUIRE.snapshot_inputs(self.root, self.checksum)


    def test_missing_unlisted_or_inconsistent_snapshot_is_rejected(self):
        for mutate in ('missing', 'extra', 'wrong-target-status'):
            saved = deepcopy(self.capture)
            if mutate == 'missing':
                del self.capture['payload_files']['/etc/apt/preferences.d/pin']
            elif mutate == 'extra':
                self.capture['payload_files']['/unlisted'] = self.capture['payload_files']['/var/lib/dpkg/status']
            else:
                self.capture['status_sha256'] = '0' * 64
            self.seal()
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                ACQUIRE.snapshot_inputs(self.root, self.checksum)
            self.capture = saved

    def test_wrong_keyring_or_repository_binding_cannot_be_accepted(self):
        saved = deepcopy(self.capture)
        self.capture['keyring']['sha256'] = '0' * 64
        self.seal()
        with self.assertRaisesRegex(ValueError, 'keyring differs'):
            ACQUIRE.snapshot_inputs(self.root, self.checksum)
        self.capture = saved
        self.capture['repositories'][0]['suite'] = 'different'
        self.seal()
        with self.assertRaisesRegex(ValueError, 'repository policy'):
            ACQUIRE.snapshot_inputs(self.root, self.checksum)

    def test_snapshot_member_cannot_escape_the_private_capture(self):
        self.capture['payload_files']['/var/lib/dpkg/status']['file'] = '../status'
        self.seal()
        with self.assertRaisesRegex(ValueError, 'Unsafe capture member'):
            ACQUIRE.snapshot_inputs(self.root, self.checksum)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.archive = self.root/'bundle.tar.gz'
        self.payload = b'public-fixture-payload'
        self.manifest = {'machine_id':'a'*32,'releases':[],'indexes':[],
                         'packages':[{'file':'example.deb','package':'example','version':'2',
                                      'architecture':'amd64','bytes':len(self.payload)}]}
        raw=json.dumps(self.manifest).encode()
        self.request={'machine_id':'a'*32,'manifest_sha256':hashlib.sha256(raw).hexdigest()}
        self.entries=[('manifest.json',raw),('example.deb',self.payload)]
        self.write_archive()

    def write_archive(self, special=None):
        with tarfile.open(self.archive,'w:gz',format=tarfile.PAX_FORMAT) as opened:
            for name,data in self.entries:
                item=tarfile.TarInfo(name);item.size=len(data)
                opened.addfile(item,io.BytesIO(data))
            if special:
                opened.addfile(special)
        self.checksum=DATA.digest(self.archive)

    def test_frame_authenticates_exact_members_without_claiming_signature_acceptance(self):
        result=DATA.archive_frame(self.archive,self.request,self.checksum)
        self.assertEqual(result['member_count'],2)
        self.assertEqual(result['package_plan'][0]['package'],'example')
        self.assertEqual(result['state'],'AUTHENTICATED_ARCHIVE_FRAME_NO_SIGNATURE_ACCEPTANCE')

    def test_transport_manifest_or_member_set_change_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'archive digest'):
            DATA.archive_frame(self.archive,self.request,'0'*64)
        with self.assertRaisesRegex(ValueError,'manifest differs'):
            DATA.archive_frame(self.archive,{**self.request,'manifest_sha256':'0'*64},self.checksum)
        for extras in ([('extra',b'not admitted')],[self.entries[-1]]):
            self.entries=[('manifest.json',json.dumps(self.manifest).encode()),('example.deb',self.payload)]+extras
            self.write_archive()
            with self.assertRaises(ValueError):
                DATA.archive_frame(self.archive,self.request,self.checksum)

    def test_traversal_absolute_links_and_devices_are_rejected_before_extraction(self):
        original=list(self.entries)
        for name in ('../escape','/escape','nested/escape'):
            self.entries=original+[(name,b'unsafe')];self.write_archive()
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'Unsafe'):
                DATA.archive_frame(self.archive,self.request,self.checksum)
        self.entries=original
        for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.CHRTYPE):
            item=tarfile.TarInfo('unsafe-link');item.type=kind;item.linkname='../escape'
            self.write_archive(special=item)
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'Unsupported'):
                DATA.archive_frame(self.archive,self.request,self.checksum)

    def test_receive_creates_only_private_files_and_requires_full_verification(self):
        destination=self.root/'receiver'
        original_read=Path.read_text
        def read(path,*args,**kwargs):
            return 'a'*32 if str(path)=='/etc/machine-id' else original_read(path,*args,**kwargs)
        with patch.object(DATA.os,'geteuid',return_value=0),patch.object(DATA.Path,'read_text',read), \
             patch.object(DATA,'verify',return_value={'state':'fixture-full-verification'}) as verifier:
            result=DATA.receive(self.archive,self.request,self.checksum,destination,'a'*32)
        self.assertFalse(result['apt_state_changed'])
        self.assertEqual((destination/'example.deb').read_bytes(),self.payload)
        self.assertEqual((destination/'example.deb').stat().st_mode & 0o777,0o600)
        verifier.assert_called_once_with(destination,self.request)

    def test_wrong_receiver_identity_never_creates_a_destination(self):
        destination=self.root/'not-created'
        with patch.object(DATA.os,'geteuid',return_value=0),patch.object(DATA.Path,'read_text',return_value='b'*32):
            with self.assertRaisesRegex(ValueError,'receiver identity'):
                DATA.receive(self.archive,self.request,self.checksum,destination,'a'*32)
        self.assertFalse(destination.exists())

if __name__ == '__main__':
    unittest.main()
