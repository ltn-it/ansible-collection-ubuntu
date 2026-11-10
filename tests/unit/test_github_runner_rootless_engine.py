"""Root filesystem/intent tests with explicit fake native daemon operations.

Run Root cases only inside the repository EE with private /run/proof. They do
not qualify a real systemd engine, GitHub registration, or kernel confinement.
"""
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'roles/github_runner/files'))
import rootless_engine as engine
from incus_lease_issuer.identity import Denied


class MappingTests(unittest.TestCase):
    def test_preserves_other_allocations_and_exact_own_allocation(self):
        raw = b'# preserved\nother:200000:65536\n'
        expected = raw + b'worker:100000:65536\n'
        self.assertEqual(engine.mapping(raw, 'worker', 2001, 100000), expected)
        self.assertEqual(engine.mapping(expected, 'worker', 2001, 100000), expected)
        numeric = b'2001:100000:65536\n'
        self.assertEqual(engine.mapping(numeric, 'worker', 2001, 100000), numeric)

    def test_overlap_duplicate_malformed_and_bool_range_refuse(self):
        for raw, start in ((b'other:99999:3\n', 100000), (b'worker:100000:65535\n', 100000),
                           (b'worker:100000:65536\nworker:100000:65536\n', 100000),
                           (b'bad line\n', 100000), (b'other:1:0\n', 100000), (b'', True),
                           (b'', 2**32), (b'', 99999)):
            with self.subTest(raw=raw, start=start), self.assertRaises(Denied):
                engine.mapping(raw, 'worker', 2001, start)

    def test_nonroot_cannot_begin_a_service_installation(self):
        with patch.object(os, 'geteuid', return_value=2001), self.assertRaisesRegex(Denied, 'engine-root-required'):
            engine.prepare({}, {}, b'', lambda argv: self.fail('effect'), lambda: self.fail('identity'))


class NativePeerTopologyTests(unittest.TestCase):
    def records(self):
        main = {'pid': 1002, 'ppid': 1, 'starttime': '13866', 'uids': [2001] * 4,
                'gids': [2001] * 4, 'groups': [2001], 'exe': '/usr/bin/podman',
                'cgroup': '0::/system.slice/fixture.service'}
        return {1002: main, 1015: {**main, 'pid': 1015, 'ppid': 1002, 'starttime': '13885'}}

    def test_actual_observed_podman_reexecution_shape_and_main_peer_are_supported(self):
        records = self.records()
        for peer in (1002, 1015):
            chain = engine.peer_lineage(peer, 1002, 2001, 2001, '/system.slice/fixture.service', records.__getitem__)
            self.assertEqual(chain[-1]['pid'], 1002)

    def test_foreign_unit_uid_executable_or_unrelated_parent_are_denied(self):
        for changed in ({'cgroup': '0::/system.slice/fixture.service-foreign'},
                        {'uids': [0] * 4}, {'groups': [2001, 998]},
                        {'exe': '/usr/bin/other'}, {'ppid': 1}, {'ppid': 1015}):
            records = self.records()
            records[1015].update(changed)
            with self.subTest(changed=changed), self.assertRaises(Denied):
                engine.peer_lineage(1015, 1002, 2001, 2001, '/system.slice/fixture.service', records.__getitem__)

    def test_reused_or_changed_peer_pid_is_rejected_on_second_kernel_read(self):
        records = self.records()
        calls = []
        def changed(pid):
            calls.append(pid)
            value = records[pid]
            return {**value, 'starttime': 'changed'} if len(calls) > 2 else value
        with self.assertRaisesRegex(Denied, 'process-changed'):
            engine.peer_lineage(1015, 1002, 2001, 2001, '/system.slice/fixture.service', changed)


@unittest.skipUnless(os.geteuid() == 0 and sys.platform == 'linux', 'isolated Root EE only')
class RootIntentTests(unittest.TestCase):
    def setUp(self):
        base = Path('/run/proof')
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest('requires private /run/proof in EE')
        self.temp = tempfile.TemporaryDirectory(prefix='rootless-engine-', dir=base)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, path in {'STATE': self.root / 'state', 'CONFIG': self.root / 'etc/client.json',
                           'CLIENT': self.root / 'libexec/podman', 'HOME': self.root / 'home',
                           'SYSTEMD': self.root / 'systemd',
                           'SUBIDS': (self.root / 'subuid', self.root / 'subgid')}.items():
            fixture = patch.object(engine, name, path)
            fixture.start()
            self.addCleanup(fixture.stop)
        engine.SYSTEMD.mkdir(mode=0o755)
        for path in engine.SUBIDS:
            path.write_bytes(b'other:200000:65536\n')
            path.chmod(0o644)
        self.binding = {'name': 'fixture', 'user': 'worker', 'group': 'worker', 'uid': 2001, 'gid': 2001,
                        'runner_id': 123, 'runner_unit': 'actions.runner.fixture.service',
                        'manifest_sha256': 'a' * 64}
        self.ranges = {'subuid_start': 100000, 'subgid_start': 100000}
        self.source = b'#!/usr/bin/python3\n# synthetic nonsecret client bytes\n'
        self.native = {'ActiveState': 'active', 'SubState': 'running', 'MainPID': '1234', 'InvocationID': 'c' * 32}
        self.runner_active = False
        self.unknown_start = False
        self.calls = []
        self.checked = 0
        self.prerequisite = patch.object(engine, 'prerequisites')
        self.prerequisite.start()
        self.addCleanup(self.prerequisite.stop)
        self.attestation = patch.object(engine, 'attest')
        self.attestation.start()
        self.addCleanup(self.attestation.stop)
        self.addCleanup(self.restore_owners)

    def restore_owners(self):
        def walk(path):
            if path.is_symlink():
                return
            os.chown(path, 0, 0)
            if path.is_dir():
                path.chmod(0o700)
                for child in path.iterdir():
                    walk(child)
        walk(self.root)

    def identity(self):
        self.checked += 1

    def command(self, argv):
        self.calls.append(argv)
        if argv[1] == 'show':
            value = self.native if argv[-1].startswith('lit-runner-engine-') else {
                'ActiveState': 'active' if self.runner_active else 'inactive', 'SubState': 'dead',
                'MainPID': '321' if self.runner_active else '0', 'InvocationID': ''}
            return ''.join(k + '=' + v + '\n' for k, v in value.items())
        if argv[0] == '/usr/sbin/usermod':
            for path in engine.SUBIDS:
                path.write_bytes(engine.mapping(path.read_bytes(), 'worker', 2001, 100000))
            return ''
        if argv[1] == 'start' and self.unknown_start:
            raise Denied('synthetic-unknown-start')
        return ''

    def apply(self):
        return engine.prepare(self.binding, self.ranges, self.source, self.command, self.identity)

    def test_real_private_files_and_idmaps_idempotent_without_second_native_start(self):
        first = self.apply()
        self.assertTrue(first['changed'])
        self.assertEqual(stat.S_IMODE(engine.STATE.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(engine.CONFIG.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(engine.CLIENT.stat().st_mode), 0o755)
        self.assertEqual(engine.CLIENT.read_bytes(), self.source)
        self.assertEqual((engine.HOME / 'fixture').stat().st_uid, 2001)
        for path in engine.SUBIDS:
            self.assertEqual(path.read_bytes(), b'other:200000:65536\nworker:100000:65536\n')
        before = {p: p.read_bytes() for p in (engine.CONFIG, engine.CLIENT, *engine.SUBIDS)}
        self.assertFalse(self.apply()['changed'])
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        self.assertEqual(len([c for c in self.calls if c[1] == 'start']), 1)
        self.assertGreaterEqual(self.checked, 3)

    def test_socket_readiness_observes_same_invocation_without_reissuing_start(self):
        with patch.object(engine, 'attest', side_effect=[FileNotFoundError(), None]) as attest:
            self.assertTrue(self.apply()['changed'])
            self.assertEqual(attest.call_count, 2)
        self.assertEqual(len([c for c in self.calls if c[1] == 'start']), 1)

    def test_unknown_start_is_retained_and_never_replayed(self):
        self.unknown_start = True
        with self.assertRaisesRegex(Denied, 'synthetic-unknown-start'):
            self.apply()
        self.assertEqual(json.loads((engine.STATE / 'journal.json').read_bytes())['phase'], 'start-intent')
        self.unknown_start = False
        with self.assertRaisesRegex(Denied, 'incomplete-or-drifted'):
            self.apply()
        self.assertEqual(len([c for c in self.calls if c[1] == 'start']), 1)

    def test_native_id_mapping_partial_outcome_is_held_without_a_second_allocation(self):
        original = self.command
        def interrupt(argv):
            if argv[0] == '/usr/sbin/usermod':
                path = engine.SUBIDS[0]
                path.write_bytes(engine.mapping(path.read_bytes(), 'worker', 2001, 100000))
                raise Denied('synthetic-mapping-outcome-unknown')
            return original(argv)
        with patch.object(self, 'command', side_effect=interrupt):
            with self.assertRaisesRegex(Denied, 'mapping-outcome-unknown'):
                self.apply()
        self.assertEqual(json.loads((engine.STATE / 'journal.json').read_bytes())['phase'], 'install-intent')
        with self.assertRaisesRegex(Denied, 'incomplete-or-drifted'):
            self.apply()
        self.assertNotIn('worker:', engine.SUBIDS[1].read_text())
        self.assertFalse(engine.CONFIG.exists())

    def test_file_drift_and_ended_native_lifetime_never_repair_or_restart(self):
        self.apply()
        engine.CLIENT.write_bytes(b'changed')
        with self.assertRaisesRegex(Denied, 'file-drift'):
            self.apply()
        self.assertEqual(engine.CLIENT.read_bytes(), b'changed')
        engine.CLIENT.write_bytes(self.source)
        self.native.update(ActiveState='inactive', SubState='dead', MainPID='0')
        with self.assertRaisesRegex(Denied, 'lifetime-ended-or-changed'):
            self.apply()
        self.assertEqual(len([c for c in self.calls if c[1] == 'start']), 1)

    def test_busy_runner_and_overlapping_map_refuse_before_any_own_file(self):
        self.runner_active = True
        with self.assertRaisesRegex(Denied, 'runner-not-stopped'):
            self.apply()
        self.assertFalse(engine.STATE.exists())
        self.runner_active = False
        engine.SUBIDS[1].write_bytes(b'other:120000:65536\n')
        with self.assertRaisesRegex(Denied, 'subid-overlap'):
            self.apply()
        self.assertFalse(engine.STATE.exists())
        self.assertEqual(engine.SUBIDS[0].read_bytes(), b'other:200000:65536\n')

    def test_existing_unproven_file_or_loaded_unit_is_not_adopted(self):
        engine.CONFIG.parent.mkdir(mode=0o755)
        with self.assertRaisesRegex(Denied, 'unproven-existing'):
            self.apply()
        engine.CONFIG.parent.rmdir()
        original = self.command
        with patch.object(self, 'command', side_effect=lambda argv:
                          'loaded unit' if argv[1] == 'list-units' else original(argv)):
            with self.assertRaisesRegex(Denied, 'unproven-loaded-unit'):
                self.apply()
        self.assertFalse(engine.STATE.exists())

    def test_symlink_subid_and_unknown_journal_refuse_without_rewrite(self):
        path = engine.SUBIDS[0]
        raw = path.read_bytes()
        path.unlink()
        path.symlink_to(engine.SUBIDS[1])
        with self.assertRaises(Denied):
            self.apply()
        self.assertTrue(path.is_symlink())
        path.unlink()
        path.write_bytes(raw)
        engine.STATE.mkdir(mode=0o700)
        (engine.STATE / 'journal.json').write_text('{"phase":"install-intent"}')
        (engine.STATE / 'journal.json').chmod(0o600)
        with self.assertRaisesRegex(Denied, 'incomplete-or-drifted'):
            self.apply()
        self.assertFalse(engine.CONFIG.exists())


if __name__ == '__main__':
    unittest.main()
