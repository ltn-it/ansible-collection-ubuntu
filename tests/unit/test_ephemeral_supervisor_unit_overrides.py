"""Real override files plus closed systemd readbacks; no native service changes."""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


class UnitOverrideTests(unittest.TestCase):
    def test_both_supervisors_reject_full_runtime_hierarchical_and_type_overrides(self):
        for filename in ('ephemeral_worker_watchdog_install_guard.py', 'ephemeral_worker_local_mail_install_guard.py'):
            spec = importlib.util.spec_from_file_location('guard', ROOT / 'roles/github_runner/files' / filename)
            guard = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(guard)
            for name in sorted(guard.UNITS):
                with tempfile.TemporaryDirectory() as temporary:
                    lookup = Path(temporary)
                    properties = 'LoadState=loaded\nFragmentPath=/etc/systemd/system/' + name + '\nDropInPaths=\n'
                    with patch.object(guard, 'systemd_output', side_effect=lambda args, lookup=lookup, response=properties: str(lookup)+'\n' if args[0].endswith('systemd-analyze') else response):
                        guard.unit_controls([name], effective=True)
                        for directory in (name+'.d', 'lit-github-runner-.'+name.rsplit('.',1)[1]+'.d', name.rsplit('.',1)[1]+'.d'):
                            with self.subTest(guard=filename, override=directory):
                                path = lookup / directory
                                path.mkdir()
                                (path/'override.conf').write_text('[Service]\nExecStart=\nExecStart=/bin/true\n')
                                with self.assertRaises(ValueError):
                                    guard.unit_controls([name])
                                (path/'override.conf').unlink()
                                path.rmdir()
                        alias = lookup/name
                        alias.symlink_to('/dev/null')
                        with self.assertRaises(ValueError):
                            guard.unit_controls([name])
                        alias.unlink()
                    for bad in ('DropInPaths=/run/systemd/system/service.d/override.conf\n',
                                'FragmentPath=/run/systemd/generator/foreign.service\n'):
                        changed = properties.replace('DropInPaths=\n', bad) if bad.startswith('DropIn') else properties.replace('FragmentPath=/etc/systemd/system/'+name+'\n', bad)
                        with patch.object(guard, 'systemd_output', side_effect=lambda args, lookup=lookup, response=changed: str(lookup)+'\n' if args[0].endswith('systemd-analyze') else response), self.assertRaises(ValueError):
                            guard.unit_controls([name], effective=True)
                    absent = 'LoadState=not-found\nFragmentPath=\nDropInPaths=\n'
                    with patch.object(guard, 'systemd_output', side_effect=lambda args, lookup=lookup, response=absent: str(lookup)+'\n' if args[0].endswith('systemd-analyze') else response):
                        guard.unit_controls([name])
                        with self.assertRaises(ValueError):
                            guard.unit_controls([name], effective=True)
                    with patch.object(guard.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'unit-paths\n', b'')) as run:
                        guard.systemd_output(['/usr/bin/systemd-analyze', 'unit-paths'])
                        self.assertNotIn('SYSTEMD_UNIT_PATH', run.call_args.kwargs['env'])
