"""Fixed endpoint client boundaries; no claim of real runner provisioning."""
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'roles/github_runner/files'))
import rootless_podman_client as client


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.config = {'schema': 1, 'uid': 2001, 'gid': 2001,
                       'socket': '/run/lit-runner-engine-fixture/podman.sock',
                       'home': '/var/lib/lit-runner-engine/fixture'}

    def test_closed_schema_and_duplicate_fields(self):
        self.assertEqual(client.parse_config(json.dumps(self.config)), self.config)
        for value in ({**self.config, 'uid': True}, {**self.config, 'gid': 0},
                      {**self.config, 'schema': True}, {**self.config, 'extra': 1},
                      {**self.config, 'socket': 'tcp://localhost'},
                      {**self.config, 'socket': '/run/../root/podman.sock'},
                      {**self.config, 'home': '/root'}):
            with self.subTest(value=value), self.assertRaises(client.Refused):
                client.parse_config(json.dumps(value))
        with self.assertRaisesRegex(client.Refused, 'duplicate'):
            client.parse_config('{"uid":2001,"uid":0}')

    def test_endpoint_and_global_option_injection_is_denied(self):
        for arguments in ([], ['--url', 'tcp://example', 'run'], ['system', 'service'],
                          ['run', '--url=tcp://example'], ['image', '--connection', 'other'],
                          ['run', '-cother'], ['info', '--remote=false'], ['run', '--module=x'],
                          ['run', '--root', '/root'], ['info', '--context=other'], ['info', '-Htcp://other']):
            with self.subTest(arguments=arguments), self.assertRaises(client.Refused):
                client.validate_arguments(arguments)
        client.validate_arguments(['run', '--rm', '--read-only', 'image@sha256:fixture', 'bash', '-lc', 'true'])
        client.validate_arguments(['info', '--format', '{{.Host.Security.Rootless}}'])

    def test_managed_python_preflight_payload_is_preserved_after_image(self):
        arguments = ['run', '--rm', '--read-only', '--cap-drop', 'ALL', '--security-opt',
                     'no-new-privileges=true', '--pids-limit', '512', '--user', '0:0',
                     '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777',
                     '--env', 'QUALITY_CONTEXT_PHASE=preflight', '--read-only-tmpfs=false',
                     '--mount', 'type=bind,source=/private,destination=/incus,readonly',
                     '--network', 'none', 'pinned-image', 'python3', '-c', 'print("--url")']
        client.validate_arguments(arguments)
        client.validate_arguments(['run', '--', 'pinned-image', 'tool', '--url=tcp://workload'])
        for arguments in (['run', '--env'], ['run', '--rm'], ['run', '--unknown', 'image'],
                          ['run', '--rm=maybe', 'image'], ['run', '--']):
            with self.subTest(arguments=arguments), self.assertRaises(client.Refused):
                client.validate_arguments(arguments)

    def identity(self, uid=2001, groups=None):
        stack = __import__('contextlib').ExitStack()
        for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
            stack.enter_context(patch.object(os, name, return_value=uid))
        stack.enter_context(patch.object(os, 'getgroups', return_value=groups or [uid]))
        return stack

    def test_actual_command_preserves_payload_and_discards_inherited_connection(self):
        args = ['run', '--rm', '--network', 'none', 'pinned-image', 'true']
        with self.identity(), patch.dict(os.environ, {'CONTAINER_HOST': 'tcp://wrong',
                                                     'DOCKER_HOST': 'unix:///var/run/docker.sock',
                                                     'LD_PRELOAD': 'untrusted'}):
            argv, env = client.invocation(self.config, args)
        self.assertEqual(argv, ['/usr/bin/podman', '--remote', '--url',
                                'unix://' + self.config['socket'], *args])
        self.assertEqual(set(env), {'PATH', 'HOME', 'XDG_RUNTIME_DIR', 'CONTAINERS_CONF'})
        self.assertEqual(env['CONTAINERS_CONF'], '/dev/null')
        self.assertEqual(env['HOME'], self.config['home'])

    def test_root_foreign_user_and_extra_groups_are_denied(self):
        for uid, groups in ((0, [0]), (2002, [2002]), (2001, [2001, 998])):
            with self.subTest(uid=uid, groups=groups), self.identity(uid, groups), self.assertRaises(client.Refused):
                client.invocation(self.config, ['info'])

    def test_cli_has_no_config_override_and_never_executes_after_endpoint_denial(self):
        with patch.object(client, 'sealed_open', return_value=json.dumps(self.config)), self.identity(), \
                patch.object(client, 'verify_endpoint', side_effect=client.Refused('denied')), \
                patch.object(client.os, 'stat') as metadata, patch.object(client.os, 'execve') as execute, \
                patch.object(sys, 'argv', ['podman', 'info']):
            import stat
            metadata.return_value.st_mode = stat.S_IFREG | 0o755
            metadata.return_value.st_uid = 0
            self.assertEqual(client.main(), 1)
            execute.assert_not_called()


class NativeFilesystemTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.directory.chmod(0o700)
        import socket
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.listener.close)
        self.endpoint = self.directory / 'podman.sock'
        self.listener.bind(str(self.endpoint))
        self.listener.listen(5)
        self.endpoint.chmod(0o600)
        self.config = {'socket': str(self.endpoint), 'uid': os.getuid(), 'gid': os.getgid()}

    def test_real_unix_peer_and_private_directory(self):
        client.verify_endpoint(self.config)
        self.directory.chmod(0o755)
        with self.assertRaisesRegex(client.Refused, 'runtime-directory'):
            client.verify_endpoint(self.config)

    def test_socket_mode_symlink_and_foreign_peer_are_denied(self):
        self.endpoint.chmod(0o660)
        with self.assertRaisesRegex(client.Refused, 'socket-not-private'):
            client.verify_endpoint(self.config)
        self.endpoint.chmod(0o600)
        link = self.directory / 'link.sock'
        link.symlink_to(self.endpoint)
        with self.assertRaisesRegex(client.Refused, 'socket-not-private'):
            client.verify_endpoint({**self.config, 'socket': str(link)})
        with self.assertRaisesRegex(client.Refused, 'engine-peer-identity'):
            client.verify_endpoint({**self.config, 'gid': os.getgid() + 1})

    @unittest.skipUnless(os.geteuid() == 0, 'Root sealed path fixture uses private /run directory')
    def test_actual_root_sealed_descriptor_walk_rejects_symlinks_and_writable_files(self):
        import tempfile
        base = '/run/proof' if Path('/run/proof').is_dir() else '/run'
        with tempfile.TemporaryDirectory(prefix='g06-client-', dir=base) as private:
            path = Path(private) / 'client.json'
            path.write_bytes(b'{}')
            path.chmod(0o644)
            self.assertEqual(client.sealed_open(str(path)), b'{}')
            path.chmod(0o666)
            with self.assertRaisesRegex(client.Refused, 'root-sealed'):
                client.sealed_open(str(path))
            path.chmod(0o644)
            link = Path(private) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                client.sealed_open(str(link))
            alias = Path(private) / 'alias'
            alias.symlink_to(Path(private), target_is_directory=True)
            with self.assertRaises(OSError):
                client.sealed_open(str(alias / 'client.json'))
            fifo = Path(private) / 'fifo'
            os.mkfifo(fifo, 0o600)
            with self.assertRaisesRegex(client.Refused, 'invalid-config-file'):
                client.sealed_open(str(fifo))
            os.link(path, Path(private) / 'hardlink')
            with self.assertRaisesRegex(client.Refused, 'invalid-config-file'):
                client.sealed_open(str(path))


if __name__ == '__main__':
    unittest.main()
