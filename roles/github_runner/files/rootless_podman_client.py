#!/usr/bin/python3
"""Unprivileged, fixed-endpoint CLI for one protected ephemeral runner.

Install as a root-owned `podman` earlier in the runner's PATH. Provisioning and
Root-side service/registration attestation are separate responsibilities. This
client confers no privileges: the daemon and its socket belong to the same UID.
"""
import json
import os
from pathlib import PurePosixPath
import re
import socket
import stat
import struct
import sys

CONFIG = '/etc/github-runner-engine/client.json'
BINARY = '/usr/bin/podman'
COMMANDS = frozenset(('info', 'run', 'image', 'images', 'inspect', 'pull', 'load', 'rm', 'ps', 'version'))
# These persistent Podman options are inherited by subcommands as well.
OVERRIDES = frozenset(('--url', '--connection', '--context', '--host', '-H', '-c', '--remote', '-r', '--root', '--runroot',
                       '--storage-driver', '--storage-opt', '--namespace', '--module',
                       '--config', '--identity', '--ssh', '--runtime', '--hooks-dir'))

RUN_BOOLEAN = frozenset(('--rm', '--read-only', '--read-only-tmpfs', '--init'))
RUN_VALUE = frozenset(('--cap-drop', '--security-opt', '--pids-limit', '--user', '--tmpfs', '--env', '--mount',
                       '--network', '--workdir', '--cpus', '--memory', '--label', '--name', '--entrypoint',
                       '--pull', '--volume', '--platform', '--log-driver'))


class Refused(ValueError):
    """No process was executed."""


def sealed_open(path):
    """Read through descriptors rooted at /; never follow a symlink ancestor."""
    canonical = PurePosixPath(path)
    if not path.startswith('/') or str(canonical) != path or '..' in canonical.parts:
        raise Refused('noncanonical-config-path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(canonical.parts[1:]):
            final = index == len(canonical.parts) - 2
            next_fd = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                              (0 if final else os.O_DIRECTORY), dir_fd=fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise Refused('config-not-root-sealed')
            if final and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096):
                raise Refused('invalid-config-file')
        return os.read(fd, 4097)
    finally:
        os.close(fd)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused('duplicate-config-field')
        result[key] = value
    return result


def parse_config(raw):
    value = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(value, dict) or set(value) != {'schema', 'uid', 'gid', 'socket', 'home'}:
        raise Refused('invalid-config-fields')
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Refused('invalid-config-schema')
    for key in ('uid', 'gid'):
        if type(value[key]) is not int or value[key] <= 0:
            raise Refused('nonpositive-service-identity')
    if not isinstance(value['socket'], str) or not re.fullmatch(
            r'/run/lit-runner-engine-[a-z0-9][a-z0-9-]{0,47}/podman\.sock', value['socket']):
        raise Refused('invalid-private-endpoint')
    if not isinstance(value['home'], str) or not re.fullmatch(
            r'/var/lib/lit-runner-engine/[a-z0-9][a-z0-9-]{0,47}', value['home']):
        raise Refused('invalid-engine-home')
    return value


def forbidden(argument):
    flag = argument.split('=', 1)[0]
    return flag in OVERRIDES or argument.startswith(('-c', '-r', '-H')) and not argument.startswith('--')


def validate_arguments(arguments):
    if not arguments or arguments[0] not in COMMANDS:
        raise Refused('unsupported-engine-command')
    if arguments[0] != 'run':
        if any(forbidden(argument) for argument in arguments[1:]):
            raise Refused('engine-override-forbidden')
        return
    # Podman run stops option parsing at IMAGE (SetInterspersed(false)).
    # Parse the managed launcher's explicit option vocabulary to locate IMAGE;
    # do not mistake python -c or a workload's --url for an engine override.
    index = 1
    while index < len(arguments):
        argument = arguments[index]
        if argument == '--':
            if index + 1 >= len(arguments) or not arguments[index + 1]:
                raise Refused('missing-image')
            return
        if not argument.startswith('-'):
            if not argument:
                raise Refused('missing-image')
            return
        if forbidden(argument):
            raise Refused('engine-override-forbidden')
        flag, separator, value = argument.partition('=')
        if flag in RUN_BOOLEAN:
            if separator and value not in ('true', 'false'):
                raise Refused('invalid-boolean-run-option')
        elif flag in RUN_VALUE:
            if not separator:
                index += 1
                if index >= len(arguments):
                    raise Refused('missing-run-option-value')
        else:
            raise Refused('unsupported-run-option')
        index += 1
    raise Refused('missing-image')


def verify_endpoint(config):
    """Require private runtime directory/socket and a real same-UID Unix peer."""
    runtime = os.path.dirname(config['socket'])
    directory = os.lstat(runtime)
    endpoint = os.lstat(config['socket'])
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != config['uid'] or directory.st_mode & 0o077:
        raise Refused('runtime-directory-not-private')
    if not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != config['uid'] or endpoint.st_mode & 0o077:
        raise Refused('socket-not-private')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(3)
        peer.connect(config['socket'])
        _, uid, gid = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if (uid, gid) != (config['uid'], config['gid']):
            raise Refused('engine-peer-identity-mismatch')
    # An unprivileged owner can replace its own socket afterwards; it cannot
    # turn this same-UID client into a privileged engine or change its fixed URL.


def invocation(config, arguments):
    validate_arguments(arguments)
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (
            config['uid'], config['uid'], config['gid'], config['gid']):
        raise Refused('service-identity-mismatch')
    if set(os.getgroups()) - {config['gid']}:
        raise Refused('supplementary-groups-forbidden')
    argv = [BINARY, '--remote', '--url', 'unix://' + config['socket'], *arguments]
    environment = {'PATH': '/usr/bin:/bin', 'HOME': config['home'],
                   'XDG_RUNTIME_DIR': os.path.dirname(config['socket']),
                   'CONTAINERS_CONF': '/dev/null'}
    return argv, environment


def main():
    try:
        config = parse_config(sealed_open(CONFIG))
        argv, environment = invocation(config, sys.argv[1:])
        binary = os.stat(BINARY, follow_symlinks=False)
        if not stat.S_ISREG(binary.st_mode) or binary.st_uid != 0 or binary.st_mode & 0o022:
            raise Refused('podman-binary-not-root-sealed')
        verify_endpoint(config)
        os.execve(BINARY, argv, environment)
    except (OSError, ValueError, TypeError):
        # Do not echo arguments, paths, environment or engine credentials.
        print('Protected rootless Podman client refused invocation.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
