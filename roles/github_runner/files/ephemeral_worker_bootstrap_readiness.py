"""Read-only prerequisites inside an owned fresh Ubuntu worker VM.

The controller must first bind the agent connection to its live lease/UUID and
authenticated image/profile. This bounded check is not an image provenance
verifier, registration grant, global secret scanner or operating acceptance.
No credential values are returned. Operational collection accepts no supplied
SSH/cloud-init facts and never repairs a rejected guest.
"""
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import uuid


class NotReady(ValueError):
    pass


def require(value, reason):
    if not value:
        raise NotReady(reason)


def guest_path(root, raw):
    require(type(raw) is str and raw.startswith('/') and str(PurePosixPath(raw)) == raw
            and '..' not in PurePosixPath(raw).parts, 'bootstrap-canonical-path')
    path = root
    for part in PurePosixPath(raw).parts[1:]:
        path /= part
        require(not path.is_symlink(), 'bootstrap-linked-path')
    return path


def system_file(root, raw, maximum, *, virtual=False):
    path = guest_path(root, raw)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o022 and 0 < before.st_size <= (4096 if virtual else maximum),
                'bootstrap-system-file')
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        require((0 < len(raw) <= maximum if virtual else len(raw) == before.st_size)
                and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'bootstrap-changing-file')
        return raw.decode('utf-8')
    finally:
        os.close(fd)


def accounts(root):
    rows = system_file(root, '/etc/passwd', 65536).splitlines()
    require(0 < len(rows) <= 256, 'bootstrap-account-bound')
    result = []
    names = set()
    for row in rows:
        fields = row.split(':')
        require(len(fields) == 7 and re.fullmatch('[a-z_][a-z0-9_-]{0,31}', fields[0])
                and fields[0] not in names, 'bootstrap-account-shape')
        names.add(fields[0])
        if fields[6] not in {'/usr/sbin/nologin', '/sbin/nologin', '/bin/false', '/bin/sync', '/usr/bin/sync'}:
            require(fields[5] != '/', 'bootstrap-interactive-root-home')
            result.append((fields[0], fields[5]))
    require(any(name == 'root' for name, _ in result), 'bootstrap-root-account')
    return result


def identity(expected_uuid, *, root=Path('/')):
    """Reattest identity even after registration; never requires a fresh root."""
    require(os.geteuid() == 0, 'bootstrap-root-required')
    require(type(expected_uuid) is str and re.fullmatch(
        '[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', expected_uuid)
        and uuid.UUID(expected_uuid).int != 0, 'bootstrap-expected-uuid')
    actual = system_file(root, '/sys/devices/virtual/dmi/id/product_uuid', 128, virtual=True).strip().lower()
    require(actual == expected_uuid, 'bootstrap-guest-uuid')
    machine = system_file(root, '/etc/machine-id', 128).strip()
    require(re.fullmatch('[0-9a-f]{32}', machine) and int(machine, 16) != 0, 'bootstrap-machine-id')
    return {'guest_uuid': actual, 'machine_id': machine}


def inspect(expected_uuid, runner_root, *, root=Path('/'), cloud_ready, ssh_policies):
    """Root library paths/facts are trusted controller dependencies, not job input."""
    binding = identity(expected_uuid, root=root)
    require(cloud_ready is True, 'bootstrap-cloud-init-unfinished')
    identities = accounts(root)
    shadow = {}
    for row in system_file(root, '/etc/shadow', 65536).splitlines():
        fields = row.split(':')
        require(len(fields) == 9 and fields[0] not in shadow, 'bootstrap-shadow-shape')
        shadow[fields[0]] = fields[1]
    require(type(ssh_policies) is dict and set(ssh_policies) == {name for name, _ in identities},
            'bootstrap-ssh-account-coverage')
    for name, home in identities:
        require(shadow.get(name, '').startswith(('!', '*')), 'bootstrap-unlocked-password')
        policy = ssh_policies[name]
        require(type(policy) is dict and (policy == {'server': 'absent'} or policy == {
            'authorizedkeysfile': '.ssh/authorized_keys .ssh/authorized_keys2',
            'authorizedkeyscommand': 'none', 'trustedusercakeys': 'none',
            'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no',
            'hostbasedauthentication': 'no', 'gssapiauthentication': 'no',
            'kerberosauthentication': 'no'}), 'bootstrap-ssh-policy')
        for relative in ['.ssh', '.aws', '.kube', '.azure']:
            path = guest_path(root, str(PurePosixPath(home) / relative))
            if not path.exists():
                continue
            require(path.is_dir(), 'bootstrap-credential-path-type')
            count = 0
            for item in path.rglob('*'):
                count += 1
                require(count <= 256, 'bootstrap-home-inventory-bound')
                info = item.lstat()
                require(not stat.S_ISLNK(info.st_mode) and
                        (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_size == 0),
                        'bootstrap-existing-home-credentials')
    target = guest_path(root, runner_root)
    require(runner_root != '/' and not target.exists(), 'bootstrap-existing-runner-root')
    return {'state': 'BOUNDED_FRESH_GUEST_BOOTSTRAP_PREREQUISITES_PASS', 'vm_uuid': binding['guest_uuid'],
            'machine_id': binding['machine_id'], 'interactive_accounts_checked': len(identities),
            'openssh_server_present': any(v != {'server': 'absent'} for v in ssh_policies.values()),
            'runner_root_absent': True, 'registration_granted': False, 'final_image_qualified': False}


def collect(expected_uuid, runner_root):
    require(os.geteuid() == 0, 'bootstrap-root-required')
    require(type(expected_uuid) is str and re.fullmatch(
        '[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', expected_uuid), 'bootstrap-expected-uuid')
    require(system_file(Path('/'), '/sys/devices/virtual/dmi/id/product_uuid', 128,
        virtual=True).strip().lower() == expected_uuid, 'bootstrap-guest-uuid')
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
    # Conditional/external SSH policy needs separate qualification. Do not infer
    # the policy for every remote address from a single sshd -T sample.
    fragments = list(Path('/etc/ssh/sshd_config.d').glob('*.conf'))
    server_present = os.path.lexists('/usr/sbin/sshd')
    require(not os.path.lexists('/usr/local/sbin/sshd'), 'bootstrap-nonstandard-ssh-server')
    if not server_present:
        require(not os.path.lexists('/etc/ssh/sshd_config') and not fragments,
                'bootstrap-partial-ssh-installation')
    configs = [Path('/etc/ssh/sshd_config'), *fragments] if server_present else []
    require(len(configs) <= 64, 'bootstrap-ssh-config-bound')
    for path in configs:
        content = system_file(Path('/'), str(path), 65536)
        for line in content.splitlines():
            directive = line.strip().split(None, 1)
            if not directive or directive[0].startswith('#'):
                continue
            require(directive[0].lower() != 'match', 'bootstrap-conditional-ssh-policy')
            if directive[0].lower() == 'include':
                require(len(directive) == 2 and directive[1] == '/etc/ssh/sshd_config.d/*.conf',
                        'bootstrap-external-ssh-config')
    cloud = subprocess.run(['/usr/bin/systemctl', 'show', 'cloud-final.service',
        '--property=ActiveState,SubState,Result'], capture_output=True, text=True, timeout=5, check=True,
        env=environment, cwd='/')
    values = dict(line.split('=', 1) for line in cloud.stdout.splitlines() if '=' in line)
    ready = values == {'ActiveState': 'active', 'SubState': 'exited', 'Result': 'success'}
    policies = {}
    for name, _ in accounts(Path('/')):
        if not server_present:
            policies[name] = {'server': 'absent'}
            continue
        result = subprocess.run(['/usr/sbin/sshd', '-T', '-C',
            'user=' + name + ',host=localhost,addr=127.0.0.1'], capture_output=True, text=True,
            timeout=5, check=True, env=environment, cwd='/')
        keys = {'authorizedkeysfile', 'authorizedkeyscommand', 'trustedusercakeys',
                'passwordauthentication', 'kbdinteractiveauthentication', 'hostbasedauthentication',
                'gssapiauthentication', 'kerberosauthentication'}
        settings = {}
        for line in result.stdout.splitlines():
            key, _, value = line.partition(' ')
            if key in keys:
                require(key not in settings, 'bootstrap-duplicate-ssh-setting')
                settings[key] = value.strip()
        policies[name] = settings
    return inspect(expected_uuid, runner_root, cloud_ready=ready, ssh_policies=policies)


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 3, 'bootstrap-fixed-inputs')
        result = (identity(sys.argv[2]) if sys.argv[1] == '--identity-only'
                  else collect(*sys.argv[1:]))
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        print(json.dumps({'state': 'BOOTSTRAP_NOT_READY', 'error_type': type(error).__name__,
                          'gate': str(error) if type(error) is NotReady else 'bootstrap-collection-failed',
                          'registration_granted': False}))
        raise SystemExit(1)
