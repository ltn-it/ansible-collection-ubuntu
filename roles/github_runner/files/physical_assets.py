"""Read-only physical runner preparation guards. Never register or stop a runner."""
from pathlib import Path
import grp
import hashlib
import importlib.util
import json
import os
import pwd
import re
import stat
import subprocess
import sys

BASE = Path('/usr/local/lib/github-runner-protected')


def loaded_profiles():
    raw = Path('/sys/kernel/security/apparmor/profiles').read_bytes()
    require(len(raw) <= 1024*1024, 'profile-inventory-limit')
    return raw.decode().splitlines()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def root_file(path, limit):
    path = Path(path)
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'unsafe-root-ancestor')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and not info.st_mode & 0o022 and info.st_size <= limit, 'unsafe-root-file')
    return path.read_bytes()


def library(files, machine_id, base=BASE):
    require(isinstance(files, dict) and len(files) > 10 and 'protected_provision.py' in files,
            'library-inventory')
    require(all(isinstance(name, str) and re.fullmatch(
        r'protected_provision[.]py|incus_lease_issuer/[a-z_]+[.]py', name)
        and isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest)
        for name, digest in files.items()), 'library-inventory')
    info = base.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, 'library-boundary')
    binding = json.loads(root_file(base/'.library-binding.json', 65536))
    require(binding.get('machine_id') == machine_id and binding.get('files') == files,
            'library-receipt')
    seen = set()
    for directory, children, leaves in os.walk(base, followlinks=False):
        for name in children:
            path = Path(directory)/name
            info = path.lstat()
            require(path.relative_to(base).as_posix() == 'incus_lease_issuer'
                    and stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                    and not info.st_mode & 0o022, 'library-directory')
        for name in leaves:
            path = Path(directory)/name
            relative = path.relative_to(base).as_posix()
            if relative == '.library-binding.json':
                continue
            require(relative in files, 'foreign-library-file')
            require(hashlib.sha256(root_file(path, 1024*1024)).hexdigest() == files[relative],
                    'library-source-drift')
            seen.add(relative)
    require(seen == set(files), 'missing-library-file')
    # Only the verified private directory participates in importing this helper.
    sys.path.insert(0, str(base))
    spec = importlib.util.spec_from_file_location('physical_asset_provisioner', base/'protected_provision.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect_assets(value, phase='before', base=BASE):
    require(os.geteuid() == 0, 'root-required')
    require(isinstance(value, dict) and set(value) == {'machine_id', 'library_files', 'configuration'},
            'assets-envelope')
    require(phase in ('before', 'verify'), 'assets-phase')
    machine_id = Path('/etc/machine-id').read_text().strip()
    require(value['machine_id'] == machine_id, 'wrong-machine')
    helper = library(value['library_files'], machine_id, base)
    config = helper.configuration(json.dumps(value['configuration']).encode())
    require(config['service_state'] == 'stopped' and config['ephemeral'] is False
            and 'rootless_engine' not in config and 'expected_guest_uuid' not in config,
            'physical-stopped-preparation-only')
    receipt = Path(config['manifest']+'.assets.json')
    require(not os.path.lexists(config['root']) and not os.path.lexists(config['manifest'])
            and not os.path.lexists(config['manifest']+'.transaction'), 'registration-state-present')
    if phase == 'before' and not os.path.lexists(receipt):
        require(not any(line.startswith(config['profile']+' (') for line in loaded_profiles()),
                'unbound-loaded-profile')
        for lookup, name in ((pwd.getpwnam, config['user']), (grp.getgrnam, config['group'])):
            try:
                lookup(name)
            except KeyError:
                pass
            else:
                raise ValueError('unbound-existing-account')
        for field in ('root', 'manifest', 'storage', 'home', 'work', 'archive', 'profile_path'):
            path = Path(config[field])
            require(not os.path.lexists(path), 'unbound-existing-asset')
            for parent in path.parents:
                if not os.path.lexists(parent):
                    continue
                info = parent.lstat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                        and not info.st_mode & 0o022, 'unsafe-existing-ancestor')
        return {'state': 'fresh-assets-only', 'registration_effects': False}
    user = helper.account(config)
    require(user.pw_gid > 0, 'privileged-primary-group')
    status = subprocess.run(['/usr/bin/passwd', '--status', config['user']], capture_output=True,
                            text=True, timeout=10, check=True)
    require(status.stdout.split()[1] in ('L', 'LK'), 'account-password-not-locked')
    for field, uid, mode in (('storage', 0, 0o710), ('home', user.pw_uid, 0o700),
                             ('work', user.pw_uid, 0o700)):
        info = Path(config[field]).lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid
                and info.st_gid == user.pw_gid and stat.S_IMODE(info.st_mode) == mode,
                'asset-directory-drift')
    require(hashlib.sha256(root_file(config['archive'], 512*1024*1024)).hexdigest()
            == helper.ARCHIVES[config['arch']], 'archive-pin')
    helper.confinement(config)
    completed = {'schema': 1, 'machine_id': machine_id, 'configuration': config,
                 'uid': user.pw_uid, 'gid': user.pw_gid}
    if phase == 'before':
        require(json.loads(root_file(receipt, 65536)) == completed, 'assets-receipt-drift')
    return {'state': 'prepared-assets-only', 'receipt': completed, 'registration_effects': False}


def main():
    try:
        require(os.uname().machine == 'x86_64', 'physical-x64-host-required')
        raw = sys.stdin.buffer.read(131073)
        require(len(raw) <= 131072, 'assets-input-limit')
        result = inspect_assets(json.loads(raw), sys.argv[1] if len(sys.argv) == 2 else '')
        print(json.dumps(result))
        return 0
    except Exception as error:
        print(json.dumps({'state': 'ASSETS_HELD', 'reason': str(error)
                          if type(error) is ValueError else type(error).__name__}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
