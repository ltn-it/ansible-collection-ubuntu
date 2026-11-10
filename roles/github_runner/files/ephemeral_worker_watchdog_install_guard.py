"""Read-only Root/machine/path/owned-asset preflight; never repairs drift."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MODULES = frozenset({'ephemeral_worker_admission.py', 'ephemeral_worker_lease.py',
    'ephemeral_worker_incus.py', 'ephemeral_worker_watchdog.py', 'ephemeral_worker_watchdog_entry.py'})
UNITS = frozenset({'lit-github-runner-ephemeral-worker-watchdog.service',
                   'lit-github-runner-ephemeral-worker-watchdog.timer'})


def require(value):
    if not value:
        raise ValueError('watchdog-install-preflight-held')


def directory(path, *, private=False):
    require(path.is_absolute() and str(path) != '/' and re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path))
            and not any(part in {'.', '..'} for part in str(path).split('/')))
    for parent in reversed([path, *path.parents]):
        if not os.path.lexists(parent):
            continue
        value = parent.lstat()
        require(stat.S_ISDIR(value.st_mode) and value.st_uid == 0 and not value.st_mode & 0o022)
        if private and parent == path:
            require(stat.S_IMODE(value.st_mode) == 0o700)


def asset(path, expected, *, mode):
    if not os.path.lexists(path):
        return False
    value = path.lstat()
    require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_gid == 0
            and value.st_nlink == 1 and stat.S_IMODE(value.st_mode) == mode)
    with path.open('rb') as source:
        require(hashlib.file_digest(source, 'sha256').hexdigest() == expected)
    return True


def main():
    require(os.geteuid() == 0 and sys.version_info >= (3, 11) and len(sys.argv) == 7)
    machine, boot, program, state, modules, units = sys.argv[1:]
    require(re.fullmatch(r'[0-9a-f]{32}', machine)
            and re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot))
    require(Path('/etc/machine-id').read_text().strip() == machine
            and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot)
    require(Path('/run/systemd/system').is_dir())
    program, state = Path(program), Path(state)
    require(str(program).startswith('/usr/local/lib/') and str(state).startswith('/var/lib/lightning-it/')
            and program != state)
    directory(program, private=True)
    directory(state, private=True)
    directory(Path('/etc/systemd/system'))
    modules, units = json.loads(modules), json.loads(units)
    require(type(modules) is dict and set(modules) == MODULES
            and type(units) is dict and set(units) == UNITS)
    require(all(type(v) is str and re.fullmatch(r'[0-9a-f]{64}', v) for v in [*modules.values(), *units.values()]))
    if program.exists():
        require(set(p.name for p in program.iterdir()) <= MODULES)
    present = [asset(program / name, digest, mode=0o600) for name, digest in modules.items()]
    existing_units = [asset(Path('/etc/systemd/system') / name, digest, mode=0o644)
                      for name, digest in units.items()]
    require(not any(existing_units) or (all(present) and state.exists()))
    print(json.dumps({'state': 'WATCHDOG_INSTALL_PREFLIGHT_PASS', 'machine_id': machine,
                      'boot_id': boot, 'existing_modules': sum(present), 'existing_units': sum(existing_units)}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'state': 'WATCHDOG_INSTALL_HELD', 'error_type': type(error).__name__}))
        raise SystemExit(1)
