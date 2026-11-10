"""Read-only first-install and owned-configuration drift guard; no mailbox reads."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

def regular(path, mode):
    value = path.lstat()
    assert stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1
    assert stat.S_IMODE(value.st_mode) == mode, 'local-mail-file-mode'
    return value

def unique(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, 'local-mail-duplicate-state-field'
        result[key] = value
    return result


def check(mode, *, root=Path('/var/lib/lit-local-mail'), config=Path('/etc/postfix'),
          spool=Path('/var/spool/postfix'), processes=Path('/proc')):
    """Trusted Root paths; the operational entry accepts no path arguments."""
    assert os.geteuid() == 0 and mode in {'initialize', 'managed'}, 'local-mail-root-input'
    receipt = root / 'ownership.json'
    configurations = {'main_cf_sha256': config / 'main.cf', 'master_cf_sha256': config / 'master.cf'}
    if receipt.exists() or receipt.is_symlink():
        value = root.lstat()
        assert stat.S_ISDIR(value.st_mode) and value.st_uid == 0 and stat.S_IMODE(value.st_mode) == 0o700
        assert regular(receipt, 0o600).st_size < 4096
        record = json.loads(receipt.read_text(), object_pairs_hook=unique)
        assert type(record) is dict and set(record) == {'schema', *configurations}
        assert type(record['schema']) is int and record['schema'] == 1
        for key, path in configurations.items():
            regular(path, 0o644)
            assert hashlib.sha256(path.read_bytes()).hexdigest() == record[key], 'local-mail-configuration-drift'
        return {'state': 'OWNED_LOCAL_MAIL_CONFIGURATION_INTACT'}
    assert mode == 'initialize', 'local-mail-explicit-initialization-required'
    assert not root.exists() and not root.is_symlink(), 'local-mail-unowned-state-directory'
    for process in processes.glob('[0-9]*'):
        try:
            if (process / 'comm').read_text().strip() != 'master':
                continue
            assert 'postfix' not in os.readlink(process / 'exe'), 'local-mail-existing-active-master'
        except FileNotFoundError:
            continue
    for name in ['active', 'incoming', 'deferred', 'defer', 'bounce', 'maildrop', 'hold', 'corrupt']:
        directory = spool / name
        if directory.exists():
            assert not any(p.is_file() or p.is_symlink() for p in directory.rglob('*')), 'local-mail-existing-queue'
    return {'state': 'EXPLICIT_EMPTY_INACTIVE_INITIALIZATION'}


if __name__ == '__main__':
    assert sys.argv[1:] in [['initialize'], ['managed']], 'local-mail-fixed-entrypoint'
    print(json.dumps(check(sys.argv[1])))
