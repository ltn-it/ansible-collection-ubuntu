"""Read-only password aging evidence without exporting shadow or credential data."""

import json
import os
from pathlib import Path
import pwd
import re
import signal
import subprocess
import sys


def require(value, message):
    if not value:
        raise ValueError(message)


def login_defaults(text):
    values = {}
    for line in text.splitlines():
        fields = line.split('#', 1)[0].split()
        if fields and fields[0] in ('PASS_MAX_DAYS', 'PASS_WARN_AGE'):
            require(len(fields) == 2 and re.fullmatch(r'[0-9]+', fields[1]), 'Invalid login aging directive')
            require(fields[0] not in values, 'Duplicate login aging directive')
            values[fields[0]] = int(fields[1])
    return values


def aging_fields(text):
    labels = {'Maximum number of days between password change': 'max_days',
              'Number of days of warning before password expires': 'warn_days'}
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition(':')
        if separator and key.strip() in labels:
            name = labels[key.strip()]
            require(name not in values and re.fullmatch(r'-?[0-9]+', value.strip()), 'Invalid account aging metadata')
            values[name] = int(value.strip())
    require(set(values) == {'max_days', 'warn_days'}, 'Incomplete account aging metadata')
    return values


def evaluate(defaults, accounts, max_days, warn_days):
    require(type(max_days) is int and 1 <= max_days <= 365, 'Invalid maximum-age policy')
    require(type(warn_days) is int and warn_days >= 7, 'Invalid warning-age policy')
    maximum_ok = defaults.get('PASS_MAX_DAYS') == max_days
    warning_ok = defaults.get('PASS_WARN_AGE') == warn_days
    locked = 0
    eligible = 0
    for account in accounts:
        if account.get('status') == 'L':
            locked += 1
            continue
        if account.get('status') != 'P':
            maximum_ok = warning_ok = False
            continue
        eligible += 1
        maximum = account.get('max_days')
        warning = account.get('warn_days')
        maximum_ok = maximum_ok and type(maximum) is int and 1 <= maximum <= max_days
        warning_ok = warning_ok and type(warning) is int and warning >= warn_days
    return {'results': [
        {'control_id': '5.4.1.1', 'check_id': 'password-max-age-effective',
         'status': 'pass' if maximum_ok else 'fail'},
        {'control_id': '5.4.1.3', 'check_id': 'password-warning-age-effective',
         'status': 'pass' if warning_ok else 'fail'}],
        'account_count': len(accounts), 'locked_account_count': locked,
        'eligible_password_account_count': eligible,
        'password_account_subjects': 'not_applicable_no_password_accounts' if not eligible else 'evaluated',
        'global_defaults_checked': True, 'read_only': True, 'credential_values_exported': False}


def collect_accounts(entries, run=subprocess.run):
    accounts = []
    require(0 < len(entries) <= 1024, 'Missing or excessive account metadata')
    for entry in entries:
        result = run(['/usr/bin/passwd', '--status', entry.pw_name], capture_output=True,
                     text=True, timeout=10, env={'LC_ALL': 'C', 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
        require(result.returncode == 0, 'Password status query failed')
        fields = result.stdout.split()
        require(len(fields) >= 2 and fields[0] == entry.pw_name, 'Invalid password status metadata')
        record = {'status': fields[1]}
        if fields[1] == 'P':
            result = run(['/usr/bin/chage', '--list', entry.pw_name], capture_output=True,
                         text=True, timeout=10, env={'LC_ALL': 'C', 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
            require(result.returncode == 0, 'Password aging query failed')
            record.update(aging_fields(result.stdout))
        accounts.append(record)
    return accounts


def main():
    require(len(sys.argv) == 3, 'Expected maximum-age and warning-age policies')
    require(os.geteuid() == 0, 'Root is required for complete account status metadata')
    signal.alarm(120)
    maximum, warning = map(int, sys.argv[1:])
    # Fixed native paths; the CLI deliberately has no test-root or account filter.
    result = evaluate(login_defaults(Path('/etc/login.defs').read_text()),
                      collect_accounts(pwd.getpwall()), maximum, warning)
    print(json.dumps(result, sort_keys=True))
    return 0 if all(item['status'] == 'pass' for item in result['results']) else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError):
        # Do not print command arguments, account names or native command output.
        print(json.dumps({'error': 'Password policy metadata could not be verified', 'read_only': True}))
        raise SystemExit(2)
