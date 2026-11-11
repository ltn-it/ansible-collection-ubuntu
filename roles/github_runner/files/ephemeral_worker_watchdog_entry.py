"""Isolated Root entrypoint for one watchdog tick; never starts workers."""
import json
import os
from pathlib import Path
import stat
import sys


def trusted_modules():
    if os.geteuid() != 0:
        raise PermissionError('root-required')
    here = Path(__file__).absolute().parent
    # Validate parents before adding this explicit path under Python -I.
    for parent in [here, *here.parents]:
        value = parent.lstat()
        if not (stat.S_ISDIR(value.st_mode) and value.st_uid == 0
                and (not value.st_mode & 0o022 or value.st_mode & stat.S_ISVTX)):
            raise PermissionError('untrusted-program-directory')
    for name in ['ephemeral_worker_watchdog_entry.py', 'ephemeral_worker_watchdog.py',
                 'ephemeral_worker_admission.py', 'ephemeral_worker_lease.py', 'ephemeral_worker_incus.py']:
        value = (here / name).lstat()
        if not (stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1
                and not value.st_mode & 0o022):
            raise PermissionError('untrusted-program-file')
    sys.path.insert(0, str(here))


def main():
    trusted_modules()
    import argparse
    import time
    from ephemeral_worker_lease import Store
    from ephemeral_worker_incus import StopOnly, RemoveOnly
    from ephemeral_worker_watchdog import Watchdog

    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--state-directory', required=True)
    args = parser.parse_args()

    class Native:
        # Lazy adapters let an empty/pre-effect Store be supervised while Incus
        # is down. Each effect still uses the native adapter's full pinned-peer
        # and one-shot Store checks; no transport settings are CLI inputs.
        @staticmethod
        def stop(store, operation):
            provider = StopOnly()
            try:
                return provider.stop(store, operation)
            finally:
                provider.close()

        @staticmethod
        def observe_runtime(name, plan):
            provider = StopOnly()
            try:
                return provider.observe_runtime(name, plan)
            finally:
                provider.close()

        @staticmethod
        def absent(name, plan):
            provider = RemoveOnly()
            try:
                return provider.absent(name, plan)
            finally:
                provider.close()

    store = Store(args.state_directory)
    try:
        result = Watchdog(store, stopper=Native(), remover=Native()).tick(now=int(time.time()))
        print(json.dumps(result, sort_keys=True))
        return 1 if result['state'] == 'ALARM_PENDING' else 0
    finally:
        store.close()


if __name__ == '__main__':
    try:
        code = main()
    except Exception as error:
        # Never print the exception payload, state bytes, credentials or argv.
        print(json.dumps({'state': 'WATCHDOG_UNAVAILABLE', 'error_type': type(error).__name__,
                          'alarm_delivered': False}))
        code = 1
    raise SystemExit(code)
