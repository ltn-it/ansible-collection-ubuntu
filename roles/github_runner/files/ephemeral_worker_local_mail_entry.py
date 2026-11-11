"""One independently supervised local-mail tick, no worker or lease effects."""
import json
import os
from pathlib import Path
import re
import stat
import sys

MODULES = frozenset({'ephemeral_worker_admission.py', 'ephemeral_worker_lease.py',
    'ephemeral_worker_incus.py', 'ephemeral_worker_watchdog.py', 'ephemeral_worker_alarm.py',
    'ephemeral_worker_local_mail.py', 'ephemeral_worker_local_mail_entry.py'})


def trusted_modules():
    if os.geteuid() != 0:
        raise PermissionError('root-required')
    here = Path(__file__).absolute().parent
    for parent in [here, *here.parents]:
        value = parent.lstat()
        if not (stat.S_ISDIR(value.st_mode) and value.st_uid == 0
                and (not value.st_mode & 0o022 or value.st_mode & stat.S_ISVTX)):
            raise PermissionError('untrusted-program-directory')
    if stat.S_IMODE(here.stat().st_mode) != 0o700:
        raise PermissionError('untrusted-program-mode')
    for name in MODULES:
        value = (here / name).lstat()
        if not (stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1
                and stat.S_IMODE(value.st_mode) == 0o600):
            raise PermissionError('untrusted-program-file')
    sys.path.insert(0, str(here))


def tick(store, *, now, machine_path='/etc/machine-id'):
    import fcntl
    from ephemeral_worker_lease import Store, Held, require
    from ephemeral_worker_local_mail import LocalForwarder

    require(type(store) is Store, 'local-mail-entry-store')
    sender = LocalForwarder(store, machine_path=machine_path)
    store._directory()
    lock = os.open('local-mail-entry.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                   0o600, dir_fd=store.fd)
    try:
        store._private_file(lock)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Held('local-mail-entry-busy') from None
        events = []
        with os.scandir(store.fd) as files:
            for count, item in enumerate(files, 1):
                require(count <= 1024, 'local-mail-entry-directory-bound')
                found = re.fullmatch(r'alarm-([0-9a-f]{64})\.json', item.name)
                if found:
                    events.append(found.group(1))
                    require(len(events) <= 256, 'local-mail-entry-event-bound')
        cursor = sender._read('local-mail-cursor.json', missing=True)
        if cursor is not None:
            require(type(cursor) is dict and set(cursor) == {'schema', 'last_event_id', 'source_machine_id'}
                and type(cursor['schema']) is int and cursor['schema'] == 1
                and type(cursor['last_event_id']) is str
                and re.fullmatch('[0-9a-f]{64}', cursor['last_event_id'])
                and cursor['source_machine_id'] == sender.machine, 'local-mail-entry-cursor')
        last = cursor['last_event_id'] if cursor else ''
        ordered = sorted(events, key=lambda event: (event <= last, event))
        for event in ordered:
            if sender.confirmed(event, now=now):
                continue
            # Durable rotation precedes dispatch: one unavailable mailbox/intent
            # cannot indefinitely starve later events after a killed tick.
            sender._save('local-mail-cursor.json', {'schema': 1, 'last_event_id': event,
                                                   'source_machine_id': sender.machine})
            receipt = sender.send(event, now=now)
            return {'state': 'LOCAL_MAIL_CONFIRMED', 'event_id': event,
                    'local_mailbox_confirmed': receipt['local_mailbox_confirmed'],
                    'personal_acknowledged': False, 'capacity_released': False}
        return {'state': 'LOCAL_MAIL_NO_UNCONFIRMED_EVENTS', 'personal_acknowledged': False,
                'capacity_released': False}
    finally:
        os.close(lock)


def main():
    trusted_modules()
    import argparse
    import time
    from ephemeral_worker_incus import machine_id
    from ephemeral_worker_lease import Store, require

    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--machine-id', required=True)
    args = parser.parse_args()
    require(re.fullmatch(r'/var/lib/lightning-it/[A-Za-z0-9_-]+', args.state_directory)
        and re.fullmatch('[0-9a-f]{32}', args.machine_id)
        and machine_id('/etc/machine-id') == args.machine_id, 'local-mail-entry-target')
    store = Store(args.state_directory)
    try:
        print(json.dumps(tick(store, now=int(time.time())), sort_keys=True))
    finally:
        store.close()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'state': 'LOCAL_MAIL_UNCONFIRMED', 'error_type': type(error).__name__,
                          'personal_acknowledged': False, 'capacity_released': False}))
        raise SystemExit(1)
