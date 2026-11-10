"""Root-owned, one-worker rootless Podman service producer.

Called only after the protected registrar re-attests a stopped ephemeral runner.
Write-ahead intent precedes ID-map/file/service effects. Incomplete states hold;
there is no restart, rollback, registration or cleanup shortcut here.
"""
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import struct
import re
import stat
import tempfile
import time

from incus_lease_issuer.identity import decode_json, require
from incus_lease_issuer.installation import trusted_file

STATE = Path('/var/lib/github-runner-engine')
CONFIG = Path('/etc/github-runner-engine/client.json')
CLIENT = Path('/usr/local/libexec/lit-runner-engine/podman')
HOME = Path('/var/lib/lit-runner-engine')
SYSTEMD = Path('/etc/systemd/system')
SUBIDS = (Path('/etc/subuid'), Path('/etc/subgid'))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def root_directory(path):
    current = Path('/')
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and not info.st_mode & 0o022, 'engine-unsealed-ancestor')


def atomic(path, raw, mode=0o600):
    root_directory(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix='.engine-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def save(value):
    atomic(STATE / 'journal.json', json.dumps(value, sort_keys=True).encode())


def mapping(raw, user, uid, start):
    require(type(start) is int and 100000 <= start <= 2**32 - 65536, 'engine-subid-range')
    owned = []
    for line in raw.decode('ascii').splitlines():
        if not line or line.startswith('#'):
            continue
        fields = line.split(':')
        require(len(fields) == 3 and re.fullmatch(r'[A-Za-z0-9_.-]+', fields[0])
                and fields[1].isdigit() and fields[2].isdigit(), 'engine-subid-file')
        begin, count = map(int, fields[1:])
        require(count > 0 and begin >= 0 and begin + count <= 2**32, 'engine-subid-file')
        if fields[0] in (user, str(uid)):
            owned.append((begin, count))
        else:
            require(begin + count <= start or start + 65536 <= begin, 'engine-subid-overlap')
    require(not owned or owned == [(start, 65536)], 'engine-existing-subid-drift')
    if owned:
        return raw
    return raw + (b'\n' if raw and not raw.endswith(b'\n') else b'') + f'{user}:{start}:65536\n'.encode()


def service(name, user, group):
    home = str(HOME / name)
    runtime = '/run/lit-runner-engine-' + name
    return ('[Unit]\nDescription=Private ephemeral worker rootless engine\n'
            '[Service]\nType=exec\nUser=' + user + '\nGroup=' + group + '\n'
            'Environment=HOME=' + home + '\nEnvironment=XDG_RUNTIME_DIR=' + runtime + '\n'
            'Environment=CONTAINERS_CONF=/dev/null\nUMask=0077\n'
            'RuntimeDirectory=lit-runner-engine-' + name + '\nRuntimeDirectoryMode=0700\n'
            'ExecStart=/usr/bin/podman --cgroup-manager=cgroupfs --events-backend=file --root=' + home + '/storage --runroot=' + runtime + '/storage '
            '--log-level=error system service --time=0 unix://' + runtime + '/podman.sock\n'
            'Restart=no\nRuntimeMaxSec=7200\nTimeoutStopSec=30\nKillMode=control-group\n'
            'Delegate=yes\nMemoryMax=8G\nTasksMax=256\n').encode()


def properties(command, unit):
    raw = command(['/usr/bin/systemctl', 'show', '--property=ActiveState,SubState,MainPID,InvocationID', '--', unit])
    value = dict(line.split('=', 1) for line in raw.splitlines())
    require(set(value) == {'ActiveState', 'SubState', 'MainPID', 'InvocationID'}, 'engine-native-state')
    return value


def process_identity(pid):
    process = Path('/proc') / str(pid)
    raw = (process / 'stat').read_text()
    status = dict(line.split(':', 1) for line in (process / 'status').read_text().splitlines())
    return {'pid': pid, 'ppid': int(status['PPid']), 'starttime': raw[raw.rfind(')') + 2:].split()[19],
            'uids': list(map(int, status['Uid'].split())), 'gids': list(map(int, status['Gid'].split())),
            'groups': list(map(int, status['Groups'].split())), 'exe': os.readlink(process / 'exe'),
            'cgroup': (process / 'cgroup').read_text().strip()}


def peer_lineage(peer_pid, main_pid, uid, gid, control_group, reader=process_identity):
    """Bind Podman's re-executed API child to its exact native service parent."""
    chain, seen = [], set()
    pid = peer_pid
    for _ in range(32):
        require(pid > 1 and pid not in seen, 'engine-peer-ancestry')
        seen.add(pid)
        value = reader(pid)
        group = value['cgroup']
        require(value['pid'] == pid and value['exe'] == '/usr/bin/podman'
                and value['uids'] == [uid] * 4 and value['gids'] == [gid] * 4
                and not set(value['groups']) - {gid}
                and (group == '0::' + control_group or group.startswith('0::' + control_group + '/')),
                'engine-peer-service-identity')
        chain.append(value)
        if pid == main_pid:
            break
        pid = value['ppid']
    require(chain[-1]['pid'] == main_pid, 'engine-peer-not-native-descendant')
    for value in chain:
        require(reader(value['pid']) == value, 'engine-peer-process-changed')
    return chain


def attest(native, binding, config, command):
    """Root-acquired kernel evidence of the exact freshly observed native PID."""
    unit = 'lit-runner-engine-' + binding['name'] + '.service'
    details = dict(line.split('=', 1) for line in command([
        '/usr/bin/systemctl', 'show', '--property=FragmentPath,DropInPaths,User,Group,Restart,RuntimeMaxUSec,ControlGroup',
        '--', unit]).splitlines())
    require(details == {'FragmentPath': str(SYSTEMD / unit), 'DropInPaths': '', 'User': binding['user'],
                        'Group': binding['group'], 'Restart': 'no', 'RuntimeMaxUSec': '2h',
                        'ControlGroup': '/system.slice/' + unit},
            'engine-native-unit-policy')
    pid = int(native['MainPID'])
    process = Path('/proc') / str(pid)
    before = (process / 'stat').read_text()
    start = before[before.rfind(')') + 2:].split()[19]
    require(os.readlink(process / 'exe') == '/usr/bin/podman', 'engine-native-executable')
    status = dict(line.split(':', 1) for line in (process / 'status').read_text().splitlines())
    require(list(map(int, status['Uid'].split())) == [binding['uid']] * 4
            and list(map(int, status['Gid'].split())) == [binding['gid']] * 4,
            'engine-native-process-identity')
    runtime = Path(config['socket']).parent
    for path, kind in ((runtime, stat.S_ISDIR), (Path(config['socket']), stat.S_ISSOCK),
                       (Path(config['home']), stat.S_ISDIR)):
        info = path.lstat()
        require(kind(info.st_mode) and info.st_uid == binding['uid'] and info.st_gid == binding['gid']
                and not info.st_mode & 0o077, 'engine-private-path-identity')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(3)
        peer.connect(config['socket'])
        peer_pid, uid, gid = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require((uid, gid) == (binding['uid'], binding['gid']), 'engine-native-socket-peer')
        peer_lineage(peer_pid, pid, uid, gid, details['ControlGroup'])
    after = (process / 'stat').read_text()
    require(after[after.rfind(')') + 2:].split()[19] == start, 'engine-native-pid-reused')


def prerequisites():
    trusted_file('/usr/bin/podman', max_bytes=256 * 1024 * 1024)
    trusted_file('/usr/sbin/usermod', max_bytes=16 * 1024 * 1024)
    for binary in ('/usr/bin/newuidmap', '/usr/bin/newgidmap'):
        root_directory(Path(binary).parent)
        descriptor = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                    and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o4755,
                    'engine-mapping-helper-not-sealed-setuid')
        finally:
            os.close(descriptor)


def prepare(binding, ranges, client, command, identity_check):
    """Binding/identity_check come from the Root protected registrar, never job JSON."""
    require(os.geteuid() == 0, 'engine-root-required')
    require(set(binding) == {'name', 'user', 'group', 'uid', 'gid', 'runner_id', 'runner_unit', 'manifest_sha256'},
            'engine-binding-shape')
    require(type(binding['runner_id']) is int and binding['runner_id'] > 0
            and type(binding['manifest_sha256']) is str
            and re.fullmatch(r'[0-9a-f]{64}', binding['manifest_sha256'])
            and type(binding['user']) is str and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', binding['user'])
            and binding['user'] != 'root' and binding['group'] == binding['user']
            and type(binding['runner_unit']) is str
            and re.fullmatch(r'actions\.runner\.[A-Za-z0-9_.-]+\.service', binding['runner_unit']),
            'engine-registration-binding')
    name = binding['name']
    require(type(name) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', name), 'engine-name')
    require(type(binding['uid']) is int and binding['uid'] > 0
            and type(binding['gid']) is int and binding['gid'] > 0, 'engine-service-identity')
    require(type(ranges) is dict and set(ranges) == {'subuid_start', 'subgid_start'}, 'engine-ranges')
    require(isinstance(client, bytes) and client.startswith(b'#!/usr/bin/python3\n'), 'engine-client-source')
    unit = 'lit-runner-engine-' + name + '.service'
    unit_path = SYSTEMD / unit
    config = {'schema': 1, 'uid': binding['uid'], 'gid': binding['gid'],
              'socket': '/run/lit-runner-engine-' + name + '/podman.sock', 'home': str(HOME / name)}
    files = {str(CONFIG): (json.dumps(config, sort_keys=True).encode(), 0o644),
             str(CLIENT): (client, 0o755), str(unit_path): (service(name, binding['user'], binding['group']), 0o644)}
    hashes = {path: digest(raw) for path, (raw, _) in files.items()}
    identity_check()
    runner = properties(command, binding['runner_unit'])
    require(runner['ActiveState'] == 'inactive' and runner['MainPID'] == '0', 'engine-runner-not-stopped')
    prerequisites()
    before, after = {}, {}
    host_ids = ([p.pw_uid for p in pwd.getpwall()], [g.gr_gid for g in grp.getgrall()])
    for path, key, allocated in zip(SUBIDS, ('subuid_start', 'subgid_start'), host_ids):
        trusted_file(str(path), max_bytes=1024 * 1024)
        raw = path.read_bytes()
        before[str(path)] = raw
        after[str(path)] = mapping(raw, binding['user'], binding['uid'], ranges[key])
        require(not any(ranges[key] <= value < ranges[key] + 65536 for value in allocated),
                'engine-subid-overlaps-host-account')
    expected = {'binding': binding, 'ranges': ranges, 'files': hashes,
                'subids': {p: digest(raw) for p, raw in after.items()}}
    if STATE.exists() or STATE.is_symlink():
        root_directory(STATE)
        require(stat.S_IMODE(STATE.stat().st_mode) == 0o700, 'engine-state-not-private')
        trusted_file(str(STATE / 'journal.json'), max_bytes=65536)
        saved = decode_json((STATE / 'journal.json').read_bytes())
        require(saved.get('phase') == 'complete' and saved.get('expected') == expected,
                'engine-incomplete-or-drifted-intent')
    else:
        require(not any(os.path.lexists(p) for p in (CONFIG.parent, CLIENT.parent, HOME / name, unit_path)),
                'engine-unproven-existing-files')
        require(not command(['/usr/bin/systemctl', 'list-units', '--all', '--plain', '--no-legend',
                             '--', unit]).strip(), 'engine-unproven-loaded-unit')
        root_directory(STATE.parent)
        STATE.mkdir(mode=0o700)
        parent_fd = os.open(STATE.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        saved = {'phase': 'install-intent', 'expected': expected,
                 'subids_before_sha256': {p: digest(raw) for p, raw in before.items()}}
        save(saved)
    lock = os.open(STATE / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'engine-lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Re-read after lock. A concurrent or interrupted intent is never replayed.
        current = decode_json((STATE / 'journal.json').read_bytes())
        require(current == saved, 'engine-concurrent-intent')
        if saved['phase'] == 'complete':
            for path, (raw, mode) in files.items():
                require(trusted_file(path, max_bytes=1024 * 1024).sha256 == digest(raw)
                        and stat.S_IMODE(Path(path).stat().st_mode) == mode, 'engine-file-drift')
            require(all(Path(p).read_bytes() == raw for p, raw in after.items()), 'engine-subid-drift')
            native = properties(command, unit)
            require(native == saved['native'] and native['ActiveState'] == 'active'
                    and native['MainPID'].isdigit() and int(native['MainPID']) > 0, 'engine-lifetime-ended-or-changed')
            attest(native, binding, config, command)
            require(properties(command, unit) == native, 'engine-native-state-changed')
            return {'changed': False, 'unit': unit, 'native': native}
        require(all(Path(path).read_bytes() == raw for path, raw in before.items()), 'engine-subid-raced')
        allocation = ['/usr/sbin/usermod']
        for path, option, key in zip(SUBIDS, ('--add-subuids', '--add-subgids'), ('subuid_start', 'subgid_start')):
            if before[str(path)] != after[str(path)]:
                allocation += [option, f'{ranges[key]}-{ranges[key] + 65535}']
        if len(allocation) > 1:
            # Shadow-utils owns native account-file locks; never replace /etc
            # mapping files with an unlocked private rewrite.
            command([*allocation, binding['user']])
        require(all(Path(path).read_bytes() == raw for path, raw in after.items()), 'engine-subid-outcome-unknown')
        for parent in (CONFIG.parent, CLIENT.parent, HOME):
            missing = []
            current = parent
            while not current.exists():
                missing.append(current)
                current = current.parent
            root_directory(current)
            for current in reversed(missing):
                current.mkdir(mode=0o755)
            root_directory(parent)
        home = HOME / name
        home.mkdir(mode=0o700)
        os.chown(home, binding['uid'], binding['gid'])
        for path, (raw, mode) in files.items():
            require(not os.path.lexists(path), 'engine-file-raced')
            atomic(Path(path), raw, mode)
        command(['/usr/bin/systemctl', 'daemon-reload'])
        identity_check()
        runner = properties(command, binding['runner_unit'])
        require(runner['ActiveState'] == 'inactive' and runner['MainPID'] == '0', 'engine-runner-not-stopped')
        saved['phase'] = 'start-intent'
        save(saved)
        command(['/usr/bin/systemctl', 'start', '--', unit])
        native = properties(command, unit)
        require(native['ActiveState'] == 'active' and native['MainPID'].isdigit()
                and int(native['MainPID']) > 0 and re.fullmatch(r'[0-9a-f]{32}', native['InvocationID']),
                'engine-start-outcome-unknown')
        deadline = time.monotonic() + 15
        while True:
            require(properties(command, unit) == native, 'engine-native-state-changed')
            try:
                attest(native, binding, config, command)
                break
            except (FileNotFoundError, ConnectionRefusedError, TimeoutError):
                require(time.monotonic() < deadline, 'engine-socket-readiness-unknown')
                time.sleep(0.1)
        require(properties(command, unit) == native, 'engine-native-state-changed')
        saved.update(phase='complete', native=native)
        save(saved)
        return {'changed': True, 'unit': unit, 'native': native}
    finally:
        os.close(lock)
