"""Offline Root generation publisher, never native job or custody authority.

Authenticated acquisition and raw Git blob matching precede immutable Root
cell/registry/preparation/runtime files. Only the fixed anchor is replaced.
Existing generations and failed partial generations are never deleted/adopted.
The socket and all accepted service instances must be inactive at both checks;
a trusted maintenance operator must exclude concurrent privileged starts;
there is intentionally no old-generation live routing or fleet activation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import time
import zipfile

from . import (admission, cell_contract, engine_policy as engine, generation_acquisition as acquisition,
               identity, installation, ledger, policy_registry, preparation, runtime_entry, runtime_rpc)
from .identity import Denied, require

ROOT = '/var/lib/lightning-it/incus-runtime-generations'
ANCHOR = runtime_entry.ANCHOR
MAX_FILE = 256*1024*1024
MAX_TOTAL = 2*1024**3
MAX_MEMBERS = 100000


@dataclass(frozen=True)
class PublishedGeneration:
    generation_path: str
    runtime_path: str
    runtime_sha256: str
    anchor_sha256: str
    provenance_sha256: str


def _read(path, digest, limit=cell_contract.MAX_CELL):
    proof, raw, stamp = installation._file(engine._path(path), limit, private=True, keep=True)
    require(proof.sha256 == engine._hash(digest), 'generation-input-drift')
    return identity.decode_json(raw)


def _write(path, raw, *, mode=0o600):
    require(type(raw) is bytes and len(raw) <= MAX_FILE and mode in {0o600,0o700}, 'generation-file-size')
    parent = installation._open_directory(str(path.parent))
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        try:
            view = memoryview(raw)
            while view:
                size = os.write(fd, view)
                require(size > 0, 'generation-short-write')
                view = view[size:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)
    return hashlib.sha256(raw).hexdigest()


def _json(path, value):
    return _write(path, ledger.canonical(value))


def _mkdir(path):
    parent = installation._open_directory(str(path.parent))
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def _relative(value):
    return engine._relative(value)


def _member_bytes(stream, size):
    require(type(size) is int and 0 <= size <= MAX_FILE, 'generation-member-size')
    raw = stream.read(size+1)
    require(len(raw) == size, 'generation-member-truncated')
    return raw


def _tar(raw, *, prefix=False):
    """Never extractall: closed regular files/directories, no link adoption."""
    files, dirs, seen, total, top = {}, set(), set(), 0, None
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for number, member in enumerate(archive):
            require(number < MAX_MEMBERS and (member.isfile() or member.isdir()), 'generation-tar-kind')
            name = member.name.rstrip('/')
            if name in {'.', ''}:
                require(member.isdir() and not prefix, 'generation-tar-root')
                continue
            name = _relative(name)
            require(name not in seen, 'generation-duplicate-member')
            seen.add(name)
            if prefix:
                pieces = name.split('/', 1)
                if top is None:
                    top = pieces[0]
                require(pieces[0] == top, 'generation-archive-prefix')
                if len(pieces) == 1:
                    require(member.isdir(), 'generation-archive-root')
                    continue
                name = _relative(pieces[1])
            if member.isdir():
                dirs.add(name)
                continue
            require(member.mode & 0o7777 in {0o644, 0o755, 0o664, 0o775, 0o600, 0o700}, 'generation-tar-mode')
            total += member.size
            require(total <= MAX_TOTAL, 'generation-tree-size')
            files[name] = (_member_bytes(archive.extractfile(member), member.size), bool(member.mode & 0o111))
    require(files and not set(files) & dirs, 'generation-empty-or-overlap')
    for name in files:
        parent = PurePosixPath(name).parent
        while parent != PurePosixPath('.'):
            require(str(parent) not in files, 'generation-file-ancestor')
            dirs.add(str(parent))
            parent = parent.parent
    return files, dirs


def _git_archive(raw, proven):
    files, directories = _tar(raw, prefix=True)
    expected = {entry.path: entry for entry in proven.files}
    require(len(expected) == len(proven.files) and set(files) == set(expected)
            and directories == set(proven.directories), 'generation-git-inventory')
    for name, (content, executable) in files.items():
        entry = expected[name]
        oid = hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()
        require(entry.size == len(content) and entry.oid == oid
                and executable == (entry.mode == '100755'), 'generation-git-blob')
    return {name: content for name, (content, _) in files.items()}


def _tree(path, files, *, executable=()):
    _mkdir(path)
    directories = set()
    for name in files:
        _relative(name)
        parent = PurePosixPath(name).parent
        while parent != PurePosixPath('.'):
            directories.add(str(parent))
            parent = parent.parent
    for name in sorted(directories, key=lambda value: (value.count('/'), value)):
        _mkdir(path/name)
    require(set(executable) <= set(files), 'generation-executable-inventory')
    hashes = {name: _write(path/name, content, mode=0o700 if name in executable else 0o600)
              for name, content in sorted(files.items())}
    value = {'path':str(path), 'files':hashes, 'directories':sorted(directories)}
    engine._tree(value)
    return value


def _source_provenance(proven):
    """Project the authenticated, blob-verified archive into engine metadata.

    Called only after _git_archive verifies every supplied Source blob. This
    records actual API commit/tree identity; it never invents Git objects or a
    checkout. The Root engine descriptor seals the derived candidate file.
    """
    require(type(proven) is acquisition.CommitAcquisition
            and proven.repository == acquisition.SUPPLEMENTARY
            and proven.repository_id == acquisition.REPOSITORIES[acquisition.SUPPLEMENTARY],
            'generation-source-provenance')
    return {'schema':1, 'repository':proven.repository, 'repository_id':proven.repository_id,
            'commit_sha':proven.commit_sha, 'tree_sha':proven.tree_sha,
            'files':[{'path':entry.path,'mode':entry.mode,'oid':entry.oid,'size':entry.size}
                     for entry in sorted(proven.files,key=lambda entry:entry.path)]}


def _runtime_bundle(raw):
    """Validate inert dependency bytes, including confined relative links.

    Never extract or follow a dependency link as Root. The unprivileged
    consumer remains responsible for its extraction policy.
    """
    seen, kinds, total, files = set(), {}, 0, 0
    candidate = ('ansible_collections', 'lit', 'supplementary')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for number, member in enumerate(archive):
            require(number < MAX_MEMBERS, 'generation-runtime-members')
            name = _relative(member.name.rstrip('/'))
            parts = PurePosixPath(name).parts
            require(parts[0] == 'ansible_collections' and parts[:3] != candidate
                and name not in seen and (member.isfile() or member.isdir() or member.issym() or member.islnk()),
                'generation-runtime-scope')
            seen.add(name); kinds[name] = 'dir' if member.isdir() else 'other'
            require(0 <= member.size <= MAX_FILE, 'generation-runtime-size')
            total += member.size
            require(total <= MAX_TOTAL, 'generation-runtime-size')
            if member.isfile():
                _member_bytes(archive.extractfile(member), member.size)
                files += 1
            if member.issym() or member.islnk():
                link = PurePosixPath(member.linkname)
                require(member.linkname and not link.is_absolute(), 'generation-runtime-link')
                target = (PurePosixPath(name).parent / link) if member.issym() else link
                normalized = []
                for piece in target.parts:
                    if piece == '..':
                        require(normalized, 'generation-runtime-link')
                        normalized.pop()
                    elif piece not in {'', '.'}:
                        normalized.append(piece)
                require(normalized and normalized[0] == 'ansible_collections'
                    and tuple(normalized[:3]) != candidate, 'generation-runtime-link')
    require(files > 0, 'generation-runtime-empty')
    for name in seen:
        require(all(kinds.get(str(parent), 'dir') == 'dir' for parent in PurePosixPath(name).parents
                    if str(parent) != '.'), 'generation-runtime-ancestor')


def _source_version(workspace):
    """The producer's simple literal galaxy version, from authenticated Git."""
    raw = workspace.get('galaxy.yml')
    require(type(raw) is bytes and 0 < len(raw) <= 131072, 'generation-source-galaxy')
    lines = [line for line in raw.decode('utf-8').splitlines() if re.match(r'version[ \t]*:',line)]
    require(len(lines) == 1, 'generation-source-version')
    match = re.fullmatch(r"version:[ \t]*(['\"]?)([0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?)\1(?:[ \t]+#.*)?[ \t]*", lines[0])
    require(match is not None, 'generation-source-version')
    return match[2]


def _candidate(raw, workspace=None):
    files, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for item in archive.infolist():
            require(len(files) < 3 and not item.is_dir() and item.filename not in files
                    and '/' not in item.filename and '\\' not in item.filename
                    and not item.flag_bits & 1 and not stat.S_ISLNK(item.external_attr >> 16), 'generation-zip-member')
            _relative(item.filename)
            total += item.file_size
            require(total <= MAX_TOTAL, 'generation-zip-size')
            files[item.filename] = _member_bytes(archive.open(item), item.file_size)
    candidates = [name for name in files if re.fullmatch(r'lit-supplementary-[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?\.tar\.gz', name)]
    require(len(candidates) == 1 and set(files) == {candidates[0], 'runtime-collections.tar.gz', 'candidate-SHA256SUMS'}, 'generation-candidate-inventory')
    checks = {}
    for line in files['candidate-SHA256SUMS'].decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        require(match is not None and match[2] not in checks, 'generation-inner-checksums')
        checks[match[2]] = match[1]
    require(set(checks) == {candidates[0], 'runtime-collections.tar.gz'}
            and all(hashlib.sha256(files[name]).hexdigest() == digest for name,digest in checks.items()), 'generation-inner-digest')
    collection, _ = _tar(files[candidates[0]])
    require({'MANIFEST.json','FILES.json'} <= set(collection), 'generation-galaxy-manifests')
    manifest = identity.decode_json(collection['MANIFEST.json'][0])
    info, file_manifest = manifest['collection_info'], manifest['file_manifest_file']
    require(info['namespace'] == 'lit' and info['name'] == 'supplementary'
            and candidates[0] == 'lit-supplementary-'+info['version']+'.tar.gz'
            and file_manifest['name'] == 'FILES.json' and file_manifest['chksum_type'] == 'sha256'
            and file_manifest['chksum_sha256'] == hashlib.sha256(collection['FILES.json'][0]).hexdigest(), 'generation-galaxy-identity')
    index = identity.decode_json(collection['FILES.json'][0])
    listed = {}
    for row in index['files']:
        if row['ftype'] == 'file':
            name = _relative(row['name'])
            require(name not in listed and row['chksum_type'] == 'sha256', 'generation-galaxy-files')
            listed[name] = row['chksum_sha256']
        else:
            require(row['ftype'] == 'dir', 'generation-galaxy-type')
    require(set(collection)-{'MANIFEST.json','FILES.json'} == set(listed)
            and all(hashlib.sha256(collection[name][0]).hexdigest() == digest for name,digest in listed.items()), 'generation-galaxy-digest')
    # Dependency bundle is retained as inert bytes, never extracted/executed as Root.
    _runtime_bundle(files['runtime-collections.tar.gz'])
    if workspace is not None:
        require(info['version'] == _source_version(workspace), 'generation-candidate-version')
        require(all(name in workspace and workspace[name] == collection[name][0] for name in listed),
                'generation-candidate-source')
    return files, candidates[0], checks


def _collector(path, digest):
    value = _read(path, digest)
    engine._keys(value, {'schema','service','profile_name','profile_path','profile_sha256',
                         'operation_reference','storage_reference','custodian_reference'})
    require(type(value['schema']) is int and value['schema'] == 1, 'generation-collector-schema')
    result = {key:value[key] for key in ('service','profile_name','profile_path','profile_sha256')}
    result = json.loads(json.dumps(result))
    result['service']['dropins'] = [{'path':row[0], 'sha256':row[1]} for row in result['service']['dropins']
                                  if type(row) is list and len(row) == 2]
    require(len(result['service']['dropins']) == len(value['service']['dropins']), 'generation-collector-dropins')
    result.update(config_path=path, config_sha256=digest)
    policy_registry._collector(result)
    return result


def _inactive():
    env = {'PATH':'/usr/bin:/bin','LC_ALL':'C'}
    result = subprocess.run(['/usr/bin/systemctl','show','lit-incus-runtime-v2.socket',
        '--property=ActiveState,SubState','--no-pager'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,timeout=5,check=False,env=env)
    require(result.returncode == 0 and set(result.stdout.decode().splitlines()) == {'ActiveState=inactive','SubState=dead'}, 'generation-socket-not-inactive')
    result = subprocess.run(['/usr/bin/systemctl','list-units','--all','--type=service','--output=json','--no-pager',
        'lit-incus-runtime-v2@*.service'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,timeout=5,check=False,env=env)
    require(result.returncode == 0 and len(result.stdout) <= 65536, 'generation-instance-inventory')
    rows = json.loads(result.stdout)
    require(type(rows) is list and len(rows) <= 128 and all(type(row) is dict
        and row.get('unit','').startswith('lit-incus-runtime-v2@') and row.get('active') == 'inactive'
        and row.get('sub') == 'dead' for row in rows), 'generation-instance-active')


def _anchor(expected):
    try:
        proof, raw, stamp = installation._file(ANCHOR, 16384, private=True, keep=True)
    except FileNotFoundError:
        require(expected is None, 'generation-anchor-missing')
        return None
    require(expected is not None and proof.sha256 == engine._hash(expected), 'generation-anchor-conflict')
    value = identity.decode_json(raw)
    engine._keys(value, {'schema','config_path','config_sha256'})
    require(type(value['schema']) is int and value['schema'] == 1, 'generation-anchor-schema')
    engine._path(value['config_path']);engine._hash(value['config_sha256'])
    require(value['config_path'] != ANCHOR, 'generation-anchor-cycle')
    return value, proof, stamp


def _fd_bytes(fd):
    os.lseek(fd,0,os.SEEK_SET)
    size = os.fstat(fd).st_size
    require(size <= MAX_TOTAL, 'generation-archive-size')
    raw = bytearray()
    while len(raw) < size:
        piece = os.read(fd,min(65536,size-len(raw)))
        require(piece, 'generation-archive-short')
        raw.extend(piece)
    return bytes(raw)


def _static_cells(registry, acquired_run_id):
    """Use actual sealed AdmissionPolicies, without inventing a native Identity."""
    now = int(time.time())
    for selector in registry.policies:
        policy = registry.select(selector)
        admission._validate_policy(policy)
        admission._controls(policy)
        cell = _read(policy.cell_config_path, policy.cell_sha256)
        engine._keys(cell, {'schema','candidate','controller','matrix','github','engine','incus'})
        require(type(cell['schema']) is int and cell['schema'] == 1, 'generation-cell-schema')
        candidate = engine._keys(cell['candidate'], {'repository','source_sha','artifact','archive_sha256'})
        controller = engine._keys(cell['controller'], {'repository','source_sha','archive_sha256','files'})
        cell_contract._repo(candidate['repository']); cell_contract._commit(candidate['source_sha'])
        cell_contract._commit(controller['source_sha'])
        require(controller['repository'] == policy.identity.reusable_repository, 'generation-controller-repository')
        # Legacy preparation uses the producer run for static template checks.
        # The Main receiver has a distinct Root-selected consumer run. Reading
        # it here is static consistency only, never native job authentication;
        # admission independently verifies that exact consumer before a lease.
        static_run_id = acquired_run_id
        if identity.validation_main_receiver(policy.identity):
            github = engine._keys(cell['github'], {'job','workflow','run_id'})
            require(type(github['run_id']) is int and 0 < github['run_id'] < 2**63,
                    'generation-receiver-run')
            static_run_id = github['run_id']
        env = cell_contract._environment(cell, policy.identity, {'run_id':static_run_id})
        cell_contract._validate_engine_template(cell['engine'], env, policy.identity, policy.deadline, now)
        cell_contract._validate_incus_template(cell['incus'], env)
        require(cell['engine']['archives']['candidate']['sha256'] == engine._hash(candidate['archive_sha256'])
            and cell['engine']['archives']['controller']['sha256'] == engine._hash(controller['archive_sha256'])
            and type(controller['files']) is dict and set(controller['files']) == engine.CONTROLLER_FILES
            and all(engine._hash(item) for item in controller['files'].values())
            and cell['engine']['trees']['controller']['files'] == controller['files']
            and cell['engine']['trees']['controller']['directories'] == [], 'generation-cell-archive-binding')


def _capture_binding(registry, config):
    for selector in registry.policies:
        policy = registry.select(selector)
        cell = _read(policy.cell_config_path,policy.cell_sha256)
        require(all(config.capture[key] == cell['engine']['capture'][key]
                    for key in ('stdout_limit','stderr_limit','total_limit')), 'generation-capture-binding')


def _acquired_receiver(registry, artifact):
    """Join acquired Main provenance to the sealed runtime, never job inputs."""
    modern = type(artifact) is acquisition.MainArtifactRequest
    for selector, policy in registry.policies.items():
        require(identity.validation_main_receiver(policy.identity) is modern,
                'generation-artifact-domain')
        if modern:
            cell = _read(policy.cell_config_path, policy.cell_sha256)
            github = engine._keys(cell['github'], {'job','workflow','run_id'})
            require(type(github['run_id']) is int and github['run_id'] == artifact.run_id
                    and policy.identity.caller_sha == artifact.head_sha
                    and policy.identity.workflow_id == artifact.workflow_id
                    and policy.identity.workflow_path == artifact.workflow_path
                    and cell['candidate']['artifact'] == artifact.name,
                    'generation-main-consumer-binding')
            matrix = cell['matrix']
            require(selector == policy_registry.profile_selector(matrix['profile'], matrix['scenario'], matrix['target']),
                    'generation-main-profile-selector')


def _inventory(directory):
    """FD-guarded immutable payload snapshot, excluding later receipt leaves."""
    ignored = {'sealed-inventory.json','publish-intent.json','published.json'}
    result = {}
    def visit(path, prefix=''):
        fd = installation._open_directory(str(path))
        try:
            for name in sorted(os.listdir(fd)):
                if not prefix and name in ignored:
                    continue
                relative = prefix + name
                _relative(relative)
                info = os.stat(name,dir_fd=fd,follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'generation-directory-mode')
                    result[relative] = {'kind':'directory','device':info.st_dev,'inode':info.st_ino}
                    visit(path/name,relative+'/')
                else:
                    proof, _, stamp = installation._file(str(path/name), MAX_TOTAL, private=False, keep=True)
                    require(stat.S_IMODE(stamp[2]) in {0o600,0o700}, 'generation-file-mode')
                    result[relative] = {'kind':'file','sha256':proof.sha256,'stamp':list(stamp)}
                require(len(result) <= MAX_MEMBERS, 'generation-inventory-size')
        finally:
            os.close(fd)
    visit(directory)
    return result


def _request(path, digest):
    value = _read(path,digest)
    engine._keys(value, {'schema','generation_id','expected_anchor_sha256','acquisition','collector',
        'registry','cells','preparation','runtime'})
    require(type(value['schema']) is int and value['schema'] == 1
        and type(value['generation_id']) is str and ledger.ID.fullmatch(value['generation_id']), 'generation-request')
    for key in ('collector','registry','preparation','runtime'):
        engine._keys(value[key], {'path','sha256'})
    require(type(value['cells']) is dict and 0 < len(value['cells']) <= 2, 'generation-pilot-cells')
    for name, ref in value['cells'].items():
        require(policy_registry.SELECTOR.fullmatch(name), 'generation-selector')
        engine._keys(ref, {'path','sha256'})
    data = value['acquisition']
    engine._keys(data, {'source','controller','artifact','credential_path','credential_sha256',
        'max_archive_bytes','max_tree_entries','max_file_bytes','total_timeout_seconds'})
    artifact_type = acquisition.MainArtifactRequest if 'request_id' in data['artifact'] else acquisition.ArtifactRequest
    request = acquisition.AcquisitionRequest(source=acquisition.CommitRequest(**data['source']),
        controller=acquisition.CommitRequest(**data['controller']),artifact=artifact_type(**data['artifact']),
        **{key:data[key] for key in ('credential_path','credential_sha256','max_archive_bytes','max_tree_entries','max_file_bytes','total_timeout_seconds')})
    acquisition._validate(request)
    return value, request


class RootGenerationPublisher:
    def __init__(self, request_path, request_sha256):
        require(os.geteuid() == 0, 'generation-root-required')
        self.path, self.sha = request_path, request_sha256
        self.value, self.acquire_request = _request(request_path,request_sha256)

    def publish(self):
        require(os.geteuid() == 0, 'generation-root-required')
        root = engine._directory(ROOT,private=True)
        lock = None
        fds = []
        try:
            lock = os.open('publisher.lock',os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,dir_fd=root)
            info = os.fstat(lock)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 0,'generation-lock')
            fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
            require(installation._stamp(os.stat('publisher.lock',dir_fd=root,follow_symlinks=False))
                == installation._stamp(info), 'generation-lock-drift')
            _inactive()
            old = _anchor(self.value['expected_anchor_sha256'])
            directory = Path(ROOT)/self.value['generation_id']
            _mkdir(directory)  # Never reuse a failed/partial generation.
            _json(directory/'intent.json',{'schema':1,'request_path':self.path,'request_sha256':self.sha,
                                         'expected_anchor_sha256':self.value['expected_anchor_sha256']})
            _mkdir(directory/'downloads')
            for name in ('artifact.zip','source.tar.gz','controller.tar.gz'):
                fd = os.open(directory/'downloads'/name,os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,0o600)
                fds.append(fd)
            acquired = acquisition.acquire(self.acquire_request,artifact_fd=fds[0],source_fd=fds[1],controller_fd=fds[2])
            raw_archives = [_fd_bytes(fd) for fd in fds]
            for raw, digest, size in zip(raw_archives,
                (acquired.artifact_sha256, acquired.source.archive_sha256, acquired.controller.archive_sha256),
                (acquired.artifact_size, acquired.source.archive_size, acquired.controller.archive_size)):
                require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest, 'generation-download-drift')
            require(acquired.artifact == self.acquire_request.artifact
                and acquired.artifact_sha256 == self.acquire_request.artifact.digest_sha256, 'generation-acquisition-binding')
            workspace = _git_archive(raw_archives[1],acquired.source)
            controller = _git_archive(raw_archives[2],acquired.controller)
            prefix = '.github/actions/run-quality-profile/'
            projected = {name:controller[prefix+name] for name in engine.CONTROLLER_FILES}
            candidates, candidate_name, inner_checks = _candidate(raw_archives[0], workspace)
            require('source-provenance.json' not in candidates, 'generation-derived-source-collision')
            candidates['source-provenance.json'] = ledger.canonical(_source_provenance(acquired.source))
            _mkdir(directory/'trees')
            trees = {'workspace':_tree(directory/'trees/workspace',workspace,
                         executable={entry.path for entry in acquired.source.files if entry.mode == '100755'}),
                     'controller':_tree(directory/'trees/controller',projected,
                         executable={entry.path[len(prefix):] for entry in acquired.controller.files
                             if entry.mode == '100755' and entry.path.startswith(prefix) and entry.path[len(prefix):] in projected}),
                     'candidate':_tree(directory/'trees/candidate',candidates)}
            _mkdir(directory/'archives')
            candidate_sha = _write(directory/'archives/candidate.tar.gz',candidates[candidate_name])
            descriptor = self.value['collector']
            registry = _read(**{'path':self.value['registry']['path'],'digest':self.value['registry']['sha256']})
            engine._keys(registry, {'schema','collector','identity','ledger_path','api_read_token_path','cells'})
            registry['collector'] = _collector(descriptor['path'],descriptor['sha256'])
            require(set(registry['cells']) == set(self.value['cells']), 'generation-cell-selection')
            _mkdir(directory/'cells')
            for selector, ref in self.value['cells'].items():
                cell = _read(ref['path'],ref['sha256'])
                engine._keys(cell, {'schema','candidate','controller','matrix','github','engine','incus'})
                require(cell['candidate']['repository'] == acquired.source.repository
                    and cell['candidate']['source_sha'] == acquired.source.commit_sha
                    and cell['candidate']['artifact'] == acquired.artifact.name
                    and cell['controller']['repository'] == acquired.controller.repository
                    and cell['controller']['source_sha'] == acquired.controller.commit_sha,
                    'generation-cell-provenance')
                cell['candidate']['archive_sha256'] = candidate_sha
                cell['controller']['archive_sha256'] = acquired.controller.archive_sha256
                cell['controller']['files'] = trees['controller']['files']
                cell['engine']['trees'] = trees
                cell['engine']['archives'] = {'candidate':{'path':str(directory/'archives/candidate.tar.gz'),'sha256':candidate_sha},
                    'controller':{'path':str(directory/'downloads/controller.tar.gz'),'sha256':acquired.controller.archive_sha256}}
                target = directory/'cells'/(selector+'.json')
                digest = _json(target,cell)
                engine._keys(registry['cells'][selector], {'native_job_name','cell_config_path','cell_sha256','custody_policy_sha256','deadline'})
                registry['cells'][selector]['cell_config_path'] = str(target)
                registry['cells'][selector]['cell_sha256'] = digest
            registry_path = directory/'registry.json'
            registry_sha = _json(registry_path,registry)
            verified = policy_registry.load_registry(str(registry_path),registry_sha)
            _acquired_receiver(verified, acquired.artifact)
            _static_cells(verified, acquired.artifact.run_id)
            prep = _read(self.value['preparation']['path'],self.value['preparation']['sha256'])
            prep.update(registry_path=str(registry_path),registry_sha256=registry_sha)
            prep_path = directory/'preparation.json';prep_sha = _json(prep_path,prep)
            preparation._config(str(prep_path),prep_sha)
            runtime = _read(self.value['runtime']['path'],self.value['runtime']['sha256'])
            runtime.update(registry_path=str(registry_path),registry_sha256=registry_sha,
                           preparation_config_path=str(prep_path),preparation_config_sha256=prep_sha)
            runtime_path = directory/'runtime.json';runtime_sha = _json(runtime_path,runtime)
            runtime_config = runtime_rpc._configuration(str(runtime_path),runtime_sha)
            _capture_binding(verified,runtime_config)
            provenance = {'schema':1,'acquisition':asdict(acquired),'inner_checksums':inner_checks,
                'trees':trees,'request_sha256':self.sha,'scope':'Rootconfiguration/provenance only; no nativeIdentity/lease/custody acceptance'}
            provenance_sha = _json(directory/'provenance.json',provenance)
            inventory = _inventory(directory)
            inventory_sha = _json(directory/'sealed-inventory.json', inventory)
            anchor = {'schema':1,'config_path':str(runtime_path),'config_sha256':runtime_sha}
            anchor_raw = ledger.canonical(anchor)
            anchor_parent = installation._open_directory(str(Path(ANCHOR).parent))
            stage_name = '.runtime-v2-anchor-'+self.value['generation_id']
            try:
                _write(Path(ANCHOR).parent/stage_name,anchor_raw)
                with preparation.preparation_lock(str(prep_path),prep_sha):
                    _inactive()
                    require(installation._stamp(os.stat('publisher.lock',dir_fd=root,follow_symlinks=False))
                        == installation._stamp(info), 'generation-lock-drift')
                    require(_anchor(self.value['expected_anchor_sha256']) == old,'generation-anchor-raced')
                    require(_request(self.path,self.sha)[0] == self.value,'generation-request-raced')
                    require(_inventory(directory) == inventory, 'generation-sealed-drift')
                    require(_read(str(directory/'sealed-inventory.json'), inventory_sha) == inventory, 'generation-inventory-drift')
                    require(policy_registry.load_registry(str(registry_path),registry_sha) == verified, 'generation-registry-drift')
                    _acquired_receiver(verified, acquired.artifact)
                    _static_cells(verified, acquired.artifact.run_id)
                    preparation._config(str(prep_path),prep_sha)
                    require(runtime_rpc._configuration(str(runtime_path),runtime_sha) == runtime_config, 'generation-runtime-drift')
                    _capture_binding(verified,runtime_config)
                    for ref in [self.value['collector'], self.value['registry'], self.value['preparation'], self.value['runtime'], *self.value['cells'].values()]:
                        _read(ref['path'],ref['sha256'])
                    if old is not None:
                        old_cfg = runtime_rpc._configuration(old[0]['config_path'],old[0]['config_sha256'])
                        previous = policy_registry.load_registry(old_cfg.registry_path,old_cfg.registry_sha256)
                        old_selected = previous.select(next(iter(previous.policies)))
                        selected = verified.select(next(iter(verified.policies)))
                        old_prep = preparation._config(old_cfg.preparation_config_path,old_cfg.preparation_config_sha256)[0]
                        require(old_selected.ledger_path == selected.ledger_path
                            and old_selected.identity.runner_id == selected.identity.runner_id
                            and old_selected.identity.service_uid == selected.identity.service_uid
                            and old_selected.collector.service.unit == selected.collector.service.unit
                            and old_prep.lock_path == prep['lock_path'],'generation-slot-change')
                    with ledger.Ledger(registry['ledger_path']) as store:
                        with store._transaction() as state:
                            require(all(row['state'] == 'closed' for row in state['leases'].values()),'generation-open-leases')
                            require(_anchor(self.value['expected_anchor_sha256']) == old,'generation-anchor-raced')
                            _json(directory/'publish-intent.json',{'anchor_sha256':hashlib.sha256(anchor_raw).hexdigest()})
                            os.replace(stage_name,Path(ANCHOR).name,src_dir_fd=anchor_parent,dst_dir_fd=anchor_parent)
                            os.fsync(anchor_parent)
                observed = runtime_entry._anchor()
                require(observed[0] == anchor,'generation-anchor-readback')
                _json(directory/'published.json',{'schema':1,'runtime_sha256':runtime_sha,'provenance_sha256':provenance_sha,
                    'anchor_sha256':hashlib.sha256(anchor_raw).hexdigest(),'inventory_sha256':inventory_sha,
                    'scope':'offlineconfiguration only, no operating activation'})
                return PublishedGeneration(str(directory),str(runtime_path),runtime_sha,
                                           hashlib.sha256(anchor_raw).hexdigest(),provenance_sha)
            finally:
                os.close(anchor_parent)
        except Exception:
            # Possible partial files/CAS are retained. Never retry or delete/adopt.
            raise Denied('generation-publish-held') from None
        finally:
            for fd in fds:os.close(fd)
            if lock is not None:
                os.close(lock)
            os.close(root)


def main(argv=None):
    """Explicit offline Root entry; no listener, installation or activation."""
    import sys
    arguments = sys.argv[1:] if argv is None else argv
    try:
        require(type(arguments) is list and len(arguments) == 2, 'generation-arguments')
        result = RootGenerationPublisher(arguments[0], arguments[1]).publish()
        print(json.dumps(asdict(result), sort_keys=True))
        return 0
    except Exception:
        print('generation-publish-held', file=sys.stderr)
        return 1
