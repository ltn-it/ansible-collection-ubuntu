"""Root-only atomic TLS2 binding publisher, not a broker or network authority.

The trusted caller MUST serialize the entire refresh -> publication -> network
renewal sequence and durably journal intent before calling publish. The digest
check and rename are a CAS only under that cooperating Root writer discipline;
POSIX rename is not an atomic conditional replacement against other Root code.
Unknown outcomes require Root readback/reconciliation, never rollback or blind
retry. No TLS issuer, ledger initialization or permission grant exists here.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import PurePosixPath
import secrets
import stat

from . import installation, signed_context
from .identity import Denied, decode_json, require
from .ledger import HEX, canonical


class PublicationDenied(Denied):
    """No live replacement was attempted; safe fixed category only."""


class PublicationUnknown(Denied):
    """Replacement was attempted or owned staging cleanup is uncertain."""


def _private_directory(fd):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, "publisher-directory")
    return info.st_dev, info.st_ino


def _entries(fd):
    # fdopendir/listdir shares the directory cursor with our stable descriptor.
    # Rewind it before every inventory, without reopening an unchecked path.
    os.lseek(fd, 0, os.SEEK_SET)
    return set(os.listdir(fd))


def _read(fd, name, limit):
    opened = os.open(name, installation.FILE_FLAGS, dir_fd=fd)
    try:
        return installation._hash_file(opened, name, limit, private=True, keep=True)
    finally:
        os.close(opened)


def _write(fd, name, raw):
    opened = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=fd)
    try:
        with os.fdopen(opened, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return installation._stamp(os.fstat(opened))
    finally:
        os.close(opened)


class RootContextPublisher:
    """Factory-fixed Root paths/key only; never construct from request JSON."""
    def __init__(self, signer, pinned_public_key, context_dir, staging_parent):
        signed_context._root()
        try:
            require(type(signer) is signed_context.RootSigner and signer._public == pinned_public_key,
                    "publisher-signer")
            signed_context._public(pinned_public_key)
            installation._absolute(context_dir)
            installation._absolute(staging_parent)
            require(context_dir != staging_parent
                    and PurePosixPath(context_dir) not in PurePosixPath(staging_parent).parents,
                    "publisher-staging-path")
            self._signer, self._public = signer, pinned_public_key
            self._context, self._parent = context_dir, staging_parent
            first = installation._open_directory(context_dir)
            try:
                second = installation._open_directory(staging_parent)
                try:
                    self._context_id, self._parent_id = _private_directory(first), _private_directory(second)
                    require(self._context_id[0] == self._parent_id[0], "publisher-filesystem")
                finally:
                    os.close(second)
            finally:
                os.close(first)
        except Exception:
            raise PublicationDenied("publication-denied") from None

    def _stable(self, context_fd, parent_fd):
        require(_private_directory(context_fd) == self._context_id
                and _private_directory(parent_fd) == self._parent_id, "publisher-directory-drift")
        for path, expected in ((self._context, self._context_id), (self._parent, self._parent_id)):
            fd = installation._open_directory(path)
            try:
                require(_private_directory(fd) == expected, "publisher-directory-drift")
            finally:
                os.close(fd)

    @staticmethod
    def _snapshot(fd):
        require(_entries(fd) == {"binding.json", "config.yml", "client.crt", "client.key", "servercerts"},
                "publisher-inventory")
        result = {name: _read(fd, name, 32768 if name == "binding.json" else 1048576)
                  for name in ("binding.json", "config.yml", "client.crt", "client.key")}
        server_fd = os.open("servercerts", installation.DIR_FLAGS, dir_fd=fd)
        try:
            server_id = _private_directory(server_fd)
            require(_entries(server_fd) == {"quality.crt"}, "publisher-inventory")
            result["servercerts/quality.crt"] = _read(server_fd, "quality.crt", 1048576)
        finally:
            os.close(server_fd)
        return result, server_id

    @staticmethod
    def _cleanup(parent_fd, name, stage_fd, stage_id, entries, server_id):
        """Delete only our exact inventory; never recurse or follow a link."""
        require(_private_directory(stage_fd) == stage_id, "publisher-stage-drift")
        linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        require((linked.st_dev, linked.st_ino) == stage_id, "publisher-stage-drift")
        expected = {p for p in entries if "/" not in p}
        if server_id is not None:
            expected.add("servercerts")
        require(_entries(stage_fd) == expected, "publisher-stage-inventory")
        server_fd = None
        try:
            if server_id is not None:
                server_fd = os.open("servercerts", installation.DIR_FLAGS, dir_fd=stage_fd)
                require(_private_directory(server_fd) == server_id
                        and _entries(server_fd) == {p.split("/")[1] for p in entries if "/" in p},
                        "publisher-stage-inventory")
            for path, stamp in entries.items():
                owner_fd = server_fd if "/" in path else stage_fd
                leaf = path.split("/")[-1]
                require(installation._stamp(os.stat(leaf, dir_fd=owner_fd, follow_symlinks=False)) == stamp,
                        "publisher-stage-entry-drift")
            for path in entries:
                os.unlink(path.split("/")[-1], dir_fd=server_fd if "/" in path else stage_fd)
            if server_fd is not None:
                os.close(server_fd)
                server_fd = None
                os.rmdir("servercerts", dir_fd=stage_fd)
            os.rmdir(name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            if server_fd is not None:
                os.close(server_fd)

    def publish(self, store, lease_id, worker, policy, *, expected_old_binding_sha256):
        """Return only the new raw binding digest after original-view verification.

        Caller must retain intent on PublicationUnknown and reconcile actual
        Root files/ledger before any network renewal or acknowledgment.
        """
        context_fd = parent_fd = stage_fd = None
        name, stage_id, server_id, entries = None, None, None, {}
        stage_created = False
        attempted = False
        result = None
        failure = None
        try:
            signed_context._root()
            require(type(expected_old_binding_sha256) is str and HEX.fullmatch(expected_old_binding_sha256),
                    "publisher-cas")
            context_fd = installation._open_directory(self._context)
            parent_fd = installation._open_directory(self._parent)
            self._stable(context_fd, parent_fd)
            original, original_server = self._snapshot(context_fd)
            require(original["binding.json"][0].sha256 == expected_old_binding_sha256, "publisher-cas")
            binding = signed_context._projection(decode_json(original["binding.json"][1]))
            name = "context-stage-" + secrets.token_hex(16)
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            stage_created = True
            stage_fd = os.open(name, installation.DIR_FLAGS, dir_fd=parent_fd)
            stage_id = _private_directory(stage_fd)
            os.mkdir("servercerts", 0o700, dir_fd=stage_fd)
            server_fd = os.open("servercerts", installation.DIR_FLAGS, dir_fd=stage_fd)
            try:
                server_id = _private_directory(server_fd)
                for path in signed_context.FILES:
                    entries[path] = _write(server_fd if "/" in path else stage_fd,
                                           path.split("/")[-1], original[path][1])
                os.fsync(server_fd)
            finally:
                os.close(server_fd)
            entries["binding.json"] = _write(stage_fd, "binding.json", canonical(binding))
            os.fsync(stage_fd)
            os.fsync(parent_fd)
            stage_path = self._parent + "/" + name
            token = self._signer.issue(store, lease_id, worker, policy, binding, stage_path)
            # This admission-free file is private staging, never the live view.
            os.unlink("binding.json", dir_fd=stage_fd)
            del entries["binding.json"]
            new_raw = canonical(binding | {"admission": token})
            entries["binding.json"] = _write(stage_fd, "binding.json", new_raw)
            os.fsync(stage_fd)
            signed_context.verify(token, self._public, store, lease_id, worker, policy, binding, stage_path)
            staged, _ = self._snapshot(stage_fd)
            require(all(staged[p][1] == original[p][1] for p in signed_context.FILES), "publisher-copy-drift")
            self._stable(context_fd, parent_fd)
            current, current_server = self._snapshot(context_fd)
            require(current_server == original_server and current == original, "publisher-cas-drift")
            # Caller serialization is mandatory: there is no POSIX conditional
            # rename that combines the preceding content check with replacement.
            require(_read(context_fd, "binding.json", 32768) == original["binding.json"], "publisher-final-cas")
            attempted = True
            os.replace("binding.json", "binding.json", src_dir_fd=stage_fd, dst_dir_fd=context_fd)
            del entries["binding.json"]
            os.fsync(context_fd)
            os.fsync(stage_fd)
            self._stable(context_fd, parent_fd)
            signed_context.verify(token, self._public, store, lease_id, worker, policy, binding, self._context)
            after, after_server = self._snapshot(context_fd)
            require(after_server == original_server
                    and all(after[p] == original[p] for p in signed_context.FILES)
                    and after["binding.json"][1] == new_raw
                    and (after["binding.json"][0].device, after["binding.json"][0].inode)
                    == (staged["binding.json"][0].device, staged["binding.json"][0].inode),
                    "publisher-postwrite-drift")
            result = {"binding_sha256": hashlib.sha256(new_raw).hexdigest()}
        except BaseException:
            failure = True
        finally:
            if stage_fd is not None:
                try:
                    self._cleanup(parent_fd, name, stage_fd, stage_id, entries, server_id)
                except BaseException:
                    attempted, failure = True, True
                try:
                    os.close(stage_fd)
                except OSError:
                    attempted, failure = True, True
            elif stage_created:
                # A created directory that could not be opened is owned state
                # whose cleanup cannot be confirmed through the stable FD.
                attempted, failure = True, True
            for fd in (parent_fd, context_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        attempted, failure = True, True
        if failure:
            if attempted:
                raise PublicationUnknown("publication-unknown") from None
            raise PublicationDenied("publication-denied") from None
        return result
