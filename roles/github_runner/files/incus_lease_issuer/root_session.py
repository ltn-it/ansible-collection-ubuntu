"""Private process/thread-bound lock capability for coordinated Root operations.

Only the context manager mints a session. It owns the actual pre-existing lock
FD until scope exit; a caller boolean or a reconstructed configuration is never
accepted. This module neither provisions files nor installs a runtime service.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import os
from pathlib import PurePosixPath
import stat
import threading
import weakref

from . import engine_policy, installation, preparation
from .identity import require


@dataclass(frozen=True, eq=False)
class _RootSession:
    config: preparation.RootConfiguration
    fd: int
    parent_fd: int
    stamp: tuple
    config_proof: object
    config_stamp: tuple
    pid: int
    thread: int


_ACTIVE = weakref.WeakSet()
_GUARD = threading.Lock()


def _require_session(session):
    require(os.geteuid() == 0 and type(session) is _RootSession,
            "root-session-required")
    with _GUARD:
        require(session in _ACTIVE, "root-session-inactive")
    require(session.pid == os.getpid() and session.thread == threading.get_ident(),
            "root-session-owner")
    observed = os.fstat(session.fd)
    current = os.stat(PurePosixPath(session.config.lock_path).name,
                      dir_fd=session.parent_fd, follow_symlinks=False)
    require(installation._stamp(observed) == session.stamp
            and installation._stamp(current) == session.stamp, "root-session-lock-drift")
    # A still-open FD alone does not prove the exclusive flock is retained.
    # A separately opened description must conflict with the owned scope.
    probe = os.open(PurePosixPath(session.config.lock_path).name,
                    installation.FILE_FLAGS, dir_fd=session.parent_fd)
    try:
        require(installation._stamp(os.fstat(probe)) == session.stamp,
                "root-session-lock-drift")
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            require(False, "root-session-lock-not-held")
    finally:
        os.close(probe)
    config, proof, stamp = preparation._config(session.config.path, session.config.sha256)
    require(config == session.config and proof == session.config_proof
            and stamp == session.config_stamp, "root-session-config-drift")
    return config


@contextmanager
def _session(path, sha256):
    parent = fd = session = None
    try:
        config, proof, stamp = preparation._config(path, sha256)
        parent = engine_policy._directory(str(PurePosixPath(config.lock_path).parent), private=True)
        fd = os.open(PurePosixPath(config.lock_path).name, installation.FILE_FLAGS, dir_fd=parent)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 0,
                "root-session-lock-file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        session = _RootSession(config, fd, parent, installation._stamp(info), proof, stamp,
                               os.getpid(), threading.get_ident())
        with _GUARD:
            _ACTIVE.add(session)
        _require_session(session)
        yield session
    finally:
        if session is not None:
            with _GUARD:
                _ACTIVE.discard(session)
        if fd is not None:
            os.close(fd)
        if parent is not None:
            os.close(parent)
