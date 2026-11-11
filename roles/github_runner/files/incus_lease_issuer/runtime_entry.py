"""Uninstalled Accept=yes Runtimev2 entry, one Root process per Unix peer.

The only configuration locator is a fixed Root-private anchor, never argv/env.
This module binds/listens/initializes nothing and grants no operating approval.
The main-thread initial-effects timer raises rather than killing processes or
retrying effects. Noninterruptible kernel/C calls remain an OS/qualification
limit; an interrupted possible effect is UNKNOWN, never an automatic retry.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
import signal
import sys
import threading
import time

from . import engine_policy, identity, installation, socket_entry
from .identity import require

_ACTIVE = None

ANCHOR = "/etc/lit/incus-lease-issuer/runtime-v2-anchor.json"


class _InitialDeadline(TimeoutError):
    """Fixed Root deadline interruption; no request or secret payload."""


def _single_thread():
    require(threading.current_thread() is threading.main_thread()
            and len(os.listdir("/proc/self/task")) == 1, "runtime-entry-single-thread")


@contextmanager
def _initial_effects_deadline(seconds, absolute_deadline):
    global _ACTIVE
    require(os.geteuid() == 0, "runtime-entry-root-required")
    _single_thread()
    require(type(seconds) is int and 0 < seconds <= 300 and type(absolute_deadline) is int,
            "runtime-entry-deadline")
    remaining = min(seconds, absolute_deadline-time.time())
    require(remaining > 0 and _ACTIVE is None and signal.getsignal(signal.SIGALRM) == signal.SIG_DFL
            and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "runtime-entry-timer-owned")
    # Root-local state only, never a request flag, permission or lease extension.
    state = {"pid": os.getpid(), "thread": threading.get_ident(), "adopting": 0, "expired": False}
    def elapsed(_number, _frame):
        state["expired"] = True
        if not state["adopting"]:
            raise _InitialDeadline("runtime-initial-deadline")
        # Never raise between possible Popen effect and original owner adoption.
        # No signal mask changes: exec children retain normal SIGALRM behavior.
    signal.signal(signal.SIGALRM, elapsed)
    _ACTIVE = state
    try:
        signal.setitimer(signal.ITIMER_REAL, remaining)
        yield
        require(not state["expired"], "runtime-initial-deadline")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        _ACTIVE = None


@contextmanager
def _spawn_adoption():
    """Defer only the owned timer exception, never block a child's signals."""
    state = _ACTIVE
    if state is None:
        yield  # Existing Root API has no timer to take over or manufacture.
        return
    require(state["pid"] == os.getpid() and state["thread"] == threading.get_ident()
            and not state["expired"], "runtime-adoption-timer")
    state["adopting"] += 1
    try:
        yield
    finally:
        state["adopting"] -= 1
        if state["expired"] and not state["adopting"]:
            raise _InitialDeadline("runtime-initial-deadline")


def _anchor():
    proof, raw, stamp = installation._file(ANCHOR, 16384, private=True, keep=True)
    value = identity.decode_json(raw)
    require(type(value.get("schema")) is int and value["schema"] in {1, 2}, "runtime-entry-anchor-schema")
    path_key, sha_key = (("bootstrap_path", "bootstrap_sha256") if value["schema"] == 2
                         else ("config_path", "config_sha256"))
    engine_policy._keys(value, {"schema", path_key, sha_key})
    engine_policy._path(value[path_key])
    engine_policy._hash(value[sha_key])
    require(value[path_key] != ANCHOR, "runtime-entry-anchor-cycle")
    return value, proof, stamp


def serve_inherited():
    """Consume duplicated connected fd0 only; no listener or policy argument.

    Return zero only for delivered result/normalized-capture terminal transport.
    This is never full Thin/VM/evidence-policy PASS or service activation. Once
    handed to RuntimeRPC, no second generic frame can follow a partial reply.
    """
    connected, handed_off = None, False
    try:
        require(os.geteuid() == 0, "runtime-entry-root-required")
        _single_thread()
        connected = socket_entry._connected_stdin()
        value, proof, stamp = _anchor()
        from . import runtime_rpc
        dispatcher = (runtime_rpc.BootstrapRuntimeRPC(value["bootstrap_path"], value["bootstrap_sha256"])
            if value["schema"] == 2 else runtime_rpc.RuntimeRPC(value["config_path"], value["config_sha256"]))
        again, after, after_stamp = _anchor()
        require(again == value and after == proof and after_stamp == stamp, "runtime-entry-anchor-drift")
        handed_off = True
        outcome = dispatcher.handle(connected)
        if outcome.get("type") in {"result", "intake-ready", "final-receipt", "operating-receipt", "operating-terminal"}:
            return 0
        if outcome.get("type") == "terminal" and outcome.get("capture", {}).get("state") == "verified":
            return 0
        return 1
    except Exception:
        if connected is not None and not handed_off:
            try:
                from . import runtime_rpc
                runtime_rpc._write(connected, {"schema": 2, "type": "failure", "operation": None,
                                              "disposition": "denied-before-intent"})
            except Exception:
                pass  # Exactly one attempt, no error/token/path/traceback output.
        return 1
    finally:
        if connected is not None:
            connected.close()


def main():
    # A Root-owned unit invokes this module with no additional arguments. No
    # configuration/selector/token is ever accepted from argv or environment.
    if len(sys.argv) != 1:
        return 1
    return serve_inherited()


if __name__ == "__main__":
    raise SystemExit(main())
