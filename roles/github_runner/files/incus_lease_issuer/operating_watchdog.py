"""One bounded Root v2 watchdog tick and private pending metadata alarms.

Filesystem bindings are locators, never native authority. Only the fixed custody
supervisor interprets actual retained runtime/ledger state. This independent
spool lock cannot wait on the worker; unknown observations remain held.
"""
from contextlib import contextmanager
import fcntl
import os
import re
import stat
import time

from . import identity, installation, ledger
from .identity import Denied, require

KINDS = frozenset({"native-status-unavailable", "expired-supervisor-held", "safety-withdrawal-held",
                   "retention-state-drift", "cleanup-unknown", "local-mail-delivery-held", "failed-cell-retained", "supervisor-observation-held"})
EVENT_KEYS = frozenset({"schema", "event_id", "source_machine_id", "source_boot_id",
    "runtime_config_sha256", "snapshot_manifest_sha256", "lease_id", "kind", "state_sha256",
    "observed_at", "delivery"})


def _private_directory(path):
    fd = installation._open_directory(path)
    value = os.fstat(fd)
    try:
        require(stat.S_IMODE(value.st_mode) == 0o700, "watchdog-private-directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(directory, name, maximum=65536):
    fd = os.open(name, installation.FILE_FLAGS, dir_fd=directory)
    try:
        proof, raw, stamp = installation._hash_file(fd, name, maximum, private=True, keep=True)
        value = identity.decode_json(raw)
        require(ledger.canonical(value) == raw, "watchdog-canonical-file")
        return value, proof.sha256, stamp
    finally:
        os.close(fd)


def _machine_boot():
    _, raw, _ = installation._file("/etc/machine-id", 128, keep=True)
    machine = raw.decode("ascii").strip()
    fd = os.open("/proc/sys/kernel/random/boot_id", installation.FILE_FLAGS)
    try:
        value = os.fstat(fd)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == 0, "watchdog-kernel-boot")
        boot = os.read(fd, 128).decode("ascii").strip()
    finally:
        os.close(fd)
    require(re.fullmatch("[0-9a-f]{32}", machine)
            and re.fullmatch("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot), "watchdog-machine")
    return machine, boot


def _config(path, expected, keys):
    require(os.geteuid() == 0 and type(expected) is str and ledger.HEX.fullmatch(expected), "watchdog-root-config")
    proof, raw, stamp = installation._file(path, 65536, private=True, keep=True)
    require(proof.sha256 == expected, "watchdog-config-sha")
    value = identity.decode_json(raw)
    require(set(value) == keys and type(value["schema"]) is int and value["schema"] == 1
            and ledger.canonical(value) == raw, "watchdog-config-schema")
    require(_machine_boot() == (value["source_machine_id"], value["source_boot_id"]), "watchdog-config-machine")
    return value, stamp


def event_fields(value):
    require(type(value) is dict and set(value) == EVENT_KEYS and type(value["schema"]) is int
            and value["schema"] == 2 and value["delivery"] == "pending"
            and type(value["kind"]) is str and value["kind"] in KINDS
            and type(value["observed_at"]) is int and value["observed_at"] > 0,
            "watchdog-event-schema")
    require(type(value["source_machine_id"]) is str and re.fullmatch("[0-9a-f]{32}", value["source_machine_id"])
            and type(value["source_boot_id"]) is str
            and re.fullmatch("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["source_boot_id"]),
            "watchdog-event-machine")
    for key in ("event_id", "runtime_config_sha256", "snapshot_manifest_sha256", "state_sha256"):
        require(type(value[key]) is str and ledger.HEX.fullmatch(value[key]), "watchdog-event-digest")
    require(value["lease_id"] is None or (type(value["lease_id"]) is str and ledger.ID.fullmatch(value["lease_id"])),
            "watchdog-event-lease")
    stable = {key: value[key] for key in EVENT_KEYS - {"schema", "event_id", "observed_at", "delivery"}}
    require(value["event_id"] == ledger.digest(stable), "watchdog-event-identity")
    return value


def alarm_envelope(*, source_machine_id, source_boot_id, runtime_config_sha256, snapshot_manifest_sha256,
                   lease_id, kind, state_sha256, observed_at):
    stable = dict(source_machine_id=source_machine_id, source_boot_id=source_boot_id,
                  runtime_config_sha256=runtime_config_sha256, snapshot_manifest_sha256=snapshot_manifest_sha256,
                  lease_id=lease_id, kind=kind, state_sha256=state_sha256)
    return event_fields({"schema": 2, "event_id": ledger.digest(stable), **stable,
                         "observed_at": observed_at, "delivery": "pending"})


def _save_once(directory, name, value):
    raw = ledger.canonical(value)
    require(len(raw) <= 65536, "watchdog-write-bound")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        data = memoryview(raw)
        while data:
            count = os.write(fd, data)
            require(count > 0, "watchdog-write-short")
            data = data[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)


@contextmanager
def _lock(directory, name):
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        info = os.fstat(fd)
        installation._regular(info, private=True)
        require(info.st_size == 0, "watchdog-lock-file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def _record(spool, value):
    event_fields(value)
    name = "alarm-" + value["event_id"] + ".json"
    try:
        _save_once(spool, name, value)
    except FileExistsError:
        previous = event_fields(_read(spool, name)[0])
        require(previous == {**value, "observed_at": previous["observed_at"]}
                and previous["observed_at"] <= value["observed_at"], "watchdog-event-drift")
    return value["event_id"]


def tick(root_config_path, expected_sha256):
    require(os.geteuid() == 0, "watchdog-root-required")
    bindings = spool = None
    try:
        keys = {"schema", "source_machine_id", "source_boot_id", "bindings_directory", "spool_directory", "max_entries"}
        config, stamp = _config(root_config_path, expected_sha256, keys)
        require(type(config["max_entries"]) is int and 0 < config["max_entries"] <= 256, "watchdog-entry-bound")
        bindings = _private_directory(config["bindings_directory"])
        spool = _private_directory(config["spool_directory"])
        require((os.fstat(bindings).st_dev, os.fstat(bindings).st_ino)
                != (os.fstat(spool).st_dev, os.fstat(spool).st_ino), "watchdog-directory-alias")
        with _lock(spool, "watchdog.lock"):
            os.lseek(bindings, 0, os.SEEK_SET)
            names = sorted(os.listdir(bindings))
            require(len(names) <= config["max_entries"], "watchdog-entry-bound")
            events = []
            pending, runtime_paths = [], set()
            for name in names:
                match = re.fullmatch("binding-([0-9a-f]{64})\\.json", name)
                require(match is not None, "watchdog-binding-name")
                value, digest, before = _read(bindings, name)
                require(digest == match[1] and set(value) == {"schema", "runtime_config_path", "runtime_config_sha256", "snapshot_manifest_sha256"}
                        and type(value["schema"]) is int and value["schema"] == 1, "watchdog-binding-schema")
                for key in ("runtime_config_sha256", "snapshot_manifest_sha256"):
                    require(type(value[key]) is str and ledger.HEX.fullmatch(value[key]), "watchdog-binding-digest")
                installation._absolute(value["runtime_config_path"])
                require(value["runtime_config_path"] not in runtime_paths, "watchdog-binding-alias")
                runtime_paths.add(value["runtime_config_path"])
                pending.append((name, value, before))
            # Validate the complete directory before any runtime provider call.
            # An unexpected later name must not permit earlier native effects.
            for name, value, before in pending:
                require(_read(bindings, name)[2] == before
                        and _config(root_config_path, expected_sha256, keys)[1] == stamp,
                        "watchdog-binding-changed")
                # Fixed Root module API; no injected providers or caller hooks.
                from . import operating_custody
                try:
                    result = operating_custody.tick_runtime(value["runtime_config_path"], value["runtime_config_sha256"],
                                                           value["snapshot_manifest_sha256"])
                except Exception:
                    result = {"state": "HELD", "native_acceptance": False, "events": [alarm_envelope(
                        source_machine_id=config["source_machine_id"], source_boot_id=config["source_boot_id"],
                        runtime_config_sha256=value["runtime_config_sha256"],
                        snapshot_manifest_sha256=value["snapshot_manifest_sha256"], lease_id=None,
                        kind="native-status-unavailable", state_sha256=ledger.digest({"state": "runtime-tick-held"}),
                        observed_at=int(time.time()))]}
                require(type(result) is dict and set(result) == {"state", "events", "native_acceptance"}
                        and type(result["state"]) is str and type(result["events"]) is list
                        and len(result["events"]) <= 256 and result["native_acceptance"] is False, "watchdog-result")
                for event in result["events"]:
                    event_fields(event)
                    require((event["source_machine_id"], event["source_boot_id"])
                            == (config["source_machine_id"], config["source_boot_id"])
                            and event["runtime_config_sha256"] == value["runtime_config_sha256"]
                            and event["snapshot_manifest_sha256"] == value["snapshot_manifest_sha256"]
                            and event["observed_at"] <= int(time.time()), "watchdog-result-binding")
                    events.append(_record(spool, event))
                require(_read(bindings, name)[2] == before, "watchdog-binding-changed")
            os.lseek(bindings, 0, os.SEEK_SET)
            require(sorted(os.listdir(bindings)) == names
                    and _config(root_config_path, expected_sha256, keys)[1] == stamp, "watchdog-config-changed")
            return {"state": "WATCHDOG_TICK_COMPLETE", "bindings": len(names), "events": events,
                    "native_acceptance": False, "capacity_released": False}
    except Exception:
        raise Denied("operating-watchdog-held") from None
    finally:
        if bindings is not None:
            os.close(bindings)
        if spool is not None:
            os.close(spool)


ANCHOR = "/etc/lit/incus-lease-issuer/operating-watchdog-anchor.json"


def main():
    """Fixed installed timer entry; no caller-supplied locator or authority."""
    import sys
    try:
        require(os.geteuid() == 0 and len(sys.argv) == 1, "watchdog-entry-root")
        _, raw, _ = installation._file(ANCHOR, 16384, private=True, keep=True)
        value = identity.decode_json(raw)
        require(type(value) is dict and set(value) == {"schema", "config_path", "config_sha256"}
                and type(value["schema"]) is int and value["schema"] == 1
                and ledger.canonical(value) == raw, "watchdog-entry-anchor")
        installation._absolute(value["config_path"])
        tick(value["config_path"], value["config_sha256"])
        return 0
    except Exception:
        return 1  # No paths, provider payload, credential or traceback logs.


if __name__ == "__main__":
    raise SystemExit(main())
