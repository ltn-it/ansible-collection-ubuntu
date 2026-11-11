"""Root v2 local-only mail, once submission and independent mailbox proof.

No legacy Store is constructed. Only the qualified legacy pure configuration
and mailbox readers are imported from one exact Root-private helper closure.
An uncertain send keeps its intent and may only reconcile the existing local
mailbox; it is never submitted again. Mail is not a personal acknowledgement,
custody release, or proof of external notification.
"""
from email.message import EmailMessage
import hashlib
import importlib
import os
import re
import stat
import subprocess
import sys
import threading
import time
import uuid

from . import installation, ledger, operating_watchdog as watchdog
from .identity import Denied, require

HELPER_ROOT = "/usr/local/lib/lightning-it/incus-operating-mail-helper"
HELPERS = frozenset({"ephemeral_worker_local_mail.py", "ephemeral_worker_alarm.py", "ephemeral_worker_incus.py",
                    "ephemeral_worker_lease.py", "ephemeral_worker_watchdog.py", "ephemeral_worker_admission.py"})
CONFIG_KEYS = frozenset({"schema", "source_machine_id", "source_boot_id", "spool_directory", "helper_sha256"})
PROPERTIES = ("inet_interfaces", "inet_protocols", "mydestination", "default_transport", "relay_transport",
              "relayhost", "transport_maps", "virtual_alias_maps", "alias_maps", "alias_database", "forward_path",
              "mailbox_command", "mailbox_transport", "home_mailbox", "mail_spool_directory",
              "allow_mail_to_commands", "allow_mail_to_files")
EXPECTED = ("127.0.0.1", "ipv4", "localhost, localhost.localdomain", "error:external delivery disabled",
            "error:external delivery disabled", "", "", "", "", "", "", "", "", "", "/var/mail", "", "")
MASTER = {"pickup": "pickup", "cleanup": "cleanup", "qmgr": "qmgr", "showq": "showq", "rewrite": "trivial-rewrite",
          "bounce": "bounce", "defer": "bounce", "trace": "bounce", "local": "local", "error": "error", "retry": "error"}


def _helpers(expected):
    require(type(expected) is dict and set(expected) == HELPERS and threading.active_count() == 1,
            "operating-mail-helper-map")
    directory = watchdog._private_directory(HELPER_ROOT)
    try:
        os.lseek(directory, 0, os.SEEK_SET)
        require(set(os.listdir(directory)) == HELPERS, "operating-mail-helper-inventory")
        for name, digest in expected.items():
            require(type(digest) is str and ledger.HEX.fullmatch(digest), "operating-mail-helper-sha")
            proof, _, _ = installation._file(HELPER_ROOT + "/" + name, 2 * 1024 * 1024, private=True)
            require(proof.sha256 == digest, "operating-mail-helper-sha")
            loaded = sys.modules.get(name[:-3])
            require(loaded is None or getattr(loaded, "__file__", None) == HELPER_ROOT + "/" + name,
                    "operating-mail-foreign-import")
        original, dont_write = list(sys.path), sys.dont_write_bytecode
        try:
            sys.path.insert(0, HELPER_ROOT)
            sys.dont_write_bytecode = True
            module = importlib.import_module("ephemeral_worker_local_mail")
        finally:
            sys.path[:] = original
            sys.dont_write_bytecode = dont_write
        for name, digest in expected.items():
            require(installation.trusted_file(HELPER_ROOT + "/" + name, 2 * 1024 * 1024).sha256 == digest,
                    "operating-mail-helper-sha")
        return module
    finally:
        os.close(directory)


def _tool(path):
    proof = installation.trusted_file(path, 64 * 1024 * 1024)
    info = os.stat(path, follow_symlinks=False)
    require((info.st_dev, info.st_ino) == (proof.device, proof.inode)
            and stat.S_IMODE(info.st_mode) == 0o755, "operating-mail-tool")


def _postconf(arguments):
    _tool("/usr/sbin/postconf")
    result = subprocess.run(["/usr/sbin/postconf", *arguments], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
    require(result.returncode == 0 and len(result.stdout) <= 16384, "operating-mail-postconf")
    return result.stdout.decode("ascii")


def _local_only(helpers):
    helpers.owned_configuration()
    raw = _postconf(["-h", *PROPERTIES])
    require(raw.endswith("\n") and tuple(raw.split("\n")[:-1]) == EXPECTED, "operating-mail-local-policy")
    rows = _postconf(["-M"]).splitlines()
    seen = set()
    for row in rows:
        parts = row.split()
        require(len(parts) == 8 and parts[0] in MASTER and parts[0] not in seen
                and parts[1] == "unix" and parts[7] == MASTER[parts[0]], "operating-mail-master-policy")
        seen.add(parts[0])
    require(seen == set(MASTER), "operating-mail-master-policy")
    # The supported Debian/Ubuntu mail submission interface is this fixed
    # regular executable. No alternative-MTA alias or distro target is guessed.
    _tool("/usr/sbin/sendmail")


def _replace_receipt(spool, name, value, expected_stamp):
    require(watchdog._read(spool, name)[2] == expected_stamp, "operating-mail-receipt-raced")
    temporary = ".mail-" + uuid.uuid4().hex
    watchdog._save_once(spool, temporary, value)
    require(watchdog._read(spool, name)[2] == expected_stamp, "operating-mail-receipt-raced")
    os.replace(temporary, name, src_dir_fd=spool, dst_dir_fd=spool)
    os.fsync(spool)


def deliver(root_config_path, expected_sha256, event_id):
    """One fixed-recipient local delivery; event ID is only a Root locator."""
    require(os.geteuid() == 0, "operating-mail-root-required")
    spool = None
    try:
        require(type(event_id) is str and ledger.HEX.fullmatch(event_id), "operating-mail-event-id")
        config, config_stamp = watchdog._config(root_config_path, expected_sha256, CONFIG_KEYS)
        helpers = _helpers(config["helper_sha256"])
        spool = watchdog._private_directory(config["spool_directory"])
        with watchdog._lock(spool, "local-mail.lock"):
            event, _, event_stamp = watchdog._read(spool, "alarm-" + event_id + ".json")
            watchdog.event_fields(event)
            now = int(time.time())
            require(event["event_id"] == event_id and event["observed_at"] <= now
                    and (event["source_machine_id"], event["source_boot_id"])
                    == (config["source_machine_id"], config["source_boot_id"]), "operating-mail-event-binding")
            body = ledger.canonical({"source_machine_id": config["source_machine_id"], "alarm": event}).decode("ascii")
            message_id = "<g06-operating-" + config["source_machine_id"] + "-" + event_id + "@localhost>"
            name = "mail-" + event_id + ".json"
            expected = {"schema": 2, "event_id": event_id, "source_machine_id": config["source_machine_id"],
                "message_id": message_id, "body_sha256": hashlib.sha256(body.encode("ascii")).hexdigest(), "recipient": "root@localhost",
                "dispatch_at": now, "phase": "DISPATCH_INTENT", "local_mailbox_confirmed": False,
                "personal_acknowledged": False, "capacity_released": False}
            try:
                previous, _, receipt_stamp = watchdog._read(spool, name)
            except FileNotFoundError:
                previous = None
            if previous is not None:
                require(type(previous) is dict and set(previous) == set(expected)
                        and type(previous["schema"]) is int and previous["schema"] == 2
                        and type(previous["dispatch_at"]) is int and event["observed_at"] <= previous["dispatch_at"] <= now
                        and previous["phase"] in {"DISPATCH_INTENT", "MAILBOX_CONFIRMED"}
                        and all(type(previous[key]) is bool for key in
                                ("local_mailbox_confirmed", "personal_acknowledged", "capacity_released"))
                        and previous == {**expected, "dispatch_at": previous["dispatch_at"], "phase": previous["phase"],
                            "local_mailbox_confirmed": previous["phase"] == "MAILBOX_CONFIRMED"},
                        "operating-mail-receipt")
                if previous["phase"] == "MAILBOX_CONFIRMED":
                    return previous
                expected = previous
            _local_only(helpers)
            if previous is None:
                watchdog._save_once(spool, name, expected)
                receipt_stamp = watchdog._read(spool, name)[2]
                message = EmailMessage()
                message["From"] = message["To"] = "root@localhost"
                message["Subject"] = "Isolated worker custody requires attention"
                message["Message-ID"] = message_id
                message.set_content(body)
                try:
                    result = subprocess.run(["/usr/sbin/sendmail", "-i", "-f", "root@localhost", "--", "root@localhost"],
                        input=message.as_bytes(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=5, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
                except Exception:
                    raise Denied("operating-mail-send-unknown-no-replay") from None
                require(result.returncode == 0, "operating-mail-send-failed-no-replay")
            for _ in range(6):
                if helpers.mailbox_contains(message_id, body):
                    require(watchdog._config(root_config_path, expected_sha256, CONFIG_KEYS)[1] == config_stamp
                            and watchdog._read(spool, "alarm-" + event_id + ".json")[2] == event_stamp,
                            "operating-mail-source-drift")
                    confirmed = {**expected, "phase": "MAILBOX_CONFIRMED", "local_mailbox_confirmed": True}
                    _replace_receipt(spool, name, confirmed, receipt_stamp)
                    return confirmed
                time.sleep(0.5)
            raise Denied("operating-mail-mailbox-unconfirmed-no-replay")
    except Exception:
        raise Denied("operating-local-mail-held") from None
    finally:
        if spool is not None:
            os.close(spool)


def tick(root_config_path, expected_sha256):
    """Independent bounded mail service tick; at most one pending dispatch.

    Durable rotation precedes delivery so an uncertain old attempt does not
    starve other pending alarms. Rotation never clears/retries that old intent.
    """
    require(os.geteuid() == 0, "operating-mail-root-required")
    spool = None
    try:
        config, _ = watchdog._config(root_config_path, expected_sha256, CONFIG_KEYS)
        spool = watchdog._private_directory(config["spool_directory"])
        with watchdog._lock(spool, "mail-tick.lock"):
            os.lseek(spool, 0, os.SEEK_SET)
            names = os.listdir(spool)
            require(len(names) <= 1024, "operating-mail-spool-bound")
            events = []
            for name in names:
                event = re.fullmatch("alarm-([0-9a-f]{64})\\.json", name)
                allowed = (event is not None or re.fullmatch("mail-[0-9a-f]{64}\\.json", name)
                           or name in {"watchdog.lock", "local-mail.lock", "mail-tick.lock", "mail-cursor.json"})
                require(allowed, "operating-mail-spool-inventory")
                if event:
                    events.append(event[1])
            require(len(events) <= 256, "operating-mail-event-bound")
            try:
                cursor, _, cursor_stamp = watchdog._read(spool, "mail-cursor.json")
            except FileNotFoundError:
                cursor = None
            if cursor is not None:
                require(type(cursor) is dict and set(cursor) == {"schema", "event_id", "source_machine_id"}
                        and type(cursor["schema"]) is int and cursor["schema"] == 2
                        and type(cursor["event_id"]) is str and ledger.HEX.fullmatch(cursor["event_id"])
                        and cursor["source_machine_id"] == config["source_machine_id"], "operating-mail-cursor")
            last = cursor["event_id"] if cursor else ""
            for event_id in sorted(events, key=lambda item: (item <= last, item)):
                try:
                    previous = watchdog._read(spool, "mail-" + event_id + ".json")[0]
                except FileNotFoundError:
                    previous = None
                if type(previous) is dict and previous.get("phase") == "MAILBOX_CONFIRMED":
                    # Full historical receipt validation, no mailbox reopen.
                    deliver(root_config_path, expected_sha256, event_id)
                    continue
                rotated = {"schema": 2, "event_id": event_id, "source_machine_id": config["source_machine_id"]}
                if cursor is None:
                    watchdog._save_once(spool, "mail-cursor.json", rotated)
                else:
                    _replace_receipt(spool, "mail-cursor.json", rotated, cursor_stamp)
                receipt = deliver(root_config_path, expected_sha256, event_id)
                return {"state": "LOCAL_MAIL_CONFIRMED", "event_id": event_id,
                        "local_mailbox_confirmed": receipt["local_mailbox_confirmed"],
                        "personal_acknowledged": False, "capacity_released": False}
            return {"state": "NO_UNCONFIRMED_LOCAL_EVENTS", "personal_acknowledged": False, "capacity_released": False}
    except Exception:
        raise Denied("operating-mail-tick-held") from None
    finally:
        if spool is not None:
            os.close(spool)


ANCHOR = "/etc/lit/incus-lease-issuer/operating-mail-anchor.json"


def main():
    """Fixed installed timer entry; metadata mailbox delivery only."""
    try:
        require(os.geteuid() == 0 and len(sys.argv) == 1, "operating-mail-entry-root")
        _, raw, _ = watchdog.installation._file(ANCHOR, 16384, private=True, keep=True)
        value = watchdog.identity.decode_json(raw)
        require(type(value) is dict and set(value) == {"schema", "config_path", "config_sha256"}
                and type(value["schema"]) is int and value["schema"] == 1
                and ledger.canonical(value) == raw, "operating-mail-entry-anchor")
        watchdog.installation._absolute(value["config_path"])
        tick(value["config_path"], value["config_sha256"])
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
