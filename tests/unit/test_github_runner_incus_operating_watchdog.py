"""Root FS/flock/alarm mechanism; native custody/provider observations modeled."""
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
import incus_lease_issuer
from incus_lease_issuer import ledger, operating_watchdog as watchdog
from incus_lease_issuer.identity import Denied

MACHINE = "1" * 32
BOOT = "11111111-2222-3333-4444-555555555555"


class EventTests(unittest.TestCase):
    def event(self, **changes):
        fields = dict(source_machine_id=MACHINE, source_boot_id=BOOT, runtime_config_sha256="a" * 64,
            snapshot_manifest_sha256="b" * 64, lease_id="c" * 32, kind="cleanup-unknown",
            state_sha256="d" * 64, observed_at=100)
        fields.update(changes)
        return watchdog.alarm_envelope(**fields)

    def test_closed_sanitized_identity_is_stable_without_free_text(self):
        event = self.event()
        self.assertEqual(event["event_id"], self.event(observed_at=101)["event_id"])
        self.assertNotEqual(event["event_id"], self.event(state_sha256="e" * 64)["event_id"])
        for change in ({"kind": "arbitrary log text"}, {"lease_id": "../../foreign"},
                       {"observed_at": True}, {"runtime_config_sha256": "token-value"}):
            with self.subTest(change=change), self.assertRaises(Denied):
                self.event(**change)
        with self.assertRaises(Denied):
            watchdog.event_fields({**event, "raw_stderr": "private"})

    def test_nonroot_cannot_tick(self):
        with mock.patch.object(watchdog.os, "geteuid", return_value=501):
            with self.assertRaisesRegex(Denied, "watchdog-root-required"):
                watchdog.tick("/not-read", "a" * 64)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootWatchdogTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires private Root0700 /run/proof")
        self.temp = tempfile.TemporaryDirectory(dir=base, prefix="operating-watchdog-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bindings = self.root / "bindings"; self.bindings.mkdir(mode=0o700)
        self.spool = self.root / "alarms"; self.spool.mkdir(mode=0o700)
        self.runtime = self.root / "runtime.json"; self.runtime.write_bytes(b"inert runtime fixture")
        self.runtime.chmod(0o600)
        self.runtime_sha = hashlib.sha256(self.runtime.read_bytes()).hexdigest()
        self.binding = {"schema": 1, "runtime_config_path": str(self.runtime), "runtime_config_sha256": self.runtime_sha,
                        "snapshot_manifest_sha256": "b" * 64}
        self.binding_path = self.bindings / ("binding-" + ledger.digest(self.binding) + ".json")
        self.binding_path.write_bytes(ledger.canonical(self.binding)); self.binding_path.chmod(0o600)
        self.config = {"schema": 1, "source_machine_id": MACHINE, "source_boot_id": BOOT,
            "bindings_directory": str(self.bindings), "spool_directory": str(self.spool), "max_entries": 8}
        self.path = self.root / "watchdog.json"
        self.write_config()
        self.event = watchdog.alarm_envelope(source_machine_id=MACHINE, source_boot_id=BOOT,
            runtime_config_sha256=self.runtime_sha, snapshot_manifest_sha256="b" * 64, lease_id="c" * 32,
            kind="cleanup-unknown", state_sha256="d" * 64, observed_at=int(time.time()))
        self.native = mock.Mock(return_value={"state": "HELD", "events": [self.event], "native_acceptance": False})
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(watchdog, "_machine_boot", return_value=(MACHINE, BOOT)).start()
        self.closed = mock.patch.object(watchdog, "_closed_binding", return_value=False).start()
        mock.patch.object(incus_lease_issuer, "operating_custody", SimpleNamespace(tick_runtime=self.native), create=True).start()

    def write_config(self):
        self.path.write_bytes(ledger.canonical(self.config)); self.path.chmod(0o600)
        self.sha = ledger.digest(self.config)

    def tick(self):
        return watchdog.tick(str(self.path), self.sha)

    def test_actual_private_alarm_once_and_fixed_native_arguments(self):
        result = self.tick()
        self.assertFalse(result["capacity_released"])
        self.assertFalse(result["native_acceptance"])
        self.native.assert_called_once_with(str(self.runtime), self.runtime_sha, "b" * 64)
        alarm = self.spool / ("alarm-" + self.event["event_id"] + ".json")
        original = alarm.read_bytes(); inode = alarm.stat().st_ino
        self.assertEqual(original, ledger.canonical(self.event))
        self.event["observed_at"] += 1
        with mock.patch.object(watchdog.time, "time", return_value=self.event["observed_at"]):
            self.tick()
        self.assertEqual(alarm.read_bytes(), original)
        self.assertEqual(alarm.stat().st_ino, inode)
        self.assertEqual(stat.S_IMODE(alarm.stat().st_mode), 0o600)

    def test_exact_digest_mode_symlink_and_extra_binding_name_fail_closed(self):
        old = self.sha; self.sha = "0" * 64
        with self.assertRaises(Denied): self.tick()
        self.sha = old
        self.path.chmod(0o644)
        with self.assertRaises(Denied): self.tick()
        self.path.chmod(0o600)
        target = self.root / "original-binding"
        self.binding_path.rename(target); self.binding_path.symlink_to(target)
        with self.assertRaises(Denied): self.tick()
        self.binding_path.unlink(); target.rename(self.binding_path)
        (self.bindings / "foreign").write_bytes(b"do not remove")
        with self.assertRaises(Denied): self.tick()
        self.assertTrue((self.bindings / "foreign").exists())
        self.native.assert_not_called()

    def test_busy_independent_flock_never_waits_or_calls_native(self):
        lock = os.open(self.spool / "watchdog.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(Denied): self.tick()
        finally:
            os.close(lock)
        self.native.assert_not_called()

    def test_native_exception_records_closed_unavailable_metadata_not_error(self):
        self.native.side_effect = RuntimeError("private error details must not escape")
        result = self.tick()
        self.assertEqual(len(result["events"]), 1)
        raw = next(self.spool.glob("alarm-*.json")).read_bytes()
        self.assertNotIn(b"private error", raw)
        self.assertIn(b'"kind":"native-status-unavailable"', raw)

    def test_wrong_result_snapshot_never_persists_alarm(self):
        self.event["snapshot_manifest_sha256"] = "f" * 64
        stable = {k: v for k, v in self.event.items() if k not in {"schema", "event_id", "observed_at", "delivery"}}
        self.event["event_id"] = ledger.digest(stable)
        with self.assertRaises(Denied): self.tick()
        self.assertEqual(list(self.spool.glob("alarm-*.json")), [])

    def test_binding_changed_during_tick_preserves_alarm_but_returns_hold(self):
        def change(*args):
            self.binding_path.chmod(0o640)
            return {"state": "HELD", "events": [self.event], "native_acceptance": False}
        self.native.side_effect = change
        with self.assertRaises(Denied): self.tick()
        self.assertEqual(len(list(self.spool.glob("alarm-*.json"))), 1)

    def test_empty_bindings_is_bounded_idle_not_capacity_release(self):
        self.binding_path.unlink()
        result = self.tick()
        self.assertEqual(result["bindings"], 0)
        self.assertFalse(result["capacity_released"])
        self.native.assert_not_called()

    def test_duplicate_runtime_locator_refused_before_any_supervisor_call(self):
        value = {**self.binding, "snapshot_manifest_sha256": "e" * 64}
        path = self.bindings / ("binding-" + ledger.digest(value) + ".json")
        path.write_bytes(ledger.canonical(value)); path.chmod(0o600)
        with self.assertRaises(Denied): self.tick()
        self.native.assert_not_called()

    def test_supervisor_cannot_claim_native_acceptance_in_watchdog_reply(self):
        self.native.return_value = {"state": "COMPLETE", "events": [], "native_acceptance": True}
        with self.assertRaises(Denied): self.tick()
        self.assertEqual(list(self.spool.glob("alarm-*.json")), [])

    def test_history_over_limit_is_fair_bounded_and_closed_bindings_retire(self):
        self.binding_path.unlink()
        rows = []
        for index in range(260):
            row = {**self.binding, "runtime_config_path": str(self.root / ("runtime-%03d.json" % index))}
            path = self.bindings / ("binding-" + ledger.digest(row) + ".json")
            path.write_bytes(ledger.canonical(row));path.chmod(0o600)
            rows.append((path, row))
        self.config["max_entries"] = 256;self.write_config()
        self.native.return_value = {"state": "CUSTODY_TICK_COMPLETE", "events": [], "native_acceptance": False}
        first = self.tick()
        self.assertEqual(first["bindings"],256)
        initial = {call.args[0] for call in self.native.call_args_list}
        self.assertEqual(len(initial),256)
        self.native.reset_mock()
        self.closed.return_value = True
        second = self.tick()
        self.assertEqual(second["bindings"],256)
        later = {call.args[0] for call in self.native.call_args_list}
        self.assertEqual(initial | later, {row["runtime_config_path"] for _,row in rows})
        self.assertEqual(len(list(self.bindings.glob("binding-*.json"))),4)
        self.tick()
        self.assertEqual(list(self.bindings.glob("binding-*.json")),[])
        self.assertTrue((self.bindings/".watchdog-state"/"cursor.json").is_file())

    def test_cursor_interrupted_write_is_only_scheduling_not_native_authority(self):
        self.tick()
        state = self.bindings/".watchdog-state"
        (state/"cursor.next").write_bytes(b'{"interrupted":')
        (state/"cursor.next").chmod(0o600)
        self.tick()
        self.assertFalse((state/"cursor.next").exists())
        self.assertEqual(self.native.call_count,2)

    def test_confirmed_archive_suppresses_producer_duplicate_without_recreation(self):
        archive = self.spool/"mail-archive";archive.mkdir(mode=0o700)
        body = ledger.canonical({"source_machine_id": MACHINE,"alarm":self.event})
        receipt = {"schema":2,"event_id":self.event["event_id"],"source_machine_id":MACHINE,
            "message_id":"<g06-operating-"+MACHINE+"-"+self.event["event_id"]+"@localhost>",
            "body_sha256":hashlib.sha256(body).hexdigest(),"recipient":"root@localhost",
            "dispatch_at":self.event["observed_at"],"phase":"MAILBOX_CONFIRMED",
            "local_mailbox_confirmed":True,"personal_acknowledged":False,"capacity_released":False}
        path=archive/(self.event["event_id"]+".json")
        value={"schema":1,"alarm":self.event,"receipt":receipt}
        path.write_bytes(ledger.canonical(value));path.chmod(0o600)
        self.tick()
        self.assertEqual(list(self.spool.glob("alarm-*.json")),[])
        value["receipt"]["phase"]="DISPATCH_INTENT"
        path.write_bytes(ledger.canonical(value))
        with self.assertRaises(Denied):self.tick()
        self.assertEqual(list(self.spool.glob("alarm-*.json")),[])
