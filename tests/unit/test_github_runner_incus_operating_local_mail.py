"""Root FS/import/config/mailbox proof with a real private Python send child.

Postfix tool responses are explicitly modeled: this is NOT native MTA/service
qualification. The child validates the actual fixed mail envelope and writes a
real Root mailbox; legacy pure mailbox/config readers are exercised unchanged.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from email import policy
from email.parser import BytesParser

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import ledger, operating_local_mail as mail, operating_watchdog as watchdog
from incus_lease_issuer.identity import Denied

MACHINE = "1" * 32
BOOT = "11111111-2222-3333-4444-555555555555"

CHILD = """import os,sys
from email import policy
from email.parser import BytesParser
raw=sys.stdin.buffer.read(16385)
assert len(raw)<=16384
message=BytesParser(policy=policy.default).parsebytes(raw)
assert message.get_all('To')==['root@localhost']
assert message.get_all('From')==['root@localhost']
assert message.get_all('Cc') is None and message.get_all('Bcc') is None
assert message.get_content_type()=='text/plain' and not message.is_multipart()
assert str(message['Message-ID']).endswith('@localhost>')
fd=os.open('/var/mail/root',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
 data=memoryview(b'From root@localhost Mon Jan 1 00:00:00 2026\\n'+raw)
 while data:
  count=os.write(fd,data)
  assert count>0
  data=data[count:]
 os.fsync(fd)
finally: os.close(fd)
"""


class BoundaryTests(unittest.TestCase):
    def test_nonroot_cannot_send_or_read_event(self):
        with mock.patch.object(mail.os, "geteuid", return_value=501):
            with self.assertRaisesRegex(Denied, "operating-mail-root-required"):
                mail.deliver("/not-read", "a" * 64, "b" * 64)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "private Root Linux EE only")
class RootMailTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires private Root0700 /run/proof")
        for path in (Path("/etc/postfix"), Path("/var/lib/lit-local-mail"), Path("/var/mail")):
            if not path.is_dir() or path.stat().st_uid != 0:
                self.skipTest("requires dedicated private Postfix-config/mailbox fixture tmpfs mounts")
        self.temp = tempfile.TemporaryDirectory(dir=base, prefix="operating-mail-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spool = self.root / "spool"; self.spool.mkdir(mode=0o700)
        self.helpers = self.root / "helpers"; self.helpers.mkdir(mode=0o700)
        self.sha_map = {}
        self.old_modules = {name[:-3]: sys.modules.pop(name[:-3], None) for name in mail.HELPERS}
        self.addCleanup(self.restore_modules)
        for name in mail.HELPERS:
            raw = (FILES / name).read_bytes()
            (self.helpers / name).write_bytes(raw); (self.helpers / name).chmod(0o600)
            self.sha_map[name] = hashlib.sha256(raw).hexdigest()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(mail, "HELPER_ROOT", str(self.helpers)).start()
        mock.patch.object(watchdog, "_machine_boot", return_value=(MACHINE, BOOT)).start()
        self.event = watchdog.alarm_envelope(source_machine_id=MACHINE, source_boot_id=BOOT,
            runtime_config_sha256="a" * 64, snapshot_manifest_sha256="b" * 64, lease_id="c" * 32,
            kind="cleanup-unknown", state_sha256="d" * 64, observed_at=100)
        self.event_id = self.event["event_id"]
        self.alarm = self.spool / ("alarm-" + self.event_id + ".json")
        self.alarm.write_bytes(ledger.canonical(self.event)); self.alarm.chmod(0o600)
        self.config = {"schema": 1, "source_machine_id": MACHINE, "source_boot_id": BOOT,
            "spool_directory": str(self.spool), "helper_sha256": self.sha_map}
        self.config_path = self.root / "mail.json"
        self.config_path.write_bytes(ledger.canonical(self.config)); self.config_path.chmod(0o600)
        self.config_sha = ledger.digest(self.config)
        self.receipt = self.spool / ("mail-" + self.event_id + ".json")
        role = FILES.parents[1] / "local_mail"
        ownership = {"schema": 1}
        for name in ("main.cf", "master.cf"):
            raw = (role / "templates" / (name + ".j2")).read_bytes()
            destination = Path("/etc/postfix") / name
            destination.write_bytes(raw); destination.chmod(0o644)
            ownership[name.replace(".", "_") + "_sha256"] = hashlib.sha256(raw).hexdigest()
        owner = Path("/var/lib/lit-local-mail/ownership.json")
        owner.write_bytes(ledger.canonical(ownership)); owner.chmod(0o600)
        self.box = Path("/var/mail/root")
        if os.path.lexists(self.box): self.box.unlink()
        self.addCleanup(lambda: self.box.unlink(missing_ok=True))
        self.real_run = subprocess.run
        self.send_count = 0
        self.mode = "ok"
        self.properties = list(mail.EXPECTED)
        self.master = "\n".join(name + " unix - - n - 1 " + command for name, command in mail.MASTER.items()) + "\n"
        self.real_tool = mail._tool
        mock.patch.object(mail, "_tool", side_effect=self.tool).start()
        mock.patch.object(mail.subprocess, "run", side_effect=self.execute).start()
        mock.patch.object(mail.time, "sleep").start()

    def restore_modules(self):
        for name, original in self.old_modules.items():
            sys.modules.pop(name, None)
            if original is not None: sys.modules[name] = original

    def tool(self, path):
        self.assertIn(path, {"/usr/sbin/postconf", "/usr/sbin/sendmail"})

    def execute(self, argv, **kwargs):
        if argv == ["/usr/sbin/postconf", "-h", *mail.PROPERTIES]:
            return subprocess.CompletedProcess(argv, 0, ("\n".join(self.properties) + "\n").encode())
        if argv == ["/usr/sbin/postconf", "-M"]:
            return subprocess.CompletedProcess(argv, 0, self.master.encode())
        self.assertEqual(argv, ["/usr/sbin/sendmail", "-i", "-f", "root@localhost", "--", "root@localhost"])
        self.assertEqual(kwargs["env"], {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
        message = BytesParser(policy=policy.default).parsebytes(kwargs["input"])
        event = re.fullmatch("<g06-operating-[0-9a-f]{32}-([0-9a-f]{64})@localhost>", str(message["Message-ID"]))
        self.assertIsNotNone(event)
        receipt = self.spool / ("mail-" + event[1] + ".json")
        self.assertTrue(receipt.exists(), "exact event's durable intent must precede child")
        self.assertEqual(json.loads(receipt.read_bytes())["phase"], "DISPATCH_INTENT")
        self.send_count += 1
        if self.mode in {"ok", "lost"}:
            result = self.real_run(["/usr/bin/python3", "-I", "-B", "-c", CHILD], input=kwargs["input"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"})
            self.assertEqual(result.returncode, 0, "private synthetic sender child must complete")
        if self.mode == "lost": raise subprocess.TimeoutExpired(argv, 5)
        return subprocess.CompletedProcess(argv, 1 if self.mode == "failed" else 0)

    def deliver(self):
        return mail.deliver(str(self.config_path), self.config_sha, self.event_id)

    def test_real_private_child_and_unchanged_mailbox_reader_confirm_once(self):
        original = self.alarm.read_bytes()
        receipt = self.deliver()
        self.assertTrue(receipt["local_mailbox_confirmed"])
        self.assertFalse(receipt["personal_acknowledged"])
        self.assertFalse(receipt["capacity_released"])
        self.assertEqual(self.deliver(), receipt)
        self.assertEqual(self.send_count, 1)
        self.assertEqual(self.alarm.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(self.receipt.stat().st_mode), 0o600)
        self.assertIn(b"g06-operating-", self.box.read_bytes())

    def test_lost_reply_reconciles_actual_existing_mailbox_without_resend(self):
        self.mode = "lost"
        with self.assertRaisesRegex(Denied, "^operating-local-mail-held$"): self.deliver()
        self.assertTrue(self.deliver()["local_mailbox_confirmed"])
        self.assertEqual(self.send_count, 1)

    def test_zero_status_without_mailbox_and_nonzero_never_confirm_or_resend(self):
        self.mode = "queued"
        for _ in range(2):
            with self.assertRaises(Denied): self.deliver()
        self.assertEqual(self.send_count, 1)
        self.assertIn(b"DISPATCH_INTENT", self.receipt.read_bytes())
        self.assertFalse(self.box.exists())

    def test_external_transport_alias_or_inet_master_denied_before_intent(self):
        self.properties[0] = "all"
        with self.assertRaises(Denied): self.deliver()
        self.properties = list(mail.EXPECTED)
        self.properties[8] = "hash:/etc/aliases"
        with self.assertRaises(Denied): self.deliver()
        self.properties = list(mail.EXPECTED)
        self.master += "smtp inet n - n - - smtpd\n"
        with self.assertRaises(Denied): self.deliver()
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.send_count, 0)

    def test_owned_config_and_private_helper_drift_denied(self):
        config = Path("/etc/postfix/main.cf")
        config.write_bytes(config.read_bytes() + b"\nrelayhost=foreign.invalid\n")
        with self.assertRaises(Denied): self.deliver()
        helper = self.helpers / "ephemeral_worker_local_mail.py"
        helper.write_bytes(helper.read_bytes() + b"\n# different bytes\n")
        with self.assertRaises(Denied): self.deliver()
        self.assertEqual(self.send_count, 0)

    def test_foreign_preloaded_helper_never_used(self):
        sys.modules["ephemeral_worker_local_mail"] = SimpleNamespace(__file__="/foreign/helper.py")
        with self.assertRaises(Denied): self.deliver()
        self.assertFalse(self.receipt.exists())

    def test_pending_mailbox_symlink_not_followed_or_removed(self):
        self.mode = "queued"
        with self.assertRaises(Denied): self.deliver()
        foreign = self.root / "foreign-box"
        foreign.write_bytes(b"do not read or delete")
        foreign.chmod(0o600)
        self.box.symlink_to(foreign)
        with self.assertRaises(Denied): self.deliver()
        self.assertTrue(self.box.is_symlink())
        self.assertEqual(foreign.read_bytes(), b"do not read or delete")
        self.assertEqual(self.send_count, 1)

    def test_receipt_boolean_types_and_event_mutation_cannot_be_adopted(self):
        self.deliver()
        receipt = json.loads(self.receipt.read_bytes())
        receipt["personal_acknowledged"] = 0
        self.receipt.write_bytes(ledger.canonical(receipt))
        with self.assertRaises(Denied): self.deliver()
        self.assertEqual(self.send_count, 1)

    def test_nonzero_send_preserves_intent_and_never_retries_submission(self):
        self.mode = "failed"
        with self.assertRaises(Denied): self.deliver()
        self.assertIn(b"DISPATCH_INTENT", self.receipt.read_bytes())
        self.mode = "ok"
        with self.assertRaises(Denied): self.deliver()
        self.assertEqual(self.send_count, 1)
        self.assertFalse(self.box.exists())

    def test_real_tool_file_metadata_rejects_alias_permissive_or_changed_mode(self):
        tool = self.root / "inert-tool"
        tool.write_bytes(b"not executed; Root metadata fixture only")
        tool.chmod(0o755)
        self.real_tool(str(tool))
        tool.chmod(0o775)
        with self.assertRaises(Denied): self.real_tool(str(tool))
        tool.chmod(0o755)
        alias = self.root / "alias"
        alias.symlink_to(tool)
        with self.assertRaises(Denied): self.real_tool(str(alias))

    def test_independent_mail_tick_confirms_then_validates_historical_receipt(self):
        result = mail.tick(str(self.config_path), self.config_sha)
        self.assertTrue(result["local_mailbox_confirmed"])
        self.assertEqual(self.send_count, 1)
        # Historical proof survives normal mailbox archival; no resubmission.
        self.box.unlink()
        result = mail.tick(str(self.config_path), self.config_sha)
        self.assertEqual(result["state"], "NO_UNCONFIRMED_LOCAL_EVENTS")
        self.assertEqual(self.send_count, 1)

    def test_mail_tick_rotates_past_uncertain_intent_without_retry(self):
        other = watchdog.alarm_envelope(**{key: value for key, value in self.event.items()
            if key not in {"schema", "event_id", "delivery", "state_sha256"}}, state_sha256="e" * 64)
        path = self.spool / ("alarm-" + other["event_id"] + ".json")
        path.write_bytes(ledger.canonical(other)); path.chmod(0o600)
        self.mode = "queued"
        with self.assertRaises(Denied): mail.tick(str(self.config_path), self.config_sha)
        self.assertEqual(self.send_count, 1)
        self.mode = "ok"
        result = mail.tick(str(self.config_path), self.config_sha)
        self.assertTrue(result["local_mailbox_confirmed"])
        self.assertEqual(self.send_count, 2)
        pending = [p for p in self.spool.glob("mail-*.json") if b"DISPATCH_INTENT" in p.read_bytes()]
        self.assertEqual(len(pending), 1)
