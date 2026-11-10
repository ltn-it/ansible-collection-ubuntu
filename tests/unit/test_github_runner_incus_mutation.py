"""Synthetic Root Unix mutation fixtures, never a real Incus daemon."""
import base64
from dataclasses import replace
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "roles/github_runner/files"))
from incus_lease_issuer import incus_admin as admin, incus_mutation as mutation  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402
from incus_lease_issuer import cell_contract, ledger  # noqa: E402
import test_github_runner_incus_ledger as ledger_fixtures  # noqa: E402

NOW = 1793772000
OPERATION = "12345678-1234-4234-8234-123456789abc"


class LegacyCertificateView:
    """Real parsed X509 bytes/fields, with pre42's missing aware properties."""
    def __init__(self, certificate):
        self.certificate = certificate

    def __getattr__(self, name):
        if name in {"not_valid_before_utc", "not_valid_after_utc"}:
            raise AttributeError(name)
        if name in {"not_valid_before", "not_valid_after"}:
            # Model pre42 naive UTC from the same real certificate without
            # invoking deprecated properties on the modern qualification EE.
            try:
                return getattr(self.certificate, name + "_utc").replace(tzinfo=None)
            except AttributeError:
                return getattr(self.certificate, name)
        return getattr(self.certificate, name)


def envelope(metadata, **changes):
    return {"type": "sync", "status": "Success", "status_code": 200, "operation": "",
            "error_code": 0, "error": "", "metadata": metadata, **changes}


def reply(value, status=200, etag=None):
    raw = json.dumps(value).encode()
    return (f"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\n"
            + ("ETag: " + etag + "\r\n" if etag is not None else "") +
            f"Content-Length: {len(raw)}\r\nConnection: close\r\n\r\n").encode() + raw


class MutationFixture:
    def __init__(self, path):
        self.path, self.requests, self.resources = path, [], {}
        self.headers, self.etag = [], '"' + "a" * 64 + '"'
        self.version, self.extensions = "7.6", list(mutation.EXTENSIONS)
        self.mutation_reply, self.async_mode, self.operation_code = None, False, 103
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(str(path))
        path.chmod(0o660)
        self.socket.listen(16)
        self.socket.settimeout(0.1)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def handle(self, method, path, body):
        if method == "GET" and path == "/1.0":
            return reply(envelope({"environment": {"server": "incus", "server_version": self.version},
                                   "auth": "trusted", "api_extensions": self.extensions}))
        if method == "GET" and path == "/1.0/certificates?recursion=1":
            return reply(envelope([value for key, value in self.resources.items()
                                   if key.startswith("/1.0/certificates/")]))
        if method == "GET" and path == "/1.0/operations/" + OPERATION:
            return reply(envelope({"id": OPERATION, "class": "task", "status_code": self.operation_code,
                                   "err": "synthetic-secret-server-error" if self.operation_code == 400 else ""}))
        if method == "GET":
            if path in self.resources:
                return reply(envelope(self.resources[path]), etag=self.etag if path.startswith("/1.0/profiles/") else None)
            return reply({"type": "error", "error_code": 404, "error": "synthetic-not-found"}, 404)
        if method == "POST":
            value = dict(body)
            if path == "/1.0/projects":
                target = "/1.0/projects/" + body["name"]
                value["used_by"] = ["/1.0/profiles/default?project=" + body["name"]]
                self.resources[value["used_by"][0]] = {"name": "default", "config": {}, "devices": {},
                    "description": "Default Incus profile for project " + body["name"], "used_by": []}
            elif path == "/1.0/networks?project=default":
                target = "/1.0/networks/" + body["name"] + "?project=default"
                value.update(managed=True, used_by=[])
            else:
                der = base64.b64decode(body["certificate"])
                fingerprint = hashlib.sha256(der).hexdigest()
                target = "/1.0/certificates/" + fingerprint
                value.update(fingerprint=fingerprint, certificate=x509.load_der_x509_certificate(der).public_bytes(
                    serialization.Encoding.PEM).decode())
            self.resources[target] = value
        elif method == "DELETE":
            self.resources.pop(path, None)
            if path.startswith("/1.0/projects/"):
                self.resources.pop("/1.0/profiles/default?project=" + path.removeprefix("/1.0/projects/"), None)
        elif method == "PUT":
            if self.headers[-1].get("if-match") != self.etag:
                return reply({"type": "error", "error_code": 412, "error": "synthetic-etag-conflict"}, 412)
            self.resources[path] = {"name": "default", "used_by": [], **body}
        if self.mutation_reply is not None:
            return self.mutation_reply
        if self.async_mode:
            return reply(envelope({"id": OPERATION, "class": "task", "status_code": 103},
                         type="async", status="Operation created", status_code=100,
                         operation="/1.0/operations/" + OPERATION), 202)
        return reply(envelope({}), 201 if method == "POST" else 200)

    def run(self):
        while not self.stop.is_set():
            try:
                connected, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connected:
                connected.settimeout(1)
                raw = b""
                try:
                    while b"\r\n\r\n" not in raw:
                        part = connected.recv(4096)
                        if not part:
                            break
                        raw += part
                    if not raw:
                        continue
                    header, body = raw.split(b"\r\n\r\n", 1)
                    method, path, _ = header.split(b"\r\n")[0].decode().split(" ")
                    length = 0
                    headers = {}
                    for line in header.split(b"\r\n")[1:]:
                        key, value = line.decode().split(":", 1)
                        headers[key.lower()] = value.strip()
                        if line.lower().startswith(b"content-length:"):
                            length = int(line.split(b":")[1])
                    while len(body) < length:
                        body += connected.recv(length - len(body))
                    value = json.loads(body) if body else None
                    self.requests.append((method, path, value))
                    self.headers.append(headers)
                    connected.sendall(self.handle(method, path, value))
                except (OSError, ValueError):
                    pass

    def close(self):
        self.stop.set()
        self.socket.close()
        self.thread.join(2)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "isolated Linux UID0 EE only")
class RootIncusMutationTests(unittest.TestCase):
    def setUp(self):
        base = Path("/run/proof")
        if not base.is_dir() or base.stat().st_uid != 0 or stat.S_IMODE(base.stat().st_mode) != 0o700:
            self.skipTest("requires privateRoot700 /run/proof tmpfs")
        self.temp = tempfile.TemporaryDirectory(prefix="incus-mutation-", dir=base)
        self.addCleanup(self.temp.cleanup)
        self.fixture = MutationFixture(Path(self.temp.name) / "unix.socket")
        self.addCleanup(self.fixture.close)
        key = ec.generate_private_key(ec.SECP384R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-lease-client")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(dt.datetime.fromtimestamp(NOW - 1, dt.timezone.utc))
                .not_valid_after(dt.datetime.fromtimestamp(NOW + 120, dt.timezone.utc)).sign(key, hashes.SHA384()))
        der = cert.public_bytes(serialization.Encoding.DER)
        fp = hashlib.sha256(der).hexdigest()
        self.owner = mutation.Ownership("synthetic-owner", "example/repository", 501, 1, "scenario", "target",
                                         "a" * 32, "b" * 64)
        self.project = mutation.ProjectSpec("lease-project", "lit" + "c" * 12, "selected-pool",
                                            mutation.ProjectLimits(2, 4 * 1024 ** 3, 20 * 1024 ** 3, 1, 1), self.owner)
        self.bridge = mutation.BridgeSpec(self.project.network, "192.0.2.1/24", "synthetic.test", self.owner)
        self.cert = mutation.CertificateSpec("lease-" + self.owner.lease_id, self.project.project, der, NOW + 180)
        target = admin.AdminTarget(str(self.fixture.path), self.project.project, self.bridge.network,
                                    "default", self.project.pool, (fp,))
        self.client = admin.RootIncusAdmin(target)
        self.transport = mutation.RootIncusMutator(self.client, self.project, self.bridge, self.cert)
        clock = mock.patch.object(mutation.time, "time", return_value=NOW)
        clock.start()
        self.addCleanup(clock.stop)

    def writes(self):
        return [r for r in self.fixture.requests if r[0] != "GET"]

    def test_real_certificate_modern_and_pre42_views_preserve_exact_time_boundaries(self):
        parse = x509.load_der_x509_certificate
        real = parse(self.cert.der)
        modern = mutation._certificate_validity(real)
        legacy = mutation._certificate_validity(LegacyCertificateView(real))
        self.assertEqual(modern, legacy)
        self.assertTrue(all(value.tzinfo == dt.timezone.utc for value in legacy))
        for legacy_view in (False, True):
            for now, allowed in ((NOW - 1, True), (NOW - 1.001, False),
                                 (NOW + 119.999, True), (NOW + 120, False)):
                with self.subTest(legacy=legacy_view, now=now):
                    factory = (lambda raw: LegacyCertificateView(parse(raw))) if legacy_view else parse
                    with mock.patch.object(mutation.x509, "load_der_x509_certificate", side_effect=factory), \
                            mock.patch.object(mutation.time, "time", return_value=now):
                        transport = mutation.RootIncusMutator(self.client, self.project, self.bridge, self.cert)
                        before = len(self.writes())
                        if allowed:
                            self.assertEqual(transport.certificate_create().response, "sync_received")
                            self.assertEqual(len(self.writes()), before + 1)
                        else:
                            with self.assertRaisesRegex(Denied, "mutation-certificate-expiry"):
                                transport.certificate_create()
                            self.assertEqual(len(self.writes()), before)

    def test_pre42_certificate_cannot_exceed_exact_lease_deadline(self):
        parse = x509.load_der_x509_certificate
        with mock.patch.object(mutation.x509, "load_der_x509_certificate",
                               side_effect=lambda raw: LegacyCertificateView(parse(raw))):
            exact = mutation.RootIncusMutator(self.client, self.project, self.bridge,
                                              replace(self.cert, deadline=NOW + 120))
            self.assertEqual(exact.certificate_create().response, "sync_received")
            short = mutation.RootIncusMutator(self.client, self.project, self.bridge,
                                              replace(self.cert, deadline=NOW + 119))
            before = len(self.writes())
            with self.assertRaisesRegex(Denied, "mutation-certificate-expiry"):
                short.certificate_create()
            self.assertEqual(len(self.writes()), before)

    def test_project_default_bridge_and_restricted_certificate_payloads(self):
        for create, kind in ((self.transport.bridge_create, "bridge"), (self.transport.project_create, "project"),
                             (self.transport.certificate_create, "certificate")):
            receipt = create()
            self.assertEqual(receipt.response, "sync_received")
            self.assertEqual(self.transport.readback(kind)["state"], "required_fields_match")
        bridge, project, cert = (r[2] for r in self.writes())
        self.assertEqual(bridge["type"], "bridge")
        self.assertEqual(bridge["config"]["ipv6.address"], "none")
        self.assertEqual(project["config"]["features.networks"], "false")
        self.assertEqual(project["config"]["restricted.storage-pools.access"], "selected-pool")
        self.assertEqual(project["config"]["limits.virtual-machines"], "1")
        self.assertEqual(cert["projects"], [self.project.project])
        self.assertEqual(cert["type"], "client")
        self.assertIs(cert["restricted"], True)
        self.assertNotIn("trust_token", cert)
        self.assertNotIn("token", cert)
        self.assertEqual(base64.b64decode(cert["certificate"]), self.cert.der)

    def test_old_backend_and_missing_extension_deny_before_mutation(self):
        self.fixture.version = "6.0.0"
        with self.assertRaises(mutation.MutationDenied):
            self.transport.project_create()
        self.fixture.version, self.fixture.extensions = "7.6", []
        with self.assertRaises(mutation.MutationDenied):
            self.transport.bridge_create()
        self.assertEqual(self.writes(), [])

    def test_configure_owned_default_profile_uses_actual_etag_and_pool_without_total_size(self):
        self.transport.project_create()
        receipt = self.transport.configure_default_profile()
        self.assertEqual(receipt.operation, "profile-configure")
        method, path, body = self.writes()[-1]
        self.assertEqual((method, path), ("PUT", "/1.0/profiles/default?project=" + self.project.project))
        self.assertEqual(self.fixture.headers[-1]["if-match"], self.fixture.etag)
        self.assertEqual(body["devices"], {"root": {"type": "disk", "path": "/", "pool": self.project.pool}})
        self.assertEqual(body["config"]["user.lit-incus-lease-id"], self.owner.lease_id)
        self.assertEqual(self.transport.readback("profile")["state"], "required_fields_match")

    def test_foreign_nonempty_profile_or_missing_etag_denies_without_put(self):
        self.transport.project_create()
        profile = self.fixture.resources["/1.0/profiles/default?project=" + self.project.project]
        profile["config"] = {"user.foreign": "synthetic-foreign"}
        with self.assertRaises(Denied):
            self.transport.configure_default_profile()
        profile["config"] = {}
        self.fixture.etag = None
        with self.assertRaises(Denied):
            self.transport.configure_default_profile()
        self.assertEqual([r for r in self.writes() if r[0] == "PUT"], [])

    def test_profile_etag_rejection_is_unknown_without_put_retry(self):
        self.transport.project_create()
        self.fixture.mutation_reply = reply({"type": "error", "error_code": 412,
                                             "error": "synthetic-secret-etag"}, 412)
        with self.assertRaises(mutation.MutationUnknown):
            self.transport.configure_default_profile()
        self.assertEqual(len([r for r in self.writes() if r[0] == "PUT"]), 1)

    def test_conflict_rejection_is_unknown_even_when_resource_was_created(self):
        self.fixture.mutation_reply = reply({"type": "error", "error_code": 409,
                                             "error": "synthetic-secret-after-commit"}, 409)
        with self.assertRaises(mutation.MutationUnknown) as caught:
            self.transport.project_create()
        self.assertEqual(str(caught.exception), "mutation-unknown")
        self.assertEqual(len(self.writes()), 1)
        self.assertEqual(self.transport.readback("project")["state"], "required_fields_match")
        with self.assertRaises(Denied):
            self.transport.project_create()
        self.assertEqual(len(self.writes()), 1)

    def test_truncated_lost_redirect_and_error_replies_unknown_no_retry(self):
        replies = [reply(envelope({}))[:-1], b"", reply({"type": "error", "error_code": 500}, 500),
                   reply({"type": "error", "error_code": 302}, 302)]
        for index, value in enumerate(replies):
            other = mutation.RootIncusMutator(self.client, self.project, self.bridge, self.cert)
            self.fixture.mutation_reply = value
            before = len(self.writes())
            with self.subTest(index=index), self.assertRaises(mutation.MutationUnknown):
                other.project_create()
            self.assertEqual(len(self.writes()), before + 1)

    def test_async_operation_pending_success_and_failure_need_resource_readback(self):
        self.fixture.async_mode = True
        receipt = self.transport.project_create()
        self.assertEqual(receipt.response, "operation_pending")
        self.assertEqual(receipt.operation_id, OPERATION)
        self.assertEqual(self.transport.operation_readback(receipt)["state"], "pending")
        self.fixture.operation_code = 200
        self.assertEqual(self.transport.operation_readback(receipt)["state"], "success_requires_resource_readback")
        self.fixture.operation_code = 400
        result = self.transport.operation_readback(receipt)
        self.assertEqual(result["state"], "failed_requires_resource_readback")
        self.assertNotIn("synthetic-secret", json.dumps(result))
        with self.assertRaises(Denied):
            self.transport.operation_readback(replace(receipt, target="project:foreign"))

    def test_async_untrusted_operation_url_and_non_task_denied_unknown(self):
        for location, kind in (("https://foreign.example/1.0/operations/" + OPERATION, "task"),
                               ("/1.0/operations/" + OPERATION, "token")):
            other = mutation.RootIncusMutator(self.client, self.project, self.bridge, self.cert)
            self.fixture.mutation_reply = reply(envelope({"id": OPERATION, "class": kind}, type="async",
                status_code=100, operation=location), 202)
            with self.assertRaises(mutation.MutationUnknown):
                other.project_create()

    def test_readback_absence_is_observation_not_not_applied(self):
        result = self.transport.readback("project")
        self.assertEqual(result["state"], "absent_observed")
        self.assertNotIn("not_applied", json.dumps(result))

    def test_delete_requires_exact_owned_empty_resource(self):
        self.transport.bridge_create()
        path = "/1.0/networks/" + self.bridge.network + "?project=default"
        self.fixture.resources[path]["used_by"] = ["/1.0/instances/foreign"]
        with self.assertRaises(Denied):
            self.transport.bridge_delete()
        self.fixture.resources[path]["used_by"] = []
        self.fixture.resources[path]["config"]["user.lit-molecule-owner"] = "foreign-owner"
        with self.assertRaises(Denied):
            self.transport.bridge_delete()
        self.assertEqual([r for r in self.writes() if r[0] == "DELETE"], [])

    def test_delete_config_drift_holds_and_owned_delete_has_no_force(self):
        self.transport.project_create()
        path = "/1.0/projects/" + self.project.project
        self.fixture.resources[path]["config"]["unexpected.policy"] = "hold"
        with self.assertRaises(Denied):
            self.transport.project_delete()
        del self.fixture.resources[path]["config"]["unexpected.policy"]
        receipt = self.transport.project_delete()
        self.assertEqual(receipt.response, "sync_received")
        self.assertEqual(self.writes()[-1], ("DELETE", path, None))
        self.assertEqual(self.transport.readback("project")["state"], "absent_observed")

    def test_expired_certificate_cannot_create_but_owned_cleanup_remains_possible(self):
        self.transport.certificate_create()
        with mock.patch.object(mutation.time, "time", return_value=NOW + 200):
            other = mutation.RootIncusMutator(self.client, self.project, self.bridge, self.cert)
            with self.assertRaises(Denied):
                other.certificate_create()
            self.assertEqual(other.certificate_delete().response, "sync_received")

    def test_no_job_dict_admin_injection_or_invalid_quotas(self):
        for project in ({"project": "default"}, replace(self.project, project="default"),
                        replace(self.project, limits=replace(self.project.limits, cpu=True)),
                        replace(self.project, limits=replace(self.project.limits, containers=1))):
            with self.assertRaises(mutation.MutationDenied):
                mutation.RootIncusMutator(self.client, project, self.bridge, self.cert)
        with self.assertRaises(mutation.MutationDenied):
            mutation.RootIncusMutator(object(), self.project, self.bridge, self.cert)
        with self.assertRaises(mutation.MutationDenied):
            mutation.RootIncusMutator(self.client, self.project, self.bridge, replace(self.cert, der=b"not-DER"))
        self.assertEqual(self.writes(), [])

    def test_actual_prepared_cell_owner_and_fields_construct_transport_pair(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import test_github_runner_incus_cell_contract as semantic_fixtures
        semantic_fixtures.RootCellContractTests.setUpClass()
        fixture = semantic_fixtures.RootCellContractTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        prepared = fixture.prepare()
        target = prepared.incus
        ownership = mutation.Ownership(**target["ownership"])
        limits = mutation.ProjectLimits(**target["project_limits"])
        project = mutation.ProjectSpec(target["project"], target["network"], target["pool"], limits, ownership)
        bridge = mutation.BridgeSpec(target["network"], target["ipv4_address"], target["dns_domain"], ownership)
        cert = replace(self.cert, project=project.project, deadline=prepared.expires_at)
        client = admin.RootIncusAdmin(replace(self.client._target, project=project.project, network=bridge.network,
                                             pool=project.pool))
        transport = mutation.RootIncusMutator(client, project, bridge, cert)
        self.assertIn("ltn-it/ansible-collection-supplementary", ownership.owner)
        self.assertEqual(transport._project.ownership.owner, ownership.owner)
        self.assertEqual(mutation._project(project)["config"]["user.lit-molecule-owner"], ownership.owner)
        self.assertEqual(self.writes(), [])

    def test_precontext_stage_has_no_certificate_routes_or_placeholder(self):
        client = admin.RootIncusAdmin(replace(self.client._target, certificate_fingerprints=()))
        transport = mutation.RootIncusMutator(client, self.project, self.bridge)
        self.assertEqual(transport.readback("project")["state"], "absent_observed")
        before = len(self.fixture.requests)
        for operation in (transport.certificate_create, transport.certificate_delete,
                          lambda: transport.readback("certificate")):
            with self.assertRaisesRegex(Denied, "mutation-certificate-stage-required"):
                operation()
        self.assertEqual(len(self.fixture.requests), before)
        self.assertIsNone(transport._certificate)
        self.assertIsNone(transport._fingerprint)
        with self.assertRaises(mutation.MutationDenied):
            mutation.RootIncusMutator(self.client, self.project, self.bridge, certificate=None)

    def test_prepared_two_stage_real_materializer_and_durable_ledger_order(self):
        # Real sealed registry/PreparedCell, Root ledger, crypto and filesystem;
        # only Incus is the isolated Unix HTTP fixture, never a native daemon.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import test_github_runner_incus_context_materializer as crypto_fixtures
        from incus_lease_issuer import context_materializer, ledger

        crypto_fixtures.RootContextMaterializerTests.setUpClass()
        crypto = crypto_fixtures.RootContextMaterializerTests()
        self.addCleanup(crypto.doCleanups)

        class FixtureDateTime(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls.fromtimestamp(crypto_fixtures.fixtures.cell.time.time(), tz)

        clock = mock.patch.object(context_materializer, "dt", SimpleNamespace(
            datetime=FixtureDateTime, timezone=dt.timezone, timedelta=dt.timedelta))
        clock.start()
        self.addCleanup(clock.stop)
        fixture = crypto.real_fixture(None)
        prepared = fixture.prepare()
        values, store, lease = prepared.incus, fixture.store, fixture.lease
        owner = mutation.Ownership(**values["ownership"])
        project = mutation.ProjectSpec(values["project"], values["network"], values["pool"],
                                        mutation.ProjectLimits(**values["project_limits"]), owner)
        bridge = mutation.BridgeSpec(values["network"], values["ipv4_address"], values["dns_domain"], owner)
        target = replace(self.client._target, project=project.project, network=bridge.network, pool=project.pool,
                         certificate_fingerprints=())
        precontext = mutation.RootIncusMutator(admin.RootIncusAdmin(target), project, bridge, certificate=None)
        for operation, locator, call, kind in (
                ("network-create", "network:default:" + bridge.network, precontext.bridge_create, "bridge"),
                ("project-create", "project:" + project.project, precontext.project_create, "project"),
                ("profile-configure", "profile:" + project.project + ":default",
                 precontext.configure_default_profile, "profile")):
            effect = store.begin(lease, operation, locator)
            self.assertEqual(call().response, "sync_received")
            observed = precontext.readback(kind)
            self.assertEqual(observed["state"], "required_fields_match")
            store.record(lease, effect, "verified", evidence_sha256=ledger.digest(observed))
        self.assertFalse(any(path == "/1.0/certificates" for _, path, _ in self.writes()))
        materialized = context_materializer.materialize(prepared, store)
        self.assertTrue(any(effect["operation"] == "context-create" and effect["state"] == "verified"
                            for effect in store.read(lease)["effects"].values()))
        cert = mutation.CertificateSpec("lease-" + lease, project.project,
                                        materialized.certificate_der, prepared.expires_at)
        bound_target = replace(target, certificate_fingerprints=(materialized.certificate_fingerprint_sha256,))
        cert_stage = mutation.RootIncusMutator(admin.RootIncusAdmin(bound_target), project, bridge, cert)
        effect = store.begin(lease, "certificate-create", "certificate:" + materialized.certificate_fingerprint_sha256)
        self.assertEqual(cert_stage.certificate_create().response, "sync_received")
        observed = cert_stage.readback("certificate")
        self.assertEqual(observed["state"], "required_fields_match")
        store.record(lease, effect, "verified", evidence_sha256=ledger.digest(observed))
        # A newly constructed object is not replay authority: the durable
        # ledger denies duplicate provisioning across these transport stages.
        with self.assertRaisesRegex(Denied, "effect-replay"):
            store.begin(lease, "network-create", "network:default:" + bridge.network)
        self.assertEqual(precontext._attempts, {
            ("network-create", "network:default:" + bridge.network),
            ("project-create", "project:" + project.project),
            ("profile-configure", "profile:" + project.project + ":default")})

    def test_socket_drift_and_nonroot_deny_without_mutation(self):
        self.fixture.path.chmod(0o666)
        with self.assertRaises(mutation.MutationDenied):
            self.transport.project_create()
        self.fixture.path.chmod(0o660)
        with mock.patch.object(mutation.os, "geteuid", return_value=2101):
            with self.assertRaises(Denied):
                mutation.RootIncusMutator(self.client, self.project, self.bridge, self.cert)
            with self.assertRaises(Denied):
                self.transport.project_create()
        self.assertEqual(self.writes(), [])


    def cleanup_fixture(self):
        """Real Ledger/X509/Unix protocol; only semantic owner acquisition modeled."""
        path = Path(self.temp.name) / "ledger"
        path.mkdir(mode=0o700)
        ledger.Ledger.initialize(path, clock=lambda: NOW)
        store = ledger.Ledger(path, clock=lambda: NOW)
        self.addCleanup(store.shutdown)
        policy = store.archive_policy(dict(ledger_fixtures.POLICY))
        worker = ledger.Worker(**ledger_fixtures.WORKER)
        challenge = store.challenge(worker)
        lease = store.prepare(challenge["nonce"], worker, ledger_fixtures.synthetic_identity(challenge["audience"]),
                              policy_sha256=policy, cell_sha256="b" * 64, deadline=NOW + 120)
        owner = replace(self.owner, lease_id=lease)
        project, bridge = replace(self.project, ownership=owner), replace(self.bridge, ownership=owner)
        cert = replace(self.cert, name="lit-lease-" + lease)
        transport = mutation.RootIncusMutator(self.client, project, bridge, cert)
        for operation, target in (("network-create", "network:default:" + bridge.network),
                ("project-create", "project:" + project.project),
                ("profile-configure", "profile:" + project.project + ":default"),
                ("context-create", "context:" + "b" * 64)):
            effect = store.begin(lease, operation, target)
            store.record(lease, effect, "verified", evidence_sha256="e" * 64)
        baseline = transport.certificate_scope_baseline()
        effect = store.begin(lease, "certificate-create", "certificate:" + baseline.initial_fingerprint)
        store.bind_certificate_scope(lease, effect, **baseline.__dict__)
        transport.certificate_create()
        store.record(lease, effect, "verified", evidence_sha256="e" * 64)
        incus = {"ownership": owner.__dict__, "project": project.project, "network": bridge.network,
            "pool": project.pool, "project_limits": project.limits.__dict__,
            "ipv4_address": bridge.ipv4_address, "dns_domain": bridge.dns_domain}
        creators = {"certificate-create": {"id": effect, "target": "certificate:" + baseline.initial_fingerprint,
                    "sha256": ledger.digest(store.read(lease)["effects"][effect])}}
        owned = cell_contract.OwnedCellForCleanup(registry=None, selector="fixture", lease_id=lease,
            cell_sha256="b" * 64, expires_at=NOW + 120, identity_policy_sha256="c" * 64,
            engine_descriptor_path="/root/not-read", engine_descriptor_bytes=b"{}", engine_descriptor_sha256="d" * 64,
            engine_policy_sha256="d" * 64, incus_bytes=ledger.canonical(incus), creator_bytes=ledger.canonical(creators),
            prepared_sha256="e" * 64, canonical_bytes=b"{}", sha256="f" * 64)
        acquire = mock.patch.object(cell_contract, "owned_cell_for_cleanup", return_value=owned)
        acquire.start()
        self.addCleanup(acquire.stop)
        return mutation.RootIncusCleanup(self.client, owned, store), store, lease, baseline

    def test_complete_baseline_before_post_and_original_scope_revoke_without_der(self):
        cleanup, store, lease, baseline = self.cleanup_fixture()
        posts = [index for index, row in enumerate(self.fixture.requests) if row[0:2] == ("POST", "/1.0/certificates")]
        reads = [index for index, row in enumerate(self.fixture.requests)
                 if row[0:2] == ("GET", "/1.0/certificates?recursion=1")]
        self.assertEqual(len(posts), 1)
        self.assertEqual(len([index for index in reads if index < posts[0]]), 2)
        snapshot = cleanup.certificate_inventory()
        self.assertEqual(snapshot.fingerprints, (baseline.initial_fingerprint,))
        before = len([row for row in self.fixture.requests if row[0] == "DELETE"])
        with self.assertRaises(Denied):
            cleanup.certificate_delete()
        self.assertEqual(len([row for row in self.fixture.requests if row[0] == "DELETE"]), before)
        for operation in (cleanup.project_create, cleanup.bridge_create, cleanup.certificate_create,
                          cleanup.configure_default_profile):
            with self.assertRaisesRegex(Denied, "mutation-cleanup-only"):
                operation()
        effect = store.begin(lease, "certificate-revoke", "certificate:" + baseline.initial_fingerprint)
        store.bind_certificate_revocation(lease, effect, current_fingerprint=snapshot.fingerprints[0],
            scope_sha256=snapshot.scope_sha256, inventory_sha256=snapshot.inventory_sha256)
        receipt = cleanup.certificate_delete()
        self.assertEqual(receipt.target, "certificate:" + baseline.initial_fingerprint)
        self.assertTrue(cleanup.certificates_absent())
        self.assertEqual(cleanup.readback("certificate")["state"], "absent_observed")
        with self.assertRaises(Denied):
            cleanup.certificate_delete()

    def test_self_renewed_fingerprint_bound_to_original_intent_and_foreign_scope_is_never_deleted(self):
        cleanup, store, lease, baseline = self.cleanup_fixture()
        old = self.fixture.resources.pop("/1.0/certificates/" + baseline.initial_fingerprint)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "new-client-material")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(99)
                .not_valid_before(dt.datetime.fromtimestamp(NOW - 1, dt.timezone.utc))
                .not_valid_after(dt.datetime.fromtimestamp(NOW + 600, dt.timezone.utc)).sign(key, hashes.SHA256()))
        fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        current = old | {"fingerprint": fp, "certificate": cert.public_bytes(serialization.Encoding.PEM).decode(),
                         "description": "client may alter this field"}
        self.fixture.resources["/1.0/certificates/" + fp] = current
        snapshot = cleanup.certificate_inventory()
        self.assertEqual(snapshot.fingerprints, (fp,))
        effect = store.begin(lease, "certificate-revoke", "certificate:" + baseline.initial_fingerprint)
        store.bind_certificate_revocation(lease, effect, current_fingerprint=fp,
            scope_sha256=snapshot.scope_sha256, inventory_sha256=snapshot.inventory_sha256)
        cleanup.certificate_delete()
        self.assertIn(("DELETE", "/1.0/certificates/" + fp, None), self.fixture.requests)
        self.assertFalse(any(method == "DELETE" and path.endswith(baseline.initial_fingerprint)
                             for method, path, _ in self.fixture.requests))
        self.fixture.resources["/1.0/certificates/" + fp] = current | {"name": "foreign-root-owner"}
        with self.assertRaises(Denied):
            cleanup.certificates_absent()

    def test_inventory_scope_drift_and_duplicate_candidates_hold_without_any_delete(self):
        cleanup, _store, _lease, baseline = self.cleanup_fixture()
        path = "/1.0/certificates/" + baseline.initial_fingerprint
        original = dict(self.fixture.resources[path])
        for changes in ({"name": "foreign"}, {"restricted": False}, {"projects": ["foreign"]},
                        {"type": "server"}, {"fingerprint": "f" * 64}):
            with self.subTest(changes=changes):
                self.fixture.resources[path] = original | changes
                with self.assertRaises((Denied, ValueError)):
                    cleanup.certificate_inventory()
        self.fixture.resources[path] = original
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "second-material")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(101)
                .not_valid_before(dt.datetime.fromtimestamp(NOW - 1, dt.timezone.utc))
                .not_valid_after(dt.datetime.fromtimestamp(NOW + 120, dt.timezone.utc)).sign(key, hashes.SHA256()))
        fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        self.fixture.resources["/1.0/certificates/" + fp] = original | {
            "fingerprint": fp, "certificate": cert.public_bytes(serialization.Encoding.PEM).decode()}
        with self.assertRaises(Denied):
            cleanup.certificate_inventory()
        self.assertFalse(any(method == "DELETE" for method, _, _ in self.fixture.requests))

    def test_lost_delete_reply_retains_original_intent_and_never_resends(self):
        cleanup, store, lease, baseline = self.cleanup_fixture()
        snapshot = cleanup.certificate_inventory()
        effect = store.begin(lease, "certificate-revoke", "certificate:" + baseline.initial_fingerprint)
        store.bind_certificate_revocation(lease, effect, current_fingerprint=snapshot.fingerprints[0],
            scope_sha256=snapshot.scope_sha256, inventory_sha256=snapshot.inventory_sha256)
        self.fixture.mutation_reply = b"HTTP/1.1 200 broken\r\n"
        with self.assertRaises(mutation.MutationUnknown):
            cleanup.certificate_delete()
        self.assertEqual(store.read(lease)["effects"][effect]["state"], "intent")
        with self.assertRaises(Denied):
            cleanup.certificate_delete()
        self.assertEqual(len([row for row in self.fixture.requests if row[0] == "DELETE"]), 1)

    def test_quiet_requires_whole_empty_instances_and_all_status_groups_twice(self):
        cleanup, _store, _lease, _baseline = self.cleanup_fixture()
        instance_path = "/1.0/instances?project=" + self.project.project
        operation_path = "/1.0/operations?project=" + self.project.project + "&recursion=1"
        self.fixture.resources[instance_path] = []
        self.fixture.resources[operation_path] = {}
        self.assertEqual(cleanup.quiet_project()["state"], "quiet_observed")
        self.fixture.resources[instance_path] = ["/1.0/instances/retained-vm?project=" + self.project.project]
        with self.assertRaises(Denied):
            cleanup.quiet_project()
        self.fixture.resources[instance_path] = []
        for code in (103, 105, 200, 400):
            status = admin.OPERATION_STATUS[code]
            self.fixture.resources[operation_path] = {status.lower(): [{"id": OPERATION, "class": "task",
                "status": status, "status_code": code, "resources": {"projects": ["foreign"]}}]}
            with self.subTest(code=code), self.assertRaises(Denied):
                cleanup.quiet_project()
        self.assertFalse(any(method == "DELETE" for method, _, _ in self.fixture.requests))

    def test_baseline_rejects_existing_fixed_name_or_any_existing_restricted_project_scope(self):
        cleanup, _store, _lease, baseline = self.cleanup_fixture()
        cert = replace(self.cert, name=baseline.certificate_name)
        transport = mutation.RootIncusMutator(self.client, cleanup._project, cleanup._bridge, cert)
        with self.assertRaises(Denied):
            transport.certificate_scope_baseline()
        path = "/1.0/certificates/" + baseline.initial_fingerprint
        self.fixture.resources[path]["name"] = "unrelated-fixed-name"
        with self.assertRaises(Denied):
            transport.certificate_scope_baseline()


class NonrootMutationGuardTests(unittest.TestCase):
    def test_nonroot_factory_denies_before_root_inputs_or_socket(self):
        if os.geteuid() == 0:
            self.skipTest("nonroot EE execution")
        with self.assertRaisesRegex(Denied, "incus-admin-root-required"):
            mutation.RootIncusMutator(None, None, None, None)


if __name__ == "__main__":
    unittest.main()
