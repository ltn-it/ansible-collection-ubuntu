"""Root local TLS preparation, not certificate admission or an engine grant.

The cooperating Root executor serializes this step with subsequent issuance and
publication. A verified journal entry attests local bytes only. Partial writes
are retained for explicit Root reconciliation; this API never adopts, removes,
retries, signs an admission, or sends a certificate to Incus.
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import os
from pathlib import PurePosixPath
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import cell_contract, engine_policy, identity, installation, ledger, signed_context
from .identity import Denied, require


class MaterializationDenied(Denied):
    """Preflight failed before any local materialization intent/write."""


class MaterializationUnknown(Denied):
    """A durable intent or attempted write needs Root-only reconciliation."""


@dataclass(frozen=True)
class MaterializationReceipt:
    lease_id: str
    effect_id: str
    context_path: str
    engine_descriptor_path: str
    engine_descriptor_sha256: str
    certificate_der: bytes
    certificate_fingerprint_sha256: str
    config_bytes: bytes
    files: tuple[tuple[str, str], ...]


def _parent(path):
    selected = PurePosixPath(path)
    fd = engine_policy._directory(str(selected.parent), private=True)
    return fd, selected.name


def _absent(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise Denied("materialization-existing-object")


def _stable_parent(path, fd):
    again, _ = _parent(path)
    try:
        old, new = os.fstat(fd), os.fstat(again)
        require((old.st_dev, old.st_ino) == (new.st_dev, new.st_ino), "materialization-parent-drift")
    finally:
        os.close(again)


def _write(fd, name, raw):
    opened = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        os.fchmod(opened, 0o600)
        with os.fdopen(opened, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        info = os.fstat(opened)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(raw), "materialization-file")
    finally:
        os.close(opened)


def _certificate_validity(certificate):
    # cryptography added the aware properties in42.0.0. Its older properties
    # are documented naive UTC, never local wall time: attach UTC explicitly.
    # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate.not_valid_before_utc
    try:
        return certificate.not_valid_before_utc, certificate.not_valid_after_utc
    except AttributeError:
        return (certificate.not_valid_before.replace(tzinfo=dt.timezone.utc),
                certificate.not_valid_after.replace(tzinfo=dt.timezone.utc))


def _payload(prepared):
    incus = prepared.incus
    pin = incus["server_certificate"]
    proof, pem, _ = installation._file(pin["path"], 65536, private=True, keep=True)
    require(proof.sha256 == pin["sha256"], "materialization-pin-drift")
    certificate = x509.load_pem_x509_certificate(pem)
    require(certificate.public_bytes(serialization.Encoding.PEM) == pem, "materialization-pin-pem")
    now = dt.datetime.now(dt.timezone.utc)
    expiry = dt.datetime.fromtimestamp(prepared.expires_at, dt.timezone.utc)
    not_before, not_after = _certificate_validity(certificate)
    require(not_before <= now < expiry <= not_after,
            "materialization-pin-expiry")
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lit-lease-" + prepared.lease_id)])
    client = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(seconds=5))
              .not_valid_after(expiry).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
              .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                          crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
              .sign(key, hashes.SHA256()))
    der = client.public_bytes(serialization.Encoding.DER)
    config = {"default-remote": "quality", "remotes": {
        "quality": {"addr": incus["server"], "auth_type": "tls", "project": incus["project"],
                    "protocol": "incus", "public": False},
        "images": {"addr": "https://images.linuxcontainers.org", "protocol": "simplestreams", "public": True}}}
    owner = incus["ownership"]
    binding = {"schema": 2, "repository": owner["repository"], "run_id": str(owner["run_id"]),
               "run_attempt": str(owner["run_attempt"]), "server": incus["server"], "project": incus["project"],
               "expires_at": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"), "runtime": signed_context.runtime_for_cell(prepared)}
    signed_context._projection(binding)
    return {
        "binding.json": ledger.canonical(binding), "config.yml": ledger.canonical(config),
        "client.crt": client.public_bytes(serialization.Encoding.PEM),
        "client.key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()),
        "servercerts/quality.crt": pem,
    }, binding, der


def materialize(prepared, store):
    """Use only the current Root registry/lease binding; no independent inputs.

    The context target is the immutable cell locator, known before TLS exists.
    Client NotAfter is exactly the existing hard deadline, never a renewal.
    """
    require(os.geteuid() == 0, "materialization-root-required")
    context_parent = descriptor_parent = context_fd = server_fd = None
    effect = None
    begin_attempted = attempted = False
    try:
        require(type(prepared) is cell_contract.PreparedCell and type(store) is ledger.Ledger,
                "materialization-input")
        require(cell_contract.prepare_cell(prepared.registry, prepared.selector, store, prepared.lease_id) == prepared,
                "materialization-preparation-drift")
        descriptor = identity.decode_json(prepared.engine_descriptor_bytes)
        context_path = descriptor["context_path"]
        context_parent, context_name = _parent(context_path)
        descriptor_parent, descriptor_name = _parent(prepared.engine_descriptor_path)
        _absent(context_parent, context_name)
        _absent(descriptor_parent, descriptor_name)
        payload, binding, der = _payload(prepared)
        begin_attempted = True
        effect = store.begin(prepared.lease_id, "context-create", "context:" + prepared.cell_sha256)
        attempted = True
        os.mkdir(context_name, 0o700, dir_fd=context_parent)
        os.fsync(context_parent)
        context_fd = os.open(context_name, installation.DIR_FLAGS, dir_fd=context_parent)
        os.fchmod(context_fd, 0o700)
        os.mkdir("servercerts", 0o700, dir_fd=context_fd)
        server_fd = os.open("servercerts", installation.DIR_FLAGS, dir_fd=context_fd)
        os.fchmod(server_fd, 0o700)
        for name, raw in payload.items():
            _write(server_fd if "/" in name else context_fd, name.rsplit("/", 1)[-1], raw)
        os.fsync(server_fd)
        os.fsync(context_fd)
        _write(descriptor_parent, descriptor_name, prepared.engine_descriptor_bytes)
        os.fsync(descriptor_parent)
        _stable_parent(context_path, context_parent)
        _stable_parent(prepared.engine_descriptor_path, descriptor_parent)
        current_context = os.stat(context_name, dir_fd=context_parent, follow_symlinks=False)
        own_context = os.fstat(context_fd)
        require((current_context.st_dev, current_context.st_ino) == (own_context.st_dev, own_context.st_ino),
                "materialization-directory-drift")
        actual = signed_context._files(context_path, binding, None)
        for name, raw in payload.items():
            observed, _ = signed_context._sealed(context_path + "/" + name)
            require(observed == raw, "materialization-file-drift")
        actual["binding.json"] = hashlib.sha256(payload["binding.json"]).hexdigest()
        engine_policy._file(prepared.engine_descriptor_path, prepared.engine_descriptor_sha256, private=True)
        require(cell_contract.prepare_cell(prepared.registry, prepared.selector, store, prepared.lease_id) == prepared,
                "materialization-preparation-drift")
        receipt = MaterializationReceipt(prepared.lease_id, effect, context_path, prepared.engine_descriptor_path,
                                         prepared.engine_descriptor_sha256, der, hashlib.sha256(der).hexdigest(),
                                         payload["config.yml"], tuple(sorted(actual.items())))
        evidence = ledger.digest({"prepared": prepared.sha256, "files": actual,
                                  "descriptor": prepared.engine_descriptor_sha256,
                                  "certificate": receipt.certificate_fingerprint_sha256})
        store.record(prepared.lease_id, effect, "verified", evidence_sha256=evidence)
        return receipt
    except Exception:
        if effect is not None:
            try:
                store.record(prepared.lease_id, effect, "unknown" if attempted else "not_applied",
                             evidence_sha256=ledger.digest({"prepared": prepared.sha256,
                                                            "local_write_attempted": attempted}))
            except Exception:
                pass  # Durable intent/possibly verified outcome must never be retried here.
        if begin_attempted:
            raise MaterializationUnknown("materialization-unknown") from None
        raise MaterializationDenied("materialization-denied") from None
    finally:
        for fd in (server_fd, context_fd, descriptor_parent, context_parent):
            if fd is not None:
                os.close(fd)
