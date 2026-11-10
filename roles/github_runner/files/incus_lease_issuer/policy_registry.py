"""Root-private cell registry; selectors are locators, never admission authority.

Root-provisioned bytes, hashes and an existing archived custody record do NOT
establish actual custodian acceptance or validated cell semantics. The existing
admission bridge must authenticate the exact native job/check and Root worker.
No ledger initialization/archive, token read, TLS/engine or socket effect exists.
The path and expected SHA are fixed trusted Root caller configuration, never
job-request fields. There is no public request handler or injected reader API.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
from types import MappingProxyType
from typing import Mapping

from . import admission, collector, identity, installation, ledger, service
from .identity import Denied, require

MAX_REGISTRY_BYTES = 1048576
MAX_CELLS = 256
SELECTOR = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
IDENTITY_KEYS = frozenset({
    "repository", "repository_id", "owner_id", "caller_sha", "workflow_id", "workflow_path",
    "reusable_repository", "reusable_path", "reusable_sha", "runner_id", "runner_name",
    "service_uid", "actor_ids", "subject", "visibility",
})


def profile_selector(profile, scenario, target):
    """Public locator ABI, independently derived inside the private Root library.

    Keep the strict client/Root derivations contract-tested. The Root daemon
    cannot import the job client's differently installed public executable.
    A locator is never authorization or a reservation.
    """
    require(type(profile) is str and profile in {"heavy", "application_acceptance"},
            "registry-profile-selector")
    require(all(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", value)
                for value in (scenario, target)), "registry-profile-selector")
    raw = json.dumps([profile, scenario, target], separators=(",", ":"), ensure_ascii=True).encode()
    return "cell-" + hashlib.sha256(raw).hexdigest()


def _keys(value, expected):
    require(type(value) is dict and set(value) == set(expected), "registry-fields")
    return value


def _text(value, limit=4096):
    require(type(value) is str and 0 < len(value) <= limit
            and not any(ord(char) < 32 or ord(char) == 127 for char in value), "registry-text")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise Denied("registry-text") from None
    return value


def _number(value):
    require(type(value) is int and 0 < value < 2 ** 63, "registry-number")
    return value


def _hash(value):
    require(type(value) is str and ledger.HEX.fullmatch(value), "registry-digest")
    return value


def _path(value):
    _text(value)
    admission._absolute(value)
    require(not value.startswith("//"), "registry-path")
    return value


def _read(path, expected):
    """Reuse the existing bounded root-safe FD reader, including exact0600."""
    _path(path)
    _hash(expected)
    proof, raw, stamp = installation._file(path, MAX_REGISTRY_BYTES, private=True, keep=True)
    require(proof.sha256 == expected, "registry-bytes-drift")
    return proof, raw, stamp


def _collector(value):
    _keys(value, {"service", "profile_name", "profile_path", "profile_sha256", "config_path", "config_sha256"})
    svc = _keys(value["service"], {"unit", "service_user", "installation", "fragment_path",
                                   "fragment_sha256", "dropins"})
    ins = _keys(svc["installation"], {"root", "manifest_path", "runner_id", "service_uid", "runner_version"})
    installed = installation.InstallationPolicy(
        root=_path(ins["root"]), manifest_path=_path(ins["manifest_path"]),
        runner_id=_number(ins["runner_id"]), service_uid=_number(ins["service_uid"]),
        runner_version=_text(ins["runner_version"], 64))
    require(installed.runner_version == installation.SUPPORTED_VERSION, "registry-runner-version")
    drops = svc["dropins"]
    require(type(drops) is list and len(drops) <= 32, "registry-dropins")
    dropins = []
    for entry in drops:
        _keys(entry, {"path", "sha256"})
        dropins.append((_path(entry["path"]), _hash(entry["sha256"])))
    selected_service = service.ServicePolicy(
        unit=_text(svc["unit"], 256), service_user=_text(svc["service_user"], 64), installation=installed,
        fragment_path=_path(svc["fragment_path"]), fragment_sha256=_hash(svc["fragment_sha256"]),
        dropins=tuple(dropins))
    service.validate_policy(selected_service)
    result = collector.CollectorPolicy(
        service=selected_service, profile_name=_text(value["profile_name"], 512),
        profile_path=_path(value["profile_path"]), profile_sha256=_hash(value["profile_sha256"]),
        config_path=_path(value["config_path"]), config_sha256=_hash(value["config_sha256"]))
    collector._controls(result)
    return result


def _identity(base, native_name):
    _keys(base, IDENTITY_KEYS)
    actors = base["actor_ids"]
    require(type(actors) is list and 0 < len(actors) <= 32
            and all(type(actor) is int and 0 < actor < 2 ** 63 for actor in actors)
            and len(set(actors)) == len(actors), "registry-actors")
    result = identity.Policy(
        repository=_text(base["repository"], 256), repository_id=_number(base["repository_id"]),
        owner_id=_number(base["owner_id"]), caller_sha=_text(base["caller_sha"], 40),
        workflow_id=_number(base["workflow_id"]), workflow_path=_text(base["workflow_path"], 256),
        reusable_repository=_text(base["reusable_repository"], 256),
        reusable_path=_text(base["reusable_path"], 256), reusable_sha=_text(base["reusable_sha"], 40),
        runner_id=_number(base["runner_id"]), runner_name=_text(base["runner_name"], 256),
        service_uid=_number(base["service_uid"]), actor_ids=frozenset(actors),
        subject=_text(base["subject"], 2048), visibility=_text(base["visibility"], 16),
        required_native_job_name=_text(native_name, 1024))
    result.validate()
    return result


@dataclass(frozen=True)
class Registry:
    path: str
    sha256: str
    policies: Mapping[str, admission.AdmissionPolicy]

    def select(self, selector):
        require(type(selector) is str and SELECTOR.fullmatch(selector), "registry-selector")
        require(selector in self.policies, "registry-cell-unknown")
        # This returns a frozen Root policy, not a reservation or authorization.
        return self.policies[selector]


def load_registry(root_path, expected_sha256):
    require(os.geteuid() == 0, "registry-root-required")
    # Import at call time: cell_contract itself consumes this registry module.
    # The sealed cell includes complete immutable source-tree inventories.
    from . import cell_contract
    try:
        before, raw, stamp = _read(root_path, expected_sha256)
        value = identity.decode_json(raw)
        _keys(value, {"schema", "collector", "identity", "ledger_path", "api_read_token_path", "cells"})
        require(type(value["schema"]) is int and value["schema"] == 1, "registry-schema")
        shared = _collector(value["collector"])
        ledger_path = _path(value["ledger_path"])
        api_token = None if value["api_read_token_path"] is None else _path(value["api_read_token_path"])
        cells = value["cells"]
        require(type(cells) is dict and 0 < len(cells) <= MAX_CELLS, "registry-cells")
        policies, names, configs, archives = {}, set(), set(), set()
        # Opening requires an initialized private ledger and validated snapshot;
        # read_policy never initializes, archives, repairs or authorizes custody.
        with ledger.Ledger(ledger_path) as store:
            for selector, cell in cells.items():
                require(type(selector) is str and SELECTOR.fullmatch(selector), "registry-selector")
                _keys(cell, {"native_job_name", "cell_config_path", "cell_sha256", "custody_policy_sha256", "deadline"})
                native = _identity(value["identity"], cell["native_job_name"])
                path, digest = _path(cell["cell_config_path"]), _hash(cell["cell_sha256"])
                custody = _hash(cell["custody_policy_sha256"])
                require(native.required_native_job_name not in names and path not in configs, "registry-cell-alias")
                names.add(native.required_native_job_name)
                configs.add(path)
                require(installation.trusted_file(path, max_bytes=cell_contract.MAX_CELL).sha256 == digest, "registry-cell-bytes")
                if custody not in archives:
                    store.read_policy(custody)
                    archives.add(custody)
                policy = admission.AdmissionPolicy(
                    collector=shared, identity=native, ledger_path=ledger_path, api_read_token_path=api_token,
                    cell_config_path=path, cell_sha256=digest, custody_policy_sha256=custody,
                    deadline=_number(cell["deadline"]))
                admission._validate_policy(policy)
                policies[selector] = policy
        after, _, again = _read(root_path, expected_sha256)
        require(after == before and stamp == again, "registry-file-changed")
        return Registry(root_path, expected_sha256, MappingProxyType(policies))
    except Denied:
        raise
    except (OSError, KeyError, ValueError, TypeError, AttributeError, RecursionError):
        raise Denied("registry-load-denied") from None
