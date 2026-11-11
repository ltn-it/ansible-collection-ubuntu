"""Root semantic binding of the selected single VM cell, before TLS effects.

Registry bytes and the existing prepared Ledger are the only authorities here.
An engine template precedes the random lease ID; its exact derived descriptor
precedes TLS, while the compiled EngineManifest digest follows the four TLS
files and precedes signed binding.json. No digest includes its own signature.
No effects, capacity attestation, artifact-to-Git provenance, operating acceptance
or native namespace/runtime proof are supplied by this semantic component.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import os
import re
import time
from types import MappingProxyType
from urllib.parse import urlsplit

from . import admission, engine_policy as engine, identity, installation, ledger, policy_registry
from .identity import Denied, require

MAX_CELL = 4 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}\Z")
PATH_KEYS = frozenset({"descriptor", "storage", "runroot", "context", "output"})
MATRIX_KEYS = frozenset({"profile", "scenario", "target", "target_disposition", "roles", "image", "instance_type",
                         "junit", "allure", "cpu_limit", "memory_limit", "disk_limit"})


@dataclass(frozen=True)
class PreparedCell:
    registry: policy_registry.Registry
    selector: str
    lease_id: str
    cell_sha256: str
    expires_at: int
    identity_policy_sha256: str
    engine_descriptor_path: str
    engine_descriptor_bytes: bytes
    engine_descriptor_sha256: str
    incus_bytes: bytes
    sha256: str
    canonical_bytes: bytes

    @property
    def incus(self):
        # Return a fresh value; callers cannot mutate this frozen binding.
        return identity.decode_json(self.incus_bytes)


@dataclass(frozen=True)
class OwnedFenceForCleanup:
    """Root-derived withdrawal locator only; never a PreparedCell or grant."""
    registry: policy_registry.Registry
    selector: str
    lease_id: str
    cell_sha256: str
    expires_at: int
    identity_policy_sha256: str
    creator_id: str
    creator_sha256: str


@dataclass(frozen=True)
class OwnedCellForCleanup:
    """Root semantic owner AFTER verified creation; never a PreparedCell grant.

    No authorization renewal, engine start, signing or materialization accepts
    this type. Paths/targets remain derivable after raw runtime files are gone.
    """
    registry: policy_registry.Registry
    selector: str
    lease_id: str
    cell_sha256: str
    expires_at: int
    identity_policy_sha256: str
    engine_descriptor_path: str
    engine_descriptor_bytes: bytes
    engine_descriptor_sha256: str
    engine_policy_sha256: str
    incus_bytes: bytes
    creator_bytes: bytes
    prepared_sha256: str
    canonical_bytes: bytes
    sha256: str

    @property
    def creator_digests(self):
        return {key: value["sha256"] for key, value in self.creators.items()}

    @property
    def creator_targets(self):
        return {key: value["target"] for key, value in self.creators.items()}

    @property
    def incus(self):
        return identity.decode_json(self.incus_bytes)

    @property
    def creators(self):
        return identity.decode_json(self.creator_bytes)


@dataclass(frozen=True)
class BoundCell:
    prepared_sha256: str
    engine_policy_sha256: str
    cell_sha256: str
    lease_id: str
    expires_at: int


def _text(value, maximum=1024):
    require(type(value) is str and 0 < len(value) <= maximum
            and not any(ord(c) < 32 or ord(c) == 127 for c in value), "cell-text")
    value.encode("utf-8")
    return value


def _name(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", value), "cell-name")
    return value


def _repo(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value), "cell-repository")
    return value


def _commit(value):
    require(type(value) is str and SHA.fullmatch(value), "cell-source-sha")
    return value


def _sealed(path, expected):
    proof, raw, stamp = installation._file(engine._path(path), MAX_CELL, private=True, keep=True)
    require(proof.sha256 == engine._hash(expected), "cell-bytes-drift")
    return identity.decode_json(raw), proof, stamp


def _store(policy, store):
    require(type(store) is ledger.Ledger and store.owner_uid == 0, "cell-root-ledger")
    fd = installation._open_directory(policy.ledger_path)
    try:
        expected, actual = os.fstat(fd), os.fstat(store.fd)
        require((expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino), "cell-ledger-path")
    finally:
        os.close(fd)


def _lease(policy, store, lease_id):
    require(type(lease_id) is str and ledger.ID.fullmatch(lease_id), "cell-lease-id")
    record = store.read(lease_id)
    who, auth, worker = record["identity"], record["authorizations"][-1], record["worker"]
    now = int(time.time())
    native = policy.identity
    require(record["state"] == "prepared" and record["cell_sha256"] == policy.cell_sha256
            and record["policy_sha256"] == policy.custody_policy_sha256
            and record["created_at"] <= now < record["expires_at"] == policy.deadline
            and auth["valid_until"] > now, "cell-lease-inactive")
    require(who["policy_sha256"] == identity.policy_digest(native)
            and who["caller_sha"] == native.caller_sha and who["reusable_sha"] == native.reusable_sha
            and who["runner_id"] == native.runner_id == worker["runner_id"]
            and who["service_uid"] == native.service_uid == worker["uid"], "cell-identity-binding")
    return record


def _bounded(value, maximum, owner=False):
    # Exact scripts/quality_cell_identity.py algorithm; full value is hashed.
    sanitized = re.sub(r"[^A-Za-z0-9._/-]" if owner else r"[^A-Za-z0-9.-]", "-", value)
    require(sanitized and sanitized[0].isalnum(), "cell-owned-identity")
    digest = hashlib.sha256((("owner" if owner else "instance") + "\0" + value).encode()).hexdigest()[:24]
    prefix = sanitized[:maximum - 25].rstrip("-._/")
    require(prefix, "cell-owned-identity")
    return prefix + "-" + digest


def _bytes(value, disk=False):
    match = re.fullmatch(r"([1-9][0-9]*)(KiB|MiB|GiB|TiB)", value)
    require(match is not None and (not disk or match[2] != "KiB"), "cell-resource")
    result = int(match[1]) * 1024 ** {"KiB": 1, "MiB": 2, "GiB": 3, "TiB": 4}[match[2]]
    require(result <= 2 ** 63 - 1, "cell-resource")
    return result



def _cell_fields(value):
    if value.get("kind") == "operating":
        return engine._keys(value, {"schema", "kind", "candidate", "controller", "operating", "github", "engine", "incus"})
    return engine._keys(value, {"schema", "candidate", "controller", "matrix", "github", "engine", "incus"})


def _environment(value, native, who):
    if value.get("kind") == "operating":
        from . import operating_cells
        return operating_cells.environment(value, native, who)
    matrix = engine._keys(value["matrix"], MATRIX_KEYS)
    receiver = identity.validation_main_receiver(native)
    github = engine._keys(value["github"], {"job", "workflow", "run_id"} if receiver else {"job", "workflow"})
    if receiver:
        require(type(github["run_id"]) is int and github["run_id"] > 0
                and github["run_id"] == who["run_id"], "cell-receiver-run-binding")
    roles = matrix["roles"]
    require(type(roles) is list and 0 < len(roles) <= 128 and len(set(roles)) == len(roles)
            and all(type(role) is str and re.fullmatch(r"[a-z][a-z0-9_]*", role) for role in roles), "cell-roles")
    require(type(matrix["junit"]) is bool and type(matrix["allure"]) is bool
            and matrix["instance_type"] == "vm", "cell-selected-vm")
    suffix = matrix["profile"] + " / " + matrix["scenario"] + " / " + matrix["target"]
    expected = native.required_native_job_name
    require(type(expected) is str and (expected == suffix or expected.endswith(" / " + suffix)), "cell-native-matrix")
    env = {"GITHUB_REPOSITORY": native.repository, "GITHUB_REPOSITORY_ID": str(native.repository_id),
           "GITHUB_RUN_ID": str(who["run_id"]), "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": native.caller_sha,
           "GITHUB_JOB": _text(github["job"], 128), "GITHUB_WORKFLOW": _text(github["workflow"])}
    rename = {"target_disposition": "TARGET_DISPOSITION", "instance_type": "INSTANCE_TYPE",
              "cpu_limit": "CPU_LIMIT", "memory_limit": "MEMORY_LIMIT", "disk_limit": "DISK_LIMIT"}
    for key in MATRIX_KEYS - {"roles", "junit", "allure"}:
        env["QUALITY_INPUT_" + rename.get(key, key.upper())] = _text(matrix[key], 512)
    env.update({"QUALITY_INPUT_ROLES": ",".join(roles), "QUALITY_INPUT_JUNIT_REQUIRED": str(matrix["junit"]).lower(),
                "QUALITY_INPUT_ALLURE_REQUIRED": str(matrix["allure"]).lower(),
                "QUALITY_INPUT_SOURCE_SHA": value["candidate"]["source_sha"],
                "QUALITY_INPUT_CANDIDATE_ARTIFACT": _text(value["candidate"]["artifact"], 255)})
    return env


def _validate_incus_template(value, env):
    """Read-only Incus static checks; derives no lease or resource identity."""
    data = engine._keys(value, {"server", "server_certificate", "pool", "project_prefix", "ipv4_address", "dns_domain", "project_limits"})
    url = urlsplit(_text(data["server"]))
    require(url.scheme == "https" and url.hostname and not url.username and not url.password
            and url.path in ("", "/") and not url.query and not url.fragment
            and (url.port is None or 1 <= url.port <= 65535), "cell-incus-server")
    pin = engine._keys(data["server_certificate"], {"path", "sha256"})
    certificate, _, _ = installation._file(engine._path(pin["path"]), 65536, private=True, keep=True)
    require(certificate.sha256 == engine._hash(pin["sha256"]), "cell-server-certificate")
    _name(data["pool"])
    prefix = _text(data["project_prefix"], 30)
    require(re.fullmatch(r"[a-z][a-z0-9-]*-", prefix), "cell-project-prefix")
    require(len(prefix) + 32 <= 63, "cell-project-prefix")
    subnet = ipaddress.IPv4Interface(data["ipv4_address"])
    require(str(subnet) == data["ipv4_address"] and 8 <= subnet.network.prefixlen <= 30
            and subnet.ip not in (subnet.network.network_address, subnet.network.broadcast_address), "cell-bridge-cidr")
    require(type(data["dns_domain"]) is str and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]", data["dns_domain"]),
            "cell-dns-domain")
    limits = engine._keys(data["project_limits"], {"cpu", "memory_bytes", "disk_bytes", "instances", "virtual_machines", "containers"})
    for key in limits:
        engine._integer(limits[key], 0 if key == "containers" else 1, 2 ** 63 - 1)
    require(limits["containers"] == 0 and limits["instances"] == limits["virtual_machines"]
            and limits["cpu"] >= int(env["QUALITY_INPUT_CPU_LIMIT"])
            and limits["memory_bytes"] >= _bytes(env["QUALITY_INPUT_MEMORY_LIMIT"])
            and limits["disk_bytes"] >= _bytes(env["QUALITY_INPUT_DISK_LIMIT"], disk=True), "cell-project-quota")
    return data


def _incus(value, env, lease_id, cell_sha):
    data = _validate_incus_template(value, env)
    pin = data["server_certificate"]
    limits = data["project_limits"]
    project = _name(data["project_prefix"] + lease_id)
    scenario, target = env["QUALITY_INPUT_SCENARIO"], env["QUALITY_INPUT_TARGET"]
    invocation = env["GITHUB_RUN_ID"] + "-1-" + scenario + "-" + target
    owner = _bounded(env["GITHUB_REPOSITORY"] + "-" + env["GITHUB_WORKFLOW"] + "-" + invocation, 255, True)
    instance = _bounded(scenario + "-" + env["GITHUB_RUN_ID"] + "-1-" + target, 63)
    ownership = {"owner": owner, "repository": env["GITHUB_REPOSITORY"], "run_id": int(env["GITHUB_RUN_ID"]),
                 "run_attempt": 1, "scenario": scenario, "target": target, "lease_id": lease_id, "cell_sha256": cell_sha}
    return {"server": data["server"], "server_certificate": pin, "project": project, "network": "lit" + hashlib.sha256(owner.encode()).hexdigest()[:12],
            "network_project": "default", "pool": data["pool"], "ipv4_address": data["ipv4_address"],
            "dns_domain": data["dns_domain"], "project_limits": limits, "ownership": ownership, "instance": instance}


def _validate_engine_template(template, env, native, deadline, created_at):
    """Read-only static template validation, without a lease or descriptor.

    Root publication supplies its real timestamp and acquired run environment.
    Validating these existing files/budgets grants no admission or runtime
    authority and does not materialize any per-lease resource.
    """
    engine._keys(template, {"image", "runner_gid", "cell_uid", "cell_gid", "uid_map", "gid_map", "limits",
                            "engine", "archives", "trees", "paths", "capture"})
    require(template["image"] == {"index_sha256": engine.IMAGE_INDEX, "manifest_sha256": engine.IMAGE_CHILD,
                                   "platform": "linux/amd64"}, "cell-engine-image")
    uid, gid, runner_gid = (engine._integer(template[k]) for k in ("cell_uid", "cell_gid", "runner_gid"))
    require(uid != native.service_uid and gid != runner_gid, "cell-engine-user")
    for key, logical, outside in (("uid_map", uid, native.service_uid), ("gid_map", gid, runner_gid)):
        mapping = engine._keys(template[key], {"host_base", "size"})
        base, size = engine._integer(mapping["host_base"], 65536), engine._integer(mapping["size"], 1024, 1048576)
        require(base + size <= 2 ** 32 - 1 and logical < size and not base <= outside < base + size, "cell-engine-map")
    limits = engine._keys(template["limits"], {"cpu_millis", "memory_bytes", "timeout_seconds"})
    engine._integer(limits["cpu_millis"], 1, 1000000)
    engine._integer(limits["memory_bytes"], 134217728, 2 ** 40)
    engine._integer(limits["timeout_seconds"], 1, 5400)
    # This is the immutable originally admitted budget. Revalidating a live
    # cell must not demand a second full execution window after time elapsed.
    # Preparation/start separately require enough remaining time before effects.
    require(type(created_at) is int and 0 < created_at < deadline
            and limits["timeout_seconds"] <= deadline - created_at, "cell-engine-deadline")
    capture = engine._keys(template["capture"], {"stdout_limit", "stderr_limit", "total_limit"})
    stdout_limit = engine._integer(capture["stdout_limit"], 1, engine.MAX_CAPTURE_STREAM_BYTES)
    stderr_limit = engine._integer(capture["stderr_limit"], 1, engine.MAX_CAPTURE_STREAM_BYTES)
    engine._integer(capture["total_limit"], 1, stdout_limit + stderr_limit)
    binary = engine._keys(template["engine"], {"executable", "executable_sha256"})
    require(binary["executable"] == engine.ENGINE, "cell-engine-executable")
    engine._file(engine.ENGINE, binary["executable_sha256"], maximum=128 * 1024 * 1024)
    paths = engine._keys(template["paths"], PATH_KEYS)
    for path in paths.values():
        fd = engine._directory(path, private=True)
        os.close(fd)
    require(len(set(paths.values())) == len(PATH_KEYS), "cell-path-overlap")
    archives = engine._keys(template["archives"], {"controller", "candidate"})
    for item in archives.values():
        engine._keys(item, {"path", "sha256"})
        engine._file(item["path"], item["sha256"])
    trees = engine._keys(template["trees"], {"workspace", "controller", "candidate"})
    for item in trees.values():
        engine._tree(item)
    roots = list(paths.values()) + [v["path"] for v in trees.values()] + [v["path"] for v in archives.values()]
    require(len(set(roots)) == len(roots) and not any(a.startswith(b + "/") for a in roots for b in roots if a != b), "cell-path-overlap")
    engine._environment(env, native.service_uid, uid, gid)
    return binary, paths


def _descriptor(template, env, native, lease_id, deadline, created_at):
    binary, paths = _validate_engine_template(template, env, native, deadline, created_at)
    return {"schema": 1, **{k: template[k] for k in ("image", "runner_gid", "cell_uid", "cell_gid", "uid_map", "gid_map", "limits", "archives", "trees", "capture")},
            "runner_uid": native.service_uid, "network_namespace_path": "/run/netns/lit-lease-" + lease_id,
            "cgroup_parent": "lit-lease-" + lease_id + ".slice",
            "engine": {**binary, "storage_root": paths["storage"] + "/" + lease_id, "runroot": paths["runroot"] + "/" + lease_id},
            "context_path": paths["context"] + "/" + lease_id, "output_path": paths["output"] + "/" + lease_id,
            "environment": env}


def owned_fence_for_cleanup(registry, selector, store, lease_id):
    """Reconstruct only an exact verified fence owner after expiry/cancel.

    This deliberately has no engine descriptor, Incus targets or signing data.
    Ordinary admission/materialization/renewal APIs still require PreparedCell.
    Kernel ownership, once-only withdrawal intent and real readback are separate
    mandatory checks in network_fence.disable; this locator grants nothing.
    """
    require(os.geteuid() == 0, "cell-root-required")
    try:
        require(type(registry) is policy_registry.Registry
                and type(registry.policies) is MappingProxyType
                and policy_registry.load_registry(registry.path, registry.sha256) == registry,
                "cell-root-registry")
        selected = registry.select(selector)
        admission._validate_policy(selected)
        _store(selected, store)
        require(type(lease_id) is str and ledger.ID.fullmatch(lease_id), "cell-lease-id")
        record = store.read(lease_id)
        who, worker = record["identity"], record["worker"]
        require(record["state"] in {"prepared", "cancelled", "retained"}
                and record["cell_sha256"] == selected.cell_sha256
                and record["policy_sha256"] == selected.custody_policy_sha256
                and record["expires_at"] == selected.deadline, "cell-cleanup-binding")
        native = selected.identity
        require(who["policy_sha256"] == identity.policy_digest(native)
                and who["caller_sha"] == native.caller_sha and who["reusable_sha"] == native.reusable_sha
                and who["runner_id"] == native.runner_id == worker["runner_id"]
                and who["service_uid"] == native.service_uid == worker["uid"], "cell-identity-binding")
        _sealed(selected.cell_config_path, selected.cell_sha256)
        matches = [(key, effect) for key, effect in record["effects"].items()
                   if effect["operation"] == "fence-create"]
        require(len(matches) == 1 and matches[0][1]["state"] == "verified"
                and matches[0][1]["target"] == "fence:" + lease_id
                and "fence" in matches[0][1]
                and not any(e["operation"] == "fence-remove" for e in record["effects"].values()),
                "cell-cleanup-fence-not-owned")
        creator, effect = matches[0]
        require(store.read(lease_id) == record
                and policy_registry.load_registry(registry.path, registry.sha256) == registry,
                "cell-cleanup-provenance-drift")
        return OwnedFenceForCleanup(registry, selector, lease_id, selected.cell_sha256,
                                    selected.deadline, identity.policy_digest(native), creator, ledger.digest(effect))
    except Denied:
        raise
    except Exception:
        raise Denied("cell-cleanup-denied") from None


def prepare_cell(registry, selector, store, lease_id):
    """Trusted Root factory; select existing policy and prepared lease only."""
    require(os.geteuid() == 0, "cell-root-required")
    try:
        require(type(registry) is policy_registry.Registry and type(registry.policies) is MappingProxyType,
                "cell-root-registry")
        require(policy_registry.load_registry(registry.path, registry.sha256) == registry, "cell-registry-drift")
        policy = registry.select(selector)
        admission._validate_policy(policy)
        _store(policy, store)
        record = _lease(policy, store, lease_id)
        value, proof, stamp = _sealed(policy.cell_config_path, policy.cell_sha256)
        _cell_fields(value)
        require(type(value["schema"]) is int and value["schema"] == 1, "cell-schema")
        candidate = engine._keys(value["candidate"], {"repository", "source_sha", "artifact", "archive_sha256"})
        controller = engine._keys(value["controller"], {"repository", "source_sha", "archive_sha256", "files"})
        _repo(candidate["repository"])
        _commit(candidate["source_sha"])
        require(controller["repository"] == policy.identity.reusable_repository, "cell-controller-repository")
        _commit(controller["source_sha"])
        # Candidate source, caller SHA, reusable workflow SHA and action/controller
        # SHA are independent legacy bindings; no global equality is imposed.
        env = _environment(value, policy.identity, record["identity"])
        descriptor = _descriptor(value["engine"], env, policy.identity, lease_id, record["expires_at"], record["created_at"])
        require(descriptor["archives"]["candidate"]["sha256"] == engine._hash(candidate["archive_sha256"])
                and descriptor["archives"]["controller"]["sha256"] == engine._hash(controller["archive_sha256"]), "cell-archive-binding")
        require(type(controller["files"]) is dict and set(controller["files"]) == engine.controller_files(env)
                and all(engine._hash(v) for v in controller["files"].values())
                and descriptor["trees"]["controller"]["files"] == controller["files"]
                and descriptor["trees"]["controller"]["directories"] == [], "cell-controller-files")
        incus = _incus(value["incus"], env, lease_id, policy.cell_sha256)
        again, after, after_stamp = _sealed(policy.cell_config_path, policy.cell_sha256)
        require(again == value and after == proof and after_stamp == stamp
                and _lease(policy, store, lease_id)["identity"] == record["identity"], "cell-provenance-drift")
        raw = engine._canonical(descriptor)
        path = value["engine"]["paths"]["descriptor"] + "/" + lease_id + ".json"
        details = {"schema": 1, "lease_id": lease_id, "cell_sha256": policy.cell_sha256,
                   "identity_policy_sha256": identity.policy_digest(policy.identity), "identity": record["identity"],
                   "expires_at": record["expires_at"], "candidate": candidate, "controller": controller,
                   "engine_descriptor_path": path, "engine_descriptor_sha256": hashlib.sha256(raw).hexdigest(), "incus": incus}
        canonical = engine._canonical(details)
        return PreparedCell(registry, selector, lease_id, policy.cell_sha256, record["expires_at"],
                            identity.policy_digest(policy.identity), path, raw, hashlib.sha256(raw).hexdigest(),
                            engine._canonical(incus), hashlib.sha256(canonical).hexdigest(), canonical)
    except Denied:
        raise
    except Exception:
        raise Denied("cell-contract-denied") from None


def bind_engine(prepared, store, manifest):
    """After TLS files exist, compare a freshly compiled exact derived engine.

    The Root materializer must already have written exact descriptor bytes0600.
    No signature/binding.json digest participates; native execution stays denied
    until the separate Root executor qualifies nsfs, image, maps and fencing.
    """
    require(os.geteuid() == 0, "cell-root-required")
    try:
        require(type(prepared) is PreparedCell and type(manifest) is engine.EngineManifest, "cell-engine-input")
        fresh = prepare_cell(prepared.registry, prepared.selector, store, prepared.lease_id)
        require(fresh == prepared, "cell-preparation-drift")
        actual = engine.compile_engine_policy(prepared.engine_descriptor_path, prepared.engine_descriptor_sha256)
        require(actual == manifest, "cell-engine-manifest-drift")
        return BoundCell(prepared.sha256, actual.sha256, prepared.cell_sha256, prepared.lease_id, prepared.expires_at)
    except Denied:
        raise
    except Exception:
        raise Denied("cell-engine-binding-denied") from None


@dataclass(frozen=True)
class OwnedCellForObservation(OwnedCellForCleanup):
    """Live read-only scope. No remote mutation accepts this type."""


def owned_cell_for_observation(registry, selector, store, lease_id):
    return _owned_cell(registry, selector, store, lease_id, live=True)


def owned_cell_for_cleanup(registry, selector, store, lease_id):
    return _owned_cell(registry, selector, store, lease_id, live=False)


def _owned_cell(registry, selector, store, lease_id, *, live):
    """Revalidate fixed Root semantics and original native creator receipts.

    No current JWT/authorization or surviving context/runroot is required. A
    partial/unknown create remains a hold, not an adopted cleanup target. This
    factory supplies only locators; every cleanup transport must independently
    reacquire native ownership and journal its own once-only effect.
    """
    require(os.geteuid() == 0, "cell-root-required")
    require(type(registry) is policy_registry.Registry and type(registry.policies) is MappingProxyType
            and policy_registry.load_registry(registry.path, registry.sha256) == registry, "cell-root-registry")
    selected = registry.select(selector)
    admission._validate_policy(selected)
    _store(selected, store)
    require(type(lease_id) is str and ledger.ID.fullmatch(lease_id), "cell-lease-id")
    record = store.read(lease_id)
    who, worker = record["identity"], record["worker"]
    native = selected.identity
    require(record["state"] in {"prepared", "cancelled", "retained", "closed"}
            and record["cell_sha256"] == selected.cell_sha256
            and record["policy_sha256"] == selected.custody_policy_sha256
            and record["expires_at"] == selected.deadline
            and who["policy_sha256"] == identity.policy_digest(native)
            and who["caller_sha"] == native.caller_sha and who["reusable_sha"] == native.reusable_sha
            and who["runner_id"] == native.runner_id == worker["runner_id"]
            and who["service_uid"] == native.service_uid == worker["uid"], "cell-cleanup-binding")
    value, proof, stamp = _sealed(selected.cell_config_path, selected.cell_sha256)
    _cell_fields(value)
    require(type(value["schema"]) is int and value["schema"] == 1, "cell-schema")
    candidate = engine._keys(value["candidate"], {"repository", "source_sha", "artifact", "archive_sha256"})
    controller = engine._keys(value["controller"], {"repository", "source_sha", "archive_sha256", "files"})
    _repo(candidate["repository"])
    _commit(candidate["source_sha"])
    require(controller["repository"] == native.reusable_repository, "cell-controller-repository")
    _commit(controller["source_sha"])
    env = _environment(value, native, who)
    descriptor = _descriptor(value["engine"], env, native, lease_id, record["expires_at"], record["created_at"])
    require(descriptor["archives"]["candidate"]["sha256"] == engine._hash(candidate["archive_sha256"])
            and descriptor["archives"]["controller"]["sha256"] == engine._hash(controller["archive_sha256"])
            and type(controller["files"]) is dict and set(controller["files"]) == engine.controller_files(env)
            and descriptor["trees"]["controller"]["files"] == controller["files"]
            and descriptor["trees"]["controller"]["directories"] == [], "cell-cleanup-source-binding")
    incus = _incus(value["incus"], env, lease_id, selected.cell_sha256)
    expected = {"network-create": "network:default:" + incus["network"],
        "project-create": "project:" + incus["project"],
        "profile-configure": "profile:" + incus["project"] + ":default",
        "context-create": "context:" + selected.cell_sha256,
        "engine-prepare": "engine:" + lease_id,
        "context-publish": "context:" + selected.cell_sha256,
        "fence-create": "fence:" + lease_id,
        "engine-start": "engine:lit-lease-" + lease_id}
    creators = {}
    for operation in (*expected, "certificate-create"):
        matches = [(identifier, effect) for identifier, effect in record["effects"].items()
                   if effect["operation"] == operation]
        require(len(matches) == 1 and matches[0][1]["state"] == "verified", "cell-cleanup-creator")
        identifier, effect = matches[0]
        if operation == "certificate-create":
            require(effect["target"].startswith("certificate:")
                    and ledger.HEX.fullmatch(effect["target"].removeprefix("certificate:")), "cell-cleanup-certificate")
        else:
            require(effect["target"] == expected[operation], "cell-cleanup-creator-target")
        creators[operation] = {"id": identifier, "target": effect["target"], "sha256": ledger.digest(effect)}
    start = record["effects"][creators["engine-start"]["id"]]
    require(all(key in start for key in ("engine_process", "engine_container_id", "engine_capture")),
            "cell-cleanup-engine-untracked")
    if live:
        require(value.get("kind") == "operating" and record["state"] == "prepared" and "engine_exit" not in start
                and int(time.time()) < min(record["expires_at"], record["authorizations"][-1]["valid_until"]),
                "cell-observation-not-live")
        ledger._validate_engine_process(start["engine_process"])
        ledger._validate_engine_capture(start["engine_capture"])
    else:
        require("engine_exit" in start, "cell-cleanup-engine-untracked")
        ledger._validate_engine_exit(start["engine_exit"], start)
    manifest_sha = start["engine_capture"]["manifest_sha256"]
    require("fence" in record["effects"][creators["fence-create"]["id"]], "cell-cleanup-fence-untracked")
    again, after, after_stamp = _sealed(selected.cell_config_path, selected.cell_sha256)
    require(again == value and after == proof and after_stamp == stamp and store.read(lease_id) == record
            and policy_registry.load_registry(registry.path, registry.sha256) == registry, "cell-cleanup-provenance-drift")
    raw = engine._canonical(descriptor)
    creator_bytes, incus_bytes = engine._canonical(creators), engine._canonical(incus)
    descriptor_path = value["engine"]["paths"]["descriptor"] + "/" + lease_id + ".json"
    binding = {"lease_id": lease_id, "cell_sha256": selected.cell_sha256,
               "identity_policy_sha256": identity.policy_digest(native), "descriptor": hashlib.sha256(raw).hexdigest(),
               "engine_policy_sha256": manifest_sha, "incus": incus, "creators": creators}
    original = {"schema": 1, "lease_id": lease_id, "cell_sha256": selected.cell_sha256,
        "identity_policy_sha256": identity.policy_digest(native), "identity": record["identity"],
        "expires_at": record["expires_at"], "candidate": candidate, "controller": controller,
        "engine_descriptor_path": descriptor_path, "engine_descriptor_sha256": hashlib.sha256(raw).hexdigest(), "incus": incus}
    canonical = engine._canonical(original)
    owner_type = OwnedCellForObservation if live else OwnedCellForCleanup
    return owner_type(registry, selector, lease_id, selected.cell_sha256, selected.deadline,
        identity.policy_digest(native), descriptor_path, raw, hashlib.sha256(raw).hexdigest(), manifest_sha,
        incus_bytes, creator_bytes, hashlib.sha256(canonical).hexdigest(), canonical, ledger.digest(binding))
