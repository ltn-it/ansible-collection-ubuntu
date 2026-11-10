"""Read one root-selected local system service; this is not worker admission.

There is no public request handler. Policy is provisioned by the root operator,
never reconstructed from a job payload. Loaded service metadata and matching
unit files do not prove process ancestry, startup/loaded-code integrity, mount
view equivalence, native assignment, isolation, or custody acceptance.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import pwd
import re
import selectors
import subprocess
import time

from .identity import Denied, decode_json, require
from .installation import InstallationPolicy, trusted_file
from .worker import absolute_path, positive

PROPERTIES = (
    "Id", "LoadState", "ActiveState", "SubState", "MainPID", "User",
    "DynamicUser", "ControlGroup", "FragmentPath", "DropInPaths",
    "NeedDaemonReload", "WorkingDirectory", "ExecStart", "EnvironmentFiles",
    "PassEnvironment", "RootDirectory", "RootImage",
)
UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,239}\.service\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_OUTPUT = 131072


@dataclass(frozen=True)
class ServicePolicy:
    unit: str
    service_user: str
    installation: InstallationPolicy
    fragment_path: str
    fragment_sha256: str
    dropins: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ServiceSnapshot:
    unit: str
    main_pid: int
    service_uid: int
    cgroup: str
    properties_sha256: str
    unit_files: tuple[tuple[str, str], ...]


def validate_policy(policy):
    require(type(policy) is ServicePolicy and type(policy.unit) is str
            and UNIT.fullmatch(policy.unit), "invalid-service-policy")
    require(type(policy.service_user) is str and re.fullmatch(
        r"[a-z_][a-z0-9_-]{0,63}", policy.service_user), "invalid-service-policy")
    require(type(policy.installation) is InstallationPolicy, "invalid-service-policy")
    require(absolute_path(policy.installation.root)
            and re.fullmatch(r"/[A-Za-z0-9_./-]+", policy.installation.root), "unsupported-runner-path")
    require(type(policy.dropins) is tuple and len(policy.dropins) <= 32, "invalid-service-policy")
    entries = ((policy.fragment_path, policy.fragment_sha256),) + policy.dropins
    require(all(type(entry) is tuple and len(entry) == 2 for entry in entries), "invalid-service-policy")
    require(all(absolute_path(path) and not any(c.isspace() for c in path)
                and type(digest) is str and SHA.fullmatch(digest) for path, digest in entries),
            "invalid-service-policy")
    require(len({path for path, _ in entries}) == len(entries), "duplicate-unit-file")
    require(positive(policy.installation.service_uid), "invalid-service-policy")


def parse_properties(raw):
    """Parse the bounded, fixed property selection, never arbitrary show output."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_OUTPUT, "invalid-service-output")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise Denied("invalid-service-output") from None
    require("\x00" not in text and "\r" not in text, "invalid-service-output")
    result = {}
    for line in text.splitlines():
        require("=" in line and not any(ord(c) < 32 for c in line), "invalid-service-output")
        key, value = line.split("=", 1)
        require(key in PROPERTIES and key not in result, "invalid-service-properties")
        result[key] = value
    require(set(result) == set(PROPERTIES), "missing-service-properties")
    return result


def qualify_properties(properties, policy):
    """Internal comparison only; supplied mappings are not acquisition evidence."""
    validate_policy(policy)
    require(type(properties) is dict and set(properties) == set(PROPERTIES)
            and all(type(v) is str for v in properties.values()), "invalid-service-properties")
    p = properties
    require((p["Id"], p["LoadState"], p["ActiveState"], p["SubState"])
            == (policy.unit, "loaded", "active", "running"), "service-not-running")
    require(p["User"] == policy.service_user and p["DynamicUser"] == "no", "service-user")
    require(p["NeedDaemonReload"] == "no", "service-reload-pending")
    require(re.fullmatch(r"[1-9][0-9]{0,9}", p["MainPID"])
            and positive(int(p["MainPID"])), "invalid-service-mainpid")
    require(absolute_path(p["ControlGroup"]) and p["ControlGroup"] != "/", "invalid-service-cgroup")
    require(p["FragmentPath"] == policy.fragment_path, "service-fragment")
    # Space/escape-bearing filenames are unsupported, not split heuristically.
    paths = p["DropInPaths"].split(" ") if p["DropInPaths"] else []
    require(paths == [path for path, _ in policy.dropins], "service-dropins")
    require(p["WorkingDirectory"] == policy.installation.root, "service-working-directory")
    require(all(p[key] == "" for key in ("EnvironmentFiles", "PassEnvironment", "RootDirectory", "RootImage")),
            "unsupported-service-startup-input")
    # systemctl includes live timestamps/PID/result metadata after these fields.
    # Only the fixed single stock executable and argument are admitted here.
    command = policy.installation.root + "/runsvc.sh"
    prefix = "{ path=" + command + " ; argv[]=" + command + " ; ignore_errors=no ; "
    require(p["ExecStart"].startswith(prefix) and p["ExecStart"].endswith(" }")
            and p["ExecStart"].count("{") == p["ExecStart"].count("}") == 1, "service-execstart")
    return int(p["MainPID"]), p["ControlGroup"]


def _command(command):
    """No inherited DBus/systemd environment, shell, pager, remote, or retry."""
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                   "SYSTEMD_COLORS": "0", "SYSTEMD_PAGER": "cat", "SYSTEMD_PAGERSECURE": "1"}
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   stdin=subprocess.DEVNULL, cwd="/", env=environment, close_fds=True)
        try:
            deadline, chunks, size = time.monotonic() + 10, [], 0
            os.set_blocking(process.stdout.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, "service-query-timeout")
                    require(selector.select(remaining), "service-query-timeout")
                    part = os.read(process.stdout.fileno(), min(65536, MAX_OUTPUT + 1 - size))
                    if not part:
                        break
                    size += len(part)
                    require(size <= MAX_OUTPUT, "service-query-output-limit")
                    chunks.append(part)
            remaining = deadline - time.monotonic()
            require(remaining > 0, "service-query-timeout")
            process.wait(timeout=remaining)
            require(process.returncode == 0, "service-query-failed")
            return b"".join(chunks)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
    except (OSError, subprocess.SubprocessError):
        raise Denied("service-query-failed") from None


def _environment_files_empty(unit):
    # systemctl255 omits this structured empty array even with --all. Absence
    # must not be interpreted as empty: acquire its typed D-Bus value instead.
    base = ["/usr/bin/busctl", "--system", "--no-pager", "--json=short"]
    obj = decode_json(_command(base + ["call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager", "GetUnit", "s", unit]))
    require(set(obj) == {"type", "data"} and obj["type"] == "o" and type(obj["data"]) is list
            and len(obj["data"]) == 1 and type(obj["data"][0]) is str
            and re.fullmatch(r"/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+", obj["data"][0]),
            "invalid-service-object")
    value = decode_json(_command(base + ["get-property", "org.freedesktop.systemd1", obj["data"][0],
                                        "org.freedesktop.systemd1.Service", "EnvironmentFiles"]))
    require(value == {"type": "a(sb)", "data": []}, "unsupported-service-environment-files")


def _show(unit):
    # The object path and CLI property values are acquired from the same root
    # manager. Integration must still compare complete snapshots around the
    # actual kernel and code checks; this function cannot grant admission.
    _environment_files_empty(unit)
    selected = [name for name in PROPERTIES if name != "EnvironmentFiles"]
    raw = _command(["/usr/bin/systemctl", "--system", "--no-pager", "--full", "--all", "show",
                    "--property=" + ",".join(selected), "--", unit])
    require(raw.endswith(b"\n"), "invalid-service-output")
    return raw + b"EnvironmentFiles=\n"


def read_service(policy):
    """Acquire metadata and exact root-provisioned unit hashes, not authority.

    The caller must compare two snapshots around kernel/code acquisition and
    separately establish all runtime trust prerequisites. Nothing is started,
    stopped, reloaded, registered, configured, or granted by this function.
    """
    require(os.geteuid() == 0, "root-service-reader-required")
    validate_policy(policy)
    try:
        require(pwd.getpwnam(policy.service_user).pw_uid == policy.installation.service_uid, "service-user")
    except KeyError:
        raise Denied("service-user") from None
    trusted_file("/usr/bin/systemctl")
    trusted_file("/usr/bin/busctl")
    expected = ((policy.fragment_path, policy.fragment_sha256),) + policy.dropins
    for path, digest in expected:
        require(trusted_file(path, max_bytes=1048576).sha256 == digest, "unit-file-mismatch")
    raw = _show(policy.unit)
    main_pid, cgroup = qualify_properties(parse_properties(raw), policy)
    for path, digest in expected:
        require(trusted_file(path, max_bytes=1048576).sha256 == digest, "unit-file-changed")
    return ServiceSnapshot(policy.unit, main_pid, policy.installation.service_uid, cgroup,
                           hashlib.sha256(raw).hexdigest(), expected)
