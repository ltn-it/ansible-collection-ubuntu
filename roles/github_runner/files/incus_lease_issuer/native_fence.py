"""Root-only READ-ONLY native quarantine and stopped-runner observations.

No group/rule/host change, token minting or operating authorization exists here.
The opaque window reference is NOT acceptance: the full migration caller must
independently establish the actual accepted operating window before any effects.
PlanningFacts never become an effect target. Only issue_after_stop can construct
a registration.VerifiedTarget after repeated native metadata, inactive exact
systemd unit and empty original cgroup/proc observations. This is still a bounded
observation, not an atomic GitHub lock or proof of machine ownership.
"""
from __future__ import annotations

from dataclasses import dataclass
import grp
import hashlib
import http.client
import json
import os
import pwd
from pathlib import PurePosixPath
import re
import ssl
import stat
import time

from .identity import Denied, decode_json, require
from .installation import trusted_file
from . import kernel, registration, service

API = "https://api.github.com"
API_VERSION = "2022-11-28"
MAX_PAGES = 101
MAX_ITEMS = 10000
MAX_RESPONSE = 2 * 1024 * 1024
MAX_PROC = 100000
MAX_CGROUP_DIRS = 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
PROPERTIES = ("Id", "LoadState", "ActiveState", "SubState", "MainPID", "ControlGroup",
              "FragmentPath", "DropInPaths", "NeedDaemonReload", "WorkingDirectory", "User", "Transient",
              "Group", "SupplementaryGroups", "UnitFileState")


@dataclass(frozen=True)
class NativeFencePolicy:
    owner_id: int
    owner_login: str
    runner_id: int
    runner_name: str
    group_id: int
    group_name: str
    labels: tuple[tuple[str, str], ...]
    target_architecture: str
    target_work_folder: str
    old_unit: str
    old_root: str
    old_user: str
    old_cgroup: str
    old_fragment: str
    old_fragment_sha256: str
    old_dropins: tuple[tuple[str, str], ...]
    read_token_path: str
    read_token_reference: str
    operations_window_reference: str


@dataclass(frozen=True)
class PlanningFacts:
    runner_id: int
    runner_name: str
    group_id: int
    online: bool
    busy: bool
    old_active_state: str
    observations_sha256: str
    operations_window_reference: str


def _root():
    require(os.geteuid() == 0, "native-fence-root-required")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _path(value):
    require(type(value) is str and value.startswith("/") and value != "/" and len(value) <= 4096
            and str(PurePosixPath(value)) == value and ".." not in PurePosixPath(value).parts
            and not any(ord(c) < 33 or ord(c) == 127 for c in value), "native-fence-path")


def _positive(value):
    return type(value) is int and 0 < value < 2 ** 63


def _validate(policy):
    _root()
    require(type(policy) is NativeFencePolicy, "native-fence-policy")
    require(all(_positive(x) for x in (policy.owner_id, policy.runner_id, policy.group_id))
            and policy.group_id < 2 ** 31, "native-fence-id")
    require(type(policy.owner_login) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", policy.owner_login)
            and type(policy.runner_name) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", policy.runner_name), "native-fence-name")
    require(type(policy.group_name) is str and 0 < len(policy.group_name) <= 128
            and not any(ord(c) < 32 for c in policy.group_name), "native-fence-group")
    require(policy.target_architecture in ("arm64", "x64") and type(policy.labels) is tuple
            and 1 <= len(policy.labels) <= 32, "native-fence-labels")
    names = set()
    for item in policy.labels:
        require(type(item) is tuple and len(item) == 2 and type(item[0]) is str
                and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", item[0]) and item[1] in ("read-only", "custom"), "native-fence-labels")
        require(item[0].lower() not in names, "native-fence-labels")
        names.add(item[0].lower())
    required = {("self-hosted", "read-only"), ("linux", "read-only"),
                ("arm64" if policy.target_architecture == "arm64" else "x64", "read-only")}
    require(required <= {(name.lower(), kind) for name, kind in policy.labels}, "native-fence-required-labels")
    require(type(policy.old_unit) is str and re.fullmatch(r"actions\.runner\.[A-Za-z0-9_.-]{1,120}\.service", policy.old_unit)
            and policy.old_cgroup == "/system.slice/" + policy.old_unit, "native-fence-old-unit")
    require(type(policy.old_user) is str and re.fullmatch(r"[a-z_][a-z0-9_-]{0,63}", policy.old_user)
            and policy.old_user != "root", "native-fence-old-user")
    for value in (policy.target_work_folder, policy.old_root, policy.old_fragment, policy.read_token_path):
        _path(value)
    require(policy.old_fragment == "/etc/systemd/system/" + policy.old_unit
            and type(policy.old_fragment_sha256) is str and HEX.fullmatch(policy.old_fragment_sha256)
            and type(policy.old_dropins) is tuple and len(policy.old_dropins) <= 32, "native-fence-unit-policy")
    paths = {policy.old_fragment}
    for item in policy.old_dropins:
        require(type(item) is tuple and len(item) == 2, "native-fence-unit-policy")
        _path(item[0])
        require(item[0].startswith("/etc/systemd/system/" + policy.old_unit + ".d/")
                and item[0].endswith(".conf") and item[0] not in paths
                and type(item[1]) is str and HEX.fullmatch(item[1]), "native-fence-unit-policy")
        paths.add(item[0])
    for reference in (policy.read_token_reference, policy.operations_window_reference):
        require(type(reference) is str and 0 < len(reference) <= 1024
                and not any(ord(c) < 32 for c in reference), "native-fence-reference")


def _read_token(path):
    proof = trusted_file(path, max_bytes=8192)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                "native-fence-token-private")
        raw = os.read(fd, 8193)
        require((info.st_dev, info.st_ino, info.st_size) == (proof.device, proof.inode, proof.size)
                and hashlib.sha256(raw).hexdigest() == proof.sha256, "native-fence-token-drift")
        token = raw.decode("ascii").removesuffix("\n")
        require(0 < len(token) <= 8192 and all(33 <= ord(c) <= 126 for c in token), "native-fence-token-input")
        return token
    finally:
        os.close(fd)


class _Reader:
    """Fixed-origin, fixed-policy GET-only reader; no URL from response is used."""
    def __init__(self, policy):
        self.prefix = "/orgs/" + policy.owner_login
        self.runner = policy.runner_id
        self.group = policy.group_id
        self._token = _read_token(policy.read_token_path)

    def get(self, path):
        bases = {self.prefix, self.prefix + "/actions/runners/" + str(self.runner),
                 self.prefix + "/actions/runner-groups/" + str(self.group)}
        paginated = {self.prefix + "/actions/runners", self.prefix + "/actions/runner-groups",
                     self.prefix + "/actions/runner-groups/" + str(self.group) + "/runners",
                     self.prefix + "/actions/runner-groups/" + str(self.group) + "/repositories"}
        allow = path in bases or any(re.fullmatch(re.escape(base) + r"\?per_page=100&page=[1-9][0-9]{0,2}", path)
                                    for base in paginated)
        require(allow, "native-fence-http-route")
        connection = None
        try:
            connection = http.client.HTTPSConnection("api.github.com", 443, timeout=15,
                                                   context=ssl.create_default_context())
            connection.request("GET", path, headers={"Authorization": "Bearer " + self._token,
                               "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION,
                               "User-Agent": "lit-root-native-fence/1"})
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE + 1)
            require(response.status == 200 and 0 < len(raw) <= MAX_RESPONSE, "native-fence-http-response")
            # Content pagination is bounded by exact total_count and a final
            # empty page. Link URLs cannot change the origin or skip pages.
            return decode_json(raw)
        except Exception:
            raise Denied("native-fence-http-failed") from None
        finally:
            if connection is not None:
                connection.close()


def _pages(reader, base, collection):
    result, count, identifiers = [], None, set()
    for page in range(1, MAX_PAGES + 1):
        data = reader.get(base + "?per_page=100&page=" + str(page))
        require(type(data) is dict and type(data.get("total_count")) is int
                and 0 <= data["total_count"] <= MAX_ITEMS and type(data.get(collection)) is list,
                "native-fence-page-shape")
        if count is None:
            count = data["total_count"]
        require(data["total_count"] == count and len(data[collection]) <= 100, "native-fence-page-drift")
        for item in data[collection]:
            require(type(item) is dict and _positive(item.get("id")) and item["id"] not in identifiers,
                    "native-fence-page-duplicate")
            identifiers.add(item["id"])
            result.append(item)
        require(len(result) <= count, "native-fence-page-count")
        if not data[collection]:
            require(len(result) == count, "native-fence-incomplete-pagination")
            return result
        # Even after reaching total_count, acquire the next empty page rather
        # than equating an advertised count with complete transport acquisition.
    raise Denied("native-fence-page-limit")


def _labels(runner):
    require(type(runner.get("labels")) is list and len(runner["labels"]) <= 32, "native-fence-runner-labels")
    values, names = [], set()
    for label in runner["labels"]:
        require(type(label) is dict and type(label.get("id")) is int and 0 <= label["id"] < 2 ** 63
                and type(label.get("name")) is str
                and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", label["name"])
                and label.get("type") in ("read-only", "custom"), "native-fence-runner-labels")
        require(label["name"].lower() not in names, "native-fence-runner-labels")
        names.add(label["name"].lower())
        values.append((label["name"], label["type"]))
    return tuple(sorted(values))


def _github(reader, policy, stopped):
    prefix = "/orgs/" + policy.owner_login
    owner = reader.get(prefix)
    require(type(owner) is dict and type(owner.get("id")) is int and owner["id"] == policy.owner_id
            and owner.get("login") == policy.owner_login and owner.get("type") == "Organization", "native-fence-owner")
    runners = _pages(reader, prefix + "/actions/runners", "runners")
    require(all(type(row.get("name")) is str and 0 < len(row["name"]) <= 255
                and not any(ord(c) < 32 for c in row["name"]) for row in runners), "native-fence-runner-name")
    require(len({row["name"].casefold() for row in runners}) == len(runners), "native-fence-ambiguous-runner-name")
    matches = [row for row in runners if row.get("id") == policy.runner_id or row.get("name") == policy.runner_name]
    require(len(matches) == 1, "native-fence-runner-identity")
    runner = reader.get(prefix + "/actions/runners/" + str(policy.runner_id))
    # The actual organization GET emits "Linux", label ID0 and may omit
    # ephemeral. Absence remains UNKNOWN, never persistent-server evidence.
    # The later expected-ID registration still requests ephemeral:false.
    require(runner == matches[0] and runner.get("name") == policy.runner_name
            and type(runner.get("os")) is str and runner["os"].casefold() == "linux"
            and type(runner.get("busy")) is bool and runner.get("status") in ("online", "offline")
            and ("ephemeral" not in runner or runner["ephemeral"] is False)
            and _labels(runner) == tuple(sorted(policy.labels)), "native-fence-runner-binding")
    if stopped:
        require(runner["status"] == "offline" and runner["busy"] is False, "native-fence-runner-not-idle-offline")
    groups = _pages(reader, prefix + "/actions/runner-groups", "runner_groups")
    matches = [row for row in groups if row.get("id") == policy.group_id or row.get("name") == policy.group_name]
    require(len(matches) == 1, "native-fence-group-identity")
    group = reader.get(prefix + "/actions/runner-groups/" + str(policy.group_id))
    require(group == matches[0] and group.get("name") == policy.group_name and group.get("inherited") is False
            and group.get("visibility") == "selected", "native-fence-group-not-quarantined")
    members = _pages(reader, prefix + "/actions/runner-groups/" + str(policy.group_id) + "/runners", "runners")
    require(members == [runner], "native-fence-group-membership")
    repositories = _pages(reader, prefix + "/actions/runner-groups/" + str(policy.group_id) + "/repositories", "repositories")
    require(repositories == [], "native-fence-group-repositories-not-empty")
    return {"owner": owner, "runners": runners, "runner": runner, "groups": groups, "group": group,
            "members": members, "repositories": repositories}


def _legacy_group_binding(user):
    """Root group is trusted only when the old runner cannot act as GID0.

    This is NSS acquisition, not a caller-supplied membership assertion. Loaded
    systemd group overrides are independently checked below. Unknown NSS denies.
    """
    try:
        account = pwd.getpwnam(user)
        root_group = grp.getgrgid(0)
        groups = os.getgrouplist(user, account.pw_gid)
        require(account.pw_name == user and type(account.pw_uid) is int and account.pw_uid > 0
                and type(account.pw_gid) is int and account.pw_gid > 0
                and type(root_group.gr_gid) is int and root_group.gr_gid == 0 and type(root_group.gr_mem) is list
                and len(root_group.gr_mem) <= 10000
                and all(type(member) is str and 0 < len(member) <= 256 for member in root_group.gr_mem)
                and user not in root_group.gr_mem
                and type(groups) is list and 0 < len(groups) <= 1024
                and all(type(gid) is int and gid > 0 for gid in groups), "native-fence-root-group-unsafe")
        return account.pw_uid, account.pw_gid, tuple(sorted(set(groups)))
    except (KeyError, OSError, OverflowError, TypeError):
        raise Denied("native-fence-root-group-unknown") from None


def _loaded_groups(values, user):
    _legacy_group_binding(user)
    tokens = ([values["Group"]] if values["Group"] else [])
    tokens += values["SupplementaryGroups"].split(" ") if values["SupplementaryGroups"] else []
    require(len(tokens) <= 1024, "native-fence-unit-groups")
    try:
        for name in tokens:
            require(type(name) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}|0|[1-9][0-9]{0,9}", name),
                    "native-fence-unit-groups")
            if name.isascii() and name.isdecimal():
                number = int(name)
                require(number > 0, "native-fence-unit-root-group")
                group = grp.getgrgid(number)
                require(group.gr_gid == number, "native-fence-unit-groups")
            else:
                group = grp.getgrnam(name)
            require(type(group.gr_gid) is int and group.gr_gid > 0, "native-fence-unit-root-group")
    except (KeyError, OSError, OverflowError):
        raise Denied("native-fence-unit-groups-unknown") from None


def _legacy_unit_file(path, expected_sha256, user):
    """READ-ONLY exception for exact old Root:Root0644/0664 unit bytes.

    No chmod, copying, adoption or execution occurs. This exception is private
    to the configured legacy fragment/drop-ins and never weakens trusted_file.
    """
    _root()
    _path(path)
    require(type(expected_sha256) is str and HEX.fullmatch(expected_sha256), "native-fence-unit-file-policy")
    parts = PurePosixPath(path).parts[1:]
    fd, opened = os.open("/", DIR), -1
    try:
        for part in parts[:-1]:
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                    and not stat.S_IMODE(info.st_mode) & 0o022, "native-fence-unit-ancestor")
            following = os.open(part, DIR, dir_fd=fd)
            os.close(fd)
            fd = following
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                and not stat.S_IMODE(info.st_mode) & 0o022, "native-fence-unit-ancestor")
        opened = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        before = os.fstat(opened)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) in {0o644, 0o664}
                and 0 <= before.st_size <= 1048576, "native-fence-unit-file-metadata")
        membership = _legacy_group_binding(user) if stat.S_IMODE(before.st_mode) == 0o664 else None
        hasher, count = hashlib.sha256(), 0
        while True:
            chunk = os.read(opened, min(65536, 1048577 - count))
            if not chunk:
                break
            count += len(chunk)
            require(count <= 1048576, "native-fence-unit-file-limit")
            hasher.update(chunk)
        after = os.fstat(opened)
        named = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        def stamp(item):
            return (item.st_dev, item.st_ino, item.st_uid, item.st_gid, item.st_mode, item.st_nlink,
                    item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(stamp(before) == stamp(after) == stamp(named) and count == after.st_size,
                "native-fence-unit-file-drift")
        if membership is not None:
            require(_legacy_group_binding(user) == membership, "native-fence-unit-group-drift")
        digest = hasher.hexdigest()
        require(digest == expected_sha256, "native-fence-unit-file-hash")
        return digest
    except OSError:
        raise Denied("native-fence-unit-file-unavailable") from None
    finally:
        if opened >= 0:
            os.close(opened)
        os.close(fd)


def _unit_files(policy):
    return [(path, _legacy_unit_file(path, expected, policy.old_user))
            for path, expected in ((policy.old_fragment, policy.old_fragment_sha256),) + policy.old_dropins]


def _read_unit(policy):
    trusted_file("/usr/bin/systemctl")
    expected = list(((policy.old_fragment, policy.old_fragment_sha256),) + policy.old_dropins)
    require(_unit_files(policy) == expected, "native-fence-unit-files")
    raw = service._command(["/usr/bin/systemctl", "--system", "--no-pager", "--full", "--all", "show",
                            "--property=" + ",".join(PROPERTIES), "--", policy.old_unit])
    require(type(raw) is bytes and 0 < len(raw) <= 65536 and raw.endswith(b"\n"), "native-fence-unit-output")
    values = {}
    for line in raw.decode("utf-8").splitlines():
        require("=" in line and not any(ord(c) < 32 for c in line), "native-fence-unit-output")
        key, value = line.split("=", 1)
        require(key in PROPERTIES and key not in values, "native-fence-unit-output")
        values[key] = value
    require(set(values) == set(PROPERTIES) and values["Id"] == policy.old_unit and values["LoadState"] == "loaded"
            and values["FragmentPath"] == policy.old_fragment
            and values["DropInPaths"] == " ".join(path for path, _ in policy.old_dropins)
            and values["WorkingDirectory"] == policy.old_root and values["User"] == policy.old_user
            and values["NeedDaemonReload"] == "no" and values["Transient"] == "no", "native-fence-unit-binding")
    require(re.fullmatch(r"[a-z][a-z-]{0,63}", values["UnitFileState"]), "native-fence-unit-file-state")
    _loaded_groups(values, policy.old_user)
    require(values["ControlGroup"] in ("", policy.old_cgroup), "native-fence-cgroup-binding")
    if values["ActiveState"] == "inactive":
        require(values["MainPID"] == "0" and values["SubState"] == "dead", "native-fence-unit-inactive-shape")
    else:
        require(values["ActiveState"] == "active" and values["SubState"] == "running"
                and re.fullmatch(r"[1-9][0-9]{0,9}", values["MainPID"])
                and values["ControlGroup"] == policy.old_cgroup, "native-fence-unit-state")
    require(_unit_files(policy) == expected, "native-fence-unit-files-drift")
    return values


def _membership(path, expected):
    return path == expected or path.startswith(expected + "/")


def _cgroup_processes(policy):
    """Read full original subtree AND proc membership, not MainPID alone."""
    proc = os.open("/proc", DIR)
    hierarchy = os.open("/sys/fs/cgroup", DIR)
    try:
        own = os.open("self", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=proc)
        try:
            mountinfo = kernel.bounded_file(own, "mountinfo", 1024 * 1024).decode("utf-8")
        finally:
            os.close(own)
        mounts = []
        for row in mountinfo.splitlines():
            fields = row.split(" ")
            if len(fields) > 7 and fields[4] == "/sys/fs/cgroup":
                separator = fields.index("-")
                mounts.append((fields[3], fields[separator + 1]))
        require(mounts == [("/", "cgroup2")], "native-fence-cgroup-view")
        root = -1
        current = os.dup(hierarchy)
        try:
            try:
                for part in PurePosixPath(policy.old_cgroup).parts[1:]:
                    next_fd = os.open(part, DIR, dir_fd=current)
                    os.close(current)
                    current = next_fd
                root, current = current, -1
            except FileNotFoundError:
                root = -1
        finally:
            if current >= 0:
                os.close(current)
        seen, tree_pids = 0, []
        def scan(fd):
            nonlocal seen
            seen += 1
            require(seen <= MAX_CGROUP_DIRS, "native-fence-cgroup-limit")
            raw = kernel.bounded_file(fd, "cgroup.procs", 65536)
            require(raw == b"", "native-fence-cgroup-populated")
            events = kernel.bounded_file(fd, "cgroup.events", 4096).decode("ascii").splitlines()
            require(events.count("populated 0") == 1, "native-fence-cgroup-populated")
            os.lseek(fd, 0, os.SEEK_SET)
            for entry in os.scandir(fd):
                require(not entry.is_symlink(), "native-fence-cgroup-symlink")
                if entry.is_dir(follow_symlinks=False):
                    child = os.open(entry.name, DIR, dir_fd=fd)
                    try:
                        scan(child)
                    finally:
                        os.close(child)
        if root >= 0:
            try:
                scan(root)
            finally:
                os.close(root)
        os.lseek(proc, 0, os.SEEK_SET)
        pids = [name for name in os.listdir(proc) if name.isascii() and name.isdecimal()]
        require(len(pids) <= MAX_PROC, "native-fence-proc-limit")
        for name in pids:
            process = -1
            try:
                process = os.open(name, DIR, dir_fd=proc)
                cgroup = kernel.parse_cgroup(kernel.bounded_file(process, "cgroup", kernel.CGROUP_LIMIT))
                require(not _membership(cgroup, policy.old_cgroup), "native-fence-original-cgroup-has-pids")
            except (FileNotFoundError, ProcessLookupError):
                # A PID that exited cannot remain in the original cgroup. All
                # permission/shape failures remain fatal, never silently skip.
                pass
            finally:
                if process >= 0:
                    os.close(process)
        return {"original_cgroup": policy.old_cgroup, "tree_pids": tree_pids, "proc_members": [],
                "hierarchy_present": root >= 0, "mount": mounts}
    finally:
        os.close(proc)
        os.close(hierarchy)


def _collect(policy, reader, stopped, unit_reader, empty_reader):
    native = _github(reader, policy, stopped)
    unit = unit_reader(policy)
    if stopped:
        require(unit["ActiveState"] == "inactive" and unit["MainPID"] == "0", "native-fence-old-unit-not-stopped")
        # A stopped legacy listener must not regain its old registration on
        # reboot while the expected-ID handoff is prepared. Read systemd's
        # actual install state on both passes; absence is not disabled proof.
        require(unit.get("UnitFileState") == "disabled", "native-fence-old-unit-autostart")
        empty = empty_reader(policy)
    else:
        empty = None
    return {"native": native, "unit": unit, "empty": empty, "boot_id": kernel.read_boot_id()}


def _observations(policy, stopped, _reader=None, _unit_reader=None, _empty_reader=None):
    _validate(policy)
    started = time.monotonic()
    reader = _Reader(policy) if _reader is None else _reader
    unit_reader = _read_unit if _unit_reader is None else _unit_reader
    empty_reader = _cgroup_processes if _empty_reader is None else _empty_reader
    first = _collect(policy, reader, stopped, unit_reader, empty_reader)
    second = _collect(policy, reader, stopped, unit_reader, empty_reader)
    require(first == second and time.monotonic() - started <= 120, "native-fence-observations-drift")
    binding = {"observations": first, "window_reference": policy.operations_window_reference,
               "read_token_reference": policy.read_token_reference}
    return first, _sha(_canonical(binding))


def inspect_before_stop(policy, *, _reader=None, _unit_reader=None):
    """Read-only plan; this result has no registration issuance capability."""
    try:
        observation, digest = _observations(policy, False, _reader, _unit_reader)
        runner = observation["native"]["runner"]
        return PlanningFacts(policy.runner_id, policy.runner_name, policy.group_id, runner["status"] == "online",
                             runner["busy"], observation["unit"]["ActiveState"], digest, policy.operations_window_reference)
    except Denied:
        raise
    except Exception:
        raise Denied("native-fence-planning-unavailable") from None


def issue_after_stop(policy, *, _reader=None, _unit_reader=None, _empty_reader=None):
    """Internal root-native entry; test reader injection is NOT a job API."""
    try:
        _, digest = _observations(policy, True, _reader, _unit_reader, _empty_reader)
        labels = tuple((name, "system" if kind == "read-only" else "user") for name, kind in policy.labels)
        return registration.VerifiedTarget(policy.owner_id, policy.owner_login, policy.runner_id, policy.runner_name,
                    policy.group_id, policy.group_name, policy.target_architecture, labels, policy.target_work_folder,
                    digest, int(time.time()) + 30, _authority=registration._FENCE_AUTHORITY)
    except Denied:
        raise
    except Exception:
        raise Denied("native-fence-acquisition-unavailable") from None
