#!/usr/bin/python3 -IB
"""Closed, once-only native package maintenance. No service or rollback authority.

The caller must arrange the reviewed shared-host maintenance/backup/restore
conditions. Root-owned JSON is input binding, never evidence those conditions
exist. APT owns its package locks; this process holds only its private once lock.
The fixed v3 hook checks final actions/archives while APT retains its frontend
lock (not the inner dpkg lock). This is not protection against arbitrary Root
writers or permission to skip actual maintenance/restore qualification.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import selectors
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit, unquote


CANDIDATE_SHA256 = "1b7c0c2c6baeb0b3130f3156047dcf1f40db59e89345ea593e909472e5ed7500"
NATIVE_APT_SHA256 = "87279ca48820a0423c2ee8b25dba48af0ad7d9f46c16f1e3cfdc07934dcf5ae1"
NATIVE_APT_VERSION = "apt 2.8.4 (amd64)"
HELPER = "/usr/libexec/lightning-it/incus-maintenance/runtime_packages.py"
DEBCONF_PROFILE = "/usr/libexec/lightning-it/incus-maintenance/runtime_packages_debconf.json"
DEBCONF_PROFILE_SHA256 = "34a91088a7972cdb4eaf59f35f8b3c5b34d40e71b8b4543120d55e71ab72c0d7"
DEBCONF_HOOK = "/usr/sbin/dpkg-preconfigure --apt || true"
DEBCONF_PROGRAM = "/usr/sbin/dpkg-preconfigure"
APT = "/usr/bin/apt-get"
DEB = "/usr/bin/dpkg-deb"
APT_CONFIG = "/usr/bin/apt-config"
STATUS = "/var/lib/dpkg/status"
MACHINE = "/etc/machine-id"
LISTS = "/var/lib/apt/lists"
CONFIG = "/etc/apt"
EXTENDED = "/var/lib/apt/extended_states"
UPDATES = "/var/lib/dpkg/updates"
DIRECT = ("incus", "incus-base", "incus-client", "podman", "crun", "conmon")
DIRECT_FILES = (
    "incus_7.6-ubuntu24.04-202611021330_amd64.deb",
    "incus-base_7.6-ubuntu24.04-202611021330_amd64.deb",
    "incus-client_7.6-ubuntu24.04-202611021330_amd64.deb",
    "podman.deb", "crun.deb", "conmon.deb",
)
SHA = re.compile(r"[0-9a-f]{64}")
SAFE_PATH = re.compile(r"/[A-Za-z0-9_./%+:-]{1,1000}")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC",
       "DEBIAN_FRONTEND": "noninteractive"}
LIMIT = 2 * 1024 * 1024


class Denied(Exception):
    """Fixed public category; never include raw command output or request data."""


def need(condition, category):
    if not condition:
        raise Denied(category)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory(path, private=False):
    need(type(path) is str and SAFE_PATH.fullmatch(path) and str(Path(path)) == path
         and ".." not in Path(path).parts, "canonical-root-path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in Path(path).parts[1:]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=fd)
            os.close(fd)
            fd = following
            info = os.fstat(fd)
            need(info.st_uid == 0 and not info.st_mode & 0o022, "root-directory-ownership")
        if private:
            need(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, "private-directory-mode")
        return fd
    except BaseException:
        os.close(fd)
        raise


def canonical_file_path(path):
    # Literal '~' is an ordinary filename byte in authenticated Ubuntu DEBs.
    # Permit it only in the final basename. Directory/request grammar is
    # unchanged; read() uses O_NOFOLLOW dirfds, never shell/home expansion.
    return (type(path) is str and len(path) <= 1001 and str(Path(path)) == path
            and ".." not in Path(path).parts
            and SAFE_PATH.fullmatch(str(Path(path).parent)) is not None
            and re.fullmatch(r"[A-Za-z0-9_.%+:~-]{1,255}", Path(path).name) is not None)


def read(path, maximum=LIMIT, private=False, links=1):
    need(canonical_file_path(path), "canonical-root-file-path")
    parent = directory(str(Path(path).parent), private=private)
    fd = None
    try:
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == links
             and not before.st_mode & 0o022 and before.st_size <= maximum,
             "root-regular-file")
        if private:
            need(stat.S_IMODE(before.st_mode) == 0o600, "private-file-mode")
        chunks = []
        count = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, maximum + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            need(count <= maximum, "file-byte-limit")
            chunks.append(chunk)
        need(stamp(before) == stamp(os.fstat(fd))
             == stamp(os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)), "file-drift")
        return b"".join(chunks), stamp(before)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate-json-field")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda unused: need(False, "nonfinite-json"))
    except (ValueError, UnicodeError, RecursionError):
        raise Denied("invalid-json") from None


def write_new(path, value):
    parent = directory(str(Path(path).parent), private=True)
    fd = None
    try:
        fd = os.open(Path(path).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        os.fsync(parent)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def replace_receipt(path, value):
    parent = directory(str(Path(path).parent), private=True)
    fd, temporary = tempfile.mkstemp(prefix=".receipt-", dir=str(Path(path).parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(value, sort_keys=True) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.fsync(parent)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)
        os.close(parent)


def tree_hash(path):
    """Bound root metadata/configuration contents; no following symlinks."""
    entries = []
    total = 0
    def visit(current, relative):
        nonlocal total
        fd = directory(current)
        try:
            before = stamp(os.fstat(fd))
            names = sorted(os.listdir(fd))
            need(len(entries) + len(names) <= 4096, "tree-entry-limit")
            for name in names:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                label = relative + name
                if path == LISTS and not relative and name in ("partial", "auxfiles"):
                    empty_auxiliary(fd, name)
                    entries.append([label + "/", info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)])
                    continue
                need(info.st_uid == 0 and not info.st_mode & 0o022, "tree-ownership")
                if stat.S_ISDIR(info.st_mode):
                    entries.append([label + "/", stat.S_IMODE(info.st_mode)])
                    visit(current + "/" + name, label + "/")
                else:
                    need(stat.S_ISREG(info.st_mode), "tree-file-type")
                    # The native lock inode/content is not package metadata.
                    if label == "lock":
                        continue
                    total += info.st_size
                    need(total <= 512 * 1024 * 1024, "tree-byte-limit")
                    raw, _ = read(current + "/" + name, 128 * 1024 * 1024)
                    entries.append([label, stat.S_IMODE(info.st_mode), digest(raw)])
            need(before == stamp(os.fstat(fd)), "tree-directory-drift")
        finally:
            os.close(fd)
    visit(path, "")
    return digest(json.dumps(entries, separators=(",", ":")).encode())


def empty_auxiliary(parent, name):
    """APT administrative empty directory, not an input/archive authority.

    APT can chown partial/auxfiles to its existing _apt service account. No
    payload is ever accepted there; the enclosing parent remains Root sealed.
    """
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(fd)
        allowed = before.st_uid == 0
        if not allowed:
            allowed = before.st_uid == pwd.getpwnam("_apt").pw_uid > 0
        need(allowed and not before.st_mode & 0o022 and not os.listdir(fd), "apt-auxiliary-not-empty-or-owned")
        need(stamp(before) == stamp(os.fstat(fd))
             == stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)), "apt-auxiliary-drift")
    finally:
        os.close(fd)


def discard_until_terminal(process):
    """Same owner, bounded discard, no child replacement/kill or early return.

    This independent polling path also handles failure of the capture selector.
    Transient pipe/selector failures are retried as reads, never as operations.
    An unreadable live child remains held rather than being abandoned.
    """
    pending = {pipe.fileno(): pipe for pipe in (process.stdout, process.stderr) if not pipe.closed}
    nonblocking = set()
    while pending:
        for fd in set(pending) - nonblocking:
            try:
                os.set_blocking(fd, False)
                nonblocking.add(fd)
            except Exception:
                if process.poll() is not None:
                    process.wait()
                    return
                time.sleep(0.01)
        ready_candidates = list(set(pending) & nonblocking)
        if not ready_candidates:
            continue
        try:
            ready, unused, exceptional = select.select(ready_candidates, [], ready_candidates, 0.5)
            ready = set(ready) | set(exceptional)
        except Exception:
            ready = ready_candidates
            time.sleep(0.01)
        for fd in ready:
            try:
                chunk = os.read(fd, 65536)
                if not chunk:
                    pending.pop(fd, None)
            except (BlockingIOError, InterruptedError):
                continue
            except Exception:
                if process.poll() is not None:
                    process.wait()
                    return
                time.sleep(0.01)
    while True:
        try:
            process.wait()
            return
        except InterruptedError:
            continue


def write_all(fd, raw):
    remaining = memoryview(raw)
    while remaining:
        count = os.write(fd, remaining)
        need(count > 0, "capture-short-write")
        remaining = remaining[count:]


def configuration_env(configuration=None):
    environment = dict(ENV)
    if configuration is not None:
        need(type(configuration) is tuple and len(configuration) == 3, "private-config-binding")
        path, expected, identity = configuration
        raw, actual = read(path, private=True)
        need(digest(raw) == expected and actual == tuple(identity), "private-config-drift")
        environment["APT_CONFIG"] = path
    return environment


def run(argv, tool_sha256, install=False, output_prefix=None, configuration=None):
    """Pinned fixed native binary; no shell/retry. Install is never killed here.

    A lost controller leaves the durable intent unresolved. Output is drained
    with bounded retention; an overflow is not permission to kill active dpkg.
    """
    need(argv[0] in (APT, DEB, APT_CONFIG) and SHA.fullmatch(tool_sha256), "fixed-tool")
    environment = configuration_env(configuration)
    raw, expected = read(argv[0], 32 * 1024 * 1024)
    need(digest(raw) == tool_sha256 and expected[4] & 0o111, "tool-digest")
    parent = directory(str(Path(argv[0]).parent))
    fd = os.open(Path(argv[0]).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    os.close(parent)
    process = None
    selector = None
    streams = {}
    try:
        need(stamp(os.fstat(fd)) == expected, "tool-inode-drift")
        if output_prefix:
            for label in ("stdout", "stderr"):
                streams[label] = os.open(output_prefix + "." + label,
                                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        process = subprocess.Popen(argv, executable="/proc/self/fd/" + str(fd), pass_fds=(fd,),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=environment, start_new_session=True)
        selector = selectors.DefaultSelector()
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        overflow = False
        for label, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
            selector.register(pipe, selectors.EVENT_READ, label)
        deadline = time.monotonic() + 120
        try:
            while selector.get_map():
                if not install and time.monotonic() >= deadline:
                    process.terminate()
                    raise Denied("readonly-command-timeout")
                for event, unused in selector.select(0.5):
                    chunk = os.read(event.fileobj.fileno(), 65536)
                    label = event.data
                    if not chunk:
                        selector.unregister(event.fileobj)
                        continue
                    retained = chunk[:max(0, LIMIT - len(buffers[label]))]
                    buffers[label].extend(retained)
                    if label in streams:
                        write_all(streams[label], retained)
                    overflow = overflow or len(retained) != len(chunk)
            code = process.wait(timeout=None if install else 5)
        finally:
            try:
                selector.close()
            finally:
                selector = None
        need(not overflow, "command-output-limit")
        need(code == 0, "native-command-rejected")
        return bytes(buffers["stdout"]), bytes(buffers["stderr"])
    finally:
        # This MUST precede any pipe close, log fsync or other fallible cleanup.
        # A capture failure is UNKNOWN, not permission to abandon active APT.
        try:
            if process is not None:
                if install:
                    while True:
                        try:
                            discard_until_terminal(process)
                            break
                        except BaseException:
                            # Retain this original owner even if fallback
                            # capture itself fails or wait is interrupted.
                            # Only an observed terminal child permits closing
                            # its pipes. No effect is restarted here.
                            if process.poll() is not None:
                                process.wait()
                                break
                            time.sleep(0.01)
                elif process.poll() is None:
                    process.kill()
                    process.wait()
        finally:
            try:
                if selector is not None:
                    selector.close()
            finally:
                if process is not None:
                    for pipe in (process.stdout, process.stderr):
                        pipe.close()
                try:
                    for output in streams.values():
                        try:
                            os.fsync(output)
                        finally:
                            os.close(output)
                finally:
                    os.close(fd)


def load_request(path, expected):
    need(os.geteuid() == 0 and SHA.fullmatch(expected), "root-and-request-digest")
    # Keep the existing request/hook reference grammar; only ordinary data
    # file basenames (e.g. passt) gain tilde support in read().
    need(type(path) is str and SAFE_PATH.fullmatch(path) and str(Path(path)) == path
         and ".." not in Path(path).parts, "canonical-root-file-path")
    raw, request_stamp = read(path, private=True)
    need(digest(raw) == expected, "request-digest")
    value = strict_json(raw)
    fields = {"schema", "hostname", "machine_id", "expires_at", "candidate_path", "payload_directory",
              "archive_directory", "reviewed_simulation_path", "reviewed_simulation_sha256",
              "dpkg_status_sha256", "apt_lists_sha256", "apt_config_sha256", "extended_states_sha256",
              "apt_get_sha256", "dpkg_deb_sha256", "apt_config_tool_sha256", "apt_version"}
    need(type(value) is dict and set(value) == fields and type(value["schema"]) is int
         and value["schema"] == 2, "request-schema")
    for key in fields:
        if key.endswith("_sha256"):
            need(type(value[key]) is str and SHA.fullmatch(value[key]), "request-hash-field")
    need(type(value["expires_at"]) is int and time.time() < value["expires_at"] <= time.time() + 3600,
         "request-expiry")
    need(value["hostname"] == socket.gethostname()
         and re.fullmatch(r"[0-9a-f]{32}", value["machine_id"])
         and read(MACHINE)[0].decode().strip() == value["machine_id"], "native-target")
    need(value["apt_version"] == NATIVE_APT_VERSION and value["apt_get_sha256"] == NATIVE_APT_SHA256,
         "apt-source-contract-binding")
    need(value["payload_directory"] != value["archive_directory"], "separate-payload-cache")
    # Paths must be distinct, Root sealed and never supplied as shell snippets.
    for key in ("candidate_path", "reviewed_simulation_path"):
        read(value[key], private=True)
    for key in ("payload_directory", "archive_directory"):
        opened = directory(value[key], private=True)
        os.close(opened)
    return value, request_stamp


def cache_filename(name, version, architecture):
    """APT 2.8.4 pkgAcqArchive names, including the encoded epoch.

    The closed candidate grammar excludes other QuoteString control bytes.
    Direct local inputs still need these cache copies for --no-download.
    """
    version = version.replace("_", "%5f").replace(":", "%3a")
    return name + "_" + version + "_" + architecture + ".deb"


def packages(request):
    raw, _ = read(request["candidate_path"], private=True)
    need(digest(raw) == CANDIDATE_SHA256, "candidate-source-binding")
    value = strict_json(raw)
    need(type(value) is dict and value.get("schema") == 1 and type(value.get("packages")) is list
         and len(value["packages"]) == 32, "candidate-inventory")
    result = {}
    for item in value["packages"]:
        need(type(item) is dict and {"package", "version", "architecture", "url", "size", "sha256"} <= set(item),
             "candidate-package")
        name = item["package"]
        need(type(name) is str and re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,99}", name)
             and name not in result and type(item["version"]) is str
             and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,150}", item["version"])
             and item["architecture"] in ("amd64", "all") and type(item["size"]) is int
             and 0 < item["size"] <= 128 * 1024 * 1024
             and type(item["sha256"]) is str and SHA.fullmatch(item["sha256"]), "candidate-package-fields")
        url = urlsplit(item["url"])
        need(url.scheme == "https" and url.hostname in ("pkgs.zabbly.com", "archive.ubuntu.com", "security.ubuntu.com")
             and not url.username and not url.password and not url.query and not url.fragment, "candidate-public-origin")
        filename = DIRECT_FILES[DIRECT.index(name)] if name in DIRECT else unquote(Path(url.path).name)
        need(re.fullmatch(r"[A-Za-z0-9_.+%:~-]+\.deb", filename), "archive-filename")
        entry = dict(item)
        entry["path"] = request["payload_directory"] + "/" + filename if name in DIRECT else (
            request["archive_directory"] + "/" + cache_filename(name, item["version"], item["architecture"]))
        entry["archive_path"] = request["archive_directory"] + "/" + cache_filename(
            name, item["version"], item["architecture"])
        result[name] = entry
    need(set(DIRECT) <= set(result), "six-direct-targets")
    return result


def control(request, name, item):
    output, _ = run([DEB, "--field", item["path"], "Package", "Version", "Architecture", "Multi-Arch"],
                    request["dpkg_deb_sha256"])
    fields = {}
    for line in output.decode("utf-8").splitlines():
        need(": " in line, "deb-control-format")
        key, value = line.split(": ", 1)
        need(key not in fields, "deb-control-duplicate")
        fields[key] = value
    need(set(fields) in ({"Package", "Version", "Architecture"},
                         {"Package", "Version", "Architecture", "Multi-Arch"})
         and fields["Package"] == name and fields["Version"] == item["version"]
         and fields["Architecture"] == item["architecture"]
         and fields.get("Multi-Arch", "none") in ("none", "same", "foreign", "allowed"),
         "deb-control-identity")
    return fields


def verify_payloads(request, inventory):
    expected_dirs = {request["payload_directory"]: set(), request["archive_directory"]: set()}
    identities = {}
    for name, item in inventory.items():
        bindings = {}
        for path in dict.fromkeys((item["path"], item["archive_path"])):
            raw, identity = read(path, 128 * 1024 * 1024, private=True)
            need(len(raw) == item["size"] and digest(raw) == item["sha256"], "payload-byte-binding")
            bindings[path] = identity
            expected_dirs[str(Path(path).parent)].add(Path(path).name)
        control(request, name, item)
        for path, identity in bindings.items():
            need(read(path, 128 * 1024 * 1024, private=True)[1] == identity, "payload-inode-drift")
        identities[name] = bindings
    for path, wanted in expected_dirs.items():
        fd = directory(path, private=True)
        try:
            actual = set(os.listdir(fd))
            if path == request["archive_directory"]:
                # APT's private cache administrative entries, never payloads.
                if "lock" in actual:
                    read(path + "/lock", 1024)
                    actual.remove("lock")
                if "partial" in actual:
                    empty_auxiliary(fd, "partial")
                    actual.remove("partial")
            need(actual == wanted, "payload-directory-inventory")
        finally:
            os.close(fd)
    return identities


def status_fields(inventory):
    raw, _ = read(STATUS, 64 * 1024 * 1024)
    result = {}
    for paragraph in raw.decode("utf-8").split("\n\n"):
        fields = {}
        for line in paragraph.splitlines():
            if line.startswith(("Package: ", "Version: ", "Status: ", "Architecture: ", "Multi-Arch: ",
                                "Triggers-Pending: ", "Triggers-Awaited: ")):
                key, value = line.split(": ", 1)
                need(key not in fields, "dpkg-duplicate-field")
                fields[key] = value
        name = fields.get("Package")
        if name in inventory:
            need(name not in result, "dpkg-duplicate-package")
            result[name] = fields
    return digest(raw), result


def state(inventory):
    status_sha, result = status_fields(inventory)
    installed = all(result.get(name, {}).get("Status") == "install ok installed"
                    and result[name].get("Version") == item["version"]
                    and result[name].get("Architecture") == item["architecture"]
                    for name, item in inventory.items())
    return status_sha, installed


def before(request, inventory):
    need(time.time() < request["expires_at"], "request-expired")
    need(state(inventory)[0] == request["dpkg_status_sha256"], "reviewed-dpkg-state-drift")
    need(tree_hash(LISTS) == request["apt_lists_sha256"]
         and tree_hash(CONFIG) == request["apt_config_sha256"]
         and digest(read(EXTENDED, 32 * 1024 * 1024)[0]) == request["extended_states_sha256"],
         "reviewed-apt-state-drift")
    updates = directory(UPDATES)
    try:
        need(not os.listdir(updates), "pending-dpkg-updates")
    finally:
        os.close(updates)
    # V3 does not serialize NoPkg ConfigurePending/TriggersPending sentinels.
    # Refuse existing pending package state; normal maintainer/trigger effects
    # of the reviewed install still require separate operating qualification.
    raw, _ = read(STATUS, 64 * 1024 * 1024)
    for paragraph in raw.decode("utf-8").split("\n\n"):
        for line in paragraph.splitlines():
            need(not line.startswith(("Triggers-Pending:", "Triggers-Awaited:")), "pending-dpkg-trigger-state")
            if line.startswith("Status: "):
                fields = line[8:].split()
                need(len(fields) == 3 and fields[1] == "ok"
                     and fields[2] in ("installed", "config-files", "not-installed"), "unclean-dpkg-state")


def root_debconfrc_absent():
    home = pwd.getpwuid(0).pw_dir
    fd = directory(home)
    try:
        try:
            os.stat(".debconfrc", dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise Denied("root-debconfrc-present")
    finally:
        os.close(fd)


def verify_debconf_profile():
    raw, _ = read(DEBCONF_PROFILE)
    need(digest(raw) == DEBCONF_PROFILE_SHA256, "fixed-debconf-profile-digest")
    profile = strict_json(raw)
    need(profile["schema"] == 1 and profile["candidate_sha256"] == CANDIDATE_SHA256
         and profile["hook_literal"] == DEBCONF_HOOK and profile["protocol"] == 1
         and len(profile["modules"]) == 101 and profile["config_present_count"] == 0
         and profile["templates_present_count"] == 0, "fixed-debconf-profile-shape")
    root_debconfrc_absent()
    unused, installed = status_fields(profile["packages"])
    for name, item in profile["packages"].items():
        need(installed.get(name, {}).get("Status") == "install ok installed"
             and installed[name].get("Version") == item["version"]
             and installed[name].get("Architecture") == item["architecture"], "debconf-package-version-drift")
    identities = {}
    for path, item in profile["public_files"].items():
        need(type(item["size"]) is int and 0 < item["size"] <= 32 * 1024 * 1024,
             "debconf-public-file-size-bound")
        # The authenticated Perl executable exceeds the general JSON/stream
        # limit. Bound this public-file read to its exact fixed-profile size,
        # never increase the generic private-input or capture limit.
        content, identity = read(path, maximum=item["size"], links=item["links"])
        need(len(content) == item["size"] and digest(content) == item["sha256"], "debconf-public-file-drift")
        if path != "/etc/debconf.conf":
            need(identity[4] & 0o111, "debconf-executable-mode")
        identities[path] = identity
    actual_files, actual_directories = set(), set()
    def visit(relative):
        path = profile["module_root"] + ("/" + relative if relative else "")
        fd = directory(path)
        try:
            initial = stamp(os.fstat(fd))
            for name in sorted(os.listdir(fd)):
                label = relative + "/" + name if relative else name
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    need(label in profile["module_directories"], "debconf-module-directory-inventory")
                    actual_directories.add(label)
                    visit(label)
                else:
                    need(label in profile["modules"], "debconf-module-file-inventory")
                    content, identity = read(profile["module_root"] + "/" + label)
                    item = profile["modules"][label]
                    need(len(content) == item["size"] and digest(content) == item["sha256"],
                         "debconf-module-drift")
                    actual_files.add(label)
                    identities[profile["module_root"] + "/" + label] = identity
            need(initial == stamp(os.fstat(fd)), "debconf-module-directory-drift")
        finally:
            os.close(fd)
    visit("")
    need(actual_files == set(profile["modules"]) and actual_directories == set(profile["module_directories"]),
         "debconf-module-inventory")
    root_debconfrc_absent()
    return digest(json.dumps(identities, sort_keys=True).encode())


def inherited_hooks(request):
    # Only the qualified native Ubuntu literal may follow our first guard.
    # Native files are never changed; only an invocation-private list is built.
    output, _ = run([APT_CONFIG, "dump"], request["apt_config_tool_sha256"])
    hooks = []
    for line in output.decode("utf-8").splitlines():
        if re.match(r"\s*DPkg::Pre-Invoke(?:::|\s)", line, re.IGNORECASE):
            need(re.fullmatch(r'\s*DPkg::Pre-Invoke "";\s*', line, re.IGNORECASE) is not None,
                 "unsupported-inherited-pre-hook")
        if re.match(r"\s*DPkg::Pre-Install-Pkgs(?:::|\s)", line, re.IGNORECASE):
            match = re.fullmatch(r'\s*DPkg::Pre-Install-Pkgs(::)? "([^"\\]*)";\s*', line, re.IGNORECASE)
            need(match is not None, "unsupported-inherited-pre-hook")
            if match[1]:
                hooks.append(match[2])
            else:
                need(match[2] == "", "unsupported-inherited-pre-hook")
        if re.match(r'\s*(?:Debug::NoLocking|Debug::pkgDPkgPM|APT::Get::(?:Simulate|Print-URIs|Download-Only)|'
                    r'pkgCacheFile::Generate|Dir::Root|DPkg::Chroot-Directory|'
                    r'DPkg::Tools::Options::' + re.escape(HELPER) + r'::)',
                    line, re.IGNORECASE):
            raise Denied("unsupported-native-apt-configuration")
        if re.match(r'\s*DPkg::Options(?:::|\s)', line, re.IGNORECASE):
            need(re.fullmatch(r'\s*DPkg::Options "";\s*', line, re.IGNORECASE) is not None,
                 "unsupported-dpkg-options")
        if re.match(r'\s*DPkg::Path\s', line, re.IGNORECASE):
            match = re.fullmatch(r'\s*DPkg::Path "([^"\\]*)";\s*', line, re.IGNORECASE)
            need(match is not None and match[1] in ("", ENV["PATH"]),
                 "unsupported-dpkg-path")
        # apt-config's own selected subtree can already be flattened in dump.
        # Check resulting common semantics below; reject future callee scopes.
        if re.match(r'\s*Binary::(?:apt-get|apt-extracttemplates|apt-config)(?:::|\s)', line, re.IGNORECASE):
            need(re.fullmatch(r'\s*Binary::(?:apt-get|apt-extracttemplates|apt-config) "";\s*',
                              line, re.IGNORECASE) is not None, "unsupported-binary-specific-configuration")
        if re.match(r'\s*DPkg::Tools::Options::' + re.escape(DEBCONF_PROGRAM) + r'::', line, re.IGNORECASE):
            match = re.fullmatch(r'\s*DPkg::Tools::Options::' + re.escape(DEBCONF_PROGRAM)
                                 + r'::(Version|InfoFD) "([0-9]+)";\s*', line, re.IGNORECASE)
            need(match is not None and match[2] == ("1" if match[1].lower() == "version" else "0"),
                 "unsupported-debconf-protocol")
    need(hooks in ([], [DEBCONF_HOOK]), "unsupported-inherited-pre-hook")
    effective_paths(request)
    profile = "guard-only"
    identity = None
    if hooks:
        identity = verify_debconf_profile()
        profile = "ubuntu-debconf-1.5.86ubuntu1"
    return output, profile, identity


DIRECTORY_KEYS = {"Dir", "Dir::State", "Dir::State::lists", "Dir::Etc", "Dir::Etc::parts",
                  "Dir::Etc::sourceparts", "Dir::Etc::preferencesparts", "Dir::Etc::trustedparts",
                  "Dir::Etc::netrcparts", "Dir::Bin::methods"}


def standard_paths():
    return {"Dir": "/", "Dir::State": "/var/lib/apt", "Dir::State::status": STATUS,
            "Dir::State::lists": LISTS, "Dir::State::extended_states": EXTENDED,
            "Dir::Etc": CONFIG, "Dir::Etc::main": CONFIG + "/apt.conf",
            "Dir::Etc::parts": CONFIG + "/apt.conf.d", "Dir::Etc::sourcelist": CONFIG + "/sources.list",
            "Dir::Etc::sourceparts": CONFIG + "/sources.list.d",
            "Dir::Etc::preferences": CONFIG + "/preferences",
            "Dir::Etc::preferencesparts": CONFIG + "/preferences.d",
            "Dir::Etc::trusted": CONFIG + "/trusted.gpg", "Dir::Etc::trustedparts": CONFIG + "/trusted.gpg.d",
            "Dir::Etc::netrc": CONFIG + "/auth.conf", "Dir::Etc::netrcparts": CONFIG + "/auth.conf.d",
            "Dir::Bin::dpkg": "/usr/bin/dpkg", "Dir::Bin::methods": "/usr/lib/apt/methods"}


def invocation_paths(request):
    result = standard_paths()
    if "_configuration" in request:
        parent = str(Path(request["_configuration"]["path"]).parent)
        result.update({"Dir::Etc::parts": parent + "/parts", "Dir::Etc::main": parent + "/main.conf"})
    return result


def configuration_tuple(request):
    if "_configuration" not in request:
        return None
    value = request["_configuration"]
    return value["path"], value["sha256"], tuple(value["stamp"])


def effective_paths(request):
    # apt-config shell emits assignments; parse them as data, NEVER eval.
    # /f and /d use APT's own effective filename/directory resolution.
    expected = {"ROOTDIR": "", "UPDATE": "false"}
    directories = set()
    query = [APT_CONFIG, "shell", "ROOTDIR", "RootDir", "UPDATE", "APT::Update/b"]
    for index, (key, value) in enumerate(invocation_paths(request).items()):
        label = "K" + str(index)
        expected[label] = value
        if key in DIRECTORY_KEYS:
            directories.add(label)
        query += [label, key + ("/d" if key in DIRECTORY_KEYS else "/f")]
    output, _ = run(query, request["apt_config_tool_sha256"], configuration=configuration_tuple(request))
    need(len(output) <= 64 * 1024, "effective-path-output-limit")
    parsed = {}
    try:
        words = shlex.split(output.decode("utf-8"), posix=True)
    except (ValueError, UnicodeError):
        raise Denied("effective-path-format") from None
    for word in words:
        need("=" in word, "effective-path-format")
        key, value = word.split("=", 1)
        need(key in expected and key not in parsed, "effective-path-format")
        parsed[key] = value
    # An unset RootDir is omitted by shell; every effective path is mandatory.
    need(parsed.get("ROOTDIR", "") == "", "unsupported-rootdir")
    need(parsed.get("UPDATE", "false") == "false", "unsupported-update-root")
    for key, value in expected.items():
        if key not in ("ROOTDIR", "UPDATE"):
            allowed = (value, value + "/") if key in directories and value != "/" else (value,)
            need(parsed.get(key) in allowed,
                 "unsupported-effective-apt-path")


def guard_command(request):
    return HELPER + " pre-install " + request["_path"] + " " + request["_sha256"]


def invocation_hooks(request):
    hooks = [guard_command(request)]
    if request["_configuration"]["profile"] == "ubuntu-debconf-1.5.86ubuntu1":
        hooks.append(DEBCONF_HOOK)
    return hooks


def common_values(request):
    result = {"Debug::NoLocking": "false", "pkgCacheFile::Generate": "true", "APT::Update": "false",
              "Dir::Cache::pkgcache": "", "Dir::Cache::srcpkgcache": "",
              "Dir::Cache::archives": request["archive_directory"], "RootDir": "", "DPkg::Path": ENV["PATH"]}
    result.update(invocation_paths(request))
    return result


def protocol_values(request):
    result = {"DPkg::Tools::Options::" + HELPER + "::Version": "3",
              "DPkg::Tools::Options::" + HELPER + "::InfoFD": "0"}
    if request["_configuration"]["profile"] == "ubuntu-debconf-1.5.86ubuntu1":
        result.update({"DPkg::Tools::Options::" + DEBCONF_PROGRAM + "::Version": "1",
                       "DPkg::Tools::Options::" + DEBCONF_PROGRAM + "::InfoFD": "0"})
    return result


def attach_configuration(request, value):
    need(type(value) is dict and set(value) == {"path", "sha256", "stamp", "directory", "parts", "main", "profile",
                                               "debconf_identity"}
         and value["profile"] in ("guard-only", "ubuntu-debconf-1.5.86ubuntu1"), "invocation-config-schema")
    need(value["debconf_identity"] is None if value["profile"] == "guard-only" else (
         type(value["debconf_identity"]) is str and SHA.fullmatch(value["debconf_identity"])),
         "invocation-debconf-identity")
    parent = str(Path(value["path"]).parent)
    expected_parent = str(Path(request["_path"]).parent)
    need(str(Path(parent).parent) == expected_parent
         and re.fullmatch(r"\.apt-invocation-[A-Za-z0-9_-]+", Path(parent).name)
         and value["path"] == parent + "/apt.conf", "invocation-config-locator")
    fd = directory(parent, private=True)
    try:
        need([os.fstat(fd).st_dev, os.fstat(fd).st_ino] == value["directory"]
             and set(os.listdir(fd)) == {"apt.conf", "parts", "main.conf"}, "invocation-directory-drift")
    finally:
        os.close(fd)
    fd = directory(parent + "/parts", private=True)
    try:
        need([os.fstat(fd).st_dev, os.fstat(fd).st_ino] == value["parts"] and not os.listdir(fd),
             "invocation-parts-drift")
    finally:
        os.close(fd)
    raw, identity = read(parent + "/main.conf", private=True)
    need(raw == b"" and list(identity) == value["main"], "invocation-main-drift")
    configuration_env((value["path"], value["sha256"], tuple(value["stamp"])))
    request["_configuration"] = value


def compile_configuration(request, native_dump, profile, debconf_identity):
    # Secrets in the native dump remain ONLY in this Root0600/0700 allocation.
    # Binary and commandline scalar values describe apt-config, not the future
    # apt-get/extractor. Their own ParseCommandLine sets the actual Binary.
    retained = []
    for line in native_dump.decode("utf-8").splitlines():
        if re.match(r'\s*(?:Binary|CommandLine::AsString)\s', line, re.IGNORECASE):
            continue
        retained.append(line)
    parent = tempfile.mkdtemp(prefix=".apt-invocation-", dir=str(Path(request["_path"]).parent))
    os.chmod(parent, 0o700)
    os.mkdir(parent + "/parts", 0o700)
    main = os.open(parent + "/main.conf", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.fsync(main)
    os.close(main)
    value = {"path": parent + "/apt.conf", "profile": profile, "debconf_identity": debconf_identity}
    request["_configuration"] = value
    retained += ["#clear DPkg::Pre-Install-Pkgs;"]
    for key, item in common_values(request).items():
        retained.append(key + " " + json.dumps(item) + ";")
    # Simulate=false MUST NOT be in this common file: --simulate remains real.
    for hook in invocation_hooks(request):
        retained.append("DPkg::Pre-Install-Pkgs:: " + json.dumps(hook) + ";")
    retained += [key + " " + json.dumps(value) + ";" for key, value in protocol_values(request).items()]
    raw = ("\n".join(retained) + "\n").encode()
    need(len(raw) <= LIMIT, "compiled-config-byte-limit")
    output = os.open(value["path"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(output, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    raw, identity = read(value["path"], private=True)
    value.update(sha256=digest(raw), stamp=list(identity))
    for name, field in ((parent, "directory"), (parent + "/parts", "parts")):
        fd = directory(name, private=True)
        try:
            os.fsync(fd)
            value[field] = [os.fstat(fd).st_dev, os.fstat(fd).st_ino]
        finally:
            os.close(fd)
    value["main"] = list(read(parent + "/main.conf", private=True)[1])
    attach_configuration(request, value)
    verify_compiled_child(request)


def verify_compiled_child(request):
    attach_configuration(request, request["_configuration"])
    effective_paths(request)
    output, _ = run([APT_CONFIG, "dump"], request["apt_config_tool_sha256"],
                    configuration=configuration_tuple(request))
    hooks = []
    expected = {key.lower(): value for key, value in common_values(request).items()}
    expected.update({key.lower(): value for key, value in protocol_values(request).items()})
    observed = {}
    for line in output.decode("utf-8").splitlines():
        match = re.fullmatch(r'\s*([^ ]+) "([^"\\]*)";\s*', line)
        if not match:
            continue
        key, value = match[1].lower(), match[2]
        if key in expected:
            need(key not in observed and value == expected[key], "child-common-profile-drift")
            observed[key] = value
        if key == "dpkg::pre-install-pkgs::":
            hooks.append(value)
        if key in ("apt::get::simulate", "apt::get::download-only", "apt::get::print-uris"):
            need(value in ("", "false"), "child-shortcut-drift")
        if key == "dpkg::options" or key.startswith("dpkg::options::"):
            need(value == "", "child-dpkg-options")
        if re.match(r"binary::(?:apt-get|apt-extracttemplates)(?:::|$)", key):
            need(value == "", "child-binary-profile-drift")
    need(observed == expected and hooks == invocation_hooks(request), "child-common-profile-drift")


def version_compare(left, right):
    """Debian epoch/upstream/revision ordering, without an unpinned executor."""
    def parts(value):
        need(type(value) is str and 0 < len(value) <= 150
             and re.fullmatch(r"(?:[0-9]{1,18}:)?[0-9][A-Za-z0-9.+:~_-]*", value),
             "plan-version-format")
        epoch, remainder = value.split(":", 1) if ":" in value else ("0", value)
        need(epoch.isdigit() and len(epoch) <= 18, "plan-version-format")
        upstream, revision = remainder.rsplit("-", 1) if "-" in remainder else (remainder, "0")
        need(upstream and revision, "plan-version-format")
        return int(epoch), upstream, revision

    def compare(a, b):
        def order(char):
            if char == "~":
                return -1
            if not char or char.isdigit():
                return 0
            return ord(char) if char.isalpha() else ord(char) + 256
        while a or b:
            while (a and not a[0].isdigit()) or (b and not b[0].isdigit()):
                first, second = order(a[:1]), order(b[:1])
                if first != second:
                    return -1 if first < second else 1
                a, b = a[1:], b[1:]
            a, b = a.lstrip("0"), b.lstrip("0")
            first, second = re.match(r"[0-9]*", a)[0], re.match(r"[0-9]*", b)[0]
            if len(first) != len(second):
                return -1 if len(first) < len(second) else 1
            if first != second:
                return -1 if first < second else 1
            a, b = a[len(first):], b[len(second):]
        return 0

    first, second = parts(left), parts(right)
    if first[0] != second[0]:
        return -1 if first[0] < second[0] else 1
    return compare(first[1], second[1]) or compare(first[2], second[2])


def planned_changes(inventory, current):
    """Exact closure members requiring work in the hash-bound dpkg snapshot."""
    result = {}
    for name, item in inventory.items():
        prior = current.get(name, {})
        if prior.get("Status") == "install ok installed":
            need(prior.get("Architecture") == item["architecture"], "plan-old-architecture-drift")
            comparison = version_compare(prior.get("Version"), item["version"])
            need(comparison <= 0, "plan-downgrade")
            if prior["Version"] == item["version"]:
                continue
            need(comparison < 0, "plan-version-alias")
            result[name] = prior["Version"]
        else:
            # No residual configured version is admitted as a fresh install.
            # Other clean dpkg states still need a separately reviewed plan.
            need(prior.get("Status") is None or (
                 re.fullmatch(r"(?:unknown|install|hold|deinstall|purge) ok not-installed",
                              prior.get("Status", "")) and not prior.get("Version")),
                 "plan-old-package-state")
            result[name] = None
    return result


def parse_plan(raw, inventory, current=None):
    need(len(raw) <= LIMIT, "plan-byte-limit")
    # Default consumers read actual native state; fixtures may supply an
    # independently constructed snapshot. Request fields cannot select it.
    if current is None:
        _unused, current = status_fields(inventory)
    expected = planned_changes(inventory, current)
    found = {"Inst": [], "Conf": []}
    for line in raw.decode("utf-8").splitlines():
        need(not line.startswith(("Remv ", "Purg ", "E:", "Err:")), "plan-rejected-operation")
        if line.startswith(("Inst ", "Conf ")):
            match = re.fullmatch(r"(Inst|Conf) ([a-z0-9][a-z0-9+.-]*)(?: \[([^\]]+)\])? "
                                 r"\(([^ ]+) [^\r\n]*\[(amd64|all)\]\)(?: \[\])?", line)
            need(match is not None, "plan-operation-format")
            phase, name, old, version, architecture = match.groups()
            need(name in inventory and version == inventory[name]["version"]
                 and architecture == inventory[name]["architecture"], "plan-package-drift")
            need(name in expected and old == (expected[name] if phase == "Inst" else None),
                 "plan-old-version-or-unchanged-package")
            found[phase].append([name, old, version, architecture])
    for entries in found.values():
        need(len(entries) == len(expected)
             and {entry[0] for entry in entries} == set(expected), "plan-not-exact-changes")
    return found


def argv(request, inventory, simulate):
    prefix = [APT, "--simulate"] if simulate else [APT, "--assume-yes", "--no-download", "--no-remove"]
    options = []
    for key, value in common_values(request).items():
        options += ["-o", key + "=" + value]
    if not simulate:
        # The common file owns the ordered first guard/qualified second hook.
        # The extractor inherits it; only actual apt-get gets Simulate=false.
        options += ["-o", "APT::Get::Download-Only=false", "-o", "APT::Get::Print-URIs=false",
                    "-o", "APT::Get::Simulate=false"]
    return prefix + options + ["install"] + [inventory[name]["path"] for name in DIRECT]


def canonical_apt_hook_value(command):
    """APT QuoteString(value, newline), only for our expected known hooks.

    The primary APT2.8 producer percent-encodes spaces and percent. Compare
    canonical expected wire values; never decode/log arbitrary config input.
    """
    need(type(command) is str and 0 < len(command) <= 8192
         and all(0x20 <= ord(char) < 0x7f for char in command), "expected-hook-command-grammar")
    return "".join("%%%02x" % byte if byte <= 0x20 or byte == 0x25 or byte >= 0x7f else chr(byte)
                   for byte in command.encode("ascii"))


def parse_hook(raw, request, inventory):
    need(len(raw) <= LIMIT, "hook-input-limit")
    lines = raw.decode("utf-8").splitlines()
    need(lines and lines[0] == "VERSION 3", "hook-protocol-version")
    try:
        boundary = lines.index("", 1)
    except ValueError:
        raise Denied("hook-config-boundary") from None
    need(boundary <= 4096, "hook-config-limit")
    fixed = {"Debug::NoLocking": "false", "pkgCacheFile::Generate": "true", "APT::Update": "false",
             "APT::Get::Download-Only": "false",
             "APT::Get::Print-URIs": "false", "APT::Get::Simulate": "false",
             "DPkg::Tools::Options::" + HELPER + "::Version": "3",
             "DPkg::Tools::Options::" + HELPER + "::InfoFD": "0"}
    fixed = {key.lower(): value for key, value in fixed.items()}
    fixed.update({key.lower(): value for key, value in protocol_values(request).items()})
    fixed.update({key.lower(): value for key, value in invocation_paths(request).items()})
    fixed.update({"dir::cache::archives": request["archive_directory"], "dpkg::path": ENV["PATH"]})
    observed = {}
    hooks = []
    for line in lines[1:boundary]:
        # Config values can be sensitive: validate framing only, never emit or
        # retain the header. Runtime config content is separately hash-bound.
        need(re.fullmatch(r'[^=\x00-\x20]{1,2048}=[^\x00-\x1f]{0,8192}', line) is not None,
             "hook-config-format")
        key, value = line.split("=", 1)
        key = key.lower()
        if key == "dpkg::pre-install-pkgs::":
            hooks.append(value)
        if key in ("rootdir", "dir::cache::pkgcache", "dir::cache::srcpkgcache"):
            need(value == "", "hook-rootdir-or-cache-redirect")
        if key == "dpkg::options" or key.startswith("dpkg::options::"):
            need(value == "", "hook-unreviewed-dpkg-options")
        if key in fixed:
            need(key not in observed and value == fixed[key], "hook-fixed-configuration")
            observed[key] = value
    need(observed == fixed, "hook-fixed-configuration")
    need(hooks == [canonical_apt_hook_value(command) for command in invocation_hooks(request)],
         "hook-order-or-duplicate")
    reviewed, _ = read(request["reviewed_simulation_path"], private=True)
    need(digest(reviewed) == request["reviewed_simulation_sha256"], "reviewed-plan-digest")
    _unused, current = status_fields(inventory)
    plan = parse_plan(reviewed, inventory, current)
    old = {row[0]: row[1] for row in plan["Inst"]}
    controls = {name: control(request, name, item) for name, item in inventory.items()}
    actions = {"Inst": [], "Conf": []}
    for line in lines[boundary + 1:]:
        fields = line.split(" ")
        need(len(fields) == 9 and all(fields), "hook-action-format")
        name, previous, old_arch, old_multi, comparison, version, architecture, multi, action = fields
        need(name in old and comparison == "<" and previous == (old[name] or "-")
             and version == inventory[name]["version"] and architecture == inventory[name]["architecture"]
             and multi == controls[name].get("Multi-Arch", "none"), "hook-version-architecture-drift")
        prior = current.get(name, {})
        if old[name] is None:
            need((old_arch, old_multi) == ("-", "none") and not prior.get("Version"), "hook-old-package-drift")
        else:
            need(prior.get("Version") == previous and prior.get("Architecture") == old_arch
                 and prior.get("Multi-Arch", "none") == old_multi, "hook-old-package-drift")
        if action == "**CONFIGURE**":
            phase = "Conf"
        else:
            need(action == inventory[name]["archive_path"], "hook-remove-error-or-foreign-archive")
            phase = "Inst"
        actions[phase].append([name, old[name] if phase == "Inst" else None, version, architecture])
    need(actions == plan, "hook-final-full-plan-drift")


def pre_install(path, expected, stream):
    request, request_stamp = load_request(path, expected)
    request.update(_path=path, _sha256=expected)
    inventory = packages(request)
    journal_path = path + ".intent.json"
    journal = strict_json(read(journal_path, private=True)[0])
    need(type(journal) is dict and set(journal) == {"schema", "state", "request_sha256", "archives_sha256",
                                                  "request_stamp", "configuration"}
         and journal["schema"] == 1 and journal["state"] == "INSTALL_INTENT"
         and journal["request_sha256"] == expected and journal["request_stamp"] == list(request_stamp),
         "hook-intent-binding")
    attach_configuration(request, journal["configuration"])
    need(os.environ.get("APT_CONFIG") == journal["configuration"]["path"], "hook-private-config-environment")
    verify_compiled_child(request)
    if journal["configuration"]["profile"] != "guard-only":
        need(verify_debconf_profile() == journal["configuration"]["debconf_identity"], "debconf-identity-drift")
    before(request, inventory)
    identities = verify_payloads(request, inventory)
    archive_sha = digest(json.dumps(identities, sort_keys=True).encode())
    need(journal["archives_sha256"] == archive_sha, "hook-original-archive-inode-drift")
    raw = stream.read(LIMIT + 1)
    parse_hook(raw, request, inventory)
    before(request, inventory)
    write_new(path + ".hook.json", {"schema": 1, "request_sha256": expected,
                                   "archives_sha256": archive_sha})


def execute(path, expected):
    request, original_stamp = load_request(path, expected)
    request.update(_path=path, _sha256=expected)
    inventory = packages(request)
    lock_path = path + ".lock"
    parent = directory(str(Path(path).parent), private=True)
    fd = os.open(Path(lock_path).name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent)
    os.close(parent)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600, "private-once-lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        journal_path = path + ".intent.json"
        previous = None
        if os.path.lexists(journal_path):
            previous = strict_json(read(journal_path, private=True)[0])
            need(type(previous) is dict and set(previous) == {"schema", "state", "request_sha256",
                                                             "after_status_sha256", "archives_sha256", "request_stamp",
                                                             "configuration"}
                 and previous.get("schema") == 1 and previous.get("request_sha256") == expected
                 and previous.get("request_stamp") == list(original_stamp)
                 and previous.get("state") == "PACKAGE_STATE_VERIFIED", "prior-install-requires-reconciliation")
            attach_configuration(request, previous["configuration"])
        installed = state(inventory)[1]
        if previous is not None:
            need(installed and previous.get("after_status_sha256") == state(inventory)[0],
                 "completed-install-state-drift")
            return {"changed": False, "state": "PACKAGE_STATE_VERIFIED", "operating_acceptance": False}
        if installed:
            return {"changed": False, "state": "ALREADY_CONFIGURED_READONLY", "operating_acceptance": False}
        before(request, inventory)
        native_dump, profile, debconf_identity = inherited_hooks(request)
        version, _ = run([APT, "--version"], request["apt_get_sha256"])
        need(version.decode().splitlines()[0] == request["apt_version"], "apt-source-version-drift")
        identities = verify_payloads(request, inventory)
        reviewed, _ = read(request["reviewed_simulation_path"], private=True)
        need(digest(reviewed) == request["reviewed_simulation_sha256"], "reviewed-plan-digest")
        plan = parse_plan(reviewed, inventory)
        compile_configuration(request, native_dump, profile, debconf_identity)
        fresh, _ = run(argv(request, inventory, True), request["apt_get_sha256"],
                       configuration=configuration_tuple(request))
        need(parse_plan(fresh, inventory) == plan, "fresh-full-plan-drift")
        before(request, inventory)
        need(verify_payloads(request, inventory) == identities, "payload-snapshot-drift")
        need(inherited_hooks(request) == (native_dump, profile, debconf_identity), "native-profile-drift")
        verify_compiled_child(request)
        need(read(path, private=True)[1] == original_stamp, "request-inode-drift")
        archive_sha = digest(json.dumps(identities, sort_keys=True).encode())
        write_new(journal_path, {"schema": 1, "state": "INSTALL_INTENT", "request_sha256": expected,
                                 "archives_sha256": archive_sha, "request_stamp": list(original_stamp),
                                 "configuration": request["_configuration"]})
        # Every failure after this durable intent holds. There is no retry,
        # rollback, implicit adoption or 'versions now match' recovery path.
        run(argv(request, inventory, False), request["apt_get_sha256"], install=True,
            output_prefix=path + ".install", configuration=configuration_tuple(request))
        hook = strict_json(read(path + ".hook.json", private=True)[0])
        need(hook.get("request_sha256") == expected and hook.get("schema") == 1
             and hook.get("archives_sha256") == archive_sha, "missing-final-hook-proof")
        after_sha, installed = state(inventory)
        need(installed, "post-install-package-state")
        replace_receipt(journal_path, {"schema": 1, "state": "PACKAGE_STATE_VERIFIED", "request_sha256": expected,
                                       "after_status_sha256": after_sha, "archives_sha256": archive_sha,
                                       "request_stamp": list(original_stamp), "configuration": request["_configuration"]})
        return {"changed": True, "state": "PACKAGE_STATE_VERIFIED", "operating_acceptance": False}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("install", "pre-install"))
    parser.add_argument("request_path")
    parser.add_argument("request_sha256")
    args = parser.parse_args()
    try:
        need(os.path.abspath(__file__) == HELPER, "fixed-installed-helper-path")
        if args.operation == "pre-install":
            pre_install(args.request_path, args.request_sha256, sys.stdin.buffer)
        else:
            print(json.dumps(execute(args.request_path, args.request_sha256), sort_keys=True))
        return 0
    except Denied as error:
        uncertain = os.path.lexists(args.request_path + ".intent.json")
        print(json.dumps({"changed": uncertain, "state": "HOLD", "category": str(error),
                          "package_transaction": "unresolved" if uncertain else "not_invoked"}))
        return 1
    except Exception:
        uncertain = os.path.lexists(args.request_path + ".intent.json")
        print(json.dumps({"changed": uncertain, "state": "HOLD", "category": "native-package-maintenance-unknown",
                          "package_transaction": "unresolved" if uncertain else "not_invoked"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
