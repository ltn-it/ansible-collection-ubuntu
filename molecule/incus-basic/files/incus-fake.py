#!/usr/bin/python3
"""Small stateful Incus CLI double for the light Molecule scenario."""

import json
import os
import sys
from pathlib import Path


STATE_DIR = Path(os.environ["LIT_INCUS_FAKE_STATE"])
if not STATE_DIR.is_absolute():
    raise ValueError("The Incus fixture state path must be absolute")
STORAGE_FILE = STATE_DIR / "storage.json"
PROJECT_FILE = STATE_DIR / "projects.json"
PROFILE_FILE = STATE_DIR / "profiles.json"
NETWORK_FILE = STATE_DIR / "networks.json"
MUTATION_FILE = STATE_DIR / "mutations.log"
STORAGE_SEEDED_FILE = STATE_DIR / "storage-seeded"


def read_json(path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def mutate(message):
    with MUTATION_FILE.open("a", encoding="utf-8") as stream:
        stream.write(message + "\n")


def option_value(arguments, name, default=None):
    if name not in arguments:
        return default
    return arguments[arguments.index(name) + 1]


def initialize_state():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not STORAGE_FILE.exists():
        write_json(STORAGE_FILE, [])
    if not PROJECT_FILE.exists():
        write_json(PROJECT_FILE, [{"config": {}, "description": "Default project", "name": "default"}])
    if not PROFILE_FILE.exists():
        write_json(PROFILE_FILE, [])
    if not NETWORK_FILE.exists():
        write_json(NETWORK_FILE, [])
    MUTATION_FILE.touch(exist_ok=True)


def handle_storage(arguments):
    if arguments[:2] == ["storage", "list"]:
        print(json.dumps(read_json(STORAGE_FILE, [])))
        return True
    if arguments[:2] == ["storage", "create"]:
        name, driver = arguments[2:4]
        pools = read_json(STORAGE_FILE, [])
        pools.append({"driver": driver, "name": name})
        write_json(STORAGE_FILE, pools)
        STORAGE_SEEDED_FILE.touch()
        mutate(f"storage create {name} {driver}")
        return True
    return False


def handle_admin(arguments):
    if arguments[:2] != ["admin", "init"]:
        return False
    if "--preseed" in arguments:
        preseed = json.loads(sys.stdin.read())
        write_json(STATE_DIR / "preseed.json", preseed)
        pools = [{"name": item["name"]} for item in preseed.get("storage_pools", [])]
        write_json(STORAGE_FILE, pools)
        mutate("admin init --preseed")
        return True
    if "--minimal" in arguments:
        write_json(STORAGE_FILE, [{"name": "default"}])
        mutate("admin init --minimal")
        return True
    return False


def handle_project(arguments):
    if arguments[:2] == ["project", "list"]:
        print(json.dumps(read_json(PROJECT_FILE, [])))
        return True
    if arguments[:2] == ["project", "create"]:
        name = arguments[2]
        projects = read_json(PROJECT_FILE, [])
        projects.append({"config": {}, "description": "", "name": name})
        write_json(PROJECT_FILE, projects)
        mutate(f"project create {name}")
        return True
    if arguments[:2] == ["project", "set"]:
        name = arguments[2]
        key, value = arguments[3].split("=", 1)
        projects = read_json(PROJECT_FILE, [])
        project = next(item for item in projects if item["name"] == name)
        project["config"][key] = value
        write_json(PROJECT_FILE, projects)
        mutate(f"project set {name} {key}={value}")
        return True
    return False


def handle_network(arguments):
    networks = read_json(NETWORK_FILE, [])
    if arguments[:2] == ["network", "list"]:
        print(json.dumps(networks))
        return True
    if arguments[:2] == ["network", "create"]:
        name = arguments[2]
        config = dict(option.split("=", 1) for option in arguments[3:])
        networks.append({"config": config, "name": name})
        write_json(NETWORK_FILE, networks)
        mutate(f"network create {name}")
        return True
    if arguments[:2] == ["network", "set"]:
        name, key, value = arguments[2:5]
        network = next(item for item in networks if item["name"] == name)
        network["config"][key] = value
        write_json(NETWORK_FILE, networks)
        mutate(f"network set {name} {key}={value}")
        return True
    return False


def handle_profile(arguments):
    project = option_value(arguments, "--project", "default")
    profiles = read_json(PROFILE_FILE, [])
    if arguments[:2] == ["profile", "list"]:
        print(json.dumps([item for item in profiles if item["project"] == project]))
        return True
    if arguments[:2] == ["profile", "create"]:
        name = arguments[2]
        profiles.append({"config": {}, "description": "", "devices": {}, "name": name, "project": project})
        write_json(PROFILE_FILE, profiles)
        mutate(f"profile create {name} --project {project}")
        return True
    if arguments[:2] == ["profile", "edit"]:
        name = arguments[2]
        payload = json.loads(sys.stdin.read())
        profile = next(item for item in profiles if item["name"] == name and item["project"] == project)
        profile.update(payload)
        write_json(PROFILE_FILE, profiles)
        mutate(f"profile edit {name} --project {project}")
        return True
    return False


def main():
    initialize_state()
    arguments = sys.argv[1:]
    for handler in (handle_storage, handle_admin, handle_project, handle_network, handle_profile):
        if handler(arguments):
            return 0
    print(f"Unsupported fake Incus invocation: {' '.join(arguments)}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
