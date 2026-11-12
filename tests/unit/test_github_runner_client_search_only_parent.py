"""Real Linux UID995 search-only directory fixture; no OIDC/lease/admission.

The separate pinned-EE Root setup creates only disposable public files/socket.
Tests execute as995:983 in that same container, without SETUID capabilities.
Ordinary unit invocations explicitly skip this additional native-DAC context.
"""
import importlib.util
import json
import os
import shutil
import socket
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"


def prepare_fixture():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("isolated Linux Root fixture only")
    root = Path(tempfile.mkdtemp(prefix="client-search-", dir="/run"))
    root.chmod(0o755)
    for name, mode, owner in (("public", 0o755, 0), ("search", 0o710, 0),
                              ("unsafe", 0o770, 0), ("foreign", 0o755, 995)):
        path = root / name
        path.mkdir()
        os.chown(path, owner, 983)
        path.chmod(mode)
    for name in ("incus_job_client.py", "incus_runtime_client.py"):
        path = root / "public" / name
        shutil.copyfile(FILES / name, path)
        path.chmod(0o644)
    (root / "symlink").symlink_to(root / "search", target_is_directory=True)
    (root / "search" / "public.json").write_text('{"public":true}')
    (root / "search" / "public.json").chmod(0o444)
    for schema in (1, 2):
        path = root / ("config" + str(schema) + ".json")
        path.write_text(json.dumps({"schema": schema, "socket_path": str(root / "search/socket")}))
        path.chmod(0o444)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(root / "search/socket"))
        os.chown(root / "search/socket", 0, 983)
        (root / "search/socket").chmod(0o660)
        listener.listen(8)
        print(json.dumps({"container": socket.gethostname(), "fixture": str(root)}), flush=True)
        deadline = time.monotonic() + 180
        while not (root / "done").exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("bounded fixture expired")
            time.sleep(0.1)
    shutil.rmtree(root)


@unittest.skipUnless(os.environ.get("LIT_CLIENT_SEARCH_FIXTURE"), "separate pinned Linux UID995 DAC fixture")
class SearchOnlyParentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != "linux" or os.geteuid() != 995 or os.getegid() != 983:
            raise AssertionError("must exercise real Linux UID995/GID983, never Root")
        cls.root = Path(os.environ["LIT_CLIENT_SEARCH_FIXTURE"])
        cls.clients = []
        for name in ("incus_job_client", "incus_runtime_client"):
            path = cls.root / "public" / (name + ".py")
            spec = importlib.util.spec_from_file_location("search_fixture_" + name, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            cls.clients.append(module)

    def test_real_read_denial_and_search_only_parent_identity(self):
        path = self.root / "search"
        self.assertEqual((path.stat().st_uid, path.stat().st_gid, stat.S_IMODE(path.stat().st_mode)), (0, 983, 0o710))
        with self.assertRaises(PermissionError):
            os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        for client in self.clients:
            with self.subTest(client=client.__name__):
                fd, leaf = client._parent(str(path / "public.json"))
                try:
                    self.assertEqual(leaf, "public.json")
                    self.assertEqual((os.fstat(fd).st_dev, os.fstat(fd).st_ino), (path.stat().st_dev, path.stat().st_ino))
                    with self.assertRaises(OSError):
                        os.listdir(fd)
                finally:
                    os.close(fd)

    def test_both_clients_reject_writable_foreign_and_symlink_parents(self):
        for client in self.clients:
            for name in ("unsafe", "foreign", "symlink"):
                with self.subTest(client=client.__name__, parent=name), self.assertRaises((client.ClientDenied, OSError)):
                    client._parent(str(self.root / name / "public.json"))

    def test_runtime_public_file_and_configuration_walk_search_only_parent(self):
        runtime = self.clients[1]
        self.assertEqual(runtime._root_file(str(self.root / "search/public.json"), 2048)[0], b'{"public":true}')
        runtime.CONFIG = str(self.root / "config2.json")
        self.assertEqual(runtime._configuration()[0], str(self.root / "search/socket"))

    def test_real_runtime_check_reaches_root_peer_without_admission(self):
        runtime = self.clients[1]
        runtime.CONFIG = str(self.root / "config2.json")
        self.assertEqual(runtime.check(), {"schema": 2, "operation": "check", "state": "local-prerequisites-only",
            "capabilities": ["initial-auth-idle-v1"], "authentication_idle_seconds": 60, "frame_seconds": 5})
        self.assertEqual(stat.S_IMODE((self.root / "search").stat().st_mode), 0o710)


if __name__ == "__main__":
    if sys.argv[1:] == ["--prepare-fixture"]:
        prepare_fixture()
    else:
        unittest.main(verbosity=2)
