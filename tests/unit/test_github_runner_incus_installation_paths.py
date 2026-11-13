"""Canonical-path equivalence to the previous published POSIX contract."""
from itertools import product
from pathlib import Path, PurePosixPath
import sys
import unittest

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import installation  # noqa: E402
from incus_lease_issuer.identity import Denied  # noqa: E402


def published(path, *, absolute):
    """Reference protocol from c204; no filesystem or native authority."""
    limit = 4096 if absolute else 1024
    valid = type(path) is str and 0 < len(path) <= limit
    valid = valid and (path.startswith("/") if absolute else not path.startswith("/"))
    valid = valid and not any(ord(c) < 32 or ord(c) == 127 for c in path)
    if not valid:
        raise Denied("reference")
    if absolute:
        valid = not path.startswith("//") and ".." not in PurePosixPath(path).parts
    else:
        parts = PurePosixPath(path).parts
        valid = bool(parts) and len(parts) <= 32 and path != "." and ".." not in parts
    if not valid or str(PurePosixPath(path)) != path:
        raise Denied("reference")
    try:
        path.encode("utf-8")
    except UnicodeError:
        raise Denied("reference") from None
    return PurePosixPath(path).parts[1:] if absolute else path


class CanonicalPathEquivalenceTests(unittest.TestCase):
    def same(self, path):
        for absolute in (False, True):
            function = installation._absolute if absolute else installation._relative
            try:
                expected = published(path, absolute=absolute)
            except Denied:
                with self.assertRaises(Denied, msg=repr((absolute, path))):
                    function(path)
            else:
                self.assertEqual(function(path), expected, repr((absolute, path)))

    def test_exhaustive_short_strings_preserve_posix_and_control_semantics(self):
        alphabet = ("/", ".", "a", "\\", ":", " ", "é", "\x00", "\x1f", "\x7f", "\ud800")
        for length in range(5):
            for parts in product(alphabet, repeat=length):
                value = "".join(parts)
                self.same(value)
                self.same("/" + value)

    def test_component_depth_length_unicode_and_exact_type_boundaries(self):
        class Text(str):
            pass
        values = [None, True, 1, b"/a", Text("/a"), "", "/", "//", "///", ".", "..",
            "a/.", "a/..", "/a/.", "/a/..", "/a//b", "a//b", "a/", "/a/",
            "a\\b", "/a\\b", "C:disk/file", "/C:disk/file", "space here/file",
            "/space here/file", "漢字/é", "/漢字/é", "a/\udfff", "/a/\udfff"]
        for size in (1023, 1024, 1025, 4095, 4096, 4097):
            values.extend(("a" * size, "/" + "a" * (size - 1), "é" * size))
        for depth in (31, 32, 33):
            values.extend(("/".join(["a"] * depth), "/" + "/".join(["a"] * depth)))
        for char in [chr(i) for i in range(32)] + ["\x7f"]:
            values.extend(("a" + char + "b", "/a" + char + "b"))
        for value in values:
            self.same(value)
