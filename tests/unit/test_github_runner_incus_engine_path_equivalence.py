"""Differential language/identity coverage against the frozen a4 path validator."""
import itertools
from pathlib import Path, PurePosixPath
import re
import sys
import unittest

FILES = Path(__file__).resolve().parents[2] / "roles/github_runner/files"
sys.path.insert(0, str(FILES))
from incus_lease_issuer import engine_policy as engine  # noqa: E402
from incus_lease_issuer.identity import Denied, require  # noqa: E402


def reference_relative(value):
    require(type(value) is str and 0 < len(value) <= 1024 and not value.startswith("/")
            and re.fullmatch(r"[A-Za-z0-9_./@-]+", value) and value != "."
            and str(PurePosixPath(value)) == value and ".." not in PurePosixPath(value).parts
            and len(PurePosixPath(value).parts) <= 32, "engine-relative-path")
    return value


class PathEquivalenceTests(unittest.TestCase):
    def compare(self, value):
        try:
            expected = reference_relative(value)
        except Denied as error:
            self.assertEqual(error.args, ("engine-relative-path",))
            with self.assertRaises(Denied) as actual:
                engine._relative(value)
            self.assertIs(type(actual.exception), type(error))
            self.assertEqual(actual.exception.args, error.args)
        else:
            self.assertIs(expected, value)
            self.assertIs(engine._relative(value), value)

    def test_types_and_return_identity(self):
        class StringSubclass(str):
            pass
        for value in (None, True, False, 0, 1, 1.5, b"a", [], {}, ("a",),
                      object(), StringSubclass("valid")):
            self.compare(value)
        value = "".join(["roles/", "podman-kube@.service.j2"])
        self.assertIs(engine._relative(value), value)

    def test_all_ascii_and_unicode_controls(self):
        for number in range(128):
            char = chr(number)
            for value in (char, "a" + char, "a/" + char + "/b"):
                self.compare(value)
        for char in ("é", "ß", "中", "😀", "\u0080", "\u0085", "\u00a0", "\u2028",
                     "\u202e", "\uff0f", "\uff0e", "\ud800", "\udfff", "\U0010ffff"):
            for value in (char, "a" + char, "a/" + char + "/b"):
                self.compare(value)

    def test_exhaustive_short_strings(self):
        alphabet = "a./@_-0\n"
        for length in range(6):
            for chars in itertools.product(alphabet, repeat=length):
                self.compare("".join(chars))

    def test_length_depth_and_long_valid_components(self):
        for length in (0, 1, 2, 1023, 1024, 1025):
            self.compare("a" * length)
        for depth in (1, 2, 31, 32, 33):
            for name in ("a", "@", ".git", "a..b", "x" * 30):
                self.compare("/".join([name] * depth))
        value = "/".join(["a" * 31] * 31 + ["b" * 32])
        self.assertEqual(len(value), 1024)
        self.assertIs(engine._relative(value), value)
        self.compare(value)
        self.compare(value + "b")

    def test_dot_slash_and_existing_template_boundaries(self):
        for value in (".", "..", "...", ".hidden", "a..", "a.b", "a/./b", "a/../b",
                      "/a", "//a", "a/", "a//b", "a///b", "./a", "../a", "a/.", "a/..",
                      "a\\b", "a:b", "a;id", "a$(id)", "roles/dhcp/templates/podman-kube@.service.j2"):
            self.compare(value)


if __name__ == "__main__":
    unittest.main()
