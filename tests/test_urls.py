#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

URL encode/decode round-trips, parameter parsing, same-host checks.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.common import urldecode, urlencode, paramToDict, checkSameHost
from lib.core.enums import PLACE

RND = random.Random(11)


class TestUrlCoding(unittest.TestCase):
    def test_known(self):
        self.assertEqual(urldecode("a%20b"), u"a b")
        self.assertEqual(urlencode("a b&c"), "a%20b&c")

    def test_encode_is_not_identity(self):
        # anchor so the round-trip property below can't pass with no-op functions:
        # special chars MUST be percent-encoded
        encoded = urlencode("a b&c=d", safe="")
        self.assertNotIn(" ", encoded)
        self.assertNotIn("&", encoded)
        self.assertEqual(encoded, "a%20b%26c%3Dd")

    def test_roundtrip_property(self):
        import string
        # NOTE: urldecode() by default preserves URL-structural chars (?, &, =, +, ;) so a full
        # round-trip needs convall=True; '+' still excluded (form-encoding maps it to space).
        alphabet = string.ascii_letters + string.digits + " &=?/#@:,'\""
        for _ in range(2000):
            s = "".join(RND.choice(alphabet) for _ in range(RND.randint(0, 25)))
            roundtripped = urldecode(urlencode(s, safe=""), convall=True)
            self.assertEqual(roundtripped, s, msg="roundtrip %r" % s)


class TestParamToDict(unittest.TestCase):
    def test_get(self):
        d = paramToDict(PLACE.GET, "a=1&b=2&c=3")
        self.assertEqual(d.get("a"), "1")
        self.assertEqual(d.get("b"), "2")
        self.assertEqual(d.get("c"), "3")

    def test_get_single(self):
        d = paramToDict(PLACE.GET, "id=42")
        self.assertEqual(d.get("id"), "42")


class TestSameHost(unittest.TestCase):
    def test_same(self):
        self.assertTrue(checkSameHost("http://h/a", "http://h/b"))
        self.assertTrue(checkSameHost("http://h:80/a", "http://h:80/b"))

    def test_www_prefix_is_same(self):
        # documented behavior: a leading www. is normalized away
        self.assertTrue(checkSameHost("http://example.com/a", "http://www.example.com/b"))

    def test_different_host_is_false(self):
        # discriminating: an always-True implementation must fail here
        self.assertFalse(checkSameHost("http://h/a", "http://other/b"))
        self.assertFalse(checkSameHost("http://example.com/a", "http://evil.com/b"))

    def test_one_none_is_false(self):
        self.assertFalse(checkSameHost("http://h/a", None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
