#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Core text<->bytes conversions (lib/core/convert.py): getBytes, getUnicode,
getText. (getOrds is covered in test_convert.py.)

These are called on essentially every request and response, on both Python 2
and 3, and are the main thing standing between sqlmap and a UnicodeDecodeError
mid-scan. Pinned with known vectors, non-string coercion, and an encoding
round-trip property over multiple charsets.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.convert import getBytes, getUnicode, getText

RND = random.Random(2024)


class TestTypes(unittest.TestCase):
    # value+type (not type alone): a stub returning b"" would pass an isinstance-only check, and
    # on py3 a getBytes that wrongly returned str would slip past a round-trip on the unicode path
    def test_getBytes_returns_bytes(self):
        out = getBytes(u"abc")
        self.assertIsInstance(out, bytes)
        self.assertEqual(out, b"abc")

    def test_getUnicode_returns_unicode(self):
        out = getUnicode(b"abc")
        self.assertIsInstance(out, type(u""))
        self.assertEqual(out, u"abc")

    def test_getText_returns_native_str(self):
        self.assertIsInstance(getText(b"abc"), str)
        self.assertEqual(getText(b"abc"), "abc")


class TestCoercion(unittest.TestCase):
    def test_getUnicode_of_number(self):
        self.assertEqual(getUnicode(123), u"123")


class TestRoundTrip(unittest.TestCase):
    def test_known_utf8(self):
        self.assertEqual(getUnicode(getBytes(u"caf\xe9", "utf-8"), "utf-8"), u"caf\xe9")

    def test_property_multi_charset(self):
        # printable BMP-ish range, round-trip through utf-8 and latin1-safe subset
        for encoding, hi in (("utf-8", 0x2000), ("latin-1", 0x100)):
            for _ in range(1000):
                s = u"".join(unichr(RND.randint(0, hi - 1)) if sys.version_info[0] < 3
                             else chr(RND.randint(0, hi - 1)) for _ in range(RND.randint(0, 16)))
                self.assertEqual(getUnicode(getBytes(s, encoding), encoding), s,
                                 msg="round-trip failed (%s): %r" % (encoding, s))


# py2 has unichr, py3 does not; normalize so the file imports cleanly on both
try:
    unichr
except NameError:
    unichr = chr


if __name__ == "__main__":
    unittest.main(verbosity=2)
