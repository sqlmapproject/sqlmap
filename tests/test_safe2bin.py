#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

safecharencode / safechardecode (lib/utils/safe2bin.py).

These make extracted DB values safe to print/store by escaping control and
non-printable characters (tab -> \\t, NUL -> \\x00, ...) and back. They are
applied to dumped data and to values written through the replication writer,
so the escape<->unescape round-trip must be exact.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.utils.safe2bin import safecharencode, safechardecode

RND = random.Random(99)


class TestKnownEscapes(unittest.TestCase):
    CASES = [
        (u"normal", u"normal"),
        (u"tab\there", u"tab\\there"),
        (u"new\nline", u"new\\nline"),
        (u"nul\x00byte", u"nul\\x00byte"),
    ]

    def test_encode(self):
        for raw, encoded in self.CASES:
            self.assertEqual(safecharencode(raw), encoded, msg="safecharencode(%r)" % raw)

    def test_plain_text_unchanged(self):
        for s in (u"plain", u"abc 123", u"semi;colon", u"a,b,c"):
            self.assertEqual(safecharencode(s), s, msg="plain text altered: %r" % s)


class TestRoundTrip(unittest.TestCase):
    def test_known_roundtrip(self):
        for raw, _ in TestKnownEscapes.CASES:
            self.assertEqual(safechardecode(safecharencode(raw)), raw, msg="round-trip %r" % raw)

    def test_property_roundtrip(self):
        # mix printable + control/non-printable code points
        pool = u"abc 123" + u"".join(chr(c) for c in (0, 1, 7, 9, 10, 13, 27, 127))
        for _ in range(2000):
            s = u"".join(RND.choice(pool) for _ in range(RND.randint(0, 24)))
            self.assertEqual(safechardecode(safecharencode(s)), s, msg="round-trip failed for %r" % s)


if __name__ == "__main__":
    unittest.main(verbosity=2)
