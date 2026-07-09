#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

String / path / escape helpers.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.common import (normalizePath, posixToNtSlashes, ntToPosixSlashes,
                             isHexEncodedString, decodeStringEscape, encodeStringEscape,
                             listToStrValue, filterControlChars, safeVariableNaming,
                             unsafeVariableNaming, longestCommonPrefix, decodeIntToUnicode)

RND = random.Random(7)


class TestPaths(unittest.TestCase):
    def test_normalizePath(self):
        self.assertEqual(normalizePath("a//b/c"), "a/b/c")

    def test_slashes(self):
        self.assertEqual(posixToNtSlashes("/a/b"), "\\a\\b")
        self.assertEqual(ntToPosixSlashes("a\\b"), "a/b")

    def test_slash_roundtrip(self):
        for _ in range(500):
            s = "/".join(["seg%d" % RND.randint(0, 9) for _ in range(RND.randint(2, 6))])
            nt = posixToNtSlashes(s)
            # non-identity anchor: the NT form must actually differ (no '/', has '\') -
            # otherwise a no-op pair would pass this round-trip
            self.assertNotIn("/", nt, msg="posixToNtSlashes left a '/': %r" % nt)
            self.assertIn("\\", nt)
            self.assertEqual(ntToPosixSlashes(nt), s)


class TestHexDetection(unittest.TestCase):
    CASES = [("0x4142", True), ("4142", True), ("zz", False), ("0xZZ", False), ("", False)]

    def test_isHexEncodedString(self):
        for v, exp in self.CASES:
            self.assertEqual(bool(isHexEncodedString(v)), exp, msg="isHexEncodedString(%r)" % v)


class TestStringEscape(unittest.TestCase):
    def test_known(self):
        self.assertEqual(decodeStringEscape("a\\tb"), "a\tb")
        self.assertEqual(encodeStringEscape("a\tb"), "a\\tb")

    def test_roundtrip_property(self):
        ctrl = "\t\n\r\\abc 123"
        for _ in range(2000):
            s = "".join(RND.choice(ctrl) for _ in range(RND.randint(0, 20)))
            self.assertEqual(decodeStringEscape(encodeStringEscape(s)), s)


class TestVariableNaming(unittest.TestCase):
    def test_transform_is_not_identity(self):
        # safeVariableNaming hex-encodes non-identifier-safe names behind an EVAL_ prefix;
        # pin the exact form so the round-trip below can't be satisfied by no-op functions
        self.assertEqual(safeVariableNaming("a.b"), "EVAL_612e62")  # 612e62 == hex("a.b")
        self.assertNotEqual(safeVariableNaming("weird name"), "weird name")

    def test_roundtrip(self):
        for ident in ["a.b", "schema.table", "x", "weird name", "a-b.c"]:
            encoded = safeVariableNaming(ident)
            if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for c in ident):
                self.assertNotEqual(encoded, ident, msg="unsafe ident %r was not transformed" % ident)
            self.assertEqual(unsafeVariableNaming(encoded), ident)


class TestMiscStrings(unittest.TestCase):
    def test_listToStrValue(self):
        self.assertEqual(listToStrValue([1, 2, 3]), "1, 2, 3")

    def test_filterControlChars(self):
        self.assertEqual(filterControlChars("a\x07b"), "a b")

    def test_longestCommonPrefix(self):
        self.assertEqual(longestCommonPrefix("abcx", "abcy"), "abc")
        self.assertEqual(longestCommonPrefix("abc", "xyz"), "")

    def test_decodeIntToUnicode(self):
        from lib.core.common import Backend
        from lib.core.data import kb

        # decodeIntToUnicode() is back-end DBMS dependent (e.g. PostgreSQL/Oracle/SQLite
        # treat >255 values as Unicode code points). Pin a clean, no-forced-DBMS state so
        # the result is deterministic regardless of test execution order (a prior dialect
        # test may otherwise leave a forced DBMS set); restore it afterwards.
        _saved = (kb.get("forcedDbms"), kb.get("stickyDBMS"))
        Backend.flushForcedDbms(force=True)
        try:
            # single-byte code points map to their char
            self.assertEqual(decodeIntToUnicode(65), u"A")
            self.assertEqual(decodeIntToUnicode(97), u"a")
            # NOTE: with no identified DBMS, >255 ints are interpreted as a multi-byte
            # sequence (not a Unicode code point), e.g. 0x2122 -> bytes 0x21 0x22 -> '!"'
            self.assertEqual(decodeIntToUnicode(0x2122), u'!"')
        finally:
            kb.forcedDbms, kb.stickyDBMS = _saved


if __name__ == "__main__":
    unittest.main(verbosity=2)
