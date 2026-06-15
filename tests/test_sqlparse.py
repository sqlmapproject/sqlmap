#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

SQL/string parsing helpers: field splitting and 0-depth (paren+quote aware)
scanning, query cleanup, regex extraction.
Includes regression cases for the quote-awareness bugs fixed previously.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.common import splitFields, zeroDepthSearch, cleanQuery, extractRegexResult


class TestSplitFields(unittest.TestCase):
    CASES = [
        ("a,b",                 ["a", "b"]),
        ("user,password",       ["user", "password"]),
        ("a,b,c",               ["a", "b", "c"]),
        ("a",                   ["a"]),
        ("max(a,b)",            ["max(a,b)"]),                 # paren-protected
        ("max(a, b),c",         ["max(a,b)", "c"]),           # ', ' normalized; outer split
        ("COUNT(*),name",       ["COUNT(*)", "name"]),
        ("f(g(x,y),z),h",       ["f(g(x,y),z)", "h"]),        # nested parens
        ("'a,b'",               ["'a,b'"]),                    # REGRESSION: comma in single-quoted literal
        ("'a,b','c|d','e&f'",   ["'a,b'", "'c|d'", "'e&f'"]),  # REGRESSION
        ('"x,y",z',             ['"x,y"', "z"]),               # double-quoted literal
    ]

    def test_table(self):
        for inp, expected in self.CASES:
            self.assertEqual(splitFields(inp), expected, msg="splitFields(%r)" % inp)


class TestZeroDepthSearch(unittest.TestCase):
    def test_quote_awareness(self):
        # ' FROM ' inside a literal must NOT be a clause boundary (regression)
        self.assertEqual(zeroDepthSearch("SELECT 'x FROM y'", " FROM "), [])
        # a real FROM must be found (exactly once here)
        self.assertEqual(len(zeroDepthSearch("SELECT a FROM t", " FROM ")), 1)

    def test_paren_awareness(self):
        self.assertEqual(zeroDepthSearch("a(,)b,c", ","), [5])   # only the depth-0 comma

    def test_doctest_vectors(self):
        q = "SELECT (SELECT id FROM users WHERE 2>1) AS result FROM DUAL"
        hits = zeroDepthSearch(q, "FROM")
        self.assertTrue(hits, "no depth-0 FROM found")        # guard: avoid a confusing IndexError
        self.assertEqual(q[hits[0]:], "FROM DUAL")            # outer FROM only
        s = "a(b; c),d;e"
        hits = zeroDepthSearch(s, "[;, ]")
        self.assertTrue(hits)
        self.assertEqual(s[hits[0]:], ",d;e")                 # char-class form


class TestCleanQuery(unittest.TestCase):
    def test_keyword_uppercasing(self):
        self.assertEqual(cleanQuery("select a from t"), "SELECT a FROM t")
        # mixed case keywords get uppercased; non-keyword identifiers are preserved verbatim
        self.assertEqual(cleanQuery("seLeCt a fRoM t"), "SELECT a FROM t")
        self.assertEqual(cleanQuery("SELECT 1"), "SELECT 1")   # already-upper unchanged

    def test_idempotent(self):
        for q in ["select a from t", "SELECT 1", "select x where y=1 order by z"]:
            once = cleanQuery(q)
            self.assertEqual(cleanQuery(once), once)
        # idempotence alone would pass even if cleanQuery uppercased EVERYTHING; anchor that it
        # uppercases keywords but preserves the lowercase identifier
        self.assertEqual(cleanQuery("select a from t"), "SELECT a FROM t")


class TestExtractRegexResult(unittest.TestCase):
    def test_named_group(self):
        self.assertEqual(extractRegexResult(r"id=(?P<result>\d+)", "id=42"), "42")
        self.assertIsNone(extractRegexResult(r"id=(?P<result>\d+)", "no match here"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
