#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Page-content extraction helpers (lib/core/common.py): getFilteredPageContent,
getPageWordSet, extractTextTagContent, and parseSqliteTableSchema.

The first three feed text-only comparison (--text-only), dynamic-content
removal, and Google-dork style scraping; the last reconstructs column metadata
from a sqlite_master CREATE TABLE statement during enumeration. All pure given
their input (the page must be unicode for tag stripping to engage - a real
gotcha pinned below).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.common import (getFilteredPageContent, getPageWordSet,
                             extractTextTagContent, parseSqliteTableSchema)
from lib.core.data import kb


class TestFilteredPageContent(unittest.TestCase):
    def test_strips_all_tags_in_text_mode(self):
        self.assertEqual(getFilteredPageContent(u"<html><title>foobar</title><body>test</body></html>"),
                         u"foobar test")

    def test_strips_script(self):
        self.assertEqual(getFilteredPageContent(u"<p>keep</p><script>var x=1;</script><p>this</p>"),
                         u"keep this")

    def test_keeps_tags_when_not_only_text(self):
        self.assertEqual(getFilteredPageContent(u"<p>a</p><script>x</script><p>b</p>", onlyText=False),
                         u"<p>a</p> <p>b</p>")

    def test_bytes_input_unchanged(self):
        # GOTCHA: tag stripping only engages for unicode input (charset-identified pages)
        raw = b"<b>x</b>"
        self.assertEqual(getFilteredPageContent(raw), raw)


class TestPageWordSet(unittest.TestCase):
    def test_words(self):
        self.assertEqual(sorted(getPageWordSet(u"<html><title>foobar</title><body>test</body></html>")),
                         [u"foobar", u"test"])


class TestExtractTextTagContent(unittest.TestCase):
    def test_multiple_tags(self):
        self.assertEqual(extractTextTagContent(u"<title>Welcome</title><p>Body text</p>"),
                         [u"Welcome", u"Body text"])


class TestParseSqliteTableSchema(unittest.TestCase):
    def setUp(self):
        kb.data.cachedColumns = {}

    def _cols(self):
        # parseSqliteTableSchema stores under cachedColumns[db][table] (both None here)
        return dict(kb.data.cachedColumns[None][None])

    def test_basic_columns_and_types(self):
        parseSqliteTableSchema("CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, age INT)")
        cols = self._cols()
        self.assertEqual(cols["id"], "INTEGER")
        self.assertEqual(cols["name"], "TEXT")
        self.assertEqual(cols["age"], "INT")

    def test_quoted_identifiers_and_sized_types(self):
        parseSqliteTableSchema('CREATE TABLE "t"("id" INTEGER, "n" VARCHAR(50), flag BOOLEAN)')
        cols = self._cols()
        self.assertIn("id", cols)
        self.assertEqual(cols["n"], "VARCHAR")     # size dropped
        self.assertEqual(cols["flag"], "BOOLEAN")


if __name__ == "__main__":
    unittest.main(verbosity=2)
