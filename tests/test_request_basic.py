#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit coverage for PURE functions in lib/request/basic.py.

These exercise getHeuristicCharEncoding (with its kb.cache.encoding memoization)
and decodePage's charset + HTML-entity decoding branches, in isolation - WITHOUT
touching the network, the DBMS or any interactive prompt.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.data import conf, kb


class TestBasicHeuristicCharEncoding(unittest.TestCase):
    def test_ascii(self):
        from lib.request.basic import getHeuristicCharEncoding
        self.assertEqual(getHeuristicCharEncoding(b"<html></html>"), "ascii")

    def test_cache_hit_returns_same(self):
        from lib.request.basic import getHeuristicCharEncoding
        page = b"<html>hello world</html>"
        first = getHeuristicCharEncoding(page)
        # second call for identical page must come back identical (and from cache)
        self.assertEqual(getHeuristicCharEncoding(page), first)
        key = (len(page), hash(page))
        self.assertEqual(kb.cache.encoding.get(key), first)


class TestBasicDecodePage(unittest.TestCase):
    """decodePage charset + HTML-entity decoding branches."""

    def setUp(self):
        self._old_encoding = conf.encoding
        self._old_null = conf.nullConnection
        conf.nullConnection = False

    def tearDown(self):
        conf.encoding = self._old_encoding
        conf.nullConnection = self._old_null

    def test_html_entity_amp(self):
        from lib.request.basic import decodePage
        from lib.core.common import getText
        conf.encoding = None
        self.assertEqual(
            getText(decodePage(b"<html>foo&amp;bar</html>", None, "text/html; charset=utf-8")),
            "<html>foo&bar</html>",
        )

    def test_numeric_hex_entity_tab(self):
        from lib.request.basic import decodePage
        from lib.core.common import getText
        conf.encoding = None
        self.assertEqual(getText(decodePage(b"&#x9;", None, "text/html; charset=utf-8")), "\t")

    def test_numeric_hex_entity_letter(self):
        from lib.request.basic import decodePage
        from lib.core.common import getText
        conf.encoding = None
        self.assertEqual(getText(decodePage(b"&#x4A;", None, "text/html; charset=utf-8")), "J")

    def test_unicode_entity(self):
        from lib.request.basic import decodePage
        conf.encoding = None
        self.assertEqual(decodePage(b"&#x2122;", None, "text/html; charset=utf-8"), u"\u2122")

    def test_empty_page(self):
        from lib.request.basic import decodePage
        from lib.core.common import getText
        # empty page short-circuits to getUnicode(page)
        self.assertEqual(getText(decodePage(b"", None, "text/html")), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
