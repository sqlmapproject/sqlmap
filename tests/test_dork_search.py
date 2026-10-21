#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit tests for lib/utils/search.py (dork search), exercising the engine loop by
MOCKING the network layer (_fetch).

No network is involved: _fetch is patched to return canned search engine result
pages, so we can assert both on the links extracted per engine and on the
abuse/captcha detection that triggers proxy rotation (SEARCH_ABUSE_MARKERS).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap

bootstrap()

from lib.core.data import conf
from lib.core.exception import SqlmapBaseException
from lib.core.settings import SEARCH_ABUSE_MARKERS
import lib.utils.search as smod

BING_PAGE = '<h2><a target="_blank" href="https://www.bing.com/ck/a?!&amp;&amp;p=1&amp;u=a1aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20vYS5waHA_aWQ9MQ&amp;ntb=1">a</a></h2>'
DUCKDUCKGO_PAGE = '<a class="result__url" href="https://www.example.com/b.php?id=2">b</a>'

class TestDorkSearch(unittest.TestCase):
    def setUp(self):
        conf.googlePage = 1
        conf.proxyList = None
        self._fetch = smod._fetch

    def tearDown(self):
        smod._fetch = self._fetch

    def _pages(self, *pages):
        """Patches _fetch to serve `pages` in engine order (None meaning no reply)"""

        served = list(pages)
        smod._fetch = lambda *args, **kwargs: served.pop(0) if served else None

    def test_duckduckgo_results(self):
        self._pages(DUCKDUCKGO_PAGE)
        self.assertEqual(smod._search("dork"), ["https://www.example.com/b.php?id=2"])

    def test_bing_fallback_decodes_redirect(self):
        self._pages(None, BING_PAGE)
        self.assertEqual(smod._search("dork"), ["https://www.example.com/a.php?id=1"])

    def test_abuse_page_switches_proxy(self):
        # Note: without '--proxy-list' there is nothing to switch to, hence no exception
        for marker in SEARCH_ABUSE_MARKERS:
            self._pages("<html>%s</html>" % marker)
            conf.proxyList = None
            self.assertEqual(smod._search("dork"), [])

            self._pages("<html>%s</html>" % marker)
            conf.proxyList = ["http://127.0.0.1:8080"]
            self.assertRaises(SqlmapBaseException, smod._search, "dork")

    def test_results_page_is_not_mistaken_for_abuse(self):
        self._pages(DUCKDUCKGO_PAGE)
        conf.proxyList = ["http://127.0.0.1:8080"]
        self.assertEqual(smod._search("dork"), ["https://www.example.com/b.php?id=2"])

if __name__ == "__main__":
    unittest.main()
