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


class TestForgeHeadersCookieMerge(unittest.TestCase):
    """A domain-scoped jar cookie (Domain=example.com -> '.example.com') must merge into the
    request for the apex host, not be dropped by a naive endswith() domain check."""

    _CONF = ("cj", "hostname", "httpHeaders", "loadCookies", "cookieDel", "parameters", "csrfToken", "safeUrl")
    _KB = ("mergeCookies", "testMode", "injection")

    def setUp(self):
        self._c = dict((k, conf.get(k)) for k in self._CONF)
        self._k = dict((k, kb.get(k)) for k in self._KB)

    def tearDown(self):
        for k, v in self._c.items():
            conf[k] = v
        for k, v in self._k.items():
            kb[k] = v

    def _jar_with_domain_cookie(self):
        try:
            from http.cookiejar import CookieJar, Cookie
        except ImportError:
            from cookielib import CookieJar, Cookie
        # a domain-scoped cookie the jar stores as '.example.com' (domain_specified=True),
        # exactly as it would after Set-Cookie: sid=NEW; Domain=example.com
        cookie = Cookie(version=0, name="sid", value="NEW", port=None, port_specified=False,
                        domain=".example.com", domain_specified=True, domain_initial_dot=True,
                        path="/", path_specified=True, secure=False, expires=None, discard=True,
                        comment=None, comment_url=None, rest={})
        cj = CookieJar()
        cj.set_cookie(cookie)
        return cj

    def test_domain_cookie_merged_on_apex_host(self):
        from lib.request.basic import forgeHeaders
        from lib.core.enums import PLACE, HTTP_HEADER
        from lib.core.datatype import AttribDict

        conf.cj = self._jar_with_domain_cookie()
        conf.hostname = "example.com"                       # apex host == cookie domain
        conf.httpHeaders = [(HTTP_HEADER.COOKIE, "sid=OLD")]
        conf.loadCookies = False
        conf.cookieDel = None
        conf.parameters = {}
        conf.csrfToken = conf.safeUrl = None
        kb.mergeCookies = True
        kb.testMode = False
        kb.injection = AttribDict()
        kb.injection.place = PLACE.GET

        headers = forgeHeaders()
        # before the fix the domain cookie was skipped for the apex host, leaving 'sid=OLD'
        self.assertEqual(headers.get(HTTP_HEADER.COOKIE), "sid=NEW")


if __name__ == "__main__":
    unittest.main(verbosity=2)
