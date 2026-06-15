#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Response charset / meta detection and parameter parsing.

checkCharEncoding canonicalizes the encoding sqlmap will decode a page with;
META_CHARSET_REGEX / HTML_TITLE_REGEX / META_REFRESH_REGEX pull structural hints
out of the body; paramToDict splits the parameters sqlmap will inject into.
These feed decodePage and the comparison engine, so the canonical/None results
are pinned here.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.request.basic import checkCharEncoding
from lib.core.common import extractRegexResult, paramToDict
from lib.core.enums import PLACE
from lib.core.settings import META_CHARSET_REGEX, HTML_TITLE_REGEX, META_REFRESH_REGEX


class TestCheckCharEncoding(unittest.TestCase):
    def test_canonical_known(self):
        for enc in ("utf-8", "windows-1252", "iso-8859-1", "ascii", "latin1"):
            self.assertEqual(checkCharEncoding(enc, False), enc, msg="checkCharEncoding(%r)" % enc)

    def test_normalizes_aliases(self):
        self.assertEqual(checkCharEncoding("UTF8", False), "utf8")
        self.assertEqual(checkCharEncoding("us-ascii", False), "ascii")

    def test_unknown_is_none(self):
        self.assertIsNone(checkCharEncoding("boguscharset123", False))

    def test_none_is_none(self):
        self.assertIsNone(checkCharEncoding(None, False))


class TestBodyHints(unittest.TestCase):
    def test_meta_charset(self):
        self.assertEqual(extractRegexResult(META_CHARSET_REGEX, '<head><meta charset="utf-8"></head>'), "utf-8")

    def test_title(self):
        self.assertEqual(extractRegexResult(HTML_TITLE_REGEX, "<title>Login Page</title>"), "Login Page")

    def test_meta_refresh_url(self):
        self.assertEqual(extractRegexResult(META_REFRESH_REGEX,
                         '<meta http-equiv="refresh" content="0; url=/next">'), "/next")

    def test_no_match_is_none(self):
        self.assertIsNone(extractRegexResult(HTML_TITLE_REGEX, "<body>no title here</body>"))


class TestParamToDict(unittest.TestCase):
    # NOTE: GET parsing is covered in test_urls.py; here we only cover the COOKIE place,
    # which uses a different (semicolon) delimiter and is a distinct code path.
    def test_cookie_semicolon_delimited(self):
        d = paramToDict(PLACE.COOKIE, "sid=abc; theme=dark")
        self.assertEqual(d.get("sid"), "abc")
        self.assertEqual(d.get("theme"), "dark")


if __name__ == "__main__":
    unittest.main(verbosity=2)
