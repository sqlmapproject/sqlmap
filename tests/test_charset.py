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
from lib.request.inject import _pageCharsetCorrupted, _looksLikeMisdecodedUtf8
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


class TestCharsetMismatchDetection(unittest.TestCase):
    """The auto-hex recovery triggers on two complementary mismatch directions:
    _pageCharsetCorrupted (page charset too NARROW -> undecodable bytes) and
    _looksLikeMisdecodedUtf8 (page charset too WIDE -> UTF-8 shown as latin-1, no
    undecodable byte). Both must fire on the corruption and NOT on clean data."""

    # correctly-decoded UTF-8 and genuine latin-1 text: neither detector may fire (no wasted re-fetch).
    # \u escapes keep this source pure-ASCII (py2): cafe / naive / Zurich / CJK / Cyrillic / resume / garcon
    CLEAN = [u"admin", u"caf\u00e9", u"na\u00efve", u"Z\u00fcrich", u"\u65e5\u672c\u8a9e",
             u"\u0417\u0434\u0440\u0430\u0432\u0435\u0439", u"r\u00e9sum\u00e9", u"gar\u00e7on"]

    def test_clean_values_trigger_neither(self):
        for v in self.CLEAN:
            self.assertFalse(_pageCharsetCorrupted(v), msg="narrow FP: %r" % v)
            self.assertFalse(_looksLikeMisdecodedUtf8(v), msg="wide FP: %r" % v)

    def test_utf8_shown_as_latin1_is_caught(self):
        # gap #1: UTF-8 column bytes decoded as latin-1 -> valid mojibake, no undecodable byte
        for word in (u"caf\u00e9", u"\u65e5\u672c\u8a9e", u"\u0417\u0434\u0440\u0430\u0432\u0435\u0439", u"\u20ac"):
            mojibake = word.encode("utf-8").decode("latin-1")
            self.assertFalse(_pageCharsetCorrupted(mojibake), msg="narrow should miss: %r" % mojibake)
            self.assertTrue(_looksLikeMisdecodedUtf8(mojibake), msg="wide should catch: %r" % mojibake)

    def test_undecodable_bytes_still_caught_by_narrow(self):
        # the other direction (page charset too narrow) leaves reversible \xNN escapes
        self.assertTrue(_pageCharsetCorrupted(u"foo\\xe9bar"))

    def test_list_and_nonstring_inputs(self):
        self.assertTrue(_looksLikeMisdecodedUtf8([u"ok", u"caf\u00c3\u00a9"]))   # 'cafe' mojibake
        self.assertFalse(_looksLikeMisdecodedUtf8([u"ok", 123, None]))


class TestParamToDict(unittest.TestCase):
    # NOTE: GET parsing is covered in test_urls.py; here we only cover the COOKIE place,
    # which uses a different (semicolon) delimiter and is a distinct code path.
    def test_cookie_semicolon_delimited(self):
        d = paramToDict(PLACE.COOKIE, "sid=abc; theme=dark")
        self.assertEqual(d.get("sid"), "abc")
        self.assertEqual(d.get("theme"), "dark")


if __name__ == "__main__":
    unittest.main(verbosity=2)
