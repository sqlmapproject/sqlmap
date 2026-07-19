#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

HTTP response decoding (lib/request/basic.py decodePage).

Every fetched page passes through decodePage: it inflates gzip/deflate bodies,
applies the charset, and guards against decompression bombs. A regression here
silently corrupts every response sqlmap compares, so the round-trips and the
malformed-input handling are pinned here.
"""

import gzip
import io
import os
import sys
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.request.basic import decodePage
from lib.core.common import extractRegexResult
from lib.core.data import conf, kb
from lib.core.exception import SqlmapCompressionException
from lib.core.settings import META_CHARSET_REGEX

BODY = b"Hello plain body content 12345 - no markup here"


def _gzip(data):
    buf = io.BytesIO()
    f = gzip.GzipFile(fileobj=buf, mode="wb")
    f.write(data)
    f.close()
    return buf.getvalue()


def _raw_deflate(data):
    # decodePage uses zlib.decompressobj(-15) => raw deflate (no zlib header)
    co = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
    return co.compress(data) + co.flush()


class TestDecompression(unittest.TestCase):
    def test_gzip_roundtrip(self):
        # exact equality (not just substring): the whole body must decompress unchanged
        out = decodePage(_gzip(BODY), "gzip", "text/html; charset=utf-8")
        self.assertEqual(out, BODY.decode("utf-8"))

    def test_deflate_roundtrip(self):
        out = decodePage(_raw_deflate(BODY), "deflate", "text/html")
        self.assertEqual(out, BODY.decode("utf-8"))

    def test_identity_passthrough(self):
        out = decodePage(BODY, None, "text/html")
        self.assertEqual(out, BODY.decode("utf-8"))
        # the exact-equality assertions above already imply a unicode return; a separate
        # type-only test would be redundant.


class TestCharset(unittest.TestCase):
    def test_utf8_decoded_to_unicode(self):
        # several distinct multi-byte sequences (2/3/4-byte) must all decode intact
        original = u"café — 你好 \U0001f512"
        out = decodePage(original.encode("utf-8"), None, "text/html; charset=utf-8")
        self.assertEqual(out, original)

    def test_meta_charset_used_when_no_http_charset(self):
        # charset declared only via <meta> (no HTTP charset) with an attribute on <head>
        # must still be honored; byte 0xC0 is 'А' (U+0410) in windows-1251
        page = b'<html><head lang="ru"><meta charset="windows-1251"></head><body>\xc0\xc1\xc2</body></html>'
        conf.encoding = None
        kb.pageEncoding = None
        out = decodePage(page, None, "text/html")
        self.assertIn(u"АБВ", out)


class TestMetaCharsetRegex(unittest.TestCase):
    """META_CHARSET_REGEX must tolerate real-world <head>/meta forms while staying scoped
    to the head so body content can't hijack the detected charset."""

    def _charset(self, html):
        return extractRegexResult(META_CHARSET_REGEX, html)

    def test_head_with_attributes(self):
        self.assertEqual(self._charset('<html><head lang="en"><meta charset="iso-8859-2"></head></html>'), "iso-8859-2")

    def test_whitespace_around_equals(self):
        self.assertEqual(self._charset('<html><head><meta  charset = "utf-8"></head></html>'), "utf-8")

    def test_single_quotes_stripped(self):
        self.assertEqual(self._charset("<html><head><meta charset='utf-8'></head></html>"), "utf-8")

    def test_http_equiv_content_type(self):
        self.assertEqual(self._charset('<html><head><meta http-equiv="Content-Type" content="text/html; charset=windows-1251"></head></html>'), "windows-1251")

    def test_header_tag_not_matched(self):
        # <header> is not <head>
        self.assertIsNone(self._charset('<html><header><meta charset="utf-8"></header></html>'))

    def test_body_meta_not_hijacked(self):
        # a meta whose content merely mentions charset= in the body must not be picked up
        self.assertIsNone(self._charset('<html><head><title>t</title></head><body><meta name="d" content="learn charset=evil"></body></html>'))


class TestMalformed(unittest.TestCase):
    def test_invalid_deflate_raises(self):
        # zlib.compress() adds a 2-byte zlib header that raw-deflate decode rejects;
        # body has no "<html" so decodePage surfaces it as a compression exception
        self.assertRaises(SqlmapCompressionException,
                          lambda: decodePage(zlib.compress(BODY), "deflate", "text/plain"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
