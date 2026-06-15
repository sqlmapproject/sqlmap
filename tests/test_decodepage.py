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
from lib.core.exception import SqlmapCompressionException

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


class TestMalformed(unittest.TestCase):
    def test_invalid_deflate_raises(self):
        # zlib.compress() adds a 2-byte zlib header that raw-deflate decode rejects;
        # body has no "<html" so decodePage surfaces it as a compression exception
        self.assertRaises(SqlmapCompressionException,
                          lambda: decodePage(zlib.compress(BODY), "deflate", "text/plain"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
