#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Tests for the dependency-free Brotli (RFC 7932) decompressor under lib/utils/brotli.py, and its wiring
into lib/request/basic.py::decodePage. The compressed fixtures were produced by the reference encoder at
various quality levels; the expected plaintext is reconstructed here by construction, so the suite
validates the decoder fully offline (no third-party 'brotli' module at test time) on Python 2.7 / 3.x.
Positive cases exercise the static dictionary + word transforms, long overlapping copies, UTF-8, the
low-quality (near-uniform tree) path and the repetitive content that relies on the higher insert-and-copy
command ranges. Negative cases assert that hostile input (truncation, garbage, output bombs) is rejected
with a BrotliError rather than silently producing corrupted output.
"""

import binascii
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.utils.brotli import decompress
from lib.utils.brotli import BrotliError


# (expected plaintext, reference-compressed stream in hex)
_CASES = [
    (b"", "3b"),
    (b"The quick brown fox jumps over the lazy dog.",
     "8b158054686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e03"),
    (b"the time of the data on the site is now and the code" * 3,
     "1b9b000004e164a9be171b85c00636e080bd799109f64571f090852e78334d90cb20ac9c346c190ff171965a3d2f7a90171c"),
    (b"the quick brown fox " * 30,
     "1b570200047463a92ee78362f22082d628041695d90acef9a3f135e9c701"),
    (b"AB" * 400, "1b1f0300a48284a2b230b009"),
    (u"caf\xe9 na\xefve \u4f60\u597d ".encode("utf-8") * 12,
     "1bef00004427477ad6d60ac38c93200a288ab462c2a06461d22d186dbbe0263e0707"),
    (b"hello hello hello world world foo bar baz " * 6,
     "8b7d000080aaaaaaeaff74e5f355048415f8c0000c201701d0ffbbeadf736f75cfa82e6f63b82b5e2c2c2c6c6cacea654675f0e1c38fc160308e33595583c16030180ce65067442a4aa370586827d97b828968074727f5b21e97eebd045d8baeefef94c3fca4fb1e"),
]

# a valid stream (~1.2 KB of text) whose truncations feed the negative corpus
_TRUNCATION_SAMPLE = binascii.unhexlify("1b570200047463a92ee78362f22082d628041695d90acef9a3f135e9c701")


class TestBrotli(unittest.TestCase):
    def test_known_fixtures(self):
        for expected, hexstream in _CASES:
            self.assertEqual(decompress(binascii.unhexlify(hexstream)), expected)

    def test_empty_stream(self):
        self.assertEqual(decompress(binascii.unhexlify("3b")), b"")

    def test_truncation_is_rejected(self):
        # every proper prefix of a valid stream is truncated -> must raise, never silently return
        # corrupted or zero-padded output
        for cut in range(1, len(_TRUNCATION_SAMPLE)):
            self.assertRaises(BrotliError, decompress, _TRUNCATION_SAMPLE[:cut])

    def test_malformed_is_rejected(self):
        for blob in (b"\xff", b"\x00\x00\x00", b"\x1b\xff\xff\xff\xff",
                     _TRUNCATION_SAMPLE + b"\x00\x00\x00\x00",   # trailing garbage
                     binascii.unhexlify("3b") + b"\xde\xad"):     # data after a complete empty stream
            self.assertRaises(BrotliError, decompress, blob)

    def test_non_brotlierror_never_escapes(self):
        # arbitrary bytes must terminate quickly and only ever raise BrotliError (never a raw exception)
        for i in range(400):
            blob = bytes(bytearray((i * 37 + j * 13) & 0xff for j in range(i % 60)))
            try:
                decompress(blob)
            except BrotliError:
                pass

    def test_bomb_cap(self):
        # a small stream must not be allowed to expand past the output cap
        self.assertRaises(BrotliError, decompress, binascii.unhexlify("1b1f0300a48284a2b230b009"), 16)


class TestBrotliDecodePage(unittest.TestCase):
    _KB = ("pageCompress", "pageEncoding", "disableHtmlDecoding", "singleLogFlags")
    _CONF = ("encoding", "nullConnection")

    def setUp(self):
        from lib.core.data import conf, kb
        self._kb = dict((name, kb.get(name)) for name in self._KB)
        self._conf = dict((name, conf.get(name)) for name in self._CONF)

    def tearDown(self):
        from lib.core.data import conf, kb
        for name, value in self._kb.items():
            kb[name] = value
        for name, value in self._conf.items():
            conf[name] = value

    def test_decodepage_br(self):
        from lib.core.data import conf, kb
        from lib.request.basic import decodePage
        from lib.core.convert import getBytes

        conf.encoding = None
        conf.nullConnection = False
        kb.pageCompress = True
        kb.pageEncoding = None
        kb.singleLogFlags = set()
        kb.disableHtmlDecoding = True

        body = b"<html><body>secret uid=admin</body></html>" * 25
        # brotli-compressed 'body' (reference encoder, quality 11)
        compressed = binascii.unhexlify(
            "1b190488c56d6c1ff52d8742bd820d3870892cd08016f661030e310d82f520b7a3513810bf66edf05d3500")
        self.assertEqual(getBytes(decodePage(compressed, "br", "text/html; charset=utf-8")), body)


if __name__ == "__main__":
    unittest.main()
