#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Tests for the dependency-free Brotli (RFC 7932) decompressor under lib/utils/brotli.py. The compressed
fixtures were produced by the reference encoder at various quality levels; the expected plaintext is
reconstructed here by construction, so the suite validates the decoder fully offline (no third-party
'brotli' module at test time) on Python 2.7 / 3.x. Cases deliberately exercise the static dictionary +
word transforms, long overlapping copies, UTF-8, the low-quality (near-uniform tree) path and the
repetitive content that relies on the higher insert-and-copy command ranges.
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
    ((u"caf\xe9 na\xefve \u4f60\u597d ").encode("utf-8") * 12,
     "1bef00004427477ad6d60ac38c93200a288ab462c2a06461d22d186dbbe0263e0707"),
    (b"hello hello hello world world foo bar baz " * 6,
     "8b7d000080aaaaaaeaff74e5f355048415f8c0000c201701d0ffbbeadf736f75cfa82e6f63b82b5e2c2c2c6c6cacea654675f0e1c38fc160308e33595583c16030180ce65067442a4aa370586827d97b828968074727f5b21e97eebd045d8baeefef94c3fca4fb1e"),
]


class TestBrotli(unittest.TestCase):
    def test_known_fixtures(self):
        for expected, hexstream in _CASES:
            self.assertEqual(decompress(binascii.unhexlify(hexstream)), expected)

    def test_empty_stream(self):
        self.assertEqual(decompress(binascii.unhexlify("3b")), b"")

    def test_malformed_raises(self):
        # a hostile/truncated stream must surface as BrotliError, never a raw exception
        for blob in (b"\xff", b"\x00\x00\x00", b"\x1b\xff\xff\xff\xff", os.urandom(32)):
            try:
                decompress(blob)
            except BrotliError:
                pass
            except Exception as ex:
                self.fail("non-BrotliError on malformed input: %s" % ex)

    def test_bomb_cap(self):
        # a small stream must not be allowed to expand past the output cap
        self.assertRaises(BrotliError, decompress, binascii.unhexlify("1b1f0300a48284a2b230b009"), 16)


if __name__ == "__main__":
    unittest.main()
