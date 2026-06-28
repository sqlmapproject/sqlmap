#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Encoding / decoding / serialization round-trips and known vectors.
Covers: hex, base64 (std + url-safe), DBMS hex decode, byte<->text conversion,
JSON (de)serialization, restricted base64-pickle.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.convert import (decodeHex, encodeHex, decodeBase64, encodeBase64,
                              getBytes, getText, getUnicode, getOrds,
                              jsonize, dejsonize, base64pickle, base64unpickle)
from lib.core.common import decodeDbmsHexValue

try:
    unichr = unichr
except NameError:
    unichr = chr

RND = random.Random(0xC0FFEE)


def _rand_bytes(maxlen=48):
    return bytes(bytearray(RND.randint(0, 255) for _ in range(RND.randint(0, maxlen))))


class TestHex(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(decodeHex("31323334", binary=True), b"1234")
        self.assertEqual(getText(encodeHex(b"1234", binary=False)), "31323334")

    def test_roundtrip_property(self):
        for _ in range(3000):
            raw = _rand_bytes()
            self.assertEqual(decodeHex(encodeHex(raw, binary=False), binary=True), raw)


class TestBase64(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(decodeBase64("MTIz", binary=True), b"123")
        self.assertEqual(decodeBase64("MTIzNA", binary=True), b"1234")      # missing padding
        self.assertEqual(decodeBase64("MTIzNA==", binary=True), b"1234")
        self.assertEqual(getText(encodeBase64(b"123", binary=False)), "MTIz")
        # url-safe and standard alphabets must decode equivalently
        self.assertEqual(decodeBase64("A-B_CDE", binary=True), decodeBase64("A+B/CDE", binary=True))

    def test_roundtrip_property(self):
        for _ in range(3000):
            raw = _rand_bytes()
            self.assertEqual(decodeBase64(encodeBase64(raw, binary=True), binary=True), raw)
            self.assertEqual(decodeBase64(encodeBase64(raw, binary=True, safe=True), binary=True), raw)
            self.assertEqual(decodeBase64(encodeBase64(raw, binary=True, padding=False), binary=True), raw)


class TestDecodeDbmsHexValue(unittest.TestCase):
    # authoritative vectors taken from the function's own doctests
    def test_known_vectors(self):
        self.assertEqual(decodeDbmsHexValue("3132332031"), u"123 1")
        self.assertEqual(decodeDbmsHexValue("31003200330020003100"), u"123 1")  # utf-16-le shaped
        self.assertEqual(decodeDbmsHexValue("00310032003300200031"), u"123 1")  # utf-16-be shaped
        self.assertEqual(decodeDbmsHexValue("0x31003200330020003100"), u"123 1")
        self.assertEqual(decodeDbmsHexValue("313233203"), u"123 ?")             # odd length
        self.assertEqual(decodeDbmsHexValue(["0x31", "0x32"]), [u"1", u"2"])    # list input

    def test_ascii_roundtrip_property(self):
        for _ in range(1000):
            s = "".join(chr(RND.randint(0x20, 0x7e)) for _ in range(RND.randint(1, 30)))
            if len(s) % 2 == 0:  # avoid the deliberate odd-length '?' behavior
                self.assertEqual(decodeDbmsHexValue(getText(encodeHex(getBytes(s), binary=False))), s)


class TestByteTextConversion(unittest.TestCase):
    def test_ascii_roundtrip(self):
        for _ in range(1000):
            s = u"".join(unichr(RND.randint(0x20, 0x7e)) for _ in range(RND.randint(0, 30)))
            self.assertEqual(getUnicode(getBytes(s)), s)

    def test_unicode_roundtrip(self):
        samples = [u"café", u"你好", u"\U0001F600", u"a’b™c"]
        for s in samples:
            self.assertEqual(getUnicode(getBytes(s)), s)

    def test_getords(self):
        self.assertEqual(getOrds(b"AB"), [65, 66])


class TestJson(unittest.TestCase):
    def test_roundtrip(self):
        for obj in [{"a": 1, "b": [1, 2, 3]}, [1, "x", None], {"nested": {"k": "v"}}, "str", 123]:
            self.assertEqual(dejsonize(jsonize(obj)), obj)

    def test_jsonize_produces_text_not_identity(self):
        # anchor: jsonize must serialize to a JSON string, not pass the object through
        out = jsonize({"a": 1})
        self.assertIsInstance(out, str)
        self.assertIn('"a"', out)
        self.assertEqual(jsonize(123), "123")          # int -> textual "123"


class TestBase64Pickle(unittest.TestCase):
    # Types sqlmap actually serializes (injection objects, cached values, BigArray).
    def test_roundtrip_allowed_types(self):
        for obj in [[1, 2, 3], {"a": 1}, (1, 2), "text", 42, 3.14, True, None, {"k": [1, {"n": "v"}]}]:
            self.assertEqual(base64unpickle(base64pickle(obj)), obj)

    # REGRESSION: under Python 3 + PICKLE_PROTOCOL=2 a raw `bytes` value is pickled via the
    # `_codecs.encode` global. The RestrictedUnpickler allowlist (patch.py) once rejected that,
    # so any serialized session value containing bytes failed to load on py3. The fix allows
    # exactly `_codecs.encode` (a benign codec call). Bytes MUST round-trip on both py2 and py3.
    def test_bytes_roundtrip(self):
        for raw in [b"x", b"\x00\x01\xff", b"\xde\xad\xbe\xef"]:
            self.assertEqual(base64unpickle(base64pickle(raw)), raw, msg="bytes round-trip %r" % raw)

    def test_bytes_nested_in_container_roundtrip(self):
        for obj in [{"a": b"bytes"}, [b"ab", "s", 1, None], ("t", b"\xde\xad")]:
            self.assertEqual(base64unpickle(base64pickle(obj)), obj, msg="nested-bytes round-trip %r" % (obj,))

    def test_dangerous_globals_still_blocked(self):
        # bootstrap() installs sqlmap's RestrictedUnpickler over pickle.loads. These are VALID
        # pickles that reference os.system / builtins.eval - stdlib would import them happily; the
        # allowlist must reject them. Assert the SPECIFIC "forbidden" ValueError (not just any
        # error) so the test proves the allowlist fired, not that the bytes failed to parse.
        import pickle
        for payload in (b"cos\nsystem\n.", b"c__builtin__\neval\n."):
            try:
                pickle.loads(payload)
                self.fail("dangerous global was NOT blocked: %r" % payload)
            except ValueError as ex:
                self.assertIn("forbidden", str(ex), msg="unexpected error for %r: %s" % (payload, ex))


if __name__ == "__main__":
    unittest.main(verbosity=2)
