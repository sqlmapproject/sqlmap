#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Tests for lib/core/compat.py -- cross-version compatibility utilities,
including WichmannHill RNG, patchHeaders, cmp_to_key, LooseVersion,
MixedWriteTextIO, and _codecs_open.
"""

import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.compat import (WichmannHill, patchHeaders, cmp, choose_boundary,
                              round, cmp_to_key, LooseVersion, _is_write_mode,
                              MixedWriteTextIO, _codecs_open)


class TestWichmannHill(unittest.TestCase):
    def test_seed_and_random(self):
        r = WichmannHill(42)
        self.assertIsInstance(r.random(), float)
        self.assertGreaterEqual(r.random(), 0.0)
        self.assertLess(r.random(), 1.0)

    def test_deterministic_seed(self):
        r1 = WichmannHill(123)
        r2 = WichmannHill(123)
        # First random numbers should match
        self.assertEqual([r1.random() for _ in range(10)],
                         [r2.random() for _ in range(10)])

    def test_getstate_setstate(self):
        r = WichmannHill(7)
        for _ in range(20):
            r.random()
        state = r.getstate()
        saved = [r.random() for _ in range(5)]
        r.setstate(state)
        self.assertEqual(saved, [r.random() for _ in range(5)])

    def test_jumpahead(self):
        r1 = WichmannHill(99)
        r2 = WichmannHill(99)
        for _ in range(10):
            r1.random()
        r2.jumpahead(10)
        self.assertEqual(r1.getstate()[1], r2.getstate()[1])

    def test_jumpahead_negative_raises(self):
        r = WichmannHill()
        with self.assertRaises(ValueError):
            r.jumpahead(-1)

    def test_whseed(self):
        # a fixed integer whseed must be deterministic across instances ...
        r1 = WichmannHill()
        r1.whseed(12345)
        r2 = WichmannHill()
        r2.whseed(12345)
        self.assertEqual([r1.random() for _ in range(10)],
                         [r2.random() for _ in range(10)])
        # ... and pin the known sequence (hash(int) == int, so stable across processes)
        r3 = WichmannHill()
        r3.whseed(12345)
        self.assertEqual([round(r3.random(), 6) for _ in range(3)],
                         [0.600031, 0.872148, 0.039151])

    def test_whseed_none(self):
        r = WichmannHill()
        r.whseed()  # seeds from current time; must not raise
        # the time-derived seed must still drive a valid in-range sequence. (Non-determinism is NOT
        # asserted here: __whseed() derives its seed from int(time.time()*256) masked to 24 bits, so
        # two back-to-back instances legitimately collide - that would be a timing-fragile test. The
        # os.urandom-backed seed() None path IS asserted non-deterministic in test_seed_none.)
        seq = [r.random() for _ in range(10)]
        self.assertTrue(all(isinstance(x, float) and 0.0 <= x < 1.0 for x in seq))
        # the seed must actually advance the generator (not stuck on a constant)
        self.assertGreater(len(set(seq)), 1)

    def test_seed_none(self):
        r = WichmannHill()
        r.seed()  # seeds from os.urandom/time; must not raise
        seq = [r.random() for _ in range(10)]
        self.assertTrue(all(isinstance(x, float) and 0.0 <= x < 1.0 for x in seq))
        other = WichmannHill()
        other.seed()
        self.assertNotEqual(seq, [other.random() for _ in range(10)])

    def test_seed_hashable(self):
        # a non-int hashable seed goes through hash(a); two instances seeded with the same
        # object in the same process must produce the same sequence (determinism). The literal
        # values are NOT pinned because hash() of a str is randomized per process.
        r1 = WichmannHill("a_string_seed")
        r2 = WichmannHill("a_string_seed")
        seq = [r1.random() for _ in range(10)]
        self.assertEqual(seq, [r2.random() for _ in range(10)])
        self.assertTrue(all(0.0 <= x < 1.0 for x in seq))
        # a different seed must yield a different sequence
        r3 = WichmannHill("different_seed")
        self.assertNotEqual(seq, [r3.random() for _ in range(10)])

    def test_setstate_bad_version(self):
        r = WichmannHill()
        with self.assertRaises(ValueError):
            r.setstate((999, (1, 1, 1), None))


class TestPatchHeaders(unittest.TestCase):
    def test_patches_dict_to_header_obj(self):
        h = patchHeaders({"Host": "example.com", "Content-Type": "text/html"})
        self.assertEqual(h["host"], "example.com")
        self.assertEqual(h["content-type"], "text/html")
        self.assertEqual(h.get("HOST"), "example.com")
        self.assertIsNone(h.get("missing"))
        self.assertIsNotNone(h.headers)
        self.assertTrue(any("Host: example.com" in _ for _ in h.headers))

    def test_passthrough_none(self):
        self.assertIsNone(patchHeaders(None))

    def test_passthrough_existing_headers_attr(self):
        d = {"A": "1"}
        d["headers"] = []
        result = patchHeaders(d)
        self.assertEqual(result, d)  # unchanged


class TestCmp(unittest.TestCase):
    def test_less(self):
        self.assertEqual(cmp("a", "b"), -1)

    def test_greater(self):
        self.assertEqual(cmp(2, 1), 1)

    def test_equal(self):
        self.assertEqual(cmp(5, 5), 0)


class TestRound(unittest.TestCase):
    def test_positive(self):
        self.assertEqual(round(2.0), 2.0)
        self.assertEqual(round(2.5), 3.0)
        self.assertEqual(round(2.499), 2.0)

    def test_negative(self):
        self.assertEqual(round(-2.5), -3.0)
        self.assertEqual(round(-2.0), -2.0)

    def test_with_decimals(self):
        self.assertAlmostEqual(round(2.567, d=2), 2.57)


class TestCmpToKey(unittest.TestCase):
    def test_sort_with_cmp(self):
        items = [3, 1, 4, 1, 5]
        key_func = cmp_to_key(lambda a, b: (a > b) - (a < b))
        self.assertEqual(sorted(items, key=key_func), [1, 1, 3, 4, 5])

    def test_reverse_sort(self):
        items = [3, 1, 2]
        key_func = cmp_to_key(lambda a, b: (b > a) - (b < a))
        self.assertEqual(sorted(items, key=key_func), [3, 2, 1])

    def test_hash_raises(self):
        k = cmp_to_key(lambda a, b: 0)(5)
        with self.assertRaises(TypeError):
            hash(k)


class TestLooseVersion(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(LooseVersion("1.0"), (1, 0))
        self.assertEqual(LooseVersion("1.0.1"), (1, 0, 1))

    def test_comparison(self):
        self.assertTrue(LooseVersion("1.0.1") > LooseVersion("1.0"))
        self.assertTrue(LooseVersion("8.0.22") > LooseVersion("8.0.2"))

    def test_no_digits(self):
        self.assertEqual(LooseVersion("alpha"), ())
        self.assertEqual(LooseVersion(""), ())
        self.assertEqual(LooseVersion(None), ())

    def test_with_suffix(self):
        self.assertEqual(LooseVersion("1.0alpha"), (1, 0))
        self.assertEqual(LooseVersion("10.5.3-beta"), (10, 5, 3))


class TestIsWriteMode(unittest.TestCase):
    def test_write_modes(self):
        for mode in ("w", "a", "x", "w+", "a+", "x+", "w+b", "ab"):
            self.assertTrue(_is_write_mode(mode), msg="mode %r" % mode)

    def test_read_modes(self):
        for mode in ("r", "rb", ""):
            self.assertFalse(_is_write_mode(mode), msg="mode %r" % mode)


class TestMixedWriteTextIO(unittest.TestCase):
    def test_text_write(self):
        buf = io.StringIO()
        w = MixedWriteTextIO(buf, "utf-8", "strict")
        w.write(u"hello")
        self.assertEqual(buf.getvalue(), "hello")

    def test_bytes_write_decodes(self):
        buf = io.StringIO()
        w = MixedWriteTextIO(buf, "utf-8", "strict")
        w.write(b"world")
        self.assertEqual(buf.getvalue(), "world")

    def test_writelines(self):
        buf = io.StringIO()
        w = MixedWriteTextIO(buf, "utf-8", "strict")
        w.writelines([u"a", u"b", u"c"])
        self.assertEqual(buf.getvalue(), "abc")

    def test_iterator(self):
        buf = io.StringIO(u"line1\nline2\n")
        w = MixedWriteTextIO(buf, "utf-8", "strict")
        self.assertEqual(list(w), ["line1\n", "line2\n"])

    def test_enter_exit(self):
        buf = io.StringIO()
        w = MixedWriteTextIO(buf, "utf-8", "strict")
        with w as f:
            f.write(u"test")
        self.assertTrue(buf.closed)


class TestCodecsOpen(unittest.TestCase):
    def test_no_encoding_returns_io_open(self):
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        tmp.close()
        try:
            f = _codecs_open(tmp.name, "w", encoding=None)
            f.write(u"test")
            f.close()
            with open(tmp.name) as fh:
                self.assertIn("test", fh.read())
        finally:
            os.unlink(tmp.name)

    def test_with_encoding(self):
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        tmp.close()
        try:
            f = _codecs_open(tmp.name, "w", encoding="utf-8")
            f.write(u"caf\xe9")
            f.close()
            with open(tmp.name, "rb") as fh:
                self.assertIn(b"caf\xc3\xa9", fh.read())
        finally:
            os.unlink(tmp.name)

    def test_with_encoding_and_bytes(self):
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        tmp.close()
        try:
            f = _codecs_open(tmp.name, "w", encoding="utf-8")
            # MixedWriteTextIO should accept bytes too
            f.write(b"bytes_input")
            f.close()
            with open(tmp.name) as fh:
                self.assertIn("bytes_input", fh.read())
        finally:
            os.unlink(tmp.name)


class TestChooseBoundary(unittest.TestCase):
    def test_length(self):
        self.assertEqual(len(choose_boundary()), 32)

    def test_hex_chars(self):
        b = choose_boundary()
        self.assertTrue(all(c in "0123456789abcdef" for c in b))


if __name__ == "__main__":
    unittest.main(verbosity=2)
