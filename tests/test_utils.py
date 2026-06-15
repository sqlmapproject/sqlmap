#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Core utility helpers: constant-time compare, numeric checks, safe formatting,
list/value normalization, randomness generators.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.common import (safeCompareStrings, isDigit, isNumber, safeStringFormat,
                             filterNone, flattenValue, isListLike, unArrayizeValue,
                             arrayizeValue, randomStr, randomInt)


class TestSafeCompareStrings(unittest.TestCase):
    def test_known(self):
        self.assertTrue(safeCompareStrings("abc", "abc"))
        self.assertFalse(safeCompareStrings("abc", "abd"))
        self.assertFalse(safeCompareStrings("test", None))
        self.assertTrue(safeCompareStrings(None, None))
        self.assertFalse(safeCompareStrings("a", "ab"))   # different length

    def test_property(self):
        for s in ["", "a", "secret", "p@ss w0rd", "x" * 100]:
            self.assertTrue(safeCompareStrings(s, s))
            self.assertFalse(safeCompareStrings(s, s + "x"))


class TestNumericChecks(unittest.TestCase):
    def test_isDigit(self):
        for v, exp in [("123", True), ("0", True), ("12a", False), ("", False), ("-1", False)]:
            self.assertEqual(bool(isDigit(v)), exp, msg="isDigit(%r)" % v)

    def test_isNumber(self):
        for v, exp in [("123", True), ("1.5", True), ("1e3", True), ("abc", False), ("", False)]:
            self.assertEqual(bool(isNumber(v)), exp, msg="isNumber(%r)" % v)


class TestSafeStringFormat(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(safeStringFormat("%s-%d", ("a", 5)), "a-5")
        self.assertEqual(safeStringFormat("%s/%s", ("x", "y")), "x/y")

    def test_survives_percent_in_value(self):
        # the WHOLE point of safeStringFormat over plain `%`: a '%' inside an argument (common in
        # payloads/URL-encoded values) must not blow up or be misread as a format spec.
        # Plain "x=%s" % ("100%done",) would raise on re-evaluation; safeStringFormat must not.
        self.assertEqual(safeStringFormat("x=%s", ("100%done",)), "x=100%done")


class TestListValueHelpers(unittest.TestCase):
    def test_filterNone(self):
        self.assertEqual(filterNone([1, None, 2, 0, "", None]), [1, 2, 0])
        self.assertEqual(filterNone([]), [])
        self.assertEqual(filterNone([None, None]), [])

    def test_flattenValue(self):
        self.assertEqual(list(flattenValue([[1, 2], [3, [4]]])), [1, 2, 3, 4])
        self.assertEqual(list(flattenValue([])), [])
        self.assertEqual(list(flattenValue([1])), [1])

    def test_isListLike(self):
        from lib.core.datatype import OrderedSet
        from lib.core.bigarray import BigArray
        # isListLike is sqlmap-specific: it must recognize sqlmap's own list-like containers
        # (OrderedSet, BigArray), not just builtin list/tuple - that's why it's not isinstance(list)
        self.assertTrue(isListLike([1]))
        self.assertTrue(isListLike((1,)))
        self.assertTrue(isListLike(OrderedSet([1, 2])))
        self.assertTrue(isListLike(BigArray([1])))
        # and must reject str (the classic trap) and dict
        self.assertFalse(isListLike("string"))
        self.assertFalse(isListLike({"a": 1}))

    def test_arrayize_roundtrip(self):
        self.assertEqual(unArrayizeValue([5]), 5)
        self.assertIsNone(unArrayizeValue([]))
        self.assertEqual(unArrayizeValue(7), 7)
        self.assertEqual(arrayizeValue(5), [5])
        self.assertEqual(arrayizeValue([5]), [5])


class TestRandomGenerators(unittest.TestCase):
    def test_randomStr_length_and_alphabet(self):
        for n in (1, 4, 16, 50):
            self.assertEqual(len(randomStr(n)), n)
        for _ in range(200):
            self.assertTrue(all("a" <= c <= "z" for c in randomStr(20, lowercase=True)))
        alpha = list("ABC")
        for _ in range(200):
            self.assertTrue(all(c in alpha for c in randomStr(20, alphabet=alpha)))

    def test_randomStr_is_actually_random(self):
        # guard against a hardcoded/constant return: 20-char strings must (essentially) never collide
        samples = set(randomStr(20) for _ in range(100))
        self.assertEqual(len(samples), 100, msg="randomStr produced collisions - not random?")

    def test_randomInt_digits(self):
        for n in (1, 3, 6):
            lo, hi = 10 ** (n - 1), 10 ** n
            for _ in range(200):
                v = randomInt(n)
                self.assertEqual(len(str(v)), n)            # exactly n digits
                self.assertTrue(lo <= v < hi, msg="randomInt(%d)=%d out of [%d,%d)" % (n, v, lo, hi))


if __name__ == "__main__":
    unittest.main(verbosity=2)
