#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Assorted pure helpers: stats, set ops, value predicates, value/counter stacks,
enum helpers, DBMS alias/version checks, column prioritization.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core import common as C
from lib.core.settings import NULL
from lib.core.enums import DBMS


class TestStats(unittest.TestCase):
    def test_average(self):
        self.assertEqual(C.average([1, 2, 3, 4]), 2.5)
        self.assertEqual(C.average([5]), 5)

    def test_stdev(self):
        self.assertAlmostEqual(C.stdev([1, 2, 3, 4]), 1.2909944, places=5)
        self.assertIsNone(C.stdev([5]))   # undefined for single sample


class TestSetOps(unittest.TestCase):
    def test_intersect(self):
        self.assertEqual(C.intersect([1, 2, 3], [2, 3, 4]), [2, 3])
        self.assertEqual(C.intersect([1], [2]), [])

    def test_filterPairValues(self):
        self.assertEqual(C.filterPairValues([[1, 2], [3], [4, 5], []]), [[1, 2], [4, 5]])


class TestValuePredicates(unittest.TestCase):
    def test_isNoneValue(self):
        for v in (None, [], "", {}):
            self.assertTrue(C.isNoneValue(v), msg="isNoneValue(%r)" % (v,))

    def test_isNullValue(self):
        self.assertTrue(C.isNullValue(NULL))
        # discriminating negatives: an always-True impl must fail these
        self.assertFalse(C.isNullValue(None))
        self.assertFalse(C.isNullValue(""))
        self.assertFalse(C.isNullValue("x"))

    def test_isNumPosStrValue(self):
        for v, exp in [("5", True), ("0", False), ("-1", False), ("a", False), ("12", True)]:
            self.assertEqual(bool(C.isNumPosStrValue(v)), exp, msg="isNumPosStrValue(%r)" % v)

    def test_firstNotNone(self):
        self.assertEqual(C.firstNotNone(None, None, 5, 6), 5)
        self.assertIsNone(C.firstNotNone(None, None))


class TestValueStackAndCounters(unittest.TestCase):
    def test_push_pop(self):
        C.pushValue(7)
        C.pushValue("x")
        self.assertEqual(C.popValue(), "x")
        self.assertEqual(C.popValue(), 7)

    def test_counters(self):
        C.resetCounter("UNITTEST")
        C.incrementCounter("UNITTEST")
        C.incrementCounter("UNITTEST")
        self.assertEqual(C.getCounter("UNITTEST"), 2)


class TestEnumAndDbmsHelpers(unittest.TestCase):
    def test_aliasToDbmsEnum(self):
        self.assertEqual(C.aliasToDbmsEnum("mysql"), DBMS.MYSQL)
        self.assertEqual(C.aliasToDbmsEnum("postgres"), DBMS.PGSQL)

    def test_getPublicTypeMembers(self):
        members = list(C.getPublicTypeMembers(DBMS, onlyValues=True))
        # goal is correct EXTRACTION, not a magic count: real members present, no private/dunder leak
        self.assertIn(DBMS.MYSQL, members)
        self.assertIn(DBMS.MSSQL, members)
        self.assertIn(DBMS.ORACLE, members)
        self.assertFalse(any(str(m).startswith("_") for m in members), msg="leaked private member: %r" % members)

    def test_isDBMSVersionAtLeast(self):
        set_dbms(DBMS.MYSQL)
        C.Backend.setVersion("5.7")
        self.assertTrue(C.isDBMSVersionAtLeast("5.0"))
        self.assertFalse(C.isDBMSVersionAtLeast("8.0"))


class TestColumnPriority(unittest.TestCase):
    def test_prioritySortColumns(self):
        # assert the FULL ordering, not just the first element (id-like floats to front,
        # rest keep their relative order)
        self.assertEqual(C.prioritySortColumns(["data", "id", "name"]), ["id", "data", "name"])

    def test_prioritySortColumns_empty(self):
        self.assertEqual(C.prioritySortColumns([]), [])


class TestArrayHelpers(unittest.TestCase):
    def test_unArrayizeValue(self):
        self.assertEqual(C.unArrayizeValue([5]), 5)        # single-element list -> the element
        self.assertEqual(C.unArrayizeValue([1, 2]), 1)     # multi -> first
        self.assertEqual(C.unArrayizeValue(7), 7)          # scalar -> unchanged
        self.assertIsNone(C.unArrayizeValue([]))           # empty -> None

    def test_arrayizeValue(self):
        self.assertEqual(C.arrayizeValue(5), [5])          # scalar -> wrapped
        self.assertEqual(C.arrayizeValue([5]), [5])        # list -> unchanged

    def test_roundtrip_scalar(self):
        for v in (0, 1, "x", "value"):
            self.assertEqual(C.unArrayizeValue(C.arrayizeValue(v)), v)


if __name__ == "__main__":
    unittest.main(verbosity=2)
