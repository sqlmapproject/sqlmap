#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Core data structures: AttribDict, OrderedSet, LRUDict, BigArray.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.datatype import AttribDict, OrderedSet, LRUDict
from lib.core.bigarray import BigArray


class TestAttribDict(unittest.TestCase):
    def test_attr_access(self):
        a = AttribDict({"x": 1})
        self.assertEqual(a.x, 1)
        a.y = 2
        self.assertEqual(a["y"], 2)
        self.assertEqual(a.get("missing", "def"), "def")

    def test_missing_attr_raises(self):
        a = AttribDict()
        self.assertRaises(AttributeError, lambda: a.nope)


class TestOrderedSet(unittest.TestCase):
    def test_order_and_dedup(self):
        s = OrderedSet()
        for v in [3, 1, 3, 2, 1, 2]:
            s.add(v)
        self.assertEqual(list(s), [3, 1, 2])
        self.assertIn(2, s)
        self.assertNotIn(9, s)
        self.assertEqual(len(s), 3)


class TestLRUDict(unittest.TestCase):
    def test_capacity_eviction(self):
        l = LRUDict(capacity=2)
        l["a"] = 1
        l["b"] = 2
        _ = l["a"]          # touch 'a' so 'b' becomes least-recently-used
        l["c"] = 3          # evicts 'b'
        self.assertEqual(sorted(l.keys()), ["a", "c"])
        self.assertNotIn("b", l)

    def test_values_retained(self):
        l = LRUDict(capacity=3)
        for i, k in enumerate("abc"):
            l[k] = i
        self.assertEqual(l["a"], 0)
        self.assertEqual(l["c"], 2)

    def test_capacity_one(self):
        # extreme: each write evicts the previous key
        l = LRUDict(capacity=1)
        l["x"] = 1
        l["y"] = 2
        self.assertNotIn("x", l)
        self.assertEqual(l["y"], 2)
        self.assertEqual(list(l.keys()), ["y"])


class TestBigArray(unittest.TestCase):
    def test_basic_ops(self):
        b = BigArray()
        for i in range(50):
            b.append(i)
        self.assertEqual(len(b), 50)
        self.assertEqual(b[0], 0)
        self.assertEqual(b[49], 49)
        self.assertEqual(b[-1], 49)        # negative indexing
        self.assertEqual(list(b)[:3], [0, 1, 2])

    def test_empty_index_raises(self):
        self.assertRaises(IndexError, lambda: BigArray()[0])

    def test_roundtrip_values(self):
        b = BigArray()
        data = list(range(100))
        for v in data:
            b.append(v)
        self.assertEqual([b[i] for i in range(len(b))], data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
