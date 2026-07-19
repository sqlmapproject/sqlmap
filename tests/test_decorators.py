#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Function decorators in lib/core/decorators.py: cachedmethod (memoization with a
hashable fast path and a frozen slow path for unhashable arguments), stackedmethod
(value-stack realignment) and lockedmethod (reentrant serialization).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.decorators import cachedmethod, stackedmethod, lockedmethod
from lib.core.threads import getCurrentThreadData


class TestCachedMethod(unittest.TestCase):
    def test_memoizes_hashable_args(self):
        calls = []

        @cachedmethod
        def f(x):
            calls.append(x)
            return x * 2

        self.assertEqual(f(3), 6)
        self.assertEqual(f(3), 6)
        self.assertEqual(len(calls), 1)          # second call served from cache

    def test_memoizes_unhashable_args(self):
        calls = []

        @cachedmethod
        def g(seq):
            calls.append(1)
            return sum(seq)

        self.assertEqual(g([1, 2, 3]), 6)
        self.assertEqual(g([1, 2, 3]), 6)        # same list content -> cache hit
        self.assertEqual(len(calls), 1)
        self.assertEqual(g([4, 5]), 9)           # different content -> recomputed
        self.assertEqual(len(calls), 2)

    def test_tuple_and_list_args_do_not_collide(self):
        # regression: a list arg ([1,2],) freezes to ((1,2),), the raw fast key of a tuple
        # arg ((1,2),); the two calls must not share a cache slot
        @cachedmethod
        def kind(x):
            return type(x).__name__

        self.assertEqual(kind((1, 2)), "tuple")
        self.assertEqual(kind([1, 2]), "list")

    def test_kwargs_are_part_of_the_key(self):
        @cachedmethod
        def h(a, b=0):
            return a + b

        self.assertEqual(h(1, b=2), 3)
        self.assertEqual(h(1, b=5), 6)           # different kwarg -> not a cache hit


class TestStackedMethod(unittest.TestCase):
    def test_realigns_leftover_pushes(self):
        td = getCurrentThreadData()
        base = len(td.valueStack)

        @stackedmethod
        def leaky(_):
            td.valueStack.append(_)              # pushes without popping

        leaky(1)
        self.assertEqual(len(td.valueStack), base)   # stack restored to original level


class TestLockedMethod(unittest.TestCase):
    def test_reentrant(self):
        @lockedmethod
        def recursive_count(n):
            return 0 if n <= 0 else n + recursive_count(n - 1)

        self.assertEqual(recursive_count(5), 15)


if __name__ == "__main__":
    unittest.main(verbosity=2)
