#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

BigArray disk-spill semantics (lib/core/bigarray.py).

BigArray is the structure that lets sqlmap dump tables far larger than RAM: once
the in-memory chunk exceeds chunk_size it is pickled to a temp file and a new
chunk starts. The tricky, easy-to-break part is that indexing / iteration /
pop / pickling must stay correct ACROSS the in-memory<->on-disk boundary.

These force a spill with a tiny chunk_size and assert the data survives intact.
"""

import os
import pickle
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.bigarray import BigArray

N = 5000


def _make_spilled():
    # tiny chunk_size guarantees many on-disk chunks for N items
    ba = BigArray(chunk_size=1024)
    for i in range(N):
        ba.append("item-%d" % i)
    return ba


class TestSpill(unittest.TestCase):
    def test_actually_spilled_to_disk(self):
        ba = _make_spilled()
        self.assertGreater(len(ba.chunks), 1, msg="expected multiple chunks (a disk spill)")
        # stronger than "more than one chunk": at least one chunk must be a real on-disk file
        # (spilled chunks are stored as filenames). Otherwise this could pass while everything
        # stayed in RAM.
        disk_chunks = [c for c in ba.chunks if isinstance(c, str)]
        self.assertTrue(disk_chunks, msg="no chunk was spilled to disk")
        self.assertTrue(os.path.exists(disk_chunks[0]), msg="spilled chunk file missing on disk")

    def test_len(self):
        self.assertEqual(len(_make_spilled()), N)

    def test_random_access_across_boundary(self):
        ba = _make_spilled()
        for i in (0, 1, 499, 500, 2500, N - 1):
            self.assertEqual(ba[i], "item-%d" % i, msg="ba[%d]" % i)

    def test_negative_index(self):
        ba = _make_spilled()
        self.assertEqual(ba[-1], "item-%d" % (N - 1))

    def test_iteration_order_preserved(self):
        ba = _make_spilled()
        for idx, value in enumerate(ba):
            if value != "item-%d" % idx:
                self.fail("iteration order broke at %d: %r" % (idx, value))
        self.assertEqual(idx, N - 1)

    def test_pop_from_end(self):
        ba = _make_spilled()
        self.assertEqual(ba.pop(), "item-%d" % (N - 1))
        self.assertEqual(len(ba), N - 1)

    def test_pickle_roundtrip_across_spill(self):
        ba = _make_spilled()
        restored = pickle.loads(pickle.dumps(ba))
        self.assertIsInstance(restored, BigArray)
        self.assertEqual(len(restored), N)
        self.assertEqual(restored[0], "item-0")
        self.assertEqual(restored[N - 1], "item-%d" % (N - 1))


class TestCacheConsistency(unittest.TestCase):
    """The on-disk chunk is served through a single-slot cache (read caching plus
    dirty write-back). These check that the cache never serves stale data."""

    def test_setitem_writeback_across_chunks(self):
        ba = _make_spilled()
        ref = ["item-%d" % i for i in range(N)]
        # mutate elements spread across several different on-disk chunks
        for i in (0, 1, 499, 500, 2500, N - 1):
            ba[i] = ref[i] = "EDIT-%d" % i
        try:
            for i in (0, 1, 499, 500, 2500, N - 1):
                self.assertEqual(ba[i], ref[i], msg="readback ba[%d]" % i)
            self.assertEqual(list(ba), ref)            # full independent traversal agrees
        finally:
            ba.close()

    def test_dirty_edit_survives_pickle(self):
        ba = _make_spilled()
        ba[10] = "EDITED-LOW"
        ba[N - 10] = "EDITED-HIGH"
        restored = pickle.loads(pickle.dumps(ba))
        try:
            self.assertEqual(restored[10], "EDITED-LOW")
            self.assertEqual(restored[N - 10], "EDITED-HIGH")
        finally:
            restored.close()
            ba.close()

    def test_pop_then_append_then_direct_read(self):
        # Regression: pop() reloads the last on-disk chunk into memory and deletes its
        # file, but a non-dirty cache entry still pointing at that chunk index was left
        # in place. A later append that re-dumps the chunk index then made the stale
        # cache serve outdated data on a direct __getitem__ (silent data corruption).
        ref = ["item-%d" % i for i in range(N)]
        ba = _make_spilled()
        try:
            cl = ba.chunk_length
            last = len(ba.chunks) - 2          # last on-disk chunk (tail is the in-memory list)
            base = last * cl

            ba[base]                           # populate cache at idx=last, NOT dirty

            while len(ba) > base + 1:          # pop() reloads chunk 'last' from disk, removes its file
                ba.pop()
                ref.pop()

            for i in range(cl):                # re-dump chunk 'last' to a brand new temp file
                value = "NEW-%d" % i
                ba.append(value)
                ref.append(value)

            # direct access to the re-dumped chunk, with no prior read to refresh the cache
            for off in range(cl):
                self.assertEqual(ba[base + off], ref[base + off], msg="offset %d" % off)
        finally:
            ba.close()


class TestInMemorySmall(unittest.TestCase):
    def test_no_spill_for_small(self):
        ba = BigArray([1, 2, 3])
        self.assertEqual(len(ba), 3)
        self.assertEqual(list(ba), [1, 2, 3])
        # the actual point of this test (the name promised it): a tiny array stays in ONE
        # in-memory chunk and never touches disk
        self.assertEqual(len(ba.chunks), 1, msg="small array unexpectedly spilled: %r" % (ba.chunks,))
        self.assertFalse(any(isinstance(c, str) for c in ba.chunks), msg="small array wrote a disk chunk")


if __name__ == "__main__":
    unittest.main(verbosity=2)
