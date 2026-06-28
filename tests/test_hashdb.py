#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Session storage layer (lib/utils/hashdb.py) - the on-disk SQLite cache that
makes --flush-session / resume work.

Exercised against a REAL temporary SQLite file (no network, no DBMS): scalar
write/retrieve, serialized round-trip for every container type sqlmap stores,
overwrite semantics, missing-key -> None, and key-hash determinism.

This is also the end-to-end regression for the base64-pickle bytes fix: a
serialized value containing raw `bytes` must survive a write/flush/retrieve
cycle on both Python 2 and 3 (it silently failed on py3 before the patch.py fix).
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.utils.hashdb import HashDB
from lib.core.datatype import AttribDict
from lib.core.bigarray import BigArray


class _HashDBCase(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.path)            # HashDB creates it lazily
        self.db = HashDB(self.path)

    def tearDown(self):
        try:
            self.db.closeAll()
        except Exception:
            pass
        if os.path.exists(self.path):
            os.remove(self.path)


class TestScalar(_HashDBCase):
    def test_string_roundtrip(self):
        self.db.write("greeting", "hello")
        self.db.flush()
        self.assertEqual(self.db.retrieve("greeting"), "hello")

    def test_non_serialized_number_comes_back_as_text(self):
        # non-serialized writes are stored via getUnicode()
        self.db.write("num", 5)
        self.db.flush()
        self.assertEqual(self.db.retrieve("num"), "5")

    def test_missing_key_is_none(self):
        self.assertIsNone(self.db.retrieve("never-written"))

    def test_overwrite_last_wins(self):
        self.db.write("k", "v1")
        self.db.write("k", "v2")
        self.db.flush()
        self.assertEqual(self.db.retrieve("k"), "v2")

    def test_keys_are_independent(self):
        self.db.write("a", "1")
        self.db.write("b", "2")
        self.db.flush()
        self.assertEqual(self.db.retrieve("a"), "1")
        self.assertEqual(self.db.retrieve("b"), "2")


class TestSerialized(_HashDBCase):
    def test_list_dict_tuple_set(self):
        cases = {
            "list":  [1, 2, 3, "x"],
            "dict":  {"k": [1, {"n": "v"}]},
            "tuple": (1, "a", None),
            "set":   set([1, 2, 3]),
        }
        for key, val in cases.items():
            self.db.write(key, val, True)
        self.db.flush()
        for key, val in cases.items():
            self.assertEqual(self.db.retrieve(key, True), val, msg="serialized round-trip for %s" % key)

    def test_attribdict_roundtrip(self):
        ad = AttribDict()
        ad.x = 1
        ad.y = [1, 2]
        self.db.write("ad", ad, True)
        self.db.flush()
        got = self.db.retrieve("ad", True)
        self.assertIsInstance(got, AttribDict)
        self.assertEqual(got.x, 1)
        self.assertEqual(got.y, [1, 2])

    def test_bigarray_roundtrip(self):
        self.db.write("ba", BigArray([1, 2, 3]), True)
        self.db.flush()
        got = self.db.retrieve("ba", True)
        self.assertIsInstance(got, BigArray)
        self.assertEqual(list(got), [1, 2, 3])

    def test_bytes_containing_value_survives(self):
        # REGRESSION (base64-pickle bytes fix): silently failed to restore on py3 before the fix.
        # Must round-trip through SQLite, not the in-memory caches: write+flush here, then open a
        # FRESH HashDB on the same file (empty read/write caches) so retrieve() hits the disk path.
        value = {"raw": b"\x00\x01\xff", "items": [b"ab", "s", 1]}
        self.db.write("bytesval", value, True)
        self.db.flush()

        fresh = HashDB(self.path)
        try:
            # sanity: the value is genuinely not in the fresh in-memory caches
            self.assertFalse(fresh._write_cache)
            hash_ = HashDB.hashKey("bytesval")
            self.assertIsNone(fresh._read_cache.get(hash_))
            self.assertEqual(fresh.retrieve("bytesval", True), value)
        finally:
            fresh.closeAll()


class TestKeyHashing(_HashDBCase):
    def test_distinct_keys_distinct_hashes(self):
        # a broken hashKey that keys only on (say) length or the last char would collide; require
        # 200 distinct keys to map to 200 distinct hashes. (Determinism is implied: the retrieve
        # round-trips in TestScalar already depend on hashKey being stable.)
        keys = ["key_%d_%s" % (i, "abcdefgh"[i % 8]) for i in range(200)]
        hashes = set(HashDB.hashKey(k) for k in keys)
        self.assertEqual(len(hashes), len(keys), msg="hashKey produced collisions across distinct keys")


if __name__ == "__main__":
    unittest.main(verbosity=2)
