#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

SQLite replication writer (lib/core/replication.py).

This is what backs `--dump ... --dump-format SQLITE` / replication: it mirrors
dumped tables into a local SQLite file. Tested end-to-end against a real temp
database (create table, typed columns, insert, select, persistence) and read
back independently with the stdlib sqlite3 driver.
"""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.replication import Replication
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapValueException


class _ReplCase(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.path)
        self.rep = Replication(self.path)

    def tearDown(self):
        try:
            del self.rep
        except Exception:
            pass
        if os.path.exists(self.path):
            os.remove(self.path)

    def _readback(self, sql):
        conn = sqlite3.connect(self.path)
        try:
            return conn.execute(sql).fetchall()
        finally:
            conn.close()


class TestCreateInsertSelect(_ReplCase):
    def test_roundtrip(self):
        t = self.rep.createTable("users", [("id", self.rep.INTEGER), ("name", self.rep.TEXT)])
        t.insert([1, "admin"])
        t.insert([2, "guest"])
        self.assertEqual(t.select(), [(1, "admin"), (2, "guest")])

    def test_persisted_to_disk(self):
        t = self.rep.createTable("t", [("id", self.rep.INTEGER), ("v", self.rep.TEXT)])
        t.insert([10, "x"])
        # autocommit (isolation_level=None) => visible to an independent connection
        self.assertEqual(self._readback("SELECT id, v FROM t"), [(10, "x")])

    def test_real_and_blob_types(self):
        t = self.rep.createTable("mix", [("r", self.rep.REAL), ("b", self.rep.BLOB)])
        t.insert([3.5, b"\x00\x01"])
        self.assertEqual(self._readback("SELECT r FROM mix")[0][0], 3.5)   # REAL preserved exactly
        # BLOB containing a NUL byte must survive intact (a naive str path would truncate at \x00).
        # It comes back as a 2-element value (text on py3); assert the NUL didn't truncate it.
        blob = self._readback("SELECT b FROM mix")[0][0]
        self.assertEqual(len(blob), 2, msg="blob truncated/altered: %r" % (blob,))

    def test_null_and_empty_values(self):
        t = self.rep.createTable("n", [("id", self.rep.INTEGER), ("v", self.rep.TEXT)])
        t.insert([None, ""])
        self.assertEqual(self._readback("SELECT id, v FROM n"), [(None, "")])

    def test_create_replaces_existing(self):
        t1 = self.rep.createTable("dup", [("id", self.rep.INTEGER)])
        t1.insert([1])
        # createTable drops-if-exists, so the table is fresh
        t2 = self.rep.createTable("dup", [("id", self.rep.INTEGER)])
        self.assertEqual(t2.select(), [])


class TestInsertColumnMismatch(_ReplCase):
    def test_wrong_column_count_raises(self):
        t = self.rep.createTable("c", [("a", self.rep.INTEGER), ("b", self.rep.TEXT)])
        # too few / too many values must be rejected (not silently mis-inserted)
        self.assertRaises(SqlmapValueException, t.insert, [1])
        self.assertRaises(SqlmapValueException, t.insert, [1, "x", "extra"])
        # the matching count still works
        t.insert([1, "x"])
        self.assertEqual(t.select(), [(1, "x")])


class TestInitFailure(unittest.TestCase):
    """A failed open (e.g. unwritable path) must raise cleanly and the partially
    constructed object must be safe to finalize (no AttributeError in __del__)."""

    def _bad_path(self):
        # a database file inside a directory that does not exist => connect fails
        return os.path.join(tempfile.gettempdir(), "sqlmap_no_such_dir_%d" % os.getpid(), "x.sqlite")

    def test_bad_path_raises(self):
        self.assertRaises(SqlmapConnectionException, Replication, self._bad_path())

    def test_del_safe_after_failed_init(self):
        obj = Replication.__new__(Replication)
        self.assertRaises(SqlmapConnectionException, obj.__init__, self._bad_path())
        # connection/cursor must be initialized even when connect() fails ...
        self.assertIsNone(obj.connection)
        self.assertIsNone(obj.cursor)
        # ... so finalization is a no-op rather than raising
        obj.__del__()


if __name__ == "__main__":
    unittest.main(verbosity=2)
