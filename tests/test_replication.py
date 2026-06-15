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


if __name__ == "__main__":
    unittest.main(verbosity=2)
