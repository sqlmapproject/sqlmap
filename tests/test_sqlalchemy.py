#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

The SQLAlchemy '-d' connector wrapper (lib/utils/sqlalchemy.py). The absolute
SQLite path must map to 'sqlite:///' + abspath: an extra slash yields the db
'//path' (tolerated only on Linux by accident) and, on Windows, a broken
'/C:\\...' that fails to open.
"""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

try:
    import sqlalchemy as _sa
    _HAVE_SA = hasattr(_sa, "dialects")
except ImportError:
    _HAVE_SA = False

from lib.core.data import conf
from lib.utils.sqlalchemy import SQLAlchemy


@unittest.skipUnless(_HAVE_SA, "SQLAlchemy not installed")
class TestSQLAlchemySqlitePath(unittest.TestCase):
    _KEYS = ("direct", "dbmsUser", "dbmsPass", "hostname", "port", "dbmsDb")

    def setUp(self):
        self._saved = dict((k, conf.get(k)) for k in self._KEYS)

    def tearDown(self):
        for k, v in self._saved.items():
            conf[k] = v

    def test_absolute_sqlite_path_opens_correct_file(self):
        d = tempfile.mkdtemp(prefix="sqlmap-sa-test")
        dbfile = os.path.join(d, "target.db")
        con = sqlite3.connect(dbfile)
        con.execute("CREATE TABLE t (x TEXT)")
        con.execute("INSERT INTO t VALUES ('secret')")
        con.commit()
        con.close()

        conf.direct = "sqlite://%s" % dbfile
        conf.dbmsUser = conf.dbmsPass = None
        conf.hostname = None
        conf.port = None
        conf.dbmsDb = dbfile

        sa = SQLAlchemy(dialect="sqlite")
        sa.connect()

        # the reformatted URL must resolve to the exact absolute file (not '//...path')
        self.assertEqual(_sa.engine.url.make_url(sa.address).database, os.path.abspath(dbfile))
        # and end-to-end it must read from that file
        self.assertEqual(sa.select("SELECT x FROM t"), [("secret",)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
