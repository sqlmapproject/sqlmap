#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.data import kb
from lib.core.enums import DBMS
from lib.core.enums import FORK
from lib.parse.html import htmlParser


class TestHtmlParserForks(unittest.TestCase):
    def setUp(self):
        kb.forkNote = None
        kb.cache.parsedDbms.clear()

    def test_cockroachdb_error_fingerprint(self):
        page = "ERROR: at or near \"SELECT\": syntax error in CockroachDB pgwire/pgerror"
        dbms = htmlParser(page)
        self.assertEqual(dbms, DBMS.PGSQL)
        self.assertEqual(kb.forkNote, FORK.COCKROACHDB)

    def test_yugabytedb_error_fingerprint(self):
        page = "YugabyteDB ERROR: check the manual that corresponds to your YugabyteDB server version"
        dbms = htmlParser(page)
        self.assertEqual(dbms, DBMS.PGSQL)
        self.assertEqual(kb.forkNote, FORK.YUGABYTEDB)

    def test_opengauss_error_fingerprint(self):
        page = "openGauss ERROR: org.opengauss.util.PSQLException: syntax error"
        dbms = htmlParser(page)
        self.assertEqual(dbms, DBMS.PGSQL)
        self.assertEqual(kb.forkNote, FORK.OPENGAUSS)

    def test_duckdb_error_fingerprint(self):
        page = "org.duckdb.DuckDBException: duckdb.duckdb.ParserException: syntax error"
        dbms = htmlParser(page)
        self.assertEqual(dbms, DBMS.SQLITE)
        self.assertEqual(kb.forkNote, FORK.DUCKDB)

    def test_trino_error_fingerprint(self):
        page = "io.trino.jdbc.TrinoSQLException: line 1:1: mismatched input 'SELECT'"
        dbms = htmlParser(page)
        self.assertEqual(dbms, DBMS.PRESTO)
        self.assertEqual(kb.forkNote, FORK.TRINO)

    def test_doris_error_fingerprint(self):
        page = "check the manual that corresponds to your Apache Doris server version with org.apache.doris.qm"
        dbms = htmlParser(page)
        self.assertEqual(dbms, DBMS.MYSQL)
        self.assertEqual(kb.forkNote, FORK.DORIS)

    def test_starrocks_error_fingerprint(self):
        page = "check the manual that corresponds to your StarRocks server version with com.starrocks.sql"
        dbms = htmlParser(page)
        self.assertEqual(dbms, DBMS.MYSQL)
        self.assertEqual(kb.forkNote, FORK.STARROCKS)


if __name__ == "__main__":
    unittest.main()
