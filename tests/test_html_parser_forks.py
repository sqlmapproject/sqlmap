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

    # NOTE: these forks all speak the PostgreSQL wire protocol and inherit its error wording, so
    # the brand name itself never appears next to 'ERROR:' - only a leaked driver package or an
    # engine-internal source reference tells them apart from stock PostgreSQL
    def test_cockroachdb_error_fingerprint(self):
        for page in (
            "ERROR: relation \"crdb_internal.tables\" does not exist",
            "DETAIL: stack trace: github.com/cockroachdb/cockroach/pkg/sql/conn_executor.go:733",
        ):
            kb.forkNote = None
            kb.cache.parsedDbms.clear()
            self.assertEqual(htmlParser(page), DBMS.PGSQL)
            self.assertEqual(kb.forkNote, FORK.COCKROACHDB)

    def test_yugabytedb_error_fingerprint(self):
        for page in (
            "com.yugabyte.util.PSQLException: ERROR: syntax error at or near \"'\"",
            "ERROR:  Query error: [Query error (yb/tserver/read_query.cc:265): MISMATCHED_SCHEMA]",
        ):
            kb.forkNote = None
            kb.cache.parsedDbms.clear()
            self.assertEqual(htmlParser(page), DBMS.PGSQL)
            self.assertEqual(kb.forkNote, FORK.YUGABYTEDB)

    def test_opengauss_error_fingerprint(self):
        page = "org.opengauss.util.PSQLException: ERROR: syntax error at or near \"'\""
        dbms = htmlParser(page)
        self.assertEqual(dbms, DBMS.PGSQL)
        self.assertEqual(kb.forkNote, FORK.OPENGAUSS)

    def test_duckdb_error_fingerprint(self):
        # Messages below are verbatim from DuckDB 1.1.3/1.5.5 (the module was renamed
        #'duckdb.duckdb' -> '_duckdb')
        for page in (
            "_duckdb.ParserException: Parser Error: unterminated quoted string at or near \"'''\"",
            "duckdb.duckdb.CatalogException: Catalog Error: Table with name t does not exist!",
            "_duckdb.BinderException: Binder Error: Referenced column \"x\" not found in FROM clause!",
            "at org.duckdb.DuckDBPreparedStatement.execute(DuckDBPreparedStatement.java:180)",
        ):
            kb.forkNote = None
            kb.cache.parsedDbms.clear()
            self.assertEqual(htmlParser(page), DBMS.PGSQL)
            self.assertEqual(kb.forkNote, FORK.DUCKDB)

    def test_trino_error_fingerprint(self):
        # the generic Presto 'mismatched input' entry also matches, so this pins the ordering
        # that keeps the Trino fork note from being swallowed by it
        page = "io.trino.jdbc.TrinoSQLException: line 1:15: mismatched input 'FROM'. Expecting: <expression>"
        dbms = htmlParser(page)
        self.assertEqual(dbms, DBMS.PRESTO)
        self.assertEqual(kb.forkNote, FORK.TRINO)

    def test_doris_error_fingerprint(self):
        # Doris speaks the MySQL wire protocol, so the client-side exception is MySQL's own -
        # only the leaked FE package name tells the fork apart
        page = "com.mysql.jdbc.exceptions.MySQLSyntaxErrorException at org.apache.doris.qe.ConnectProcessor"
        dbms = htmlParser(page)
        self.assertEqual(dbms, DBMS.MYSQL)
        self.assertEqual(kb.forkNote, FORK.DORIS)

    def test_starrocks_error_fingerprint(self):
        for page in (
            "com.mysql.jdbc.exceptions.MySQLSyntaxErrorException at com.starrocks.qe.ConnectProcessor",
            "(1064, 'Getting syntax error from line 1, column 7 to line 1, column 62. Detail message: x.')",
        ):
            kb.forkNote = None
            kb.cache.parsedDbms.clear()
            self.assertEqual(htmlParser(page), DBMS.MYSQL)
            self.assertEqual(kb.forkNote, FORK.STARROCKS)


if __name__ == "__main__":
    unittest.main()
