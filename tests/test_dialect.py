#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Per-DBMS query building (the injection-engine "dialect" layer).

These pin the exact SQL that agent.* emits for each back-end. They are the
regression net for queries.xml edits and for dialect gates in agent.py - the
kind of change that silently mis-builds a payload for one DBMS while leaving
every other green.

Includes the SYBASE limitQuery fix: Sybase must now emit a TOP-based limited
query like MSSQL (previously it fell through and returned the query unchanged).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.agent import agent
from lib.core.enums import DBMS


class TestLimitQuery(unittest.TestCase):
    """agent.limitQuery(num, query, field) per dialect (probed, not guessed)."""

    def test_mysql(self):
        set_dbms(DBMS.MYSQL)
        self.assertEqual(agent.limitQuery(0, "SELECT name FROM users", "name"),
                         "SELECT name FROM users LIMIT 0,1")

    def test_pgsql(self):
        set_dbms(DBMS.PGSQL)
        self.assertEqual(agent.limitQuery(0, "SELECT name FROM users", "name"),
                         "SELECT name FROM users OFFSET 0 LIMIT 1")

    def test_oracle(self):
        set_dbms(DBMS.ORACLE)
        self.assertEqual(agent.limitQuery(0, "SELECT name FROM users", "name"),
                         "SELECT name FROM (SELECT name,ROWNUM AS CAP FROM users) WHERE CAP=1")

    def test_mssql_is_top_based(self):
        set_dbms(DBMS.MSSQL)
        q = agent.limitQuery(0, "SELECT name FROM users", "name")
        self.assertTrue(q.startswith("SELECT TOP 1 name FROM users WHERE"), msg=q)
        self.assertIn("ORDER BY 1", q)

    def test_sybase_limit_fix_is_top_based(self):
        # REGRESSION: the user's limitQuery fix. Sybase must now produce a TOP-based
        # limited query (mirroring MSSQL), NOT the query returned unchanged.
        set_dbms(DBMS.SYBASE)
        q = agent.limitQuery(0, "SELECT name FROM users", "name")
        self.assertTrue(q.startswith("SELECT TOP 1 name FROM users WHERE"), msg=q)
        self.assertIn("ORDER BY 1", q)
        self.assertNotEqual(q, "SELECT name FROM users")   # the pre-fix (broken) behavior
        # Sybase casts via CONVERT(VARCHAR(...)), distinguishing it from MSSQL's NVARCHAR
        self.assertIn("CONVERT(VARCHAR", q)


class TestNullAndCastField(unittest.TestCase):
    """agent.nullAndCastField('col') differs per dialect - pin each."""

    CASES = {
        DBMS.MYSQL:  "IFNULL(CAST(col AS NCHAR),' ')",
        DBMS.MSSQL:  "ISNULL(CAST(col AS NVARCHAR(4000)),' ')",
        DBMS.SYBASE: "ISNULL(CONVERT(VARCHAR(4000),col),' ')",
        DBMS.PGSQL:  "COALESCE(CAST(col AS VARCHAR(10000))::text,' ')",
        DBMS.ORACLE: "NVL(CAST(col AS VARCHAR(4000)),' ')",
    }

    def test_per_dbms(self):
        for dbms, expected in self.CASES.items():
            set_dbms(dbms)
            self.assertEqual(agent.nullAndCastField("col"), expected, msg="nullAndCastField for %s" % dbms)


class TestHexConvertField(unittest.TestCase):
    # hexConvertField differs per dialect; pin each (was a one-platform stub before)
    CASES = {
        DBMS.MYSQL:  "HEX(name)",
        DBMS.ORACLE: "RAWTOHEX(name)",
        DBMS.PGSQL:  "ENCODE(CONVERT_TO((name),'UTF8'),'HEX')",
        DBMS.MSSQL:  "master.dbo.fn_varbintohexstr(CAST(name AS VARBINARY(8000)))",
    }

    def test_per_dbms(self):
        for dbms, expected in self.CASES.items():
            set_dbms(dbms)
            self.assertEqual(agent.hexConvertField("name"), expected, msg="hexConvertField for %s" % dbms)


class TestForgeUnionQuery(unittest.TestCase):
    def test_position_and_count(self):
        # count=3, position=1 -> the real column is slotted at index 1, NULLs elsewhere
        set_dbms(DBMS.MYSQL)
        q = agent.forgeUnionQuery("SELECT a FROM t", 1, 3, None, "", "", "NULL", None)
        self.assertEqual(q, " UNION ALL SELECT NULL,a,NULL FROM t")


if __name__ == "__main__":
    unittest.main(verbosity=2)
