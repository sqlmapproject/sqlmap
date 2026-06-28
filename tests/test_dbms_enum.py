#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

DBMS-specific enumeration overrides (plugins/dbms/<dbms>/enumeration.py),
driven through each full DBMS handler with the injection layer mocked, so the
dialect-specific table/column discovery paths run without a live target. The
in-band (UNION/error/direct) branch is taken via conf.direct=True and
inject.getValue is stubbed with canned result rows.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.data import conf, kb
from lib.core.enums import EXPECTED


class _EnumBase(unittest.TestCase):
    """Snapshot/restore the global state these enumerators mutate."""
    module = None  # the enumeration module whose inject.getValue we patch

    def setUp(self):
        self._direct = conf.direct
        self._db = conf.db
        self._gv = self.module.inject.getValue
        self._cachedTables = kb.data.get("cachedTables")
        self._cachedColumns = kb.data.get("cachedColumns")
        conf.direct = True
        kb.data.cachedTables = {}
        kb.data.cachedColumns = {}

    def tearDown(self):
        conf.direct = self._direct
        conf.db = self._db
        self.module.inject.getValue = self._gv
        kb.data.cachedTables = self._cachedTables
        kb.data.cachedColumns = self._cachedColumns


class TestMSSQLServerEnum(_EnumBase):
    import plugins.dbms.mssqlserver.enumeration as module

    def _handler(self):
        from plugins.dbms.mssqlserver import MSSQLServerMap
        set_dbms("Microsoft SQL Server")
        return MSSQLServerMap()

    def test_get_tables(self):
        # one database (conf.db), single-column rows: getTables keys the cache by
        # the db loop variable and stores the rows run through
        # arrayize -> unArrayize -> safeSQLIdentificatorNaming -> sorted().
        conf.db = "appdb"
        self.module.inject.getValue = lambda q, *a, **k: (
            3 if k.get("expected") == EXPECTED.INT else [["users"], ["products"], ["customers"]]
        )
        self._handler().getTables()
        tables = kb.data.cachedTables
        self.assertEqual(list(tables.keys()), ["appdb"])
        stored = tables["appdb"]
        # value is a real sorted list (the final sort step), not an echo of input
        self.assertEqual(stored, sorted(stored))
        # MSSQL qualifies bare names with the dbo schema; assert exact membership
        self.assertIn("dbo.users", stored)
        self.assertEqual(stored, ["dbo.customers", "dbo.products", "dbo.users"])

    def test_get_tables_multiple_dbs(self):
        # exercise the per-database keying with two DBs (conf.db = "a,b"): each db
        # in the loop gets its OWN sorted table list. Rows are single-column;
        # unArrayizeValue collapses each 1-tuple row to the scalar table name.
        conf.db = "appdb,salesdb"

        def getValue(q, *a, **k):
            if k.get("expected") == EXPECTED.INT:
                return 3
            # the query carries the db name (%s substituted); route per database
            if "appdb" in q:
                return [["users"], ["sessions"], ["accounts"]]
            return [["orders"], ["invoices"]]

        self.module.inject.getValue = getValue
        self._handler().getTables()
        tables = kb.data.cachedTables
        # exactly the two requested databases, each mapped to its own sorted list
        self.assertEqual(sorted(tables.keys()), ["appdb", "salesdb"])
        self.assertEqual(tables["appdb"], ["dbo.accounts", "dbo.sessions", "dbo.users"])
        self.assertEqual(tables["salesdb"], ["dbo.invoices", "dbo.orders"])


if __name__ == "__main__":
    unittest.main()
