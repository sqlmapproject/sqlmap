#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit tests for plugins/generic/search.py (Search) and plugins/generic/entries.py
(Entries), exercising searchDb / searchTable / searchColumn and dumpTable by
MOCKING the injection layer (lib.request.inject.getValue) and the dumper.

No network and no DBMS are involved: conf.direct=True selects the simple inband
branches, inject.getValue is patched to return canned rows in the exact shape the
methods parse, and conf.dumper is replaced with a recording stub so we can assert
on what each method produced (kb.data caches / returned dicts).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms

bootstrap()

from lib.core.data import conf, kb
import plugins.generic.search as smod
import plugins.generic.entries as emod
from plugins.generic.search import Search
from plugins.generic.entries import Entries


class _RecordingDumper(object):
    """Minimal stand-in for conf.dumper that records calls instead of printing/writing."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.listed = []          # (header, elements)
        self.dbTablesArg = None
        self.dbColumnsArg = None
        self.dbTableColumnsArg = None
        self.tableValues = []

    def lister(self, header, elements, content_type=None, sort=True):
        self.listed.append((header, list(elements) if elements else []))

    def dbTables(self, dbTables):
        self.dbTablesArg = dbTables

    def dbColumns(self, dbColumnsDict, colConsider, dbs):
        self.dbColumnsArg = (dbColumnsDict, colConsider, dbs)

    def dbTableColumns(self, tableColumns, content_type=None):
        self.dbTableColumnsArg = tableColumns

    def dbTableValues(self, tableValues):
        self.tableValues.append(tableValues)


class _TestSearch(Search):
    """Search with the cross-mixin collaborators it relies on stubbed out.

    The real Search lives in a multiple-inheritance hierarchy; in isolation we
    must supply likeOrExact/forceDbmsEnum/getCurrentDb/getColumns/dumpFoundTables/
    excludeDbsList, mirroring the inputs the production mixins would provide.
    """

    excludeDbsList = ["information_schema", "mysql"]

    def __init__(self):
        Search.__init__(self)
        self.like = ('1', " LIKE '%%%s%%'")
        self.dumpFoundTablesCalls = []
        self.dumpFoundColumnCalls = []
        self.getColumnsCalls = []
        self._cannedColumns = {}

    def likeOrExact(self, what):
        return self.like

    def forceDbmsEnum(self):
        pass

    def getCurrentDb(self):
        return "testdb"

    def dumpFoundTables(self, tables):
        self.dumpFoundTablesCalls.append(tables)

    def dumpFoundColumn(self, dbs, foundCols, colConsider):
        self.dumpFoundColumnCalls.append((dbs, foundCols, colConsider))

    def getColumns(self, onlyColNames=False, colTuple=None, bruteForce=None, dumpMode=False):
        # Emulate column discovery by populating kb.data.cachedColumns for the
        # currently-targeted conf.db/conf.tbl/conf.col, as the real plugin does.
        self.getColumnsCalls.append((conf.db, conf.tbl, conf.col))
        db, tbl, col = conf.db, conf.tbl, conf.col
        if db and tbl:
            kb.data.cachedColumns.setdefault(db, {}).setdefault(tbl, {})
            kb.data.cachedColumns[db][tbl][col] = "varchar"


class _TestEntries(Entries):
    """Entries with cross-mixin collaborators stubbed (forceDbmsEnum/getCurrentDb/getColumns/getTables)."""

    def __init__(self):
        Entries.__init__(self)
        self.getColumnsResult = {}    # {db: {tbl: {col: type}}}
        self.getTablesResult = {}     # value assigned to kb.data.cachedTables
        self.getColumnsCalls = []

    def forceDbmsEnum(self):
        pass

    def getCurrentDb(self):
        return "testdb"

    def getColumns(self, onlyColNames=False, colTuple=None, bruteForce=None, dumpMode=False):
        self.getColumnsCalls.append((conf.db, conf.tbl))
        kb.data.cachedColumns = dict(self.getColumnsResult)

    def getTables(self, bruteForce=None):
        kb.data.cachedTables = dict(self.getTablesResult)


class _SearchEnumBase(unittest.TestCase):
    def setUp(self):
        # Save mutated globals
        self._saved_conf = {k: conf.get(k) for k in (
            "db", "tbl", "col", "direct", "excludeSysDbs", "exclude", "search",
            "disableHashing", "noKeyset", "keyset", "forcePivoting",
        )}
        self._saved_dumper = conf.get("dumper")
        self._search_getValue = smod.inject.getValue
        self._entries_getValue = emod.inject.getValue
        self._search_readInput = smod.readInput
        self._entries_readInput = emod.readInput
        self._saved_has_is = kb.data.get("has_information_schema")
        self._saved_cachedColumns = kb.data.get("cachedColumns")
        self._saved_cachedTables = kb.data.get("cachedTables")
        self._saved_dumpedTable = kb.data.get("dumpedTable")
        self._saved_dumpKbInt = kb.get("dumpKeyboardInterrupt")
        self._saved_permissionFlag = kb.get("permissionFlag")

        set_dbms("MySQL")
        conf.direct = True
        conf.excludeSysDbs = False
        conf.exclude = None
        conf.search = True
        conf.disableHashing = True
        conf.noKeyset = True
        conf.keyset = False
        conf.forcePivoting = False
        conf.dumper = _RecordingDumper()

        kb.data.has_information_schema = True
        kb.data.cachedColumns = {}
        kb.data.cachedTables = {}
        kb.data.dumpedTable = {}
        kb.dumpKeyboardInterrupt = False
        kb.permissionFlag = False

        # Non-interactive prompts: collapse readInput to its default.
        def _readInput(message, default=None, checkBatch=True, boolean=False):
            if boolean:
                return True if (default in (None, 'Y', 'y', True)) else False
            return default
        smod.readInput = _readInput
        emod.readInput = _readInput

    def tearDown(self):
        for k, v in self._saved_conf.items():
            conf[k] = v
        conf.dumper = self._saved_dumper
        smod.inject.getValue = self._search_getValue
        emod.inject.getValue = self._entries_getValue
        smod.readInput = self._search_readInput
        emod.readInput = self._entries_readInput
        kb.data.has_information_schema = self._saved_has_is
        kb.data.cachedColumns = self._saved_cachedColumns
        kb.data.cachedTables = self._saved_cachedTables
        kb.data.dumpedTable = self._saved_dumpedTable
        kb.dumpKeyboardInterrupt = self._saved_dumpKbInt
        kb.permissionFlag = self._saved_permissionFlag


class TestSearch(_SearchEnumBase):
    # --- searchDb -----------------------------------------------------------

    def test_search_db_found(self):
        s = _TestSearch()
        conf.db = "testdb"
        # Feed identifiers that REQUIRE normalization: "select" is a reserved
        # keyword and "weird db" contains a space; both force MySQL backtick
        # quoting via safeSQLIdentificatorNaming. The plain "testdb" passes
        # through unchanged. Asserting the quoted output proves the transform ran
        # (a mock-echo would surface the raw, unquoted inputs instead).
        smod.inject.getValue = lambda *a, **k: ["select", "weird db", "testdb"]

        s.searchDb()

        self.assertEqual(conf.dumper.listed[-1][0], "found databases")
        self.assertEqual(conf.dumper.listed[-1][1], ["`select`", "`weird db`", "testdb"])

    def test_search_db_multiple_terms(self):
        s = _TestSearch()
        conf.db = "foo,bar"

        # Return a DISTINCT value per search term by keying off the query string:
        # each term is folded into the generated query (search_db inband query),
        # so "foo" vs "bar" produce different queries. This proves the method
        # actually iterates over both terms and records the right match for each,
        # rather than appending the same constant twice.
        def gv(query, *a, **k):
            if "foo" in query:
                return "foo_db"
            elif "bar" in query:
                return "bar_db"
            return None

        smod.inject.getValue = gv
        s.searchDb()
        # Two search terms => one distinct value found per term, in order.
        self.assertEqual(conf.dumper.listed[-1][1], ["foo_db", "bar_db"])

    def test_search_db_none_value(self):
        s = _TestSearch()
        conf.db = "nope"
        smod.inject.getValue = lambda *a, **k: None
        s.searchDb()
        self.assertEqual(conf.dumper.listed[-1][1], [])

    def test_search_db_exclude_sys_dbs(self):
        s = _TestSearch()
        conf.db = "testdb"
        conf.excludeSysDbs = True
        seen = {}

        def gv(query, *a, **k):
            seen["query"] = query
            return ["testdb"]
        smod.inject.getValue = gv

        s.searchDb()
        # The exclusion clause for each system DB must be folded into the query.
        self.assertIn("information_schema", seen["query"])
        self.assertEqual(conf.dumper.listed[-1][1], ["testdb"])

    # --- searchTable --------------------------------------------------------

    def test_search_table_found_grouped_by_db(self):
        s = _TestSearch()
        conf.tbl = "users"
        conf.db = None
        smod.inject.getValue = lambda *a, **k: [["testdb", "users"], ["otherdb", "users"]]

        s.searchTable()

        self.assertEqual(conf.dumper.dbTablesArg, {"testdb": ["users"], "otherdb": ["users"]})
        # dumpFoundTables is invoked with the same mapping.
        self.assertEqual(s.dumpFoundTablesCalls[-1], {"testdb": ["users"], "otherdb": ["users"]})

    def test_search_table_with_db_filter(self):
        s = _TestSearch()
        conf.tbl = "users"
        conf.db = "testdb"
        captured = {}

        def gv(query, *a, **k):
            captured["query"] = query
            return [["testdb", "users"]]
        smod.inject.getValue = gv

        s.searchTable()
        # conf.db present => a WHERE clause restricting to that db is appended.
        self.assertIn("testdb", captured["query"])
        self.assertEqual(conf.dumper.dbTablesArg, {"testdb": ["users"]})

    def test_search_table_none_found(self):
        s = _TestSearch()
        conf.tbl = "ghost"
        conf.db = None
        smod.inject.getValue = lambda *a, **k: None
        s.searchTable()
        # No tables => dbTables/dumpFoundTables never called.
        self.assertIsNone(conf.dumper.dbTablesArg)
        self.assertEqual(s.dumpFoundTablesCalls, [])

    # --- searchColumn -------------------------------------------------------

    def test_search_column_db_and_tbl_provided(self):
        s = _TestSearch()
        conf.col = "password"
        conf.db = "testdb"
        conf.tbl = "users"
        # With both db & tbl set, searchColumn does NOT call inject for table
        # discovery; it assumes the provided db/tbl and calls getColumns.
        smod.inject.getValue = lambda *a, **k: self.fail("getValue should not be called")

        s.searchColumn()

        self.assertEqual(conf.dumper.dbColumnsArg[1], '1')          # colConsider
        dbs = conf.dumper.dbColumnsArg[2]
        self.assertIn("testdb", dbs)
        self.assertIn("users", dbs["testdb"])
        self.assertIn("password", dbs["testdb"]["users"])
        self.assertEqual(s.dumpFoundColumnCalls[-1][2], '1')
        # getColumns was consulted for the assumed db/tbl/col.
        self.assertIn(("testdb", "users", "password"), s.getColumnsCalls)

    def test_search_column_enumerate_tables(self):
        s = _TestSearch()
        conf.col = "password"
        conf.db = None
        conf.tbl = None
        # db & tbl missing => inject returns (db, table) pairs to scan.
        smod.inject.getValue = lambda *a, **k: [["testdb", "users"]]

        s.searchColumn()

        dbs = conf.dumper.dbColumnsArg[2]
        self.assertIn("testdb", dbs)
        self.assertIn("users", dbs["testdb"])
        # The requested column must have actually landed under the discovered
        # db/table (getColumns populated kb.data.cachedColumns, which searchColumn
        # folds into dbs); db/table presence alone wouldn't prove that.
        self.assertIn("password", dbs["testdb"]["users"])

    def test_search_column_none_found(self):
        s = _TestSearch()
        conf.col = "password"
        conf.db = None
        conf.tbl = None
        smod.inject.getValue = lambda *a, **k: None
        s.searchColumn()
        # Nothing discovered => dumper.dbColumns not called.
        self.assertIsNone(conf.dumper.dbColumnsArg)

    # --- search() dispatcher ------------------------------------------------

    def test_search_dispatch_to_column(self):
        s = _TestSearch()
        conf.col = "password"
        conf.tbl = "users"
        conf.db = "testdb"
        smod.inject.getValue = lambda *a, **k: None
        # Should route to searchColumn (col takes precedence). With db & tbl both
        # provided, searchColumn assumes them and consults getColumns for the
        # requested db/tbl/col -> at least one recorded call, matching the request.
        s.search()
        self.assertGreaterEqual(len(s.getColumnsCalls), 1)
        self.assertIn(("testdb", "users", "password"), s.getColumnsCalls)

    def test_search_dispatch_missing_param(self):
        s = _TestSearch()
        conf.col = None
        conf.tbl = None
        conf.db = None
        from lib.core.exception import SqlmapMissingMandatoryOptionException
        self.assertRaises(SqlmapMissingMandatoryOptionException, s.search)


class TestEntries(_SearchEnumBase):
    def _entries_with_cols(self, db="testdb", tbl="users", cols=("id", "name")):
        e = _TestEntries()
        e.getColumnsResult = {db: {tbl: {c: "varchar" for c in cols}}}
        return e

    # --- dumpTable: inband (conf.direct) ------------------------------------

    def test_dump_table_inband_rows(self):
        e = self._entries_with_cols(cols=("id", "name"))
        conf.db = "testdb"
        conf.tbl = "users"
        conf.col = None
        # MySQL inband dump returns a list of [colVal, colVal] rows.
        emod.inject.getValue = lambda *a, **k: [["1", "alice"], ["2", "bob"]]

        e.dumpTable()

        dumped = conf.dumper.tableValues[-1]
        self.assertEqual(dumped["__infos__"]["count"], 2)
        self.assertEqual(dumped["__infos__"]["table"], "users")
        self.assertEqual(dumped["__infos__"]["db"], "testdb")
        self.assertEqual(list(dumped["id"]["values"]), ["1", "2"])
        self.assertEqual(list(dumped["name"]["values"]), ["alice", "bob"])

    def test_dump_table_uses_foundData(self):
        e = _TestEntries()
        conf.db = "testdb"
        conf.tbl = "users"
        conf.col = None
        emod.inject.getValue = lambda *a, **k: [["x"]]
        foundData = {"testdb": {"users": {"id": "int"}}}

        e.dumpTable(foundData=foundData)

        # foundData short-circuits column discovery: getColumns must not run.
        self.assertEqual(e.getColumnsCalls, [])
        self.assertIn("id", conf.dumper.tableValues[-1])

    def test_dump_table_no_columns_skips(self):
        e = _TestEntries()
        e.getColumnsResult = {}     # discovery yields nothing
        conf.db = "testdb"
        conf.tbl = "ghost"
        conf.col = None
        emod.inject.getValue = lambda *a, **k: self.fail("should not fetch entries")

        e.dumpTable()
        # No columns => no values dumped.
        self.assertEqual(conf.dumper.tableValues, [])

    def test_dump_table_empty_entries(self):
        e = self._entries_with_cols(cols=("id",))
        conf.db = "testdb"
        conf.tbl = "users"
        conf.col = None
        emod.inject.getValue = lambda *a, **k: None     # no rows

        e.dumpTable()
        # Nothing retrieved => dumpedTable empty => dbTableValues not called.
        self.assertEqual(conf.dumper.tableValues, [])

    def test_dump_table_current_db(self):
        e = self._entries_with_cols(db="testdb", tbl="users", cols=("id",))
        conf.db = None              # triggers getCurrentDb() -> "testdb"
        conf.tbl = "users"
        conf.col = None
        emod.inject.getValue = lambda *a, **k: [["7"]]

        e.dumpTable()
        self.assertEqual(conf.db, "testdb")
        self.assertEqual(list(conf.dumper.tableValues[-1]["id"]["values"]), ["7"])

    def test_dump_table_multiple_db_error(self):
        e = _TestEntries()
        conf.db = "a,b"
        conf.tbl = "users"
        conf.col = None
        from lib.core.exception import SqlmapMissingMandatoryOptionException
        self.assertRaises(SqlmapMissingMandatoryOptionException, e.dumpTable)

    def test_dump_table_get_tables_when_no_tbl(self):
        e = _TestEntries()
        e.getTablesResult = {"testdb": ["users"]}
        e.getColumnsResult = {"testdb": {"users": {"id": "int"}}}
        conf.db = "testdb"
        conf.tbl = None
        conf.col = None
        emod.inject.getValue = lambda *a, **k: [["42"]]

        e.dumpTable()
        # Tables were discovered via getTables, then the row dumped.
        self.assertEqual(list(conf.dumper.tableValues[-1]["id"]["values"]), ["42"])

    # --- dumpAll: single-db delegation --------------------------------------

    def test_dump_all_single_db_delegates(self):
        e = self._entries_with_cols(db="testdb", tbl="users", cols=("id",))
        # dumpAll with db set & tbl None must delegate straight to dumpTable.
        conf.db = "testdb"
        conf.tbl = None
        conf.col = None
        e.getTablesResult = {"testdb": ["users"]}
        emod.inject.getValue = lambda *a, **k: [["9"]]

        e.dumpAll()
        self.assertTrue(conf.dumper.tableValues)


if __name__ == "__main__":
    unittest.main()
