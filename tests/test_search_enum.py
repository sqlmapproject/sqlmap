#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit tests for plugins/generic/search.py (Search), exercising searchDb /
searchTable / searchColumn by MOCKING the injection layer
(lib.request.inject.getValue) and the dumper.

No network and no DBMS are involved: conf.direct=True selects the simple inband
branches (TestSearch), or conf.direct=False with a BOOLEAN injection state selects
the inference branches (TestSearchInference); inject.getValue is patched to return
canned rows in the exact shape the methods parse, and conf.dumper is replaced with
a recording stub so we can assert on what each method produced.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms

bootstrap()

from lib.core.data import conf, kb
from lib.core.enums import EXPECTED, PAYLOAD
import plugins.generic.search as smod
import plugins.generic.entries as emod
from plugins.generic.search import Search


def _inference_gv(count, sequence):
    """Build an inject.getValue stub for blind inference branches.

    Returns `count` (as str) whenever the caller asks for EXPECTED.INT, otherwise
    yields the next item from `sequence` wrapped as a single-cell row ([value]),
    cycling if exhausted. This mirrors the count-then-per-row contract of every
    isInferenceAvailable() branch.
    """
    state = {"i": 0}

    def gv(query, *a, **k):
        if k.get("expected") == EXPECTED.INT:
            return str(count)
        val = sequence[state["i"] % len(sequence)]
        state["i"] += 1
        return [val]

    return gv


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


# --------------------------------------------------------------------------- #
# search.py - inference (blind) paths
# --------------------------------------------------------------------------- #

class _TestSearchInf(Search):
    excludeDbsList = ["information_schema", "mysql"]

    def __init__(self):
        Search.__init__(self)
        self.like = ('2', "='%s'")     # exact match (colConsider '2')
        self.dumpFoundTablesCalls = []
        self.dumpFoundColumnCalls = []

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
        db, tbl, col = conf.db, conf.tbl, conf.col
        if db and tbl:
            kb.data.cachedColumns.setdefault(db, {}).setdefault(tbl, {})
            kb.data.cachedColumns[db][tbl][col] = "varchar"


class _RecDumper(object):
    def __init__(self):
        self.listed = []
        self.dbTablesArg = None
        self.dbColumnsArg = None

    def lister(self, header, elements, content_type=None, sort=True):
        self.listed.append((header, list(elements) if elements else []))

    def dbTables(self, dbTables):
        self.dbTablesArg = dbTables

    def dbColumns(self, dbColumnsDict, colConsider, dbs):
        self.dbColumnsArg = (dbColumnsDict, colConsider, dbs)


class _SearchBase(unittest.TestCase):
    _CONF_KEYS = ("db", "tbl", "col", "direct", "technique", "excludeSysDbs",
                  "exclude", "search")

    def setUp(self):
        self._saved_conf = {k: conf.get(k) for k in self._CONF_KEYS}
        self._saved_dumper = conf.get("dumper")
        self._gv = smod.inject.getValue
        self._readInput = smod.readInput
        self._saved_has_is = kb.data.get("has_information_schema")
        self._saved_cachedColumns = kb.data.get("cachedColumns")
        self._saved_hintValue = kb.get("hintValue")
        self._saved_injection_data = kb.injection.data

        set_dbms("MySQL")
        conf.direct = False
        conf.technique = None
        conf.excludeSysDbs = False
        conf.exclude = None
        conf.search = True
        conf.dumper = _RecDumper()

        kb.data.has_information_schema = True
        kb.data.cachedColumns = {}
        kb.injection.data = {PAYLOAD.TECHNIQUE.BOOLEAN: {"title": "AND boolean-based blind"}}

    def tearDown(self):
        for k, v in self._saved_conf.items():
            conf[k] = v
        conf.dumper = self._saved_dumper
        smod.inject.getValue = self._gv
        smod.readInput = self._readInput
        kb.data.has_information_schema = self._saved_has_is
        kb.data.cachedColumns = self._saved_cachedColumns
        kb.hintValue = self._saved_hintValue
        kb.injection.data = self._saved_injection_data


class TestSearchInference(_SearchBase):
    def test_search_db_inference(self):
        # Blind searchDb: count of matching dbs, then one db name per index.
        s = _TestSearchInf()
        conf.db = "testdb"
        smod.inject.getValue = _inference_gv(2, ["testdb", "testdb2"])
        s.searchDb()
        self.assertEqual(conf.dumper.listed[-1][0], "found databases")
        self.assertEqual(sorted(conf.dumper.listed[-1][1]), ["testdb", "testdb2"])

    def test_search_db_inference_no_match(self):
        # Count fails (non-numeric) => no databases appended, empty listing.
        s = _TestSearchInf()
        conf.db = "ghost"
        smod.inject.getValue = lambda query, *a, **k: (None if k.get("expected") == EXPECTED.INT else self.fail("must not page when count fails"))
        s.searchDb()
        self.assertEqual(conf.dumper.listed[-1][1], [])

    def test_search_table_inference_grouped(self):
        # Blind searchTable, no conf.db: outer count of dbs holding the table, then
        # per-db a name, then per-db a count of matching tables, then table names.
        s = _TestSearchInf()
        conf.tbl = "users"
        conf.db = None

        # Sequencing by the EXPECTED.INT counts + the per-index string results.
        # 1st count: number of databases with the table -> 1
        # 1st db name -> "testdb"
        # 2nd count: number of tables in testdb -> 1
        # table name -> "users"
        seq = {"counts": ["1", "1"], "ci": 0, "vals": ["testdb", "users"], "vi": 0}

        def gv(query, *a, **k):
            if k.get("expected") == EXPECTED.INT:
                v = seq["counts"][seq["ci"] % len(seq["counts"])]
                seq["ci"] += 1
                return v
            v = seq["vals"][seq["vi"] % len(seq["vals"])]
            seq["vi"] += 1
            return [v]

        smod.inject.getValue = gv
        s.searchTable()
        self.assertEqual(conf.dumper.dbTablesArg, {"testdb": ["users"]})
        self.assertEqual(s.dumpFoundTablesCalls[-1], {"testdb": ["users"]})

    def test_search_table_mysql_lt5_bruteforce_decline(self):
        # MySQL < 5 forces the bruteforce path; declining the prompt returns None
        # without any injection.
        s = _TestSearchInf()
        conf.tbl = "users"
        conf.db = None
        kb.data.has_information_schema = False
        smod.readInput = lambda *a, **k: "N"
        smod.inject.getValue = lambda *a, **k: self.fail("bruteforce decline must not query")
        self.assertIsNone(s.searchTable())

    def test_search_column_inference(self):
        # Blind searchColumn, no db/tbl: count of dbs with the column, then db name;
        # then per-db count of tables with the column, then table name -> getColumns
        # folds the column into dbs.
        s = _TestSearchInf()
        conf.col = "password"
        conf.db = None
        conf.tbl = None

        seq = {"counts": ["1", "1"], "ci": 0, "vals": ["testdb", "users"], "vi": 0}

        def gv(query, *a, **k):
            if k.get("expected") == EXPECTED.INT:
                v = seq["counts"][seq["ci"] % len(seq["counts"])]
                seq["ci"] += 1
                return v
            v = seq["vals"][seq["vi"] % len(seq["vals"])]
            seq["vi"] += 1
            return [v]

        smod.inject.getValue = gv
        s.searchColumn()
        dbs = conf.dumper.dbColumnsArg[2]
        self.assertIn("testdb", dbs)
        self.assertIn("users", dbs["testdb"])
        self.assertIn("password", dbs["testdb"]["users"])

    def test_search_column_mysql_lt5_bruteforce_decline(self):
        s = _TestSearchInf()
        conf.col = "password"
        conf.db = None
        conf.tbl = None
        kb.data.has_information_schema = False
        smod.readInput = lambda *a, **k: "N"
        smod.inject.getValue = lambda *a, **k: self.fail("bruteforce decline must not query")
        # Declining returns None and never reaches dbColumns.
        self.assertIsNone(s.searchColumn())
        self.assertIsNone(conf.dumper.dbColumnsArg)


if __name__ == "__main__":
    unittest.main()
