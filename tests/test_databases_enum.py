#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit tests for the enumeration methods of plugins/generic/databases.py.

The injection layer (lib.request.inject.getValue) is mocked so no network or
live DBMS is required; each test drives a single enumeration method down a
specific branch (conf.direct "inband" path or the isInferenceAvailable() blind
path) and asserts on the returned value / kb.data.cached* state.

CRITICAL: every test restores conf.*, the patched dbmod.inject.getValue, and the
mutated kb.data flags in tearDown so global state does not leak into the rest of
the suite.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms

bootstrap()

from lib.core.data import conf, kb
from lib.core.enums import EXPECTED, PAYLOAD
import plugins.generic.databases as dbmod
from plugins.generic.databases import Databases

# Databases.forceDbmsEnum() is supplied at runtime by the concrete dbms fingerprint
# plugin mixin (plugins/dbms/*/fingerprint.py); a bare Databases() instance lacks it,
# so neutralize it for the duration of these tests. Restored in tearDown via the saved ref.
_NOOP = lambda self: None


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


class _BaseEnumTest(unittest.TestCase):
    """Shared setup/teardown that snapshots and restores all touched global state."""

    # conf keys every test may read/write
    _CONF_KEYS = ("direct", "technique", "db", "tbl", "col", "exclude",
                  "getComments", "excludeSysDbs", "search", "freshQueries")

    def setUp(self):
        self._saved_conf = {k: conf.get(k) for k in self._CONF_KEYS}
        self._saved_getValue = dbmod.inject.getValue
        self._saved_injection_data = kb.injection.data
        self._saved_has_is = kb.data.get("has_information_schema")
        # the inference paths of getTables/getColumns set kb.hintValue as a side effect;
        # snapshot it so we never leak a stale hint into other test files (e.g. the
        # inference engine's tryHint(), whose setUp does not reset it).
        self._saved_hintValue = kb.get("hintValue")
        self._saved_forceDbmsEnum = getattr(Databases, "forceDbmsEnum", None)
        Databases.forceDbmsEnum = _NOOP

        # sane defaults shared by most tests
        conf.getComments = False
        conf.excludeSysDbs = False
        conf.exclude = None
        conf.search = False
        conf.freshQueries = False
        conf.col = None
        kb.data.has_information_schema = True

    def tearDown(self):
        for k, v in self._saved_conf.items():
            conf[k] = v
        dbmod.inject.getValue = self._saved_getValue
        kb.injection.data = self._saved_injection_data
        kb.data.has_information_schema = self._saved_has_is
        kb.hintValue = self._saved_hintValue
        if self._saved_forceDbmsEnum is not None:
            Databases.forceDbmsEnum = self._saved_forceDbmsEnum
        else:
            try:
                del Databases.forceDbmsEnum
            except AttributeError:
                pass

    # helpers -----------------------------------------------------------------

    def _fresh(self):
        """Return a Databases() instance with every cache reset to empty."""
        d = Databases()
        kb.data.currentDb = ""
        kb.data.cachedDbs = []
        kb.data.cachedTables = {}
        kb.data.cachedColumns = {}
        kb.data.cachedCounts = {}
        kb.data.cachedStatements = []
        kb.data.cachedProcedures = []
        return d

    def _enable_inference(self):
        """Take the blind inference branch: conf.direct off, a BOOLEAN technique present."""
        conf.direct = False
        conf.technique = None
        kb.injection.data = {PAYLOAD.TECHNIQUE.BOOLEAN: {"title": "AND boolean-based blind"}}


class TestGetCurrentDb(_BaseEnumTest):
    def test_current_db_mysql(self):
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        dbmod.inject.getValue = lambda query, *a, **k: "testdb"
        self.assertEqual(d.getCurrentDb(), "testdb")
        self.assertEqual(kb.data.currentDb, "testdb")

    def test_current_db_cached(self):
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        kb.data.currentDb = "already"

        def _boom(*a, **k):
            raise AssertionError("inject.getValue must not be called when currentDb is cached")

        dbmod.inject.getValue = _boom
        self.assertEqual(d.getCurrentDb(), "already")

    def test_current_db_oracle_schema_warning_branch(self):
        # Oracle takes the schema-name warning branch; result still returned.
        set_dbms("Oracle")
        conf.direct = True
        d = self._fresh()
        dbmod.inject.getValue = lambda query, *a, **k: "SYSTEM"
        self.assertEqual(d.getCurrentDb(), "SYSTEM")


class TestGetDbs(_BaseEnumTest):
    def test_get_dbs_direct_mysql(self):
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        dbmod.inject.getValue = lambda query, *a, **k: [["information_schema"], ["mysql"], ["testdb"]]
        result = d.getDbs()
        self.assertEqual(sorted(result), ["information_schema", "mysql", "testdb"])
        self.assertIn("testdb", kb.data.cachedDbs)

    def test_get_dbs_cached_short_circuit(self):
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        kb.data.cachedDbs = ["pre", "cached"]

        def _boom(*a, **k):
            raise AssertionError("must not query when cachedDbs is populated")

        dbmod.inject.getValue = _boom
        self.assertEqual(d.getDbs(), ["pre", "cached"])

    def test_get_dbs_direct_pgsql_schema_branch(self):
        set_dbms("PostgreSQL")
        conf.direct = True
        d = self._fresh()
        dbmod.inject.getValue = lambda query, *a, **k: [["public"], ["information_schema"]]
        result = d.getDbs()
        self.assertEqual(sorted(result), ["information_schema", "public"])

    def test_get_dbs_mysql_no_information_schema(self):
        # MySQL < 5: query2 / count2 branch; still inband under conf.direct.
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        kb.data.has_information_schema = False
        dbmod.inject.getValue = lambda query, *a, **k: [["mysql"], ["app"]]
        result = d.getDbs()
        self.assertEqual(sorted(result), ["app", "mysql"])

    def test_get_dbs_inference(self):
        set_dbms("MySQL")
        self._enable_inference()
        d = self._fresh()

        names = ["alpha", "beta", "gamma"]
        state = {"i": 0}

        def gv(query, *a, **k):
            if k.get("expected") == EXPECTED.INT:
                return str(len(names))
            val = names[state["i"]]
            state["i"] += 1
            return [val]

        dbmod.inject.getValue = gv
        result = d.getDbs()
        self.assertEqual(sorted(result), sorted(names))

    def test_get_dbs_fallback_to_current(self):
        # No dbs returned inband -> falls back to current database.
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        state = {"n": 0}

        def gv(query, *a, **k):
            state["n"] += 1
            if state["n"] == 1:
                return None          # getDbs inband: nothing
            return "fallbackdb"      # getCurrentDb

        dbmod.inject.getValue = gv
        result = d.getDbs()
        self.assertEqual(result, ["fallbackdb"])


class TestGetTables(_BaseEnumTest):
    def test_get_tables_direct_mysql(self):
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        conf.db = "testdb"
        conf.tbl = None
        dbmod.inject.getValue = lambda query, *a, **k: [["testdb", "users"], ["testdb", "posts"]]
        result = d.getTables()
        self.assertIn("testdb", result)
        self.assertEqual(sorted(result["testdb"]), ["posts", "users"])

    def test_get_tables_cached_short_circuit(self):
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        kb.data.cachedTables = {"db": ["t1"]}

        def _boom(*a, **k):
            raise AssertionError("must not query when cachedTables is populated")

        dbmod.inject.getValue = _boom
        self.assertEqual(d.getTables(), {"db": ["t1"]})

    def test_get_tables_direct_pgsql(self):
        set_dbms("PostgreSQL")
        conf.direct = True
        d = self._fresh()
        conf.db = "public"
        conf.tbl = None
        dbmod.inject.getValue = lambda query, *a, **k: [["public", "accounts"]]
        result = d.getTables()
        self.assertEqual(result.get("public"), ["accounts"])

    def test_get_tables_inference(self):
        set_dbms("MySQL")
        self._enable_inference()
        d = self._fresh()
        conf.db = "testdb"
        conf.tbl = None

        tables = ["t_a", "t_b"]
        state = {"i": 0}

        def gv(query, *a, **k):
            if k.get("expected") == EXPECTED.INT:
                return str(len(tables))
            val = tables[state["i"] % len(tables)]
            state["i"] += 1
            return [val]

        dbmod.inject.getValue = gv
        result = d.getTables()
        self.assertIn("testdb", result)
        self.assertEqual(sorted(result["testdb"]), sorted(tables))


class TestGetColumns(_BaseEnumTest):
    def _run_direct(self, dbms, db, tbl, rows):
        set_dbms(dbms)
        conf.direct = True
        d = self._fresh()
        conf.db = db
        conf.tbl = tbl
        dbmod.inject.getValue = lambda query, *a, **k: rows
        return d.getColumns()

    def test_columns_direct_mysql(self):
        result = self._run_direct("MySQL", "testdb", "users", [["id", "int"], ["age", "int"]])
        self.assertIn("testdb", result)
        cols = result["testdb"]["users"]
        self.assertEqual(cols.get("id"), "int")
        self.assertEqual(cols.get("age"), "int")

    def test_columns_direct_pgsql(self):
        result = self._run_direct("PostgreSQL", "public", "users", [["id", "integer"]])
        self.assertEqual(result["public"]["users"].get("id"), "integer")

    def test_columns_direct_oracle_uppercase(self):
        # Oracle is an UPPER_CASE dbms: conf.db/tbl get upcased internally.
        result = self._run_direct("Oracle", "system", "users", [["ID", "NUMBER"]])
        # Oracle quotes the identifier ("SYSTEM"); assert the column landed regardless.
        flat = {}
        for tables in result.values():
            for cols in tables.values():
                flat.update(cols)
        self.assertEqual(flat.get("ID"), "NUMBER")

    def test_columns_direct_mssql(self):
        result = self._run_direct("Microsoft SQL Server", "master", "users", [["id", "int"]])
        # MSSQL wraps the db identifier in [brackets]; assert the column landed.
        flat = {}
        for tables in result.values():
            for cols in tables.values():
                flat.update(cols)
        self.assertEqual(flat.get("id"), "int")

    def test_columns_only_names(self):
        # onlyColNames is ONLY read in the inference branch (the INBAND path
        # ignores it), so drive the blind inference path like
        # test_columns_inference_mysql but with onlyColNames=True. The flag must
        # SUPPRESS the type lookup: each column's value lands as None instead of
        # the real type. Asserting cols.get("id") is None proves the flag took
        # effect (otherwise the type query would run and return "int").
        set_dbms("MySQL")
        self._enable_inference()
        d = self._fresh()
        conf.db = "testdb"
        conf.tbl = "users"

        colnames = ["id", "name"]
        state = {"i": 0}
        type_queries = {"n": 0}

        def gv(query, *a, **k):
            if k.get("expected") == EXPECTED.INT:
                return str(len(colnames))
            # With onlyColNames the second-stage type query (blind.query2, which
            # selects column_type) must NEVER be issued.
            if "column_type" in query.lower():
                type_queries["n"] += 1
                return ["int"]
            val = colnames[state["i"] % len(colnames)]
            state["i"] += 1
            return [val]

        dbmod.inject.getValue = gv
        result = d.getColumns(onlyColNames=True)
        cols = result["testdb"]["users"]
        # both column names enumerated...
        self.assertEqual(len(cols), len(colnames))
        self.assertIn("id", cols)
        # ...but their types were suppressed (None), and no type query ran.
        self.assertIsNone(cols.get("id"))
        self.assertEqual(type_queries["n"], 0)

    def test_columns_inference_mysql(self):
        set_dbms("MySQL")
        self._enable_inference()
        d = self._fresh()
        conf.db = "testdb"
        conf.tbl = "users"

        colnames = ["id", "name"]
        state = {"i": 0, "names": True}

        def gv(query, *a, **k):
            if k.get("expected") == EXPECTED.INT:
                return str(len(colnames))
            # alternate: column name then its type
            if state["names"]:
                val = colnames[state["i"] % len(colnames)]
                state["i"] += 1
                state["names"] = False
                return [val]
            else:
                state["names"] = True
                return ["int"]

        dbmod.inject.getValue = gv
        result = d.getColumns()
        self.assertIn("testdb", result)
        cols = result["testdb"]["users"]
        # both columns enumerated (reserved words like "name" get quoted, so count, not exact keys)
        self.assertEqual(len(cols), len(colnames))
        self.assertEqual(cols.get("id"), "int")


class TestGetCount(_BaseEnumTest):
    def test_count_single_table_mysql(self):
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        conf.db = "testdb"
        conf.tbl = "users"
        dbmod.inject.getValue = lambda query, *a, **k: "42"
        result = d.getCount()
        self.assertEqual(result, {"testdb": {42: ["users"]}})

    def test_count_dotted_table_splits_db(self):
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        conf.db = None
        conf.tbl = "shop.orders"
        dbmod.inject.getValue = lambda query, *a, **k: "7"
        result = d.getCount()
        self.assertEqual(result, {"shop": {7: ["orders"]}})

    def test_count_multiple_tables(self):
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        conf.db = "testdb"
        conf.tbl = "users,posts"
        counts = {"users": "3", "posts": "5"}

        def gv(query, *a, **k):
            # the table name appears in the FROM clause of the generated query
            for t, c in counts.items():
                if t in query:
                    return c
            return "0"

        dbmod.inject.getValue = gv
        result = d.getCount()
        self.assertIn("testdb", result)
        self.assertIn("users", result["testdb"][3])
        self.assertIn("posts", result["testdb"][5])


class TestGetStatements(_BaseEnumTest):
    def test_statements_direct_mysql(self):
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        dbmod.inject.getValue = lambda query, *a, **k: [["SELECT 1"], ["SELECT 2"]]
        result = d.getStatements()
        self.assertEqual(sorted(result), ["SELECT 1", "SELECT 2"])

    def test_statements_direct_pgsql(self):
        set_dbms("PostgreSQL")
        conf.direct = True
        d = self._fresh()
        dbmod.inject.getValue = lambda query, *a, **k: [["SELECT now()"]]
        result = d.getStatements()
        self.assertEqual(result, ["SELECT now()"])

    def test_statements_inference(self):
        set_dbms("PostgreSQL")
        self._enable_inference()
        d = self._fresh()
        stmts = ["SELECT a", "SELECT b"]
        state = {"i": 0}

        def gv(query, *a, **k):
            if k.get("expected") == EXPECTED.INT:
                return str(len(stmts))
            val = stmts[state["i"] % len(stmts)]
            state["i"] += 1
            return [val]

        dbmod.inject.getValue = gv
        result = d.getStatements()
        self.assertEqual(sorted(result), sorted(stmts))


class TestGetSchema(_BaseEnumTest):
    def test_schema_mysql(self):
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        conf.db = "testdb"
        conf.tbl = None
        conf.col = None
        state = {"n": 0}

        def gv(query, *a, **k):
            state["n"] += 1
            if state["n"] == 1:
                # getTables call
                return [["testdb", "users"]]
            # getColumns call
            return [["id", "int"]]

        dbmod.inject.getValue = gv
        result = d.getSchema()
        self.assertIn("testdb", result)
        self.assertIn("users", result["testdb"])
        self.assertEqual(result["testdb"]["users"].get("id"), "int")


class TestGetProcedures(_BaseEnumTest):
    def test_procedures_direct_pgsql(self):
        set_dbms("PostgreSQL")
        conf.direct = True
        d = self._fresh()
        dbmod.inject.getValue = lambda query, *a, **k: [["proc_a"], ["proc_b"]]
        result = d.getProcedures()
        self.assertEqual(sorted(result), ["proc_a", "proc_b"])

    def test_procedures_inference_mysql(self):
        set_dbms("MySQL")
        self._enable_inference()
        d = self._fresh()
        procs = ["sp_one", "sp_two"]
        state = {"i": 0}

        def gv(query, *a, **k):
            if k.get("expected") == EXPECTED.INT:
                return str(len(procs))
            val = procs[state["i"] % len(procs)]
            state["i"] += 1
            return [val]

        dbmod.inject.getValue = gv
        result = d.getProcedures()
        self.assertEqual(sorted(result), sorted(procs))


# --------------------------------------------------------------------------- #
# Inference / brute-force branches (relocated from test_generic_enum_more.py)
# --------------------------------------------------------------------------- #

class _DbBase(unittest.TestCase):
    _CONF_KEYS = ("direct", "technique", "db", "tbl", "col", "exclude",
                  "getComments", "excludeSysDbs", "search", "freshQueries")

    def setUp(self):
        self._saved_conf = {k: conf.get(k) for k in self._CONF_KEYS}
        self._saved_getValue = dbmod.inject.getValue
        self._saved_checkBool = dbmod.inject.checkBooleanExpression
        self._saved_injection_data = kb.injection.data
        self._saved_has_is = kb.data.get("has_information_schema")
        self._saved_hintValue = kb.get("hintValue")
        self._saved_choices = dict(kb.choices)
        self._saved_readInput = dbmod.readInput
        self._saved_forceDbmsEnum = getattr(Databases, "forceDbmsEnum", None)
        Databases.forceDbmsEnum = _NOOP

        conf.getComments = False
        conf.excludeSysDbs = False
        conf.exclude = None
        conf.search = False
        conf.freshQueries = False
        conf.col = None
        kb.data.has_information_schema = True

    def tearDown(self):
        for k, v in self._saved_conf.items():
            conf[k] = v
        dbmod.inject.getValue = self._saved_getValue
        dbmod.inject.checkBooleanExpression = self._saved_checkBool
        dbmod.readInput = self._saved_readInput
        kb.injection.data = self._saved_injection_data
        kb.data.has_information_schema = self._saved_has_is
        kb.hintValue = self._saved_hintValue
        kb.choices.clear()
        kb.choices.update(self._saved_choices)
        if self._saved_forceDbmsEnum is not None:
            Databases.forceDbmsEnum = self._saved_forceDbmsEnum
        else:
            try:
                del Databases.forceDbmsEnum
            except AttributeError:
                pass

    def _fresh(self):
        d = Databases()
        kb.data.currentDb = ""
        kb.data.cachedDbs = []
        kb.data.cachedTables = {}
        kb.data.cachedColumns = {}
        kb.data.cachedCounts = {}
        kb.data.cachedStatements = []
        kb.data.cachedProcedures = []
        return d

    def _inference(self):
        conf.direct = False
        conf.technique = None
        kb.injection.data = {PAYLOAD.TECHNIQUE.BOOLEAN: {"title": "AND boolean-based blind"}}


class TestDatabasesInference(_DbBase):
    def test_get_columns_inference_pgsql_types(self):
        # Blind column enumeration on PostgreSQL: a count, then for each index a
        # column name followed by its type. Assert the {db:{tbl:{col:type}}} parse.
        set_dbms("PostgreSQL")
        self._inference()
        d = self._fresh()
        conf.db = "public"
        conf.tbl = "users"

        names = ["id", "email"]
        state = {"i": 0, "name": True}

        def gv(query, *a, **k):
            if k.get("expected") == EXPECTED.INT:
                return str(len(names))
            if state["name"]:
                val = names[state["i"] % len(names)]
                state["i"] += 1
                state["name"] = False
                return [val]
            state["name"] = True
            return ["integer"]

        dbmod.inject.getValue = gv
        result = d.getColumns()
        cols = result["public"]["users"]
        self.assertEqual(len(cols), 2)
        self.assertEqual(cols.get("id"), "integer")

    def test_get_columns_inference_dump_mode_collist(self):
        # dumpMode with an explicit conf.col list: in the inference branch the
        # columns are taken straight from colList (no count/type queries at all)
        # and stored with value None. Asserting no getValue ran proves the
        # dump-mode shortcut, not a network round-trip.
        set_dbms("MySQL")
        self._inference()
        d = self._fresh()
        conf.db = "testdb"
        conf.tbl = "users"
        conf.col = "id,name"

        def boom(*a, **k):
            raise AssertionError("dumpMode+colList must not query in inference branch")

        dbmod.inject.getValue = boom
        result = d.getColumns(dumpMode=True)
        cols = result["testdb"]["users"]
        # "name" is a reserved word -> safeSQLIdentificatorNaming backtick-quotes it;
        # both columns must be present (count, since exact key varies by quoting).
        self.assertEqual(len(cols), 2)
        self.assertIn("id", cols)
        self.assertIsNone(cols.get("id"))

    def test_get_count_over_cached_tables_inference(self):
        # getCount with no conf.tbl: it calls getTables() then per-table _tableGetCount.
        # Drive the inband table fetch + per-table count and assert the
        # {db:{count:[tables]}} grouping (tables sharing a count are grouped).
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        conf.db = "testdb"
        conf.tbl = None
        kb.data.cachedTables = {"testdb": ["users", "posts"]}

        counts = {"users": "5", "posts": "5"}

        def gv(query, *a, **k):
            for t, c in counts.items():
                if t in query:
                    return c
            return "0"

        dbmod.inject.getValue = gv
        result = d.getCount()
        # both tables have count 5 -> grouped under the same key
        self.assertEqual(sorted(result["testdb"][5]), ["posts", "users"])

    def test_get_statements_count_zero_returns_empty(self):
        # Inference path: a zero count short-circuits to the (empty) cache.
        set_dbms("PostgreSQL")
        self._inference()
        d = self._fresh()
        # getStatements compares the count with the int literal 0 (count == 0), so
        # the count stub must return an int 0 (not "0") to take the empty branch.
        dbmod.inject.getValue = lambda query, *a, **k: 0 if k.get("expected") == EXPECTED.INT else self.fail("must not fetch rows when count is 0")
        result = d.getStatements()
        self.assertEqual(result, [])

    def test_get_procedures_inference(self):
        set_dbms("PostgreSQL")
        self._inference()
        d = self._fresh()
        dbmod.inject.getValue = _inference_gv(2, ["sp_a", "sp_b"])
        result = d.getProcedures()
        self.assertEqual(sorted(result), ["sp_a", "sp_b"])

    def test_get_dbs_mssql_inband_paging(self):
        # MSSQL with no rows from the primary query falls into the query2 paging
        # loop (one indexed query per db until a blank value stops it).
        set_dbms("Microsoft SQL Server")
        conf.direct = True
        d = self._fresh()
        dbs = ["master", "model"]

        def gv(query, *a, **k):
            # The primary inband query is 'SELECT name FROM master..sysdatabases'
            # (no DB_NAME); make it return nothing so getDbs falls into the
            # 'SELECT DB_NAME(<index>)' paging loop (query2).
            if "DB_NAME" not in query:
                return None
            import re as _re
            idx = int(_re.findall(r"DB_NAME\((\d+)\)", query)[0])
            return dbs[idx] if idx < len(dbs) else ""

        dbmod.inject.getValue = gv
        result = d.getDbs()
        self.assertEqual(sorted(result), ["master", "model"])

    def test_get_tables_inference_grouped_per_db(self):
        # Blind table enumeration: count for the db, then one table name per index.
        set_dbms("MySQL")
        self._inference()
        d = self._fresh()
        conf.db = "shop"
        conf.tbl = None
        dbmod.inject.getValue = _inference_gv(2, ["orders", "items"])
        result = d.getTables()
        self.assertIn("shop", result)
        self.assertEqual(sorted(result["shop"]), ["items", "orders"])


class TestDatabasesBruteForce(_DbBase):
    def test_get_columns_mysql_lt5_bruteforce_decline(self):
        # MySQL < 5 (no information_schema) forces bruteForce in getColumns; with
        # the common-column-existence prompt answered 'N' it returns None without
        # issuing any column query.
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        conf.db = "testdb"
        conf.tbl = "users"
        kb.data.has_information_schema = False
        kb.choices.columnExists = None
        dbmod.readInput = lambda *a, **k: "N"

        def boom(*a, **k):
            raise AssertionError("bruteForce decline must not query columns")

        dbmod.inject.getValue = boom
        result = d.getColumns()
        self.assertIsNone(result)

    def test_get_columns_bruteforce_dumpmode_collist_on_decline(self):
        # bruteForce + decline + dumpMode + colList: the columns from colList are
        # stored with None type (the dump-mode salvage branch), not dropped.
        set_dbms("MySQL")
        conf.direct = True
        d = self._fresh()
        conf.db = "testdb"
        conf.tbl = "users"
        conf.col = "a,b"
        kb.data.has_information_schema = False
        kb.choices.columnExists = None
        dbmod.readInput = lambda *a, **k: "N"
        dbmod.inject.getValue = lambda *a, **k: None
        result = d.getColumns(dumpMode=True)
        cols = result["testdb"]["users"]
        self.assertEqual(sorted(cols.keys()), ["a", "b"])
        self.assertIsNone(cols.get("a"))


if __name__ == "__main__":
    unittest.main()
