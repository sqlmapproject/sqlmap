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


if __name__ == "__main__":
    unittest.main()
