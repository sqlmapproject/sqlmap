#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Second batch of DBMS-specific enumeration override tests (companion to
tests/test_dbms_enum.py, which covers Microsoft SQL Server getTables).

Each test drives a FULL per-DBMS handler (the *Map class in
plugins/dbms/<dbms>/__init__.py) with the injection layer mocked, so the
dialect-specific table/column/user/privilege discovery paths run without a live
target, network, or DBMS. The in-band (UNION/error/direct) branch is taken via
conf.direct=True; conf.batch=True avoids interactive prompts.

Covered here:
  * Sybase          - getUsers, getDbs, getTables, getColumns, getPrivileges,
                      searchDb/searchTable/searchColumn, getHostname, getStatements
  * SAP MaxDB       - getDbs, getTables, getColumns, getPrivileges,
                      getPasswordHashes, getHostname, getStatements
  * Microsoft SQL Server - getPrivileges, searchTable, searchColumn
                      (getTables already covered by test_dbms_enum.py)
  * IBM DB2         - getPasswordHashes, getStatements
  * Informix        - searchDb, searchTable, searchColumn, getStatements
  * Firebird        - getDbs, getPasswordHashes, searchDb, getHostname, getStatements
  * HSQLDB          - getBanner, getPrivileges, getHostname, getStatements,
                      getCurrentDb

Sybase/MaxDB enumeration goes through lib.utils.pivotdumptable.pivotDumpTable
(imported into the module namespace), so for those we mock that wrapper - it is
part of the same data-retrieval layer - and mock inject.getValue elsewhere.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import importlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.data import conf, kb
from lib.core.common import Backend
from lib.core.enums import EXPECTED
from lib.request import inject


def _fresh_cached():
    kb.data.cachedDbs = []
    kb.data.cachedTables = {}
    kb.data.cachedColumns = {}
    kb.data.cachedUsers = []
    kb.data.cachedUsersPrivileges = {}
    kb.data.cachedCounts = {}
    kb.data.cachedStatements = []
    kb.data.banner = None


class _NoOpDumper(object):
    """Swallow every dumper call so search methods don't emit/prompt."""

    def __getattr__(self, name):
        return lambda *a, **k: None


def _handler(display_name, dirname):
    """Instantiate the full *Map handler for the given DBMS."""
    set_dbms(display_name)
    main = importlib.import_module("plugins.dbms.%s" % dirname)
    cls = [getattr(main, n) for n in dir(main) if n.endswith("Map")][0]
    return cls()


class _EnumBase(unittest.TestCase):
    """Snapshot/restore every global these enumerators mutate."""

    # subclasses set these
    display_name = None
    dirname = None

    def setUp(self):
        # config snapshot
        self._direct = conf.direct
        self._batch = conf.batch
        self._db = conf.db
        self._tbl = conf.tbl
        self._col = conf.col
        self._user = conf.user
        self._exclude = conf.exclude
        self._search = conf.search
        self._getBanner = conf.getBanner
        self._excludeSysDbs = conf.excludeSysDbs
        self._dumper = conf.get("dumper")

        # kb snapshot
        self._cached = {k: kb.data.get(k) for k in (
            "cachedDbs", "cachedTables", "cachedColumns", "cachedUsers",
            "cachedUsersPrivileges", "cachedCounts", "cachedStatements", "banner",
        )}
        self._hintValue = kb.hintValue
        self._injectionData = kb.injection.data
        self._currentDb = kb.data.get("currentDb")
        self._hasIS = kb.data.get("has_information_schema")

        # injection layer snapshot
        self._gv = inject.getValue
        self._cbe = getattr(inject, "checkBooleanExpression", None)

        # baseline config the in-band/non-interactive paths need
        conf.direct = True
        conf.batch = True
        kb.data.has_information_schema = True
        _fresh_cached()

        # restore the chosen DBMS for every test
        self.handler = _handler(self.display_name, self.dirname)
        # the enumeration module whose pivotDumpTable some tests stub
        self.em = importlib.import_module("plugins.dbms.%s.enumeration" % self.dirname)

    def tearDown(self):
        conf.direct = self._direct
        conf.batch = self._batch
        conf.db = self._db
        conf.tbl = self._tbl
        conf.col = self._col
        conf.user = self._user
        conf.exclude = self._exclude
        conf.search = self._search
        conf.getBanner = self._getBanner
        conf.excludeSysDbs = self._excludeSysDbs
        conf.dumper = self._dumper

        for k, v in self._cached.items():
            kb.data[k] = v
        kb.hintValue = self._hintValue
        kb.injection.data = self._injectionData
        kb.data.currentDb = self._currentDb
        kb.data.has_information_schema = self._hasIS

        inject.getValue = self._gv
        if self._cbe is not None:
            inject.checkBooleanExpression = self._cbe
        if hasattr(self.em, "pivotDumpTable"):
            # restore the pristine reference from the wrapper module
            import lib.utils.pivotdumptable as _pdt
            self.em.pivotDumpTable = _pdt.pivotDumpTable


# ---------------------------------------------------------------------------
# Sybase
# ---------------------------------------------------------------------------

class TestSybaseEnum(_EnumBase):
    display_name = "Sybase"
    dirname = "sybase"

    def _pivot(self, *value_lists):
        """Make em.pivotDumpTable return canned (entries, lengths) per call.

        Each successive call pops the next mapping of {colName: [values]}.
        """
        calls = list(value_lists)

        def fake(table, colList, count=None, blind=True, alias=None):
            mapping = calls.pop(0) if calls else {}
            entries = {}
            lengths = {}
            for col in colList:
                vals = mapping.get(col.split(".")[-1], [])
                entries[col] = list(vals)
                lengths[col] = 0
            return entries, lengths

        self.em.pivotDumpTable = fake

    def test_get_users(self):
        self._pivot({"name": ["sa", "guest"]})
        users = self.handler.getUsers()
        self.assertIn("sa", users)
        self.assertIn("guest", users)

    def test_get_dbs(self):
        self._pivot({"name": ["master", "model"]})
        dbs = self.handler.getDbs()
        self.assertEqual(sorted(dbs), ["master", "model"])

    def test_get_tables(self):
        conf.db = "testdb"
        self._pivot({"name": ["users", "logs"]})
        tables = self.handler.getTables()
        self.assertIn("testdb", tables)
        self.assertEqual(sorted(tables["testdb"]), ["logs", "users"])

    def test_get_columns(self):
        conf.db = "testdb"
        conf.tbl = "users"
        # column pivot returns name + usertype: REAL Sybase numeric type ids that
        # getColumns resolves through SYBASE_TYPES (7 -> "int", 2 -> "varchar").
        from lib.core.dicts import SYBASE_TYPES
        self._pivot({"name": ["id", "name"], "usertype": ["7", "2"]})
        cols = self.handler.getColumns()
        self.assertIn("testdb", cols)
        # table key is identifier-normalized (may be schema-qualified)
        tbls = cols["testdb"]
        self.assertTrue(any("users" in t for t in tbls))
        colset = list(tbls.values())[0]
        # the VALUE is the resolved type name, not the raw usertype number:
        # proves the SYBASE_TYPES numeric->name mapping actually ran.
        self.assertEqual(colset["id"], SYBASE_TYPES[7])      # "int"
        self.assertEqual(colset["name"], SYBASE_TYPES[2])    # "varchar"

    def test_get_privileges(self):
        # getPrivileges -> getUsers (pivot) then isDba (checkBooleanExpression).
        # Drive the admin-set branch BOTH ways via the isDba oracle so the result
        # is not forced by a constant-True stub.
        conf.user = None

        # oracle True: every user is flagged DBA -> admins == all users
        self._pivot({"name": ["sa", "guest"]})
        inject.checkBooleanExpression = lambda *a, **k: True
        privs, admins = self.handler.getPrivileges()
        self.assertIn("sa", privs)        # users still enumerated as privilege keys
        self.assertIn("guest", privs)
        self.assertEqual(admins, set(["sa", "guest"]))

        # oracle False: nobody is a DBA -> admins is empty, but users still listed
        _fresh_cached()
        self._pivot({"name": ["sa", "guest"]})
        inject.checkBooleanExpression = lambda *a, **k: False
        privs, admins = self.handler.getPrivileges()
        self.assertIn("sa", privs)
        self.assertEqual(admins, set())

    def test_search_not_implemented(self):
        # these intentionally return [] with a warning on Sybase
        self.assertEqual(self.handler.searchDb(), [])
        self.assertEqual(self.handler.searchTable(), [])
        self.assertEqual(self.handler.searchColumn(), [])

    def test_get_hostname(self):
        # not possible on Sybase; just must not raise
        self.assertIsNone(self.handler.getHostname())

    def test_get_statements(self):
        self.assertEqual(self.handler.getStatements(), [])


# ---------------------------------------------------------------------------
# SAP MaxDB
# ---------------------------------------------------------------------------

class TestMaxDBEnum(_EnumBase):
    display_name = "SAP MaxDB"
    dirname = "maxdb"

    def _pivot(self, *value_lists):
        calls = list(value_lists)

        def fake(table, colList, count=None, blind=True, alias=None):
            mapping = calls.pop(0) if calls else {}
            entries = {}
            lengths = {}
            for col in colList:
                vals = mapping.get(col.split(".")[-1], [])
                entries[col] = list(vals)
                lengths[col] = 0
            return entries, lengths

        self.em.pivotDumpTable = fake

    def test_get_dbs(self):
        self._pivot({"schemaname": ["SYSTEM", "DOMAIN"]})
        dbs = self.handler.getDbs()
        self.assertEqual(sorted(dbs), ["DOMAIN", "SYSTEM"])

    def test_get_tables(self):
        conf.db = "SYSTEM"
        self._pivot({"tablename": ["USERS", "TABLES"]})
        tables = self.handler.getTables()
        # db key is identifier-normalized (uppercase names get quoted)
        self.assertEqual(len(tables), 1)
        tbls = list(tables.values())[0]
        self.assertEqual(sorted(tbls), ["TABLES", "USERS"])

    def test_get_columns(self):
        conf.db = "SYSTEM"
        conf.tbl = "USERS"
        self._pivot({
            "columnname": ["ID", "NAME"],
            "datatype": ["INTEGER", "CHAR"],
            "len": ["4", "32"],
        })
        cols = self.handler.getColumns()
        self.assertEqual(len(cols), 1)
        tbls = list(cols.values())[0]
        self.assertIn("USERS", tbls)
        self.assertEqual(tbls["USERS"]["ID"], "INTEGER(4)")

    def test_get_privileges_empty(self):
        self.assertEqual(self.handler.getPrivileges(), {})

    def test_get_password_hashes_empty(self):
        self.assertEqual(self.handler.getPasswordHashes(), {})

    def test_get_hostname(self):
        self.assertIsNone(self.handler.getHostname())

    def test_get_statements(self):
        self.assertEqual(self.handler.getStatements(), [])


# ---------------------------------------------------------------------------
# Microsoft SQL Server (methods NOT covered by test_dbms_enum.py)
# ---------------------------------------------------------------------------

class TestMSSQLServerExtraEnum(_EnumBase):
    display_name = "Microsoft SQL Server"
    dirname = "mssqlserver"

    def test_get_privileges(self):
        # getPrivileges -> getUsers (generic, inject.getValue) then isDba.
        # Exercise the admin-set branch BOTH ways via the isDba oracle.
        conf.user = None
        inject.getValue = lambda q, *a, **k: ["sa", "BUILTIN\\Administrators"]

        # oracle True: all users flagged DBA
        inject.checkBooleanExpression = lambda *a, **k: True
        privs, admins = self.handler.getPrivileges()
        self.assertIn("sa", privs)
        self.assertEqual(admins, set(["sa", "BUILTIN\\Administrators"]))

        # oracle False: none are DBA -> empty admin set, users still enumerated
        _fresh_cached()
        inject.getValue = lambda q, *a, **k: ["sa", "BUILTIN\\Administrators"]
        inject.checkBooleanExpression = lambda *a, **k: False
        privs, admins = self.handler.getPrivileges()
        self.assertIn("sa", privs)
        self.assertEqual(admins, set())

    def test_search_table(self):
        conf.db = "testdb"
        conf.tbl = "users"
        # in-band branch: getValue returns matching table name(s)
        inject.getValue = lambda q, *a, **k: ["users"]
        # capture the discovered tables instead of dumping them
        captured = {}
        conf.dumper = _NoOpDumper()
        self.handler.dumpFoundTables = lambda tables: captured.update(tables)
        self.handler.searchTable()
        # at least one database mapped to the matched table
        flat = set()
        for tbls in captured.values():
            flat.update(tbls)
        self.assertTrue(any("users" in t for t in flat))

    def test_search_column(self):
        conf.db = "testdb"
        conf.tbl = None
        conf.col = "password"
        # exact match (no wildcard) so no recursive getColumns call;
        # getValue returns the tables that contain the column
        inject.getValue = lambda q, *a, **k: ["users"]
        captured = {}
        conf.dumper = _NoOpDumper()
        self.handler.dumpFoundColumn = lambda dbs, foundCols, colConsider: captured.update(dbs)
        self.handler.searchColumn()
        # the searched column was located in at least one table
        flat = set()
        for tbls in captured.values():
            flat.update(tbls)
        self.assertTrue(any("users" in t for t in flat))


# ---------------------------------------------------------------------------
# IBM DB2
# ---------------------------------------------------------------------------

class TestDB2Enum(_EnumBase):
    display_name = "IBM DB2"
    dirname = "db2"

    def test_get_password_hashes_empty(self):
        self.assertEqual(self.handler.getPasswordHashes(), {})

    def test_get_statements_empty(self):
        self.assertEqual(self.handler.getStatements(), [])


# ---------------------------------------------------------------------------
# Informix
# ---------------------------------------------------------------------------

class TestInformixEnum(_EnumBase):
    display_name = "Informix"
    dirname = "informix"

    def test_search_db(self):
        self.assertEqual(self.handler.searchDb(), [])

    def test_search_table(self):
        self.assertEqual(self.handler.searchTable(), [])

    def test_search_column(self):
        self.assertEqual(self.handler.searchColumn(), [])

    def test_get_statements(self):
        self.assertEqual(self.handler.getStatements(), [])


# ---------------------------------------------------------------------------
# Firebird
# ---------------------------------------------------------------------------

class TestFirebirdEnum(_EnumBase):
    display_name = "Firebird"
    dirname = "firebird"

    def test_get_dbs_empty(self):
        self.assertEqual(self.handler.getDbs(), [])

    def test_get_password_hashes_empty(self):
        self.assertEqual(self.handler.getPasswordHashes(), {})

    def test_search_db_empty(self):
        self.assertEqual(self.handler.searchDb(), [])

    def test_get_hostname(self):
        self.assertIsNone(self.handler.getHostname())

    def test_get_statements_empty(self):
        self.assertEqual(self.handler.getStatements(), [])


# ---------------------------------------------------------------------------
# HSQLDB
# ---------------------------------------------------------------------------

class TestHSQLDBEnum(_EnumBase):
    display_name = "HSQLDB"
    dirname = "hsqldb"

    def test_get_banner(self):
        conf.getBanner = True
        kb.data.banner = None
        # getValue returns a single-element LIST; getBanner pipes it through
        # unArrayizeValue, which must unwrap it to the scalar banner string.
        inject.getValue = lambda q, *a, **k: ["HSQLDB 2.5.1"]
        banner = self.handler.getBanner()
        self.assertEqual(banner, "HSQLDB 2.5.1")

    def test_get_privileges_empty(self):
        self.assertEqual(self.handler.getPrivileges(), {})

    def test_get_hostname(self):
        self.assertIsNone(self.handler.getHostname())

    def test_get_statements_empty(self):
        self.assertEqual(self.handler.getStatements(), [])

    def test_get_current_db_default_schema(self):
        from lib.core.settings import HSQLDB_DEFAULT_SCHEMA
        self.assertEqual(self.handler.getCurrentDb(), HSQLDB_DEFAULT_SCHEMA)


if __name__ == "__main__":
    unittest.main()
