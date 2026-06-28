#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

DBMS-specific enumeration overrides (plugins/dbms/<dbms>/enumeration.py),
driven through each full DBMS handler with the injection layer mocked, so the
dialect-specific table/column/user/privilege discovery paths run without a live
target, network, or DBMS. The in-band (UNION/error/direct) branch is taken via
conf.direct=True and inject.getValue is stubbed with canned result rows;
conf.batch=True avoids interactive prompts.

Consolidated from former tests/test_dbms_enum.py (Microsoft SQL Server),
tests/test_dbms_enum_a.py (Oracle/PostgreSQL/MySQL/SQLite) and
tests/test_dbms_enum_b.py (Sybase/MaxDB/MSSQL extra/DB2/Informix/Firebird/HSQLDB).

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import importlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.common import Backend
from lib.core.data import conf, kb
from lib.core.enums import EXPECTED
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.request import inject


# ---------------------------------------------------------------------------
# Base for Microsoft SQL Server getTables (former test_dbms_enum.py)
# ---------------------------------------------------------------------------

class _EnumBaseMSSQL(unittest.TestCase):
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


class TestMSSQLServerEnum(_EnumBaseMSSQL):
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


# ---------------------------------------------------------------------------
# Base for Oracle/PostgreSQL/MySQL/SQLite (former test_dbms_enum_a.py)
# ---------------------------------------------------------------------------

class _EnumBaseA(unittest.TestCase):
    """Snapshot/restore the global state these enumerators mutate.

    Other tests in the suite depend on clean globals (a leaked kb.hintValue
    breaks test_inference_engine; a leaked forced DBMS breaks others), so every
    knob touched here is captured in setUp and put back in tearDown.
    """

    # the enumeration module whose inject.getValue we patch (overridden per DBMS)
    module = None

    def setUp(self):
        # conf knobs
        self._direct = conf.direct
        self._batch = conf.batch
        self._user = conf.user
        self._db = conf.get("db")
        self._tbl = conf.get("tbl")
        self._exclude = conf.get("exclude")

        # injection layer (some override modules - e.g. SQLite/PostgreSQL - do not
        # import inject because their overrides return constants without querying)
        self._has_inject = hasattr(self.module, "inject")
        if self._has_inject:
            self._gv = self.module.inject.getValue

        # kb.data cached* containers
        self._cachedTables = kb.data.get("cachedTables")
        self._cachedColumns = kb.data.get("cachedColumns")
        self._cachedDbs = kb.data.get("cachedDbs")
        self._cachedUsers = kb.data.get("cachedUsers")
        self._cachedUsersRoles = kb.data.get("cachedUsersRoles")
        self._cachedUsersPrivileges = kb.data.get("cachedUsersPrivileges")
        self._has_information_schema = kb.data.get("has_information_schema")

        # state other tests are sensitive to
        self._hintValue = kb.hintValue
        self._injectionData = kb.injection.data
        self._forcedDbms = Backend.getForcedDbms()
        self._stickyDBMS = kb.stickyDBMS

        # avoid readInput EOFError flakiness and interactive prompts
        conf.direct = True
        conf.batch = True

    def tearDown(self):
        conf.direct = self._direct
        conf.batch = self._batch
        conf.user = self._user
        conf.db = self._db
        conf.tbl = self._tbl
        conf.exclude = self._exclude

        if self._has_inject:
            self.module.inject.getValue = self._gv

        kb.data.cachedTables = self._cachedTables
        kb.data.cachedColumns = self._cachedColumns
        kb.data.cachedDbs = self._cachedDbs
        kb.data.cachedUsers = self._cachedUsers
        kb.data.cachedUsersRoles = self._cachedUsersRoles
        kb.data.cachedUsersPrivileges = self._cachedUsersPrivileges
        kb.data.has_information_schema = self._has_information_schema

        kb.hintValue = self._hintValue
        kb.injection.data = self._injectionData
        kb.stickyDBMS = self._stickyDBMS
        if self._forcedDbms is not None:
            Backend.forceDbms(self._forcedDbms)
        else:
            kb.forcedDbms = None


class TestOracleEnum(_EnumBaseA):
    module = importlib.import_module("plugins.dbms.oracle.enumeration")

    def _handler(self):
        from plugins.dbms.oracle import OracleMap
        set_dbms("Oracle")
        return OracleMap()

    def test_get_roles(self):
        # rows are [GRANTEE, GRANTED_ROLE]; first column is the user, the rest roles
        conf.user = None
        kb.data.cachedUsersRoles = {}
        self.module.inject.getValue = lambda q, *a, **k: [
            ["SYS", "DBA"], ["SYS", "CONNECT"], ["SCOTT", "RESOURCE"]
        ]
        roles, areAdmins = self._handler().getRoles()
        self.assertIn("SYS", roles)
        self.assertIn("SCOTT", roles)
        self.assertEqual(set(roles["SYS"]), {"DBA", "CONNECT"})
        # DBA implies administrator
        self.assertIn("SYS", areAdmins)

    def test_get_roles_filtered_by_user(self):
        # conf.user populates a WHERE clause; canned rows still drive the parse
        conf.user = "SCOTT"
        kb.data.cachedUsersRoles = {}
        self.module.inject.getValue = lambda q, *a, **k: [["SCOTT", "RESOURCE"]]
        roles, _ = self._handler().getRoles()
        self.assertEqual(list(roles.keys()), ["SCOTT"])
        self.assertEqual(roles["SCOTT"], ["RESOURCE"])

    def test_get_roles_multiple_roles_per_user(self):
        # a user appearing across several rows accumulates all granted roles
        conf.user = None
        kb.data.cachedUsersRoles = {}
        self.module.inject.getValue = lambda q, *a, **k: [
            ["APP", "CONNECT"], ["APP", "RESOURCE"], ["APP", "CREATE SESSION"]
        ]
        roles, _ = self._handler().getRoles()
        self.assertEqual(
            set(roles["APP"]), {"CONNECT", "RESOURCE", "CREATE SESSION"}
        )


class TestPostgreSQLEnum(_EnumBaseA):
    module = importlib.import_module("plugins.dbms.postgresql.enumeration")

    def _handler(self):
        from plugins.dbms.postgresql import PostgreSQLMap
        set_dbms("PostgreSQL")
        return PostgreSQLMap()

    def test_get_hostname_unsupported(self):
        # PostgreSQL overrides getHostname purely to warn; it returns None
        self.assertIsNone(self._handler().getHostname())


class TestMySQLEnum(_EnumBaseA):
    # MySQL's enumeration.py adds no overrides (it is a bare `pass`); cover the
    # generic discovery path through the full MySQL handler instead.
    module = importlib.import_module("plugins.generic.enumeration")

    def _handler(self):
        from plugins.dbms.mysql import MySQLMap
        set_dbms("MySQL")
        return MySQLMap()

    def test_get_dbs(self):
        conf.db = None
        kb.data.cachedDbs = []
        kb.data.has_information_schema = True
        self.module.inject.getValue = lambda q, *a, **k: (
            3 if k.get("expected") == EXPECTED.INT
            else [["information_schema"], ["testdb"], ["mysql"]]
        )
        dbs = self._handler().getDbs()
        self.assertIn("testdb", dbs)
        self.assertEqual(set(kb.data.cachedDbs), set(dbs))


class TestSQLiteEnum(_EnumBaseA):
    module = importlib.import_module("plugins.dbms.sqlite.enumeration")

    def _handler(self):
        from plugins.dbms.sqlite import SQLiteMap
        set_dbms("SQLite")
        return SQLiteMap()

    def test_unsupported_simple_overrides(self):
        # SQLite overrides these to a warning + an empty/neutral return value
        h = self._handler()
        self.assertIsNone(h.getCurrentUser())
        self.assertIsNone(h.getCurrentDb())
        self.assertIsNone(h.getHostname())
        self.assertEqual(h.getUsers(), [])
        self.assertEqual(h.getDbs(), [])
        self.assertEqual(h.searchDb(), [])
        self.assertEqual(h.getStatements(), [])
        self.assertEqual(h.getPasswordHashes(), {})
        self.assertEqual(h.getPrivileges(), {})

    def test_is_dba_always_true(self):
        # on SQLite the current user is treated as having all privileges
        self.assertTrue(self._handler().isDba())

    def test_search_column_raises(self):
        with self.assertRaises(SqlmapUnsupportedFeatureException):
            self._handler().searchColumn()


# ---------------------------------------------------------------------------
# Base + helpers for Sybase/MaxDB/MSSQL extra/DB2/Informix/Firebird/HSQLDB
# (former test_dbms_enum_b.py)
# ---------------------------------------------------------------------------

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


class _EnumBaseB(unittest.TestCase):
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

class TestSybaseEnum(_EnumBaseB):
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

class TestMaxDBEnum(_EnumBaseB):
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
# Microsoft SQL Server (methods NOT covered by TestMSSQLServerEnum above)
# ---------------------------------------------------------------------------

class TestMSSQLServerExtraEnum(_EnumBaseB):
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

class TestDB2Enum(_EnumBaseB):
    display_name = "IBM DB2"
    dirname = "db2"

    def test_get_password_hashes_empty(self):
        self.assertEqual(self.handler.getPasswordHashes(), {})

    def test_get_statements_empty(self):
        self.assertEqual(self.handler.getStatements(), [])


# ---------------------------------------------------------------------------
# Informix
# ---------------------------------------------------------------------------

class TestInformixEnum(_EnumBaseB):
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

class TestFirebirdEnum(_EnumBaseB):
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

class TestHSQLDBEnum(_EnumBaseB):
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
