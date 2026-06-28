#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

DBMS-specific enumeration overrides for Oracle, PostgreSQL, MySQL and SQLite
(plugins/dbms/<dbms>/enumeration.py), driven through each full DBMS handler with
the injection layer mocked, so the dialect-specific discovery paths run without a
live target. The in-band (UNION/error/direct) branch is taken via conf.direct=True
and inject.getValue is stubbed with canned result rows.

Companion to tests/test_dbms_enum.py (which covers Microsoft SQL Server).
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


class _EnumBase(unittest.TestCase):
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


class TestOracleEnum(_EnumBase):
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


class TestPostgreSQLEnum(_EnumBase):
    module = importlib.import_module("plugins.dbms.postgresql.enumeration")

    def _handler(self):
        from plugins.dbms.postgresql import PostgreSQLMap
        set_dbms("PostgreSQL")
        return PostgreSQLMap()

    def test_get_hostname_unsupported(self):
        # PostgreSQL overrides getHostname purely to warn; it returns None
        self.assertIsNone(self._handler().getHostname())


class TestMySQLEnum(_EnumBase):
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


class TestSQLiteEnum(_EnumBase):
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


if __name__ == "__main__":
    unittest.main()
