#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit tests for the enumeration methods of plugins/generic/users.py.

The injection layer (lib.request.inject.getValue) is mocked so the methods can
be exercised against canned result rows without a live target, network, or DBMS.
Each test sets conf.direct = True to drive the inband (union/error/query OR
conf.direct) branch of the method under test, patches inject.getValue with rows
matching the shape the method parses, then asserts the relevant kb.data.cached*
container was populated.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms

bootstrap()

from lib.core.data import conf, kb
import plugins.generic.users as umod
from plugins.generic.users import Users
from lib.core.settings import CURRENT_USER


class TestUsersEnum(unittest.TestCase):
    def setUp(self):
        # Snapshot the global state these tests mutate so tearDown can restore it
        # exactly (other test files share conf / kb / the inject module).
        self._direct = conf.direct
        self._user = conf.user
        self._gv = umod.inject.getValue
        self._cbe = umod.inject.checkBooleanExpression
        self._store = umod.storeHashesToFile
        self._attack = umod.attackCachedUsersPasswords
        self._readInput = umod.readInput
        self._his = kb.data.get("has_information_schema")

        set_dbms("MySQL")
        conf.direct = True
        conf.user = None
        kb.data.has_information_schema = True

        # Neutralize the side effects getPasswordHashes triggers once it has
        # populated the cache (file write + interactive dictionary attack prompt).
        umod.storeHashesToFile = lambda *a, **k: None
        umod.attackCachedUsersPasswords = lambda *a, **k: None
        umod.readInput = lambda *a, **k: "N"

    def tearDown(self):
        conf.direct = self._direct
        conf.user = self._user
        umod.inject.getValue = self._gv
        umod.inject.checkBooleanExpression = self._cbe
        umod.storeHashesToFile = self._store
        umod.attackCachedUsersPasswords = self._attack
        umod.readInput = self._readInput
        if self._his is None:
            kb.data.pop("has_information_schema", None)
        else:
            kb.data.has_information_schema = self._his

    # --- getUsers -----------------------------------------------------------

    def test_get_users_mysql(self):
        umod.inject.getValue = lambda query, *a, **k: [["root"], ["guest"]]
        kb.data.cachedUsers = []
        res = Users().getUsers()
        self.assertIn("root", res)
        self.assertIn("guest", res)
        self.assertIn("root", kb.data.cachedUsers)

    def test_get_users_postgresql(self):
        set_dbms("PostgreSQL")
        umod.inject.getValue = lambda query, *a, **k: [["postgres"], ["app"]]
        kb.data.cachedUsers = []
        res = Users().getUsers()
        self.assertEqual(sorted(res), ["app", "postgres"])

    def test_get_users_mssql(self):
        set_dbms("Microsoft SQL Server")
        umod.inject.getValue = lambda query, *a, **k: [["sa"], ["dbo"]]
        kb.data.cachedUsers = []
        res = Users().getUsers()
        self.assertIn("sa", res)

    def test_get_users_oracle(self):
        set_dbms("Oracle")
        umod.inject.getValue = lambda query, *a, **k: [["SYS"], ["SYSTEM"]]
        kb.data.cachedUsers = []
        res = Users().getUsers()
        self.assertIn("SYS", res)

    def test_get_users_none_leaves_cache_empty(self):
        # isNoneValue([]) -> cache stays empty; inband branch skips appends.
        # Strengthen: prove getUsers actually QUERIED (no stale-cache short-circuit
        # returning the constant []) by spying on getValue, then in the same test
        # re-run with a non-empty result to prove the cache repopulates from the
        # newly fetched rows.
        calls = {"n": 0}

        def gv_empty(query, *a, **k):
            calls["n"] += 1
            return []

        umod.inject.getValue = gv_empty
        users = Users()
        kb.data.cachedUsers = []
        res = users.getUsers()
        self.assertEqual(res, [])
        # The inband branch must have issued at least one query, not short-circuited.
        self.assertGreaterEqual(calls["n"], 1)

        # Paired non-empty case: same instance, fresh cache, real rows -> cache
        # must repopulate with exactly those users.
        umod.inject.getValue = lambda query, *a, **k: [["root"], ["guest"]]
        kb.data.cachedUsers = []
        res2 = users.getUsers()
        self.assertEqual(sorted(res2), ["guest", "root"])
        self.assertIn("root", kb.data.cachedUsers)

    # --- getCurrentUser -----------------------------------------------------

    def test_get_current_user(self):
        umod.inject.getValue = lambda query, *a, **k: "root@localhost"
        users = Users()
        kb.data.currentUser = ""
        self.assertEqual(users.getCurrentUser(), "root@localhost")
        self.assertEqual(kb.data.currentUser, "root@localhost")

    # --- isDba --------------------------------------------------------------

    def test_is_dba_mysql(self):
        umod.inject.getValue = lambda query, *a, **k: "root@localhost"
        umod.inject.checkBooleanExpression = lambda query, *a, **k: True
        users = Users()
        kb.data.currentUser = ""
        kb.data.isDba = None
        self.assertTrue(users.isDba())

    def test_is_dba_postgresql_false(self):
        set_dbms("PostgreSQL")
        umod.inject.checkBooleanExpression = lambda query, *a, **k: False
        users = Users()
        kb.data.isDba = None
        self.assertFalse(users.isDba())

    # --- getPasswordHashes --------------------------------------------------

    def test_get_password_hashes_mysql(self):
        # filterPairValues keeps length-2 rows -> {user: [hash]}
        umod.inject.getValue = lambda query, *a, **k: [["root", "*ABC123"], ["guest", "*DEF456"]]
        users = Users()
        kb.data.cachedUsersPasswords = {}
        res = users.getPasswordHashes()
        self.assertIn("root", res)
        self.assertIn("guest", res)
        self.assertEqual(res["root"], ["*ABC123"])

    def test_get_password_hashes_with_conf_user(self):
        conf.user = "root@localhost"
        umod.inject.getValue = lambda query, *a, **k: [["root", "*HASH"]]
        users = Users()
        kb.data.cachedUsersPasswords = {}
        res = users.getPasswordHashes()
        self.assertIn("root", res)

    def test_get_password_hashes_oracle(self):
        set_dbms("Oracle")
        conf.user = "system"
        umod.inject.getValue = lambda query, *a, **k: [["SYSTEM", "ABCDEF1234567890"]]
        users = Users()
        kb.data.cachedUsersPasswords = {}
        res = users.getPasswordHashes()
        self.assertIn("SYSTEM", res)
        # conf.user upper-cased for Oracle
        self.assertEqual(conf.user, "SYSTEM")

    def test_get_password_hashes_current_user(self):
        conf.user = CURRENT_USER
        # First getValue resolves current user, subsequent ones return the rows.
        def gv(query, *a, **k):
            if "CURRENT_USER" in query.upper() or "current_user" in query:
                return "root@localhost"
            return [["root", "*HASH"]]
        umod.inject.getValue = gv
        users = Users()
        kb.data.currentUser = ""
        kb.data.cachedUsersPasswords = {}
        res = users.getPasswordHashes()
        self.assertIn("root", res)

    # --- getPrivileges ------------------------------------------------------

    def test_get_privileges_mysql(self):
        # MySQL with information_schema: privilege column added verbatim.
        umod.inject.getValue = lambda query, *a, **k: [["root", "SUPER"], ["guest", "SELECT"]]
        users = Users()
        kb.data.cachedUsersPrivileges = {}
        privileges, areAdmins = users.getPrivileges()
        self.assertIn("root", privileges)
        self.assertIn("SUPER", privileges["root"])
        self.assertIn("root", areAdmins)
        self.assertNotIn("guest", areAdmins)

    def test_get_privileges_postgresql(self):
        set_dbms("PostgreSQL")
        from lib.core.dicts import PGSQL_PRIVS
        # PGSQL: digit columns map to PGSQL_PRIVS by column index; col 1 == True.
        idx = sorted(PGSQL_PRIVS.keys())[0]
        row = ["pguser"] + ["0"] * (max(PGSQL_PRIVS.keys()))
        row[idx] = "1"
        umod.inject.getValue = lambda query, *a, **k: [row]
        users = Users()
        kb.data.cachedUsersPrivileges = {}
        privileges, areAdmins = users.getPrivileges()
        self.assertIn("pguser", privileges)
        self.assertIn(PGSQL_PRIVS[idx], privileges["pguser"])

    def test_get_privileges_oracle(self):
        set_dbms("Oracle")
        umod.inject.getValue = lambda query, *a, **k: [["SYS", "DBA"]]
        users = Users()
        kb.data.cachedUsersPrivileges = {}
        privileges, areAdmins = users.getPrivileges()
        self.assertIn("SYS", privileges)
        self.assertIn("DBA", privileges["SYS"])
        self.assertIn("SYS", areAdmins)

    def test_get_privileges_with_conf_user(self):
        conf.user = "root"
        umod.inject.getValue = lambda query, *a, **k: [["root", "SELECT"]]
        users = Users()
        kb.data.cachedUsersPrivileges = {}
        privileges, areAdmins = users.getPrivileges()
        self.assertIn("root", privileges)

    # --- getRoles (delegates to getPrivileges) ------------------------------

    def test_get_roles(self):
        umod.inject.getValue = lambda query, *a, **k: [["root", "SUPER"]]
        users = Users()
        kb.data.cachedUsersPrivileges = {}
        privileges, areAdmins = users.getRoles()
        self.assertIn("root", privileges)
        self.assertIn("root", areAdmins)


if __name__ == "__main__":
    unittest.main()
