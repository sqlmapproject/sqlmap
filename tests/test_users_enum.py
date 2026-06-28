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
container was populated. Inference (blind) branches set conf.direct = False with a
BOOLEAN technique present and follow the count-then-per-index contract.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms

bootstrap()

from lib.core.data import conf, kb
from lib.core.enums import EXPECTED, PAYLOAD
import plugins.generic.users as umod
from plugins.generic.users import Users
from lib.core.settings import CURRENT_USER


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


# --------------------------------------------------------------------------- #
# Privilege parsing / inference branches (relocated from test_generic_enum_more.py)
# --------------------------------------------------------------------------- #

class _UsersBase(unittest.TestCase):
    def setUp(self):
        self._direct = conf.direct
        self._technique = conf.technique
        self._user = conf.user
        self._gv = umod.inject.getValue
        self._cbe = umod.inject.checkBooleanExpression
        self._store = umod.storeHashesToFile
        self._attack = umod.attackCachedUsersPasswords
        self._readInput = umod.readInput
        self._his = kb.data.get("has_information_schema")
        self._injection_data = kb.injection.data

        set_dbms("MySQL")
        conf.direct = True
        conf.user = None
        kb.data.has_information_schema = True

        umod.storeHashesToFile = lambda *a, **k: None
        umod.attackCachedUsersPasswords = lambda *a, **k: None
        umod.readInput = lambda *a, **k: "N"

    def tearDown(self):
        conf.direct = self._direct
        conf.technique = self._technique
        conf.user = self._user
        umod.inject.getValue = self._gv
        umod.inject.checkBooleanExpression = self._cbe
        umod.storeHashesToFile = self._store
        umod.attackCachedUsersPasswords = self._attack
        umod.readInput = self._readInput
        kb.injection.data = self._injection_data
        if self._his is None:
            kb.data.pop("has_information_schema", None)
        else:
            kb.data.has_information_schema = self._his

    def _inference(self):
        conf.direct = False
        conf.technique = None
        kb.injection.data = {PAYLOAD.TECHNIQUE.BOOLEAN: {"title": "AND boolean-based blind"}}


class TestUsersPrivilegesInband(_UsersBase):
    def test_privileges_pgsql_multiple_digit_columns(self):
        # PostgreSQL: privilege columns are digit flags; a column index maps to
        # PGSQL_PRIVS only when its value is "1". Set createdb(1)=1 and super(2)=1,
        # leave the rest 0; assert exactly those two privileges are parsed and that
        # "super" makes the user an admin.
        set_dbms("PostgreSQL")
        from lib.core.dicts import PGSQL_PRIVS
        ncols = max(PGSQL_PRIVS.keys())
        row = ["pguser"] + ["0"] * ncols
        row[1] = "1"   # createdb
        row[2] = "1"   # super
        umod.inject.getValue = lambda query, *a, **k: [row]
        users = Users()
        kb.data.cachedUsersPrivileges = {}
        privileges, areAdmins = users.getPrivileges()
        self.assertEqual(set(privileges["pguser"]), {PGSQL_PRIVS[1], PGSQL_PRIVS[2]})
        self.assertIn("pguser", areAdmins)

    def test_privileges_mysql_lt5_yn_flags(self):
        # MySQL < 5 (no information_schema): privilege columns are 'Y'/'N' flags
        # mapped to MYSQL_PRIVS by column position. Y in col 1 -> select_priv.
        set_dbms("MySQL")
        from lib.core.dicts import MYSQL_PRIVS
        kb.data.has_information_schema = False
        ncols = max(MYSQL_PRIVS.keys())
        row = ["root"] + ["N"] * ncols
        row[1] = "Y"   # select_priv
        row[3] = "Y"   # update_priv
        umod.inject.getValue = lambda query, *a, **k: [row]
        users = Users()
        kb.data.cachedUsersPrivileges = {}
        privileges, areAdmins = users.getPrivileges()
        self.assertIn(MYSQL_PRIVS[1], privileges["root"])
        self.assertIn(MYSQL_PRIVS[3], privileges["root"])
        self.assertNotIn(MYSQL_PRIVS[2], privileges["root"])

    def test_privileges_firebird_letter_codes(self):
        # Firebird: each privilege is a single letter mapped via FIREBIRD_PRIVS.
        set_dbms("Firebird")
        from lib.core.dicts import FIREBIRD_PRIVS
        umod.inject.getValue = lambda query, *a, **k: [["fbuser", "S"], ["fbuser", "I"]]
        users = Users()
        kb.data.cachedUsersPrivileges = {}
        privileges, areAdmins = users.getPrivileges()
        self.assertEqual(set(privileges["fbuser"]),
                         {FIREBIRD_PRIVS["S"], FIREBIRD_PRIVS["I"]})

    def test_privileges_db2_grant_codes(self):
        # DB2: privilege string is "<name>,<grant-letters>"; each 'Y'/'G' letter at
        # position i appends the DB2_PRIVS[i] name to the privilege.
        set_dbms("DB2")
        from lib.core.dicts import DB2_PRIVS
        conf.user = "db2admin"
        # "DBADM" plus a grant string whose first letter (position 1) is 'Y' ->
        # DB2_PRIVS[1] ("CONTROLAUTH") is appended.
        umod.inject.getValue = lambda query, *a, **k: [["DB2ADMIN", "DBADM,Y"]]
        users = Users()
        kb.data.cachedUsersPrivileges = {}
        privileges, areAdmins = users.getPrivileges()
        joined = " ".join(privileges["DB2ADMIN"])
        self.assertIn("DBADM", joined)
        self.assertIn(DB2_PRIVS[1], joined)


class TestUsersPrivilegesInference(_UsersBase):
    def test_privileges_inference_mysql(self):
        # Blind privilege enumeration for a named user: count, then one privilege
        # string per index. MySQL >= 5 adds each verbatim.
        set_dbms("MySQL")
        self._inference()
        conf.user = "root"
        privs = ["SELECT", "SUPER"]
        umod.inject.getValue = _inference_gv(2, privs)
        users = Users()
        kb.data.cachedUsersPrivileges = {}
        privileges, areAdmins = users.getPrivileges()
        # the user key is wildcard-wrapped for the MySQL information_schema LIKE
        key = [k for k in privileges if "root" in k][0]
        self.assertEqual(set(privileges[key]), {"SELECT", "SUPER"})
        self.assertTrue(areAdmins)   # SUPER => admin

    def test_privileges_inference_oracle(self):
        set_dbms("Oracle")
        self._inference()
        conf.user = "system"
        umod.inject.getValue = _inference_gv(1, ["DBA"])
        users = Users()
        kb.data.cachedUsersPrivileges = {}
        privileges, areAdmins = users.getPrivileges()
        self.assertIn("SYSTEM", privileges)
        self.assertEqual(privileges["SYSTEM"], ["DBA"])
        self.assertIn("SYSTEM", areAdmins)


class TestUsersPasswordHashesInference(_UsersBase):
    def test_password_hashes_inference_grouping(self):
        # Blind password-hash enumeration for two users: per-user count, then one
        # hash per index. Assert each user maps to its own hash list.
        set_dbms("MySQL")
        self._inference()
        conf.user = "root,guest"

        # per-user single hash; count is 1 for every user
        hashes = {"root": "*ROOTHASH", "guest": "*GUESTHASH"}

        def gv(query, *a, **k):
            if k.get("expected") == EXPECTED.INT:
                return "1"
            for u, h in hashes.items():
                if u in query:
                    return [h]
            return [None]

        umod.inject.getValue = gv
        users = Users()
        kb.data.cachedUsersPasswords = {}
        res = users.getPasswordHashes()
        self.assertEqual(res["root"], ["*ROOTHASH"])
        self.assertEqual(res["guest"], ["*GUESTHASH"])

    def test_password_hashes_inference_dedup(self):
        # The same hash returned twice for a user must be de-duplicated at the end
        # (kb.data.cachedUsersPasswords[user] = list(set(...))).
        set_dbms("MySQL")
        self._inference()
        conf.user = "root"
        umod.inject.getValue = _inference_gv(2, ["*DUP", "*DUP"])
        users = Users()
        kb.data.cachedUsersPasswords = {}
        res = users.getPasswordHashes()
        self.assertEqual(res["root"], ["*DUP"])


class TestUsersGetUsersInference(_UsersBase):
    def test_get_users_inference(self):
        set_dbms("MySQL")
        self._inference()
        umod.inject.getValue = _inference_gv(2, ["root@localhost", "guest@%"])
        users = Users()
        kb.data.cachedUsers = []
        res = users.getUsers()
        self.assertEqual(sorted(res), ["guest@%", "root@localhost"])

    def test_is_dba_mssql(self):
        # MSSQL isDba goes through the generic checkBooleanExpression branch.
        set_dbms("Microsoft SQL Server")
        umod.inject.checkBooleanExpression = lambda query, *a, **k: True
        users = Users()
        kb.data.isDba = None
        self.assertTrue(users.isDba())


if __name__ == "__main__":
    unittest.main()
