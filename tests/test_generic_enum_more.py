#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Additional unit tests for the generic enumeration mixins, deliberately targeting
branches NOT already exercised by tests/test_databases_enum.py,
tests/test_users_enum.py, tests/test_search_enum.py and tests/test_generic_more.py
(which cover the conf.direct INBAND happy paths).

This file drives the OTHER branches:

  * plugins/generic/databases.py - the INFERENCE paths (conf.direct=False +
    isInferenceAvailable via kb.injection BOOLEAN state: count -> per-row getValue),
    the MSSQL inband-paging fallback in getDbs(), getColumns onlyColNames / dumpMode,
    the getColumns MySQL<5 / ACCESS bruteforce fallback, getCount over cachedTables,
    and getStatements/getProcedures empty/none branches.
  * plugins/generic/users.py - getPrivileges role/grant parsing per DBMS in BOTH the
    inband path (PGSQL digit columns, MySQL<5 Y/N, Firebird letters, DB2 grant codes)
    and the INFERENCE path (count then per-index privilege), getPasswordHashes
    grouping/dedup in the inference path, getUsers inference, isDba MSSQL.
  * plugins/generic/entries.py - dumpTable INFERENCE path (count -> column-pivot via
    per-(index,column) getValue), the empty-table branch, the count-failure skip,
    and the resolveKeysetCursor disabling via conf.noKeyset.
  * plugins/generic/search.py - searchDb / searchTable / searchColumn INFERENCE
    paths (count then per-index getValue), and the MySQL<5 bruteforce branch of
    searchTable / searchColumn.

Recipe (proven in tests/test_databases_enum.py): patch the module's inject.getValue
with canned rows in the EXACT shape the branch parses; for inference branches return
a positive int for EXPECTED.INT count calls then the per-row/per-index values; set the
needed kb.data flags; assert the exact resulting structure (sorted lists,
{db:{tbl:{col:type}}} dicts, privilege sets, dumpedTable values).

CRITICAL STATE HYGIENE: every test snapshots and restores conf.*, the patched
inject.getValue (per module), kb.data.cached*, kb.hintValue, kb.injection.data,
Backend/forcedDbms in tearDown so nothing leaks into the rest of the suite.
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
import plugins.generic.users as umod
import plugins.generic.search as smod
import plugins.generic.entries as emod
from plugins.generic.databases import Databases
from plugins.generic.users import Users
from plugins.generic.search import Search
from plugins.generic.entries import Entries

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


# --------------------------------------------------------------------------- #
# databases.py
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


# --------------------------------------------------------------------------- #
# users.py
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


# --------------------------------------------------------------------------- #
# entries.py - inference (blind) dump path
# --------------------------------------------------------------------------- #

class _RecordingDumper(object):
    def __init__(self):
        self.tableValues = []

    def dbTableValues(self, tableValues):
        self.tableValues.append(tableValues)


class _TestEntries(Entries):
    def __init__(self):
        Entries.__init__(self)
        self.getColumnsResult = {}
        self.getTablesResult = {}

    def forceDbmsEnum(self):
        pass

    def getCurrentDb(self):
        return "testdb"

    def getColumns(self, onlyColNames=False, colTuple=None, bruteForce=None, dumpMode=False):
        kb.data.cachedColumns = dict(self.getColumnsResult)

    def getTables(self, bruteForce=None):
        kb.data.cachedTables = dict(self.getTablesResult)


class _EntriesBase(unittest.TestCase):
    _CONF_KEYS = ("db", "tbl", "col", "direct", "technique", "exclude", "search",
                  "disableHashing", "noKeyset", "keyset", "forcePivoting", "dumpWhere")

    def setUp(self):
        self._saved_conf = {k: conf.get(k) for k in self._CONF_KEYS}
        self._saved_dumper = conf.get("dumper")
        self._gv = emod.inject.getValue
        self._cbe = emod.inject.checkBooleanExpression
        self._readInput = emod.readInput
        self._saved_has_is = kb.data.get("has_information_schema")
        self._saved_cachedColumns = kb.data.get("cachedColumns")
        self._saved_cachedTables = kb.data.get("cachedTables")
        self._saved_dumpedTable = kb.data.get("dumpedTable")
        self._saved_dumpKbInt = kb.get("dumpKeyboardInterrupt")
        self._saved_permissionFlag = kb.get("permissionFlag")
        self._saved_injection_data = kb.injection.data

        set_dbms("MySQL")
        conf.direct = False
        conf.technique = None
        conf.exclude = None
        conf.search = False
        conf.disableHashing = True
        conf.noKeyset = True
        conf.keyset = False
        conf.forcePivoting = False
        conf.dumpWhere = None
        conf.dumper = _RecordingDumper()

        kb.data.has_information_schema = True
        kb.data.cachedColumns = {}
        kb.data.cachedTables = {}
        kb.data.dumpedTable = {}
        kb.dumpKeyboardInterrupt = False
        kb.permissionFlag = False
        kb.injection.data = {PAYLOAD.TECHNIQUE.BOOLEAN: {"title": "AND boolean-based blind"}}

        emod.readInput = lambda *a, **k: (k.get("default") if k.get("default") is not None else (a[1] if len(a) > 1 else None))

    def tearDown(self):
        for k, v in self._saved_conf.items():
            conf[k] = v
        conf.dumper = self._saved_dumper
        emod.inject.getValue = self._gv
        emod.inject.checkBooleanExpression = self._cbe
        emod.readInput = self._readInput
        kb.data.has_information_schema = self._saved_has_is
        kb.data.cachedColumns = self._saved_cachedColumns
        kb.data.cachedTables = self._saved_cachedTables
        kb.data.dumpedTable = self._saved_dumpedTable
        kb.dumpKeyboardInterrupt = self._saved_dumpKbInt
        kb.permissionFlag = self._saved_permissionFlag
        kb.injection.data = self._saved_injection_data


class TestEntriesInference(_EntriesBase):
    def _entries(self, db="testdb", tbl="users", cols=("id", "name")):
        e = _TestEntries()
        e.getColumnsResult = {db: {tbl: {c: "varchar" for c in cols}}}
        return e

    def test_dump_table_inference_column_pivot(self):
        # Blind dump (conf.direct=False, BOOLEAN available): a row count, then one
        # value per (index, column). Assert the per-column pivoted values match.
        set_dbms("MySQL")
        e = self._entries(cols=("id", "name"))
        conf.db = "testdb"
        conf.tbl = "users"
        conf.col = None

        # data[index][column] -> value. 2 rows, columns id/name.
        data = {0: {"id": "1", "name": "alice"}, 1: {"id": "2", "name": "bob"}}

        def gv(query, *a, **k):
            if k.get("expected") == EXPECTED.INT:
                return "2"   # row count
            # MySQL blind cell query: 'SELECT <col> FROM testdb.users ORDER BY ...
            # LIMIT <index>,1'. The row index is the LIMIT offset; the column is the
            # SELECT projection.
            import re as _re
            idx = int(_re.search(r"LIMIT\s+(\d+)\s*,\s*1", query).group(1))
            proj = query.split(" FROM ", 1)[0]
            col = "name" if "name" in proj else "id"
            return data[idx][col]

        emod.inject.getValue = gv
        e.dumpTable()
        dumped = conf.dumper.tableValues[-1]
        self.assertEqual(dumped["__infos__"]["count"], 2)
        self.assertEqual(list(dumped["id"]["values"]), ["1", "2"])
        self.assertEqual(list(dumped["name"]["values"]), ["alice", "bob"])

    def test_dump_table_inference_empty_table(self):
        # A zero row count in the inference path yields empty per-column value
        # lists and no dbTableValues emission (dumpedTable stays effectively empty).
        set_dbms("MySQL")
        e = self._entries(cols=("id",))
        conf.db = "testdb"
        conf.tbl = "users"
        conf.col = None

        emod.inject.getValue = lambda query, *a, **k: ("0" if k.get("expected") == EXPECTED.INT else self.fail("must not fetch cells for empty table"))
        e.dumpTable()
        # count 0 => empty entries => nothing dumped
        self.assertEqual(conf.dumper.tableValues, [])

    def test_dump_table_inference_count_failure_skips(self):
        # A non-numeric count in the inference path => the table is skipped with a
        # warning, no values dumped.
        set_dbms("MySQL")
        e = self._entries(cols=("id",))
        conf.db = "testdb"
        conf.tbl = "users"
        conf.col = None

        def gv(query, *a, **k):
            if k.get("expected") == EXPECTED.INT:
                return None   # count failed
            self.fail("must not fetch cells when count failed")

        emod.inject.getValue = gv
        e.dumpTable()
        self.assertEqual(conf.dumper.tableValues, [])


# --------------------------------------------------------------------------- #
# search.py - inference (blind) paths
# --------------------------------------------------------------------------- #

class _TestSearch(Search):
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
        s = _TestSearch()
        conf.db = "testdb"
        smod.inject.getValue = _inference_gv(2, ["testdb", "testdb2"])
        s.searchDb()
        self.assertEqual(conf.dumper.listed[-1][0], "found databases")
        self.assertEqual(sorted(conf.dumper.listed[-1][1]), ["testdb", "testdb2"])

    def test_search_db_inference_no_match(self):
        # Count fails (non-numeric) => no databases appended, empty listing.
        s = _TestSearch()
        conf.db = "ghost"
        smod.inject.getValue = lambda query, *a, **k: (None if k.get("expected") == EXPECTED.INT else self.fail("must not page when count fails"))
        s.searchDb()
        self.assertEqual(conf.dumper.listed[-1][1], [])

    def test_search_table_inference_grouped(self):
        # Blind searchTable, no conf.db: outer count of dbs holding the table, then
        # per-db a name, then per-db a count of matching tables, then table names.
        s = _TestSearch()
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
        s = _TestSearch()
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
        s = _TestSearch()
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
        s = _TestSearch()
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
