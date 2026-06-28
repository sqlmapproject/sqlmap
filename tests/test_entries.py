#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit tests for plugins/generic/entries.py (Entries), exercising dumpTable /
dumpAll / dumpFoundTables / dumpFoundColumn by MOCKING the injection layer
(lib.request.inject.getValue) and the dumper.

No network and no DBMS are involved: conf.direct=True selects the simple inband
branches, or conf.direct=False with a BOOLEAN injection state selects the
inference (blind) branches; inject.getValue is patched to return canned rows in
the exact shape the methods parse, and conf.dumper is replaced with a recording
stub so we can assert on what each method produced (kb.data caches / returned
dicts). Every test restores all touched conf.* / kb.* / patched module attributes
in tearDown so nothing leaks.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms

bootstrap()

from lib.core.common import Backend
from lib.core.data import conf, kb
from lib.core.enums import EXPECTED, PAYLOAD

import plugins.generic.search as smod
import plugins.generic.entries as emod
import plugins.generic.custom as cmod
import plugins.generic.misc as mmod
from plugins.generic.entries import Entries


# --------------------------------------------------------------------------- #
# Helpers/base from tests/test_search_enum.py (inband TestEntries)
# --------------------------------------------------------------------------- #

class _RecordingDumperSE(object):
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


class _TestEntriesSE(Entries):
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
        conf.dumper = _RecordingDumperSE()

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


class TestEntries(_SearchEnumBase):
    def _entries_with_cols(self, db="testdb", tbl="users", cols=("id", "name")):
        e = _TestEntriesSE()
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
        e = _TestEntriesSE()
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
        e = _TestEntriesSE()
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
        e = _TestEntriesSE()
        conf.db = "a,b"
        conf.tbl = "users"
        conf.col = None
        from lib.core.exception import SqlmapMissingMandatoryOptionException
        self.assertRaises(SqlmapMissingMandatoryOptionException, e.dumpTable)

    def test_dump_table_get_tables_when_no_tbl(self):
        e = _TestEntriesSE()
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


# --------------------------------------------------------------------------- #
# Helpers/base from tests/test_generic_more.py (inband dump branches)
# --------------------------------------------------------------------------- #

class _RecordingDumperGM(object):
    """Recording stand-in for conf.dumper (no printing / file writing)."""

    def __init__(self):
        self.tableValues = []
        self.sqlQueries = []

    def dbTableValues(self, tableValues):
        self.tableValues.append(tableValues)

    def sqlQuery(self, query, queryRes):
        self.sqlQueries.append((query, queryRes))


class _TestEntriesGM(Entries):
    """Entries with cross-mixin collaborators stubbed.

    forceDbmsEnum / getCurrentDb / getColumns / getTables are normally supplied by
    sibling mixins; we emulate column/table discovery by populating kb.data.cached*
    from canned attributes, exactly as the production plugins do.
    """

    def __init__(self):
        Entries.__init__(self)
        self.getColumnsResult = {}     # assigned to kb.data.cachedColumns
        self.getTablesResult = {}      # assigned to kb.data.cachedTables
        self.getColumnsCalls = []
        self.getTablesCalls = 0

    def forceDbmsEnum(self):
        pass

    def getCurrentDb(self):
        return "testdb"

    def getColumns(self, onlyColNames=False, colTuple=None, bruteForce=None, dumpMode=False):
        self.getColumnsCalls.append((conf.db, conf.tbl))
        kb.data.cachedColumns = dict(self.getColumnsResult)

    def getTables(self, bruteForce=None):
        self.getTablesCalls += 1
        kb.data.cachedTables = dict(self.getTablesResult)


class _GenericBase(unittest.TestCase):
    """Snapshot/restore for everything the generic mixins touch."""

    _CONF_KEYS = (
        "db", "tbl", "col", "direct", "batch", "exclude", "search",
        "disableHashing", "noKeyset", "keyset", "forcePivoting", "dumpWhere",
        "tmpPath", "sqlQuery", "sqlFile", "regKey", "regVal", "regData",
        "regType", "osPwn", "osShell", "cleanup", "privEsc",
    )

    def setUp(self):
        self._saved_conf = {k: conf.get(k) for k in self._CONF_KEYS}
        self._saved_dumper = conf.get("dumper")

        self._saved_getValue = {
            emod: emod.inject.getValue,
            cmod: cmod.inject.getValue,
            mmod: mmod.inject.getValue,
        }
        self._saved_goStacked = {
            cmod: cmod.inject.goStacked,
            mmod: mmod.inject.goStacked,
        }
        self._saved_emod_readInput = emod.readInput
        self._saved_mmod_readInput = mmod.readInput

        self._saved_kb = {
            "cachedColumns": kb.data.get("cachedColumns"),
            "cachedTables": kb.data.get("cachedTables"),
            "dumpedTable": kb.data.get("dumpedTable"),
            "has_information_schema": kb.data.get("has_information_schema"),
            "dumpKeyboardInterrupt": kb.get("dumpKeyboardInterrupt"),
            "permissionFlag": kb.get("permissionFlag"),
            "hintValue": kb.get("hintValue"),
            "injection_data": kb.injection.data,
            "bannerFp": kb.get("bannerFp"),
            "os": kb.get("os"),
        }
        self._saved_forceDbms = kb.get("forcedDbms")

        conf.direct = True
        conf.batch = True
        conf.exclude = None
        conf.search = False
        conf.disableHashing = True
        conf.noKeyset = True
        conf.keyset = False
        conf.forcePivoting = False
        conf.dumpWhere = None
        conf.dumper = _RecordingDumperGM()

        kb.data.cachedColumns = {}
        kb.data.cachedTables = {}
        kb.data.dumpedTable = {}
        kb.data.has_information_schema = True
        kb.dumpKeyboardInterrupt = False
        kb.permissionFlag = False

        def _readInput(message, default=None, checkBatch=True, boolean=False):
            if boolean:
                return default in (None, 'Y', 'y', True)
            return default

        emod.readInput = _readInput
        mmod.readInput = _readInput

    def tearDown(self):
        for k, v in self._saved_conf.items():
            conf[k] = v
        conf.dumper = self._saved_dumper

        for mod, fn in self._saved_getValue.items():
            mod.inject.getValue = fn
        for mod, fn in self._saved_goStacked.items():
            mod.inject.goStacked = fn
        emod.readInput = self._saved_emod_readInput
        mmod.readInput = self._saved_mmod_readInput

        kb.data.cachedColumns = self._saved_kb["cachedColumns"]
        kb.data.cachedTables = self._saved_kb["cachedTables"]
        kb.data.dumpedTable = self._saved_kb["dumpedTable"]
        kb.data.has_information_schema = self._saved_kb["has_information_schema"]
        kb.dumpKeyboardInterrupt = self._saved_kb["dumpKeyboardInterrupt"]
        kb.permissionFlag = self._saved_kb["permissionFlag"]
        kb.hintValue = self._saved_kb["hintValue"]
        kb.injection.data = self._saved_kb["injection_data"]
        kb.bannerFp = self._saved_kb["bannerFp"]
        kb.os = self._saved_kb["os"]
        kb.forcedDbms = self._saved_forceDbms

    @staticmethod
    def _force_os(os_name):
        # Backend.setOs only assigns when kb.os is currently None; reset first so
        # tests can deterministically pin the back-end OS.
        kb.os = None
        Backend.setOs(os_name)


class TestEntriesDumpTable(_GenericBase):
    def _entries(self, db="testdb", tbl="users", cols=("id", "name")):
        e = _TestEntriesGM()
        e.getColumnsResult = {db: {tbl: {c: "varchar" for c in cols}}}
        return e

    def test_exclude_filters_columns(self):
        set_dbms("MySQL")
        e = self._entries(cols=("id", "secret"))
        conf.db = "testdb"
        conf.tbl = "users"
        conf.col = None
        conf.exclude = "secret"
        emod.inject.getValue = lambda *a, **k: [["1"]]

        e.dumpTable()
        dumped = conf.dumper.tableValues[-1]
        self.assertIn("id", dumped)
        self.assertNotIn("secret", dumped)

    def test_exclude_all_columns_skips(self):
        set_dbms("MySQL")
        e = self._entries(cols=("secret",))
        conf.db = "testdb"
        conf.tbl = "users"
        conf.col = None
        conf.exclude = "secret"
        emod.inject.getValue = lambda *a, **k: self.fail("should not fetch entries")

        e.dumpTable()
        # all columns excluded => "no usable column names" => nothing dumped
        self.assertEqual(conf.dumper.tableValues, [])

    def test_dumpwhere_rewrites_query(self):
        set_dbms("MySQL")
        e = self._entries(cols=("id",))
        conf.db = "testdb"
        conf.tbl = "users"
        conf.col = None
        conf.dumpWhere = "id>5"
        captured = {}

        def gv(query, *a, **k):
            captured["query"] = query
            return [["9"]]

        emod.inject.getValue = gv
        e.dumpTable()
        # agent.whereQuery folds conf.dumpWhere into the dump query
        self.assertIn("id>5", captured["query"])
        self.assertEqual(list(conf.dumper.tableValues[-1]["id"]["values"]), ["9"])

    def test_disablehashing_false_path(self):
        # conf.disableHashing False => attackDumpedTable() is invoked; with no
        # hashes present it must complete without raising and still emit values.
        set_dbms("MySQL")
        e = self._entries(cols=("id", "name"))
        conf.db = "testdb"
        conf.tbl = "users"
        conf.col = None
        conf.disableHashing = False
        emod.inject.getValue = lambda *a, **k: [["1", "alice"]]

        # Spy on attackDumpedTable: with disableHashing False it MUST be invoked
        # after the values are dumped. A recorder replaces it so we can assert the
        # call happened (and no real dictionary attack runs).
        saved_attack = emod.attackDumpedTable
        calls = {"n": 0}
        emod.attackDumpedTable = lambda *a, **k: calls.__setitem__("n", calls["n"] + 1)
        try:
            e.dumpTable()
        finally:
            emod.attackDumpedTable = saved_attack

        self.assertEqual(calls["n"], 1)
        self.assertEqual(conf.dumper.tableValues[-1]["__infos__"]["count"], 1)

    def test_missing_columns_skips_table(self):
        # getColumns yields nothing for the targeted table => skip without fetching.
        set_dbms("MySQL")
        e = _TestEntriesGM()
        e.getColumnsResult = {"testdb": {"other": {"id": "int"}}}
        conf.db = "testdb"
        conf.tbl = "users"
        conf.col = None
        emod.inject.getValue = lambda *a, **k: self.fail("should not fetch entries")

        e.dumpTable()
        self.assertEqual(conf.dumper.tableValues, [])

    def test_multiple_tables_one_dumped(self):
        set_dbms("MySQL")
        e = _TestEntriesGM()
        e.getColumnsResult = {"testdb": {"users": {"id": "int"}, "posts": {"pid": "int"}}}
        conf.db = "testdb"
        conf.tbl = "users,posts"
        conf.col = None
        emod.inject.getValue = lambda *a, **k: [["1"]]

        e.dumpTable()
        # both tables share the same cachedColumns dict => both dumped
        tables = [tv["__infos__"]["table"] for tv in conf.dumper.tableValues]
        self.assertIn("users", tables)
        self.assertIn("posts", tables)

    def test_metadb_suffix_db(self):
        # A db whose name carries the METADB_SUFFIX must not get a "db" prefix in
        # kb.dumpTable, and dumping still succeeds.
        from lib.core.settings import METADB_SUFFIX
        set_dbms("MySQL")
        metadb = "x%s" % METADB_SUFFIX
        e = self._entries(db=metadb, tbl="t", cols=("c",))
        conf.db = metadb
        conf.tbl = "t"
        conf.col = None
        emod.inject.getValue = lambda *a, **k: [["v"]]

        e.dumpTable()
        self.assertEqual(list(conf.dumper.tableValues[-1]["c"]["values"]), ["v"])


class TestEntriesDumpAll(_GenericBase):
    def test_dumpall_multiple_dbs_tables(self):
        set_dbms("MySQL")
        e = _TestEntriesGM()
        conf.db = None
        conf.tbl = None
        conf.col = None
        e.getTablesResult = {"db1": ["t1"], "db2": ["t2"]}
        # dumpTable re-discovers columns per (db, tbl); supply both.
        e.getColumnsResult = {
            "db1": {"t1": {"a": "int"}},
            "db2": {"t2": {"b": "int"}},
        }
        emod.inject.getValue = lambda *a, **k: [["x"]]

        e.dumpAll()
        # Every table contributed a values batch.
        self.assertEqual(len(conf.dumper.tableValues), 2)

    def test_dumpall_list_cached_tables(self):
        # cachedTables as a bare list => wrapped under {None: [...]}.
        set_dbms("MySQL")
        e = _TestEntriesGM()
        conf.db = None
        conf.tbl = None
        conf.col = None

        # getTables sets cachedTables; emulate the list shape directly.
        class _ListTables(_TestEntriesGM):
            def getTables(self_inner, bruteForce=None):
                kb.data.cachedTables = ["users"]

        e = _ListTables()
        # dumpAll wraps a bare list as {None: [...]}; dumpTable then resolves the
        # None db via getCurrentDb() -> "testdb", so columns live under "testdb".
        e.getColumnsResult = {"testdb": {"users": {"id": "int"}}}
        emod.inject.getValue = lambda *a, **k: [["1"]]

        e.dumpAll()
        self.assertTrue(conf.dumper.tableValues)
        # The bare-list None db must be resolved via getCurrentDb() -> "testdb"
        # before the dump; assert the dumped __infos__ carries the real db (not
        # None) for the requested "users" table.
        infos = conf.dumper.tableValues[-1]["__infos__"]
        self.assertEqual(infos["db"], "testdb")
        self.assertEqual(infos["table"], "users")

    def test_dumpall_exclude_skips_table(self):
        set_dbms("MySQL")
        e = _TestEntriesGM()
        conf.db = None
        conf.tbl = None
        conf.col = None
        conf.exclude = "secret"
        e.getTablesResult = {"db1": ["secret", "users"]}
        e.getColumnsResult = {"db1": {"users": {"id": "int"}, "secret": {"id": "int"}}}
        emod.inject.getValue = lambda *a, **k: [["1"]]

        e.dumpAll()
        tables = [tv["__infos__"]["table"] for tv in conf.dumper.tableValues]
        self.assertIn("users", tables)
        self.assertNotIn("secret", tables)


class TestEntriesDumpFound(_GenericBase):
    def _entries(self):
        e = _TestEntriesGM()
        e.getColumnsResult = {"testdb": {"users": {"id": "int"}}}
        return e

    def test_dump_found_tables_yes_all(self):
        set_dbms("MySQL")
        e = self._entries()
        emod.inject.getValue = lambda *a, **k: [["1"]]
        # batch readInput -> 'Y' (boolean True) and 'a'/'a' for db/table choices.
        e.dumpFoundTables({"testdb": ["users"]})
        self.assertTrue(conf.dumper.tableValues)
        # The interactive selection must dump the REQUESTED db/table, not just
        # "something": assert the dumped __infos__ maps to testdb.users.
        infos = conf.dumper.tableValues[-1]["__infos__"]
        self.assertEqual(infos["db"], "testdb")
        self.assertEqual(infos["table"], "users")

    def test_dump_found_tables_declined(self):
        set_dbms("MySQL")
        e = self._entries()

        def _no(message, default=None, checkBatch=True, boolean=False):
            if boolean:
                return False
            return default

        emod.readInput = _no
        emod.inject.getValue = lambda *a, **k: self.fail("must not dump when declined")
        e.dumpFoundTables({"testdb": ["users"]})
        self.assertEqual(conf.dumper.tableValues, [])

    def test_dump_found_column_yes_all(self):
        set_dbms("MySQL")
        e = self._entries()
        emod.inject.getValue = lambda *a, **k: [["1"]]
        dbs = {"testdb": {"users": {"id": "int"}}}
        e.dumpFoundColumn(dbs, foundCols=None, colConsider='1')
        self.assertTrue(conf.dumper.tableValues)
        # The selection must dump the REQUESTED db/table mapping, not just
        # "something": assert the dumped __infos__ maps to testdb.users.
        infos = conf.dumper.tableValues[-1]["__infos__"]
        self.assertEqual(infos["db"], "testdb")
        self.assertEqual(infos["table"], "users")


# --------------------------------------------------------------------------- #
# Helpers/base from tests/test_generic_enum_more.py (inference branches)
# --------------------------------------------------------------------------- #

class _RecordingDumperInf(object):
    def __init__(self):
        self.tableValues = []

    def dbTableValues(self, tableValues):
        self.tableValues.append(tableValues)


class _TestEntriesInf(Entries):
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
        conf.dumper = _RecordingDumperInf()

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
        e = _TestEntriesInf()
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


if __name__ == "__main__":
    unittest.main()
