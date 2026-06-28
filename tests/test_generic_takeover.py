#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit tests for the generic plugin mixins covering:

  * plugins/generic/custom.py   - sqlQuery SELECT/non-query/stacked branches, the
    MSSQL FROM rewrite, METADB suffix stripping, SqlmapNoneDataException handling,
    and sqlFile.
  * plugins/generic/misc.py     - getRemoteTempPath (posix / windows-direct / MSSQL
    ErrorLog), getVersionFromBanner, delRemoteFile, createSupportTbl, likeOrExact.
  * plugins/generic/takeover.py - the PURE helpers only: Takeover.__init__ table
    naming and the regRead/regAdd/regDel/osBof/osSmb control flow with the process/
    network collaborators stubbed out (no metasploit/icmpsh/UDF spawning).

The injection layer (lib.request.inject.{getValue,goStacked}) is patched per
module, conf.direct=True selects the simple inband branches, conf.batch=True keeps
prompts non-interactive, and conf.dumper is a recording stub. Every test restores
all touched conf.* / kb.* / patched module attributes in tearDown so nothing leaks.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms

bootstrap()

from lib.core.common import Backend
from lib.core.data import conf, kb
from lib.core.enums import OS
from lib.core.settings import NULL

import plugins.generic.entries as emod
import plugins.generic.custom as cmod
import plugins.generic.misc as mmod
import plugins.generic.takeover as tmod
from plugins.generic.custom import Custom
from plugins.generic.misc import Miscellaneous


class _RecordingDumper(object):
    """Recording stand-in for conf.dumper (no printing / file writing)."""

    def __init__(self):
        self.tableValues = []
        self.sqlQueries = []

    def dbTableValues(self, tableValues):
        self.tableValues.append(tableValues)

    def sqlQuery(self, query, queryRes):
        self.sqlQueries.append((query, queryRes))


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
        conf.dumper = _RecordingDumper()

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


# --------------------------------------------------------------------------- #
# custom.py
# --------------------------------------------------------------------------- #

class TestCustomSqlQuery(_GenericBase):
    def test_select_joins_listlike_rows(self):
        set_dbms("MySQL")
        c = Custom()
        cmod.inject.getValue = lambda query, **k: [["1", "alice"], ["2", "bob"]]
        out = c.sqlQuery("SELECT id, name FROM users;")
        # SELECT + list-like rows => each row joined into a single scalar string.
        self.assertEqual(len(out), 2)
        self.assertTrue(all(isinstance(_, str) for _ in out))

    def test_select_scalar_passthrough(self):
        set_dbms("MySQL")
        c = Custom()
        captured = {}

        def gv(query, **k):
            captured["query"] = query
            captured["fromUser"] = k.get("fromUser")
            return "42"

        cmod.inject.getValue = gv
        out = c.sqlQuery("SELECT COUNT(*) FROM users")
        self.assertEqual(out, "42")
        self.assertTrue(captured["fromUser"])

    def test_metadb_suffix_stripped(self):
        from lib.core.settings import METADB_SUFFIX
        set_dbms("MySQL")
        c = Custom()
        captured = {}

        def gv(query, **k):
            captured["query"] = query
            return "x"

        cmod.inject.getValue = gv
        c.sqlQuery("SELECT * FROM foo%s.bar" % METADB_SUFFIX)
        # the METADB-suffixed schema qualifier is stripped before injection
        self.assertNotIn(METADB_SUFFIX, captured["query"])

    def test_mssql_from_dbo_rewrite(self):
        set_dbms("Microsoft SQL Server")
        c = Custom()
        captured = {}

        def gv(query, **k):
            captured["query"] = query
            return "x"

        cmod.inject.getValue = gv
        c.sqlQuery("SELECT * FROM mydb.users")
        # single-dot FROM target gets the .dbo. schema spliced in for MSSQL
        self.assertIn("mydb.dbo.users", captured["query"])

    def test_nonquery_without_stacking_warns_none(self):
        set_dbms("MySQL")
        conf.direct = False
        kb.injection.data = {}        # no stacking technique available
        c = Custom()
        cmod.inject.getValue = lambda *a, **k: self.fail("must not run a query")
        out = c.sqlQuery("DELETE FROM users")
        self.assertIsNone(out)

    def test_nonquery_stacked_returns_null(self):
        set_dbms("MySQL")
        conf.direct = True            # direct => stacked execution allowed
        c = Custom()
        calls = {}

        def go(query, *a, **k):
            calls["query"] = query

        cmod.inject.goStacked = go
        out = c.sqlQuery("DROP TABLE users")
        self.assertEqual(out, NULL)
        self.assertIn("DROP TABLE users", calls["query"])

    def test_nonedata_exception_handled(self):
        from lib.core.exception import SqlmapNoneDataException
        set_dbms("MySQL")
        c = Custom()

        def boom(*a, **k):
            raise SqlmapNoneDataException("no data")

        cmod.inject.getValue = boom
        # exception is swallowed and logged; output stays None
        self.assertIsNone(c.sqlQuery("SELECT 1"))


class TestCustomSqlFile(_GenericBase):
    def test_sqlfile_select_snippets(self):
        set_dbms("MySQL")
        c = Custom()
        cmod.inject.getValue = lambda query, **k: "r"

        # getSQLSnippet reads from disk; patch it to return inline SQL.
        saved = cmod.getSQLSnippet
        try:
            cmod.getSQLSnippet = lambda dbms, filename, **kw: "SELECT 1;SELECT 2"
            conf.sqlFile = "dummy.sql"
            c.sqlFile()
            # two SELECT statements => two recorded dumper.sqlQuery calls
            self.assertEqual(len(conf.dumper.sqlQueries), 2)
        finally:
            cmod.getSQLSnippet = saved

    def test_sqlfile_nonselect_snippet(self):
        set_dbms("MySQL")
        conf.direct = True
        c = Custom()
        cmod.inject.goStacked = lambda *a, **k: None

        saved = cmod.getSQLSnippet
        try:
            cmod.getSQLSnippet = lambda dbms, filename, **kw: "DROP TABLE x"
            conf.sqlFile = "dummy.sql"
            c.sqlFile()
            # non-SELECT => single recorded call with the whole snippet
            self.assertEqual(len(conf.dumper.sqlQueries), 1)
            self.assertEqual(conf.dumper.sqlQueries[0][0], "DROP TABLE x")
        finally:
            cmod.getSQLSnippet = saved


# --------------------------------------------------------------------------- #
# misc.py
# --------------------------------------------------------------------------- #

class _TestMisc(Miscellaneous):
    """Miscellaneous with the OS/exec collaborators stubbed."""

    cmdTblName = "sqlmapoutput"

    def __init__(self):
        Miscellaneous.__init__(self)
        self.checkDbmsOsCalls = 0
        self.execCmdCalls = []

    def checkDbmsOs(self, detailed=False, vatch=False):
        self.checkDbmsOsCalls += 1

    def execCmd(self, cmd, silent=False):
        self.execCmdCalls.append((cmd, silent))


class TestMisc(_GenericBase):
    def test_remote_temp_path_posix(self):
        set_dbms("MySQL")
        self._force_os(OS.LINUX)
        conf.tmpPath = None
        m = _TestMisc()
        out = m.getRemoteTempPath()
        self.assertEqual(out, "/tmp")
        self.assertEqual(conf.tmpPath, "/tmp")

    def test_remote_temp_path_windows_direct(self):
        set_dbms("MySQL")
        self._force_os(OS.WINDOWS)
        conf.tmpPath = None
        conf.direct = True
        m = _TestMisc()
        out = m.getRemoteTempPath()
        self.assertEqual(out, "%TEMP%")

    def test_remote_temp_path_explicit_windows_drive(self):
        # An explicit Windows-style drive path flips Backend OS to Windows.
        set_dbms("MySQL")
        conf.tmpPath = "C:\\Temp"
        kb.os = None  # let getRemoteTempPath detect Windows from the drive path
        m = _TestMisc()
        out = m.getRemoteTempPath()
        self.assertTrue(Backend.isOs(OS.WINDOWS))
        self.assertIn("Temp", out)
        self.assertNotIn("\\", out)   # ntToPosixSlashes normalized the path

    def test_remote_temp_path_mssql_errorlog(self):
        set_dbms("Microsoft SQL Server")
        conf.tmpPath = None
        mmod.inject.getValue = lambda query, **k: "C:\\Logs\\ERRORLOG"
        m = _TestMisc()
        out = m.getRemoteTempPath()
        # ntpath.dirname strips the ERRORLOG filename, then ntToPosixSlashes
        # normalizes the slashes: the exact temp dir must be "C:/Logs". Asserting
        # the full path (and that the filename is gone) proves dirname ran.
        self.assertEqual(out, "C:/Logs")
        self.assertNotIn("ERRORLOG", out)

    def test_get_version_from_banner(self):
        set_dbms("MySQL")
        conf.direct = True
        kb.bannerFp = {}
        mmod.inject.getValue = lambda query, **k: "5.7.31-log"
        m = _TestMisc()
        m.getVersionFromBanner()
        # regex \d[\d.-]* extracts the leading numeric-ish run (trailing '-' kept)
        self.assertEqual(kb.bannerFp["dbmsVersion"], "5.7.31-")

    def test_get_version_from_banner_cached(self):
        set_dbms("MySQL")
        kb.bannerFp = {"dbmsVersion": "8.0"}
        mmod.inject.getValue = lambda *a, **k: self.fail("must not query when cached")
        m = _TestMisc()
        m.getVersionFromBanner()
        self.assertEqual(kb.bannerFp["dbmsVersion"], "8.0")

    def test_del_remote_file_posix(self):
        set_dbms("MySQL")
        self._force_os(OS.LINUX)
        m = _TestMisc()
        m.delRemoteFile("/tmp/foo")
        self.assertEqual(m.execCmdCalls[-1], ("rm -f /tmp/foo", True))

    def test_del_remote_file_windows(self):
        set_dbms("MySQL")
        self._force_os(OS.WINDOWS)
        m = _TestMisc()
        m.delRemoteFile("C:/tmp/foo")
        cmd, silent = m.execCmdCalls[-1]
        self.assertTrue(cmd.startswith("del /F /Q"))
        self.assertTrue(silent)

    def test_del_remote_file_empty_noop(self):
        set_dbms("MySQL")
        m = _TestMisc()
        m.delRemoteFile(None)
        self.assertEqual(m.execCmdCalls, [])
        self.assertEqual(m.checkDbmsOsCalls, 0)

    def test_create_support_tbl(self):
        set_dbms("MySQL")
        m = _TestMisc()
        stacked = []
        mmod.inject.goStacked = lambda query, **k: stacked.append(query)
        m.createSupportTbl("mytbl", "data", "TEXT")
        joined = " | ".join(stacked)
        self.assertIn("DROP TABLE mytbl", joined)
        self.assertIn("CREATE TABLE mytbl(data TEXT)", joined)

    def test_create_support_tbl_mssql_cmdtbl(self):
        set_dbms("Microsoft SQL Server")
        m = _TestMisc()
        stacked = []
        mmod.inject.goStacked = lambda query, **k: stacked.append(query)
        m.createSupportTbl(m.cmdTblName, "data", "NVARCHAR(4000)")
        joined = " | ".join(stacked)
        # MSSQL cmd output table gets an IDENTITY id column
        self.assertIn("IDENTITY", joined)

    def test_like_or_exact_default(self):
        m = _TestMisc()
        mmod.readInput = lambda *a, **k: '1'
        choice, cond = m.likeOrExact("table")
        self.assertEqual(choice, '1')
        self.assertIn("LIKE", cond)

    def test_like_or_exact_exact(self):
        m = _TestMisc()
        mmod.readInput = lambda *a, **k: '2'
        choice, cond = m.likeOrExact("table")
        self.assertEqual(choice, '2')
        self.assertEqual(cond, "='%s'")

    def test_like_or_exact_invalid(self):
        from lib.core.exception import SqlmapNoneDataException
        m = _TestMisc()
        mmod.readInput = lambda *a, **k: '9'
        self.assertRaises(SqlmapNoneDataException, m.likeOrExact, "table")


# --------------------------------------------------------------------------- #
# takeover.py (pure helpers only)
# --------------------------------------------------------------------------- #

class _TestTakeover(tmod.Takeover):
    """Takeover with all process/network collaborators stubbed.

    Only the pure control-flow helpers (table naming, reg read/add/del dispatch,
    osBof/osSmb guards) are exercised; metasploit/icmpsh/UDF spawning is replaced
    with recorders so no external process or socket is ever created.
    """

    def __init__(self):
        tmod.Takeover.__init__(self)
        self.regCalls = []
        self.osVal = OS.WINDOWS
        self.smbCalled = False
        self.bofCalled = False
        self._regInitCalled = 0

    # neutralize environment setup / OS detection
    def _regInit(self):
        self._regInitCalled += 1

    def checkDbmsOs(self, detailed=False, vatch=False):
        pass

    def initEnv(self, *a, **k):
        pass

    def getRemoteTempPath(self):
        return "/tmp"

    def createMsfShellcode(self, *a, **k):
        pass

    def readRegKey(self, regKey, regValue, parse=False):
        self.regCalls.append(("read", regKey, regValue))
        return "value"

    def addRegKey(self, regKey, regValue, regType, regData):
        self.regCalls.append(("add", regKey, regValue, regType, regData))

    def delRegKey(self, regKey, regValue):
        self.regCalls.append(("del", regKey, regValue))

    def smb(self):
        self.smbCalled = True

    def bof(self):
        self.bofCalled = True


class TestTakeover(_GenericBase):
    def _saved_takeover_readInput(self):
        return tmod.readInput

    def setUp(self):
        _GenericBase.setUp(self)
        self._saved_t_readInput = tmod.readInput

    def tearDown(self):
        tmod.readInput = self._saved_t_readInput
        _GenericBase.tearDown(self)

    def test_init_cmd_table_name(self):
        set_dbms("MySQL")
        t = _TestTakeover()
        self.assertEqual(t.cmdTblName, "%soutput" % conf.tablePrefix)
        self.assertEqual(t.tblField, "data")

    def test_reg_read_from_conf(self):
        set_dbms("Microsoft SQL Server")
        conf.regKey = "HKLM\\Soft"
        conf.regVal = "Name"
        t = _TestTakeover()
        out = t.regRead()
        self.assertEqual(out, "value")
        self.assertEqual(t.regCalls[-1], ("read", "HKLM\\Soft", "Name"))
        self.assertEqual(t._regInitCalled, 1)

    def test_reg_read_defaults(self):
        set_dbms("Microsoft SQL Server")
        conf.regKey = None
        conf.regVal = None
        tmod.readInput = lambda message, default=None, **k: default
        t = _TestTakeover()
        t.regRead()
        kind, regKey, regVal = t.regCalls[-1]
        self.assertEqual(kind, "read")
        self.assertIn("CurrentVersion", regKey)
        self.assertEqual(regVal, "ProductName")

    def test_reg_add_from_conf(self):
        set_dbms("Microsoft SQL Server")
        conf.regKey = "HKLM\\Soft"
        conf.regVal = "Name"
        conf.regData = "data"
        conf.regType = "REG_SZ"
        t = _TestTakeover()
        t.regAdd()
        self.assertEqual(t.regCalls[-1], ("add", "HKLM\\Soft", "Name", "REG_SZ", "data"))

    def test_reg_add_missing_key_raises(self):
        from lib.core.exception import SqlmapMissingMandatoryOptionException
        set_dbms("Microsoft SQL Server")
        conf.regKey = None
        conf.regVal = None
        conf.regData = None
        conf.regType = None
        tmod.readInput = lambda *a, **k: ""    # empty -> missing mandatory option
        t = _TestTakeover()
        self.assertRaises(SqlmapMissingMandatoryOptionException, t.regAdd)

    def test_reg_del_confirmed(self):
        set_dbms("Microsoft SQL Server")
        conf.regKey = "HKLM\\Soft"
        conf.regVal = "Name"
        tmod.readInput = lambda message, default=None, boolean=False, **k: True if boolean else default
        t = _TestTakeover()
        t.regDel()
        self.assertEqual(t.regCalls[-1], ("del", "HKLM\\Soft", "Name"))

    def test_reg_del_declined(self):
        set_dbms("Microsoft SQL Server")
        conf.regKey = "HKLM\\Soft"
        conf.regVal = "Name"
        tmod.readInput = lambda message, default=None, boolean=False, **k: False if boolean else default
        t = _TestTakeover()
        t.regDel()
        # declined => no delRegKey call recorded
        self.assertEqual([c for c in t.regCalls if c[0] == "del"], [])

    def test_osbof_wrong_dbms_raises(self):
        from lib.core.exception import SqlmapUnsupportedDBMSException
        set_dbms("MySQL")
        conf.direct = True
        t = _TestTakeover()
        self.assertRaises(SqlmapUnsupportedDBMSException, t.osBof)

    def test_osbof_no_stacking_returns(self):
        set_dbms("Microsoft SQL Server")
        conf.direct = False
        kb.injection.data = {}        # no stacking, not direct => early return
        t = _TestTakeover()
        self.assertIsNone(t.osBof())
        self.assertFalse(t.bofCalled)

    def test_ossmb_non_windows_raises(self):
        from lib.core.exception import SqlmapUnsupportedDBMSException
        set_dbms("MySQL")
        conf.direct = True
        t = _TestTakeover()

        # checkDbmsOs is a no-op here, so force the non-Windows OS explicitly
        self._force_os(OS.LINUX)
        self.assertRaises(SqlmapUnsupportedDBMSException, t.osSmb)
        self.assertFalse(t.smbCalled)

    def test_ossmb_windows_invokes_smb(self):
        set_dbms("MySQL")
        conf.direct = True
        self._force_os(OS.WINDOWS)
        t = _TestTakeover()
        t.osSmb()
        self.assertTrue(t.smbCalled)


if __name__ == "__main__":
    unittest.main()
