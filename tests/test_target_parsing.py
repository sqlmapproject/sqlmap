#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Target-environment setup in lib/core/target.py.

target.py wires a single scan's per-host state together: it derives the output /
dump / files directories from the hostname, opens (and optionally flushes) the
HashDB session file, resumes a previously-fingerprinted DBMS/OS and stored kb
values out of that session, decides the custom injection marker, normalizes the
POST body (url-decode / base64), splits GET/POST/Cookie/header strings into the
testable paramDict, and restores the per-target merged options between targets.

None of that needs a live HTTP target or a real DBMS connection: every function
reads conf/kb globals (which are set up here per-test and restored in tearDown)
and at most touches the local filesystem (pointed at a private temp tree) or a
local SQLite session file. Those side-effecting paths are still pure with
respect to the network, so they are exercised here against real temp dirs.

All expected values below were probed from actual output, not assumed.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import mergedOptions
from lib.core.data import paths
from lib.core.common import Backend
from lib.core.common import hashDBWrite
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import PLACE
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapNoneDataException
from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR
from lib.core.settings import RESTORE_MERGED_OPTIONS
from lib.core.settings import UNENCODED_ORIGINAL_VALUE
from lib.core.threads import getCurrentThreadData
from lib.utils.hashdb import HashDB
from lib.core.target import _createDumpDir
from lib.core.target import _createFilesDir
from lib.core.target import _createTargetDirs
from lib.core.target import _resumeDBMS
from lib.core.target import _resumeHashDBValues
from lib.core.target import _resumeOS
from lib.core.target import _restoreMergedOptions
from lib.core.target import _setAuxOptions
from lib.core.target import _setHashDB
from lib.core.target import _setRequestParams
from lib.core.target import _setResultsFile
from lib.core.target import initTargetEnv

SCRATCH = "/tmp/claude-1000/-tmp-tmp-oUnlQJzlQN/fcd55d25-6313-49ed-817e-dcbe7fc2bf22/scratchpad"

# conf/kb keys that the tests below mutate; saved in setUp, restored in tearDown so
# one test can never leak global state into another (or into the rest of the suite).
_CONF_KEYS = (
    "direct", "parameters", "paramDict", "method", "data", "cookie", "httpHeaders",
    "testParameter", "csrfToken", "url", "forms", "crawlDepth", "hostname", "path",
    "port", "dbms", "os", "offline", "tmpPath", "technique", "dumpTable", "dumpAll",
    "search", "fileRead", "commonFiles", "dumpPath", "filePath", "outputPath",
    "hashDB", "hashDBFile", "sessionFile", "flushSession", "freshQueries",
    "multipleTargets", "resultsFP", "resultsFile", "base64Parameter", "forceDbms",
)
_KB_KEYS = (
    "processUserMarks", "postHint", "customInjectionMark", "testOnlyCustom",
    "resumeValues", "aliasName", "errorChunkLength", "xpCmdshellAvailable",
    "chars", "originalUrls", "postUrlEncode", "postSpaceToPlus",
)
_PATH_KEYS = ("SQLMAP_OUTPUT_PATH", "SQLMAP_DUMP_PATH", "SQLMAP_FILES_PATH")


class _TargetTestBase(unittest.TestCase):
    """Snapshot/restore conf, kb and paths globals around each test."""

    def setUp(self):
        self._conf = {k: conf.get(k) for k in _CONF_KEYS}
        self._kb = {k: kb.get(k) for k in _KB_KEYS}
        self._paths = {k: paths.get(k) for k in _PATH_KEYS}
        # _resumeDBMS/_resumeOS mutate these kb fields via Backend.set* (not in _KB_KEYS)
        self._dbms = kb.get("dbms")
        self._forcedDbms = kb.get("forcedDbms")
        self._tmpdirs = []

    def tearDown(self):
        # close any session DB we opened before restoring globals
        if conf.get("hashDB"):
            try:
                conf.hashDB.close()
            except Exception:
                pass
        getCurrentThreadData().hashDBCursor = None
        if conf.get("resultsFP"):
            try:
                conf.resultsFP.close()
            except Exception:
                pass
        for k, v in self._conf.items():
            conf[k] = v
        for k, v in self._kb.items():
            kb[k] = v
        for k, v in self._paths.items():
            paths[k] = v
        kb.dbms = self._dbms                   # _resumeDBMS may have set an identified DBMS
        kb.forcedDbms = self._forcedDbms
        for d in self._tmpdirs:
            shutil.rmtree(d, ignore_errors=True)

    def _outdir(self, name):
        d = os.path.join(SCRATCH, name)
        shutil.rmtree(d, ignore_errors=True)
        self._tmpdirs.append(d)
        paths.SQLMAP_OUTPUT_PATH = d
        paths.SQLMAP_DUMP_PATH = os.path.join(d, "%s", "dump")
        paths.SQLMAP_FILES_PATH = os.path.join(d, "%s", "files")
        return d

    def _new_hashdb(self):
        handle, path = tempfile.mkstemp(suffix=".sqlite", dir=SCRATCH)
        os.close(handle)
        os.remove(path)
        getCurrentThreadData().hashDBCursor = None
        conf.hashDB = HashDB(path)
        conf.hostname = "h"
        conf.path = "/"
        conf.port = 80
        kb.resumeValues = True
        conf.flushSession = False
        conf.freshQueries = False
        # another test file may have force-set a DBMS via set_dbms(); a leaked forcedDbms
        # takes precedence in getIdentifiedDbms() and would mask what _resumeDBMS resolves
        conf.forceDbms = None
        kb.forcedDbms = None
        kb.dbms = None
        self.addCleanup(self._cleanup_hashdb, path)
        return path

    def _cleanup_hashdb(self, path):
        for f in (path, path + "-wal", path + "-shm"):
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass


class TestRestoreMergedOptions(_TargetTestBase):
    def test_restores_each_option_from_mergedOptions(self):
        saved = {}
        for opt in RESTORE_MERGED_OPTIONS:
            saved[opt] = mergedOptions.get(opt)
            mergedOptions[opt] = "VAL_%s" % opt
            conf[opt] = "tampered"
        try:
            _restoreMergedOptions()
            for opt in RESTORE_MERGED_OPTIONS:
                self.assertEqual(conf[opt], "VAL_%s" % opt,
                                 msg="option %r not restored from mergedOptions" % opt)
        finally:
            for opt, v in saved.items():
                mergedOptions[opt] = v


class TestSetAuxOptions(_TargetTestBase):
    def test_alias_is_nonempty_string(self):
        conf.hostname = "example.com"
        _setAuxOptions()
        self.assertIsInstance(kb.aliasName, str)
        self.assertTrue(kb.aliasName)

    def test_alias_deterministic_for_same_host(self):
        conf.hostname = "example.com"
        _setAuxOptions()
        first = kb.aliasName
        _setAuxOptions()
        self.assertEqual(kb.aliasName, first)

    def test_alias_handles_none_host(self):
        conf.hostname = None
        _setAuxOptions()                       # seed=hash("") must not raise
        self.assertIsInstance(kb.aliasName, str)


class TestInitTargetEnv(_TargetTestBase):
    def _base(self):
        conf.url = "http://h/?id=1"
        conf.data = None
        conf.httpHeaders = []
        conf.base64Parameter = None
        conf.multipleTargets = False

    def test_default_injection_marker(self):
        self._base()
        initTargetEnv()
        self.assertEqual(kb.customInjectionMark, CUSTOM_INJECTION_MARK_CHAR)

    def test_inject_here_marker_detected(self):
        self._base()
        conf.url = "http://h/?id=%INJECT_HERE%"
        initTargetEnv()
        self.assertEqual(kb.customInjectionMark, "%INJECT_HERE%")

    def test_urlencoded_post_body_is_decoded(self):
        self._base()
        conf.url = "http://h/"
        conf.data = "id=a%20b"
        conf.httpHeaders = [("Content-Type", "application/x-www-form-urlencoded")]
        initTargetEnv()
        self.assertTrue(kb.postUrlEncode)
        self.assertEqual(str(conf.data), "id=a b")
        # the raw (still-encoded) original is preserved as an attribute for later re-encoding
        self.assertEqual(getattr(conf.data, UNENCODED_ORIGINAL_VALUE, None), "id=a%20b")

    def test_non_urlencoded_content_type_skips_decode(self):
        self._base()
        conf.url = "http://h/"
        conf.data = "id=a%20b"
        conf.httpHeaders = [("Content-Type", "application/json")]
        conf.base64Parameter = None
        initTargetEnv()
        self.assertFalse(kb.postUrlEncode)

    def test_base64_post_body_is_decoded(self):
        self._base()
        conf.url = "http://h/"
        conf.data = "aWQ9MQ=="                 # base64 of "id=1"
        conf.httpHeaders = [("Content-Type", "application/json")]
        conf.base64Parameter = "POST"
        initTargetEnv()
        self.assertEqual(str(conf.data), "id=1")
        self.assertEqual(getattr(conf.data, UNENCODED_ORIGINAL_VALUE, None), "aWQ9MQ==")


class TestSetRequestParams(_TargetTestBase):
    def _fresh(self):
        conf.direct = None
        conf.parameters = {}
        conf.paramDict = {}
        conf.method = HTTPMETHOD.GET
        conf.data = None
        conf.cookie = None
        conf.httpHeaders = []
        conf.testParameter = None
        conf.csrfToken = None
        conf.url = "http://h/"
        conf.forms = False
        conf.crawlDepth = None
        kb.processUserMarks = None
        kb.postHint = None
        kb.customInjectionMark = "*"
        kb.testOnlyCustom = False

    def test_direct_connection_shortcut(self):
        self._fresh()
        conf.direct = "mysql://u:p@h/db"
        conf.parameters = {}
        _setRequestParams()
        self.assertEqual(conf.parameters[None], "direct connection")

    def test_get_parameters_split(self):
        self._fresh()
        conf.parameters = {PLACE.GET: "id=1&name=foo"}
        conf.url = "http://h/?id=1&name=foo"
        _setRequestParams()
        self.assertEqual(dict(conf.paramDict[PLACE.GET]), {"id": "1", "name": "foo"})

    def test_post_parameters_split(self):
        self._fresh()
        conf.method = HTTPMETHOD.POST
        conf.data = "a=1&b=2"
        _setRequestParams()
        self.assertEqual(dict(conf.paramDict[PLACE.POST]), {"a": "1", "b": "2"})

    def test_cookie_parameters_split(self):
        self._fresh()
        conf.parameters = {PLACE.GET: "id=1"}
        conf.url = "http://h/?id=1"
        conf.cookie = "sess=abc; uid=5"
        _setRequestParams()
        self.assertIn(PLACE.COOKIE, conf.paramDict)
        self.assertEqual(dict(conf.paramDict[PLACE.COOKIE]), {"sess": "abc", "uid": "5"})

    def test_user_agent_header_is_testable(self):
        self._fresh()
        conf.httpHeaders = [(HTTP_HEADER.USER_AGENT, "Mozilla")]
        _setRequestParams()
        self.assertIn(PLACE.USER_AGENT, conf.paramDict)

    def test_referer_header_is_testable(self):
        self._fresh()
        conf.httpHeaders = [(HTTP_HEADER.REFERER, "http://ref/")]
        _setRequestParams()
        self.assertIn(PLACE.REFERER, conf.paramDict)

    def test_no_parameters_raises(self):
        self._fresh()
        with self.assertRaises(SqlmapGenericException):
            _setRequestParams()

    def test_empty_post_body_defaults_to_empty_string(self):
        self._fresh()
        conf.method = HTTPMETHOD.POST
        conf.data = None
        conf.parameters = {PLACE.GET: "id=1"}      # keep a testable param so it doesn't raise
        conf.url = "http://h/?id=1"
        _setRequestParams()
        self.assertEqual(conf.data, "")


class TestResumeDBMS(_TargetTestBase):
    def test_resumes_dbms_with_version(self):
        self._new_hashdb()
        conf.dbms = None
        conf.offline = False
        hashDBWrite(HASHDB_KEYS.DBMS, "MySQL 5.0")
        _resumeDBMS()
        self.assertEqual(Backend.getIdentifiedDbms(), "MySQL")

    def test_no_stored_dbms_returns_quietly(self):
        self._new_hashdb()
        conf.dbms = None
        conf.offline = False
        _resumeDBMS()                           # nothing stored: must just return
        # the quiet-return branch must leave NO DBMS identified (a real
        # side-effect assertion, not merely "did not raise")
        self.assertIsNone(Backend.getIdentifiedDbms())

    def test_offline_without_session_raises(self):
        self._new_hashdb()
        conf.dbms = None
        conf.offline = True
        with self.assertRaises(SqlmapNoneDataException):
            _resumeDBMS()


class TestResumeOS(_TargetTestBase):
    def test_resumes_os(self):
        self._new_hashdb()
        conf.os = None
        hashDBWrite(HASHDB_KEYS.OS, "Linux")
        _resumeOS()
        self.assertEqual(conf.os, "Linux")

    def test_no_stored_os_returns_quietly(self):
        self._new_hashdb()
        conf.os = None
        _resumeOS()
        self.assertIsNone(conf.os)

    def test_stored_none_string_is_ignored(self):
        self._new_hashdb()
        conf.os = None
        hashDBWrite(HASHDB_KEYS.OS, "None")
        _resumeOS()
        self.assertIsNone(conf.os)


class TestResumeHashDBValues(_TargetTestBase):
    def _base(self):
        self._new_hashdb()
        conf.dbms = None
        conf.offline = False
        conf.os = None
        conf.tmpPath = None
        conf.technique = None
        conf.paramDict = {}

    def test_resumes_serialized_chars(self):
        self._base()
        kb.chars = None
        hashDBWrite(HASHDB_KEYS.KB_CHARS, {"a": 1}, serialize=True)
        _resumeHashDBValues()
        self.assertEqual(kb.chars, {"a": 1})

    def test_resumes_numeric_error_chunk_length(self):
        self._base()
        kb.errorChunkLength = None
        hashDBWrite(HASHDB_KEYS.KB_ERROR_CHUNK_LENGTH, "5")
        _resumeHashDBValues()
        self.assertEqual(kb.errorChunkLength, 5)

    def test_non_numeric_chunk_length_becomes_none(self):
        self._base()
        kb.errorChunkLength = 99
        hashDBWrite(HASHDB_KEYS.KB_ERROR_CHUNK_LENGTH, "notanumber")
        _resumeHashDBValues()
        self.assertIsNone(kb.errorChunkLength)

    def test_xp_cmdshell_true_coerced_to_bool(self):
        self._base()
        kb.xpCmdshellAvailable = False
        hashDBWrite(HASHDB_KEYS.KB_XP_CMDSHELL_AVAILABLE, str(True))
        _resumeHashDBValues()
        self.assertIs(kb.xpCmdshellAvailable, True)


class TestSetHashDB(_TargetTestBase):
    def test_derives_session_file_under_output_path(self):
        out = self._outdir("hdb_out")
        os.makedirs(out)
        getCurrentThreadData().hashDBCursor = None
        conf.hashDBFile = None
        conf.sessionFile = None
        conf.outputPath = out
        conf.flushSession = False
        conf.hashDB = None
        _setHashDB()
        self.assertTrue(conf.hashDBFile.startswith(out))
        self.assertIsInstance(conf.hashDB, HashDB)

    def test_explicit_session_file_takes_precedence(self):
        out = self._outdir("hdb_out2")
        os.makedirs(out)
        sess = os.path.join(out, "custom.sqlite")
        getCurrentThreadData().hashDBCursor = None
        conf.hashDBFile = None
        conf.sessionFile = sess
        conf.outputPath = out
        conf.flushSession = False
        conf.hashDB = None
        _setHashDB()
        self.assertEqual(conf.hashDBFile, sess)


class TestCreateDirs(_TargetTestBase):
    def test_dump_dir_skipped_without_dump_flags(self):
        self._outdir("d_out")
        conf.hostname = "example.com"
        conf.dumpPath = None
        conf.dumpTable = False
        conf.dumpAll = False
        conf.search = False
        _createDumpDir()
        self.assertIsNone(conf.dumpPath)

    def test_dump_dir_created_per_host(self):
        self._outdir("d_out2")
        conf.hostname = "example.com"
        conf.dumpTable = True
        conf.dumpAll = False
        conf.search = False
        _createDumpDir()
        self.assertTrue(os.path.isdir(conf.dumpPath))
        self.assertIn("example.com", conf.dumpPath)

    def test_files_dir_skipped_without_file_flags(self):
        self._outdir("f_out")
        conf.hostname = "example.com"
        conf.filePath = None
        conf.fileRead = None
        conf.commonFiles = None
        _createFilesDir()
        self.assertIsNone(conf.filePath)

    def test_files_dir_created_per_host(self):
        self._outdir("f_out2")
        conf.hostname = "example.com"
        conf.fileRead = "/etc/passwd"
        conf.commonFiles = None
        _createFilesDir()
        self.assertTrue(os.path.isdir(conf.filePath))
        self.assertIn("example.com", conf.filePath)

    def test_target_dir_and_target_txt(self):
        self._outdir("t_out")
        conf.hostname = "example.com"
        conf.url = "http://example.com/?id=1"
        conf.data = None
        conf.dumpTable = False
        conf.dumpAll = False
        conf.search = False
        conf.fileRead = None
        conf.commonFiles = None
        kb.originalUrls = {}
        _createTargetDirs()
        self.assertTrue(os.path.isdir(conf.outputPath))
        target = os.path.join(conf.outputPath, "target.txt")
        self.assertTrue(os.path.exists(target))
        with open(target) as f:
            content = f.read()
        self.assertIn("http://example.com/?id=1", content)
        self.assertIn("(%s)" % HTTPMETHOD.GET, content)


class TestSetResultsFile(_TargetTestBase):
    def test_skipped_when_not_multiple_targets(self):
        self._outdir("r_out")
        conf.multipleTargets = False
        conf.resultsFP = None
        _setResultsFile()
        self.assertIsNone(conf.resultsFP)

    def test_creates_csv_with_header_in_multiple_target_mode(self):
        out = self._outdir("r_out2")
        os.makedirs(out)
        conf.multipleTargets = True
        conf.resultsFile = os.path.join(out, "res.csv")
        conf.resultsFP = None
        _setResultsFile()
        self.assertTrue(os.path.exists(conf.resultsFile))
        conf.resultsFP.flush()
        with open(conf.resultsFile) as f:
            header = f.readline()
        self.assertIn("Target URL", header)
        self.assertIn("Parameter", header)


if __name__ == "__main__":
    unittest.main(verbosity=2)
