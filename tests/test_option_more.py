#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Additional coverage for option setup / normalization helpers in
lib/core/option.py, targeting functions and branches NOT already exercised by
tests/test_option_setup.py:

  * _setTamperingFunctions   (loads real tamper modules into kb.tamperFunctions)
  * _setPreprocessFunctions  (loads a preprocess(req) script into kb.preprocessFunctions)
  * _setPostprocessFunctions (loads a postprocess(page, headers, code) script)
  * _setSafeVisit            (parses a safe request file into kb.safeReq)
  * _cleanupOptions          (additional normalization branches: delay cast,
                              csvDel/paramDel escape, col/binaryFields split,
                              torType upper, abortCode, getAll, dummy->batch)
  * _basicOptionValidation   (additional illegal option combinations / branches)
  * _normalizeOptions        (string + boolean option coercion)
  * setVerbosity             (eta clamp + high verbose)

As in test_option_setup.py, option.py mutates the global conf/kb singletons
aggressively, so every test saves and restores the conf/kb fields it touches via
the _preserve() context manager so the shared state stays pristine for the rest
of the suite.
"""

import contextlib
import logging
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.data import conf, kb, logger, paths
from lib.core.exception import SqlmapSyntaxException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapValueException
from lib.core.settings import MAX_CONNECT_RETRIES

import lib.core.option as option

_SENTINEL = object()

# scratchpad for the preprocess/postprocess/safe-req fixture files
_SCRATCH = os.environ.get("CLAUDE_SCRATCH") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "_option_more_tmp")


def tearDownModule():
    """Remove the scratch fixture directory so it never lingers on disk (and so a
    stray __init__.py there can't shadow imports in a subsequent run)."""
    import shutil
    if os.path.isdir(_SCRATCH):
        shutil.rmtree(_SCRATCH, ignore_errors=True)


@contextlib.contextmanager
def _preserve(target, *keys):
    """Save the given keys of an AttribDict (conf/kb), then restore on exit.

    Missing keys are restored to absent so a test can't leak a brand-new field.
    """
    saved = {}
    for key in keys:
        saved[key] = target[key] if key in target else _SENTINEL
    try:
        yield
    finally:
        for key in keys:
            if saved[key] is _SENTINEL:
                try:
                    del target[key]
                except KeyError:
                    pass
            else:
                target[key] = saved[key]


class _ImportSandboxMixin(object):
    """Loaders in option.py (tamper/preprocess/postprocess) permanently
    `sys.path.insert(0, <script dir>)` and import the script module, which would
    otherwise leak the scratch directory onto sys.path (shadowing later imports)
    and leave stray modules in sys.modules for the rest of the suite. Snapshot
    both around the test class and restore them so the shared interpreter state
    stays pristine for the other ~900 tests.
    """

    @classmethod
    def setUpClass(cls):
        cls._saved_path = list(sys.path)
        cls._saved_modules = set(sys.modules)

    @classmethod
    def tearDownClass(cls):
        sys.path[:] = cls._saved_path
        for name in list(sys.modules):
            if name not in cls._saved_modules:
                del sys.modules[name]


class TestSetTamperingFunctions(_ImportSandboxMixin, unittest.TestCase):
    """_setTamperingFunctions imports the named tamper modules and appends their
    tamper() callables to kb.tamperFunctions."""

    def test_none_noop(self):
        with _preserve(conf, "tamper"), _preserve(kb, "tamperFunctions"):
            kb.tamperFunctions = []
            conf.tamper = None
            option._setTamperingFunctions()
            self.assertEqual(kb.tamperFunctions, [])

    def test_loads_named_scripts(self):
        # 'between' (HIGHEST) before 'space2comment' (LOW) keeps priorities
        # non-increasing, so the interactive "mixed order" prompt is not triggered.
        with _preserve(conf, "tamper"), _preserve(kb, "tamperFunctions"):
            kb.tamperFunctions = []
            conf.tamper = "between,space2comment"
            option._setTamperingFunctions()
            self.assertEqual(len(kb.tamperFunctions), 2)
            names = sorted(f.__name__ for f in kb.tamperFunctions)
            self.assertEqual(names, ["between", "space2comment"])
            # each loaded entry is a callable tamper function
            self.assertTrue(all(callable(f) for f in kb.tamperFunctions))

    def test_mixed_order_auto_resolved_in_batch(self):
        # 'space2comment' (LOW) before 'between' (HIGHEST) trips the priority
        # mixup; in batch mode readInput uses the 'Y' default and auto-resolves,
        # sorting kb.tamperFunctions by priority (descending).
        with _preserve(conf, "tamper", "batch"), _preserve(kb, "tamperFunctions"):
            kb.tamperFunctions = []
            conf.batch = True
            conf.tamper = "space2comment,between"
            option._setTamperingFunctions()
            self.assertEqual(len(kb.tamperFunctions), 2)
            # after auto-resolve, 'between' (HIGHEST) comes first
            self.assertEqual(kb.tamperFunctions[0].__name__, "between")

    def test_missing_script_raises(self):
        with _preserve(conf, "tamper"), _preserve(kb, "tamperFunctions"):
            kb.tamperFunctions = []
            conf.tamper = "definitely_not_a_tamper_script_xyz"
            self.assertRaises(SqlmapFilePathException, option._setTamperingFunctions)


class TestSetPreprocessFunctions(_ImportSandboxMixin, unittest.TestCase):
    """_setPreprocessFunctions imports a preprocess(req) script and appends it to
    kb.preprocessFunctions (after a successful test-run against a dummy Request)."""

    @classmethod
    def setUpClass(cls):
        super(TestSetPreprocessFunctions, cls).setUpClass()
        if not os.path.isdir(_SCRATCH):
            os.makedirs(_SCRATCH)
        # an empty __init__.py is required next to the script
        with open(os.path.join(_SCRATCH, "__init__.py"), "w") as f:
            f.write("")
        cls.script = os.path.join(_SCRATCH, "pre_ok.py")
        with open(cls.script, "w") as f:
            f.write("#!/usr/bin/env\n\ndef preprocess(req):\n    pass\n")
        cls.bad = os.path.join(_SCRATCH, "pre_no_func.py")
        with open(cls.bad, "w") as f:
            f.write("#!/usr/bin/env\n\ndef notpreprocess(req):\n    pass\n")

    def test_none_noop(self):
        with _preserve(conf, "preprocess"), _preserve(kb, "preprocessFunctions"):
            kb.preprocessFunctions = []
            conf.preprocess = None
            option._setPreprocessFunctions()
            self.assertEqual(kb.preprocessFunctions, [])

    def test_loads_script(self):
        with _preserve(conf, "preprocess", "debug"), _preserve(kb, "preprocessFunctions"):
            kb.preprocessFunctions = []
            conf.debug = False
            conf.preprocess = self.script
            option._setPreprocessFunctions()
            self.assertEqual(len(kb.preprocessFunctions), 1)
            self.assertTrue(callable(kb.preprocessFunctions[0]))

    def test_missing_function_raises(self):
        with _preserve(conf, "preprocess", "debug"), _preserve(kb, "preprocessFunctions"):
            kb.preprocessFunctions = []
            conf.debug = False
            conf.preprocess = self.bad
            self.assertRaises(SqlmapGenericException, option._setPreprocessFunctions)

    def test_missing_file_raises(self):
        with _preserve(conf, "preprocess", "debug"), _preserve(kb, "preprocessFunctions"):
            kb.preprocessFunctions = []
            conf.debug = False
            conf.preprocess = os.path.join(_SCRATCH, "nope.py")
            self.assertRaises(SqlmapFilePathException, option._setPreprocessFunctions)


class TestSetPostprocessFunctions(_ImportSandboxMixin, unittest.TestCase):
    """_setPostprocessFunctions imports a postprocess(page, headers, code) script
    that must return a (page, headers, code) tuple."""

    @classmethod
    def setUpClass(cls):
        super(TestSetPostprocessFunctions, cls).setUpClass()
        if not os.path.isdir(_SCRATCH):
            os.makedirs(_SCRATCH)
        with open(os.path.join(_SCRATCH, "__init__.py"), "w") as f:
            f.write("")
        cls.script = os.path.join(_SCRATCH, "post_ok.py")
        with open(cls.script, "w") as f:
            f.write("#!/usr/bin/env\n\ndef postprocess(page, headers=None, code=None):\n    return page, headers, code\n")
        cls.bad = os.path.join(_SCRATCH, "post_no_func.py")
        with open(cls.bad, "w") as f:
            f.write("#!/usr/bin/env\n\ndef other(page, headers=None, code=None):\n    return page, headers, code\n")

    def test_none_noop(self):
        with _preserve(conf, "postprocess"), _preserve(kb, "postprocessFunctions"):
            kb.postprocessFunctions = []
            conf.postprocess = None
            option._setPostprocessFunctions()
            self.assertEqual(kb.postprocessFunctions, [])

    def test_loads_script(self):
        with _preserve(conf, "postprocess"), _preserve(kb, "postprocessFunctions"):
            kb.postprocessFunctions = []
            conf.postprocess = self.script
            option._setPostprocessFunctions()
            self.assertEqual(len(kb.postprocessFunctions), 1)
            self.assertTrue(callable(kb.postprocessFunctions[0]))

    def test_missing_function_raises(self):
        with _preserve(conf, "postprocess"), _preserve(kb, "postprocessFunctions"):
            kb.postprocessFunctions = []
            conf.postprocess = self.bad
            self.assertRaises(SqlmapGenericException, option._setPostprocessFunctions)


class TestSetSafeVisit(unittest.TestCase):
    """_setSafeVisit parses a raw HTTP request file into kb.safeReq, or normalizes
    a bare safeUrl, and enforces safeFreq > 0."""

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(_SCRATCH):
            os.makedirs(_SCRATCH)
        cls.reqfile = os.path.join(_SCRATCH, "safe_req.txt")
        with open(cls.reqfile, "w") as f:
            f.write("GET /safe?ping=1 HTTP/1.1\nHost: victim.example\nUser-Agent: t\n\n")
        cls.badfile = os.path.join(_SCRATCH, "safe_req_bad.txt")
        with open(cls.badfile, "w") as f:
            f.write("this is not a valid request line\n")

    def _keys(self):
        return ("safeUrl", "safeReqFile", "safeFreq", "safePost")

    def test_noop_when_unset(self):
        with _preserve(conf, *self._keys()):
            conf.safeUrl = None
            conf.safeReqFile = None
            conf.safeFreq = 0
            option._setSafeVisit()  # must not raise

    def test_safe_url_scheme_prepended(self):
        with _preserve(conf, *self._keys()):
            conf.safeUrl = "victim.example/keepalive"
            conf.safeReqFile = None
            conf.safeFreq = 5
            option._setSafeVisit()
            self.assertTrue(conf.safeUrl.startswith("http://"), msg=conf.safeUrl)

    def test_safe_url_requires_positive_freq(self):
        with _preserve(conf, *self._keys()):
            conf.safeUrl = "http://victim.example/k"
            conf.safeReqFile = None
            conf.safeFreq = 0
            self.assertRaises(SqlmapSyntaxException, option._setSafeVisit)

    def test_safe_req_file_parsed(self):
        with _preserve(conf, *self._keys()), _preserve(kb, "safeReq"):
            conf.safeUrl = None
            conf.safePost = None
            conf.safeReqFile = self.reqfile
            conf.safeFreq = 3
            option._setSafeVisit()
            self.assertEqual(kb.safeReq.method, "GET")
            self.assertIn("victim.example", kb.safeReq.url)
            self.assertEqual(kb.safeReq.headers.get("User-Agent"), "t")

    def test_safe_req_file_invalid_format_raises(self):
        with _preserve(conf, *self._keys()), _preserve(kb, "safeReq"):
            conf.safeUrl = None
            conf.safePost = None
            conf.safeReqFile = self.badfile
            conf.safeFreq = 3
            self.assertRaises(SqlmapSyntaxException, option._setSafeVisit)


class TestCleanupOptionsExtra(unittest.TestCase):
    """Additional _cleanupOptions normalization branches not covered by
    test_option_setup.py."""

    _KEYS = (
        "encoding", "eta", "testParameter", "ignoreCode", "abortCode",
        "paramFilter", "base64Parameter", "agent", "user", "rParam",
        "paramDel", "skip", "cookie", "delay", "url", "fileRead",
        "fileWrite", "fileDest", "msfPath", "tmpPath", "googleDork",
        "logFile", "bulkFile", "forms", "crawlDepth", "stdinPipe",
        "multipleTargets", "optimize", "os", "forceDbms", "dbms",
        "uValues", "uCols", "testFilter", "csrfToken", "testSkip",
        "tor", "timeSec", "retries", "code", "csvDel", "torPort",
        "torType", "outputDir", "string", "getAll", "noCast",
        "dumpFormat", "col", "exclude", "binaryFields", "proxy",
        "proxyFile", "dummy", "batch", "scope",
    )

    def _base(self):
        for key in self._KEYS:
            conf[key] = None
        conf.eta = False
        conf.optimize = False
        conf.tor = False
        conf.getAll = False
        conf.noCast = False
        conf.dummy = False
        conf.batch = False
        conf.timeSec = 5
        conf.retries = 3
        conf.multipleTargets = False

    @contextlib.contextmanager
    def _ctx(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            yield

    def test_delay_cast_to_float(self):
        with self._ctx():
            conf.delay = "2"
            option._cleanupOptions()
            self.assertEqual(conf.delay, 2.0)
            self.assertIsInstance(conf.delay, float)

    def test_csv_del_escape_decoded(self):
        with self._ctx():
            conf.csvDel = "\\t"
            option._cleanupOptions()
            self.assertEqual(conf.csvDel, "\t")

    def test_param_del_escape_decoded(self):
        with self._ctx():
            conf.paramDel = "\\n"
            option._cleanupOptions()
            self.assertEqual(conf.paramDel, "\n")

    def test_col_whitespace_normalized(self):
        with self._ctx():
            conf.col = "id , name ,  pass"
            option._cleanupOptions()
            self.assertEqual(conf.col, "id,name,pass")

    def test_binary_fields_split(self):
        with self._ctx():
            conf.binaryFields = "data, blob"
            option._cleanupOptions()
            self.assertEqual(conf.binaryFields, ["data", "blob"])

    def test_tor_type_uppercased(self):
        with self._ctx():
            conf.torType = "socks5"
            option._cleanupOptions()
            self.assertEqual(conf.torType, "SOCKS5")

    def test_abort_code_empty_becomes_list(self):
        with self._ctx():
            conf.abortCode = None
            option._cleanupOptions()
            self.assertEqual(conf.abortCode, [])

    def test_abort_code_invalid_raises(self):
        with self._ctx():
            conf.abortCode = "notanumber"
            self.assertRaises(SqlmapSyntaxException, option._cleanupOptions)

    def test_user_spaces_stripped(self):
        with self._ctx():
            conf.user = "ad min"
            option._cleanupOptions()
            self.assertEqual(conf.user, "admin")

    def test_dummy_forces_batch(self):
        with self._ctx():
            conf.dummy = True
            option._cleanupOptions()
            self.assertTrue(conf.batch)

    def test_string_escape_decoded(self):
        with self._ctx():
            conf.string = "a\\tb"
            option._cleanupOptions()
            self.assertEqual(conf.string, "a\tb")

    def test_retries_clamped(self):
        with self._ctx():
            conf.retries = 9999
            option._cleanupOptions()
            # clamped to exactly MAX_CONNECT_RETRIES, not merely "less than 9999"
            self.assertEqual(conf.retries, MAX_CONNECT_RETRIES)

    def test_unknown_encoding_raises(self):
        with self._ctx():
            conf.encoding = "definitely-not-an-encoding"
            self.assertRaises(SqlmapValueException, option._cleanupOptions)


class TestBasicOptionValidationExtra(unittest.TestCase):
    """Additional illegal option combinations / validation branches in
    _basicOptionValidation not covered by test_option_setup.py."""

    _KEYS = (
        "limitStart", "limitStop", "level", "risk", "firstChar", "lastChar",
        "textOnly", "nullConnection", "uValues", "uChar", "base64Parameter",
        "tamper", "eta", "verbose", "direct", "url", "dbms", "tor", "proxy",
        "ignoreProxy", "regexp", "timeSec", "torPort", "torType", "dumpFormat",
        "technique", "threads", "predictOutput", "optimize", "csrfToken",
        "csrfUrl", "csrfMethod", "csrfData", "string", "notString", "noCast",
        "hexConvert", "titles", "dumpTable", "search", "dumpAll", "data",
        "requestFile", "forms", "googleDork", "bulkFile", "chunked",
        "cookieDel", "dbmsCred", "mobile", "agent", "crawlExclude",
        "crawlDepth", "safePost", "safeUrl", "safeReqFile", "safeFreq",
        "proxyFile", "proxyFreq", "checkTor", "alert", "secondUrl",
        "secondReq", "http2", "osPwn",
    )

    def _base(self):
        for key in self._KEYS:
            conf[key] = None
        conf.textOnly = False
        conf.nullConnection = False
        conf.eta = False
        conf.direct = False
        conf.tor = False
        conf.ignoreProxy = False
        conf.predictOutput = False
        conf.optimize = False
        conf.noCast = False
        conf.hexConvert = False
        conf.titles = False
        conf.mobile = False
        conf.chunked = False
        conf.checkTor = False
        conf.http2 = False
        conf.osPwn = False
        conf.verbose = 1
        conf.timeSec = 5
        conf.torPort = None
        conf.torType = "SOCKS5"
        conf.dumpFormat = "CSV"
        conf.technique = [1, 2, 6, 4, 5]
        conf.threads = 1

    @contextlib.contextmanager
    def _ctx(self):
        with _preserve(conf, *self._KEYS):
            self._base()
            yield

    def test_bad_limit_start_raises(self):
        with self._ctx():
            conf.limitStart = -1
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_bad_limit_stop_raises(self):
        with self._ctx():
            conf.limitStop = 0
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_first_char_gt_last_char_raises(self):
        with self._ctx():
            conf.firstChar = 5
            conf.lastChar = 2
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_base64_tamper_incompatible(self):
        with self._ctx():
            conf.base64Parameter = "id"
            conf.tamper = "space2comment"
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_direct_dbms_incompatible(self):
        with self._ctx():
            conf.direct = "mysql://u:p@h/db"
            conf.dbms = "MySQL"
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_titles_nullconnection_incompatible(self):
        with self._ctx():
            conf.titles = True
            conf.nullConnection = True
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_dump_search_incompatible(self):
        with self._ctx():
            conf.dumpTable = True
            conf.search = True
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_string_notstring_incompatible(self):
        with self._ctx():
            conf.string = "ok"
            conf.notString = "bad"
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_chunked_requires_post(self):
        with self._ctx():
            conf.chunked = True
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_cookie_del_single_char(self):
        with self._ctx():
            conf.cookieDel = ";;"
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_dbms_cred_format(self):
        with self._ctx():
            conf.dbmsCred = "rootnopassword"
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_mobile_agent_incompatible(self):
        with self._ctx():
            conf.mobile = True
            conf.agent = "UA/1.0"
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_proxy_ignoreproxy_incompatible(self):
        with self._ctx():
            conf.proxy = "http://127.0.0.1:8080"
            conf.ignoreProxy = True
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_csrf_url_requires_token(self):
        with self._ctx():
            conf.csrfUrl = "http://x/token"
            conf.csrfToken = None
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_csrf_token_threads_incompatible(self):
        with self._ctx():
            conf.csrfToken = "tok"
            conf.threads = 4
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_time_sec_must_be_positive(self):
        with self._ctx():
            conf.timeSec = 0
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_forms_requires_target(self):
        with self._ctx():
            conf.forms = True
            conf.url = None
            conf.googleDork = None
            conf.bulkFile = None
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_safe_post_requires_safe_url(self):
        with self._ctx():
            conf.safePost = "x=1"
            conf.safeUrl = None
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_proxy_freq_requires_proxy_file(self):
        with self._ctx():
            conf.proxyFreq = 5
            conf.proxyFile = None
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_check_tor_requires_tor_or_proxy(self):
        with self._ctx():
            conf.checkTor = True
            conf.tor = False
            conf.proxy = None
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_second_url_req_incompatible(self):
        with self._ctx():
            conf.secondUrl = "http://x/2"
            conf.secondReq = "/path/req.txt"
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_alert_unsafe_requires_env(self):
        # _basicOptionValidation raises SqlmapSystemException for --alert without env
        with self._ctx():
            saved = os.environ.pop("SQLMAP_UNSAFE_ALERT", None)
            try:
                conf.alert = "echo hi"
                self.assertRaises(SqlmapSystemException, option._basicOptionValidation)
            finally:
                if saved is not None:
                    os.environ["SQLMAP_UNSAFE_ALERT"] = saved


class TestNormalizeOptionsExtra(unittest.TestCase):
    """_normalizeOptions coerces values by option type. test_option_setup covers
    INTEGER; here cover FLOAT and BOOLEAN coercion (STRING is left untouched)."""

    def test_float_coercion(self):
        # 'delay' is a FLOAT option; a string value is coerced to float
        opts = {"delay": "2.5"}
        option._normalizeOptions(opts)
        self.assertEqual(opts["delay"], 2.5)

    def test_bad_float_becomes_zero(self):
        opts = {"delay": "notafloat"}
        option._normalizeOptions(opts)
        self.assertEqual(opts["delay"], 0.0)

    def test_boolean_coercion(self):
        # 'forms' is a BOOLEAN option; a truthy non-empty value -> True
        opts = {"forms": 1}
        option._normalizeOptions(opts)
        self.assertIs(opts["forms"], True)

    def test_boolean_empty_false(self):
        opts = {"forms": ""}
        option._normalizeOptions(opts)
        self.assertIs(opts["forms"], False)


class TestSetVerbosityExtra(unittest.TestCase):
    """setVerbosity branches not covered by test_option_setup.py."""

    def test_eta_clamps_verbose(self):
        saved_level = logger.level
        try:
            with _preserve(conf, "verbose", "eta"):
                conf.verbose = 5
                conf.eta = True
                option.setVerbosity()
                # with eta on and verbose > 2, verbose is clamped to 2 (DEBUG)
                self.assertEqual(conf.verbose, 2)
                self.assertEqual(logger.level, logging.DEBUG)
        finally:
            logger.setLevel(saved_level)

    def test_string_verbose_coerced_to_int(self):
        saved_level = logger.level
        try:
            with _preserve(conf, "verbose", "eta"):
                conf.verbose = "1"
                conf.eta = False
                option.setVerbosity()
                self.assertEqual(conf.verbose, 1)
                self.assertEqual(logger.level, logging.INFO)
        finally:
            logger.setLevel(saved_level)


if __name__ == "__main__":
    unittest.main(verbosity=2)
