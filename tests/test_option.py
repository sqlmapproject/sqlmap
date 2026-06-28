#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Option setup / normalization helpers in lib/core/option.py.

These exercise the (mostly) pure config-massaging functions that parse, validate
and normalize user-supplied option values into the canonical conf.*/kb.* shapes
that the rest of sqlmap relies on - WITHOUT touching the network, the DBMS, the
filesystem (beyond what bootstrap already set up) or any interactive prompt.

option.py mutates the global conf/kb singletons aggressively, so every test that
writes a conf/kb field saves and restores it via the _preserve() helper so the
shared state stays pristine for the other test files in the suite.
"""

import contextlib
import logging
import os
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.data import conf, kb, logger
from lib.core.common import Backend
from lib.core.enums import AUTH_TYPE
from lib.core.enums import HTTP_HEADER
from lib.core.settings import DEFAULT_USER_AGENT
from lib.core.settings import IGNORE_CODE_WILDCARD
from lib.core.settings import MAX_CONNECT_RETRIES
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapSyntaxException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUnsupportedDBMSException
from lib.core.exception import SqlmapValueException
from thirdparty.six.moves import urllib as _urllib

import lib.core.option as option

_SENTINEL = object()

# scratchpad for the preprocess/postprocess/safe-req fixture files
_SCRATCH = os.environ.get("CLAUDE_SCRATCH") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "_option_more_tmp")

# conf/kb fields that Backend.getIdentifiedDbms()/getOs() consult; any test that
# might touch DBMS/OS forcing snapshots ALL of them so no fingerprint state leaks
# into sibling test files (e.g. test_target_parsing's resume tests).
_BACKEND_CONF_KEYS = ("dbms", "forceDbms", "os")
_BACKEND_KB_KEYS = ("dbms", "dbmsVersion", "forcedDbms", "dbmsFilter", "os", "osVersion", "osSP")


def tearDownModule():
    """Remove the scratch fixture directory so it never lingers on disk (and so a
    stray __init__.py there can't shadow imports in a subsequent run)."""
    import shutil
    if os.path.isdir(_SCRATCH):
        shutil.rmtree(_SCRATCH, ignore_errors=True)


class _BackendGuard(unittest.TestCase):
    """Mixin: fully snapshot & restore Backend-relevant conf/kb state per test."""

    def setUp(self):
        super(_BackendGuard, self).setUp()
        self._snap_conf = {k: (conf[k] if k in conf else _SENTINEL) for k in _BACKEND_CONF_KEYS}
        self._snap_kb = {k: (kb[k] if k in kb else _SENTINEL) for k in _BACKEND_KB_KEYS}

    def tearDown(self):
        for store, snap, keys in ((conf, self._snap_conf, _BACKEND_CONF_KEYS),
                                  (kb, self._snap_kb, _BACKEND_KB_KEYS)):
            for k in keys:
                if snap[k] is _SENTINEL:
                    try:
                        del store[k]
                    except KeyError:
                        pass
                else:
                    store[k] = snap[k]
        super(_BackendGuard, self).tearDown()


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


class TestSetTechnique(unittest.TestCase):
    def test_letters_to_ints(self):
        # BEUST(Q) letters map to the PAYLOAD.TECHNIQUE ints (B=1,E=2,U=6,S=4,T=5)
        with _preserve(conf, "technique"):
            conf.technique = "BEUST"
            option._setTechnique()
            self.assertEqual(conf.technique, [1, 2, 6, 4, 5])

    def test_lowercase_accepted(self):
        with _preserve(conf, "technique"):
            conf.technique = "bt"
            option._setTechnique()
            self.assertEqual(conf.technique, [1, 5])

    def test_invalid_letter_raises(self):
        with _preserve(conf, "technique"):
            conf.technique = "X"
            self.assertRaises(SqlmapSyntaxException, option._setTechnique)

    def test_already_list_left_alone(self):
        # non-string (already-normalized) value is a no-op
        with _preserve(conf, "technique"):
            conf.technique = [1, 6]
            option._setTechnique()
            self.assertEqual(conf.technique, [1, 6])


class TestSetDBMS(_BackendGuard):
    def test_none_noop(self):
        with _preserve(conf, "dbms"):
            conf.dbms = None
            option._setDBMS()
            self.assertIsNone(conf.dbms)

    def test_plain_canonicalized(self):
        # input is lowercased then mapped to the canonical DBMS name via DBMS_ALIASES
        with _preserve(conf, "dbms"):
            conf.dbms = "MySQL"
            option._setDBMS()
            self.assertEqual(conf.dbms, "MySQL")

        # non-identity case: an all-caps spelling must be lowercased and run
        # through the alias map back to the canonical "MySQL" (proves the
        # lower -> alias-lookup -> canonical transform actually executes, rather
        # than the test passing because input already equals output)
        with _preserve(conf, "dbms"):
            conf.dbms = "MYSQL"
            option._setDBMS()
            self.assertEqual(conf.dbms, "MySQL")

    def test_alias_canonicalized(self):
        # "pgsql" is an alias for PostgreSQL
        with _preserve(conf, "dbms"):
            conf.dbms = "pgsql"
            option._setDBMS()
            self.assertEqual(conf.dbms.lower(), "postgresql")

    def test_version_extracted_into_backend(self):
        # _setDBMS calls Backend.setVersion -> mutates kb.dbmsVersion; preserve it too
        with _preserve(conf, "dbms"), _preserve(kb, "dbmsVersion"):
            conf.dbms = "mysql 5.7"
            option._setDBMS()
            self.assertEqual(conf.dbms, "MySQL")
            self.assertIn("5.7", Backend.getVersion())

    def test_unsupported_raises(self):
        with _preserve(conf, "dbms"):
            conf.dbms = "totallynotadbms"
            self.assertRaises(SqlmapUnsupportedDBMSException, option._setDBMS)


class TestSetOS(_BackendGuard):
    def test_none_noop(self):
        with _preserve(conf, "os"):
            conf.os = None
            option._setOS()  # must not raise

    def test_valid_os_sets_backend(self):
        # _setOS calls Backend.setOs -> mutates kb.os; preserve it too
        with _preserve(conf, "os"), _preserve(kb, "os"):
            conf.os = "Linux"
            option._setOS()
            self.assertEqual(Backend.getOs(), "Linux")

    def test_unsupported_os_raises(self):
        with _preserve(conf, "os"):
            conf.os = "plan9"
            self.assertRaises(SqlmapUnsupportedDBMSException, option._setOS)


class TestSetDBMSAuthentication(unittest.TestCase):
    def test_none_noop(self):
        with _preserve(conf, "dbmsCred", "dbmsUsername", "dbmsPassword"):
            conf.dbmsCred = None
            option._setDBMSAuthentication()
            # nothing populated
            self.assertIsNone(conf.get("dbmsUsername"))

    def test_splits_user_password(self):
        with _preserve(conf, "dbmsCred", "dbmsUsername", "dbmsPassword"):
            conf.dbmsCred = "root:secret"
            option._setDBMSAuthentication()
            self.assertEqual(conf.dbmsUsername, "root")
            self.assertEqual(conf.dbmsPassword, "secret")

    def test_empty_password_allowed(self):
        with _preserve(conf, "dbmsCred", "dbmsUsername", "dbmsPassword"):
            conf.dbmsCred = "sa:"
            option._setDBMSAuthentication()
            self.assertEqual(conf.dbmsUsername, "sa")
            self.assertEqual(conf.dbmsPassword, "")


class TestSetThreads(unittest.TestCase):
    def test_zero_becomes_one(self):
        with _preserve(conf, "threads"):
            conf.threads = 0
            option._setThreads()
            self.assertEqual(conf.threads, 1)

    def test_negative_becomes_one(self):
        with _preserve(conf, "threads"):
            conf.threads = -5
            option._setThreads()
            self.assertEqual(conf.threads, 1)

    def test_non_int_becomes_one(self):
        with _preserve(conf, "threads"):
            conf.threads = None
            option._setThreads()
            self.assertEqual(conf.threads, 1)

    def test_positive_int_preserved(self):
        with _preserve(conf, "threads"):
            conf.threads = 7
            option._setThreads()
            self.assertEqual(conf.threads, 7)


class TestSetPrefixSuffix(unittest.TestCase):
    def test_no_prefix_suffix_noop(self):
        with _preserve(conf, "prefix", "suffix", "boundaries"):
            conf.prefix = None
            conf.suffix = None
            conf.boundaries = []
            option._setPrefixSuffix()
            self.assertEqual(conf.boundaries, [])

    def test_builds_single_boundary(self):
        with _preserve(conf, "prefix", "suffix", "boundaries"):
            conf.prefix = "')"
            conf.suffix = "-- -"
            conf.boundaries = []
            option._setPrefixSuffix()
            self.assertEqual(len(conf.boundaries), 1)
            b = conf.boundaries[0]
            self.assertEqual(b.prefix, "')")
            self.assertEqual(b.suffix, "-- -")
            self.assertEqual(b.level, 1)

    def test_ptype_single_quote(self):
        with _preserve(conf, "prefix", "suffix", "boundaries"):
            conf.prefix = "'"
            conf.suffix = "'"
            conf.boundaries = []
            option._setPrefixSuffix()
            self.assertEqual(conf.boundaries[0].ptype, 2)

    def test_ptype_double_quote(self):
        with _preserve(conf, "prefix", "suffix", "boundaries"):
            conf.prefix = '"'
            conf.suffix = '"'
            conf.boundaries = []
            option._setPrefixSuffix()
            self.assertEqual(conf.boundaries[0].ptype, 4)

    def test_ptype_plain(self):
        with _preserve(conf, "prefix", "suffix", "boundaries"):
            conf.prefix = " "
            conf.suffix = ""
            conf.boundaries = []
            option._setPrefixSuffix()
            self.assertEqual(conf.boundaries[0].ptype, 1)


class TestSetHostname(unittest.TestCase):
    def test_extracts_host(self):
        with _preserve(conf, "url", "hostname"):
            conf.url = "http://www.example.com:8080/page?id=1"
            option._setHostname()
            self.assertEqual(conf.hostname, "www.example.com")

    def test_no_url_noop(self):
        with _preserve(conf, "url", "hostname"):
            conf.url = None
            conf.hostname = "preexisting"
            option._setHostname()
            self.assertEqual(conf.hostname, "preexisting")


class TestSetHTTPHeaderSetters(unittest.TestCase):
    def test_referer_appended(self):
        with _preserve(conf, "referer", "httpHeaders"):
            conf.httpHeaders = []
            conf.referer = "http://ref.example/"
            option._setHTTPReferer()
            self.assertIn((HTTP_HEADER.REFERER, "http://ref.example/"), conf.httpHeaders)

    def test_referer_none_noop(self):
        with _preserve(conf, "referer", "httpHeaders"):
            conf.httpHeaders = []
            conf.referer = None
            option._setHTTPReferer()
            self.assertEqual(conf.httpHeaders, [])

    def test_host_appended(self):
        with _preserve(conf, "host", "httpHeaders"):
            conf.httpHeaders = []
            conf.host = "victim.local"
            option._setHTTPHost()
            self.assertIn((HTTP_HEADER.HOST, "victim.local"), conf.httpHeaders)

    def test_cookie_appended(self):
        with _preserve(conf, "cookie", "httpHeaders"):
            conf.httpHeaders = []
            conf.cookie = "SESSION=abc"
            option._setHTTPCookies()
            self.assertIn((HTTP_HEADER.COOKIE, "SESSION=abc"), conf.httpHeaders)


class TestSetHTTPUserAgent(unittest.TestCase):
    def test_explicit_agent(self):
        with _preserve(conf, "agent", "mobile", "randomAgent", "httpHeaders"):
            conf.httpHeaders = []
            conf.mobile = False
            conf.randomAgent = False
            conf.agent = "MyCustomUA/1.0"
            option._setHTTPUserAgent()
            self.assertIn((HTTP_HEADER.USER_AGENT, "MyCustomUA/1.0"), conf.httpHeaders)

    def test_default_agent_when_unset(self):
        with _preserve(conf, "agent", "mobile", "randomAgent", "httpHeaders"):
            conf.httpHeaders = []
            conf.mobile = False
            conf.randomAgent = False
            conf.agent = None
            option._setHTTPUserAgent()
            self.assertIn((HTTP_HEADER.USER_AGENT, DEFAULT_USER_AGENT), conf.httpHeaders)

    def test_existing_ua_not_duplicated(self):
        with _preserve(conf, "agent", "mobile", "randomAgent", "httpHeaders"):
            conf.httpHeaders = [(HTTP_HEADER.USER_AGENT, "Already/1.0")]
            conf.mobile = False
            conf.randomAgent = False
            conf.agent = None
            option._setHTTPUserAgent()
            uas = [v for (h, v) in conf.httpHeaders if h.upper() == HTTP_HEADER.USER_AGENT.upper()]
            self.assertEqual(uas, ["Already/1.0"])


class TestSetHTTPExtraHeaders(unittest.TestCase):
    def test_parses_newline_separated(self):
        with _preserve(conf, "headers", "httpHeaders", "requestFile", "encoding"):
            conf.httpHeaders = []
            conf.headers = "X-Foo: bar\nX-Baz: qux"
            option._setHTTPExtraHeaders()
            self.assertIn(("X-Foo", "bar"), conf.httpHeaders)
            self.assertIn(("X-Baz", "qux"), conf.httpHeaders)

    def test_escaped_newline_form(self):
        with _preserve(conf, "headers", "httpHeaders", "requestFile", "encoding"):
            conf.httpHeaders = []
            conf.headers = "X-A: 1\\nX-B: 2"
            option._setHTTPExtraHeaders()
            self.assertIn(("X-A", "1"), conf.httpHeaders)
            self.assertIn(("X-B", "2"), conf.httpHeaders)

    def test_invalid_header_raises(self):
        with _preserve(conf, "headers", "httpHeaders", "requestFile", "encoding"):
            conf.httpHeaders = []
            conf.headers = "no-colon-here"
            self.assertRaises(SqlmapSyntaxException, option._setHTTPExtraHeaders)

    def test_no_headers_adds_cache_control(self):
        # with no explicit headers and no requestFile, a Cache-Control:no-cache is appended
        with _preserve(conf, "headers", "httpHeaders", "requestFile", "encoding"):
            conf.httpHeaders = []
            conf.headers = None
            conf.requestFile = None
            conf.encoding = None
            option._setHTTPExtraHeaders()
            self.assertIn((HTTP_HEADER.CACHE_CONTROL, "no-cache"), conf.httpHeaders)


class TestNormalizeOptions(unittest.TestCase):
    def test_integer_coercion(self):
        # 'threads' is an INTEGER option; a string value is coerced to int in place
        opts = {"threads": "5"}
        option._normalizeOptions(opts)
        self.assertEqual(opts["threads"], 5)

    def test_bad_integer_becomes_zero(self):
        opts = {"threads": "notanumber"}
        option._normalizeOptions(opts)
        self.assertEqual(opts["threads"], 0)

    def test_none_left_alone(self):
        opts = {"threads": None}
        option._normalizeOptions(opts)
        self.assertIsNone(opts["threads"])

    def test_unknown_key_untouched(self):
        opts = {"definitelyNotAnOption": "value"}
        option._normalizeOptions(opts)
        self.assertEqual(opts["definitelyNotAnOption"], "value")


class TestSetVerbosity(unittest.TestCase):
    def _restore_logger(self):
        return _preserve(conf, "verbose", "eta")

    def test_none_becomes_one(self):
        saved_level = logger.level
        try:
            with self._restore_logger():
                conf.verbose = None
                conf.eta = False
                option.setVerbosity()
                self.assertEqual(conf.verbose, 1)
                self.assertEqual(logger.level, logging.INFO)
        finally:
            logger.setLevel(saved_level)

    def test_zero_sets_error_level(self):
        saved_level = logger.level
        try:
            with self._restore_logger():
                conf.verbose = 0
                conf.eta = False
                option.setVerbosity()
                self.assertEqual(logger.level, logging.ERROR)
        finally:
            logger.setLevel(saved_level)

    def test_two_sets_debug_level(self):
        saved_level = logger.level
        try:
            with self._restore_logger():
                conf.verbose = 2
                conf.eta = False
                option.setVerbosity()
                self.assertEqual(logger.level, logging.DEBUG)
        finally:
            logger.setLevel(saved_level)


class TestCleanupOptions(_BackendGuard):
    """_cleanupOptions touches a huge number of conf fields; preserve broadly."""

    # the subset of conf keys these tests read or write
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
        """Set the cleanup-relevant conf fields to inert defaults, then let the
        individual test override the one(s) it cares about."""
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

    def test_test_parameter_split(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.testParameter = "id,name"
            option._cleanupOptions()
            self.assertEqual(conf.testParameter, ["id", "name"])

    def test_empty_test_parameter_becomes_list(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.testParameter = None
            option._cleanupOptions()
            self.assertEqual(conf.testParameter, [])

    def test_ignore_code_wildcard(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.ignoreCode = IGNORE_CODE_WILDCARD
            option._cleanupOptions()
            self.assertIn(404, conf.ignoreCode)
            self.assertIn(0, conf.ignoreCode)

    def test_ignore_code_list(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.ignoreCode = "401,403"
            option._cleanupOptions()
            self.assertEqual(conf.ignoreCode, [401, 403])

    def test_ignore_code_invalid_raises(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.ignoreCode = "abc"
            self.assertRaises(SqlmapSyntaxException, option._cleanupOptions)

    def test_abort_code_list(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.abortCode = "500,502"
            option._cleanupOptions()
            self.assertEqual(conf.abortCode, [500, 502])

    def test_param_filter_uppercased_and_split(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.paramFilter = "get,post"
            option._cleanupOptions()
            self.assertEqual(conf.paramFilter, ["GET", "POST"])

    def test_skip_split(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.skip = "a, b ,c"
            option._cleanupOptions()
            self.assertEqual(conf.skip, ["a", "b", "c"])

    def test_url_scheme_prepended(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.url = "example.com/page?id=1"
            option._cleanupOptions()
            self.assertTrue(conf.url.startswith("http://"), msg=conf.url)

    def test_url_credentials_extracted_to_basic_auth(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"), \
                _preserve(conf, "authType", "authCred"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.authType = None
            conf.authCred = None
            conf.url = "http://user:pass@example.com/page?id=1"
            option._cleanupOptions()
            self.assertNotIn("user:pass@", conf.url)
            self.assertEqual(conf.authCred, "user:pass")

    def test_random_pool_from_rparam(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.rParam = "id=1,2,3"
            option._cleanupOptions()
            self.assertEqual(conf.rParam, ["id"])
            self.assertEqual(kb.randomPool["id"], ["1", "2", "3"])

    def test_code_cast_to_int(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.code = "200"
            option._cleanupOptions()
            self.assertEqual(conf.code, 200)

    def test_dump_format_uppercased(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.dumpFormat = "csv"
            option._cleanupOptions()
            self.assertEqual(conf.dumpFormat, "CSV")

    def test_uvalues_sets_ucols(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.uValues = "NULL,1,2"
            option._cleanupOptions()
            self.assertEqual(conf.uCols, "3-3")

    def test_multiple_targets_flag(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.crawlDepth = 2
            option._cleanupOptions()
            self.assertTrue(conf.multipleTargets)

    def test_proxy_disables_precon(self):
        with _preserve(conf, *self._KEYS), _preserve(kb, "explicitSettings", "randomPool", "dbmsFilter", "adjustTimeDelay"), \
                _preserve(conf, "disablePrecon"):
            kb.explicitSettings = set()
            kb.randomPool = {}
            self._base()
            conf.disablePrecon = False
            conf.proxy = "http://127.0.0.1:8080"
            option._cleanupOptions()
            self.assertTrue(conf.disablePrecon)


class TestBasicOptionValidation(_BackendGuard):
    """_basicOptionValidation reads a wide swathe of conf; set up a benign baseline
    and flip one offending pair per test."""

    _KEYS = (
        "limitStart", "limitStop", "level", "risk", "firstChar", "lastChar",
        "textOnly", "nullConnection", "uValues", "uChar", "base64Parameter",
        "tamper", "eta", "verbose", "direct", "url", "dbms", "tor", "proxy",
        "ignoreProxy", "regexp", "timeSec", "torPort", "torType", "dumpFormat",
        "technique", "threads", "predictOutput", "optimize", "csrfToken",
        "csrfUrl", "string", "notString", "noCast", "hexConvert",
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
        conf.verbose = 1
        conf.timeSec = 5
        conf.torPort = None
        conf.torType = "SOCKS5"
        conf.dumpFormat = "CSV"
        conf.technique = [1, 2, 6, 4, 5]
        conf.threads = 1

    def test_clean_baseline_passes(self):
        with _preserve(conf, *self._KEYS):
            self._base()
            option._basicOptionValidation()  # must not raise

    def test_bad_level_raises(self):
        with _preserve(conf, *self._KEYS):
            self._base()
            conf.level = 99
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_bad_risk_raises(self):
        with _preserve(conf, *self._KEYS):
            self._base()
            conf.risk = 9
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_textonly_nullconnection_incompatible(self):
        with _preserve(conf, *self._KEYS):
            self._base()
            conf.textOnly = True
            conf.nullConnection = True
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_direct_url_incompatible(self):
        with _preserve(conf, *self._KEYS):
            self._base()
            conf.direct = "mysql://u:p@h/db"
            conf.url = "http://x/?id=1"
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_empty_technique_raises(self):
        with _preserve(conf, *self._KEYS):
            self._base()
            conf.technique = []
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_bad_regexp_raises(self):
        with _preserve(conf, *self._KEYS):
            self._base()
            conf.regexp = "("
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_bad_dump_format_raises(self):
        with _preserve(conf, *self._KEYS):
            self._base()
            conf.dumpFormat = "BOGUS"
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_bad_tor_port_raises(self):
        with _preserve(conf, *self._KEYS):
            self._base()
            conf.torPort = 70000
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_uvalues_uchar_incompatible(self):
        with _preserve(conf, *self._KEYS):
            self._base()
            conf.uValues = "NULL,1"
            conf.uChar = "NULL"
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)

    def test_tor_ignoreproxy_incompatible(self):
        with _preserve(conf, *self._KEYS):
            self._base()
            conf.tor = True
            conf.ignoreProxy = True
            self.assertRaises(SqlmapSyntaxException, option._basicOptionValidation)


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
    TestCleanupOptions."""

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
    _basicOptionValidation not covered by TestBasicOptionValidation."""

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
    """_normalizeOptions coerces values by option type. TestNormalizeOptions covers
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
    """setVerbosity branches not covered by TestSetVerbosity."""

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


class TestOptionSetPrefixSuffix(unittest.TestCase):
    """_setPrefixSuffix boundary construction (pure conf-mutation, no I/O)."""

    def setUp(self):
        self._saved = {k: conf.get(k) for k in ("prefix", "suffix", "boundaries")}

    def tearDown(self):
        for k, v in self._saved.items():
            conf[k] = v

    def _run(self, prefix, suffix):
        from lib.core.option import _setPrefixSuffix
        conf.prefix = prefix
        conf.suffix = suffix
        conf.boundaries = None
        _setPrefixSuffix()
        return conf.boundaries

    def test_none_no_boundary(self):
        # when either prefix or suffix is None, no boundary is created
        self.assertIsNone(self._run(None, None))

    def test_single_quote_ptype(self):
        boundaries = self._run("' AND ", "'")
        self.assertEqual(len(boundaries), 1)
        b = boundaries[0]
        self.assertEqual(b.prefix, "' AND ")
        self.assertEqual(b.suffix, "'")
        self.assertEqual(b.ptype, 2)         # single-quote, no LIKE
        self.assertEqual(b.level, 1)
        self.assertEqual(b.clause, [0])

    def test_double_quote_ptype(self):
        boundaries = self._run('" AND ', '"')
        self.assertEqual(boundaries[0].ptype, 4)   # double-quote, no LIKE

    def test_numeric_ptype(self):
        boundaries = self._run(" AND ", "")
        self.assertEqual(boundaries[0].ptype, 1)   # no quoting

    def test_like_single_quote_ptype(self):
        boundaries = self._run("' AND ", "' like '%")
        self.assertEqual(boundaries[0].ptype, 3)   # LIKE with single quote


class TestOptionSetWriteFile(unittest.TestCase):

    def setUp(self):
        self._saved = (conf.fileWrite, conf.fileDest, conf.get("fileWriteType"))

    def tearDown(self):
        conf.fileWrite, conf.fileDest, conf.fileWriteType = self._saved

    def test_noop_when_no_filewrite(self):
        conf.fileWrite = None
        self.assertIsNone(option._setWriteFile())

    def test_raises_on_missing_local_file(self):
        conf.fileWrite = "/no/such/local_file_xyz"
        conf.fileDest = "/var/www/x"
        with self.assertRaises(SqlmapFilePathException):
            option._setWriteFile()

    def test_raises_on_missing_dest(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            conf.fileWrite = path
            conf.fileDest = None
            with self.assertRaises(SqlmapMissingMandatoryOptionException):
                option._setWriteFile()
        finally:
            os.unlink(path)

    def test_sets_file_write_type(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            conf.fileWrite = path
            conf.fileDest = "/var/www/x"
            option._setWriteFile()
            self.assertIn(conf.fileWriteType, ("text", "binary"))
        finally:
            os.unlink(path)


class TestOptionSetHTTPTimeout(unittest.TestCase):

    def setUp(self):
        self._savedTimeout = conf.timeout
        self._savedSocket = socket.getdefaulttimeout()

    def tearDown(self):
        conf.timeout = self._savedTimeout
        socket.setdefaulttimeout(self._savedSocket)

    def test_explicit_timeout(self):
        conf.timeout = 10
        option._setHTTPTimeout()
        self.assertEqual(conf.timeout, 10.0)

    def test_below_minimum_is_clamped(self):
        conf.timeout = 1
        option._setHTTPTimeout()
        self.assertEqual(conf.timeout, 3.0)

    def test_default_when_unset(self):
        conf.timeout = None
        option._setHTTPTimeout()
        self.assertEqual(conf.timeout, 30.0)


class TestOptionSetHTTPAuthentication(unittest.TestCase):

    def setUp(self):
        self._saved = {
            "authType": conf.authType,
            "authCred": conf.authCred,
            "authFile": conf.authFile,
            "authUsername": conf.authUsername,
            "authPassword": conf.authPassword,
            "httpHeaders": list(conf.httpHeaders),
            "passwordMgr": kb.passwordMgr,
        }
        # provide a real password manager so the basic/digest branches work
        kb.passwordMgr = _urllib.request.HTTPPasswordMgrWithDefaultRealm()

    def tearDown(self):
        conf.authType = self._saved["authType"]
        conf.authCred = self._saved["authCred"]
        conf.authFile = self._saved["authFile"]
        conf.authUsername = self._saved["authUsername"]
        conf.authPassword = self._saved["authPassword"]
        conf.httpHeaders = self._saved["httpHeaders"]
        kb.passwordMgr = self._saved["passwordMgr"]

    def test_noop_when_nothing_set(self):
        conf.authType = None
        conf.authCred = None
        conf.authFile = None
        self.assertIsNone(option._setHTTPAuthentication())

    def test_basic_credentials_parsed(self):
        conf.authType = "basic"
        conf.authCred = "admin:secret"
        conf.authFile = None
        option._setHTTPAuthentication()
        self.assertEqual(conf.authUsername, "admin")
        self.assertEqual(conf.authPassword, "secret")

    def test_ntlm_credentials_parsed(self):
        conf.authType = "ntlm"
        conf.authCred = "DOMAIN\\user:pa:ss"
        conf.authFile = None
        conf.authUsername = None
        conf.authPassword = None
        # The python-ntlm handler module is optional; credential parsing happens
        # before the handler import, so the parsed creds are set regardless.
        try:
            option._setHTTPAuthentication()
        except SqlmapMissingDependence:
            pass
        self.assertEqual(conf.authUsername, "DOMAIN\\user")
        self.assertEqual(conf.authPassword, "pa:ss")

    def test_ntlm_bad_format_raises(self):
        conf.authType = "ntlm"
        conf.authCred = "nobackslash:pass"
        conf.authFile = None
        with self.assertRaises(SqlmapSyntaxException):
            option._setHTTPAuthentication()

    def test_bearer_appends_authorization_header(self):
        conf.authType = "bearer"
        conf.authCred = "tok123"
        conf.authFile = None
        conf.httpHeaders = []
        option._setHTTPAuthentication()
        self.assertIn((HTTP_HEADER.AUTHORIZATION, "Bearer tok123"), conf.httpHeaders)

    def test_unsupported_type_raises(self):
        conf.authType = "wrongtype"
        conf.authCred = "a:b"
        conf.authFile = None
        with self.assertRaises(SqlmapSyntaxException):
            option._setHTTPAuthentication()

    def test_type_without_credentials_raises(self):
        conf.authType = "basic"
        conf.authCred = None
        conf.authFile = None
        with self.assertRaises(SqlmapSyntaxException):
            option._setHTTPAuthentication()

    def test_credentials_without_type_raises(self):
        conf.authType = None
        conf.authCred = "a:b"
        conf.authFile = None
        with self.assertRaises(SqlmapSyntaxException):
            option._setHTTPAuthentication()

    def test_authfile_without_type_defaults_to_pki(self):
        conf.authType = None
        conf.authCred = None
        conf.authFile = __file__  # exists, so checkFile() inside PKI branch passes
        option._setHTTPAuthentication()
        self.assertEqual(conf.authType, AUTH_TYPE.PKI)

    def test_pki_type_without_authfile_raises(self):
        conf.authType = "pki"
        conf.authCred = "x"
        conf.authFile = None
        with self.assertRaises(SqlmapSyntaxException):
            option._setHTTPAuthentication()


class TestOptionSetAuthCred(unittest.TestCase):

    def setUp(self):
        self._saved = {
            "scheme": conf.scheme,
            "hostname": conf.hostname,
            "port": conf.port,
            "authUsername": conf.authUsername,
            "authPassword": conf.authPassword,
            "passwordMgr": kb.passwordMgr,
        }

    def tearDown(self):
        conf.scheme = self._saved["scheme"]
        conf.hostname = self._saved["hostname"]
        conf.port = self._saved["port"]
        conf.authUsername = self._saved["authUsername"]
        conf.authPassword = self._saved["authPassword"]
        kb.passwordMgr = self._saved["passwordMgr"]

    def test_noop_without_password_manager(self):
        kb.passwordMgr = None
        # Must not raise when there is no password manager configured
        self.assertIsNone(option._setAuthCred())

    def test_adds_credentials_to_manager(self):
        kb.passwordMgr = _urllib.request.HTTPPasswordMgrWithDefaultRealm()
        conf.scheme = "http"
        conf.hostname = "host"
        conf.port = 80
        conf.authUsername = "u"
        conf.authPassword = "p"
        option._setAuthCred()
        self.assertEqual(
            kb.passwordMgr.find_user_password(None, "http://host:80"),
            ("u", "p"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
