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
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.data import conf, kb, logger
from lib.core.common import Backend
from lib.core.enums import HTTP_HEADER
from lib.core.settings import DEFAULT_USER_AGENT
from lib.core.settings import IGNORE_CODE_WILDCARD
from lib.core.exception import SqlmapSyntaxException
from lib.core.exception import SqlmapUnsupportedDBMSException

import lib.core.option as option

_SENTINEL = object()

# conf/kb fields that Backend.getIdentifiedDbms()/getOs() consult; any test that
# might touch DBMS/OS forcing snapshots ALL of them so no fingerprint state leaks
# into sibling test files (e.g. test_target_parsing's resume tests).
_BACKEND_CONF_KEYS = ("dbms", "forceDbms", "os")
_BACKEND_KB_KEYS = ("dbms", "dbmsVersion", "forcedDbms", "dbmsFilter", "os", "osVersion", "osSP")


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
