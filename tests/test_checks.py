#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit tests for lib/controller/checks.py driven with a MOCKED HTTP layer.

checks.py is the injection-detection controller; almost everything in it goes
through the network seam (lib.request.connect.Connect, imported into the module
as `Request`). By monkeypatching `Request.queryPage` / `Request.getPage` to
return canned (page, headers/ratio, code) tuples - and stubbing `agent.payload`
where the real payload machinery would require a fully-built target - the
decision logic of each check (the kb.*/conf.*/return-value verdict) can be
exercised offline, without a live target, DBMS, or DNS.

Every test snapshots and restores the conf/kb fields it touches AND every
module attribute it monkeypatches, so ordering between tests (and with the rest
of the suite) is irrelevant. conf.batch is forced on to avoid interactive
prompts, and readInput is stubbed per-test where a branch would prompt.
"""

import os
import re
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import lib.controller.checks as checks
from lib.core.data import conf, kb
from lib.core.datatype import AttribDict, InjectionDict
from lib.core.dicts import FROM_DUMMY_TABLE
from lib.core.enums import DBMS
from lib.core.enums import HEURISTIC_TEST
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NULLCONNECTION
from lib.core.enums import PLACE
from lib.core.settings import SINGLE_QUOTE_MARKER
from lib.core.common import getCurrentThreadData
from lib.parse.html import htmlParser


# conf/kb fields any of the checks read or write; snapshotted wholesale so a
# test never leaks state into another test or the rest of the suite.
_CONF_KEYS = (
    "paramDict", "parameters", "url", "hostname", "method", "skipHeuristics",
    "prefix", "suffix", "nosql", "graphql", "ldap", "xpath", "ssti", "beep", "string",
    "notString", "regexp", "regex", "dummy", "offline", "skipWaf", "data",
    "hashDB", "cj", "cookie", "dropSetCookie", "httpHeaders", "proxy", "tor",
    "tamper", "timeout", "retries", "textOnly", "ignoreCode", "disablePrecon",
    "ipv6", "multipleTargets", "level", "base64Parameter", "batch",
)
_KB_KEYS = (
    "heavilyDynamic", "dynamicParameter", "originalPage", "originalPageTime",
    "originalCode", "ignoreCasted", "heuristicMode", "disableHtmlDecoding",
    "heuristicTest", "heuristicPage", "heuristicCode", "pageStable",
    "nullConnection", "pageCompress", "matchRatio", "skipSeqMatcher",
    "choices", "injection", "errorIsNone", "serverHeader", "identifiedWafs",
    "tamperFunctions", "resendPostOnRedirect", "checkWafMode", "wafBypass",
    "heuristicExtendedDbms", "resumeValues", "mergeCookies", "httpErrorCodes",
)


def _snapshot():
    return (
        dict((k, conf.get(k)) for k in _CONF_KEYS),
        dict((k, kb.get(k)) for k in _KB_KEYS),
    )


def _restore(snap):
    confSnap, kbSnap = snap
    for k, v in confSnap.items():
        conf[k] = v
    for k, v in kbSnap.items():
        kb[k] = v


class _ChecksTestBase(unittest.TestCase):
    """Snapshots conf/kb and the patchable seams; restores them in tearDown."""

    def setUp(self):
        self._snap = _snapshot()
        # remember the real seams so monkeypatches can't leak. agent.payload /
        # addPayloadDelimiters are class methods on a shared singleton: patching
        # sets an *instance* attribute, so it's restored by deleting that
        # attribute (reassigning would leave a stale bound method behind).
        self._origQueryPage = checks.Request.queryPage
        self._origGetPage = checks.Request.getPage
        self._agentHadPayload = "payload" in checks.agent.__dict__
        self._agentHadAddDelims = "addPayloadDelimiters" in checks.agent.__dict__
        self._origReadInput = checks.readInput
        self._origDbmsErr = checks.wasLastResponseDBMSError
        self._origHttpErr = checks.wasLastResponseHTTPError
        self._origCBE = checks.checkBooleanExpression

        # sane offline baseline shared by most checks
        conf.batch = True
        conf.skipHeuristics = False
        conf.prefix = conf.suffix = None
        conf.hashDB = None
        conf.dummy = conf.offline = conf.proxy = conf.tor = None
        kb.choices = AttribDict(keycheck=False)

    def tearDown(self):
        checks.Request.queryPage = self._origQueryPage
        checks.Request.getPage = self._origGetPage
        if not self._agentHadPayload and "payload" in checks.agent.__dict__:
            del checks.agent.payload
        if not self._agentHadAddDelims and "addPayloadDelimiters" in checks.agent.__dict__:
            del checks.agent.addPayloadDelimiters
        checks.readInput = self._origReadInput
        checks.wasLastResponseDBMSError = self._origDbmsErr
        checks.wasLastResponseHTTPError = self._origHttpErr
        checks.checkBooleanExpression = self._origCBE
        _restore(self._snap)

    # --- helpers ---

    def _patchQueryPage(self, fn):
        checks.Request.queryPage = staticmethod(fn)

    def _patchGetPage(self, fn):
        checks.Request.getPage = staticmethod(fn)

    @staticmethod
    def _contentQuery(page, code=200, headers=None):
        """A queryPage that returns (page, headers/ratio, code) when content is
        requested and a plain truthiness otherwise."""
        def _fn(*args, **kwargs):
            if kwargs.get("content"):
                return (page, headers, code)
            return bool(page)
        return _fn

    @staticmethod
    def _detectingContentQuery(page, code=200, headers=None):
        """Like _contentQuery, but mirrors the real connection layer's
        error-detection seam: it advances the request UID and runs the REAL
        htmlParser() over the page (exactly as Connect.getPage() does), so the
        page is classified by sqlmap's genuine error regexes. The unstubbed
        wasLastResponseDBMSError() then reads the threadData.lastErrorPage this
        leaves behind - the heuristic verdict is the detector's, not the stub's."""
        def _fn(*args, **kwargs):
            threadData = getCurrentThreadData()
            kb.requestCounter = (kb.get("requestCounter") or 0) + 1
            threadData.lastRequestUID = kb.requestCounter
            htmlParser(page or "")
            if kwargs.get("content"):
                return (page, headers, code)
            return bool(page)
        return _fn

    @staticmethod
    def _comparingQuery(page, code=200, headers=None):
        """A queryPage that, for a non-content request, runs the REAL
        comparison() engine of the injected page against kb.pageTemplate (the
        same call Connect.queryPage makes for its True/False verdict). The
        matchRatio/seqMatcher dynamicity logic therefore actually executes -
        the verdict is computed, not hard-coded."""
        def _fn(*args, **kwargs):
            if kwargs.get("content"):
                return (page, headers, code)
            return checks.comparison(page, headers, code, getRatioValue=False)
        return _fn


class TestHeuristicCheckSqlInjection(_ChecksTestBase):
    def setUp(self):
        super(TestHeuristicCheckSqlInjection, self).setUp()
        conf.paramDict = {PLACE.GET: {"id": "1"}}
        conf.parameters = {PLACE.GET: "id=1"}
        conf.url = "http://test.invalid/index.php?id=1"
        conf.method = None
        conf.nosql = conf.graphql = conf.ldap = conf.xpath = conf.ssti = False
        conf.beep = False
        kb.heavilyDynamic = False
        kb.dynamicParameter = False
        kb.originalPage = ""
        kb.ignoreCasted = False
        # clear any error-page marker left by an earlier request so the real
        # wasLastResponseDBMSError() starts from a clean slate
        td = getCurrentThreadData()
        td.lastErrorPage = tuple()
        td.lastRequestUID = 0
        # bypass the full payload-building machinery (needs a built target)
        checks.agent.payload = lambda *a, **kw: "PAYLOAD"

    def test_skip_heuristics_returns_none(self):
        conf.skipHeuristics = True
        self.assertIsNone(checks.heuristicCheckSqlInjection(PLACE.GET, "id"))

    def test_positive_on_dbms_error(self):
        # Feed a GENUINE MySQL error page (matches sqlmap's real error regex in
        # data/xml/errors.xml) through the detecting stub and let the UNSTUBBED
        # wasLastResponseDBMSError() classify it. The POSITIVE verdict is then
        # the real detector's, not a hard-coded True.
        page = ("<html><body>You have an error in your SQL syntax; check the "
                "manual that corresponds to your MySQL server version</body></html>")
        self._patchQueryPage(self._detectingContentQuery(page))
        result = checks.heuristicCheckSqlInjection(PLACE.GET, "id")
        self.assertEqual(result, HEURISTIC_TEST.POSITIVE)
        self.assertEqual(kb.heuristicTest, HEURISTIC_TEST.POSITIVE)

    def test_negative_on_clean_page(self):
        # A clean page matches none of sqlmap's error regexes, so the unstubbed
        # wasLastResponseDBMSError() returns false -> NEGATIVE verdict.
        self._patchQueryPage(self._detectingContentQuery("a perfectly ordinary page"))
        result = checks.heuristicCheckSqlInjection(PLACE.GET, "id")
        self.assertEqual(result, HEURISTIC_TEST.NEGATIVE)
        self.assertEqual(kb.heuristicTest, HEURISTIC_TEST.NEGATIVE)

    def test_records_page_and_resets_mode(self):
        self._patchQueryPage(self._detectingContentQuery("nothing special here"))
        checks.heuristicCheckSqlInjection(PLACE.GET, "id")
        # mode flags must be flipped back off after the check
        self.assertFalse(kb.heuristicMode)
        self.assertFalse(kb.disableHtmlDecoding)


class TestHeuristicCheckDbms(_ChecksTestBase):
    def setUp(self):
        super(TestHeuristicCheckDbms, self).setUp()
        kb.injection = InjectionDict()

    def test_skip_heuristics_returns_false(self):
        conf.skipHeuristics = True
        self.assertFalse(checks.heuristicCheckDbms(InjectionDict()))

    def test_no_match_when_all_expressions_false(self):
        checks.checkBooleanExpression = lambda expr: False
        self.assertFalse(checks.heuristicCheckDbms(InjectionDict()))

    def test_identifies_dbms_on_distinguishing_pair(self):
        # An expr-AWARE oracle that recognises ONLY the predicate
        # heuristicCheckDbms() builds for one CHOSEN target DBMS. The function
        # iterates every DBMS, forging for each the pair
        #   positive: (SELECT '<r1>'<FROM dbms>)=<Q><r1><Q>   -> must be True
        #   negative: (SELECT '<r1>'<FROM dbms>)=<Q><r2><Q>   -> must be False
        # (<Q> == SINGLE_QUOTE_MARKER, r1 != r2). The DBMS is reported only when
        # the positive holds AND the negative fails. The oracle below returns
        # True exactly for that shape - it keys off the chosen DBMS's UNIQUE
        # FROM clause (so no other DBMS's predicate matches) and off the two
        # quoted literals being equal (so the "must differ" negative is False).
        # Firebird is chosen because its FROM clause (' FROM RDB$DATABASE') is
        # unique in FROM_DUMMY_TABLE and it is not a HEURISTIC_NULL_EVAL DBMS,
        # so heuristicCheckDbms() takes the SELECT-literal predicate path for it.
        target = DBMS.FIREBIRD
        targetFrom = FROM_DUMMY_TABLE[target]
        predicate = re.compile(
            r"\(SELECT '([^']*)'( FROM [^)]*)?\)="
            + re.escape(SINGLE_QUOTE_MARKER) + r"(.*?)" + re.escape(SINGLE_QUOTE_MARKER)
        )

        def oracle(expr):
            match = predicate.search(expr)
            if not match:
                return False
            selected, fromClause, compared = match.group(1), match.group(2) or "", match.group(3)
            # True only for the target DBMS's FROM clause with matching literals
            return fromClause == targetFrom and selected == compared

        checks.checkBooleanExpression = oracle
        result = checks.heuristicCheckDbms(InjectionDict())
        # real predicate matching must single out the chosen DBMS, not whatever
        # getPublicTypeMembers() happens to yield first
        self.assertEqual(result, target)
        self.assertEqual(kb.heuristicExtendedDbms, target)


class TestCheckDynParam(_ChecksTestBase):
    # A stable baseline page that checkDynParam's injected response is compared
    # against by the REAL comparison() engine. Long enough that difflib's
    # quick_ratio is meaningful rather than degenerate.
    _BASELINE = ("<html><head><title>Welcome</title></head><body>"
                 + "the quick brown fox jumps over the lazy dog. " * 20
                 + "</body></html>")

    def setUp(self):
        super(TestCheckDynParam, self).setUp()
        conf.method = None
        checks.agent.payload = lambda *a, **kw: "PAYLOAD"
        # state the real comparison() engine reads
        conf.string = conf.notString = conf.regexp = conf.code = None
        conf.titles = conf.textOnly = False
        kb.nullConnection = False
        kb.heavilyDynamic = False
        kb.skipSeqMatcher = False
        kb.errorIsNone = False
        kb.negativeLogic = False
        kb.pageCompress = False
        kb.matchRatio = None
        kb.pageTemplate = self._BASELINE

    def test_redirect_short_circuits(self):
        kb.choices.redirect = "yes"
        self.assertIsNone(checks.checkDynParam(PLACE.GET, "id", "1"))

    def test_dynamic_when_page_differs(self):
        # A response wildly different from the baseline drives the real
        # comparison() ratio below LOWER_RATIO_BOUND -> queryPage returns False
        # (page differs) -> parameter is dynamic.
        self._patchQueryPage(self._comparingQuery("totally unrelated content " + "Z" * 200))
        result = checks.checkDynParam(PLACE.GET, "id", "1")
        self.assertTrue(result)
        self.assertTrue(kb.dynamicParameter)

    def test_not_dynamic_when_page_same(self):
        # An identical response yields ratio 1.0 (> UPPER_RATIO_BOUND) from the
        # real comparison() -> queryPage returns True (page same) -> not dynamic.
        self._patchQueryPage(self._comparingQuery(self._BASELINE))
        result = checks.checkDynParam(PLACE.GET, "id", "1")
        self.assertFalse(result)
        self.assertFalse(kb.dynamicParameter)


class TestCheckDynamicContent(_ChecksTestBase):
    def setUp(self):
        super(TestCheckDynamicContent, self).setUp()
        kb.nullConnection = False

    def test_null_connection_skips(self):
        kb.nullConnection = NULLCONNECTION.HEAD
        self.assertIsNone(checks.checkDynamicContent("a", "b"))

    def test_missing_page_aborts(self):
        self.assertIsNone(checks.checkDynamicContent(None, "x"))

    def test_identical_pages_no_dynamicity(self):
        # high ratio -> no dynamic-content engine, no further requests
        self._patchQueryPage(lambda *a, **kw: self.fail("should not request"))
        self.assertIsNone(checks.checkDynamicContent("identical content", "identical content"))


class TestCheckStability(_ChecksTestBase):
    def setUp(self):
        super(TestCheckStability, self).setUp()
        kb.originalPageTime = time.time()
        kb.nullConnection = False

    def test_stable_when_pages_match(self):
        kb.originalPage = "SAME PAGE"
        self._patchQueryPage(self._contentQuery("SAME PAGE"))
        self.assertTrue(checks.checkStability())
        self.assertTrue(kb.pageStable)

    def test_redirect_returns_none(self):
        kb.originalPage = "SAME PAGE"
        self._patchQueryPage(self._contentQuery("SAME PAGE"))
        kb.choices.redirect = "yes"
        self.assertIsNone(checks.checkStability())

    def test_unstable_continue_choice(self):
        kb.originalPage = "FIRST PAGE CONTENT"
        conf.retries = 0
        kb.heavilyDynamic = False
        checks.readInput = lambda *a, **kw: "C"

        def _q(*a, **kw):
            if kw.get("content"):
                return ("SECOND DIFFERENT PAGE", None, 200)
            return True  # keeps checkDynamicContent's retry loop from firing
        self._patchQueryPage(_q)

        result = checks.checkStability()
        self.assertFalse(result)
        self.assertFalse(kb.pageStable)

    def test_unstable_string_choice_sets_conf_string(self):
        kb.originalPage = "FIRST"
        self._patchQueryPage(self._contentQuery("SECOND"))
        replies = iter(["S", "MATCHME"])
        checks.readInput = lambda *a, **kw: next(replies)
        checks.checkStability()
        self.assertEqual(conf.string, "MATCHME")


class TestCheckNullConnection(_ChecksTestBase):
    def setUp(self):
        super(TestCheckNullConnection, self).setUp()
        conf.data = None
        kb.pageCompress = False
        kb.nullConnection = None

    def test_post_data_disables_null_connection(self):
        conf.data = "a=b"
        self.assertFalse(checks.checkNullConnection())

    def test_head_content_length(self):
        def _getPage(*a, **kw):
            if kw.get("method") == HTTPMETHOD.HEAD:
                return ("", {HTTP_HEADER.CONTENT_LENGTH: "1234"}, 200)
            return ("x", {}, 200)
        self._patchGetPage(_getPage)
        self.assertTrue(checks.checkNullConnection())
        self.assertEqual(kb.nullConnection, NULLCONNECTION.HEAD)

    def test_range_content_range(self):
        def _getPage(*a, **kw):
            if kw.get("method") == HTTPMETHOD.HEAD:
                return ("", {}, 200)            # no Content-Length on HEAD
            if kw.get("auxHeaders"):
                return ("A", {HTTP_HEADER.CONTENT_RANGE: "bytes 0-0/100"}, 206)
            return ("x", {}, 200)
        self._patchGetPage(_getPage)
        self.assertTrue(checks.checkNullConnection())
        self.assertEqual(kb.nullConnection, NULLCONNECTION.RANGE)

    def test_not_supported(self):
        # nothing usable on any method -> nullConnection ends up False
        self._patchGetPage(lambda *a, **kw: ("xx", {}, 200))
        self.assertFalse(checks.checkNullConnection())
        self.assertFalse(kb.nullConnection)


class TestCheckConnection(_ChecksTestBase):
    def setUp(self):
        super(TestCheckConnection, self).setUp()
        conf.hostname = "1.2.3.4"   # dotted-quad -> no DNS resolution
        conf.string = conf.regexp = None
        conf.cj = None
        conf.ignoreCode = None
        kb.httpErrorCodes = {}
        checks.wasLastResponseHTTPError = lambda: False
        checks.wasLastResponseDBMSError = lambda: False
        td = getCurrentThreadData()
        td.lastPage = "PAGE CONTENT"
        td.lastCode = 200

    class _Headers(object):
        headers = "Server: test\r\n"

    def test_success_sets_error_is_none(self):
        self._patchQueryPage(lambda *a, **kw: ("PAGE CONTENT", self._Headers(), 200))
        self.assertTrue(checks.checkConnection())
        self.assertTrue(kb.errorIsNone)
        self.assertEqual(kb.originalPage, "PAGE CONTENT")

    def test_dbms_error_clears_error_is_none(self):
        self._patchQueryPage(lambda *a, **kw: ("oops SQL error", self._Headers(), 200))
        checks.wasLastResponseDBMSError = lambda: True
        self.assertTrue(checks.checkConnection())
        self.assertFalse(kb.errorIsNone)

    def test_string_not_in_response_still_continues(self):
        conf.string = "NEEDLE-NOT-PRESENT"
        self._patchQueryPage(lambda *a, **kw: ("haystack only", self._Headers(), 200))
        # warns but carries on (returns True)
        self.assertTrue(checks.checkConnection())


class TestCheckWaf(_ChecksTestBase):
    def setUp(self):
        super(TestCheckWaf, self).setUp()
        conf.string = conf.notString = conf.regexp = None
        conf.dummy = conf.offline = conf.skipWaf = None
        kb.originalCode = 200
        kb.originalPage = "page"
        conf.parameters = {PLACE.GET: "id=1"}
        kb.resendPostOnRedirect = False
        conf.timeout = 30
        kb.identifiedWafs = []
        conf.tamper = None
        kb.tamperFunctions = []
        checks.agent.addPayloadDelimiters = lambda v: v

    def test_skips_when_string_set(self):
        conf.string = "x"
        self.assertIsNone(checks.checkWaf())

    def test_not_detected_on_high_ratio(self):
        # queryPage()[1] is the ratio; high ratio -> not blocked
        self._patchQueryPage(lambda *a, **kw: ("ok", 0.9, 200))
        self.assertFalse(checks.checkWaf())

    def test_detected_on_low_ratio(self):
        self._patchQueryPage(lambda *a, **kw: ("blocked", 0.1, 403))
        checks.readInput = lambda *a, **kw: True   # continue + accept bypass
        import lib.utils.wafbypass as wafbypass
        orig = wafbypass.neutralizeFingerprint
        wafbypass.neutralizeFingerprint = lambda: None
        try:
            self.assertTrue(checks.checkWaf())
        finally:
            wafbypass.neutralizeFingerprint = orig


class TestCheckInternet(_ChecksTestBase):
    def test_internet_available(self):
        self._patchGetPage(lambda *a, **kw: ("ok", None, checks.CHECK_INTERNET_CODE))
        self.assertTrue(checks.checkInternet())

    def test_internet_unavailable(self):
        self._patchGetPage(lambda *a, **kw: ("captive portal", None, 500))
        self.assertFalse(checks.checkInternet())


if __name__ == "__main__":
    unittest.main(verbosity=2)
