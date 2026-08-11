#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Adversarial "shitty response" JITTER harness for BOOLEAN-based blind extraction.

Boolean-blind decides each bit through the REAL comparison() oracle (--string / --not-string /
--regexp / --code / page-ratio). In the wild a target throws transient junk between good responses -
gateway 5xx, WAF/rate-limit pages, a Cloudflare "just a moment" interstitial, a captcha, a
maintenance banner, a truncated or empty body, an A/B variant, even a page that COINCIDENTALLY
contains the --string token (a direction-flipping false positive). This drives the REAL bisection() +
REAL comparison() + REAL validateChar() re-validation against a mock oracle that injects that catalog
(IID or in bursts) at controllable rates, with NO network, fully deterministic per seed.

The template is PAYLOAD_DELIMITER-wrapped so validateChar's per-char '!=' re-check actually fires
(the same fidelity trap the time-based harness hit), and the mock sets threadData.lastCode so the
unexpectedCode -> validateChar defense engages exactly as in a live run.

Two tiers (mirrors tests/test_jitter_stress.py):
  * TestBooleanJitterRegression - ALWAYS runs. Deterministic, non-flaky guards: clean extraction is
                                  perfect, benign dynamic content never corrupts, and a transient
                                  unexpected-code response landing on a validation request is ridden out.
  * TestBooleanJitterSweep      - OPT-IN (SQLMAP_JITTER_STRESS=1). The creative failure-surface sweep
                                  (IID + bursty), informational + loose bounds, kept out of normal CI.
"""

import os
import random
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms, reset_dbms
bootstrap()

from lib.core.data import conf, kb
from lib.core.common import getCurrentThreadData, setTechnique
from lib.core.datatype import AttribDict
from lib.core.enums import HTTP_HEADER, PAYLOAD
from lib.core.settings import PAYLOAD_DELIMITER
from lib.request.comparison import comparison
from lib.request.connect import Connect
import lib.techniques.blind.inference as inf

_D = PAYLOAD_DELIMITER
_TEMPLATE = "%sEXPR=%%s IDX=%%d CMP>%%d%s" % (_D, _D)   # delimiter-wrapped -> validateChar '!=' fires
_PARSE = re.compile(r"IDX=(\d+) CMP(!=|=|>)(\d+)")
_SECRET = "Str0ng!"
_STRING = "luther"
# realistic-size bodies (shared nav/footer boilerplate) so the "resembles neither model" anomaly guard
# behaves as on a real page: benign dynamic noise is proportionally tiny (stays a match), while a junk
# interstitial/maintenance/empty body clearly matches neither
_BOILER = "<html><head><title>Acme Portal</title></head><body><nav>home about contact help terms privacy account</nav><div class=main>" * 8
_FOOT = "</div><footer>(c) Acme Corp - all rights reserved - support@acme.example - v4.2</footer></body></html>" * 8
_TRUE_BODY = _BOILER + "welcome %s, dashboard: orders profile settings billing (12 items)" % _STRING + _FOOT
_FALSE_BODY = _BOILER + "invalid credentials, no such record found, please retry" + _FOOT
_INTERSTITIAL = "<html><body>Just a moment... checking your browser before access (DDoS protection)</body></html>"
_STRESS = os.environ.get("SQLMAP_JITTER_STRESS")


class _Headers(object):
    def __init__(self, ct="text/html"):
        self.headers = ["Content-Type: %s\r\n" % ct]
        self._d = {HTTP_HEADER.CONTENT_TYPE: ct}

    def get(self, key, default=None):
        return self._d.get(key, default)


# ---- creative jitter catalog: each maps the clean intended body -> a transient junk response --------
def _gw502(intended, rng):      return "<html><h1>502 Bad Gateway</h1></html>", 502, "text/html"
def _gw504(intended, rng):      return "<html><h1>504 Gateway Time-out</h1></html>", 504, "text/html"
def _rate429(intended, rng):    return "{\"error\":\"rate limited\"}", 429, "application/json"
def _waf403(intended, rng):     return "<html>Request blocked by security policy #%d</html>" % rng.randint(1, 9), 403, "text/html"
def _cf(intended, rng):         return "<html><title>Just a moment...</title>Checking your browser (Cloudflare)</html>", 200, "text/html"
def _captcha(intended, rng):    return "<html>Please complete the CAPTCHA to continue</html>", 200, "text/html"
def _maintenance(intended, rng):return "<html>We'll be back shortly - scheduled maintenance</html>", 200, "text/html"
def _empty(intended, rng):      return "", 200, "text/html"
def _truncated(intended, rng):  return intended[:rng.randint(10, 30)], 200, "text/html"
def _lang(intended, rng):       return "<html><body>bienvenue, voici votre tableau de bord</body></html>", 200, "text/html"
def _dynamic(intended, rng):    return intended.replace("</body>", "<span id=csrf>%d</span><span>%d views</span></body>" % (rng.getrandbits(32), rng.randint(1, 999))), 200, "text/html"
def _coincidence(intended, rng):return "<html><body>system message from %s: degraded, retry later</body></html>" % _STRING, 200, "text/html"

_CODE_CHANGING = (_gw502, _gw504, _rate429, _waf403)
_SAME_CODE = (_cf, _captcha, _maintenance, _empty, _truncated, _lang)


def _vector():
    d = AttribDict()
    d.payload = _TEMPLATE; d.where = 1; d.vector = _TEMPLATE; d.comment = ""
    d.templatePayload = None; d.matchRatio = None; d.trueCode = 200; d.falseCode = 200
    return d


class _BooleanJitterBase(unittest.TestCase):
    _CONF = ("threads", "api", "verbose", "direct", "string", "notString", "regexp", "code", "lengths",
             "titles", "textOnly", "hexConvert", "charset", "firstChar", "lastChar",
             "ignoreCode", "ignoreTimeouts")
    _KB = ("negativeLogic", "nullConnection", "errorIsNone", "pageTemplate", "matchRatio", "heavilyDynamic",
           "pageStructurallyStable", "skipSeqMatcher", "pageEncoding", "partRun", "safeCharEncode",
           "bruteMode", "fileReadMode", "disableShiftTable", "prependFlag", "timeless", "counters",
           "originalCode", "originalPage", "trueTemplate", "falseTemplate", "dynamicMarkings")

    def setUp(self):
        self._saved_conf = {k: conf.get(k) for k in self._CONF}
        self._saved_kb = {k: kb.get(k) for k in self._KB}
        self._saved_inj = kb.injection.data
        self._saved_qp = Connect.queryPage
        self._saved_technique = getCurrentThreadData().technique

    def tearDown(self):
        for k, v in self._saved_conf.items():
            conf[k] = v
        for k, v in self._saved_kb.items():
            kb[k] = v
        kb.injection.data = self._saved_inj
        Connect.queryPage = self._saved_qp
        inf.Request.queryPage = self._saved_qp
        setTechnique(self._saved_technique)

    def _configure(self):
        set_dbms("MySQL")
        conf.threads = 1; conf.api = False; conf.verbose = 0; conf.direct = False
        conf.string = _STRING; conf.notString = None; conf.regexp = None; conf.code = None
        conf.lengths = None; conf.titles = None; conf.textOnly = None
        conf.hexConvert = False; conf.charset = None; conf.firstChar = None; conf.lastChar = None
        conf.ignoreCode = []; conf.ignoreTimeouts = False
        kb.negativeLogic = False; kb.nullConnection = False; kb.errorIsNone = True
        kb.pageTemplate = _FALSE_BODY; kb.matchRatio = None; kb.heavilyDynamic = False
        kb.pageStructurallyStable = False; kb.skipSeqMatcher = False; kb.pageEncoding = None
        kb.partRun = None; kb.safeCharEncode = False; kb.bruteMode = False; kb.fileReadMode = False
        kb.disableShiftTable = False; kb.prependFlag = False; kb.timeless = None; kb.counters = {}
        kb.originalCode = None; kb.originalPage = None
        # calibrated reference bodies for the same-code anomaly guard (Fix B); no learned dynamic markings
        kb.trueTemplate = _TRUE_BODY; kb.falseTemplate = _FALSE_BODY; kb.dynamicMarkings = []
        kb.injection.data = {PAYLOAD.TECHNIQUE.BOOLEAN: _vector()}
        setTechnique(PAYLOAD.TECHNIQUE.BOOLEAN)
        kb.data.processChar = None
        getCurrentThreadData().validationRun = 0

    def _extract(self, respond):
        """`respond(payload, cond, rng)` returns (body, code, contentType); drives real bisection ->
        real comparison(). Bit truth `cond` is derived from the parseable delimiter-wrapped payload."""
        def oracle(payload=None, timeBasedCompare=False, **kwargs):
            td = getCurrentThreadData()
            m = _PARSE.search(payload or "")
            if not m:
                td.lastPage = _FALSE_BODY; td.lastCode = 200
                return comparison(_FALSE_BODY, _Headers(), 200)
            idx, op, thr = int(m.group(1)), m.group(2), int(m.group(3))
            ch = ord(_SECRET[idx - 1]) if 0 <= idx - 1 < len(_SECRET) else 0
            cond = (ch > thr) if op == ">" else (ch != thr) if op == "!=" else (ch == thr)
            if "NOT(" in (payload or ""):
                cond = not cond
            body, code, ct = respond(payload or "", cond)
            td.lastPage = body; td.lastCode = code
            return comparison(body, _Headers(ct), code)

        Connect.queryPage = staticmethod(oracle)
        inf.Request.queryPage = staticmethod(oracle)   # staticmethod on BOTH (py2 unbound-method guard)
        td = getCurrentThreadData()
        td.shared.value = ""; td.shared.index = [0]; td.shared.start = 0; td.shared.count = 0
        _, value = inf.bisection(_TEMPLATE, "SELECT secret", length=len(_SECRET), charsetType=None)
        return value

    def _rate(self, arrival, trials=40, seed0=3000):
        ok = 0
        for t in range(trials):
            rng = random.Random(seed0 + t)

            def respond(payload, cond, rng=rng):
                intended = _TRUE_BODY if cond else _FALSE_BODY
                jitter = arrival(rng)
                return jitter(intended, rng) if jitter is not None else (intended, 200, "text/html")

            self._configure()
            try:
                ok += (self._extract(respond) == _SECRET)
            except Exception:
                pass
        return ok, trials


def _iid(p, kinds):
    ks = list(kinds)
    return lambda rng: rng.choice(ks) if rng.random() < p else None


def _burst(p_enter, mean_len, kinds):
    ks = list(kinds); state = {"bad": 0}

    def f(rng):
        if state["bad"] > 0:
            state["bad"] -= 1; return rng.choice(ks)
        if rng.random() < p_enter:
            state["bad"] = max(0, int(rng.expovariate(1.0 / mean_len))) - 1
            return rng.choice(ks)
        return None
    return f


class TestBooleanJitterRegression(_BooleanJitterBase):
    """Always-on, deterministic, non-flaky guards for the boolean decision stack."""

    def test_clean_extraction_is_perfect(self):
        ok, n = self._rate(lambda rng: None)
        self.assertEqual(ok, n, "clean boolean extraction must be flawless (%d/%d)" % (ok, n))

    def test_benign_dynamic_content_does_not_corrupt(self):
        # csrf tokens / view counters / timestamps churn every response body; with the --string oracle
        # they must never flip a bit. A regression that starts trusting raw-body noise fails here.
        ok, n = self._rate(_iid(1.0, (_dynamic,)))
        self.assertEqual(ok, n, "benign dynamic content must not corrupt extraction (%d/%d)" % (ok, n))

    def test_unexpected_code_during_validation_is_ridden_out(self):
        # Fix A guard: a transient unexpected-code response (503) landing on validateChar's own
        # re-check request must not confirm a bit - the char is re-extracted. Here EVERY validation
        # ('!=') request returns 503 once, deterministically; extraction must still be exact.
        fired = {"n": 0}

        def respond(payload, cond):
            if "!=" in payload and fired["n"] < 3:      # poison the first few validation re-checks
                fired["n"] += 1
                return "<html><h1>503 Service Unavailable</h1></html>", 503, "text/html"
            body = _TRUE_BODY if cond else _FALSE_BODY
            return body, 200, "text/html"

        self._configure()
        self.assertEqual(self._extract(respond), _SECRET)

    def test_anomaly_classifier_flags_only_junk(self):
        # Fix B core: a response resembling NEITHER calibrated model is flagged; the models themselves
        # and a benign dynamic variant are not. Deterministic, no network.
        self._configure()
        self.assertFalse(inf._resemblesNeitherModel(_TRUE_BODY))
        self.assertFalse(inf._resemblesNeitherModel(_FALSE_BODY))
        self.assertFalse(inf._resemblesNeitherModel(_TRUE_BODY.replace("dashboard", "dashboard <b>7 new</b> tok=abc123")))
        for junk in (_INTERSTITIAL, "", "<html><h1>502 Bad Gateway</h1></html>", _TRUE_BODY[:60]):
            self.assertTrue(inf._resemblesNeitherModel(junk), msg="must flag junk %r" % junk[:40])

    def test_same_code_body_jitter_is_ridden_out(self):
        # Fix B guard: a transient same-HTTP-code junk page that resembles NEITHER model makes a
        # character mis-resolve to a wrong (valid) value; the anomaly guard triggers validateChar to
        # re-extract it. The junk here carries the --string token (so it reads True and pushes the char
        # HIGH -> a wrong valid char, the case validateChar covers), and is unlike both models -> flagged.
        junk = "<html><body>notice: %s service temporarily degraded, retry</body></html>" % _STRING
        poisoned = {"n": 0}

        def respond(payload, cond):
            m = _PARSE.search(payload)
            idx = int(m.group(1)) if m else 0
            if idx == 4 and "!=" not in payload and poisoned["n"] < 3:
                poisoned["n"] += 1
                return junk, 200, "text/html"
            return (_TRUE_BODY if cond else _FALSE_BODY), 200, "text/html"

        self._configure()
        self.assertTrue(inf._resemblesNeitherModel(junk))   # precondition: the junk IS anomalous
        self.assertEqual(self._extract(respond), _SECRET)


@unittest.skipUnless(_STRESS, "creative boolean-jitter sweep is opt-in (set SQLMAP_JITTER_STRESS=1)")
class TestBooleanJitterSweep(_BooleanJitterBase):
    """Opt-in creative failure-surface map (IID + bursty). Informational; asserts only the clean case."""

    def _sweep(self, label, factory, kinds, rates=(0.0, 0.02, 0.05, 0.10, 0.20)):
        print("\n[bool-jitter] %s:" % label)
        for r in rates:
            ok, n = self._rate(factory(r, kinds))
            print("  rate=%.2f -> %d/%d (%3.0f%%)" % (r, ok, n, 100.0 * ok / n))
            if r == 0.0:
                self.assertEqual(ok, n)

    def test_iid_code_changing(self):
        self._sweep("IID code-changing (502/504/429/403)", _iid, _CODE_CHANGING)

    def test_iid_same_code_body(self):
        self._sweep("IID same-code 200 body (cf/captcha/maint/empty/trunc/lang)", _iid, _SAME_CODE)

    def test_iid_string_coincidence(self):
        self._sweep("IID string-coincidence (fake page contains --string)", _iid, (_coincidence,))

    def test_burst_same_code_body(self):
        self._sweep("BURST(mean=4) same-code 200 body", lambda r, k: _burst(r, 4, k), _SAME_CODE)


if __name__ == "__main__":
    unittest.main(verbosity=2)


def tearDownModule():
    reset_dbms()
