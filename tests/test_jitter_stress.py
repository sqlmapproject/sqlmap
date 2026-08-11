#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Adversarial JITTER stress harness for time-based blind extraction.

Drives the REAL bisection() + REAL wasLastResponseDelayed() + REAL validateChar() re-validation
against a mock oracle that returns a simulated RESPONSE DURATION (base + jitter + timeSec-if-condition-
true) instead of a boolean - so the whole time-based decision stack runs under controlled network
jitter, with NO real sleeping (thousands of extractions per second, fully deterministic per seed).
The delimiter-wrapped template is what lets validateChar's per-char '!=' re-check actually fire (it is
sqlmap's main defense against a single spike faking one bit); without it the harness is far too harsh.

Two tiers:
  * TestJitterRegression   - ALWAYS runs. Low/mild jitter MUST extract perfectly, and a spike in the
                             baseline model MUST NOT hide genuine delays. Deterministic, fast, non-flaky.
  * TestJitterStressSweep  - OPT-IN (set env SQLMAP_JITTER_STRESS=1). Adversarial sweeps (Gaussian
                             sigma, heavy-tailed spikes) mapping where extraction finally degrades.
                             Informational + loose bounds only; kept out of normal CI (slow/noisy).

Run the sweep on demand:  SQLMAP_JITTER_STRESS=1 python -m unittest tests.test_jitter_stress -v
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
from lib.core.enums import ADJUST_TIME_DELAY, CHARSET_TYPE, PAYLOAD
from lib.core.settings import MIN_TIME_RESPONSES, PAYLOAD_DELIMITER, TIME_STDEV_COEFF
from lib.request.connect import Connect
import lib.techniques.blind.inference as inf

# The comparison must sit BETWEEN PAYLOAD_DELIMITERs: validateChar (inference.py) rewrites '>' to '!='
# with a regex anchored on the delimiters, and without them that per-char re-validation silently
# no-ops (defeating sqlmap's main per-request-spike defense and making this harness far too pessimistic).
_TEMPLATE = "%sEXPR=%%s IDX=%%d CMP>%%d%s" % (PAYLOAD_DELIMITER, PAYLOAD_DELIMITER)
_PARSE = re.compile(r"IDX=(\d+) CMP(!=|=|>)(\d+)")   # bisection '>'/'=' plus validateChar's '!='
_TIMESEC = 5.0
_BASE = 0.10          # base (non-delay) round-trip latency, seconds
_QUERY_COST = 2.0     # what the injected subquery itself costs (e.g. COUNT(*) over a large table)
_STRESS = os.environ.get("SQLMAP_JITTER_STRESS")


def _timeVector():
    d = AttribDict()
    d.payload = _TEMPLATE; d.where = 1; d.vector = _TEMPLATE
    d.comment = ""; d.templatePayload = None; d.matchRatio = None
    d.trueCode = None; d.falseCode = None
    return d


class _JitterBase(unittest.TestCase):
    _CONF = ("threads", "api", "verbose", "direct", "disableStats", "timeSec",
             "hexConvert", "charset", "firstChar", "lastChar")
    _KB = ("responseTimeMode", "responseTimePayload", "adjustTimeDelay", "laggingChecked", "partRun",
           "safeCharEncode", "bruteMode", "fileReadMode", "disableShiftTable", "prependFlag",
           "originalTimeDelay", "counters", "responseTimes")

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
        setTechnique(self._saved_technique)   # setTechnique() sets a thread-local; restore so it can't leak into other modules

    def _configure(self, baselineJitter, rng, nBaseline=30):
        set_dbms("MySQL")
        conf.threads = 1; conf.api = False; conf.verbose = 0; conf.direct = False
        conf.disableStats = False; conf.timeSec = _TIMESEC
        conf.hexConvert = False; conf.charset = None; conf.firstChar = None; conf.lastChar = None
        kb.responseTimeMode = None
        kb.responseTimePayload = None
        kb.adjustTimeDelay = ADJUST_TIME_DELAY.DISABLE   # never prompt / never mutate timeSec
        kb.laggingChecked = True
        kb.partRun = None; kb.safeCharEncode = False; kb.bruteMode = False
        kb.fileReadMode = False; kb.disableShiftTable = False; kb.prependFlag = False
        kb.originalTimeDelay = _TIMESEC; kb.counters = {}
        kb.injection.data = {PAYLOAD.TECHNIQUE.TIME: _timeVector()}
        setTechnique(PAYLOAD.TECHNIQUE.TIME)
        # jitter is always ADDITIVE (network delays only slow a response, never speed it below base),
        # so the baseline is right-skewed with a floor at base - like real kb.responseTimes, and with
        # no fake point-mass at 0 that a clamp (max(0.0, ..)) would create and that would skew stats
        kb.responseTimes = {None: [_BASE + abs(baselineJitter(rng)) for _ in range(nBaseline)]}
        kb.data.processChar = None

    def _extract(self, secret, jitter, rng):
        from lib.core.common import wasLastResponseDelayed

        def oracle(payload=None, timeBasedCompare=False, **kwargs):
            td = getCurrentThreadData()
            m = _PARSE.search(payload or "")
            if not m:
                td.lastQueryDuration = _BASE + abs(jitter(rng))
                return False
            idx, op, thr = int(m.group(1)), m.group(2), int(m.group(3))
            ch = ord(secret[idx - 1]) if 0 <= idx - 1 < len(secret) else 0
            cond = (ch > thr) if op == ">" else (ch != thr) if op == "!=" else (ch == thr)
            if "NOT(" in payload:
                cond = not cond
            td.lastQueryDuration = _BASE + abs(jitter(rng)) + (_TIMESEC if cond else 0.0)
            return wasLastResponseDelayed() if timeBasedCompare else cond

        Connect.queryPage = staticmethod(oracle)
        inf.Request.queryPage = staticmethod(oracle)   # Note: staticmethod on BOTH (py2 makes a bare function an unbound method)
        td = getCurrentThreadData()
        td.shared.value = ""; td.shared.index = [0]; td.shared.start = 0; td.shared.count = 0
        _, value = inf.bisection(_TEMPLATE, "SELECT secret", length=len(secret), charsetType=None)
        return value

    def _rate(self, secret, jitter, trials=40, seed0=1000):
        ok = 0
        for t in range(trials):
            rng = random.Random(seed0 + t)
            self._configure(jitter, rng)
            try:
                ok += (self._extract(secret, jitter, rng) == secret)
            except Exception:
                pass
        return ok, trials


def _gaussian(sigma):
    return lambda rng: rng.gauss(0, sigma)


def _spike(sigma, p, mag):
    def f(rng):
        v = rng.gauss(0, sigma)
        if rng.random() < p:
            v += mag
        return v
    return f


class TestJitterRegression(_JitterBase):
    """Always-on, deterministic, non-flaky: under low/mild jitter (7*sigma well below timeSec and no
    heavy tail) the time-based stack MUST reconstruct the value exactly, every seed."""

    SECRET = "Str0ng!"

    def test_no_jitter_is_perfect(self):
        ok, n = self._rate(self.SECRET, _gaussian(0.0))
        self.assertEqual(ok, n, "time-based extraction must be flawless with zero jitter (%d/%d)" % (ok, n))

    def test_mild_gaussian_is_perfect(self):
        # sigma=0.3 -> false bits at base+|N(0,0.3)| (<~1s) stay well under the threshold, << timeSec=5
        ok, n = self._rate(self.SECRET, _gaussian(0.3))
        self.assertEqual(ok, n, "mild gaussian jitter must not corrupt extraction (%d/%d)" % (ok, n))

    def test_baseline_spike_does_not_hide_a_genuine_delay(self):
        # A single latency spike captured in the response-time model must not raise the delay
        # threshold (avg + 7*stdev) so high that a real timeSec delay is missed. Deterministic.
        from lib.core.common import wasLastResponseDelayed, average, stdev
        from lib.core.settings import TIME_STDEV_COEFF

        set_dbms("MySQL")
        conf.direct = False; conf.disableStats = False; conf.timeSec = _TIMESEC
        kb.adjustTimeDelay = ADJUST_TIME_DELAY.DISABLE
        kb.responseTimeMode = None
        bulk = [0.15, 0.25] * 15                    # clean model, small non-zero stdev
        kb.responseTimes = {None: bulk + [8.0]}     # one 8s spike poisons the baseline
        td = getCurrentThreadData()
        td.lastQueryDuration = _BASE + _TIMESEC      # a genuine time-based delay (~5.1s)

        raw = kb.responseTimes[None]                 # the un-trimmed model WOULD miss it (fix is load-bearing)
        self.assertLess(td.lastQueryDuration, average(raw) + TIME_STDEV_COEFF * stdev(raw))
        self.assertTrue(wasLastResponseDelayed())    # with spike-trimming the delay is recognized


class TestTimeModelSaturation(_JitterBase):
    """Always-on: an expression whose own SQL is slower than the plain page must not saturate the
    oracle. kb.responseTimeMode is only keyed for dump pagination, so elsewhere even a FALSE probe
    lands above the threshold and the digit search runs off the top of the charset."""

    SECRET = "309586433"
    EXPRESSION = "SELECT LTRIM(STR(COUNT(*))) FROM Database.dbo.Final"   # no ORDER BY -> mode stays None

    def _costAwareOracle(self, secret, jitter, rng):
        from lib.core.common import wasLastResponseDelayed

        def oracle(payload=None, timeBasedCompare=False, **kwargs):
            td = getCurrentThreadData()

            # like connect.py: the model is built by replaying kb.responseTimePayload, and only a
            # false-payload replay carries the subquery cost (the bare original request does not)
            if timeBasedCompare and not conf.disableStats:
                if len(kb.responseTimes.get(kb.responseTimeMode, [])) < MIN_TIME_RESPONSES:
                    cost = _QUERY_COST if kb.responseTimePayload else 0.0
                    kb.responseTimes.setdefault(kb.responseTimeMode, [])
                    while len(kb.responseTimes[kb.responseTimeMode]) < MIN_TIME_RESPONSES:
                        kb.responseTimes[kb.responseTimeMode].append(_BASE + cost + abs(jitter(rng)))

            m = _PARSE.search(payload or "")
            if not m:
                td.lastQueryDuration = _BASE + abs(jitter(rng))
                return False

            idx, op, thr = int(m.group(1)), m.group(2), int(m.group(3))
            ch = ord(secret[idx - 1]) if 0 <= idx - 1 < len(secret) else 0
            cond = (ch > thr) if op == ">" else (ch != thr) if op == "!=" else (ch == thr)
            if "NOT(" in payload:
                cond = not cond

            # every probe pays the subquery cost, the injected sleep only when the condition holds
            td.lastQueryDuration = _BASE + _QUERY_COST + abs(jitter(rng)) + (_TIMESEC if cond else 0.0)
            return wasLastResponseDelayed() if timeBasedCompare else cond

        return oracle

    def test_saturated_model_is_recalibrated(self):
        from lib.core.common import average, stdev

        rng = random.Random(1234)
        jitter = _gaussian(0.05)          # small but non-zero, so the stdev branch is the one used
        self._configure(jitter, rng)
        kb.responseTimes = {}             # let the oracle calibrate, the way connect.py does

        oracle = self._costAwareOracle(self.SECRET, jitter, rng)
        Connect.queryPage = staticmethod(oracle)
        inf.Request.queryPage = staticmethod(oracle)

        td = getCurrentThreadData()
        td.shared.value = ""; td.shared.index = [0]; td.shared.start = 0; td.shared.count = 0
        _, value = inf.bisection(_TEMPLATE, self.EXPRESSION, length=len(self.SECRET), charsetType=CHARSET_TYPE.DIGITS)

        cheap = kb.responseTimes[None]               # against the bare-page model even a FALSE probe reads delayed
        self.assertGreater(_BASE + _QUERY_COST, average(cheap) + TIME_STDEV_COEFF * stdev(cheap))

        self.assertEqual(kb.responseTimeMode, self.EXPRESSION)   # the walk-off re-keyed the model
        self.assertEqual(value, self.SECRET)


@unittest.skipUnless(_STRESS, "adversarial jitter sweep is opt-in (set SQLMAP_JITTER_STRESS=1)")
class TestJitterStressSweep(_JitterBase):
    """Opt-in failure-surface map. Prints correctness vs jitter and asserts only loose, non-flaky
    invariants (clean case perfect). Use to evaluate hardening changes."""

    SECRET = "Str0ng!"

    def test_gaussian_sweep(self):
        # Continuous jitter: degrades only once sigma approaches timeSec/7 (7*stdev threshold nears the
        # real delay). That is the FUNDAMENTAL limit of the statistic - the answer there is a larger
        # timeSec (--time-sec), not a code change; shown here so a regression that degrades it earlier is visible.
        print("\n[jitter] Gaussian sigma sweep (timeSec=%.0f, base=%.2f):" % (_TIMESEC, _BASE))
        for sigma in (0.0, 0.3, 0.5, 0.7, 0.9, 1.2):
            ok, n = self._rate(self.SECRET, _gaussian(sigma))
            print("  sigma=%.2fs -> %d/%d (%3.0f%%)" % (sigma, ok, n, 100.0 * ok / n))
            if sigma == 0.0:
                self.assertEqual(ok, n)

    def test_heavy_tailed_spike_sweep(self):
        # One-off +8s spikes: baseline-trim (stripTimeOutliers) keeps the model clean and validateChar's
        # '!=' re-check catches a spike that fakes a single bit, so extraction stays ~perfect until an
        # absurd spike rate (a fifth of all requests). This is the payoff of both defenses together.
        print("\n[jitter] Heavy-tailed spike sweep (base sigma=0.2, spike=+8s):")
        for p in (0.0, 0.01, 0.03, 0.05, 0.10, 0.20):
            ok, n = self._rate(self.SECRET, _spike(0.2, p, 8.0))
            print("  spike_p=%.2f -> %d/%d (%3.0f%%)" % (p, ok, n, 100.0 * ok / n))
            if p == 0.0:
                self.assertEqual(ok, n)


if __name__ == "__main__":
    unittest.main(verbosity=2)


def tearDownModule():
    reset_dbms()
