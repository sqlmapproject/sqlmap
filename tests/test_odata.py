#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Offline, deterministic tests for the OData '$filter' injection engine. A mock oracle mirrors the
boolean-blind semantics of a real OData service (a broken-out filter reduced to its injected predicate),
so detection, OData-only confirmation, version fingerprinting and per-entity blind extraction are
exercised without a live OData endpoint.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import lib.techniques.odata.inject as odata
from lib.core.settings import ODATA_CHARSET_BLOCK
from lib.core.settings import ODATA_ERROR_REGEX

_ENTITIES = (
    {"Id": 1, "Name": "luther", "Secret": "S3CR3Tvalue"},
    {"Id": 2, "Name": "fluffy", "Secret": "hunter2"},
    {"Id": 3, "Name": "wu", "Secret": "letmein"},
)
_FIELDS = ("Id", "Name", "Secret")


def _wrapped(expr):
    if not (expr.startswith("(") and expr.endswith(")")):
        return False
    depth = 0
    for i, ch in enumerate(expr):
        depth += (ch == "(") - (ch == ")")
        if depth == 0 and i < len(expr) - 1:
            return False
    return True


def _split(expr, sep):
    parts, buf = [], []
    for token in expr.split(sep):
        buf.append(token)
        chunk = sep.join(buf)
        if chunk.count("(") == chunk.count(")"):
            parts.append(chunk)
            buf = []
    if buf:
        parts.append(sep.join(buf))
    return parts


class _ODErr(Exception):
    pass


def _atom(e, a):
    a = a.strip()
    while _wrapped(a):
        a = a[1:-1].strip()
    m = re.match(r"^length\('([^']*)'\) eq (\d+)$", a)
    if m:
        return len(m.group(1)) == int(m.group(2))
    m = re.match(r"^startswith\('([^']*)','([^']*)'\)$", a)
    if m:
        return m.group(1).startswith(m.group(2))
    m = re.match(r"^contains\('([^']*)','([^']*)'\)$", a)
    if m:
        return m.group(2) in m.group(1)
    if a.startswith("substringof("):
        raise _ODErr("v4 has no substringof")
    m = re.match(r"^'([^']*)' eq '([^']*)'$", a)
    if m:
        return m.group(1) == m.group(2)
    m = re.match(r"^(\d+) eq (\d+)$", a)
    if m:
        return m.group(1) == m.group(2)
    m = re.match(r"^(\w+) eq '([^']*)'$", a)
    if m:
        if m.group(1) not in _FIELDS:
            raise _ODErr("unknown property")
        return "%s" % e.get(m.group(1)) == m.group(2)
    m = re.match(r"^(\w+) ne null$", a)
    if m:
        if m.group(1) not in _FIELDS:
            raise _ODErr("unknown property")
        return e.get(m.group(1)) is not None
    m = re.match(r"^(\w+) (eq|ge|gt|le|lt) (-?\d+)$", a)
    if m:
        p, op, num = m.group(1), m.group(2), int(m.group(3))
        if p not in _FIELDS:
            raise _ODErr("unknown property")
        v = e.get(p)
        if not isinstance(v, int):
            return False
        return {"eq": v == num, "ge": v >= num, "gt": v > num, "le": v <= num, "lt": v < num}[op]
    m = re.match(r"^length\((\w+)\) (eq|ge) (\d+)$", a)
    if m:
        p, op, num = m.group(1), m.group(2), int(m.group(3))
        if p not in _FIELDS:
            raise _ODErr("unknown property")
        n = len("%s" % e.get(p, ""))
        return n == num if op == "eq" else n >= num
    # an inner single quote arrives DOUBLED, the way the OData spec escapes it
    m = re.match(r"^substring\((\w+),(\d+),1\) eq '(''|.)'$", a)
    if m:
        p, pos, ch = m.group(1), int(m.group(2)), m.group(3)
        ch = "'" if ch == "''" else ch
        if p not in _FIELDS:
            raise _ODErr("unknown property")
        t = "%s" % e.get(p, "")
        return pos < len(t) and t[pos] == ch
    raise _ODErr("syntax error")


def _eval(e, expr):
    expr = expr.strip()
    while _wrapped(expr):
        expr = expr[1:-1].strip()
    ors = _split(expr, " or ")
    if len(ors) > 1:
        return any(_eval(e, o) for o in ors)
    ands = _split(expr, " and ")
    if len(ands) > 1:
        return all(_eval(e, a) for a in ands)
    return _atom(e, expr)


_EMPTY = "<html><body><ul></ul></body></html>"


def _render(matched):
    return "<html><body><ul>%s</ul></body></html>" % "".join("<li>%s: %s</li>" % (e["Id"], e["Name"]) for e in matched)


def _mockSend(place, parameter, value, raw=False):
    expr = "Name eq '%s'" % value
    if expr.count("'") % 2:
        return "<pre>The query specified in the URI is not valid. There is an unterminated string literal at position 8</pre>" if raw else None
    try:
        matched = [e for e in _ENTITIES if _eval(e, expr)]
    except _ODErr:
        return "<pre>Could not find a property named 'x' on type 'Default.Product'. Microsoft.OData</pre>" if raw else None
    return _render(matched)


class TestHelpers(unittest.TestCase):
    def test_is_error_and_backend(self):
        self.assertTrue(odata._isError("The query specified in the URI is not valid. Microsoft.OData"))
        self.assertFalse(odata._isError(_EMPTY))
        self.assertEqual(odata._backendFromError("Could not find a property named 'X'"), "Microsoft OData (WebAPI/.NET)")

    def test_error_regex_matches_real(self):
        self.assertIsNotNone(re.search(ODATA_ERROR_REGEX, "There is an unterminated string literal at position 17 in 'Name eq'"))


class TestNoAmpersandInvariant(unittest.TestCase):
    """A raw '&' in a GET value is the parameter delimiter; OData uses the 'or'/'and' keywords, so no
    payload may carry one."""

    def test_boundaries_and_predicates_have_no_ampersand(self):
        for row in odata._BOUNDARY_TABLE:
            for field in row:
                self.assertNotIn("&", field)
        for t, f in odata._ODATA_PREDICATES:
            self.assertNotIn("&", t)
            self.assertNotIn("&", f)

    def test_send_url_encodes_the_payload(self):
        """The boundaries being '&'-free was never enough: the character scan emits '&' (and '+') as
        DATA. _send() must URL-encode, or those probes split the request, the truncated $filter 400s,
        and the resulting InconclusiveError aborts the WHOLE property (it dumped as '?')."""
        sent = []
        savedParams, odata.conf.parameters = odata.conf.parameters, {odata.PLACE.GET: "name=luther"}
        savedGet = odata.Request.getPage
        odata.Request.getPage = staticmethod(
            lambda **kwargs: (sent.append(odata.conf.parameters[odata.PLACE.GET]), "", None, 200)[1:])
        try:
            odata._send(odata.PLACE.GET, "name", odata._literal(ord("&")))
        finally:
            odata.Request.getPage = savedGet
            odata.conf.parameters = savedParams
        self.assertEqual(len(sent), 1)
        self.assertNotIn("&", sent[0].split("=", 1)[1], sent[0])
        self.assertIn("%26", sent[0])


class TestCharsetCoverage(unittest.TestCase):
    """The scan is EXACT equality, not a bisection, so the ORDER is free but the COVERAGE is not: an
    excluded codepoint is simply never recoverable. The one character an OData literal cannot carry
    raw, the single quote, is doubled per the spec rather than dropped.

    (This replaces an earlier assertion pinning 0x27/0x5c as EXCLUDED, which cost coverage of two
    characters common in real names and paths for no correctness gain.)"""

    def test_charset_covers_every_printable(self):
        self.assertEqual(sorted(odata._CS_ORDS),
                         list(range(odata.ODATA_CHAR_MIN, odata.ODATA_CHAR_MAX + 1)))

    def test_quote_is_doubled(self):
        self.assertEqual(odata._literal(0x27), "''''")
        self.assertEqual(odata._literal(0x5c), "'\\'")
        self.assertEqual(odata._literal(ord("a")), "'a'")


def _mockSendV23(place, parameter, value, raw=False):
    """A v2/v3 service: contains() is an unknown function (400), substringof() is the one that parses."""
    if "contains(" in value:
        return "<pre>Syntax error at position 0. Microsoft.OData</pre>" if raw else None
    return _mockSend(place, parameter, value.replace("substringof('sql','sqlmap')", "1 eq 1"), raw)


def _mockSendQuiet(place, parameter, value, raw=False):
    """An endpoint that SWALLOWS the service's 400: same boolean oracle, no error surface at all - a
    failed $filter is rendered as the ordinary empty result page, error body and status included."""
    expr = "Name eq '%s'" % value
    if expr.count("'") % 2:
        return _EMPTY
    try:
        return _render([e for e in _ENTITIES if _eval(e, expr)])
    except _ODErr:
        return _EMPTY


class TestVersionFingerprintDoesNotCrash(unittest.TestCase):
    """Both version probes are EXPECTED to fail on the dialect that does not own them. An unknown
    $filter function is a 400 the oracle can only call inconclusive, and that must read as a negative
    answer - not as an exception that aborts the scan before the finding is even reported, on exactly
    the v2/v3 services the second branch exists to name."""

    def setUp(self):
        self.saved, self.savedParams = odata._send, odata.conf.parameters
        odata.conf.parameters = {odata.PLACE.GET: "name=luther"}
        odata.SENTINEL = "zzsentinelzz"

    def tearDown(self):
        odata._send, odata.conf.parameters = self.saved, self.savedParams

    def test_v23_service_is_named_not_fatal(self):
        odata._send = _mockSendV23
        _t, _p, boundary = odata._detectBoolean(odata.PLACE.GET, "name")
        oracle = odata._makeOracle(odata.PLACE.GET, "name", boundary)
        self.assertIsNotNone(oracle)
        self.assertEqual(odata._fingerprintVersion(oracle), "v2/v3")

    def test_service_speaking_neither_returns_none(self):
        odata._send = lambda place, parameter, value, raw=False: _mockSend(
            place, parameter, value.replace("contains('sqlmap','sql')", "unknownfn()"), raw)
        _t, _p, boundary = odata._detectBoolean(odata.PLACE.GET, "name")
        oracle = odata._makeOracle(odata.PLACE.GET, "name", boundary)
        self.assertIsNone(odata._fingerprintVersion(oracle))


class TestErrorSurfaceGate(unittest.TestCase):
    """_fieldExists() is an error/no-error split, so on an endpoint that swallows the service's 400 it
    answers 'exists' for EVERY name - which reported all 37 candidate properties as reachable and
    dumped a wall of empty columns. _hasErrorSurface() tells the two apart in one request."""

    def setUp(self):
        self.saved, self.savedParams = odata._send, odata.conf.parameters
        odata.conf.parameters = {odata.PLACE.GET: "name=luther"}
        odata.SENTINEL = "zzsentinelzz"

    def tearDown(self):
        odata._send, odata.conf.parameters = self.saved, self.savedParams

    def _boundary(self):
        return odata._detectBoolean(odata.PLACE.GET, "name")[2]

    def test_error_surface_present(self):
        odata._send = _mockSend
        boundary = self._boundary()
        self.assertTrue(odata._hasErrorSurface(odata.PLACE.GET, "name", boundary))

    def test_error_surface_absent(self):
        odata._send = _mockSendQuiet
        boundary = self._boundary()
        self.assertFalse(odata._hasErrorSurface(odata.PLACE.GET, "name", boundary))
        # the error-based check is useless here - every unknown name looks real
        self.assertTrue(odata._fieldExists(odata.PLACE.GET, "name", boundary, "TotallyMadeUp"))
        # ...so existence falls through to the boolean oracle, which still separates them. The dump
        # must keep working on a blind target, not be surrendered because one probe went blind.
        oracle = odata._makeOracle(odata.PLACE.GET, "name", boundary, truePredicate="(Id eq 1)")
        self.assertIsNotNone(oracle)
        self.assertTrue(odata._fieldExistsBlind(oracle, "Id", 1, "Secret"))
        self.assertFalse(odata._fieldExistsBlind(oracle, "Id", 1, "TotallyMadeUp"))


class TestDetectionAndExtraction(unittest.TestCase):
    def setUp(self):
        self.saved = odata._send
        odata._send = _mockSend
        self.savedParams = odata.conf.parameters
        odata.conf.parameters = {odata.PLACE.GET: "name=luther"}
        odata.SENTINEL = "zzsentinelzz"

    def tearDown(self):
        odata._send = self.saved
        odata.conf.parameters = self.savedParams

    def test_boolean_detection(self):
        template, payload, boundary = odata._detectBoolean(odata.PLACE.GET, "name")
        self.assertIsNotNone(template)

    def test_confirms_odata(self):
        _t, _p, boundary = odata._detectBoolean(odata.PLACE.GET, "name")
        self.assertTrue(odata._confirmOData(odata.PLACE.GET, "name", boundary))

    def test_version_fingerprint_v4(self):
        _t, _p, boundary = odata._detectBoolean(odata.PLACE.GET, "name")
        oracle = odata._makeOracle(odata.PLACE.GET, "name", boundary)
        self.assertEqual(odata._fingerprintVersion(oracle), "v4")

    def test_field_existence(self):
        _t, _p, boundary = odata._detectBoolean(odata.PLACE.GET, "name")
        self.assertTrue(odata._fieldExists(odata.PLACE.GET, "name", boundary, "Secret"))
        self.assertFalse(odata._fieldExists(odata.PLACE.GET, "name", boundary, "Nope"))

    def test_key_and_entities(self):
        _t, _p, boundary = odata._detectBoolean(odata.PLACE.GET, "name")
        key, keys = odata._findKeyAndEntities(odata.PLACE.GET, "name", boundary, _EMPTY)
        self.assertEqual(key, "Id")
        self.assertEqual(keys, [1, 2, 3])

    def test_blind_field_extraction_reaches_secret(self):
        _t, _p, boundary = odata._detectBoolean(odata.PLACE.GET, "name")
        oracle = odata._makeOracle(odata.PLACE.GET, "name", boundary, truePredicate="(Id eq 1)")
        self.assertIsNotNone(oracle)
        self.assertEqual(odata._inferField(oracle, "Id", 1, "Name"), "luther")
        self.assertEqual(odata._inferField(oracle, "Id", 1, "Secret"), "S3CR3Tvalue")

    def test_plain_sql_endpoint_not_confirmed(self):
        odata._send = lambda place, parameter, value, raw=False: _render(_ENTITIES)  # always same
        template, _p, _b = odata._detectBoolean(odata.PLACE.GET, "name")
        self.assertIsNone(template)


class TestCapsAreDisclosed(unittest.TestCase):
    """Every bound here is a bisection bound, so a result sitting ON it is a FLOOR, not a measurement.
    Handing back a capped prefix (or a capped entity list) with no word said reads exactly like a
    complete answer - the one failure mode a blind dumper must never have."""

    def setUp(self):
        self.saved, self.savedParams = odata._send, odata.conf.parameters
        odata._send = _mockSend
        odata.conf.parameters = {odata.PLACE.GET: "name=luther"}
        odata.SENTINEL = "zzsentinelzz"
        self.savedWarning, self.warnings = odata.logger.warning, []
        odata.logger.warning = lambda message, *args: self.warnings.append(message % args if args else message)

    def tearDown(self):
        odata._send, odata.conf.parameters = self.saved, self.savedParams
        odata.logger.warning = self.savedWarning

    def _oracle(self):
        _t, _p, boundary = odata._detectBoolean(odata.PLACE.GET, "name")
        oracle = odata._makeOracle(odata.PLACE.GET, "name", boundary, truePredicate="(Id eq 1)")
        self.assertIsNotNone(oracle)
        return oracle

    def test_truncated_value_is_reported(self):
        value = odata._inferField(self._oracle(), "Id", 1, "Secret", maxLen=4)
        self.assertEqual(value, "S3CR")
        self.assertTrue(any("at least 4 characters" in _ for _ in self.warnings), self.warnings)

    def test_value_that_fits_is_silent(self):
        value = odata._inferField(self._oracle(), "Id", 1, "Name", maxLen=64)
        self.assertEqual(value, "luther")
        self.assertEqual(self.warnings, [])

    def test_entity_cap_is_reported(self):
        savedCap, odata.ODATA_MAX_RECORDS = odata.ODATA_MAX_RECORDS, 2
        try:
            _t, _p, boundary = odata._detectBoolean(odata.PLACE.GET, "name")
            key, keys = odata._findKeyAndEntities(odata.PLACE.GET, "name", boundary, _EMPTY)
        finally:
            odata.ODATA_MAX_RECORDS = savedCap

        self.assertEqual(key, "Id")
        self.assertEqual(keys, [1, 2])          # the third entity exists but is beyond the cap...
        self.assertTrue(any("2-entity cap" in _ for _ in self.warnings), self.warnings)


_LITERAL = r"'(?:[^']|'')*'"
_IN_REGEX = re.compile(r"(?P<lhs>substring\(\w+,\d+,1\)|%s) in \((?P<items>%s(?:,%s)*)\)"
                       % (_LITERAL, _LITERAL, _LITERAL))


def _expandIn(expr):
    """Rewrite a v4.01 "X in (a,b,c)" into the equivalent v4.0 disjunction - all the mock parser needs
    in order to model a service that offers the operator, without teaching _atom() a second syntax."""

    def expand(match):
        lhs = match.group("lhs")
        return "(%s)" % " or ".join("%s eq %s" % (lhs, _) for _ in re.findall(_LITERAL, match.group("items")))

    return _IN_REGEX.sub(expand, expr)


def _mockSendIn(place, parameter, value, raw=False):
    """A v4.01 service: identical semantics, but it also parses the 'in' operator."""
    return _mockSend(place, parameter, _expandIn(value), raw)


class TestSetMembershipRecovery(unittest.TestCase):
    """Character recovery asks about a whole candidate SET per request. .NET string comparison is
    culture-aware and case-folding, so a lexicographic bisection is unusable - but set membership needs
    no ordering and halves the space just the same. This pins the cost: the linear scan this replaced
    spent one request per candidate, up to the whole charset for a single character."""

    def setUp(self):
        self.saved, self.savedParams = odata._send, odata.conf.parameters
        odata.conf.parameters = {odata.PLACE.GET: "name=luther"}
        odata.SENTINEL = "zzsentinelzz"
        self.sent = []

    def tearDown(self):
        odata._send, odata.conf.parameters = self.saved, self.savedParams

    def _extract(self, service, field="Secret"):
        def counting(place, parameter, value, raw=False):
            self.sent.append(value)
            return service(place, parameter, value, raw)

        odata._send = counting
        _t, _p, boundary = odata._detectBoolean(odata.PLACE.GET, "name")
        oracle = odata._makeOracle(odata.PLACE.GET, "name", boundary, truePredicate="(Id eq 1)")
        self.assertIsNotNone(oracle)
        before = len(self.sent)
        return odata._inferField(oracle, "Id", 1, field), len(self.sent) - before

    def test_v40_service_extracts_under_a_linear_scan(self):
        value, cost = self._extract(_mockSend)
        self.assertEqual(value, "S3CR3Tvalue")
        self.assertLess(cost, len(value) * len(odata._CS_ORDS))

    def test_v401_service_extracts_the_same_value(self):
        value, cost = self._extract(_mockSendIn)
        self.assertEqual(value, "S3CR3Tvalue")
        self.assertLess(cost, len(value) * len(odata._CS_ORDS))

    def test_in_encoding_is_used_only_when_offered(self):
        self._extract(_mockSendIn)
        self.assertTrue(any(" in (" in _ for _ in self.sent))
        self.sent = []
        self._extract(_mockSend)
        self.assertFalse(any("substring(Secret,0,1) in (" in _ for _ in self.sent))

    def test_disjunction_stays_inside_the_node_budget(self):
        """Every 'or' term costs the service's parser ~8 of the 100 nodes ASP.NET Core OData allows by
        default (MaxNodeCount); an 11-term disjunction was measured being rejected outright."""

        self._extract(_mockSend)
        for value in self.sent:
            self.assertLessEqual(value.count("substring("), ODATA_CHARSET_BLOCK)

    def test_split_point_never_degenerates(self):
        """A cut of 0 or of len(candidates) would leave the set unchanged and loop forever."""

        for size in range(2, len(odata._CS_ORDS) + 1):
            cut = odata._splitPoint(odata._CS_ORDS[:size])
            self.assertTrue(0 < cut < size, "size %d cut %d" % (size, cut))


if __name__ == "__main__":
    unittest.main(verbosity=2)
