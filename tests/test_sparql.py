#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Offline, deterministic tests for the SPARQL injection engine. A mock oracle mirrors the boolean-blind
semantics of a real triple store (a broken-out FILTER reduced to its injected predicate), so detection,
SPARQL-only confirmation, error fingerprinting and schema-agnostic blind extraction are exercised
without a live SPARQL endpoint.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import lib.techniques.sparql.inject as sparql
from lib.core.settings import SPARQL_ERROR_REGEX


# a tiny fixed graph the mock evaluates against
_TRIPLES = (
    ("http://example.org/p1", "http://xmlns.com/foaf/0.1/name", "luther"),
    ("http://example.org/p1", "http://xmlns.com/foaf/0.1/mbox", "luther@example.org"),
    ("http://example.org/secret", "http://example.org/flag", "S3CR3Tvalue"),
    # every character class the transport used to mangle or the charset used to alias:
    # '&' split the request, '+' arrived as a space, '"' and '\\' were holes in the bisection
    ("http://example.org/edge", "http://example.org/raw", 'a&b+c"d\\e()'),
)
_PREDICATES = sorted(set(_[1] for _ in _TRIPLES))
_OBJECTS = sorted(_[2] for _ in _TRIPLES)


def _bind(inner, offset):
    if "COUNT(*)" in inner:
        return len(_TRIPLES)
    if "COUNT(DISTINCT ?p)" in inner:
        return len(_PREDICATES)
    if "DISTINCT ?p" in inner:
        return _PREDICATES[offset] if offset < len(_PREDICATES) else None
    if "SELECT ?o" in inner:
        return _OBJECTS[offset] if offset < len(_OBJECTS) else None
    return None


def _cmp(value, expr):
    match = re.match(r"^\?v >= (\d+)$", expr)
    if match:
        return isinstance(value, int) and value >= int(match.group(1))
    match = re.match(r"^STRLEN\(STR\(\?v\)\) >= (\d+)$", expr)
    if match:
        return len("%s" % value) >= int(match.group(1))
    # the literal may be escaped ('\"' / '\\'), the way a real store receives it
    match = re.match(r'^SUBSTR\(STR\(\?v\),(\d+),1\) >= "(\\.|.)"$', expr)
    if match:
        pos, ch = int(match.group(1)), match.group(2)
        ch = {'\\"': '"', "\\\\": "\\"}.get(ch, ch)
        text = "%s" % value
        return (text[pos - 1] if pos <= len(text) else "") >= ch
    return False


def _predicate(pred):
    pred = pred.strip()
    if pred in ("1=1", "(1=1)"):
        return True
    if pred in ("1=2", "(1=2)"):
        return False
    if "FILTER(!isIRI(?zo))" in pred:
        return False
    if pred == "EXISTS { ?zs ?zp ?zo }":
        return True
    match = re.match(r"^EXISTS \{ SELECT \?v WHERE \{ (.*) FILTER\((.*)\) \} \}$", pred)
    if match:
        inner, expr = match.group(1).strip(), match.group(2).strip()
        off = re.search(r"OFFSET (\d+)", inner)
        value = _bind(inner, int(off.group(1)) if off else 0)
        return value is not None and _cmp(value, expr)
    return False


def _evaluate(value):
    for quote, tail in (('"', '""!="'), ("'", "''!='")):
        marker, suffix = '%s || (' % quote, ') || %s' % tail
        if marker in value and value.endswith(suffix):
            return _predicate(value.split(marker, 1)[1][:-len(suffix)])
    match = re.match(r"^\d+ \|\| \((.*)\)$", value)        # numeric / unquoted slot
    if match:
        return _predicate(match.group(1))
    if value.count('"') % 2 or value.rstrip().endswith(("'", ")", ".")):
        return "ERROR"
    return any(o == value for _s, p, o in _TRIPLES if p.endswith("name"))


_ROWS = "<html><body><ul><li>luther</li></ul></body></html>"
_EMPTY = "<html><body><ul></ul></body></html>"
_ERROR = "<html><body><pre>Parse error: Lexical error at line 1, column 42.</pre></body></html>"


def _mockSend(place, parameter, value, raw=False):
    verdict = _evaluate(value)
    if verdict == "ERROR":
        return _ERROR if raw else None      # a 500 is nulled for the oracle, kept for the error probe
    return _ROWS if verdict else _EMPTY


class TestHelpers(unittest.TestCase):
    def test_is_error(self):
        self.assertTrue(sparql._isError("Parse error: Lexical error at line 1, column 42."))
        self.assertFalse(sparql._isError("<html><body><ul><li>luther</li></ul></body></html>"))

    def test_backend_from_error(self):
        self.assertEqual(sparql._backendFromError("Lexical error at line 1, column 8."), "Apache Jena / Fuseki")
        self.assertEqual(sparql._backendFromError("org.eclipse.rdf4j.query.parser.ParseException"), "RDF4J / GraphDB")
        self.assertIsNone(sparql._backendFromError("plain results page"))

    def test_error_regex_matches_real_jena(self):
        self.assertIsNotNone(re.search(SPARQL_ERROR_REGEX, "Parse error: Lexical error at line 1, column 136."))


class TestNoAmpersandInvariant(unittest.TestCase):
    """A raw '&' in a GET value is the parameter delimiter, so any payload carrying '&&' would be split
    in transit and arrive as a truncated query (a 500 that mimics a dead oracle). Every boundary and
    attribution predicate must therefore use SPARQL's '||' / two-FILTER conjunction, never '&&'."""

    def test_boundaries_have_no_ampersand(self):
        for row in sparql._BOUNDARY_TABLE:
            for field in row[:4]:
                self.assertNotIn("&", field, row)

    def test_confirm_predicates_have_no_ampersand(self):
        for truePred, falsePred in sparql._SPARQL_PREDICATES:
            self.assertNotIn("&", truePred)
            self.assertNotIn("&", falsePred)

    def test_send_url_encodes_the_payload(self):
        """The boundaries being '&'-free was never enough: the character probes emit '&' (and '+') as
        DATA. _send() must URL-encode, or those probes split the request and the bisection is answered
        by a truncated query."""
        sent = []
        savedParams, sparql.conf.parameters = sparql.conf.parameters, {sparql.PLACE.GET: "q=luther"}
        savedGet = sparql.Request.getPage
        sparql.Request.getPage = staticmethod(
            lambda **kwargs: (sent.append(sparql.conf.parameters[sparql.PLACE.GET]), "", None, 200)[1:])
        try:
            sparql._send(sparql.PLACE.GET, "q", sparql._cmpChar(1, ord("&")))
        finally:
            sparql.Request.getPage = savedGet
            sparql.conf.parameters = savedParams
        self.assertEqual(len(sent), 1)
        self.assertNotIn("&", sent[0].split("=", 1)[1], sent[0])
        self.assertIn("%26", sent[0])


class TestCharsetContiguity(unittest.TestCase):
    """The character recovery is a lexicographic '>=' BISECTION, so the charset must have no holes.
    Excluding a codepoint does not make it come back as '?' - it makes the bisection converge on the
    hole's neighbour and report a DIFFERENT character with no warning. '"' and '\\' consequently stay in
    the charset and travel as their SPARQL escapes.

    (This replaces an earlier assertion that pinned the opposite - that 0x22/0x5c were EXCLUDED. That
    contract was wrong: live against Jena Fuseki it silently decoded 'A&x', 'A)x' and 'A+x' all as
    'A%x'. The gap is the bug, not the fix.)"""

    def test_charset_is_contiguous(self):
        self.assertEqual(sparql._CS_ORDS,
                         list(range(sparql.SPARQL_CHAR_MIN, sparql.SPARQL_CHAR_MAX + 1)))

    def test_meta_characters_travel_escaped(self):
        self.assertEqual(sparql._literal(0x22), '"\\""')
        self.assertEqual(sparql._literal(0x5c), '"\\\\"')
        self.assertEqual(sparql._literal(ord('a')), '"a"')

    def test_every_char_probe_is_a_well_formed_literal(self):
        # exactly one opening and one closing quote, everything inside either plain or backslash-escaped
        for ordinal in sparql._CS_ORDS:
            probe = sparql._cmpChar(1, ordinal)
            body = probe.split(">= ", 1)[1]
            self.assertTrue(body.startswith('"') and body.endswith('"'), probe)
            inner = body[1:-1]
            self.assertEqual(inner.replace('\\"', "").replace("\\\\", "").count('"'), 0, probe)


def _mockSendNumeric(place, parameter, value, raw=False):
    """An UNQUOTED numeric slot: FILTER(?age = <value>). A string boundary lands a bare word / stray
    quote in a term position, which a real store rejects outright - only the numeric shape parses."""
    match = re.match(r"^\d+ \|\| \((.*)\)$", value)
    if match:
        return _ROWS if _predicate(match.group(1)) else _EMPTY
    if value.isdigit():
        return _ROWS
    return _ERROR if raw else None          # syntax error: nulled for the oracle, kept for the probe


class TestNumericBoundary(unittest.TestCase):
    """The unquoted numeric/term slot. The base has to be a valid SPARQL TERM there - a random word is
    not one, it is a syntax error, so the row as first written could never fire (verified live: the old
    shape returned 500 'Lexical error ... after prefix "zzsentinelzz"' from Jena, the new one 200)."""

    def setUp(self):
        self.saved, self.savedParams = sparql._send, sparql.conf.parameters
        sparql._send = _mockSendNumeric
        sparql.conf.parameters = {sparql.PLACE.GET: "age=30"}
        sparql.SENTINEL, sparql.NUMBER_SENTINEL = "zzsentinelzz", "961962811"

    def tearDown(self):
        sparql._send, sparql.conf.parameters = self.saved, self.savedParams

    def test_numeric_row_uses_a_numeric_base(self):
        row = [_ for _ in sparql._BOUNDARY_TABLE if _[4] == sparql._BASE_NUMBER]
        self.assertEqual(len(row), 1)
        trueBreak, falseBreak, prefix, suffix, _kind = row[0]
        boundary = sparql.Boundary(prefix, suffix, sparql._BASE_NUMBER)
        self.assertEqual(sparql._base(boundary), "961962811")
        # the payload must be a valid term followed by an OR - no quote to close, no paren to re-balance
        self.assertEqual(sparql._base(boundary) + trueBreak, "961962811 || (1=1)")
        self.assertEqual(sparql._base(boundary) + falseBreak, "961962811 || (1=2)")
        self.assertEqual(sparql._wrap(sparql._base(boundary), boundary, "PRED"), "961962811 || (PRED)")

    def test_string_rows_keep_the_word_base(self):
        for row in [_ for _ in sparql._BOUNDARY_TABLE if _[4] == sparql._BASE_STRING]:
            boundary = sparql.Boundary(row[2], row[3], sparql._BASE_STRING)
            self.assertEqual(sparql._base(boundary), "zzsentinelzz")

    def test_numeric_slot_detects_and_extracts(self):
        template, payload, boundary = sparql._detectBoolean(sparql.PLACE.GET, "age")
        self.assertIsNotNone(template)
        self.assertEqual(boundary.base, sparql._BASE_NUMBER)
        self.assertTrue(payload.startswith("961962811"))
        truth = sparql._makeOracle(sparql.PLACE.GET, "age", boundary)
        self.assertIsNotNone(truth)
        self.assertEqual(sparql._inferString(truth, sparql._nthObject(0)), _OBJECTS[0])


class TestErrorStatusIsNeverAnOracleSample(unittest.TestCase):
    """A 4xx body must be a NON-ANSWER, not a cheap false. Nulling only 5xx let a front-end that serves
    its parser failure as a generic 400 feed that body to the oracle, and when it resembled the FALSE
    model the bit was decided FALSE instead of INCONCLUSIVE. Measured live: a stored 'A(x' came back as
    'A\'x'. The error probe still needs the body, hence raw=True."""

    def _sendWithCode(self, code, raw):
        savedParams, sparql.conf.parameters = sparql.conf.parameters, {sparql.PLACE.GET: "q=luther"}
        savedGet = sparql.Request.getPage
        sparql.Request.getPage = staticmethod(lambda **kwargs: ("BODY", None, code))
        try:
            return sparql._send(sparql.PLACE.GET, "q", "x", raw=raw)
        finally:
            sparql.Request.getPage = savedGet
            sparql.conf.parameters = savedParams

    def test_4xx_and_5xx_are_nulled_for_the_oracle(self):
        for code in (400, 403, 404, 429, 500, 503):
            self.assertIsNone(self._sendWithCode(code, raw=False), code)

    def test_2xx_and_3xx_are_usable(self):
        for code in (200, 204, 302):
            self.assertEqual(self._sendWithCode(code, raw=False), "BODY", code)

    def test_raw_keeps_the_body_for_the_error_probe(self):
        for code in (400, 500):
            self.assertEqual(self._sendWithCode(code, raw=True), "BODY", code)


class TestOriginalValue(unittest.TestCase):
    def setUp(self):
        self.savedParams = sparql.conf.parameters
        self.savedDict = sparql.conf.paramDict
        sparql.conf.parameters = {sparql.PLACE.GET: "q=luther"}

    def tearDown(self):
        sparql.conf.parameters = self.savedParams
        sparql.conf.paramDict = self.savedDict

    def test_reads_and_replaces(self):
        self.assertEqual(sparql._originalValue(sparql.PLACE.GET, "q"), "luther")
        self.assertEqual(sparql._replaceSegment(sparql.PLACE.GET, "q", "X"), "q=X")


class TestDetectionAndExtraction(unittest.TestCase):
    def setUp(self):
        self.saved = sparql._send
        sparql._send = _mockSend
        self.savedParams = sparql.conf.parameters
        sparql.conf.parameters = {sparql.PLACE.GET: "q=luther"}
        sparql.SENTINEL = "zzsentinelzz"

    def tearDown(self):
        sparql._send = self.saved
        sparql.conf.parameters = self.savedParams

    def test_boolean_detection(self):
        template, payload, boundary = sparql._detectBoolean(sparql.PLACE.GET, "q")
        self.assertIsNotNone(template)
        self.assertEqual(boundary.base, sparql._BASE_STRING)

    def test_confirms_sparql(self):
        _t, _p, boundary = sparql._detectBoolean(sparql.PLACE.GET, "q")
        self.assertTrue(sparql._confirmSparql(sparql.PLACE.GET, "q", boundary))

    def test_error_probe_fingerprints_jena(self):
        backend, _page = sparql._probeError(sparql.PLACE.GET, "q")
        self.assertEqual(backend, "Apache Jena / Fuseki")

    def test_blind_extraction_recovers_objects(self):
        _t, _p, boundary = sparql._detectBoolean(sparql.PLACE.GET, "q")
        truth = sparql._makeOracle(sparql.PLACE.GET, "q", boundary)
        self.assertIsNotNone(truth)
        self.assertEqual(sparql._inferCount(truth, sparql._COUNT_TRIPLES, 10 ** 9), len(_TRIPLES))
        self.assertEqual(sparql._inferCount(truth, sparql._COUNT_PREDICATES, 64), len(_PREDICATES))
        # every seeded object comes back BYTE-FOR-BYTE, including the edge value whose '&', '+', '"'
        # and '\' used to be silently rewritten (transport split / charset hole)
        for offset, expected in enumerate(_OBJECTS):
            self.assertEqual(sparql._inferString(truth, sparql._nthObject(offset)), expected)
        self.assertEqual(sparql._inferString(truth, sparql._nthPredicate(0)), _PREDICATES[0])

    def test_plain_sql_endpoint_is_not_confirmed(self):
        # an endpoint where the injected predicate has no effect (always same page) must not confirm
        sparql._send = lambda place, parameter, value, raw=False: _ROWS
        template, _p, boundary = sparql._detectBoolean(sparql.PLACE.GET, "q")
        self.assertIsNone(template)      # no true/false divergence -> not even boolean-detected


class _Dumper(object):
    """Stands in for conf.dumper, which the offline bootstrap does not build."""

    def __init__(self):
        self.output = []

    def singleString(self, value):
        self.output.append(value)


class TestCapsAreDisclosed(unittest.TestCase):
    """Both bounds here are bisection bounds, so a result sitting ON one is a FLOOR, not a measurement.
    A capped IRI reads exactly like a whole one, and a capped predicate count reads like the size of
    the graph - the reader has no way to tell unless it is said."""

    def setUp(self):
        self.saved, self.savedParams = sparql._send, sparql.conf.parameters
        sparql._send = _mockSend
        sparql.conf.parameters = {sparql.PLACE.GET: "q=luther"}
        sparql.SENTINEL = "zzsentinelzz"
        self.savedDumper, sparql.conf.dumper = sparql.conf.get("dumper"), _Dumper()
        self.savedWarning, self.warnings = sparql.logger.warning, []
        sparql.logger.warning = lambda message, *args: self.warnings.append(message % args if args else message)

    def tearDown(self):
        sparql._send, sparql.conf.parameters = self.saved, self.savedParams
        sparql.conf.dumper = self.savedDumper
        sparql.logger.warning = self.savedWarning

    def _truth(self):
        _t, _p, boundary = sparql._detectBoolean(sparql.PLACE.GET, "q")
        truth = sparql._makeOracle(sparql.PLACE.GET, "q", boundary)
        self.assertIsNotNone(truth)
        return truth

    def test_truncated_value_is_reported(self):
        value = sparql._inferString(self._truth(), sparql._nthObject(0), maxLen=4)
        self.assertEqual(value, _OBJECTS[0][:4])
        self.assertTrue(any("at least 4 characters" in _ for _ in self.warnings), self.warnings)

    def test_value_that_fits_is_silent(self):
        value = sparql._inferString(self._truth(), sparql._nthObject(0), maxLen=64)
        self.assertEqual(value, _OBJECTS[0])
        self.assertEqual(self.warnings, [])

    def test_saturated_predicate_count_is_reported_as_a_floor(self):
        saved, sparql.SPARQL_MAX_PREDICATES = sparql.SPARQL_MAX_PREDICATES, 2
        try:
            sparql._dumpGraph(self._truth())
        finally:
            sparql.SPARQL_MAX_PREDICATES = saved

        self.assertTrue(any("hit the 2 cap" in _ for _ in self.warnings), self.warnings)


if __name__ == "__main__":
    unittest.main(verbosity=2)
