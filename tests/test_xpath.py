#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Offline, deterministic tests for the XPath injection engine. Mock oracles stand in for the
HTTP/lxml layer so detection, fingerprinting, blind inference, payload building, and output
formatting can be exercised without a live target.
"""

import unittest

from _testutils import bootstrap
bootstrap()

import lib.techniques.xpath.inject as xpath


SENTINEL = xpath.SENTINEL


class TestHelpers(unittest.TestCase):
    def test_ratio(self):
        self.assertGreater(xpath._ratio("abc", "abc"), 0.9)
        self.assertLess(xpath._ratio("abc", "xyz"), 0.5)

    def test_delim(self):
        from lib.core.enums import PLACE
        self.assertEqual(xpath._delim(PLACE.GET), '&')
        self.assertEqual(xpath._delim(PLACE.COOKIE), ';')

    def test_is_error(self):
        self.assertTrue(xpath._isError("javax.xml.xpath.XPathExpressionException: error"))
        self.assertTrue(xpath._isError("lxml.etree.XPathEvalError: Invalid expression"))
        self.assertFalse(xpath._isError("normal page content"))

    def test_backend_from_error(self):
        self.assertIsNotNone(xpath._backendFromError("lxml.etree.XPathEvalError: Invalid expression"))
        self.assertIsNotNone(xpath._backendFromError("System.Xml.XPath.XPathException: has an invalid token"))
        self.assertIsNone(xpath._backendFromError("normal page"))

    def test_is_password_param(self):
        self.assertTrue(xpath._isPasswordParam("password"))
        self.assertTrue(xpath._isPasswordParam("pass"))
        self.assertFalse(xpath._isPasswordParam("username"))

    def test_xpath_quote(self):
        self.assertEqual(xpath._xpathQuote("hello"), "'hello'")
        self.assertEqual(xpath._xpathQuote("it's"), "\"it's\"")
        self.assertEqual(xpath._xpathQuote('say "hi"'), "'say \"hi\"'")
        both = "it's \"great\""
        q = xpath._xpathQuote(both)
        self.assertIn("concat", q)

    def test_make_payload_with_suffix(self):
        b = xpath.Boundary("') or ", " or ('", True)
        p = xpath._makePayload("x", b, "starts-with(name(/*),'d')")
        self.assertEqual(p, "x') or starts-with(name(/*),'d') or ('")

    def test_make_payload_no_suffix(self):
        b = xpath.Boundary("' or ", "", True)
        p = xpath._makePayload("x", b, "1=1")
        self.assertEqual(p, "x' or 1=1")

    def test_make_payload_with_suffix_only(self):
        b = xpath.Boundary("' or ", " and '1'='1", True)
        p = xpath._makePayload("x", b, "1=1")
        self.assertEqual(p, "x' or 1=1 and '1'='1")


class TestBoundaryTable(unittest.TestCase):
    def test_all_entries_in_boundary_lookup(self):
        for bk in xpath.XPATH_BREAKOUT_PREFIXES:
            self.assertIn(bk, xpath._BREAKOUT_BOUNDARY,
                "Breakout '%s' not found in _BREAKOUT_BOUNDARY" % bk)

    def test_function_arg_boundaries_are_extractable(self):
        for bk in ("') or true() or ('", "') or '1'='1' or ('", "') or 1=1 or ('"):
            b = xpath._BREAKOUT_BOUNDARY[bk]
            self.assertTrue(b.extractable)
            self.assertTrue(len(b.prefix) > 0)
            self.assertTrue(len(b.suffix) > 0)

    def test_simple_string_boundaries_have_suffix(self):
        for bk in ("' or '1'='1", "' or true() or '", "' or 1=1 or '",
                   '" or "1"="1', '" or true() or "'):
            b = xpath._BREAKOUT_BOUNDARY[bk]
            if b is not None:
                self.assertTrue(b.extractable)
                self.assertTrue(len(b.suffix) > 0,
                    "Simple string breakout '%s' needs a suffix to absorb the trailing quote" % bk)

    def test_union_wildcard_is_not_extractable(self):
        b = xpath._BREAKOUT_BOUNDARY.get("']|//*|test['")
        self.assertIsNone(b, "Union wildcard must not have an extraction boundary")

    def test_numeric_has_leading_space(self):
        for bk in (" or 1=1", " or true()"):
            self.assertTrue(bk.startswith(" "),
                "Numeric breakout '%s' needs leading whitespace" % bk)
            b = xpath._BREAKOUT_BOUNDARY[bk]
            self.assertTrue(b.extractable)

    def test_all_extractable_have_prefix(self):
        for bk, b in xpath._BREAKOUT_BOUNDARY.items():
            if b is not None:
                self.assertTrue(len(b.prefix) > 0,
                    "Extractable boundary for '%s' needs a prefix" % bk)


class TestPayloadBuilder(unittest.TestCase):
    def setUp(self):
        self.boundary = xpath._BREAKOUT_BOUNDARY["') or true() or ('"]
        self.builder = xpath._XPathPayloadBuilder("x", self.boundary)

    def test_name_starts_with(self):
        p = self.builder.nameStartsWith("/*", "d")
        self.assertIn("starts-with(name(/*)", p)
        self.assertIn("'d'", p)

    def test_name_length(self):
        p = self.builder.nameLength("/*", 9)
        self.assertIn("string-length(name(/*))=9", p)

    def test_child_count(self):
        p = self.builder.childCount("/*", 3)
        self.assertIn("count(/*/*)>=3", p)

    def test_attribute_count(self):
        p = self.builder.attributeCount("/*[1]", 2)
        self.assertIn("count(/*[1]/@*)>=2", p)

    def test_text_starts_with(self):
        p = self.builder.textStartsWith("/*[1]/*[1]", "lut")
        self.assertIn("starts-with(string(/*[1]/*[1])", p)

    def test_empty_prefix(self):
        p = self.builder.nameStartsWith("/*", "")
        self.assertIn("''", p)

    def test_uses_boundary_not_hardcoded(self):
        p = self.builder.nameStartsWith("/*", "d")
        self.assertNotIn("contains(username", p)
        self.assertIn("x') or ", p)
        self.assertIn(" or ('", p)

    def test_simple_string_boundary_builder(self):
        b = xpath._BREAKOUT_BOUNDARY["' or '1'='1"]
        builder = xpath._XPathPayloadBuilder("x", b)
        p = builder.nameStartsWith("/*", "d")
        self.assertIn("x' or ", p)
        self.assertIn(" and '1'='1", p)


class TestBooleanDetection(unittest.TestCase):
    def setUp(self):
        self.original_send = xpath._send

    def tearDown(self):
        xpath._send = self.original_send

    def test_false_page_must_be_reproducible(self):
        # True is stable, false changes every time -> no oracle
        true_calls = [0]

        def mock(place, parameter, value):
            if "true()" in value:
                return "true-page"
            elif "false()" in value:
                true_calls[0] += 1
                return "false-page-%d" % true_calls[0]
            return "default"

        xpath._send = mock
        template, payload, boundary = xpath._detectBoolean("GET", "q")
        self.assertIsNone(template)

    def test_detection_returns_extractable_boundary(self):
        def mock(place, parameter, value):
            if "true()" in value:
                return '{"count":7,"entries":[{...}]}'
            elif "false()" in value:
                return '{"count":0,"entries":[],"error":null}'
            return "default"

        xpath._send = mock
        template, payload, boundary = xpath._detectBoolean("GET", "q")
        self.assertIsNotNone(template)
        self.assertIsNotNone(boundary)
        self.assertTrue(boundary.extractable)


class TestGridAndTable(unittest.TestCase):
    def test_grid(self):
        columns = ["Path", "Element", "Value"]
        rows = [["/*", "root", ""], ["/*[1]", "child", "text"]]
        grid = xpath._grid(columns, rows)
        self.assertIn("Path", grid)
        self.assertIn("root", grid)

    def test_grid_empty(self):
        grid = xpath._grid([], [])
        self.assertIn("+", grid)

    def test_tree_to_table(self):
        node = {
            "name": "directory", "path": "/*",
            "children": [{"name": "user", "path": "/*[1]", "children": [],
                          "attributes": [{"name": "id", "value": "1"}], "text": None}],
            "attributes": [], "text": None,
        }
        columns, rows = xpath._treeToTable(node)
        self.assertIn("Path", columns)
        self.assertGreater(len(rows), 0)


class TestExtraction(unittest.TestCase):
    def test_infer_value_mock(self):
        expected = "directory"
        boundary = xpath._BREAKOUT_BOUNDARY["') or true() or ('"]
        builder = xpath._XPathPayloadBuilder("x", boundary)

        class MockOracle(object):
            def extract(self, payload):
                import re
                m = re.search(r"""starts-with\(name\(/\*\),'([^']*)'\)""", payload)
                return expected.startswith(m.group(1)) if m else False

        oracle = MockOracle()
        result = xpath._inferValue(oracle, builder, "/*",
                                   lambda b, p, prefix: b.nameStartsWith(p, prefix),
                                   maxLen=20)
        self.assertEqual(result, expected)

    def test_infer_count(self):
        expected = 3
        boundary = xpath._BREAKOUT_BOUNDARY["') or true() or ('"]
        builder = xpath._XPathPayloadBuilder("x", boundary)

        class MockOracle(object):
            def extract(self, payload):
                import re
                m = re.search(r"count\(/\*/\*\)>=(\d+)", payload)
                if m:
                    return int(m.group(1)) <= expected
                return False

        oracle = MockOracle()
        result = xpath._inferCount(oracle, builder, "/*",
                                   lambda b, p, c: b.childCount(p, c),
                                   maxCount=8)
        self.assertEqual(result, expected)

    def test_infer_string_binary_search(self):
        # Drive the binary-search extractor through real lxml evaluation of the
        # boundary-wrapped predicates against _XML and confirm exact recovery.
        boundary = xpath._BREAKOUT_BOUNDARY["') or true() or ('"]
        builder = xpath._XPathPayloadBuilder("x", boundary)
        template = _XPATH_TEMPLATES["function_arg"]

        class MockOracle(object):
            def extract(self, payload):
                return _xpath_eval(template, payload) > 0

        oracle = MockOracle()
        # Absolute targets are resolved the same way the live tree-walk would.
        self.assertEqual(xpath._inferString(oracle, builder, "name(/*)", maxLen=32), "directory")
        self.assertEqual(xpath._inferString(oracle, builder, "string(//user[1]/name)", maxLen=32), "luther")
        self.assertEqual(xpath._inferString(oracle, builder, "string(//user[1]/@id)", maxLen=32), "1")

    def test_infer_string_matches_linear(self):
        # The fast extractor must agree with the legacy linear extractor.
        boundary = xpath._BREAKOUT_BOUNDARY["') or true() or ('"]
        builder = xpath._XPathPayloadBuilder("x", boundary)
        template = _XPATH_TEMPLATES["function_arg"]

        class MockOracle(object):
            def extract(self, payload):
                return _xpath_eval(template, payload) > 0

        oracle = MockOracle()
        fast = xpath._inferString(oracle, builder, "name(/*)", maxLen=32)
        linear = xpath._inferValue(oracle, builder, "/*",
                                   lambda b, p, prefix: b.nameStartsWith(p, prefix),
                                   maxLen=32)
        self.assertEqual(fast, linear)


class TestBackendFingerprint(unittest.TestCase):
    def test_lxml(self):
        page = "lxml.etree.XPathEvalError: Invalid expression"
        backend = xpath._backendFromError(page)
        self.assertIsNotNone(backend)
        self.assertIn("lxml", backend)

    def test_java_jaxp(self):
        page = "javax.xml.xpath.XPathExpressionException: A location path was expected"
        backend = xpath._backendFromError(page)
        self.assertIsNotNone(backend)

    def test_dotnet(self):
        page = "System.Xml.XPath.XPathException: Expression must evaluate to a node-set"
        backend = xpath._backendFromError(page)
        self.assertIsNotNone(backend)

    def test_no_error(self):
        page = "Normal page with user data"
        backend = xpath._backendFromError(page)
        self.assertIsNone(backend)


# --- Real XPath syntax validation (lxml) ---------------------------------------

_XML = b"""<?xml version="1.0"?><directory><user id="1"><name>luther</name></user><user id="2"><name>fluffy</name></user></directory>"""

_XPATH_TEMPLATES = {
    "function_arg":      "//user[contains(name,'%s')]",
    "single_quoted":     "//user[name='%s']",
    "double_quoted":     '//user[name="%s"]',
    "numeric":           "//user[position()=%s]",
    "bare_predicate":    "//user[%s]",
}


def _xpath_eval(template, payload):
    """Evaluate an XPath expression against _XML, return the match count."""
    try:
        from lxml import etree
    except ImportError:
        raise unittest.SkipTest("lxml not available")
    root = etree.fromstring(_XML)
    expr = template % payload
    return len(root.xpath(expr))


class TestRealXPathSyntax(unittest.TestCase):
    """Verify that detection payloads and extraction predicates are syntactically
    valid XPath and produce the expected boolean results."""

    @staticmethod
    def _count(template, payload):
        return _xpath_eval(template, payload)

    def _test_family(self, template_key, true_breakout, false_breakout, boundary_key, original="x"):
        template = _XPATH_TEMPLATES[template_key]
        boundary = xpath._BREAKOUT_BOUNDARY[boundary_key]
        self.assertIsNotNone(boundary)
        self.assertTrue(boundary.extractable)

        # Detection payloads must be syntactically valid and yield true/false
        truePayload = original + true_breakout
        falsePayload = original + false_breakout
        self.assertGreater(self._count(template, truePayload), 0,
            "True payload '%s' should match at least one node" % truePayload)
        self.assertEqual(self._count(template, falsePayload), 0,
            "False payload '%s' should match no nodes" % falsePayload)

        # Extraction predicate must be valid and change the result truthfully
        self.assertIsNotNone(xpath._XPathPayloadBuilder(original, boundary))
        truePred = xpath._makePayload(original, boundary, "true()")
        falsePred = xpath._makePayload(original, boundary, "false()")
        self.assertGreater(self._count(template, truePred), 0,
            "Extraction true predicate must match")
        self.assertEqual(self._count(template, falsePred), 0,
            "Extraction false predicate must not match")

    def test_function_arg_family(self):
        self._test_family("function_arg",
            "') or true() or ('", "') and false() and ('",
            "') or true() or ('")

    def test_single_quoted_family(self):
        self._test_family("single_quoted",
            "' or '1'='1", "' and '1'='2",
            "' or '1'='1")

    def test_double_quoted_family(self):
        self._test_family("double_quoted",
            '" or "1"="1', '" and "1"="2',
            '" or "1"="1')

    def test_numeric_family(self):
        self._test_family("numeric",
            " or 1=1", " and 1=2",
            " or 1=1", original="1")

    def test_bare_predicate_family(self):
        self._test_family("bare_predicate",
            " or true()", " and false()",
            " or true()", original="1")

    def test_function_arg_second_variant(self):
        self._test_family("function_arg",
            "') or '1'='1' or ('", "') and '1'='2' and ('",
            "') or '1'='1' or ('")

    def test_single_quoted_with_matching_original(self):
        """When the original value matches a record (name='luther'), OR-style
        extraction with 'and' suffix is still decisive because the engine uses
        a non-matching sentinel base for tree-walking."""
        boundary = xpath._BREAKOUT_BOUNDARY["' or '1'='1"]
        # Simulate what xpathScan() does: use a sentinel as base for OR-style
        sentinel = "zzznotpresent"
        self.assertIsNotNone(xpath._XPathPayloadBuilder(sentinel, boundary))
        truePred = xpath._makePayload(sentinel, boundary, "true()")
        falsePred = xpath._makePayload(sentinel, boundary, "false()")
        tpl = _XPATH_TEMPLATES["single_quoted"]
        self.assertGreater(self._count(tpl, truePred), 0,
            "OR extraction must match with sentinel base + true predicate")
        self.assertEqual(self._count(tpl, falsePred), 0,
            "OR extraction must not match with sentinel base + false predicate")

    def test_all_extractable_boundaries_have_valid_extraction(self):
        # Match each boundary to an appropriate template and original value.
        _CONTEXT = {
            "') or true() or ('": ("function_arg", "x"),
            "') or '1'='1' or ('": ("function_arg", "x"),
            "') or 1=1 or ('": ("function_arg", "x"),
            '") or true() or ("': ("function_arg", "x"),
            "' or '1'='1": ("single_quoted", "x"),
            "' or true() or '": ("single_quoted", "x"),
            "' or 1=1 or '": ("single_quoted", "x"),
            "' and '1'='1": ("single_quoted", "x"),
            '" or "1"="1': ("double_quoted", "x"),
            '" or true() or "': ("double_quoted", "x"),
            " or 1=1": ("numeric", "999"),
            " or true()": ("bare_predicate", "999"),
        }
        for bk, boundary in xpath._BREAKOUT_BOUNDARY.items():
            if boundary is None or not boundary.extractable:
                continue
            tkey, original = _CONTEXT.get(bk, ("function_arg", "x"))
            template = _XPATH_TEMPLATES[tkey]
            payload = xpath._makePayload(original, boundary, "true()")
            try:
                count = self._count(template, payload)
            except unittest.SkipTest:
                raise  # lxml unavailable -> skip cleanly; SkipTest is an Exception, so the broad except below would otherwise mask it into a failure
            except Exception as e:
                self.fail("Boundary '%s' in '%s' with orig='%s' invalid: %s\n  payload: %s" % (bk, tkey, original, e, payload))
            self.assertIsInstance(count, int,
                "Boundary '%s' in '%s' produced no count" % (bk, tkey))
