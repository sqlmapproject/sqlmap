#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Coverage for the XSLT injection engine (lib/techniques/xslt/inject.py) and the XQuery tier the XPath
engine gained (lib/techniques/xpath/inject.py).

Network-free: the payload builders, engine fingerprinting and charset construction are pure functions, so
they are asserted directly. The parts that decide a VERDICT get the most attention - a detection tier that
rests on "the page changed" is exactly the kind that invents findings, so its guards are pinned here.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.settings import XSLT_ERROR_REGEX
from lib.core.settings import XSLT_RCE_PROBES
from lib.core.settings import XSLT_VENDOR_PROPERTIES
from lib.core.settings import XQUERY_CAPABILITY_PROBES
from lib.core.settings import XQUERY_FILE_READ
from lib.techniques.xslt import inject as _xslt
from lib.techniques.xpath import inject as _xpath


def _source(*parts):
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", *parts)) as f:
        return f.read()


class XsltPayloadTest(unittest.TestCase):
    def test_element_payload_is_a_whole_instruction(self):
        payload = _xslt._elementPayload("'a'")
        self.assertTrue(payload.startswith("<xsl:value-of "))
        self.assertIn('select="\'a\'"', payload)

    def test_value_payload_is_the_bare_expression(self):
        """The value slot already sits inside select="...", so wrapping it would break the attribute."""
        self.assertEqual(_xslt._valuePayload("system-property('xsl:vendor')"), "system-property('xsl:vendor')")

    def test_sentinel_wrapping_makes_a_hit_unambiguous(self):
        expression = _xslt._concat("'S'", "system-property('xsl:vendor')", "'S'")
        self.assertEqual(expression, "concat('S',system-property('xsl:vendor'),'S')")

    def test_both_slots_are_probed(self):
        self.assertEqual([_ for _, __ in _xslt._BUILDERS], [_xslt.CONTEXT_ELEMENT, _xslt.CONTEXT_VALUE])


class XsltReflectionSafetyTest(unittest.TestCase):
    """The tier that reports a finding must not be satisfiable by an application that merely echoes the
    parameter. This is the exact defect two reviewers found: a plain search page was reported vulnerable
    and then 'read' /etc/shadow out of its own reflected payload."""

    def test_joined_marker_is_absent_from_the_raw_payload(self):
        """An echo can only reflect what was sent, so the marker must not exist until concat() runs."""
        head, tail = _xslt._marks()
        payload = _xslt._wrap("system-property('xsl:vendor')")
        self.assertIn(head, payload)
        self.assertIn(tail, payload)
        self.assertNotIn(head + tail, payload)

    def test_echoed_payload_yields_no_capture(self):
        payload = _xslt._wrap("system-property('xsl:vendor')")
        echoed = "<html><body>you searched for: %s</body></html>" % payload
        self.assertIsNone(_xslt._captured(page=echoed, payload=payload))

    def test_evaluated_response_yields_the_result(self):
        head, tail = _xslt._marks()
        payload = _xslt._wrap("system-property('xsl:vendor')")
        page = "<html><body>%slibxslt%s</body></html>" % (head + tail, head + tail)
        self.assertEqual(_xslt._captured(page=page, payload=payload), "libxslt")

    def test_raw_expression_in_the_page_is_rejected_even_with_the_marker(self):
        """Defence in depth: a compiled transform emits its RESULT, never its source text."""
        head, tail = _xslt._marks()
        payload = _xslt._wrap("system-property('xsl:vendor')")
        page = "%slibxslt%s and also %s" % (head + tail, head + tail, payload)
        self.assertIsNone(_xslt._captured(page=page, payload=payload))

    def test_empty_capture_is_reachable_and_means_executed(self):
        """The span allows a zero-length capture, so 'concat ran but the property is unset' is a real
        outcome rather than the dead branch it used to be."""
        head, tail = _xslt._marks()
        payload = _xslt._wrap("system-property('xsl:unset')")
        page = "%s%s" % (head + tail, head + tail)
        self.assertEqual(_xslt._captured(page=page, payload=payload, span="0,120"), "")


class XsltDifferentialTest(unittest.TestCase):
    def test_both_slots_use_a_baseline_preserving_valid_form(self):
        """The 'valid' probe has to leave the page identical to the baseline. An element-slot form that
        EMITS a sentinel can never satisfy that, which made the whole element branch unreachable."""
        import inspect
        source = inspect.getsource(_xslt._probeCompile)
        self.assertIn("(CONTEXT_ELEMENT, original,", source)
        self.assertNotIn("_elementPayload(\"'%s'\" % SENTINEL)", source)

    def test_element_slot_has_an_xpath_function_guard(self):
        """Without it the element branch would report on 'the page changed', which any parser does."""
        import inspect
        source = inspect.getsource(_xslt._probeCompile)
        self.assertIn("_elementPayload(\"substring(", source)


class XsltFingerprintTest(unittest.TestCase):
    def test_known_engines_are_attributed(self):
        for page, expected in (
            ("lxml.etree.XSLTParseError: bad stylesheet", "libxslt / lxml"),
            ("xsltParseStylesheet : problem", "libxslt"),
            ("net.sf.saxon.trans.XPathException: XTDE1260", "Saxon"),
            ("javax.xml.transform.TransformerConfigurationException", "Xalan / Java JAXP"),
            ("System.Xml.Xsl.XslLoadException: bad", ".NET XslCompiledTransform"),
            ("XSLTProcessor::importStylesheet(): compilation error", "PHP XSLTProcessor"),
        ):
            self.assertEqual(_xslt._vendorFromError(page), expected, page)

    def test_a_specific_binding_wins_over_the_generic_engine(self):
        """PHP's XSLTProcessor and lxml are both libxslt and emit its wording, so the specific binding has
        to be reported - that is what tells the tester what they are actually talking to."""
        self.assertEqual(_xslt._vendorFromError("XSLTProcessor::transformToXml(): compilation error"), "PHP XSLTProcessor")
        self.assertEqual(_xslt._vendorFromError("lxml.etree.XSLTApplyError: compilation error"), "libxslt / lxml")

    def test_a_plain_page_is_not_an_error(self):
        for page in ("<html><body>luther</body></html>", "", None, "no results found"):
            self.assertFalse(_xslt._isError(page), repr(page))

    def test_error_regex_is_anchored_to_xslt_vocabulary(self):
        """This regex also drives the GLOBAL heuristic hint, so a generic compiler/regex/SQL failure must
        not suggest '--xslt' on a target that has nothing to do with XSLT."""
        for page in ("You have an error in your SQL syntax", "Traceback (most recent call last)",
                     "org.postgresql.util.PSQLException", "500 Internal Server Error",
                     "gcc: compilation error", "javac: compilation error",
                     "Invalid expression at line 4", "regex: Invalid expression"):
            self.assertIsNone(re.search(XSLT_ERROR_REGEX, page), page)

    def test_error_regex_still_matches_every_real_engine(self):
        for page in ("xsltParseStylesheet : problem", "lxml.etree.XSLTParseError: bad",
                     "XSLTProcessor::importStylesheet(): compilation error",
                     "System.Xml.Xsl.XslLoadException", "net.sf.saxon.trans.XPathException: XTDE1260",
                     "javax.xml.transform.TransformerConfigurationException"):
            self.assertIsNotNone(re.search(XSLT_ERROR_REGEX, page), page)

    def test_unquotable_paths_do_not_break_the_literal(self):
        """XPath 1.0 has no escape character, so a path with both quote kinds needs concat()."""
        self.assertEqual(_xslt._quote("/etc/passwd"), "'/etc/passwd'")
        self.assertEqual(_xslt._quote("/tmp/o'brien"), '"/tmp/o\'brien"')
        self.assertTrue(_xslt._quote("/tmp/bo\"th's").startswith("concat("))

    def test_vendor_properties_are_xslt_defined(self):
        self.assertIn("xsl:vendor", XSLT_VENDOR_PROPERTIES)
        for prop in XSLT_VENDOR_PROPERTIES:
            self.assertTrue(prop.startswith("xsl:"), prop)


class XsltRcePolicyTest(unittest.TestCase):
    """The extension surfaces are reported, never invoked - the probes must only ASK whether a function
    exists, never call it."""

    def test_probes_only_test_availability(self):
        for label, expression in XSLT_RCE_PROBES:
            self.assertTrue(expression.startswith("string(function-available(")
                            or expression.startswith("string(element-available("), expression)
            self.assertNotIn("Runtime.exec", expression)
            self.assertNotIn("system(", expression)

    def test_labels_say_what_the_primitive_is(self):
        joined = " ".join(label for label, _ in XSLT_RCE_PROBES).lower()
        for expected in ("php", "exsl", "saxon", "java"):
            self.assertIn(expected, joined)


class XQueryTierTest(unittest.TestCase):
    def test_capability_probes_are_absent_from_xpath_1_0(self):
        """Each probe calls a function XPath 1.0 does not define, which is what makes a positive answer a
        demonstrated capability rather than an inference."""
        for probe in XQUERY_CAPABILITY_PROBES:
            self.assertTrue(any(fn in probe for fn in ("string-join", "upper-case", "matches")), probe)

    def test_file_read_uses_unparsed_text(self):
        self.assertIn("unparsed-text", XQUERY_FILE_READ)
        self.assertEqual(XQUERY_FILE_READ % "'/etc/passwd'", "unparsed-text('/etc/passwd')")

    def test_file_charset_covers_tab_and_newline(self):
        """The XML-tree charset excludes them; a file recovered with newlines replaced by '?' is useless."""
        self.assertIn(0x09, _xpath._FILE_ORDS)
        self.assertIn(0x0a, _xpath._FILE_ORDS)
        self.assertIn(ord('&'), _xpath._FILE_ORDS)

    def test_file_charset_literal_carries_no_transport_hazard(self):
        """Built from codepoints because the charset contains ' " & and < - a bare '&' is an invalid
        entity in an XQuery string literal AND splits a query-string parameter in two."""
        literal = _xpath._FILE_LITERAL
        self.assertTrue(literal.startswith("codepoints-to-string(("))
        for hazard in ("'", '"', "&", "<"):
            self.assertNotIn(hazard, literal)

    def test_file_charset_literal_matches_the_ordinals(self):
        codes = [int(_) for _ in re.search(r"\(\((.*)\)\)", _xpath._FILE_LITERAL).group(1).split(",")]
        self.assertEqual(codes, _xpath._FILE_ORDS)

    def test_builders_accept_a_charset_override(self):
        """The override is what keeps the file read from disturbing XML-tree extraction."""
        builder = _xpath._XPathPayloadBuilder("x", _xpath.Boundary("' or ", " and '1'='1", True))
        self.assertIn("ZZZ", builder.charPresent("t", 1, "ZZZ"))
        self.assertIn("ZZZ", builder.charIndexAtLeast("t", 1, 2, "ZZZ"))
        self.assertIn(_xpath._CS_LITERAL, builder.charPresent("t", 1))


class SwitchWiringTest(unittest.TestCase):
    def test_switch_is_registered_and_mutually_exclusive(self):
        from lib.core.optiondict import optDict
        self.assertEqual(optDict["Techniques"].get("xslt"), "boolean")

        self.assertIn('("--xslt", conf.xslt)', _source("lib", "core", "option.py"))

    def test_controller_dispatches_the_scan(self):
        self.assertIn("from lib.techniques.xslt.inject import xsltScan", _source("lib", "controller", "controller.py"))


if __name__ == "__main__":
    unittest.main()
