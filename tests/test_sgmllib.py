#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Tests for lib/utils/sgmllib.py -- the SGML/HTML parser used internally by
sqlmap for page content analysis. Exercises the parser with valid SGML/HTML
constructs and verifies the event stream.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.utils.sgmllib import SGMLParser


class RecordingParser(SGMLParser):
    """SGMLParser subclass that records parse events AND delegates to parent."""

    def __init__(self):
        SGMLParser.__init__(self)
        self.events = []

    def _gather_data(self):
        """Extract concatenated text from data events."""
        return "".join(body for ev in self.events if ev[0] == "data" for body in (ev[1],))

    def handle_data(self, data):
        self.events.append(("data", data))

    def handle_comment(self, data):
        self.events.append(("comment", data))
        SGMLParser.handle_comment(self, data)

    def handle_decl(self, decl):
        self.events.append(("decl", decl))

    def handle_pi(self, data):
        self.events.append(("pi", data))

    def handle_charref(self, name):
        self.events.append(("charref", name))
        SGMLParser.handle_charref(self, name)    # do the actual conversion -> handle_data

    def handle_entityref(self, name):
        self.events.append(("entityref", name))
        SGMLParser.handle_entityref(self, name)  # do the actual conversion -> handle_data

    def unknown_starttag(self, tag, attrs):
        self.events.append(("start", tag, attrs))

    def unknown_endtag(self, tag):
        self.events.append(("end", tag))

    def unknown_charref(self, ref):
        self.events.append(("unknown_charref", ref))

    def unknown_entityref(self, ref):
        self.events.append(("unknown_entityref", ref))


class TestBasicParsing(unittest.TestCase):
    def setUp(self):
        self.p = RecordingParser()

    def test_plain_text(self):
        self.p.feed("hello world")
        self.p.close()
        self.assertEqual(self.p._gather_data(), "hello world")

    def test_simple_start_and_end_tag(self):
        self.p.feed("<p>text</p>")
        self.p.close()
        self.assertIn(("start", "p", []), self.p.events)
        self.assertIn(("data", "text"), self.p.events)
        self.assertIn(("end", "p"), self.p.events)

    def test_nested_tags(self):
        self.p.feed("<div><span>hello</span></div>")
        self.p.close()
        self.assertIn(("start", "div", []), self.p.events)
        self.assertIn(("start", "span", []), self.p.events)
        self.assertIn(("data", "hello"), self.p.events)
        self.assertIn(("end", "span"), self.p.events)
        self.assertIn(("end", "div"), self.p.events)

    def test_sgml_shorttag(self):
        # SGML shorthand: <tag/data/ == <tag>data</tag>
        self.p.feed("<br/data/")
        self.p.close()
        self.assertIn(("start", "br", []), self.p.events)
        self.assertIn(("data", "data"), self.p.events)
        self.assertIn(("end", "br"), self.p.events)

    def test_attributes(self):
        self.p.feed('<a href="/page" class="link">click</a>')
        self.p.close()
        start_events = [e for e in self.p.events if e[0] == "start"]
        self.assertEqual(len(start_events), 1)
        tag, attrs = start_events[0][1], start_events[0][2]
        self.assertEqual(tag, "a")
        self.assertIn(("href", "/page"), attrs)
        self.assertIn(("class", "link"), attrs)

    def test_entity_reference(self):
        self.p.feed("x &lt; y &amp; z")
        self.p.close()
        self.assertEqual(self.p._gather_data(), "x < y & z")

    def test_known_entityref_event(self):
        self.p.feed("&lt;")
        self.p.close()
        self.assertIn(("entityref", "lt"), self.p.events)

    def test_numeric_charref(self):
        self.p.feed("&#65;")
        self.p.close()
        self.assertEqual(self.p._gather_data(), "A")

    def test_comment(self):
        self.p.feed("a<!-- comment -->b")
        self.p.close()
        self.assertIn(("comment", " comment "), self.p.events)
        self.assertEqual(self.p._gather_data(), "ab")

    def test_doctype(self):
        self.p.feed("<!DOCTYPE html>text")
        self.p.close()
        # The DOCTYPE must be reported as a declaration event (proving it was
        # routed through parse_declaration, not mishandled as data) ...
        self.assertIn(("decl", "DOCTYPE html"), self.p.events)
        # ... and the trailing text must be the only data emitted.
        self.assertEqual(self.p._gather_data(), "text")

    def test_empty_input(self):
        self.p.feed("")
        self.p.close()
        self.assertEqual(len(self.p.events), 0)

    def test_feed_in_chunks(self):
        for ch in "<p>abc</p>":
            self.p.feed(ch)
        self.p.close()
        self.assertIn(("start", "p", []), self.p.events)
        self.assertIn(("end", "p"), self.p.events)
        self.assertEqual(self.p._gather_data(), "abc")

    def test_multiple_feeds(self):
        self.p.feed("<p>first</p>")
        self.p.feed("<p>second</p>")
        self.p.close()
        starts = [e for e in self.p.events if e[0] == "start"]
        self.assertEqual(len(starts), 2)
        self.assertEqual(self.p._gather_data(), "firstsecond")


class TestEntityConversion(unittest.TestCase):
    def test_convert_entityref_known(self):
        p = SGMLParser()
        self.assertEqual(p.convert_entityref("lt"), "<")
        self.assertEqual(p.convert_entityref("gt"), ">")
        self.assertEqual(p.convert_entityref("amp"), "&")
        self.assertEqual(p.convert_entityref("quot"), '"')
        self.assertEqual(p.convert_entityref("apos"), "'")

    def test_convert_entityref_unknown(self):
        p = SGMLParser()
        self.assertIsNone(p.convert_entityref("unknown"))

    def test_convert_charref_valid(self):
        p = SGMLParser()
        self.assertEqual(p.convert_charref("65"), "A")
        self.assertEqual(p.convert_charref("97"), "a")

    def test_convert_charref_invalid(self):
        p = SGMLParser()
        self.assertIsNone(p.convert_charref("notanumber"))
        self.assertIsNone(p.convert_charref("9999"))  # > 127

    def test_convert_codepoint(self):
        p = SGMLParser()
        self.assertEqual(p.convert_codepoint(65), "A")


class TestCustomEntitydefs(unittest.TestCase):
    def test_custom_entity(self):
        p = RecordingParser()
        p.entitydefs["copy"] = "\xa9"
        p.feed("&copy;")
        p.close()
        self.assertEqual(p._gather_data(), "\xa9")


class TestGetStarttagText(unittest.TestCase):
    def test_starttag_text(self):
        p = RecordingParser()
        p.feed("<div class='x'>text</div>")
        p.close()
        # get_starttag_text() must return the exact raw start-tag source,
        # verbatim including the original quoting -- not a normalized form.
        self.assertEqual(p.get_starttag_text(), "<div class='x'>")


class TestSetnomoretags(unittest.TestCase):
    def test_nomoretags(self):
        p = RecordingParser()
        p.setnomoretags()
        p.feed("<p>raw <b>text</b></p>")
        p.close()
        self.assertEqual(p._gather_data(), "<p>raw <b>text</b></p>")


class TestReset(unittest.TestCase):
    def test_reset_clears_parser_state(self):
        p = RecordingParser()
        p.feed("<p>hello</p>")
        # verify rawdata is cleared after close
        self.assertEqual(p.rawdata, "")
        p.reset()
        self.assertEqual(p.stack, [])
        self.assertEqual(p.lasttag, "???")


class TestVerbose(unittest.TestCase):
    # In this parser, `verbose` only gates the debug printing emitted by
    # report_unbalanced() (an unbalanced </tag> for which an end_<tag>
    # handler exists). So a meaningful test must trigger that path and
    # observe the difference on stdout.
    class _Parser(SGMLParser):
        def end_b(self):
            pass

    def _run(self, verbose):
        p = self._Parser()
        p.verbose = verbose
        _captured = []

        class _Cap(object):
            def write(self, s):
                _captured.append(s)

            def flush(self):
                pass

        _saved = sys.stdout
        sys.stdout = _Cap()
        try:
            p.feed("</b>")  # unbalanced end tag -> report_unbalanced()
            p.close()
        finally:
            sys.stdout = _saved
        return "".join(_captured)

    def test_verbose_mode_emits_debug(self):
        out = self._run(1)
        self.assertIn("*** Unbalanced </b>", out)
        self.assertIn("*** Stack:", out)

    def test_nonverbose_mode_is_silent(self):
        self.assertEqual(self._run(0), "")


class TestSGMLParseError(unittest.TestCase):
    def test_error_class(self):
        from lib.utils.sgmllib import SGMLParseError
        e = SGMLParseError("test")
        self.assertIsInstance(e, RuntimeError)


if __name__ == "__main__":
    unittest.main(verbosity=2)
