#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Offline, deterministic tests for the XXE injection engine. Pure helpers are exercised
directly; detection tiers run against a mocked _send() so reflected/error/echo oracles
can be simulated without a live target; and crafted payloads are parsed with real lxml
to prove they are well-formed and actually expand the injected entity.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import lib.techniques.xxe.inject as xxe
from lib.core.data import conf
from lib.core.data import kb


class TestLooksXmlAndClean(unittest.TestCase):
    def test_looks_xml(self):
        self.assertTrue(xxe._looksXml("<user><name>x</name></user>"))
        self.assertTrue(xxe._looksXml("  <?xml version='1.0'?><r/>"))
        self.assertFalse(xxe._looksXml("id=1&name=x"))
        self.assertFalse(xxe._looksXml("{\"a\": 1}"))
        self.assertFalse(xxe._looksXml(""))

    def test_clean_body_strips_marks_and_bom(self):
        conf.data = u"\ufeff<user><name>luther%s</name></user>" % (kb.customInjectionMark or "*")
        cleaned = xxe._cleanBody()
        self.assertFalse(cleaned.startswith(u"\ufeff"))
        self.assertNotIn(kb.customInjectionMark or "*", cleaned)
        self.assertTrue(cleaned.startswith("<user>"))


class TestRootName(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(xxe._rootName("<user><name>x</name></user>"), "user")

    def test_with_prolog_and_comment(self):
        self.assertEqual(xxe._rootName("<?xml version='1.0'?><!-- hi --><order id='1'>x</order>"), "order")

    def test_namespaced(self):
        self.assertEqual(xxe._rootName('<soap:Envelope xmlns:soap="x"><b/></soap:Envelope>'), "soap:Envelope")

    def test_existing_doctype_skipped(self):
        self.assertEqual(xxe._rootName('<!DOCTYPE user SYSTEM "u.dtd"><user/>'), "user")


class TestBuildDoctype(unittest.TestCase):
    SUBSET = '<!ENTITY x "y">'

    def test_no_doctype_prepended(self):
        out = xxe._buildDoctype("<r>x</r>", "r", self.SUBSET)
        self.assertIn("<!DOCTYPE r [", out)
        self.assertIn(self.SUBSET, out)

    def test_after_prolog(self):
        out = xxe._buildDoctype("<?xml version='1.0'?><r>x</r>", "r", self.SUBSET)
        self.assertLess(out.index("<?xml"), out.index("<!DOCTYPE"))

    def test_existing_internal_subset_spliced(self):
        out = xxe._buildDoctype("<!DOCTYPE r [<!ELEMENT r ANY>]><r>x</r>", "r", self.SUBSET)
        self.assertEqual(out.count("<!DOCTYPE"), 1)   # no second DOCTYPE
        self.assertIn(self.SUBSET, out)

    def test_subsetless_doctype_extended(self):
        out = xxe._buildDoctype('<!DOCTYPE r SYSTEM "r.dtd"><r>x</r>', "r", self.SUBSET)
        self.assertEqual(out.count("<!DOCTYPE"), 1)   # extended, not duplicated
        self.assertIn(self.SUBSET, out)
        self.assertIn("[", out)


class TestPlaceRef(unittest.TestCase):
    def test_all_text_nodes(self):
        out = xxe._placeRef("<p><a>one</a><b>two</b></p>", "&e;")
        self.assertEqual(out.count("&e;"), 2)
        self.assertNotIn("one", out)
        self.assertNotIn("two", out)

    def test_attributes_only_when_requested(self):
        text = '<u id="1"><n>luther</n></u>'
        self.assertNotIn('id="&e;"', xxe._placeRef(text, "&e;"))            # attrs off by default
        self.assertIn('id="&e;"', xxe._placeRef(text, "&e;", attrs=True))   # attrs on

    def test_xmlns_preserved(self):
        out = xxe._placeRef('<soap:E xmlns:soap="ns"><b>x</b></soap:E>', "&e;", attrs=True)
        self.assertIn('xmlns:soap="ns"', out)   # namespace decl untouched

    def test_self_closing_fallback(self):
        out = xxe._placeRef("<r/>", "&e;")
        self.assertIn("&e;", out)
        self.assertIn("</r>", out)

    def test_empty_element_fallback(self):
        out = xxe._placeRef("<r></r>", "&e;")
        self.assertIn("<r>&e;</r>", out)


class TestGuards(unittest.TestCase):
    def test_echoed(self):
        self.assertTrue(xxe._echoed("... <!DOCTYPE r [ ... "))
        self.assertTrue(xxe._echoed("mirror <!ENTITY x ..."))
        self.assertFalse(xxe._echoed("Hello, expanded value!"))

    def test_fingerprint(self):
        self.assertIsNotNone(xxe._fingerprint('failed to load external entity "file:///x"'))
        self.assertIsNotNone(xxe._fingerprint('failed to load "file:///x": No such file'))  # PHP form
        self.assertIsNotNone(xxe._fingerprint("org.xml.sax.SAXParseException: DOCTYPE"))
        self.assertIsNone(xxe._fingerprint("perfectly normal response"))

    def test_confirm_read_baseline_guard(self):
        pattern = r"(?i)^(?:NAME|ID|VERSION)="
        page = "content:\nNAME=\"Ubuntu\"\nID=ubuntu"
        self.assertIsNotNone(xxe._confirmRead(page, pattern, baseline="unrelated"))
        # a line already present in the baseline must not count as a read
        self.assertIsNone(xxe._confirmRead("NAME=\"Ubuntu\"", pattern, baseline="NAME=\"Ubuntu\""))


class TestOobToggle(unittest.TestCase):
    def test_oob_enabled_default(self):
        conf.oobServer = None
        self.assertTrue(xxe._oobEnabled())

    def test_oob_disabled_sentinels(self):
        for sentinel in ("none", "off", "0", "No", "DISABLE", "false"):
            conf.oobServer = sentinel
            self.assertFalse(xxe._oobEnabled(), "'%s' should disable OOB" % sentinel)
        conf.oobServer = None

    def test_oob_custom_server_enabled(self):
        conf.oobServer = "myinteractsh.example.com"
        self.assertTrue(xxe._oobEnabled())
        conf.oobServer = None


class TestDetectionMocked(unittest.TestCase):
    def setUp(self):
        self._send = xxe._send
        xxe.SENTINEL = "sentineltoken1"

    def tearDown(self):
        xxe._send = self._send

    def test_internal_reflected_positive(self):
        xxe._send = lambda body: "Hello, %s! (parsed)" % xxe.SENTINEL
        payload, _ = xxe._tryInternal("<u><n>luther</n></u>", "u", baseline="Hello, luther!")
        self.assertIsNotNone(payload)

    def test_internal_echo_rejected(self):
        # endpoint mirrors the raw body back (never parses) -> must NOT be a hit
        xxe._send = lambda body: "You sent: %s" % body
        payload, _ = xxe._tryInternal("<u><n>luther</n></u>", "u", baseline="You sent: <u><n>luther</n></u>")
        self.assertIsNone(payload)

    def test_internal_baseline_contains_sentinel_rejected(self):
        xxe._send = lambda body: "Hello, %s!" % xxe.SENTINEL
        payload, _ = xxe._tryInternal("<u><n>luther</n></u>", "u", baseline="already %s here" % xxe.SENTINEL)
        self.assertIsNone(payload)

    def test_error_based_positive(self):
        xxe._send = lambda body: 'XML error: failed to load external entity "file:///%s/nonexistent"' % xxe.SENTINEL
        payload, page = xxe._tryError("<u><n>x</n></u>", "u")
        self.assertIsNotNone(payload)
        self.assertIsNotNone(xxe._fingerprint(page))

    def test_error_based_echo_rejected(self):
        xxe._send = lambda body: "You sent: %s" % body   # echoes DOCTYPE/ENTITY -> _echoed guard
        payload, _ = xxe._tryError("<u><n>x</n></u>", "u")
        self.assertIsNone(payload)

    def test_error_exfil_extraction_base64(self):
        import base64
        from lib.core.convert import getText
        secret = getText(base64.b64encode(b"root:x:0:0:root:/root:/bin/sh"))

        def mock(body):
            m = re.search(r'file:///(\w+)/&#x25;file;', body) or re.search(r'file:///(\w+)/%file;', body)
            marker = m.group(1) if m else "zzz"
            return 'failed to load "file:///%s/%s"' % (marker, secret)

        xxe._send = mock
        conf.fileRead = "/etc/passwd"
        try:
            content, name = xxe._tryErrorExfil("<u><n>x</n></u>", "u")
        finally:
            conf.fileRead = None
        self.assertEqual(name, "/etc/passwd")
        self.assertIn("root:x:0:0", content or "")


class TestRealXmlPayloads(unittest.TestCase):
    """Prove crafted payloads are well-formed and actually expand the entity."""

    @staticmethod
    def _expand(payload):
        try:
            from lxml import etree
        except ImportError:
            raise unittest.SkipTest("lxml not available")
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True, huge_tree=False)
        doc = etree.fromstring(payload.encode("utf-8"), parser)
        return "".join(doc.itertext())

    def test_internal_entity_expands(self):
        xxe.SENTINEL = "realxmlsentinel"
        ent = "abcd"
        subset = '<!ENTITY %s "%s">' % (ent, xxe.SENTINEL)
        payload = xxe._placeRef(xxe._buildDoctype("<u><n>luther</n></u>", "u", subset), "&%s;" % ent)
        self.assertIn(xxe.SENTINEL, self._expand(payload))

    def test_internal_entity_expands_with_existing_doctype(self):
        xxe.SENTINEL = "realxmlsentinel2"
        ent = "efgh"
        subset = '<!ENTITY %s "%s">' % (ent, xxe.SENTINEL)
        base = '<?xml version="1.0"?><!DOCTYPE u [<!ELEMENT n ANY>]><u><n>luther</n></u>'
        payload = xxe._placeRef(xxe._buildDoctype(base, "u", subset), "&%s;" % ent)
        self.assertIn(xxe.SENTINEL, self._expand(payload))

    def test_attribute_entity_expands(self):
        xxe.SENTINEL = "attrsentinel"
        ent = "ijkl"
        subset = '<!ENTITY %s "%s">' % (ent, xxe.SENTINEL)
        payload = xxe._placeRef(xxe._buildDoctype('<u id="1"><n>x</n></u>', "u", subset), "&%s;" % ent, attrs=True)
        self.assertIn(xxe.SENTINEL, self._expand(payload))


if __name__ == "__main__":
    unittest.main()
