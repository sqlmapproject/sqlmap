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

    def test_existing_internal_subset_with_gt_in_entity_value(self):
        # a '>' inside a quoted entity value must not fool the internal-subset splice
        out = xxe._buildDoctype('<!DOCTYPE r [<!ENTITY a "x>y">]><r>z</r>', "r", self.SUBSET)
        self.assertEqual(out.count("<!DOCTYPE"), 1)
        self.assertIn(self.SUBSET, out)

    def test_existing_external_subset(self):
        out = xxe._buildDoctype('<!DOCTYPE r SYSTEM "http://x/r.dtd"><r>z</r>', "r", self.SUBSET)
        self.assertEqual(out.count("<!DOCTYPE"), 1)
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

    def test_echoed_escaped_forms(self):
        # a debug endpoint that reflects the body in escaped form is still an echo
        self.assertTrue(xxe._echoed("You sent: &lt;!DOCTYPE r [&lt;!ENTITY e ..."))   # HTML-entity
        self.assertTrue(xxe._echoed("You sent: %3C!ENTITY e ..."))                     # percent-encoded
        self.assertTrue(xxe._echoed("You sent: &#x3c;!DOCTYPE ..."))                   # hex numeric
        self.assertTrue(xxe._echoed("json {\\u003c!ENTITY e ...}"))                    # JSON \\u escape
        self.assertFalse(xxe._echoed("result: sentineltoken1"))                        # pure expanded value

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


class TestOobConsent(unittest.TestCase):
    """No third-party OOB without explicit opt-in: --oob-server none disables it,
    an explicit server opts in, and an unset server under --batch defaults to NO."""

    def setUp(self):
        self._batch = conf.get("batch")
        conf.batch = True
        xxe._OOB_CONSENT = None

    def tearDown(self):
        conf.batch = self._batch
        conf.oobServer = None
        xxe._OOB_CONSENT = None

    def test_none_denies(self):
        conf.oobServer = "none"
        self.assertFalse(xxe._oobConsent())

    def test_explicit_server_opts_in(self):
        conf.oobServer = "my.interactsh.example"
        self.assertTrue(xxe._oobConsent())

    def test_unset_under_batch_defaults_no(self):
        conf.oobServer = None
        self.assertFalse(xxe._oobConsent())   # readInput returns the 'N' default under --batch


class TestPathNorm(unittest.TestCase):
    def test_unix(self):
        self.assertEqual(xxe._toSystemId("/etc/passwd"), "file:///etc/passwd")
        self.assertEqual(xxe._toResource("/etc/passwd"), "/etc/passwd")

    def test_windows(self):
        self.assertEqual(xxe._toSystemId("C:\\Windows\\win.ini"), "file:///C:/Windows/win.ini")
        self.assertEqual(xxe._toResource("C:\\Windows\\win.ini"), "C:/Windows/win.ini")

    def test_already_uri(self):
        self.assertEqual(xxe._toSystemId("file:///etc/passwd"), "file:///etc/passwd")
        self.assertEqual(xxe._toSystemId("php://filter/x"), "php://filter/x")
        self.assertEqual(xxe._toResource("file:///etc/passwd"), "/etc/passwd")


class TestMarkerHonored(unittest.TestCase):
    def tearDown(self):
        xxe._MARKER = None

    def test_place_ref_honors_marker(self):
        xxe._MARKER = "xxemarkzzzz"
        out = xxe._placeRef("<u><n>xxemarkzzzz</n><m>other</m></u>", "&e;")
        self.assertIn("<n>&e;</n>", out)
        self.assertIn("<m>other</m>", out)          # other node left intact
        self.assertNotIn("xxemarkzzzz", out)

    def test_clean_body_sets_marker_on_user_marks(self):
        conf.data = "<u><n>luther%s</n></u>" % (kb.customInjectionMark or "*")
        kb.processUserMarks = True
        try:
            cleaned = xxe._cleanBody()
            self.assertIsNotNone(xxe._MARKER)
            self.assertIn(xxe._MARKER, cleaned)
        finally:
            kb.processUserMarks = False
            xxe._MARKER = None


class TestReportMethod(unittest.TestCase):
    def test_report_uses_conf_method(self):
        captured = []

        class _Dumper(object):
            def singleString(self, data, content_type=None):
                captured.append(data)

        old_dumper, old_method, old_beep = conf.get("dumper"), conf.get("method"), conf.get("beep")
        conf.dumper, conf.method, conf.beep = _Dumper(), "PUT", False
        try:
            xxe._report("Title", "Payload")
        finally:
            conf.dumper, conf.method, conf.beep = old_dumper, old_method, old_beep
        self.assertIn("Parameter: XML body (PUT)", captured[0])


class TestHarvestFiles(unittest.TestCase):
    def test_harvest_collects_dedups_and_skips_empty(self):
        # simulate a target that returns real content for two files, an empty read for
        # one (skipped), and an identical stub for the rest (deduped to a single entry)
        def _fake(xml, rootName, path):
            if path == "/etc/passwd":
                return "root:x:0:0:root:/root:/bin/sh\n", "PAYLOAD-passwd"
            if path == "/etc/hostname":
                return "host01\n", "PAYLOAD-hostname"
            if path == "/etc/hosts":
                return "   ", "PAYLOAD-empty"   # whitespace-only -> skipped
            return "same stub", "PAYLOAD-stub"  # identical for every other path -> deduped

        old = xxe._tryInbandFileRead
        xxe._tryInbandFileRead = _fake
        try:
            harvested = xxe._harvestFiles("<user><name>x</name></user>", "user")
        finally:
            xxe._tryInbandFileRead = old

        paths = [p for p, _, _ in harvested]
        self.assertIn("/etc/passwd", paths)
        self.assertIn("/etc/hostname", paths)
        self.assertNotIn("/etc/hosts", paths)          # empty read skipped
        self.assertEqual(paths.count("/etc/passwd"), 1)
        self.assertEqual(sum(1 for c in (c for _, c, _ in harvested) if c == "same stub"), 1)  # stub deduped


class TestOobBase64Capture(unittest.TestCase):
    def test_path_capture_survives_plus_slash_equals(self):
        import base64
        from lib.core.convert import getText, decodeBase64
        marker = "mk12345678"
        raw = b">>>\xff\xfe some + / = data =="
        blob = getText(base64.b64encode(raw))
        self.assertTrue(any(c in blob for c in "+/="))   # ensure the risky chars are present
        url = "http://webhook.site/tok/%s/%s" % (marker, blob)   # base64 in the PATH
        m = re.search(r"/%s/([A-Za-z0-9+/=]+)" % re.escape(marker), url)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), blob)
        self.assertEqual(decodeBase64(m.group(1)), raw)


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
