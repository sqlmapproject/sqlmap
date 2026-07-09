#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

D1 - structure-aware (JSON) detection oracle. Two layers:
  * jsonMinimize() (lib/core/common.py): the order-independent leaf-path projection.
  * comparison() (lib/request/comparison.py): when the response Content-Type is JSON, the
    similarity ratio is computed over that projection instead of raw text - so key
    reordering / whitespace noise no longer perturbs it (false-positive fix) and a small
    value/structure change is no longer drowned out in a large body (false-negative fix).

The headline tests assert the JSON path is *better* than the text path on the same inputs,
not merely that it runs; and that any non-JSON / unparseable / explicit-mode case falls
back to the exact text behavior (so the HTML oracle is untouched).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.common import jsonMinimize
from lib.core.data import conf, kb
from lib.core.enums import HTTP_HEADER
from lib.core.settings import UPPER_RATIO_BOUND
from lib.core.threads import getCurrentThreadData
from lib.request.comparison import comparison


class _Headers(object):
    """Minimal stand-in for the per-response headers object the oracle receives."""
    def __init__(self, contentType):
        self._ct = contentType

    def get(self, name, default=None):
        return self._ct if (self._ct and name.lower() == HTTP_HEADER.CONTENT_TYPE.lower()) else default

    @property
    def headers(self):
        return ["%s: %s\r\n" % (HTTP_HEADER.CONTENT_TYPE, self._ct)] if self._ct else []


class TestJsonMinimize(unittest.TestCase):
    def test_order_and_whitespace_immune(self):
        self.assertEqual(jsonMinimize('{"b":2,"a":1}'), jsonMinimize('{ "a": 1,\n  "b": 2 }'))

    def test_value_flip_differs(self):
        self.assertNotEqual(jsonMinimize('{"ok":true}'), jsonMinimize('{"ok":false}'))

    def test_array_length_registers(self):
        self.assertNotEqual(jsonMinimize('{"r":[1,2,3]}'), jsonMinimize('{"r":[1,2,3,4]}'))

    def test_parse_failure_is_none(self):
        for bad in ("", "{bad", "<html></html>", "{'a':1}", None):
            self.assertIsNone(jsonMinimize(bad))

    def test_valid_edge_shapes_are_not_none(self):
        # bare array, scalar, and top-level null are valid JSON -> defined (non-None) projections
        for ok in ("[1,2]", "42", "null", '"x"'):
            self.assertIsNotNone(jsonMinimize(ok))
        self.assertEqual(jsonMinimize("{}"), "")   # empty object -> empty projection (not None)


class _OracleCase(unittest.TestCase):
    _FLAGS = ("string", "notString", "regexp", "code", "titles", "textOnly")
    _KB = ("matchRatio", "nullConnection", "heavilyDynamic", "skipSeqMatcher",
           "errorIsNone", "negativeLogic", "dynamicMarkings", "testMode", "pageTemplate")

    def setUp(self):
        self._c = dict((k, conf.get(k)) for k in self._FLAGS)
        self._k = dict((k, kb.get(k)) for k in self._KB)
        for k in self._FLAGS:
            conf[k] = None
        kb.nullConnection = kb.heavilyDynamic = kb.skipSeqMatcher = kb.errorIsNone = kb.negativeLogic = kb.testMode = False
        kb.dynamicMarkings = []

    def tearDown(self):
        for k, v in self._c.items():
            conf[k] = v
        for k, v in self._k.items():
            kb[k] = v

    def ratio(self, template, page, contentType):
        # fresh, uncalibrated comparison each call
        kb.matchRatio = None
        kb.pageTemplate = template
        td = getCurrentThreadData()
        td.lastPageTemplate = None
        return comparison(page, _Headers(contentType), getRatioValue=True)


class TestStructuredOracle(_OracleCase):
    def test_noise_immunity_beats_text(self):
        # same data, keys reordered + reindented: JSON path ~identical, text path measurably lower.
        # This is D1's core win - reorder/whitespace noise (ubiquitous in real APIs) stops
        # perturbing the ratio, which also stabilizes the kb.matchRatio calibration.
        a = '{"id":1,"name":"alice","role":"admin"}'
        b = '{ "role": "admin",\n  "name": "alice",\n  "id": 1 }'
        jsonRatio = self.ratio(a, b, "application/json")
        textRatio = self.ratio(a, b, "text/html")
        self.assertGreater(jsonRatio, UPPER_RATIO_BOUND)        # JSON: noise ignored -> True
        self.assertLess(textRatio, jsonRatio)                   # text: perturbed by reordering

    def test_real_difference_still_detected(self):
        # normalization must not over-collapse: a genuinely different value still separates
        a = '{"role":"admin"}'
        b = '{"role":"guest"}'
        self.assertLess(self.ratio(a, b, "application/json"), UPPER_RATIO_BOUND)

    def test_html_contenttype_uses_text_path(self):
        # identical inputs through a text/html response must equal the pure text baseline
        a = '{"id":1,"name":"alice"}'
        b = '{ "name": "alice", "id": 1 }'
        conf.code = None
        self.assertEqual(self.ratio(a, b, "text/html"), self.ratio(a, b, None))

    def test_unparseable_json_falls_back(self):
        # application/json Content-Type but a non-JSON body -> behaves exactly like the text path
        a, b = "<html>x</html>", "<html>y</html>"
        self.assertEqual(self.ratio(a, b, "application/json"), self.ratio(a, b, "text/html"))

    def test_structured_suffix_contenttype_gated_in(self):
        a = '{"id":1,"name":"alice","role":"admin"}'
        b = '{ "role":"admin", "name":"alice", "id":1 }'
        self.assertGreater(self.ratio(a, b, "application/vnd.api+json; charset=utf-8"), UPPER_RATIO_BOUND)

    def test_textonly_escape_hatch_bypasses_json(self):
        a = '{"id":1,"name":"alice"}'
        b = '{ "name":"alice", "id":1 }'
        withJson = self.ratio(a, b, "application/json")
        conf.textOnly = True
        withoutJson = self.ratio(a, b, "application/json")
        self.assertGreater(withJson, withoutJson)               # --text-only opts out of the JSON path


if __name__ == "__main__":
    unittest.main()
