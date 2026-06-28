#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Request-body injection-point handling:
 - recognition regexes (REAL, imported from settings) classify JSON/JSON_LIKE/XML/PLAIN
 - JSON/XML injection-point marking preserves every value (mirrors target.py)
 - HPP transform reconstructs the original SQL after ASP comma-join
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.settings import (JSON_RECOGNITION_REGEX, JSON_LIKE_RECOGNITION_REGEX,
                               XML_RECOGNITION_REGEX, PAYLOAD_DELIMITER,
                               CUSTOM_INJECTION_MARK_CHAR)

# The real source marks injection points with kb.customInjectionMark, which defaults to
# CUSTOM_INJECTION_MARK_CHAR ('*'). Tie the test's mark char to the source constant so a
# change there is reflected here too.
MARK = CUSTOM_INJECTION_MARK_CHAR


def classify(d):
    if re.search(JSON_RECOGNITION_REGEX, d):
        return "JSON"
    if re.search(JSON_LIKE_RECOGNITION_REGEX, d):
        return "JSON_LIKE"
    if re.search(XML_RECOGNITION_REGEX, d):
        return "XML"
    return "PLAIN"


def _drive_request_marking(body):
    """Run sqlmap's REAL request-body injection-point marking on `body`.

    Approach (a): drive the genuine code path in lib.core.target._setRequestParams()
    (the same function the CLI uses) with a minimal conf/kb state, a POST body, and
    readInput auto-answering 'Y'. The marking regexes (target.py:159-215) run against
    `conf.data`; the fully-marked string is the snapshot of conf.data carrying the most
    injection marks, captured BEFORE the later strip (target.py:~348) removes them.

    Returns (fully_marked_data, kb.postHint). A regression in the source marking regexes
    changes this output and breaks the asserting tests.
    """
    import lib.core.target as target
    from lib.core.data import conf, kb
    from lib.core.enums import HTTPMETHOD

    snapshots = []
    base = type(conf)
    orig_setitem = base.__setitem__

    def _record(self, key, value):
        if key == "data" and isinstance(value, str):
            snapshots.append(value)
        orig_setitem(self, key, value)

    orig_readInput = target.readInput
    target.readInput = lambda *a, **k: 'Y'
    base.__setitem__ = _record
    try:
        conf.parameters = {}
        conf.paramDict = {}
        conf.direct = False
        conf.method = HTTPMETHOD.POST
        conf.url = "http://test.invalid/"
        conf.cookie = None
        conf.httpHeaders = []
        conf.testParameter = None
        conf.forms = None
        conf.crawlDepth = None
        kb.processUserMarks = None
        kb.postHint = None
        kb.customInjectionMark = MARK
        kb.testOnlyCustom = False
        conf.data = body
        target._setRequestParams()
        postHint = kb.postHint
    finally:
        base.__setitem__ = orig_setitem
        target.readInput = orig_readInput

    fully_marked = max(snapshots, key=lambda s: s.count(MARK))
    return fully_marked, postHint


class TestRecognitionRegexes(unittest.TestCase):
    CASES = [
        ('{"id":1}',           "JSON"),
        ('{"a":"b"}',          "JSON"),
        ('{"n":1,"m":"s"}',    "JSON"),
        ('[{"id":1}]',         "JSON"),
        ('[{"id":1},{"id":2}]', "JSON"),
        ("{'a':'b'}",          "JSON_LIKE"),
        ("<a>1</a>",           "XML"),
        ("<soap:Body><q>1</q></soap:Body>", "XML"),
        ("<ns:tag attr='x'>v</ns:tag>",     "XML"),
        ("id=1&x=2",           "PLAIN"),
        ("just text",          "PLAIN"),
    ]

    def test_classification(self):
        for body, expected in self.CASES:
            self.assertEqual(classify(body), expected, msg="classify(%r)" % body)


class TestJsonMarking(unittest.TestCase):
    # Approach (a): exercises the REAL JSON injection-point marking in
    # lib.core.target._setRequestParams() (target.py:159-162) via _drive_request_marking().
    # No source logic is copied into the test; a regression in the source regexes fails it.
    @staticmethod
    def mark(data):
        marked, postHint = _drive_request_marking(data)
        assert postHint == "JSON", "expected JSON postHint, got %r for %r" % (postHint, data)
        return marked

    CASES = [
        ('{"id":1}',            '{"id":1*}'),
        ('{"name":"abc"}',      '{"name":"abc*"}'),
        ('{"a":{"b":"1"}}',     '{"a":{"b":"1*"}}'),
        ('{"empty":""}',        '{"empty":"*"}'),
        ('{"b":true,"n":null}', '{"b":true*,"n":null*}'),
        ('{"a":"x","b":"y"}',   '{"a":"x*","b":"y*"}'),
        ('{"url":"http://h:8080/p"}', '{"url":"http://h:8080/p*"}'),
    ]

    def test_cases(self):
        for inp, expected in self.CASES:
            self.assertEqual(self.mark(inp), expected, msg="mark(%r)" % inp)

    def test_value_preserved_property(self):
        # marking must not delete/garble the original value characters
        for inp, _ in self.CASES:
            out = self.mark(inp)
            self.assertEqual(out.replace(MARK, ""), inp, msg="marking altered %r" % inp)


class TestXmlMarking(unittest.TestCase):
    # Approach (a): exercises the REAL SOAP/XML injection-point marking in
    # lib.core.target._setRequestParams() (target.py:215) via _drive_request_marking().
    # A regression in the source XML regex fails this test.
    def mark(self, data):
        from lib.core.enums import POST_HINT
        marked, postHint = _drive_request_marking(data)
        self.assertIn(postHint, (POST_HINT.XML, POST_HINT.SOAP),
                      msg="expected XML/SOAP postHint, got %r for %r" % (postHint, data))
        return marked

    CASES = [
        ("<a>x</a>",                                 "<a>x*</a>"),
        ('<a id="1">x</a>',                          '<a id="1">x*</a>'),
        ("<user><name>bob</name><id>5</id></user>",  "<user><name>bob*</name><id>5*</id></user>"),
        ("<ns:tag>v</ns:tag>",                       "<ns:tag>v*</ns:tag>"),
        ("<soap:Body><q>1</q></soap:Body>",          "<soap:Body><q>1*</q></soap:Body>"),
    ]

    def test_cases(self):
        for inp, expected in self.CASES:
            self.assertEqual(self.mark(inp), expected, msg="xmlmark(%r)" % inp)


def _drive_hpp(payload, name="id"):
    """Run sqlmap's REAL HTTP-parameter-pollution payload reconstruction on `payload`.

    Approach (a): drive the genuine HPP block inside lib.request.connect.Connect.queryPage()
    (connect.py:1168-1192) -- the same method the engine uses to issue every request -- with
    conf.hpp enabled and a GET value carrying the payload between PAYLOAD_DELIMITERs.
    conf.skipUrlEncode is set so the unencoded splitter branch runs (matching the pinned
    expected strings). queryPage's network call (agent.removePayloadDelimiters, invoked
    immediately AFTER the HPP block) is hijacked to capture the transformed `value` and abort
    before any I/O; the payload is then extracted from between the delimiters. A regression in
    the source HPP logic changes this output and breaks the asserting tests.
    """
    from lib.core.data import conf, kb
    from lib.core.enums import PLACE
    from lib.core.agent import agent
    from lib.request.connect import Connect

    class _Sentinel(Exception):
        pass

    captured = {}

    def _capture(value):
        captured["value"] = value
        raise _Sentinel()

    orig_remove = agent.removePayloadDelimiters
    agent.removePayloadDelimiters = _capture
    try:
        conf.direct = False
        conf.hpp = True
        conf.method = "GET"
        conf.paramDel = None
        conf.skipUrlEncode = True
        conf.url = "http://test.invalid/page.asp?%s=1" % name
        kb.postUrlEncode = False
        kb.tamperFunctions = []
        kb.postSpaceToPlus = False
        value = "%s=%s%s%s" % (name, PAYLOAD_DELIMITER, payload, PAYLOAD_DELIMITER)
        try:
            _qp = getattr(Connect.queryPage, "__func__", Connect.queryPage)
            _qp(value=value, place=PLACE.GET, disableTampering=True)
        except _Sentinel:
            pass
    finally:
        agent.removePayloadDelimiters = orig_remove

    _ = re.escape(PAYLOAD_DELIMITER)
    return re.search(r"(?s)%s(?P<result>.*?)%s" % (_, _), captured["value"]).group("result")


class TestHppReconstruction(unittest.TestCase):
    # Approach (a): drives the REAL HPP reconstruction (connect.py:1168-1192) via _drive_hpp().

    def hpp(self, payload, name="id"):
        return _drive_hpp(payload, name)

    # Exact transform outputs (verified live against an ASP-style join). We pin the produced
    # string rather than "reconstruct the SQL", because reconstruction depends on the SQL parser
    # treating /* */ as a token separator (1/*,*/AND -> "1 AND"), which a string compare can't model.
    CASES = [
        ("1",            "1"),
        ("1 AND 2=2",    "1/*&id=*/AND/*&id=*/2=2"),
        ("1 AND 'a'='a'", "1/*&id=*/AND/*&id=*/'a'='a'"),
    ]

    def test_exact_outputs(self):
        for payload, expected in self.CASES:
            self.assertEqual(self.hpp(payload), expected, msg="hpp(%r)" % payload)

    def test_balanced_comments(self):
        # every /* must have a matching */ (no dangling comment bridge)
        for payload in ["1 UNION SELECT a,b", "1 AND 2=2 OR 3=3", "x y z"]:
            out = self.hpp(payload)
            self.assertEqual(out.count("/*"), out.count("*/"), msg="unbalanced comments for %r" % payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
