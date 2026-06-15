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
                               XML_RECOGNITION_REGEX, PAYLOAD_DELIMITER, DEFAULT_GET_POST_DELIMITER)

MARK = "*"


def classify(d):
    if re.search(JSON_RECOGNITION_REGEX, d):
        return "JSON"
    if re.search(JSON_LIKE_RECOGNITION_REGEX, d):
        return "JSON_LIKE"
    if re.search(XML_RECOGNITION_REGEX, d):
        return "XML"
    return "PLAIN"


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
    # mirrors target.py:159-162 JSON injection-point marking
    @staticmethod
    def mark(data):
        data = re.sub(r'("(?P<name>[^"]+)"\s*:\s*".*?)"(?<!\\")', r'\g<1>%s"' % MARK, data)
        data = re.sub(r'("(?P<name>[^"]+)"\s*:\s*")"', r'\g<1>%s"' % MARK, data)
        data = re.sub(r'("(?P<name>[^"]+)"\s*:\s*)(-?\d[\d\.]*)\b', r'\g<1>\g<3>%s' % MARK, data)
        data = re.sub(r'("(?P<name>[^"]+)"\s*:\s*)((true|false|null))\b', r'\g<1>\g<3>%s' % MARK, data)
        return data

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
    RX = r"(<(?P<name>[^>]+)( [^<]*)?>)([^<]+)(</\2)"

    def mark(self, data):
        return re.sub(self.RX, r"\g<1>\g<4>%s\g<5>" % MARK, data)

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


class TestHppReconstruction(unittest.TestCase):
    # mirrors connect.py:1171-1187 HPP splitting
    def hpp(self, payload, name="id"):
        from thirdparty.six.moves import urllib as _urllib  # py2+py3
        quote = _urllib.parse.quote

        def ue(s):
            try:
                return quote(s)
            except Exception:
                return s
        value = "%s=%s%s%s" % (name, PAYLOAD_DELIMITER, payload, PAYLOAD_DELIMITER)
        _ = re.escape(PAYLOAD_DELIMITER)
        match = re.search(r"(?P<name>\w+)=%s(?P<value>.+?)%s" % (_, _), value)
        out = match.group("value")
        for splitter in (ue(' '), ' '):
            if splitter in out:
                prefix, suffix = ("*/", "/*") if splitter == ' ' else (ue(x) for x in ("*/", "/*"))
                parts = out.split(splitter)
                parts[0] = "%s%s" % (parts[0], suffix)
                parts[-1] = "%s%s=%s%s" % (DEFAULT_GET_POST_DELIMITER, match.group("name"), prefix, parts[-1])
                for i in range(1, len(parts) - 1):
                    parts[i] = "%s%s=%s%s%s" % (DEFAULT_GET_POST_DELIMITER, match.group("name"), prefix, parts[i], suffix)
                out = "".join(parts)
        for splitter in (ue(','), ','):
            out = out.replace(splitter, "%s%s=" % (DEFAULT_GET_POST_DELIMITER, match.group("name")))
        return out

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
