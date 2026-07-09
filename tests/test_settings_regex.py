#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Compiled-regex battery for lib/core/settings.py.

settings.py defines ~40 module-level *_REGEX patterns that drive WAF/error/
charset/IP/title detection. A bad edit to any one of them is a silent failure
(detection just stops firing). This compiles them all and pins the behavior of
the high-traffic detection patterns with positive + negative cases.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import lib.core.settings as S
from lib.core.common import extractRegexResult


class TestAllRegexesCompile(unittest.TestCase):
    def test_every_regex_constant_compiles(self):
        names = [n for n in dir(S) if n.endswith("_REGEX")]
        self.assertGreater(len(names), 20, msg="expected many *_REGEX constants")
        failures = []
        for name in names:
            value = getattr(S, name)
            if isinstance(value, str):
                # some carry a single %s placeholder (e.g. SENSITIVE_DATA_REGEX) - fill it before compiling
                candidate = value.replace("%s", "X") if "%s" in value else value
                try:
                    re.compile(candidate)
                except re.error as ex:
                    failures.append("%s: %s" % (name, ex))
        self.assertEqual(failures, [], msg="non-compiling regexes: %s" % failures)


class TestDetectionPatterns(unittest.TestCase):
    def test_ip_address(self):
        self.assertTrue(re.search(S.IP_ADDRESS_REGEX, "connect to 192.168.0.1 now"))
        self.assertFalse(re.search(S.IP_ADDRESS_REGEX, "999.999.999.999"))

    def test_permission_denied(self):
        self.assertEqual(extractRegexResult(S.PERMISSION_DENIED_REGEX, "access denied for user 'x'"),
                         "access denied")

    def test_parameter_splitting(self):
        self.assertEqual(re.split(S.PARAMETER_SPLITTING_REGEX, "a,b;c|d"), ["a", "b", "c", "d"])

    def test_html_title(self):
        self.assertEqual(extractRegexResult(S.HTML_TITLE_REGEX, "<title>Hello</title>"), "Hello")
        # case-insensitive tag, first-of-two wins, empty/absent -> None (probed)
        self.assertEqual(extractRegexResult(S.HTML_TITLE_REGEX, "<TITLE>x</TITLE>"), "x")
        self.assertEqual(extractRegexResult(S.HTML_TITLE_REGEX, "<title>A</title><title>B</title>"), "A")
        self.assertIsNone(extractRegexResult(S.HTML_TITLE_REGEX, "<title></title>"))
        self.assertIsNone(extractRegexResult(S.HTML_TITLE_REGEX, "no title here"))

if __name__ == "__main__":
    unittest.main(verbosity=2)
