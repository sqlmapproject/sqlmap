#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

The true/false/None response oracle (lib/request/comparison.py).

The seqMatcher ratio path needs a live page template and is intentionally left
to --vuln. What IS pure and worth pinning here is the short-circuit decision
table: --string / --not-string / --regexp / --code matching, and the _adjust()
negative-logic flip. These are the rules that decide whether a payload counts
as True, and they are easy to break with a refactor.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.request.comparison import comparison, _adjust
from lib.core.common import removeReflectiveValues
from lib.core.settings import REFLECTED_VALUE_MARKER
from lib.core.data import conf, kb


def _reset_match_conf():
    conf.string = conf.notString = conf.regexp = conf.code = None


class TestStringMatch(unittest.TestCase):
    def setUp(self):
        _reset_match_conf()
        kb.negativeLogic = False

    def tearDown(self):
        _reset_match_conf()

    def test_string_present_is_true(self):
        conf.string = "WELCOME"
        self.assertTrue(comparison("xx WELCOME yy", None, code=200))

    def test_string_absent_is_false(self):
        conf.string = "WELCOME"
        self.assertFalse(comparison("nothing here", None, code=200))


class TestRegexpMatch(unittest.TestCase):
    def setUp(self):
        _reset_match_conf()
        kb.negativeLogic = False

    def tearDown(self):
        _reset_match_conf()

    def test_regexp_match_is_true(self):
        conf.regexp = "id=\\d+"
        self.assertTrue(comparison("user id=42 ok", None, code=200))

    def test_regexp_nomatch_is_false(self):
        conf.regexp = "id=\\d+"
        self.assertFalse(comparison("user name", None, code=200))


class TestCodeMatch(unittest.TestCase):
    def setUp(self):
        _reset_match_conf()
        kb.negativeLogic = False

    def tearDown(self):
        _reset_match_conf()

    def test_code_match_is_true(self):
        conf.code = 200
        self.assertTrue(comparison("body", None, code=200))

    def test_code_mismatch_is_false(self):
        conf.code = 200
        self.assertFalse(comparison("body", None, code=404))


class TestAdjustNegativeLogic(unittest.TestCase):
    """_adjust flips the condition under negative logic (the raw-page scheme),
    but leaves None untouched and never flips when getRatioValue is requested."""

    def setUp(self):
        _reset_match_conf()   # negative logic only applies with no string/regexp/code set

    def tearDown(self):
        _reset_match_conf()
        kb.negativeLogic = False

    def test_plain_passthrough(self):
        kb.negativeLogic = False
        self.assertEqual(_adjust(True, False), True)
        self.assertEqual(_adjust(False, False), False)

    def test_negative_logic_flips(self):
        kb.negativeLogic = True
        self.assertEqual(_adjust(True, False), False)
        self.assertEqual(_adjust(False, False), True)

    def test_negative_logic_leaves_none(self):
        kb.negativeLogic = True
        self.assertIsNone(_adjust(None, False))


class TestRemoveReflectiveValues(unittest.TestCase):
    """Reflected payloads are masked before comparison so a page echoing the
    injected string isn't mistaken for a True/different response. Note: the
    masking engages for *bordered* payloads (containing non-alpha chars), which
    is what real injection payloads look like."""

    def test_reflected_payload_is_masked(self):
        out = removeReflectiveValues(u"id=1 UNION SELECT 1,2,3 end", u"1 UNION SELECT 1,2,3")
        self.assertIn(REFLECTED_VALUE_MARKER, out)
        self.assertNotIn(u"UNION SELECT 1,2,3", out)

    def test_not_reflected_unchanged(self):
        content = u"<html>nothing reflected here</html>"
        self.assertEqual(removeReflectiveValues(content, u"1 AND 1=1"), content)

    def test_none_payload_unchanged(self):
        content = u"id=1 AND 1=1 end"
        self.assertEqual(removeReflectiveValues(content, None), content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
