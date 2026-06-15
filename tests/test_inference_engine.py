#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

The blind-SQLi extraction engine (lib/techniques/blind/inference.py bisection).

This is the actual algorithm that pulls data out one character at a time over a
boolean/blind oracle - the heart of sqlmap. It is normally network-coupled, so
here we drive the REAL bisection() against a mock oracle: Request.queryPage is
replaced with a function that decodes the forged payload (we control the payload
template, so it is trivially parseable) and answers the comparison against a
known secret. If bisection's binary search, charset narrowing, or value assembly
regress, these go red - without a live target.

Also asserts the search is logarithmic (binary search), not a linear scan of the
character space.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.data import conf, kb
from lib.core.common import getCurrentThreadData
from lib.request.connect import Connect
import lib.techniques.blind.inference as inf

# bisection does: safeStringFormat(payload, (expression, idx, posValue)); '>' is the
# greater-char marker (swapped to '=' on the final equality check). We pass a parseable
# template so the mock oracle can recover (idx, operator, threshold).
TEMPLATE = "EXPR=%s IDX=%d CMP>%d"
_PARSE = re.compile(r"IDX=(\d+) CMP(.)(\d+)")

# conf/kb knobs bisection reads on the simple single-threaded, no-prediction path
_CONF = {"predictOutput": False, "threads": 1, "api": False, "verbose": 0, "hexConvert": False,
         "charset": None, "firstChar": None, "lastChar": None, "timeSec": 5}
_KB = {"partRun": None, "safeCharEncode": False, "bruteMode": False, "fileReadMode": False,
       "disableShiftTable": False, "originalTimeDelay": 5, "prependFlag": False}


class _EngineCase(unittest.TestCase):
    def setUp(self):
        self._saved_conf = {k: conf.get(k) for k in _CONF}
        self._saved_kb = {k: kb.get(k) for k in _KB}
        self._saved_qp = Connect.queryPage
        self._saved_processChar = kb.data.get("processChar")
        for k, v in _CONF.items():
            conf[k] = v
        for k, v in _KB.items():
            kb[k] = v
        kb.data.processChar = None
        set_dbms("MySQL")

    def tearDown(self):
        for k, v in self._saved_conf.items():
            conf[k] = v
        for k, v in self._saved_kb.items():
            kb[k] = v
        kb.data.processChar = self._saved_processChar
        Connect.queryPage = self._saved_qp
        inf.Request.queryPage = self._saved_qp

    def _extract(self, secret, charsetType=None):
        def oracle(payload=None, *args, **kwargs):
            m = _PARSE.search(payload)
            idx, op, threshold = int(m.group(1)), m.group(2), int(m.group(3))
            ch = ord(secret[idx - 1]) if 0 <= idx - 1 < len(secret) else 0
            return (ch > threshold) if op == ">" else (ch == threshold)

        Connect.queryPage = staticmethod(oracle)
        inf.Request.queryPage = staticmethod(oracle)
        td = getCurrentThreadData()
        td.shared.value = ""
        td.shared.index = [0]
        td.shared.start = 0
        td.shared.count = 0
        count, value = inf.bisection(TEMPLATE, "SELECT secret", length=len(secret), charsetType=charsetType)
        return value, count


class TestBisectionExtraction(_EngineCase):
    # NOTE: the alpha / numeric / mixed cases are NOT redundant - getChar has per-class
    # "first character" position heuristics (distinct branches for a-z, A-Z and 0-9 at
    # inference.py ~331-336), so each character class exercises a different code path.
    def test_single_char(self):
        value, _ = self._extract("X")
        self.assertEqual(value, "X")

    def test_alpha(self):
        value, _ = self._extract("AdminUser")    # exercises the a-z / A-Z heuristic branch
        self.assertEqual(value, "AdminUser")

    def test_alphanumeric(self):
        value, _ = self._extract("admin123")
        self.assertEqual(value, "admin123")

    def test_with_spaces_and_symbols(self):
        value, _ = self._extract("p@ss W0rd!")
        self.assertEqual(value, "p@ss W0rd!")

    def test_numeric_string(self):
        value, _ = self._extract("4815162342")    # exercises the 0-9 heuristic branch
        self.assertEqual(value, "4815162342")

    def test_longer_value(self):
        secret = "The quick brown fox 0123456789"
        value, _ = self._extract(secret)
        self.assertEqual(value, secret)


class TestUnicodeExpansion(_EngineCase):
    """charsetType=None starts with a 0..127 table and gradually expands it (shiftTable) to
    reach higher code points. This test exercises the FIRST expansion step (code points
    128..1023) via Latin-1 chars, where the per-byte oracle model is exact.

    NOTE: kb.disableShiftTable is an INTENTIONAL session-level safety latch (sqlmap author's
    design): once expansion runs all the way to the top - only reachable by a code point above
    0xFFFFF, or by a misbehaving always-TRUE oracle - it disables further expansion to prevent
    runaway / erroneous extraction. That is deliberate, so this test does NOT assert that
    expansion survives across such an event.

    (Code points >= 256 are retrieved/assembled byte-wise in real runs - decodeIntToUnicode
    splits them into a byte sequence - so a simple ord()-based mock oracle only models the
    single-byte range; those are out of scope here.)"""

    def test_extracts_latin1_via_first_expansion(self):
        for s in (u"caf\xe9", u"\xfcber", u"ni\xf1o", u"\xe9\xe8\xea\xeb"):
            self.assertEqual(self._extract(s)[0], s, msg="expansion extraction failed for %r" % s)


class TestSearchIsLogarithmic(_EngineCase):
    def test_query_count_is_sublinear_in_charset(self):
        # GOAL: catch a regression from binary search to a linear/per-codepoint scan.
        # Observed cost is ~6-22 queries/char (it varies: the first-char heuristic's benefit
        # depends on ambient kb/conf state, so a tighter bound would flake). A linear scan of the
        # 128-char ASCII space would be ~128/char (~3840 for 30 chars). Bound at 40/char cleanly
        # separates "logarithmic" (passes) from "linearized" (fails) without being flaky.
        secret = "x" * 30
        _, count = self._extract(secret)
        self.assertLess(count, len(secret) * 40,
                        msg="bisection used %d queries for %d chars (~%.1f/char) - search regressed toward linear?"
                            % (count, len(secret), count / float(len(secret))))


if __name__ == "__main__":
    unittest.main(verbosity=2)
