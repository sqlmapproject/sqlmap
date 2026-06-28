#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Edge cases / control-flow branches of the blind-SQLi inference engine
(lib/techniques/blind/inference.py) plus the pure UNION configuration helper
(lib/techniques/union/use.py configUnion).

Complements tests/test_inference_engine.py (which covers the happy-path char-by-char
extraction). Here we drive the REAL bisection() / queryOutputLength() against a mock
oracle (Request.queryPage replaced by a parser of our own parseable payload template)
to exercise the branches the engine test does not reach:

  * trivial returns: payload is None, length == 0
  * --first-char / --last-char range limiting (both via the function args and via
    conf.firstChar / conf.lastChar)
  * --hex output decoding of the assembled value
  * kb.data.processChar post-processing hook
  * session resume from HashDB: a fully cached value, and a PARTIAL_VALUE_MARKER
    partial value that bisection continues from (against a REAL temp SQLite HashDB)
  * queryOutputLength() forging + DIGITS-charset length retrieval

No network, no live target, no real DBMS - exactly like the sibling engine test.
"""

import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.data import conf, kb
from lib.core.common import decodeDbmsHexValue
from lib.core.common import getCurrentThreadData
from lib.core.common import hashDBWrite
from lib.core.enums import CHARSET_TYPE
from lib.core.exception import SqlmapSyntaxException
from lib.core.settings import PARTIAL_VALUE_MARKER
from lib.request.connect import Connect
from lib.utils.hashdb import HashDB
import lib.techniques.blind.inference as inf
import lib.techniques.union.use as uu

# bisection forges: safeStringFormat(payload, (expression, idx, posValue)); '>' is the
# greater-char marker (swapped to '=' on the final equality check). A parseable template
# lets the mock oracle recover (idx, operator, threshold) and answer against a known secret.
TEMPLATE = "EXPR=%s IDX=%d CMP>%d"
_PARSE = re.compile(r"IDX=(\d+) CMP(.)(\d+)")

# conf/kb knobs bisection reads on the simple single-threaded, no-prediction path
_CONF = {"predictOutput": False, "threads": 1, "api": False, "verbose": 0, "hexConvert": False,
         "charset": None, "firstChar": None, "lastChar": None, "timeSec": 5, "eta": False,
         "repair": False, "flushSession": None, "freshQueries": None, "hashDB": None}
_KB = {"partRun": None, "safeCharEncode": False, "bruteMode": False, "fileReadMode": False,
       "disableShiftTable": False, "originalTimeDelay": 5, "prependFlag": False,
       "resumeValues": True, "inferenceMode": False}


class _InferenceCase(unittest.TestCase):
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

    def _install_oracle(self, secret):
        def oracle(payload=None, *args, **kwargs):
            m = _PARSE.search(payload)
            idx, op, threshold = int(m.group(1)), m.group(2), int(m.group(3))
            ch = ord(secret[idx - 1]) if 0 <= idx - 1 < len(secret) else 0
            return (ch > threshold) if op == ">" else (ch == threshold)

        Connect.queryPage = staticmethod(oracle)
        inf.Request.queryPage = staticmethod(oracle)

    @staticmethod
    def _reset_thread():
        td = getCurrentThreadData()
        td.shared.value = ""
        td.shared.index = [0]
        td.shared.start = 0
        td.shared.count = 0

    def _bisect(self, secret, expression="SELECT secret", length=None, **kwargs):
        self._install_oracle(secret)
        self._reset_thread()
        if length is None:
            length = len(secret)
        return inf.bisection(TEMPLATE, expression, length=length, **kwargs)


class TestTrivialReturns(_InferenceCase):
    def test_none_payload(self):
        # payload is None -> (0, None) without ever touching the oracle
        self.assertEqual(inf.bisection(None, "SELECT x"), (0, None))

    def test_zero_length(self):
        # length == 0 -> (0, "") short-circuit
        self._install_oracle("ignored")
        self._reset_thread()
        self.assertEqual(inf.bisection(TEMPLATE, "SELECT x", length=0), (0, ""))


class TestRangeLimiting(_InferenceCase):
    SECRET = "ABCDEFGH"

    def test_first_char_arg(self):
        # firstChar=3 -> start from the 3rd character (1-based) -> drop "AB"
        _, value = self._bisect(self.SECRET, firstChar=3)
        self.assertEqual(value, "CDEFGH")

    def test_last_char_arg(self):
        # lastChar=4 -> stop after the 4th character
        _, value = self._bisect(self.SECRET, lastChar=4)
        self.assertEqual(value, "ABCD")

    def test_conf_first_char(self):
        conf.firstChar = 4
        _, value = self._bisect(self.SECRET)
        self.assertEqual(value, "DEFGH")

    def test_conf_last_char(self):
        conf.lastChar = 3
        _, value = self._bisect(self.SECRET)
        self.assertEqual(value, "ABC")

    def test_first_and_last_window(self):
        # combined window: chars 3..6 inclusive -> "CDEF"
        _, value = self._bisect(self.SECRET, firstChar=3, lastChar=6)
        self.assertEqual(value, "CDEF")


class TestHexConvert(_InferenceCase):
    def test_hex_output_decoded(self):
        # --hex: the retrieved value is a hex string the engine decodes on the way out
        conf.hexConvert = True
        hexed = "48656C6C6F"            # "Hello"
        _, value = self._bisect(hexed)
        self.assertEqual(value, "Hello")
        self.assertEqual(value, decodeDbmsHexValue(hexed))


class TestProcessCharHook(_InferenceCase):
    def test_process_char_applied_to_each_char(self):
        # kb.data.processChar transforms every assembled character
        kb.data.processChar = lambda c: c.upper()
        _, value = self._bisect("abcde")
        self.assertEqual(value, "ABCDE")


class TestResumeFromHashDB(_InferenceCase):
    """bisection() consults the session store first (hashDBRetrieve(checkConf=True)).
    Exercised against a REAL temporary SQLite HashDB (same approach as test_hashdb.py)."""

    def setUp(self):
        _InferenceCase.setUp(self)
        fd, self.path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.path)            # HashDB creates it lazily
        conf.hashDB = HashDB(self.path)
        # hashDBRetrieve/Write key off these
        self._saved_loc = (conf.get("hostname"), conf.get("path"), conf.get("port"))
        conf.hostname = "test.invalid"
        conf.path = "/"
        conf.port = 80

    def tearDown(self):
        conf.hostname, conf.path, conf.port = self._saved_loc
        try:
            conf.hashDB.closeAll()
        except Exception:
            pass
        if os.path.exists(self.path):
            os.remove(self.path)
        _InferenceCase.tearDown(self)

    def test_full_value_resumed(self):
        # a complete cached value short-circuits the whole bisection (0 queries)
        hashDBWrite("SELECT cached", "RESUMED")
        conf.hashDB.flush()
        count, value = self._bisect("ignored-secret", expression="SELECT cached", length=7)
        self.assertEqual(value, "RESUMED")
        self.assertEqual(count, 0)

    def test_partial_value_continued(self):
        # a PARTIAL_VALUE_MARKER value is resumed-from: bisection keeps the prefix
        # and extracts only the remaining characters
        kb.inferenceMode = True          # partial markers are honored only in inference mode
        hashDBWrite("SELECT partial", "%sAB" % PARTIAL_VALUE_MARKER)
        conf.hashDB.flush()
        count, value = self._bisect("ABCDE", expression="SELECT partial", length=5)
        self.assertEqual(value, "ABCDE")
        self.assertGreater(count, 0)     # it did real work for "CDE"


class TestQueryOutputLength(_InferenceCase):
    def test_length_retrieved(self):
        # queryOutputLength forges a LENGTH() expression and runs bisection with the
        # DIGITS charset; the mock "secret" is the textual length itself
        self._install_oracle("42")
        self._reset_thread()
        self.assertEqual(int(inf.queryOutputLength("SELECT data", TEMPLATE)), 42)

    def test_length_single_digit(self):
        self._install_oracle("7")
        self._reset_thread()
        self.assertEqual(int(inf.queryOutputLength("SELECT data", TEMPLATE)), 7)

    def test_digits_charset_extracts_number(self):
        # direct bisection with the DIGITS charset (queryOutputLength's inner call)
        _, value = self._bisect("2026", charsetType=CHARSET_TYPE.DIGITS)
        self.assertEqual(value, "2026")


class TestConfigUnion(unittest.TestCase):
    """lib/techniques/union/use.py configUnion - pure parsing of --union-char / --union-cols."""

    _CONF = {"uChar": None, "uCols": None, "uColsStart": 1, "uColsStop": 50}

    def setUp(self):
        self._saved = {k: conf.get(k) for k in self._CONF}
        self._saved_uchar = kb.get("uChar")
        for k, v in self._CONF.items():
            conf[k] = v

    def tearDown(self):
        for k, v in self._saved.items():
            conf[k] = v
        kb.uChar = self._saved_uchar

    def test_char_and_range(self):
        uu.configUnion(char="NULL", columns="2-6")
        self.assertEqual(kb.uChar, "NULL")
        self.assertEqual((conf.uColsStart, conf.uColsStop), (2, 6))

    def test_single_column(self):
        uu.configUnion(char="NULL", columns="4")
        self.assertEqual((conf.uColsStart, conf.uColsStop), (4, 4))

    def test_uchar_substitution_quoted(self):
        # conf.uChar (non-digit) gets quoted and substituted into the [CHAR] template
        conf.uChar = "test"
        uu.configUnion(char="x[CHAR]x", columns="1")
        self.assertEqual(kb.uChar, "x'test'x")

    def test_uchar_substitution_digit(self):
        # a digit conf.uChar is substituted unquoted
        conf.uChar = "88"
        uu.configUnion(char="[CHAR]", columns="1")
        self.assertEqual(kb.uChar, "88")

    def test_conf_ucols_overrides_columns_arg(self):
        # conf.uCols takes precedence over the columns argument
        conf.uCols = "3-9"
        uu.configUnion(char="NULL", columns="1-2")
        self.assertEqual((conf.uColsStart, conf.uColsStop), (3, 9))

    def test_non_integer_range_raises(self):
        self.assertRaises(SqlmapSyntaxException, uu.configUnion, char="NULL", columns="abc")

    def test_inverted_range_raises(self):
        self.assertRaises(SqlmapSyntaxException, uu.configUnion, char="NULL", columns="9-2")

    def test_non_string_char_ignored(self):
        # a non-string char leaves kb.uChar untouched (early return)
        kb.uChar = "SENTINEL"
        uu.configUnion(char=None, columns="1")
        self.assertEqual(kb.uChar, "SENTINEL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
