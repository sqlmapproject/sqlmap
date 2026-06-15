#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

The UNION-based column-count detection engine (lib/techniques/union/test.py).

_findUnionCharCount discovers how many columns a UNION injection needs. Its
fastest path is the ORDER BY technique: a valid target accepts ORDER BY 1..N and
errors on ORDER BY N+1, so it binary-searches for N. We drive the REAL function
against a mock oracle (Request.queryPage replaced) that errors once the requested
column index exceeds a known true count - exercising the actual detection +
binary search with no live target.

This requires the full injection context (conf.parameters / conf.paramDict /
kb.injection) because column detection builds real payloads via agent.payload.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.data import conf, kb
from lib.core.enums import PAYLOAD, PLACE
from lib.request.connect import Connect
import lib.techniques.union.test as ut

MARKER = "MARKER42"
VALID_PAGE = "<html>results %s</html>" % MARKER

_CONF = {"string": MARKER, "notString": None, "regexp": None, "code": None,
         "uCols": None, "uColsStart": 1, "uColsStop": 50, "base64Parameter": ()}
_KB = {"heavilyDynamic": False, "errorIsNone": False, "futileUnion": False,
       "uChar": "NULL", "forceWhere": None}


class TestOrderByColumnCount(unittest.TestCase):
    def setUp(self):
        self._sc = {k: conf.get(k) for k in _CONF}
        self._sk = {k: kb.get(k) for k in _KB}
        self._sp = (conf.get("parameters"), conf.get("paramDict"))
        self._sqp = Connect.queryPage
        self._stmpl = kb.get("pageTemplate")
        self._sinj = (kb.injection.place, kb.injection.parameter)

        for k, v in _CONF.items():
            conf[k] = v
        for k, v in _KB.items():
            kb[k] = v
        conf.parameters = {PLACE.GET: "id=1"}
        conf.paramDict = {PLACE.GET: {"id": "1"}}
        kb.pageTemplate = VALID_PAGE
        kb.injection.place = None
        kb.injection.parameter = None
        set_dbms("MySQL")

    def tearDown(self):
        for k, v in self._sc.items():
            conf[k] = v
        for k, v in self._sk.items():
            kb[k] = v
        conf.parameters, conf.paramDict = self._sp
        kb.pageTemplate = self._stmpl
        kb.injection.place, kb.injection.parameter = self._sinj
        Connect.queryPage = self._sqp
        ut.Request.queryPage = self._sqp

    def _detect(self, true_count):
        def oracle(payload=None, place=None, content=False, raise404=True, **kwargs):
            m = re.search(r"ORDER BY (\d+)", payload or "")
            cols = int(m.group(1)) if m else 1
            if cols <= true_count:
                page = VALID_PAGE
            else:
                page = "<html>Unknown column '%d' in 'order clause'</html>" % cols
            return (page, {}, 200) if content else True

        Connect.queryPage = staticmethod(oracle)
        ut.Request.queryPage = staticmethod(oracle)
        kb.orderByColumns = None
        return ut._findUnionCharCount("-- -", PLACE.GET, "id", "1", "", "", PAYLOAD.WHERE.ORIGINAL)

    def test_detect_single_column(self):
        self.assertEqual(self._detect(1), 1)

    def test_detect_small(self):
        self.assertEqual(self._detect(3), 3)

    def test_detect_medium(self):
        self.assertEqual(self._detect(7), 7)

    def test_detect_larger(self):
        self.assertEqual(self._detect(12), 12)

    def test_detect_beyond_first_step(self):
        # > ORDER_BY_STEP (10): forces the expand-then-bisect branch
        self.assertEqual(self._detect(25), 25)


if __name__ == "__main__":
    unittest.main(verbosity=2)
