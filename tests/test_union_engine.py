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
from _testutils import bootstrap, set_dbms, reset_dbms
bootstrap()

from lib.core.agent import agent
from lib.core.data import conf, kb
from lib.core.datatype import AttribDict
from lib.core.enums import PAYLOAD, PLACE
from lib.request.connect import Connect
import lib.techniques.union.test as ut
import lib.techniques.union.use as uu

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
        # canary: a leaked agent.payload stub (another module patching the shared singleton and
        # restoring it by assignment) makes every probe below identical, so the ORDER BY oracle turns
        # unusable and this test used to fail as a bare 'None != 25'. Name the cause instead.
        self.assertNotIn("payload", agent.__dict__,
                         "agent.payload is stubbed - a test module leaked it (see _testutils.save_attrs)")

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


class TestMssqlJsonAggFalsyValues(unittest.TestCase):
    """Regression: MSSQL UNION dumps use FOR JSON (jsonAggMode), whose output carries native JSON
    types. A real 0 / '' / false is a value; only JSON null is SQL NULL. The old `row.get(field) or
    NULL` mapped every falsy value to the literal string 'NULL' - proven live (SELECT 0,'','ok'
    dumped as NULL,NULL,ok). We drive the REAL _oneShotUnionUse against a mock FOR JSON page."""

    def setUp(self):
        self._s = {
            "hexConvert": conf.get("hexConvert"), "parameters": conf.get("parameters"),
            "paramDict": conf.get("paramDict"), "base64Parameter": conf.get("base64Parameter"),
            "pageEncoding": conf.get("pageEncoding"), "hashDB": conf.get("hashDB"),
            "inj": (kb.injection.place, kb.injection.parameter, kb.injection.data),
            "jsonAggMode": kb.get("jsonAggMode"), "unionDuplicates": kb.get("unionDuplicates"),
            "forcePartialUnion": kb.get("forcePartialUnion"), "tableFrom": kb.get("tableFrom"),
            "unionTemplate": kb.get("unionTemplate"), "qp": Connect.queryPage,
        }
        conf.hexConvert = False
        conf.parameters = {PLACE.GET: "id=1"}
        conf.paramDict = {PLACE.GET: {"id": "1"}}
        conf.base64Parameter = ()
        conf.pageEncoding = None
        conf.hashDB = None
        v = AttribDict()
        v.vector = (0, 4, "", "", "", "NULL", PAYLOAD.WHERE.NEGATIVE, False, False, None, None)
        kb.injection.place = PLACE.GET
        kb.injection.parameter = "id"
        kb.injection.data = {PAYLOAD.TECHNIQUE.UNION: v}
        kb.jsonAggMode = True
        kb.unionDuplicates = kb.forcePartialUnion = False
        kb.tableFrom = kb.unionTemplate = None
        set_dbms("MSSQL")

    def tearDown(self):
        conf.hexConvert = self._s["hexConvert"]
        conf.parameters = self._s["parameters"]
        conf.paramDict = self._s["paramDict"]
        conf.base64Parameter = self._s["base64Parameter"]
        conf.pageEncoding = self._s["pageEncoding"]
        conf.hashDB = self._s["hashDB"]
        kb.injection.place, kb.injection.parameter, kb.injection.data = self._s["inj"]
        kb.jsonAggMode = self._s["jsonAggMode"]
        kb.unionDuplicates = self._s["unionDuplicates"]
        kb.forcePartialUnion = self._s["forcePartialUnion"]
        kb.tableFrom = self._s["tableFrom"]
        kb.unionTemplate = self._s["unionTemplate"]
        Connect.queryPage = self._s["qp"]
        uu.Request.queryPage = self._s["qp"]

    def _dump(self, jsonstr):
        # jsonstr is exactly what MSSQL FOR JSON AUTO, INCLUDE_NULL_VALUES emits (literal to keep key
        # order stable across py2/py3); object_pairs_hook=OrderedDict preserves that order downstream
        page = "%s%s%s" % (kb.chars.start, jsonstr, kb.chars.stop)

        def oracle(payload=None, content=False, raise404=True, **kwargs):
            return (page, {}, 200) if content else True

        Connect.queryPage = staticmethod(oracle)
        uu.Request.queryPage = staticmethod(oracle)
        kb.jsonAggMode = True
        out = uu._oneShotUnionUse("SELECT a,b,c,d FROM users", False)
        firstRow = out.replace(kb.chars.start, "").split(kb.chars.stop)[0]
        return firstRow.split(kb.chars.delimiter)

    def test_falsy_values_preserved(self):
        fields = self._dump('[{"a":0,"b":"","c":"ok","d":null}]')
        self.assertEqual(fields, ["0", "", "ok", "NULL"])   # only JSON null -> NULL


if __name__ == "__main__":
    unittest.main(verbosity=2)


def tearDownModule():
    reset_dbms()   # clear any DBMS forced via set_dbms() so it can't leak into later test modules
