#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

The error-based extraction engine (lib/techniques/error/use.py _oneShotErrorUse).

Error-based SQLi coaxes the DBMS into emitting the target value inside an error
message, wrapped between two random delimiters (kb.chars.start/stop). The engine
fires the payload and pulls the value back out with a regex. We drive the REAL
_oneShotErrorUse against a mock oracle whose "error page" embeds a known secret
between those delimiters, and assert it recovers the value exactly - no live DBMS.

Requires an error-technique injection context (kb.injection.data[...].vector with
[QUERY], plus the parameter context agent.payload needs). kb.errorChunkLength is
pre-set so the MySQL/MSSQL chunk-length probing loop is skipped.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.data import conf, kb
from lib.core.datatype import AttribDict
from lib.core.enums import PAYLOAD, PLACE
from lib.request.connect import Connect
import lib.techniques.error.use as eu


def _make_vector():
    d = AttribDict()
    d.vector = "AND EXTRACTVALUE(1,CONCAT(0x7e,([QUERY]),0x7e))"
    d.where = PAYLOAD.WHERE.ORIGINAL
    d.comment = ""
    d.prefix = ""
    d.suffix = ""
    return d


class TestOneShotErrorUse(unittest.TestCase):
    def setUp(self):
        self._saved = {
            "conf.hexConvert": conf.get("hexConvert"), "conf.charset": conf.get("charset"),
            "conf.hashDB": conf.get("hashDB"), "conf.parameters": conf.get("parameters"),
            "conf.paramDict": conf.get("paramDict"), "conf.base64Parameter": conf.get("base64Parameter"),
            "kb.errorChunkLength": kb.get("errorChunkLength"), "kb.testMode": kb.get("testMode"),
            "kb.forceWhere": kb.get("forceWhere"), "kb.technique": kb.get("technique"),
            "kb.inj": (kb.injection.place, kb.injection.parameter, kb.injection.data),
            "qp": Connect.queryPage,
        }
        conf.hexConvert = False
        conf.charset = None
        conf.hashDB = None
        conf.parameters = {PLACE.GET: "id=1"}
        conf.paramDict = {PLACE.GET: {"id": "1"}}
        conf.base64Parameter = ()
        kb.errorChunkLength = 0
        kb.testMode = False
        kb.forceWhere = None
        kb.injection.place = PLACE.GET
        kb.injection.parameter = "id"
        kb.technique = PAYLOAD.TECHNIQUE.ERROR
        kb.injection.data = {PAYLOAD.TECHNIQUE.ERROR: _make_vector()}
        set_dbms("MySQL")

    def tearDown(self):
        conf.hexConvert = self._saved["conf.hexConvert"]
        conf.charset = self._saved["conf.charset"]
        conf.hashDB = self._saved["conf.hashDB"]
        conf.parameters = self._saved["conf.parameters"]
        conf.paramDict = self._saved["conf.paramDict"]
        conf.base64Parameter = self._saved["conf.base64Parameter"]
        kb.errorChunkLength = self._saved["kb.errorChunkLength"]
        kb.testMode = self._saved["kb.testMode"]
        kb.forceWhere = self._saved["kb.forceWhere"]
        kb.technique = self._saved["kb.technique"]
        kb.injection.place, kb.injection.parameter, kb.injection.data = self._saved["kb.inj"]
        Connect.queryPage = self._saved["qp"]
        eu.Request.queryPage = self._saved["qp"]

    def _extract(self, secret, page_template="XPATH syntax error: '%s%s%s'"):
        def oracle(payload=None, content=False, raise404=True, **kwargs):
            page = page_template % (kb.chars.start, secret, kb.chars.stop)
            return (page, {}, 200) if content else True

        Connect.queryPage = staticmethod(oracle)
        eu.Request.queryPage = staticmethod(oracle)
        return eu._oneShotErrorUse("SELECT CONCAT(user())")

    def test_simple_value(self):
        self.assertEqual(self._extract("root@localhost"), "root@localhost")

    def test_version_string(self):
        self.assertEqual(self._extract("5.7.31-0ubuntu0.18.04.1-log"), "5.7.31-0ubuntu0.18.04.1-log")

    def test_value_with_symbols(self):
        self.assertEqual(self._extract("a-b_c.d:e/f"), "a-b_c.d:e/f")

    def test_no_markers_returns_none(self):
        def oracle(payload=None, content=False, raise404=True, **kwargs):
            return ("a perfectly ordinary page with no error", {}, 200) if content else True
        Connect.queryPage = staticmethod(oracle)
        eu.Request.queryPage = staticmethod(oracle)
        self.assertIsNone(eu._oneShotErrorUse("SELECT CONCAT(user())"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
