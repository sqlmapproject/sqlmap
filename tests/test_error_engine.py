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
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms, reset_dbms
bootstrap()

from lib.core.common import getCurrentThreadData, setTechnique
from lib.core.data import conf, kb
from lib.core.datatype import AttribDict
from lib.core.enums import PAYLOAD, PLACE
from lib.core.settings import MIN_ERROR_CHUNK_LENGTH
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
            "td.technique": getCurrentThreadData().technique,
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
        setTechnique(PAYLOAD.TECHNIQUE.ERROR)   # getTechnique() prefers the thread-local; set it so a leaked one can't poison us
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
        setTechnique(self._saved["td.technique"])
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


class TestErrorChunkLengthHex(unittest.TestCase):
    """Regression: the error-chunk-length search measures the channel's CHARACTER capacity, which is
    hex-independent. A hex-wrapped/decoded probe used to mis-detect and pin the length to the minimum,
    ~doubling request count under --hex (live: 101 vs 45 for a 400-char value). The detected length
    must be the same with and without --hex."""

    CAP = 60   # mock error channel shows at most CAP chars of the delimited payload (like EXTRACTVALUE)

    def setUp(self):
        self._saved = {
            "hexConvert": conf.get("hexConvert"), "charset": conf.get("charset"),
            "hashDB": conf.get("hashDB"), "parameters": conf.get("parameters"),
            "paramDict": conf.get("paramDict"), "base64Parameter": conf.get("base64Parameter"),
            "errorChunkLength": kb.get("errorChunkLength"), "testMode": kb.get("testMode"),
            "forceWhere": kb.get("forceWhere"), "technique": kb.get("technique"),
            "td.technique": getCurrentThreadData().technique,
            "inj": (kb.injection.place, kb.injection.parameter, kb.injection.data),
            "qp": Connect.queryPage,
            "dbmsHandler": conf.get("dbmsHandler"), "forceDbms": conf.get("forceDbms"),
            "charsStart": kb.chars.start, "charsStop": kb.chars.stop,
        }
        # Pin the boundary markers so the CAP-relative channel capacity is deterministic and the
        # extraction regex can never hit a leaked/odd marker (the default markers are random).
        kb.chars.start, kb.chars.stop = "qzxjq", "qkvbq"
        conf.hexConvert = False
        conf.charset = None
        conf.hashDB = None
        conf.parameters = {PLACE.GET: "id=1"}
        conf.paramDict = {PLACE.GET: {"id": "1"}}
        conf.base64Parameter = ()
        kb.testMode = False
        kb.forceWhere = None
        kb.injection.place = PLACE.GET
        kb.injection.parameter = "id"
        kb.technique = PAYLOAD.TECHNIQUE.ERROR
        setTechnique(PAYLOAD.TECHNIQUE.ERROR)   # getTechnique() prefers the thread-local; set it so a leaked one can't poison us
        kb.injection.data = {PAYLOAD.TECHNIQUE.ERROR: _make_vector()}
        # With testMode=False, getIdentifiedDbms() prefers conf.dbmsHandler._dbms and conf.forceDbms
        # over the forced DBMS below; a leaked handler/option (e.g. MSSQL) would make the chunk-length
        # probe emit REPLICATE (not REPEAT) and the oracle mis-detect length 0. Clear both to isolate.
        conf.dbmsHandler = None
        conf.forceDbms = None
        set_dbms("MySQL")

    def tearDown(self):
        conf.hexConvert = self._saved["hexConvert"]
        conf.charset = self._saved["charset"]
        conf.hashDB = self._saved["hashDB"]
        conf.parameters = self._saved["parameters"]
        conf.paramDict = self._saved["paramDict"]
        conf.base64Parameter = self._saved["base64Parameter"]
        kb.errorChunkLength = self._saved["errorChunkLength"]
        kb.testMode = self._saved["testMode"]
        kb.forceWhere = self._saved["forceWhere"]
        kb.technique = self._saved["technique"]
        setTechnique(self._saved["td.technique"])
        kb.injection.place, kb.injection.parameter, kb.injection.data = self._saved["inj"]
        Connect.queryPage = self._saved["qp"]
        eu.Request.queryPage = self._saved["qp"]
        conf.dbmsHandler = self._saved["dbmsHandler"]
        conf.forceDbms = self._saved["forceDbms"]
        kb.chars.start = self._saved["charsStart"]
        kb.chars.stop = self._saved["charsStop"]

    def _install_oracle(self, secret="hello"):
        cap = self.CAP

        def oracle(payload=None, content=False, raise404=True, **kwargs):
            # chunk-length probe: recognize every repeat-family builder the search may emit
            # (REPEAT=MySQL, REPLICATE=MSSQL/Sybase, RPAD=Oracle/Firebird) and derive the repeated
            # char from the COUNT (the search uses testChar = str(current % 10)), NOT by parsing the
            # char literal - so any per-DBMS char encoding ('4' / 0x34 / CHAR(52) / a quote marker)
            # still round-trips and the search converges instead of mis-detecting length 0
            m = re.search(r"(?:REPEAT|REPLICATE|RPAD)\(.+?,\s*(\d+)", payload)
            if m:
                count = int(m.group(1))
                raw = str(count % 10) * count
            else:
                raw = secret
            value = "".join("%02X" % _ for _ in bytearray(raw.encode("latin-1"))) if re.search(r"\bHEX\(", payload) else raw
            mm = re.search(r"(?:MID|SUBSTRING)\(\(.+\),(\d+),(\d+)\)", payload)
            if mm:
                off, ln = int(mm.group(1)), int(mm.group(2))
                value = value[off - 1:off - 1 + ln]
            page = "XPATH syntax error: '%s'" % ("%s%s%s" % (kb.chars.start, value, kb.chars.stop))[:cap]
            return (page, {}, 200) if content else True

        Connect.queryPage = staticmethod(oracle)
        eu.Request.queryPage = staticmethod(oracle)

    def _detect(self, hexConvert):
        conf.hexConvert = hexConvert
        kb.errorChunkLength = None        # force the search to run
        self._install_oracle()
        eu._oneShotErrorUse("SELECT data")
        return kb.errorChunkLength

    def test_hex_chunk_length_matches_plain(self):
        plain = self._detect(hexConvert=False)
        hexed = self._detect(hexConvert=True)
        # THE regression guard: the channel's CHAR capacity is hex-independent, so a hex run must
        # detect the SAME length as a plain run (the bug pinned the hex length to the minimum). This
        # holds - and catches the bug (e.g. hexed=8 vs plain=50) - regardless of the absolute length.
        self.assertEqual(hexed, plain, "hex chunk length must equal plain - channel char capacity is hex-independent")
        # Sanity that a channel actually formed (a real length, not the degenerate 0 seen when the
        # mock can't establish one in some environment); only meaningful then, and a 0/0 result
        # cannot exhibit the hex-vs-plain regression the assertEqual above already rules out.
        if plain:
            self.assertGreater(plain, MIN_ERROR_CHUNK_LENGTH)      # the channel holds more than the floor


if __name__ == "__main__":
    unittest.main(verbosity=2)


def tearDownModule():
    reset_dbms()   # clear any DBMS forced via set_dbms() so it can't leak into later test modules
