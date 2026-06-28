#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Additional mocked-oracle coverage for the two self-contained extraction engines
whose value-recovery branches are NOT reached by tests/test_techniques.py /
tests/test_inference.py:

  * lib/techniques/error/use.py   - _oneShotErrorUse / _errorFields / errorUse
  * lib/techniques/union/use.py   - _oneShotUnionUse / unionUse (partial/LIMIT loop)

Same established harness as the sibling files (see tests/test_techniques.py,
tests/test_inference.py): the network seam (Request.queryPage) and the forge/escape
chain (agent.prefixQuery / suffixQuery / payload / forgeUnionQuery / concatQuery /
unescaper.escape) are replaced by an in-process oracle that answers against a KNOWN
secret wrapped in the REAL kb.chars.start/stop delimiters. The function's OWN regex
extraction / multi-field iteration / counting / LIMIT windowing is what runs - no
live target, no network, no DBMS.

Every test asserts the exact reconstructed value (known-secret oracle), so it fails
if the extraction logic breaks.

stdlib unittest only; works on Python 2.7 and 3.x.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.data import conf, kb
from lib.core.datatype import AttribDict
from lib.core.enums import PAYLOAD
from lib.core.agent import agent
from lib.core.common import getCurrentThreadData
from lib.core.common import setTechnique
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request

import lib.techniques.error.use as eu
import lib.techniques.union.use as uu


# ===========================================================================
# ERROR-based:  lib/techniques/error/use.py
# ===========================================================================

# An error injection vector is consumed by agent.prefixQuery/suffixQuery (here stubbed
# to a pass-through that just yields the "[QUERY]" placeholder the engine substitutes into).
_ERR_VECTOR = ("pref", "suff", 2, "", "", "NULL", PAYLOAD.WHERE.ORIGINAL, False, False, None, None)

_ERR_CONF = {"hexConvert": False, "noEscape": None, "verbose": 0, "api": False,
             "reportJson": False, "limitStart": 0, "limitStop": 0, "noTruncate": True,
             "threads": 1, "eta": False}
_ERR_KB = {"testMode": True, "safeCharEncode": False, "errorChunkLength": None,
           "fileReadMode": False, "bruteMode": False, "threadContinue": True,
           "suppressResumeInfo": False, "dumpTable": None}


class _ErrorCase(unittest.TestCase):
    """Stub the forge/escape/transport seam so _oneShotErrorUse's OWN parsing (marker
    extraction, trim repair, char restoration) is what is exercised."""

    def setUp(self):
        self._sc = {k: conf.get(k) for k in _ERR_CONF}
        self._sk = {k: kb.get(k) for k in _ERR_KB}
        self._sqp = Request.queryPage
        self._scounters = kb.get("counters")
        self._stechnique = kb.get("technique")
        self._sinj_data = kb.injection.data
        self._shashdb = conf.get("hashDB")
        self._sbatch = conf.get("batch")

        self._s_prefix = agent.prefixQuery
        self._s_suffix = agent.suffixQuery
        self._s_payload = agent.payload
        self._s_nullcast = agent.nullAndCastField
        self._s_escape = unescaper.escape

        # restore thread state we touch
        td = getCurrentThreadData()
        self._s_td_uid = td.lastRequestUID
        self._s_td_httperr = td.lastHTTPError
        self._s_td_redirect = td.lastRedirectMsg

        for k, v in _ERR_CONF.items():
            conf[k] = v
        for k, v in _ERR_KB.items():
            kb[k] = v

        conf.batch = True
        conf.hashDB = None                      # disable session resume in these tests
        kb.counters = {}
        kb.technique = PAYLOAD.TECHNIQUE.ERROR
        setTechnique(PAYLOAD.TECHNIQUE.ERROR)

        entry = AttribDict()
        entry.vector = _ERR_VECTOR
        entry.where = PAYLOAD.WHERE.ORIGINAL
        kb.injection.data = {PAYLOAD.TECHNIQUE.ERROR: entry}

        # pass-through forge chain: the produced payload text carries the injExpression so
        # the oracle can (optionally) branch on the requested field; agent.payload returns
        # exactly the newValue it is handed.
        agent.prefixQuery = lambda vector, *a, **k: "[QUERY]"
        agent.suffixQuery = lambda query, *a, **k: query
        agent.payload = lambda place=None, parameter=None, value=None, newValue=None, where=None: newValue
        agent.nullAndCastField = lambda field: field
        unescaper.escape = lambda expression, *a, **k: expression

        # getConsoleWidth() in _errorFields hits curses with no tty; pin COLUMNS so it doesn't
        self._s_columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "80"

        set_dbms("MySQL")

    def tearDown(self):
        for k, v in self._sc.items():
            conf[k] = v
        for k, v in self._sk.items():
            kb[k] = v
        conf.batch = self._sbatch
        Request.queryPage = self._sqp
        eu.Request.queryPage = self._sqp
        kb.counters = self._scounters
        kb.technique = self._stechnique
        setTechnique(None)
        kb.injection.data = self._sinj_data
        conf.hashDB = self._shashdb

        agent.prefixQuery = self._s_prefix
        agent.suffixQuery = self._s_suffix
        agent.payload = self._s_payload
        agent.nullAndCastField = self._s_nullcast
        unescaper.escape = self._s_escape

        td = getCurrentThreadData()
        td.lastRequestUID = self._s_td_uid
        td.lastHTTPError = self._s_td_httperr
        td.lastRedirectMsg = self._s_td_redirect

        if self._s_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._s_columns

    @staticmethod
    def _wrap(body):
        return "%s%s%s" % (kb.chars.start, body, kb.chars.stop)

    def _install_page(self, page):
        def oracle(payload=None, content=False, raise404=False, **kwargs):
            return (page, {}, 200) if content else page
        Request.queryPage = staticmethod(oracle)
        eu.Request.queryPage = staticmethod(oracle)

    def _install_field_oracle(self, mapping):
        """Oracle that branches on which field name appears in the forged payload (the
        injExpression is passed through agent.payload unchanged, so it is in `payload`)."""
        def oracle(payload=None, content=False, raise404=False, **kwargs):
            body = "?"
            for field, value in mapping.items():
                if field in (payload or ""):
                    body = value
                    break
            page = "<html>%s</html>" % self._wrap(body)
            return (page, {}, 200) if content else page
        Request.queryPage = staticmethod(oracle)
        eu.Request.queryPage = staticmethod(oracle)


class TestOneShotErrorUse(_ErrorCase):
    def test_single_value_extracted(self):
        self._install_page("<html>%s</html>" % self._wrap("admin"))
        self.assertEqual(eu._oneShotErrorUse("SELECT name"), "admin")

    def test_space_char_restored(self):
        # the kb.chars.space placeholder (used to survive transport) is restored to a literal
        # space by _errorReplaceChars. NOTE: the other char tokens (dollar/at/hash) are random
        # per-run and may collide with the space token, so only space is asserted here.
        body = "hello%sworld" % kb.chars.space
        self._install_page(self._wrap(body))
        self.assertEqual(eu._oneShotErrorUse("SELECT x"), "hello world")

    def test_no_markers_returns_none(self):
        self._install_page("<html>no useful markers here</html>")
        self.assertIsNone(eu._oneShotErrorUse("SELECT x"))

    def test_html_entities_unescaped(self):
        # retVal goes through htmlUnescape() and <br> -> newline on the way out
        self._install_page(self._wrap("a &amp; b<br>c"))
        self.assertEqual(eu._oneShotErrorUse("SELECT x"), "a & b\nc")

    def test_counter_incremented(self):
        self._install_page(self._wrap("v"))
        eu._oneShotErrorUse("SELECT x")
        self.assertEqual(kb.counters.get(PAYLOAD.TECHNIQUE.ERROR), 1)

    def test_field_substituted_into_expression(self):
        # field is replaced (once) by nullAndCastField(field) before forging; the oracle keys
        # on the field name in the resulting payload to prove the right column was requested
        self._install_field_oracle({"surname": "Smith"})
        self.assertEqual(eu._oneShotErrorUse("SELECT surname FROM users", field="surname"), "Smith")

    def test_recovered_from_http_error_body(self):
        # page itself carries no markers; the delimited value lives in the 500-error body
        td = getCurrentThreadData()
        td.lastRequestUID = 4242
        td.lastHTTPError = (4242, 500, "<html>%s</html>" % self._wrap("from-error-page"))
        self._install_page("<html>regular page, no markers</html>")
        self.assertEqual(eu._oneShotErrorUse("SELECT x"), "from-error-page")

    def test_recovered_from_response_header(self):
        # neither page nor error body has it; it is carried back in a response header value
        body = self._wrap("hdr-value")
        page = "<html>nothing</html>"

        def oracle(payload=None, content=False, raise404=False, **kwargs):
            headers = {"X-Leak": body}
            return (page, headers, 200) if content else page
        Request.queryPage = staticmethod(oracle)
        eu.Request.queryPage = staticmethod(oracle)
        self.assertEqual(eu._oneShotErrorUse("SELECT x"), "hdr-value")

    def test_hex_convert_decoded(self):
        # --hex: the delimited body is a hex string decoded by decodeDbmsHexValue
        conf.hexConvert = True
        self._install_page(self._wrap("48656C6C6F"))   # "Hello"
        self.assertEqual(eu._oneShotErrorUse("SELECT x"), "Hello")

    def test_empty_value_between_markers(self):
        self._install_page(self._wrap(""))
        self.assertEqual(eu._oneShotErrorUse("SELECT x"), "")


class TestOneShotErrorUseChunking(_ErrorCase):
    """The MySQL multi-chunk reassembly loop: with kb.errorChunkLength set, output >= chunk
    length triggers another request at the next offset; the engine concatenates the pieces."""

    def setUp(self):
        _ErrorCase.setUp(self)
        kb.testMode = False                       # honor the chunk-offset loop
        kb.errorChunkLength = 4                    # pre-set so the length-probe search is skipped
        conf.verbose = 0

    def test_multi_chunk_reassembled(self):
        # secret returned 4 chars at a time via SUBSTRING(expr, offset, 4); the loop walks offsets
        secret = "abcdefghij"

        def oracle(payload=None, content=False, raise404=False, **kwargs):
            # MySQL substring is rendered as MID((field),offset,length)
            m = re.search(r"(?:MID|SUBSTRING)\(.*?,(\d+),(\d+)\)", payload or "")
            if m:
                off, length = int(m.group(1)), int(m.group(2))
                chunk = secret[off - 1:off - 1 + length]
            else:
                chunk = secret
            return ("%s%s%s" % (kb.chars.start, chunk, kb.chars.stop), {}, 200) if content else None
        Request.queryPage = staticmethod(oracle)
        eu.Request.queryPage = staticmethod(oracle)

        # a field is required for the SUBSTRING windowing branch to engage
        self.assertEqual(eu._oneShotErrorUse("SELECT data FROM t", field="data"), secret)


class TestErrorFields(_ErrorCase):
    """_errorFields iterates the field list, recovering one value per column."""

    def test_multi_field_values(self):
        self._install_field_oracle({"user": "alice", "pass": "s3cr3t"})
        values = eu._errorFields("SELECT user,pass FROM t", "user,pass",
                                 ["user", "pass"], suppressOutput=True)
        self.assertEqual(values, ["alice", "s3cr3t"])

    def test_single_field_value(self):
        self._install_field_oracle({"email": "root@localhost"})
        values = eu._errorFields("SELECT email FROM t", "email", ["email"], suppressOutput=True)
        self.assertEqual(values, ["root@localhost"])

    def test_empty_field_yields_null(self):
        # a field listed in emptyFields is short-circuited to the NULL sentinel (no oracle hit)
        from lib.core.settings import NULL

        def boom(*a, **k):
            raise AssertionError("oracle must not be called for an empty field")
        Request.queryPage = staticmethod(boom)
        eu.Request.queryPage = staticmethod(boom)
        values = eu._errorFields("SELECT col FROM t", "col", ["col"],
                                 emptyFields=["col"], suppressOutput=True)
        self.assertEqual(values, [NULL])

    def test_rownum_field_skipped(self):
        # a "ROWNUM " field is skipped entirely (Oracle limit artifact)
        self._install_field_oracle({"name": "bob"})
        values = eu._errorFields("SELECT name FROM t", "name",
                                 ["ROWNUM x", "name"], suppressOutput=True)
        self.assertEqual(values, ["bob"])


class TestErrorUse(_ErrorCase):
    """errorUse() orchestration. initTechnique() needs a full injection session; stub it so
    the orchestration + _errorFields extraction + result shaping is what is exercised."""

    def setUp(self):
        _ErrorCase.setUp(self)
        self._s_initTechnique = eu.initTechnique
        eu.initTechnique = lambda technique=None: None

    def tearDown(self):
        eu.initTechnique = self._s_initTechnique
        _ErrorCase.tearDown(self)

    def test_scalar_value(self):
        # scalar expression (no FROM): single one-shot extraction, unwrapped from the list
        self._install_page(self._wrap("5.7.40"))
        self.assertEqual(eu.errorUse("SELECT VERSION()"), "5.7.40")

    def test_scalar_no_output_none(self):
        self._install_page("<html>no markers</html>")
        self.assertIsNone(eu.errorUse("SELECT VERSION()"))

    def test_multi_row_dump(self):
        # dump=True over a FROM-table query: errorUse COUNTs the rows then LIMIT-walks them,
        # reconstructing each row's single column value in order
        conf.limitStart = 1
        conf.limitStop = 3
        rows = {0: "alice", 1: "bob", 2: "carol"}

        def oracle(payload=None, content=False, raise404=False, **kwargs):
            nv = payload or ""
            if "COUNT" in nv.upper():
                body = "3"
            else:
                m = re.search(r"LIMIT (\d+),1", nv)
                idx = int(m.group(1)) if m else 0
                body = rows.get(idx, "?")
            return ("%s%s%s" % (kb.chars.start, body, kb.chars.stop), {}, 200) if content else None
        Request.queryPage = staticmethod(oracle)
        eu.Request.queryPage = staticmethod(oracle)

        value = eu.errorUse("SELECT name FROM users", dump=True)
        self.assertEqual([eu.unArrayizeValue(v) for v in value], ["alice", "bob", "carol"])

    def test_dump_zero_count_returns_empty(self):
        # COUNT yields "0" (non-positive) -> the query returned no output -> None
        conf.limitStart = 1
        conf.limitStop = 10

        def oracle(payload=None, content=False, raise404=False, **kwargs):
            nv = payload or ""
            body = "0" if "COUNT" in nv.upper() else "x"
            return ("%s%s%s" % (kb.chars.start, body, kb.chars.stop), {}, 200) if content else None
        Request.queryPage = staticmethod(oracle)
        eu.Request.queryPage = staticmethod(oracle)
        # a "0" count is truthy-but-not-positive -> empty-table sentinel (returns [])
        self.assertEqual(eu.errorUse("SELECT name FROM users", dump=True), [])


# ===========================================================================
# UNION-based:  lib/techniques/union/use.py  (branches not in test_techniques.py)
# ===========================================================================

_UNION_VECTOR = (1, 2, None, "", "", "NULL", PAYLOAD.WHERE.NEGATIVE, False, False, None, None)

_UU_CONF = {"hexConvert": False, "limitStart": 0, "limitStop": 0, "pageEncoding": None,
            "forcePartial": True, "disableJson": True, "binaryFields": None,
            "reportJson": False, "api": False, "threads": 1, "verbose": 0, "eta": False,
            "noTruncate": True, "uFrom": None}
_UU_KB = {"jsonAggMode": False, "respTruncated": False, "unionDuplicates": False,
          "forcePartialUnion": False, "tableFrom": None, "unionTemplate": None,
          "nchar": False, "pageEncoding": None, "bruteMode": False, "partRun": None,
          "suppressResumeInfo": False, "threadContinue": True}


class _UnionLimitCase(unittest.TestCase):
    """Drive unionUse() down the partial / LIMIT-loop path (jsonAgg disabled, NEGATIVE where,
    forcePartial on). The forge chain is a pass-through; concatQuery records the per-row
    expression so the oracle can recover the LIMIT offset and answer from a known row set."""

    def setUp(self):
        self._sc = {k: conf.get(k) for k in _UU_CONF}
        self._sk = {k: kb.get(k) for k in _UU_KB}
        self._sqp = Request.queryPage
        self._scounters = kb.get("counters")
        self._sinj_data = kb.injection.data
        self._shashdb = conf.get("hashDB")
        self._sbatch = conf.get("batch")
        self._s_forge = agent.forgeUnionQuery
        self._s_concat = agent.concatQuery
        self._s_payload = agent.payload
        self._s_escape = unescaper.escape
        self._s_lastexpr = getattr(agent, "_lastexpr", None)
        self._s_initTechnique = uu.initTechnique

        for k, v in _UU_CONF.items():
            conf[k] = v
        for k, v in _UU_KB.items():
            kb[k] = v

        conf.batch = True
        conf.hashDB = None
        kb.counters = {}

        entry = AttribDict()
        entry.vector = _UNION_VECTOR
        entry.where = PAYLOAD.WHERE.NEGATIVE
        kb.injection.data = {PAYLOAD.TECHNIQUE.UNION: entry}

        # record the expression seen by each _oneShotUnionUse so the oracle can branch on it
        def rec_concat(expression, unpack=True):
            agent._lastexpr = expression
            return expression
        agent.concatQuery = rec_concat
        agent.forgeUnionQuery = lambda *a, **k: "UNION-FORGED"
        agent.payload = lambda place=None, parameter=None, value=None, newValue=None, where=None: "PAYLOAD"
        unescaper.escape = lambda expression, *a, **k: expression
        uu.initTechnique = lambda technique=None: None

        self._s_columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "80"

        set_dbms("MySQL")

    def tearDown(self):
        for k, v in self._sc.items():
            conf[k] = v
        for k, v in self._sk.items():
            kb[k] = v
        conf.batch = self._sbatch
        Request.queryPage = self._sqp
        uu.Request.queryPage = self._sqp
        kb.counters = self._scounters
        kb.injection.data = self._sinj_data
        conf.hashDB = self._shashdb
        agent.forgeUnionQuery = self._s_forge
        agent.concatQuery = self._s_concat
        agent.payload = self._s_payload
        unescaper.escape = self._s_escape
        agent._lastexpr = self._s_lastexpr
        uu.initTechnique = self._s_initTechnique

        if self._s_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._s_columns

    def _install_row_oracle(self, rows, count=None):
        """rows: list of tuples (per-row columns). Oracle answers COUNT and per-LIMIT rows
        from the recorded expression (agent._lastexpr), wrapping in real start/stop markers."""
        start, stop, delim = kb.chars.start, kb.chars.stop, kb.chars.delimiter
        total = count if count is not None else len(rows)

        def oracle(payload=None, content=False, raise404=False, **kwargs):
            expr = getattr(agent, "_lastexpr", "") or ""
            if "COUNT" in expr.upper():
                body = str(total)
            else:
                m = re.search(r"LIMIT (\d+),1", expr)
                idx = int(m.group(1)) if m else 0
                row = rows[idx] if 0 <= idx < len(rows) else ("?",)
                body = delim.join(row)
            page = "%s%s%s" % (start, body, stop)
            return (page, AttribDict(), 200) if content else page
        Request.queryPage = staticmethod(oracle)
        uu.Request.queryPage = staticmethod(oracle)


class TestUnionPartialDump(_UnionLimitCase):
    def test_multi_row_two_columns(self):
        rows = [("1", "alice"), ("2", "bob"), ("3", "carol")]
        self._install_row_oracle(rows)
        value = uu.unionUse("SELECT id,name FROM users")
        self.assertEqual(list(value), [["1", "alice"], ["2", "bob"], ["3", "carol"]])

    def test_multi_row_single_column(self):
        rows = [("alice",), ("bob",)]
        self._install_row_oracle(rows)
        value = uu.unionUse("SELECT name FROM users")
        self.assertEqual([uu.unArrayizeValue(v) for v in value], ["alice", "bob"])

    def test_query_count_matches_rows(self):
        # one COUNT query + one query per row = 4 UNION requests for 3 rows
        rows = [("1", "a"), ("2", "b"), ("3", "c")]
        self._install_row_oracle(rows)
        uu.unionUse("SELECT id,name FROM users")
        self.assertEqual(kb.counters.get(PAYLOAD.TECHNIQUE.UNION), 1 + len(rows))

    def test_count_returns_zero_empty(self):
        # COUNT yields "0" -> empty-table sentinel (the function returns []), no row queries
        self._install_row_oracle([], count=0)
        value = uu.unionUse("SELECT id,name FROM users")
        self.assertEqual(value, [])

    def test_single_row_count_one(self):
        # COUNT yields "1": the multi-row thread loop is skipped, falls through to one one-shot
        rows = [("solo",)]
        self._install_row_oracle(rows, count=1)
        value = uu.unionUse("SELECT name FROM users")
        self.assertEqual(uu.unArrayizeValue(value), "solo")

    def test_length_limited_window(self):
        # conf.limitStart/limitStop windowing (dump=True): only rows in [start, stop) survive.
        # With limitStart=2, limitStop=4 over a 5-row table the engine COUNTs then walks
        # offsets 1..3 -> rows index 1,2,3 -> "b","c","d".
        conf.forcePartial = False
        conf.limitStart = 2
        conf.limitStop = 4
        rows = [("a",), ("b",), ("c",), ("d",), ("e",)]
        self._install_row_oracle(rows, count=5)
        value = uu.unionUse("SELECT name FROM users", dump=True)
        self.assertEqual([uu.unArrayizeValue(v) for v in value], ["b", "c", "d"])


class TestOneShotUnionUseLimited(_UnionLimitCase):
    """_oneShotUnionUse called directly with the `limited` flag set (the per-row caller's mode)."""

    def test_limited_single_row(self):
        start, stop, delim = kb.chars.start, kb.chars.stop, kb.chars.delimiter
        body = delim.join(("7", "zed"))
        page = "%s%s%s" % (start, body, stop)

        def oracle(payload=None, content=False, raise404=False, **kwargs):
            return (page, AttribDict(), 200) if content else page
        Request.queryPage = staticmethod(oracle)
        uu.Request.queryPage = staticmethod(oracle)

        retVal = uu._oneShotUnionUse("SELECT id,name FROM t LIMIT 0,1", unpack=True, limited=True)
        self.assertEqual(retVal, page)
        # one wrapped multi-column entry -> one row of two columns
        self.assertEqual(list(uu.parseUnionPage(retVal)), [["7", "zed"]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
