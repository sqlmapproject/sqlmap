#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Mocked-oracle / canned-input coverage for the self-contained extraction /
inference engines under lib/techniques/*:

  * lib/techniques/union/use.py        - _oneShotUnionUse / unionUse / configUnion
  * lib/techniques/error/use.py        - _oneShotErrorUse / _errorFields / errorUse
  * lib/techniques/ldap/inject.py      - boolean-blind LDAP oracle + blind char inference
  * lib/techniques/graphql/inject.py   - schema walk, query building, blind-SQLi inference
  * lib/techniques/blind/inference.py  - bisection / queryOutputLength edge branches

The established pattern (see tests/test_inference_engine.py,
tests/test_union_engine.py) is followed: the network seam (Request.queryPage /
Request.getPage / the per-module _send / _gqlSend) and the forge/escape chain are
replaced by a deterministic in-process oracle that answers against a known secret,
so the REAL extraction / parsing / bisection logic runs with no live target,
no network and no DBMS.

stdlib unittest only; works on Python 2.7 and 3.x.
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
from lib.core.datatype import AttribDict
from lib.core.common import decodeDbmsHexValue
from lib.core.common import getCurrentThreadData
from lib.core.common import hashDBWrite
from lib.core.common import setTechnique
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.exception import SqlmapSyntaxException
from lib.core.settings import PARTIAL_VALUE_MARKER
from lib.core.agent import agent
from lib.core.unescaper import unescaper
from lib.request.connect import Connect
from lib.request.connect import Connect as Request
from lib.utils.hashdb import HashDB

import lib.techniques.union.use as uu
import lib.techniques.error.use as eu
import lib.techniques.ldap.inject as ldap
import lib.techniques.graphql.inject as gql
import lib.techniques.blind.inference as inf


# ===========================================================================
# UNION:  lib/techniques/union/use.py
# ===========================================================================

# A UNION injection vector is a tuple consumed positionally by _oneShotUnionUse /
# forgeUnionQuery (vector[0..10]). The exact contents do not matter here because the
# forge chain is stubbed to a pass-through; only the indexes the function itself reads
# (7=unionDuplicates, 8=forcePartialUnion, 9=tableFrom, 10=unionTemplate) carry meaning.
_UNION_VECTOR = (1, 2, None, "", "", "NULL", PAYLOAD.WHERE.ORIGINAL, False, False, None, None)

_UU_CONF = {"hexConvert": False, "limitStart": 0, "limitStop": 0, "pageEncoding": None,
            "forcePartial": False, "disableJson": False, "binaryFields": None,
            "reportJson": False, "api": False, "threads": 1, "verbose": 0, "eta": False,
            "noTruncate": True, "uFrom": None}
_UU_KB = {"jsonAggMode": False, "respTruncated": False, "unionDuplicates": False,
          "forcePartialUnion": False, "tableFrom": None, "unionTemplate": None,
          "nchar": False, "pageEncoding": None, "bruteMode": False, "partRun": None,
          "suppressResumeInfo": False}


def _wrap(start, body, stop=None):
    """Wrap a value in the current UNION markers, exactly as the target page would."""
    return "%s%s%s" % (start, body, stop if stop is not None else kb.chars.stop)


class _UnionCase(unittest.TestCase):
    """Base: stub the forge/escape/transport seam so _oneShotUnionUse's OWN parsing
    (marker extraction, hashDB caching, json-agg, trimming, retry) is what is exercised."""

    def setUp(self):
        self._sc = {k: conf.get(k) for k in _UU_CONF}
        self._sk = {k: kb.get(k) for k in _UU_KB}
        self._sqp = Request.queryPage
        self._scounters = kb.get("counters")
        self._sinj_data = kb.injection.data
        self._shashdb = conf.get("hashDB")
        self._s_forge = agent.forgeUnionQuery
        self._s_concat = agent.concatQuery
        self._s_payload = agent.payload
        self._s_escape = unescaper.escape

        for k, v in _UU_CONF.items():
            conf[k] = v
        for k, v in _UU_KB.items():
            kb[k] = v

        kb.counters = {}
        conf.hashDB = None                      # disable session resume in these tests
        # minimal injection context the function reads
        entry = AttribDict()
        entry.vector = _UNION_VECTOR
        entry.where = PAYLOAD.WHERE.ORIGINAL
        kb.injection.data = {PAYLOAD.TECHNIQUE.UNION: entry}

        # pass-through forge chain: the produced payload text is irrelevant - the mock
        # oracle answers from the EXPRESSION recorded out-of-band, not from the payload
        agent.forgeUnionQuery = lambda *a, **k: "UNION-FORGED"
        agent.concatQuery = lambda expression, unpack=True: expression
        agent.payload = lambda place=None, parameter=None, value=None, newValue=None, where=None: "PAYLOAD"
        unescaper.escape = lambda expression, *a, **k: expression

        set_dbms("MySQL")

    def tearDown(self):
        for k, v in self._sc.items():
            conf[k] = v
        for k, v in self._sk.items():
            kb[k] = v
        Request.queryPage = self._sqp
        uu.Request.queryPage = self._sqp
        kb.counters = self._scounters
        kb.injection.data = self._sinj_data
        conf.hashDB = self._shashdb
        agent.forgeUnionQuery = self._s_forge
        agent.concatQuery = self._s_concat
        agent.payload = self._s_payload
        unescaper.escape = self._s_escape

    def _install_page(self, page):
        def oracle(payload=None, content=False, raise404=False, **kwargs):
            return (page, AttribDict(), 200) if content else page
        Request.queryPage = staticmethod(oracle)
        uu.Request.queryPage = staticmethod(oracle)


class TestOneShotUnionUse(_UnionCase):
    def test_single_value_extracted(self):
        page = "<html>%s</html>" % _wrap(kb.chars.start, "hello")
        self._install_page(page)
        self.assertEqual(uu._oneShotUnionUse("SELECT a"), _wrap(kb.chars.start, "hello"))

    def test_multi_column_delimited(self):
        body = kb.chars.delimiter.join(("u", "p"))
        page = "x %s y" % _wrap(kb.chars.start, body)
        self._install_page(page)
        retVal = uu._oneShotUnionUse("SELECT u,p")
        self.assertIn("u%sp" % kb.chars.delimiter, retVal)

    def test_no_markers_returns_none(self):
        self._install_page("<html>nothing useful here</html>")
        self.assertIsNone(uu._oneShotUnionUse("SELECT a"))

    def test_counter_incremented(self):
        self._install_page(_wrap(kb.chars.start, "v"))
        uu._oneShotUnionUse("SELECT a")
        self.assertEqual(kb.counters.get(PAYLOAD.TECHNIQUE.UNION), 1)

    def test_last_char_trim_patched(self):
        # the page carries chars.stop with its final char trimmed; the engine repairs it
        trimmed = kb.chars.stop[:-1]
        page = "%s%s%s" % (kb.chars.start, "data", trimmed)
        self._install_page(page)
        retVal = uu._oneShotUnionUse("SELECT a")
        self.assertEqual(retVal, _wrap(kb.chars.start, "data"))

    def test_upper_cased_results_lowered(self):
        # force-uppercased response: function lower-cases the whole page before parsing
        page = ("PREFIX %s" % _wrap(kb.chars.start, "value")).upper()
        self._install_page(page)
        retVal = uu._oneShotUnionUse("SELECT a")
        self.assertEqual(retVal, _wrap(kb.chars.start, "value").lower())

    def test_order_by_retry_without_clause(self):
        # first try (with ORDER BY) yields nothing; the engine retries stripping ORDER BY.
        # both expressions feed the same stubbed oracle, so we vary the page by call count.
        state = {"calls": 0}

        def oracle(payload=None, content=False, raise404=False, **kwargs):
            state["calls"] += 1
            page = "" if state["calls"] == 1 else _wrap(kb.chars.start, "recovered")
            return (page, AttribDict(), 200) if content else page

        Request.queryPage = staticmethod(oracle)
        uu.Request.queryPage = staticmethod(oracle)
        retVal = uu._oneShotUnionUse("SELECT a ORDER BY 1")
        self.assertEqual(retVal, _wrap(kb.chars.start, "recovered"))
        self.assertEqual(state["calls"], 2)

    def test_hashdb_resume_short_circuits(self):
        # a cached value is returned without ever touching the oracle
        import tempfile
        from lib.utils.hashdb import HashDB
        from lib.core.common import hashDBWrite

        fd, path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(path)
        saved_loc = (conf.get("hostname"), conf.get("path"), conf.get("port"))
        try:
            conf.hashDB = HashDB(path)
            conf.hostname, conf.path, conf.port = "union.invalid", "/", 80
            hashDBWrite("%s%s" % (conf.hexConvert or False, "SELECT cached"), "CACHED-UNION")
            conf.hashDB.flush()

            def boom(*a, **k):
                raise AssertionError("oracle must not be called on a cache hit")
            Request.queryPage = staticmethod(boom)
            uu.Request.queryPage = staticmethod(boom)

            self.assertEqual(uu._oneShotUnionUse("SELECT cached"), "CACHED-UNION")
        finally:
            conf.hostname, conf.path, conf.port = saved_loc
            try:
                conf.hashDB.closeAll()
            except Exception:
                pass
            if os.path.exists(path):
                os.remove(path)


class TestJsonAggExtraction(_UnionCase):
    """kb.jsonAggMode path: the page carries a JSON array between the markers (MySQL branch)."""

    def setUp(self):
        _UnionCase.setUp(self)
        kb.jsonAggMode = True

    def test_json_array_rows_wrapped(self):
        # MySQL non-MSSQL/PGSQL branch: json.loads(output) over a JSON-array body, each row
        # re-wrapped in start/stop markers so parseUnionPage can later split it
        import json
        body = json.dumps(["alice", "bob"])
        page = "%s%s%s" % (kb.chars.start, body, kb.chars.stop)
        self._install_page(page)
        retVal = uu._oneShotUnionUse("SELECT name FROM users", False)
        self.assertIn("alice", retVal)
        self.assertIn("bob", retVal)
        self.assertEqual(retVal.count(kb.chars.start), 2)

    def test_truncated_aggregate_sets_flag(self):
        # leading marker present but no trailing marker -> single-shot considered truncated
        page = "%sincomplete-json-array-no-stop" % kb.chars.start
        self._install_page(page)
        retVal = uu._oneShotUnionUse("SELECT name FROM users", False)
        self.assertIsNone(retVal)
        self.assertTrue(kb.respTruncated)


class TestUnionUse(_UnionCase):
    """unionUse() orchestration over the (stubbed) one-shot path. set_dbms forced to a DBMS
    NOT in FROM_DUMMY_TABLE and a scalar (no FROM) expression so the partial/limit/json-agg
    branches are skipped and it falls through to the single one-shot extraction + parse."""

    def setUp(self):
        _UnionCase.setUp(self)
        set_dbms("MySQL")
        # initTechnique() only does session/template bookkeeping (page template, match ratio,
        # resumed conf) irrelevant to the extraction under test, and needs a full injection
        # session to run; stub it so unionUse()'s orchestration + parse is what is exercised.
        self._s_initTechnique = uu.initTechnique
        uu.initTechnique = lambda technique=None: None
        # unionUse() calls getConsoleWidth(); with no tty (test runner) it falls back to
        # curses.initscr(), which flips the terminal to the alternate screen. Pin COLUMNS
        # so that path is never taken and the runner output stays clean.
        self._s_columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "80"

    def tearDown(self):
        if self._s_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._s_columns
        uu.initTechnique = self._s_initTechnique
        _UnionCase.tearDown(self)

    def test_scalar_value(self):
        self._install_page(_wrap(kb.chars.start, "scalar-result"))
        value = uu.unionUse("SELECT 1")
        self.assertEqual(value, "scalar-result")

    def test_scalar_empty(self):
        self._install_page("<html>no markers</html>")
        value = uu.unionUse("SELECT 1")
        self.assertIsNone(value)


# ===========================================================================
# UNION-based:  lib/techniques/union/use.py  (partial / LIMIT-loop branches)
# ===========================================================================

# Distinct from the scalar _UNION_VECTOR / _UU_CONF / _UU_KB above: these drive the
# partial / LIMIT-loop path (NEGATIVE where, forcePartial on, jsonAgg disabled).
_UNION_VECTOR_LIMIT = (1, 2, None, "", "", "NULL", PAYLOAD.WHERE.NEGATIVE, False, False, None, None)

_UU_CONF_LIMIT = {"hexConvert": False, "limitStart": 0, "limitStop": 0, "pageEncoding": None,
                  "forcePartial": True, "disableJson": True, "binaryFields": None,
                  "reportJson": False, "api": False, "threads": 1, "verbose": 0, "eta": False,
                  "noTruncate": True, "uFrom": None}
_UU_KB_LIMIT = {"jsonAggMode": False, "respTruncated": False, "unionDuplicates": False,
                "forcePartialUnion": False, "tableFrom": None, "unionTemplate": None,
                "nchar": False, "pageEncoding": None, "bruteMode": False, "partRun": None,
                "suppressResumeInfo": False, "threadContinue": True}


class _UnionLimitCase(unittest.TestCase):
    """Drive unionUse() down the partial / LIMIT-loop path (jsonAgg disabled, NEGATIVE where,
    forcePartial on). The forge chain is a pass-through; concatQuery records the per-row
    expression so the oracle can recover the LIMIT offset and answer from a known row set."""

    def setUp(self):
        self._sc = {k: conf.get(k) for k in _UU_CONF_LIMIT}
        self._sk = {k: kb.get(k) for k in _UU_KB_LIMIT}
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

        for k, v in _UU_CONF_LIMIT.items():
            conf[k] = v
        for k, v in _UU_KB_LIMIT.items():
            kb[k] = v

        conf.batch = True
        conf.hashDB = None
        kb.counters = {}

        entry = AttribDict()
        entry.vector = _UNION_VECTOR_LIMIT
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
# LDAP:  lib/techniques/ldap/inject.py
# ===========================================================================

class TestLdapPureHelpers(unittest.TestCase):
    def test_ratio(self):
        self.assertEqual(ldap._ratio("abc", "abc"), 1.0)
        self.assertLess(ldap._ratio("hello", "zzzzz"), 0.5)
        self.assertEqual(ldap._ratio(None, None), 1.0)

    def test_ldap_literal_escapes_metachars(self):
        self.assertEqual(ldap._ldapLiteral("a*b(c)"), "a\\2ab\\28c\\29")

    def test_ldap_literal_backslash(self):
        self.assertEqual(ldap._ldapLiteral("a\\b"), "a\\5cb")

    def test_transport_encode(self):
        self.assertEqual(ldap._transportEncode("a b&c=d"), "a%20b%26c%3Dd")

    def test_is_password_param(self):
        self.assertTrue(ldap._isPasswordParam("password"))
        self.assertTrue(ldap._isPasswordParam("userPwd"))
        self.assertTrue(ldap._isPasswordParam("auth_token"))
        self.assertFalse(ldap._isPasswordParam("username"))
        self.assertFalse(ldap._isPasswordParam(None))

    def test_is_error(self):
        self.assertTrue(ldap._isError("LdapErr: DSID-0123ABCD"))
        self.assertTrue(ldap._isError("Invalid DN syntax (34)"))
        self.assertFalse(ldap._isError("everything is fine"))

    def test_backend_from_error(self):
        self.assertEqual(ldap._backendFromError("LdapErr: DSID-0AB12345 problem"),
                         "Microsoft Active Directory")
        # a generic LDAP error that matches the umbrella regex but no specific signature
        self.assertEqual(ldap._backendFromError("Invalid DN syntax (34)"), "OpenLDAP")
        self.assertIsNone(ldap._backendFromError("no error at all"))

    def test_fingerprint_by_error(self):
        self.assertEqual(ldap._fingerprintByError("Microsoft Active Directory"),
                         "Microsoft Active Directory")
        self.assertEqual(ldap._fingerprintByError("OpenLDAP"), "OpenLDAP")
        self.assertEqual(ldap._fingerprintByError("ApacheDS"), "ApacheDS")
        self.assertEqual(ldap._fingerprintByError("389 Directory Server"),
                         "389 Directory Server")
        self.assertIsNone(ldap._fingerprintByError(None))

    def test_grid_renders_table(self):
        grid = ldap._grid(["a", "bb"], [["1", "2"], ["33", "4"]])
        self.assertIn("| a  | bb |", grid)
        self.assertIn("| 33 | 4  |", grid)
        # header + 2 rows + 4 separators (top, under-header, ... actually 3 borders + n rows)
        self.assertEqual(grid.count("+----+----+"), 3)

    def test_charset_excludes_metachars(self):
        for meta in ("*", "(", ")", "\\"):
            self.assertNotIn(ord(meta), ldap._CHARSET)
        self.assertIn(ord("a"), ldap._CHARSET)
        self.assertIn(ord("0"), ldap._CHARSET)

    def test_probe_builder_shapes(self):
        b = ldap._ProbeBuilder("*)")
        self.assertTrue(b.presence("uid").endswith("(uid=*"))
        self.assertIn("(cn=adm*", b.prefix("cn", "adm"))
        # compound probe closes its own (&...) and opens a suffix-eater
        compound = b.presence("uid", constraint=("ou", "people"))
        self.assertIn("(ou=people)", compound)
        self.assertIn("(objectClass=", compound)

    def test_probe_builder_default_breakout(self):
        b = ldap._ProbeBuilder(None)
        self.assertEqual(b.breakout, ")")


class _LdapOracleCase(unittest.TestCase):
    """Drive the real boolean oracle + blind inference against an in-process directory.
    The _send seam is replaced by a function that simulates an LDAP-to-application filter
    match: a payload's trailing assertion '(attr=value*' matches when the directory holds
    `attr` whose value starts with `value`."""

    DIRECTORY = {"uid": "admin", "mail": "bob", "cn": "Administrator"}

    def setUp(self):
        self._sparams = conf.get("parameters")
        self._spdict = conf.get("paramDict")
        self._scookiedel = conf.get("cookieDel")
        self._ssend = ldap._send

        conf.parameters = {PLACE.GET: "user=admin"}
        conf.paramDict = {PLACE.GET: {"user": "admin"}}
        conf.cookieDel = None

        directory = self.DIRECTORY

        def fake_send(place, parameter, value):
            assertions = re.findall(r"\((\w+)=([^()]*)", value)
            if not assertions:
                return "FALSE-PAGE-baseline-content"
            attr, pat = assertions[-1]
            pat = pat.rstrip("*")
            if attr in directory and directory[attr].startswith(pat):
                return "TRUE-CONTENT-stable-match-%s" % attr
            return "FALSE-PAGE-baseline-content"

        ldap._send = fake_send

    def tearDown(self):
        conf.parameters = self._sparams
        conf.paramDict = self._spdict
        conf.cookieDel = self._scookiedel
        ldap._send = self._ssend


class TestLdapParamSegment(_LdapOracleCase):
    def test_original_value(self):
        self.assertEqual(ldap._originalValue(PLACE.GET, "user"), "admin")

    def test_original_value_from_paramdict_fallback(self):
        self.assertEqual(ldap._originalValue(PLACE.GET, "missing"), "")

    def test_replace_segment(self):
        self.assertEqual(ldap._replaceSegment(PLACE.GET, "user", "XYZ"), "user=XYZ")


class TestLdapOracle(_LdapOracleCase):
    def _oracle(self):
        return ldap._makeOracle(PLACE.GET, "user", "TRUE-CONTENT-stable-match-uid")

    def test_exists_true(self):
        oracle, builder = self._oracle(), ldap._ProbeBuilder(")")
        self.assertTrue(ldap._exists(oracle, builder, "uid"))

    def test_exists_false(self):
        oracle, builder = self._oracle(), ldap._ProbeBuilder(")")
        self.assertFalse(ldap._exists(oracle, builder, "nonexistent"))

    def test_infer_attribute_uid(self):
        oracle, builder = self._oracle(), ldap._ProbeBuilder(")")
        self.assertEqual(ldap._inferAttribute(oracle, builder, "uid"), "admin")

    def test_infer_attribute_mail(self):
        oracle, builder = self._oracle(), ldap._ProbeBuilder(")")
        self.assertEqual(ldap._inferAttribute(oracle, builder, "mail"), "bob")

    def test_infer_attribute_missing_none(self):
        oracle, builder = self._oracle(), ldap._ProbeBuilder(")")
        self.assertIsNone(ldap._inferAttribute(oracle, builder, "zzz"))

    def test_enumerate_entry_keys(self):
        oracle, builder = self._oracle(), ldap._ProbeBuilder(")")
        keyAttr, values = ldap._enumerateEntryKeys(oracle, builder)
        self.assertEqual(keyAttr, "uid")
        self.assertEqual(values, ["admin"])


class TestLdapBoolean(_LdapOracleCase):
    def test_boolean_divergent_returns_true_page(self):
        page = ldap._boolean(lambda: "TRUE-STABLE-CONTENT-HERE",
                             lambda: "FALSE-DIFFERENT-PAGE-XX")
        self.assertEqual(page, "TRUE-STABLE-CONTENT-HERE")

    def test_boolean_identical_returns_none(self):
        self.assertIsNone(ldap._boolean(lambda: "SAME-PAGE", lambda: "SAME-PAGE"))

    def test_boolean_error_true_returns_none(self):
        self.assertIsNone(ldap._boolean(lambda: "Invalid DN syntax (34)",
                                        lambda: "anything"))

    def test_detect_boolean_finds_tautology(self):
        # the fake oracle returns a stable TRUE page for any tautology assertion
        # '(objectClass=*' / '(uid=*' / '(cn=*' and a distinct FALSE page for SENTINEL
        template, payload, breakout = ldap._detectBoolean(PLACE.GET, "user")
        self.assertIsNotNone(template)
        self.assertIsNotNone(breakout)
        self.assertIn("=*", payload)


# ===========================================================================
# GraphQL:  lib/techniques/graphql/inject.py
# ===========================================================================

class TestGraphqlPureHelpers(unittest.TestCase):
    def test_unwrap_type_chain(self):
        t = {"kind": "NON_NULL", "name": None,
             "ofType": {"kind": "LIST", "name": None,
                        "ofType": {"kind": "SCALAR", "name": "String"}}}
        self.assertEqual(gql._unwrapType(t),
                         [("NON_NULL", None), ("LIST", None), ("SCALAR", "String")])

    def test_unwrap_type_depth_guard(self):
        # malformed / non-dict terminates without recursion error
        self.assertEqual(gql._unwrapType("notadict"), [])

    def test_leaf_name(self):
        chain = [("NON_NULL", None), ("SCALAR", "Int")]
        self.assertEqual(gql._leafName(chain), "Int")
        self.assertIsNone(gql._leafName([("LIST", None)]))

    def test_classify_arg(self):
        self.assertEqual(gql._classifyArg({"kind": "SCALAR", "name": "String"}), "string")
        self.assertEqual(gql._classifyArg({"kind": "SCALAR", "name": "Int"}), "numeric")
        self.assertEqual(gql._classifyArg({"kind": "SCALAR", "name": "ID"}), "id_dual")
        self.assertIsNone(gql._classifyArg({"kind": "SCALAR", "name": "DateTime"}))

    def test_escape_graphql_string(self):
        self.assertEqual(gql._escapeGraphQLString('a"b\\c'), 'a\\"b\\\\c')
        self.assertEqual(gql._escapeGraphQLString("a\nb"), "a\\nb")

    def test_cell(self):
        self.assertEqual(gql._cell(None), "NULL")
        self.assertEqual(gql._cell({"b": 1, "a": 2}), '{"a": 2, "b": 1}')
        self.assertEqual(gql._cell("plain"), "plain")
        self.assertEqual(gql._cell(7), "7")

    def test_chunks(self):
        self.assertEqual(list(gql._chunks([1, 2, 3, 4, 5], 2)), [[1, 2], [3, 4], [5]])

    def test_render_arg(self):
        self.assertEqual(gql._renderArg("id", "5", "numeric"), "id:5")
        self.assertEqual(gql._renderArg("n", "hi", "string"), 'n:"hi"')
        self.assertEqual(gql._renderArg("id", "9", "id_dual"), "id:9")          # digit -> bare
        self.assertEqual(gql._renderArg("id", "ab", "id_dual"), 'id:"ab"')      # non-digit -> quoted

    def test_render_type_str(self):
        self.assertEqual(gql._renderTypeStr(gql._unwrapType(
            {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String"}})), "String!")
        self.assertEqual(gql._renderTypeStr(gql._unwrapType(
            {"kind": "LIST", "name": None, "ofType": {"kind": "OBJECT", "name": "User"}})), "[User]")

    def test_parse_json(self):
        self.assertEqual(gql._parseJSON('{"a": 1}'), {"a": 1})
        self.assertIsNone(gql._parseJSON("not json"))
        self.assertIsNone(gql._parseJSON(""))

    def test_is_graphql_response(self):
        self.assertTrue(gql._isGraphQLResponse('{"data": {"__typename": "Query"}}'))
        self.assertFalse(gql._isGraphQLResponse('{"data": {"id": 1}}'))
        self.assertFalse(gql._isGraphQLResponse("[]"))

    def test_error_text(self):
        page = '{"errors": [{"message": "boom", "extensions": {"code": "BAD"}}]}'
        text = gql._errorText(page)
        self.assertIn("boom", text)
        self.assertIn("BAD", text)
        self.assertEqual(gql._errorText("{}"), "")

    def test_slot_value(self):
        self.assertEqual(gql._slotValue('{"data": {"f": {"x": 1}}}'), '{"x": 1}')
        # non-graphql passes through unchanged
        self.assertEqual(gql._slotValue("raw"), "raw")

    def test_default_for_arg(self):
        self.assertEqual(gql._defaultForArg({"kind": "SCALAR", "name": "Int"}, None), 0)
        self.assertEqual(gql._defaultForArg({"kind": "SCALAR", "name": "String"}, None), "x")
        self.assertEqual(gql._defaultForArg({"kind": "SCALAR", "name": "String"}, "given"), "given")


# A minimal but realistic introspection schema: query user(id: String, limit: Int): User
_GQL_SCHEMA = {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {"kind": "OBJECT", "name": "Query", "fields": [
            {"name": "user", "args": [
                {"name": "id", "type": {"kind": "SCALAR", "name": "String"}, "defaultValue": None},
                {"name": "limit", "type": {"kind": "SCALAR", "name": "Int"}, "defaultValue": None},
            ], "type": {"kind": "OBJECT", "name": "User"}},
        ]},
        {"kind": "OBJECT", "name": "Mutation", "fields": [
            {"name": "addUser", "args": [
                {"name": "name", "type": {"kind": "SCALAR", "name": "String"}, "defaultValue": None},
            ], "type": {"kind": "OBJECT", "name": "User"}},
        ]},
        {"kind": "OBJECT", "name": "User", "fields": [
            {"name": "name", "type": {"kind": "SCALAR", "name": "String"}, "args": []},
            {"name": "uid", "type": {"kind": "SCALAR", "name": "ID"}, "args": []},
        ]},
    ],
}


class TestGraphqlSchemaWalk(unittest.TestCase):
    def setUp(self):
        self._sfields = dict(gql._inputFields)

    def tearDown(self):
        gql._inputFields.clear()
        gql._inputFields.update(self._sfields)

    def test_extract_slots(self):
        slots = gql._extractSlots(_GQL_SCHEMA)
        byArg = dict((s.targetArg, s) for s in slots)
        self.assertIn("id", byArg)
        self.assertEqual(byArg["id"].strategy, "string")
        self.assertEqual(byArg["id"].operation, "query")
        self.assertIn("limit", byArg)
        self.assertEqual(byArg["limit"].strategy, "numeric")
        # the mutation slot is harvested too (reported but not exercised by the scanner)
        self.assertIn("name", byArg)
        self.assertEqual(byArg["name"].operation, "mutation")

    def test_return_selection_set(self):
        slots = gql._extractSlots(_GQL_SCHEMA)
        slot = next(s for s in slots if s.targetArg == "id")
        self.assertEqual(slot.returnKind, "OBJECT")
        self.assertIn("name", slot.returnSel)
        self.assertIn("uid", slot.returnSel)

    def test_scalar_fields(self):
        typeByName = {"User": _GQL_SCHEMA["types"][2],
                      "String": {"kind": "SCALAR", "name": "String"},
                      "ID": {"kind": "SCALAR", "name": "ID"}}
        names = gql._scalarFields(_GQL_SCHEMA["types"][2], typeByName)
        self.assertEqual(set(names), {"name", "uid"})

    def test_render_selection(self):
        self.assertIsNone(gql._renderSelection("SCALAR", "String", [], {}))
        sel = gql._renderSelection("OBJECT", "User", ["name", "uid"], {})
        self.assertEqual(sel, "{ name uid }")


class TestGraphqlQueryBuilding(unittest.TestCase):
    def setUp(self):
        self._sfields = dict(gql._inputFields)
        self.slots = gql._extractSlots(_GQL_SCHEMA)
        self.strSlot = next(s for s in self.slots if s.targetArg == "id")
        self.numSlot = next(s for s in self.slots if s.targetArg == "limit")

    def tearDown(self):
        gql._inputFields.clear()
        gql._inputFields.update(self._sfields)

    def test_build_query_string_arg(self):
        q = gql._buildQuery(self.strSlot, "x' OR '1'='1")
        self.assertTrue(q.startswith("{user:user("))
        self.assertIn('id:"x\' OR \'1\'=\'1"', q)
        self.assertIn("limit:0", q)             # required-ish sibling defaulted
        self.assertIn("{ name uid }", q)

    def test_build_query_numeric_rejects_non_numeric(self):
        self.assertEqual(gql._buildQuery(self.numSlot, "notanumber"), "")

    def test_build_query_numeric_accepts_digit(self):
        self.assertIn("limit:42", gql._buildQuery(self.numSlot, "42"))

    def test_build_batch(self):
        query, aliases = gql._buildBatch(self.strSlot, ["a", "b", "c"])
        self.assertEqual(aliases, ["a0", "a1", "a2"])
        self.assertIn("a0:user(", query)
        self.assertIn("a2:user(", query)

    def test_build_batch_aborts_on_unembeddable(self):
        query, aliases = gql._buildBatch(self.numSlot, ["1", "notnum"])
        self.assertEqual((query, aliases), ("", []))

    def test_mutation_prefix(self):
        mutSlot = next(s for s in self.slots if s.operation == "mutation")
        self.assertTrue(gql._buildQuery(mutSlot, "x").startswith("mutation {"))


def _make_sql_truth(secret, dialect):
    """A generic boolean SQL oracle: evaluate the LENGTH / ASCII-SUBSTRING / bit predicates
    that _inferExpr / _inferExprBatched emit, against a known `secret`, using `dialect`'s
    rendering. Independent of the concrete expression text."""

    def truth(cond):
        m = re.search(r"(?:CHAR_LENGTH|LENGTH|LEN)\(\((.+?)\)\)\s*(>=|>|=)\s*(\d+)", cond)
        if m:
            op, n, L = m.group(2), int(m.group(3)), len(secret)
            return (L >= n) if op == ">=" else (L > n) if op == ">" else (L == n)
        m = re.search(r"\((?:ASCII|UNICODE)\((?:SUBSTRING|SUBSTR)\(\((.+?)\),(\d+),1\)\)\s*&\s*(\d+)\)>0", cond)
        if m:
            pos, bit = int(m.group(2)), int(m.group(3))
            c = ord(secret[pos - 1]) if pos - 1 < len(secret) else 0
            return (c & bit) > 0
        m = re.search(r"(?:ASCII|UNICODE)\((?:SUBSTRING|SUBSTR)\(\((.+?)\),(\d+),1\)\)\s*(>=|>|=)\s*(\d+)", cond)
        if m:
            pos, op, n = int(m.group(2)), m.group(3), int(m.group(4))
            c = ord(secret[pos - 1]) if pos - 1 < len(secret) else 0
            return (c >= n) if op == ">=" else (c > n) if op == ">" else (c == n)
        if cond == "1=1":
            return True
        if cond == "1=2":
            return False
        return False

    return truth


class TestGraphqlBlindInference(unittest.TestCase):
    DIALECT = gql.DIALECTS["MySQL"]

    def test_infer_expr_recovers_string(self):
        truth = _make_sql_truth("Hello", self.DIALECT)
        self.assertEqual(gql._inferExpr(truth, self.DIALECT, "version()"), "Hello")

    def test_infer_expr_recovers_with_symbols(self):
        secret = "root@%"
        truth = _make_sql_truth(secret, self.DIALECT)
        self.assertEqual(gql._inferExpr(truth, self.DIALECT, "CURRENT_USER()"), secret)

    def test_infer_expr_empty_value(self):
        truth = _make_sql_truth("", self.DIALECT)
        self.assertEqual(gql._inferExpr(truth, self.DIALECT, "expr"), "")

    def test_infer_expr_batched_recovers_string(self):
        secret = "MariaDB"
        truth = _make_sql_truth(secret, self.DIALECT)
        truthBatch = lambda conds: [truth(c) for c in conds]
        self.assertEqual(gql._inferExprBatched(truthBatch, self.DIALECT, "version()"), secret)

    def test_infer_expr_batched_empty(self):
        truth = _make_sql_truth("", self.DIALECT)
        truthBatch = lambda conds: [truth(c) for c in conds]
        self.assertEqual(gql._inferExprBatched(truthBatch, self.DIALECT, "expr"), "")

    def test_inferrer_picks_batched_when_supported(self):
        secret = "abc"
        truth = _make_sql_truth(secret, self.DIALECT)
        truthBatch = lambda conds: [truth(c) for c in conds]
        infer = gql._inferrer(truth, truthBatch, self.DIALECT)
        self.assertEqual(infer("version()"), secret)

    def test_inferrer_falls_back_to_sequential(self):
        secret = "xyz"
        truth = _make_sql_truth(secret, self.DIALECT)
        infer = gql._inferrer(truth, None, self.DIALECT)
        self.assertEqual(infer("version()"), secret)

    def test_fingerprint(self):
        for dbms, dialect in gql.DIALECTS.items():
            truth = lambda cond, expected=dialect.fingerprint: cond == expected
            self.assertEqual(gql._fingerprint(truth), dbms)

    def test_fingerprint_unknown(self):
        self.assertIsNone(gql._fingerprint(lambda cond: False))


class TestGraphqlDumpTable(unittest.TestCase):
    DIALECT = gql.DIALECTS["MySQL"]

    def test_dump_table_grid(self):
        # infer() returns the column list for dialect.columns(table), then the concatenated
        # rows scalar for dialect.rows(...). We map by which sub-expression is requested.
        columns_expr = self.DIALECT.columns("users")
        rows_value = gql.COL_SEP.join(("1", "alice")) + gql.ROW_SEP + gql.COL_SEP.join(("2", "bob"))

        def infer(expr, maxLen=gql.MAX_LENGTH):
            return "id,name" if expr == columns_expr else rows_value

        columns, rows = gql._dumpTable(infer, self.DIALECT, "users")
        self.assertEqual(columns, ["id", "name"])
        self.assertEqual(rows, [["1", "alice"], ["2", "bob"]])

    def test_dump_table_no_columns(self):
        self.assertIsNone(gql._dumpTable(lambda e, maxLen=0: "", self.DIALECT, "users"))


class TestGraphqlParseRows(unittest.TestCase):
    def test_parse_rows_list(self):
        page = '{"data": {"users": [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]}}'
        columns, rows = gql._parseRows(page, None)
        self.assertEqual(columns, ["id", "name"])
        self.assertEqual(rows, [["1", "a"], ["2", "b"]])

    def test_parse_rows_single_object(self):
        page = '{"data": {"user": {"id": 7, "name": "z"}}}'
        columns, rows = gql._parseRows(page, None)
        self.assertEqual(columns, ["id", "name"])
        self.assertEqual(rows, [["7", "z"]])

    def test_parse_rows_null_data(self):
        self.assertIsNone(gql._parseRows('{"data": {"user": null}}', None))

    def test_parse_rows_non_json(self):
        self.assertIsNone(gql._parseRows("not json", None))

    def test_grid_empty(self):
        self.assertEqual(gql._grid([], []), "(empty)")

    def test_grid_renders(self):
        out = gql._grid(["a", "b"], [["1", "22"]])
        self.assertIn("| a | b  |", out)
        self.assertIn("| 1 | 22 |", out)


# ===========================================================================
# Blind inference:  lib/techniques/blind/inference.py
# ===========================================================================

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
