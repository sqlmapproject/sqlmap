#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Mocked-oracle / canned-input coverage for three self-contained injection engines:

  * lib/techniques/union/use.py        - _oneShotUnionUse value extraction + unionUse
  * lib/techniques/ldap/inject.py      - boolean-blind LDAP oracle + blind char inference
  * lib/techniques/graphql/inject.py   - schema walk, query building, blind-SQLi inference

The established pattern (see tests/test_inference.py, tests/test_union_engine.py) is
followed: the network seam (Request.queryPage / Request.getPage / the per-module _send /
_gqlSend) is replaced by a deterministic in-process oracle that answers against a known
secret, so the REAL extraction / parsing / bisection logic runs with no live target,
no network and no DBMS.

configUnion is already covered by tests/test_inference.py - not duplicated here.

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
from lib.core.enums import PAYLOAD, PLACE
from lib.core.agent import agent
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request

import lib.techniques.union.use as uu
import lib.techniques.ldap.inject as ldap
import lib.techniques.graphql.inject as gql


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
        sentinel = ldap.SENTINEL

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
