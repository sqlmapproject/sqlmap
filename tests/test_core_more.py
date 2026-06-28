#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Additional unit coverage for lib/core/agent.py, lib/core/common.py and
lib/utils/brute.py, targeting functions/branches NOT already exercised by:

  * tests/test_agent.py           (payload delimiters, prefix/suffix defaults,
                                   getFields(SELECT a,b), one MySQL concatQuery,
                                   cleanupPayload RANDNUM)
  * tests/test_agent_dialects.py  (null/cast/concat, hexConvertField,
                                   nullAndCastField, simpleConcatenate,
                                   forgeUnionQuery(-1,3,...), limitQuery(0,...),
                                   forgeCaseStatement, runAsDBMSUser-noop)
  * tests/test_common_utils.py    (paramToDict, getCharset, getLimitRange,
                                   parseUnionPage, safeStringFormat, urlencode,
                                   parseTargetUrl/Direct, safeSQLIdentificatorNaming)
  * tests/test_common_parsers.py  (request-file parsers, reflective masking,
                                   findPageForms, saveConfig, getSQLSnippet,
                                   Backend setters, urlencode/safeStringFormat extras)

This file instead covers:

  agent.py:  forgeUnionQuery (limited / multipleUnions / fromTable / collate /
             INTO OUTFILE), limitQuery across several DBMS shapes (TOP/ROWNUM/
             OFFSET dialects + the " FROM "-less early return), whereQuery
             (dumpWhere splicing), getComment, concatQuery(unpack=False),
             cleanupPayload([ORIGVALUE]/[ORIGINAL]/[SPACE_REPLACE]),
             adjustLateValues (SLEEPTIME/base64/RANDNUM), getFields on TOP /
             DISTINCT / function / no-FROM shapes, prefixQuery/suffixQuery with
             explicit prefix/suffix/clause/comment args, nullAndCastField noCast.

  common.py: isNoneValue, isNullValue, isNumPosStrValue, isNumber, isListLike,
             filterPairValues, filterListValue, filterNone, filterStringValue,
             zeroDepthSearch, splitFields, unArrayizeValue, flattenValue,
             arrayizeValue, joinValue, aliasToDbmsEnum, getPageWordSet,
             resetCookieJar (clear branch), normalizeUnicode.

  brute.py:  tableExists / columnExists driven with conf.direct=True and the
             external collaborators (inject.checkBooleanExpression, getFileItems,
             runThreads) monkeypatched, plus _addPageTextWords.

Everything runs in isolation (no network, no DBMS, no filesystem mutation of
the project). Any global conf/kb/Backend state that a call reads or writes is
snapshotted in setUp and restored in tearDown so test ordering is irrelevant.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.agent import agent
from lib.core.data import conf, kb, queries
from lib.core.enums import DBMS
from lib.core.settings import (
    PAYLOAD_DELIMITER,
    SLEEP_TIME_MARKER,
    BOUNDED_BASE64_MARKER,
    NULL,
)
from lib.core.common import (
    Backend,
    isNoneValue,
    isNullValue,
    isNumPosStrValue,
    isNumber,
    isListLike,
    filterPairValues,
    filterListValue,
    filterNone,
    filterStringValue,
    zeroDepthSearch,
    splitFields,
    unArrayizeValue,
    flattenValue,
    arrayizeValue,
    joinValue,
    aliasToDbmsEnum,
    getPageWordSet,
    resetCookieJar,
    normalizeUnicode,
)


class DbmsStateMixin(object):
    """Snapshot/restore the Backend/kb DBMS-forcing state so set_dbms() does not leak."""

    def setUp(self):
        self._forcedDbms = kb.forcedDbms
        self._sticky = kb.stickyDBMS
        self._batch = conf.batch
        conf.batch = True

    def tearDown(self):
        kb.forcedDbms = self._forcedDbms
        kb.stickyDBMS = self._sticky
        conf.batch = self._batch


# --------------------------------------------------------------------------- #
# lib/core/agent.py
# --------------------------------------------------------------------------- #

class TestForgeUnionQuery(DbmsStateMixin, unittest.TestCase):
    """forgeUnionQuery arg combinations not reached by the dialect smoke test."""

    def test_limited_subselect_wraps_query(self):
        set_dbms(DBMS.MYSQL)
        # limited=True wraps the payload as (SELECT ...) at `position`, fills the
        # rest with `char`, and appends the FROM/comment/suffix
        out = agent.forgeUnionQuery("SELECT user FROM mysql.user", 1, 3, None,
                                    None, None, "NULL", None, limited=True)
        self.assertIn("(SELECT user FROM mysql.user)", out)
        self.assertTrue(out.startswith(" UNION ALL SELECT NULL,(SELECT"), msg=out)
        # position 1 of 3 => NULL,<payload>,NULL
        self.assertEqual(out.count("NULL"), 2, msg=out)

    def test_multiple_unions_appends_second_select(self):
        set_dbms(DBMS.MYSQL)
        out = agent.forgeUnionQuery("SELECT a FROM t", 0, 2, None, None, None,
                                    "NULL", None, multipleUnions="b")
        # the multipleUnions payload produces a *second* UNION ALL SELECT
        self.assertEqual(out.upper().count("UNION ALL SELECT"), 2, msg=out)
        self.assertIn("b", out)

    def test_from_table_override(self):
        set_dbms(DBMS.MYSQL)
        out = agent.forgeUnionQuery("SELECT 1", 0, 1, None, None, None, "NULL",
                                    None, fromTable=" FROM dummytable")
        self.assertIn("FROM dummytable", out, msg=out)

    def test_into_outfile_forces_null_position(self):
        set_dbms(DBMS.MYSQL)
        # an INTO OUTFILE clause forces position 0 / char NULL and re-appends the file part
        out = agent.forgeUnionQuery("SELECT a INTO OUTFILE '/tmp/o.txt' FROM t",
                                    1, 2, None, None, None, "NULL", None)
        self.assertIn("INTO OUTFILE '/tmp/o.txt'", out, msg=out)

    def test_collate_clause_on_mysql(self):
        set_dbms(DBMS.MYSQL)
        # collate=True on MySQL wraps a non-NULL, non-numeric value in the
        # MYSQL_UNION_VALUE_CAST collation wrapper
        out = agent.forgeUnionQuery("SELECT user FROM mysql.user", 0, 1, None,
                                    None, None, "NULL", None, collate=True)
        self.assertIn("CONVERT", out.upper(), msg=out)


class TestLimitQuery(DbmsStateMixin, unittest.TestCase):
    """limitQuery dialect shapes beyond the single limitQuery(0,...) smoke test."""

    def test_no_from_returns_unchanged(self):
        set_dbms(DBMS.MYSQL)
        self.assertEqual(agent.limitQuery(5, "SELECT 1", "1"), "SELECT 1")

    def test_mysql_appends_limit_offset_one(self):
        set_dbms(DBMS.MYSQL)
        out = agent.limitQuery(7, "SELECT user FROM mysql.user", "user")
        self.assertTrue(out.endswith("LIMIT 7,1"), msg=out)

    def test_pgsql_offset_form(self):
        set_dbms(DBMS.PGSQL)
        out = agent.limitQuery(4, "SELECT usename FROM pg_shadow", "usename")
        self.assertIn("OFFSET 4 LIMIT 1", out, msg=out)

    def test_oracle_rownum_wrap(self):
        set_dbms(DBMS.ORACLE)
        out = agent.limitQuery(2, "SELECT banner FROM v$version", ["banner"])
        # Oracle wraps in a ROWNUM-bounded subselect ending with =<num+1>
        self.assertIn("ROWNUM", out.upper(), msg=out)
        self.assertTrue(out.rstrip().endswith("=3"), msg=out)

    def test_firebird_first_skip(self):
        set_dbms(DBMS.FIREBIRD)
        out = agent.limitQuery(3, "SELECT foo FROM bar", "foo")
        self.assertIsInstance(out, str)
        self.assertIn("foo", out)
        # Firebird uses ROWS <num+1> TO <num+1> (the FIRST/SKIP emulation); pin
        # the exact shape so a broken offset arithmetic is caught.
        self.assertTrue(out.endswith("ROWS 4 TO 4"), msg=out)

    def test_mssql_top_not_in(self):
        set_dbms(DBMS.MSSQL)
        out = agent.limitQuery(2, "SELECT name FROM sysobjects", "name", uniqueField="name")
        # MSSQL emulates LIMIT via TOP + NOT IN
        self.assertIn("TOP", out.upper(), msg=out)
        self.assertIn("NOT IN", out.upper(), msg=out)


class TestWhereQuery(DbmsStateMixin, unittest.TestCase):
    """whereQuery only acts when conf.dumpWhere is set."""

    def setUp(self):
        DbmsStateMixin.setUp(self)
        self._dumpWhere = conf.dumpWhere
        self._tbl = conf.tbl

    def tearDown(self):
        conf.dumpWhere = self._dumpWhere
        conf.tbl = self._tbl
        DbmsStateMixin.tearDown(self)

    def test_no_dumpwhere_is_identity(self):
        set_dbms(DBMS.MYSQL)
        conf.dumpWhere = None
        self.assertEqual(agent.whereQuery("SELECT a FROM t"), "SELECT a FROM t")

    def test_appends_where_clause(self):
        set_dbms(DBMS.MYSQL)
        conf.dumpWhere = "id>10"
        conf.tbl = None
        out = agent.whereQuery("SELECT a FROM t")
        self.assertIn("WHERE id>10", out, msg=out)

    def test_existing_where_gets_anded(self):
        set_dbms(DBMS.MYSQL)
        conf.dumpWhere = "id>10"
        conf.tbl = None
        out = agent.whereQuery("SELECT a FROM t WHERE b=1")
        self.assertIn("AND id>10", out, msg=out)

    def test_order_by_suffix_preserved(self):
        set_dbms(DBMS.MYSQL)
        conf.dumpWhere = "id>10"
        conf.tbl = None
        out = agent.whereQuery("SELECT a FROM t ORDER BY a")
        # the genuine trailing ORDER BY is kept after the spliced WHERE
        self.assertIn("WHERE id>10", out, msg=out)
        # the ORDER BY must survive *after* the spliced WHERE clause; the
        # substring check alone could pass even if the suffix were dropped.
        self.assertTrue(out.rstrip().endswith("ORDER BY a"), msg=out)


class TestGetComment(unittest.TestCase):
    def test_present(self):
        from lib.core.datatype import AttribDict
        self.assertEqual(agent.getComment(AttribDict({"comment": "-- x"})), "-- x")

    def test_absent_returns_empty(self):
        from lib.core.datatype import AttribDict
        self.assertEqual(agent.getComment(AttribDict()), "")


class TestConcatQueryUnpack(DbmsStateMixin, unittest.TestCase):
    def test_unpack_false_returns_input_unchanged(self):
        set_dbms(DBMS.MYSQL)
        self.assertEqual(agent.concatQuery("SELECT a FROM t", unpack=False),
                         "SELECT a FROM t")

    def test_pgsql_unpack_uses_pipe_concat(self):
        set_dbms(DBMS.PGSQL)
        out = agent.concatQuery("SELECT usename FROM pg_shadow")
        self.assertIn("||", out, msg=out)
        self.assertIn(kb.chars.start, out, msg=out)
        self.assertIn(kb.chars.stop, out, msg=out)


class TestCleanupPayloadOrigValue(DbmsStateMixin, unittest.TestCase):
    def test_origvalue_digit_inlined(self):
        out = agent.cleanupPayload("x=[ORIGVALUE]", origValue="42")
        self.assertEqual(out, "x=42")

    def test_origvalue_nondigit_quoted(self):
        out = agent.cleanupPayload("x=[ORIGVALUE]", origValue="abc")
        self.assertIn("'abc'", out, msg=out)

    def test_original_marker_raw_substitution(self):
        out = agent.cleanupPayload("p=[ORIGINAL]", origValue="raw")
        self.assertEqual(out, "p=raw")

    def test_space_replace_marker(self):
        out = agent.cleanupPayload("a[SPACE_REPLACE]b")
        self.assertEqual(out, "a%sb" % kb.chars.space)

    def test_non_string_returns_none(self):
        self.assertIsNone(agent.cleanupPayload(None))


class TestAdjustLateValues(DbmsStateMixin, unittest.TestCase):
    def test_sleeptime_replaced_with_timesec(self):
        out = agent.adjustLateValues("SLEEP(%s)" % SLEEP_TIME_MARKER)
        self.assertEqual(out, "SLEEP(%s)" % conf.timeSec)
        self.assertNotIn(SLEEP_TIME_MARKER, out)

    def test_randnum_marker_substituted(self):
        out = agent.adjustLateValues("v=[RANDNUM]")
        self.assertNotIn("[RANDNUM]", out)
        self.assertTrue(out.split("=")[1].isdigit(), msg=out)

    def test_bounded_base64_marker_encoded(self):
        payload = "%sAB%s" % (BOUNDED_BASE64_MARKER, BOUNDED_BASE64_MARKER)
        out = agent.adjustLateValues(payload)
        # the marked region is base64-encoded and the markers are consumed
        self.assertNotIn(BOUNDED_BASE64_MARKER, out)
        self.assertEqual(out, "QUI=")

    def test_empty_payload_passthrough(self):
        self.assertEqual(agent.adjustLateValues(""), "")


class TestGetFieldsShapes(DbmsStateMixin, unittest.TestCase):
    def test_select_top(self):
        set_dbms(DBMS.MSSQL)
        res = agent.getFields("SELECT TOP 1 name FROM sysobjects")
        self.assertIsNotNone(res[3], msg="fieldsSelectTop not matched")
        self.assertEqual(res[6], "name")

    def test_distinct(self):
        set_dbms(DBMS.MYSQL)
        res = agent.getFields("SELECT DISTINCT(name) FROM t")
        self.assertEqual(res[6], "name")

    def test_function_is_single_element(self):
        set_dbms(DBMS.MYSQL)
        res = agent.getFields("SELECT COUNT(*) FROM t")
        self.assertEqual(res[5], ["COUNT(*)"])

    def test_no_from_keeps_whole_select_list(self):
        set_dbms(DBMS.MYSQL)
        res = agent.getFields("SELECT a,b,c")
        self.assertIsNone(res[0], msg="fieldsSelectFrom must be None without FROM")
        self.assertEqual(res[5], ["a", "b", "c"])


class TestPrefixSuffixArgs(DbmsStateMixin, unittest.TestCase):
    def test_prefix_with_explicit_prefix(self):
        set_dbms(DBMS.MYSQL)
        out = agent.prefixQuery("1=1", prefix="')")
        self.assertIn("')", out, msg=out)
        self.assertTrue(out.endswith("1=1"), msg=out)

    def test_prefix_group_by_clause_uses_prefix_verbatim(self):
        set_dbms(DBMS.MYSQL)
        # clause == [2] (GROUP BY / ORDER BY) => no trailing space added
        out = agent.prefixQuery("1=1", prefix="X", clause=[2])
        self.assertEqual(out, "X1=1")

    def test_suffix_appends_comment(self):
        set_dbms(DBMS.MYSQL)
        out = agent.suffixQuery("1=1", comment="-- -")
        self.assertTrue(out.startswith("1=1"), msg=out)
        self.assertIn("-", out)

    def test_suffix_appends_suffix_no_comment(self):
        set_dbms(DBMS.MYSQL)
        out = agent.suffixQuery("1=1", suffix="')")
        self.assertIn("')", out, msg=out)


class TestNullAndCastFieldNoCast(DbmsStateMixin, unittest.TestCase):
    def setUp(self):
        DbmsStateMixin.setUp(self)
        self._noCast = conf.noCast

    def tearDown(self):
        conf.noCast = self._noCast
        DbmsStateMixin.tearDown(self)

    def test_nocast_returns_field_unchanged(self):
        set_dbms(DBMS.MYSQL)
        conf.noCast = True
        self.assertEqual(agent.nullAndCastField("colname"), "colname")

    def test_cast_present_when_nocast_off(self):
        set_dbms(DBMS.MYSQL)
        conf.noCast = False
        out = agent.nullAndCastField("colname")
        self.assertIn("CAST", out.upper(), msg=out)
        self.assertIn("colname", out)


# --------------------------------------------------------------------------- #
# lib/core/common.py
# --------------------------------------------------------------------------- #

class TestSmallPredicates(unittest.TestCase):
    def test_is_none_value(self):
        self.assertTrue(isNoneValue(None))
        self.assertTrue(isNoneValue("None"))
        self.assertTrue(isNoneValue(""))
        self.assertTrue(isNoneValue([]))
        self.assertTrue(isNoneValue(["None", ""]))
        self.assertTrue(isNoneValue({}))
        self.assertFalse(isNoneValue([2]))
        self.assertFalse(isNoneValue("x"))

    def test_is_null_value(self):
        self.assertTrue(isNullValue(u"NULL"))
        self.assertTrue(isNullValue(u"null"))
        self.assertFalse(isNullValue(u"foobar"))
        self.assertFalse(isNullValue(5))

    def test_is_num_pos_str_value(self):
        self.assertTrue(isNumPosStrValue(1))
        self.assertTrue(isNumPosStrValue("1"))
        self.assertFalse(isNumPosStrValue(0))
        self.assertFalse(isNumPosStrValue("-2"))
        self.assertFalse(isNumPosStrValue("100000000000000000000"))
        self.assertFalse(isNumPosStrValue("abc"))

    def test_is_number(self):
        self.assertTrue(isNumber(1))
        self.assertTrue(isNumber("0"))
        self.assertTrue(isNumber("3.14"))
        self.assertFalse(isNumber("foobar"))
        self.assertFalse(isNumber(None))

    def test_is_list_like(self):
        self.assertTrue(isListLike([1]))
        self.assertTrue(isListLike((1,)))
        self.assertTrue(isListLike(set([1])))
        self.assertFalse(isListLike("x"))
        self.assertFalse(isListLike(5))


class TestValueShaping(unittest.TestCase):
    def test_filter_pair_values(self):
        self.assertEqual(filterPairValues([[1, 2], [3], 1, [4, 5]]), [[1, 2], [4, 5]])
        self.assertEqual(filterPairValues(None), [])

    def test_filter_list_value(self):
        self.assertEqual(filterListValue(["users", "admins", "logs"], r"(users|admins)"),
                         ["users", "admins"])
        # non-list input returned unchanged
        self.assertEqual(filterListValue("notlist", r"x"), "notlist")
        # no regex returns input
        self.assertEqual(filterListValue(["a"], None), ["a"])

    def test_filter_none(self):
        self.assertEqual(filterNone([1, 2, "", None, 3, 0]), [1, 2, 3, 0])

    def test_filter_string_value(self):
        self.assertEqual(filterStringValue("wzydeadbeef0123#", r"[0-9a-f]"), "deadbeef0123")

    def test_un_arrayize_value(self):
        self.assertEqual(unArrayizeValue(["1"]), "1")
        self.assertEqual(unArrayizeValue("1"), "1")
        self.assertEqual(unArrayizeValue(["1", "2"]), "1")
        self.assertEqual(unArrayizeValue([["a", "b"], "c"]), "a")
        self.assertIsNone(unArrayizeValue([]))

    def test_flatten_value(self):
        self.assertEqual(list(flattenValue([["1"], [["2"], "3"]])), ["1", "2", "3"])

    def test_arrayize_value(self):
        self.assertEqual(arrayizeValue("1"), ["1"])
        self.assertEqual(arrayizeValue(["1"]), ["1"])

    def test_join_value(self):
        self.assertEqual(joinValue(["1", "2"]), "1,2")
        self.assertEqual(joinValue("1"), "1")
        self.assertEqual(joinValue(["1", None]), "1,None")


class TestZeroDepthAndSplit(unittest.TestCase):
    def test_zero_depth_search_skips_parens(self):
        expr = "SELECT (SELECT id FROM users WHERE 2>1) AS r FROM DUAL"
        idx = zeroDepthSearch(expr, " FROM ")
        # only the outer top-level FROM is found, not the one inside the subselect
        self.assertEqual(len(idx), 1)
        self.assertTrue(expr[idx[0]:].startswith(" FROM DUAL"))

    def test_zero_depth_search_ignores_quoted(self):
        expr = "a , 'b , c' , d"
        # commas inside the quoted literal are not reported
        self.assertEqual(len(zeroDepthSearch(expr, ",")), 2)

    def test_split_fields_basic(self):
        self.assertEqual(splitFields("foo, bar, max(foo, bar)"),
                         ["foo", "bar", "max(foo,bar)"])

    def test_split_fields_quoted(self):
        self.assertEqual(splitFields("a, 'b, c', d"), ["a", "'b, c'", "d"])

    def test_split_fields_custom_delimiter(self):
        self.assertEqual(splitFields("a; b; max(c; d)", delimiter=";"),
                         ["a", "b", "max(c;d)"])


class TestAliasToDbmsEnum(unittest.TestCase):
    def test_known_aliases(self):
        self.assertEqual(aliasToDbmsEnum("mssql"), DBMS.MSSQL)
        self.assertEqual(aliasToDbmsEnum("mysql"), DBMS.MYSQL)
        self.assertEqual(aliasToDbmsEnum("postgres"), DBMS.PGSQL)

    def test_unknown_alias_returns_none(self):
        self.assertIsNone(aliasToDbmsEnum("definitely_not_a_dbms"))

    def test_empty_returns_none(self):
        self.assertIsNone(aliasToDbmsEnum(""))


class TestGetPageWordSet(unittest.TestCase):
    def test_word_extraction(self):
        words = getPageWordSet(u"<html><title>foobar</title><body>test</body></html>")
        self.assertEqual(sorted(words), [u"foobar", u"test"])

    def test_non_string_returns_empty(self):
        self.assertEqual(getPageWordSet(None), set())


class TestNormalizeUnicode(unittest.TestCase):
    def test_accents_stripped(self):
        # normalizeUnicode collapses accented chars to their ASCII base
        self.assertEqual(normalizeUnicode(u"éè"), "ee")

    def test_plain_ascii_unchanged(self):
        self.assertEqual(normalizeUnicode(u"abc123"), "abc123")

    def test_none_returns_none(self):
        self.assertIsNone(normalizeUnicode(None))


class TestResetCookieJar(unittest.TestCase):
    """resetCookieJar's clear branch (conf.loadCookies falsy)."""

    def setUp(self):
        self._loadCookies = conf.loadCookies
        conf.loadCookies = None

    def tearDown(self):
        conf.loadCookies = self._loadCookies

    def test_clear_branch(self):
        try:
            from http.cookiejar import CookieJar
        except ImportError:  # Python 2
            from cookielib import CookieJar

        jar = CookieJar()
        cleared = {"called": False}

        class _Jar(object):
            def clear(self):
                cleared["called"] = True

        resetCookieJar(_Jar())
        self.assertTrue(cleared["called"])
        # also accepts a real jar without raising
        self.assertIsNone(resetCookieJar(jar))


# --------------------------------------------------------------------------- #
# lib/utils/brute.py
# --------------------------------------------------------------------------- #

import lib.utils.brute as brute
from lib.request import inject
import lib.core.threads as threads_mod
import lib.core.common as common_mod


class TestBrute(DbmsStateMixin, unittest.TestCase):
    """Drive tableExists / columnExists with all external collaborators stubbed.

    conf.direct=True skips the time/stacked recommendation prompt. checkBooleanExpression,
    getFileItems and runThreads are monkeypatched so the check runs synchronously,
    deterministically and offline. getPageWordSet is neutralized so the wordlist is
    just what the stub returns.
    """

    def setUp(self):
        DbmsStateMixin.setUp(self)
        self._saved_conf = {k: conf.get(k) for k in
                            ("direct", "db", "tbl", "threads", "api", "verbose")}
        self._choices = kb.choices
        self._cachedTables = kb.data.get("cachedTables")
        self._cachedColumns = kb.data.get("cachedColumns")
        self._brute = kb.brute
        self._origPage = kb.originalPage

        # stub the collaborators
        self._orig_cbe = inject.checkBooleanExpression
        self._orig_brute_cbe = brute.inject.checkBooleanExpression
        self._orig_getFileItems = brute.getFileItems
        self._orig_runThreads = brute.runThreads
        self._orig_getPageWordSet = brute.getPageWordSet

        from lib.core.datatype import AttribDict
        kb.choices = AttribDict(keycheck=False)
        kb.choices.tableExists = None
        kb.choices.columnExists = None
        kb.data.cachedTables = {}
        kb.data.cachedColumns = {}
        kb.brute = AttribDict({"tables": [], "columns": []})
        kb.originalPage = None

        conf.direct = True
        conf.db = None
        conf.threads = 1
        conf.api = False
        conf.verbose = 0

        # runThreads -> just call the worker once synchronously
        def _fakeRunThreads(numThreads, threadFunction, *args, **kwargs):
            kb.threadContinue = True
            threadFunction()
        brute.runThreads = _fakeRunThreads
        # no page words injected into the wordlist
        brute.getPageWordSet = lambda page: set()
        # wordlist file -> small fixed list
        brute.getFileItems = lambda *a, **k: ["users", "logs", "secret_t"]

    def tearDown(self):
        for k, v in self._saved_conf.items():
            conf[k] = v
        kb.choices = self._choices
        if self._cachedTables is None:
            kb.data.pop("cachedTables", None)
        else:
            kb.data.cachedTables = self._cachedTables
        if self._cachedColumns is None:
            kb.data.pop("cachedColumns", None)
        else:
            kb.data.cachedColumns = self._cachedColumns
        kb.brute = self._brute
        kb.originalPage = self._origPage
        brute.inject.checkBooleanExpression = self._orig_brute_cbe
        brute.getFileItems = self._orig_getFileItems
        brute.runThreads = self._orig_runThreads
        brute.getPageWordSet = self._orig_getPageWordSet
        DbmsStateMixin.tearDown(self)

    def test_table_exists_collects_true_results(self):
        set_dbms(DBMS.MYSQL)

        def _cbe(expression, expectingNone=True):
            # initial sanity probe (random table) -> must be False, otherwise the
            # function raises SqlmapDataException; then only "users" exists.
            return "users" in expression
        brute.inject.checkBooleanExpression = _cbe

        result = brute.tableExists("/nonexistent/tables.txt")
        # cachedTables keyed by conf.db (None here) holds the discovered table
        self.assertIn(None, result)
        self.assertIn("users", result[None])
        self.assertNotIn("logs", result.get(None, []))
        # also recorded in kb.brute.tables as (db, table)
        self.assertIn((None, "users"), kb.brute.tables)

    def test_table_exists_invalid_results_raises(self):
        from lib.core.exception import SqlmapDataException
        set_dbms(DBMS.MYSQL)
        # the initial random-table probe returns True -> "invalid results" guard
        brute.inject.checkBooleanExpression = lambda *a, **k: True
        with self.assertRaises(SqlmapDataException):
            brute.tableExists("/nonexistent/tables.txt")

    def test_column_exists_requires_table(self):
        from lib.core.exception import SqlmapMissingMandatoryOptionException
        set_dbms(DBMS.MYSQL)
        conf.tbl = None
        # the sanity probe is False so we reach the missing-table guard
        brute.inject.checkBooleanExpression = lambda *a, **k: False
        with self.assertRaises(SqlmapMissingMandatoryOptionException):
            brute.columnExists("/nonexistent/columns.txt")

    def test_column_exists_collects_and_types(self):
        set_dbms(DBMS.MYSQL)
        conf.tbl = "users"
        brute.getFileItems = lambda *a, **k: ["id", "name"]

        calls = {"n": 0}

        def _cbe(expression, expectingNone=True):
            calls["n"] += 1
            # initial sanity probe uses two random strings (no real column name)
            if "id" not in expression and "name" not in expression:
                return False
            # MySQL numeric-type follow-up: `not checkBooleanExpression(... REGEXP '[^0-9]')`.
            # 'id' is numeric (no non-digit chars => probe False => numeric);
            # 'name' is non-numeric (has non-digit chars => probe True => non-numeric).
            if "REGEXP" in expression:
                return "name" in expression
            # plain existence check (EXISTS(SELECT <col> FROM <tbl>)) => both columns exist
            return True
        brute.inject.checkBooleanExpression = _cbe

        result = brute.columnExists("/nonexistent/columns.txt")
        self.assertIn(None, result)
        cols = result[None]["users"]
        # column names are run through safeSQLIdentificatorNaming, so the MySQL
        # reserved word "name" comes back backtick-quoted
        from lib.core.common import safeSQLIdentificatorNaming, getText
        self.assertEqual(cols.get(getText(safeSQLIdentificatorNaming("id"))), "numeric")
        self.assertEqual(cols.get(getText(safeSQLIdentificatorNaming("name"))), "non-numeric")

    def test_add_page_text_words_filters(self):
        # restore the real getPageWordSet for this one and drive it directly
        brute.getPageWordSet = self._orig_getPageWordSet
        kb.originalPage = u"<html>admin password 1abc xy verylongword</html>"
        words = brute._addPageTextWords()
        # words <= 2 chars or starting with a digit are dropped
        self.assertIn("admin", words)
        self.assertIn("password", words)
        self.assertNotIn("xy", words)
        self.assertNotIn("1abc", words)


if __name__ == "__main__":
    unittest.main(verbosity=2)
