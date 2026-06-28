#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Consolidated unit coverage for lib/core/agent.py.

This file merges the agent.py tests previously spread across
test_agent.py, test_agent_dialects.py, test_core_more.py and
test_core_extra.py:

  * Payload assembly helpers (DBMS-independent string transforms that wrap,
    fold and clean a payload on its way to the wire): prefix/suffix, payload
    delimiters, field extraction, CONCAT folding, RAND-marker cleanup.

  * Cross-dialect exercise of the payload-assembly helpers. agent.py builds SQL
    payloads from per-DBMS dialect templates (queries.xml); the helpers are pure
    given the identified back-end DBMS, so driving each one across EVERY
    supported dialect walks the dialect-specific branches (CAST forms,
    concatenation operators, LIMIT/TOP/ROWNUM shapes, ...) without a live target.

  * Argument-combination / shape coverage for forgeUnionQuery, limitQuery,
    whereQuery, getComment, concatQuery(unpack=False), cleanupPayload markers,
    adjustLateValues, getFields shapes, prefix/suffix args, nullAndCastField
    noCast, plus the pure agent helpers (extractPayload/replacePayload, ...).

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import os
import re
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
)

DIALECTS = sorted(queries.keys())

# --------------------------------------------------------------------------- #
# Per-dialect expectation maps (keyed by the DBMS display name == queries key).
#
# These were derived by inspecting the actual agent.py output for every dialect
# (the queries.xml templates drive the branches). They pin the *distinctive*
# dialect token so an assertion fails if the dialect branch collapses to the
# wrong form (e.g. concat operator swapped, null-wrapper dropped).
# --------------------------------------------------------------------------- #

# concatQuery / simpleConcatenate join operator per dialect.
CONCAT_OPERATOR = {
    "ClickHouse": "CONCAT(",
    "Informix": "CONCAT(",
    "MySQL": "CONCAT(",
    "SAP MaxDB": "CONCAT(",
    "Microsoft SQL Server": "+",
    "Sybase": "+",
    "Microsoft Access": "&",
}
# everything not listed above uses the SQL standard "||"
CONCAT_OPERATOR_DEFAULT = "||"

# nullAndCastField / nullCastConcatFields NULL-wrapper function per dialect.
NULL_WRAPPER = {
    "Altibase": "NVL",
    "Apache Derby": "COALESCE",
    "ClickHouse": "ifNull",
    "CrateDB": "COALESCE",
    "Cubrid": "IFNULL",
    "Firebird": "COALESCE",
    "FrontBase": "COALESCE",
    "H2": "IFNULL",
    "HSQLDB": "IFNULL",
    "IBM DB2": "COALESCE",
    "Informix": "NVL",
    "InterSystems Cache": "COALESCE",
    "Mckoi": "IF(",
    "Microsoft Access": "IIF",
    "Microsoft SQL Server": "ISNULL",
    "MimerSQL": "COALESCE",
    "MonetDB": "COALESCE",
    "MySQL": "IFNULL",
    "Oracle": "NVL",
    "PostgreSQL": "COALESCE",
    "Presto": "COALESCE",
    "Raima Database Manager": "IFNULL",
    "SAP MaxDB": "VALUE",
    "SQLite": "COALESCE",
    "Snowflake": "NVL",
    "Spanner": "IFNULL",
    "Sybase": "ISNULL",
    "Vertica": "COALESCE",
    "Virtuoso": "__MAX_NOTNULL",
    "eXtremeDB": "IFNULL",
}

# hexConvertField: dialects that DO have a hex function, mapped to its token.
HEX_FUNCTION = {
    "Altibase": "HEX_ENCODE(",
    "Cubrid": "HEX(",
    "H2": "RAWTOHEX(",
    "IBM DB2": "HEX(",
    "Microsoft SQL Server": "fn_varbintohexstr",
    "MySQL": "HEX(",
    "Oracle": "RAWTOHEX(",
    "PostgreSQL": "ENCODE(",
    "Presto": "TO_HEX(",
    "SAP MaxDB": "HEX(",
    "SQLite": "HEX(",
    "Spanner": "TO_HEX(",
    "Sybase": "BINTOSTR",
    "Vertica": "TO_HEX(",
}
# dialects that intentionally do NOT support hex conversion and return the
# field unchanged (a no-op the old "colname in out" check silently masked).
HEX_NOOP = set(DIALECTS) - set(HEX_FUNCTION)

# limitQuery: dialects whose limit template is empty so the call legitimately
# raises (no .limit.query). These are skipped by name in the limit-token test.
LIMIT_RAISES = {"Mckoi", "Raima Database Manager"}
# dialects with no special limitQuery branch: the query is returned unchanged
# (no limit token is emitted).
LIMIT_PASSTHROUGH = {"Informix", "Microsoft Access", "SAP MaxDB"}
# broad set of dialect limit tokens; every running, non-passthrough dialect
# emits at least one of these.
LIMIT_TOKENS = ("LIMIT", "TOP", "ROWNUM", "FETCH", "ROWS", "OFFSET", "ROW_NUMBER")


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
# Single-DBMS payload-assembly helpers (formerly test_agent.py)
# --------------------------------------------------------------------------- #

class TestPayloadDelimiters(unittest.TestCase):
    def test_add(self):
        self.assertEqual(agent.addPayloadDelimiters("1 AND 1=1"),
                         "%s1 AND 1=1%s" % (PAYLOAD_DELIMITER, PAYLOAD_DELIMITER))

    def test_remove(self):
        wrapped = "%spayload%s" % (PAYLOAD_DELIMITER, PAYLOAD_DELIMITER)
        self.assertEqual(agent.removePayloadDelimiters(wrapped), "payload")

    def test_remove_none_is_none(self):
        self.assertIsNone(agent.removePayloadDelimiters(None))

    def test_roundtrip(self):
        for p in ["1=1", "1 AND SLEEP(5)", "' OR '1'='1", "", "a%sb" % "x"]:
            self.assertEqual(agent.removePayloadDelimiters(agent.addPayloadDelimiters(p)), p,
                             msg="delimiter round-trip for %r" % p)


class TestPrefixSuffix(unittest.TestCase):
    def test_prefix_default_pads_space(self):
        # with no configured prefix, a single leading space is prepended
        self.assertEqual(agent.prefixQuery("1=1"), " 1=1")

    def test_suffix_default_identity(self):
        self.assertEqual(agent.suffixQuery("1=1"), "1=1")


class TestGetFields(unittest.TestCase):
    def test_extracts_select_list(self):
        # getFields(query) returns an 8-tuple; the fields-bearing slots are:
        #   [0],[1] = regex match objects for the SELECT/expression (must be found, not None)
        #   [5]     = parsed field list, [6] = raw fields string
        # (asserting the match objects guards against a refactor that silently shifts the tuple)
        result = agent.getFields("SELECT a,b FROM t")
        self.assertIsNotNone(result[0], msg="getFields did not match the SELECT")
        self.assertEqual(result[5], ["a", "b"])
        self.assertEqual(result[6], "a,b")


class TestConcatQuery(unittest.TestCase):
    def test_mysql_concat_folding(self):
        set_dbms(DBMS.MYSQL)
        q = agent.concatQuery("SELECT a FROM t")
        # folds the field through CONCAT with the start/stop delimiters and keeps the FROM
        self.assertTrue(q.startswith("CONCAT("), msg=q)
        self.assertIn("IFNULL(CAST(a AS NCHAR),' ')", q)
        self.assertTrue(q.endswith("FROM t"), msg=q)


class TestCleanupPayload(unittest.TestCase):
    def test_randnum_marker_replaced_with_digits(self):
        out = agent.cleanupPayload("SELECT [RANDNUM]")
        self.assertNotIn("[RANDNUM]", out, msg="marker not replaced: %r" % out)   # actually substituted
        self.assertTrue(out.startswith("SELECT "), msg=out)
        self.assertTrue(out.split()[-1].isdigit(), msg=out)   # ...and replaced with a concrete number


# --------------------------------------------------------------------------- #
# Cross-dialect smoke coverage (formerly test_agent_dialects.py)
# --------------------------------------------------------------------------- #

class TestNullCastConcatFields(unittest.TestCase):
    def test_all_dialects(self):
        for dbms in DIALECTS:
            set_dbms(dbms)
            out = agent.nullCastConcatFields("user,password")
            self.assertIsInstance(out, str, msg=dbms)
            # both column names survive the null/cast/concat rewrite
            self.assertIn("user", out, msg=dbms)
            self.assertIn("password", out, msg=dbms)
            # the dialect-specific NULL-wrapper must be present (the column-name
            # check above is always satisfied and so cannot catch a broken
            # branch); this fails if the wrapper collapses to the wrong form.
            self.assertIn(NULL_WRAPPER[dbms], out, msg="%s: %s" % (dbms, out))

    def test_literal_passthrough(self):
        for dbms in DIALECTS:
            set_dbms(dbms)
            # a bare quoted literal is returned untouched
            self.assertEqual(agent.nullCastConcatFields("'abc'"), "'abc'", msg=dbms)


class TestNullAndCastField(unittest.TestCase):
    def test_all_dialects(self):
        for dbms in DIALECTS:
            set_dbms(dbms)
            out = agent.nullAndCastField("colname")
            self.assertIsInstance(out, str, msg=dbms)
            self.assertIn("colname", out, msg=dbms)
            # dialect-specific NULL wrapper (IFNULL/COALESCE/NVL/ISNULL/IIF/...)
            self.assertIn(NULL_WRAPPER[dbms], out, msg="%s: %s" % (dbms, out))


class TestHexConvertField(unittest.TestCase):
    def test_all_dialects(self):
        for dbms in DIALECTS:
            set_dbms(dbms)
            out = agent.hexConvertField("colname")
            self.assertIsInstance(out, str, msg=dbms)
            self.assertIn("colname", out, msg=dbms)
            if dbms in HEX_FUNCTION:
                # the dialect's hex function wraps the field
                self.assertIn(HEX_FUNCTION[dbms], out, msg="%s: %s" % (dbms, out))
            else:
                # intentional no-op: the field is returned verbatim. The old
                # "colname in out" check masked this; pin the exact identity.
                self.assertEqual(out, "colname", msg="%s expected no-op: %s" % (dbms, out))


class TestConcatQueryDialects(unittest.TestCase):
    def test_all_dialects(self):
        for dbms in DIALECTS:
            set_dbms(dbms)
            out = agent.concatQuery("SELECT user FROM users")
            self.assertIsInstance(out, str, msg=dbms)
            # concatQuery output is dialect-specific: MySQL/ClickHouse/Informix/
            # SAP MaxDB use CONCAT(...), MSSQL/Sybase use +, Access uses &, and
            # the rest use the SQL-standard ||. Assert the right operator so the
            # test fails if the dialect collapses to the wrong concatenation.
            expected = CONCAT_OPERATOR.get(dbms, CONCAT_OPERATOR_DEFAULT)
            self.assertIn(expected, out, msg="%s: %s" % (dbms, out))


class TestSimpleConcatenate(unittest.TestCase):
    def test_all_dialects(self):
        for dbms in DIALECTS:
            set_dbms(dbms)
            out = agent.simpleConcatenate("a", "b")
            self.assertIsInstance(out, str, msg=dbms)
            self.assertIn("a", out, msg=dbms)
            self.assertIn("b", out, msg=dbms)


class TestForgeUnionQueryDialects(unittest.TestCase):
    def test_all_dialects(self):
        for dbms in DIALECTS:
            set_dbms(dbms)
            count = 3
            out = agent.forgeUnionQuery("SELECT user FROM users", -1, count, None,
                                        None, None, "NULL", None)
            self.assertIsInstance(out, str, msg=dbms)
            self.assertIn("UNION", out.upper(), msg=dbms)
            # position -1 with char NULL fills every one of the `count` columns
            # with the char, so the NULL char must appear exactly `count` times.
            # (a hardcoded "UNION in out" check could not catch a wrong column
            # count.) Match NULL as a whole token to avoid matching substrings.
            self.assertEqual(re.findall(r"\bNULL\b", out).__len__(), count,
                             msg="%s expected %d NULLs: %s" % (dbms, count, out))


class TestLimitQueryDialects(unittest.TestCase):
    def test_all_dialects(self):
        for dbms in DIALECTS:
            set_dbms(dbms)

            # Only Mckoi/Raima have an empty limit template and legitimately
            # raise; skip exactly those by name rather than swallowing *any*
            # exception (which would hide a real regression in another dialect).
            if dbms in LIMIT_RAISES:
                with self.assertRaises(Exception, msg=dbms):
                    agent.limitQuery(0, "SELECT user FROM users", "user")
                continue

            out = agent.limitQuery(0, "SELECT user FROM users", "user")
            self.assertIsInstance(out, str, msg=dbms)

            if dbms in LIMIT_PASSTHROUGH:
                # these dialects have no dedicated limitQuery branch and return
                # the query unchanged (documented no-op).
                self.assertEqual(out, "SELECT user FROM users", msg=dbms)
            else:
                # every other running dialect emits a real limit construct
                self.assertTrue(any(tok in out.upper() for tok in LIMIT_TOKENS),
                                msg="%s missing limit token: %s" % (dbms, out))


class TestForgeCaseStatement(unittest.TestCase):
    def test_all_dialects(self):
        for dbms in DIALECTS:
            set_dbms(dbms)
            out = agent.forgeCaseStatement("1=1")
            self.assertIsInstance(out, str, msg=dbms)
            # dialects vary on the conditional form (CASE / IIF / IF); the
            # condition itself is always embedded
            self.assertIn("1=1", out, msg=dbms)
            # ...but the conditional construct itself must also be present,
            # otherwise the "1=1" check alone could pass on a degenerate output.
            self.assertTrue("CASE" in out or "IIF" in out or "IF(" in out,
                            msg="%s missing conditional construct: %s" % (dbms, out))


class TestPrefixSuffixAcrossDialects(unittest.TestCase):
    def test_prefix_suffix(self):
        for dbms in DIALECTS:
            set_dbms(dbms)
            prefix = agent.prefixQuery("1=1")
            suffix = agent.suffixQuery("1=1")
            self.assertIsInstance(prefix, str, msg=dbms)
            self.assertIsInstance(suffix, str, msg=dbms)
            # prefixQuery pads a leading space ahead of the expression by default
            self.assertEqual(prefix, " 1=1", msg="%s prefix: %r" % (dbms, prefix))
            # suffixQuery returns the expression itself (no extra clause/comment)
            self.assertEqual(suffix, "1=1", msg="%s suffix: %r" % (dbms, suffix))


class TestRunAsDBMSUserAndWhere(unittest.TestCase):
    def test_run_as_user_noop_without_conf(self):
        for dbms in DIALECTS:
            set_dbms(dbms)
            # without conf.dbmsCred the query is returned unchanged
            self.assertEqual(agent.runAsDBMSUser("SELECT 1"), "SELECT 1", msg=dbms)


# --------------------------------------------------------------------------- #
# Argument-combination / shape coverage (formerly test_core_more.py)
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
# Pure agent helpers (formerly test_core_extra.py)
# --------------------------------------------------------------------------- #

class TestAgentPure(unittest.TestCase):
    """Pure agent.py methods independent of full injection state."""

    @classmethod
    def setUpClass(cls):
        from lib.core.agent import agent
        cls.agent = agent

    def tearDown(self):
        set_dbms(None)

    def test_get_comment_present(self):
        from lib.core.datatype import AttribDict
        request = AttribDict()
        request.comment = "-- foo"
        self.assertEqual(self.agent.getComment(request), "-- foo")

    def test_get_comment_absent(self):
        from lib.core.datatype import AttribDict
        request = AttribDict()
        self.assertEqual(self.agent.getComment(request), "")

    def test_add_payload_delimiters(self):
        from lib.core.settings import PAYLOAD_DELIMITER
        value = "1 AND 1=1"
        result = self.agent.addPayloadDelimiters(value)
        self.assertEqual(result, "%s%s%s" % (PAYLOAD_DELIMITER, value, PAYLOAD_DELIMITER))
        # falsy value returned unchanged
        self.assertEqual(self.agent.addPayloadDelimiters(""), "")

    def test_remove_payload_delimiters_roundtrip(self):
        self.assertEqual(
            self.agent.removePayloadDelimiters(self.agent.addPayloadDelimiters("1 AND 1=1")),
            "1 AND 1=1",
        )

    def test_extract_payload(self):
        wrapped = "prefix" + self.agent.addPayloadDelimiters("1 AND 1=1") + "suffix"
        self.assertEqual(self.agent.extractPayload(wrapped), "1 AND 1=1")

    def test_replace_payload(self):
        wrapped = "prefix" + self.agent.addPayloadDelimiters("OLD") + "suffix"
        replaced = self.agent.replacePayload(wrapped, "NEW")
        self.assertEqual(self.agent.extractPayload(replaced), "NEW")
        # surrounding text preserved
        self.assertTrue(replaced.startswith("prefix"))
        self.assertTrue(replaced.endswith("suffix"))

    def test_simple_concatenate_mysql(self):
        set_dbms(DBMS.MYSQL)
        # MySQL concatenate query template is 'CONCAT(%s,%s)'
        self.assertEqual(self.agent.simpleConcatenate("a", "b"), "CONCAT(a,b)")

    def test_hex_convert_field_mysql(self):
        set_dbms(DBMS.MYSQL)
        # MySQL hex template is 'HEX(%s)'
        self.assertEqual(self.agent.hexConvertField("col"), "HEX(col)")

    def test_get_fields_select_from(self):
        set_dbms(DBMS.MYSQL)
        result = self.agent.getFields("SELECT a, b FROM users")
        fieldsToCastList = result[5]
        fieldsToCastStr = result[6]
        self.assertEqual(fieldsToCastStr, "a, b")
        self.assertEqual(fieldsToCastList, ["a", "b"])

    def test_get_fields_no_from(self):
        set_dbms(DBMS.MYSQL)
        # a bare SELECT without FROM -> fieldsSelectFrom is None, casts the whole select list
        result = self.agent.getFields("SELECT 1")
        fieldsSelectFrom = result[0]
        self.assertIsNone(fieldsSelectFrom)
        self.assertEqual(result[6], "1")


class TestAgentWhereQuery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from lib.core.agent import agent
        cls.agent = agent

    def setUp(self):
        self._old_dumpWhere = conf.dumpWhere
        self._old_tbl = conf.tbl
        conf.tbl = None

    def tearDown(self):
        conf.dumpWhere = self._old_dumpWhere
        conf.tbl = self._old_tbl
        set_dbms(None)

    def test_no_dumpwhere_passthrough(self):
        conf.dumpWhere = None
        query = "SELECT a FROM t"
        self.assertEqual(self.agent.whereQuery(query), query)

    def test_appends_where_clause(self):
        set_dbms(DBMS.MYSQL)
        conf.dumpWhere = "id>0"
        # no existing WHERE -> appends ' WHERE id>0'
        self.assertEqual(self.agent.whereQuery("SELECT a FROM t"), "SELECT a FROM t WHERE id>0")

    def test_and_when_where_present(self):
        set_dbms(DBMS.MYSQL)
        conf.dumpWhere = "id>0"
        # existing WHERE -> appended with AND
        self.assertEqual(
            self.agent.whereQuery("SELECT a FROM t WHERE x=1"),
            "SELECT a FROM t WHERE x=1 AND id>0",
        )

    def test_splices_before_order_by(self):
        set_dbms(DBMS.MYSQL)
        conf.dumpWhere = "id>0"
        # WHERE must be spliced before the trailing ORDER BY suffix
        self.assertEqual(
            self.agent.whereQuery("SELECT a FROM t ORDER BY a"),
            "SELECT a FROM t WHERE id>0 ORDER BY a",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
