#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Cross-dialect exercise of lib/core/agent.py payload-assembly helpers.

agent.py builds SQL payloads from per-DBMS dialect templates (queries.xml).
The helpers are pure given the identified back-end DBMS, so driving each one
across EVERY supported dialect walks the dialect-specific branches (CAST forms,
concatenation operators, LIMIT/TOP/ROWNUM shapes, ...) without a live target.

These are smoke-level assertions (right type, dialect tokens present) rather than
golden strings: the goal is to traverse the dialect branches the single-DBMS
tests in test_agent.py do not reach.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.agent import agent
from lib.core.data import queries

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


class TestConcatQuery(unittest.TestCase):
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


class TestForgeUnionQuery(unittest.TestCase):
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


class TestLimitQuery(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
