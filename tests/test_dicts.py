#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Structural invariants of the data-mapping tables in lib/core/dicts.py.

These tables drive DBMS recognition, connector selection, dummy-table dialect,
and dump formatting. They are pure data, so the right tests are shape/coverage
invariants: every back-end has a connector entry, alias lists are well-formed,
and the dialect maps carry the values the engine expects.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core import dicts
from lib.core.enums import DBMS
from lib.core.common import getPublicTypeMembers


class TestDbmsDict(unittest.TestCase):
    def test_every_dbms_enum_has_connector_entry(self):
        # DBMS_DICT keys must cover every public DBMS enum value
        enum_values = set(v for _, v in getPublicTypeMembers(DBMS))
        missing = enum_values - set(dicts.DBMS_DICT.keys())
        self.assertEqual(missing, set(), msg="DBMS without DBMS_DICT entry: %s" % missing)

    def test_entry_shape(self):
        # each entry: (aliases-tuple, connector-name, connector-url, sqlalchemy-dialect)
        self.assertGreaterEqual(len(dicts.DBMS_DICT), 25, msg="DBMS_DICT suspiciously small")
        for name, entry in dicts.DBMS_DICT.items():
            self.assertEqual(len(entry), 4, msg="malformed DBMS_DICT entry for %s" % name)
            aliases = entry[0]
            self.assertIsInstance(aliases, (tuple, list), msg="aliases not list-like for %s" % name)
            self.assertGreaterEqual(len(aliases), 1, msg="no aliases for %s" % name)
            for a in aliases:   # per-item, so a failure names the offending alias
                self.assertIsInstance(a, str, msg="non-str alias %r for %s" % (a, name))

    def test_aliases_are_lowercase(self):
        for name, entry in dicts.DBMS_DICT.items():
            for alias in entry[0]:
                self.assertEqual(alias, alias.lower(), msg="alias %r (for %s) is not lowercase" % (alias, name))


class TestFromDummyTable(unittest.TestCase):
    def test_oracle_uses_dual(self):
        self.assertEqual(dicts.FROM_DUMMY_TABLE[DBMS.ORACLE], " FROM DUAL")

    def test_mysql_has_no_dummy_table(self):
        # MySQL allows a bare SELECT, so it must NOT appear here
        self.assertNotIn(DBMS.MYSQL, dicts.FROM_DUMMY_TABLE)

    def test_values_start_with_from(self):
        # strict: must be (optional leading space) FROM <whitespace> <a real table token> -
        # not just startswith("FROM"), which would accept "FROMX" or a bare "FROM"
        for name, clause in dicts.FROM_DUMMY_TABLE.items():
            self.assertTrue(re.match(r"^\s*FROM\s+\S", clause.upper()),
                            msg="FROM_DUMMY_TABLE[%s]=%r is not a well-formed FROM clause" % (name, clause))


class TestSqlStatements(unittest.TestCase):
    def test_known_categories_present(self):
        for category in ("SQL data definition", "SQL data manipulation", "SQL data control"):
            self.assertIn(category, dicts.SQL_STATEMENTS, msg="missing SQL_STATEMENTS category %r" % category)

    def test_keywords_are_lowercase_tokens(self):
        for category, keywords in dicts.SQL_STATEMENTS.items():
            self.assertTrue(len(keywords) >= 1, msg="empty category %r" % category)
            for kw in keywords:
                self.assertEqual(kw, kw.lower(), msg="keyword %r in %r not lowercase" % (kw, category))


class TestDumpReplacements(unittest.TestCase):
    def test_markers(self):
        self.assertEqual(dicts.DUMP_REPLACEMENTS.get(""), "<blank>")
        self.assertEqual(dicts.DUMP_REPLACEMENTS.get(" "), "NULL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
