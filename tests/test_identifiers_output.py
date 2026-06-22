#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Identifier quoting per DBMS dialect, CSV value escaping, and dump value
replacement markers.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.common import safeSQLIdentificatorNaming, unsafeSQLIdentificatorNaming, safeCSValue
from lib.core.enums import DBMS


class TestIdentifierQuoting(unittest.TestCase):
    # special-char identifier -> the per-dialect quoting wrapper
    WRAP = {
        DBMS.MYSQL:  "`weird name`",
        DBMS.MSSQL:  "[weird name]",
        DBMS.PGSQL:  '"weird name"',
        DBMS.ORACLE: '"WEIRD NAME"',   # Oracle upper-cases quoted identifiers
    }

    def test_special_identifier_quoting(self):
        for dbms, wrapped in self.WRAP.items():
            set_dbms(dbms)
            self.assertEqual(safeSQLIdentificatorNaming("weird name"), wrapped, msg=str(dbms))

    def test_simple_identifier_roundtrip(self):
        # plain identifier needs no quoting; round-trips identically on case-preserving dialects
        for dbms in (DBMS.MYSQL, DBMS.MSSQL, DBMS.PGSQL):
            set_dbms(dbms)
            for ident in ("users", "password", "tbl1"):
                self.assertEqual(safeSQLIdentificatorNaming(ident), ident, msg="%s %r" % (dbms, ident))
                self.assertEqual(unsafeSQLIdentificatorNaming(safeSQLIdentificatorNaming(ident)), ident)

    def test_oracle_uppercases_on_unsafe(self):
        # documented dialect quirk: Oracle unsafe-naming upper-cases identifiers
        set_dbms(DBMS.ORACLE)
        self.assertEqual(safeSQLIdentificatorNaming("users"), "users")
        self.assertEqual(unsafeSQLIdentificatorNaming(safeSQLIdentificatorNaming("users")), "USERS")

    def test_unsafe_strips_quotes(self):
        for dbms in (DBMS.MYSQL, DBMS.MSSQL, DBMS.PGSQL):
            set_dbms(dbms)
            self.assertEqual(unsafeSQLIdentificatorNaming(safeSQLIdentificatorNaming("weird name")), "weird name")


class TestSafeCSValue(unittest.TestCase):
    CASES = [
        ("foobar",   "foobar"),       # plain -> unchanged
        ("foo,bar",  '"foo,bar"'),    # contains delimiter -> quoted
        ('he"y',     '"he""y"'),      # contains quote -> doubled + wrapped
        ("a\nb",     '"a\nb"'),       # contains newline -> quoted
        ('"a","b"',  '"""a"",""b"""'),  # value that begins+ends with a quote must STILL be escaped
        ('"',        '""""'),           # lone quote -> doubled + wrapped
    ]

    def test_table(self):
        for inp, expected in self.CASES:
            self.assertEqual(safeCSValue(inp), expected, msg="safeCSValue(%r)" % inp)

    def test_csv_roundtrip(self):
        # the real invariant: a dumped cell must come back as exactly ONE field with its original
        # content (a value that begins+ends with '"' must not be emitted verbatim - that splits it)
        import csv
        for value in ("foobar", "foo,bar", 'he"y', '"a","b"', '"', 'a"b"c'):
            line = safeCSValue(value)
            fields = next(csv.reader([line]))   # csv.reader accepts any iterable of text lines (py2+py3)
            self.assertEqual(fields, [value], msg="round-trip failed for %r -> %r" % (value, line))


# (DUMP_REPLACEMENTS markers are covered in test_dicts.py - not duplicated here)


if __name__ == "__main__":
    unittest.main(verbosity=2)
