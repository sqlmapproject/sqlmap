#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

The keyset (seek) pagination dump engine (lib/utils/keysetdump.py).

Large tables are dumped one row at a time by seeking on an indexed cursor (a
row-id or the primary key). For a COMPOSITE key the walk must advance the tuple
lexicographically. Doing that with an ANSI row-value comparison ((a,b)>(x,y))
breaks on back-ends without row-value support (MSSQL/Oracle): the advance query
errors, the walk stops after the very first row and the rest of the table is
silently dropped (proven live against MSSQL: a 5-row table dumped a single row).

We drive the REAL keysetDumpTable against a mock oracle backing a small table.
The mock has a knob to REJECT ANSI row-value comparisons (like MSSQL/Oracle);
the composite walk must still retrieve every row via the portable
(a>x) OR (a=x AND b>y) predicate.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms, reset_dbms
bootstrap()

from lib.core.data import conf, kb
from lib.request import inject
import lib.utils.keysetdump as ks

# table with a COMPOSITE key (a, b), kept in (a, b) order; third column is plain data
_ROWS = [(1, 1, "alpha"), (1, 2, "beta"), (2, 5, "gamma"), (3, 1, "delta"), (3, 2, "epsilon")]
_COL_INDEX = {"a": 0, "b": 1, "d": 2}


def _condTrue(cond, row):
    """Evaluate a (simple) SQL WHERE condition emitted by keysetdump against one row."""
    a, b, d = row
    expr = cond.replace(" AND ", " and ").replace(" OR ", " or ")
    expr = re.sub(r"\bd\b", repr(d), expr)
    expr = re.sub(r"\ba\b", str(a), expr)
    expr = re.sub(r"\bb\b", str(b), expr)
    expr = expr.replace("=", "==")
    return bool(eval(expr))


class TestKeysetCompositeCursor(unittest.TestCase):
    def setUp(self):
        self._s = {
            "db": conf.get("db"), "limitStart": conf.get("limitStart"), "limitStop": conf.get("limitStop"),
            "dumpWhere": conf.get("dumpWhere"), "cachedColumns": kb.data.get("cachedColumns"),
            "gv": inject.getValue,
        }
        conf.db = "testdb"
        conf.limitStart = conf.limitStop = conf.dumpWhere = None
        kb.data.cachedColumns = {}
        set_dbms("MySQL")

    def tearDown(self):
        conf.db = self._s["db"]
        conf.limitStart = self._s["limitStart"]
        conf.limitStop = self._s["limitStop"]
        conf.dumpWhere = self._s["dumpWhere"]
        kb.data.cachedColumns = self._s["cachedColumns"]
        inject.getValue = self._s["gv"]

    def _install_oracle(self, rowValueSupported, dropped=()):
        def oracle(query=None, **kwargs):
            # a back-end without ANSI row-value support errors on (a,b)>(x,y) -> no result
            if re.search(r"\)\s*>\s*\(", query or "") and not rowValueSupported:
                return None
            m = re.search(r"SELECT (\w+) FROM .+? WHERE (.+) ORDER BY .+ LIMIT 1", query or "")   # advance
            if m:
                cand = sorted(r for r in _ROWS if _condTrue(m.group(2), r))
                if not cand:
                    return None
                if (m.group(1), cand[0]) in dropped:   # a key cell the channel did not bring back
                    return None
                return str(cand[0][_COL_INDEX[m.group(1)]])
            m = re.search(r"SELECT MAX\((\w+)\) FROM .+? WHERE (.+)", query or "")                 # point fetch
            if m:
                cand = [r for r in _ROWS if _condTrue(m.group(2), r)]
                return None if not cand else str(cand[0][_COL_INDEX[m.group(1)]])
            return None

        inject.getValue = oracle

    def _walk(self, rowValueSupported, dropped=()):
        """The raw result: (entries, lengths), or None when the walk gave up and the caller must fall back."""

        self._install_oracle(rowValueSupported, dropped)

        return ks.keysetDumpTable("users", ["a", "b", "d"], len(_ROWS), ["a", "b"])

    def _dump(self, rowValueSupported, dropped=()):
        entries, _ = self._walk(rowValueSupported, dropped)

        return list(zip(entries["a"], entries["b"], entries["d"]))

    def test_all_rows_when_row_value_supported(self):
        rows = self._dump(rowValueSupported=True)
        self.assertEqual(len(rows), len(_ROWS))

    def test_all_rows_when_row_value_rejected(self):
        # MSSQL/Oracle case: the composite walk must NOT truncate to the first row
        rows = self._dump(rowValueSupported=False)
        self.assertEqual(len(rows), len(_ROWS))
        self.assertEqual([r[2] for r in rows], [r[2] for r in _ROWS])

    def test_unretrieved_key_cell_is_handed_back_for_the_offset_fallback(self):
        # one key column of a row that does not come back (an error-channel miss, a blocked payload)
        # leaves a None in the cursor tuple. Seeking on it is impossible, so the walk must hand back
        # NOTHING - it used to format that None into the next seek predicate (a TypeError, issue
        # #6097) and, once the predicate became a plain '%s', to emit a row of empty cells and then
        # silently truncate the table
        self.assertIsNone(self._walk(rowValueSupported=True, dropped={("b", (2, 5, "gamma"))}))


if __name__ == "__main__":
    unittest.main(verbosity=2)


def tearDownModule():
    reset_dbms()   # clear any DBMS forced via set_dbms() so it can't leak into later test modules
