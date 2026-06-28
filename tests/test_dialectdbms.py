#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Operator-dialect DBMS heuristic (lib/utils/dialect.py). These lock in the empirical truth
table: the (xor, intdiv, pgcast, bitor) operator signatures measured across 11 live engines
on an OWASP-CRS test platform, asserting that _classify() maps each to the expected back-end
DBMS - and, just as importantly, that the engines whose signatures collide or are ambiguous
map to None (no prior), so the heuristic never wrong-foots detection. The end-to-end behaviour
(the probes producing these signatures through a real boolean injection) is exercised against
the live platform, not here.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import lib.utils.dialect as dialect
from lib.core.data import kb
from lib.core.enums import DBMS
from lib.utils.dialect import _classify
from lib.utils.dialect import dialectCheckDbms

# measured 2026-06 across the sqli-platform (boolean form "id=2 AND <probe>", anchor value 2);
# base signature = (2^0=2, 2^3=8, 5/2=2, 2|0=2). The 5th probe (1<<2=4, bit-shift) is the MonetDB-vs-
# SQL Server disambiguator and is asserted separately (SHIFT_SENSITIVE); for every other engine the
# shift flag does NOT change the classification, which the test proves by trying it both ways.
MEASURED = {
    "mysql":      ((True,  False, False, True),  DBMS.MYSQL),
    "mysql5":     ((True,  False, False, True),  DBMS.MYSQL),
    "tidb":       ((True,  False, False, True),  DBMS.MYSQL),    # MySQL wire-compatible
    "postgres":   ((False, True,  True,  True),  DBMS.PGSQL),
    "cockroach":  ((False, True,  False, True),  DBMS.PGSQL),    # pgwire (exponent '^', decimal division)
    "cratedb":    ((False, True,  True,  True),  DBMS.PGSQL),    # pgwire family
    "sqlite":     ((False, False, True,  True),  DBMS.SQLITE),
    # not distinctive enough -> deliberately no prior (operators alone can't safely separate these)
    "firebird":   ((False, False, True,  False), None),
    "hsqldb":     ((False, False, True,  False), None),          # collides with firebird/derby/h2
    "derby":      ((False, False, True,  False), None),
    "h2":         ((False, False, True,  False), None),
    "trino":      ((False, False, True,  False), None),
    "iris":       ((False, False, False, False), None),          # all-error, like Oracle/broken channel
    "clickhouse": ((False, False, False, False), None),          # all-error, like Oracle/broken channel
}

# engines whose full 5-probe signature (incl. 1<<2=4) is needed because they share base-4 (xor,intdiv)
# and only the bit-shift probe separates them: SQL Server has no shift operator, MonetDB does.
SHIFT_SENSITIVE = {
    "mssql":   ((True, False, True, True, False), DBMS.MSSQL),
    "monetdb": ((True, False, True, True, True),  DBMS.MONETDB),
}


class TestDialectClassification(unittest.TestCase):
    def test_shift_sensitive_engines_split_correctly(self):
        # MonetDB shared MSSQL's (xor, intdiv) signature exactly (a false positive before the shift
        # probe); 1<<2=4 (MonetDB only) now separates them.
        for engine, (signature, expected) in SHIFT_SENSITIVE.items():
            self.assertEqual(_classify(signature), expected, "engine %r misclassified" % engine)

    def test_measured_engines_map_as_expected(self):
        # for non-shift-sensitive engines the shift flag is irrelevant: assert BOTH values map to the
        # expected DBMS (proves the new probe never perturbs the existing classifications).
        for engine, (base, expected) in MEASURED.items():
            for shift in (False, True):
                self.assertEqual(_classify(base + (shift,)), expected, "engine %r misclassified (shift=%s)" % (engine, shift))

    def test_no_false_positive_across_measured_set(self):
        # non-collision property: every measured engine maps to EXACTLY its expected DBMS (or None),
        # never to some other back-end. The shift flag is irrelevant for these (non-shift-sensitive)
        # engines, so assert it both ways.
        for engine, (base, expected) in MEASURED.items():
            for shift in (False, True):
                result = _classify(base + (shift,))
                self.assertEqual(result, expected, "engine %r misclassified (shift=%s): got %r, expected %r" % (engine, shift, result, expected))
        # the only non-None DBMS priors the measured set can yield (sanity on the mapping itself)
        produced = set(expected for _, expected in MEASURED.values() if expected is not None)
        self.assertEqual(produced, {DBMS.MYSQL, DBMS.PGSQL, DBMS.SQLITE})

    def test_all_error_signature_yields_no_prior(self):
        # an all-error signature (Oracle, ClickHouse, IRIS, or simply a WAF-blocked channel) is not
        # distinctive enough - it must NOT be guessed as any DBMS
        self.assertIsNone(_classify((False, False, False, False, False)))
        self.assertIsNone(_classify((False, False, False, False, True)))

    def test_pgpow_dominates_as_postgres_marker(self):
        # exponentiation '^' is a positive PostgreSQL-family marker regardless of division flavour
        self.assertEqual(_classify((False, True, True, True, False)), DBMS.PGSQL)
        self.assertEqual(_classify((False, True, False, True, False)), DBMS.PGSQL)


class TestDialectCheckDbmsGuard(unittest.TestCase):
    """dialectCheckDbms() end-to-end with a mocked boolean oracle: correct DBMS on a good
    channel, and None (no prior) whenever the channel is unreliable - the safety contract."""

    def _run(self, truth):
        # truth: {expression: bool} simulating checkBooleanExpression through a confirmed injection
        orig = dialect.checkBooleanExpression
        dialect.checkBooleanExpression = lambda expr, **kwargs: bool(truth.get(expr, False))
        saved = kb.get("injection")
        try:
            return dialectCheckDbms(object())   # the injection arg is only stashed, never inspected here
        finally:
            dialect.checkBooleanExpression = orig
            kb.injection = saved

    def test_identifies_mysql_on_good_channel(self):
        truth = {"2=2": True, "2=3": False, "2^0=2": True, "2^3=8": False, "5/2=2": False, "2|0=2": True}
        self.assertEqual(self._run(truth), DBMS.MYSQL)

    def test_identifies_postgres_on_good_channel(self):
        truth = {"2=2": True, "2=3": False, "2^0=2": False, "2^3=8": True, "5/2=2": True, "2|0=2": True}
        self.assertEqual(self._run(truth), DBMS.PGSQL)

    def test_none_on_blocked_channel(self):
        # everything blocked/false -> the tautology 2=2 reads False -> sanity fails -> None
        self.assertIsNone(self._run({}))

    def test_none_on_static_channel(self):
        # a static page reads everything True, so the contradiction 2=3 is True -> sanity fails -> None
        self.assertIsNone(self._run({"2=2": True, "2=3": True, "2^0=2": True, "2^3=8": True, "5/2=2": True, "2|0=2": True}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
