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
# signature = (2^0=2, 2^3=8, 5/2=2, 2|0=2)
MEASURED = {
    "mysql":      ((True,  False, False, True),  DBMS.MYSQL),
    "tidb":       ((True,  False, False, True),  DBMS.MYSQL),    # MySQL wire-compatible
    "mssql":      ((True,  False, True,  True),  DBMS.MSSQL),
    "postgres":   ((False, True,  True,  True),  DBMS.PGSQL),
    "cockroach":  ((False, True,  False, True),  DBMS.PGSQL),    # pgwire (exponent '^', decimal division)
    "sqlite":     ((False, False, True,  True),  DBMS.SQLITE),
    # not distinctive enough -> deliberately no prior (operators alone can't safely separate these)
    "firebird":   ((False, False, True,  False), None),
    "hsqldb":     ((False, False, True,  False), None),          # collides with firebird/derby/h2
    "derby":      ((False, False, True,  False), None),
    "h2":         ((False, False, True,  False), None),
    "clickhouse": ((False, False, False, False), None),          # all-error, like Oracle/broken channel
}


class TestDialectClassification(unittest.TestCase):
    def test_measured_engines_map_as_expected(self):
        for engine, (signature, expected) in MEASURED.items():
            self.assertEqual(_classify(signature), expected, "engine %r misclassified" % engine)

    def test_no_false_positive_across_measured_set(self):
        # ambiguous engines must not borrow a major-DBMS identity; concrete ones must stay in range
        for engine, (signature, expected) in MEASURED.items():
            result = _classify(signature)
            if expected is None:
                self.assertIsNone(result, "ambiguous engine %r leaked a DBMS prior" % engine)
            else:
                self.assertIn(result, (DBMS.MYSQL, DBMS.MSSQL, DBMS.PGSQL, DBMS.SQLITE, DBMS.ORACLE))

    def test_all_error_signature_yields_no_prior(self):
        # an all-error signature (Oracle, ClickHouse, or simply a WAF-blocked channel) is not
        # distinctive enough - it must NOT be guessed as any DBMS
        self.assertIsNone(_classify((False, False, False, False)))

    def test_pgpow_dominates_as_postgres_marker(self):
        # exponentiation '^' is a positive PostgreSQL-family marker regardless of division flavour
        self.assertEqual(_classify((False, True, True, True)), DBMS.PGSQL)
        self.assertEqual(_classify((False, True, False, True)), DBMS.PGSQL)


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
