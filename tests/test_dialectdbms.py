#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Operator-dialect DBMS heuristic (lib/utils/dialect.py). These lock in the empirical truth table:
the full 5-probe (2^0=2, 2^3=8, 5/2=2, 2|0=2, 1<<2=4) operator signatures measured across the live
SQL engines on an OWASP-CRS test platform, asserting _classify() maps each EXACT signature to the
expected back-end DBMS via its whitelist - and, just as importantly, that anything else (an
unmeasured engine, an ambiguous signature, or a physically-impossible / noise signature) maps to
None, so the heuristic never wrong-foots detection. The end-to-end behaviour (the probes producing
these signatures through a real boolean injection) is exercised against the live platform, not here.
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
from lib.utils.dialect import DIALECT_CANARY

# Full 5-probe signature (2^0=2, 2^3=8, 5/2=2, 2|0=2, 1<<2=4) measured live -> expected DBMS.
# Every bit is significant now (whitelist): e.g. MySQL/PostgreSQL/... all have a working '<<', so
# shift=True is part of their signature; a one-bit-off variant is simply not a known fingerprint.
MEASURED = {
    "mysql":      ((True,  False, False, True,  True),  DBMS.MYSQL),
    "mysql5":     ((True,  False, False, True,  True),  DBMS.MYSQL),
    "tidb":       ((True,  False, False, True,  True),  DBMS.MYSQL),    # MySQL wire-compatible
    "postgres":   ((False, True,  True,  True,  True),  DBMS.PGSQL),
    "cockroach":  ((False, True,  False, True,  True),  DBMS.PGSQL),    # pgwire (exponent '^', decimal division, has '<<')
    "cratedb":    ((False, True,  True,  True,  False), DBMS.PGSQL),    # pgwire family (no '<<')
    "mssql":      ((True,  False, True,  True,  False), DBMS.MSSQL),    # '^' XOR, integer division, NO bit-shift
    "monetdb":    ((True,  False, True,  True,  True),  DBMS.MONETDB),  # shares MSSQL base but HAS '<<'
    "sqlite":     ((False, False, True,  True,  True),  DBMS.SQLITE),
    # not distinctive enough -> deliberately no prior (operators alone can't safely separate these)
    "firebird":   ((False, False, True,  False, False), None),
    "hsqldb":     ((False, False, True,  False, False), None),          # collides with firebird/derby/h2/trino
    "derby":      ((False, False, True,  False, False), None),
    "h2":         ((False, False, True,  False, False), None),
    "trino":      ((False, False, True,  False, False), None),
    "iris":       ((False, False, False, False, False), None),         # all-error, like Oracle/broken channel
    "clickhouse": ((False, False, False, False, False), None),         # all-error, like Oracle/broken channel
}


class TestDialectClassification(unittest.TestCase):
    def test_measured_engines_map_as_expected(self):
        # each engine's exact measured 5-probe signature maps to its expected DBMS (or None)
        for engine, (signature, expected) in MEASURED.items():
            self.assertEqual(_classify(signature), expected, "engine %r misclassified" % engine)

    def test_shift_splits_monetdb_from_mssql(self):
        # MonetDB shares MSSQL's (xor, intdiv) base exactly (a false positive before the shift probe);
        # 1<<2=4 (MonetDB has it, SQL Server never does) is the sole separator.
        self.assertEqual(_classify((True, False, True, True, False)), DBMS.MSSQL)
        self.assertEqual(_classify((True, False, True, True, True)), DBMS.MONETDB)

    def test_whitelist_is_exact_no_false_positive(self):
        # only the measured classifying signatures may yield a DBMS; everything else -> None.
        classifying = set(sig for sig, exp in MEASURED.values() if exp is not None)
        produced = set(exp for _, exp in MEASURED.values() if exp is not None)
        self.assertEqual(produced, {DBMS.MYSQL, DBMS.PGSQL, DBMS.MSSQL, DBMS.MONETDB, DBMS.SQLITE})
        # exhaustively sweep all 32 signatures: a non-None result is allowed ONLY for a measured one
        for bits in range(32):
            sig = tuple(bool(bits & (1 << i)) for i in range(5))
            result = _classify(sig)
            if sig not in classifying:
                self.assertIsNone(result, "unmeasured signature %r wrongly mapped to %r" % (sig, result))

    def test_all_true_noise_is_rejected(self):
        # a channel that reads EVERY probe true (a static/reflected page, or a WAF/false-positive
        # oracle) produces the all-true signature - physically impossible ('^' cannot be XOR and
        # exponentiation at once). It must NOT be guessed (previously it mis-read as PostgreSQL).
        self.assertIsNone(_classify((True, True, True, True, True)))

    def test_all_error_signature_yields_no_prior(self):
        # an all-error signature (Oracle, ClickHouse, IRIS, or a WAF-blocked channel) is not
        # distinctive - it must NOT be guessed as any DBMS
        self.assertIsNone(_classify((False, False, False, False, False)))
        self.assertIsNone(_classify((False, False, False, False, True)))

    def test_pgpow_alone_is_not_enough(self):
        # exponentiation '^' is a PostgreSQL marker, but pgpow ALONE no longer classifies: the full
        # signature must match a measured PostgreSQL fingerprint (this is what stops the all-true noise
        # from riding the old 'pgpow dominates' rule into a bogus PostgreSQL claim).
        self.assertEqual(_classify((False, True, True, True, True)), DBMS.PGSQL)   # real PostgreSQL
        self.assertIsNone(_classify((True, True, False, False, False)))            # pgpow set, but not a real signature


class TestDialectCheckDbmsGuard(unittest.TestCase):
    """dialectCheckDbms() end-to-end with a mocked boolean oracle: correct DBMS on a good channel,
    and None (no prior) whenever the channel is unreliable - the safety contract, including the
    canary that turns a trashy false-positive channel into a true negative."""

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
        truth = {"2=2": True, "2=3": False, DIALECT_CANARY: False,
                 "2^0=2": True, "2^3=8": False, "5/2=2": False, "2|0=2": True, "1<<2=4": True}
        self.assertEqual(self._run(truth), DBMS.MYSQL)

    def test_identifies_postgres_on_good_channel(self):
        truth = {"2=2": True, "2=3": False, DIALECT_CANARY: False,
                 "2^0=2": False, "2^3=8": True, "5/2=2": True, "2|0=2": True, "1<<2=4": True}
        self.assertEqual(self._run(truth), DBMS.PGSQL)

    def test_none_on_blocked_channel(self):
        # everything blocked/false -> the tautology 2=2 reads False -> sanity fails -> None
        self.assertIsNone(self._run({}))

    def test_none_on_static_channel(self):
        # a static page reads everything True, so the contradiction 2=3 is True -> sanity fails -> None
        self.assertIsNone(self._run({"2=2": True, "2=3": True, DIALECT_CANARY: True,
                                     "2^0=2": True, "2^3=8": True, "5/2=2": True, "2|0=2": True, "1<<2=4": True}))

    def test_none_when_canary_reads_true(self):
        # THE canary contract: a channel can look like a clean oracle (2=2 true, 2=3 false) and even
        # yield a DBMS-shaped signature, but if the syntactically-invalid canary also reads TRUE the
        # channel accepts garbage -> it is a false positive -> return None (true negative), never a DBMS.
        truth = {"2=2": True, "2=3": False, DIALECT_CANARY: True,
                 "2^0=2": True, "2^3=8": False, "5/2=2": False, "2|0=2": True, "1<<2=4": True}  # would be MySQL
        self.assertIsNone(self._run(truth))


if __name__ == "__main__":
    unittest.main(verbosity=2)
