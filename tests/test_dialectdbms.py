#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Operator/typing-dialect DBMS heuristic (lib/utils/dialect.py). Locks in the empirical 8-probe truth
table: each measured signature maps to its expected back-end DBMS, and every other signature (unmeasured
engine, ambiguous, or noise) maps to None so the heuristic never wrong-foots detection.
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
from lib.utils.dialect import _reachCanary
from lib.utils.dialect import dialectCheckDbms
from lib.utils.dialect import DIALECT_CANARY
from lib.utils.dialect import DIALECT_PROBES
from lib.utils.dialect import DIALECT_REACH_CANARY
from lib.utils.dialect import _DIALECT_REACH_CHARS

# Full 8-probe signature (pow, intdiv, mod, bitor, xeq, bslash, catplus, numcat) measured live -> DBMS.
# Every bit is significant (strict whitelist); a one-bit-off variant is simply not a known fingerprint.
MEASURED = {
    "mysql":     (False, False, True , True , False, False, True , True , DBMS.MYSQL),
    "mysql5":    (False, False, True , True , False, False, True , True , DBMS.MYSQL),
    "tidb":      (False, False, True , True , False, False, True , True , DBMS.MYSQL),      # MySQL wire-compatible
    "postgres":  (True , True , True , True , False, False, False, False, DBMS.PGSQL),
    "opengauss": (True , False, True , True , True , False, False, True , DBMS.PGSQL),      # Oracle-compat '^='
    "cockroach": (True , False, True , True , False, False, False, False, DBMS.PGSQL),      # decimal division
    "cratedb":   (True , True , True , True , False, False, False, True , DBMS.PGSQL),
    "mssql2019": (False, True , True , True , False, False, True , False, DBMS.MSSQL),      # no '<<'
    "mssql2022": (False, True , True , True , False, False, True , False, DBMS.MSSQL),      # gained '<<' but shift is not a probe -> same signature
    "sqlite":    (False, True , True , True , False, False, False, False, DBMS.SQLITE),
    "clickhouse":(False, False, True , False, False, False, False, True , DBMS.CLICKHOUSE),# no bitwise-OR
    "monetdb":   (False, True , True , True , False, False, False, True , DBMS.MONETDB),    # like MSSQL but no '+' concat
    "firebird":  (False, True , False, False, True , False, False, True , DBMS.FIREBIRD),  # has '^='
    "h2":        (False, True , True , False, False, False, False, True , DBMS.H2),
    "hsqldb":    (False, True , False, False, False, False, True , False, DBMS.HSQLDB),    # '+' concat
    "derby":     (False, True , False, False, False, False, False, False, DBMS.DERBY),
    "iris":      (False, False, False, False, False, True , False, True , DBMS.CACHE),     # '\' int-div (Oracle-like but no '^=')
    "trino":     (False, True , True , False, False, False, False, False, DBMS.PRESTO),
    "oracle":    (False, False, False, False, True , False, False, True , DBMS.ORACLE),    # '^=' not-equal
    "informix":  (False, False, False, False, False, False, False, True , DBMS.INFORMIX),
    "cubrid":    (False, True , True , True , False, False, True , True , DBMS.CUBRID),     # like MonetDB but '+' concat
    "db2":       (False, True , True , True , True , False, False, True , DBMS.DB2),        # '^=', no '<<'/'\'
    "vertica":   (True , False, True , True , False, False, False, True , DBMS.VERTICA),    # pg-derived but numeric '||'
    "access":    (True , False, False, False, False, True , True , False, DBMS.ACCESS),    # ACE/JET: '^' exp + '\' int-div + '+' concat, no '%'/'|'/'||'
}

# Documentation-derived (vendor operator spec, not live-tested); only where the signature is a free slot.
DOCUMENTED = {
    "spanner":   (False, False, False, True , False, False, False, False, DBMS.SPANNER),
}

_PROBE_COUNT = len(DIALECT_PROBES)
_ALL = dict(MEASURED); _ALL.update(DOCUMENTED)


def _sig(engine):
    return _ALL[engine][:_PROBE_COUNT]


class TestDialectClassification(unittest.TestCase):
    def test_probe_count_matches_signature_width(self):
        # the MEASURED rows and the doctested matrix must stay the same width as DIALECT_PROBES
        self.assertEqual(_PROBE_COUNT, 8)

    def test_measured_engines_map_as_expected(self):
        # each engine's exact measured 8-probe signature maps to its expected DBMS
        for engine, row in MEASURED.items():
            self.assertEqual(_classify(row[:_PROBE_COUNT]), row[_PROBE_COUNT], "engine %r misclassified" % engine)

    def test_documented_engines_map_as_expected(self):
        # doc-derived rows (not live-tested) still resolve to their expected DBMS via the whitelist
        for engine, row in DOCUMENTED.items():
            self.assertEqual(_classify(row[:_PROBE_COUNT]), row[_PROBE_COUNT], "engine %r misclassified" % engine)

    def test_mssql_version_agnostic(self):
        # SQL Server 2022 gained '<<' but 'shift' is deliberately NOT a probe (it collided MSSQL 2022
        # with MonetDB); both versions share one signature and '+' concat separates MSSQL from MonetDB.
        self.assertEqual(_classify(_sig("mssql2019")), DBMS.MSSQL)
        self.assertEqual(_classify(_sig("mssql2022")), DBMS.MSSQL)
        self.assertEqual(_classify(_sig("monetdb")), DBMS.MONETDB)

    def test_oracle_iris_split_by_operators(self):
        # Oracle and IRIS are near-identical; '^=' (Oracle) vs '\' int-div (IRIS) split them.
        self.assertEqual(_classify(_sig("oracle")), DBMS.ORACLE)
        self.assertEqual(_classify(_sig("iris")), DBMS.CACHE)

    def test_previously_colliding_engines_now_split(self):
        # the 4 late-measured engines collided on smaller probe sets; the 8-probe matrix separates them
        # (Informix != IRIS, CUBRID != MonetDB, Vertica != PostgreSQL, DB2 != all-true noise).
        self.assertEqual(_classify(_sig("informix")), DBMS.INFORMIX)
        self.assertEqual(_classify(_sig("cubrid")), DBMS.CUBRID)
        self.assertEqual(_classify(_sig("vertica")), DBMS.VERTICA)
        self.assertEqual(_classify(_sig("db2")), DBMS.DB2)

    def test_whitelist_is_exact_no_false_positive(self):
        # exhaustively sweep all 256 signatures: a non-None result is allowed ONLY for a known one
        classifying = set(row[:_PROBE_COUNT] for row in _ALL.values())
        for bits in range(1 << _PROBE_COUNT):
            sig = tuple(bool(bits & (1 << i)) for i in range(_PROBE_COUNT))
            if sig not in classifying:
                self.assertIsNone(_classify(sig), "unmeasured signature %r wrongly mapped to %r" % (sig, _classify(sig)))

    def test_all_true_noise_is_rejected(self):
        # a channel reading EVERY probe true (static/reflected page or false-positive oracle) is
        # physically impossible and must NOT be guessed
        self.assertIsNone(_classify((True,) * _PROBE_COUNT))


class TestDialectCheckDbmsGuard(unittest.TestCase):
    """dialectCheckDbms() end-to-end with a mocked boolean oracle: correct DBMS on a good channel, and
    None whenever the channel is unreliable (including the canary that turns a trashy false-positive
    channel into a true negative)."""

    def _run(self, probeBits, gate=(True, False, False), blocked=()):
        # probeBits: {probe_name: bool}; gate: (2=2, 2=3, canary); blocked: chars a WAF drops
        truth = {"2=2": gate[0], "2=3": gate[1], DIALECT_CANARY: gate[2]}
        for name, expr in DIALECT_PROBES:
            truth[expr] = bool(probeBits.get(name, False))
        # clean channel: all reachability canaries TRUE; a blocked char reads FALSE (combined + per-char)
        truth[DIALECT_REACH_CANARY] = not blocked
        for char, _ in _DIALECT_REACH_CHARS:
            truth[_reachCanary(char)] = char not in blocked
        orig = dialect.checkBooleanExpression
        dialect.checkBooleanExpression = lambda expr, **kwargs: bool(truth.get(expr, False))
        saved = kb.get("injection")
        try:
            return dialectCheckDbms(object())
        finally:
            dialect.checkBooleanExpression = orig
            kb.injection = saved

    @staticmethod
    def _bits(engine):
        return dict(zip((n for n, _ in DIALECT_PROBES), _sig(engine)))

    def test_identifies_mysql_on_good_channel(self):
        self.assertEqual(self._run(self._bits("mysql")), DBMS.MYSQL)

    def test_identifies_postgres_on_good_channel(self):
        self.assertEqual(self._run(self._bits("postgres")), DBMS.PGSQL)

    def test_identifies_oracle_on_good_channel(self):
        self.assertEqual(self._run(self._bits("oracle")), DBMS.ORACLE)

    def test_none_on_blocked_channel(self):
        # everything blocked/false -> the tautology 2=2 reads False -> sanity fails -> None
        self.assertIsNone(self._run({}, gate=(False, False, False)))

    def test_none_on_static_channel(self):
        # a static page reads everything True -> the contradiction 2=3 is True -> sanity fails -> None
        self.assertIsNone(self._run(self._bits("mysql"), gate=(True, True, True)))

    def test_none_when_canary_reads_true(self):
        # THE canary contract: a channel can look clean (2=2 true, 2=3 false) and yield a DBMS-shaped
        # signature, but if the invalid canary also reads TRUE the channel accepts garbage -> None.
        self.assertIsNone(self._run(self._bits("mysql"), gate=(True, False, True)))


class TestDialectAdversarial(unittest.TestCase):
    """WAF that selectively drops operator characters: a dropped probe reads FALSE, silently degrading
    the signature. Reachability canaries mark those bits unknown and _classify() abstains unless the
    trusted bits are unanimous - so char-blocking can never MISCLASSIFY (only answer correctly or None)."""

    def test_guard_never_misclassifies_under_single_char_block(self):
        # for every droppable probe character, no known engine is ever read as a DIFFERENT DBMS
        for char, bits in _DIALECT_REACH_CHARS:
            for engine, row in _ALL.items():
                expected = row[_PROBE_COUNT]
                got = _classify(row[:_PROBE_COUNT], unknown=set(bits))
                self.assertIn(got, (expected, None), "%s under blocked %r -> %s" % (engine, char, got))

    def test_guard_recovers_when_trusted_bits_are_unique(self):
        # MySQL stays uniquely pinned with 'mod' (%) blocked
        self.assertEqual(_classify(_sig("mysql"), unknown={2}), DBMS.MYSQL)

    def test_guard_abstains_when_ambiguous(self):
        # H2 vs Presto differ only in numcat; blocking '|' (kills numcat) makes them indistinguishable
        self.assertIsNone(_classify(_sig("h2"), unknown={7}))


class TestDialectCheckDbmsReachability(TestDialectCheckDbmsGuard):
    """dialectCheckDbms() end-to-end when a WAF drops a probe character."""

    def test_blocked_char_abstains_instead_of_misclassifying(self):
        # '|' dropped: H2 can no longer be told from Presto -> None (not a wrong guess)
        self.assertIsNone(self._run(self._bits("h2"), blocked=("|",)))

    def test_blocked_char_still_identifies_when_unique(self):
        # '%' dropped: MySQL stays uniquely identifiable
        self.assertEqual(self._run(self._bits("mysql"), blocked=("%",)), DBMS.MYSQL)


if __name__ == "__main__":
    unittest.main(verbosity=2)
