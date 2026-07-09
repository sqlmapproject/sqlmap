#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.request.inject import checkBooleanExpression

# Operator-dialect probes for a keyword-free back-end DBMS heuristic.
#
# Each probe is an arithmetic identity that holds only in the dialect(s) noted, using operator
# *semantics* alone - no SQL keywords, functions, quotes or schema names. It complements
# heuristicCheckDbms() (which uses (SELECT 'x')='x' string round-trips): the dialect probes carry
# no SELECT/quote, so they can narrow the back-end DBMS where those are dropped (e.g. a
# keyword-matching WAF/IPS, or when kb.droppingRequests has it skipped entirely).
#
# Each probe is evaluated through checkBooleanExpression(), i.e. as an appended boolean
# (... AND (<probe>)), which yields a clean true/false from the comparison oracle. (A value-position
# variant - replacing the value with id=2^0 etc. - was prototyped and rejected: those probes land on
# OTHER valid rows, which sqlmap's fuzzy page comparison conflates with the anchor row, producing
# false positives. See PROVE_DESIGN.md.)
#
# Signatures were measured against every SQL engine on a live OWASP-CRS platform (MySQL/MySQL5,
# MariaDB/TiDB, PostgreSQL, CockroachDB, CrateDB, Microsoft SQL Server, SQLite, Firebird, ClickHouse,
# H2, HSQLDB, Derby, MonetDB, IRIS, Trino) and encoded as an exact-signature WHITELIST in _classify()
# (only measured signatures classify; anything else -> None). With anchor value 2:
#
#   * 2^0=2  -> '^' is bitwise XOR (MySQL/MSSQL/MonetDB: 2^0=2) vs exponentiation (PostgreSQL: 2^0=1)
#              vs no such operator (SQLite/Oracle/... -> error, so false)
#   * 2^3=8  -> '^' is exponentiation (PostgreSQL/CockroachDB/CrateDB: 2^3=8) - false for XOR dialects
#              (2^3=1) and erroring dialects; a positive PostgreSQL-family marker. CAVEAT:
#              '^'=exponentiation is not strictly unique to PostgreSQL - MS Access/Jet and DuckDB
#              also use it (neither on the platform), so this can read as PostgreSQL there.
#   * 5/2=2  -> integer division (PostgreSQL/MSSQL/SQLite/MonetDB) vs real division (MySQL/Oracle: 2.5)
#   * 2|0=2  -> a bitwise OR operator exists (absent in Firebird/Oracle/ClickHouse/H2)
#   * 1<<2=4 -> a bit-shift operator exists. MonetDB shares MSSQL's (xor, intdiv) = (True, True)
#              signature exactly, which would misread MonetDB as SQL Server; MonetDB HAS '<<' while
#              SQL Server has NO shift operator (any version) -> this probe splits that one collision.
DIALECT_PROBES = (
    ("xor", "2^0=2"),
    ("pgpow", "2^3=8"),
    ("intdiv", "5/2=2"),
    ("bitor", "2|0=2"),
    ("shift", "1<<2=4"),
)

# Canary for the trustworthiness gate: a syntactically-invalid expression (a trailing operator) that
# a real SQL back-end can only read as FALSE - the appended clause is a parse error, the query fails,
# no row. A false-positive / noise channel (a WAF, a reflection, or a backend that ignores the
# injected tail and reads every probe the same) reads it as TRUE, which is proof the boolean oracle
# is trash, so the heuristic returns None (a true negative) rather than a bogus DBMS from a
# meaningless signature. It uses a trailing-operator form, distinct from the '<n> <m>' no-operator
# form already exercised by sqlmap's earlier false-positive check, so it adds new information.
DIALECT_CANARY = "2+"

# Exact operator-dialect signature -> back-end DBMS. Strict WHITELIST re-derived from the live
# measurement above: ONLY these signatures classify; any other - an engine not measured here, or a
# false-positive / noise channel - returns None. This deliberately replaces earlier partial-condition
# rules, which would confidently mis-map physically-impossible signatures onto a DBMS (e.g. the
# all-true 'reads everything as true' noise, where '^' would be XOR and exponentiation at once).
_SIGNATURE_DBMS = {
    #  xor    pgpow  intdiv bitor  shift
    (True,  False, False, True,  True):  DBMS.MYSQL,    # MySQL / MariaDB / TiDB
    (False, True,  True,  True,  True):  DBMS.PGSQL,    # PostgreSQL
    (False, True,  False, True,  True):  DBMS.PGSQL,    # CockroachDB (pgwire; has '<<' -> shift True)
    (False, True,  True,  True,  False): DBMS.PGSQL,    # CrateDB
    (True,  False, True,  True,  False): DBMS.MSSQL,    # Microsoft SQL Server (no bit-shift)
    (True,  False, True,  True,  True):  DBMS.MONETDB,  # MonetDB (as MSSQL but has '<<')
    (False, False, True,  True,  True):  DBMS.SQLITE,   # SQLite
}

def _classify(signature):
    """
    Maps an exact operator-dialect signature (xor, pgpow, intdiv, bitor, shift) to a back-end DBMS
    through a strict whitelist of live-measured signatures, or returns None when the signature is not
    a known DBMS fingerprint - an engine not measured, or a noise / false-positive channel - so
    detection proceeds unchanged and the heuristic never wrong-foots the scan.

    >>> _classify((True, False, False, True, True))            # MySQL / MariaDB / TiDB
    'MySQL'
    >>> _classify((False, True, True, True, True))             # PostgreSQL
    'PostgreSQL'
    >>> _classify((False, True, False, True, True))            # CockroachDB -> PostgreSQL family
    'PostgreSQL'
    >>> _classify((False, True, True, True, False))            # CrateDB -> PostgreSQL family
    'PostgreSQL'
    >>> _classify((True, False, True, True, False))            # Microsoft SQL Server (no bit-shift)
    'Microsoft SQL Server'
    >>> _classify((True, False, True, True, True))             # MonetDB (as MSSQL but has '<<')
    'MonetDB'
    >>> _classify((False, False, True, True, True))            # SQLite
    'SQLite'
    >>> _classify((True, True, True, True, True)) is None      # 'reads everything true' noise -> None
    True
    >>> _classify((False, False, False, False, False)) is None # all-false (Oracle/ClickHouse/IRIS/blocked) -> None
    True
    >>> _classify((False, False, True, False, False)) is None  # Firebird/H2/HSQLDB/Derby/Trino -> not distinctive
    True
    """

    return _SIGNATURE_DBMS.get(tuple(bool(_) for _ in signature))

def dialectCheckDbms(injection):
    """
    Keyword-free back-end DBMS heuristic via operator-dialect differentials, evaluated through the
    given (boolean-capable) injection. Complements heuristicCheckDbms() - which is skipped when the
    WAF/IPS is dropping requests and otherwise relies on SELECT/quote payloads - because every probe
    here is built from operator semantics alone. Returns the DBMS name or None; an ambiguous,
    WAF-blocked or false-positive channel yields None, leaving the scan unchanged.
    """

    retVal = None

    if conf.skipHeuristics:
        return retVal

    pushValue(kb.injection)
    kb.injection = injection

    try:
        # Trustworthiness gate: a real boolean oracle reads a tautology TRUE, a contradiction FALSE,
        # and a syntactically-invalid canary FALSE (the appended clause is a parse error -> the query
        # fails). A false-positive / noise channel reads them all alike - the canary as TRUE - which
        # is proof the oracle is trash, so classification is skipped (a true negative) instead of
        # emitting a bogus DBMS from a meaningless signature.
        if checkBooleanExpression("2=2") and not checkBooleanExpression("2=3") and not checkBooleanExpression(DIALECT_CANARY):
            signature = tuple(bool(checkBooleanExpression(expr)) for _, expr in DIALECT_PROBES)
            retVal = _classify(signature)
    finally:
        kb.injection = popValue()

    if retVal and not Backend.getIdentifiedDbms():
        infoMsg = "heuristic (dialect) test shows that the back-end DBMS could be '%s'" % retVal
        logger.info(infoMsg)

    return retVal
