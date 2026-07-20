#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Live cross-DBMS validator for data/xml/boundaries.xml.

WHAT
    For every reachable DBMS this builds the REAL injected parameter value for each
    boundary - through the actual agent.prefixQuery / suffixQuery / cleanupPayload
    path, NOT a re-implementation - across a set of representative host-query
    contexts, runs the TRUE and FALSE variants against the live engine, and
    classifies the boundary via three oracles:

        W (WORKS)  boolean: TRUE/FALSE variants are valid AND their row counts differ
        T (TIME)   inline conditional sleep delays on TRUE, not on FALSE (MySQL/PG only)
        I (INBAND) an injected marker surfaces in the result set (table cross-join / UNION)
        . (inert)  valid SQL but no channel discriminates in the contexts tried
        x (invalid) a syntax/semantic error on this engine

    Output is a boundary x engine matrix plus the boundaries usable via NO oracle on any
    reachable engine - the "no working context found" review candidates.

WHY
    boundaries.xml is the detection core. This answers "does boundary X actually
    produce valid, discriminating SQL on engine Y" with evidence instead of argument.

FAITHFULNESS (do not remove the plugins.dbms.* imports)
    The per-DBMS `unescaper` registrations load only when the plugin packages are
    imported. Without them "SELECT '[RANDSTR]'" renders as a bare identifier instead
    of the real 0x-hex / CHR() literal, and every concat-style boundary is falsely
    reported broken. The import plus _faithful_or_die() guard against that.

SCOPE / LIMITATION
    Covers the boolean, inline-time (MySQL/PG) and inband oracles over a representative
    set of host contexts. Still NOT modeled: the error-based oracle, inline time on
    MSSQL/Oracle (statement/privilege-gated sleep), and any host context not in the set.
    So a boundary flagged "usable via NO oracle" may still work via one of those - confirm
    before acting. "inert" means no channel discriminated in the contexts tried.

BENCH
    Needs live engines. Defaults target the local docker bench; any engine that does
    not connect (driver missing or refused) is SKIPPED and reported as skipped - never
    silently counted as covered. Override a target with an env var (host:port:user:pass[:db]):

        MySQL       BC_MYSQL       default 127.0.0.1:13306:root:root
        PostgreSQL  BC_POSTGRES    default 127.0.0.1:15432:esp:pass:espdb
        MSSQL       BC_MSSQL       default 127.0.0.1:11433:sa:Esp_pass123
        Oracle      BC_ORACLE      default 127.0.0.1:1521:system:oracle:FREEPDB1  (service_name in db slot)

USAGE (from the sqlmap root)
        python extra/boundarycheck/boundarycheck.py
"""

from __future__ import print_function

import os
import sys
import time
import xml.etree.ElementTree as ET

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "tests"))

from _testutils import bootstrap, set_dbms
bootstrap()

# Faithfulness (see FAITHFULNESS above): importing each DBMS plugin package runs its module-level
# `unescaper[<dbms>] = Syntax.escape` registration - a side effect, not a symbol we use. Trigger it via
# import_module so there is no bound-but-unused name for pyflakes to flag.
import importlib
for _plugin in ("mysql", "postgresql", "oracle", "mssqlserver"):
    importlib.import_module("plugins.dbms.%s" % _plugin)

from lib.core.data import conf, kb
from lib.core.datatype import AttribDict
from lib.core.enums import PAYLOAD
from lib.core.unescaper import unescaper
import lib.core.agent as _agentmod

agent = _agentmod.agent
conf.noEscape = False

TRUE_PAYLOAD = "AND 9911=9911"
FALSE_PAYLOAD = "AND 9911=9912"
TIME_THRESHOLD = 0.4   # seconds; a conditional sleep of ~0.7s must clear this, a no-op must not
INBAND_MARKER = "qBCiNBANDq"                 # distinctive token; if it surfaces in the result set the
INBAND_PAYLOAD = "(SELECT '%s')" % INBAND_MARKER   # boundary opens an inband output channel (e.g. a table cross-join)

# per-engine conditional-sleep payload pair (delay-if-true, no-delay) for the TIME oracle. Only engines
# with an INLINE sleep expression are covered; MSSQL (WAITFOR is a statement) and Oracle (DBMS_LOCK/PIPE,
# privilege-gated) need a statement/stacked sleep, so their inline time-usability is NOT modeled here.
SLEEP = {
    "MySQL":      ("AND 0=(SELECT SLEEP(0.7))", "AND 0=(SELECT SLEEP(0))"),        # subquery => fires once, not per-row
    "PostgreSQL": ("AND 1=(SELECT 1 FROM pg_sleep(0.7))", "AND 1=(SELECT 1 FROM pg_sleep(0))"),
}

# portable WHERE-clause contexts at parenthesis depths 0-3 (numeric + single-quoted string), so the
# ')' / '))' / ')))' and "'" / "')" / "'))" boundary families each meet a host that actually closes
# the matching depth. Reused by every engine; engine-specific contexts are appended in the adapters.
WHERE_CONTEXTS = [
    ("SELECT COUNT(*) FROM bc WHERE name LIKE '%%%s%%'", "orig"),                     # LIKE '%...%'
    ("SELECT COUNT(*) FROM bc %s", ""),                                              # bare pre-WHERE (add a WHERE)
    ("SELECT COUNT(*) FROM (SELECT * FROM bc WHERE id=%s) q", "1"),                   # derived table (numeric)
    ("SELECT COUNT(*) FROM (SELECT * FROM bc WHERE name='%s') q", "orig"),            # derived table (single-quote)
    ("SELECT COUNT(*) FROM (SELECT * FROM (SELECT * FROM bc WHERE id=%s) a) q", "1"),        # derived table 2-deep
    ("SELECT COUNT(*) FROM (SELECT * FROM (SELECT * FROM bc WHERE name='%s') a) q", "orig"),
    ("UPDATE bc SET note='%s' WHERE id=1", "orig"),                                  # pre-WHERE DML (rowcount oracle)
    ("SELECT * FROM %s", "bc"),                                                      # table-name (inband cross-join)
]
for _depth in range(4):
    _open, _close = "(" * _depth, ")" * _depth
    WHERE_CONTEXTS.append(("SELECT COUNT(*) FROM bc WHERE " + _open + "id=%s" + _close, "1"))
    WHERE_CONTEXTS.append(("SELECT COUNT(*) FROM bc WHERE " + _open + "name='%s'" + _close, "orig"))


def _faithful_or_die():
    set_dbms("MySQL")
    if unescaper.escape("abc", quote=False) == "abc":
        sys.exit("FATAL: unescaper not registered - '[RANDSTR]' would render as a bare identifier and "
                 "verdicts would be wrong. Check the plugins.dbms.* imports at the top of this file.")


def build_value(dbms, prefix, suffix, clause, payload, orig):
    """The real injected parameter value for where=ORIGINAL (checks.py:490-493 + agent.payload line 181/183)."""
    set_dbms(dbms)
    kb.injection = AttribDict()
    for _ in ("prefix", "suffix", "clause", "ptype", "place", "parameter"):
        kb.injection[_] = None
    kb.injection.data = AttribDict()
    kb.technique = None
    forged = agent.prefixQuery(agent.cleanupPayload(payload), prefix, PAYLOAD.WHERE.ORIGINAL, clause)
    forged = agent.suffixQuery(forged, None, suffix, PAYLOAD.WHERE.ORIGINAL)
    value = agent.cleanupPayload("%s%s" % (orig, forged), orig) or ""
    return value.replace(_agentmod.BOUNDARY_BACKSLASH_MARKER, "\\")


def make_run(cur, rollback=None):
    """A query runner: returns ("ok", rows) for a result set, ("ok", ("rc", n)) for a DML row count
    (cursor.description is None => no result set), or ("err", msg). DML lets pre-WHERE boundaries be
    judged by affected-row count (TRUE matches rows, FALSE matches none)."""
    def run(sql):
        try:
            cur.execute(sql)
        except Exception as e:
            if rollback:
                try:
                    rollback()
                except Exception:
                    pass
            return ("err", str(e).splitlines()[-1][:50])
        if cur.description is None:
            return ("ok", ("rc", cur.rowcount))
        return ("ok", tuple(cur.fetchall()))
    return run


def classify(run, dbms, prefix, suffix, clause, contexts):
    """Best verdict of a boundary across the engine's contexts: WORKS(boolean) > TIME > inert > invalid.

    The TIME oracle only runs when the boolean probe was valid-but-inert (best=='inert') - i.e. the
    injected SQL parses and runs but the boolean AND does not change the row count. That is exactly the
    error/time-primitive candidate: a conditional sleep that delays on TRUE and not on FALSE proves the
    injected expression actually executes. If every boolean probe was a syntax error (best=='invalid'),
    the same syntax fails the time payload too, so it is skipped."""
    best = "invalid"
    for host, orig in contexts:
        st, rt = run(host % build_value(dbms, prefix, suffix, clause, TRUE_PAYLOAD, orig))
        sf, rf = run(host % build_value(dbms, prefix, suffix, clause, FALSE_PAYLOAD, orig))
        if st == "ok" and sf == "ok":
            if rt != rf:
                return "WORKS"
            best = "inert"

    if best == "inert" and dbms in SLEEP:
        slow_p, fast_p = SLEEP[dbms]
        for host, orig in contexts:
            t0 = time.time()
            run(host % build_value(dbms, prefix, suffix, clause, slow_p, orig))
            if time.time() - t0 >= TIME_THRESHOLD:                      # TRUE variant delayed
                t0 = time.time()
                run(host % build_value(dbms, prefix, suffix, clause, fast_p, orig))
                if time.time() - t0 < TIME_THRESHOLD:                   # FALSE variant did not
                    return "TIME"

    # inband: the injected expression's output surfaces directly in the result set (a table-name
    # cross-join, UNION or select-list channel) - invisible to the boolean/time oracles above.
    for host, orig in contexts:
        st, r = run(host % build_value(dbms, prefix, suffix, clause, INBAND_PAYLOAD, orig))
        if st == "ok" and INBAND_MARKER in str(r):
            return "INBAND"
    return best


def _env(name, default):
    parts = (os.environ.get(name) or default).split(":")
    parts += [None] * (5 - len(parts))
    host, port, user, pwd, db = parts[:5]
    return host, int(port), user, pwd, db


# --- engine adapters: return (sqlmap_dbms, run_fn, contexts, cleanup_fn) or None to skip -------------

def _mysql():
    try:
        import pymysql
        h, p, u, w, _ = _env("BC_MYSQL", "127.0.0.1:13306:root:root")
        c = pymysql.connect(host=h, port=p, user=u, password=w, connect_timeout=5, autocommit=True)
        cur = c.cursor()
        cur.execute("CREATE DATABASE IF NOT EXISTS boundarycheck")
        cur.execute("USE boundarycheck")
        for q in ("DROP TABLE IF EXISTS bc",
                  "CREATE TABLE bc(id INT,name VARCHAR(64),note VARCHAR(64),FULLTEXT(name)) ENGINE=InnoDB",
                  "INSERT INTO bc VALUES(1,'orig','n'),(2,'x','n'),(3,'y','n')"):
            cur.execute(q)
        c.commit()
    except Exception as ex:
        return None, str(ex).splitlines()[0][:60]

    run = make_run(cur, c.rollback)
    contexts = WHERE_CONTEXTS + [
                ("SELECT `%s` FROM bc", "name"),                           # backtick column identifier
                ('SELECT COUNT(*) FROM bc WHERE name="%s"', "orig"),        # MySQL: " is a string delim
                ('SELECT COUNT(*) FROM bc WHERE (name="%s")', "orig"),
                ('SELECT COUNT(*) FROM bc WHERE ((name="%s"))', "orig"),
                ('SELECT COUNT(*) FROM bc WHERE (((name="%s")))', "orig"),
                ('UPDATE bc SET note="%s" WHERE id=1', "orig"),            # double-quote pre-WHERE DML
                ('SELECT COUNT(*) FROM (SELECT * FROM bc WHERE name="%s") q', "orig"),           # dq derived table
                ('SELECT COUNT(*) FROM (SELECT * FROM (SELECT * FROM bc WHERE name="%s") a) q', "orig"),
                ("SELECT COUNT(*) FROM bc WHERE id=1 /* c='%s' */", "x"),   # block comment
                ("SELECT COUNT(*) FROM bc WHERE MATCH(name) AGAINST('%s')", "orig"),  # fulltext (IN BOOLEAN MODE)
                ("SELECT COUNT(*) FROM `%s`", "bc"),                        # backtick table
                ("SELECT COUNT(*) FROM (SELECT * FROM `%s`) q", "bc")]      # backtick table in derived

    def cleanup():
        try:
            cur.execute("DROP DATABASE boundarycheck"); c.commit(); c.close()
        except Exception:
            pass
    return ("MySQL", run, contexts, cleanup), None


def _postgres():
    try:
        import psycopg2
        h, p, u, w, db = _env("BC_POSTGRES", "127.0.0.1:15432:esp:pass:espdb")
        c = psycopg2.connect(host=h, port=p, user=u, password=w, dbname=db, connect_timeout=5)
        c.autocommit = True
        cur = c.cursor()
        cur.execute("DROP TABLE IF EXISTS bc")
        cur.execute("CREATE TABLE bc(id INT,name VARCHAR(64),note VARCHAR(64))")
        cur.execute("INSERT INTO bc VALUES(1,'orig','n'),(2,'x','n'),(3,'y','n')")
    except Exception as ex:
        return None, str(ex).splitlines()[0][:60]

    run = make_run(cur, c.rollback)
    contexts = WHERE_CONTEXTS + [
                ('SELECT id FROM bc ORDER BY "%s"', "name"),               # ANSI double-quote identifier
                ("SELECT COUNT(*) FROM bc WHERE id=1 /* c='%s' */", "x"),   # block comment
                ("SELECT COUNT(*) FROM bc WHERE name=$$%s$$", "orig")]      # dollar quoting

    def cleanup():
        try:
            cur.execute("DROP TABLE bc"); c.close()
        except Exception:
            pass
    return ("PostgreSQL", run, contexts, cleanup), None


def _mssql():
    try:
        import pymssql
        h, p, u, w, _ = _env("BC_MSSQL", "127.0.0.1:11433:sa:Esp_pass123")
        c = pymssql.connect(server=h, port=p, user=u, password=w, database="master", autocommit=True, login_timeout=5)
        cur = c.cursor()
        for q in ("IF OBJECT_ID('bc') IS NOT NULL DROP TABLE bc", "CREATE TABLE bc(id INT,name VARCHAR(64),note VARCHAR(64))",
                  "INSERT INTO bc VALUES(1,'orig','n'),(2,'x','n'),(3,'y','n')"):
            cur.execute(q)
    except Exception as ex:
        return None, str(ex).splitlines()[-1][:60]

    run = make_run(cur)
    contexts = WHERE_CONTEXTS + [
                ("SELECT [%s] FROM bc", "name"),                           # bracket column identifier (string)
                ("SELECT [%s] FROM bc", "id"),                             # bracket column identifier (numeric)
                ("SELECT COUNT(*) FROM bc WHERE id=1 /* c='%s' */", "x")]   # block comment

    def cleanup():
        try:
            cur.execute("IF OBJECT_ID('bc') IS NOT NULL DROP TABLE bc"); c.close()
        except Exception:
            pass
    return ("Microsoft SQL Server", run, contexts, cleanup), None


def _oracle():
    try:
        try:
            import oracledb as ora
        except ImportError:
            import cx_Oracle as ora
        h, p, u, w, svc = _env("BC_ORACLE", "127.0.0.1:1521:system:oracle:FREEPDB1")
        c = ora.connect(user=u, password=w, dsn=ora.makedsn(h, p, service_name=svc))
        c.autocommit = True
        cur = c.cursor()
        for q in ("BEGIN EXECUTE IMMEDIATE 'DROP TABLE bc'; EXCEPTION WHEN OTHERS THEN NULL; END;",
                  "CREATE TABLE bc(id INT, name VARCHAR2(64), note VARCHAR2(64))",
                  "INSERT INTO bc VALUES(1,'orig','n')", "INSERT INTO bc VALUES(2,'x','n')"):
            cur.execute(q)
        c.commit()
    except Exception as ex:
        return None, str(ex).splitlines()[0][:60]

    run = make_run(cur, c.rollback)
    contexts = WHERE_CONTEXTS + [
                ("SELECT COUNT(*) FROM bc WHERE id=1 /* c='%s' */", "x"),   # block comment
                ("SELECT COUNT(*) FROM bc WHERE name=q'[%s]'", "orig"),     # alternative quoting q'[...]'
                ("SELECT COUNT(*) FROM bc WHERE name=q'{%s}'", "orig"),
                ("SELECT COUNT(*) FROM bc WHERE name=q'(%s)'", "orig"),
                ("SELECT COUNT(*) FROM bc WHERE name=q'<%s>'", "orig")]

    def cleanup():
        try:
            c.close()
        except Exception:
            pass
    return ("Oracle", run, contexts, cleanup), None


ADAPTERS = [_mysql, _postgres, _mssql, _oracle]


def main():
    _faithful_or_die()

    boundaries = ET.parse(os.path.join(_ROOT, "data", "xml", "boundaries.xml")).findall(".//boundary")

    engines, skipped = [], []
    for adapter in ADAPTERS:
        got, why = adapter()
        (engines if got else skipped).append(got or (adapter.__name__.strip("_"), why))

    if not engines:
        print("no reachable DBMS - nothing validated. Bring up the bench (see module docstring).")
        for name, why in skipped:
            print("  skipped %-12s (%s)" % (name, why))
        return

    names = [e[0] for e in engines]
    mark = {"WORKS": "W", "TIME": "T", "INBAND": "I", "inert": ".", "invalid": "x"}
    print("boundary%s %s" % (" " * 38, "  ".join("%-6s" % n[:6] for n in names)))
    print("-" * (46 + 8 * len(names)))

    verdicts = []
    for idx, b in enumerate(boundaries, 1):
        g = lambda k: (b.findtext(k) or "").strip()
        prefix, suffix = b.findtext("prefix") or "", b.findtext("suffix") or ""  # NOT stripped: leading/trailing space is significant SQL
        clause = [int(x) for x in (g("clause") or "0").split(",") if x.strip().isdigit()]
        row = []
        for dbms, run, contexts, _ in engines:
            row.append(classify(run, dbms, prefix, suffix, clause, contexts))
        verdicts.append((idx, prefix, row))
        cells = "  ".join("%-6s" % mark[v] for v in row)
        print("#%02d p%s c%-5s %-30r %s" % (idx, g("ptype"), g("clause"), prefix[:30], cells))

    for _, _, _, cleanup in engines:
        cleanup()

    print("\nlegend: W=works (boolean)  T=works (time)  I=works (inband output)  .=valid but inert  x=invalid")
    print("contexts modeled: WHERE numeric/single-quote (paren depths 0-3), LIKE, block comment, plus")
    print("  per-engine (MySQL: double-quote + backtick table; PG: ANSI-ident + dollar; Oracle: q'..').")
    print("  NOT modeled: pre-WHERE DML (clause 9), derived-table AS-alias, table/column identifier,")
    print("  fulltext AGAINST - boundaries needing those (and any error/time-only ones) show inert here.")
    print("engines: " + ", ".join(names))
    for name, why in skipped:
        print("skipped: %-14s (%s)" % (name, why))

    never = [idx for idx, _, row in verdicts if not ({"WORKS","TIME","INBAND"} & set(row))]
    print("\nboundaries usable via NO oracle (boolean/time/inband) on any reachable engine (review): %s"
          % (", ".join("#%02d" % i for i in never) or "none"))
    print("NOTE: boolean + inline-time oracles over sampled contexts. Still unmodeled: the ERROR oracle,")
    print("      inline time on MSSQL/Oracle (statement/privilege-gated sleep), and some host contexts.")
    print("      A boundary here may still be usable via one of those, so confirm before acting.")


if __name__ == "__main__":
    main()
