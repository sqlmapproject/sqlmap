#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Regression suite for the DBMS-agnostic engine (extra/esperanto/), in two parts:

1. Semantic corpus - round-trips awkward values through an in-memory SQLite boolean
   oracle and asserts the correctness invariants the engine must never break: no silent
   character substitution or deletion, length never exceeds maxlen (over-length is
   flagged), limit=0 is an incomplete empty prefix, NULL stays distinct from '',
   truncation sets complete=False, bytes-first extraction is byte-exact, and the
   capability fallbacks (pattern-match floor, length-from-substring, LEFT/RIGHT
   composition) and the frozen InferenceStrategy hand-off all still extract.

2. Adversarial dialect scenarios - an intermediate oracle disguises the same SQLite as
   a different / hostile back-end by BLOCKING the SQL forms the fake engine lacks and
   REWRITING its forms into the SQLite equivalent, so the engine must discover and adapt
   the dialect it is handed (substring=SUBSTRING, length=LEN, charcode=ASCII,
   concat=CONCAT, no usable '>'/BETWEEN, no readable catalog) rather than only working
   on dialects it already knows.

stdlib unittest only; Python 2.7 and 3.x.
"""

import os
import re
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from extra.esperanto import Cap
from extra.esperanto import Esperanto
from extra.esperanto import hostExtract

EXPR = "(SELECT v FROM t)"

# awkward values (NULL handled separately - it is not a string value)
CORPUS = [
    u"", u"A", u"AB", u"A ", u" leading", u"trailing ", u"two  spaces",
    u"O'Reilly", u'double"quote', u"comma,value", u"back\\slash",
    u"line\nbreak", u"\t", u"é", u"€", u"中文",
    u"\U00010348", u"Aé€\U00010348Z",
]


def _oracle(value=None, is_null=False):
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE t (v TEXT)")
    con.execute("INSERT INTO t VALUES (?)", (None if is_null else value,))
    con.commit()

    def ask(cond):
        try:
            return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
        except Exception:
            return False
    return ask


# -- adversarial dialect scenarios: one SQLite disguised as many hostile back-ends -----

# ground truth seeded into every disguised scenario
_SEED = (
    "CREATE TABLE users (id INTEGER, name TEXT, email TEXT)",
    "INSERT INTO users VALUES (1,'luther','a@b.c'),(2,'admin','p@w.n'),(3,'wu',NULL)",
)
_SECRET_EXPR = "(SELECT name FROM users WHERE id=2)"        # -> 'admin'


def _concatFn(*args):
    return "".join(u"" if a is None else (a if isinstance(a, type(u"")) else str(a)) for a in args)


def _disguisedOracle(blocked=None, rewrites=(), funcs=()):
    """Boolean oracle over a disguised SQLite. `blocked` (regex) forms read False (the
    fake engine lacks them); `rewrites` translate the fake engine's forms into SQLite;
    `funcs` registers extra SQL functions (e.g. a variadic CONCAT SQLite lacks). The
    engine never sees SQLite - it must adapt to whatever back-end the scenario emulates."""
    con = sqlite3.connect(":memory:")
    for name, narg, fn in funcs:
        con.create_function(name, narg, fn)
    for stmt in _SEED:
        con.execute(stmt)
    con.commit()
    blk = re.compile(blocked, re.I) if blocked else None
    rw = [(re.compile(p, re.I), r) for p, r in rewrites]

    def ask(cond):
        if blk and blk.search(cond):
            return False                                    # fake engine doesn't support it
        sql = cond
        for rx, rep in rw:
            sql = rx.sub(rep, sql)
        try:
            return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % sql).fetchone()[0] == 1
        except Exception:
            return False
    return ask


# coherent whole-back-end disguises: each blocks the forms its fake DBMS lacks and maps
# the forms it "has" onto SQLite. All must discover the dialect and dump every row.
# (name, blocked, rewrites, funcs)
_DIALECTS = (
    ("mysql-ish: MID / CHAR_LENGTH / ORD, backtick idents, || is OR -> CONCAT",
     r"\bSUBSTR\(|\bSUBSTRING\(|\bLEN\(|\bLENGTH\(|\bASCII\(|\bUNICODE\(|\|\|",
     [(r"\bMID\(", "substr("), (r"CHAR_LENGTH\(", "length("), (r"\bORD\(", "unicode("), (r"`", '"')],
     [("CONCAT", -1, _concatFn)]),
    ("mssql-ish: SUBSTRING / LEN / UNICODE, '+' concat, [..] idents",
     r"\bSUBSTR\(|\bMID\(|CHAR_LENGTH\(|\bLENGTH\(|\bASCII\(|\bORD\(|\|\||\bCONCAT\(|\"|`",
     [(r"SUBSTRING\(", "substr("), (r"\bLEN\(", "length("), (r"\)\+\(", ")||(")],
     ()),
    ("postgres-ish: SUBSTRING / LENGTH / ASCII, || concat",
     r"\bSUBSTR\(|\bMID\(|\bLEN\(|CHAR_LENGTH\(|\bUNICODE\(|\bORD\(",
     [(r"SUBSTRING\(", "substr("), (r"\bASCII\(", "unicode(")],
     ()),
    ("oracle-ish: SUBSTR / LENGTH / ASCII / CHR, || concat",
     r"\bMID\(|\bLEN\(|CHAR_LENGTH\(|\bUNICODE\(|\bORD\(|\bCHAR\(",
     [(r"\bASCII\(", "unicode("), (r"\bCHR\(", "char(")],
     ()),
    ("waf: code fns and collation stripped -> forced hex extraction",
     r"\bASCII\(|\bUNICODE\(|\bORD\(|CODEPOINT\(|COLLATE|AS\s+BLOB",
     (), ()),
    ("waf: '>'/'<' stripped on top of a MID/CHAR_LENGTH dialect",
     r">|<|\bSUBSTR\(|\bSUBSTRING\(|\bLENGTH\(|\bLEN\(|\|\|",
     [(r"\bMID\(", "substr("), (r"CHAR_LENGTH\(", "length(")],
     [("CONCAT", -1, _concatFn)]),
)


class TestEsperanto(unittest.TestCase):
    def test_bytes_roundtrip(self):
        # bytes-first round-trips EVERY value exactly (the fundamental guarantee)
        for v in CORPUS:
            esp = Esperanto(_oracle(v))
            esp.discover()
            self.assertEqual(esp.extractBytes(EXPR), v.encode("utf-8"), "extractBytes %r" % v)
            self.assertEqual(esp.extractText(EXPR), v, "extractText %r" % v)

    def test_no_silent_corruption(self):
        # any deviation must be surfaced (replacement marker + warning), never a
        # wrong-but-plausible character silently substituted
        for v in CORPUS:
            for mode in ("code", "ordinal", "collation", "hex"):
                esp = Esperanto(_oracle(v))
                esp.discover()
                esp.dialect.compare = mode
                if mode == "hex":
                    esp._ensureHexfn()
                elif mode == "collation":       # SQLite is byte-ordered via BLOB cast
                    esp.dialect.binwrap = Cap("cast_blob", "CAST(({x}) AS BLOB)")
                res = esp.extractResult(EXPR)
                if res.value == v:
                    continue
                self.assertTrue(not res.complete and res.warnings,
                                "silent corruption in %s mode for %r -> %r" % (mode, v, res.value))
                self.assertTrue(u"�" in res.value or res.value == u"",
                                "%s mode invented a value for %r -> %r" % (mode, v, res.value))

    def test_null_vs_empty(self):
        esp = Esperanto(_oracle(is_null=True))
        esp.discover()
        rnull = esp.extractResult(EXPR)
        self.assertTrue(rnull.is_null and rnull.value is None, "NULL not null: %r" % rnull)
        esp = Esperanto(_oracle(u""))
        esp.discover()
        rempty = esp.extractResult(EXPR)
        self.assertTrue((not rempty.is_null) and rempty.value == u"" and rempty.complete,
                        "empty string mis-reported: %r" % rempty)

    def test_limit_and_maxlen(self):
        # limit=0 on a non-empty value -> empty prefix, but INCOMPLETE/TRUNCATED
        esp = Esperanto(_oracle(u"hello"))
        esp.discover()
        r0 = esp.extractResult(EXPR, limit=0)
        self.assertTrue(r0.value == u"" and r0.truncated and not r0.complete, "limit=0: %r" % r0)
        # over-maxlen -> truncated flagged, length bounded
        esp = Esperanto(_oracle(u"0123456789ABCDEF"), maxlen=4)
        esp.discover()
        rt = esp.extractResult(EXPR)
        self.assertTrue(rt.truncated and not rt.complete and len(rt.value) <= 4, "over-maxlen: %r" % rt)

    def test_integer(self):
        for n in (0, 1, 42, 255, 65535, 1000000, 2147483648, -1, -42):
            esp = Esperanto(_oracle())
            esp.discover()
            self.assertEqual(esp.extractInteger("(%d)" % n), n, "extractInteger(%d)" % n)

    def test_fixup_length(self):
        # a trailing-space-trimming length fn is rebuilt as LEN(x||'.')-1
        esp = Esperanto(_oracle(u"x"))
        esp.discover()
        esp.dialect.length = Cap("LEN", "LEN({expr})", unit="characters", trailing=False, empty_is_null=False)
        esp.dialect.concat = Cap("plus", "({a})+({b})")
        esp._fixupLength()
        self.assertTrue(esp.dialect.length.name.endswith("+dot") and esp.dialect.length.get("trailing"),
                        "_fixupLength did not rebuild: %r" % esp.dialect.length)

    def test_lit_escaping(self):
        esp = Esperanto(_oracle(u"x"))
        esp.discover()
        esp._backslashEscape = True
        self.assertEqual(esp._lit("\\"), "'\\\\'")
        esp._backslashEscape = False
        self.assertEqual(esp._lit("\\"), "'\\'")
        self.assertEqual(esp._lit("'"), "''''")

    def test_build_literal(self):
        esp = Esperanto(_oracle(u"x"))
        esp.discover()
        lit = esp.buildLiteral("a\\b'c")
        self.assertTrue(esp._ask("%s IS NOT NULL" % lit), "buildLiteral invalid SQL: %s" % lit)
        self.assertEqual(esp.extract(lit), "a\\b'c")

    def test_coalesce(self):
        esp = Esperanto(_oracle(u"x"))
        esp.discover()
        if esp.dialect.coalesce:
            self.assertEqual(esp.extract(esp.coalesce("NULL", "'Z'")), "Z")

    def test_enumerate(self):
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE alpha (x)")
        con.execute("CREATE TABLE beta (y)")
        con.commit()

        def ask(cond):
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except Exception:
                return False
        esp = Esperanto(ask)
        esp.discover()
        tabs = set(esp.enumerate("table", limit=10) or [])
        self.assertTrue(set(["alpha", "beta"]).issubset(tabs), "enumerate tables: %r" % tabs)

    def test_dump(self):
        # row DATA byte-exact, including commas / quotes / unicode (hex framing keeps intact)
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE users (id, uname, note)")
        truth = [(1, u"admin", u"all,good"), (2, u"o'brien", u"café,€"), (3, u"x", u"")]
        for row in truth:
            con.execute("INSERT INTO users VALUES (?,?,?)", row)
        con.commit()

        def ask(cond):
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except Exception:
                return False
        esp = Esperanto(ask)
        esp.discover()
        d = esp.dump("users", limit=10)
        got = set(frozenset(dict(zip(d["columns"], r)).items()) for r in d["rows"])
        want = set(frozenset({"id": str(i), "uname": u, "note": n}.items()) for i, u, n in truth)
        self.assertTrue(d["complete"] and got == want, "dump mismatch: %r" % d["rows"])

    def test_dump_scavenges_without_hex_or_concat(self):
        # DOOMSDAY: a back-end with NO hex function AND NO concat operator (nothing to
        # frame a whole row with) must still be dumped - cell by cell, one value per
        # extraction. Quotes/commas/NULLs in the data must survive (a single value has
        # no framing ambiguity). This is the scavenger's whole reason to exist.
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT)")
        for row in ((1, "luther", "a@b.c"), (2, "o'brien", "x,y@z"), (3, "wu", None)):
            con.execute("INSERT INTO users VALUES (?,?,?)", row)
        con.commit()
        blk = re.compile(r"(?i)\bHEX\(|RAWTOHEX|ENCODE\(|BINTOHEX|HEX_ENCODE|TO_HEX|BINTOSTR|"
                         r"\|\||\bCONCAT\(|CONCAT_WS|\)\+\(|\)&\(")   # no hex, no concat at all

        def ask(cond):
            if blk.search(cond):
                return False
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask)
        esp.discover()
        self.assertIsNone(esp.dialect.hexfn)
        self.assertIsNone(esp.dialect.concat)
        d = esp.dump("users")
        got = set(frozenset(dict(zip(d["columns"], r)).items()) for r in d["rows"])
        want = set(frozenset(v.items()) for v in (
            {"id": "1", "name": "luther", "email": "a@b.c"},
            {"id": "2", "name": "o'brien", "email": "x,y@z"},
            {"id": "3", "name": "wu", "email": None}))
        self.assertTrue(d["complete"] and got == want, "cell-by-cell dump: %r" % d["rows"])

    def test_enumerate_without_count(self):
        # COUNT() filtered (a WAF, or an exotic engine) must not kill discovery:
        # catalog detection, brute-force existence probing, and identifier quoting are
        # all COUNT-free (scalar-subquery existence), so tables/columns/dump still work.
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE users (id INTEGER, name TEXT)")
        con.execute("INSERT INTO users VALUES (1, 'admin'), (2, 'root')")
        con.commit()
        blk = re.compile(r"(?i)\bCOUNT\s*\(")

        def ask(cond):
            if blk.search(cond):
                return False
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask)
        esp.discover()
        self.assertEqual(esp.enumerate("table", limit=10), ["users"])
        self.assertEqual(sorted(esp.columns("users")), ["id", "name"])
        rows = (esp.dump("users") or {}).get("rows") or []
        got = set(frozenset(dict(zip(esp.dump("users")["columns"], r)).items()) for r in rows)
        want = set(frozenset(v.items()) for v in ({"id": "1", "name": "admin"}, {"id": "2", "name": "root"}))
        self.assertEqual(got, want)

    def test_quoting(self):
        # reserved-word / spaced column names must be quoted, not interpolated raw
        con = sqlite3.connect(":memory:")
        con.execute('CREATE TABLE q (id INTEGER, "order" TEXT, "group by" TEXT)')
        con.execute('INSERT INTO q VALUES (1, ?, ?)', ("a'b", "x,y"))
        con.commit()

        def ask(cond):
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask)
        esp.discover()
        dq = esp.dump("q")
        got = set(frozenset(dict(zip(dq["columns"], r)).items()) for r in dq["rows"])
        want = set([frozenset({"id": "1", "order": "a'b", "group by": "x,y"}.items())])
        self.assertTrue(dq["complete"] and got == want and esp.dialect.identQuote,
                        "quoted-identifier dump failed: %r" % dq["rows"])

    def test_strategy_handoff(self):
        # the frozen InferenceStrategy is a *sufficient* host interface, and immutable
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE k (v TEXT)")
        con.execute("INSERT INTO k VALUES ('Str4t3gy!')")
        con.commit()

        def ask(cond):
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask)
        esp.discover()
        strat = esp.strategy()
        self.assertRaises(AttributeError, setattr, strat, "compare_mode", "x")
        self.assertEqual(hostExtract(ask, strat, "(SELECT v FROM k)"), "Str4t3gy!")
        self.assertTrue(strat.asQueriesRow()["substring"])

    def test_pattern_match_fallback(self):
        # SUBSTR + LENGTH + hex + code fns ALL blacklisted -> pure GLOB/LIKE floor
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE flag (id INTEGER, v TEXT)")
        con.execute("INSERT INTO flag VALUES (1, 'FLAG{no_SUBSTR_%_needed}')")
        con.commit()
        blk = re.compile(r"(?i)\bSUBSTR|SUBSTRING|\bMID\(|\bLENGTH|CHAR_LENGTH|\bLEN\(|"
                         r"OCTET_LENGTH|LENGTHB|DATALENGTH|(ASCII|UNICODE|ORD)\(|\bHEX\(|"
                         r"RAWTOHEX|ENCODE\(")

        def ask(cond):
            if blk.search(cond):
                return False
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask)
        esp.discover()
        self.assertIsNotNone(esp.dialect.prefix)
        self.assertEqual(esp.extract("(SELECT v FROM flag WHERE id=1)"), "FLAG{no_SUBSTR_%_needed}")

    def test_like_floor_escapes_wildcard_chars(self):
        # the classic trap: on the LIKE floor '_' and '%' ARE the wildcards, so a value
        # like 'all_products' must escape them (\_ ESCAPE '\'), not treat them as
        # match-anything. GLOB is blocked here to force LIKE (where '_'/'%' are magic).
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE v (val TEXT)")
        con.execute("INSERT INTO v VALUES ('all_products')")
        for t in ("all_products", "wp_users", "sales%2024"):     # '_'/'%' in identifiers
            con.execute('CREATE TABLE "%s" (id)' % t)
        con.commit()
        blk = re.compile(r"(?i)\bSUBSTR|SUBSTRING|\bMID\(|\bLENGTH|CHAR_LENGTH|\bLEN\(|"
                         r"OCTET_LENGTH|LENGTHB|DATALENGTH|(ASCII|UNICODE|ORD|CODEPOINT)\(|"
                         r"\bHEX\(|RAWTOHEX|ENCODE\(|GLOB")     # +GLOB -> only LIKE left

        def ask(cond):
            if blk.search(cond):
                return False
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask)
        esp.discover()
        self.assertEqual(esp.dialect.prefix.name, "LIKE")        # GLOB gone -> LIKE floor
        self.assertEqual(esp.extract("(SELECT val FROM v)"), "all_products")
        tabs = esp.enumerate("table", limit=10) or []
        self.assertEqual(sorted(tabs), ["all_products", "sales%2024", "v", "wp_users"])

    def test_length_from_substring(self):
        # every length fn blacklisted but SUBSTR present -> length derived from the end
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t6 (v TEXT)")
        con.execute(u"INSERT INTO t6 VALUES ('Admin-42€')")
        con.commit()
        blk = re.compile(r"(?i)\b(CHAR_LENGTH|LENGTH|LEN)\s*\(")

        def ask(cond):
            if blk.search(cond):
                return False
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask)
        d = esp.discover()
        self.assertIsNone(d.length)
        self.assertEqual(esp.extract("(SELECT v FROM t6)"), u"Admin-42€")

    def test_enumeration_degrades_not_crashes(self):
        # a permission/charset wall mid-walk (oracle can't decide the keyset bound)
        # must STOP with partial results, never crash with OracleUndecided
        con = sqlite3.connect(":memory:")
        for t in ("alpha", "beta", "gamma"):
            con.execute("CREATE TABLE %s (x)" % t)
        con.commit()

        def ask(cond):
            if "name>" in cond.replace(" ", "").lower():     # the keyset bound
                raise RuntimeError("simulated permission/charset wall")
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except Exception:
                return False
        esp = Esperanto(ask)
        esp.discover()
        names = esp.enumerate("table", limit=10)             # must not raise
        self.assertEqual(names, ["alpha"])
        self.assertTrue(any("stopped early" in n for n in esp.dialect.notes))

    def test_left_right_rung(self):
        # SUBSTR/SUBSTRING/MID blocked but LEFT+RIGHT present -> RIGHT(LEFT(x,p),1).
        # LEFT/RIGHT are reserved JOIN keywords in SQLite; some builds reject LEFT(/RIGHT(
        # as function calls (syntax error, keyword) rather than invoking a same-named UDF,
        # so register the shims under non-keyword names and translate the engine's LEFT(/
        # RIGHT( onto them (the same rewrite the disguised-dialect oracles use). Keeps the
        # test portable across SQLite builds while still exercising the real left_right rung.
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t7 (v TEXT)")
        con.execute("INSERT INTO t7 VALUES ('Zagreb-42')")
        con.commit()
        con.create_function("esp_left", 2, lambda s, n: (s or "")[:max(n, 0)])
        con.create_function("esp_right", 2, lambda s, n: (s or "")[len(s or "") - n:] if n > 0 else "")
        blk = re.compile(r"(?i)\b(SUBSTR|SUBSTRING|SUBSTRC|MID)\s*\(")
        rwLeft = re.compile(r"(?i)\bLEFT\s*\(")
        rwRight = re.compile(r"(?i)\bRIGHT\s*\(")

        def ask(cond):
            if blk.search(cond):
                return False
            sql = rwRight.sub("esp_right(", rwLeft.sub("esp_left(", cond))
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % sql).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask)
        d = esp.discover()
        self.assertTrue(d.substring is not None and d.substring[0] == "left_right")
        self.assertEqual(esp.extract("(SELECT v FROM t7)"), "Zagreb-42")

    # -- adversarial dialect scenarios ---------------------------------------------

    def _adapt(self, oracle):
        esp = Esperanto(oracle)
        esp.discover()
        return esp, esp.extract(_SECRET_EXPR)

    def test_disguise_substring_is_SUBSTRING(self):
        # SUBSTR/MID blocked; the engine "has" SUBSTRING -> mapped to SQLite substr
        esp, got = self._adapt(_disguisedOracle(
            blocked=r"\bSUBSTR\(|\bMID\(|\bSUBSTRC\(",
            rewrites=[(r"SUBSTRING\(", "substr(")]))
        self.assertEqual(esp.dialect.substring[0], "SUBSTRING")
        self.assertEqual(got, "admin")

    def test_disguise_length_is_LEN(self):
        # CHAR_LENGTH/LENGTH blocked; the engine "has" LEN -> mapped to SQLite length
        esp, got = self._adapt(_disguisedOracle(
            blocked=r"CHAR_LENGTH\(|\bLENGTH\(",
            rewrites=[(r"\bLEN\(", "length(")]))
        self.assertEqual(esp.dialect.length[0], "LEN")
        self.assertEqual(got, "admin")

    def test_disguise_charcode_is_ASCII(self):
        # UNICODE/ORD blocked; the engine "has" ASCII -> mapped to SQLite unicode()
        esp, got = self._adapt(_disguisedOracle(
            blocked=r"\bUNICODE\(|\bORD\(|CODEPOINT\(",
            rewrites=[(r"\bASCII\(", "unicode(")]))
        self.assertEqual(esp.dialect.charcode[0], "ASCII")
        self.assertEqual(esp.dialect.compare, "code")
        self.assertEqual(got, "admin")

    def test_disguise_concat_is_CONCAT_not_pipes(self):
        # || blocked (as if it were logical OR, MySQL-style); engine has variadic CONCAT
        esp, got = self._adapt(_disguisedOracle(
            blocked=r"\|\|",
            funcs=[("CONCAT", -1, _concatFn)]))
        self.assertEqual(esp.dialect.concat[0], "concat")
        self.assertEqual(got, "admin")

    def test_disguise_no_catalog_brute_forces_schema(self):
        # every system catalog denied: the engine knows NOTHING about the schema and
        # must brute-force the table + columns, then dump
        esp = Esperanto(_disguisedOracle(
            blocked=r"sqlite_master|INFORMATION_SCHEMA|SYS\.|SYSIBM|pg_catalog|pg_tables|"
                    r"syscat|RDB\$|master\.\.|sys\.tables|sys\.schemas"))
        esp.discover()
        self.assertIsNone(esp.dialect.catalog)
        self.assertEqual(esp.enumerate("table"), ["users"])
        self.assertEqual(esp.columns("users"), ["id", "name", "email"])
        rows = (esp.dump("users") or {}).get("rows")
        self.assertEqual(rows, [["1", "luther", "a@b.c"], ["2", "admin", "p@w.n"], ["3", "wu", None]])

    def test_disguise_gt_blocked_falls_to_between(self):
        # a WAF that strips '<'/'>' must not break bisection - retry via BETWEEN
        esp = Esperanto(_disguisedOracle(blocked=r">|<"))
        esp.discover()
        self.assertEqual(esp._comparator, "between")
        self.assertEqual(esp.extract(_SECRET_EXPR), "admin")
        self.assertEqual(len((esp.dump("users") or {}).get("rows") or []), 3)   # BETWEEN keyset pages all

    def test_disguise_gt_and_between_blocked_use_operator_free(self):
        # '<'/'>' AND BETWEEN gone: rather than drop to slow order-free membership, the ladder
        # finds an ORDERED operator-free rung (SIGN((e)-(n))=1 etc.) that needs no comparison
        # operator - keeping efficient log2 bisection alive.
        esp = Esperanto(_disguisedOracle(blocked=r">|<|BETWEEN"))
        esp.discover()
        self.assertEqual(esp._comparator, "sign")
        self.assertEqual(esp.extract(_SECRET_EXPR), "admin")
        self.assertEqual(len((esp.dump("users") or {}).get("rows") or []), 3)   # ordered rung still pages all

    def test_disguise_no_ordering_no_in_still_extracts(self):
        # the hard floor: no '<'/'>', no BETWEEN, no IN, and no operator-free ordered rung
        # (SIGN/ABS/LEAST/GREATEST/NULLIF/WIDTH_BUCKET/INTERVAL) - only '=' equality. Values
        # still extract (linear scan); multi-row dump honestly degrades (can't page)
        esp = Esperanto(_disguisedOracle(
            blocked=r">|<|BETWEEN|\bIN\s*\(|SIGN\(|ABS\(|LEAST\(|GREATEST\(|NULLIF\(|WIDTH_BUCKET\(|INTERVAL\("))
        esp.discover()
        self.assertEqual(esp.extract(_SECRET_EXPR), "admin")
        rows = (esp.dump("users") or {}).get("rows")
        self.assertTrue(rows and rows[0] == ["1", "luther", "a@b.c"])

    def test_disguise_everything_at_once(self):
        # the monster: SUBSTRING + LEN + ASCII(->unicode) + variadic CONCAT (no ||) +
        # NO catalog, all at once - the engine must adapt to every disguise and dump
        esp = Esperanto(_disguisedOracle(
            blocked=(r"\bSUBSTR\(|\bMID\(|\bSUBSTRC\(|CHAR_LENGTH\(|\bLENGTH\(|"
                     r"\bUNICODE\(|\bORD\(|CODEPOINT\(|\|\||"
                     r"sqlite_master|INFORMATION_SCHEMA|SYS\.|SYSIBM|pg_catalog|pg_tables|"
                     r"syscat|RDB\$|master\.\.|sys\.tables|sys\.schemas"),
            rewrites=[(r"SUBSTRING\(", "substr("), (r"\bLEN\(", "length("), (r"\bASCII\(", "unicode(")],
            funcs=[("CONCAT", -1, _concatFn)]))
        esp.discover()
        self.assertEqual(esp.dialect.substring[0], "SUBSTRING")
        self.assertEqual(esp.dialect.length[0], "LEN")
        self.assertEqual(esp.dialect.charcode[0], "ASCII")
        self.assertEqual(esp.dialect.concat[0], "concat")
        self.assertIsNone(esp.dialect.catalog)
        rows = (esp.dump("users") or {}).get("rows")
        self.assertEqual(rows, [["1", "luther", "a@b.c"], ["2", "admin", "p@w.n"], ["3", "wu", None]])

    def test_disguise_dialect_profiles(self):
        # each coherent fake back-end must be discovered from scratch and yield every
        # row byte-exact - not just the one capability the disguise touches (column
        # ORDER is a dialect detail, so compare rows as column->value maps)
        want = set(frozenset(d.items()) for d in (
            {"id": "1", "name": "luther", "email": "a@b.c"},
            {"id": "2", "name": "admin", "email": "p@w.n"},
            {"id": "3", "name": "wu", "email": None}))
        for name, blocked, rewrites, funcs in _DIALECTS:
            esp = Esperanto(_disguisedOracle(blocked, rewrites, funcs))
            esp.discover()
            self.assertEqual(esp.extract(_SECRET_EXPR), "admin", "%s: extract" % name)
            d = esp.dump("users") or {}
            got = set(frozenset(dict(zip(d.get("columns") or [], r)).items()) for r in (d.get("rows") or []))
            self.assertEqual(got, want, "%s: dump %r" % (name, d.get("rows")))

    def test_disguise_bracket_quoting_reserved_words(self):
        # '"' and backtick idents blocked -> the engine must fall to [..] quoting to
        # reach reserved-word columns; commas/quotes in the data must survive framing
        seed = ('CREATE TABLE q (id INTEGER, "order" TEXT, "group" TEXT)',
                "INSERT INTO q VALUES (1, ?, ?)")
        con = sqlite3.connect(":memory:")
        con.execute(seed[0]); con.execute(seed[1], ("a,b", "x'y")); con.commit()
        blk = re.compile(r'"|`')

        def ask(cond):
            if blk.search(cond):
                return False
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except Exception:
                return False
        esp = Esperanto(ask); esp.discover()
        dq = esp.dump("q")
        self.assertEqual(esp.dialect.identQuote, ("[", "]"))    # forced past " and ` to [..]
        got = set(frozenset(dict(zip(dq["columns"], r)).items()) for r in dq["rows"])
        want = set([frozenset({"id": "1", "order": "a,b", "group": "x'y"}.items())])
        self.assertTrue(dq["complete"] and got == want, "bracket-quoted dump: %r" % dq["rows"])

    def test_disguise_lossy_charcode_escalates_to_hex(self):
        # a first-byte charcode fn (MySQL-style ASCII) is lossy for non-ASCII; the
        # engine must detect that and escalate to hex, recovering the bytes exactly
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t (v TEXT)")
        con.execute(u"INSERT INTO t VALUES ('café-€')")   # cafe-EUR
        con.commit()
        con.create_function("ASCII", 1, lambda s: (bytearray(s.encode("utf-8"))[0] if s else None))
        blk = re.compile(r"\bUNICODE\(|\bORD\(|CODEPOINT\(")

        def ask(cond):
            if blk.search(cond):
                return False
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except Exception:
                return False
        esp = Esperanto(ask); esp.discover()
        self.assertEqual(esp.dialect.charcode[0], "ASCII")
        self.assertEqual(esp.extractText("(SELECT v FROM t)"), u"café-€")

    def test_disguise_unicode_through_dialect(self):
        # non-ASCII data recovered byte-exact even while the dialect is disguised
        # (SUBSTR/MID/CHAR_LENGTH/LENGTH blocked -> SUBSTRING/LEN mapped to SQLite)
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE s (v TEXT)")
        con.execute(u"INSERT INTO s VALUES ('Zagreb-župa-€42')")   # Zagreb-zupa-EUR42
        con.commit()
        blk = re.compile(r"\bSUBSTR\(|\bMID\(|CHAR_LENGTH\(|\bLENGTH\(", re.I)
        rw = [(re.compile(r"SUBSTRING\(", re.I), "substr("), (re.compile(r"\bLEN\(", re.I), "length(")]

        def ask(cond):
            if blk.search(cond):
                return False
            sql = cond
            for rx, rep in rw:
                sql = rx.sub(rep, sql)
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % sql).fetchone()[0] == 1
            except Exception:
                return False
        esp = Esperanto(ask); esp.discover()
        self.assertEqual(esp.extractText("(SELECT v FROM s)"), u"Zagreb-župa-€42")


if __name__ == "__main__":
    unittest.main(verbosity=2)
