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

import binascii
import os
import re
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from extra.esperanto import Cap
from extra.esperanto import Esperanto
from extra.esperanto import hostExtract
from extra.esperanto import Integrity

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

    def test_between_no_saturation(self):
        # #1: BETWEEN caps range probes at the ceiling, so an out-of-range value must be
        # flagged (truncated length / OverflowError), NEVER converge to a wrong SMALL value
        # (the old bug read a len-16 value as length 1 and an int 100/max-10 as 0).
        esp = Esperanto(_oracle(u"0123456789ABCDEF"), maxlen=8)     # true length 16 > ceiling 8
        esp.discover()
        esp._comparator = "between"
        n, trunc = esp._measureLength(EXPR, ceiling=8)
        self.assertTrue(trunc and n == 8, "between over-length saturated wrong: (%r,%r)" % (n, trunc))
        esp2 = Esperanto(_oracle())
        esp2.discover()
        esp2._comparator = "between"
        self.assertEqual(esp2.extractInteger("(100)", maximum=1000), 100)
        self.assertRaises(OverflowError, esp2.extractInteger, "(100)", 10)

    def test_framing_requires_terminal_marker(self):
        # a length-framed token MUST carry its terminal ';' - a truncated final token (no ';')
        # must be rejected, not accepted as valid
        esp = Esperanto(lambda c: False)
        esp._rowLenFramed = True
        self.assertEqual(esp._splitRow("V3:414243", 1), (None, False))    # no terminator -> invalid
        self.assertEqual(esp._splitRow("V3:414243;", 1), (["ABC"], True))  # terminated -> valid
        self.assertEqual(esp._splitRow("V4:414243;", 1), (None, False))    # declared 4 != decoded 3

    def test_host_native_integrity_parity(self):
        # hostExtract must mirror the native EXACT/AMBIGUOUS verdict: in a mode with no byte-exact
        # witness (ordinal), both must be WHOLE_BUT_AMBIGUOUS, not native-ambiguous/host-exact.
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t (v TEXT)")
        con.execute("INSERT INTO t VALUES ('Admin-42')")
        con.commit()
        blk = re.compile(r"(?i)\bHEX\(|RAWTOHEX|ENCODE\(|(ASCII|UNICODE|ORD)\(|COLLATE|BLOB|BINARY")

        def ask(cond):
            if blk.search(cond):
                return False
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask, maxlen=64)
        esp.discover()
        if esp._byteFaithful():
            self.skipTest("dialect still byte-faithful")
        native = esp.extractResult("(SELECT v FROM t)")
        host = hostExtract(ask, esp.strategy(), "(SELECT v FROM t)")
        self.assertEqual(host.value, native.value)
        self.assertFalse(host.exact, "host claimed exact without a witness: %r" % host)
        self.assertEqual(host.integrity, native.integrity)

    def test_framing_length_witness_catches_capped_hex(self):
        # a HEX fn that silently caps its output (correct up to a point, then truncates) would
        # shorten a framed cell. The independent <charlen> witness in the row token (V<len>:<hex>;)
        # must reject the shortened token -> fall back to cell-by-cell (which reads the true
        # length via substring), so a 400-char value is recovered whole, not silently as 300.
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        big = "A" * 400
        con.execute("INSERT INTO t VALUES (1, ?)", (big,))
        con.commit()
        con.create_function("CHEX", 1, lambda s: binascii.hexlify((s or "").encode("utf-8")[:300]).decode().upper())

        def ask(cond):
            c = re.sub(r"UPPER\(HEX\(([^()]*)\)\)", r"CHEX(\1)", cond)   # HEX -> a 300-byte-capped hex
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % c).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask, maxlen=8192)
        esp.discover()
        d = esp.dump("t")
        val = d["rows"][0][1] if d and d["rows"] else None
        self.assertTrue((val == big and d["complete"]) or (d and not d["complete"]),
                        "capped hex slipped through: %r len=%s" % ((val or "")[:8], len(val) if val else None))

    def test_integer_final_equality(self):
        # comparator proven on literals, but the backend rewrites '>' to '>=' for scalar/fn
        # operands -> bisection converges off-by-one. The final `expr = recovered` check must
        # reject it (fail closed) rather than return a silently-wrong integer.
        con = sqlite3.connect(":memory:")

        def ask(cond):
            c = cond
            if re.search(r"(SELECT|LENGTH|UNICODE|SUBSTR|\+)", c, re.I):
                c = c.replace(">", ">=")
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % c).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask)
        esp.discover()
        self.assertRaises(Exception, esp.extractInteger, "(SELECT 5)", 10)   # OracleUndecided (fail closed)

    def test_charset_codec_quirks(self):
        from extra.esperanto.atlas import _charsetCodec
        self.assertEqual(_charsetCodec("latin1"), "cp1252")          # MySQL 'latin1' is Windows-1252
        self.assertEqual(_charsetCodec("utf8mb4"), "utf-8")
        self.assertEqual(_charsetCodec("utf8mb4_general_ci"), "utf-8")   # collation suffix peeled
        self.assertEqual(_charsetCodec("WE8MSWIN1252"), "cp1252")     # Oracle
        self.assertEqual(_charsetCodec("1252"), "cp1252")            # SQL Server code page
        self.assertEqual(_charsetCodec("AL32UTF8"), "utf-8")
        self.assertIsNone(_charsetCodec("some_unknown_set"))

    def test_host_length_code_final_equality(self):
        # Round 8 #1: hostExtract must apply the native reader's final-equality to the recovered
        # LENGTH and each per-char CODE - a backend that rewrites '>' to '>=' for computed operands
        # (LENGTH(..)>n, UNICODE(..)>n) converges off-by-one; the '=' confirmation must fail closed
        # rather than hand back silently-wrong code-point text as exact.
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t (v TEXT)")
        con.execute("INSERT INTO t VALUES ('Admin-42')")
        con.commit()

        def ask(cond):
            c = cond
            if re.search(r"(LENGTH|UNICODE|SUBSTR)\(", c, re.I):     # '>' rewritten for computed operands
                c = c.replace(">", ">=")
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % c).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask, maxlen=64)
        esp.discover()
        if esp.dialect.compare != "code":
            self.skipTest("dialect not in code mode")
        host = hostExtract(ask, esp.strategy(), "(SELECT v FROM t)")
        # the invariant: anything claimed EXACT must be CORRECT. An off-by-one read is caught by
        # the final equality and must surface as non-exact/failed, never as a wrong exact value.
        self.assertTrue(host.value == "Admin-42" or not host.exact,
                        "host handed back a wrong value as exact: %r" % host)

    def test_hex_unknown_codec_non_ascii_not_exact(self):
        # Round 8 #2: scalar hex recovery under an UNKNOWN codec must not certify non-ASCII text
        # (e.g. utf-8 bytes with an embedded NUL heuristically read as UTF-16). Bytes are faithful;
        # only a PROVEN codec makes the decoded text exact.
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t (v TEXT)")
        con.execute("INSERT INTO t VALUES (?)", (u"é",))            # utf-8 C3 A9 -> non-ASCII bytes
        con.execute("CREATE TABLE a (v TEXT)")
        con.execute("INSERT INTO a VALUES ('plain')")
        con.commit()

        def ask(cond):
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask, maxlen=64)
        esp.discover()
        if not esp._ensureHexfn():
            self.skipTest("no hex fn")
        esp.dialect.charset = None                                  # force UNKNOWN codec
        hx = esp.dialect.hexfn
        esp.dialect.hexfn = Cap(hx.name, hx[1], encoding=None)
        self.assertIsNone(esp._extractViaHex("(SELECT v FROM t)"),  # non-ASCII + unknown codec -> refuse
                          "unknown-codec non-ASCII hex certified as exact")
        ascii_r = esp._extractViaHex("(SELECT v FROM a)")           # ASCII is codec-invariant -> still OK
        self.assertTrue(ascii_r is None or ascii_r.value == "plain")

    def test_bytelen_witness_fails_closed(self):
        # Round 8 #5: once a byte-length witness is selected, an UNDECIDED reading must reject the
        # bytes (fail closed), never treat "couldn't verify" as "matched".
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t (v TEXT)")
        con.execute("INSERT INTO t VALUES ('abc')")
        con.commit()

        def ask(cond):
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask, maxlen=64)
        esp.discover()
        if not esp._ensureHexfn():
            self.skipTest("no hex fn")
        esp.dialect.bytelen = Cap("blen", "OCTET_NOSUCH({expr})")   # a byte-length fn that never resolves
        self.assertIsNone(esp.extractBytes("(SELECT v FROM t)"),
                          "undecided byte-length witness slipped through")

    def test_unknown_codec_nul_not_shortened(self):
        # Round 8 (final) blocker #1: unknown codec + embedded NUL is genuinely ambiguous - bytes
        # 41 00 are valid UTF-8 ("A"+NUL) AND valid UTF-16LE ("A"). _decodeHexToken must refuse
        # rather than collapse to a shortened ASCII "A" that then reads as exact. The framed dump
        # calls _decodeHexToken directly, so the guard has to live there (not just _extractViaHex).
        esp = Esperanto(lambda c: False)
        self.assertIsNone(esp._decodeHexToken("4100", None))                # ambiguous -> refuse
        self.assertEqual(esp._decodeHexToken("4100", "utf-8"), u"A\x00")    # proven codec keeps NUL
        self.assertEqual(esp._decodeHexToken("41", None), u"A")             # pure ASCII still fine

    def test_lossy_cast_marked_inexact(self):
        # Round 8 (final) blocker #2: a text cast that FOLDS non-ASCII to "?" (café -> caf?) yields
        # an ASCII-only result, so gating the cast-safety canary on _hasNonAscii(rows) meant it
        # never ran on the very failure it defends against. The canary must run whenever a textcast
        # was applied, and an unproven cast must not certify source identity.
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        con.execute(u"INSERT INTO t VALUES (1, 'café')")
        con.commit()
        con.create_function("LOSSY", 1, lambda s: "".join(c if ord(c) < 128 else "?" for c in (s or "")))

        def ask(cond):
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask, maxlen=64)
        esp.discover()
        esp.dialect.charset = None                              # unknown -> exercise the canary path
        esp.dialect.textcast = Cap("lossy", "LOSSY({expr})")   # a narrowing/folding cast
        esp._castPreserves = None
        self.assertFalse(esp._castPreservesAccents(), "folding cast wrongly certified as preserving")
        d = esp.dump("t")
        self.assertTrue(d and d["rows"], "dump returned nothing")
        self.assertFalse(d["exact"], "folded (café->caf?) dump reported source-exact: %r" % d["rows"])

    def test_repl_chars_escalate_to_hex(self):
        # a code fn lossy for a column type (Oracle NVARCHAR2 read in code mode marks non-ASCII
        # chars outside its alphabet -> _REPL). Rather than return the marked-incomplete value,
        # the engine must escalate to the cast+hex path (which the framed dump proves works) and
        # recover the value exactly. Without hex, it stays honestly incomplete (no false-complete).
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t (v TEXT)")
        con.execute(u"INSERT INTO t VALUES ('café-€')")
        con.commit()
        con.create_function("UNICODE", 1, lambda s: (ord(s[0]) if s and ord(s[0]) < 128 else None))

        def make(block_hex):
            pat = r"\bASCII\(|\bORD\(" + (r"|RAWTOHEX|\bHEX\(|ENCODE\(" if block_hex else "")
            blk = re.compile(pat, re.I)

            def ask(cond):
                if blk.search(cond):
                    return False
                try:
                    return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
                except Exception:
                    return False
            return ask
        with_hex = Esperanto(make(False)); with_hex.discover()
        r = with_hex.extractResult("(SELECT v FROM t)")
        self.assertEqual(r.value, u"café-€", "hex escalation failed to recover _REPL value: %r" % r.value)
        no_hex = Esperanto(make(True)); no_hex.discover()
        r2 = no_hex.extractResult("(SELECT v FROM t)")
        self.assertFalse(r2.complete, "no-hex _REPL value must stay incomplete, got complete: %r" % r2.value)

    def test_keyset_cycle_detection(self):
        # Round 8 (keyset): paging and read-back can resolve under different collations, so the
        # walk can revisit an earlier name (f,e,f,e...). Full cycle detection (not just the
        # immediate predecessor) must stop with a partial, de-duplicated list, never loop.
        esp = Esperanto(lambda c: True)                            # _keysetWalk only, no discovery
        seq = iter(["f", "e", "f", "e", "f"])

        class _R(object):
            def __init__(self, v):
                self.value, self.complete, self.exact, self.is_null = v, True, True, False
        esp.extractResult = lambda *a, **k: _R(next(seq))
        esp._ask = lambda c: True
        esp._beyondSql = lambda *a, **k: "1=1"
        names = esp._keysetWalk("name", "cat", "", 10)
        self.assertEqual(names, ["f", "e"], "cycle not detected/deduped: %r" % names)

    def test_terminal_sanitized(self):
        from extra.esperanto.__main__ import _safeterm
        self.assertEqual(_safeterm(u"ok"), u"ok")
        self.assertEqual(_safeterm(u"a\x1b[2Jb"), u"a\\x1b[2Jb")     # ANSI clear-screen neutralized
        self.assertEqual(_safeterm(u"x\ny"), u"x\\x0ay")            # embedded newline neutralized

    def test_comparator_rejects_gte_rewrite(self):
        # a '>' -> '>=' rewrite passes 2>1 / !2>3 but FAILS the equality boundary (2>2 must be
        # False). the full truth table must reject 'gt' (and fall to BETWEEN) so counts/lengths
        # aren't read off-by-one. reproduced: extractInteger('5',max=10) used to return 6.
        con = sqlite3.connect(":memory:")

        def ask(cond):
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond.replace(">", ">=")).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask)
        esp.discover()
        self.assertNotEqual(esp._comparator, "gt", "'>'->'>=' rewrite wrongly accepted as gt")
        self.assertEqual(esp.extractInteger("(5)", maximum=10), 5)

    def test_exact_requires_byte_witness(self):
        # without a proven hex/binary witness (or code-codepoint), a value is WHOLE_BUT_AMBIGUOUS,
        # never EXACT - plain '=' is collation-dependent and can't certify byte-exactness.
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t (v TEXT)")
        con.execute("INSERT INTO t VALUES ('Zz')")
        con.commit()
        blk = re.compile(r"(?i)\bHEX\(|RAWTOHEX|ENCODE\(|(ASCII|UNICODE|ORD)\(|GLOB|COLLATE|BLOB|BINARY")

        def ask(cond):
            if blk.search(cond):
                return False
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask, maxlen=64)
        esp.discover()
        r = esp.extractResult("(SELECT v FROM t)")
        if esp._byteFaithful():
            self.skipTest("dialect still has a byte-faithful primitive")
        self.assertEqual(r.value, "Zz")
        self.assertFalse(r.exact, "value marked exact without a byte-faithful witness: %r" % r)

    def test_extractresult_no_contradiction(self):
        # a hard defect (incomplete/truncated) is classified before null-exactness
        from extra.esperanto import ExtractResult, Integrity
        self.assertEqual(ExtractResult(None, is_null=True, complete=False).integrity, Integrity.FAILED)
        self.assertEqual(ExtractResult(None, is_null=True, complete=True).integrity, Integrity.EXACT)
        self.assertFalse(ExtractResult(None, is_null=True, complete=False).exact)

    def test_host_maxlen_zero(self):
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t (v TEXT)")
        con.execute("INSERT INTO t VALUES ('abcdef')")
        con.commit()

        def ask(cond):
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask)
        esp.discover()
        r = hostExtract(ask, esp.strategy(), "(SELECT v FROM t)", maxlen=0)
        self.assertEqual(r.value, "")
        self.assertTrue(r.truncated and not r.complete)

    def test_between_overflow_magnitude(self):
        # a positive value beyond BETWEEN's global ceiling fails closed WITHOUT claiming "below
        # minimum" (the direction is genuinely unknown to a bounded range predicate)
        esp = Esperanto(_oracle())
        esp.discover()
        esp._comparator = "between"
        try:
            esp.extractInteger("(%d)" % ((1 << 62) + 5))
            self.fail("expected OverflowError")
        except OverflowError as ex:
            self.assertNotIn("below minimum", str(ex))

    def test_integrity_semantics(self):
        # `complete` (walk finished) must be distinct from `exact` (bytes proven identical).
        # a case-insensitive collation recovers a WHOLE value that is NOT exact.
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t (v TEXT)")
        con.execute("INSERT INTO t VALUES ('A')")
        con.commit()
        blk = re.compile(r"(?i)\bHEX\(|RAWTOHEX|ENCODE\(|(ASCII|UNICODE|ORD)\(|GLOB|COLLATE|BLOB")

        def ask(cond):
            if blk.search(cond):
                return False
            try:
                return con.execute("SELECT CASE WHEN (%s COLLATE NOCASE) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                try:
                    return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
                except sqlite3.DatabaseError:
                    return False
        esp = Esperanto(ask, maxlen=64)
        esp.discover()
        self.assertEqual(esp.dialect.compare, "equality-ci")
        r = esp.extractResult(EXPR.replace("v FROM t", "v FROM t"))
        self.assertTrue(r.complete, "case-ci value should be WHOLE: %r" % r)
        self.assertFalse(r.exact, "case-ci value must NOT be exact: %r" % r)
        self.assertEqual(r.integrity, Integrity.WHOLE_BUT_AMBIGUOUS)

    def test_hostextract_structured_and_tristate(self):
        # hostExtract returns an ExtractResult: a bounded read is TRUNCATED (not a bare string),
        # and an undecided (None) host observation degrades to a FAILED result, never a fake bit.
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t (v TEXT)")
        con.execute("INSERT INTO t VALUES ('abcdef')")
        con.commit()

        def ask(cond):
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except sqlite3.DatabaseError:
                return False
        esp = Esperanto(ask, maxlen=64)
        esp.discover()
        strat = esp.strategy()
        r = hostExtract(ask, strat, "(SELECT v FROM t)", maxlen=3)
        self.assertEqual(r.value, "abc")
        self.assertTrue(r.truncated and not r.exact and r.integrity == Integrity.TRUNCATED)
        undecided = hostExtract(lambda c: None, strat, "(SELECT v FROM t)")
        self.assertTrue(undecided.value is None and not undecided.complete)

    def test_between_overflow_direction(self):
        # a positive value above the cap in BETWEEN mode must report ABOVE maximum (not below)
        esp = Esperanto(_oracle())
        esp.discover()
        esp._comparator = "between"
        try:
            esp.extractInteger("(100)", maximum=10)
            self.fail("expected OverflowError")
        except OverflowError as ex:
            self.assertIn("exceeds maximum", str(ex))

    def test_key_uniqueness_gate(self):
        # #2: a keyset ordering column MUST be single-column unique + non-NULL. a composite
        # key's first column repeats -> `> prev` paging silently drops rows sharing it, so it
        # must be REJECTED (COUNT(*) != COUNT(DISTINCT col)); only a unique column is accepted.
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE k (a INT, b INT, u INT, nul INT)")
        con.executemany("INSERT INTO k VALUES (?,?,?,?)", [(1, 1, 10, 1), (1, 2, 20, None), (2, 1, 30, 3)])
        con.commit()

        def ask(cond):
            try:
                return con.execute("SELECT CASE WHEN (%s) THEN 1 ELSE 0 END" % cond).fetchone()[0] == 1
            except Exception:
                return False
        esp = Esperanto(ask)
        esp.discover()
        self.assertFalse(esp._keyIsUnique("a", "k"), "non-unique composite-first column accepted")
        self.assertFalse(esp._keyIsUnique("nul", "k"), "nullable column accepted as key")
        self.assertTrue(esp._keyIsUnique("u", "k"), "unique non-null column rejected")

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
        hr = hostExtract(ask, strat, "(SELECT v FROM k)")
        self.assertEqual(hr.value, "Str4t3gy!")
        self.assertTrue(hr.exact)
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
