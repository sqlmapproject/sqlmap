#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from .atlas import _BANNER_KEYWORDS
from .atlas import _BANNERS
from .atlas import _BINWRAP
from .atlas import _BYTELEN
from .atlas import _CATALOGS
from .atlas import _CHARCODE
from .atlas import _CHARFROM
from .atlas import _COALESCE
from .atlas import _CONCAT
from .atlas import _DUAL
from .atlas import _DUAL_IMPLIES
from .atlas import _HEXFN
from .atlas import _IDENTITY
from .atlas import _LENGTH
from .atlas import _PREFIX
from .atlas import _SUBSTRING
from .atlas import _TEXTCAST
from .records import Cap
from .records import OracleUndecided


class _Discovery(object):
    """_Discovery

    probe the target to build the Dialect; populates self.dialect, never extracts data."""

    def discover(self):
        with self._probePhase():
            return self._discover()

    def _discover(self):
        if not self._sanity():
            raise RuntimeError("oracle does not behave (1=1 true / 1=2 false failed)")
        try:
            self._discoverSubstring()
        except RuntimeError:
            # MAX-CONSTRAINT path: every substring fn is blacklisted. fall back to a
            # pure pattern-match extractor (LIKE/GLOB) that needs no SUBSTR/LENGTH/
            # code/hex fn.
            if self._fallbackPrefix():
                return self.dialect
            raise
        try:
            self._discoverLength()
        except RuntimeError:
            # no length fn - derive length from the substring's end behavior, provided
            # that end is observable (empty/NULL). one more laddered capability, so a
            # backend with substring but no CHAR_LENGTH/LENGTH/LEN still extracts.
            # if the end isn't observable (e.g. LEFT/RIGHT), drop to the pattern floor.
            if self.dialect.substring.get("beyond_end") not in ("empty", "null-or-error"):
                if self._fallbackPrefix():
                    return self.dialect
                raise
            self.dialect.notes.append("no length fn; length derived from substring end")
        self._discoverBytelen()
        self._discoverConcat()
        self._fixupLength()
        self._discoverTextcast()
        self._discoverCoalesce()
        self._discoverCompare()
        self._discoverComparator()
        self._discoverCharfrom()
        self._discoverDual()
        self._discoverIdentity()
        self._discoverCatalog()
        self._checkCompat()
        self._discovered = True
        return self.dialect

    def _fallbackPrefix(self):
        # pure LIKE/GLOB pattern-match floor: usable when there is no workable
        # substring+length combo (substring absent, or present but unmeasurable).
        # only the pattern-INDEPENDENT capabilities (charfrom/dual/catalog use no
        # SUBSTR) are discovered; concat/compare/etc. stay None.
        if not self._discoverPrefix():
            return False
        self.dialect.substring = None       # route retrieval to the pattern-match path
        self.dialect.length = None
        self.dialect.compare = "like"
        self._discoverCharfrom()
        self._discoverDual()
        self._discoverCatalog()
        self._discovered = True
        return True

    def _discoverPrefix(self):
        # LIKE/GLOB pattern match: 'sqlmap' <op> 'sq<multi>' true, 'zz<multi>' false.
        # also measure case-sensitivity ('a' <op> 'A').
        for op, multi, single in _PREFIX:
            if self._ask("('sqlmap') %s 'sq%s'" % (op, multi)) and \
               not self._ask("('sqlmap') %s 'zz%s'" % (op, multi)):
                ci = self._ask("('a') %s 'A'" % op)
                self.dialect.prefix = Cap(op, "%s", multi=multi, single=single, case_insensitive=ci)
                return op
        return None

    def identify(self):
        """Fuse catalog family + required dual-table + version banner (+ behavioral
        tells) into a best-guess product with an evidence trail. Run after
        discover(). This is the CTF step: name the abomination on the other end."""
        d = self.dialect
        if not self._discovered:
            self.discover()
        ev = []
        if d.catalog:
            ev.append(("catalog = %s" % d.catalog, d.family))
        if d.dual and d.dual[0] != "bare":
            ev.append(("bare SELECT needs FROM %s" % d.dual[0], _DUAL_IMPLIES.get(d.dual[0], "?")))
        product = None
        # best-effort naming: on a permission/charset wall a probe may be undecided;
        # degrade to whatever evidence was gathered rather than crash the verdict
        try:
            # cheap behavioral tell: || is logical OR -> MySQL family (one probe, no banner)
            if d.concat and d.concat[0] != "pipes" and self._ask("(%s)=1" % _CONCAT[0][1].format(a="1", b="1")):
                ev.append(("|| is logical OR (not concat)", "MySQL family"))
                product = "MySQL"
            # the version banner is the EXPENSIVE part (blind-reading a long string), so
            # it is paid for ONLY when the catalog family can't name the product on its
            # own - i.e. the shared INFORMATION_SCHEMA / unknown-catalog case. A specific
            # catalog (SQLite/Oracle/PostgreSQL/MSSQL/...) names the product for free, and
            # --banner reads the full version explicitly via banner().
            if product is None and (not d.family or "ANSI" in d.family):
                val, implied = self._probeBanner()
                if val:
                    ev.append(("banner", val))
                    product = self._nameFromBanner(val) or implied
                if product is None and self._hasChars("@@version_comment"):
                    comment = self.extract("@@version_comment", limit=64)
                    if comment:
                        ev.append(("@@version_comment", comment))
                        product = self._nameFromBanner(comment)
        except OracleUndecided:
            ev.append(("product identification", "stopped (oracle undecided - permission/charset wall)"))

        d.product = product or d.family
        d.evidence = ev
        return {"product": d.product, "version": d.version, "family": d.family,
                "dual": d.dual[0] if d.dual else None, "compare": d.compare,
                "evidence": ev}

    def _probeBanner(self):
        # blind-read the version string (expensive - a long string over the oracle).
        # caches on the dialect; returns (version, implied_product) - some exprs imply a
        # product just by existing (e.g. H2VERSION() -> H2)
        for _label, expr, prod, implies in _BANNERS:
            if self._hasChars(expr):
                val = self.extract(expr, limit=96)
                if val:
                    self.dialect.version = val
                    return val, (prod if implies else None)
        return None, None

    def banner(self):
        """The --banner action: the full version string, read on demand ONLY. The
        fingerprint never triggers this - naming the product (identify) is cheap and
        does not need the banner unless the catalog family is ambiguous."""
        if not self._discovered:
            self.discover()
        if self.dialect.version is None:
            try:
                self._probeBanner()
            except OracleUndecided:
                pass
        return self.dialect.version

    @staticmethod
    def _nameFromBanner(text):
        low = text.lower()
        for kw in _BANNER_KEYWORDS:
            if kw.lower() in low:
                return kw
        return None

    def _discoverSubstring(self):
        for name, tmpl in _SUBSTRING:
            g = lambda e, p, ln: tmpl.format(expr=e, pos=p, len=ln)
            base = None
            if self._ask("%s='q'" % g("'sqlmap'", 2, 1)) and not self._ask("%s='z'" % g("'sqlmap'", 2, 1)):
                base = 1
            elif self._ask("%s='q'" % g("'sqlmap'", 1, 1)) and self._ask("%s='s'" % g("'sqlmap'", 0, 1)):
                base = 0
            if base is None:
                continue
            self.dialect.substring = Cap(name, tmpl, index_base=base)
            # base detection above CONFIRMS the substring fn works; the property
            # measurements below are best-effort and MUST NOT discard it - a probe the
            # oracle can't decide leaves the property at a safe default, never aborts.
            props = self.dialect.substring.props
            try:
                props["beyond_end"] = self._edgeBehavior(self._sub("'ABCDE'", 6, 1))
                props["zero_length"] = self._edgeBehavior(self._sub("'ABCDE'", 1, 0))
                props["unit"] = self._substringUnit()
            except OracleUndecided:
                pass
            props.setdefault("beyond_end", "unknown")
            props.setdefault("zero_length", "unknown")
            props.setdefault("unit", "unknown")
            return name
        self.dialect.substring = None
        raise RuntimeError("no working substring function found")

    def _codeCharTmpl(self):
        # a code->char template (CHAR/CHR/NCHAR), probed ASCII-only and cached. lets
        # the unicode PROPERTY probes build a multibyte test char server-side instead
        # of pushing a raw non-ASCII byte through the URL/app/DBMS encoding layers.
        if self._codeTmpl is None:
            self._codeTmpl = False
            for _, tmpl in _CHARFROM:
                if self._ask("%s='a'" % tmpl.format(code=97)) and not self._ask("%s='b'" % tmpl.format(code=97)):
                    self._codeTmpl = tmpl
                    break
        return self._codeTmpl or None

    def _substringUnit(self):
        # char vs byte, ASCII-only + self-referential: SUBSTR(<mb>,1,1) returns the
        # whole char (== <mb>) if char-based, or a partial byte (!= <mb>) if byte-based.
        # <mb> is a multibyte codepoint built from its numeric code (no raw bytes sent).
        cf = self._codeCharTmpl()
        if not cf:
            return "unknown"
        mb = cf.format(code=0x20AC)                     # U+20AC (multibyte in UTF-8)
        if self._ask("%s=%s" % (self._sub(mb, 1, 1), mb)):
            return "characters"
        return "bytes-or-unknown"

    def _edgeBehavior(self, expr):
        if self._ask("%s=''" % expr):
            return "empty"
        if not self._ask("%s IS NOT NULL" % expr):
            return "null-or-error"
        return "other"

    def _discoverLength(self):
        # prefer a CHARACTER-count fn (pass 1); fall back to any working fn (pass 2)
        # so length stays in the same unit as the char-indexed substring
        for prefer_chars in (True, False):
            for name, tmpl in _LENGTH:
                f = lambda s: tmpl.format(expr=s)
                if not (self._ask("%s=1" % f("'A'")) and self._ask("%s=2" % f("'AB'"))):
                    continue
                try:
                    unit = self._lengthUnit(f)
                except OracleUndecided:
                    unit = "unknown"
                if prefer_chars and unit != "characters":
                    continue
                trailing = self._ask("%s=2" % f("'A '"))       # preserves trailing space?
                empty_null = not self._ask("(%s) IS NOT NULL" % f("''"))  # LENGTH('') errors/NULL?
                self.dialect.length = Cap(name, tmpl, unit=unit, trailing=trailing,
                                          empty_is_null=empty_null)
                return name
        self.dialect.length = None
        raise RuntimeError("no working length function found")

    def _lengthUnit(self, f):
        # ASCII-only: measure the length of a multibyte char built from its code.
        # 1 => character-counting, >=2 => byte-counting. no raw non-ASCII on the wire.
        cf = self._codeCharTmpl()
        if not cf:
            return "unknown"
        mb = cf.format(code=0x20AC)
        if self._ask("%s=1" % f(mb)):
            return "characters"
        if self._ask("%s>=2" % f(mb)):
            return "bytes"
        return "unknown"

    def _fixupLength(self):
        # a length fn that trims trailing spaces (SQL Server/Sybase LEN) truncates
        # any value ending in spaces; rebuild it as LEN(x||'.')-1 with the concat.
        L = self.dialect.length
        if not L or L.get("trailing"):
            return
        if self.dialect.concat:
            joined = self.dialect.concat[1].format(a="({expr})", b="'.'")
            props = dict(L.props, trailing=True)
            self.dialect.length = Cap(L.name + "+dot", "(%s)-1" % L[1].format(expr=joined), **props)
            self.dialect.notes.append("length fn trims trailing spaces; using %s(x||'.')-1" % L.name)
        else:
            self.dialect.notes.append("length fn trims trailing spaces and no concat to correct it")

    def _checkCompat(self):
        # substring positions and the length count must be in the SAME unit, else
        # the per-position walk desyncs on multibyte data
        s, ln = self.dialect.substring, self.dialect.length
        if s and ln:
            su, lu = s.get("unit"), ln.get("unit")
            if su == "characters" and lu == "bytes":
                self.dialect.notes.append("UNIT MISMATCH: char-indexed substring vs byte-count length - multibyte values may desync")

    def _discoverBytelen(self):
        # a *byte*-length fn - distinguished from char length with a multibyte char
        # (a char-length fn would report 1). the char is built from its code (ASCII on
        # the wire); if it can't be built, the atlas name is trusted on the ASCII check.
        cf = self._codeCharTmpl()
        mb = cf.format(code=0x20AC) if cf else None
        for name, tmpl in _BYTELEN:
            try:
                if not self._ask("%s=2" % tmpl.format(expr="'AB'")):
                    continue
                if mb and not self._ask("%s>=2" % tmpl.format(expr=mb)):
                    continue                            # counts chars, not bytes
            except OracleUndecided:
                continue
            self.dialect.bytelen = Cap(name, tmpl)
            return name

    def _discoverTextcast(self):
        # a cast that stringifies a number: substr(cast(123),1,1)='1' and the
        # negative sign survives (substr(cast(-42),1,1)='-')
        for name, tmpl in _TEXTCAST:
            c123, cneg = tmpl.format(expr="123"), tmpl.format(expr="-42")
            if self._ask("%s='1'" % self._sub(c123, 1, 1)) and \
               self._lenEquals(c123, 3) and \
               self._ask("%s='-'" % self._sub(cneg, 1, 1)):
                self.dialect.textcast = Cap(name, tmpl)
                return name

    def _discoverCoalesce(self):
        # COALESCE(NULL,'X') -> 'X'. whether empty stays empty is a *measured*
        # property, not a requirement (on Oracle '' IS NULL, so it becomes 'X').
        for name, tmpl in _COALESCE:
            g = lambda e, fb: tmpl.format(expr=e, fallback=fb)
            if self._ask("%s='X'" % self._sub(g("NULL", "'X'"), 1, 1)):
                empty_distinct = self._lenEquals(g("''", "'X'"), 0)
                self.dialect.coalesce = Cap(name, tmpl, empty_distinct=empty_distinct)
                return name

    def _discoverDual(self):
        # the tableless-SELECT FROM suffix; a non-bare match is a family fingerprint
        for name, frm in _DUAL:
            if self._ask("(SELECT 1%s)=1" % frm):
                self.dialect.dual = Cap(name, frm)
                return name

    def _discoverConcat(self):
        # test via substring of the joined result to dodge numeric-coercion
        # false positives (MySQL 'a'+'b' -> 0, '||' -> logical OR, etc.)
        for name, tmpl in _CONCAT:
            joined = tmpl.format(a="'sq'", b="'lm'")
            if self._ask("%s='l'" % self._sub(joined, 3, 1)) and \
               self._lenEquals(joined, 4):
                self.dialect.concat = Cap(name, tmpl)
                # function-style concat (CONCAT(a,b)) may be VARIADIC - a flat
                # CONCAT(a,b,c,...) beats deeply nested CONCAT(CONCAT(...)) (smaller
                # payload, less WAF/URL surface). operators (||/+) split() to "".
                func = tmpl.split("(")[0]
                if func:
                    try:
                        three = "%s('s','q','l')" % func
                        if self._ask("%s='q'" % self._sub(three, 2, 1)) and self._lenEquals(three, 3):
                            self.dialect.concat.props["variadic"] = func
                    except OracleUndecided:
                        pass
                return name
        self.dialect.concat = None
        self.dialect.notes.append("no concatenation operator discovered")

    def _discoverCompare(self):
        # 1) numeric code function - fast, unambiguous bisection
        one = self._sub("'sqlmap'", 2, 1)       # -> 'q' (code 113 / 0x71)
        for name, tmpl in _CHARCODE:
            code = tmpl.format(expr=one)
            if self._ask("%s=113" % code) and not self._ask("%s=112" % code):
                self.dialect.charcode = Cap(name, tmpl, semantics=self._charcodeSemantics(tmpl))
                self.dialect.compare = "code"
                self.dialect.ordered = True
                return "code:%s" % name
        self.dialect.charcode = None

        # 2) force byte-ordered comparison via COLLATE / binary cast - as fast as a
        #    code function (one compare per bisection) and recovers case under CI /
        #    locale collations. tried before hex because it's cheaper.
        for name, tmpl in _BINWRAP:
            w = lambda s: tmpl.format(x=s)
            if self._ask("%s>%s" % (w("'a'"), w("'A'"))) and \
               not self._ask("%s>%s" % (w("'A'"), w("'a'"))) and \
               not self._ask("%s=%s" % (w("'a'"), w("'A'"))):
                self.dialect.binwrap = Cap(name, tmpl)
                self.dialect.compare = "collation"
                self.dialect.ordered = True
                return "collation:%s" % name

        # 3) hex/byte function - collation-independent, recovers letter case even
        #    under case-insensitive collations (the key fallback when code fns are
        #    filtered by a WAF)
        for name, tmpl in _HEXFN:
            enc = self._hexEncoding(tmpl)
            if enc:
                self.dialect.hexfn = Cap(name, tmpl, encoding=enc)
                self.dialect.compare = "hex"
                self.dialect.ordered = True
                return "hex:%s" % name

        # 4) direct string comparison - only trustworthy where the collation follows
        #    byte order (probe the ASCII case/range invariants first)
        byteOrdered = (self._ask("'a'>'A'") and self._ask("'Z'<'a'") and self._ask("'0'<'A'"))
        if byteOrdered and self._ask("%s>'p'" % one) and not self._ask("%s>'r'" % one):
            self.dialect.compare = "ordinal"
            self.dialect.ordered = True
            return "ordinal"

        # 5) equality scan - case-correct only under a case-sensitive collation
        if not self._ask("'a'='A'"):
            self.dialect.compare = "equality"
            return "equality"

        # 6) last resort: case-insensitive equality. letters recovered, CASE LOST
        #    (no code/hex function and a CI collation - a genuine hard limit)
        self.dialect.compare = "equality-ci"
        self.dialect.notes.append("case-insensitive collation and no code/hex function: letter case is not recoverable")
        return "equality-ci"

    def _discoverComparator(self):
        # how to express "value > threshold" for bisection. A WAF that strips '<'/'>'
        # (very common) would otherwise leave code-mode picking '>' and silently
        # failing. Prefer '>'; else BETWEEN (ordered, no angle brackets); else fall
        # to order-free IN() subset bisection which needs only '=' membership.
        try:
            if self._ask("2>1") and not self._ask("2>3"):
                self._comparator = "gt"
            elif self._ask("2 BETWEEN 2 AND 3") and not self._ask("5 BETWEEN 2 AND 3"):
                self._comparator = "between"
                self.dialect.notes.append("'>' unusable; bisecting via BETWEEN")
            else:
                self._comparator = "membership"
                self.dialect.notes.append("no ordered comparator; using order-free IN() subset bisection")
            self._inOk = self._ask("2 IN (2,3)") and not self._ask("9 IN (2,3)")
        except OracleUndecided:
            pass    # keep the safe defaults (gt / IN-ok)

    def _charcodeSemantics(self, tmpl):
        # ASCII-only ROUND-TRIP: build a char from its code, then read the code back.
        # code(char(N))==N means extract-then-rebuild is faithful for N. no raw
        # non-ASCII byte ever crosses the URL/app/DBMS encoding layers.
        cf = self._codeCharTmpl()
        if not cf:
            return "unknown"
        code = lambda n: tmpl.format(expr=cf.format(code=n))
        try:
            if not self._ask("%s=233" % code(0x00E9)):       # U+00E9 round-trips (code(charfrom(0xE9))==0xE9)
                return "unknown"
            if not self._ask("%s=8364" % code(0x20AC)):      # U+20AC does NOT (single-byte codepage can't represent it)
                return "codepage"                            # single-byte codepage only
            # a supplementary char proves full codepoint vs a UTF-16 code-unit fn
            # (SQL Server UNICODE() returns the leading surrogate for U+1F642).
            if self._ask("%s=128578" % code(0x1F642)):
                return "codepoint"
            if self._ask("%s=55357" % code(0x1F642)):        # high surrogate
                return "utf16_unit"
            return "bmp_codepoint"                           # verified on BMP only
        except OracleUndecided:
            return "unknown"

    def _discoverCharfrom(self):
        for name, tmpl in _CHARFROM:
            if self._ask("%s='a'" % tmpl.format(code=97)) and \
               not self._ask("%s='b'" % tmpl.format(code=97)):
                self.dialect.charfrom = Cap(name, tmpl)
                return name
        self.dialect.charfrom = None

    def _discoverIdentity(self):
        for kind, candidates in sorted(_IDENTITY.items()):
            for expr in candidates:
                # a valid identity expression has non-zero length; invalid -> error -> false
                if self._hasChars(expr):
                    self.dialect.identity[kind] = expr
                    break

    def _discoverCatalog(self):
        for table, family, enum in _CATALOGS:
            if self._exists(table):
                self.dialect.catalog = table
                self.dialect.family = family
                self.dialect.catalogEnum = enum
                return table
