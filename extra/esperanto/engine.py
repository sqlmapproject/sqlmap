#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from .atlas import _FREQ_ORDER
from .atlas import _hardWarnings
from .atlas import _PRINTABLE_SORTED
from .atlas import _REPL
from .atlas import _unichr
from .records import Dialect
from .records import ExtractResult
from .records import OracleUndecided
from .oracle import _OracleCore
from .discovery import _Discovery
from .extraction import _Extraction
from .enumeration import _Enumeration


class Esperanto(_OracleCore, _Discovery, _Extraction, _Enumeration):
    """DBMS-agnostic blind extractor. Behaviour lives in four mixins by concern
    (oracle / discovery / extraction / enumeration); this class only holds
    construction + the query counter."""

    def __init__(self, oracle, verbose=False, maxlen=4096, retries=1, quorum=1,
                 maxbytes=None, max_queries=None):
        """oracle: callable(condition_str) -> bool.
        quorum>1 turns on majority voting (2*quorum-1 samples) so a noisy or
        intermittently-erroring oracle can't flip a single probe and corrupt a
        result; retries re-attempts a raised call before it counts as an error.
        maxlen caps text characters; maxbytes separately caps byte/hex recovery
        (default 4*maxlen); max_queries is an optional hard oracle-call ceiling."""
        if not callable(oracle):
            raise TypeError("oracle must be callable")
        self.oracle = oracle
        self.verbose = verbose
        self.maxlen = maxlen
        self.maxbytes = maxlen * 4 if maxbytes is None else maxbytes
        self.retries = retries
        self.quorum = max(1, quorum)
        self.max_queries = max_queries
        self.dialect = Dialect()
        self._queries = 0
        self._errors = 0
        self._hexProbed = False
        self._hexOrdered = None
        self._backslashEscape = None
        self._codeTmpl = None
        self._comparator = "gt"         # ordered-compare op: "gt" / "between" / operator-free rung / "membership"
        self._cmpTemplate = None        # operator-free ordered rung: an "expr > n" template with {expr}/{n}
        self._inOk = True               # IN(...) usable (order-free subset bisection)
        self._lastTruncated = False
        self._discovered = False
        self._nonExactNamesNoted = False   # one-shot: enumerated-identifier-ambiguity note fired
        self._castPreserves = None         # cached: does the text cast preserve a canary accent?
        self._probing = False           # True while laddering CANDIDATE rungs (discovery or lazy _ensure*): an
                                        # undecidable probe there = "rung unusable" -> False; elsewhere (reading
                                        # committed data) an undecidable probe stays undecided so it degrades loudly
        self._progress = None           # optional host callback(str) for live per-VALUE feedback
        self._charProgress = None       # optional host callback(partial, total) for live per-CHARACTER
                                        # feedback DURING a long extraction (so the user sees it working)

    @property
    def queryCount(self):
        return self._queries


def hostExtract(oracle, strategy, expr, maxlen=4096):
    """Reference HOST inference loop driven ONLY by an InferenceStrategy + oracle.

    Proof that the strategy is a sufficient hand-off: it reproduces char-by-char
    extraction with zero dependency on Esperanto's own retrieval code - what sqlmap's
    `bisection()`/`queryOutputLength()` would do instead. EVERY numeric compare renders
    through strategy.renderGt (the discovered comparator), so it survives a WAF that
    strips '>' exactly as the engine does, and length is measured via the length fn OR,
    when there is none, derived from the substring's end.

    It covers the char-comparison modes (code / collation / ordinal / equality) with an
    ordered comparator. Pattern-only (LIKE floor) and pure membership (no ordered
    comparator) are NOT driven by this reference - it raises rather than silently
    emitting an operator the dialect declared unusable or returning wrong data.

    Returns an ExtractResult (value / exact / truncated / integrity), NOT a bare string:
    an undecided host observation degrades to a FAILED result (never a manufactured bit),
    a value longer than maxlen is flagged TRUNCATED, and a code-mode value read through an
    UNPROVEN char-code fn is whole-value verified so a lossy code fn is caught (integrity
    FAILED), exactly as the native engine does - so this stays a faithful sufficiency proof."""
    HUGE = 1 << 62

    def ask(cond):
        # STRICT tri-state, like _OracleCore._ask: only a real bool is an observation; anything
        # else (None from a transport/undecided oracle) is NOT coerced to False.
        r = oracle(cond)
        if r is True or r is False:
            return r
        raise OracleUndecided("host oracle undecided: %s" % cond)

    if strategy.compare_mode == "like" or (strategy.substring is None and strategy.length is None):
        raise NotImplementedError("hostExtract: pattern-only extraction is not driven by this reference")
    if strategy.comparator == "membership":
        raise NotImplementedError("hostExtract: an ordered comparator is required (membership-only unsupported)")

    def _run():
        if strategy.length is not None:
            L = strategy.renderLength(expr)
            if not ask(strategy.renderGt(L, -1, HUGE)):     # L >= 0: defined and non-negative
                is_null = ask(strategy.renderIsNull(expr))  # ask ONCE (a noisy oracle could disagree twice)
                return ExtractResult(None, is_null=is_null, complete=is_null)
            if maxlen <= 0:                                 # non-empty but capped to nothing
                return ExtractResult("", complete=False, truncated=True)
            if not ask(strategy.renderGt(L, 0, HUGE)):      # not L > 0 -> empty string
                return ExtractResult("", complete=True)
            lo, hi = 1, min(8, maxlen)
            while hi < maxlen and ask(strategy.renderGt(L, hi, HUGE)):
                lo, hi = hi + 1, min(hi * 2, maxlen)
            while lo < hi:
                mid = (lo + hi) // 2
                lo, hi = (mid + 1, hi) if ask(strategy.renderGt(L, mid, HUGE)) else (lo, mid)
            length = lo
            truncated = length >= maxlen and ask(strategy.renderGt(L, maxlen, HUGE))   # a char past the cap
            # FINAL EQUALITY (as the native integer reader does): the comparator is proven only on
            # literals; a backend that rewrites '>' to '>=' for a computed operand (LENGTH(..)>n)
            # converges off-by-one. Confirm the length directly, else fail closed.
            if not truncated and not ask("(%s)=%d" % (L, length)):
                raise OracleUndecided("host length failed final equality")
        else:                                               # no length fn: derive from substring end
            exists = lambda n: ask(strategy.renderCharExists(expr, n))
            if not exists(1):
                is_null = ask(strategy.renderIsNull(expr))  # ask ONCE
                return ExtractResult(None, is_null=is_null, complete=is_null)
            if maxlen <= 0:                                 # non-empty but capped to nothing
                return ExtractResult("", complete=False, truncated=True)
            lo, hi = 1, min(8, maxlen)
            while hi < maxlen and exists(hi):
                lo, hi = hi, min(hi * 2, maxlen)
            while lo < hi:
                mid = (lo + hi + 1) // 2
                lo, hi = (mid, hi) if exists(mid) else (lo, mid - 1)
            length = lo
            truncated = length >= maxlen and exists(maxlen + 1)

        def read(pos):
            mode = strategy.compare_mode
            if mode == "code":
                code = strategy.renderCode(expr, pos)
                top = 0x10FFFF
                for cap in (127, 255, 0xFFFF, 0x10FFFF):
                    if not ask(strategy.renderGt(code, cap, HUGE)):
                        top = cap
                        break
                a, b = 0, top
                while a < b:
                    m = (a + b) // 2
                    a, b = (m + 1, b) if ask(strategy.renderGt(code, m, HUGE)) else (a, m)
                # FINAL EQUALITY on the code: comparator semantics are INDEPENDENT of the code
                # fn's semantics, so a '>'->'>=' rewrite on the code expression converges off-by-
                # one even when the code fn is codepoint-faithful. Confirm directly, else fail.
                if not ask("(%s)=%d" % (code, a)):
                    raise OracleUndecided("host code failed final equality")
                return _unichr(a)
            if mode in ("collation", "ordinal"):
                cs = _PRINTABLE_SORTED
                a, b = 0, len(cs) - 1
                while a < b:
                    m = (a + b) // 2
                    a, b = (m + 1, b) if ask(strategy.renderCharCmp(expr, pos, cs[m], ">")) else (a, m)
                return cs[a]
            for ch in _FREQ_ORDER:                          # equality scan
                if ask(strategy.renderCharCmp(expr, pos, ch, "=")):
                    return ch
            return _REPL

        value = "".join(read(i) for i in range(1, length + 1))
        warns = ["contains unresolved char"] if _REPL in value else []
        if strategy.compare_mode == "equality-ci":
            warns.append("lossy equality collation: case/accents ambiguous")
        # WHOLE-VALUE verification: mirrors the native verify. Run it regardless of code-point
        # semantics - the code fn being codepoint-faithful says nothing about the COMPARATOR (a
        # rewritten '>' still corrupts a codepoint-faithful read), so the value must be confirmed
        # against the source rather than trusted because the code fn is faithful.
        needs_verify = not truncated and _REPL not in value
        if needs_verify and not ask(strategy.renderExactEq(expr, strategy.lit(value))):
            warns.append("whole-value verification failed")
            return ExtractResult(value, complete=False, truncated=truncated, warnings=warns)
        # mirror the native EXACT gate: without a proven byte-exact witness (hex / binary /
        # codepoint) the value is WHOLE_BUT_AMBIGUOUS, never EXACT - renderExactEq falls back to
        # collation-dependent plain '=' which cannot certify byte-exactness.
        if value and not truncated and _REPL not in value and strategy.exact_witness is None:
            warns.append("byte-exactness unproven: collation-dependent comparison, no hex/binary witness")
        return ExtractResult(value, complete=not truncated and not _hardWarnings(warns),
                             truncated=truncated, warnings=warns)

    try:
        return _run()
    except OracleUndecided:
        return ExtractResult(None, complete=False, warnings=["host oracle undecided"])
