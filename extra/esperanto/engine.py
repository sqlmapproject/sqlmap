#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from .atlas import _FREQ_ORDER
from .atlas import _PRINTABLE_SORTED
from .atlas import _REPL
from .atlas import _unichr
from .records import Dialect
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
        self._comparator = "gt"         # ordered-compare op: "gt" / "between" / "membership"
        self._inOk = True               # IN(...) usable (order-free subset bisection)
        self._lastTruncated = False
        self._discovered = False
        self._probing = False           # True while laddering CANDIDATE rungs (discovery or lazy _ensure*): an
                                        # undecidable probe there = "rung unusable" -> False; elsewhere (reading
                                        # committed data) an undecidable probe stays undecided so it degrades loudly
        self._progress = None           # optional host callback(str) for live feedback

    @property
    def queryCount(self):
        return self._queries


def hostExtract(oracle, strategy, expr, maxlen=4096):
    """Reference HOST inference loop driven ONLY by an InferenceStrategy + oracle.

    This is the proof that the strategy is a sufficient hand-off: it reproduces
    char-by-char extraction with zero dependency on Esperanto's own retrieval code -
    exactly what sqlmap's `bisection()`/`queryOutputLength()` would do instead, but in
    ~30 lines. Covers the char-comparison modes (code / collation / ordinal /
    equality); hex mode is reachable the same way via strategy.renderHex()."""
    ask = lambda cond: bool(oracle(cond))
    L = strategy.renderLength(expr)
    if not ask("%s>=0" % L):
        return None
    if ask("%s=0" % L):
        return ""
    lo, hi = 1, min(8, maxlen)
    while hi < maxlen and ask("%s>%d" % (L, hi)):
        lo, hi = hi + 1, min(hi * 2, maxlen)
    while lo < hi:
        mid = (lo + hi) // 2
        lo, hi = (mid + 1, hi) if ask("%s>%d" % (L, mid)) else (lo, mid)
    length = lo

    def read(pos):
        mode = strategy.compare_mode
        if mode == "code":
            code = strategy.renderCode(expr, pos)
            top = 0x10FFFF
            for cap in (127, 255, 0xFFFF, 0x10FFFF):
                if not ask("%s>%d" % (code, cap)):
                    top = cap
                    break
            a, b = 0, top
            while a < b:
                m = (a + b) // 2
                a, b = (m + 1, b) if ask("%s>%d" % (code, m)) else (a, m)
            return _unichr(a)
        if mode in ("collation", "ordinal"):
            cs = _PRINTABLE_SORTED
            a, b = 0, len(cs) - 1
            while a < b:
                m = (a + b) // 2
                a, b = (m + 1, b) if ask(strategy.renderCharCmp(expr, pos, cs[m], ">")) else (a, m)
            return cs[a]
        for ch in _FREQ_ORDER:                       # equality scan
            if ask(strategy.renderCharCmp(expr, pos, ch, "=")):
                return ch
        return _REPL

    return "".join(read(i) for i in range(1, length + 1))
