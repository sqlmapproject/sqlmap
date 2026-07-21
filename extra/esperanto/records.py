#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

class OracleUndecided(RuntimeError):
    """The oracle gave no reliable True/False after retries/voting - a transport or
    observation failure, NOT a definitive answer. Raised so blind extraction fails
    CLOSED instead of converging on plausible-but-wrong data from a manufactured
    False. (A wrong-dialect/unsupported probe must be reported as False by the
    oracle itself; exceptions are reserved for 'could not observe'.)"""


class NumericOutOfRange(OverflowError):
    """A bounded numeric read proved the value lies OUTSIDE [lo, hi] (above or below).
    Raised so a bounded search never invents an in-range boundary value (saturating to
    `hi`, or - for BETWEEN - converging to a wrong small value). Callers decide: length
    measurement converts it to (ceiling, truncated=True); integer extraction re-raises."""


class Cap(object):
    """A discovered primitive: (name, template) PLUS measured semantic properties.
    Indexable like the old (name, template) tuple so existing call sites keep working
    (`cap[0]`, `cap[1]`), with `cap.props` / `cap.get(key)` for the measured facts -
    e.g. length unit=characters|bytes, substring index_base, charcode semantics."""
    __slots__ = ("name", "template", "props")

    def __init__(self, name, template, **props):
        self.name, self.template, self.props = name, template, props

    def __getitem__(self, i):
        return (self.name, self.template)[i]

    def get(self, key, default=None):
        return self.props.get(key, default)

    def __repr__(self):
        extra = (" " + " ".join("%s=%s" % kv for kv in sorted(self.props.items()))) if self.props else ""
        return "%s(%s)" % (self.name, extra.strip() or self.template)


class Integrity(object):
    """How much the engine PROVED about a recovered value - separating 'the walk finished'
    from 'the bytes are exactly the source'. `complete` alone conflated the two; a value can
    be WHOLE (every position visited) yet not EXACT (case/accent ambiguous under a lossy
    collation). Anything used as executable SQL metadata or a paging boundary requires EXACT."""
    EXACT = "exact"                      # proven byte-identical to the source value (or a proven NULL)
    WHOLE_BUT_AMBIGUOUS = "ambiguous"    # every position visited, but case/accent is uncertain
    TRUNCATED = "truncated"              # a bounded prefix; the source continues
    UNRESOLVED = "unresolved"            # a character could not be recovered (U+FFFD present)
    FAILED = "failed"                    # could not observe / verify (e.g. whole-value check failed)


# warnings that leave a value WHOLE but not EXACT (case/accent uncertain) - distinct from the
# "recovered via hex" soft note (that value IS exact) and from hard integrity warnings.
_AMBIGUOUS_WARNINGS = ("case", "collation")
_U_REPL = u"\uFFFD"


class ExtractResult(object):
    """Structured extraction outcome - keeps NULL, empty, truncated and failed
    distinct (str-like so `str(r)`/truthiness still read naturally)."""
    __slots__ = ("value", "is_null", "complete", "truncated", "queries", "warnings")

    def __init__(self, value, is_null=False, complete=True, truncated=False, queries=0, warnings=None):
        self.value = value
        self.is_null = is_null
        self.complete = complete
        self.truncated = truncated
        self.queries = queries
        self.warnings = warnings or []

    @property
    def integrity(self):
        # classify what was PROVED (see Integrity). Order matters: a HARD defect (truncated /
        # unresolved / incomplete) is classified BEFORE null-exactness, so an inconsistent
        # (value=None, is_null=True, complete=False) can never read as EXACT.
        if self.truncated:
            return Integrity.TRUNCATED
        if self.value is not None and _U_REPL in self.value:
            return Integrity.UNRESOLVED
        if not self.complete:                        # a hard warning / failed verify -> not exact
            return Integrity.FAILED
        if self.value is None:
            return Integrity.EXACT if self.is_null else Integrity.FAILED
        if any(a in w for w in self.warnings for a in _AMBIGUOUS_WARNINGS):
            return Integrity.WHOLE_BUT_AMBIGUOUS
        return Integrity.EXACT

    @property
    def exact(self):
        # True ONLY when the recovered bytes are proven identical to the source. Required for
        # any value that becomes executable SQL (identifier, qualifier, exact literal).
        return self.integrity == Integrity.EXACT

    def __str__(self):
        return "" if self.value is None else self.value

    def __bool__(self):
        return bool(self.value)

    __nonzero__ = __bool__               # py2

    def __repr__(self):
        return ("ExtractResult(value=%r null=%s integrity=%s truncated=%s q=%d%s)"
                % (self.value, self.is_null, self.integrity, self.truncated, self.queries,
                   " warnings=%r" % self.warnings if self.warnings else ""))


class BulkResult(object):
    """List-like bulk-enumeration outcome that also reports completeness against an
    independent COUNT (so a truncated dump is visible, not silently short)."""
    __slots__ = ("values", "expected", "complete")

    def __init__(self, values, expected=None, complete=True):
        self.values = values
        self.expected = expected
        self.complete = complete

    def __iter__(self):
        return iter(self.values)

    def __len__(self):
        return len(self.values)

    def __getitem__(self, i):
        return self.values[i]

    def __repr__(self):
        return "%r%s" % (self.values, "" if self.complete else " (incomplete: %s of %s)" % (len(self.values), self.expected))


class Dialect(object):
    """Discovered target profile - the synthesized 'queries.xml row'."""

    __slots__ = ("concat", "substring", "length", "bytelen", "textcast",
                 "coalesce", "charcode", "charfrom", "hexfn", "binwrap", "charset",
                 "bulkAgg", "dual", "identQuote", "prefix", "compare", "ordered",
                 "identity", "catalog", "catalogEnum", "family", "product",
                 "version", "evidence", "notes")

    def __init__(self):
        self.identQuote = None      # (open, close) identifier-quote chars, or None
        self.prefix = None          # (op, multi, single) LIKE/GLOB fallback, or None
        self.concat = None          # (name, template)
        self.substring = None
        self.length = None
        self.bytelen = None         # (name, template) byte length (vs char length)
        self.textcast = None        # (name, template) scalar -> text
        self.coalesce = None        # (name, template) NULL guard
        self.charcode = None        # None -> no code fn (direct-compare mode)
        self.charfrom = None
        self.hexfn = None           # (name, template) for hex/byte extraction
        self.binwrap = None         # (name, template) byte-ordered comparison wrapper
        self.charset = None         # Python codec for the DB's DECLARED charset (authoritative hex decode)
        self.bulkAgg = None         # (name, template) row-aggregation for bulk enum
        self.dual = None            # (name, from-suffix) tableless-SELECT skeleton
        self.compare = None         # 'code' | 'collation' | 'hex' | 'ordinal' | 'equality' | 'equality-ci'
        self.ordered = False        # 'b' > 'a' holds (lexicographic bisection ok)
        self.identity = {}
        self.catalog = None
        self.catalogEnum = {}       # {kind: (name_col, source, filter)}
        self.family = None          # from the catalog probe
        self.product = None         # best-guess product (the detective verdict)
        self.version = None         # extracted banner string
        self.evidence = []          # [(signal, implication), ...]
        self.notes = []

    def __repr__(self):
        pick = lambda x: x[0] if x else None
        return ("Dialect(concat=%r substring=%r length=%r compare=%r dual=%r "
                "catalog=%r product=%r)" % (
                    pick(self.concat), pick(self.substring), pick(self.length),
                    self.compare, pick(self.dual), self.catalog,
                    self.product or self.family))


class InferenceStrategy(object):
    """An immutable, host-consumable rendering of a discovered dialect.

    This is the crystallization esperanto is really for: the discovery half produces
    ONE frozen strategy, and a host inference engine (ideally sqlmap's existing
    bisection - which already owns threading, hashDB resume, prediction, and the
    known-answer reliability litmus) drives the loop by calling these PURE render_*
    methods. No oracle here, no retrieval loop - just SQL construction from the
    discovered primitives. Frozen after construction so worker threads can share it.

    The reference host loop `hostExtract()` below drives extraction using ONLY a
    strategy + an oracle, with no dependency on Esperanto's own retrieval code.

    SCOPE (honest): this is a PARTIAL hand-off, not yet a full sufficiency proof.
    `hostExtract()` drives the code/collation/ordinal/equality char modes under an
    ordered comparator (gt / BETWEEN / operator-free), with length-fn OR substring-
    derived length, tri-state and integrity-carrying. It does NOT yet drive pattern-only
    (LIKE floor) or membership-only extraction, and the frozen field set does not yet
    carry every discovered semantic (hex-encoding confidence, IN support, wildcard
    semantics, substring/length units, cast bounds). Those modes/semantics must be added
    - or the claim narrowed - before this can be called a complete interface; the
    long-term direction is predicate renderers driven by sqlmap's own inference engine.
    """

    _FIELDS = ("product", "family", "compare_mode", "catalog", "dual", "notes",
               "substring", "index_base", "length", "charcode", "charcode_sem",
               "hexfn", "binwrap", "charfrom", "concat", "identquote", "backslash",
               "comparator", "cmp_template", "exact_witness")

    def __init__(self, **kw):
        for f in self._FIELDS:
            object.__setattr__(self, f, kw.get(f))
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, *a):                       # immutable
        raise AttributeError("InferenceStrategy is frozen")

    # -- pure SQL construction (no oracle) ----------------------------------
    def substr(self, expr, pos, length=1):
        p = pos if self.index_base == 1 else pos - 1
        return self.substring.format(expr=expr, pos=p, len=length)

    def renderLength(self, expr):
        return self.length.format(expr=expr)

    def renderIsNull(self, expr):
        return "(%s) IS NULL" % expr

    def renderCharExists(self, expr, pos):
        # a character exists at 1-based pos: its 1-char substring is non-empty. Uses '='
        # only (no '>'/'<'), and reads False for a past-end substring whether the engine
        # returns '' or NULL there - so length can be derived when there is no length fn.
        return "NOT ((%s)='')" % self.substr(expr, pos)

    def renderHex(self, expr):
        return self.hexfn.format(expr=expr) if self.hexfn else None

    def renderCode(self, expr, pos):
        # scalar code point of the char at pos (None unless a code fn was found)
        return self.charcode.format(expr=self.substr(expr, pos)) if self.charcode else None

    def renderGt(self, expr, n, high=None):
        # "expr > n" via the DISCOVERED comparator, so a host driving this strategy
        # survives a WAF that strips '>'/'<' exactly as esperanto's own loop does.
        # BETWEEN needs the current upper bound; operator-free rungs (sign/abs/...) don't.
        if self.comparator == "between" and high is not None:
            return "%s BETWEEN %d AND %d" % (expr, n + 1, high)
        if self.cmp_template:
            return self.cmp_template.format(expr=expr, n=n)
        return "%s>%d" % (expr, n)

    def renderCharCmp(self, expr, pos, ch, op=">"):
        # boolean: char at pos <op> literal ch, byte-ordered when a binary wrapper
        # is available (else the target's own collation)
        one = self.substr(expr, pos)
        if self.binwrap:
            return "%s%s%s" % (self.binwrap.format(x=one), op, self.binwrap.format(x=self.lit(ch)))
        return "%s%s%s" % (one, op, self.lit(ch))

    def renderExactEq(self, left, right):
        # whole-value byte-exact equality (hex > binary wrapper > plain)
        if self.hexfn:
            return "(%s)=(%s)" % (self.hexfn.format(expr=left), self.hexfn.format(expr=right))
        if self.binwrap:
            return "(%s)=(%s)" % (self.binwrap.format(x=left), self.binwrap.format(x=right))
        return "(%s)=(%s)" % (left, right)

    def lit(self, value):
        s = value.replace("\\", "\\\\") if self.backslash else value
        return "'%s'" % s.replace("'", "''")

    def buildLiteral(self, value):
        if value and self.charfrom and self.concat and all(0 < ord(c) < 128 for c in value):
            parts = [self.charfrom.format(code=ord(c)) for c in value]
            out = parts[0]
            for p in parts[1:]:
                out = self.concat.format(a=out, b=p)
            return out
        return self.lit(value)

    def quoteIdent(self, name):
        if not self.identquote:
            return name
        o, c = self.identquote
        return "%s%s%s" % (o, name.replace(c, c * 2), c)

    def asQueriesRow(self):
        """The sqlmap queries.xml-shaped mapping - the concrete integration hook.
        These four templates are what sqlmap's inference/error/union machinery reads
        from queries[Backend.getIdentifiedDbms()]. The `inference` template renders the
        char-code comparison through the DISCOVERED comparator, so a strategy that survives
        a '>'-stripping WAF natively is NOT turned back into a blocked '>' here. Membership
        mode has no ordered `>%d` form, so `inference` is None (that mode needs the predicate
        interface, not this 4-field row)."""
        inference = None
        if self.charcode:
            code = self.charcode.format(expr=self.substr("%s", "%d"))
            if self.comparator == "membership":
                inference = None
            elif self.cmp_template:                          # operator-free rung (SIGN/ABS/...)
                inference = self.cmp_template.replace("{expr}", code).replace("{n}", "%d")
            elif self.comparator == "between":
                inference = "%s BETWEEN (%%d)+1 AND 9223372036854775807" % code
            else:                                            # gt
                inference = "%s>%%d" % code
        return {
            "length": self.length,
            "substring": self.substring,
            "inference": inference,
            "case": "SELECT (CASE WHEN (%s) THEN 1 ELSE 0 END)" + self.dual,
            "hex": self.hexfn,
        }

    def __repr__(self):
        return "InferenceStrategy(product=%r compare=%r catalog=%r)" % (
            self.product, self.compare_mode, self.catalog)


class QueryBudgetExceeded(OracleUndecided):
    """The configured hard oracle-call budget was exhausted mid-operation."""
