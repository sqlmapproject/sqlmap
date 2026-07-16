#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from .atlas import *


class OracleUndecided(RuntimeError):
    """The oracle gave no reliable True/False after retries/voting - a transport or
    observation failure, NOT a definitive answer. Raised so blind extraction fails
    CLOSED instead of converging on plausible-but-wrong data from a manufactured
    False. (A wrong-dialect/unsupported probe must be reported as False by the
    oracle itself; exceptions are reserved for 'could not observe'.)"""


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

    def __str__(self):
        return "" if self.value is None else self.value

    def __bool__(self):
        return bool(self.value)

    __nonzero__ = __bool__               # py2

    def __repr__(self):
        return ("ExtractResult(value=%r null=%s complete=%s truncated=%s q=%d%s)"
                % (self.value, self.is_null, self.complete, self.truncated, self.queries,
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
                 "coalesce", "charcode", "charfrom", "hexfn", "binwrap",
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

    The reference host loop `hostExtract()` below proves this interface is
    *sufficient*: it extracts data using ONLY a strategy + an oracle, with no
    dependency on Esperanto's own retrieval code.
    """

    _FIELDS = ("product", "family", "compare_mode", "catalog", "dual", "notes",
               "substring", "index_base", "length", "charcode", "charcode_sem",
               "hexfn", "binwrap", "charfrom", "concat", "identquote", "backslash")

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

    def renderHex(self, expr):
        return self.hexfn.format(expr=expr) if self.hexfn else None

    def renderCode(self, expr, pos):
        # scalar code point of the char at pos (None unless a code fn was found)
        return self.charcode.format(expr=self.substr(expr, pos)) if self.charcode else None

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
        from queries[Backend.getIdentifiedDbms()]."""
        return {
            "length": self.length,
            "substring": self.substring,
            "inference": ("%s>%%d" % self.charcode.format(expr=self.substr("%s", "%d")))
                         if self.charcode else None,
            "case": "SELECT (CASE WHEN (%s) THEN 1 ELSE 0 END)" + self.dual,
            "hex": self.hexfn,
        }

    def __repr__(self):
        return "InferenceStrategy(product=%r compare=%r catalog=%r)" % (
            self.product, self.compare_mode, self.catalog)


class QueryBudgetExceeded(OracleUndecided):
    """The configured hard oracle-call budget was exhausted mid-operation."""
