#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Offline, deterministic tests for the GraphQL injection engine. Mock oracles stand in for the
HTTP/GraphQL layer so endpoint detection, introspection parsing, slot enumeration, query
construction, and boolean/error-based detection can be exercised without a live target.
"""

import json
import re
import unittest

from _testutils import bootstrap
bootstrap()

import lib.techniques.graphql.inject as gi

# --- Mock helpers -----------------------------------------------------------

MATCH = '{"data":{"user":{"id":1,"name":"luther","surname":"blisset"}}}'
NOMATCH = '{"data":{"user":null}}'
DB_ERROR = '{"errors":[{"message":"You have an error in your SQL syntax; check the manual...","path":["user"]}]}'
GQL_PARSE_ERROR = '{"errors":[{"message":"Syntax Error: Expected Name, found )","extensions":{"code":"GRAPHQL_PARSE_FAILED"}}]}'

MOCK_SCHEMA = {
    "data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "subscriptionType": None,
        "directives": [],
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": [
                {"name": "user", "args": [
                    {"name": "username", "defaultValue": None,
                     "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}}
                ], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                {"name": "byId", "args": [
                    {"name": "id", "defaultValue": None,
                     "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "Int", "ofType": None}}}
                ], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                {"name": "login", "args": [
                    {"name": "username", "defaultValue": None,
                     "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}},
                    {"name": "password", "defaultValue": None,
                     "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}},
                ], "type": {"kind": "OBJECT", "name": "AuthPayload", "ofType": None}},
                {"name": "version", "args": [],
                 "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
            ], "inputFields": None, "enumValues": None},
            {"kind": "SCALAR", "name": "String"},
            {"kind": "SCALAR", "name": "Int"},
            {"kind": "SCALAR", "name": "Float"},
            {"kind": "SCALAR", "name": "ID"},
            {"kind": "OBJECT", "name": "User", "fields": [
                {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "Int", "ofType": None}},
                {"name": "name", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
            ], "inputFields": None, "enumValues": None},
            {"kind": "OBJECT", "name": "AuthPayload", "fields": [
                {"name": "token", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                {"name": "user", "args": [], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
            ], "inputFields": None, "enumValues": None},
        ]
    }}
}


def _slot(opType, rootName, fieldName, argName, strategy="string",
           returnKind="OBJECT", returnType="User",
           returnSel="{ id name }", allArgs=None):
    """Test helper: build a minimal Slot with sensible defaults"""
    if allArgs is None:
        argType = {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}
        if strategy == "numeric":
            argType = {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "Int", "ofType": None}}
        elif strategy == "id_dual":
            argType = {"kind": "SCALAR", "name": "ID"}
        allArgs = [(argName, argType, None)]
    return gi.Slot(opType, rootName, fieldName, allArgs, argName, strategy,
                    returnKind, returnType, returnSel)


# --- Tests -----------------------------------------------------------------

class TestGraphqlHelpers(unittest.TestCase):
    """Unit tests for type-walking, classification, and response parsing"""

    def test_unwrap_simple_scalar(self):
        chain = gi._unwrapType({"kind": "SCALAR", "name": "String"})
        self.assertEqual(chain, [("SCALAR", "String")])

    def test_unwrap_non_null(self):
        chain = gi._unwrapType({"kind": "NON_NULL", "name": None,
                                 "ofType": {"kind": "SCALAR", "name": "String"}})
        self.assertEqual(chain, [("NON_NULL", None), ("SCALAR", "String")])

    def test_unwrap_list_non_null(self):
        chain = gi._unwrapType({"kind": "LIST", "name": None,
                                 "ofType": {"kind": "NON_NULL", "name": None,
                                            "ofType": {"kind": "OBJECT", "name": "User"}}})
        self.assertEqual(chain, [("LIST", None), ("NON_NULL", None), ("OBJECT", "User")])

    def test_classify_string(self):
        self.assertEqual(gi._classifyArg({"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "String"}}), "string")

    def test_classify_int(self):
        self.assertEqual(gi._classifyArg({"kind": "SCALAR", "name": "Int"}), "numeric")

    def test_classify_float(self):
        self.assertEqual(gi._classifyArg({"kind": "SCALAR", "name": "Float"}), "numeric")

    def test_classify_id(self):
        self.assertEqual(gi._classifyArg({"kind": "SCALAR", "name": "ID"}), "id_dual")

    def test_classify_boolean_is_none(self):
        self.assertIsNone(gi._classifyArg({"kind": "SCALAR", "name": "Boolean"}))

    def test_escape_graphql_string(self):
        self.assertEqual(gi._escapeGraphQLString('test"quote'), 'test\\"quote')
        self.assertEqual(gi._escapeGraphQLString("back\\slash"), "back\\\\slash")

    def test_is_graphql_response_with_typename(self):
        self.assertTrue(gi._isGraphQLResponse('{"data":{"__typename":"Query"}}'))

    def test_is_graphql_response_parse_error(self):
        self.assertTrue(gi._isGraphQLResponse(
            '{"errors":[{"message":"Syntax Error: Unexpected <EOF>","extensions":{"code":"GRAPHQL_PARSE_FAILED"}}]}'))

    def test_not_graphql_response(self):
        self.assertFalse(gi._isGraphQLResponse("<html><body>hello</body></html>"))
        self.assertFalse(gi._isGraphQLResponse(""))
        self.assertFalse(gi._isGraphQLResponse('{"data":{"user":{"id":1}}}'))    # no __typename, no graphql error phrasing

    def test_error_text_extraction(self):
        err = gi._errorText(DB_ERROR)
        self.assertIn("SQL syntax", err)
        self.assertIn("check the manual", err)

    def test_error_text_from_parse_failure(self):
        err = gi._errorText(GQL_PARSE_ERROR)
        self.assertIn("GRAPHQL_PARSE_FAILED", err)
        self.assertIn("Syntax Error", err)

    def test_slot_value_from_data(self):
        val = gi._slotValue(MATCH)
        self.assertIn("luther", val)
        self.assertIn("blisset", val)

    def test_slot_value_null(self):
        val = gi._slotValue(NOMATCH)
        self.assertIn("null", val)


class TestGraphqlIntrospection(unittest.TestCase):
    """Schema walking and slot enumeration"""

    def test_extract_slots(self):
        schema = MOCK_SCHEMA["data"]["__schema"]
        slots = gi._extractSlots(schema)
        names = [(s.parentType, s.fieldName, s.targetArg, s.strategy) for s in slots]
        self.assertIn(("Query", "user", "username", "string"), names)
        self.assertIn(("Query", "byId", "id", "numeric"), names)

    def test_login_has_two_args(self):
        """login(username: String!, password: String!) -- both required args should be in Slot"""
        schema = MOCK_SCHEMA["data"]["__schema"]
        slots = gi._extractSlots(schema)
        loginSlots = [s for s in slots if s.fieldName == "login"]
        self.assertEqual(len(loginSlots), 2)
        for s in loginSlots:
            self.assertEqual(len(s.allArgs), 2)       # username + password

    def test_scalar_return_has_empty_selection(self):
        """version: String -- field with no args produces no slots"""
        schema = MOCK_SCHEMA["data"]["__schema"]
        slots = gi._extractSlots(schema)
        # version has no args, so it should NOT appear in slots
        versionSlots = [s for s in slots if s.fieldName == "version"]
        self.assertEqual(len(versionSlots), 0)


class TestGraphqlBuildQuery(unittest.TestCase):
    """GraphQL query document construction from Slot + value"""

    def test_string_arg(self):
        slot = _slot("query", "Query", "user", "username", "string")
        q = gi._buildQuery(slot, "luther")
        self.assertIn('user(username:"luther")', q)
        self.assertIn("{ id name }", q)

    def test_string_injection_payload(self):
        slot = _slot("query", "Query", "user", "username", "string")
        q = gi._buildQuery(slot, "' OR '1'='1")
        self.assertIn("' OR '1'='1", q)

    def test_numeric_with_payload_is_empty(self):
        """Numeric GraphQL literals cannot carry SQL payloads; _buildQuery returns ''"""
        slot = _slot("query", "Query", "byId", "id", "numeric")
        q = gi._buildQuery(slot, "1 OR 1=1")
        self.assertEqual(q, "")

    def test_numeric_with_valid_integer(self):
        slot = _slot("query", "Query", "byId", "id", "numeric")
        q = gi._buildQuery(slot, "1")
        self.assertIn("byId(id:1)", q)

    def test_id_string(self):
        slot = _slot("query", "Query", "get", "uid", "id_dual")
        q = gi._buildQuery(slot, "abc")
        self.assertIn('get(uid:"abc")', q)

    def test_id_numeric(self):
        slot = _slot("query", "Query", "get", "uid", "id_dual")
        q = gi._buildQuery(slot, "123")
        self.assertIn("get(uid:123)", q)

    def test_two_required_args_renders_both(self):
        """login(username: String!, password: String!) -- uninjected sibling gets a default"""
        allArgs = [
            ("username", {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}, None),
            ("password", {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}, None),
        ]
        slot = gi.Slot("query", "Query", "login", allArgs, "password", "string",
                        "OBJECT", "AuthPayload", "{ token user { id name } }")
        q = gi._buildQuery(slot, "' OR '1'='1")
        self.assertIn("login(", q)
        self.assertIn("username:", q)       # required sibling rendered
        self.assertIn("password:", q)       # target arg rendered
        self.assertIn("' OR '1'='1", q)

    def test_mutation_wraps_with_mutation_keyword(self):
        allArgs = [
            ("id", {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "Int", "ofType": None}}, None),
            ("email", {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}, None),
        ]
        slot = gi.Slot("mutation", "Mutation", "updateUser", allArgs, "email", "string",
                        "OBJECT", "User", "{ id name }")
        q = gi._buildQuery(slot, "x' OR '1'='1")
        self.assertTrue(q.startswith("mutation {"))


class TestGraphqlBooleanDetection(unittest.TestCase):
    """Boolean-based detection via mock oracle"""

    def setUp(self):
        self._gql = gi._gqlSend
        gi.conf = type("C", (), {"url": "http://test/graphql"})()

        pages = {"true": MATCH, "false": NOMATCH}
        def fakeSend(endpoint, query, variables=None):
            if "'1'='1" in query:
                return pages["true"], 200
            if "'1'='2" in query:
                return pages["false"], 200
            return NOMATCH, 200
        gi._gqlSend = fakeSend

    def tearDown(self):
        gi._gqlSend = self._gql

    def test_boolean_detected(self):
        slot = _slot("query", "Query", "user", "username", "string")
        oracleType, template = gi._detectBoolean(slot, "http://test/graphql")
        self.assertIsNotNone(oracleType)
        self.assertIn("boolean-based", oracleType)

    def test_numeric_skipped(self):
        slot = _slot("query", "Query", "byId", "id", "numeric")
        oracleType, template = gi._detectBoolean(slot, "http://test/graphql")
        self.assertIsNone(oracleType)


class TestGraphqlErrorDetection(unittest.TestCase):
    """Error-based detection via mock oracle"""

    def setUp(self):
        self._gql = gi._gqlSend
        gi.conf = type("C", (), {"url": "http://test/graphql"})()

        def fakeSend(endpoint, query, variables=None):
            if "'" in query and "'1'='1" not in query:
                return DB_ERROR, 500
            return NOMATCH, 200
        gi._gqlSend = fakeSend

    def tearDown(self):
        gi._gqlSend = self._gql

    def test_error_detected(self):
        slot = _slot("query", "Query", "user", "username", "string")
        oracleType, detail = gi._detectError(slot, "http://test/graphql")
        self.assertEqual(oracleType, "error-based")


class TestGraphqlParseRows(unittest.TestCase):
    """JSON data row parsing for in-band dumps"""

    def test_single_object(self):
        page = '{"data":{"user":{"id":1,"name":"luther","surname":"blisset"}}}'
        slot = _slot("query", "Query", "user", "username", "string")
        result = gi._parseRows(page, slot)
        self.assertIsNotNone(result)
        columns, rows = result
        self.assertIn("id", columns)
        self.assertIn("name", columns)
        self.assertEqual(rows[0][columns.index("name")], "luther")

    def test_list_of_objects(self):
        page = '{"data":{"search":[{"id":1,"name":"luther"},{"id":2,"name":"fluffy"}]}}'
        slot = _slot("query", "Query", "search", "term", "string")
        columns, rows = gi._parseRows(page, slot)
        self.assertEqual(len(rows), 2)
        names = [r[columns.index("name")] for r in rows]
        self.assertIn("luther", names)
        self.assertIn("fluffy", names)

    def test_null_returns_none(self):
        page = '{"data":{"user":null}}'
        slot = _slot("query", "Query", "user", "username", "string")
        self.assertIsNone(gi._parseRows(page, slot))

    def test_non_json_returns_none(self):
        self.assertIsNone(gi._parseRows("<html></html>", None))


class TestGraphqlGrid(unittest.TestCase):
    """ASCII table rendering"""

    def test_grid(self):
        output = gi._grid(["id", "name"], [["1", "luther"], ["2", "fluffy"]])
        self.assertIn("id", output)
        self.assertIn("luther", output)
        self.assertIn("fluffy", output)
        self.assertIn("+-", output)
        self.assertIn("|", output)


class TestGraphqlEndpointDetection(unittest.TestCase):
    """Mock endpoint detection"""

    def setUp(self):
        self._gql = gi._gqlSend
        def fakeSend(endpoint, query, variables=None):
            if endpoint.endswith("/graphql") and "__typename" in query:
                return '{"data":{"__typename":"Query"}}', 200
            return 'Not Found', 404
        gi._gqlSend = fakeSend

    def tearDown(self):
        gi._gqlSend = self._gql

    def test_detect_direct_url(self):
        endpoint, page = gi._detectEndpoint("http://test/graphql", probePaths=False)
        self.assertEqual(endpoint, "http://test/graphql")

    def test_detect_via_probe(self):
        endpoint, page = gi._detectEndpoint("http://test", probePaths=True)
        self.assertEqual(endpoint, "http://test/graphql")

    def test_not_graphql_endpoint(self):
        def fakeSend(endpoint, query, variables=None):
            return 'Not Found', 404
        gi._gqlSend = fakeSend
        endpoint, page = gi._detectEndpoint("http://test", probePaths=True)
        self.assertIsNone(endpoint)


class TestGraphqlIntrospectionFallback(unittest.TestCase):
    """Introspection without specifiedByURL (older servers)"""

    def setUp(self):
        self._gql = gi._gqlSend
        gi.conf = type("C", (), {"url": "http://test/graphql"})()

    def tearDown(self):
        gi._gqlSend = self._gql

    def test_fallback_without_specifiedByURL(self):
        calls = []
        def fakeSend(endpoint, query, variables=None):
            calls.append(query)
            if "specifiedByURL" in query:
                return '{"errors":[{"message":"Unknown field specifiedByURL"}]}', 400
            return json.dumps(MOCK_SCHEMA), 200

        gi._gqlSend = fakeSend
        schema = gi._introspect("http://test/graphql")
        self.assertIsNotNone(schema)
        self.assertIn("queryType", schema)
        self.assertEqual(len(calls), 2)       # first fails, second succeeds


class TestGraphqlNestedReturnSelection(unittest.TestCase):
    """Nested return selections for object-typed fields within the return type"""

    def test_auth_payload_nested_user(self):
        """AuthPayload { token, user { id name } } -- selection must nest user sub-fields"""
        schema = MOCK_SCHEMA["data"]["__schema"]
        slots = gi._extractSlots(schema)
        loginSlots = [s for s in slots if s.fieldName == "login"]
        self.assertTrue(len(loginSlots) > 0)
        # The nested selection should include 'user { ... }' at some level
        for s in loginSlots:
            self.assertIn("token", s.returnSel)
            # user sub-fields should appear
            self.assertIn("id", s.returnSel)
            self.assertIn("name", s.returnSel)


class TestGraphqlCell(unittest.TestCase):
    """Dump-cell rendering: scalars as text, nested structures as compact JSON, null as NULL"""

    def test_scalar(self):
        self.assertEqual(gi._cell("luther"), "luther")
        self.assertEqual(gi._cell(7), "7")

    def test_null(self):
        self.assertEqual(gi._cell(None), "NULL")

    def test_nested_object_is_json_not_repr(self):
        # issue B: a nested object must not leak Python dict syntax into the dump
        self.assertEqual(gi._cell({"id": 1, "name": "luther"}), '{"id": 1, "name": "luther"}')
        self.assertEqual(gi._cell([1, 2]), "[1, 2]")


class TestGraphqlDialects(unittest.TestCase):
    """Per-DBMS SQL building blocks"""

    def test_sqlite_ordinal_and_length(self):
        d = gi.DIALECTS["SQLite"]
        self.assertEqual(d.length("x"), "LENGTH((x))")
        self.assertEqual(d.ordinal("x", 3), "UNICODE(SUBSTR((x),3,1))")

    def test_sqlite_rows_handles_nulls(self):
        d = gi.DIALECTS["SQLite"]
        sql = d.rows(["name", "surname"], "users")
        self.assertIn("GROUP_CONCAT", sql)
        self.assertIn("COALESCE(CAST(name AS TEXT),'NULL')", sql)
        self.assertIn("FROM users", sql)

    def test_mysql_uses_sleep_delay(self):
        d = gi.DIALECTS["MySQL"]
        self.assertEqual(d.delay("1=1", 5), "IF((1=1),SLEEP(5),0)")

    def test_sqlite_has_no_delay(self):
        self.assertIsNone(gi.DIALECTS["SQLite"].delay)


def _dbmsTruth(dbms):
    """A truth() oracle that behaves like a real `dbms` back-end: it answers each
    dialect's fingerprint predicate by the SQL *semantics* a genuine instance would
    exhibit, keyed on the function tokens the predicate emits - never on the
    fingerprint constant itself. A predicate referencing a function the back-end does
    not implement raises an error on a real server and is therefore falsy here."""

    # Which vendor-specific tokens each back-end actually understands. A predicate is
    # true only if every vendor token it mentions belongs to this back-end (mirroring
    # an unknown function being a hard error rather than a false comparison).
    knows = {
        "SQLite": ("SQLITE_VERSION()",),
        "Microsoft SQL Server": ("@@VERSION",),
        "PostgreSQL": ("version()",),
        "MySQL": ("@@VERSION_COMMENT", "@@VERSION"),
    }
    # @@VERSION exists on both MSSQL and MySQL; the distinguishing factor is the
    # '%Microsoft%' banner match, which only an actual Microsoft server satisfies.
    vendorTokens = ("SQLITE_VERSION()", "@@VERSION_COMMENT", "@@VERSION", "version()")
    owned = knows[dbms]

    def truth(cond):
        # Any vendor token the predicate names must be implemented by this back-end,
        # else the probe errors out (falsy).
        for token in vendorTokens:
            if token in cond and token not in owned:
                # @@VERSION is shared; let the banner clause below decide instead.
                if token == "@@VERSION" and "@@VERSION_COMMENT" not in cond:
                    continue
                return False
        if not any(token in cond for token in vendorTokens):
            return False
        # @@VERSION LIKE '%Microsoft%' is only true on a real Microsoft server.
        if "@@VERSION" in cond and "Microsoft" in cond:
            return dbms == "Microsoft SQL Server"
        # version() LIKE 'PostgreSQL%' is only true on a real PostgreSQL server.
        if "version()" in cond and "PostgreSQL" in cond:
            return dbms == "PostgreSQL"
        return True

    return truth


class TestGraphqlFingerprint(unittest.TestCase):
    """DBMS fingerprinting drives off the universal truth() predicate"""

    def test_identifies_sqlite(self):
        # A SQLite-modelled oracle answers only SQLite's own probe; _fingerprint must
        # discriminate to land on SQLite rather than echo the asserted constant.
        self.assertEqual(gi._fingerprint(_dbmsTruth("SQLite")), "SQLite")

    def test_identifies_mysql(self):
        self.assertEqual(gi._fingerprint(_dbmsTruth("MySQL")), "MySQL")

    def test_identifies_mssql(self):
        # @@VERSION is shared with MySQL; only the '%Microsoft%' banner match resolves it.
        self.assertEqual(gi._fingerprint(_dbmsTruth("Microsoft SQL Server")),
                         "Microsoft SQL Server")

    def test_identifies_postgresql(self):
        self.assertEqual(gi._fingerprint(_dbmsTruth("PostgreSQL")), "PostgreSQL")

    def test_unknown_backend(self):
        self.assertIsNone(gi._fingerprint(lambda cond: False))


def _mockOracle(target):
    """A synthetic SQLite-like dialect plus truth/truthBatch closures that answer comparison and bit
    predicates against a known `target` string - lets the blind extractors be exercised without HTTP."""

    dialect = gi.Dialect(
        fingerprint="FP", delay=None, banner=None, currentUser=None, currentDb=None,
        tables=None, columns=None,
        length=lambda expr: "LEN(%s)" % expr,
        ordinal=lambda expr, pos: "ORD(%s,%d)" % (expr, pos),
        rows=None)

    def _value(cond):
        pos = None
        if cond.startswith("LEN("):
            value = len(target)
        else:                                          # ORD(<expr>,<pos>)
            pos = int(cond[cond.index(",") + 1:cond.rindex(")")])
            value = ord(target[pos - 1]) if pos - 1 < len(target) else 0
        return value

    def truth(cond):
        tail = cond[cond.rindex(")") + 1:]             # e.g. ">=65"
        op = re.match(r"(>=|>|=)", tail).group(1)
        num = int(tail[len(op):])
        value = _value(cond)
        return {">": value > num, ">=": value >= num, "=": value == num}[op]

    def truthBatch(conditions):
        results = []
        for cond in conditions:
            bit = re.match(r"\(ORD\(.*?,(\d+)\) & (\d+)\)>0$", cond)
            if bit:
                pos, mask = int(bit.group(1)), int(bit.group(2))
                value = ord(target[pos - 1]) if pos - 1 < len(target) else 0
                results.append((value & mask) > 0)
            else:
                results.append(truth(cond))
        return results

    return dialect, truth, truthBatch


class TestGraphqlInference(unittest.TestCase):
    """Blind value recovery: sequential bisection and bit-parallel batched extraction"""

    def test_sequential_extraction(self):
        for target in ("3.45.1", "users,creds", "db3a16990a0008a3b04707fdef6584a0", ""):
            dialect, truth, _ = _mockOracle(target)
            self.assertEqual(gi._inferExpr(truth, dialect, "EXPR"), target)

    def test_batched_extraction_matches_sequential(self):
        for target in ("3.45.1", "users,creds", "luther~~~blisset^^^fluffy~~~bunny"):
            dialect, _, truthBatch = _mockOracle(target)
            self.assertEqual(gi._inferExprBatched(truthBatch, dialect, "EXPR"), target)

    def test_batched_empty(self):
        dialect, _, truthBatch = _mockOracle("")
        self.assertEqual(gi._inferExprBatched(truthBatch, dialect, "EXPR"), "")


class TestGraphqlDumpTable(unittest.TestCase):
    """Whole-table dump: column list + row scalar split back into a grid"""

    def test_dump_table(self):
        responses = {
            "(SELECT GROUP_CONCAT(name) FROM pragma_table_info('users'))": "id,name",
        }
        rowScalar = "1%snull^^^2%sluther" % ("~~~", "~~~")     # two rows, two columns

        def infer(expr, maxLen=gi.MAX_LENGTH):
            if expr in responses:
                return responses[expr]
            return rowScalar                                   # the GROUP_CONCAT row dump

        columns, rows = gi._dumpTable(infer, gi.DIALECTS["SQLite"], "users")
        self.assertEqual(columns, ["id", "name"])
        self.assertEqual(rows, [["1", "null"], ["2", "luther"]])


class TestGraphqlMakeOracle(unittest.TestCase):
    """Universal truth()/truthBatch() primitive built from a slot's true/false contrast"""

    USER_OBJ = {"id": 1, "name": "luther", "surname": "blisset"}

    def setUp(self):
        self._gql = gi._gqlSend

        def fakeSend(endpoint, query, variables=None):
            if "a0:" in query:                                 # batched, aliased request
                data = {}
                for m in re.finditer(r'(a\d+):\w+\(\w+:"[^"]*\((1=1|1=2)\)', query):
                    data[m.group(1)] = self.USER_OBJ if m.group(2) == "1=1" else None
                return json.dumps({"data": data}), 200
            if "(1=1)" in query:
                return json.dumps({"data": {"user": self.USER_OBJ}}), 200
            return json.dumps({"data": {"user": None}}), 200

        gi._gqlSend = fakeSend

    def tearDown(self):
        gi._gqlSend = self._gql

    def test_truth_primitive(self):
        slot = _slot("query", "Query", "user", "username", "string")
        truth, truthBatch = gi._makeOracle(slot, "http://test/graphql")
        self.assertIsNotNone(truth)
        self.assertTrue(truth("1=1"))
        self.assertFalse(truth("1=2"))

    def test_batched_truth(self):
        slot = _slot("query", "Query", "user", "username", "string")
        _, truthBatch = gi._makeOracle(slot, "http://test/graphql")
        self.assertEqual(truthBatch(["1=1", "1=2", "1=1"]), [True, False, True])


class TestVulnserverGraphqlParser(unittest.TestCase):
    """The vulnserver's selection parser must survive aliased batches and bracketed payloads"""

    def setUp(self):
        from extra.vulnserver import vulnserver
        self.vs = vulnserver

    def test_match_skips_quoted_brackets(self):
        text = 'user(username:"x\' OR (1=1)-- "){ id }'
        end = self.vs._graphql_match(text, text.index("("))
        self.assertEqual(text[end - 1], ")")          # the args close-paren, not one inside the string

    def test_single_field(self):
        sels = self.vs._graphql_selections('user(username:"luther"){ id name }')
        self.assertEqual(sels, [(None, "user", 'username:"luther"')])

    def test_aliased_batch_with_payloads(self):
        body = 'a0:user(username:"x\' OR (1=1)-- "){ id } a1:user(username:"x\' OR (1=2)-- "){ id }'
        sels = self.vs._graphql_selections(body)
        self.assertEqual([(a, f) for a, f, _ in sels], [("a0", "user"), ("a1", "user")])
        self.assertIn("(1=1)", sels[0][2])
        self.assertIn("(1=2)", sels[1][2])

    def test_nested_selection_set(self):
        sels = self.vs._graphql_selections('login(username:"a", password:"b"){ token user { id name } }')
        self.assertEqual(len(sels), 1)
        self.assertEqual(sels[0][1], "login")


class TestGraphqlSiblingDefaults(unittest.TestCase):
    """Required sibling arguments must use their real type, not be hardcoded as strings"""

    def test_numeric_sibling_not_quoted(self):
        """field(name: String!, limit: Int!) -- injecting 'name' renders limit:0, not limit:\"0\""""
        allArgs = [
            ("name", {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}, None),
            ("limit", {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "Int", "ofType": None}}, None),
        ]
        slot = gi.Slot("query", "Query", "search", allArgs, "name", "string",
                        "OBJECT", "User", "{ id }")
        q = gi._buildQuery(slot, "' OR '1'='1")
        self.assertIn("limit:0", q)
        self.assertNotIn('limit:"0"', q)

    def test_boolean_sibling_gets_default_string(self):
        """field(name: String!, active: Boolean!) -- Boolean gets \"x\" since there is no Boolean strategy"""
        allArgs = [
            ("name", {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}, None),
            ("active", {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "Boolean", "ofType": None}}, None),
        ]
        slot = gi.Slot("query", "Query", "toggle", allArgs, "name", "string",
                        "OBJECT", "User", "{ id }")
        q = gi._buildQuery(slot, "test")
        self.assertIn('active:"x"', q)


class TestGraphqlScalarReturnSelection(unittest.TestCase):
    """Scalar and list-of-scalar returns must not get a spurious {__typename} selection"""

    def test_scalar_return_has_no_selection(self):
        """version(format: String): String -- no sub-selection"""
        allArgs = [
            ("format", {"kind": "SCALAR", "name": "String"}, None),
        ]
        slot = gi.Slot("query", "Query", "version", allArgs, "format", "string",
                        "SCALAR", "String", None)
        q = gi._buildQuery(slot, "json")
        self.assertIn('version(format:"json")', q)
        self.assertNotIn("{", q.split(")")[1] if ")" in q else q)

    def test_list_of_scalars_has_no_selection(self):
        """tags(prefix: String): [String] -- no sub-selection"""
        allArgs = [
            ("prefix", {"kind": "SCALAR", "name": "String"}, None),
        ]
        slot = gi.Slot("query", "Query", "tags", allArgs, "prefix", "string",
                        "SCALAR", "String", None)
        q = gi._buildQuery(slot, "a")
        self.assertIn('tags(prefix:"a")', q)
        self.assertNotIn("{", q.split(")")[1] if ")" in q else q)


class TestGraphqlUnicodeSafety(unittest.TestCase):
    """All string conversions must be safe under Python 2 and 3 for non-ASCII data"""

    def test_escape_graphql_string_unicode(self):
        escaped = gi._escapeGraphQLString(u"caf\xe9")
        self.assertIn("caf", escaped)

    def test_error_text_unicode(self):
        page = u'{"errors":[{"message":"caf\xe9","extensions":{"code":"SYNTAX_ERROR"}}]}'
        text = gi._errorText(page)
        self.assertIn("caf", text)

    def test_cell_unicode(self):
        self.assertIn("caf", gi._cell(u"caf\xe9"))


class TestGraphqlSuggestionRecovery(unittest.TestCase):
    """G1: schema recovery from 'Did you mean' suggestions when introspection is disabled."""

    def setUp(self):
        self._gql = gi._gqlSend

    def tearDown(self):
        gi._gqlSend = self._gql

    def test_harvest_suggestions_both_quote_styles(self):
        # graphql-js uses double quotes; some servers use single quotes + Oxford 'or'
        self.assertEqual(
            gi._harvestSuggestions('Cannot query field "x" on type "Query". Did you mean "user" or "search"?'),
            ["user", "search"])
        self.assertEqual(
            gi._harvestSuggestions("Cannot query field 'x' on type 'Query'. Did you mean 'user', 'me', or 'node'?"),
            ["user", "me", "node"])
        self.assertEqual(gi._harvestSuggestions("no suggestion here"), [])

    def test_suggest_fields_from_validation_errors(self):
        # An unknown field elicits the closest real field names (graphql-js phrasing)
        def fake(endpoint, query, variables=None):
            if "{ user }" in query or "{user}" in query:
                return '{"data":{"user":null}}', 200          # 'user' is a real (resolving) field
            return ('{"errors":[{"message":"Cannot query field \\"%s\\" on type \\"Query\\". '
                    'Did you mean \\"user\\", \\"search\\" or \\"login\\"?"}]}'
                    % "zz", 200)
        gi._gqlSend = fake
        fields = gi._suggestFields("http://t/graphql", "query")
        for expected in ("user", "search", "login"):
            self.assertIn(expected, fields)

    def test_suggest_args_from_unknown_argument(self):
        def fake(endpoint, query, variables=None):
            return ('{"errors":[{"message":"Unknown argument \\"zz\\" on field \\"Query.user\\". '
                    'Did you mean \\"username\\"?"}]}', 200)
        gi._gqlSend = fake
        self.assertIn("username", gi._suggestArgs("http://t/graphql", "query", "user"))

    def test_introspect_via_suggestions_builds_slots(self):
        def fake(endpoint, query, variables=None):
            # introspection-style queries already filtered upstream; here every unknown field
            # yields the same suggestion set, and 'search' resolves as a real field
            if "{ search }" in query or "{search}" in query:
                return '{"data":{"search":[]}}', 200
            if "Unknown argument" in query:   # never matches; args fall back to wordlist
                return '{}', 200
            return ('{"errors":[{"message":"Cannot query field \\"zz\\" on type \\"Query\\". '
                    'Did you mean \\"search\\"?"}]}', 200)
        gi._gqlSend = fake
        slots = gi._introspectViaSuggestions("http://t/graphql")
        self.assertIsNotNone(slots)
        self.assertTrue(any(s.fieldName == "search" for s in slots))
        self.assertTrue(all(s.strategy == "string" for s in slots))

    def test_introspect_via_suggestions_none_without_suggestions(self):
        def fake(endpoint, query, variables=None):
            return '{"errors":[{"message":"Syntax Error: unexpected token"}]}', 200
        gi._gqlSend = fake
        self.assertIsNone(gi._introspectViaSuggestions("http://t/graphql"))


if __name__ == "__main__":
    unittest.main()
