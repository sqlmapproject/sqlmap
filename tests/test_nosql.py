#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Offline, deterministic tests for the NoSQL injection engine. Mock oracles stand in for the
HTTP/back-end layer so detection and blind extraction can be exercised without a live target,
covering each dialect: MongoDB/CouchDB operator injection, Elasticsearch/Solr query_string,
Neo4j Cypher and ArangoDB AQL string break-out.
"""

import re
import time
import unittest

from _testutils import bootstrap
bootstrap()

import lib.techniques.nosql.inject as ni

# several setUps here write these conf keys without restoring them; snapshot/restore at the module
# boundary so they can't leak into later test modules (order-dependent flakiness)
_NOSQL_CONF_KEYS = ("parameters", "paramDict", "timeSec", "cookieDel")
_saved_conf = {}

def setUpModule():
    from lib.core.data import conf
    for k in _NOSQL_CONF_KEYS:
        _saved_conf[k] = conf.get(k)

def tearDownModule():
    from lib.core.data import conf
    for k, v in _saved_conf.items():
        conf[k] = v

SECRET = "S3cr3t_9"
MATCH = "<html><body>Welcome user; rows: alpha, bravo, charlie</body></html>"
NOMATCH = "<html><body>Invalid credentials; no rows</body></html>"


def _mongo(place, parameter, op, value, isArray=False):
    if op == "$ne":
        return MATCH
    if op == "$in":
        return NOMATCH
    if op == "$regex":
        try:
            return MATCH if re.match(value, SECRET) is not None else NOMATCH
        except re.error:
            return "<html><body>error: invalid regular expression</body></html>"
    return ""


def _es(place, parameter, value):
    if value == "*":
        return MATCH
    if "AND NOT" in value:                                      # Lucene (rand AND NOT rand) -> nothing
        return NOMATCH
    if value.startswith("(NOT ") and value.endswith(")"):       # Lucene (NOT rand) -> everything
        return MATCH
    if value == ni.NOSQL_SENTINEL:
        return NOMATCH
    if value.startswith("/") and value.endswith("/"):           # Lucene regexp is full-anchored
        try:
            return MATCH if re.match("^(?:%s)$" % value[1:-1], SECRET) is not None else NOMATCH
        except re.error:
            return "<html><body>error: parse_exception</body></html>"
    return NOMATCH


class TestNoSqlMongo(unittest.TestCase):
    def setUp(self):
        self._orig = ni._fetch
        ni._fetch = _mongo

    def tearDown(self):
        ni._fetch = self._orig

    def test_detect(self):
        self.assertTrue(ni._detectMongo("GET", "password"))

    def test_extract(self):
        template = ni._fetch("GET", "password", "$ne", ni.NOSQL_SENTINEL)
        value = ni._extract(template,
                            lambda v: ni._fetch("GET", "password", "$regex", v),
                            lambda n: "^.{%d,}$" % n,
                            lambda known, klass: "^" + re.escape(known) + klass)
        self.assertEqual(value, SECRET)

    def test_not_injectable(self):
        ni._fetch = lambda *args, **kwargs: MATCH
        self.assertIsNone(ni._detectMongo("GET", "password"))

    def test_resolve_vector_carries_false_model(self):
        # the LIVE vector must carry a calibrated false model so extraction is dual-model, not one-sided
        vector = ni._resolve("GET", "password", "password")
        self.assertIsNotNone(vector)
        self.assertEqual(vector.falseModel, NOMATCH)          # $in[sentinel] no-match page

    def test_dual_model_extraction_and_unrelated_page_inconclusive(self):
        template = MATCH
        falseModel = NOMATCH
        value = ni._extract(template,
                            lambda v: ni._fetch("GET", "password", "$regex", v),
                            lambda n: "^.{%d,}$" % n,
                            lambda known, klass: "^" + re.escape(known) + klass,
                            falseModel=falseModel)
        self.assertEqual(value, SECRET)
        # an unrelated usable page (neither true nor false model) must be inconclusive, not a false bit
        self.assertRaises(ni.InconclusiveError,
                          ni._contentBit, lambda v: "CCCCC unrelated captcha page", "A", MATCH, NOMATCH)


class TestNoSqlElasticsearch(unittest.TestCase):
    def setUp(self):
        self._orig = ni._fetchValue
        ni._fetchValue = _es

    def tearDown(self):
        ni._fetchValue = self._orig

    def test_detect(self):
        self.assertTrue(ni._detectES("GET", "q"))

    def test_extract(self):
        template = ni._fetchValue("GET", "q", "*")
        value = ni._extract(template,
                            lambda v: ni._fetchValue("GET", "q", v),
                            lambda n: "/.{%d,}/" % n,
                            lambda known, klass: "/%s%s.*/" % (ni._lucene(known), klass))
        self.assertEqual(value, SECRET)

    def test_not_injectable(self):
        ni._fetchValue = lambda *args, **kwargs: MATCH
        self.assertIsNone(ni._detectES("GET", "q"))


def _cypher(place, parameter, value):
    m = re.search(r"STARTS WITH '([^']*)'", value)              # Cypher-only prefix predicate on 'ab'
    if m:
        return MATCH if "ab".startswith(m.group(1)) else NOMATCH
    m = re.search(r"=~ '\^(.*)$", value)                        # the regex body after the =~ operator
    if m:
        try:
            return MATCH if re.match("^(?:%s)$" % m.group(1), SECRET) is not None else NOMATCH
        except re.error:
            return NOMATCH
    if "'1'='1" in value:
        return MATCH
    if "'1'='2" in value:
        return NOMATCH
    return NOMATCH


class TestNoSqlCypher(unittest.TestCase):
    def setUp(self):
        self._orig = ni._fetchValue
        ni._fetchValue = _cypher

    def tearDown(self):
        ni._fetchValue = self._orig

    def test_detect(self):
        self.assertTrue(ni._detectCypher("GET", "password"))

    def test_extract(self):
        template = ni._fetchValue("GET", "password", ni.NOSQL_SENTINEL + "' OR '1'='1")
        value = ni._extract(template,
                            lambda v: ni._fetchValue("GET", "password", v),
                            lambda n: "%s' OR u.password =~ '^.{%d,}" % (ni.NOSQL_SENTINEL, n),
                            lambda known, klass: "%s' OR u.password =~ '^%s%s.*" % (ni.NOSQL_SENTINEL, ni._javaEscape(known), klass))
        self.assertEqual(value, SECRET)


def _aql(place, parameter, value):
    m = re.search(r"=~ '(\^[^']*)'", value)                     # the regex body inside =~ '...'
    if m:
        try:                                                    # ArangoDB =~ is a partial (unanchored) match
            return MATCH if re.search(m.group(1), SECRET) is not None else NOMATCH
        except re.error:
            return NOMATCH
    if "'1'=='1" in value:
        return MATCH
    return NOMATCH


class TestNoSqlArango(unittest.TestCase):
    def setUp(self):
        self._orig = ni._fetchValue
        ni._fetchValue = _aql

    def tearDown(self):
        ni._fetchValue = self._orig

    def test_detect(self):
        self.assertTrue(ni._detectAQL("GET", "password"))

    def test_extract(self):
        template = ni._fetchValue("GET", "password", ni.NOSQL_SENTINEL + "' || '1'=='1")
        value = ni._extract(template,
                            lambda v: ni._fetchValue("GET", "password", v),
                            lambda n: "%s' || (u.password =~ '^.{%d,}') || '1'=='2" % (ni.NOSQL_SENTINEL, n),
                            lambda known, klass: "%s' || (u.password =~ '^%s%s') || '1'=='2" % (ni.NOSQL_SENTINEL, ni._javaEscape(known), klass))
        self.assertEqual(value, SECRET)


def _n1ql(place, parameter, value):
    m = re.search(r"REGEXP_CONTAINS\([^,]+, '([^']*)'\)", value)
    if m:
        try:                                                    # model the single-quoted string layer (collapse the doubled backslashes)
            return MATCH if re.search(m.group(1).replace("\\\\", "\\"), SECRET) is not None else NOMATCH
        except re.error:
            return NOMATCH
    if "=~" in value:                                           # N1QL has no =~ operator -> engine error
        return "error: syntax error near '=~'"
    if "'1'='1" in value:
        return MATCH
    return NOMATCH


class TestNoSqlN1QL(unittest.TestCase):
    """Couchbase N1QL shares the ' OR '1'='1 break-out with Neo4j; _resolve() must disambiguate by the
    regexp-match primitive (=~ fails, REGEXP_CONTAINS works) and still extract"""

    def setUp(self):
        self._f, self._fv = ni._fetch, ni._fetchValue
        ni._fetch = lambda *args, **kwargs: ""              # keep MongoDB operator detection out of the way
        ni._fetchValue = _n1ql
        ni.conf.parameters = {"GET": "name=luther&password=x"}

    def tearDown(self):
        ni._fetch, ni._fetchValue = self._f, self._fv

    def test_resolve_disambiguates_couchbase(self):
        vector = ni._resolve("GET", "password", "password")
        self.assertEqual(vector.dbms, "Couchbase")
        self.assertEqual(vector.bypass, "' OR '1'='1")

    def test_extract(self):
        vector = ni._resolve("GET", "password", "password")
        self.assertEqual(ni._extract(vector.template, vector.fetch, vector.lengthValue, vector.charValue, vector.truth), SECRET)


def _whereTruth(payload):
    # emulate the $where timing oracle: a payload "delays" (=> True) iff its embedded JS condition holds
    m = re.search(r"length>=(\d+)", payload)
    if m:
        return len(SECRET) >= int(m.group(1))
    m = re.search(r"/\^([^/]*)/\.test", payload)
    if m:
        return re.search("^" + m.group(1), SECRET) is not None
    return False


class TestNoSqlWhere(unittest.TestCase):
    """MongoDB $where time-based: validates the server-side-JS payload shapes and the time-based
    extraction loop (timing predicate emulated deterministically)"""

    def setUp(self):
        ni.conf.timeSec = 5

    def test_extract(self):
        key = "password"
        lengthValue = lambda n: ni._whereDelay("d.%s&&d.%s.length>=%d" % (key, key, n))
        charValue = lambda known, klass: ni._whereDelay("d.%s&&/^%s%s/.test(d.%s)" % (key, ni._javaEscape(known), klass, key))
        self.assertEqual(ni._extract(None, None, lengthValue, charValue, _whereTruth), SECRET)

    def test_where_delay_is_dos_bounded(self):
        # the per-document busy-loop must be capped to ONE document per query (shared-scope counter),
        # so a loose/unconditional condition on a large collection cannot block for docCount*timeSec.
        # The condition and delay budget must still be embedded verbatim (oracle unchanged).
        payload = ni._whereDelay("true")
        self.assertIn("__c", payload)                       # shared-scope counter present
        self.assertIn("__c<1", payload)                     # loop gated on the one-shot cap
        self.assertIn("(true)", payload)                    # original condition preserved
        self.assertIn(str(int(ni.conf.timeSec * 1000)), payload)   # delay budget preserved


def _jswhere(place, parameter, value):
    # emulate a content-bearing MongoDB $where (server-side JavaScript) endpoint
    if " OR " in value or " =~ " in value:                      # not valid JS -> consistent (non-diverging) error
        return "<error>"
    m = re.search(r"/(.)/\.test\('x'\)", value)                 # JS regexp-test disambiguation probe
    if m:
        return MATCH if re.search(m.group(1), "x") is not None else NOMATCH
    m = re.search(r"/\^([^/]*)/\.test\(this\.password\)", value)        # value extraction
    if m:
        try:
            return MATCH if re.search("^" + m.group(1), SECRET) is not None else NOMATCH
        except re.error:
            return NOMATCH
    m = re.search(r"length>=(\d+)", value)                      # length search
    if m:
        return MATCH if len(SECRET) >= int(m.group(1)) else NOMATCH
    if "'1'=='1" in value or "this.password)" in value:         # boolean detection / bound always-true template
        return MATCH
    return NOMATCH


class TestNoSqlWhereContent(unittest.TestCase):
    """Content-bearing MongoDB $where shares the ' || '1'=='1 break-out with ArangoDB; _resolve() must
    disambiguate (AQL '=~' fails, a JS /re/.test() holds) and extract via the content oracle"""

    def setUp(self):
        self._f, self._fv = ni._fetch, ni._fetchValue
        ni._fetch = lambda *args, **kwargs: ""
        ni._fetchValue = _jswhere
        ni.conf.parameters = {"GET": "username=luther&password=x"}

    def tearDown(self):
        ni._fetch, ni._fetchValue = self._f, self._fv

    def test_resolve_where_content(self):
        vector = ni._resolve("GET", "password", "password")
        self.assertEqual(vector.dbms, "MongoDB ($where)")
        self.assertEqual(vector.bypass, "' || '1'=='1")

    def test_extract(self):
        vector = ni._resolve("GET", "password", "password")
        self.assertEqual(ni._extract(vector.template, vector.fetch, vector.lengthValue, vector.charValue, vector.truth), SECRET)


class TestNoSqlWhereDump(unittest.TestCase):
    """$where whole-document dump: Object.keys(this) enumeration drives name + value recovery for every
    field (per-field char recovery itself is covered by TestNoSqlWhere)"""

    DOC = [("id", "1"), ("username", "luther"), ("password", "s3cr3t"), ("role", "admin")]

    def setUp(self):
        self._orig = ni._whereField
        names = [name for name, _ in self.DOC]
        values = dict(self.DOC)

        def fake(place, parameter, bound, expr, threshold, strict=False):
            m = re.search(r"Object\.keys\(d\)\[(\d+)\]", expr)
            if m:
                index = int(m.group(1))
                return names[index] if index < len(names) else None
            m = re.search(r"d\['([^']*)'\]", expr)
            if m:
                return values.get(m.group(1))
            return None

        ni._whereField = fake

    def tearDown(self):
        ni._whereField = self._orig

    def test_dump(self):
        columns, rows, bound, complete = ni._whereDump("GET", "password", "", 0)
        self.assertEqual(columns, ["id", "username", "password", "role"])
        self.assertEqual(rows, [["1", "luther", "s3cr3t", "admin"]])

    def test_empty_document(self):
        ni._whereField = lambda *args, **kwargs: None
        self.assertIsNone(ni._whereDump("GET", "password", "", 0))


class TestNoSqlRecordBinding(unittest.TestCase):
    """A whole-document dump must be flagged bound only when a unique-record constraint pins it; an
    unbound dump (no distinguishing sibling) is representative, not one coherent document."""

    def test_vector_bound_defaults_true(self):
        self.assertTrue(ni.Vector("X", None, None, None).bound)
        self.assertFalse(ni.Vector("X", None, None, None, bound=False).bound)

    def test_where_vector_unbound_without_sibling(self):
        # single injected param, no sibling -> _constraint is "" -> $where dump is representative
        ni.conf.parameters = {ni.PLACE.GET: "name=luther"}
        ni.conf.paramDict = {ni.PLACE.GET: {"name": "luther"}}
        self.assertEqual(ni._constraint(ni.PLACE.GET, "name", "==", "&&", prefix="d."), "")

    def test_where_vector_bound_with_sibling(self):
        # a distinguishing sibling pins the record -> bound constraint is non-empty
        ni.conf.parameters = {ni.PLACE.GET: "id=7&name=luther"}
        ni.conf.paramDict = {ni.PLACE.GET: {"name": "luther"}}
        bound = ni._constraint(ni.PLACE.GET, "name", "==", "&&", prefix="d.")
        self.assertIn("d.id=='7'", bound)
        self.assertTrue(bool(bound))


class TestNoSqlTriStateOracle(unittest.TestCase):
    """A failed/blocked NoSQL response is UNKNOWN, retried, then aborts - never a silent false bit."""

    def test_content_bit_retries_transient_then_recovers(self):
        state = {"n": 0}
        def fetch(value):
            state["n"] += 1
            return None if state["n"] == 1 else "TEMPLATE"      # first send fails, retry recovers
        self.assertTrue(ni._contentBit(fetch, "A", "TEMPLATE"))

    def test_content_bit_persistent_failure_raises(self):
        self.assertRaises(ni.InconclusiveError, ni._contentBit, lambda v: None, "A", "TEMPLATE")

    def test_content_bit_error_page_is_not_true(self):
        # an error page is unusable -> retried -> InconclusiveError, never classified true/false
        self.assertRaises(ni.InconclusiveError, ni._contentBit,
                          lambda v: "MongoServerError: unknown operator: $foo", "A", "TEMPLATE")

    def test_extract_aborts_value_on_inconclusive(self):
        # a persistently failing oracle aborts the value (None), never fabricates a length/char
        self.assertIsNone(ni._extract("TMPL", lambda v: None,
                                      lambda n: "len>=%d" % n, lambda k, c: "char", truthFn=None))

    def test_timed_bit_rejects_blocked_slow_response(self):
        # a slow response that is BLOCKED (WAF/5xx) must not count as a true timing bit
        self._fv = ni._fetchValue
        try:
            ni._lastCode = 429
            ni._fetchValue = lambda *a, **k: (time.sleep(0.01) or "")     # slow but blocked (_isError via 429)
            self.assertRaises(ni.InconclusiveError, ni._timedBit, "GET", "q", "payload", 0.0)
        finally:
            ni._fetchValue = self._fv
            ni._lastCode = None

    def test_content_bit_unrelated_page_is_inconclusive_not_false(self):
        # P0-2: a usable page matching NEITHER the true nor the false model is UNKNOWN, not false -
        # with both models supplied it must abort (InconclusiveError), never silently return False
        self.assertRaises(ni.InconclusiveError,
                          ni._contentBit, lambda v: "CCCCC unrelated soft-WAF page", "A", "AAAAA", "BBBBB")

    def test_content_bit_both_models_classify_true_and_false(self):
        self.assertTrue(ni._contentBit(lambda v: "AAAAA", "A", "AAAAA", "BBBBB"))
        self.assertFalse(ni._contentBit(lambda v: "BBBBB", "A", "AAAAA", "BBBBB"))

    def test_detect_where_rejects_blocked_slow_responses(self):
        # P0-2: delayed BLOCKED responses (zero usable) must NOT establish a $where timing threshold
        self._fv = ni._fetchValue
        try:
            ni.conf.timeSec = 5
            ni.conf.parameters = {ni.PLACE.GET: "q=1"}
            ni.conf.paramDict = {ni.PLACE.GET: {"q": "1"}}
            ni._lastCode = 503
            ni._fetchValue = lambda *a, **k: (time.sleep(0.02) or None)   # slow AND blocked/failed
            self.assertIsNone(ni._detectWhere("GET", "q"))
        finally:
            ni._fetchValue = self._fv
            ni._lastCode = None


class TestNoSqlEnumDump(unittest.TestCase):
    """Content-based whole-document dump (e.g. Neo4j keys(u)): enumerate field names then values"""

    DOC = [("id", "1"), ("username", "luther"), ("password", "s3cr3t"), ("role", "admin")]

    def setUp(self):
        self._ef, self._fv = ni._enumField, ni._fetchValue
        # true (any-match '.*') vs false (never-match sentinel) template must be SEPARABLE so _enumDump
        # can calibrate both models; a constant page would (correctly) disable the dump
        ni._fetchValue = lambda place, parameter, value: (NOMATCH if ni.NOSQL_SENTINEL in value else MATCH)
        names = [name for name, _ in self.DOC]
        values = dict(self.DOC)

        def fake(place, parameter, template, payloadFor, strict=False, falseModel=None):
            probe = payloadFor("X")                                     # render to inspect the target expression
            m = re.search(r"\(u\)\[(\d+)\]", probe)                     # keys/ATTRIBUTES/OBJECT_NAMES(u)[i]
            if m:
                index = int(m.group(1))
                return names[index] if index < len(names) else None
            m = re.search(r"u\['([^']*)'\]", probe)                     # toString/TO_STRING/TOSTRING(u['name'])
            if m:
                return values.get(m.group(1))
            return None

        ni._enumField = fake

    def tearDown(self):
        ni._enumField, ni._fetchValue = self._ef, self._fv

    def _check(self, keysExpr, valueExpr):
        makePayload = lambda expr, rb: "X' OR %s =~ '^%s.*" % (expr, rb)
        columns, rows, bound, complete = ni._enumDump("GET", "password", makePayload, keysExpr, valueExpr)
        self.assertEqual(columns, ["id", "username", "password", "role"])
        self.assertEqual(rows, [["1", "luther", "s3cr3t", "admin"]])
        # a constraint-only enum dump is NOT proven single-record -> the dump reports itself unbound
        self.assertFalse(bound)

    def test_cypher(self):
        self._check(lambda i: "keys(u)[%d]" % i, lambda n: "toString(u[%s])" % ni._propLiteral(n))

    def test_aql(self):
        self._check(lambda i: "ATTRIBUTES(u)[%d]" % i, lambda n: "TO_STRING(u[%s])" % ni._propLiteral(n))

    def test_n1ql(self):
        self._check(lambda i: "OBJECT_NAMES(u)[%d]" % i, lambda n: "TOSTRING(u[%s])" % ni._propLiteral(n))


class TestNoSqlBypass(unittest.TestCase):
    """Confirmed injection must surface the always-true (authentication/filter bypass) payload"""

    def setUp(self):
        self._f = ni._fetch
        ni._fetch = _mongo

    def tearDown(self):
        ni._fetch = self._f

    def test_mongo_bypass(self):
        vector = ni._resolve("GET", "password", "password")
        self.assertEqual(vector.dbms, "MongoDB")
        self.assertEqual(vector.bypass, '{"$ne": null}')


class TestNoSqlInband(unittest.TestCase):
    """In-band exposure gate: _inband() returns the always-true response only when it carries
    materially more reflected content than the original request"""

    def setUp(self):
        self._fv = ni._fetchValue
        ni.conf.parameters = {"GET": "id=1"}

    def tearDown(self):
        ni._fetchValue = self._fv

    def test_exposure_detected(self):
        ni._fetchValue = lambda place, parameter, value: "<table><tr><td>1</td><td>luther</td></tr></table>"   # original (one row)
        template = "<table><tr><td>1</td><td>luther</td></tr><tr><td>2</td><td>fluffy</td></tr><tr><td>3</td><td>wu</td></tr></table>"
        self.assertEqual(ni._inband("GET", "id", template), template)

    def test_no_exposure_when_not_larger(self):
        ni._fetchValue = lambda place, parameter, value: "X" * 200                       # original (large)
        self.assertIsNone(ni._inband("GET", "id", "<b>Welcome</b>"))                      # always-true smaller -> no dump


class TestNoSqlRecords(unittest.TestCase):
    """Reflected responses are parsed into (columns, rows) for a regular table dump"""

    def test_html_table_without_header(self):
        page = ("<html><body><b>Results:</b><table border=\"1\">"
                "<tr><td>1</td><td>luther</td><td>blisset</td></tr>"
                "<tr><td>2</td><td>fluffy</td><td>bunny</td></tr></table></body></html>")
        columns, rows = ni._records(page)
        self.assertEqual(columns, ["column_1", "column_2", "column_3"])
        self.assertEqual(rows, [["1", "luther", "blisset"], ["2", "fluffy", "bunny"]])

    def test_html_table_with_header(self):
        page = "<table><tr><th>id</th><th>user</th></tr><tr><td>1</td><td>luther</td></tr></table>"
        columns, rows = ni._records(page)
        self.assertEqual(columns, ["id", "user"])
        self.assertEqual(rows, [["1", "luther"]])

    def test_json_array_of_objects(self):
        page = '{"results": [{"id": 1, "username": "luther", "password": null}, {"id": 2, "username": "fluffy"}]}'
        columns, rows = ni._records(page)
        self.assertEqual(columns, ["id", "username", "password"])
        self.assertEqual(rows, [["1", "luther", "NULL"], ["2", "fluffy", ""]])

    def test_unstructured_returns_none(self):
        self.assertIsNone(ni._records("<html><body>just some prose, no records here</body></html>"))


def _numeric(place, parameter, value):
    # numeric-context Neo4j: 'OR 1=1' is always-true (rows), 'AND 1=2' is false, PLUS the Cypher-only
    # STARTS WITH prefix predicate the detector now requires to attribute Neo4j (vs plain SQL)
    m = re.search(r"STARTS WITH '([^']*)'", value)
    if m:
        return MATCH if "ab".startswith(m.group(1)) else NOMATCH
    if "OR 1=1" in value:
        return MATCH
    if "AND 1=2" in value:
        return NOMATCH
    return MATCH if value == "1" else NOMATCH


class TestNoSqlNumeric(unittest.TestCase):
    """Numeric-context (unquoted) break-out, e.g. 'WHERE id = <input>': detected via OR/AND, with the
    always-true response carried as the in-band dump template"""

    def setUp(self):
        self._f, self._fv = ni._fetch, ni._fetchValue
        ni._fetch = lambda *args, **kwargs: ""
        ni._fetchValue = _numeric
        ni.conf.parameters = {"GET": "id=1"}
        ni.conf.paramDict = {"GET": {"id": "1"}}

    def tearDown(self):
        ni._fetch, ni._fetchValue = self._f, self._fv

    def test_resolve_numeric(self):
        vector = ni._resolve("GET", "id", "id")
        self.assertEqual(vector.dbms, "Neo4j")
        self.assertEqual(vector.bypass, "1 OR 1=1")
        self.assertIsNone(vector.lengthValue)                   # numeric field -> in-band only, no blind extraction

    def test_skips_non_numeric(self):
        ni.conf.parameters = {"GET": "name=luther"}
        self.assertIsNone(ni._detectNumeric("GET", "name"))     # only applies to a numeric field value


def _numericN1ql(place, parameter, value):
    # numeric-context Couchbase: OR/AND boolean plus the N1QL-only REGEXP_CONTAINS discriminator
    m = re.search(r"REGEXP_CONTAINS\('ab', '([^']*)'\)", value)
    if m:
        return MATCH if re.search(m.group(1), "ab") is not None else NOMATCH
    if "OR 1=1" in value:
        return MATCH
    if "AND 1=2" in value:
        return NOMATCH
    return MATCH if value == "1" else NOMATCH


class TestNoSqlNumericN1QL(unittest.TestCase):
    """A numeric Couchbase point is disambiguated from Neo4j by the N1QL-only REGEXP_CONTAINS probe"""

    def setUp(self):
        self._f, self._fv = ni._fetch, ni._fetchValue
        ni._fetch = lambda *args, **kwargs: ""
        ni._fetchValue = _numericN1ql
        ni.conf.parameters = {"GET": "id=1"}

    def tearDown(self):
        ni._fetch, ni._fetchValue = self._f, self._fv

    def test_resolve_numeric_couchbase(self):
        dbms, _, bypass = ni._detectNumeric("GET", "id")
        self.assertEqual(dbms, "Couchbase")
        self.assertEqual(bypass, "1 OR 1=1")


def _numericAql(place, parameter, value):
    # numeric-context ArangoDB: the ||/&& family diverges, PLUS the AQL-only two-arg LIKE(text, search)
    # function the detector now requires to attribute ArangoDB (SQL's LIKE is an operator, not a function)
    m = re.search(r"LIKE\('ab', '([^%]*)%'\)", value)
    if m:
        return MATCH if "ab".startswith(m.group(1)) else NOMATCH
    return MATCH if "|| 1==1" in value else NOMATCH


class TestNoSqlNumericAQL(unittest.TestCase):
    """A numeric ArangoDB point is detected via the ||/&& family once OR/AND yields no divergence"""

    def setUp(self):
        self._f, self._fv = ni._fetch, ni._fetchValue
        ni._fetch = lambda *args, **kwargs: ""
        ni._fetchValue = _numericAql
        ni.conf.parameters = {"GET": "id=1"}

    def tearDown(self):
        ni._fetch, ni._fetchValue = self._f, self._fv

    def test_resolve_numeric_arango(self):
        dbms, _, bypass = ni._detectNumeric("GET", "id")
        self.assertEqual(dbms, "ArangoDB")
        self.assertEqual(bypass, "1 || 1==1")


def _partiql(place, parameter, value):
    # DynamoDB PartiQL string-context oracle: 'field >= prefix' matches the bound record iff
    # SECRET >= prefix (ordered comparison, the basis of the comparison-bisection extraction);
    # 'begins_with(field, prefix)' matches iff SECRET starts with prefix
    m = re.search(r">= '(.*)$", value)
    if m:
        return MATCH if SECRET >= m.group(1).replace("''", "'") else NOMATCH
    m = re.search(r"begins_with\([^,]+, '(.*?)'\) OR '1'='2", value)
    if m:
        return MATCH if SECRET.startswith(m.group(1)) else NOMATCH
    return NOMATCH


class TestNoSqlPartiQL(unittest.TestCase):
    """DynamoDB PartiQL: no regexp engine, so a value is recovered by ordered string comparison
    (field >= 'prefix') bisected over the printable-ASCII range"""

    def setUp(self):
        self._fv = ni._fetchValue
        ni._fetchValue = _partiql
        ni.conf.parameters = {"GET": "username=luther&password=x"}
        ni.conf.paramDict = {"GET": {"password": "x"}}

    def tearDown(self):
        ni._fetchValue = self._fv

    def test_extract(self):
        value = ni._partiqlValue("GET", "password", "", "password")
        self.assertEqual(value, SECRET)

    def test_dump_binds_sibling(self):
        columns, rows, bound, complete = ni._partiqlDump("GET", "password", "password")
        self.assertEqual(columns, ["password"])
        self.assertEqual(rows, [[SECRET]])

    def test_dump_without_sibling_returns_none(self):
        ni.conf.parameters = {"GET": "password=x"}                  # no sibling to pin a single record
        ni.conf.paramDict = {"GET": {"password": "x"}}
        self.assertIsNone(ni._partiqlDump("GET", "password", "password"))


def _numericDdb(place, parameter, value):
    # numeric-context DynamoDB: OR/AND boolean plus the PartiQL-only begins_with discriminator
    m = re.search(r"begins_with\('ab', '([^']*)'\)", value)
    if m:
        return MATCH if "ab".startswith(m.group(1)) else NOMATCH
    if "OR 1=1" in value:
        return MATCH
    if "AND 1=2" in value:
        return NOMATCH
    return MATCH if value == "1" else NOMATCH


class TestNoSqlNumericDynamoDB(unittest.TestCase):
    """A numeric DynamoDB point is disambiguated from Neo4j/Couchbase by the PartiQL-only begins_with probe"""

    def setUp(self):
        self._f, self._fv = ni._fetch, ni._fetchValue
        ni._fetch = lambda *args, **kwargs: ""
        ni._fetchValue = _numericDdb
        ni.conf.parameters = {"GET": "id=1"}

    def tearDown(self):
        ni._fetch, ni._fetchValue = self._f, self._fv

    def test_resolve_numeric_dynamodb(self):
        dbms, _, bypass = ni._detectNumeric("GET", "id")
        self.assertEqual(dbms, "DynamoDB")
        self.assertEqual(bypass, "1 OR 1=1")


class TestNoSqlCookiePlace(unittest.TestCase):
    """Cookie place: parameters split/join on ';' (not '&') and the segment routes to the Cookie header"""

    def setUp(self):
        ni.conf.cookieDel = None
        ni.conf.parameters = {ni.PLACE.COOKIE: "session=abc; username=luther; password=x"}
        ni.conf.paramDict = {ni.PLACE.COOKIE: {"password": "x"}}

    def test_delimiter(self):
        self.assertEqual(ni._delim(ni.PLACE.COOKIE), ";")
        self.assertEqual(ni._delim(ni.PLACE.GET), "&")

    def test_original_value(self):
        self.assertEqual(ni._originalValue(ni.PLACE.COOKIE, "username").strip(), "luther")

    def test_replace_segment(self):
        out = ni._replaceSegment(ni.PLACE.COOKIE, "password", "password[$ne]=zzz")
        self.assertIn("session=abc", out)
        self.assertIn("username=luther", out)
        self.assertIn("password[$ne]=zzz", out)
        self.assertEqual(out.count(";"), 2)                     # 3 segments -> 2 delimiters (no '&')
        self.assertNotIn("&", out)

    def test_constraint_binds_siblings(self):
        constraint = ni._constraint(ni.PLACE.COOKIE, "password")
        self.assertIn("u.session='abc'", constraint)
        self.assertIn("u.username='luther'", constraint)

    def test_constraint_escapes_literal_and_skips_non_identifiers(self):
        # a quote/backslash in a sibling value must be escaped (not break out of the string literal),
        # and a non-identifier field name must be skipped rather than alter the predicate structure
        ni.conf.parameters = {ni.PLACE.GET: "q=x&name=o'brien&weird.field=v&password=p"}
        ni.conf.paramDict = {ni.PLACE.GET: {"q": "x"}}
        constraint = ni._constraint(ni.PLACE.GET, "q")
        self.assertIn("u.name='o\\'brien'", constraint)          # single quote escaped
        self.assertNotIn("weird.field", constraint)              # dotted (non-identifier) name skipped
        self.assertIn("u.password='p'", constraint)


class TestNoSqlJsonRawReplace(unittest.TestCase):
    """Parse-failure JSON fallback: mutate ONLY the target key's value span in a JSON-like body, never
    reconstruct it with a form serializer (which would produce unrelated 'name=value&...' content)."""

    def test_double_quoted_value_replaced_in_place(self):
        body = '{"name": "luther", "role": "user"}'
        out = ni._jsonRawReplace(body, "name", {"$ne": None})
        self.assertEqual(out, '{"name": {"$ne": null}, "role": "user"}')
        self.assertIn('"role": "user"', out)                    # sibling preserved verbatim

    def test_json_like_single_quotes_not_form_serialized(self):
        # single-quoted -> json.loads() fails in the real flow; the span replace still works and the
        # body stays JSON-shaped (no '&', no 'name=value' reconstruction)
        body = "{'name': 'luther', 'active': true}"
        out = ni._jsonRawReplace(body, "name", "payload")
        self.assertIsNotNone(out)
        self.assertIn("'active': true", out)                    # sibling + JS literal preserved
        self.assertNotIn("&", out)
        self.assertTrue(out.strip().startswith("{"))            # still a JSON object, not form content

    def test_bareword_and_numeric_values(self):
        self.assertEqual(ni._jsonRawReplace('{"age": 42}', "age", 7), '{"age": 7}')
        self.assertEqual(ni._jsonRawReplace('{"ok": true}', "ok", "x"), '{"ok": "x"}')

    def test_missing_key_returns_none(self):
        # key absent -> None so the caller SKIPS the probe rather than corrupt the body
        self.assertIsNone(ni._jsonRawReplace('{"other": "v"}', "name", "x"))

    def test_key_like_text_inside_string_is_not_matched(self):
        # the reviewer's reproduction: 'name: old' inside the "note" STRING must NOT be mutated - only
        # the real "name" property is replaced
        body = '{"note":"name: old", "name":"real"}'
        out = ni._jsonRawReplace(body, "name", {"$ne": None})
        self.assertEqual(out, '{"note":"name: old", "name":{"$ne": null}}')
        self.assertIn('"note":"name: old"', out)                 # decoy string untouched

    def test_key_like_text_inside_single_quoted_string(self):
        body = "{'note':'name: trap', 'name':'real'}"
        out = ni._jsonRawReplace(body, "name", "P")
        self.assertIn("'note':'name: trap'", out)                # decoy untouched
        self.assertTrue(out.endswith('"P"}'))                    # real value replaced

    def test_key_like_text_inside_comment_is_not_matched(self):
        body = '{/* name: not here */ "name": "real"}'
        out = ni._jsonRawReplace(body, "name", "P")
        self.assertIn("/* name: not here */", out)               # comment untouched
        self.assertIn('"name": "P"', out)

    def test_object_and_array_values_replaced_whole(self):
        # an object/array as the original value must be replaced in full, not partially
        self.assertEqual(ni._jsonRawReplace('{"f": {"a": 1, "b": [2, 3]}, "g": 9}', "f", "X"),
                         '{"f": "X", "g": 9}')
        self.assertEqual(ni._jsonRawReplace('{"f": [1, {"x": "}"}, 2], "g": 9}', "f", 0),
                         '{"f": 0, "g": 9}')

    def test_nested_property_located_at_depth(self):
        # a nested property (not top-level) is located and replaced without disturbing structure
        out = ni._jsonRawReplace('{"outer": {"name": "luther"}}', "name", {"$ne": None})
        self.assertEqual(out, '{"outer": {"name": {"$ne": null}}}')

    def test_brace_inside_string_value_does_not_close_object(self):
        # a '}' inside a string value must not end the value token early
        out = ni._jsonRawReplace('{"a": "va}lue", "name": "x"}', "name", "P")
        self.assertIn('"a": "va}lue"', out)
        self.assertIn('"name": "P"', out)

    def test_brace_inside_comment_in_value_does_not_close_object(self):
        # reviewer P0-2 reproduction: a '}' inside a COMMENT within an object value closed it early
        out = ni._jsonRawReplace('{"f": {/* } */ "a": 1}, "g": 9}', "f", "X")
        self.assertEqual(out, '{"f": "X", "g": 9}')

    def test_key_like_text_inside_regex_literal_is_not_matched(self):
        # reviewer P0-2 reproduction: 'name:' inside a /regex/ literal must not be taken as the property
        out = ni._jsonRawReplace('{pattern: /name: trap/, name: "real"}', "name", "P")
        self.assertEqual(out, '{pattern: /name: trap/, name: "P"}')

    def test_regex_with_slash_in_char_class(self):
        # a regex value containing '/' inside a [..] class and a '}' must be skipped whole
        out = ni._jsonRawReplace('{"re": /[a/}]x/, "name": "y"}', "name", "P")
        self.assertIn("/[a/}]x/", out)
        self.assertIn('"name": "P"', out)

    def test_backtick_string_is_not_a_key(self):
        # a backtick template value containing 'name:' must not be mistaken for the property
        out = ni._jsonRawReplace('{"tpl": `name: ${x}`, "name": "z"}', "name", "P")
        self.assertIn("`name: ${x}`", out)
        self.assertIn('"name": "P"', out)

    def test_regex_value_flags_consumed(self):
        # P0-6: a regex value's span must include trailing flags, else a dangling 'i' is left behind
        self.assertEqual(ni._jsonRawReplace('{re: /abc/i, name: "x"}', "re", "P"),
                         '{re: "P", name: "x"}')

    def test_duplicate_key_at_different_depths_is_skipped(self):
        # P0-6: with only the leaf key name, an ambiguous body (same key at 2 places) must be SKIPPED,
        # never guessed - the payload could otherwise reach the wrong field
        self.assertIsNone(ni._jsonRawReplace('{"outer":{"name":"first"},"name":"second"}', "name", "P"))

    def test_single_occurrence_still_mutates(self):
        self.assertEqual(ni._jsonRawReplace('{"a":1,"name":"real"}', "name", "P"), '{"a":1,"name":"P"}')


class TestNoSqlErrorRegex(unittest.TestCase):
    """The heuristic regex must match real back-end error structures, not bare product names (so an
    article merely mentioning MongoDB/Elasticsearch/Cassandra is never flagged as injectable)"""

    from lib.core.settings import NOSQL_ERROR_REGEX

    POSITIVES = (
        'MongoServerError: unknown operator: $foo',
        '{"ok":0,"errmsg":"unknown top level operator: $where","code":2,"codeName":"BadValue"}',
        'MongoServerError: Regular expression is invalid: missing )',
        'CastError: Cast to ObjectId failed',
        '{"error":"query_parse_error","reason":"Invalid operator: $foo"}',
        '{"error":{"root_cause":[{"type":"query_shard_exception","reason":"Failed to parse query [luther\']"}]},"status":400}',
        '{"type":"x_content_parse_exception","reason":"[1:18] [bool] failed to parse"}',
        '{"error":{"msg":"org.apache.solr.search.SyntaxError: Cannot parse \'username:\'","code":400}}',
        "Neo.ClientError.Statement.SyntaxError: Invalid input",
        'Neo4j error: Failed to parse string literal. The query must contain an even number of non-escaped quotes. (line 1, column 30) "MATCH (u:User) WHERE u.id = 1"',
        "<b>Neo4j error:</b> Invalid input ''x'': expected an expression, 'FOREACH', 'MATCH', 'MERGE', 'UNWIND', 'WITH' or <EOF>",
        '{"error":true,"errorNum":1501,"errorMessage":"AQL: syntax error, unexpected quoted string"}',
        "ResponseError: line 1:38 no viable alternative at input",
        "SyntaxException: line 1:42 mismatched input ''' expecting EOF",
        '{"error":{"root_cause":[{"type":"number_format_exception","reason":"For input string"}]},"status":400}',
        'ReplyError: WRONGTYPE Operation against a key holding the wrong kind of value',
        'ReplyError: ERR Error compiling script (new function): user_script:1: unexpected symbol',
        'CLIENT_ERROR bad command line format',
        'error parsing query: found WHERE, expected identifier at line 1',
        'org.apache.phoenix.exception.PhoenixIOException: failed',
    )

    NEGATIVES = (
        "This article explains how MongoDB, CouchDB and Elasticsearch handle queries.",
        "Cassandra and Redis are popular NoSQL databases; Neo4j is a graph database.",
        "We migrated from Solr to OpenSearch last year. ArangoDB is multi-model.",
        "<html><body><b>Results:</b><table><tr><td>1</td><td>luther</td></tr></table></body></html>",
        "<html><body><b>Invalid credentials</b></body></html>",
    )

    def test_matches_real_errors(self):
        for sample in self.POSITIVES:
            self.assertIsNotNone(re.search(self.NOSQL_ERROR_REGEX, sample), "should match: %s" % sample)

    def test_ignores_benign_text(self):
        for sample in self.NEGATIVES:
            self.assertIsNone(re.search(self.NOSQL_ERROR_REGEX, sample), "should NOT match: %s" % sample)


class TestNoSqlNoneSafety(unittest.TestCase):
    """A blocked/failed request makes _send() return None; the fingerprint/error helpers must not
    crash calling .lower() on it."""

    def setUp(self):
        self._f, self._fv = ni._fetch, ni._fetchValue
        ni._fetch = lambda *a, **k: None
        ni._fetchValue = lambda *a, **k: None
        ni.conf.parameters = {"GET": "q=x"}
        ni.conf.paramDict = {"GET": {"q": "x"}}

    def tearDown(self):
        ni._fetch, ni._fetchValue = self._f, self._fv

    def test_nosql_failed_fingerprint_does_not_crash(self):
        # None responses must not raise (was: 'NoneType' has no attribute 'lower')
        self.assertIn(ni._fingerprintMongo("GET", "q"), ("CouchDB", "MongoDB", "MongoDB/CouchDB-compatible operator back-end"))
        self.assertIn(ni._fingerprintLucene("GET", "q"), ("Solr", "OpenSearch", "Lucene query_string-compatible back-end"))
        self.assertIsNone(ni._detectError("GET", "q"))


if __name__ == "__main__":
    unittest.main()

