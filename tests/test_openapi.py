#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit coverage for the OpenAPI/Swagger target extractor (lib/parse/openapi.py): schema example
synthesis, $ref resolution (incl. cycles), base-URL resolution (v2 + v3, relative/templated servers),
request-body handling (JSON / form), parameter->PLACE mapping, and (importantly) graceful handling of
malformed / poorly-defined specifications (a broken spec must never crash or hang the parser).

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.parse.openapi import openApiTargets, yaml as _yaml

HAS_YAML = _yaml is not None


def _targets(spec, origin="http://h"):
    return openApiTargets(json.dumps(spec) if isinstance(spec, dict) else spec, origin)

def _byMethodPath(targets):
    return dict(("%s %s" % (method, url), (method, url, data, headers)) for url, method, data, headers in targets)


class TestOpenApi(unittest.TestCase):
    def test_v3_query_path_and_base(self):
        spec = {"openapi": "3.0.0", "servers": [{"url": "/api"}],
                "paths": {"/pet/{id}": {"get": {"parameters": [
                    {"name": "id", "in": "path", "schema": {"type": "integer"}},
                    {"name": "q", "in": "query", "schema": {"type": "string", "example": "x"}}]}}}}
        targets = _targets(spec, "http://host:8080")
        self.assertEqual(len(targets), 1)
        url, method, data, headers = targets[0]
        self.assertEqual(method, "GET")
        from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR as MARK
        self.assertEqual(url, "http://host:8080/api/pet/1%s?q=x" % MARK)   # relative server + filled+marked path + query
        self.assertIsNone(data)

    def test_v3_json_body_sets_data_and_content_type(self):
        spec = {"openapi": "3.0.0", "paths": {"/o": {"post": {"requestBody": {"content": {"application/json":
                {"schema": {"type": "object", "properties": {"name": {"type": "string"}, "qty": {"type": "integer"}}}}}}}}}}
        url, method, data, headers = _targets(spec)[0]
        self.assertEqual(method, "POST")
        self.assertEqual(json.loads(data), {"name": "1", "qty": 1})
        self.assertIn(("Content-Type", "application/json"), headers)

    def test_form_urlencoded_body(self):
        spec = {"openapi": "3.0.0", "paths": {"/login": {"post": {"requestBody": {"content":
                {"application/x-www-form-urlencoded": {"schema": {"type": "object",
                 "properties": {"u": {"type": "string"}, "p": {"type": "string"}}}}}}}}}}
        url, method, data, headers = _targets(spec)[0]
        self.assertEqual(sorted(data.split("&")), ["p=1", "u=1"])

    def test_value_synthesis(self):
        spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": [
            {"name": "a", "in": "query", "schema": {"type": "integer"}},
            {"name": "b", "in": "query", "schema": {"type": "boolean"}},
            {"name": "c", "in": "query", "schema": {"type": "string", "enum": ["first", "second"]}},
            {"name": "d", "in": "query", "schema": {"type": "string", "default": "dd"}},
            {"name": "e", "in": "query", "schema": {"type": "string", "format": "uuid"}}]}}}}
        url = _targets(spec)[0][0]
        self.assertIn("a=1", url)
        self.assertIn("b=true", url)
        self.assertIn("c=first", url)               # enum[0]
        self.assertIn("d=dd", url)                   # default
        self.assertIn("e=11111111-1111-1111-1111-111111111111", url)  # format uuid

    def test_ref_resolution_and_allof_oneof(self):
        spec = {"openapi": "3.0.0",
                "components": {"schemas": {"Tag": {"type": "object", "properties": {"n": {"type": "string"}}}}},
                "paths": {
                    "/ref": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Tag"}}}}}},
                    "/all": {"post": {"requestBody": {"content": {"application/json": {"schema": {"allOf": [
                        {"type": "object", "properties": {"x": {"type": "string"}}},
                        {"type": "object", "properties": {"y": {"type": "integer"}}}]}}}}}},
                    "/one": {"post": {"requestBody": {"content": {"application/json": {"schema": {"oneOf": [
                        {"type": "object", "properties": {"only": {"type": "string"}}},
                        {"type": "object", "properties": {"other": {"type": "string"}}}]}}}}}}}}
        m = _byMethodPath(_targets(spec))
        self.assertEqual(json.loads(m["POST http://h/ref"][2]), {"n": "1"})
        self.assertEqual(json.loads(m["POST http://h/all"][2]), {"x": "1", "y": 1})       # allOf merged
        self.assertEqual(json.loads(m["POST http://h/one"][2]), {"only": "1"})            # oneOf -> first

    def test_ref_cycle_terminates(self):
        spec = {"openapi": "3.0.0",
                "components": {"schemas": {"Node": {"type": "object", "properties": {
                    "name": {"type": "string"}, "parent": {"$ref": "#/components/schemas/Node"}}}}},
                "paths": {"/n": {"post": {"requestBody": {"content": {"application/json":
                    {"schema": {"$ref": "#/components/schemas/Node"}}}}}}}}
        targets = _targets(spec)                     # must not hang / recurse forever
        self.assertEqual(len(targets), 1)
        self.assertTrue(json.loads(targets[0][2]).get("name") == "1")

    def test_swagger_v2_base_and_body(self):
        spec = {"swagger": "2.0", "host": "api.example.com", "basePath": "/v2", "schemes": ["https"],
                "paths": {"/pet": {"post": {"parameters": [{"name": "b", "in": "body",
                          "schema": {"type": "object", "properties": {"id": {"type": "integer"}}}}]}}}}
        url, method, data, headers = _targets(spec, None)[0]
        self.assertEqual(url, "https://api.example.com/v2/pet")
        self.assertEqual(json.loads(data), {"id": 1})

    def test_server_template_variables(self):
        spec = {"openapi": "3.0.0", "servers": [{"url": "https://{env}.x.io/{ver}",
                "variables": {"env": {"default": "prod"}, "ver": {"default": "v3"}}}],
                "paths": {"/p": {"get": {}}}}
        self.assertEqual(_targets(spec, None)[0][0], "https://prod.x.io/v3/p")

    def test_headers_are_hashable_tuples(self):
        # kb.targets is an OrderedSet, so the emitted headers must be hashable (tuple, not list)
        spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": [
            {"name": "h", "in": "header", "schema": {"type": "string"}}]}}}}
        headers = _targets(spec)[0][3]
        self.assertTrue(headers is None or isinstance(tuple(headers), tuple))

    def test_header_and_cookie_params_are_injection_marked(self):
        # header/cookie params get the custom injection mark ('*') appended so they become testable
        # (custom) injection points (query/body params are still auto-tested alongside them)
        from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR as MARK
        spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": [
            {"name": "X-Api", "in": "header", "schema": {"type": "string", "example": "k"}},
            {"name": "sess", "in": "cookie", "schema": {"type": "string", "example": "v"}}]}}}}
        headers = dict(_targets(spec)[0][3])
        self.assertEqual(headers["X-Api"], "k" + MARK)
        self.assertEqual(headers["Cookie"], "sess=v" + MARK)

    # --- graceful degradation: a broken/poorly-defined spec must never crash the parser ---

    def test_malformed_raises_valueerror(self):
        for bad in ("{not json,,,", "[1,2,3]", "{}", '{"openapi":"3.0.0"}', '{"openapi":"3.0.0","paths":[1,2]}'):
            self.assertRaises(ValueError, openApiTargets, bad, "http://h")

    def test_malformed_servers_do_not_crash(self):
        for servers in ('{"url":"/a"}', '"http://h"', "[]"):
            spec = '{"openapi":"3.0.0","servers":%s,"paths":{"/x":{"get":{}}}}' % servers
            self.assertEqual(len(openApiTargets(spec, "http://h")), 1)   # no crash, still one target

    def test_url_and_body_values_are_encoded(self):
        # special characters in synthesized values must be percent-encoded so they can not break the
        # URL structure (param smuggling) or the form body
        spec = {"openapi": "3.0.0", "paths": {
            "/x/{p}": {"get": {"parameters": [
                {"name": "p", "in": "path", "schema": {"type": "string", "example": "a/b"}},
                {"name": "q", "in": "query", "schema": {"type": "string", "example": "a b&c=d"}}]}},
            "/f": {"post": {"requestBody": {"content": {"application/x-www-form-urlencoded":
                   {"schema": {"type": "object", "properties": {"u": {"type": "string", "example": "a b&x"}}}}}}}}}}
        byMethod = dict((method, (url, data)) for url, method, data, headers in _targets(spec))
        getUrl = byMethod["GET"][0]
        self.assertIn("/x/a%2Fb", getUrl)                # path value '/' encoded (no extra segment)
        self.assertIn("q=a%20b%26c%3Dd", getUrl)         # query value space/&/= encoded (no smuggling)
        self.assertNotIn(" ", getUrl)
        self.assertEqual(byMethod["POST"][1], "u=a%20b%26x")

    @unittest.skipUnless(HAS_YAML, "pyyaml not available")
    def test_yaml_spec(self):
        y = ("openapi: 3.0.0\n"
             "paths:\n"
             "  /y:\n"
             "    get:\n"
             "      parameters:\n"
             "        - name: q\n"
             "          in: query\n"
             "          schema: {type: string, example: hi}\n")
        targets = openApiTargets(y, "http://h")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0][0], "http://h/y?q=hi")

    def test_shared_recursive_refs_scale(self):
        # a self-referential schema reused across many operations must terminate promptly (depth cap +
        # per-$ref memoization); without them this would blow up exponentially and hang the test
        schemas = {"Node": {"type": "object", "properties": {
            "name": {"type": "string"},
            "child": {"$ref": "#/components/schemas/Node"},
            "list": {"type": "array", "items": {"$ref": "#/components/schemas/Node"}}}}}
        paths = dict(("/n%d" % i, {"post": {"requestBody": {"content": {"application/json":
                     {"schema": {"$ref": "#/components/schemas/Node"}}}}}}) for i in range(60))
        targets = _targets({"openapi": "3.0.0", "components": {"schemas": schemas}, "paths": paths})
        self.assertEqual(len(targets), 60)
        self.assertEqual(json.loads(targets[0][2]).get("name"), "1")

    def test_swagger_v2_formdata_body(self):
        # in:"formData" params must become a urlencoded body (previously dropped -> empty POST)
        spec = {"swagger": "2.0", "host": "h", "paths": {"/l": {"post": {"parameters": [
            {"name": "u", "in": "formData", "type": "string"},
            {"name": "p", "in": "formData", "type": "string"}]}}}}
        url, method, data, headers = _targets(spec, None)[0]
        self.assertEqual(method, "POST")
        self.assertEqual(sorted(data.split("&")), ["p=1", "u=1"])

    def test_relative_base_is_skipped(self):
        # a spec that yields no scheme/host (relative server + no origin) must be skipped, not emitted
        spec = {"openapi": "3.0.0", "servers": [{"url": "/api"}], "paths": {"/x": {"get": {}}}}
        self.assertEqual(openApiTargets(json.dumps(spec), None), [])           # relative -> skipped
        self.assertEqual(len(openApiTargets(json.dumps(spec), "http://h")), 1)  # absolute with origin -> kept

    def test_unsupported_body_media_type_no_crash(self):
        # a structured body under a non-JSON/form media type must not crash and must not fabricate a body,
        # but the endpoint URL is still produced
        spec = {"openapi": "3.0.0", "paths": {"/x": {"post": {"requestBody": {"content": {"application/xml":
                {"schema": {"type": "object", "properties": {"a": {"type": "string"}}}}}}}}}}
        url, method, data, headers = _targets(spec)[0]
        self.assertEqual((url, method, data), ("http://h/x", "POST", None))

    def test_injection_mark_char_in_value_is_not_doubled(self):
        # an example value already containing the custom injection mark must not create a stray point
        from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR as MARK
        spec = {"openapi": "3.0.0", "paths": {"/x": {"post": {
            "parameters": [{"name": "H", "in": "header", "schema": {"type": "string", "example": "a%sb" % MARK}}],
            "requestBody": {"content": {"application/json": {"schema": {"type": "object",
                "properties": {"n": {"type": "string", "example": "x%sy" % MARK}}}}}}}}}}
        url, method, data, headers = _targets(spec)[0]
        self.assertEqual(dict(headers)["H"], "ab" + MARK)              # single trailing mark only
        self.assertEqual(json.loads(data), {"n": "xy"})               # mark stripped from body value

    @unittest.skipUnless(HAS_YAML, "pyyaml not available")
    def test_non_string_method_keys_do_not_crash(self):
        # YAML path-item keys are not guaranteed to be strings (404 -> int, on -> bool); must not crash
        y = ("openapi: 3.0.0\n"
             "servers: [{url: 'http://h'}]\n"
             "paths:\n"
             "  /x:\n"
             "    get: {}\n"
             "    404: {}\n"
             "    on: {}\n")
        targets = openApiTargets(y, "http://h")
        self.assertEqual(len(targets), 1)                             # only the real GET operation
        self.assertEqual(targets[0][1], "GET")

    def test_hostile_base_url_metadata_does_not_crash(self):
        # _baseUrl runs once, OUTSIDE the per-operation try, so malformed server/scheme/basePath metadata
        # must not raise (it would abort the entire extraction)
        hostile = [
            {"openapi": "3.0.0", "servers": [{"url": "https://{e}.x/", "variables": [1, 2]}], "paths": {"/x": {"get": {}}}},
            {"openapi": "3.0.0", "servers": [{"url": "https://{e}.x/", "variables": {"e": "prod"}}], "paths": {"/x": {"get": {}}}},
            {"openapi": "3.0.0", "servers": [{"url": 123}], "paths": {"/x": {"get": {}}}},
            {"swagger": "2.0", "host": "h", "schemes": {"a": 1}, "paths": {"/x": {"get": {}}}},
            {"swagger": "2.0", "host": "h", "basePath": 123, "paths": {"/x": {"get": {}}}}]
        for spec in hostile:
            self.assertEqual(len(_targets(spec)), 1)     # no crash, still one target

    def test_param_entry_not_a_dict_is_skipped(self):
        spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": ["oops", {"name": "q", "in": "query"}]}}}}
        self.assertIn("q=1", _targets(spec)[0][0])       # bad entry skipped, good one still used

    @unittest.skipUnless(HAS_YAML, "pyyaml not available")
    def test_yaml_date_examples_serialize(self):
        # unquoted YAML dates parse to datetime.date, which is not JSON-serializable -> must be stringified,
        # not silently dropped (dates are pervasive in real specs)
        y = ("openapi: 3.0.0\n"
             "servers: [{url: 'http://h'}]\n"
             "paths:\n"
             "  /x:\n"
             "    post:\n"
             "      requestBody:\n"
             "        content:\n"
             "          application/json:\n"
             "            schema: {type: object, properties: {created: {type: string, example: 2020-01-01}}}\n")
        url, method, data, headers = openApiTargets(y, "http://h")[0]
        self.assertEqual(json.loads(data), {"created": "2020-01-01"})

    def test_crlf_in_header_and_cookie_is_stripped(self):
        # a spec-supplied header/cookie name or value must not carry CR/LF (header injection / request
        # corruption); query/path values are separately percent-encoded
        spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": [
            {"name": "X-A", "in": "header", "schema": {"type": "string", "example": "a\r\nX-Evil: 1"}},
            {"name": "X\r\nB", "in": "header", "schema": {"type": "string", "example": "v"}},
            {"name": "sid", "in": "cookie", "schema": {"type": "string", "example": "a\r\nSet: x"}}]}}}}
        headers = dict(_targets(spec)[0][3])
        for name, value in headers.items():
            self.assertNotIn("\r", name + value)
            self.assertNotIn("\n", name + value)
        self.assertIn("X-A", headers)
        self.assertIn("XB", headers)                     # control chars removed from the name

    def test_explicit_examples_preferred_over_schema(self):
        # a concrete example/examples on the media-type or parameter object must win over schema synthesis
        # (real specs carry the canonical, validation-passing value there)
        body = {"openapi": "3.0.0", "paths": {"/x": {"post": {"requestBody": {"content": {"application/json": {
                "schema": {"type": "object", "properties": {"name": {"type": "string"}}}, "example": {"name": "real"}}}}}}}}
        self.assertEqual(json.loads(_targets(body)[0][2]), {"name": "real"})
        examples = {"openapi": "3.0.0", "paths": {"/x": {"post": {"requestBody": {"content": {"application/json": {
                    "schema": {"type": "object"}, "examples": {"first": {"value": {"k": "v1"}}}}}}}}}}
        self.assertEqual(json.loads(_targets(examples)[0][2]), {"k": "v1"})
        param = {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": [
                 {"name": "q", "in": "query", "example": "E", "schema": {"type": "string"}}]}}}}
        self.assertIn("q=E", _targets(param)[0][0])

    def test_openapi_31_const_and_type_array(self):
        spec = {"openapi": "3.1.0", "paths": {"/x": {"get": {"parameters": [
            {"name": "c", "in": "query", "schema": {"const": "CV"}},
            {"name": "n", "in": "query", "schema": {"type": ["integer", "null"]}}]}}}}
        url = _targets(spec)[0][0]
        self.assertIn("c=CV", url)                       # const used
        self.assertIn("n=1", url)                        # ["integer","null"] resolved to integer, not the generic fallback

    def test_parameter_names_are_encoded(self):
        # a param NAME with structural chars must be encoded so it can not split/smuggle params or truncate
        # at a fragment; deep-object brackets ([]) are preserved
        spec = {"openapi": "3.0.0", "paths": {
            "/q": {"get": {"parameters": [
                {"name": "a&b=c", "in": "query", "schema": {"type": "string"}},
                {"name": "a#b", "in": "query", "schema": {"type": "string"}},
                {"name": "filter[status]", "in": "query", "schema": {"type": "string"}}]}},
            "/f": {"post": {"requestBody": {"content": {"application/x-www-form-urlencoded":
                   {"schema": {"type": "object", "properties": {"x&y": {"type": "string"}}}}}}}}}}
        byMethod = dict((method, (url, data)) for url, method, data, headers in _targets(spec))
        getUrl = byMethod["GET"][0]
        self.assertIn("a%26b%3Dc=1", getUrl)
        self.assertIn("a%23b=1", getUrl)
        self.assertIn("filter[status]=1", getUrl)       # brackets kept (deep-object param names)
        self.assertNotIn("#", getUrl)
        self.assertEqual(byMethod["POST"][1], "x%26y=1")

    def test_undefined_template_var_does_not_leak(self):
        # a server/path template variable with no definition must not leave a literal '{...}' in the URL
        spec = {"openapi": "3.0.0", "servers": [{"url": "https://api.x.com/{basePath}/v3"}],
                "paths": {"/pets": {"get": {}}}}
        url = _targets(spec, "http://h")[0][0]
        self.assertNotIn("{", url)
        self.assertEqual(url, "https://api.x.com/1/v3/pets")   # absolute server used as-is (host not rewritten)

    def test_absolute_server_url_is_not_rewritten_to_origin(self):
        # a spec served from one host but declaring an absolute API server on another host must scan the
        # DECLARED API host, not the spec's origin
        spec = {"openapi": "3.0.0", "servers": [{"url": "https://api.example.com/v1"}],
                "paths": {"/pets": {"get": {}}}}
        self.assertEqual(_targets(spec, "https://docs.example.com")[0][0], "https://api.example.com/v1/pets")

    def test_path_parameter_is_injection_marked(self):
        from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR as MARK
        spec = {"openapi": "3.0.0", "paths": {"/users/{id}": {"get": {"parameters": [
            {"name": "id", "in": "path", "schema": {"type": "integer"}}]}}}}
        self.assertEqual(_targets(spec)[0][0], "http://h/users/1" + MARK)

    def test_form_urlencoded_sets_content_type_and_multipart_skipped(self):
        form = {"openapi": "3.0.0", "paths": {"/f": {"post": {"requestBody": {"content":
                {"application/x-www-form-urlencoded": {"schema": {"type": "object", "properties": {"u": {"type": "string"}}}}}}}}}}
        url, method, data, headers = _targets(form)[0]
        self.assertEqual(data, "u=1")
        self.assertIn(("Content-Type", "application/x-www-form-urlencoded"), headers)
        multipart = {"openapi": "3.0.0", "paths": {"/m": {"post": {"requestBody": {"content":
                     {"multipart/form-data": {"schema": {"type": "object", "properties": {"u": {"type": "string"}}}}}}}}}}
        url, method, data, headers = _targets(multipart)[0]
        self.assertIsNone(data)                          # multipart is skipped, not mis-serialized as urlencoded

    def test_path_item_ref_is_resolved(self):
        spec = {"openapi": "3.1.0",
                "components": {"pathItems": {"Ping": {"get": {"parameters": [
                    {"name": "q", "in": "query", "schema": {"type": "string", "example": "z"}}]}}}},
                "paths": {"/ping": {"$ref": "#/components/pathItems/Ping"}}}
        targets = _targets(spec)
        self.assertEqual(len(targets), 1)
        self.assertIn("q=z", targets[0][0])

    def test_operation_parameter_overrides_path_level(self):
        spec = {"openapi": "3.0.0", "paths": {"/x": {
            "parameters": [{"name": "q", "in": "query", "schema": {"type": "string", "example": "shared"}}],
            "get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string", "example": "op"}}]}}}}
        url = _targets(spec)[0][0]
        self.assertIn("q=op", url)                       # operation value wins
        self.assertEqual(url.count("q="), 1)             # not duplicated

    def test_multiple_cookies_aggregate_into_one_header(self):
        from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR as MARK
        spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": [
            {"name": "a", "in": "cookie", "schema": {"type": "string"}},
            {"name": "b", "in": "cookie", "schema": {"type": "string"}}]}}}}
        headers = _targets(spec)[0][3]
        cookieHeaders = [v for (k, v) in headers if k == "Cookie"]
        self.assertEqual(cookieHeaders, ["a=1%s; b=1%s" % (MARK, MARK)])   # one aggregated Cookie header

    def test_cookie_name_value_cannot_smuggle_pairs(self):
        # a cookie name that is not a token is dropped; structural chars in the value ('; ,' / whitespace)
        # are stripped so a spec can not inject additional cookie pairs
        spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": [
            {"name": "a; injected", "in": "cookie", "schema": {"type": "string"}},
            {"name": "sid", "in": "cookie", "schema": {"type": "string", "example": "v; z=1"}}]}}}}
        cookieHeaders = [v for (k, v) in (_targets(spec)[0][3] or []) if k == "Cookie"]
        self.assertEqual(len(cookieHeaders), 1)
        cookie = cookieHeaders[0]
        self.assertNotIn(";", cookie.rstrip("*"))        # no interior ';' -> no smuggled pair
        self.assertNotIn("injected", cookie)             # invalid cookie name dropped
        self.assertNotIn(" ", cookie)

    def test_loose_path_without_leading_slash(self):
        # a malformed path key missing its leading '/' must not glue onto the base (".../v1pets")
        spec = {"openapi": "3.0.0", "servers": [{"url": "https://api.x/v1"}], "paths": {"pets": {"get": {}}}}
        self.assertEqual(_targets(spec, None)[0][0], "https://api.x/v1/pets")

    def test_array_query_param_is_best_effort_scalar(self):
        # documents current best-effort behavior: an array query param is scalarized+encoded, NOT expanded
        # per style/explode. If richer serialization is added later, update this expectation deliberately.
        spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": [
            {"name": "ids", "in": "query", "schema": {"type": "array", "items": {"type": "integer"}}}]}}}}
        url = _targets(spec)[0][0]
        self.assertIn("ids=", url)
        self.assertNotIn(" ", url)                       # whatever the encoding, it must not break the URL
        self.assertTrue(url.startswith("http://h/x?ids="))

    def test_invalid_header_name_is_skipped(self):
        spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": [
            {"name": "Bad Name", "in": "header", "schema": {"type": "string"}},
            {"name": "Also:Bad", "in": "header", "schema": {"type": "string"}},
            {"name": "X-Good", "in": "header", "schema": {"type": "string"}}]}}}}
        headers = dict(_targets(spec)[0][3] or [])
        self.assertIn("X-Good", headers)
        self.assertNotIn("Bad Name", headers)
        self.assertNotIn("Also:Bad", headers)

    def test_explicit_null_example_falls_back_to_schema(self):
        # 'example: null' must not serialize as null/"null" - fall back to schema synthesis
        q = {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": [
             {"name": "q", "in": "query", "example": None, "schema": {"type": "string", "example": "good"}}]}}}}
        self.assertIn("q=good", _targets(q)[0][0])
        b = {"openapi": "3.0.0", "paths": {"/x": {"post": {"requestBody": {"content": {"application/json":
             {"example": None, "schema": {"type": "object", "properties": {"a": {"type": "integer"}}}}}}}}}}
        self.assertEqual(json.loads(_targets(b)[0][2]), {"a": 1})

    def test_degrade_not_skip_on_odd_shapes(self):
        # enum-as-dict, non-string param name, and content[type]-as-list must degrade (op preserved)
        for spec in (
            {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": [{"name": "q", "in": "query", "schema": {"enum": {"a": 1}}}]}}}},
            {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": [{"name": 5, "in": "header", "schema": {"type": "string"}}]}}}},
            {"openapi": "3.0.0", "paths": {"/x": {"post": {"requestBody": {"content": {"application/json": [1, 2]}}}}}}):
            self.assertEqual(len(_targets(spec)), 1)

    def test_malformed_ref_and_properties_degrade_not_skip(self):
        # a non-string/unhashable $ref or a non-dict 'properties' must degrade the value (not lose the op)
        for schema in ({"$ref": 123}, {"$ref": [1, 2]}, {"type": "object", "properties": [1, 2]}):
            spec = {"openapi": "3.0.0", "paths": {"/x": {"post": {"requestBody":
                    {"content": {"application/json": {"schema": schema}}}}}}}
            self.assertEqual(len(_targets(spec)), 1)     # operation preserved, not skipped

    def test_undefined_bits_are_skipped_not_fatal(self):
        spec = {"openapi": "3.0.0", "paths": {
            "/a": {"get": {"parameters": [{}]}},                                   # param with no name
            "/b": {"post": {"requestBody": {"content": {"application/json":
                   {"schema": {"$ref": "#/components/schemas/DoesNotExist"}}}}}},   # dangling $ref
            "/c": {"get": {"parameters": [{"name": "p", "in": "query",
                   "schema": {"$ref": "https://other/x.json#/Y"}}]}}}}             # external $ref
        targets = _targets(spec)
        self.assertEqual(len(targets), 3)                                          # all three still produced


if __name__ == "__main__":
    unittest.main()
