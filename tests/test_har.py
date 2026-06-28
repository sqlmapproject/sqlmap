#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Tests for lib/utils/har.py -- HAR (HTTP Archive) collector and HTTP
request/response parsing used by sqlmap's --har-file feature.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.utils import har as H


class TestFakeSocket(unittest.TestCase):
    def test_makefile_returns_bytesio(self):
        sock = H.FakeSocket(b"hello\r\n")
        f = sock.makefile()
        self.assertEqual(f.read(), b"hello\r\n")


class TestRawPair(unittest.TestCase):
    def test_stores_fields(self):
        pair = H.RawPair(b"GET / HTTP/1.0\r\n\r\n",
                         b"HTTP/1.0 200 OK\r\n\r\n",
                         startTime=1000, endTime=2000)
        self.assertEqual(pair.request, b"GET / HTTP/1.0\r\n\r\n")
        self.assertEqual(pair.response, b"HTTP/1.0 200 OK\r\n\r\n")
        self.assertEqual(pair.startTime, 1000)
        self.assertEqual(pair.endTime, 2000)


class TestHTTPCollector(unittest.TestCase):
    def test_collect_and_obtain(self):
        c = H.HTTPCollector()
        c.collectRequest(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
                         b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\nbody",
                         startTime=1000, endTime=2000)
        result = c.obtain()
        log = result["log"]
        self.assertEqual(log["version"], "1.2")
        self.assertEqual(log["creator"]["name"], "sqlmap")
        entries = log["entries"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["request"]["method"], "GET")
        self.assertEqual(entries[0]["response"]["status"], 200)


class TestHTTPCollectorFactory(unittest.TestCase):
    def test_create_returns_collector(self):
        f = H.HTTPCollectorFactory(harFile=True)
        c = f.create()
        self.assertIsInstance(c, H.HTTPCollector)


class TestEntry(unittest.TestCase):
    def test_toDict(self):
        req = H.Request("GET", "/path", "HTTP/1.1",
                        {"Host": "example.com"})
        resp = H.Response("HTTP/1.1", 200, "OK",
                          {"Content-Type": "text/html"}, b"body")
        entry = H.Entry(req, resp, startTime=1000, endTime=2000,
                        extendedArguments={})
        d = entry.toDict()
        self.assertEqual(d["request"]["method"], "GET")
        self.assertEqual(d["response"]["status"], 200)
        self.assertEqual(d["time"], 1000000)
        self.assertIn("startedDateTime", d)


class TestRequest(unittest.TestCase):
    def test_parse_simple_get(self):
        raw = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = H.Request.parse(raw)
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.path, "/path")
        self.assertEqual(req.httpVersion, "HTTP/1.1")
        self.assertEqual(req.headers.get("Host"), "example.com")

    def test_parse_with_comment(self):
        raw = (b"HTTP request [#1]:\r\n"
               b"POST /submit HTTP/1.0\r\n"
               b"Host: example.com\r\n"
               b"Content-Type: text/plain\r\n"
               b"Content-Length: 4\r\n"
               b"\r\n"
               b"body")
        req = H.Request.parse(raw)
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.path, "/submit")
        self.assertEqual(req.comment, b"HTTP request [#1]:")
        self.assertIn(b"body", req.postBody)

    def test_toDict(self):
        req = H.Request("GET", "/", "HTTP/1.0",
                        {"Host": "test.com", "Accept": "*/*"})
        d = req.toDict()
        self.assertEqual(d["method"], "GET")
        self.assertEqual(d["url"], "http://test.com/")
        self.assertEqual(len(d["headers"]), 2)

    def test_toDict_with_postbody(self):
        req = H.Request("POST", "/", "HTTP/1.1",
                        {"Host": "test.com", "Content-Type": "application/json"},
                        postBody=b'{"a":1}')
        d = req.toDict()
        self.assertEqual(d["postData"]["mimeType"], "application/json")
        self.assertIn('{"a":1}', d["postData"]["text"])

    def test_url_property(self):
        req = H.Request("GET", "/path?q=1", "HTTP/1.0",
                        {"Host": "example.com"})
        self.assertEqual(req.url, "http://example.com/path?q=1")

    def test_url_no_host_header(self):
        req = H.Request("GET", "/", "HTTP/1.0", {})
        self.assertIn("unknown", req.url)


class TestResponse(unittest.TestCase):
    def test_parse_simple(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 4\r\n\r\nbody"
        resp = H.Response.parse(raw)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.statusText, "OK")
        self.assertEqual(resp.headers.get("Content-Type"), "text/html")
        self.assertEqual(resp.content, b"body")

    def test_parse_with_comment(self):
        raw = (b"HTTP response [#1] (200 Fine):\r\n"
               b"HTTP/1.0 200 Fine\r\n"
               b"Content-Type: text/plain\r\n"
               b"\r\n"
               b"response body")
        resp = H.Response.parse(raw)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.statusText, "Fine")
        self.assertIn(b"HTTP response", resp.comment)

    def test_toDict(self):
        resp = H.Response("HTTP/1.1", 404, "Not Found",
                          {"Content-Type": "text/html"}, b"not found")
        d = resp.toDict()
        self.assertEqual(d["status"], 404)
        self.assertEqual(d["statusText"], "Not Found")
        self.assertEqual(d["content"]["text"], "not found")
        self.assertEqual(d["content"]["size"], 9)

    def test_toDict_binary_content_encoded(self):
        resp = H.Response("HTTP/1.1", 200, "OK",
                          {"Content-Type": "application/octet-stream"},
                          b"\x00\x01\xff")
        d = resp.toDict()
        self.assertEqual(d["content"]["encoding"], "base64")

    def test_toDict_non_text_content(self):
        resp = H.Response("HTTP/1.1", 200, "OK",
                          {"Content-Type": "text/plain"}, b"plain text")
        d = resp.toDict()
        self.assertEqual(d["content"]["text"], "plain text")


if __name__ == "__main__":
    unittest.main(verbosity=2)
