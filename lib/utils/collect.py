#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from BaseHTTPServer import BaseHTTPRequestHandler
from httplib import HTTPResponse
from StringIO import StringIO
import base64
import re

from lib.core.data import logger
from lib.core.settings import VERSION


class RequestCollectorFactory:

    def __init__(self, collect=False):
        self.collect = collect

    def create(self):
        collector = RequestCollector()

        if not self.collect:
            collector.collectRequest = self._noop
        else:
            logger.info("Request collection is enabled.")

        return collector

    @staticmethod
    def _noop(*args, **kwargs):
        pass


class RequestCollector:

    def __init__(self):
        self.reset()

    def collectRequest(self, requestMessage, responseMessage):
        self.messages.append(RawPair(requestMessage, responseMessage))

    def reset(self):
        self.messages = []

    def obtain(self):
        if self.messages:
            return {"log": {
                "version": "1.2",
                "creator": {"name": "SQLMap", "version": VERSION},
                "entries": [pair.toEntry().toDict() for pair in self.messages],
            }}


class RawPair:

    def __init__(self, request, response):
        self.request = request
        self.response = response

    def toEntry(self):
        return Entry(request=Request.parse(self.request),
                     response=Response.parse(self.response))


class Entry:

    def __init__(self, request, response):
        self.request = request
        self.response = response

    def toDict(self):
        return {
            "request": self.request.toDict(),
            "response": self.response.toDict(),
        }


class Request:

    def __init__(self, method, path, httpVersion, headers, postBody=None, raw=None, comment=None):
        self.method = method
        self.path = path
        self.httpVersion = httpVersion
        self.headers = headers or {}
        self.postBody = postBody
        self.comment = comment
        self.raw = raw

    @classmethod
    def parse(cls, raw):
        request = HTTPRequest(raw)
        return cls(method=request.command,
                   path=request.path,
                   httpVersion=request.request_version,
                   headers=request.headers,
                   postBody=request.rfile.read(),
                   comment=request.comment,
                   raw=raw)

    @property
    def url(self):
        host = self.headers.get('Host', 'unknown')
        return "http://%s%s" % (host, self.path)

    def toDict(self):
        out = {
            "method": self.method,
            "url": self.url,
            "headers": [dict(name=key, value=value) for key, value in self.headers.items()],
            "comment": self.comment,
            "_raw": self.raw,
        }
        if self.postBody:
            contentType = self.headers.get('Content-Type')
            out["postData"] = {
                "mimeType": contentType,
                "text": self.postBody,
            }
        return out


class Response:

    extract_status = re.compile(r'\((\d{3}) (.*)\)')

    def __init__(self, httpVersion, status, statusText, headers, content, raw=None, comment=None):
        self.raw = raw
        self.httpVersion = httpVersion
        self.status = status
        self.statusText = statusText
        self.headers = headers
        self.content = content
        self.comment = comment

    @classmethod
    def parse(cls, raw):
        altered = raw
        comment = None

        if altered.startswith("HTTP response ["):
            io = StringIO(raw)
            first_line = io.readline()
            parts = cls.extract_status.search(first_line)
            status_line = "HTTP/1.0 %s %s" % (parts.group(1), parts.group(2))
            remain = io.read()
            altered = status_line + "\n" + remain
            comment = first_line

        response = HTTPResponse(FakeSocket(altered))
        response.begin()
        return cls(httpVersion="HTTP/1.1" if response.version == 11 else "HTTP/1.0",
                   status=response.status,
                   statusText=response.reason,
                   headers=response.msg,
                   content=response.read(-1),
                   comment=comment,
                   raw=raw)

    def toDict(self):
        return {
            "httpVersion": self.httpVersion,
            "status": self.status,
            "statusText": self.statusText,
            "headers": [dict(name=key, value=value) for key, value in self.headers.items()],
            "content": {
                "mimeType": self.headers.get('Content-Type'),
                "encoding": "base64",
                "text": base64.b64encode(self.content),
            },
            "comment": self.comment,
            "_raw": self.raw,
        }


class FakeSocket:
    # Original source:
    # https://stackoverflow.com/questions/24728088/python-parse-http-response-string

    def __init__(self, response_text):
        self._file = StringIO(response_text)

    def makefile(self, *args, **kwargs):
        return self._file


class HTTPRequest(BaseHTTPRequestHandler):
    # Original source:
    # https://stackoverflow.com/questions/4685217/parse-raw-http-headers

    def __init__(self, request_text):
        self.comment = None
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()

        if self.raw_requestline.startswith("HTTP request ["):
            self.comment = self.raw_requestline
            self.raw_requestline = self.rfile.readline()

        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message


if __name__ == '__main__':
    import unittest

    class RequestParseTest(unittest.TestCase):

        def test_basic_request(self):
            req = Request.parse("GET /test HTTP/1.0\r\n"
                                "Host: test\r\n"
                                "Connection: close")
            self.assertEqual("GET", req.method)
            self.assertEqual("/test", req.path)
            self.assertEqual("close", req.headers['Connection'])
            self.assertEqual("test", req.headers['Host'])
            self.assertEqual("HTTP/1.0", req.httpVersion)

        def test_with_request_as_logged_by_sqlmap(self):
            raw = "HTTP request [#75]:\nPOST /create.php HTTP/1.1\nHost: 127.0.0.1\nAccept-encoding: gzip,deflate\nCache-control: no-cache\nContent-type: application/x-www-form-urlencoded; charset=utf-8\nAccept: */*\nUser-agent: Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10\nCookie: PHPSESSID=65c4a9cfbbe91f2d975d50ce5e8d1026\nContent-length: 138\nConnection: close\n\nname=test%27%29%3BSELECT%20LIKE%28%27ABCDEFG%27%2CUPPER%28HEX%28RANDOMBLOB%280.0.10000%2F2%29%29%29%29--&csrfmiddlewaretoken=594d26cfa3fad\n"  # noqa
            req = Request.parse(raw)
            self.assertEqual("POST", req.method)
            self.assertEqual("138", req.headers["Content-Length"])
            self.assertIn("csrfmiddlewaretoken", req.postBody)
            self.assertEqual("HTTP request [#75]:\n", req.comment)

    class RequestRenderTest(unittest.TestCase):
        def test_render_get_request(self):
            req = Request(method="GET",
                          path="/test.php",
                          headers={"Host": "example.com", "Content-Length": "0"},
                          httpVersion="HTTP/1.1",
                          comment="Hello World")
            out = req.toDict()
            self.assertEqual("GET", out["method"])
            self.assertEqual("http://example.com/test.php", out["url"])
            self.assertIn({"name": "Host", "value": "example.com"}, out["headers"])
            self.assertEqual("Hello World", out["comment"])

        def test_render_with_post_body(self):
            req = Request(method="POST",
                          path="/test.php",
                          headers={"Host": "example.com",
                                   "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
                          httpVersion="HTTP/1.1",
                          postBody="name=test&csrfmiddlewaretoken=594d26cfa3fad\n")
            out = req.toDict()
            self.assertEqual(out["postData"], {
                "mimeType": "application/x-www-form-urlencoded; charset=utf-8",
                "text": "name=test&csrfmiddlewaretoken=594d26cfa3fad\n",
            })

    class ResponseParseTest(unittest.TestCase):
        def test_parse_standard_http_response(self):
            raw = "HTTP/1.1 404 Not Found\nContent-length: 518\nX-powered-by: PHP/5.6.30\nContent-encoding: gzip\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\nVary: Accept-Encoding\nUri: http://127.0.0.1/\nServer: Apache/2.4.10 (Debian)\nConnection: close\nPragma: no-cache\nCache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\nDate: Fri, 23 Jun 2017 16:18:17 GMT\nContent-type: text/html; charset=UTF-8\n\n<!doctype html>\n<html>Test</html>\n"  # noqa
            resp = Response.parse(raw)
            self.assertEqual(resp.status, 404)
            self.assertEqual(resp.statusText, "Not Found")

        def test_parse_response_as_logged_by_sqlmap(self):
            raw = "HTTP response [#74] (200 OK):\nContent-length: 518\nX-powered-by: PHP/5.6.30\nContent-encoding: gzip\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\nVary: Accept-Encoding\nUri: http://127.0.0.1/\nServer: Apache/2.4.10 (Debian)\nConnection: close\nPragma: no-cache\nCache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\nDate: Fri, 23 Jun 2017 16:18:17 GMT\nContent-type: text/html; charset=UTF-8\n\n<!doctype html>\n<html>Test</html>\n"  # noqa
            resp = Response.parse(raw)
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.statusText, "OK")
            self.assertEqual(resp.headers["Content-Length"], "518")
            self.assertIn("Test", resp.content)
            self.assertEqual("HTTP response [#74] (200 OK):\n", resp.comment)

    class ResponseRenderTest(unittest.TestCase):
        def test_simple_page_encoding(self):
            resp = Response(status=200, statusText="OK",
                            httpVersion="HTTP/1.1",
                            headers={"Content-Type": "text/html"},
                            content="<html><body>Hello</body></html>\n")
            out = resp.toDict()
            self.assertEqual(200, out["status"])
            self.assertEqual("OK", out["statusText"])
            self.assertIn({"name": "Content-Type", "value": "text/html"}, out["headers"])
            self.assertEqual(out["content"], {
                "mimeType": "text/html",
                "encoding": "base64",
                "text": "PGh0bWw+PGJvZHk+SGVsbG88L2JvZHk+PC9odG1sPgo=",
            })

    unittest.main(buffer=False)
