#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO

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

    def __init__(self):
        pass

    @classmethod
    def parse(cls, raw):
        return cls()

    def toDict(self):
        return {
        }


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
            raw = "HTTP request [#75]:\nPOST /create.php HTTP/1.1\nHost: 240.0.0.2\nAccept-encoding: gzip,deflate\nCache-control: no-cache\nContent-type: application/x-www-form-urlencoded; charset=utf-8\nAccept: */*\nUser-agent: Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10\nCookie: PHPSESSID=65c4a9cfbbe91f2d975d50ce5e8d1026\nContent-length: 138\nConnection: close\n\nname=test%27%29%3BSELECT%20LIKE%28%27ABCDEFG%27%2CUPPER%28HEX%28RANDOMBLOB%28000000000%2F2%29%29%29%29--&csrfmiddlewaretoken=594d26cfa3fad\n"  # noqa
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

    unittest.main(buffer=False)
