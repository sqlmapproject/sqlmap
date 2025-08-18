#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import base64
import datetime
import io
import re
import time

from lib.core.bigarray import BigArray
from lib.core.convert import getBytes
from lib.core.convert import getText
from lib.core.settings import VERSION
from thirdparty.six.moves import BaseHTTPServer as _BaseHTTPServer
from thirdparty.six.moves import http_client as _http_client

# Reference: https://dvcs.w3.org/hg/webperf/raw-file/tip/specs/HAR/Overview.html
#            http://www.softwareishard.com/har/viewer/

class HTTPCollectorFactory(object):
    def __init__(self, harFile=False):
        self.harFile = harFile

    def create(self):
        return HTTPCollector()

class HTTPCollector(object):
    def __init__(self):
        self.messages = BigArray()
        self.extendedArguments = {}

    def setExtendedArguments(self, arguments):
        self.extendedArguments = arguments

    def collectRequest(self, requestMessage, responseMessage, startTime=None, endTime=None):
        self.messages.append(RawPair(requestMessage, responseMessage,
                                     startTime=startTime, endTime=endTime,
                                     extendedArguments=self.extendedArguments))

    def obtain(self):
        return {"log": {
            "version": "1.2",
            "creator": {"name": "sqlmap", "version": VERSION},
            "entries": [pair.toEntry().toDict() for pair in self.messages],
        }}

class RawPair(object):
    def __init__(self, request, response, startTime=None, endTime=None, extendedArguments=None):
        self.request = getBytes(request)
        self.response = getBytes(response)
        self.startTime = startTime
        self.endTime = endTime
        self.extendedArguments = extendedArguments or {}

    def toEntry(self):
        return Entry(request=Request.parse(self.request), response=Response.parse(self.response),
                     startTime=self.startTime, endTime=self.endTime,
                     extendedArguments=self.extendedArguments)

class Entry(object):
    def __init__(self, request, response, startTime, endTime, extendedArguments):
        self.request = request
        self.response = response
        self.startTime = startTime or 0
        self.endTime = endTime or 0
        self.extendedArguments = extendedArguments

    def toDict(self):
        out = {
            "request": self.request.toDict(),
            "response": self.response.toDict(),
            "cache": {},
            "timings": {
                "send": -1,
                "wait": -1,
                "receive": -1,
            },
            "time": int(1000 * (self.endTime - self.startTime)),
            "startedDateTime": "%s%s" % (datetime.datetime.fromtimestamp(self.startTime).isoformat(), time.strftime("%z")) if self.startTime else None
        }
        out.update(self.extendedArguments)
        return out

class Request(object):
    def __init__(self, method, path, httpVersion, headers, postBody=None, raw=None, comment=None):
        self.method = method
        self.path = path
        self.httpVersion = httpVersion
        self.headers = headers or {}
        self.postBody = postBody
        self.comment = comment.strip() if comment else comment
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
        host = self.headers.get("Host", "unknown")
        return "http://%s%s" % (host, self.path)

    def toDict(self):
        out = {
            "httpVersion": self.httpVersion,
            "method": self.method,
            "url": self.url,
            "headers": [dict(name=key.capitalize(), value=value) for key, value in self.headers.items()],
            "cookies": [],
            "queryString": [],
            "headersSize": -1,
            "bodySize": -1,
            "comment": getText(self.comment),
        }

        if self.postBody:
            contentType = self.headers.get("Content-Type")
            out["postData"] = {
                "mimeType": contentType,
                "text": getText(self.postBody).rstrip("\r\n"),
            }

        return out

class Response(object):
    extract_status = re.compile(b'\\((\\d{3}) (.*)\\)')

    def __init__(self, httpVersion, status, statusText, headers, content, raw=None, comment=None):
        self.raw = raw
        self.httpVersion = httpVersion
        self.status = status
        self.statusText = statusText
        self.headers = headers
        self.content = content
        self.comment = comment.strip() if comment else comment

    @classmethod
    def parse(cls, raw):
        altered = raw
        comment = b""

        if altered.startswith(b"HTTP response [") or altered.startswith(b"HTTP redirect ["):
            stream = io.BytesIO(raw)
            first_line = stream.readline()
            parts = cls.extract_status.search(first_line)
            status_line = "HTTP/1.0 %s %s" % (getText(parts.group(1)), getText(parts.group(2)))
            remain = stream.read()
            altered = getBytes(status_line) + b"\r\n" + remain
            comment = first_line

        response = _http_client.HTTPResponse(FakeSocket(altered))
        response.begin()

        # NOTE: https://github.com/sqlmapproject/sqlmap/issues/5942
        response.length = len(raw[raw.find(b"\r\n\r\n") + 4:])

        try:
            content = response.read()
        except _http_client.IncompleteRead:
            content = raw[raw.find(b"\r\n\r\n") + 4:].rstrip(b"\r\n")

        return cls(httpVersion="HTTP/1.1" if response.version == 11 else "HTTP/1.0",
                   status=response.status,
                   statusText=response.reason,
                   headers=response.msg,
                   content=content,
                   comment=comment,
                   raw=raw)

    def toDict(self):
        content = {
            "mimeType": self.headers.get("Content-Type"),
            "text": self.content,
            "size": len(self.content or "")
        }

        binary = set([b'\0', b'\1'])
        if any(c in binary for c in self.content):
            content["encoding"] = "base64"
            content["text"] = getText(base64.b64encode(self.content))
        else:
            content["text"] = getText(content["text"])

        return {
            "httpVersion": self.httpVersion,
            "status": self.status,
            "statusText": self.statusText,
            "headers": [dict(name=key.capitalize(), value=value) for key, value in self.headers.items() if key.lower() != "uri"],
            "cookies": [],
            "content": content,
            "headersSize": -1,
            "bodySize": -1,
            "redirectURL": "",
            "comment": getText(self.comment),
        }

class FakeSocket(object):
    # Original source:
    # https://stackoverflow.com/questions/24728088/python-parse-http-response-string

    def __init__(self, response_text):
        self._file = io.BytesIO(response_text)

    def makefile(self, *args, **kwargs):
        return self._file

class HTTPRequest(_BaseHTTPServer.BaseHTTPRequestHandler):
    # Original source:
    # https://stackoverflow.com/questions/4685217/parse-raw-http-headers

    def __init__(self, request_text):
        self.comment = None
        self.rfile = io.BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()

        if self.raw_requestline.startswith(b"HTTP request ["):
            self.comment = self.raw_requestline
            self.raw_requestline = self.rfile.readline()

        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message
