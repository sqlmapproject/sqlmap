#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import io
import mimetypes
import re

from lib.core.compat import choose_boundary
from lib.core.convert import getBytes
from lib.core.exception import SqlmapDataException
from thirdparty.six.moves import urllib as _urllib

# Controls how sequences are encoded: if True, an element may be given multiple values by assigning a sequence
DOSEQ = True

class MultipartPostHandler(_urllib.request.BaseHandler):
    """
    urllib handler that transparently encodes a dict request body as multipart/form-data when it carries
    file-like values (and as a plain urlencoded body otherwise). Native replacement for the historically
    vendored 'thirdparty/multipart/multipartpost.py' (Will Holcomb, 2006); the logic already relied on
    sqlmap's own helpers, so it now lives here as a first-class request handler.
    """

    handler_order = _urllib.request.HTTPHandler.handler_order - 10   # must run before the HTTP handler

    def http_request(self, request):
        data = request.data

        if isinstance(data, dict):
            files, variables = [], []

            try:
                for key, value in data.items():
                    if hasattr(value, "fileno") or hasattr(value, "file") or isinstance(value, io.IOBase):
                        files.append((key, value))
                    else:
                        variables.append((key, value))
            except TypeError:
                raise SqlmapDataException("not a valid non-string sequence or mapping object")

            if not files:
                data = _urllib.parse.urlencode(variables, DOSEQ)
            else:
                boundary, data = self.multipartEncode(variables, files)
                request.add_unredirected_header("Content-Type", "multipart/form-data; boundary=%s" % boundary)

            request.data = data

        # normalize bare LF to CRLF inside a multipart body (Reference: https://github.com/sqlmapproject/sqlmap/issues/4235)
        if request.data:
            for match in re.finditer(b"(?i)\\s*-{20,}\\w+(\\s+Content-Disposition[^\\n]+\\s+|\\-\\-\\s*)", request.data):
                part = match.group(0)
                if b'\r' not in part:
                    request.data = request.data.replace(part, part.replace(b'\n', b"\r\n"))

        return request

    def multipartEncode(self, variables, files, boundary=None):
        boundary = boundary or choose_boundary()
        buffer_ = b""

        for key, value in variables:
            if key is not None and value is not None:
                buffer_ += b"--%s\r\n" % getBytes(boundary)
                buffer_ += b"Content-Disposition: form-data; name=\"%s\"" % getBytes(key)
                buffer_ += b"\r\n\r\n" + getBytes(value) + b"\r\n"

        for key, fd in files:
            filename = fd.name.split('/')[-1] if '/' in fd.name else fd.name.split('\\')[-1]
            try:
                contentType = mimetypes.guess_type(filename)[0] or b"application/octet-stream"
            except Exception:
                # Reference: http://bugs.python.org/issue9291
                contentType = b"application/octet-stream"
            buffer_ += b"--%s\r\n" % getBytes(boundary)
            buffer_ += b"Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n" % (getBytes(key), getBytes(filename))
            buffer_ += b"Content-Type: %s\r\n" % getBytes(contentType)
            fd.seek(0)
            buffer_ += b"\r\n%s\r\n" % fd.read()

        buffer_ += b"--%s--\r\n\r\n" % getBytes(boundary)

        return boundary, getBytes(buffer_)

    https_request = http_request
