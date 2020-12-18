#!/usr/bin/env python

"""
02/2006 Will Holcomb <wholcomb@gmail.com>

Reference: http://odin.himinbi.org/MultipartPostHandler.py

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

import io
import mimetypes
import os
import re
import stat
import sys

from lib.core.compat import choose_boundary
from lib.core.convert import getBytes
from lib.core.convert import getText
from lib.core.exception import SqlmapDataException
from thirdparty.six.moves import urllib as _urllib

# Controls how sequences are uncoded. If true, elements may be given
# multiple values by assigning a sequence.
doseq = 1


class MultipartPostHandler(_urllib.request.BaseHandler):
    handler_order = _urllib.request.HTTPHandler.handler_order - 10 # needs to run first

    def http_request(self, request):
        data = request.data

        if isinstance(data, dict):
            v_files = []
            v_vars = []

            try:
                for(key, value) in data.items():
                    if hasattr(value, "fileno") or hasattr(value, "file") or isinstance(value, io.IOBase):
                        v_files.append((key, value))
                    else:
                        v_vars.append((key, value))
            except TypeError:
                systype, value, traceback = sys.exc_info()
                raise SqlmapDataException("not a valid non-string sequence or mapping object '%s'" % traceback)

            if len(v_files) == 0:
                data = _urllib.parse.urlencode(v_vars, doseq)
            else:
                boundary, data = self.multipart_encode(v_vars, v_files)
                contenttype = "multipart/form-data; boundary=%s" % boundary
                #if (request.has_header("Content-Type") and request.get_header("Content-Type").find("multipart/form-data") != 0):
                #    print "Replacing %s with %s" % (request.get_header("content-type"), "multipart/form-data")
                request.add_unredirected_header("Content-Type", contenttype)

            request.data = data

        # NOTE: https://github.com/sqlmapproject/sqlmap/issues/4235
        if request.data:
            for match in re.finditer(b"(?i)\\s*-{20,}\\w+(\\s+Content-Disposition[^\\n]+\\s+|\\-\\-\\s*)", request.data):
                part = match.group(0)
                if b'\r' not in part:
                    request.data = request.data.replace(part, part.replace(b'\n', b"\r\n"))

        return request

    def multipart_encode(self, vars, files, boundary=None, buf=None):
        if boundary is None:
            boundary = choose_boundary()

        if buf is None:
            buf = b""

        for (key, value) in vars:
            if key is not None and value is not None:
                buf += b"--%s\r\n" % getBytes(boundary)
                buf += b"Content-Disposition: form-data; name=\"%s\"" % getBytes(key)
                buf += b"\r\n\r\n" + getBytes(value) + b"\r\n"

        for (key, fd) in files:
            file_size = fd.len if hasattr(fd, "len") else os.fstat(fd.fileno())[stat.ST_SIZE]
            filename = fd.name.split("/")[-1] if "/" in fd.name else fd.name.split("\\")[-1]
            try:
                contenttype = mimetypes.guess_type(filename)[0] or b"application/octet-stream"
            except:
                # Reference: http://bugs.python.org/issue9291
                contenttype = b"application/octet-stream"
            buf += b"--%s\r\n" % getBytes(boundary)
            buf += b"Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n" % (getBytes(key), getBytes(filename))
            buf += b"Content-Type: %s\r\n" % getBytes(contenttype)
            # buf += b"Content-Length: %s\r\n" % file_size
            fd.seek(0)

            buf += b"\r\n%s\r\n" % fd.read()

        buf += b"--%s--\r\n\r\n" % getBytes(boundary)
        buf = getBytes(buf)

        return boundary, buf

    https_request = http_request
