#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import conf
from lib.core.enums import HTTP_HEADER
from thirdparty.six.moves import urllib as _urllib

class ChunkedHandler(_urllib.request.HTTPHandler):
    """
    Ensures that HTTPHandler is working properly in case of Chunked Transfer-Encoding
    """

    def _http_request(self, request):
        host = request.get_host() if hasattr(request, "get_host") else request.host
        if not host:
            raise _urllib.error.URLError("no host given")

        if request.data is not None:  # POST
            data = request.data
            if not request.has_header(HTTP_HEADER.CONTENT_TYPE):
                request.add_unredirected_header(HTTP_HEADER.CONTENT_TYPE, "application/x-www-form-urlencoded")
            if not request.has_header(HTTP_HEADER.CONTENT_LENGTH) and not conf.chunked:
                request.add_unredirected_header(HTTP_HEADER.CONTENT_LENGTH, "%d" % len(data))

        sel_host = host
        if request.has_proxy():
            sel_host = _urllib.parse.urlsplit(request.get_selector()).netloc

        if not request.has_header(HTTP_HEADER.HOST):
            request.add_unredirected_header(HTTP_HEADER.HOST, sel_host)
        for name, value in self.parent.addheaders:
            name = name.capitalize()
            if not request.has_header(name):
                request.add_unredirected_header(name, value)
        return request

    http_request = _http_request
