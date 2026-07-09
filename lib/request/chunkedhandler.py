#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import conf
from lib.core.enums import HTTP_HEADER
from thirdparty.six.moves import urllib as _urllib

class ChunkedHandler(_urllib.request.HTTPHandler):
    """
    Ensures that HTTPHandler is working properly in case of Chunked Transfer-Encoding
    """

    # Note: run after urllib's own request munging so that a Content-Length it may have added (the
    # HTTPS path on Python 2 adds one unconditionally) is present to be stripped when '--chunked'
    handler_order = _urllib.request.HTTPHandler.handler_order + 1

    def _http_request(self, request):
        host = request.get_host() if hasattr(request, "get_host") else request.host
        if not host:
            raise _urllib.error.URLError("no host given")

        if request.data is not None:  # POST
            data = request.data
            if not request.has_header(HTTP_HEADER.CONTENT_TYPE):
                request.add_unredirected_header(HTTP_HEADER.CONTENT_TYPE, "application/x-www-form-urlencoded")
            if conf.chunked:  # Content-Length must not accompany 'Transfer-Encoding: chunked'
                for store in (request.headers, request.unredirected_hdrs):
                    for name in [_ for _ in store if _.lower() == HTTP_HEADER.CONTENT_LENGTH.lower()]:
                        del store[name]
            elif not request.has_header(HTTP_HEADER.CONTENT_LENGTH):
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

    http_request = https_request = _http_request
