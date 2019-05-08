#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import conf
from thirdparty.six.moves import urllib as _urllib

class ChunkedHandler(_urllib.request.HTTPHandler):
    """
    Ensures that HTTPHandler is working properly in case of Chunked Transfer-Encoding
    """

    def _http_request(self, request):
        host = request.get_host()
        if not host:
            raise _urllib.error.URLError("no host given")

        if request.has_data():  # POST
            data = request.get_data()
            if not request.has_header("Content-type"):
                request.add_unredirected_header(
                    "Content-type",
                    "application/x-www-form-urlencoded")
            if not request.has_header("Content-length") and not conf.chunked:
                request.add_unredirected_header(
                    "Content-length", "%d" % len(data))

        sel_host = host
        if request.has_proxy():
            sel_host = _urllib.parse.urlsplit(request.get_selector()).netloc

        if not request.has_header("Host"):
            request.add_unredirected_header("Host", sel_host)
        for name, value in self.parent.addheaders:
            name = name.capitalize()
            if not request.has_header(name):
                request.add_unredirected_header(name, value)
        return request

    http_request = _http_request
