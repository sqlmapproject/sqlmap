#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import httplib
import socket
import urllib2

from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException

ssl = None
try:
    import ssl as _ssl
    ssl = _ssl
except ImportError:
    pass

_protocols = [ssl.PROTOCOL_SSLv3, ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_SSLv23]

class HTTPSConnection(httplib.HTTPSConnection):
    """
    Connection class that enables usage of newer SSL protocols.

    Reference: http://bugs.python.org/msg128686
    """

    def __init__(self, *args, **kwargs):
        httplib.HTTPSConnection.__init__(self, *args, **kwargs)

    def connect(self):
        def create_sock():
            sock = socket.create_connection((self.host, self.port), self.timeout)
            if getattr(self, "_tunnel_host", None):
                self.sock = sock
                self._tunnel()
            return sock

        success = False

        for protocol in _protocols:
            try:
                sock = create_sock()
                _ = ssl.wrap_socket(sock, self.key_file, self.cert_file, ssl_version=protocol)
                if _:
                    success = True
                    self.sock = _
                    _protocols.remove(protocol)
                    _protocols.insert(0, protocol)
                    break
                else:
                    sock.close()
            except ssl.SSLError, errMsg:
                logger.debug("SSL connection error occurred ('%s')" % errMsg)

        if not success:
            raise SqlmapConnectionException("can't establish SSL connection")

class HTTPSHandler(urllib2.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(HTTPSConnection if ssl else httplib.HTTPSConnection, req)

# Bug fix (http://bugs.python.org/issue17849)

def _(self, *args):
    return self._readline()

httplib.LineAndFileWrapper._readline = httplib.LineAndFileWrapper.readline
httplib.LineAndFileWrapper.readline = _
