#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import httplib
import socket
import urllib
import urllib2

from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.settings import PYVERSION

if PYVERSION >= "2.6":
    import ssl

class ProxyHTTPConnection(httplib.HTTPConnection):
    _ports = {"http" : 80, "https" : 443}

    def request(self, method, url, body=None, headers={}):
        # Request is called before connect, so can interpret url and get
        # real host/port to be used to make CONNECT request to proxy
        proto, rest = urllib.splittype(url)

        if proto is None:
            raise ValueError, "unknown URL type: %s" % url

        # Get host
        host, rest = urllib.splithost(rest)

        # Try to get port
        host, port = urllib.splitport(host)

        # If port is not defined try to get from proto
        if port is None:
            try:
                port = self._ports[proto]
            except KeyError:
                raise ValueError, "unknown protocol for: %s" % url

        self._real_host = host
        self._real_port = int(port)

        httplib.HTTPConnection.request(self, method, rest, body, headers)

    def connect(self):
        httplib.HTTPConnection.connect(self)

        # Send proxy CONNECT request
        self.send("CONNECT %s:%d HTTP/1.0\r\n\r\n" % (self._real_host, self._real_port))

        # Expect a HTTP/1.0 200 Connection established
        response = self.response_class(self.sock, strict=self.strict, method=self._method)
        (version, code, message) = response._read_status()

        # Probably here we can handle auth requests...
        if code != 200:
            # Proxy returned and error, abort connection, and raise exception
            self.close()

            raise socket.error, "Proxy connection failed: %d %s" % (code, message.strip())

        # Eat up header block from proxy
        while True:
            # Should not use directly fp probably
            line = response.fp.readline()

            if line == "\r\n":
                break

class ProxyHTTPSConnection(ProxyHTTPConnection):
    default_port = 443

    def __init__(self, host, port=None, key_file=None, cert_file=None, strict=None, timeout=None):
        ProxyHTTPConnection.__init__(self, host, port)
        self.key_file = key_file
        self.cert_file = cert_file

    def connect(self):
        ProxyHTTPConnection.connect(self)

        # Make the sock ssl-aware
        if PYVERSION >= "2.6":
            sslobj    = ssl.wrap_socket(self.sock, self.key_file, self.cert_file)
            self.sock = sslobj
        else:
            sslobj    = socket.ssl(self.sock, self.key_file, self.cert_file)
            self.sock = httplib.FakeSocket(self.sock, sslobj)

class ProxyHTTPHandler(urllib2.HTTPHandler):
    def __init__(self, proxy=None, debuglevel=0):
        self.proxy = proxy

        urllib2.HTTPHandler.__init__(self, debuglevel)

    def do_open(self, http_class, req):
        if self.proxy is not None:
            req.set_proxy(self.proxy, "http")

        return urllib2.HTTPHandler.do_open(self, ProxyHTTPConnection, req)

if PYVERSION >= "2.6":
    class ProxyHTTPSHandler(urllib2.HTTPSHandler):
        def __init__(self, proxy=None, debuglevel=0):
            self.proxy = proxy

            urllib2.HTTPSHandler.__init__(self, debuglevel)

        def do_open(self, http_class, req):
            if self.proxy is not None:
                req.set_proxy(self.proxy, "https")

            return urllib2.HTTPSHandler.do_open(self, ProxyHTTPSConnection, req)
else:
    class ProxyHTTPSHandler:
        def __init__(self, *args, **kwargs):
            errMsg = "unsupported feature on versions of Python before 2.6"
            raise sqlmapUnsupportedFeatureException, errMsg
