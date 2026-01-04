#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

ssl = None
try:
    import ssl as _ssl
    ssl = _ssl
except ImportError:
    pass

from lib.core.data import conf
from lib.core.common import getSafeExString
from lib.core.exception import SqlmapConnectionException
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import urllib as _urllib


class HTTPSPKIAuthHandler(_urllib.request.HTTPSHandler):
    def __init__(self, auth_file):
        _urllib.request.HTTPSHandler.__init__(self)
        self.auth_file = auth_file

    def https_open(self, req):
        return self.do_open(self.getConnection, req)

    def getConnection(self, host, timeout=None):
        if timeout is None:
            timeout = conf.timeout

        if not hasattr(_http_client, "HTTPSConnection"):
            raise SqlmapConnectionException("HTTPS support is not available in this Python build")

        try:
            if ssl and hasattr(ssl, "SSLContext") and hasattr(ssl, "create_default_context"):
                ctx = ssl.create_default_context()
                ctx.load_cert_chain(certfile=self.auth_file, keyfile=self.auth_file)
                try:
                    return _http_client.HTTPSConnection(host, timeout=timeout, context=ctx)
                except TypeError:
                    pass

            return _http_client.HTTPSConnection(host, cert_file=self.auth_file, key_file=self.auth_file, timeout=timeout)

        except (IOError, OSError) as ex:
            errMsg = "error occurred while using key "
            errMsg += "file '%s' ('%s')" % (self.auth_file, getSafeExString(ex))
            raise SqlmapConnectionException(errMsg)
