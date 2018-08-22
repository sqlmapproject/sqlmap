#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import httplib
import urllib2

from lib.core.data import conf
from lib.core.common import getSafeExString
from lib.core.exception import SqlmapConnectionException

class HTTPSPKIAuthHandler(urllib2.HTTPSHandler):
    def __init__(self, auth_file):
        urllib2.HTTPSHandler.__init__(self)
        self.auth_file = auth_file

    def https_open(self, req):
        return self.do_open(self.getConnection, req)

    def getConnection(self, host, timeout=None):
        try:
            # Reference: https://docs.python.org/2/library/ssl.html#ssl.SSLContext.load_cert_chain
            return httplib.HTTPSConnection(host, cert_file=self.auth_file, key_file=self.auth_file, timeout=conf.timeout)
        except IOError, ex:
            errMsg = "error occurred while using key "
            errMsg += "file '%s' ('%s')" % (self.auth_file, getSafeExString(ex))
            raise SqlmapConnectionException(errMsg)
