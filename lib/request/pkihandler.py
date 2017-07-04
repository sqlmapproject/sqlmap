#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import httplib
import urllib2

from lib.core.data import conf

class HTTPSPKIAuthHandler(urllib2.HTTPSHandler):
    def __init__(self, auth_file):
        urllib2.HTTPSHandler.__init__(self)
        self.auth_file = auth_file

    def https_open(self, req):
        return self.do_open(self.getConnection, req)

    def getConnection(self, host, timeout=None):
        # Reference: https://docs.python.org/2/library/ssl.html#ssl.SSLContext.load_cert_chain
        return httplib.HTTPSConnection(host, cert_file=self.auth_file, key_file=self.auth_file, timeout=conf.timeout)
