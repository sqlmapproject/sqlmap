#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import httplib
import urllib2

from lib.core.data import conf

class HTTPSPKIAuthHandler(urllib2.HTTPSHandler):
    def __init__(self, key_file):
        urllib2.HTTPSHandler.__init__(self)
        self.key_file = key_file

    def https_open(self, req):
        return self.do_open(self.getConnection, req)

    def getConnection(self, host, timeout=None):
        return httplib.HTTPSConnection(host, key_file=self.key_file, timeout=conf.timeout)
