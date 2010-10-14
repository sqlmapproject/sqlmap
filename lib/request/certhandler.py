#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import httplib
import urllib2
import sys

from lib.core.data import conf

class HTTPSCertAuthHandler(urllib2.HTTPSHandler):
    def __init__(self, key_file, cert_file):
        urllib2.HTTPSHandler.__init__(self)
        self.key_file = key_file
        self.cert_file = cert_file

    def https_open(self, req):
        return self.do_open(self.getConnection, req)

    def getConnection(self, host):
        if sys.version_info >= (2,6):
            retVal = httplib.HTTPSConnection(host, key_file=self.key_file, cert_file=self.cert_file, timeout=conf.timeout)
        else:
            retVal = httplib.HTTPSConnection(host, key_file=self.key_file, cert_file=self.cert_file)
        return retVal
