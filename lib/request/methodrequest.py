#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import urllib2


class MethodRequest(urllib2.Request):
    '''
    Used to create HEAD/PUT/DELETE/... requests with urllib2
    '''

    def set_method(self, method):
        self.method = method.upper()

    def get_method(self):
        return getattr(self, 'method', urllib2.Request.get_method(self))
