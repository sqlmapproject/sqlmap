#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from thirdparty.six.moves import urllib as _urllib

class MethodRequest(_urllib.request.Request):
    """
    Used to create HEAD/PUT/DELETE/... requests with urllib
    """

    def set_method(self, method):
        self.method = method.upper()

    def get_method(self):
        return getattr(self, 'method', _urllib.request.Request.get_method(self))
