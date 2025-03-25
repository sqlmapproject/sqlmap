#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.convert import getText
from thirdparty.six.moves import urllib as _urllib

class MethodRequest(_urllib.request.Request):
    """
    Used to create HEAD/PUT/DELETE/... requests with urllib
    """

    def set_method(self, method):
        self.method = getText(method.upper())  # Dirty hack for Python3 (may it rot in hell!)

    def get_method(self):
        return getattr(self, 'method', _urllib.request.Request.get_method(self))
