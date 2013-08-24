#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import base64

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def decode(page, headers, code, **kwargs):
    """
    Base64 decode a response
    """

    try:
        retval = base64.b64decode(page)
    except TypeError: # Decode error
        retval = page

    return retval, headers, code
