#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import base64

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload):
    """
    Base64 all characters in a given payload

    Example:
        * Input: 1' AND SLEEP(5)#
        * Output: MScgQU5EIFNMRUVQKDUpIw==
    """

    return base64.b64encode(payload) if payload else payload
