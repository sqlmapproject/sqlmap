#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, headers):
    """
    Replaces apostrophe character with its illegal double unicode counterpart

    Example:
        * Input: AND '1'='1'
        * Output: AND %00%271%00%27=%00%271%00%27
    """

    return payload.replace('\'', "%00%27") if payload else payload, headers
