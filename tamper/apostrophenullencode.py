#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces apostrophe character with its illegal double unicode counterpart

    >>> tamper("1 AND '1'='1")
    '1 AND %00%271%00%27=%00%271'
    """

    return payload.replace('\'', "%00%27") if payload else payload
