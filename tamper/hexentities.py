#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    HTML encode in hexadecimal (using code points) all characters (e.g. ' -> &#x31;)

    >>> tamper("1' AND SLEEP(5)#")
    '&#x31;&#x27;&#x20;&#x41;&#x4e;&#x44;&#x20;&#x53;&#x4c;&#x45;&#x45;&#x50;&#x28;&#x35;&#x29;&#x23;'
    """

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            retVal += "&#x%s;" % format(ord(payload[i]), "x")
            i += 1

    return retVal
