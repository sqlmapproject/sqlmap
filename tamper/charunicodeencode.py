#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload):
    """
    Unicode-url-encodes non-encoded characters in a given payload (not
    processing already encoded)

    Example:
        * Input: SELECT FIELD%20FROM TABLE
        * Output: %u0053%u0045%u004c%u0045%u0043%u0054%u0020%u0046%u0049%u0045%u004c%u0044%u0020%u0046%u0052%u004f%u004d%u0020%u0054%u0041%u0042%u004c%u0045'

    Notes:
        * Does this ever work?
    """

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i+1] in string.hexdigits and payload[i+2] in string.hexdigits:
                retVal += "%%u00%s" % payload[i+1:i+3]
                i += 3
            else:
                retVal += '%%u00%X' % ord(payload[i])
                i += 1

    return retVal
