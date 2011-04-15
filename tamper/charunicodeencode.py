#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import string

from lib.core.enums import PRIORITY
from lib.core.exception import sqlmapUnsupportedFeatureException

__priority__ = PRIORITY.LOWEST

def tamper(payload):
    """
    Replaces payload with unicode-urlencode of non-encoded chars in payload (not processing already encoded)
    Example: 'SELECT FIELD%20FROM TABLE' becomes '%u0053%u0045%u004c%u0045%u0043%u0054%u0020%u0046%u0049%u0045%u004c%u0044%u0020%u0046%u0052%u004f%u004d%u0020%u0054%u0041%u0042%u004c%u0045'
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
