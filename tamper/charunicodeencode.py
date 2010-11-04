#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import string

from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.priority import PRIORITY

__priority__ = PRIORITY.LOWEST

def tamper(value):
    """
    Replaces value with unicode-urlencode of non-encoded chars in value
    Example: 'SELECT%20FIELD%20FROM%20TABLE' becomes '%u0053%u0045%u004c%u0045%u0043%u0054%u0020%u0046%u0049%u0045%u004c%u0044%u0020%u0046%u0052%u004f%u004d%u0020%u0054%u0041%u0042%u004c%u0045'
    """

    retVal = value

    if value:
        retVal = ""
        i = 0

        while i < len(value):
            if value[i] == '%' and (i < len(value) - 2) and value[i+1] in string.hexdigits and value[i+2] in string.hexdigits:
                retVal += "%%u00%s" % value[i+1:i+3]
                i += 3
            else:
                retVal += '%%u00%X' % ord(value[i])
                i += 1

    return retVal
