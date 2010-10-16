#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import string

from lib.core.exception import sqlmapUnsupportedFeatureException

def tamper(place, value):
    """
    Replaces value with urlencode of non-encoded chars in value
    Example: 'SELECT%20FIELD%20FROM%20TABLE' becomes '%53%45%4c%45%43%54%20%46%49%45%4c%44%20%46%52%4f%4d%20%54%41%42%4c%45'
    """

    retVal = value

    if value:
        if place != "URI":
            retVal = ""
            i = 0

            while i < len(value):
                if value[i] == '%' and (i < len(value) - 2) and value[i+1] in string.hexdigits and value[i+2] in string.hexdigits:
                    retVal += value[i:i+3]
                    i += 3
                else:
                    retVal += '%%%X' % ord(value[i])
                    i += 1
        else:
            raise sqlmapUnsupportedFeatureException, "can't use tamper script '%s' with 'URI' type injections" % __name__

    return retVal
