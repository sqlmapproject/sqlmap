#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.convert import urlencode
from lib.core.exception import sqlmapUnsupportedFeatureException

def tamper(place, value):
    """
    Replaces value with urlencode(value)
    Example: 'SELECT%20FIELD%20FROM%20TABLE' becomes 'SELECT%25%20FIELD%25%20FROM%25%20TABLE'
    """

    if value:
        if place != "URI":
            value = urlencode(value, convall=True)
        else:
            raise sqlmapUnsupportedFeatureException, "can't use tamper script '%s' with 'URI' type injections" % __name__

    return value
