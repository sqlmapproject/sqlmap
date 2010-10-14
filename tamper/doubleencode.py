#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.convert import urlencode
from lib.core.exception import sqlmapUnsupportedFeatureException

"""
Tampering value -> urlencode(value) (e.g., SELECT%20FIELD%20FROM%20TABLE -> SELECT%25%20FIELD%25%20FROM%25%20TABLE)
"""
def tamper(place, value):
    if value:
        if place != "URI":
            value = urlencode(value)
        else:
            raise sqlmapUnsupportedFeatureException, "can't use tampering module '%s' with 'URI' type injections" % __name__

    return value
