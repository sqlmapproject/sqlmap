#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def tamper(payload):
    """
    Appends encoded null byte character at the end of payload
    Example: "AND 1=1" becomes "AND 1=1%00"
    Reference: http://projects.webappsec.org/w/page/13246949/Null-Byte-Injection
    """

    retVal = payload

    if payload:
        retVal = "%s%%00" % payload

    return retVal
