#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import string

from lib.core.enums import PRIORITY
from lib.core.common import singleTimeWarnMessage

__priority__ = PRIORITY.LOWEST

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against ASP or ASP.NET web applications" % os.path.basename(__file__).split(".")[0])

def tamper(payload, **kwargs):
    """
    Unicode-url-encodes non-encoded characters in a given payload (not
    processing already encoded)

    Requirement:
        * ASP
        * ASP.NET

    Tested against:
        * Microsoft SQL Server 2000
        * Microsoft SQL Server 2005
        * MySQL 5.1.56
        * PostgreSQL 9.0.3

    Notes:
        * Useful to bypass weak web application firewalls that do not
          unicode url-decode the request before processing it through their
          ruleset

    >>> tamper('SELECT FIELD%20FROM TABLE')
    '%u0053%u0045%u004C%u0045%u0043%u0054%u0020%u0046%u0049%u0045%u004C%u0044%u0020%u0046%u0052%u004F%u004D%u0020%u0054%u0041%u0042%u004C%u0045'
    """

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += "%%u00%s" % payload[i + 1:i + 3]
                i += 3
            else:
                retVal += '%%u%.4X' % ord(payload[i])
                i += 1

    return retVal
