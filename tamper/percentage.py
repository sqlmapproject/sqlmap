#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import string

from lib.core.enums import PRIORITY
from lib.core.common import singleTimeWarnMessage

__priority__ = PRIORITY.LOW

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against ASP web applications" % os.path.basename(__file__).split(".")[0])

def tamper(payload):
    """
    Adds a percentage sign ('%') infront of each character

    Example:
        * Input: SELECT FIELD FROM TABLE
        * Output: %S%E%L%E%C%T %F%I%E%L%D %F%R%O%M %T%A%B%L%E

    Requirement:
        * ASP

    Tested against:
        * Microsoft SQL Server 2000, 2005
        * MySQL 5.1.56, 5.5.11
        * PostgreSQL 9.0

    Notes:
        * Useful to bypass weak and bespoke web application firewalls
    """

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i+1:i+2] in string.hexdigits and payload[i+2:i+3] in string.hexdigits:
                retVal += payload[i:i+3]
                i += 3
            elif payload[i] != ' ':
                retVal += '%%%s' % payload[i]
                i += 1
            else:
                retVal += payload[i]
                i += 1

    return retVal
