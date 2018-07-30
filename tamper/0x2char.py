#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces each (MySQL) 0x<hex> encoded string with equivalent CONCAT(CHAR(),...) counterpart

    Requirement:
        * MySQL

    Tested against:
        * MySQL 4, 5.0 and 5.5

    Notes:
        * Useful in cases when web application does the upper casing

    >>> tamper('SELECT 0xdeadbeef')
    'SELECT CONCAT(CHAR(222),CHAR(173),CHAR(190),CHAR(239))'
    """

    retVal = payload

    if payload:
        for match in re.finditer(r"\b0x([0-9a-f]+)\b", retVal):
            if len(match.group(1)) > 2:
                result = "CONCAT(%s)" % ','.join("CHAR(%d)" % ord(_) for _ in match.group(1).decode("hex"))
            else:
                result = "CHAR(%d)" % ord(match.group(1).decode("hex"))
            retVal = retVal.replace(match.group(0), result)

    return retVal
