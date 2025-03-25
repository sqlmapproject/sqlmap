#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces greater than operator ('>') with 'GREATEST' counterpart

    Tested against:
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 8.4, 9.0

    Notes:
        * Useful to bypass weak and bespoke web application firewalls that
          filter the greater than character
        * The GREATEST clause is a widespread SQL command. Hence, this
          tamper script should work against majority of databases

    >>> tamper('1 AND A > B')
    '1 AND GREATEST(A,B+1)=A'
    """

    retVal = payload

    if payload:
        match = re.search(r"(?i)(\b(AND|OR)\b\s+)([^>]+?)\s*>\s*(\w+|'[^']+')", payload)

        if match:
            _ = "%sGREATEST(%s,%s+1)=%s" % (match.group(1), match.group(3), match.group(4), match.group(3))
            retVal = retVal.replace(match.group(0), _)

    return retVal
