#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces greater than operator ('>') with 'SIGN' counterpart (e.g. SIGN((A)-(B))=1)

    Tested against:
        * MySQL 5
        * Oracle 11g
        * PostgreSQL 9
        * Microsoft SQL Server 2012

    Notes:
        * Useful to bypass filtering of comparison operators altogether (>, <,
          >=, <=), as SIGN() needs none of them - only subtraction and '='.
          sqlmap's blind inference always compares a numeric ordinal against an
          integer literal, so SIGN((A)-(B))=1 is an exact equivalent of A>B
          there (no NULL/decimal/date/collation/overflow concerns in that domain)

    >>> tamper('1 AND A > B')
    '1 AND SIGN((A)-(B))=1'
    """

    retVal = payload

    if payload:
        match = re.search(r"(?i)(\b(AND|OR)\b\s+)([^><]+?)\s*(?<![<>!])>(?!=)\s*(\w+|'[^']+')", payload)

        if match:
            _ = "%sSIGN((%s)-(%s))=1" % (match.group(1), match.group(3), match.group(4))
            retVal = retVal.replace(match.group(0), _)

    return retVal
