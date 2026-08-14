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
    Replaces greater than operator ('>') with 'LEAST' counterpart

    Requirement:
        * MySQL
        * MariaDB
        * PostgreSQL
        * Microsoft SQL Server >= 2022
        * Oracle

    Tested against:
        * MySQL 8.4.9
        * MariaDB 11.8.8
        * PostgreSQL 16.11
        * Microsoft SQL Server 2022
        * Oracle 23ai

    Notes:
        * Useful to bypass weak and bespoke web application firewalls that
          filter the greater than character
        * NOT usable against SQLite, which has no LEAST() (it overloads
          MIN() for the multi-argument case instead). Microsoft SQL Server
          only gained LEAST() in 2022

    >>> tamper('1 AND A > B')
    '1 AND LEAST(A,B+1)=B+1'
    """

    retVal = payload

    if payload:
        match = re.search(r"(?i)(\b(AND|OR)\b\s+)([^>]+?)\s*>\s*(\w+|'[^']+')", payload)

        if match:
            _ = "%sLEAST(%s,%s+1)=%s+1" % (match.group(1), match.group(3), match.group(4), match.group(4))
            retVal = retVal.replace(match.group(0), _)

    return retVal
