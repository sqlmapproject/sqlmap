#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.compat import xrange
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces space character (' ') with a tab character ('\t')

    Tested against:
        * Microsoft SQL Server 2005, 2019
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 9.0
        * SQLite 3

    Notes:
        * Useful to bypass WAFs that block %20 (URL-encoded space)
          but allow %09 (URL-encoded tab), which is valid whitespace
          in most SQL engines
        * This tamper script should work against all (?) databases

    >>> tamper('SELECT id FROM users')
    'SELECT\tid\tFROM\tusers'
    >>> tamper('1 AND 1=1')
    '1\tAND\t1=1'
    >>> tamper("SELECT * FROM users WHERE id='1 2'")
    "SELECT\t*\tFROM\tusers\tWHERE\tid='1 2'"
    """

    if not payload:
        return payload

    if not payload:
        return payload

    retVal = ""

    if payload:
        quote, doublequote = False, False

        for i in xrange(len(payload)):
            if payload[i] == '\'' and (i == 0 or payload[i - 1] != '\\'):
                quote = not quote
            elif payload[i] == '"' and (i == 0 or payload[i - 1] != '\\'):
                doublequote = not doublequote

            if not quote and not doublequote and payload[i] == ' ':
                retVal += '\t'
            else:
                retVal += payload[i]

    return retVal
