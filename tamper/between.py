#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, headers=None):
    """
    Replaces greater than operator ('>') with 'NOT BETWEEN 0 AND #'

    Example:
        * Input: 'A > B'
        * Output: 'A NOT BETWEEN 0 AND B'

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
    """

    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += " "
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == ">" and not doublequote and not quote:
                retVal += " " if i > 0 and not payload[i-1].isspace() else ""
                retVal += "NOT BETWEEN 0 AND"
                retVal += " " if i < len(payload) - 1 and not payload[i+1:i+2].isspace() else ""

                continue

            retVal += payload[i]

    return retVal
