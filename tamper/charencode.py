#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, headers):
    """
    Url-encodes all characters in a given payload (not processing already
    encoded)

    Example:
        * Input: SELECT FIELD FROM%20TABLE
        * Output: %53%45%4c%45%43%54%20%46%49%45%4c%44%20%46%52%4f%4d%20%54%41%42%4c%45

    Tested against:
        * Microsoft SQL Server 2005
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 8.4, 9.0

    Notes:
        * Useful to bypass very weak web application firewalls that do not
          url-decode the request before processing it through their ruleset
        * The web server will anyway pass the url-decoded version behind,
          hence it should work against any DBMS
    """

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i+1:i+2] in string.hexdigits and payload[i+2:i+3] in string.hexdigits:
                retVal += payload[i:i+3]
                i += 3
            else:
                retVal += '%%%.2X' % ord(payload[i])
                i += 1

    return retVal, headers
