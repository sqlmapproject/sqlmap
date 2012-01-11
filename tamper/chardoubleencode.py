#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload):
    """
    Double url-encodes all characters in a given payload (not processing
    already encoded)

    Example:
        * Input: SELECT FIELD FROM%20TABLE
        * Output: %2553%2545%254c%2545%2543%2554%2520%2546%2549%2545%254c%2544%2520%2546%2552%254f%254d%2520%2554%2541%2542%254c%2545

    Notes:
        * Useful to bypass some weak web application firewalls that do not
          double url-decode the request before processing it through their
          ruleset
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
                retVal += '%%25%X' % ord(payload[i])
                i += 1

    return retVal
