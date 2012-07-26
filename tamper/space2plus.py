#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, headers):
    """
    Replaces space character (' ') with plus ('+')

    Example:
        * Input: SELECT id FROM users
        * Output: SELECT+id+FROM+users

    Notes:
        * Is this any useful? The plus get's url-encoded by sqlmap engine
          invalidating the query afterwards
        * This tamper script works against all databases
    """

    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += "+"
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i]==" " and not doublequote and not quote:
                retVal += "+"
                continue

            retVal += payload[i]

    return retVal, headers
