#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def tamper(payload):
    """
    Replaces '>' with 'NOT BETWEEN 0 AND #'
    Example: 'A > B' becomes 'A NOT BETWEEN 0 AND B'
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
                retVal += " " if i < len(payload) - 1 and not payload[i+1].isspace() else ""

                continue

            retVal += payload[i]

    return retVal

