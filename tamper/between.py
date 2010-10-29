#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

def tamper(value):
    """
    Replaces '>' with 'NOT BETWEEN 0 AND #'
    Example: 'A > B' becomes 'A NOT BETWEEN 0 AND B'
    """

    retVal = value

    if value:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(value)):
            if not firstspace:

                if value[i].isspace():
                    firstspace = True
                    retVal += " "
                    continue

            elif value[i] == '\'':
                quote = not quote

            elif value[i] == '"':
                doublequote = not doublequote

            elif value[i] == ">" and not doublequote and not quote:
                retVal += " " if i > 0 and not value[i-1].isspace() else ""
                retVal += "NOT BETWEEN 0 AND"
                retVal += " " if i < len(value) - 1 and not value[i+1].isspace() else ""

                continue

            retVal += value[i]

    return retVal

