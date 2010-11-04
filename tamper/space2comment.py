#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

def tamper(value):
    """
    Replaces ' ' with '/**/'
    Example: 'SELECT id FROM users' becomes 'SELECT/**/id/**/FROM/**/users'
    """

    retVal = value

    if value:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(value)):
            if not firstspace:
                if value[i].isspace():
                    firstspace = True
                    retVal += "/**/"
                    continue

            elif value[i] == '\'':
                quote = not quote

            elif value[i] == '"':
                doublequote = not doublequote

            elif value[i]==" " and not doublequote and not quote:
                retVal += "/**/"
                continue

            retVal += value[i]

    return retVal

