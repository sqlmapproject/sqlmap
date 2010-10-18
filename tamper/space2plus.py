#!/usr/bin/env python

"""
$Id: space2comment.py 2035 2010-10-16 21:33:15Z inquisb $

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.convert import urldecode
from lib.core.convert import urlencode

def tamper(place, value):
    """
    Replaces ' ' with '/**/'
    Example: 'SELECT id FROM users' becomes 'SELECT+id+FROM+users'
    """

    retVal = value

    if value:
        if place != "URI":
            value = urldecode(value)

        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(value)):
            if not firstspace:
                if value[i].isspace():
                    firstspace = True
                    retVal += "+"
                    continue

            elif value[i] == '\'':
                quote = not quote

            elif value[i] == '"':
                doublequote = not doublequote

            elif value[i]==" " and not doublequote and not quote:
                retVal += "+"
                continue

            retVal += value[i]

        if place != "URI":
            retVal = urlencode(retVal)

    return retVal

