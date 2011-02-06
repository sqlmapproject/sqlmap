#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import random

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def tamper(value):
    """
    Replaces ' ' with a random blank char from a set ('\r', '\n', '\t')
    Example: 'SELECT id FROM users' becomes 'SELECT\rid\tFROM\nusers'
    """

    blanks = ['\r', '\n', '\t']
    retVal = value

    if value:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(value)):
            if not firstspace:
                if value[i].isspace():
                    firstspace = True
                    retVal += random.choice(blanks)
                    continue

            elif value[i] == '\'':
                quote = not quote

            elif value[i] == '"':
                doublequote = not doublequote

            elif value[i]==" " and not doublequote and not quote:
                retVal += random.choice(blanks)
                continue

            retVal += value[i]

    return retVal

