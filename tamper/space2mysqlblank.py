#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os
import random

from lib.core.common import singleTimeWarnMessage
from lib.core.compat import xrange
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload, **kwargs):
    """
    Replaces (MySQL) instances of space character (' ') with a random blank character from a valid set of alternate characters

    Requirement:
        * MySQL

    Tested against:
        * MySQL 5.1

    Notes:
        * Useful to bypass several web application firewalls

    >>> random.seed(0)
    >>> tamper('SELECT id FROM users')
    'SELECT%A0id%0CFROM%0Dusers'
    """

    # ASCII table:
    #   TAB     09      horizontal TAB
    #   LF      0A      new line
    #   FF      0C      new page
    #   CR      0D      carriage return
    #   VT      0B      vertical TAB        (MySQL and Microsoft SQL Server only)
    #           A0      non-breaking space
    blanks = ('%09', '%0A', '%0C', '%0D', '%0B', '%A0')
    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += random.choice(blanks)
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == " " and not doublequote and not quote:
                retVal += random.choice(blanks)
                continue

            retVal += payload[i]

    return retVal
