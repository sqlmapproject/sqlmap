#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload, **kwargs):
    """
    Replaces space character (' ') with a dash comment ('--') followed by
    a new line ('\n')

    Requirement:
        * MySQL
        * MSSQL

    Tested against:

    Notes:
        * Useful to bypass several web application firewalls.

    >>> tamper('1 AND 9227=9227')
    '1--%0AAND--%0A9227=9227'
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
