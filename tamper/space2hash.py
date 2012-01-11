#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import random
import string

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload):
    """
    Replaces space character (' ') with a pound character ('#') followed by
    a random string and a new line ('\n')

    Example:
        * Input: 1 AND 9227=9227
        * Output: 1%23PTTmJopxdWJ%0AAND%23cWfcVRPV%0A9227=9227

    Requirement:
        * MySQL

    Tested against:
        * MySQL 4.0, 5.0

    Notes:
        * Useful to bypass several web application firewalls
        * Used during the ModSecurity SQL injection challenge,
          http://modsecurity.org/demo/challenge.html
    """

    retVal = ""

    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                randomStr = ''.join(random.choice(string.ascii_uppercase + string.lowercase) for _ in xrange(random.randint(6, 12)))
                retVal += "%%23%s%%0A" % randomStr
            elif payload[i] == '#' or payload[i:i+3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal
