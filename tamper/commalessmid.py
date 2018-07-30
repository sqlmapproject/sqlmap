#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGH

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload, **kwargs):
    """
    Replaces (MySQL) instances like 'MID(A, B, C)' with 'MID(A FROM B FOR C)' counterpart

    Requirement:
        * MySQL

    Tested against:
        * MySQL 5.0 and 5.5

    >>> tamper('MID(VERSION(), 1, 1)')
    'MID(VERSION() FROM 1 FOR 1)'
    """

    retVal = payload

    warnMsg = "you should consider usage of switch '--no-cast' along with "
    warnMsg += "tamper script '%s'" % os.path.basename(__file__).split(".")[0]
    singleTimeWarnMessage(warnMsg)

    match = re.search(r"(?i)MID\((.+?)\s*,\s*(\d+)\s*\,\s*(\d+)\s*\)", payload or "")
    if match:
        retVal = retVal.replace(match.group(0), "MID(%s FROM %s FOR %s)" % (match.group(1), match.group(2), match.group(3)))

    return retVal
