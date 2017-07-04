#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Converts all characters in a given payload (not processing already
    encoded)

    Reference: https://www.acunetix.com/vulnerabilities/unicode-transformation-issues/

    >>> tamper('SELECT FIELD FROM TABLE WHERE 2>1')
    'SELECT%C0%AAFIELD%C0%AAFROM%C0%AATABLE%C0%AAWHERE%C0%AA2%C0%BE1'
    """

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += payload[i:i + 3]
                i += 3
            else:
                if payload[i] not in (string.ascii_letters + string.digits):
                    retVal += "%%C0%%%.2X" % (0x8A | ord(payload[i]))
                else:
                    retVal += payload[i]
                i += 1

    return retVal
