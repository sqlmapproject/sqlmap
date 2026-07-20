#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import string

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against ASP or ASP.NET web applications" % os.path.basename(__file__).split(".")[0])

def tamper(payload, **kwargs):
    """
    Unicode-URL-encodes all characters in a given payload (not processing already encoded) (e.g. SELECT -> %u0053%u0045%u004C%u0045%u0043%u0054)

    Requirement:
        * ASP
        * ASP.NET

    Tested against:
        * Microsoft SQL Server 2000
        * Microsoft SQL Server 2005
        * MySQL 5.1.56
        * PostgreSQL 9.0.3

    Notes:
        * Useful to bypass weak web application firewalls that do not unicode URL-decode the request before processing it through their ruleset

    >>> tamper('SELECT FIELD%20FROM TABLE')
    '%u0053%u0045%u004C%u0045%u0043%u0054%u0020%u0046%u0049%u0045%u004C%u0044%u0020%u0046%u0052%u004F%u004D%u0020%u0054%u0041%u0042%u004C%u0045'
    >>> tamper(u'\U0001F600') == '%uD83D%uDE00'
    True
    """

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += "%%u00%s" % payload[i + 1:i + 3]
                i += 3
            else:
                ordinal = ord(payload[i])
                if ordinal > 0xFFFF:
                    # Note: %uXXXX is UTF-16 based, so a non-BMP char (e.g. an emoji) must be emitted
                    # as a surrogate pair - '%.4X' alone would produce an invalid 5-digit '%uXXXXX'
                    ordinal -= 0x10000
                    retVal += "%%u%04X%%u%04X" % (0xD800 + (ordinal >> 10), 0xDC00 + (ordinal & 0x3FF))
                else:
                    retVal += '%%u%.4X' % ordinal
                i += 1

    return retVal
