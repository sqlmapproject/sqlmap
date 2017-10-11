#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def tamper(payload, **kwargs):
    """
    Unicode-escapes non-encoded characters in a given payload (not
    processing already encoded)

    Notes:
        * Useful to bypass weak filtering and/or WAFs in JSON contexes

    >>> tamper('SELECT FIELD FROM TABLE')
    '\\\\u0053\\\\u0045\\\\u004C\\\\u0045\\\\u0043\\\\u0054\\\\u0020\\\\u0046\\\\u0049\\\\u0045\\\\u004C\\\\u0044\\\\u0020\\\\u0046\\\\u0052\\\\u004F\\\\u004D\\\\u0020\\\\u0054\\\\u0041\\\\u0042\\\\u004C\\\\u0045'
    """

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += "\\u00%s" % payload[i + 1:i + 3]
                i += 3
            else:
                retVal += '\\u%.4X' % ord(payload[i])
                i += 1

    return retVal
