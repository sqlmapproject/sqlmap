#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def tamper(payload, **kwargs):
    """
    Unicode-escapes non-encoded characters in a given payload (not processing already encoded) (e.g. SELECT -> \u0053\u0045\u004C\u0045\u0043\u0054)

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
                ordinal = ord(payload[i])
                if ordinal > 0xFFFF:
                    # non-BMP: emit a UTF-16 surrogate pair (a bare 5-hex '\uXXXXX' is invalid)
                    ordinal -= 0x10000
                    retVal += "\\u%04X\\u%04X" % (0xD800 + (ordinal >> 10), 0xDC00 + (ordinal & 0x3FF))
                else:
                    retVal += "\\u%04X" % ordinal
                i += 1

    return retVal
