#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Converts all (non-alphanum) characters in a given payload to overlong UTF8 (not processing already encoded) (e.g. ' -> %C0%A7)

    Reference:
        * https://www.acunetix.com/vulnerabilities/unicode-transformation-issues/
        * https://www.thecodingforums.com/threads/newbie-question-about-character-encoding-what-does-0xc0-0x8a-have-in-common-with-0xe0-0x80-0x8a.170201/

    >>> tamper('SELECT FIELD FROM TABLE WHERE 2>1')
    'SELECT%C0%A0FIELD%C0%A0FROM%C0%A0TABLE%C0%A0WHERE%C0%A02%C0%BE1'
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
                    ordinal = ord(payload[i])
                    if ordinal <= 0x7FF:
                        retVal += "%%%.2X%%%.2X" % (0xc0 + (ordinal >> 6), 0x80 + (ordinal & 0x3f))
                    else:
                        # the 2-byte overlong form can't hold code points > U+07FF; fall back to real UTF-8
                        retVal += "".join("%%%.2X" % _ for _ in bytearray(payload[i].encode("utf8")))
                else:
                    retVal += payload[i]
                i += 1

    return retVal
