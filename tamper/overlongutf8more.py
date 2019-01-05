#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Converts all characters in a given payload to overlong UTF8 (not processing already encoded) (e.g. SELECT -> %C1%93%C1%85%C1%8C%C1%85%C1%83%C1%94)

    Reference:
        * https://www.acunetix.com/vulnerabilities/unicode-transformation-issues/
        * https://www.thecodingforums.com/threads/newbie-question-about-character-encoding-what-does-0xc0-0x8a-have-in-common-with-0xe0-0x80-0x8a.170201/

    >>> tamper('SELECT FIELD FROM TABLE WHERE 2>1')
    '%C1%93%C1%85%C1%8C%C1%85%C1%83%C1%94%C0%A0%C1%86%C1%89%C1%85%C1%8C%C1%84%C0%A0%C1%86%C1%92%C1%8F%C1%8D%C0%A0%C1%94%C1%81%C1%82%C1%8C%C1%85%C0%A0%C1%97%C1%88%C1%85%C1%92%C1%85%C0%A0%C0%B2%C0%BE%C0%B1'
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
                retVal += "%%%.2X%%%.2X" % (0xc0 + (ord(payload[i]) >> 6), 0x80 + (ord(payload[i]) & 0x3f))
                i += 1

    return retVal
