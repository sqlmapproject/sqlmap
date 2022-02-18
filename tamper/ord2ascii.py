#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces ORD() occurences with equivalent ASCII() calls 

    >>> tamper("ORD('42')")
    "ASCII('42')"
    """

    retVal = payload

    if payload:
        retVal = re.sub(r"(?i)\bORD\(\b", "ASCII(", payload)

    return retVal
