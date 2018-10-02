#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re
import urllib

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces AND and OR logical operators with their symbolic counterparts (&& and ||)

    >>> tamper("1 AND '1'='1")
    "1 %26%26 '1'='1"
    """

    retVal = payload

    if payload:
        retVal = re.sub(r"(?i)\bAND\b", urllib.quote("&&"), re.sub(r"(?i)\bOR\b", urllib.quote("||"), payload))

    return retVal
