#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces instances of UNION ALL SELECT with UNION SELECT counterpart

    >>> tamper('-1 UNION ALL SELECT')
    '-1 UNION SELECT'
    """

    return re.sub(r"(?i)UNION\s+ALL\s+SELECT", "UNION SELECT", payload) if payload else payload
