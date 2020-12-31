#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload, **kwargs):
    """
    Replaces instances of UNION with -.1UNION

    Requirement:
        * MySQL

    Notes:
        * Reference: https://raw.githubusercontent.com/y0unge/Notes/master/SQL%20Injection%20WAF%20Bypassing%20shortcut.pdf

    >>> tamper('1 UNION ALL SELECT')
    '1-.1UNION ALL SELECT'
    >>> tamper('1" UNION ALL SELECT')
    '1"-.1UNION ALL SELECT'
    """

    return re.sub(r"(?i)\s+(UNION )", r"-.1\g<1>", payload) if payload else payload
