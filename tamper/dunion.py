#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.ORACLE))

def tamper(payload, **kwargs):
    """
    Replaces instances of <int> UNION with <int>DUNION

    Requirement:
        * Oracle

    Notes:
        * Reference: https://media.blackhat.com/us-13/US-13-Salgado-SQLi-Optimization-and-Obfuscation-Techniques-Slides.pdf

    >>> tamper('1 UNION ALL SELECT')
    '1DUNION ALL SELECT'
    """

    return re.sub(r"(?i)(\d+)\s+(UNION )", r"\g<1>D\g<2>", payload) if payload else payload
