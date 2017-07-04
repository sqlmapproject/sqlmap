#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import random
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def tamper(payload, **kwargs):
    """
    Replaces predefined SQL keywords with representations
    suitable for replacement (e.g. .replace("SELECT", "")) filters

    Notes:
        * Useful to bypass very weak custom filters

    >>> random.seed(0)
    >>> tamper('1 UNION SELECT 2--')
    '1 UNIOUNIONN SELESELECTCT 2--'
    """

    keywords = ("UNION", "SELECT", "INSERT", "UPDATE", "FROM", "WHERE")
    retVal = payload

    warnMsg = "currently only couple of keywords are being processed %s. " % str(keywords)
    warnMsg += "You can set it manually according to your needs"
    singleTimeWarnMessage(warnMsg)

    if payload:
        for keyword in keywords:
            _ = random.randint(1, len(keyword) - 1)
            retVal = re.sub(r"(?i)\b%s\b" % keyword, "%s%s%s" % (keyword[:_], keyword, keyword[_:]), retVal)

    return retVal
