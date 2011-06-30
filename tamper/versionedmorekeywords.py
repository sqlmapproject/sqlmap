#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.common import randomRange
from lib.core.common import singleTimeWarnMessage
from lib.core.data import kb
from lib.core.enums import PRIORITY
from lib.core.settings import IGNORE_SPACE_AFFECTED_KEYWORDS

__priority__ = PRIORITY.HIGHER

def tamper(payload):
    """
    Encloses each keyword with versioned MySQL comment (MySQL >= 5.1.13)
    Example: 'INSERT' will become '/*!INSERT*/'
    """

    def process(match):
        word = match.group('word')
        if word.upper() in kb.keywords and word.upper() not in IGNORE_SPACE_AFFECTED_KEYWORDS:
            return match.group().replace(word, "/*!%s*/" % word)
        else:
            return match.group()

    singleTimeWarnMessage("This tamper script is only meant to be run against MySQL >= 5.1.13")

    retVal = payload

    if payload:
        retVal = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=\W|\Z)", lambda match: process(match), retVal)
        retVal = retVal.replace(" /*!", "/*!").replace("*/ ", "*/")

    return retVal
