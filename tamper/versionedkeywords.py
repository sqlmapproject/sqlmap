#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.common import randomRange
from lib.core.data import kb
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def tamper(payload):
    """
    Encloses each keyword with versioned comment
    Example: 'INSERT' will become '/*!INSERT*/'
    """

    def process(match):
        word = match.group('word')
        if word.upper() in kb.keywords and word.upper() not in ["CAST"]: # CAST can't be commented out
            return match.group().replace(word, "/*!%s*/" % word)
        else:
            return match.group()

    retVal = payload

    if payload:
        retVal = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=\W|\Z)", lambda match: process(match), retVal)
        retVal = retVal.replace(" /*!", "/*!").replace("*/ ", "*/")

    return retVal
