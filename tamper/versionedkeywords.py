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

__priority__ = PRIORITY.HIGHER

def tamper(payload):
    """
    Encloses each non-function keyword with versioned MySQL comment
    Example: 'INSERT' will become '/*!INSERT*/'
    """

    def process(match):
        word = match.group('word')
        if word.upper() in kb.keywords:
            return match.group().replace(word, "/*!%s*/" % word)
        else:
            return match.group()

    retVal = payload

    if payload:
        retVal = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=[^\w(]|\Z)", lambda match: process(match), retVal)
        retVal = retVal.replace(" /*!", "/*!").replace("*/ ", "*/")

    return retVal
