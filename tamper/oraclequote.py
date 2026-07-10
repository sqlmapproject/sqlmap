#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.ORACLE))

def tamper(payload, **kwargs):
    """
    Replaces single-quoted strings with Oracle alternative-quoted strings (e.g. 'abc' -> q'[abc]')

    Requirement:
        * Oracle 10g+

    Tested against:
        * Oracle 11g, 12c, 18c, 19c, 21c, 23ai

    Notes:
        * Useful to bypass filters that block, strip or escape the single-quote
          character: q-quoting delimits the literal with a chosen bracket/char
          so the inner text needs no quote at all
        * The first delimiter whose characters are absent from the literal is
          used; a literal that contains every candidate delimiter is left untouched

    >>> tamper("SELECT 'abc' FROM DUAL")
    "SELECT q'[abc]' FROM DUAL"
    """

    def _quote(match):
        value = match.group(1)
        for start, end in (("[", "]"), ("{", "}"), ("(", ")"), ("<", ">"), ("!", "!"), ("|", "|"), ("#", "#")):
            if start not in value and end not in value:
                return "q'%s%s%s'" % (start, value, end)
        return match.group(0)

    retVal = payload

    if payload:
        retVal = re.sub(r"'([^']*)'", _quote, payload)

    return retVal
