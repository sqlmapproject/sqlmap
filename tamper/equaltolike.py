#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def tamper(payload):
    """
    Replaces all occurances of operator = with operator LIKE
    Example: 'SELECT * FROM users WHERE id=1' becomes 'SELECT * FROM users WHERE id LIKE 1'
    """

    def process(match):
        word = match.group()
        word = "%sLIKE%s" % (" " if word[0]!=" " else "", " " if word[-1]!=" " else "")
        return word

    retVal = payload

    if payload:
        retVal = re.sub(r"\s*=\s*", lambda match: process(match), retVal)

    return retVal
