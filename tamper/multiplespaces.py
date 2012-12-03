#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import random
import re

from lib.core.data import kb
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Adds multiple spaces around SQL keywords

    Example:
        * Input: UNION SELECT
        * Output:  UNION   SELECT  

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that has poorly written permissive regular expressions

    Reference: https://www.owasp.org/images/7/74/Advanced_SQL_Injection.ppt
    """

    retVal = payload

    if payload:
        words = set()

        for match in re.finditer(r"[A-Za-z_]+", payload):
            word = match.group()

            if word.upper() in kb.keywords:
                words.add(word)

        for word in words:
            retVal = re.sub("(?<=\W)%s(?=[^A-Za-z_(]|\Z)" % word, "%s%s%s" % (' '*random.randrange(1,4), word, ' '*random.randrange(1,4)), retVal)
            retVal = re.sub("(?<=\W)%s(?=[(])" % word, "%s%s" % (' '*random.randrange(1,4), word), retVal)

    return retVal
