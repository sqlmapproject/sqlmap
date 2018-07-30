#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
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
    Adds multiple spaces (' ') around SQL keywords

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that has poorly written permissive regular expressions

    Reference: https://www.owasp.org/images/7/74/Advanced_SQL_Injection.ppt

    >>> random.seed(0)
    >>> tamper('1 UNION SELECT foobar')
    '1    UNION     SELECT   foobar'
    """

    retVal = payload

    if payload:
        words = set()

        for match in re.finditer(r"\b[A-Za-z_]+\b", payload):
            word = match.group()

            if word.upper() in kb.keywords:
                words.add(word)

        for word in words:
            retVal = re.sub(r"(?<=\W)%s(?=[^A-Za-z_(]|\Z)" % word, "%s%s%s" % (' ' * random.randrange(1, 4), word, ' ' * random.randrange(1, 4)), retVal)
            retVal = re.sub(r"(?<=\W)%s(?=[(])" % word, "%s%s" % (' ' * random.randrange(1, 4), word), retVal)

    return retVal
