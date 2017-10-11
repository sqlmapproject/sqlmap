#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import randomRange
from lib.core.data import kb
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces each keyword character with random case value

    Tested against:
        * Microsoft SQL Server 2005
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 8.4, 9.0

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that has poorly written permissive regular expressions
        * This tamper script should work against all (?) databases

    >>> import random
    >>> random.seed(0)
    >>> tamper('INSERT')
    'INseRt'
    """

    retVal = payload

    if payload:
        for match in re.finditer(r"[A-Za-z_]+", retVal):
            word = match.group()

            if word.upper() in kb.keywords:
                while True:
                    _ = ""

                    for i in xrange(len(word)):
                        _ += word[i].upper() if randomRange(0, 1) else word[i].lower()

                    if len(_) > 1 and _ not in (_.lower(), _.upper()):
                        break

                retVal = retVal.replace(word, _)

    return retVal
