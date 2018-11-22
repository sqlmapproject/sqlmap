#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
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
    Replaces each keyword character with mixed case value (e.g. SELECT -> SeLeCt)

    Tested against:
        * SQLite 3

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that has poorly written permissive regular expressions
        * This tamper script should work against all (?) databases
        * Usefull when some keywords like 'as' are part or words like 'last'
          and that randomcase temper script get you caught because it outputted
          'lasT' ('as' is flagged where 'aS' or 'As' is not).
    """

    retVal = payload

    if payload:
        for match in re.finditer(r"\b[A-Za-z_]+\b", retVal):
            word = match.group()

            if word.upper() in kb.keywords or ("%s(" % word) in payload:
                while True:
                    _ = ""

                    for i in xrange(len(word)):
                        _ += word[i].upper() if i%2==0 else word[i].lower()

                    if len(_) > 1 and _ not in (_.lower(), _.upper()):
                        break

                retVal = retVal.replace(word, _)

    return retVal
