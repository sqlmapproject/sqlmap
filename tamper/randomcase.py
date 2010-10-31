#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.common import randomRange
from lib.core.data import kb

def tamper(value):
    """
    Replaces each character with random case value
    Example: 'INSERT' might become 'InsERt'
    """

    retVal = value

    if value:
        for match in re.finditer(r"[A-Za-z_]+", retVal):
            word = match.group()

            if word.upper() in kb.keywords:
                newWord = str()

                for i in xrange(len(word)):
                    newWord += word[i].upper() if randomRange(0, 1) else word[i].lower()

                retVal = retVal.replace(word, newWord)

    return retVal
