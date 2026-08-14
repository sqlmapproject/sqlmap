#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.data import kb
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces each keyword character with lower case value (e.g. SELECT -> select)

    Tested against:
        * MySQL 8.4.9
        * MariaDB 11.8.8
        * PostgreSQL 16.11
        * SQLite 3.45.1
        * Microsoft SQL Server 2022
        * Oracle 23ai

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that has poorly written permissive regular expressions

    >>> tamper('INSERT')
    'insert'
    """

    retVal = payload

    if payload:
        for match in re.finditer(r"\b[A-Za-z_]+\b", retVal):
            word = match.group()

            if word.upper() in kb.keywords:
                retVal = retVal.replace(word, word.lower())

    return retVal
