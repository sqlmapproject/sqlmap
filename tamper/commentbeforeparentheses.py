#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Prepends (inline) comment before parentheses (e.g. ( -> /**/()

    Tested against:
        * MySQL 8.4.9
        * MariaDB 11.8.8
        * PostgreSQL 16.11
        * SQLite 3.45.1
        * Microsoft SQL Server 2022
        * Oracle 23ai

    Notes:
        * Useful to bypass web application firewalls that block usage
          of function calls

    >>> tamper('SELECT ABS(1)')
    'SELECT ABS/**/(1)'
    """

    retVal = payload

    if payload:
        retVal = re.sub(r"\b(\w+)\(", r"\g<1>/**/(", retVal)

    return retVal
