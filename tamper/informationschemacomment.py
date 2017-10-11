#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def tamper(payload, **kwargs):
    """
    Add a comment to the end of all occurrences of (blacklisted) "information_schema" identifier

    >>> tamper('SELECT table_name FROM INFORMATION_SCHEMA.TABLES')
    'SELECT table_name FROM INFORMATION_SCHEMA/**/.TABLES'
    """

    retVal = payload

    if payload:
        retVal = re.sub(r"(?i)(information_schema)\.", "\g<1>/**/.", payload)

    return retVal
