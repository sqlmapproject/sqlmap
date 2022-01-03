#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def tamper(payload, **kwargs):
    """
    Add an inline comment (/**/) to the end of all occurrences of (MySQL) "information_schema" identifier

    >>> tamper('SELECT table_name FROM INFORMATION_SCHEMA.TABLES')
    'SELECT table_name FROM INFORMATION_SCHEMA/**/.TABLES'
    """

    retVal = payload

    if payload:
        retVal = re.sub(r"(?i)(information_schema)\.", r"\g<1>/**/.", payload)

    return retVal
