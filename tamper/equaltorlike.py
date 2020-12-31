#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces all occurrences of operator equal ('=') with 'RLIKE' counterpart

    Tested against:
        * MySQL 4, 5.0 and 5.5

    Notes:
        * Useful to bypass weak and bespoke web application firewalls that
          filter the equal character ('=')

    >>> tamper('SELECT * FROM users WHERE id=1')
    'SELECT * FROM users WHERE id RLIKE 1'
    """

    retVal = payload

    if payload:
        retVal = re.sub(r"\s*=\s*", " RLIKE ", retVal)

    return retVal
