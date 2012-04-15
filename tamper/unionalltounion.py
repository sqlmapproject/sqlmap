#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload):
    """
    Replaces UNION ALL SELECT with UNION SELECT

    Example:
        * Input: -1 UNION ALL SELECT
        * Output: -1 UNION SELECT
    """

    return payload.replace("UNION ALL SELECT", "UNION SELECT") if payload else payload
