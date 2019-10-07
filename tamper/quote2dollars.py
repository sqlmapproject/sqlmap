#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces single quote with dollar signs (e.g. ' -> $$)
    
    Tested against:
    * PostgreSQL 12.0
    
    Notes: useful for applications that use PostgreSQL database and encodes or sanitizes quote characters
    
    >>> tamper("1' or '1'='1")
    "1$$ or $$1$$=$$1"
    """

    return payload.replace("'", "$$")
