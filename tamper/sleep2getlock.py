#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import kb
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces instances like 'SLEEP(5)' with (e.g.) "GET_LOCK('ETgP',5)"

    Requirement:
        * MySQL

    Tested against:
        * MySQL 5.0 and 5.5

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that filter the SLEEP() and BENCHMARK() functions

        * Reference: https://zhuanlan.zhihu.com/p/35245598

    >>> tamper('SLEEP(5)') == "GET_LOCK('%s',5)" % kb.aliasName
    True
    """

    if payload:
        payload = payload.replace("SLEEP(", "GET_LOCK('%s'," % kb.aliasName)

    return payload
