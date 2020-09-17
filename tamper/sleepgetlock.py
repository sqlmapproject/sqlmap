#!/usr/bin/env python

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces instances like 'SLEEP(x)' with "get_lock('sqlmap',x)"

    Requirement:
        * MySQL

    Tested against:
        * MySQL 5.0 and 5.5

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that filter the SLEEP() and BENCHMARK() functions

        * Reference: https://zhuanlan.zhihu.com/p/35245598

    >>> tamper('SLEEP(2)')
    "get_lock('sqlmap',2)"
    """

    if payload and payload.find("SLEEP") > -1:
        while payload.find("SLEEP(") > -1:
            index = payload.find("SLEEP(")
            depth = 1
            
            num = payload[index+6]

            newVal = "get_lock('sqlmap',%s)" % (num)
            payload = payload[:index] + newVal + payload[index+8:]


    return payload
