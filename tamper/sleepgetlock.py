#!/usr/bin/env python

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces instances like 'SLEEP(A)' with "get_lock('do9gy',A)"

    Requirement:
        * MySQL

    Tested against:
        * MySQL 5.0 and 5.5

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that filter the SLEEP() and BENCHMARK() functions

    >>> tamper('SLEEP(2)')
    "get_lock('do9gy',2)"
    """

    if payload and payload.find("SLEEP") > -1:
        while payload.find("SLEEP(") > -1:
            index = payload.find("SLEEP(")
            depth = 1
            
            num = payload[index+6]

            
            newVal = "get_lock('do9gy',%s)" % (num)
            payload = payload[:index] + newVal + payload[index+8:]


    return payload
