#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import PRIORITY
from random import sample
__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def randomIP():
    numbers = []
    while not numbers or numbers[0] in (10, 172, 192):
        numbers = sample(xrange(1, 255), 4)
    return '.'.join(str(_) for _ in numbers)

def tamper(payload, **kwargs):
    """
    Append a fake HTTP header 'X-Forwarded-For' to bypass
    WAF (usually application based) protection
    """

    headers = kwargs.get("headers", {})
    headers["X-Forwarded-For"] = randomIP()
    return payload
