#!/usr/bin/env python

"""
Copyright (c) 2006-2014 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import PRIORITY
from random import randrange
__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def generateIP():
    blockOne = randrange(0, 255, 1)
    blockTwo = randrange(0, 255, 1)
    blockThree = randrange(0, 255, 1)
    blockFour = randrange(0, 255, 1)
    if blockOne == 10:
        return generateIP()
    elif blockOne == 172:
        return generateIP()
    elif blockOne == 192:
        return generateIP()
    else:
        return str(blockOne) + '.' + str(blockTwo) + '.' + str(blockThree) + '.' + str(blockFour)

def tamper(payload, **kwargs):
    """
    Append a HTTP Request Parameter to bypass
    WAF (usually application based ) Ban
    protection bypass.

    Mehmet INCE
    """

    headers = kwargs.get("headers", {})
    headers["X-Forwarded-For"] = generateIP()
    return payload
