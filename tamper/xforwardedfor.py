#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import random

from lib.core.compat import xrange
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def randomIP():
    numbers = []

    while not numbers or numbers[0] in (10, 172, 192):
        numbers = random.sample(xrange(1, 255), 4)

    return '.'.join(str(_) for _ in numbers)

def tamper(payload, **kwargs):
    """
    Append a fake HTTP header 'X-Forwarded-For'
    """

    headers = kwargs.get("headers", {})
    headers["X-Forwarded-For"] = randomIP()
    headers["X-Client-Ip"] = randomIP()
    headers["X-Real-Ip"] = randomIP()
    return payload
