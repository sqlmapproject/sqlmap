#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
author: 3H34N
"""
import string
import random
from lib.core.enums import PRIORITY
__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def randomsession():
	length = 32
	chars = string.ascii_letters.lower() + string.digits
	password = ''.join(random.choice(chars) for i in range(length))
	return "PHPSESSID="+password

def tamper(payload, **kwargs):
    """
    Append a random session HTTP header 'PHPSESSID' to bypass
    WAF (usually application based) protection
    """

    headers = kwargs.get("headers", {})
    headers["Cookie"] = randomsession()
    return payload
