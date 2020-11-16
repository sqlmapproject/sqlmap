#!/usr/bin/env python

from urllib.parse import quote
from lib.core.enums import PRIORITY
__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Standard url encoder using quote
    >>> tamper('select user from users;--+')
    'select%20user%20from%20users%3B--%2B'
    """

    return quote(payload)
