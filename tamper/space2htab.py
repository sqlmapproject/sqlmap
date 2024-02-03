#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.compat import xrange
from lib.core.enums import PRIORITY


__priority__ = PRIORITY.NORMAL


def dependencies():
    pass

def tamper(payload:str,**kwargs):
    """
    Replace payload space characters with horizontal space(%09)
    >>> tamper("SELECT id FROM users")
    'SELECT%09id%09FROM%09users' 
    """
    retVal = payload
    place_space = "%9"
    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                rm_value = payload[i]
                retVal = retVal.replace(rm_value, place_space)

    return retVal
