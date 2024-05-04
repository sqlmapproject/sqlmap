#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

def tamper(payload,**kwargs):
    """
    Reverses the payload

    >>> tamper("SELECT * FROM users;")
    ;sresu MORF * TCELES
    """
    retVal = payload
    if payload:
        return payload[::-1]
    
    return retVal