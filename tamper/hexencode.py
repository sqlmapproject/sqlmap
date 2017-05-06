#!/usr/bin/env python

"""
Copyright (c) 2006-2015 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import PRIORITY
from lib.core.settings import UNICODE_ENCODING

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Base16 all characters in a given payload

    Notes:
        * unrecommended/untested for int types, Only string
        
    >>> tamper("UNION ALL SELECT NULL,NULL,NULL#")
    '554e494f4e20414c4c2053454c454354204e554c4c2c4e554c4c2c4e554c4c23'
    """
    return payload.encode('hex')
