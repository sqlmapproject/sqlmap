#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import hashlib

from lib.core.threads import getCurrentThreadData

def cachedmethod(f, cache={}):
    """
    Method with a cached content

    Reference: http://code.activestate.com/recipes/325205-cache-decorator-in-python-24/
    """

    def _(*args, **kwargs):
        key = int(hashlib.md5("|".join(str(_) for _ in (f, args, kwargs))).hexdigest(), 16) & 0x7fffffffffffffff
        if key not in cache:
            cache[key] = f(*args, **kwargs)

        return cache[key]

    return _

def stackedmethod(f):
    def _(*args, **kwargs):
        threadData = getCurrentThreadData()
        originalLevel = len(threadData.valueStack)

        try:
            result = f(*args, **kwargs)
        finally:
            if len(threadData.valueStack) > originalLevel:
                threadData.valueStack = threadData.valueStack[:originalLevel]

        return result

    return _
