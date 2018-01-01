#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import hashlib

def cachedmethod(f, cache={}):
    """
    Method with a cached content

    Reference: http://code.activestate.com/recipes/325205-cache-decorator-in-python-24/
    """

    def _(*args, **kwargs):
        key = int(hashlib.md5("".join(str(_) for _ in (f, args, kwargs))).hexdigest()[:8], 16)
        if key not in cache:
            cache[key] = f(*args, **kwargs)

        return cache[key]

    return _
