#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import functools
import hashlib
import threading

from lib.core.datatype import LRUDict
from lib.core.settings import MAX_CACHE_ITEMS
from lib.core.settings import UNICODE_ENCODING
from lib.core.threads import getCurrentThreadData

_cache = {}
_method_locks = {}

def cachedmethod(f):
    """
    Method with a cached content

    >>> __ = cachedmethod(lambda _: _)
    >>> __(1)
    1
    >>> __(1)
    1
    >>> __ = cachedmethod(lambda *args, **kwargs: args[0])
    >>> __(2)
    2
    >>> __ = cachedmethod(lambda *args, **kwargs: next(iter(kwargs.values())))
    >>> __(foobar=3)
    3

    Reference: http://code.activestate.com/recipes/325205-cache-decorator-in-python-24/
    """

    _cache[f] = LRUDict(capacity=MAX_CACHE_ITEMS)
    _method_locks[f] = threading.RLock()

    @functools.wraps(f)
    def _f(*args, **kwargs):
        parts = (
            f.__module__ + "." + f.__name__,
            "^".join(repr(a) for a in args),
            "^".join("%s=%r" % (k, kwargs[k]) for k in sorted(kwargs))
        )
        try:
            key = int(hashlib.md5("`".join(parts).encode(UNICODE_ENCODING)).hexdigest(), 16) & 0x7fffffffffffffff
        except ValueError:  # https://github.com/sqlmapproject/sqlmap/issues/4281 (NOTE: non-standard Python behavior where hexdigest returns binary value)
            result = f(*args, **kwargs)
        else:
            lock, cache = _method_locks[f], _cache[f]
            with lock:
                try:
                    result = cache[key]
                except KeyError:
                    result = f(*args, **kwargs)
                    cache[key] = result

        return result

    return _f

def stackedmethod(f):
    """
    Method using pushValue/popValue functions (fallback function for stack realignment)

    >>> threadData = getCurrentThreadData()
    >>> original = len(threadData.valueStack)
    >>> __ = stackedmethod(lambda _: threadData.valueStack.append(_))
    >>> __(1)
    >>> len(threadData.valueStack) == original
    True
    """

    @functools.wraps(f)
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

def lockedmethod(f):
    lock = threading.RLock()

    @functools.wraps(f)
    def _(*args, **kwargs):
        with lock:
            result = f(*args, **kwargs)
        return result

    return _
