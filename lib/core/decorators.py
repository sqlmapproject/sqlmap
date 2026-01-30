#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import functools
import threading

from lib.core.datatype import LRUDict
from lib.core.settings import MAX_CACHE_ITEMS
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

    def _freeze(val):
        if isinstance(val, (list, set, tuple)):
            return tuple(_freeze(x) for x in val)
        if isinstance(val, dict):
            return tuple(sorted((k, _freeze(v)) for k, v in val.items()))
        return val

    @functools.wraps(f)
    def _f(*args, **kwargs):
        lock, cache = _method_locks[f], _cache[f]

        try:
            if kwargs:
                key = (args, frozenset(kwargs.items()))
            else:
                key = args

            with lock:
                if key in cache:
                    return cache[key]

        except TypeError:
            # Note: fallback (slowpath(
            if kwargs:
                key = (_freeze(args), _freeze(kwargs))
            else:
                key = _freeze(args)

            with lock:
                if key in cache:
                    return cache[key]

        result = f(*args, **kwargs)

        with lock:
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
                del threadData.valueStack[originalLevel:]

        return result

    return _

def lockedmethod(f):
    """
    Decorates a function or method with a reentrant lock (only one thread can execute the function at a time)

    >>> @lockedmethod
    ... def recursive_count(n):
    ...     if n <= 0: return 0
    ...     return n + recursive_count(n - 1)
    >>> recursive_count(5)
    15
    """

    lock = threading.RLock()

    @functools.wraps(f)
    def _(*args, **kwargs):
        with lock:
            result = f(*args, **kwargs)
        return result

    return _
