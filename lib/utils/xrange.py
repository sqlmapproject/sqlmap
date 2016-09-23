#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

class xrange(object):
    """
    Advanced (re)implementation of xrange (supports slice/copy/etc.)
    Reference: http://code.activestate.com/recipes/521885-a-pythonic-implementation-of-xrange/

    >>> foobar = xrange(1, 10)
    >>> 7 in foobar
    True
    >>> 11 in foobar
    False
    >>> foobar[0]
    1
    """

    __slots__ = ['_slice']

    def __init__(self, *args):
        if args and isinstance(args[0], type(self)):
            self._slice = slice(args[0].start, args[0].stop, args[0].step)
        else:
            self._slice = slice(*args)
        if self._slice.stop is None:
            raise TypeError("xrange stop must not be None")

    @property
    def start(self):
        if self._slice.start is not None:
            return self._slice.start
        return 0

    @property
    def stop(self):
        return self._slice.stop

    @property
    def step(self):
        if self._slice.step is not None:
            return self._slice.step
        return 1

    def __hash__(self):
        return hash(self._slice)

    def __cmp__(self, other):
        return (cmp(type(self), type(other)) or
                cmp(self._slice, other._slice))

    def __repr__(self):
        return '%s(%r, %r, %r)' % (type(self).__name__,
                                   self.start, self.stop, self.step)

    def __len__(self):
        return self._len()

    def _len(self):
        return max(0, int((self.stop - self.start) / self.step))

    def __contains__(self, value):
        return (self.start <= value < self.stop) and (value - self.start) % self.step == 0

    def __getitem__(self, index):
        if isinstance(index, slice):
            start, stop, step = index.indices(self._len())
            return xrange(self._index(start),
                          self._index(stop), step*self.step)
        elif isinstance(index, (int, long)):
            if index < 0:
                fixed_index = index + self._len()
            else:
                fixed_index = index

            if not 0 <= fixed_index < self._len():
                raise IndexError("Index %d out of %r" % (index, self))

            return self._index(fixed_index)
        else:
            raise TypeError("xrange indices must be slices or integers")

    def _index(self, i):
        return self.start + self.step * i

    def index(self, i):
        if self.start <= i < self.stop:
            return i - self.start
        else:
            raise ValueError("%d is not in list" % i)
