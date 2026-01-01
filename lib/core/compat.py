#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import codecs
import binascii
import functools
import io
import math
import os
import random
import re
import sys
import time
import uuid

class WichmannHill(random.Random):
    """
    Reference: https://svn.python.org/projects/python/trunk/Lib/random.py
    """

    VERSION = 1     # used by getstate/setstate

    def seed(self, a=None):
        """Initialize internal state from hashable object.

        None or no argument seeds from current time or from an operating
        system specific randomness source if available.

        If a is not None or an int or long, hash(a) is used instead.

        If a is an int or long, a is used directly.  Distinct values between
        0 and 27814431486575L inclusive are guaranteed to yield distinct
        internal states (this guarantee is specific to the default
        Wichmann-Hill generator).
        """

        if a is None:
            try:
                a = int(binascii.hexlify(os.urandom(16)), 16)
            except NotImplementedError:
                a = int(time.time() * 256)  # use fractional seconds

        if not isinstance(a, int):
            a = hash(a)

        a, x = divmod(a, 30268)
        a, y = divmod(a, 30306)
        a, z = divmod(a, 30322)
        self._seed = int(x) + 1, int(y) + 1, int(z) + 1

        self.gauss_next = None

    def random(self):
        """Get the next random number in the range [0.0, 1.0)."""

        # Wichman-Hill random number generator.
        #
        # Wichmann, B. A. & Hill, I. D. (1982)
        # Algorithm AS 183:
        # An efficient and portable pseudo-random number generator
        # Applied Statistics 31 (1982) 188-190
        #
        # see also:
        #        Correction to Algorithm AS 183
        #        Applied Statistics 33 (1984) 123
        #
        #        McLeod, A. I. (1985)
        #        A remark on Algorithm AS 183
        #        Applied Statistics 34 (1985),198-200

        # This part is thread-unsafe:
        # BEGIN CRITICAL SECTION
        x, y, z = self._seed
        x = (171 * x) % 30269
        y = (172 * y) % 30307
        z = (170 * z) % 30323
        self._seed = x, y, z
        # END CRITICAL SECTION

        # Note:  on a platform using IEEE-754 double arithmetic, this can
        # never return 0.0 (asserted by Tim; proof too long for a comment).
        return (x / 30269.0 + y / 30307.0 + z / 30323.0) % 1.0

    def getstate(self):
        """Return internal state; can be passed to setstate() later."""
        return self.VERSION, self._seed, self.gauss_next

    def setstate(self, state):
        """Restore internal state from object returned by getstate()."""
        version = state[0]
        if version == 1:
            version, self._seed, self.gauss_next = state
        else:
            raise ValueError("state with version %s passed to "
                             "Random.setstate() of version %s" %
                             (version, self.VERSION))

    def jumpahead(self, n):
        """Act as if n calls to random() were made, but quickly.

        n is an int, greater than or equal to 0.

        Example use:  If you have 2 threads and know that each will
        consume no more than a million random numbers, create two Random
        objects r1 and r2, then do
            r2.setstate(r1.getstate())
            r2.jumpahead(1000000)
        Then r1 and r2 will use guaranteed-disjoint segments of the full
        period.
        """

        if n < 0:
            raise ValueError("n must be >= 0")
        x, y, z = self._seed
        x = int(x * pow(171, n, 30269)) % 30269
        y = int(y * pow(172, n, 30307)) % 30307
        z = int(z * pow(170, n, 30323)) % 30323
        self._seed = x, y, z

    def __whseed(self, x=0, y=0, z=0):
        """Set the Wichmann-Hill seed from (x, y, z).

        These must be integers in the range [0, 256).
        """

        if not type(x) == type(y) == type(z) == int:
            raise TypeError('seeds must be integers')
        if not (0 <= x < 256 and 0 <= y < 256 and 0 <= z < 256):
            raise ValueError('seeds must be in range(0, 256)')
        if 0 == x == y == z:
            # Initialize from current time
            t = int(time.time() * 256)
            t = int((t & 0xffffff) ^ (t >> 24))
            t, x = divmod(t, 256)
            t, y = divmod(t, 256)
            t, z = divmod(t, 256)
        # Zero is a poor seed, so substitute 1
        self._seed = (x or 1, y or 1, z or 1)

        self.gauss_next = None

    def whseed(self, a=None):
        """Seed from hashable object's hash code.

        None or no argument seeds from current time.  It is not guaranteed
        that objects with distinct hash codes lead to distinct internal
        states.

        This is obsolete, provided for compatibility with the seed routine
        used prior to Python 2.1.  Use the .seed() method instead.
        """

        if a is None:
            self.__whseed()
            return
        a = hash(a)
        a, x = divmod(a, 256)
        a, y = divmod(a, 256)
        a, z = divmod(a, 256)
        x = (x + a) % 256 or 1
        y = (y + a) % 256 or 1
        z = (z + a) % 256 or 1
        self.__whseed(x, y, z)

def patchHeaders(headers):
    if headers is not None and not hasattr(headers, "headers"):
        if isinstance(headers, dict):
            class _(dict):
                def __getitem__(self, key):
                    for key_ in self:
                        if key_.lower() == key.lower():
                            return super(_, self).__getitem__(key_)

                    raise KeyError(key)

                def get(self, key, default=None):
                    try:
                        return self[key]
                    except KeyError:
                        return default

            headers = _(headers)

        headers.headers = ["%s: %s\r\n" % (header, headers[header]) for header in headers]

    return headers

def cmp(a, b):
    """
    >>> cmp("a", "b")
    -1
    >>> cmp(2, 1)
    1
    """

    if a < b:
        return -1
    elif a > b:
        return 1
    else:
        return 0

# Reference: https://github.com/urllib3/urllib3/blob/master/src/urllib3/filepost.py
def choose_boundary():
    """
    >>> len(choose_boundary()) == 32
    True
    """

    retval = ""

    try:
        retval = uuid.uuid4().hex
    except AttributeError:
        retval = "".join(random.sample("0123456789abcdef", 1)[0] for _ in xrange(32))

    return retval

# Reference: http://python3porting.com/differences.html
def round(x, d=0):
    """
    >>> round(2.0)
    2.0
    >>> round(2.5)
    3.0
    """

    p = 10 ** d
    if x > 0:
        return float(math.floor((x * p) + 0.5)) / p
    else:
        return float(math.ceil((x * p) - 0.5)) / p

# Reference: https://code.activestate.com/recipes/576653-convert-a-cmp-function-to-a-key-function/
def cmp_to_key(mycmp):
    """Convert a cmp= function into a key= function"""
    class K(object):
        __slots__ = ['obj']

        def __init__(self, obj, *args):
            self.obj = obj

        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0

        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0

        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0

        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0

        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0

        def __ne__(self, other):
            return mycmp(self.obj, other.obj) != 0

        def __hash__(self):
            raise TypeError('hash not implemented')

    return K

# Note: patch for Python 2.6
if not hasattr(functools, "cmp_to_key"):
    functools.cmp_to_key = cmp_to_key

if sys.version_info >= (3, 0):
    xrange = range
    buffer = memoryview
else:
    xrange = xrange
    buffer = buffer

def LooseVersion(version):
    """
    >>> LooseVersion("1.0") == LooseVersion("1.0")
    True
    >>> LooseVersion("1.0.1") > LooseVersion("1.0")
    True
    >>> LooseVersion("1.0.1-") == LooseVersion("1.0.1")
    True
    >>> LooseVersion("1.0.11") < LooseVersion("1.0.111")
    True
    >>> LooseVersion("foobar") > LooseVersion("1.0")
    False
    >>> LooseVersion("1.0") > LooseVersion("foobar")
    False
    >>> LooseVersion("3.22-mysql") == LooseVersion("3.22-mysql-ubuntu0.3")
    True
    >>> LooseVersion("8.0.22-0ubuntu0.20.04.2")
    8.000022
    """

    match = re.search(r"\A(\d[\d.]*)", version or "")

    if match:
        result = 0
        value = match.group(1)
        weight = 1.0
        for part in value.strip('.').split('.'):
            if part.isdigit():
                result += int(part) * weight
            weight *= 1e-3
    else:
        result = float("NaN")

    return result

# NOTE: codecs.open re-implementation (deprecated in Python 3.14)

try:
    # Py2
    _text_type = unicode
    _bytes_types = (str, bytearray)
except NameError:
    # Py3
    _text_type = str
    _bytes_types = (bytes, bytearray, memoryview)

_WRITE_CHARS = ("w", "a", "x", "+")

def _is_write_mode(mode):
    return any(ch in mode for ch in _WRITE_CHARS)

class MixedWriteTextIO(object):
    """
    Text-ish stream wrapper that accepts both text and bytes in write().
    Bytes are decoded using the file's (encoding, errors) before writing.

    Optionally approximates line-buffering by flushing when a newline is written.
    """
    def __init__(self, fh, encoding, errors, line_buffered=False):
        self._fh = fh
        self._encoding = encoding
        self._errors = errors
        self._line_buffered = line_buffered

    def write(self, data):
        # bytes-like but not text -> decode
        if isinstance(data, _bytes_types) and not isinstance(data, _text_type):
            data = bytes(data).decode(self._encoding, self._errors)
        elif not isinstance(data, _text_type):
            data = _text_type(data)

        n = self._fh.write(data)

        # Approximate "line buffering" behavior if requested
        if self._line_buffered and u"\n" in data:
            try:
                self._fh.flush()
            except Exception:
                pass

        return n

    def writelines(self, lines):
        for x in lines:
            self.write(x)

    def __iter__(self):
        return iter(self._fh)

    def __next__(self):
        return next(self._fh)

    def next(self):  # Py2
        return self.__next__()

    def __getattr__(self, name):
        return getattr(self._fh, name)

    def __enter__(self):
        self._fh.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._fh.__exit__(exc_type, exc, tb)


def _codecs_open(filename, mode="r", encoding=None, errors="strict", buffering=-1):
    """
    Replacement for deprecated codecs.open() entry point with sqlmap-friendly behavior.

    - If encoding is None: return io.open(...) as-is.
    - If encoding is set: force underlying binary mode and wrap via StreamReaderWriter
      (like codecs.open()).
    - For write-ish modes: return a wrapper that also accepts bytes on .write().
    - Handles buffering=1 in binary mode by downgrading underlying buffering to -1,
      while optionally preserving "flush on newline" behavior in the wrapper.
    """
    if encoding is None:
        return io.open(filename, mode, buffering=buffering)

    bmode = mode
    if "b" not in bmode:
        bmode += "b"

    # Avoid line-buffering warnings/errors on binary streams
    line_buffered = (buffering == 1)
    if line_buffered:
        buffering = -1

    f = io.open(filename, bmode, buffering=buffering)

    try:
        info = codecs.lookup(encoding)
        srw = codecs.StreamReaderWriter(f, info.streamreader, info.streamwriter, errors)
        srw.encoding = encoding

        if _is_write_mode(mode):
            return MixedWriteTextIO(srw, encoding, errors, line_buffered=line_buffered)

        return srw
    except Exception:
        try:
            f.close()
        finally:
            raise

codecs_open = _codecs_open if sys.version_info >= (3, 14) else codecs.open
