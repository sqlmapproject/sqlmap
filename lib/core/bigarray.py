#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

try:
    import cPickle as pickle
except:
    import pickle

import itertools
import os
import shutil
import sys
import tempfile
import threading
import zlib

from lib.core.compat import xrange
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.exception import SqlmapSystemException
from lib.core.settings import BIGARRAY_CHUNK_SIZE
from lib.core.settings import BIGARRAY_COMPRESS_LEVEL

try:
    DEFAULT_SIZE_OF = sys.getsizeof(object())
except TypeError:
    DEFAULT_SIZE_OF = 16

try:
    # Python 2: basestring covers str and unicode
    STRING_TYPES = (basestring,)
except NameError:
    # Python 3: str and bytes are separate
    STRING_TYPES = (str, bytes)

def _size_of(instance):
    """
    Returns total size of a given instance / object (in bytes)
    """

    retval = sys.getsizeof(instance, DEFAULT_SIZE_OF)

    if isinstance(instance, STRING_TYPES):
        return retval
    elif isinstance(instance, dict):
        retval += sum(_size_of(_) for _ in itertools.chain.from_iterable(instance.items()))
    elif isinstance(instance, (list, tuple, set, frozenset)):
        retval += sum(_size_of(_) for _ in instance if _ is not instance)

    return retval

class Cache(object):
    """
    Auxiliary class used for storing cached chunks
    """

    def __init__(self, index, data, dirty):
        self.index = index
        self.data = data
        self.dirty = dirty

class BigArray(list):
    """
    List-like class used for storing large amounts of data (disk cached)

    >>> _ = BigArray(xrange(100000), chunk_size=500 * 1024)
    >>> _[20] = 0
    >>> _[-1] = 999
    >>> _[99999]
    999
    >>> _[100000]
    Traceback (most recent call last):
    ...
    IndexError: BigArray index out of range
    >>> _ += [0]
    >>> sum(_)
    4999850980
    >>> _[len(_) // 2] = 17
    >>> sum(_)
    4999800997
    >>> _[100000]
    0
    >>> _[0] = [None]
    >>> _.index(0)
    20
    >>> import pickle; __ = pickle.loads(pickle.dumps(_))
    >>> __.append(1)
    >>> len(_)
    100001
    >>> _ = __
    >>> _[-1]
    1
    >>> _.pop()
    1
    >>> len(_)
    100001
    >>> len([_ for _ in BigArray(xrange(100000))])
    100000
    """

    def __init__(self, items=None, chunk_size=BIGARRAY_CHUNK_SIZE):
        self.chunks = [[]]
        self.chunk_length = sys.maxsize
        self.cache = None
        self.filenames = set()
        self._lock = threading.Lock()
        self._os_remove = os.remove
        self._size_counter = 0
        self._chunk_size = chunk_size

        for item in (items or []):
            self.append(item)

    def __add__(self, value):
        retval = BigArray(self)

        for _ in value:
            retval.append(_)

        return retval

    def __iadd__(self, value):
        for _ in value:
            self.append(_)

        return self

    def append(self, value):
        with self._lock:
            self.chunks[-1].append(value)

            if self.chunk_length == sys.maxsize:
                self._size_counter += _size_of(value)
                if self._size_counter >= self._chunk_size:
                    self.chunk_length = len(self.chunks[-1])
                    self._size_counter = None

            if len(self.chunks[-1]) >= self.chunk_length:
                filename = self._dump(self.chunks[-1])
                self.chunks[-1] = filename
                self.chunks.append([])

    def extend(self, value):
        for _ in value:
            self.append(_)

    def pop(self):
        with self._lock:
            if not self.chunks[-1] and len(self.chunks) > 1:
                self.chunks.pop()
                try:
                    filename = self.chunks[-1]
                    with open(filename, "rb") as f:
                        self.chunks[-1] = pickle.loads(zlib.decompress(f.read()))
                    self._os_remove(filename)
                    self.filenames.discard(filename)
                except IOError as ex:
                    errMsg = "exception occurred while retrieving data "
                    errMsg += "from a temporary file ('%s')" % ex
                    raise SqlmapSystemException(errMsg)

        return self.chunks[-1].pop()

    def index(self, value):
        for index in xrange(len(self)):
            if self[index] == value:
                return index

        raise ValueError("%s is not in list" % value)

    def __reduce__(self):
        return (self.__class__, (), self.__getstate__())

    def close(self):
        with self._lock:
            while self.filenames:
                filename = self.filenames.pop()
                try:
                    self._os_remove(filename)
                except OSError:
                    pass
            self.chunks = [[]]
            self.cache = None
            self.chunk_length = getattr(sys, "maxsize", None)
            self._size_counter = 0

    def __del__(self):
        self.close()

    def _dump(self, chunk):
        try:
            handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.BIG_ARRAY)
            self.filenames.add(filename)
            with os.fdopen(handle, "w+b") as f:
                f.write(zlib.compress(pickle.dumps(chunk, pickle.HIGHEST_PROTOCOL), BIGARRAY_COMPRESS_LEVEL))
            return filename
        except (OSError, IOError) as ex:
            errMsg = "exception occurred while storing data "
            errMsg += "to a temporary file ('%s'). Please " % ex
            errMsg += "make sure that there is enough disk space left. If problem persists, "
            errMsg += "try to set environment variable 'TEMP' to a location "
            errMsg += "writeable by the current user"
            raise SqlmapSystemException(errMsg)

    def _checkcache(self, index):
        if self.cache is not None and not isinstance(self.cache, Cache):
            self.cache = None

        if (self.cache and self.cache.index != index and self.cache.dirty):
            filename = self._dump(self.cache.data)
            self.chunks[self.cache.index] = filename

        if not (self.cache and self.cache.index == index):
            try:
                with open(self.chunks[index], "rb") as f:
                    self.cache = Cache(index, pickle.loads(zlib.decompress(f.read())), False)
            except Exception as ex:
                errMsg = "exception occurred while retrieving data "
                errMsg += "from a temporary file ('%s')" % ex
                raise SqlmapSystemException(errMsg)

    def __getstate__(self):
        if self.cache and self.cache.dirty:
            filename = self._dump(self.cache.data)
            self.chunks[self.cache.index] = filename
            self.cache.dirty = False

        return self.chunks, self.filenames, self.chunk_length

    def __setstate__(self, state):
        self.__init__()
        chunks, filenames, self.chunk_length = state

        file_mapping = {}
        self.filenames = set()
        self.chunks = []

        for filename in filenames:
            if not os.path.exists(filename):
                continue

            try:
                handle, new_filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.BIG_ARRAY)
                os.close(handle)
                shutil.copyfile(filename, new_filename)
                self.filenames.add(new_filename)
                file_mapping[filename] = new_filename
            except (OSError, IOError):
                pass

        for chunk in chunks:
            if isinstance(chunk, STRING_TYPES):
                if chunk in file_mapping:
                    self.chunks.append(file_mapping[chunk])
                else:
                    errMsg = "exception occurred while restoring BigArray chunk "
                    errMsg += "from file '%s'" % chunk
                    raise SqlmapSystemException(errMsg)
            else:
                self.chunks.append(chunk)

    def __getitem__(self, y):
        with self._lock:
            length = len(self)
            if length == 0:
                raise IndexError("BigArray index out of range")

            if y < 0:
                y += length

            if y < 0 or y >= length:
                raise IndexError("BigArray index out of range")

            index = y // self.chunk_length
            offset = y % self.chunk_length
            chunk = self.chunks[index]

            if isinstance(chunk, list):
                return chunk[offset]
            else:
                self._checkcache(index)
                return self.cache.data[offset]

    def __setitem__(self, y, value):
        with self._lock:
            length = len(self)
            if length == 0:
                raise IndexError("BigArray index out of range")

            if y < 0:
                y += length

            if y < 0 or y >= length:
                raise IndexError("BigArray index out of range")

            index = y // self.chunk_length
            offset = y % self.chunk_length
            chunk = self.chunks[index]

            if isinstance(chunk, list):
                chunk[offset] = value
            else:
                self._checkcache(index)
                self.cache.data[offset] = value
                self.cache.dirty = True

    def __repr__(self):
        return "%s%s" % ("..." if len(self.chunks) > 1 else "", self.chunks[-1].__repr__())

    def __iter__(self):
        with self._lock:
            chunks = list(self.chunks)
            cache_index = self.cache.index if isinstance(self.cache, Cache) else None
            cache_data = self.cache.data if isinstance(self.cache, Cache) else None

        for idx, chunk in enumerate(chunks):
            if isinstance(chunk, list):
                for item in chunk:
                    yield item
            else:
                try:
                    if cache_index == idx and cache_data is not None:
                        data = cache_data
                    else:
                        with open(chunk, "rb") as f:
                            data = pickle.loads(zlib.decompress(f.read()))
                except Exception as ex:
                    errMsg = "exception occurred while retrieving data "
                    errMsg += "from a temporary file ('%s')" % ex
                    raise SqlmapSystemException(errMsg)

                for item in data:
                    yield item

    def __len__(self):
        return len(self.chunks[-1]) if len(self.chunks) == 1 else (len(self.chunks) - 1) * self.chunk_length + len(self.chunks[-1])
