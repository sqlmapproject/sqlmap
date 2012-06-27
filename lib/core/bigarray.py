#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import pickle
import tempfile

from lib.core.settings import BIGARRAY_CHUNK_LENGTH

class Cache:
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
    """

    def __init__(self):
        self.chunks = [[]]
        self.cache = None
        self.length = 0
        self.filenames = set()

    def append(self, value):
        self.chunks[-1].append(value)
        if len(self.chunks[-1]) >= BIGARRAY_CHUNK_LENGTH:
            filename = self._dump(self.chunks[-1])
            del(self.chunks[-1][:])
            self.chunks[-1] = filename
            self.chunks.append([])

    def pop(self):
        if len(self.chunks[-1]) < 1:
            self.chunks.pop()
            with open(self.chunks[-1], "rb") as fp:
                self.chunks[-1] = pickle.load(fp)
        return self.chunks[-1].pop()

    def index(self, value):
        for index in xrange(len(self)):
            if self[index] == value:
                return index
        return ValueError, "%s is not in list" % value

    def _dump(self, value):
        handle, filename = tempfile.mkstemp()
        self.filenames.add(filename)
        os.close(handle)
        with open(filename, "w+b") as fp:
            pickle.dump(value, fp)
        return filename

    def _checkcache(self, index):
        if (self.cache and self.cache.index != index and self.cache.dirty):
            filename = self._dump(self.cache.data)
            self.chunks[self.cache.index] = filename
        if not (self.cache and self.cache.index == index):
            with open(self.chunks[index], "rb") as fp:
                self.cache = Cache(index, pickle.load(fp), False)

    def __getitem__(self, y):
        index = y / BIGARRAY_CHUNK_LENGTH
        offset = y % BIGARRAY_CHUNK_LENGTH
        chunk = self.chunks[index]
        if isinstance(chunk, list):
            return chunk[offset]
        else:
            self._checkcache(index)
            return self.cache.data[offset]

    def __setitem__(self, y, value):
        index = y / BIGARRAY_CHUNK_LENGTH
        offset = y % BIGARRAY_CHUNK_LENGTH
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
        for i in xrange(len(self)):
            yield self[i]

    def __len__(self):
        return len(self.chunks[-1]) if len(self.chunks) == 1 else (len(self.chunks) - 1) * BIGARRAY_CHUNK_LENGTH + len(self.chunks[-1])

    def __del__(self):
        for filename in self.filenames:
            try:
                os.remove(filename)
            except OSError:
                pass
