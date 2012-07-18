#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

class Wordlist:
    """
    Iterator for looping over a large dictionaries
    """

    def __init__(self, filenames, proc_id=None, proc_count=None, custom=None):
        self.filenames = filenames
        self.fp = None
        self.index = 0
        self.counter = -1
        self.iter = None
        self.custom = custom or []
        self.proc_id = proc_id
        self.proc_count = proc_count
        self.adjust()

    def __iter__(self):
        return self

    def adjust(self):
        self.closeFP()
        if self.index > len(self.filenames):
            raise StopIteration
        elif self.index == len(self.filenames):
            if not self.proc_id:
                self.iter = iter(self.custom)
            else:
                raise StopIteration
        else:
            current = self.filenames[self.index]
            self.fp = open(current, "r")
            self.iter = iter(self.fp)

        self.index += 1

    def closeFP(self):
        if self.fp:
            self.fp.close()
            self.fp = None

    def next(self):
        retVal = None
        while True:
            try:
                retVal = self.iter.next().rstrip()
            except StopIteration:
                self.adjust()
                retVal = self.iter.next().rstrip()
            if not self.proc_count:
                break
            self.counter += 1
            if self.counter % self.proc_count == self.proc_id:
                break
        return retVal

    def rewind(self):
        self.index = 0
        self.adjust()
