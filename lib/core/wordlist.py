#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import singleTimeLogMessage

class Wordlist:
    """
    Iterator for looping over a large dictionaries
    """

    def __init__(self, filenames):
        self.filenames = filenames
        self.fp = None
        self.index = 0
        self.iter = None
        self.custom = []
        self.adjust()
        self.lock = None

    def __iter__(self):
        return self

    def adjust(self):
        self.closeFP()
        if self.index > len(self.filenames):
            raise StopIteration
        elif self.index == len(self.filenames):
            if self.custom:
                self.iter = iter(self.custom)
            else:
                raise StopIteration
        else:
            current = self.filenames[self.index]
            infoMsg = "loading dictionary from '%s'" % current
            singleTimeLogMessage(infoMsg)
            self.fp = open(current, "r")
            self.iter = iter(self.fp)

        self.index += 1

    def append(self, value):
        self.custom.append(value)
        
    def closeFP(self):
        if self.fp:
            self.fp.close()
            self.fp = None

    def next(self):
        retVal = None
        if self.lock:
            self.lock.acquire()
        try:
            retVal = self.iter.next().rstrip()
        except StopIteration:
            self.adjust()
            retVal = self.iter.next().rstrip()
        finally:
            if self.lock:
                self.lock.release()
        return retVal

    def rewind(self):
        self.index = 0
        self.adjust()
