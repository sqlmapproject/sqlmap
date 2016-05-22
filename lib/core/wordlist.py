#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import zipfile

from lib.core.common import getSafeExString
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapInstallationException

class Wordlist(object):
    """
    Iterator for looping over a large dictionaries
    """

    def __init__(self, filenames, proc_id=None, proc_count=None, custom=None):
        self.filenames = filenames
        self.fp = None
        self.index = 0
        self.counter = -1
        self.current = None
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
            self.iter = iter(self.custom)
        else:
            self.current = self.filenames[self.index]
            if os.path.splitext(self.current)[1].lower() == ".zip":
                try:
                    _ = zipfile.ZipFile(self.current, 'r')
                except zipfile.error, ex:
                    errMsg = "something appears to be wrong with "
                    errMsg += "the file '%s' ('%s'). Please make " % (self.current, getSafeExString(ex))
                    errMsg += "sure that you haven't made any changes to it"
                    raise SqlmapInstallationException, errMsg
                if len(_.namelist()) == 0:
                    errMsg = "no file(s) inside '%s'" % self.current
                    raise SqlmapDataException(errMsg)
                self.fp = _.open(_.namelist()[0])
            else:
                self.fp = open(self.current, 'r')
            self.iter = iter(self.fp)

        self.index += 1

    def closeFP(self):
        if self.fp:
            self.fp.close()
            self.fp = None

    def next(self):
        retVal = None
        while True:
            self.counter += 1
            try:
                retVal = self.iter.next().rstrip()
            except zipfile.error, ex:
                errMsg = "something appears to be wrong with "
                errMsg += "the file '%s' ('%s'). Please make " % (self.current, getSafeExString(ex))
                errMsg += "sure that you haven't made any changes to it"
                raise SqlmapInstallationException, errMsg
            except StopIteration:
                self.adjust()
                retVal = self.iter.next().rstrip()
            if not self.proc_count or self.counter % self.proc_count == self.proc_id:
                break
        return retVal

    def rewind(self):
        self.index = 0
        self.adjust()
