#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import zipfile

from lib.core.common import getSafeExString
from lib.core.common import isZipFile
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapInstallationException
from thirdparty import six

class Wordlist(six.Iterator):
    """
    Iterator for looping over a large dictionaries

    >>> from lib.core.option import paths
    >>> isinstance(next(Wordlist(paths.SMALL_DICT)), six.binary_type)
    True
    >>> isinstance(next(Wordlist(paths.WORDLIST)), six.binary_type)
    True
    """

    def __init__(self, filenames, proc_id=None, proc_count=None, custom=None):
        self.filenames = [filenames] if isinstance(filenames, six.string_types) else filenames
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
            return  # Note: https://stackoverflow.com/a/30217723 (PEP 479)
        elif self.index == len(self.filenames):
            self.iter = iter(self.custom)
        else:
            self.current = self.filenames[self.index]
            if isZipFile(self.current):
                try:
                    _ = zipfile.ZipFile(self.current, 'r')
                except zipfile.error as ex:
                    errMsg = "something appears to be wrong with "
                    errMsg += "the file '%s' ('%s'). Please make " % (self.current, getSafeExString(ex))
                    errMsg += "sure that you haven't made any changes to it"
                    raise SqlmapInstallationException(errMsg)
                if len(_.namelist()) == 0:
                    errMsg = "no file(s) inside '%s'" % self.current
                    raise SqlmapDataException(errMsg)
                self.fp = _.open(_.namelist()[0])
            else:
                self.fp = open(self.current, "rb")
            self.iter = iter(self.fp)

        self.index += 1

    def closeFP(self):
        if self.fp:
            self.fp.close()
            self.fp = None

    def __next__(self):
        retVal = None
        while True:
            self.counter += 1
            try:
                retVal = next(self.iter).rstrip()
            except zipfile.error as ex:
                errMsg = "something appears to be wrong with "
                errMsg += "the file '%s' ('%s'). Please make " % (self.current, getSafeExString(ex))
                errMsg += "sure that you haven't made any changes to it"
                raise SqlmapInstallationException(errMsg)
            except StopIteration:
                self.adjust()
                retVal = next(self.iter).rstrip()
            if not self.proc_count or self.counter % self.proc_count == self.proc_id:
                break
        return retVal

    def rewind(self):
        self.index = 0
        self.adjust()
