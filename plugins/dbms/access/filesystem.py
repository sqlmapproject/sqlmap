#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def readFile(self, rFile):
        errMsg = "on Microsoft Access it is not possible to read files"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def writeFile(self, wFile, dFile, fileType=None, forceCheck=False):
        errMsg = "on Microsoft Access it is not possible to write files"
        raise SqlmapUnsupportedFeatureException(errMsg)
