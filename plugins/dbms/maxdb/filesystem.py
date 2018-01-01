#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def __init__(self):
        GenericFilesystem.__init__(self)

    def readFile(self, rFile):
        errMsg = "on SAP MaxDB reading of files is not supported"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def writeFile(self, wFile, dFile, fileType=None, forceCheck=False):
        errMsg = "on SAP MaxDB writing of files is not supported"
        raise SqlmapUnsupportedFeatureException(errMsg)
