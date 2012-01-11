#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.exception import sqlmapUnsupportedFeatureException

from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def __init__(self):
        GenericFilesystem.__init__(self)

    def readFile(self, rFile):
        errMsg = "on Sybase it is not possible to read files"
        raise sqlmapUnsupportedFeatureException, errMsg

    def writeFile(self, wFile, dFile, fileType=None, confirm=True):
        errMsg = "on Sybase it is not possible to write files"
        raise sqlmapUnsupportedFeatureException, errMsg
