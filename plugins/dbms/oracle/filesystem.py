#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.exception import sqlmapUnsupportedFeatureException

from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def __init__(self):
        GenericFilesystem.__init__(self)

    def readFile(self, rFile):
        errMsg = "File system read access not yet implemented for "
        errMsg += "Oracle"
        raise sqlmapUnsupportedFeatureException, errMsg

    def writeFile(self, wFile, dFile, fileType=None, confirm=True):
        errMsg = "File system write access not yet implemented for "
        errMsg += "Oracle"
        raise sqlmapUnsupportedFeatureException, errMsg
