#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file doc/COPYING for copying permission.
"""

from lib.core.exception import sqlmapUndefinedMethod

class Fingerprint:
    """
    This class defines generic fingerprint functionalities for plugins.
    """

    def __init__(self):
        pass

    def getFingerprint(self):
        errMsg  = "'getFingerprint' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def checkDbms(self):
        errMsg  = "'checkDbms' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def checkDbmsOs(self, detailed=False):
        errMsg  = "'checkDbmsOs' method must be defined "
        errMsg += "into the specific DBMS plugin"
        raise sqlmapUndefinedMethod, errMsg

    def forceDbmsEnum(self):
        pass
