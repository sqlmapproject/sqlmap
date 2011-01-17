#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import readInput
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapUndefinedMethod

class Fingerprint:
    """
    This class defines generic fingerprint functionalities for plugins.
    """

    def __init__(self, dbms):
        kb.misc.forcedDbms = dbms

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

    def userChooseDbmsOs(self):
        warnMsg = "for some reason sqlmap was unable to fingerprint "
        warnMsg += "the back-end DBMS operating system"
        logger.warn(warnMsg)

        msg = "do you want to provide the OS? [(W)indows/(l)inux]"

        while True:
            os = readInput(msg, default="W")

            if os[0].lower() == "w":
                kb.os = "Windows"
                break
            elif os[0].lower() == "l":
                kb.os = "Linux"
                break
            else:
                warnMsg = "invalid value"
                logger.warn(warnMsg)
