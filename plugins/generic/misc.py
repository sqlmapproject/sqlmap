#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.common import getCompiledRegex
from lib.core.common import isTechniqueAvailable
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import posixToNtSlashes
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.session import setRemoteTempPath
from lib.request import inject

class Miscellaneous:
    """
    This class defines miscellaneous functionalities for plugins.
    """

    def __init__(self):
        pass

    def getRemoteTempPath(self):
        if not conf.tmpPath:
            if kb.os == "Windows":
                conf.tmpPath = "C:/WINDOWS/Temp"
            else:
                conf.tmpPath = "/tmp"

        if getCompiledRegex("(?i)\A[\w]:[\/\\\\]+").search(conf.tmpPath):
            kb.os = "Windows"

        conf.tmpPath = normalizePath(conf.tmpPath)
        conf.tmpPath = ntToPosixSlashes(conf.tmpPath)

        setRemoteTempPath()

    def getVersionFromBanner(self):
        if "dbmsVersion" in kb.bannerFp:
            return

        infoMsg = "detecting back-end DBMS version from its banner"
        logger.info(infoMsg)

        if kb.dbms == DBMS.MYSQL:
            first, last = 1, 6

        elif kb.dbms == DBMS.PGSQL:
            first, last = 12, 6

        elif kb.dbms == DBMS.MSSQL:
            first, last = 29, 9

        else:
            raise sqlmapUnsupportedFeatureException, "unsupported DBMS"

        query = queries[kb.dbms].substring.query % (queries[kb.dbms].banner.query, first, last)

        if conf.direct:
            query = "SELECT %s" % query

        kb.bannerFp["dbmsVersion"] = inject.getValue(query, unpack=False)
        kb.bannerFp["dbmsVersion"] = kb.bannerFp["dbmsVersion"].replace(",", "").replace("-", "").replace(" ", "")

    def delRemoteFile(self, tempFile):
        self.checkDbmsOs()

        if kb.os == "Windows":
            tempFile = posixToNtSlashes(tempFile)
            cmd = "del /F /Q %s" % tempFile
        else:
            cmd = "rm -f %s" % tempFile

        self.execCmd(cmd, silent=True)

    def createSupportTbl(self, tblName, tblField, tblType):
        inject.goStacked("DROP TABLE %s" % tblName, silent=True)
        inject.goStacked("CREATE TABLE %s(%s %s)" % (tblName, tblField, tblType))

    def cleanup(self, onlyFileTbl=False, udfDict=None):
        """
        Cleanup database from sqlmap create tables and functions
        """

        if not isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED) and not conf.direct:
            return

        if kb.os == "Windows":
            libtype = "dynamic-link library"

        elif kb.os == "Linux":
            libtype = "shared object"

        else:
            libtype = "shared library"

        if onlyFileTbl:
            logger.debug("cleaning up the database management system")
        else:
            logger.info("cleaning up the database management system")

        logger.debug("removing support tables")
        inject.goStacked("DROP TABLE %s" % self.fileTblName, silent=True)

        if not onlyFileTbl:
            inject.goStacked("DROP TABLE %s" % self.cmdTblName, silent=True)

            if kb.dbms == DBMS.MSSQL:
                return

            if udfDict is None:
                udfDict = self.sysUdfs

            for udf, inpRet in udfDict.items():
                message = "do you want to remove UDF '%s'? [Y/n] " % udf
                output  = readInput(message, default="Y")

                if not output or output in ("y", "Y"):
                    dropStr = "DROP FUNCTION %s" % udf

                    if kb.dbms == DBMS.PGSQL:
                        inp      = ", ".join(i for i in inpRet["input"])
                        dropStr += "(%s)" % inp

                    logger.debug("removing UDF '%s'" % udf)
                    inject.goStacked(dropStr, silent=True)

            logger.info("database management system cleanup finished")

            warnMsg = "remember that UDF %s files " % libtype

            if conf.osPwn:
                warnMsg += "and Metasploit related files in the temporary "
                warnMsg += "folder "

            warnMsg += "saved on the file system can only be deleted "
            warnMsg += "manually"
            logger.warn(warnMsg)

    def likeOrExact(self, what):
        message = "do you want sqlmap to consider provided %s(s):\n" % what
        message += "[1] as LIKE %s names (default)\n" % what
        message += "[2] as exact %s names" % what

        choice = readInput(message, default="1")

        if not choice or choice == "1":
            choice = "1"
            condParam = " LIKE '%%%s%%'"
        elif choice.isdigit() and choice == "2":
            condParam = "='%s'"
        else:
            errMsg = "invalid value"
            raise sqlmapNoneDataException, errMsg

        return choice, condParam
