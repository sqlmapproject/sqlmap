#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import ntpath
import re

from lib.core.common import Backend
from lib.core.common import hashDBWrite
from lib.core.common import isStackingAvailable
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import posixToNtSlashes
from lib.core.common import readInput
from lib.core.common import singleTimeDebugMessage
from lib.core.common import unArrayizeValue
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import OS
from lib.core.exception import SqlmapNoneDataException
from lib.request import inject

class Miscellaneous(object):
    """
    This class defines miscellaneous functionalities for plugins.
    """

    def __init__(self):
        pass

    def getRemoteTempPath(self):
        if not conf.tmpPath and Backend.isDbms(DBMS.MSSQL):
            debugMsg = "identifying Microsoft SQL Server error log directory "
            debugMsg += "that sqlmap will use to store temporary files with "
            debugMsg += "commands' output"
            logger.debug(debugMsg)

            _ = unArrayizeValue(inject.getValue("SELECT SERVERPROPERTY('ErrorLogFileName')", safeCharEncode=False))

            if _:
                conf.tmpPath = ntpath.dirname(_)

        if not conf.tmpPath:
            if Backend.isOs(OS.WINDOWS):
                if conf.direct:
                    conf.tmpPath = "%TEMP%"
                else:
                    self.checkDbmsOs(detailed=True)

                    if Backend.getOsVersion() in ("2000", "NT"):
                        conf.tmpPath = "C:/WINNT/Temp"
                    elif Backend.isOs("XP"):
                        conf.tmpPath = "C:/Documents and Settings/All Users/Application Data/Temp"
                    else:
                        conf.tmpPath = "C:/Windows/Temp"
            else:
                conf.tmpPath = "/tmp"

        if re.search(r"\A[\w]:[\/\\]+", conf.tmpPath, re.I):
            Backend.setOs(OS.WINDOWS)

        conf.tmpPath = normalizePath(conf.tmpPath)
        conf.tmpPath = ntToPosixSlashes(conf.tmpPath)

        singleTimeDebugMessage("going to use '%s' as temporary files directory" % conf.tmpPath)

        hashDBWrite(HASHDB_KEYS.CONF_TMP_PATH, conf.tmpPath)

        return conf.tmpPath

    def getVersionFromBanner(self):
        if "dbmsVersion" in kb.bannerFp:
            return

        infoMsg = "detecting back-end DBMS version from its banner"
        logger.info(infoMsg)

        query = queries[Backend.getIdentifiedDbms()].banner.query

        if conf.direct:
            query = "SELECT %s" % query

        kb.bannerFp["dbmsVersion"] = unArrayizeValue(inject.getValue(query)) or ""

        match = re.search(r"\d[\d.-]*", kb.bannerFp["dbmsVersion"])
        if match:
            kb.bannerFp["dbmsVersion"] = match.group(0)

    def delRemoteFile(self, filename):
        if not filename:
            return

        self.checkDbmsOs()

        if Backend.isOs(OS.WINDOWS):
            filename = posixToNtSlashes(filename)
            cmd = "del /F /Q %s" % filename
        else:
            cmd = "rm -f %s" % filename

        self.execCmd(cmd, silent=True)

    def createSupportTbl(self, tblName, tblField, tblType):
        inject.goStacked("DROP TABLE %s" % tblName, silent=True)

        if Backend.isDbms(DBMS.MSSQL) and tblName == self.cmdTblName:
            inject.goStacked("CREATE TABLE %s(id INT PRIMARY KEY IDENTITY, %s %s)" % (tblName, tblField, tblType))
        else:
            inject.goStacked("CREATE TABLE %s(%s %s)" % (tblName, tblField, tblType))

    def cleanup(self, onlyFileTbl=False, udfDict=None, web=False):
        """
        Cleanup file system and database from sqlmap create files, tables
        and functions
        """

        if web and self.webBackdoorFilePath:
            logger.info("cleaning up the web files uploaded")

            self.delRemoteFile(self.webStagerFilePath)
            self.delRemoteFile(self.webBackdoorFilePath)

        if (not isStackingAvailable() or kb.udfFail) and not conf.direct:
            return

        if any((conf.osCmd, conf.osShell)) and Backend.isDbms(DBMS.PGSQL) and kb.copyExecTest:
            return

        if Backend.isOs(OS.WINDOWS):
            libtype = "dynamic-link library"

        elif Backend.isOs(OS.LINUX):
            libtype = "shared object"

        else:
            libtype = "shared library"

        if onlyFileTbl:
            logger.debug("cleaning up the database management system")
        else:
            logger.info("cleaning up the database management system")

        logger.debug("removing support tables")
        inject.goStacked("DROP TABLE %s" % self.fileTblName, silent=True)
        inject.goStacked("DROP TABLE %shex" % self.fileTblName, silent=True)

        if not onlyFileTbl:
            inject.goStacked("DROP TABLE %s" % self.cmdTblName, silent=True)

            if Backend.isDbms(DBMS.MSSQL):
                udfDict = {"master..new_xp_cmdshell": {}}

            if udfDict is None:
                udfDict = getattr(self, "sysUdfs", {})

            for udf, inpRet in udfDict.items():
                message = "do you want to remove UDF '%s'? [Y/n] " % udf

                if readInput(message, default='Y', boolean=True):
                    dropStr = "DROP FUNCTION %s" % udf

                    if Backend.isDbms(DBMS.PGSQL):
                        inp = ", ".join(i for i in inpRet["input"])
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

        choice = readInput(message, default='1')

        if not choice or choice == '1':
            choice = '1'
            condParam = " LIKE '%%%s%%'"
        elif choice == '2':
            condParam = "='%s'"
        else:
            errMsg = "invalid value"
            raise SqlmapNoneDataException(errMsg)

        return choice, condParam
