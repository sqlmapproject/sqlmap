#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
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



import os

from lib.core.common import randomStr
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger


class Registry:
    """
    This class defines methods to read and write Windows registry keys
    """

    def __initVars(self, regKey, regName, regType=None, regValue=None, parse=False):
        self.__regKey        = regKey
        self.__regName       = regName
        self.__regType       = regType
        self.__regValue      = regValue

        self.__randStr       = randomStr(lowercase=True)
        self.__batPathRemote = "%s/sqlmapreg%s%s.bat" % (conf.tmpPath, self.__operation, self.__randStr)
        self.__batPathLocal  = "%s/sqlmapreg%s%s.bat" % (conf.outputPath, self.__operation, self.__randStr)

        if parse == True:
            readParse = "FOR /F \"tokens=2* delims==\" %%A IN ('REG QUERY \"" + self.__regKey + "\" /v \"" + self.__regName + "\"') DO SET value=%%A\r\nECHO %value%\r\n"
        else:
            readParse = "REG QUERY \"" + self.__regKey + "\" /v \"" + self.__regName + "\""

        self.__batRead = (
                           "@ECHO OFF\r\n",
                           readParse
                         )

        self.__batAdd  = (
                           "@ECHO OFF\r\n",
                           "REG ADD \"%s\" /v \"%s\" /t %s /d %s /f" % (self.__regKey, self.__regName, self.__regType, self.__regValue)
                         )

        self.__batDel  = (
                           "@ECHO OFF\r\n",
                           "REG DELETE \"%s\" /v \"%s\" /f" % (self.__regKey, self.__regName)
                         )


    def __execBatPathRemote(self):
        if kb.dbms == "Microsoft SQL Server":
            cmd = self.xpCmdshellForgeCmd(self.__batPathRemote)
        else:
            cmd = self.__batPathRemote

        self.execCmd(cmd)


    def __createLocalBatchFile(self):
        self.__batPathFp = open(self.__batPathLocal, "w")

        if self.__operation == "read":
            lines = self.__batRead
        elif self.__operation == "add":
            lines = self.__batAdd
        elif self.__operation == "delete":
            lines = self.__batDel

        for line in lines:
            self.__batPathFp.write(line)

        self.__batPathFp.close()


    def __createRemoteBatchFile(self):
        logger.debug("creating batch file '%s'" % self.__batPathRemote)

        self.__createLocalBatchFile()
        self.writeFile(self.__batPathLocal, self.__batPathRemote, "text", False)

        os.unlink(self.__batPathLocal)


    def readRegKey(self, regKey, regName, parse):
        self.__operation = "read"

        self.__initVars(regKey, regName, parse=parse)
        self.__createRemoteBatchFile()

        logger.debug("reading registry key '%s' name '%s'" % (regKey, regName))

        return self.evalCmd(self.__batPathRemote)


    def addRegKey(self, regKey, regName, regType, regValue):
        self.__operation = "add"

        self.__initVars(regKey, regName, regType, regValue)
        self.__createRemoteBatchFile()

        debugMsg  = "adding registry key name '%s' " % self.__regName
        debugMsg += "to registry key '%s'" % self.__regKey
        logger.debug(debugMsg)

        self.__execBatPathRemote()


    def delRegKey(self, regKey, regName):
        self.__operation = "delete"

        self.__initVars(regKey, regName)
        self.__createRemoteBatchFile()

        debugMsg  = "deleting registry key name '%s' " % self.__regName
        debugMsg += "from registry key '%s'" % self.__regKey
        logger.debug(debugMsg)

        self.__execBatPathRemote()
