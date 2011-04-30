#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import os

from lib.core.common import randomStr
from lib.core.data import conf
from lib.core.data import logger

class Registry:
    """
    This class defines methods to read and write Windows registry keys
    """

    def __initVars(self, regKey, regValue, regType=None, regData=None, parse=False):
        self.__regKey = regKey
        self.__regValue = regValue
        self.__regType = regType
        self.__regData = regData

        self.__randStr = randomStr(lowercase=True)
        self.__batPathRemote = "%s/tmpr%s.bat" % (conf.tmpPath, self.__randStr)
        self.__batPathLocal = os.path.join(conf.outputPath, "tmpr%s.bat" % self.__randStr)

        if parse:
            readParse = "FOR /F \"tokens=*\" %%A IN ('REG QUERY \"" + self.__regKey + "\" /v \"" + self.__regValue + "\"') DO SET value=%%A\r\nECHO %value%\r\n"
        else:
            readParse = "REG QUERY \"" + self.__regKey + "\" /v \"" + self.__regValue + "\""

        self.__batRead = (
                           "@ECHO OFF\r\n",
                           readParse
                         )

        self.__batAdd = (
                           "@ECHO OFF\r\n",
                           "REG ADD \"%s\" /v \"%s\" /t %s /d %s /f" % (self.__regKey, self.__regValue, self.__regType, self.__regData)
                         )

        self.__batDel = (
                           "@ECHO OFF\r\n",
                           "REG DELETE \"%s\" /v \"%s\" /f" % (self.__regKey, self.__regValue)
                         )

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

    def readRegKey(self, regKey, regValue, parse=False):
        self.__operation = "read"

        self.__initVars(regKey, regValue, parse=parse)
        self.__createRemoteBatchFile()

        logger.debug("reading registry key '%s' value '%s'" % (regKey, regValue))

        data = self.evalCmd(self.__batPathRemote)

        if data and not parse:
            pattern = '    '
            index = data.find(pattern)
            if index != -1:
                data = data[index + len(pattern):]

        self.delRemoteFile(self.__batPathRemote)

        return data

    def addRegKey(self, regKey, regValue, regType, regData):
        self.__operation = "add"

        self.__initVars(regKey, regValue, regType, regData)
        self.__createRemoteBatchFile()

        debugMsg = "adding registry key value '%s' " % self.__regValue
        debugMsg += "to registry key '%s'" % self.__regKey
        logger.debug(debugMsg)

        self.execCmd(cmd=self.__batPathRemote)
        self.delRemoteFile(self.__batPathRemote)

    def delRegKey(self, regKey, regValue):
        self.__operation = "delete"

        self.__initVars(regKey, regValue)
        self.__createRemoteBatchFile()

        debugMsg = "deleting registry key value '%s' " % self.__regValue
        debugMsg += "from registry key '%s'" % self.__regKey
        logger.debug(debugMsg)

        self.execCmd(cmd=self.__batPathRemote)
        self.delRemoteFile(self.__batPathRemote)
