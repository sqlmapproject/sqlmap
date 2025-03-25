#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os

from lib.core.common import openFile
from lib.core.common import randomStr
from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import REGISTRY_OPERATION

class Registry(object):
    """
    This class defines methods to read and write Windows registry keys
    """

    def _initVars(self, regKey, regValue, regType=None, regData=None, parse=False):
        self._regKey = regKey
        self._regValue = regValue
        self._regType = regType
        self._regData = regData

        self._randStr = randomStr(lowercase=True)
        self._batPathRemote = "%s/tmpr%s.bat" % (conf.tmpPath, self._randStr)
        self._batPathLocal = os.path.join(conf.outputPath, "tmpr%s.bat" % self._randStr)

        if parse:
            readParse = "FOR /F \"tokens=*\" %%A IN ('REG QUERY \"" + self._regKey + "\" /v \"" + self._regValue + "\"') DO SET value=%%A\r\nECHO %value%\r\n"
        else:
            readParse = "REG QUERY \"" + self._regKey + "\" /v \"" + self._regValue + "\""

        self._batRead = (
            "@ECHO OFF\r\n",
            readParse,
        )

        self._batAdd = (
            "@ECHO OFF\r\n",
            "REG ADD \"%s\" /v \"%s\" /t %s /d %s /f" % (self._regKey, self._regValue, self._regType, self._regData),
        )

        self._batDel = (
            "@ECHO OFF\r\n",
            "REG DELETE \"%s\" /v \"%s\" /f" % (self._regKey, self._regValue),
        )

    def _createLocalBatchFile(self):
        self._batPathFp = openFile(self._batPathLocal, "w")

        if self._operation == REGISTRY_OPERATION.READ:
            lines = self._batRead
        elif self._operation == REGISTRY_OPERATION.ADD:
            lines = self._batAdd
        elif self._operation == REGISTRY_OPERATION.DELETE:
            lines = self._batDel

        for line in lines:
            self._batPathFp.write(line)

        self._batPathFp.close()

    def _createRemoteBatchFile(self):
        logger.debug("creating batch file '%s'" % self._batPathRemote)

        self._createLocalBatchFile()
        self.writeFile(self._batPathLocal, self._batPathRemote, "text", forceCheck=True)

        os.unlink(self._batPathLocal)

    def readRegKey(self, regKey, regValue, parse=False):
        self._operation = REGISTRY_OPERATION.READ

        Registry._initVars(self, regKey, regValue, parse=parse)
        self._createRemoteBatchFile()

        logger.debug("reading registry key '%s' value '%s'" % (regKey, regValue))

        data = self.evalCmd(self._batPathRemote)

        if data and not parse:
            pattern = '    '
            index = data.find(pattern)
            if index != -1:
                data = data[index + len(pattern):]

        self.delRemoteFile(self._batPathRemote)

        return data

    def addRegKey(self, regKey, regValue, regType, regData):
        self._operation = REGISTRY_OPERATION.ADD

        Registry._initVars(self, regKey, regValue, regType, regData)
        self._createRemoteBatchFile()

        debugMsg = "adding registry key value '%s' " % self._regValue
        debugMsg += "to registry key '%s'" % self._regKey
        logger.debug(debugMsg)

        self.execCmd(cmd=self._batPathRemote)
        self.delRemoteFile(self._batPathRemote)

    def delRegKey(self, regKey, regValue):
        self._operation = REGISTRY_OPERATION.DELETE

        Registry._initVars(self, regKey, regValue)
        self._createRemoteBatchFile()

        debugMsg = "deleting registry key value '%s' " % self._regValue
        debugMsg += "from registry key '%s'" % self._regKey
        logger.debug(debugMsg)

        self.execCmd(cmd=self._batPathRemote)
        self.delRemoteFile(self._batPathRemote)
