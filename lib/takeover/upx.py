#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""


import os
import stat
import time

from subprocess import PIPE
from subprocess import STDOUT
from subprocess import Popen as execute

from lib.core.common import dataToStdout
from lib.core.common import decloakToMkstemp
from lib.core.data import logger
from lib.core.data import paths
from lib.core.settings import IS_WIN
from lib.core.settings import PLATFORM
from lib.core.subprocessng import pollProcess

class UPX:
    """
    This class defines methods to compress binary files with UPX (Ultimate
    Packer for eXecutables).

    Reference:
    * http://upx.sourceforge.net    
    """

    def __initialize(self, srcFile, dstFile=None):
        if PLATFORM == "mac":
            self.__upxTemp = decloakToMkstemp("%s/upx/macosx/upx_" % paths.SQLMAP_CONTRIB_PATH)

        elif PLATFORM in ( "ce", "nt" ):
            self.__upxTemp = decloakToMkstemp("%s\upx\windows\upx.exe_" % paths.SQLMAP_CONTRIB_PATH, suffix=".exe")

        elif PLATFORM == "posix":
            self.__upxTemp = decloakToMkstemp("%s/upx/linux/upx_" % paths.SQLMAP_CONTRIB_PATH)

        else:
            warnMsg  = "unsupported platform for the compression tool "
            warnMsg += "(upx), sqlmap will continue anyway"
            logger.warn(warnMsg)

            self.__upxTemp = decloakToMkstemp("%s/upx/linux/upx_" % paths.SQLMAP_CONTRIB_PATH)

        self.__upxPath = self.__upxTemp.name
        self.__upxTemp.close() #needed for execution rights

        if not IS_WIN:
            os.chmod(self.__upxPath, stat.S_IXUSR)

        self.__upxCmd = "%s -9 -qq %s" % (self.__upxPath, srcFile)

        if dstFile:
            self.__upxCmd += " -o %s" % dstFile

    def pack(self, srcFile, dstFile=None):
        self.__initialize(srcFile, dstFile)

        logger.debug("executing local command: %s" % self.__upxCmd)
        process = execute(self.__upxCmd, shell=True, stdout=PIPE, stderr=STDOUT)

        dataToStdout("\r[%s] [INFO] compression in progress " % time.strftime("%X"))
        pollProcess(process)
        upxStdout, upxStderr = process.communicate()

        if hasattr(self, '__upxTemp'):
            os.remove(self.__upxTemp.name)

        msg = "failed to compress the file"

        if "NotCompressibleException" in upxStdout:
            msg += " because you provided a Metasploit version above "
            msg += "3.3-dev revision 6681. This will not inficiate "
            msg += "the correct execution of sqlmap. It might "
            msg += "only slow down a bit the execution"
            logger.debug(msg)

        elif upxStderr:
            logger.warn(msg)

        else:
            return os.path.getsize(srcFile)

        return None

    def unpack(self, srcFile, dstFile=None):
        pass

    def verify(self, filePath):
        pass

upx = UPX()
