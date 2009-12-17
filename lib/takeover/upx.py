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
import time

from subprocess import PIPE
from subprocess import STDOUT
from subprocess import Popen as execute

from lib.core.common import dataToStdout
from lib.core.common import pollProcess
from lib.core.data import logger
from lib.core.data import paths
from lib.core.settings import PLATFORM


class UPX:
    """
    This class defines methods to compress binary files with UPX (Ultimate
    Packer for eXecutables).

    Reference:
    * http://upx.sourceforge.net    
    """

    def __initialize(self, srcFile, dstFile=None):
        if "darwin" in PLATFORM:
            self.__upxPath = "%s/upx/macosx/upx" % paths.SQLMAP_CONTRIB_PATH

        elif "win" in PLATFORM:
            self.__upxPath = "%s\upx\windows\upx.exe" % paths.SQLMAP_CONTRIB_PATH

        elif "linux" in PLATFORM:
            self.__upxPath = "%s/upx/linux/upx" % paths.SQLMAP_CONTRIB_PATH

        else:
            warnMsg  = "unsupported platform for the compression tool "
            warnMsg += "(upx), sqlmap will continue anyway"
            logger.warn(warnMsg)

            self.__upxPath = "%s/upx/linux/upx" % paths.SQLMAP_CONTRIB_PATH

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
