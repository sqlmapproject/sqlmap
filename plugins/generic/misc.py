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



import re
import os

from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.session import setRemoteTempPath
from lib.request import inject
from lib.techniques.outband.stacked import stackedTest


class Miscellaneous:
    """
    This class defines miscellaneous functionalities for plugins.
    """

    def getRemoteTempPath(self):
        if not conf.tmpPath:
            if kb.os == "Windows":
                # NOTES:
                #
                # * The system-wide temporary files directory is
                # C:\WINDOWS\Temp
                #
                # * MySQL runs by default as SYSTEM
                #
                # * PostgreSQL runs by default as postgres user and the
                #   temporary files directory is C:\Documents and Settings\postgres\Local Settings\Temp,
                #   however the system-wide folder is writable too
                #
                #infoMsg  = "retrieving remote absolute path of temporary files "
                #infoMsg += "directory"
                #logger.info(infoMsg)
                #
                #conf.tmpPath = self.evalCmd("echo %TEMP%")
                conf.tmpPath = "C:/WINDOWS/Temp"
            else:
                conf.tmpPath = "/tmp"

        if re.search("^[\w]\:[\/\\\\]+", conf.tmpPath, re.I):
            kb.os = "Windows"

        conf.tmpPath = conf.tmpPath.replace("\\", "/")
        conf.tmpPath = os.path.normpath(conf.tmpPath)

        setRemoteTempPath()


    def delRemoteFile(self, tempFile, doubleslash=False):
        self.checkDbmsOs()

        if kb.os == "Windows":
            if doubleslash is True:
                tempFile = tempFile.replace("/", "\\\\")
            else:
                tempFile = tempFile.replace("/", "\\")

            cmd = "del /F /Q %s" % tempFile
        else:
            cmd = "rm -f %s" % tempFile

        self.execCmd(cmd, forgeCmd=True)


    def createSupportTbl(self, tblName, tblField, tblType):
        inject.goStacked("DROP TABLE %s" % tblName)
        inject.goStacked("CREATE TABLE %s(%s %s)" % (tblName, tblField, tblType))


    def cleanup(self, onlyFileTbl=False, udfDict=None):
        """
        Cleanup database from sqlmap create tables and functions
        """

        stackedTest()

        if kb.stackedTest == False:
            return

        if kb.os == "Windows":
            libtype = "dynamic-link library"

        elif kb.os == "Linux":
            libtype = "shared object"

        else:
            libtype = "shared library"

        if onlyFileTbl == True:
            logger.debug("cleaning up the database management system")
        else:
            logger.info("cleaning up the database management system")

        logger.debug("removing support tables")
        inject.goStacked("DROP TABLE %s" % self.fileTblName)

        if onlyFileTbl == False:
            inject.goStacked("DROP TABLE %s" % self.cmdTblName)

            if kb.dbms == "Microsoft SQL Server":
                return

            if udfDict is None:
                udfDict = self.sysUdfs

            for udf, inpRet in udfDict.items():
                message = "do you want to remove UDF '%s'? [Y/n] " % udf
                output  = readInput(message, default="Y")

                if not output or output in ("y", "Y"):
                    dropStr = "DROP FUNCTION %s" % udf

                    if kb.dbms == "PostgreSQL":
                        inp      = ", ".join(i for i in inpRet["input"])
                        dropStr += "(%s)" % inp

                    logger.debug("removing UDF '%s'" % udf)
                    inject.goStacked(dropStr)

            logger.info("database management system cleanup finished")

            warnMsg = "remember that UDF %s files " % libtype

            if conf.osPwn:
                warnMsg += "and Metasploit related files in the temporary "
                warnMsg += "folder "

            warnMsg += "saved on the file system can only be deleted "
            warnMsg += "manually"
            logger.warn(warnMsg)
